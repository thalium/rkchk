// SPDX-License-Identifier: GPL-2.0

//! Rust character device sample.
use core::clone::Clone;
use core::default::Default;
use core::ffi::c_char;
use core::hash::Hash;
use core::hash::Hasher;
use core::iter::Iterator;
use core::mem;
use core::ptr::addr_of;
use core::result::Result::Err;
use core::result::Result::Ok;
use core::slice;
use core::str;
use event::EBPFFuncInfo;
use event::Events;
use event::FunctionInfo;
use event::IndirectCallHijackInfo;
use event::LoadedLKMInfo;
use event::ModuleInfo;
use event::ProcessInfo;
use kernel::bindings;
use kernel::c_str;
use kernel::error::Result;
use kernel::fprobe::FprobeOperations;
use kernel::impl_has_list_links;
use kernel::impl_list_item;
use kernel::ioctl::_IO;
use kernel::ioctl::_IOC_SIZE;
use kernel::ioctl::_IOR;
use kernel::list::impl_list_arc_safe;
use kernel::list::List;
use kernel::list::ListArc;
use kernel::list::ListLinks;
use kernel::miscdevice;
use kernel::miscdevice::MiscDevice;
use kernel::miscdevice::MiscDeviceRegistration;
use kernel::module::is_kernel;
use kernel::module::is_module;
use kernel::module::symbols_lookup_name;
use kernel::new_condvar;
use kernel::new_spinlock;
use kernel::prelude::*;
use kernel::socket;
use kernel::str::CStr;
use kernel::str::CString;
use kernel::sync::Arc;
use kernel::sync::ArcBorrow;
use kernel::sync::CondVar;
use kernel::sync::SpinLock;
use kernel::task::Task;
use kernel::transmute::AsBytes;
use kernel::types::ForeignOwnable;
use kernel::uaccess::UserSlice;

use kernel::fprobe;
use kernel::insn;
use kernel::module;
use kernel::uaccess::UserSliceReader;

pub mod event;
pub mod fx_hash;

unsafe impl AsBytes for event::Events {}

/// The maximum number of byte we saved for a given function
const MAX_SAVED_SIZE: usize = 4096;
/// The number of syscall on my computer
const NB_SYCALLS: usize = 332;

/// `kallsyms_lookup_name` symbol black list
const NAME_LOOKUP: [&str; 12] = [
    "module_tree_insert",
    "module_tree_remove",
    "module_mutex",
    "sys_call_table",
    "__x64_sys_init_module",
    "sys_kill",
    "vfs_read",
    "__x64_sys_kill",
    "__x64_sys_getdents",
    "__x64_sys_getdents64",
    "tcp6_seq_show",
    "tcp4_seq_show",
];

/// Write Protect : the CPU cannot write ro page in ring 0
const CR0_WP: u64 = 1 << 16;
/// User-Mode Instruction Prevention : block the usage of some instructions in user mode
const CR4_UMIP: u64 = 1 << 16;
/// Supervisor Mode Access Execution Protection Enable
const CR4_SMEP: u64 = 1 << 20;
/// Supervisor Mode Access Prevention Enable
const CR4_SMAP: u64 = 1 << 21;

/// Some x86 opcode

/// Jump
const X86_OP_JMP: i32 = 0xE9;
/// Breakpoint
const X86_OP_BP: i32 = 0xCC;

/// RKCHK ioctl type (aka magic number)
const RKCHK_IOC_MAGIC: u32 = b'j' as u32;
/// Run all the integrity checks (ioctl sequence number)
const RKCHK_INTEG_ALL_NR: u32 = 1;
/// Run all the integrity checks (ioctl command)
const RKCHK_INTEG_ALL: u32 = _IO(RKCHK_IOC_MAGIC, RKCHK_INTEG_ALL_NR);
/// Read new events (ioctl sequence number)
const RKCHK_READ_EVENT_NR: u32 = 2;
/// Read new events (ioctl command)
const RKCHK_READ_EVENT: u32 = _IOR::<event::Events>(RKCHK_IOC_MAGIC, RKCHK_READ_EVENT_NR);

static mut EVENT_STACK: Option<Arc<EventStack>> = None;

static mut COMMUNICATION: Option<Arc<Communication>> = None;

module! {
    type: RootkitDetection,
    name: "rootkit_detection",
    author: "Rust for Linux Contributors",
    description: "Rust rootkit detection module",
    license: "GPL",
}

#[pin_data]
struct KEvents {
    #[pin]
    list_link: ListLinks<0>,
    event: Events,
}

// TODO : Ask for Infaillible Error
impl KEvents {
    fn new(event: Events) -> Result<ListArc<Self>> {
        ListArc::pin_init(
            try_pin_init!(KEvents {
                list_link <- ListLinks::new(),
                event,
            }),
            GFP_KERNEL,
        )
    }

    fn get_ref_event(&self) -> &Events {
        &self.event
    }
}

impl_has_list_links!(impl HasListLinks for KEvents { self.list_link });
impl_list_item!(impl ListItem<0> for KEvents { using ListLinks; });
impl_list_arc_safe!(impl ListArcSafe<0> for KEvents { untracked; });

#[pin_data]
struct EventStack {
    x: u32,
    #[pin]
    wait_queue: CondVar,
    #[pin]
    event_stack: SpinLock<List<KEvents, 0>>,
}

impl EventStack {
    fn init() -> Result<Arc<Self>> {
        Arc::pin_init(
            pin_init!(EventStack {
                x : 0,
                wait_queue <- new_condvar!("data queue"),
                event_stack <- new_spinlock!(List::new(), "event stack"),
            }),
            GFP_KERNEL,
        )
    }

    fn push_event(&self, event: ListArc<KEvents, 0>) {
        self.event_stack.lock().push_front(event);

        self.wait_queue.notify_one();
    }

    fn wait_events(&self) -> Result<ListArc<KEvents, 0>> {
        let mut lock = self.event_stack.lock();
        while lock.is_empty() {
            if self.wait_queue.wait_interruptible(&mut lock) {
                return Err(EINTR);
            }
        }
        // If we could make a while let with an else let statment this situation won't exist,
        // We cannot get the None option of this match but anyway
        match lock.pop_back() {
            Some(event) => Ok(event),
            None => Err(EAGAIN),
        }
    }
}

/// Run a series of test to check if the address come from a normal space
/// 1 - Check if it ome from a module, if yes get the module name (use the mod_tree struct in the kernel)
/// 2 - If it has a module name, check that it's in the linked list of module :
///     many rootkit remove themselves from the linked list but not from the mod tree
/// 3 - If a module name wasn't found check that it come from the kernel executable
/// # Return :
/// In case of an Ok return :
///     Some(()) => an inconsistency was found
///     None => everything is fine
fn check_address_consistency(addr: u64) -> Result<Option<event::Events>> {
    let mut offset: u64 = 0;
    let mut _symbolsize: u64 = 0;

    let (modname, symbol): (Option<KVec<u8>>, Option<KVec<u8>>) =
        module::symbols_lookup_address(addr, &mut offset, &mut _symbolsize)?;

    if let Some(name) = modname {
        let mut buf = [0 as u8; event::MODULE_NAME_SIZE];
        for (i, e) in name.iter().enumerate() {
            let b = match buf.get_mut(i) {
                None => break,
                Some(b) => b,
            };
            *b = *e;
        }
        if !is_module(CStr::from_bytes_with_nul(name.as_slice())?) {
            pr_alert!("While checking address : {:#016x}\nSuspicious activity : module name [{}] not in module list\n",addr, CStr::from_bytes_with_nul(name.as_slice())?);
            if let Some(symbol) = symbol {
                pr_info!(
                    "Address's function : {}+{} [{}]\n",
                    CStr::from_bytes_with_nul(symbol.as_slice())?,
                    offset,
                    CStr::from_bytes_with_nul(name.as_slice())?
                );
            }

            let event = event::Events::ModuleInconsistency(ModuleInfo { name: buf });
            return Ok(Some(event));
        }
        let event = event::Events::ModuleAddress(ModuleInfo { name: buf });
        Ok(Some(event))
    } else {
        if !is_kernel(addr) {
            pr_alert!("Suspicious activity : address neither in module address space or kernel address space.\n");
            return Ok(Some(event::Events::HiddenModule));
        }
        Ok(None)
    }
}

/// Get the parent ip (the ip of the calling function)
/// Check this address with the `check_address_consistency` function
fn check_caller_consistency(pip: usize) -> Result<Option<event::Events>> {
    match check_address_consistency(pip as u64) {
        Ok(Some(event::Events::ModuleAddress(_))) => Ok(None),
        other => other,
    }
}

struct UsermodehelperProbe;

impl fprobe::FprobeOperations for UsermodehelperProbe {
    type Data = Arc<EventStack>;
    type EntryData = ();
    /// Check only the module consistency
    fn entry_handler(
        data: ArcBorrow<'_, EventStack>,
        _entry_ip: usize,
        ret_ip: usize,
        regs: &bindings::pt_regs,
        _entry_data: Option<&mut ()>,
    ) -> Option<()> {
        let pstr = regs.di as *const c_char;

        if pstr.is_null() {
            return Some(());
        }

        //SAFETY : The C code should give us a valid pointer to a null terminated string
        let prog = unsafe { CStr::from_char_ptr(pstr) };

        pr_info!("Executing the program : {}\n", prog);

        match check_caller_consistency(ret_ip) {
            Err(_) => {
                pr_err!("Error while checking module consistency\n");
                return Some(());
            }
            Ok(Some(event)) => match KEvents::new(event) {
                Err(_) => pr_err!("Error while pushing event\n"),
                Ok(kevent) => data.push_event(kevent),
            },
            _ => (),
        };
        Some(())
    }

    fn exit_handler(
        _data: ArcBorrow<'_, EventStack>,
        _entry_ip: usize,
        _ret_ip: usize,
        _regs: &bindings::pt_regs,
        _entry_data: Option<&mut ()>,
    ) {
    }
}

struct CommitCredsProbe;

impl fprobe::FprobeOperations for CommitCredsProbe {
    type Data = Arc<EventStack>;
    type EntryData = ();
    /// Check only the module consistency
    fn entry_handler(
        data: ArcBorrow<'_, EventStack>,
        _entry_ip: usize,
        ret_ip: usize,
        _regs: &bindings::pt_regs,
        _entry_data: Option<&mut ()>,
    ) -> Option<()> {
        match check_caller_consistency(ret_ip) {
            Err(_) => {
                pr_err!("Error while checking module consistency\n");
                return Some(());
            }
            Ok(Some(event)) => match KEvents::new(event) {
                Err(_) => pr_err!("Error while pushing event\n"),
                Ok(kevent) => data.push_event(kevent),
            },
            _ => (),
        };
        Some(())
    }
    fn exit_handler(
        _data: ArcBorrow<'_, EventStack>,
        _entry_ip: usize,
        _ret_ip: usize,
        _regs: &bindings::pt_regs,
        _entry_data: Option<&mut ()>,
    ) {
    }
}

struct KallsymsLookupNameProbe;

impl fprobe::FprobeOperations for KallsymsLookupNameProbe {
    type Data = Arc<EventStack>;
    type EntryData = ();
    /// Check the module consistency
    /// Check that the symbol looked up for is in the blacklist or not
    fn entry_handler(
        data: ArcBorrow<'_, EventStack>,
        _entry_ip: usize,
        ret_ip: usize,
        regs: &bindings::pt_regs,
        _entry_data: Option<&mut ()>,
    ) -> Option<()> {
        match check_caller_consistency(ret_ip) {
            Err(_) => {
                pr_err!("Error while checking module consistency\n");
                return Some(());
            }
            Ok(Some(event)) => match KEvents::new(event) {
                Err(_) => pr_err!("Error while pushing event\n"),
                Ok(kevent) => data.push_event(kevent),
            },
            _ => (),
        };

        let pstr = regs.di as *const c_char;

        let str = unsafe { CStr::from_char_ptr(pstr) };

        for fct in NAME_LOOKUP.iter() {
            if (*fct).as_bytes() == str.as_bytes() {
                pr_alert!(
                    "kallsyms_lookup_name : looking up for suspicious function : {}",
                    str
                );
                break;
            }
        }
        Some(())
    }
    fn exit_handler(
        _data: ArcBorrow<'_, EventStack>,
        _entry_ip: usize,
        _ret_ip: usize,
        _regs: &bindings::pt_regs,
        _entry_data: Option<&mut ()>,
    ) {
    }
}

struct MSRIntegrity {
    events: Arc<EventStack>,
}

impl MSRIntegrity {
    fn init(events: Arc<EventStack>) -> Result<Self> {
        Ok(MSRIntegrity { events })
    }

    /// Some bit in the CR should be set in kernel mode, check them
    #[cfg(target_arch = "x86_64")]
    fn check_pinned_cr_bits(&self) -> Result {
        use core::arch::asm;

        let cr_4: u64;

        // SAFETY: CR4 register always exist on x86_64
        unsafe {
            asm!("mov {cr_4}, cr4", cr_4 = out(reg) cr_4);
        }

        if (cr_4 & CR4_SMAP == 0) || (cr_4 & CR4_SMEP == 0) || (cr_4 & CR4_UMIP == 0) {
            self.events
                .push_event(KEvents::new(event::Events::TamperedMSR)?);
            //pr_alert!("Invariant bit in CR4 = {:#016x}\n", cr_4);
        }

        let cr_0: u64;

        // SAFETY: CR0 register always exist on x86_64
        unsafe {
            asm!("mov {cr_0}, cr0", cr_0 = out(reg) cr_0);
        }

        if cr_0 & CR0_WP == 0 {
            self.events
                .push_event(KEvents::new(event::Events::TamperedMSR)?);
            //pr_alert!("Invariant bit in CR0 = {:#016x}\n", cr_0);
        }

        Ok(())
    }

    /// Check if the MSR LSTAR register (used to setup the address to jump to in case of long mode syscall)
    /// is set to the right symbol (see the function `syscall_init` in arch/x86/kernel/cpu/common.c)
    #[cfg(target_arch = "x86_64")]
    fn check_msr_lstar(&self) -> Result {
        use core::arch::asm;

        let lstar: u64;
        let lstar_nb: u32 = bindings::MSR_LSTAR;

        // SAFETY: lstar register exist on x86_64 processor
        // `rdmsr` store the 64 bit value in edx:eax
        // The high order bit of rax, rdx are cleared by rdmsr so we can `OR`` the two
        unsafe {
            asm!("rdmsr",
                "shl rdx, 32",
                "or rax, rdx", 
                in("ecx") lstar_nb,
                out("rax") lstar,
                out("rdx") _);
        }

        // `entry_SYSCALL_64` is the function the LSTAR register is set
        let entry_syscall_64 = symbols_lookup_name(c_str!("entry_SYSCALL_64"));

        // Checking the integrity of the register
        if lstar != entry_syscall_64 {
            self.events
                .push_event(KEvents::new(event::Events::TamperedMSR)?);
            //pr_alert!("MSR LSTAR register (syscall jump address) not set to the right symbol\n");
        }

        Ok(())
    }
}

struct SyscallIntegrity {
    events: Arc<EventStack>,
}

impl SyscallIntegrity {
    fn init(events: Arc<EventStack>) -> Result<Self> {
        Ok(SyscallIntegrity { events })
    }

    /// For each entry in the syscall table check that the address isn't in a module
    /// Works only if the module that hijacked the syscalls is still in the `mod_tree` structure
    fn check_syscall_position(&self) -> Result {
        pr_info!("Checking for syscalls table integrity\n");
        let addr_sys_table = symbols_lookup_name(c_str!("sys_call_table"));

        static_assert!(
            ((NB_SYCALLS * mem::size_of::<bindings::sys_call_ptr_t>()) as u128)
                < (isize::MAX as u128)
        );

        // SAFETY:
        // 1- The object we manipulate is cthe sycall_table so it won't be deallocated
        // 2- addr is non null and aligned
        // 3- from addr to addr+NB_SYSCALL the memory is valid and readable because it is the syscall_table
        // 4- The slice is non mutable so it will not be mutated
        // 5- NB_SYSCALLS * mem::size_of::<sys_call_ptr_t>() < isize::MAX
        let sys_call_table =
            unsafe { slice::from_raw_parts(addr_sys_table as *const u64, NB_SYCALLS) };

        for syscall in sys_call_table {
            if let Some(event) = check_address_consistency(*syscall)? {
                self.events
                    .push_event(KEvents::new(event::Events::IndirectCallHijack(
                        IndirectCallHijackInfo {
                            ptr_type: event::FunctionPointerType::Syscall,
                        },
                    ))?);
                self.events.push_event(KEvents::new(event)?);
            }
        }
        Ok(())
    }
}

struct FunctionIntegrity {
    events: Arc<EventStack>,
    saved_function: KVec<(CString, u64)>,
}

impl FunctionIntegrity {
    fn init(events: Arc<EventStack>) -> Result<Self> {
        let mut fct_integ = FunctionIntegrity {
            saved_function: KVec::new(),
            events,
        };

        fct_integ.save_function(c_str!("ip_rcv"))?;
        fct_integ.save_function(c_str!("tcp4_seq_show"))?;
        fct_integ.save_function(c_str!("__x64_sys_getdents"))?;
        fct_integ.save_function(c_str!("__x64_sys_getdents64"))?;
        fct_integ.save_function(c_str!("__x64_sys_kill"))?;

        Ok(fct_integ)
    }

    /// Return the hash calculated off the text's byte of the function
    /// Calculate the hash from at max the MAX_SAVED_SIZE first bytes
    fn get_function_hash(&self, name: &CStr) -> Result<u64> {
        let addr = module::symbols_lookup_name(name);

        if addr == 0 as u64 {
            pr_info!("Invalid address lookup\n");
            return Err(EINVAL);
        }

        let (mut symbolsize, offset) = module::symbols_lookup_size_offset(addr);

        if offset != 0 {
            pr_info!("Invalid offset, (weird) : {}\n", offset);
            return Err(EINVAL);
        }

        static_assert!(((MAX_SAVED_SIZE * mem::size_of::<u8>()) as u128) < (isize::MAX as u128));

        if symbolsize > MAX_SAVED_SIZE {
            symbolsize = MAX_SAVED_SIZE;
        }

        // SAFETY:
        // 1- The object we manipulate is code so it should not be deallocated, except if the module we look at is unloaded (TODO : find a way to ensure that the module is not unloaded)
        // 2- addr is non null and aligned (because we ask for 1 byte data)
        // 3- from addr to addr+symbolsize the memory is valid and readable (in the kernel or a module)
        // 4- The slice is non mutable so it will not be mutated
        // 5- symbolsize <= MAX_SAVED_SIZE < mem::size_of::<u8>() * isize::MAX
        let tab: &[u8] = unsafe { slice::from_raw_parts(addr as *const u8, symbolsize as usize) };

        let mut hasher = fx_hash::FxHasher::default();

        tab.hash(&mut hasher);

        Ok(hasher.finish())
    }

    /// Save the function's text bytes in the struct's `saved_function` field
    fn save_function(&mut self, name: &CStr) -> Result {
        let hash = self.get_function_hash(name)?;

        self.saved_function
            .push((name.to_cstring()?, hash), GFP_KERNEL)?;

        Ok(())
    }

    /// Iter through all the saved functions
    /// Get the current text bytes and compare it to the saved text byte
    fn check_functions(&self) -> Result<()> {
        pr_info!("Checking for function integrity\n");
        for (name, hash) in &self.saved_function {
            let new_hash = self.get_function_hash(&name)?;
            if new_hash != *hash {
                let mut buf = [0 as u8; event::SIZE_STRING];
                for (i, e) in name.as_bytes().iter().enumerate() {
                    let b = match buf.get_mut(i) {
                        None => break,
                        Some(b) => b,
                    };
                    *b = *e;
                }
                let event = event::Events::TamperedFunction(FunctionInfo { name: buf });
                self.events.push_event(KEvents::new(event)?);
            }
        }
        Ok(())
    }
}

struct CFIntegrity {
    events: Arc<EventStack>,
    checked_function: KVec<&'static CStr>,
}

impl CFIntegrity {
    /// Create a new instance of the structure
    fn init(events: Arc<EventStack>) -> Result<Self> {
        let mut checked_function = KVec::new();
        checked_function.push(c_str!("ip_rcv"), GFP_KERNEL)?;
        checked_function.push(c_str!("tcp4_seq_show"), GFP_KERNEL)?;
        Ok(CFIntegrity {
            checked_function,
            events,
        })
    }

    /// Check the first instruction of the function "name" to see if it isn't hooked.
    /// The check consist to see if this instruction isn't a breakpoint or a jump
    fn check_custom_hook(&self) -> Result {
        pr_info!("Checking for custom hook\n");
        for fct_name in &self.checked_function {
            let addr = module::symbols_lookup_name(fct_name);

            // SAFETY:
            // 1- The object we manipulate is code so it should not be deallocated, except if the module we look at is unloaded (TODO : find a way to ensure that the module is not unloaded)
            // 2- addr is non null and aligned (because we ask for 1 byte data)
            // 3- We assume that from addr to addr+15 the memory is valid and readable (the disassembler should read only one instruction and nothing more so it isn't a problem)
            // 4- The slice is non mutable so it will not be mutated
            // 5- 15 < mem::size_of::<u8>() * isize::MAX
            let tab: &[u8] = unsafe { slice::from_raw_parts(addr as *const u8, 15 as usize) };

            let mut diss = insn::Insn::new(tab);

            let opcode = diss.get_opcode()?;

            if opcode == X86_OP_BP || opcode == X86_OP_JMP {
                /*pr_alert!(
                    "Function : {} probably hooked using opcode {:#02x}\n",
                    fct_name,
                    opcode
                );*/
                let mut buf = [0 as u8; event::SIZE_STRING];
                for (i, e) in fct_name.as_bytes().iter().enumerate() {
                    let b = match buf.get_mut(i) {
                        None => break,
                        Some(b) => b,
                    };
                    *b = *e;
                }

                let event = event::Events::HookedFunction(FunctionInfo { name: buf });
                self.events.push_event(KEvents::new(event)?);
            }
        }
        Ok(())
    }
}

struct IntegrityCheck {
    function_integ: FunctionIntegrity,
    syscall_integ: SyscallIntegrity,
    msr_integ: MSRIntegrity,
    cf_integ: CFIntegrity,
}

impl IntegrityCheck {
    fn init(events: Arc<EventStack>) -> Result<Self> {
        Ok(IntegrityCheck {
            function_integ: FunctionIntegrity::init(events.clone())?,
            syscall_integ: SyscallIntegrity::init(events.clone())?,
            msr_integ: MSRIntegrity::init(events.clone())?,
            cf_integ: CFIntegrity::init(events.clone())?,
        })
    }
}

struct LoadModuleProbe;

impl FprobeOperations for LoadModuleProbe {
    type Data = Arc<EventStack>;
    type EntryData = ();
    fn entry_handler(
        data: ArcBorrow<'_, EventStack>,
        _entry_ip: usize,
        _ret_ip: usize,
        regs: &bindings::pt_regs,
        _entry_data: Option<&mut ()>,
    ) -> Option<()> {
        let module = regs.di as *const bindings::module;

        if module == core::ptr::null() {
            return Some(());
        }

        // SAFETY: module is non null so is valid
        let core_layout = unsafe { (*module).mem[bindings::mod_mem_type_MOD_TEXT as usize] };

        let size = core_layout.size as usize;
        let addr_core = core_layout.base as *const u8;

        // SAFETY:
        // 1- The object we manipulate is code so it should not be deallocated, except if the module we look at is unloaded (TODO : find a way to ensure that the module is not unloaded)
        // 2- addr is non null and aligned (because we ask for 1 byte data)
        // 3- from addr_core to addr_core+size the memory is valid and readable
        // 4- The slice is non mutable so it will not be mutated
        // 5- size <= MAX_SAVED_SIZE < mem::size_of::<u8>() * isize::MAX
        let tab: &[u8] = unsafe { slice::from_raw_parts(addr_core, size as usize) };

        // SAFETY: module is non null so is valid
        let pname = unsafe { *(&(*module).name as *const [i8; 56] as *const [u8; 56]) };

        let mut hasher = fx_hash::FxHasher::default();

        tab.hash(&mut hasher);

        let name = pname.clone();

        let event = event::Events::LoadedLKM(LoadedLKMInfo {
            hash: hasher.finish(),
            name,
        });

        match KEvents::new(event) {
            Err(_) => pr_info!("Error trying to push a new event\n"),
            Ok(kevent) => data.push_event(kevent),
        };
        Some(())
    }
    fn exit_handler(
        _data: ArcBorrow<'_, EventStack>,
        _entry_ip: usize,
        _ret_ip: usize,
        _regs: &bindings::pt_regs,
        _entry_data: Option<&mut ()>,
    ) {
    }
}

struct KSysDup3Probe;

// This probe is for checking if someone try to map stdin/stdout to a socket
impl FprobeOperations for KSysDup3Probe {
    type Data = Arc<EventStack>;
    type EntryData = ();

    fn entry_handler(
        data: <Self::Data as ForeignOwnable>::Borrowed<'_>,
        _entry_ip: usize,
        _ret_ip: usize,
        regs: &bindings::pt_regs,
        _entry_data: Option<&mut ()>,
    ) -> Option<()> {
        let oldfd: i32 = regs.di as i32;
        let newfd: i32 = regs.si as i32;

        let res = match socket::is_fd_sock(oldfd) {
            Err(_) => {
                pr_info!("Error looking at fd\n");
                return Some(());
            }
            Ok(res) => res,
        };

        // The oldfd (so the one being mapped) is a socket
        if res {
            // If the socket is being mapped to stdin or stdout's fd
            if newfd == 1 || newfd == 0 {
                let event = event::Events::StdioToSocket(ProcessInfo {
                    // SAFETY: while this function execute this task exist
                    tgid: unsafe { Task::current() }.pid() as i32,
                });
                match KEvents::new(event) {
                    Err(_) => pr_info!("Error trying to push a new event\n"),
                    Ok(kevent) => data.push_event(kevent),
                };
            }
        }
        Some(())
    }
    fn exit_handler(
        _data: <Self::Data as ForeignOwnable>::Borrowed<'_>,
        _entry_ip: usize,
        _ret_ip: usize,
        _regs: &bindings::pt_regs,
        _entry_data: Option<&mut ()>,
    ) {
    }
}

struct CheckHelperCall;

// This probe is for checking the function an eBPF programm is loading
// We hook a bpf verifier's function that is called at each time a call bpf instruction is met
// and log each time `bpf_probe_write_user` or `bpf_override_return` is called
impl FprobeOperations for CheckHelperCall {
    type Data = Arc<EventStack>;
    type EntryData = ();
    fn entry_handler(
        data: <Self::Data as ForeignOwnable>::Borrowed<'_>,
        _entry_ip: usize,
        _ret_ip: usize,
        regs: &bindings::pt_regs,
        _entry_data: Option<&mut ()>,
    ) -> Option<()> {
        let insn: *mut bindings::bpf_insn = regs.si as *mut bindings::bpf_insn;
        if insn.is_null() {
            return None;
        }

        // We get the function id of the called function
        // SAFETY: The pointer is not null, we can dereference it
        let func_id = unsafe { (*insn).imm } as bindings::bpf_func_id;

        let func_type = match func_id {
            bindings::bpf_func_id_BPF_FUNC_override_return => event::EBPFFuncType::OverrideReturn,
            bindings::bpf_func_id_BPF_FUNC_probe_write_user => event::EBPFFuncType::WriteUser,
            _ => return None,
        };

        let event = event::Events::EBPFFunc(EBPFFuncInfo {
            tgid: current!().pid(),
            func_type,
        });
        match KEvents::new(event) {
            Ok(kevent) => data.push_event(kevent),
            Err(_) => pr_info!("Error trying to create a KEvent\n"),
        };

        Some(())
    }
    fn exit_handler(
        _data: <Self::Data as ForeignOwnable>::Borrowed<'_>,
        _entry_ip: usize,
        _ret_ip: usize,
        _regs: &bindings::pt_regs,
        _entry_data: Option<&mut ()>,
    ) {
    }
}

struct SysGetDents64;

impl SysGetDents64 {
    fn check_hidden_file(mut dirp: UserSliceReader) -> Result<Option<ListArc<KEvents>>> {
        while dirp.len() > 0 {
            // We skip the two first field
            let d_ino = dirp.read::<u64>()?;
            pr_info!("We have d_ino : {}\n", d_ino);
            dirp.skip(8)?;
            // The field indicating the len of this entry
            // This is the field tampered with by rootkits
            let d_reclen: u16 = dirp.read::<u16>()?;
            pr_info!("We have reclen : {}\n", d_reclen);
            // Skip another field
            dirp.skip(1)?;
            let mut name_size: u16 = 1;
            while dirp.read::<u8>()? != 0 {
                name_size += 1;
            }
            // We calculate the size that should have the structure
            // The 5 field don't have padding between them so it's just the addition of their size (which is 19)
            let mut normal_size = name_size + 19;
            // The structure is 8 aligned so we add the padding at the end if needed
            let padding_size = if normal_size % 8 == 0 {
                0
            } else {
                8 - (normal_size % 8)
            };
            dirp.skip(padding_size as usize)?;
            normal_size += padding_size;

            pr_info!("We have normal_size: {}\n", normal_size);

            // This mean the reclen has been tampered with
            if d_reclen != normal_size {
                let kevent = KEvents::new(event::Events::HiddenFile(event::HiddenFileInfo {
                    normal_size,
                    d_reclen,
                }))?;
                return Ok(Some(kevent));
            }
        }
        Ok(None)
    }
}

impl FprobeOperations for SysGetDents64 {
    type Data = Arc<EventStack>;
    type EntryData = usize;

    fn entry_handler(
        _data: <Self::Data as ForeignOwnable>::Borrowed<'_>,
        _entry_ip: usize,
        _ret_ip: usize,
        regs: &bindings::pt_regs,
        entry_data: Option<&mut usize>,
    ) -> Option<()> {
        if let Some(ptr) = entry_data {
            let user_regs: *const bindings::pt_regs = regs.di as *const bindings::pt_regs;

            if user_regs.is_null() {
                return None;
            }

            let user_regs = unsafe { user_regs.read_unaligned() };
            let dirp: usize = user_regs.si as usize;
            *ptr = dirp;
            Some(())
        } else {
            None
        }
    }
    fn exit_handler(
        data: <Self::Data as ForeignOwnable>::Borrowed<'_>,
        _entry_ip: usize,
        _ret_ip: usize,
        regs: &bindings::pt_regs,
        entry_data: Option<&mut usize>,
    ) {
        if let Some(dirp) = entry_data {
            // The return of the syscall is the number of bytes written to the user buffer
            let ret = regs.ax as usize;
            if ret <= 0 {
                return;
            }
            let dirp = UserSlice::new(*dirp, ret as usize).reader();
            match Self::check_hidden_file(dirp) {
                Err(_) => pr_info!("Error checking for hidden file\n"),
                Ok(Some(kevent)) => data.push_event(kevent),
                _ => (),
            }
        }
    }
}

struct Probes {
    _usermodehelper_probe: Pin<KBox<fprobe::Fprobe<UsermodehelperProbe>>>,
    _commit_creds_probe: Pin<KBox<fprobe::Fprobe<CommitCredsProbe>>>,
    _kallsyms_lookup_name_probe: Pin<KBox<fprobe::Fprobe<KallsymsLookupNameProbe>>>,
    _load_module_probe: Pin<KBox<fprobe::Fprobe<LoadModuleProbe>>>,
    _ksys_dup3_probe: Pin<KBox<fprobe::Fprobe<KSysDup3Probe>>>,
    _check_helper_call: Pin<KBox<fprobe::Fprobe<CheckHelperCall>>>,
    _sys_getdents64: Pin<KBox<fprobe::Fprobe<SysGetDents64>>>,
}

impl Probes {
    fn init(events: Arc<EventStack>) -> Result<Self> {
        pr_info!("Registering probes\n");

        let _usermodehelper_probe = KBox::pin_init(
            fprobe::Fprobe::new(c_str!("call_usermodehelper"), None, events.clone()),
            GFP_KERNEL,
        )?;
        let _commit_creds_probe = KBox::pin_init(
            fprobe::Fprobe::new(c_str!("commit_creds"), None, events.clone()),
            GFP_KERNEL,
        )?;
        let _kallsyms_lookup_name_probe = KBox::pin_init(
            fprobe::Fprobe::new(c_str!("kallsyms_lookup_name"), None, events.clone()),
            GFP_KERNEL,
        )?;
        let _load_module_probe = KBox::pin_init(
            fprobe::Fprobe::new(c_str!("do_init_module"), None, events.clone()),
            GFP_KERNEL,
        )?;
        let _ksys_dup3_probe = KBox::pin_init(
            fprobe::Fprobe::new(c_str!("ksys_dup3"), None, events.clone()),
            GFP_KERNEL,
        )?;

        let _check_helper_call = KBox::pin_init(
            fprobe::Fprobe::new(c_str!("check_helper_call"), None, events.clone()),
            GFP_KERNEL,
        )?;

        let _sys_getdents64 = KBox::pin_init(
            fprobe::Fprobe::new(c_str!("__x64_sys_getdents64"), None, events.clone()),
            GFP_KERNEL,
        )?;

        let probes = Probes {
            _usermodehelper_probe,
            _commit_creds_probe,
            _kallsyms_lookup_name_probe,
            _load_module_probe,
            _ksys_dup3_probe,
            _check_helper_call,
            _sys_getdents64,
        };

        Ok(probes)
    }
}

impl Drop for Probes {
    fn drop(&mut self) {
        pr_info!("Rootkit detection (exit)\n");
    }
}

struct Communication {
    integrity_check: Arc<IntegrityCheck>,
    events: Arc<EventStack>,
}

#[vtable]
impl MiscDevice for Communication {
    type Ptr = Arc<Self>;

    fn open() -> Result<Self::Ptr> {
        unsafe {
            match &*addr_of!(COMMUNICATION) {
                None => Err(ENOMEM),
                Some(communication) => Ok(communication.clone()),
            }
        }
    }

    fn ioctl(
        data: <Self::Ptr as ForeignOwnable>::Borrowed<'_>,
        cmd: u32,
        arg: usize,
    ) -> Result<isize> {
        let size = _IOC_SIZE(cmd);
        let user_slice = UserSlice::new(arg, size);
        match cmd {
            RKCHK_INTEG_ALL => {
                data.integrity_check.function_integ.check_functions()?;

                data.integrity_check
                    .syscall_integ
                    .check_syscall_position()?;

                data.integrity_check.msr_integ.check_pinned_cr_bits()?;
                data.integrity_check.msr_integ.check_msr_lstar()?;

                data.integrity_check.cf_integ.check_custom_hook()?;

                Ok(0)
            }
            RKCHK_READ_EVENT => {
                let mut writer = user_slice.writer();
                let event = data.events.wait_events()?;

                // Once a new event arrived we send it if the buffer is long enough
                if writer.len() < core::mem::size_of::<event::Events>() {
                    return Err(ENOMEM);
                }

                writer.write::<event::Events>(event.get_ref_event())?;
                /*let buf = unsafe {
                    core::mem::transmute::<Events, [u8; core::mem::size_of::<Events>()]>(event)
                };

                for e in &buf {
                    writer.write(e)?;
                }*/

                Ok(core::mem::size_of::<event::Events>() as _)
            }
            _ => Err(ENOTTY),
        }
    }
}
/*
impl file::IoctlHandler for Communication {
    type Target<'a> = ArcBorrow<'a, Communication>;
    fn pure(this: Self::Target<'_>, _file: &file::File, _cmd: u32, _arg: usize) -> Result<i32> {
        match (bindings::_IOC_NRMASK & _cmd) >> bindings::_IOC_NRSHIFT {
            RKCHK_INTEG_ALL => {
                this.integrity_check.function_integ.check_functions()?;

                this.integrity_check
                    .syscall_integ
                    .check_syscall_position()?;

                this.integrity_check.msr_integ.check_pinned_cr_bits()?;
                this.integrity_check.msr_integ.check_msr_lstar()?;

                this.integrity_check.cf_integ.check_custom_hook()?;

                Ok(0)
            }
            _ => Err(ENOTTY),
        }
    }
    fn read(
        _this: Self::Target<'_>,
        _file: &file::File,
        _cmd: u32,
        _writer: &mut kernel::user_ptr::UserSlicePtrWriter,
    ) -> Result<i32> {
        Err(ENOTTY)
    }
    fn read_write(
        _this: Self::Target<'_>,
        _file: &file::File,
        _cmd: u32,
        _data: kernel::user_ptr::UserSlicePtr,
    ) -> Result<i32> {
        Err(ENOTTY)
    }
    fn write(
        _this: Self::Target<'_>,
        _file: &file::File,
        _cmd: u32,
        _reader: &mut kernel::user_ptr::UserSlicePtrReader,
    ) -> Result<i32> {
        Err(ENOTTY)
    }
}
*/

struct RootkitDetection {
    _registration: Pin<KBox<MiscDeviceRegistration<Communication>>>,
    _probe: Arc<Probes>,
    _integrity_check: Arc<IntegrityCheck>,
    _communication: Arc<Communication>,
}

impl kernel::Module for RootkitDetection {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("Rootkit detection written in Rust\n");

        pr_info!("Registering the device\n");

        unsafe { EVENT_STACK = Some(EventStack::init()?) };

        let event_stack = unsafe {
            match &*addr_of!(EVENT_STACK) {
                None => return Err(ENOMEM),
                Some(event) => event.clone(),
            }
        };
        // Setting up the probes
        let _probe = Arc::new(Probes::init(event_stack.clone())?, GFP_KERNEL)?;

        let _integrity_check = Arc::new(IntegrityCheck::init(event_stack.clone())?, GFP_KERNEL)?;

        // Checks relative to the integrity (of text section, functions pointer, control registers...)
        // Initialize the integrity structure, saving th state of multiple elements
        unsafe {
            COMMUNICATION = Some(Arc::new(
                Communication {
                    integrity_check: _integrity_check.clone(),
                    events: event_stack.clone(),
                },
                GFP_KERNEL,
            )?)
        };

        let communication = unsafe {
            match &*addr_of!(COMMUNICATION) {
                None => return Err(ENOMEM),
                Some(communication) => communication.clone(),
            }
        };

        // Create a simple character device (only one device file) to communicate with userspace
        // For now only used to trigger the integrity check
        let _registration = KBox::pin_init(
            miscdevice::MiscDeviceRegistration::register(miscdevice::MiscDeviceOptions {
                name: c_str!("rkchk"),
            }),
            GFP_KERNEL,
        )?;

        Ok(RootkitDetection {
            _registration,
            _probe,
            _integrity_check,
            _communication: communication,
        })
    }
}
