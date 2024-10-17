// SPDX-License-Identifier: GPL-2.0

//! Rust character device sample.
use core::clone::Clone;
use core::hash::Hash;

use core::default::Default;
use core::ffi::c_char;
use core::hash::Hasher;
use core::iter::Iterator;
use core::result::Result::Err;
use core::result::Result::Ok;
use core::slice;
use core::str;

use event::Events;
use event::IndirectCallHijackInfo;
use event::LoadedLKMInfo;
use event::ModuleInfo;
use kernel::fprobe::FprobeOperations;
use kernel::module::is_kernel;
use kernel::module::symbols_lookup_name;
use kernel::sync::Arc;
use kernel::sync::ArcBorrow;
use kernel::sync::CondVar;

use core::mem;
use kernel::bindings;
use kernel::c_str;
use kernel::error::Result;
use kernel::file;
use kernel::miscdev::Registration;
use kernel::module::is_module;
use kernel::str::CStr;

use alloc::boxed::Box;
use kernel::sync::SpinLock;

use kernel::fprobe;
use kernel::insn;
use kernel::module;
use kernel::prelude::*;

pub mod event;
pub mod fx_hash;

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

/// IOCTL number
/// Run all the integrity checks
const RKCHK_INTEG_ALL: u32 = 1;

module! {
    type: RootkitDetection,
    name: "rootkit_detection",
    author: "Rust for Linux Contributors",
    description: "Rust rootkit detection module",
    license: "GPL",
}

struct EventStack {
    wait_queue: Pin<Box<CondVar>>,
    event_stack: Pin<Box<SpinLock<Vec<Events>>>>,
}

impl EventStack {
    fn init() -> Result<Arc<Self>> {
        // SAFETY : CondVar::init() is called below
        let mut wait_queue = Box::into_pin(Box::try_new(unsafe { CondVar::new() })?);
        kernel::condvar_init!(wait_queue.as_mut(), "data queue");

        // Create a Spiinlock for the event_stack field because we can be called from everywhere
        // so we shouldn't block like a mutex/semaphore do.
        // SAFETY : `spinlock_init` is called below
        let event_stack = unsafe { SpinLock::new(Vec::new()) };

        let mut event_stack = Box::into_pin(Box::try_new(event_stack)?);
        kernel::spinlock_init!(event_stack.as_mut(), "event stack");

        Arc::try_new(EventStack {
            wait_queue,
            event_stack,
        })
    }

    fn push_event(&self, event: event::Events) -> Result<()> {
        self.event_stack.lock().try_push(event)?;

        self.wait_queue.notify_all();

        Ok(())
    }

    fn wait_events(&self) -> Result<event::Events> {
        let mut lock = self.event_stack.lock();
        while lock.is_empty() {
            if self.wait_queue.wait(&mut lock) {
                return Err(EINTR);
            }
        }
        // If we could make a while let with an else let statment this situation won't exist,
        // We cannot get the None option of this match but anyway
        match lock.pop() {
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

    let (modname, symbol): (Option<Vec<u8>>, Option<Vec<u8>>) =
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
fn check_caller_consistency(regs: &bindings::pt_regs) -> Result<Option<event::Events>> {
    let sp = regs.sp as *const u64;

    // Parent ip
    // SAFETY : The sp should point to a valid point in memory
    let pip = unsafe { *sp };

    match check_address_consistency(pip) {
        Ok(Some(event::Events::ModuleAddress(_))) => Ok(None),
        other => other,
    }
}

struct UsermodehelperProbe;

impl fprobe::FprobeOperations for UsermodehelperProbe {
    type Data = Arc<EventStack>;
    /// Check only the module consistency
    fn entry_handler(data: ArcBorrow<'_, EventStack>, _entry_ip: usize, regs: &bindings::pt_regs) {
        let pstr = regs.di as *const c_char;

        if pstr.is_null() {
            return;
        }

        //SAFETY : The C code should give us a valid pointer to a null terminated string
        let prog = unsafe { CStr::from_char_ptr(pstr) };

        pr_info!("Executing the program : {}\n", prog);

        match check_caller_consistency(regs) {
            Err(_) => {
                pr_err!("Error while checking module consistency\n");
                return;
            }
            Ok(Some(event)) => match data.push_event(event) {
                Err(_) => pr_err!("Error while pushing event\n"),
                _ => (),
            },
            _ => (),
        };
    }

    fn exit_handler(_data: ArcBorrow<'_, EventStack>, _entry_ip: usize, _regs: &bindings::pt_regs) {
    }
}

struct CommitCredsProbe;

impl fprobe::FprobeOperations for CommitCredsProbe {
    type Data = Arc<EventStack>;
    /// Check only the module consistency
    fn entry_handler(data: ArcBorrow<'_, EventStack>, _entry_ip: usize, regs: &bindings::pt_regs) {
        match check_caller_consistency(regs) {
            Err(_) => {
                pr_err!("Error while checking module consistency\n");
                return;
            }
            Ok(Some(event)) => match data.push_event(event) {
                Err(_) => pr_err!("Error while pushing event\n"),
                _ => (),
            },
            _ => (),
        };
    }
    fn exit_handler(_data: ArcBorrow<'_, EventStack>, _entry_ip: usize, _regs: &bindings::pt_regs) {
    }
}

struct KallsymsLookupNameProbe;

impl fprobe::FprobeOperations for KallsymsLookupNameProbe {
    type Data = Arc<EventStack>;
    /// Check the module consistency
    /// Check that the symbol looked up for is in the blacklist or not
    fn entry_handler(data: ArcBorrow<'_, EventStack>, _entry_ip: usize, regs: &bindings::pt_regs) {
        match check_caller_consistency(regs) {
            Err(_) => {
                pr_err!("Error while checking module consistency\n");
                return;
            }
            Ok(Some(event)) => match data.push_event(event) {
                Err(_) => pr_err!("Error while pushing event\n"),
                _ => (),
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
    }
    fn exit_handler(_data: ArcBorrow<'_, EventStack>, _entry_ip: usize, _regs: &bindings::pt_regs) {
    }
}

struct MSRIntegrity;

impl MSRIntegrity {
    fn init() -> Result<Self> {
        Ok(MSRIntegrity)
    }

    /// Some bit in the CR should be set in kernel mode, check them
    #[cfg(target_arch = "x86_64")]
    fn check_pinned_cr_bits(&self) -> Result {
        use core::arch::asm;

        let cr_4: u64;

        // SAFETY : CR4 register always exist on x86_64
        unsafe {
            asm!("mov {cr_4}, cr4", cr_4 = out(reg) cr_4);
        }

        if (cr_4 & CR4_SMAP == 0) || (cr_4 & CR4_SMEP == 0) || (cr_4 & CR4_UMIP == 0) {
            pr_alert!("Invariant bit in CR4 = {:#016x}\n", cr_4);
        }

        let cr_0: u64;

        // SAFETY: CR0 register always exist on x86_64
        unsafe {
            asm!("mov {cr_0}, cr0", cr_0 = out(reg) cr_0);
        }

        if cr_0 & CR0_WP == 0 {
            pr_alert!("Invariant bit in CR0 = {:#016x}\n", cr_0);
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

        // SAFETY : lstar register exist on x86_64 processor
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
            pr_alert!("MSR LSTAR register (syscall jump address) not set to the right symbol\n");
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

        // SAFETY :
        // 1- The object we manipulate is cthe sycall_table so it won't be deallocated
        // 2- addr is non null and aligned
        // 3- from addr to addr+NB_SYSCALL the memory is valid and readable because it is the syscall_table
        // 4- The slice is non mutable so it will not be mutated
        // 5- NB_SYSCALLS * mem::size_of::<sys_call_ptr_t>() < isize::MAX
        let sys_call_table =
            unsafe { slice::from_raw_parts(addr_sys_table as *const u64, NB_SYCALLS) };

        for syscall in sys_call_table {
            if let Some(event) = check_address_consistency(*syscall)? {
                self.events.push_event(event::Events::IndirectCallHijack(
                    IndirectCallHijackInfo {
                        ptr_type: event::FunctionPointerType::Syscall,
                    },
                ))?;
                self.events.push_event(event)?;
            }
        }
        Ok(())
    }
}

struct FunctionIntegrity {
    saved_function: Vec<(String, u64)>,
}

impl FunctionIntegrity {
    fn init() -> Result<Self> {
        let mut fct_integ = FunctionIntegrity {
            saved_function: Vec::new(),
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
            return Err(EINVAL);
        }

        let (mut symbolsize, offset) = module::symbols_lookup_size_offset(addr);

        if offset != 0 {
            return Err(EINVAL);
        }

        static_assert!(((MAX_SAVED_SIZE * mem::size_of::<u8>()) as u128) < (isize::MAX as u128));

        if symbolsize > MAX_SAVED_SIZE {
            symbolsize = MAX_SAVED_SIZE;
        }

        // SAFETY :
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

        // Converting &Cstr to String (kind of a pain)
        let mut name_buf: Vec<u8> = Vec::try_with_capacity(name.len())?;
        name_buf.try_extend_from_slice(name.as_bytes_with_nul())?;
        let name = match String::from_utf8(name_buf) {
            Ok(name) => name,
            Err(_) => return Err(EINVAL),
        };

        self.saved_function.try_push((name, hash))?;

        Ok(())
    }

    /// Iter through all the saved functions
    /// Get the current text bytes and compare it to the saved text byte
    fn check_functions(&self) -> Result<Option<&String>> {
        pr_info!("Checking for function integrity\n");
        for (name, hash) in &self.saved_function {
            let new_hash = self.get_function_hash(CStr::from_bytes_with_nul(name.as_bytes())?)?;
            if new_hash != *hash {
                return Ok(Some(name));
            }
        }
        Ok(None)
    }
}

struct CFIntegrity {
    checked_function: Vec<&'static CStr>,
}

impl CFIntegrity {
    /// Create a new instance of the structure
    fn init() -> Result<Self> {
        let mut checked_function = Vec::new();
        checked_function.try_push(c_str!("ip_rcv"))?;
        checked_function.try_push(c_str!("tcp4_seq_show"))?;
        Ok(CFIntegrity { checked_function })
    }

    /// Check the first instruction of the function "name" to see if it isn't hooked.
    /// The check consist to see if this instruction isn't a breakpoint or a jump
    fn check_custom_hook(&self) -> Result {
        pr_info!("Checking for custom hook\n");
        for fct_name in &self.checked_function {
            let addr = module::symbols_lookup_name(fct_name);

            // SAFETY :
            // 1- The object we manipulate is code so it should not be deallocated, except if the module we look at is unloaded (TODO : find a way to ensure that the module is not unloaded)
            // 2- addr is non null and aligned (because we ask for 1 byte data)
            // 3- We assume that from addr to addr+15 the memory is valid and readable (the disassembler should read only one instruction and nothing more so it isn't a problem)
            // 4- The slice is non mutable so it will not be mutated
            // 5- 15 < mem::size_of::<u8>() * isize::MAX
            let tab: &[u8] = unsafe { slice::from_raw_parts(addr as *const u8, 15 as usize) };

            let mut diss = insn::Insn::new(tab);

            let opcode = diss.get_opcode()?;

            if opcode == X86_OP_BP || opcode == X86_OP_JMP {
                pr_alert!(
                    "Function : {} probably hooked using opcode {:#02x}\n",
                    fct_name,
                    opcode
                );
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
            function_integ: FunctionIntegrity::init()?,
            syscall_integ: SyscallIntegrity::init(events.clone())?,
            msr_integ: MSRIntegrity::init()?,
            cf_integ: CFIntegrity::init()?,
        })
    }
}

struct LoadModuleProbe;

impl FprobeOperations for LoadModuleProbe {
    type Data = Arc<EventStack>;

    fn entry_handler(data: ArcBorrow<'_, EventStack>, _entry_ip: usize, regs: &bindings::pt_regs) {
        let module = regs.di as *const bindings::module;

        if module == core::ptr::null() {
            return;
        }

        // SAFETY : module is non null so is valid
        let core_layout = unsafe { (*module).core_layout };

        let size = core_layout.size as usize;
        let addr_core = core_layout.base as *const u8;

        // SAFETY :
        // 1- The object we manipulate is code so it should not be deallocated, except if the module we look at is unloaded (TODO : find a way to ensure that the module is not unloaded)
        // 2- addr is non null and aligned (because we ask for 1 byte data)
        // 3- from addr_core to addr_core+size the memory is valid and readable
        // 4- The slice is non mutable so it will not be mutated
        // 5- size <= MAX_SAVED_SIZE < mem::size_of::<u8>() * isize::MAX
        let tab: &[u8] = unsafe { slice::from_raw_parts(addr_core, size as usize) };

        // SAFETY : module is non null so is valid
        let pname = unsafe { *(&(*module).name as *const [i8; 56] as *const [u8; 56]) };

        let mut hasher = fx_hash::FxHasher::default();

        tab.hash(&mut hasher);

        let name = pname.clone();

        let event = event::Events::LoadedLKM(LoadedLKMInfo {
            hash: hasher.finish(),
            name,
        });

        match data.push_event(event) {
            Err(_) => pr_info!("Error trying to push a new event\n"),
            _ => (),
        };
    }
    fn exit_handler(_data: ArcBorrow<'_, EventStack>, _entry_ip: usize, _regs: &bindings::pt_regs) {
    }
}

struct Probes {
    _usermodehelper_probe: Pin<Box<fprobe::Fprobe<UsermodehelperProbe>>>,
    _commit_creds_probe: Pin<Box<fprobe::Fprobe<CommitCredsProbe>>>,
    _kallsyms_lookup_name_probe: Pin<Box<fprobe::Fprobe<KallsymsLookupNameProbe>>>,
    _load_module_probe: Pin<Box<fprobe::Fprobe<LoadModuleProbe>>>,
}

impl Probes {
    fn init(events: Arc<EventStack>) -> Result<Self> {
        pr_info!("Registering probes\n");

        let _usermodehelper_probe =
            fprobe::Fprobe::new_pinned("call_usermodehelper", None, events.clone())?;
        let _commit_creds_probe = fprobe::Fprobe::new_pinned("commit_creds", None, events.clone())?;
        let _kallsyms_lookup_name_probe =
            fprobe::Fprobe::new_pinned("kallsyms_lookup_name", None, events.clone())?;
        let _load_module_probe =
            fprobe::Fprobe::new_pinned("do_init_module", None, events.clone())?;

        let probes = Probes {
            _usermodehelper_probe,
            _commit_creds_probe,
            _kallsyms_lookup_name_probe,
            _load_module_probe,
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
impl file::Operations for Communication {
    type OpenData = Arc<Self>;
    type Data = Arc<Self>;
    fn open(context: &Self::OpenData, _file: &file::File) -> Result<Self::Data> {
        Ok(context.clone())
    }

    fn read(
        _data: <Self::Data as kernel::ForeignOwnable>::Borrowed<'_>,
        _file: &file::File,
        _writer: &mut impl kernel::io_buffer::IoBufferWriter,
        _offset: u64,
    ) -> Result<usize> {
        let event = _data.events.wait_events()?;

        // Once a new event arrived we send it if the buffer is long enough
        if _writer.len() < core::mem::size_of::<[u8; core::mem::size_of::<Events>()]>() {
            return Err(ENOMEM);
        }

        let buf =
            unsafe { core::mem::transmute::<Events, [u8; core::mem::size_of::<Events>()]>(event) };

        for e in &buf {
            _writer.write(e)?;
        }

        Ok(core::mem::size_of::<[u8; core::mem::size_of::<Events>()]>())
    }

    fn ioctl(
        data: <Self::Data as kernel::ForeignOwnable>::Borrowed<'_>,
        file: &file::File,
        cmd: &mut file::IoctlCommand,
    ) -> Result<i32> {
        cmd.dispatch::<Communication>(data, file)
    }
}

impl file::IoctlHandler for Communication {
    type Target<'a> = ArcBorrow<'a, Communication>;
    fn pure(this: Self::Target<'_>, _file: &file::File, _cmd: u32, _arg: usize) -> Result<i32> {
        match (bindings::_IOC_NRMASK & _cmd) >> bindings::_IOC_NRSHIFT {
            RKCHK_INTEG_ALL => {
                if let Some(fct) = this.integrity_check.function_integ.check_functions()? {
                    pr_alert!("Function {} is hooked\n", fct);
                }

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

struct RootkitDetection {
    _registration: Pin<Box<Registration<Communication>>>,
    _probe: Probes,
    _integrity_check: Arc<IntegrityCheck>,
    _communication: Arc<Communication>,
}

impl kernel::Module for RootkitDetection {
    fn init(name: &'static CStr, _module: &'static ThisModule) -> Result<Self> {
        pr_info!("Rootkit detection written in Rust\n");

        pr_info!("Registering the device\n");

        let event_stack = EventStack::init()?;

        // Setting up the probes
        let _probe = Probes::init(event_stack.clone())?;

        let _integrity_check = Arc::try_new(IntegrityCheck::init(event_stack.clone())?)?;

        // Checks relative to the integrity (of text section, functions pointer, control registers...)
        // Initialize the integrity structure, saving th state of multiple elements
        let communication = Arc::try_new(Communication {
            integrity_check: _integrity_check.clone(),
            events: event_stack,
        })?;

        // Create a simple character device (only one device file) to communicate with userspace
        // For now only used to trigger the integrity check
        let _registration = kernel::miscdev::Registration::<Communication>::new_pinned(
            fmt!("{name}"),
            communication.clone(),
        )?;

        Ok(RootkitDetection {
            _registration,
            _probe,
            _integrity_check,
            _communication: communication,
        })
    }
}
