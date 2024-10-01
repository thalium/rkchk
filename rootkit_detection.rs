// SPDX-License-Identifier: GPL-2.0

//! Rust character device sample.

pub mod fx_hash;

use core::hash::Hash;

use core::default::Default;
use core::ffi::c_char;
use core::hash::Hasher;
use core::result::Result::Ok;
use core::slice;
use core::str;

use kernel::module::symbols_lookup_address;
use kernel::module::symbols_lookup_name;
use kernel::sync::Arc;

use core::mem;
use kernel::c_str;
use kernel::miscdev::Registration;
use kernel::error::Result;
use kernel::bindings;
use kernel::file;
use kernel::module::is_module;
use kernel::str::CStr;

use kernel::prelude::*;
use kernel::fprobe;
use kernel::module;
use kernel::insn;

/// The maximum number of byte we saved for a given function
const MAX_SAVED_SIZE : usize = 4096;
/// The number of syscall on my computer
const NB_SYCALLS : usize = 332;

/// `kallsyms_lookup_name` symbol black list
const NAME_LOOKUP: [&str; 12] = ["module_tree_insert", "module_tree_remove", "module_mutex", "sys_call_table", "__x64_sys_init_module", "sys_kill", "vfs_read", "__x64_sys_kill",  "__x64_sys_getdents", "__x64_sys_getdents64", "tcp6_seq_show", "tcp4_seq_show"];

/// Write Protect : the CPU cannot write ro page in ring 0
const CR0_WP : u64 = 1 << 16;
/// User-Mode Instruction Prevention : block the usage of some instructions in user mode
const CR4_UMIP : u64 = 1 << 16;
/// Supervisor Mode Access Execution Protection Enable
const CR4_SMEP : u64 = 1 << 20;
/// Supervisor Mode Access Prevention Enable
const CR4_SMAP : u64 = 1 << 21;

/// Some x86 opcode

/// Jump
const X86_OP_JMP : i32 = 0xE9;
/// Breakpoint
const X86_OP_BP : i32 = 0xCC;

module! {
    type: RootkitDetection,
    name: "rootkit_detection",
    author: "Rust for Linux Contributors",
    description: "Rust rootkit detection module",
    license: "GPL",
}



struct SysInitModuleProbe;
impl fprobe::FprobeOperations for SysInitModuleProbe {
    fn entry_handler(_fprobe : &fprobe::Fprobe<Self>, _entry_ip: usize, _regs: &bindings::pt_regs) {
        pr_info!("We entered `__x64_sys_init_module`\n");
    }   
    fn exit_handler(_fprobe : &fprobe::Fprobe<Self>, _entry_ip: usize, _regs: &bindings::pt_regs) {
        pr_info!("We exited `__x64_sys_init_module`\n");
    } 
}

/// Get the parent ip (the ip of the calling function)
/// Get the name of the module this address is in (if not it mean it's probably in kernel text and abort)
/// Check that this module is in the linked list of module
/// If not, it mean that the module removed itself from it which is suspicious 
fn check_module_consistency(regs : &bindings::pt_regs) -> Result<Option<()>> {
    let sp = regs.sp as *const u64;

    // Parent ip
    // SAFETY : The sp should point to a valid point in memory 
    let pip  = unsafe {
        *sp
    };

    let mut offset : u64 = 0;
    let mut _symbolsize : u64 = 0;

    let (modname, symbol) = module::symbols_lookup_address(pip, &mut offset, &mut _symbolsize)?;

    if let Some(name) = modname {
        
        if !is_module(CStr::from_bytes_with_nul(name.as_slice())?) {
            pr_alert!("Suspicious activity : module name [{}] not in module list\n", CStr::from_bytes_with_nul(name.as_slice())?);
            if let Some(symbol) = symbol {
                pr_info!("Calling function : {}+{} [{}]\n", CStr::from_bytes_with_nul(symbol.as_slice())?, offset, CStr::from_bytes_with_nul(name.as_slice())?);
            }
            return Ok(Some(()));
        }
    }

    Ok(None)
}

struct UsermodehelperProbe;

impl fprobe::FprobeOperations for UsermodehelperProbe {
    /// Check only the module consistency
    fn entry_handler(_fprobe : &fprobe::Fprobe<Self>, _entry_ip: usize, regs: &bindings::pt_regs) {
        let pstr = regs.di as *const c_char;
        
        if pstr == 0 as *const i8 {
            return;
        }

        //SAFETY : The C code should give us a valid pointer to a null terminated string
        let prog = unsafe { CStr::from_char_ptr(pstr) };

        pr_info!("Executing the program : {}\n", prog);

        match check_module_consistency(regs) {
            Err(_) => {
                pr_err!("Error while checking module consistency\n");
                return;
            }
            Ok(Some(())) => pr_alert!("Called function : usermode_helper\n"),
            _ => (),
        };

    }

    fn exit_handler(_fprobe : &fprobe::Fprobe<Self>, _entry_ip: usize, _regs: &bindings::pt_regs) {
    }
}

struct CommitCredsProbe;

impl fprobe::FprobeOperations for CommitCredsProbe {
    /// Check only the module consistency
    fn entry_handler(_fprobe : &fprobe::Fprobe<Self>, _entry_ip: usize, regs: &bindings::pt_regs) {
        match check_module_consistency(regs) {
            Err(_) => {
                pr_err!("Error while checking module consistency\n");
                return;
            }
            Ok(Some(())) => pr_alert!("Called function : commit_creds\n"),
            _ => (),
        };
    }
    fn exit_handler(_fprobe : &fprobe::Fprobe<Self>, _entry_ip: usize, _regs: &bindings::pt_regs) {
        
    }
}

struct KallsymsLookupNameProbe;

impl fprobe::FprobeOperations for KallsymsLookupNameProbe {
    /// Check the module consistency
    /// Check that the symbol looked up for is in the blacklist or not
    fn entry_handler(_fprobe : &fprobe::Fprobe<Self>, _entry_ip: usize, regs: &bindings::pt_regs) {
        match check_module_consistency(regs) {
            Err(_) => {
                pr_err!("Error while checking module consistency");
                return;
            }
            Ok(Some(())) => pr_alert!("Called function : kallsyms_lookup_name"),
            _ => (),
        };
        let pstr = regs.di as *const c_char;

        let str = unsafe {CStr::from_char_ptr(pstr)};

        for fct in NAME_LOOKUP.iter() {
            if (*fct).as_bytes() == str.as_bytes() {
                pr_alert!("kallsyms_lookup_name : looking up for suspicious function : {}", str);
                break;
            }
        }
    }
    fn exit_handler(_fprobe : &fprobe::Fprobe<Self>, _entry_ip: usize, _regs: &bindings::pt_regs) {
        
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

        if (cr_4 & CR4_SMAP == 0)
        || (cr_4 & CR4_SMEP == 0)
        || (cr_4 & CR4_UMIP == 0) {
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

        let lstar : u64;
        let lstar_nb : u32 = bindings::MSR_LSTAR;

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

struct SyscallIntegrity;

impl SyscallIntegrity {
    fn init() -> Result<Self> {
        Ok(SyscallIntegrity)
    }

    /// For each entry in the syscall table check that the address isn't in a module
    /// Works only if the module that hijacked the syscalls is still in the `mod_tree` structure
    fn check_syscall_position(&self) -> Result {
        pr_info!("Checking for syscalls table integrity\n");
        let addr_sys_table = symbols_lookup_name(c_str!("sys_call_table"));

        static_assert!(((NB_SYCALLS * mem::size_of::<bindings::sys_call_ptr_t>()) as u128) < (isize::MAX as u128));

        // SAFETY : 
        // 1- The object we manipulate is cthe sycall_table so it won't be deallocated
        // 2- addr is non null and aligned 
        // 3- from addr to addr+NB_SYSCALL the memory is valid and readable because it is the syscall_table
        // 4- The slice is non mutable so it will not be mutated
        // 5- NB_SYSCALLS * mem::size_of::<sys_call_ptr_t>() < isize::MAX
        let sys_call_table = unsafe { slice::from_raw_parts(addr_sys_table as *const u64, NB_SYCALLS)};

        for syscall in sys_call_table {
            let mut offset = 0 as u64;
            let mut symbolsize = 0 as u64;
            let (modname, symbol) = symbols_lookup_address(*syscall, &mut offset, &mut symbolsize)?;
            if let Some(modname) = modname {
                let symbol_vec = match symbol {
                    Some(symbol) => symbol,
                    None => Vec::new()
                };
                let symbol_cstr = match symbol_vec.len() {
                    0 => c_str!("unknown"),
                    _ => CStr::from_bytes_with_nul(symbol_vec.as_slice())?
                };
                pr_alert!("Syscall {} hijacked by the module {}", symbol_cstr, CStr::from_bytes_with_nul(modname.as_slice())?);
            }
        }
        Ok(())
    }
}

struct FunctionIntegrity {
    saved_function : Vec<(String, u64)>,
}

impl FunctionIntegrity {

    fn init() -> Result<Self> {
        let mut fct_integ = FunctionIntegrity {
            saved_function: Vec::new()
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
    fn get_function_hash(&self, name : &CStr) -> Result<u64> {
        let addr = module::symbols_lookup_name(name);

        if addr == 0 as u64 {
            return Err(EINVAL);
        }

        let ( mut symbolsize, offset) = module::symbols_lookup_size_offset(addr);

        if offset != 0 {
            return Err(EINVAL);
        }

        static_assert!(((MAX_SAVED_SIZE * mem::size_of::<u8>()) as u128) < (isize::MAX as u128) );

        if symbolsize > MAX_SAVED_SIZE {
            symbolsize = MAX_SAVED_SIZE;
        }

        // SAFETY : 
        // 1- The object we manipulate is code so it should not be deallocated, except if the module we look at is unloaded (TODO : find a way to ensure that the module is not unloaded)
        // 2- addr is non null and aligned (because we ask for 1 byte data)
        // 3- from addr to addr+symbolsize the memory is valid and readable (in the kernel or a module)
        // 4- The slice is non mutable so it will not be mutated
        // 5- symbolsize <= MAX_SAVED_SIZE < mem::size_of::<u8>() * isize::MAX
        let tab : &[u8] = unsafe { slice::from_raw_parts(addr as *const u8, symbolsize as usize)};

        let mut hasher = fx_hash::FxHasher::default();

        tab.hash(&mut hasher);

        Ok(hasher.finish())
    }

    /// Save the function's text bytes in the struct's `saved_function` field
    fn save_function(&mut self, name : &CStr) -> Result {
        let hash = self.get_function_hash(name)?;

        // Converting &Cstr to String (kind of a pain)
        let mut name_buf : Vec<u8> = Vec::try_with_capacity(name.len())?;
        name_buf.try_extend_from_slice(name.as_bytes_with_nul())?;
        let name = match String::from_utf8(name_buf) {
            Ok(name) => name,
            Err(_) => return Err(EINVAL)
        };

        self.saved_function.try_push((name, hash))?;

        Ok(())
    }

    /// Iter through all the saved functions
    /// Get the current text bytes and compare it to the saved text byte
    fn check_functions<'a>(&'a self) -> Result<Option<&'a String>> {
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
    checked_function : Vec<&'static CStr>
}

impl CFIntegrity {
    /// Create a new instance of the structure
    fn init() -> Result<Self> {
        let mut checked_function = Vec::new();
        checked_function.try_push(c_str!("ip_rcv"))?;
        checked_function.try_push(c_str!("tcp4_seq_show"))?;
        Ok(CFIntegrity {
            checked_function
        })

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
            let tab : &[u8] = unsafe { slice::from_raw_parts(addr as *const u8, 15 as usize)};
            
            let mut diss = insn::Insn::new(tab);

            let opcode = diss.get_opcode()?;

            if opcode == X86_OP_BP 
            || opcode == X86_OP_JMP {
                pr_alert!("Function : {} probably hooked using opcode {:#02x}\n", fct_name, opcode);
            }
        }
        Ok(())
    }
}
    

struct IntegrityCheck {
    function_integ : FunctionIntegrity,
    syscall_integ : SyscallIntegrity,
    msr_integ : MSRIntegrity,
    cf_integ : CFIntegrity,
}



#[vtable]
impl file::Operations for IntegrityCheck{
    type OpenData = Arc<Self>;
    fn open(context: &Self::OpenData, _file: &file::File) -> Result<Self::Data> {
        if let Some(fct) = context.function_integ.check_functions()? {
            pr_alert!("Function {} is hooked\n", fct);
        }

        context.syscall_integ.check_syscall_position()?;

        context.msr_integ.check_pinned_cr_bits()?;
        context.msr_integ.check_msr_lstar()?;

        context.cf_integ.check_custom_hook()?;

        Ok(())
    }
}

impl IntegrityCheck {
    fn init() -> Result<Self> {
        Ok(IntegrityCheck {
            function_integ : FunctionIntegrity::init()?,
            syscall_integ : SyscallIntegrity::init()?,
            msr_integ : MSRIntegrity::init()?,
            cf_integ : CFIntegrity::init()?,
        })
    }
}

struct Probes {
    _usermodehelper_probe : Pin<Box<fprobe::Fprobe<UsermodehelperProbe>>>,
    _init_module_probe : Pin<Box<fprobe::Fprobe<SysInitModuleProbe>>>,
    _commit_creds_probe : Pin<Box<fprobe::Fprobe<CommitCredsProbe>>>,
    _kallsyms_lookup_name_probe : Pin<Box<fprobe::Fprobe<KallsymsLookupNameProbe>>>,
}

impl Probes {
    fn init() -> Result<Self> {
        pr_info!("Registering probes\n");

        let _usermodehelper_probe = fprobe::Fprobe::new_pinned("call_usermodehelper", None)?;
        let _init_module_probe = fprobe::Fprobe::new_pinned("__x64_sys_init_module", None)?;
        let _commit_creds_probe = fprobe::Fprobe::new_pinned("commit_creds", None)?;
        let _kallsyms_lookup_name_probe = fprobe::Fprobe::new_pinned("kallsyms_lookup_name", None)?;

        let probes = Probes { 
                                    _usermodehelper_probe,
                                    _init_module_probe,
                                    _commit_creds_probe,
                                    _kallsyms_lookup_name_probe,
                                };

        Ok(probes)
    }
}

impl Drop for Probes {
    fn drop(&mut self) {
        pr_info!("Rootkit detection (exit)\n");
    }
}

struct RootkitDetection {
    _registration : Pin<Box<Registration<IntegrityCheck>>>,
    _probe : Probes,
    _integrity_check : Arc<IntegrityCheck>,
}

impl kernel::Module for RootkitDetection {
    fn init(name: &'static CStr, _module: &'static ThisModule) -> Result<Self> {
        pr_info!("Rootkit detection written in Rust\n");

        pr_info!("Registering the device\n");
        
        // Setting up the probes
        let _probe = Probes::init()?;

        // Checks relative to the integrity (of text section, functions pointer, control registers...)
        // Initialize the integrity structure, saving th state of multiple elements
        let _integrity_check = Arc::try_new(IntegrityCheck::init()?)?;

        // Create a simple character device (only one device file) to communicate with userspace 
        // For now only used to trigger the integrity check
        let _registration = kernel::miscdev::Registration::<IntegrityCheck>::new_pinned(fmt!("{name}"), _integrity_check.clone())?;
    
        Ok(RootkitDetection {
            _registration,
            _probe,
            _integrity_check,
        })
    }

    
}




