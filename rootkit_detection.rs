// SPDX-License-Identifier: GPL-2.0

//! Rust character device sample.

use core::ffi::c_char;
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

/// The maximum number of byte we saved for a given function
const MAX_SAVED_SIZE : usize = 4096;
// The number of syscall on my computer
const NB_SYCALLS : usize = 451;

const NAME_LOOKUP: [&str; 12] = ["module_tree_insert", "module_tree_remove", "module_mutex", "sys_call_table", "__x64_sys_init_module", "sys_kill", "vfs_read", "__x64_sys_kill",  "__x64_sys_getdents", "__x64_sys_getdents64", "tcp6_seq_show", "tcp4_seq_show"];


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
                pr_err!("Error while checking module consistency");
                return;
            }
            Ok(Some(())) => pr_alert!("Called function : commit_creds"),
            _ => (),
        };

    }

    fn exit_handler(_fprobe : &fprobe::Fprobe<Self>, _entry_ip: usize, _regs: &bindings::pt_regs) {
    }
}

struct CommitCredsProbe;

impl fprobe::FprobeOperations for CommitCredsProbe {
    fn entry_handler(_fprobe : &fprobe::Fprobe<Self>, _entry_ip: usize, regs: &bindings::pt_regs) {
        match check_module_consistency(regs) {
            Err(_) => {
                pr_err!("Error while checking module consistency");
                return;
            }
            Ok(Some(())) => pr_alert!("Called function : commit_creds"),
            _ => (),
        };
    }
    fn exit_handler(_fprobe : &fprobe::Fprobe<Self>, _entry_ip: usize, _regs: &bindings::pt_regs) {
        
    }
}

struct KallsymsLookupNameProbe;

impl fprobe::FprobeOperations for KallsymsLookupNameProbe {
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

struct SyscallIntegrity;

impl SyscallIntegrity {
    fn init() -> Result<Self> {
        Ok(SyscallIntegrity)
    }

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
    saved_function : Vec<(String, Vec<u8>)>,
}

impl FunctionIntegrity {

    fn init() -> Result<Self> {
        let mut fct_integ = FunctionIntegrity {
            saved_function: Vec::new()
        };

        fct_integ.save_function(c_str!("ip_rcv"))?;

        Ok(fct_integ)
    }

    /// Return the bytes of the function `name`
    /// Return at max MAX_SAVED_SIZE first bytes
    fn get_function_as_bytes(&self, name : &CStr) -> Result<Vec<u8>> {
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

        let mut buffer = Vec::try_with_capacity(symbolsize)?;
        buffer.try_extend_from_slice(tab)?;

        Ok(buffer)
    }

    // Save the function in the struct's `saved_function` field
    fn save_function(&mut self, name : &CStr) -> Result {
        let buffer = self.get_function_as_bytes(name)?;

        let mut name_buf : Vec<u8> = Vec::try_with_capacity(name.len())?;
        name_buf.try_extend_from_slice(name.as_bytes_with_nul())?;
        let name = match String::from_utf8(name_buf) {
            Ok(name) => name,
            Err(_) => return Err(EINVAL)
        };
    
        self.saved_function.try_push((name, buffer))?;

        Ok(())
    }
    fn check_functions<'a>(&'a self) -> Result<Option<&'a String>> {
        for (name, bytes) in &self.saved_function {
            let new_bytes = self.get_function_as_bytes(CStr::from_bytes_with_nul(name.as_bytes())?)?;
            if new_bytes != *bytes {
                return Ok(Some(name));
            }
       }
       Ok(None)
    }

}

struct IntegrityCheck {
    function_integ : FunctionIntegrity,
    syscall_integ : SyscallIntegrity,
}

#[vtable]
impl file::Operations for IntegrityCheck{
    type OpenData = Arc<Self>;
    fn open(context: &Self::OpenData, _file: &file::File) -> Result<Self::Data> {
        if let Some(fct) = context.function_integ.check_functions()? {
            pr_alert!("Function {} is hooked\n", fct);
        }

        context.syscall_integ.check_syscall_position()?;

        Ok(())
    }
}

impl IntegrityCheck {
    fn init() -> Result<Self> {
        Ok(IntegrityCheck {
            function_integ : FunctionIntegrity::init()?,
            syscall_integ : SyscallIntegrity::init()?,
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
        
        let _probe = Probes::init()?;

        let _integrity_check = Arc::try_new(IntegrityCheck::init()?)?;

        let _registration = kernel::miscdev::Registration::<IntegrityCheck>::new_pinned(fmt!("{name}"), _integrity_check.clone())?;
    
        Ok(RootkitDetection {
            _registration,
            _probe,
            _integrity_check,
        })
    }

    
}




