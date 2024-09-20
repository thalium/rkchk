// SPDX-License-Identifier: GPL-2.0

//! Rust character device sample.

use core::ffi::c_char;
use core::result::Result::Ok;

use kernel::error::Result;
use kernel::bindings;
use kernel::module::is_module;
use kernel::str::CStr;

use kernel::prelude::*;
use kernel::fprobe;
use kernel::module;


module! {
    type: Probes,
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

fn check_module_consistency(regs : &bindings::pt_regs) -> Result {
    let sp = regs.sp as *const u64;

    // Parent ip
    // SAFETY : The sp should point to a valid point in memory 
    let pip  = unsafe {
        *sp
    };

    let mut offset : u64 = 0;
    let mut _symbolsize : u64 = 0;

    let (modname, symbol) = module::symbols_lookup(pip, &mut offset, &mut _symbolsize)?;

    if let Some(name) = modname {
        pr_info!("Module source : {}\n", CStr::from_bytes_with_nul(name.as_slice())?);
        if let Some(symbol) = symbol {
            pr_info!("Symbol info : {}+{}\n", CStr::from_bytes_with_nul(symbol.as_slice())?, offset);
        }
        if !is_module(CStr::from_bytes_with_nul(name.as_slice())?) {
            pr_alert!("Suspicious activity : module name [{}] not in module list\n", CStr::from_bytes_with_nul(name.as_slice())?);
        }
    }

    Ok(())
}

struct UsermodehelperProbe;

impl fprobe::FprobeOperations for UsermodehelperProbe {
    fn entry_handler(_fprobe : &fprobe::Fprobe<Self>, _entry_ip: usize, _regs: &bindings::pt_regs) {
        pr_info!("We entered `call_usermodehelper`\n");
        let pstr = _regs.di as *const c_char;
        
        if pstr == 0 as *const i8 {
            return;
        }

        //SAFETY : The C code should give us a valid pointer to a null terminated string
        let prog = unsafe { CStr::from_char_ptr(pstr) };

        pr_info!("Executing the program : {}\n", prog);

        if let Err(_) = check_module_consistency(_regs) {
            pr_err!("Error while checking module consistency");
        }

    }

    fn exit_handler(_fprobe : &fprobe::Fprobe<Self>, _entry_ip: usize, _regs: &bindings::pt_regs) {
        pr_info!("We exited `call_usermodehelper`\n");
    }
}

struct CommitCredsProbe;

impl fprobe::FprobeOperations for CommitCredsProbe {
    fn entry_handler(_fprobe : &fprobe::Fprobe<Self>, _entry_ip: usize, regs: &bindings::pt_regs) {
        if let Err(_) = check_module_consistency(regs) {
            pr_err!("Error while checking module consistency");
        }
    }
    fn exit_handler(_fprobe : &fprobe::Fprobe<Self>, _entry_ip: usize, _regs: &bindings::pt_regs) {
        
    }
}

struct Probes {
    _usermodehelper_probe : Pin<Box<fprobe::Fprobe<UsermodehelperProbe>>>,
    _init_module_probe : Pin<Box<fprobe::Fprobe<SysInitModuleProbe>>>,
    _commit_creds_probe : Pin<Box<fprobe::Fprobe<CommitCredsProbe>>>
}

impl kernel::Module for Probes {
    fn init(_name: &'static CStr, _module: &'static ThisModule) -> Result<Self> {
        pr_info!("Rootkit detection written in Rust\n");

        pr_info!("Registering probes\n");

        let _usermodehelper_probe = fprobe::Fprobe::new_pinned("call_usermodehelper", None)?;

        let _init_module_probe = fprobe::Fprobe::new_pinned("__x64_sys_init_module", None)?;

        let _commit_creds_probe = fprobe::Fprobe::new_pinned("commit_creds", None)?;

        Ok(Probes { 
            _usermodehelper_probe,
            _init_module_probe,
            _commit_creds_probe,
        })
    }
}

impl Drop for Probes {
    fn drop(&mut self) {
        pr_info!("Rootkit detection (exit)\n");
    }
}
