// SPDX-License-Identifier: GPL-2.0

//! Rust character device sample.
use core::clone::Clone;
use core::ffi::c_char;
use core::hash::Hash;
use core::hash::Hasher;
use core::iter::Iterator;
use core::result::Result::Err;
use core::result::Result::Ok;
use core::slice;
use core::str;
use event::EBPFFuncInfo;
use event::LoadedLKMInfo;
use event::ModuleInfo;
use event::ProcessInfo;
use kernel::bindings;
use kernel::c_str;
use kernel::error::Result;
use kernel::fprobe::FprobeOperations;
use kernel::list::ListArc;
use kernel::module::is_kernel;
use kernel::module::is_module;
use kernel::prelude::*;
use kernel::socket;
use kernel::str::CStr;
use kernel::sync::Arc;
use kernel::sync::ArcBorrow;
use kernel::task::Task;
use kernel::types::ForeignOwnable;
use kernel::uaccess::UserSlice;

use kernel::fprobe;
use kernel::module;
use kernel::uaccess::UserSliceReader;

use crate::event;
use crate::fx_hash;
use crate::EventStack;
use crate::KEvents;

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

/// Run a series of test to check if the address come from a normal space
/// 1 - Check if it ome from a module, if yes get the module name (use the mod_tree struct in the kernel)
/// 2 - If it has a module name, check that it's in the linked list of module :
///     many rootkit remove themselves from the linked list but not from the mod tree
/// 3 - If a module name wasn't found check that it come from the kernel executable
/// # Return :
/// In case of an Ok return :
///     Some(()) => an inconsistency was found
///     None => everything is fine
pub fn check_address_consistency(addr: u64) -> Result<Option<event::Events>> {
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

/// Get the parent ip (the ip of the calling function).
/// Check this address with the `check_address_consistency` function.
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
            bindings::bpf_func_id_BPF_FUNC_send_signal => event::EBPFFuncType::SendSignal,
            bindings::bpf_func_id_BPF_FUNC_send_signal_thread => event::EBPFFuncType::SendSignal,
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

/// Used to hold all the structure representing the probes placed in the kernel
pub struct Probes {
    _usermodehelper_probe: Pin<KBox<fprobe::Fprobe<UsermodehelperProbe>>>,
    _commit_creds_probe: Pin<KBox<fprobe::Fprobe<CommitCredsProbe>>>,
    _kallsyms_lookup_name_probe: Pin<KBox<fprobe::Fprobe<KallsymsLookupNameProbe>>>,
    _load_module_probe: Pin<KBox<fprobe::Fprobe<LoadModuleProbe>>>,
    _ksys_dup3_probe: Pin<KBox<fprobe::Fprobe<KSysDup3Probe>>>,
    _check_helper_call: Pin<KBox<fprobe::Fprobe<CheckHelperCall>>>,
    _sys_getdents64: Pin<KBox<fprobe::Fprobe<SysGetDents64>>>,
}

impl Probes {
    /// Create a new instance
    pub fn init(events: Arc<EventStack>) -> Result<Self> {
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
