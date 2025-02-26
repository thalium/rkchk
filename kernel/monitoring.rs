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
use kernel::fs::file::flags;
use kernel::fs::File;
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
use kernel::workqueue;

use crate::event;
use crate::event::EnvType;
use crate::fx_hash;
use crate::EventStack;
use crate::KEvents;
use crate::StacktraceWork;

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
                if let Ok(stacktrace) = StacktraceWork::new(30, GFP_ATOMIC, data.into()) {
                    if let Err(_) = workqueue::system().enqueue(stacktrace) {
                        pr_info!("Failed to enqueue the stacktrace\n");
                    }
                }
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
                    tgid: unsafe { Task::current() }.tgid_nr_ns(None) as i32,
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
            dirp.skip(16)?;
            // The field indicating the len of this entry
            // This is the field tampered with by rootkits
            let d_reclen: u16 = dirp.read::<u16>()?;
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

            // SAFETY: The pointer is not null, aligned and point to an initialized structure
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

/// Copy a string pointed to by a user pointer
///
/// # Safety:
///     The pointer should be `NULL` or point to a valid `null terminated` C string
/// # Return:
///     - Ok(None) if the pointer is null
///     - Ok(Some(vec)) if the copy is successfull, vec containing the null terminated string
///     - Err(_) if there was an allocation or user pointer read error
unsafe fn copy_string_from_user(user_str: *const c_char) -> Result<Option<KVec<u8>>> {
    let mut vec = KVec::new();
    if user_str.is_null() {
        return Ok(None);
    }

    let mut i = 0;
    // Loop invariant : we exit at the first encountered null character
    loop {
        // SAFETY: The count of the .add() method if always valid because the string is `null terminated`
        // therefor while we are in the loop a null character hasn't been hit
        let mut user_slice =
            UserSlice::new(unsafe { user_str.add(i) } as usize, size_of::<u8>()).reader();
        let char = user_slice.read::<u8>()?;
        vec.push(char, GFP_KERNEL)?;

        if char == 0 {
            break;
        }
        i += 1;
    }

    Ok(Some(vec))
}

const SUS_ENV: [(&CStr, EnvType); 2] = [
    (c_str!("LD_PRELOAD="), EnvType::LDPreload),
    (c_str!("LD_LIBRARY_PATH="), EnvType::LDLibraryPath),
];

/// Verify the presence of certain environement variable
/// in the envp vector:
/// - LD_PRELOAD
/// - LD_LIBRARY_PATH
/// # Safety:
///     The pointer should be `NULL` or point to a valid `null terminated` array
///     of C null terminated string
/// # Return:
///     - `Ok(None)` if the pointer is null or no events detected
///     - `Ok(Some(_))` if successfull, kevent being a detected event
///     - `Err(_)` if there was an allocation or user pointer read error
#[cfg(target_arch = "x86_64")]
unsafe fn check_envp(envp: *const *const c_char) -> Result<Option<ListArc<KEvents>>> {
    if envp.is_null() {
        return Ok(None);
    }

    let mut i = 0;
    // Loop invariant: We exit at the first encountered null pointer value
    loop {
        let mut user_slice =
            // We read the array, one item at the time
            // SAFETY: We know that the vector end with a null pointer 
            // and we exit at the first null pointer
            UserSlice::new(unsafe { envp.add(i) } as usize, size_of::<usize>()).reader();
        let user_str = user_slice.read::<usize>()? as *const c_char;

        // SAFETY: According to the safety contract of the function
        // the pointer is null or point to a null terminated string
        if let Some(vec) = unsafe { copy_string_from_user(user_str)? } {
            for (env, env_type) in SUS_ENV {
                if vec.starts_with(env.as_bytes()) {
                    let (_, path) = vec
                        .split_at_checked(env.len())
                        .ok_or(kernel::error::code::EAGAIN)?;

                    let mut event = event::EnvInfo {
                        env_type,
                        path: [0_u8; event::SIZE_STRING],
                    };

                    let (path_dst, _) = event
                        .path
                        .split_at_mut_checked(path.len())
                        .ok_or(kernel::error::code::EAGAIN)?;

                    // This won't panic because by construction
                    // `path` and `path_dst` are of the same size
                    path_dst.copy_from_slice(path);

                    let kevent = KEvents::new(event::Events::EnvPreload(event))?;

                    return Ok(Some(kevent));
                }
            }
        } else {
            break;
        }
        // We advance in the array
        i += 1;
    }

    Ok(None)
}

struct SysExecve;

impl FprobeOperations for SysExecve {
    type Data = Arc<EventStack>;
    type EntryData = ();

    fn entry_handler(
        data: <Self::Data as ForeignOwnable>::Borrowed<'_>,
        _entry_ip: usize,
        _ret_ip: usize,
        regs: &bindings::pt_regs,
        _entry_data: Option<&mut Self::EntryData>,
    ) -> Option<()> {
        let user_regs: *const bindings::pt_regs = regs.di as _;

        if user_regs.is_null() {
            return None;
        }

        // SAFETY: Pointer not null, aligned and point to an initialized structure
        let envp: *const *const c_char = unsafe { (*user_regs).dx } as _;

        // SAFETY: The envp point to the envirronment variable array
        // which have all the wanted property
        match unsafe { check_envp(envp) } {
            Err(err) => pr_info!("Error checking envp : {:?}\n", err),
            Ok(Some(kevent)) => data.push_event(kevent),
            _ => (),
        }
        None
    }
    fn exit_handler(
        _data: <Self::Data as ForeignOwnable>::Borrowed<'_>,
        _entry_ip: usize,
        _ret_ip: usize,
        _regs: &bindings::pt_regs,
        _entry_data: Option<&mut Self::EntryData>,
    ) {
    }
}

struct DoFilpOpen;

const SENSIBLE_FILE: [&CStr; 2] = [&c_str!("ld.preload.so"), &c_str!("ld-linux-x86-64.so")];

impl FprobeOperations for DoFilpOpen {
    type Data = Arc<EventStack>;
    type EntryData = Option<&'static CStr>;

    fn entry_handler(
        _data: <Self::Data as ForeignOwnable>::Borrowed<'_>,
        _entry_ip: usize,
        _ret_ip: usize,
        regs: &bindings::pt_regs,
        entry_data: Option<&mut Self::EntryData>,
    ) -> Option<()> {
        if let Some(entry_data) = entry_data {
            let pathname = regs.si as *const bindings::filename;

            // SAFETY : It's a valid pointer according to the function's usage of the pointer
            let namep = unsafe { (*pathname).name } as *const i8;

            // SAFETY : namep is a valid pointer to a null terminated string
            let name_slice = unsafe { CStr::from_char_ptr(namep) };

            for sensible in &SENSIBLE_FILE {
                if name_slice.ends_with(*sensible) {
                    *entry_data = Some(*sensible);
                    return Some(());
                }
            }
        }
        return None;
    }
    fn exit_handler(
        _data: <Self::Data as ForeignOwnable>::Borrowed<'_>,
        _entry_ip: usize,
        _ret_ip: usize,
        regs: &bindings::pt_regs,
        entry_data: Option<&mut Self::EntryData>,
    ) {
        if let Some(option) = entry_data {
            if let Some(name) = option {
                let file = unsafe { File::from_raw_file(regs.ax as *const bindings::file) };

                if file.flags() | flags::O_RDWR != 0 || file.flags() | flags::O_WRONLY != 0 {
                    pr_alert!("Opened {:?} with write mode\n", name);
                } else {
                    return;
                }
            } else {
                return;
            }
        } else {
            return;
        }
    }
}

struct SysExecveat;

impl FprobeOperations for SysExecveat {
    type Data = Arc<EventStack>;
    type EntryData = ();

    fn entry_handler(
        data: <Self::Data as ForeignOwnable>::Borrowed<'_>,
        _entry_ip: usize,
        _ret_ip: usize,
        regs: &bindings::pt_regs,
        _entry_data: Option<&mut Self::EntryData>,
    ) -> Option<()> {
        let user_regs: *const bindings::pt_regs = regs.di as _;

        if user_regs.is_null() {
            return None;
        }

        // SAFETY: Pointer not null, aligned and point to an initialized structure
        let envp: *const *const c_char = unsafe { (*user_regs).r10 } as _;

        // SAFETY: The envp point to the envirronment variable array
        // which have all the wanted property
        match unsafe { check_envp(envp) } {
            Err(err) => pr_info!("Error checking envp : {:?}\n", err),
            Ok(Some(kevent)) => data.push_event(kevent),
            _ => (),
        }
        None
    }
    fn exit_handler(
        _data: <Self::Data as ForeignOwnable>::Borrowed<'_>,
        _entry_ip: usize,
        _ret_ip: usize,
        _regs: &bindings::pt_regs,
        _entry_data: Option<&mut Self::EntryData>,
    ) {
    }
}

macro_rules! probes {
    ($(probe $func:ident => $structure:ty );*) => {
        #[pin_data]
        /// Gather all the Fprobe structure for lifetime reason
        pub struct Probes {
            $(
            #[allow(dead_code)]
            #[pin]
            $func : kernel::fprobe::Fprobe<$structure>,
            )*
        }

        impl Probes {
            /// Create a new Arc instance of Probes gathering all the Fprobe structure
            pub fn init(events: Arc<$crate::EventStack>) -> Result<Arc<Self>> {
                Arc::pin_init(
                    try_pin_init!(Probes {
                        $(
                        $func <- kernel::fprobe::Fprobe::<$structure>::new(c_str!(stringify!($func)), None, events.clone()) ,
                        )*
                    }),
                    GFP_KERNEL,
                )
            }

            /// Fill the user provided buffer with the list of the functions
            pub fn fill_traced_list(buffer: &mut kernel::uaccess::UserSliceWriter) -> Result<usize> {
                let mut nb = 0;
                $(
                let mut fct = [0_u8; event::SIZE_STRING];
                for (i, c) in stringify!($func).as_bytes().iter().enumerate() {
                    if let Some(e) = fct.get_mut(i) {
                        *e = *c;
                    }
                    else {
                        break;
                    }
                }
                buffer.write::<[u8; event::SIZE_STRING]>(&fct)?;
                nb +=1;
                )*
                Ok(nb)
            }
        }
    };
}

probes!(probe call_usermodehelper => UsermodehelperProbe;
        probe commit_creds => CommitCredsProbe;
        probe kallsyms_lookup_name => KallsymsLookupNameProbe;
        probe do_init_module => LoadModuleProbe;
        probe ksys_dup3 => KSysDup3Probe;
        probe check_helper_call => CheckHelperCall;
        probe __x64_sys_getdents64 => SysGetDents64;
        probe __x64_sys_execve => SysExecve;
        probe __x64_sys_execveat => SysExecveat;
        probe do_filp_open => DoFilpOpen);
