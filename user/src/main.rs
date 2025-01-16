use nix::{self, Result};
use nix::errno::Errno;
use nix::fcntl;
use nix::libc::{pid_t, sleep};
use nix::sys::signal;
use nix::sys::signal::Signal::SIGKILL;
use nix::sys::stat::Mode;
use nix::unistd::Pid;
use std::borrow::Borrow;
use std::ffi::{CStr, CString};
use std::fmt::{write, Display};
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use std::{fs, str, thread};
use std::str::FromStr;
use std::sync::Arc;
nix::ioctl_none!(rkchk_run_all_integ, RKCHK_IOC_MAGIC, RKCHK_INTEG_ALL_NR);
nix::ioctl_read!(
    rkchk_read_event,
    RKCHK_IOC_MAGIC,
    RKCHK_READ_EVENT_NR,
    event::Events
);
nix::ioctl_read!(
    rkchk_number_task,
    RKCHK_IOC_MAGIC,
    RKCHK_NUMBER_TASK_NR,
    usize
);
nix::ioctl_read_buf!(rkchk_pid_list, RKCHK_IOC_MAGIC, RKCHK_PID_LIST_NR, pid_t);
nix::ioctl_read_buf!(rkchk_traced_list, RKCHK_IOC_MAGIC, RKCHK_TRACED_LIST_NR, [u8; event::SIZE_STRING]);
nix::ioctl_none!(rkchk_switch_page, RKCHK_IOC_MAGIC, RKCHK_SWITCH_PAGE_NR);
nix::ioctl_none!(rkchk_lsmod, RKCHK_IOC_MAGIC, RKCHK_LSMOD_NR);
nix::ioctl_none!(rkchk_ls_hook_inline, RKCHK_IOC_MAGIC, RKCHK_GET_INLINE_HOOK_NR);
nix::ioctl_read_buf!(rkchk_get_stacktrace, RKCHK_IOC_MAGIC, RKCHK_GET_STACKTRACE_NR, StackEntry);


impl Display for event::Events {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LoadedLKM(info) => {
                let mut name = String::from_utf8_lossy(&info.name).into_owned();

                name.retain(|c| c != '\0');

                write!(
                    f,
                    "Loaded module :\n\tname: {name}\n\thash: {:#016x}",
                    info.hash
                )
            }
            Self::IndirectCallHijack(info) => {
                write!(f, "Control flow hijack :\nA function pointer was modified by a module:\n(if present, the direct precedent module named)\n\ttype of pointer : {}", info.ptr_type)
            }
            Self::ModuleInconsistency(info) => {
                let mut name = String::from_utf8_lossy(&info.name).into_owned();

                name.retain(|c| c != '\0');

                write!(
                    f,
                    "An inconsistency in the kernel's module structure detected\nA module tried to hide himself\n\tname : {}", name)
            }
            Self::ModuleAddress(info) => {
                let mut name = String::from_utf8_lossy(&info.name).into_owned();

                name.retain(|c| c != '\0');

                write!(f, "A suspicious module was found :\n\tname: {}", name)
            }
            Self::HiddenModule => write!(
                f,
                "An hidden module was found\nNo information about it could be gathered"
            ),
            Self::HookedFunction(info) => {
                let mut name = String::from_utf8_lossy(&info.name).into_owned();

                name.retain(|c| c != '\0');

                write!(
                    f,
                    "Function with first instruction set to JMP/INT3 detected:\n\tname: {}",
                    name
                )
            }
            Self::TamperedFunction(info) => {
                let mut name = String::from_utf8_lossy(&info.name).into_owned();

                name.retain(|c| c != '\0');

                write!(
                    f,
                    "Function tampered with detected (failed integrity check):\n\tname: {}",
                    name
                )
            }
            Self::TamperedMSR => write!(f, "An MSR (CR0 or CR4 or LSTAR) was tampered with"),
            Self::StdioToSocket(info) => {
                //write!(f, "Somone mapped stadanrd I/O to a socket\nThis is a common technique to open reverse shell\n\ttgid: {}", info.tgid)
                write!(f, "Mapped I/O on a socket (mostly false positive)")
            }
            Self::EBPFFunc(info) => {
                write!(f, "An eBPF programm was loaded and is using a function that can tamper with user or kernel space :\n\tfunction: {}\n\ttgid: {}", info.func_type, info.tgid)
            }
            Self::HiddenFile(info) => {
                write!(
                    f,
                    "A hidden file was found : excpected size : {}, gotten size: {}",
                    info.normal_size, info.d_reclen
                )
            }
            Self::EnvPreload(info) => {
                write!(
                    f,
                    "A process was executed with an suspicious environment variable:\n\tvariable: {}\n\tpath: {:?}", 
                    info.env_type, 
                    // The string provided by the LKM are valid ASCII null terminated string
                    CStr::from_bytes_until_nul(&info.path).unwrap() ,
                )
            }
            _ => {
                write!(f, "To be implemented\n")
            }
        }
    }
}

impl Display for event::EnvType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LDLibraryPath => write!(f, "LD_LIBRARY_PATH"),
            Self::LDPreload => write!(f, "LD_PRELOAD"),
        }
    }
}

impl Display for event::FunctionPointerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Syscall => write!(f, "syscall table entry"),
            Self::Other => write!(f, "others"),
        }
    }
}

impl Display for event::EBPFFuncType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OverrideReturn => write!(f, "bpf_override_return"),
            Self::WriteUser => write!(f, "bpf_probe_write_user"),
            Self::SendSignal => write!(f, "bpf_send_signal"),
        }
    }
}

impl Display for StackEntry{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:x}", self.addr)?;
        if let Some(symbol) = &self.name {
            if let Ok(symbol) = CStr::from_bytes_until_nul(symbol) {
                write!(f, " : {:?} + {:x}",symbol, self.offset)?;
            }
            else {
                write!(f, " : {:?}", symbol)?;
            }
        }
        if let Some(module) = &self.modname {
            if let Ok(module) = CStr::from_bytes_until_nul(module) {
                write!(f, " [{:?}]", module)?;
            }
            else {
                write!(f, " [{:?}]", module)?;
            }
        }
        Ok(())
    }
}


fn read_data<T>(trigger : impl FnOnce(&mut MaybeUninit<usize>) -> Result<usize>, next : impl Fn(&mut MaybeUninit<T>) -> Result<usize>) -> Result<Vec<T>> {
    let mut n = MaybeUninit::uninit();

    trigger(&mut n)?;

    let n = unsafe {
        n.assume_init()
    };

    let mut res = Vec::with_capacity(n);

    let buf  = res.spare_capacity_mut();
    for i in 0..n {
        let tmp = buf.get_mut(i).unwrap(); // By the with_capacity guaranty we have enought element in buf
        
        next(tmp)?;
    }

    unsafe {
        res.set_len(n);
    }

    Ok(res)
}

fn check_hidden_process(fd: i32) -> std::io::Result<Option<Vec<pid_t>>> {
    let read_dir = std::fs::read_dir("/proc/")?;

    let mut suspect_pid: Vec<pid_t> = Vec::new();

    let proc_pid_vec: Vec<pid_t> = read_dir
        .filter_map(|dir_entry| -> Option<pid_t> {
            if let Ok(dir_entry) = dir_entry {
                if let Ok(dir_str) = dir_entry.file_name().into_string() {
                    if let Ok(pid) = dir_str.parse::<pid_t>() {
                        return Some(pid);
                    }
                }
            }
            return None;
        })
        .collect();

    let mut number_task: usize = 0;

    unsafe { rkchk_number_task(fd, &mut number_task as *mut usize) }.unwrap();

    let mut pid_list = [0_i32; 300];

    unsafe { rkchk_pid_list(fd, &mut pid_list) }.unwrap();

    for pid in pid_list {
        // The pid 0 exit in kernel but is not shown in the /proc
        // virtual filesystem
        if pid == 0 {
            continue;
        }

        if !proc_pid_vec.contains(&pid) {
            suspect_pid.push(pid);
        }
    }

    if suspect_pid.is_empty() {
        Ok(None)
    } else {
        Ok(Some(suspect_pid))
    }
}

fn check_ftrace_hook(fd: i32 ) -> std::io::Result<Option<Vec<String>>> {
    // This file list all the traced functions using kernel hooks
    let content = fs::read_to_string("/sys/kernel/debug/tracing/enabled_functions")?;

    let mut rkchk_functions = [[0_u8; event::SIZE_STRING]; 20];

    unsafe { rkchk_traced_list(fd, &mut rkchk_functions) }.unwrap();

    let mut rkchk_function_vec : Vec<String> = Vec::new();

    for fct in rkchk_functions {
        // It's a tab of 100 so there is a first element
        if *fct.get(0).unwrap() != 0 {
            let mut string_fct = String::from_utf8_lossy(&fct).into_owned();
            string_fct.retain(|c| c!= '\0');
            rkchk_function_vec.push(string_fct);
        }
    }


    let mut res = Vec::new();

    for line in content.lines() {
        if let Some(fct_name) = line.split_ascii_whitespace().next() {
            let fct_name = String::from_str(fct_name).unwrap();
            if !rkchk_function_vec.contains(&fct_name) {
                res.push(fct_name);
            }
        }
    }


    if res.is_empty() {
        Ok(None)
    }
    else {
        Ok(Some(res))
    }
}

pub trait Threat
where
    Self: Display,
{
    fn remove(&self) {
        println!("To be implemented....\n");
    }
}

struct LKM {
    events: Vec<event::Events>,
    name: Vec<u8>,
}

impl Display for LKM {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Suspicious module : {:?}\n", self.name)
    }
}

impl Threat for LKM {
    fn remove(&self) {
        // We know that the name contain only ascii character and
        // end with a null character.
        let name = CStr::from_bytes_until_nul(&self.name).unwrap();
        // Do the equivalent of `rmmod --force`
        if let Err(err) = nix::kmod::delete_module(
            &name,
            nix::kmod::DeleteModuleFlags::O_TRUNC | nix::kmod::DeleteModuleFlags::O_NONBLOCK,
        ) {
            println!("Error unloading the module {:?} : {err}", name);
        }
    }
}

struct Process {
    events: Vec<event::Events>,
    tgid: pid_t,
}

impl Display for Process {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Suspicious process of pid : {}\n", self.tgid)
    }
}

impl Threat for Process {
    fn remove(&self) {
        if let Err(_) = signal::kill(Pid::from_raw(self.tgid), Some(SIGKILL)) {
            println!("Failed to remove process of pid {}\n", self.tgid);
        }
    }
}

fn run_integrity_check(fd: i32) {
    unsafe {
        rkchk_run_all_integ(fd).unwrap();
    }

    let traced_functions = check_ftrace_hook(fd).unwrap();
    if let Some(traced_function) = traced_functions {
        println!("Found traced functions:");
        for fct in traced_function {
            println!("{fct}");
        }
    }

    unsafe {
        rkchk_lsmod(fd).unwrap();
    }

    unsafe {
        rkchk_ls_hook_inline(fd).unwrap();
    }
}


pub mod event;

use event::ioctl::*;

fn get_print_stacktrace(fd : i32, n : usize) {
    let mut vec = Vec::new();
    vec.resize(n, StackEntry::default());


    if let Err(err) = unsafe { rkchk_get_stacktrace(fd, &mut vec) } {
        println!("Error getting stacktrace : {}", err);
    }

    if !vec.is_empty() {
        println!("[DUMP STACK]");
    }
    for entry in vec {
        println!("  {}", entry);
    }
}


fn main() {
    let fd = fcntl::open("/dev/rkchk", fcntl::OFlag::O_RDWR, Mode::empty()).unwrap();

    let term = Arc::new(AtomicBool::new(false));    

    let term_thread = term.clone();
   
    println!("Checking for hidden process");
    let suspect_pid = check_hidden_process(fd).unwrap();
    if let Some(pid_list) = suspect_pid {
        println!("Found some suspect_pid : {:?}\n", pid_list);
        for pid in pid_list {
            let threat = Process {
                events: Vec::new(),
                tgid: pid as _,
            };
            threat.remove();
        }
    }

    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&term)).unwrap();

    let thread_handle = thread::spawn(move || {
        while !term_thread.load(std::sync::atomic::Ordering::Relaxed) { 
            let fd = fcntl::open("/dev/rkchk", fcntl::OFlag::O_RDWR, Mode::empty()).unwrap();
            run_integrity_check(fd);
            std::thread::sleep(Duration::from_secs(5));
        }
        nix::unistd::close(fd).unwrap();
    });

    while !term.load(std::sync::atomic::Ordering::Relaxed) {
        let mut event = event::Events::NoEvent;
        unsafe { rkchk_read_event(fd, &mut event as _).unwrap() };
        
        match event {
            event::Events::StdioToSocket(_) => (),
            event::Events::Stacktrace(n) => get_print_stacktrace(fd, n),
            _ => println!("{}", event),

        };
    }
    thread_handle.join().unwrap();
    nix::unistd::close(fd).unwrap();
}
