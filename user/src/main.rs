use std::fmt::Display;

use nix;
use nix::fcntl;
use nix::sys::stat::Mode;
const RKCHK_IOC_MAGIC: u8 = b'j';
const RKCHK_INTEG_ALL_NR: u8 = 1;
const RKCHK_READ_EVENT_NR: u8 = 2;
nix::ioctl_none!(rkchk_run_all_integ, RKCHK_IOC_MAGIC, RKCHK_INTEG_ALL_NR);
nix::ioctl_read_buf!(
    rkchk_read_event,
    RKCHK_IOC_MAGIC,
    RKCHK_READ_EVENT_NR,
    event::Events
);

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
                write!(f, "Somone mapped stadanrd I/O to a socket\nThis is a common technique to open reverse shell\n\ttgid: {}", info.tgid)
            }
            Self::EBPFFunc(info) => {
                write!(f, "An eBPF programm was loaded and is using a function that can tamper with user or kernel space :\n\tfunction: {}\n\ttgid: {}", info.func_type, info.tgid)
            }
            _ => {
                write!(f, "To be implemented\n")
            }
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
        }
    }
}

pub mod event;
fn main() {
    let fd = fcntl::open("/dev/rkchk", fcntl::OFlag::O_RDWR, Mode::empty()).unwrap();

    println!("Running all the integrity checks\n");

    unsafe {
        rkchk_run_all_integ(fd).unwrap();
    }
    // TODO : Set all the string and pointer in the event structures to direct buffer because otherwise we transmit the kernel pointer
    loop {
        let mut event = [event::Events::NoEvent];
        unsafe { rkchk_read_event(fd, &mut event).unwrap() };

        // The device should return a type event
        /*let event = unsafe {
            std::mem::transmute::<[u8; std::mem::size_of::<Events>()], Events>(raw_event)
        };*/

        println!("{}", event.get(0).unwrap());
    }
}
