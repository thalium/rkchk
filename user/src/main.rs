use std::fmt::Display;

use nix;
use nix::fcntl;
use nix::sys::stat::Mode;
const RKCHK_IOC_MAGIC: u8 = b'j';
const RKCHK_INTEG_ALL: u8 = 1;
nix::ioctl_none!(rkchk_run_all_integ, RKCHK_IOC_MAGIC, RKCHK_INTEG_ALL);

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

pub mod event;
use event::Events;
fn main() {
    let fd = fcntl::open(
        "/dev/rootkit_detection",
        fcntl::OFlag::O_RDWR,
        Mode::empty(),
    )
    .unwrap();

    let mut raw_event = [0 as u8; core::mem::size_of::<Events>()];

    println!("Running all the integrity checks\n");

    unsafe {
        rkchk_run_all_integ(fd).unwrap();
    }
    // TODO : Set all the string and pointer in the event structures to direct buffer because otherwise we transmit the kernel pointer
    loop {
        nix::unistd::read(fd, &mut raw_event).unwrap();

        // The device should return a type event
        let event = unsafe {
            std::mem::transmute::<[u8; std::mem::size_of::<Events>()], Events>(raw_event)
        };

        println!("{event}");
    }
}
