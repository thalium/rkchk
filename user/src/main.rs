use nix;
use nix::fcntl;
use nix::sys::stat::Mode;
const RKCHK_IOC_MAGIC: u8 = b'j';
const RKCHK_INTEG_ALL: u8 = 1;
nix::ioctl_none!(rkchk_run_all_integ, RKCHK_IOC_MAGIC, RKCHK_INTEG_ALL);

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

        match event {
            Events::LoadedLKM(info) => println!(
                "We have the module : {:?} with hash {}\n",
                String::from_utf8_lossy(&info.name).into_owned(),
                info.hash
            ),
            _ => println!("Unknown type\n"),
        }
    }
}
