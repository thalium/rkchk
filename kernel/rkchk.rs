// SPDX-License-Identifier: GPL-2.0

#![recursion_limit = "256"]

//! Rust character device sample.
use core::clone::Clone;
use core::ptr::addr_of;
use core::result::Result::Err;
use core::result::Result::Ok;
use core::str;
use event::Events;
use kernel::c_str;
use kernel::error::Result;
use kernel::impl_has_list_links;
use kernel::impl_list_item;
use kernel::ioctl::_IO;
use kernel::ioctl::_IOC_SIZE;
use kernel::ioctl::_IOR;
use kernel::list::impl_list_arc_safe;
use kernel::list::List;
use kernel::list::ListArc;
use kernel::list::ListLinks;
use kernel::miscdevice;
use kernel::miscdevice::MiscDevice;
use kernel::miscdevice::MiscDeviceRegistration;
use kernel::new_condvar;
use kernel::new_spinlock;
use kernel::prelude::*;
use kernel::sync::Arc;
use kernel::sync::CondVar;
use kernel::sync::SpinLock;
use kernel::transmute::AsBytes;
use kernel::types::ForeignOwnable;
use kernel::uaccess::UserSlice;

/// RKCHK ioctl type (aka magic number)
const RKCHK_IOC_MAGIC: u32 = b'j' as u32;
/// Run all the integrity checks (ioctl sequence number)
const RKCHK_INTEG_ALL_NR: u32 = 1;
/// Run all the integrity checks (ioctl command)
const RKCHK_INTEG_ALL: u32 = _IO(RKCHK_IOC_MAGIC, RKCHK_INTEG_ALL_NR);
/// Read new events (ioctl sequence number)
const RKCHK_READ_EVENT_NR: u32 = 2;
/// Read new events (ioctl command)
const RKCHK_READ_EVENT: u32 = _IOR::<event::Events>(RKCHK_IOC_MAGIC, RKCHK_READ_EVENT_NR);
/// Read number task_struct (ioctl sequence number)
const RKCHK_NUMBER_TASK_NR: u32 = 3;
/// Read number task_stuct (ioctl command)
const RKCHK_NUMBER_TASK: u32 = _IOR::<usize>(RKCHK_IOC_MAGIC, RKCHK_NUMBER_TASK_NR);
/// Read all pid (ioctl sequence number)
const RKCHK_PID_LIST_NR: u32 = 4;
/// Read all pid (ioctl command)
const RKCHK_PID_LIST: u32 =
    _IOR::<[kernel::bindings::pid_t; 300]>(RKCHK_IOC_MAGIC, RKCHK_PID_LIST_NR);
static mut EVENT_STACK: Option<Arc<EventStack>> = None;

static mut COMMUNICATION: Option<Arc<Communication>> = None;

pub mod event;
pub mod fx_hash;
pub mod integrity;
pub mod monitoring;

use integrity::*;
use monitoring::*;

unsafe impl AsBytes for event::Events {}

module! {
    type: RootkitDetection,
    name: "rootkit_detection",
    author: "Rust for Linux Contributors",
    description: "Rust rootkit detection module",
    license: "GPL",
}

/// An event on the kernel side
/// Placed inside a linked list
#[pin_data]
pub struct KEvents {
    #[pin]
    list_link: ListLinks<0>,
    event: Events,
}

impl KEvents {
    /// Create a new `KEvents` from an `Events`
    pub fn new(event: Events) -> Result<ListArc<Self>> {
        ListArc::pin_init(
            try_pin_init!(KEvents {
                list_link <- ListLinks::new(),
                event,
            }),
            GFP_KERNEL,
        )
    }

    fn get_ref_event(&self) -> &Events {
        &self.event
    }
}

impl_has_list_links!(impl HasListLinks for KEvents { self.list_link });
impl_list_item!(impl ListItem<0> for KEvents { using ListLinks; });
impl_list_arc_safe!(impl ListArcSafe<0> for KEvents { untracked; });

/// The linked list on event
#[pin_data]
pub struct EventStack {
    x: u32,
    #[pin]
    wait_queue: CondVar,
    #[pin]
    event_stack: SpinLock<List<KEvents, 0>>,
}

impl EventStack {
    fn init() -> Result<Arc<Self>> {
        Arc::pin_init(
            pin_init!(EventStack {
                x : 0,
                wait_queue <- new_condvar!("data queue"),
                event_stack <- new_spinlock!(List::new(), "event stack"),
            }),
            GFP_KERNEL,
        )
    }

    /// Push a Kevent on the linked list so it can be read by
    /// the userside program
    /// # Safety:
    ///     This function lock, so it should not execute in an atomic context
    pub fn push_event(&self, event: ListArc<KEvents, 0>) {
        self.event_stack.lock().push_front(event);

        self.wait_queue.notify_one();
    }

    fn wait_events(&self) -> Result<ListArc<KEvents, 0>> {
        let mut lock = self.event_stack.lock();
        while lock.is_empty() {
            if self.wait_queue.wait_interruptible(&mut lock) {
                return Err(EINTR);
            }
        }
        // If we could make a while let with an else let statment this situation won't exist,
        // We cannot get the None option of this match but anyway
        match lock.pop_back() {
            Some(event) => Ok(event),
            None => Err(EAGAIN),
        }
    }
}

struct Communication {
    integrity_check: Arc<IntegrityCheck>,
    events: Arc<EventStack>,
}

#[vtable]
impl MiscDevice for Communication {
    type Ptr = Arc<Self>;

    fn open() -> Result<Self::Ptr> {
        unsafe {
            match &*addr_of!(COMMUNICATION) {
                None => Err(ENOMEM),
                Some(communication) => Ok(communication.clone()),
            }
        }
    }

    fn ioctl(
        data: <Self::Ptr as ForeignOwnable>::Borrowed<'_>,
        cmd: u32,
        arg: usize,
    ) -> Result<isize> {
        let size = _IOC_SIZE(cmd);
        let user_slice = UserSlice::new(arg, size);
        match cmd {
            RKCHK_NUMBER_TASK => {
                user_slice.writer().write(&number_tasks())?;
                Ok(core::mem::size_of::<usize>() as _)
            }
            RKCHK_PID_LIST => {
                let mut writer = user_slice.writer();
                let nb = fill_pid_list(&mut writer)?;
                Ok((core::mem::size_of::<kernel::bindings::pid_t>() * nb) as _)
            }
            RKCHK_INTEG_ALL => {
                data.integrity_check.function_integ.check_functions()?;

                data.integrity_check
                    .syscall_integ
                    .check_syscall_position()?;

                data.integrity_check.msr_integ.check_pinned_cr_bits()?;
                data.integrity_check.msr_integ.check_msr_lstar()?;

                data.integrity_check.cf_integ.check_custom_hook()?;

                Ok(0)
            }
            RKCHK_READ_EVENT => {
                let mut writer = user_slice.writer();
                let event = data.events.wait_events()?;

                // Once a new event arrived we send it if the buffer is long enough
                if writer.len() < core::mem::size_of::<event::Events>() {
                    return Err(ENOMEM);
                }

                writer.write::<event::Events>(event.get_ref_event())?;
                /*let buf = unsafe {
                    core::mem::transmute::<Events, [u8; core::mem::size_of::<Events>()]>(event)
                };

                for e in &buf {
                    writer.write(e)?;
                }*/

                Ok(core::mem::size_of::<event::Events>() as _)
            }

            _ => Err(ENOTTY),
        }
    }
}

struct RootkitDetection {
    _registration: Pin<KBox<MiscDeviceRegistration<Communication>>>,
    _probe: Arc<Probes>,
    _integrity_check: Arc<IntegrityCheck>,
    _communication: Arc<Communication>,
}

impl kernel::Module for RootkitDetection {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("Rootkit detection written in Rust\n");

        pr_info!("Registering the device\n");

        unsafe { EVENT_STACK = Some(EventStack::init()?) };

        let event_stack = unsafe {
            match &*addr_of!(EVENT_STACK) {
                None => return Err(ENOMEM),
                Some(event) => event.clone(),
            }
        };
        // Setting up the probes
        let _probe = Probes::init(event_stack.clone())?;

        let _integrity_check = Arc::new(IntegrityCheck::init(event_stack.clone())?, GFP_KERNEL)?;

        // Checks relative to the integrity (of text section, functions pointer, control registers...)
        // Initialize the integrity structure, saving th state of multiple elements
        unsafe {
            COMMUNICATION = Some(Arc::new(
                Communication {
                    integrity_check: _integrity_check.clone(),
                    events: event_stack.clone(),
                },
                GFP_KERNEL,
            )?)
        };

        let communication = unsafe {
            match &*addr_of!(COMMUNICATION) {
                None => return Err(ENOMEM),
                Some(communication) => communication.clone(),
            }
        };

        // Create a simple character device (only one device file) to communicate with userspace
        // For now only used to trigger the integrity check
        let _registration = KBox::pin_init(
            miscdevice::MiscDeviceRegistration::register(miscdevice::MiscDeviceOptions {
                name: c_str!("rkchk"),
            }),
            GFP_KERNEL,
        )?;

        Ok(RootkitDetection {
            _registration,
            _probe,
            _integrity_check,
            _communication: communication,
        })
    }
}
