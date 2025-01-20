// SPDX-License-Identifier: GPL-2.0
#![recursion_limit = "256"]
//! Rust character device sample.
use core::ptr::addr_of;
use core::str;
use event::ioctl;
use event::Events;
use event::MODULE_NAME_SIZE;
use inline_hooks::InlineHook;
use kernel::c_str;
use kernel::error::Result;
use kernel::impl_has_list_links;
use kernel::impl_list_item;
use kernel::ioctl::{_IOC_NR, _IOC_SIZE};
use kernel::list::impl_list_arc_safe;
use kernel::list::List;
use kernel::list::ListArc;
use kernel::list::ListLinks;
use kernel::miscdevice;
use kernel::miscdevice::MiscDevice;
use kernel::miscdevice::MiscDeviceRegistration;
use kernel::module::symbols_lookup_name;
use kernel::module::ModuleIter;
use kernel::new_condvar;
use kernel::new_spinlock;
use kernel::prelude::*;
use kernel::sync::Arc;
use kernel::sync::CondVar;
use kernel::sync::SpinLock;
use kernel::transmute::AsBytes;
use kernel::types::ForeignOwnable;
use kernel::uaccess::UserSlice;

pub mod event;

use event::ioctl::*;

static mut COMMUNICATION: Option<Arc<Communication>> = None;

pub mod fx_hash;
pub mod inline_hooks;
pub mod integrity;
pub mod monitoring;
pub mod response;
pub mod stacktrace;

use integrity::*;
use kernel::uaccess::UserSliceWriter;
use monitoring::*;
use response::Response;
use stacktrace::*;

unsafe impl AsBytes for event::Events {}
unsafe impl AsBytes for ioctl::StackEntry {}
unsafe impl AsBytes for ioctl::LKM {}
unsafe impl AsBytes for ioctl::InlineHookInfo {}

module! {
    type: RootkitDetection,
    name: "rootkit_detection",
    author: "Rust for Linux Contributors",
    description: "Rust rootkit detection module",
    license: "GPL",
}

/// Write a possible absent vector to a zeroed fixed size array
pub fn write_to_slice<const N: usize>(src: &Option<KVec<u8>>) -> Option<[u8; N]> {
    if let Some(src) = src {
        let mut dst = [0; N];
        for (i, e) in src.iter().enumerate() {
            if let Some(c) = dst.get_mut(i) {
                *c = *e;
            } else {
                unsafe { *dst.get_unchecked_mut(N - 1) = 0 }
                break;
            }
        }
        Some(dst)
    } else {
        None
    }
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

/// The list of detected mods
#[pin_data]
pub struct ModList {
    vec: KVec<LKM>,
    #[pin]
    list_link: ListLinks<0>,
}

impl ModList {
    /// Create a new ModList
    pub fn new() -> Result<ListArc<Self>> {
        let iter = ModuleIter::new().map(|e| {
            let name: &[u8; 56] = &unsafe {
                *(&(*e.as_ptr()).name as *const [i8; MODULE_NAME_SIZE]
                    as *const [u8; MODULE_NAME_SIZE])
            };

            LKM {
                name: Some(name.clone()),
            }
        });

        let mut vec = KVec::new();
        for e in iter {
            vec.push(e, GFP_KERNEL)?;
        }

        ListArc::pin_init(
            try_pin_init!(ModList {
                list_link <- ListLinks::new(),
                vec,
            }),
            GFP_KERNEL,
        )
    }
    /// Get the len of the ModList
    pub fn len(&self) -> usize {
        self.vec.len()
    }

    /// Write the module to the user provided slice
    pub fn write_to_user(&self, writer: &mut UserSliceWriter) -> Result<isize> {
        for lkm in &self.vec {
            writer.write(lkm)?;
        }
        Ok((size_of::<LKM>() * self.vec.len()) as _)
    }
}

impl_has_list_links!(impl HasListLinks for ModList {self.list_link });
impl_list_item!(impl ListItem<0> for ModList {using ListLinks; });
impl_list_arc_safe!(impl ListArcSafe<0> for ModList {untracked; });

/// The linked list on event and stacktrace
/// And in a more general manner stack that contain all data that need to be stored before being
/// fetched by the userspace programms
#[pin_data]
pub struct EventStack {
    x: u32,
    #[pin]
    wait_queue: CondVar,
    #[pin]
    event_stack: SpinLock<List<KEvents, 0>>,
    #[pin]
    stacktrace_stack: SpinLock<List<StacktraceInfo, 0>>,
    #[pin]
    lsmod_stack: SpinLock<List<ModList, 0>>,
    #[pin]
    inline_hook_stack: SpinLock<List<InlineHook, 0>>,
}

impl EventStack {
    fn init() -> Result<Arc<Self>> {
        Arc::pin_init(
            pin_init!(EventStack {
                x : 0,
                wait_queue <- new_condvar!("data queue"),
                event_stack <- new_spinlock!(List::new(), "event stack"),
                stacktrace_stack <- new_spinlock!(List::new(), "stacktrace stack"),
                lsmod_stack <- new_spinlock!(List::new(), "lsmod stack"),
                inline_hook_stack <- new_spinlock!(List::new(), "inline hook stack"),
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

    /// Push a collected stacktrace on the linked list of availabale stacktrace
    pub fn push_stacktrace(&self, stacktrace: ListArc<StacktraceInfo, 0>) {
        self.stacktrace_stack.lock().push_front(stacktrace);
    }

    /// Return a stacktrace from the linked list of stacktrace (FIFO order)
    pub fn pop_stacktrace(&self) -> Option<ListArc<StacktraceInfo, 0>> {
        self.stacktrace_stack.lock().pop_back()
    }

    /// Push a collected list of module
    pub fn push_lsmod(&self, lsmod: ListArc<ModList, 0>) {
        self.lsmod_stack.lock().push_front(lsmod);
    }

    /// Pop a collected list of module (FIFO order)
    pub fn pop_lsmod(&self) -> Option<ListArc<ModList, 0>> {
        self.lsmod_stack.lock().pop_back()
    }

    /// Push a detected inline hook
    pub fn push_inline_hook(&self, inline_hook: ListArc<InlineHook, 0>) {
        self.inline_hook_stack.lock().push_front(inline_hook);
    }

    /// Pop a detected inline hook (FIFO order)
    pub fn pop_inline_hook(&self) -> Option<ListArc<InlineHook, 0>> {
        self.inline_hook_stack.lock().pop_back()
    }
}
struct Communication {
    response: Arc<Response>,
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
        match _IOC_NR(cmd) {
            RKCHK_NUMBER_TASK_NR => {
                user_slice.writer().write(&number_tasks())?;
                Ok(core::mem::size_of::<usize>() as _)
            }
            RKCHK_PID_LIST_NR => {
                let mut writer = user_slice.writer();
                let nb = fill_pid_list(&mut writer)?;
                Ok((core::mem::size_of::<kernel::bindings::pid_t>() * nb) as _)
            }
            RKCHK_TRACED_LIST_NR => {
                let mut writer = user_slice.writer();
                let nb = Probes::fill_traced_list(&mut writer)?;
                Ok((core::mem::size_of::<[u8; event::SIZE_STRING]>() * nb) as _)
            }
            RKCHK_INTEG_ALL_NR => {
                data.integrity_check.function_integ.check_functions()?;

                data.integrity_check
                    .syscall_integ
                    .check_syscall_position()?;

                data.integrity_check.msr_integ.check_pinned_cr_bits()?;
                data.integrity_check.msr_integ.check_msr_lstar()?;

                data.integrity_check.cf_integ.check_custom_hook()?;
                data.response.compare_page(&data.events, 0)?;

                Ok(0)
            }
            RKCHK_READ_EVENT_NR => {
                let mut writer = user_slice.writer();
                let event = data.events.wait_events()?;

                // Once a new event arrived we send it if the buffer is long enough
                if writer.len() < core::mem::size_of::<event::Events>() {
                    return Err(ENOMEM);
                }

                writer.write::<event::Events>(event.get_ref_event())?;

                Ok(core::mem::size_of::<event::Events>() as _)
            }

            RKCHK_SWITCH_PAGE_NR => {
                data.response.switch_page(0)?;

                Ok(0)
            }

            RKCHK_REFRESH_MOD_NR => {
                let mut writer = user_slice.writer();

                let mod_list = ModList::new()?;

                writer.write(&mod_list.len())?;

                data.events.push_lsmod(mod_list);

                // This use the mod tree, for a future use
                /*
                for m in module_iter {
                    let mut offset = 0;
                    let mut symbolsize = 0;
                    let (modname, _) =
                        symbols_lookup_address(m.as_ptr() as _, &mut offset, &mut symbolsize)?;
                    if let Some(modname) = modname {
                        let name = CStr::from_bytes_with_nul(&modname)?;
                        pr_info!("Found also the module : {:?}\n", name);
                    } else {
                        pr_info!("Suspiciously hidden module !\n");
                    }
                }*/

                Ok(size_of::<usize>() as _)
            }

            RKCHK_GET_MOD_NR => {
                let mut writer = user_slice.writer();

                if let Some(lsmod) = data.events.pop_lsmod() {
                    lsmod.write_to_user(&mut writer)
                } else {
                    Ok(0)
                }
            }

            RKCHK_GET_INLINE_HOOK_NR => {
                let mut writer = user_slice.writer();

                if let Some(inline_hook) = data.events.pop_inline_hook() {
                    inline_hook.write_to_user(&mut writer)
                } else {
                    Ok(0)
                }
            }

            RKCHK_GET_STACKTRACE_NR => {
                let mut writer = user_slice.writer();

                if let Some(stackinfo) = data.events.pop_stacktrace() {
                    stackinfo.write_to_user(&mut writer)
                } else {
                    Ok(0)
                }
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

        let event_stack = EventStack::init()?;

        // Setting up the probes
        let _probe = Probes::init(event_stack.clone())?;

        let _integrity_check = Arc::new(IntegrityCheck::init(event_stack.clone())?, GFP_KERNEL)?;

        let response = Arc::pin_init(Response::new(), GFP_KERNEL)?;
        let address: usize = symbols_lookup_name(c_str!("__x64_sys_delete_module")) as _;
        response.add_copy(address)?;

        pr_info!("We successfully copied the kernel page!");

        // Checks relative to the integrity (of text section, functions pointer, control registers...)
        // Initialize the integrity structure, saving th state of multiple elements
        unsafe {
            COMMUNICATION = Some(Arc::new(
                Communication {
                    response,
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
