//! Stacktrace information gathering and management crate

use kernel::{
    alloc::{Flags, KVec},
    error::Result,
    impl_has_list_links, impl_has_work, impl_list_arc_safe, impl_list_item,
    init::InPlaceInit,
    list::{ListArc, ListLinks},
    macros::pin_data,
    module::symbols_lookup_address,
    new_work, pin_init,
    prelude::GFP_KERNEL,
    stacktrace::Stacktrace,
    sync::Arc,
    try_pin_init,
    uaccess::UserSliceWriter,
    workqueue::{Work, WorkItem},
};

use crate::{event::Events, KEvents};
use crate::{write_to_slice, EventStack, StackEntry};

/// Gather the information from a generated stacktrace

/// A collected stack-trace prepared to be put in a work queue to gather information on it.
/// Therefor transforming it in a StacktraceInfo.
#[pin_data]
pub struct StacktraceWork {
    stacktrace: Stacktrace,
    #[pin]
    work: Work<StacktraceWork>,
    event_stack: Arc<EventStack>,
}

impl_has_work! {impl HasWork<Self> for StacktraceWork { self.work }}

impl WorkItem for StacktraceWork {
    type Pointer = Arc<Self>;

    fn run(this: Self::Pointer) {
        if let Ok(stackinfo) = StacktraceInfo::new(&this.stacktrace) {
            if let Ok(kevent) = KEvents::new(Events::Stacktrace(stackinfo.vec.len())) {
                this.event_stack.push_stacktrace(stackinfo);
                this.event_stack.push_event(kevent);
            }
        }
    }
}

impl StacktraceWork {
    /// Create a new instance ready to be enqueued on a worklist
    pub fn new(size: usize, flags: Flags, stack: Arc<EventStack>) -> Result<Arc<Self>> {
        let stacktrace = Stacktrace::new(size, flags)?;

        Arc::pin_init(
            pin_init!(StacktraceWork {
                stacktrace,
                work <- new_work!("Stacktrace::work"),
                event_stack : stack,
            }),
            flags,
        )
    }
}

/// Represent informations gathered on a single stack entry
struct StacktraceInfoEntry {
    addr: u64,
    offset: u64,
    symbol: Option<KVec<u8>>,
    module: Option<KVec<u8>>,
}
/*
impl Display for StacktraceInfoEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:x}", self.addr)?;
        if let Some(symbol) = &self.symbol {
            write!(f, " : {} + {:x}", &symbol.deref(), self.offset)?;
        }
        if let Some(module) = &self.module {
            write!(f, " [{}]", &<CString as Deref>::deref(module))?;
        }
        Ok(())
    }
}*/

impl StackEntry {
    fn from_stackinfo(entry: &StacktraceInfoEntry) -> StackEntry {
        StackEntry {
            addr: entry.addr,
            offset: entry.offset,
            name: write_to_slice(&entry.symbol),
            modname: write_to_slice(&entry.module),
        }
    }
}

/// Information of the stack trace
#[pin_data]
pub struct StacktraceInfo {
    vec: KVec<StacktraceInfoEntry>,
    #[pin]
    list_link: ListLinks<0>,
}

impl StacktraceInfo {
    /// Gather information on a collected stacktrace
    pub fn new(stack: &Stacktrace) -> Result<ListArc<Self>> {
        let mut vec = KVec::new();

        for addr in stack.iter() {
            let mut offset = 0;
            let mut symbolsize = 0;
            let (module, symbol) = symbols_lookup_address(*addr, &mut offset, &mut symbolsize)?;
            /*
            let modname = match modname {
                Some(modname) => Some(CString::try_from_fmt(fmt!(
                    "{}",
                    CStr::from_bytes_with_nul(&modname)?,
                ))?),
                None => None,
            };

            let symbol = match symbol {
                Some(symbol) => Some(CString::try_from_fmt(fmt!(
                    "{}",
                    CStr::from_bytes_with_nul(&symbol)?,
                ))?),
                None => None,
            };
            */
            vec.push(
                StacktraceInfoEntry {
                    addr: *addr,
                    offset,
                    symbol,
                    module,
                },
                GFP_KERNEL,
            )?;
        }

        ListArc::pin_init(
            try_pin_init!(StacktraceInfo {
                list_link <- ListLinks::new(),
                vec,
            }),
            GFP_KERNEL,
        )
    }

    /// Write to the user the `StacktraceInfo` converting it to a shared, serializable `StackEntry` type
    pub fn write_to_user(&self, writer: &mut UserSliceWriter) -> Result<isize> {
        for entry in &self.vec {
            writer.write(&StackEntry::from_stackinfo(entry))?;
        }
        Ok((core::mem::size_of::<StackEntry>() * self.vec.len()) as isize)
    }
}

impl_has_list_links!(impl HasListLinks for StacktraceInfo {self.list_link});
impl_list_item!(impl ListItem<0> for StacktraceInfo { using ListLinks; });
impl_list_arc_safe!(impl ListArcSafe<0> for StacktraceInfo { untracked; });
