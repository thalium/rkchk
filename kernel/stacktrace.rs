use kernel::{
    alloc::Flags,
    error::Result,
    impl_has_work,
    init::InPlaceInit,
    list::List,
    macros::pin_data,
    new_work, pin_init,
    stacktrace::{self, Stacktrace},
    sync::{Arc, SpinLock},
    uaccess::UserSliceWriter,
    workqueue::WorkItem,
};

use crate::EventStack;

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
            this.event_stack.push_stacktrace(stackinfo);
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
    symbol: Option<CString>,
    module: Option<CString>,
}

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
}

impl StackEntry {
    pub fn from_stackinfo(entry: &StacktraceInfoEntry) -> StackEntry {
        StackEntry {
            addr: entry.addr,
            offset: entry.offset,
            name: if let Some(symbol) = entry.symbol {
                let name = [0; SIZE_STRING];
                for (i, e) in symbol.as_bytes().iter().enumerate() {
                    if let Some(c) = name.get_mut(i) {
                        *c = e;
                    } else {
                        break;
                    }
                }
                Some(name)
            } else {
                None
            },
            modname: if let Some(module) = entry.module {
                let modname = [0; SIZE_STRING];
                for (i, e) in module.as_bytes().iter().enumerate() {
                    if let Some(c) = modname.get_mut(i) {
                        *c = e;
                    } else {
                        break;
                    }
                }
                Some(modname)
            } else {
                None
            },
        }
    }
}

/// Information of the stack trace
pub struct StacktraceInfo {
    vec: KVec<StacktraceInfoEntry>,
    #[pin]
    list_link: ListLinks<0>,
}

impl StacktraceInfo {
    /// Gather information on a collected stacktrace
    pub fn new(stack: &Stacktrace) -> Result<ListArc<Self>> {
        let mut vec = KVec::new();

        for addr in stack.into_iter() {
            let mut offset = 0;
            let mut symbolsize = 0;
            let (modname, symbol) = symbols_lookup_address(addr, &mut offset, &mut symbolsize)?;

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

            vec.push(
                StacktraceInfoEntry {
                    addr,
                    offset,
                    symbol,
                    module: modname,
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

    pub fn write_to_user(&self, writer: &mut UserSliceWriter) -> Result<isize> {
        for entry in &self.vec {
            writer.write(&StackEntry::from_stackinfo(entry))?;
        }
        Ok((core::mem::size_of::<StackEntry>() * stacktrace.vec.len()) as isize)
    }
}

impl IntoIterator for StacktraceInfo {
    type Item = StacktraceInfoEntry;
    type IntoIter = IntoIter<StacktraceInfoEntry, Kmalloc>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl_has_list_links!(impl HasListLinks for StasktraceInfo {self.list_link});
impl_list_item!(impl ListItem<0> for StacktraceInfo { using ListLinks; });
impl_list_arc_safe!(impl ListArcSafe<0> for StacktraceInfo { untracked });
