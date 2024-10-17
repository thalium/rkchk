//! Events that can be registered by the rootkit_detection module (aka rkchk)

/// Size of the strings in the events info structure
pub const SIZE_STRING: usize = 100;

/// Maximum size of the module name string
pub const MODULE_NAME_SIZE: usize = 56;

/// Info of a loaded Kernel Module
#[repr(C)]
pub struct LoadedLKMInfo {
    /// hash of the module's text
    pub hash: u64,
    /// name of the module
    pub name: [u8; MODULE_NAME_SIZE],
}
/// Type of a function
#[repr(C)]
pub enum FunctionPointerType {
    /// Syscall table entry
    Syscall,
    /// Other
    Other,
}

/// Info about an fonction pointer hijack
#[repr(C)]
pub struct IndirectCallHijackInfo {
    /// Type of fct pointer hijacked
    pub ptr_type: FunctionPointerType,
}

/// Info about a module found
#[repr(C)]
pub struct ModuleInfo {
    /// Name of the module concerned
    pub name: [u8; MODULE_NAME_SIZE],
}

/// Type of event that can be triggered
#[repr(C)]
pub enum Events {
    /// No event
    NoEvent,
    /// A Module kernel has been loaded
    LoadedLKM(LoadedLKMInfo),
    /// A fonction pointer has been hijacked
    IndirectCallHijack(IndirectCallHijackInfo),
    /// An inconsistency in the structures used to store the module has been detected
    ModuleInconsistency(ModuleInfo),
    /// An address coming from a module was found
    ModuleAddress(ModuleInfo),
    /// An hidden module was detected
    HiddenModule,
}
