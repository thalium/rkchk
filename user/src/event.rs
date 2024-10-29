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

/// Info about a function found
#[repr(C)]
pub struct FunctionInfo {
    /// Name of the function concerned
    pub name: [u8; SIZE_STRING],
}

/// Information about a process
pub struct ProcessInfo {
    /// TGID of the process
    pub tgid: i32,
}
/// eBPF function capable of modifing kernel or
pub enum EBPFFuncType {
    /// Function usable in KPROBE type of program
    /// that can ovveride the return of the hooked function
    OverrideReturn,
    /// Allow to write arbitrary data into an userspace buffer
    WriteUser,
}
/// Info
pub struct HiddenFileInfo {
    /// Expected size
    pub normal_size: u16,
    /// Gotten size
    pub d_reclen: u16,
}

/// Info about a function being analysed by the verifier
pub struct EBPFFuncInfo {
    /// TGID of the program that called he verifier
    pub tgid: i32,
    /// Suspicious function that was called
    pub func_type: EBPFFuncType,
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
    /// Hooked function was detected
    HookedFunction(FunctionInfo),
    /// Function whose code has been modified was detected
    TamperedFunction(FunctionInfo),
    /// An MSR (CR0 or CR4 or LSTAR) was tampered with
    TamperedMSR,
    /// Standard output or standard input is being mapped to a socket
    StdioToSocket(ProcessInfo),
    /// An eBPF program with a function altering user or kernel memory
    /// function is being loaded
    EBPFFunc(EBPFFuncInfo),
    /// An hidden file has been found
    HiddenFile(HiddenFileInfo),
}
