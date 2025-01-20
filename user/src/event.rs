//! Events that can be registered by the rootkit_detection module (aka rkchk)

/// Size of the strings in the events info structure
pub const SIZE_STRING: usize = 100;

/// Maximum size of the module name string
pub const MODULE_NAME_SIZE: usize = 56;

/// Module of the different defined ioctl number and their associated structure
pub mod ioctl {
    /// RKCHK ioctl type (aka magic number)
    pub const RKCHK_IOC_MAGIC: u32 = b'j' as u32;
    /// Run all the integrity checks (ioctl sequence number)
    pub const RKCHK_INTEG_ALL_NR: u32 = 1;
    /// Read new events (ioctl sequence number)
    pub const RKCHK_READ_EVENT_NR: u32 = 2;
    /// Read number task_struct (ioctl sequence number)
    pub const RKCHK_NUMBER_TASK_NR: u32 = 3;
    /// Read all pid (ioctl sequence number)
    pub const RKCHK_PID_LIST_NR: u32 = 4;
    /// Read all the traced functions (ioctl sequence number)
    pub const RKCHK_TRACED_LIST_NR: u32 = 5;
    /// Switch the kernel page to a saved one (ioctl sequence number)
    pub const RKCHK_SWITCH_PAGE_NR: u32 = 6;
    /// Print all the module in the linked list (ioctl sequence number)
    pub const RKCHK_REFRESH_MOD_NR: u32 = 7;
    /// Print all the inline hook detected (ioctl sequence number)
    pub const RKCHK_GET_INLINE_HOOK_NR: u32 = 8;
    /// Get a stack trace information (ioctl sequence number)
    pub const RKCHK_GET_STACKTRACE_NR: u32 = 9;
    /// Get the list of the refreshed module (ioctl sequence number)
    pub const RKCHK_GET_MOD_NR: u32 = 10;

    use crate::event::{MODULE_NAME_SIZE, SIZE_STRING};

    /// Represent a loaded LKM
    #[repr(C)]
    #[derive(Default, Clone)]
    pub struct LKM {
        /// Name of the LKM
        pub name: Option<[u8; MODULE_NAME_SIZE]>,
    }

    /// Represent a entry in the stacktrace with all the information gathered
    #[repr(C)]
    #[derive(Default, Clone)]
    pub struct StackEntry {
        /// Symbol
        pub name: Option<[u8; SIZE_STRING]>,
        /// Name of the module, `kernel` otherwise
        pub modname: Option<[u8; MODULE_NAME_SIZE]>,
        /// Addr on the stack
        pub addr: u64,
        /// Offset of the address relatively to the symbol
        pub offset: u64,
    }

    /// Represent a detected inline hook in the kernel's text and the information gathered on it
    #[repr(C)]
    #[derive(Default, Clone)]
    pub struct InlineHookInfo {
        /// Symbol
        pub name: Option<[u8; SIZE_STRING]>,
        /// Offset of the address respectivly to the symbol
        pub offset: u64,
        /// Name of the module
        pub modname: Option<[u8; MODULE_NAME_SIZE]>,
        /// Addr on the stack
        pub addr: u64,
        /// Opcode
        pub opcode: [u8; 15],
        /// Length of the opcode
        pub opcode_len: u64,
    }
}

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

#[repr(C)]
/// Information about a process
pub struct ProcessInfo {
    /// TGID of the process
    pub tgid: i32,
}
#[repr(C)]
/// eBPF function capable of modifing kernel or
pub enum EBPFFuncType {
    /// Function usable in KPROBE type of program
    /// that can ovveride the return of the hooked function
    OverrideReturn,
    /// Allow to write arbitrary data into an userspace buffer
    WriteUser,
    /// Allow to send signal to a program
    SendSignal,
}
#[repr(C)]
/// Info
pub struct HiddenFileInfo {
    /// Expected size
    pub normal_size: u16,
    /// Gotten size
    pub d_reclen: u16,
}

#[repr(C)]
/// Info about a function being analysed by the verifier
pub struct EBPFFuncInfo {
    /// TGID of the program that called he verifier
    pub tgid: i32,
    /// Suspicious function that was called
    pub func_type: EBPFFuncType,
}

/// Type of suspicious environment variable
#[repr(C)]
pub enum EnvType {
    /// LD_PRELOAD
    LDPreload,
    /// LD_LIBRARY_PATH
    LDLibraryPath,
}

/// Info about suspicious environment variable
#[repr(C)]
pub struct EnvInfo {
    /// Type
    pub env_type: EnvType,
    /// Path
    pub path: [u8; SIZE_STRING],
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
    /// A suspicious envirronement variable was found
    EnvPreload(EnvInfo),
    /// An available Stacktrace, contain the number of entry of type `StackEntry`
    Stacktrace(usize),
    /// An inline hooks has been detected, more information should be gotten using the GET_INLINE_HOOK ioctl
    InlineHookDetected,
}
