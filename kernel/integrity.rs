// SPDX-License-Identifier: GPL-2.0

//! Rust character device sample.
use core::hash::Hash;
use core::hash::Hasher;
use core::iter::Iterator;
use core::mem;
use core::result::Result::Err;
use core::result::Result::Ok;
use core::slice;
use core::str;
use kernel::bindings;
use kernel::c_str;
use kernel::error::Result;
use kernel::module::symbols_lookup_name;
use kernel::prelude::*;
use kernel::str::CStr;
use kernel::str::CString;
use kernel::sync::Arc;

use kernel::insn;
use kernel::module;
use kernel::types::ARef;
use kernel::uaccess::UserSliceWriter;

use crate::event;
use crate::fx_hash;
use crate::monitoring::check_address_consistency;
use crate::EventStack;
use crate::KEvents;

/// The maximum number of byte we saved for a given function
const MAX_SAVED_SIZE: usize = 4096;
/// The number of syscall on my computer
const NB_SYCALLS: usize = 332;

/// Write Protect : the CPU cannot write ro page in ring 0
const CR0_WP: u64 = 1 << 16;
/// User-Mode Instruction Prevention : block the usage of some instructions in user mode
const CR4_UMIP: u64 = 1 << 16;
/// Supervisor Mode Access Execution Protection Enable
const CR4_SMEP: u64 = 1 << 20;
/// Supervisor Mode Access Prevention Enable
const CR4_SMAP: u64 = 1 << 21;

/// Some x86 opcode

/// Jump
const X86_OP_JMP: i32 = 0xE9;
/// Breakpoint
const X86_OP_BP: i32 = 0xCC;

/// Structure used to run integrity check on CPU's MSR
/// See `check_pinned_cr_bits` and `check_msr_star` for more
/// information
pub struct MSRIntegrity {
    events: Arc<EventStack>,
}

impl MSRIntegrity {
    fn init(events: Arc<EventStack>) -> Result<Self> {
        Ok(MSRIntegrity { events })
    }

    /// Check that the following bits are set in CR4 and CR0 MSR:
    /// - CR4:SMAP
    /// - CR4:SMEP
    /// - CR4:UMIP
    /// - CR0:WP
    #[cfg(target_arch = "x86_64")]
    pub fn check_pinned_cr_bits(&self) -> Result {
        use core::arch::asm;

        let cr_4: u64;

        // SAFETY: CR4 register always exist on x86_64
        unsafe {
            asm!("mov {cr_4}, cr4", cr_4 = out(reg) cr_4);
        }

        if (cr_4 & CR4_SMAP == 0) || (cr_4 & CR4_SMEP == 0) || (cr_4 & CR4_UMIP == 0) {
            self.events
                .push_event(KEvents::new(event::Events::TamperedMSR)?);
            //pr_alert!("Invariant bit in CR4 = {:#016x}\n", cr_4);
        }

        let cr_0: u64;

        // SAFETY: CR0 register always exist on x86_64
        unsafe {
            asm!("mov {cr_0}, cr0", cr_0 = out(reg) cr_0);
        }

        if cr_0 & CR0_WP == 0 {
            self.events
                .push_event(KEvents::new(event::Events::TamperedMSR)?);
            //pr_alert!("Invariant bit in CR0 = {:#016x}\n", cr_0);
        }

        Ok(())
    }

    /// Check if the MSR LSTAR register (used to setup the address to jump to in case of long mode syscall)
    /// is set to the right symbol (see the function `syscall_init` in arch/x86/kernel/cpu/common.c)
    #[cfg(target_arch = "x86_64")]
    pub fn check_msr_lstar(&self) -> Result {
        use core::arch::asm;

        let lstar: u64;
        let lstar_nb: u32 = bindings::MSR_LSTAR;

        // SAFETY: lstar register exist on x86_64 processor
        // `rdmsr` store the 64 bit value in edx:eax
        // The high order bit of rax, rdx are cleared by rdmsr so we can `OR`` the two
        unsafe {
            asm!("rdmsr",
                "shl rdx, 32",
                "or rax, rdx", 
                in("ecx") lstar_nb,
                out("rax") lstar,
                out("rdx") _);
        }

        // `entry_SYSCALL_64` is the function the LSTAR register is set at boot time
        let entry_syscall_64 = symbols_lookup_name(c_str!("entry_SYSCALL_64"));

        // Checking the integrity of the register
        if lstar != entry_syscall_64 {
            self.events
                .push_event(KEvents::new(event::Events::TamperedMSR)?);
            //pr_alert!("MSR LSTAR register (syscall jump address) not set to the right symbol\n");
        }

        Ok(())
    }
}

/// Structure used to run integrity check on the syscall table
/// # Note:
///     The syscall table is no longer used from kernel 6.9 onward
///     , but the symbol still exist because it's still used notably by tracepoints
pub struct SyscallIntegrity {
    events: Arc<EventStack>,
}

impl SyscallIntegrity {
    fn init(events: Arc<EventStack>) -> Result<Self> {
        Ok(SyscallIntegrity { events })
    }

    /// For each entry in the syscall table check that the address isn't in a module or in an undefined space
    /// Works only if the module that hijacked the syscalls is still in the `mod_tree` structure
    pub fn check_syscall_position(&self) -> Result {
        pr_info!("Checking for syscalls table integrity\n");
        let addr_sys_table = symbols_lookup_name(c_str!("sys_call_table"));

        static_assert!(
            ((NB_SYCALLS * mem::size_of::<bindings::sys_call_ptr_t>()) as u128)
                < (isize::MAX as u128)
        );

        // SAFETY:
        // 1- The object we manipulate is cthe sycall_table so it won't be deallocated
        // 2- addr is non null and aligned
        // 3- from addr to addr+NB_SYSCALL the memory is valid and readable because it is the syscall_table
        // 4- The slice is non mutable so it will not be mutated
        // 5- NB_SYSCALLS * mem::size_of::<sys_call_ptr_t>() < isize::MAX
        let sys_call_table =
            unsafe { slice::from_raw_parts(addr_sys_table as *const u64, NB_SYCALLS) };

        for syscall in sys_call_table {
            if let Some(event) = check_address_consistency(*syscall)? {
                self.events
                    .push_event(KEvents::new(event::Events::IndirectCallHijack(
                        event::IndirectCallHijackInfo {
                            ptr_type: event::FunctionPointerType::Syscall,
                        },
                    ))?);
                self.events.push_event(KEvents::new(event)?);
            }
        }
        Ok(())
    }
}

/// Check that some function (statically defined)
/// are not tampered with by calculating the hash of their text regularly
pub struct FunctionIntegrity {
    events: Arc<EventStack>,
    saved_function: KVec<(CString, u64)>,
}

impl FunctionIntegrity {
    fn init(events: Arc<EventStack>) -> Result<Self> {
        let mut fct_integ = FunctionIntegrity {
            saved_function: KVec::new(),
            events,
        };

        fct_integ.save_function(c_str!("ip_rcv"))?;
        fct_integ.save_function(c_str!("tcp4_seq_show"))?;
        fct_integ.save_function(c_str!("__x64_sys_getdents"))?;
        fct_integ.save_function(c_str!("__x64_sys_getdents64"))?;
        fct_integ.save_function(c_str!("__x64_sys_kill"))?;

        Ok(fct_integ)
    }

    /// Return the hash calculated off the text's byte of the function
    /// Calculate the hash from at max the MAX_SAVED_SIZE first bytes
    fn get_function_hash(&self, name: &CStr) -> Result<u64> {
        let addr = module::symbols_lookup_name(name);

        if addr == 0 as u64 {
            pr_info!("Invalid address lookup\n");
            return Err(EINVAL);
        }

        let (mut symbolsize, offset) = module::symbols_lookup_size_offset(addr);

        if offset != 0 {
            pr_info!("Invalid offset, (weird) : {}\n", offset);
            return Err(EINVAL);
        }

        static_assert!(((MAX_SAVED_SIZE * mem::size_of::<u8>()) as u128) < (isize::MAX as u128));

        if symbolsize > MAX_SAVED_SIZE {
            symbolsize = MAX_SAVED_SIZE;
        }

        // SAFETY:
        // 1- The object we manipulate is code so it should not be deallocated, except if the module we look at is unloaded (TODO : find a way to ensure that the module is not unloaded)
        // 2- addr is non null and aligned (because we ask for 1 byte data)
        // 3- from addr to addr+symbolsize the memory is valid and readable (in the kernel or a module)
        // 4- The slice is non mutable so it will not be mutated
        // 5- symbolsize <= MAX_SAVED_SIZE < mem::size_of::<u8>() * isize::MAX
        let tab: &[u8] = unsafe { slice::from_raw_parts(addr as *const u8, symbolsize as usize) };

        let mut hasher = fx_hash::FxHasher::default();

        tab.hash(&mut hasher);

        Ok(hasher.finish())
    }

    /// Save the function's text bytes in the struct's `saved_function` field
    fn save_function(&mut self, name: &CStr) -> Result {
        let hash = self.get_function_hash(name)?;

        self.saved_function
            .push((name.to_cstring()?, hash), GFP_KERNEL)?;

        Ok(())
    }

    /// Iter through all the saved functions.
    /// Get the current text's hash and compare it with the saved one.
    pub fn check_functions(&self) -> Result<()> {
        //pr_info!("Checking for function integrity\n");
        for (name, hash) in &self.saved_function {
            let new_hash = self.get_function_hash(&name)?;
            if new_hash != *hash {
                let mut buf = [0 as u8; event::SIZE_STRING];
                for (i, e) in name.as_bytes().iter().enumerate() {
                    let b = match buf.get_mut(i) {
                        None => break,
                        Some(b) => b,
                    };
                    *b = *e;
                }
                let event = event::Events::TamperedFunction(event::FunctionInfo { name: buf });
                self.events.push_event(KEvents::new(event)?);
            }
        }
        Ok(())
    }
}

/// Used to run check on statically saved function
/// to see if their flow isn't hijacked
pub struct CFIntegrity {
    events: Arc<EventStack>,
    checked_function: KVec<&'static CStr>,
}

impl CFIntegrity {
    /// Create a new instance of the structure
    fn init(events: Arc<EventStack>) -> Result<Self> {
        let mut checked_function = KVec::new();
        checked_function.push(c_str!("ip_rcv"), GFP_KERNEL)?;
        checked_function.push(c_str!("tcp4_seq_show"), GFP_KERNEL)?;
        Ok(CFIntegrity {
            checked_function,
            events,
        })
    }

    /// Check the first instruction of the function "name" to see if it isn't hooked.
    /// The check consist to see if this instruction isn't a breakpoint or a jump
    pub fn check_custom_hook(&self) -> Result {
        //pr_info!("Checking for custom hook\n");
        for fct_name in &self.checked_function {
            let addr = module::symbols_lookup_name(fct_name);

            // SAFETY:
            // 1- The object we manipulate is code so it should not be deallocated, except if the module we look at is unloaded (TODO : find a way to ensure that the module is not unloaded)
            // 2- addr is non null and aligned (because we ask for 1 byte data)
            // 3- We assume that from addr to addr+15 the memory is valid and readable (the disassembler should read only one instruction and nothing more so it isn't a problem)
            // 4- The slice is non mutable so it will not be mutated
            // 5- 15 < mem::size_of::<u8>() * isize::MAX
            let tab: &[u8] = unsafe { slice::from_raw_parts(addr as *const u8, 15 as usize) };

            let mut diss = insn::Insn::new(tab);

            let opcode = diss.get_opcode()?;

            if opcode == X86_OP_BP || opcode == X86_OP_JMP {
                /*pr_alert!(
                    "Function : {} probably hooked using opcode {:#02x}\n",
                    fct_name,
                    opcode
                );*/
                let mut buf = [0 as u8; event::SIZE_STRING];
                for (i, e) in fct_name.as_bytes().iter().enumerate() {
                    let b = match buf.get_mut(i) {
                        None => break,
                        Some(b) => b,
                    };
                    *b = *e;
                }

                let event = event::Events::HookedFunction(event::FunctionInfo { name: buf });
                self.events.push_event(KEvents::new(event)?);
            }
        }
        Ok(())
    }
}
/// Fill the user buffer with the list of all the pid
pub fn fill_pid_list(buffer: &mut UserSliceWriter) -> Result<usize> {
    let current = ARef::from(current!());
    let mut nb = 0;

    for task in current {
        buffer.write::<bindings::pid_t>(&task.tgid_nr_ns(None))?;
        nb += 1;
    }
    Ok(nb)
}
/// Return the number of tasks struct running in the kernel
pub fn number_tasks() -> usize {
    let current = ARef::from(current!());
    current.into_iter().count()
}

/// Hold all the instance of the structures used to
/// run integrity check in the kernel
pub struct IntegrityCheck {
    /// Function integrity
    pub function_integ: FunctionIntegrity,
    /// Syscall integrity
    pub syscall_integ: SyscallIntegrity,
    /// MSR integrity
    pub msr_integ: MSRIntegrity,
    /// CFI Integrity
    pub cf_integ: CFIntegrity,
}

impl IntegrityCheck {
    /// Create a new instance
    pub fn init(events: Arc<EventStack>) -> Result<Self> {
        Ok(IntegrityCheck {
            function_integ: FunctionIntegrity::init(events.clone())?,
            syscall_integ: SyscallIntegrity::init(events.clone())?,
            msr_integ: MSRIntegrity::init(events.clone())?,
            cf_integ: CFIntegrity::init(events.clone())?,
        })
    }
}
