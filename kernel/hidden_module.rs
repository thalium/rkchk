//! Search for hidden modules using bruteforce
//!
//! Inspired by : https://phrack.org/issues/71/12

use core::ffi::CStr;

use kernel::bindings::{p4d_t, pgd_t, pmd_t, pte_t, pud_t};

use kernel::{current, pr_err, pr_info};

fn is_in_module_space(addr: u64) -> bool {
    // SAFETY: This function is always safe to call
    addr > unsafe { kernel::bindings::modules_vaddr() }
        // SAFETY: This function is always safe to call
        && addr < unsafe { kernel::bindings::modules_end() }
}

/// A iterator over all the valid place where we can find
/// a `struct module`
///
/// # Invariant
///     The pointer yielded are non null, valid and
pub struct ModuleAddressIter {
    end: u64,
    cursor: u64,
}

impl ModuleAddressIter {
    pub fn new() -> Self {
        ModuleAddressIter {
            // SAFETY: This function is always safe to call
            end: unsafe { kernel::bindings::modules_end() },
            // Invariant: the address returned is aligned to a page so aligned to a `module`
            // SAFETY: This function is always safe to call
            cursor: unsafe { kernel::bindings::modules_vaddr() },
        }
    }
}

fn is_valid_addr_range(addr: u64, end: u64) -> bool {
    if addr > end {
        return true;
    }

    let mut level: u32 = 0;
    let top_pat = unsafe { kernel::bindings::lookup_address(addr, &mut level as _) };

    if top_pat.is_null() {
        return false;
    }

    if unsafe {
        match level {
            kernel::bindings::pg_level_PG_LEVEL_4K => kernel::bindings::pte_present(*top_pat),
            kernel::bindings::pg_level_PG_LEVEL_2M => {
                kernel::bindings::pmd_present(*(top_pat as *mut pmd_t))
            }
            kernel::bindings::pg_level_PG_LEVEL_1G => {
                kernel::bindings::pud_present(*(top_pat as *mut put_t))
            }
            kernel::bindings::pg_level_PG_LEVEL_512G => {
                kernel::bindings::p4d_present(*(top_pat as *mut p4d_t))
            }
            kernel::bindings::pg_level_PG_LEVEL_256T => {
                kernel::bindings::pgd_present(*(top_pat as *mut pgd_t))
            }
            _ => {
                pr_err!("Couldn't match a level\n");
                return false;
            }
        }
    } == 0
    {
        return false;
    }

    let new_addr = ((addr >> kernel::bindings::PAGE_SHIFT) + 1) << kernel::bindings::PAGE_SHIFT;

    is_valid_addr_range(new_addr, end)
}

impl Iterator for ModuleAddressIter {
    type Item = *const kernel::bindings::module;
    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.end {
            return None;
        }

        loop {
            let end_cursor = match self
                .cursor
                .checked_add(size_of::<kernel::bindings::module>() as u64)
            {
                None => return None,
                Some(val) => val,
            };

            if is_valid_addr_range(self.cursor, end_cursor) {
                break;
            }

            self.cursor = match self
                .cursor
                .checked_add(align_of::<kernel::bindings::module>() as u64)
            {
                None => return None,
                Some(val) => val,
            };
        }

        // Invariant : We have that the pointer is well aligned, non null and valid by the above check
        let ret = Some(self.cursor as *const kernel::bindings::module);
        self.cursor = match self
            .cursor
            .checked_add(align_of::<kernel::bindings::module>() as u64)
        {
            None => return None,
            Some(val) => val,
        };
        ret
    }
}

pub fn detect_stray_struct_module() {
    let iter = ModuleAddressIter::new();
    pr_info!("We search for module\n");
    for addr in iter {
        let mut score = 0;

        // We check the `state` field and it's possible value
        let state = unsafe { *addr }.state;
        if state == kernel::bindings::module_state_MODULE_STATE_LIVE
            || state == kernel::bindings::module_state_MODULE_STATE_COMING
            || state == kernel::bindings::module_state_MODULE_STATE_GOING
            || state == kernel::bindings::module_state_MODULE_STATE_UNFORMED
        {
            score += 1;
        }

        // We check the `exit` and `init` field, the possible values are :
        // - Null
        // - Address in the module's address space
        let exit = unsafe { *addr }.exit;
        if let Some(f) = exit {
            if is_in_module_space(f as u64) {
                score += 1;
            }
        } else {
            score += 1;
        }
        let init = unsafe { *addr }.init;
        if let Some(f) = init {
            if is_in_module_space(f as u64) {
                score += 1;
            }
        } else {
            score += 1;
        }

        // We check the `name` field property :
        // - String length is not null and inferior to `MODULE_NAME_LEN`
        if let Ok(name_ptr) = CStr::from_bytes_until_nul(
            unsafe { *(&(*addr).name as *const [i8; 56] as *const [u8; 56]) }.as_slice(),
        ) {
            let str_len = name_ptr.count_bytes();
            if str_len > 0 && str_len < 56 {
                score += 1
            }
        }

        let core_layout_size =
            unsafe { *addr }.mem[kernel::bindings::mod_mem_type_MOD_TEXT as usize].size;
        if core_layout_size != 0 && (core_layout_size as usize) % kernel::bindings::PAGE_SIZE == 0 {
            score += 1
        }

        if score >= 3 {
            pr_info!(
                "We found a module, score {}, name : {:?}",
                score,
                CStr::from_bytes_until_nul(
                    unsafe { *(&(*addr).name as *const [i8; 56] as *const [u8; 56]) }.as_slice(),
                )
            );
        }
    }
}
