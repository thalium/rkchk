// SPDX-License-Identifier: GPL-2.0

//! The response part of rkchk

use kernel::{
    c_str,
    module::symbols_lookup_name,
    page, pr_info,
    prelude::{EINVAL, GFP_KERNEL},
};

use kernel::error::Result;
/// Represent a copy of a kernel text page
pub struct KernelTextPage {
    _page: page::Page,
}

impl KernelTextPage {
    /// Copy the kernel page containing the text of the page
    pub fn copy_center_page() -> Result<KernelTextPage> {
        let order = 9;
        let n_pages = (2usize).pow(order);
        let n_bytes = page::PAGE_SIZE * n_pages;

        let _page = page::Page::alloc_pages(GFP_KERNEL, order)?;

        let address: usize = symbols_lookup_name(c_str!("__x64_sys_delete_module")) as _;

        let address = page::page_align_down(address, n_bytes) as *const u8;

        if address.is_null() {
            return Err(EINVAL);
        }

        // SAFETY : We read from the kernel text directly, and experience show
        // that an order 9 allocation fit in the kernel text page
        // TODO : Verify this using page table walking
        unsafe { _page.write_raw_multiple(address, 0, n_bytes)? };

        Ok(KernelTextPage { _page })
    }
}
