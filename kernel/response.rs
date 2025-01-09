// SPDX-License-Identifier: GPL-2.0

//! The response part of rkchk

use core::ffi::c_void;

use kernel::fmt;
use kernel::{
    alloc::{KVec, Vec},
    bindings,
    error::Error,
    init::PinInit,
    module::symbols_lookup_address,
    new_mutex, page,
    pgtable::{self, lookup_address, Pgtable},
    pin_init, pr_alert, pr_info,
    prelude::{pin_data, EINVAL, GFP_KERNEL},
    str::{CStr, CString},
    sync::{
        lock::{mutex::MutexBackend, Guard},
        Mutex,
    },
};

use kernel::error::Result;
/// Represent a copy of a kernel text page
///
/// # Invariant :
///     The `_page` point to the physical continuous allocation of the same order as the
///     page level of `begin_addr`'s page table
struct KernelTextPage {
    // The address of the begining of the copied kernel page
    begin_addr: usize,
    // The pfn of the original page at the switched virtual address.
    begin_pfn: u64,
    // The page pointer to the copy
    _page: page::Page,
    // Keep the switched state of the variable
    is_switched: bool,
}
// Change the pfn of the pgtable that the `vadd` points to (according to `lookup_address`),
// to `new_pfn`.
//
// # Return
//  Return the pfn that has been overwritten
//
// # Safety
//  The order of `vaddr` is the same as `new_pfn`'s order
//
unsafe fn switch(vaddr: usize, new_pfn: u64) -> Result<u64> {
    let mut pgtable = pgtable::lookup_address(vaddr)?;

    let pgprot = pgtable.pgprot();

    let old_pfn = pgtable.pfn();

    // SAFETY : According to the safety contract of the function `new_pfn` is of the same order as
    // `pgprot`'s order.
    // The call to `flush_tlb` is made below.
    unsafe { pgtable.set_pgtable(new_pfn, pgprot) };

    // SAFETY : Just an FFI call.
    unsafe { bindings::flush_tlb_each_cpu(vaddr as _) };
    Ok(old_pfn)
}

impl KernelTextPage {
    /// Copy the kernel page containing the text of the page
    fn copy_page(address: usize) -> Result<KernelTextPage> {
        let pgtable = pgtable::lookup_address(address)?;
        let order = pgtable.order();
        let n_pages = (2usize).pow(order);
        let n_bytes = page::PAGE_SIZE * n_pages;

        // We allocate `begin_addr`'s page table order physically continuous page which are correclty aligned
        // according to the `alloc_pages` guarantee
        let _page = page::Page::alloc_pages(GFP_KERNEL, order)?;

        let address = page::page_align_down(address, n_bytes) as *const u8;

        if address.is_null() {
            return Err(EINVAL);
        }

        // SAFETY : We read from the kernel text directly
        unsafe { _page.write_raw_multiple(address, 0, n_bytes)? };

        let begin_pfn = lookup_address(address as _)?.pfn();

        // `_page` fulfill the invariant guarantee of the type
        Ok(KernelTextPage {
            begin_addr: address as _,
            begin_pfn,
            _page,
            is_switched: false,
        })
    }

    fn compare_page(&self) -> Result {
        let pgtable = pgtable::lookup_address(self.begin_addr)?;
        let order = pgtable.order();
        let n_pages = (2usize).pow(order);
        let n_bytes = page::PAGE_SIZE * n_pages;

        let diffs = unsafe {
            self._page
                .compare_raw_multiple(self.begin_addr as *const u8, 0, n_bytes)
        }?;

        pr_info!(
            "We found {} difference, listing the corresponding symbols\n",
            diffs.len()
        );

        if diffs.is_empty() {
            pr_info!("Found no hook\n");
        }

        for diff in diffs {
            let mut offset = 0;
            let mut symbolsize = 0;
            let (modname, symbolname) =
                symbols_lookup_address(diff as u64, &mut offset, &mut symbolsize)?;

            let symbolname = match symbolname {
                None => CString::try_from_fmt(fmt!("{:x}", diff as usize))?,
                Some(vec) => CString::try_from_fmt(fmt!("{}", CStr::from_bytes_with_nul(&vec)?))?,
            };
            let modname = match modname {
                None => CString::try_from_fmt(fmt!("kernel"))?,
                Some(vec) => CString::try_from_fmt(fmt!("{}", CStr::from_bytes_with_nul(&vec)?))?,
            };

            pr_info!(
                "Found a hook at {} + {:x} [{}]\n",
                symbolname.to_str()?,
                offset,
                modname.to_str()?
            );
        }
        Ok(())
    }

    /// Switch between the saved page and the real page of the saved page in the page table
    fn switch(&mut self) -> Result<()> {
        // We transition from the original page to the copied page
        if !self.is_switched {
            // SAFETY : `_page` is valid due to the type invariant.
            // A call to kunmap_local is made at the end of the function
            let mapped_addr: *mut c_void =
                unsafe { bindings::kmap_local_page(self._page.as_ptr()) };
            if mapped_addr.is_null() {
                return Err(EINVAL);
            }

            let mapped_pgtable =
                pgtable::lookup_address(mapped_addr as _).or_else(|err| -> Result<_, Error> {
                    // SAFETY : `mapped_addr` is not null and we unmap in the reverse order in which we map
                    unsafe { bindings::kunmap_local(mapped_addr as _) };
                    Err(err)
                })?;

            let pfn = mapped_pgtable.pfn();

            // SAFETY : According to the type invariant `begin_addr`'s order is the same as `mapped_pgtable`'s pfn's order
            unsafe { switch(self.begin_addr, pfn) }.or_else(|err| -> Result<_, Error> {
                // SAFETY : `mapped_addr` is not null and we unmap in the reverse order in which we map
                unsafe { bindings::kunmap_local(mapped_addr as _) };
                Err(err)
            })?;

            // We don't care about the returned pfn, we can get it using the `_page` virtual address.
            // SAFETY : `mapped_addr` is not null and we unmap in the reverse order in which we map
            unsafe { bindings::kunmap_local(mapped_addr as _) };
        }
        // We transition from the copied page to the original page
        else {
            // We don't care about the returned pfn, we can get it using the `_page` virtual address.
            // SAFETY : According to type invariant `begin_addr`'s order is the same as `begin_pfn` order
            unsafe { switch(self.begin_addr, self.begin_pfn)? };
        }
        self.is_switched = !self.is_switched;
        Ok(())
    }
}

impl Drop for KernelTextPage {
    fn drop(&mut self) {
        if self.is_switched {
            match self.switch() {
                Ok(_) => (),
                Err(err) => pr_alert!("Error while switching the page {:?}", err),
            }
        }
    }
}

/// The response state of rkchk
#[pin_data]
pub struct Response {
    #[pin]
    /// The list of copied kernel text page, which can be switched to ensure the absence of
    /// rootkit inline hooks
    pub kernel_text: Mutex<KVec<KernelTextPage>>,
}

impl Response {
    /// Create a new instance
    pub fn new() -> impl PinInit<Self> {
        pin_init!(
            Response {
                kernel_text <- new_mutex!(Vec::new()),
            }
        )
    }

    /// Add copy of kernel text page to the response capabilities
    pub fn add_copy(&self, address: usize) -> Result<()> {
        let mut lock: Guard<'_, KVec<KernelTextPage>, MutexBackend> = self.kernel_text.lock();

        match lock.push(KernelTextPage::copy_page(address)?, GFP_KERNEL) {
            Ok(()) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    /// Switch a page from the saved pages
    pub fn switch_page(&self, id: usize) -> Result<()> {
        let mut lock: Guard<'_, KVec<KernelTextPage>, MutexBackend> = self.kernel_text.lock();

        let page = match lock.get_mut(id) {
            Some(e) => e,
            None => return Err(EINVAL),
        };

        page.switch()
    }

    /// Compare the differents pages
    pub fn compare_page(&self, id: usize) -> Result {
        let mut lock = self.kernel_text.lock();

        let page = match lock.get_mut(id) {
            Some(e) => e,
            None => return Err(EINVAL),
        };

        page.compare_page()
    }
}

/*
struct IsSwitched {
    // The virtual address of the beginning of the page.
    begin_addr: usize,
    // The pfn of the original page at the switched virtual address.
    begin_pfn: u64,

    is_switched: bool,
}

// To maintain invariant we need to switch the page before dropping and freeing it.
impl Drop for IsSwitched {
    fn drop(&mut self) {
        if self.is_switched {
            // SAFETY : According to type invariant `begin_addr`'s order is the same as `begin_pfn` order
            match unsafe { switch(self.begin_addr, self.begin_pfn) } {
                Ok(_) => (),
                Err(_) => pr_alert!("We couldn't switch the table"),
            }
        }
    }
}

impl IsSwitched {
    fn toogle(mut self) -> Self {
        self.is_switched = !self.is_switched;
        self
    }
}

/// Represent a kernel page that has been switch to the copy of it
///
/// # Invariant :
///     While the kernel page is switched the `_page` allocation is valid.
///     begin_pfn's order is of the same as `_page`'s virtual address's page table's order.
pub struct KernelTextPageSwitched {
    // The virtual address of the beginning of the page.
    begin_addr: usize,
    // The pfn of the original page at the switched virtual address.
    begin_pfn: u64,
    // The page containing the page structure.
    _page: page::Page,
    // Allow us to maintain invariant
    is_switched: IsSwitched,
}

impl KernelTextPageSwitched {
    /// Switch between the saved page and the real page of the saved page in the page table
    pub fn switch(self) -> Result<KernelTextPageOrig> {
        // We don't care about the returned pfn, we can get it using the `_page` virtual address.
        // SAFETY : According to type invariant `begin_addr`'s order is the same as `begin_pfn` order
        unsafe { switch(self.begin_addr, self.begin_pfn)? };

        Ok(KernelTextPageOrig {
            begin_addr: self.begin_addr,
            _page: self._page,
            is_switched: self.is_switched.toogle(),
        })
    }
}
pub enum KernelTextPage {
    Original(KernelTextPageOrig),
    Switched(KernelTextPageSwitched),
}

impl KernelTextPage {
    pub fn new(address: usize) -> Result<Self> {
        Ok(KernelTextPage::Original(KernelTextPageOrig::copy_page(
            address,
        )?))
    }

    pub fn switch(self) -> Result<Self> {
        Ok(match self {
            KernelTextPage::Original(orig) => KernelTextPage::Switched(orig.switch()?),
            KernelTextPage::Switched(switched) => KernelTextPage::Original(switched.switch()?),
        })
    }
}*/
