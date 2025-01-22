//! Gather the information on inline hooks

use core::{ops::Range, slice};

use kernel::{
    alloc::KVec,
    error::Result,
    impl_has_list_links, impl_list_arc_safe, impl_list_item, insn,
    list::{ListArc, ListLinks},
    macros::pin_data,
    module::symbols_lookup_address,
    prelude::GFP_KERNEL,
    try_pin_init,
    uaccess::UserSliceWriter,
};

use crate::{event, write_to_slice, InlineHookInfo};

/// The maximum size of an instruction on AMD64
pub const MAX_INSTR_SIZE: usize = 15;

/// Hold information on a single InlineHook
#[pin_data]
pub struct InlineHook {
    symbol: Option<KVec<u8>>,
    offset: u64,
    modname: Option<KVec<u8>>,
    opcode: [u8; MAX_INSTR_SIZE],
    opcode_len: u64,
    addr: u64,
    #[pin]
    list_link: ListLinks<0>,
}

impl_has_list_links!(impl HasListLinks for InlineHook { self.list_link });
impl_list_item!(impl ListItem<0> for InlineHook { using ListLinks; });
impl_list_arc_safe!(impl ListArcSafe<0> for InlineHook { untracked; });

impl InlineHook {
    /// Create a vector of InlineHookInfo from a vector of addresses
    pub fn from_addr(addrs: KVec<*const u8>) -> Result<KVec<ListArc<Self>>> {
        let mut last_range: Range<usize> = 0..0;
        let mut ret = KVec::new();

        for addr in addrs {
            if last_range.contains(&(addr as usize)) {
                continue;
            }
            let mut offset = 0;
            let mut symbolsize = 0;
            let (modname, symbolname) =
                symbols_lookup_address(addr as u64, &mut offset, &mut symbolsize)?;

            // SAFETY: This is a pointer to kernel text so it's valid for 15 byte I hope
            let buf = unsafe { slice::from_raw_parts(addr, 15) };

            let mut insn = insn::Insn::new(buf);

            let length = insn.get_length()?;

            last_range = (addr as usize)..((addr as usize) + (length as usize));

            let mut opcode: [u8; 15] = [0; 15];
            opcode.copy_from_slice(buf);

            /*for i in 0..length {
                *opcode.get_mut(i).unwrap() = unsafe { *((addr + i as u64) as *const u8) };
            }*/

            ret.push(
                ListArc::pin_init(
                    try_pin_init!(InlineHook {
                        symbol: symbolname,
                        modname: modname,
                        offset: offset,
                        addr: addr as u64,
                        opcode: opcode,
                        opcode_len: length as u64,
                        list_link <- ListLinks::new(),
                    }),
                    GFP_KERNEL,
                )?,
                GFP_KERNEL,
            )?;
        }
        Ok(ret)
    }

    /// Write an inline hook to user provided buffer
    pub fn write_to_user(&self, writer: &mut UserSliceWriter) -> Result<isize> {
        let hook = event::ioctl::InlineHookInfo {
            name: write_to_slice(&self.symbol),
            offset: self.offset,
            modname: write_to_slice(&self.modname),
            addr: self.addr,
            opcode: self.opcode,
            opcode_len: self.opcode_len,
        };
        writer.write(&hook)?;
        Ok(size_of::<InlineHookInfo>() as isize)
    }
}
