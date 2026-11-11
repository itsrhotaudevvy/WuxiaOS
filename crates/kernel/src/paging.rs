//! Bootstrap page-table construction over Limine's higher-half direct map.
//!
//! This builds a four-level hierarchy for one user page and walks it back to
//! prove every entry is reachable. It does not load CR3: the active
//! bootloader tables stay in place until the kernel owns its own mapping.

use wuxia_core::Error;
use wuxia_core::hhdm::DirectMap;
use wuxia_core::paging::{
    ENTRIES_PER_TABLE, PagePermissions, PageTableReader, leaf, table_entry, table_index, walk,
};
use wuxia_core::region::BumpAllocator;

/// A user virtual address used to exercise the bootstrap hierarchy.
pub const TEST_VIRTUAL_ADDRESS: u64 = 0x0040_0000;

/// The verified root and leaf produced by [`build`].
#[derive(Clone, Copy, Debug)]
pub struct BootstrapTables {
    /// Physical address of the new PML4.
    pub pml4: u64,
    /// Physical address of the populated page table.
    pub page_table: u64,
    /// The encoded leaf entry written for the test address.
    pub leaf_entry: u64,
}

/// Allocate and zero four frames, link them, and verify the resulting walk.
pub fn build<const N: usize>(
    allocator: &mut BumpAllocator<N>,
    direct_map: DirectMap,
    virtual_address: u64,
    physical_address: u64,
) -> Result<BootstrapTables, Error> {
    let pml4 = allocator.allocate_frame().ok_or(Error::TableFull)?;
    let pdpt = allocator.allocate_frame().ok_or(Error::TableFull)?;
    let pd = allocator.allocate_frame().ok_or(Error::TableFull)?;
    let pt = allocator.allocate_frame().ok_or(Error::TableFull)?;
    for frame in [pml4, pdpt, pd, pt] {
        zero_frame(direct_map, frame)?;
    }

    let index0 = table_index(virtual_address, 0)?;
    let index1 = table_index(virtual_address, 1)?;
    let index2 = table_index(virtual_address, 2)?;
    let index3 = table_index(virtual_address, 3)?;

    write_entry(frame_pointer(direct_map, pml4)?, index0, table_entry(pdpt, true)?);
    write_entry(frame_pointer(direct_map, pdpt)?, index1, table_entry(pd, true)?);
    write_entry(frame_pointer(direct_map, pd)?, index2, table_entry(pt, true)?);
    let leaf_value = leaf(
        virtual_address,
        physical_address,
        PagePermissions::USER_READ_ONLY,
    )?;
    write_entry(frame_pointer(direct_map, pt)?, index3, leaf_value);

    verify(
        direct_map,
        pml4,
        virtual_address,
        leaf_value,
    )?;

    Ok(BootstrapTables {
        pml4,
        page_table: pt,
        leaf_entry: leaf_value,
    })
}

/// Walk the hierarchy through the direct map and confirm it resolves.
fn verify(
    direct_map: DirectMap,
    pml4: u64,
    virtual_address: u64,
    expected_leaf: u64,
) -> Result<(), Error> {
    let reader = DirectMapReader { direct_map };
    if walk(&reader, pml4, virtual_address)? != expected_leaf {
        return Err(Error::InvalidState);
    }
    Ok(())
}

/// A [`PageTableReader`] that reads physical frames through the HHDM.
struct DirectMapReader {
    direct_map: DirectMap,
}

impl PageTableReader for DirectMapReader {
    fn read_entry(&self, table_frame: u64, index: usize) -> u64 {
        match frame_pointer(self.direct_map, table_frame) {
            Ok(pointer) => read_entry(pointer, index),
            Err(_) => 0,
        }
    }
}

fn zero_frame(direct_map: DirectMap, frame: u64) -> Result<(), Error> {
    let pointer = frame_pointer(direct_map, frame)?;
    for index in 0..ENTRIES_PER_TABLE {
        write_entry(pointer, index, 0);
    }
    Ok(())
}

fn frame_pointer(direct_map: DirectMap, frame: u64) -> Result<*mut u64, Error> {
    let virtual_address = direct_map.physical_to_virtual(frame)?;
    Ok(virtual_address as *mut u64)
}

fn write_entry(pointer: *mut u64, index: usize, value: u64) {
    // SAFETY: the frame is a 4 KiB direct-mapped table and `index` is bounded
    // by `ENTRIES_PER_TABLE`, so the write stays inside one page.
    unsafe {
        pointer.add(index).write_volatile(value);
    }
}

fn read_entry(pointer: *const u64, index: usize) -> u64 {
    // SAFETY: the frame is a 4 KiB direct-mapped table and `index` is bounded
    // by `ENTRIES_PER_TABLE`, so the read stays inside one page.
    unsafe { pointer.add(index).read_volatile() }
}
