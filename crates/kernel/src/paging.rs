//! Bootstrap page tables: build a user subtree, clone the bootloader root and
//! switch CR3.
//!
//! Cloning the active PML4 keeps every bootloader mapping (kernel image, HHDM,
//! stack) reachable after the switch. Only one previously absent lower-half
//! slot is replaced, so the new root is a strict superset of the old one.

use core::arch::asm;

use wuxia_core::Error;
use wuxia_core::hhdm::DirectMap;
use wuxia_core::paging::{
    ENTRIES_PER_TABLE, PagePermissions, PageTableReader, is_present, leaf, table_entry, table_index,
    walk,
};
use wuxia_core::region::BumpAllocator;

/// The lowest PML4 slot considered for an isolated user mapping.
///
/// Slot zero is skipped because bootloaders commonly keep a low identity map
/// there; slots 1..=255 are the remaining lower-half user range.
const FIRST_USER_SLOT: usize = 1;
/// Slot 255 still maps below the 128 TiB user address limit.
const LAST_USER_SLOT: usize = 255;

/// Details of the installed and activated user mapping.
#[derive(Clone, Copy, Debug)]
pub struct InstalledMapping {
    /// Physical root that was active before the switch.
    pub old_pml4: u64,
    /// Physical root loaded into CR3.
    pub new_pml4: u64,
    /// Virtual address the user leaf now maps.
    pub virtual_address: u64,
    /// Encoded leaf entry written for the user page.
    pub leaf_entry: u64,
}

/// Build a user subtree, clone the active root and load the clone into CR3.
pub fn install_user_mapping<const N: usize>(
    allocator: &mut BumpAllocator<N>,
    direct_map: DirectMap,
    physical_address: u64,
) -> Result<InstalledMapping, Error> {
    let old_pml4 = read_cr3();
    let old_root = frame_pointer(direct_map, old_pml4)?;
    let slot = (FIRST_USER_SLOT..=LAST_USER_SLOT)
        .find(|index| !is_present(read_entry(old_root, *index)))
        .ok_or(Error::TableFull)?;
    let virtual_address = (slot as u64) << 39;

    let (pdpt, leaf_entry) =
        link_chain(allocator, direct_map, virtual_address, physical_address)?;

    let new_pml4 = allocator.allocate_frame().ok_or(Error::TableFull)?;
    zero_frame(direct_map, new_pml4)?;
    let new_root = frame_pointer(direct_map, new_pml4)?;
    for index in 0..ENTRIES_PER_TABLE {
        write_entry(new_root, index, read_entry(old_root, index));
    }
    write_entry(
        new_root,
        table_index(virtual_address, 0)?,
        table_entry(pdpt, true)?,
    );

    Ok(InstalledMapping {
        old_pml4,
        new_pml4,
        virtual_address,
        leaf_entry,
    })
}

/// Load a physical PML4 into CR3 and flush the non-global TLB.
pub fn activate(pml4: u64) {
    // SAFETY: `pml4` is a present, page-aligned root built by this module. The
    // new tree keeps every bootloader mapping, so the stack and kernel image
    // stay valid across the switch.
    unsafe {
        asm!("mov cr3, {}", in(reg) pml4, options(nostack, preserves_flags));
    }
}

/// Read the active page-table root, discarding PCID bits.
pub fn read_cr3() -> u64 {
    let value: u64;
    // SAFETY: reading CR3 has no side effects.
    unsafe {
        asm!("mov {}, cr3", out(reg) value, options(nostack, preserves_flags));
    }
    value & !0xfff
}

/// Resolve a user address through the currently active root.
pub fn resolve(direct_map: DirectMap, virtual_address: u64) -> Result<u64, Error> {
    let reader = DirectMapReader { direct_map };
    walk(&reader, read_cr3(), virtual_address)
}

fn link_chain<const N: usize>(
    allocator: &mut BumpAllocator<N>,
    direct_map: DirectMap,
    virtual_address: u64,
    physical_address: u64,
) -> Result<(u64, u64), Error> {
    let pdpt = allocator.allocate_frame().ok_or(Error::TableFull)?;
    let pd = allocator.allocate_frame().ok_or(Error::TableFull)?;
    let pt = allocator.allocate_frame().ok_or(Error::TableFull)?;
    for frame in [pdpt, pd, pt] {
        zero_frame(direct_map, frame)?;
    }
    write_entry(
        frame_pointer(direct_map, pdpt)?,
        table_index(virtual_address, 1)?,
        table_entry(pd, true)?,
    );
    write_entry(
        frame_pointer(direct_map, pd)?,
        table_index(virtual_address, 2)?,
        table_entry(pt, true)?,
    );
    let leaf_entry = leaf(
        virtual_address,
        physical_address,
        PagePermissions::USER_READ_ONLY,
    )?;
    write_entry(
        frame_pointer(direct_map, pt)?,
        table_index(virtual_address, 3)?,
        leaf_entry,
    );
    Ok((pdpt, leaf_entry))
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
