//! Limine physical-memory discovery.
//!
//! Pure normalization and allocation live in `wuxia-core`, where boundary
//! conditions can be tested on the host. This module only adapts the bootloader
//! response into the validated core representation.

use limine::memory_map::EntryType;

/// A normalized physical memory map used by the bootstrap allocator.
pub type MemoryMap<const N: usize> = wuxia_core::region::RegionMap<N>;

/// Convert only Limine's usable entries into normalized physical ranges.
pub fn from_limine<const N: usize>(
    response: &limine::response::MemoryMapResponse,
) -> Result<MemoryMap<N>, wuxia_core::Error> {
    let mut map = MemoryMap::<N>::new();
    for entry in response.entries().iter() {
        if entry.entry_type != EntryType::USABLE {
            continue;
        }
        let start = entry
            .base
            .checked_add(0xfff)
            .map(|base| base & !0xfff)
            .ok_or(wuxia_core::Error::OutOfRange)?;
        let end = entry
            .base
            .checked_add(entry.length)
            .map(|end| end & !0xfff)
            .ok_or(wuxia_core::Error::OutOfRange)?;
        if end > start {
            map.add(start, end - start)?;
        }
    }
    Ok(map)
}

/// A reclaimable pool of physical frames.
pub use wuxia_core::frames::FramePool;

/// The pool capacity used by the bootstrap.
pub type KernelFrames = FramePool<65536>;

static mut POOL: Option<KernelFrames> = None;

/// Publish the frame pool for post-bootstrap teardown.
pub fn install_pool(pool: KernelFrames) {
    // SAFETY: installed once after all bootstrap allocations are finished.
    unsafe {
        *core::ptr::addr_of_mut!(POOL) = Some(pool);
    }
}

/// Take a frame from the installed pool.
pub fn allocate_frame() -> Option<u64> {
    // SAFETY: the pool is installed before ring 3 starts and traps do not nest.
    unsafe {
        match &mut *core::ptr::addr_of_mut!(POOL) {
            Some(pool) => pool.allocate(),
            None => None,
        }
    }
}

/// Return a frame to the installed pool.
pub fn free_frame(frame: u64) -> Result<(), wuxia_core::Error> {
    // SAFETY: the pool is installed before ring 3 starts and traps do not nest.
    unsafe {
        match &mut *core::ptr::addr_of_mut!(POOL) {
            Some(pool) => pool.free(frame),
            None => Err(wuxia_core::Error::InvalidState),
        }
    }
}

/// Build a frame pool from every page-aligned frame in the usable map.
pub fn frame_pool<const N: usize, const R: usize>(
    map: &MemoryMap<R>,
) -> Result<FramePool<N>, wuxia_core::Error> {
    let mut pool = FramePool::<N>::new();
    for region in map.iter() {
        pool.add_region(region.start, region.length)?;
    }
    Ok(pool)
}
