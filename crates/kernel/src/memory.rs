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

/// A page-aligned physical range the bootstrap must never hand out.
#[derive(Clone, Copy, Debug)]
pub struct Reserved {
    /// First byte of the range.
    pub start: u64,
    /// Length of the range in bytes.
    pub length: u64,
}

impl Reserved {
    /// Whether `frame` falls inside the range.
    pub fn contains(&self, frame: u64) -> bool {
        frame >= self.start && frame - self.start < self.length
    }
}

/// Fill the process-wide pool from every usable frame that is not reserved.
///
/// Memory the boot code is still using, above all its own stack, must never enter
/// the pool: a frame handed out twice would be zeroed under the running code and
/// silently corrupt it, which is exactly how a boot dies far from the cause.
pub fn fill<const R: usize, const S: usize>(
    pool: &mut KernelFrames,
    map: &MemoryMap<R>,
    reserved: &[Reserved; S],
) -> Result<(), wuxia_core::Error> {
    let mask = wuxia_core::paging::PAGE_SIZE - 1;
    for region in map.iter() {
        let start = region
            .start
            .checked_add(mask)
            .ok_or(wuxia_core::Error::OutOfRange)?
            & !mask;
        let end = region
            .start
            .checked_add(region.length)
            .ok_or(wuxia_core::Error::OutOfRange)?
            & !mask;
        let mut frame = start;
        while frame < end {
            if !reserved.iter().any(|range| range.contains(frame)) {
                pool.push(frame)?;
            }
            frame += wuxia_core::paging::PAGE_SIZE;
        }
    }
    Ok(())
}

/// The pool capacity used by the bootstrap.
pub type KernelFrames = FramePool<65536>;

/// The one pool of free frames, kept in the kernel image rather than on the stack.
///
/// A pool this large must not live on the boot stack: its own frames would then be
/// candidates for allocation, and the first time one was handed out the pool would
/// be zeroed underneath the running boot code.
static mut POOL: KernelFrames = KernelFrames::new();

/// The process-wide frame pool.
///
/// # Safety
///
/// The returned borrow must not overlap any other use of the pool. The bootstrap
/// thread fills it and then hands frames to the loaders; from ring 3 onward only
/// [`allocate_frame`] and [`with_pool`] touch it, one call at a time.
pub fn pool() -> &'static mut KernelFrames {
    // SAFETY: the pool is a single static and callers use it sequentially.
    unsafe { &mut *core::ptr::addr_of_mut!(POOL) }
}

/// Take a frame from the installed pool.
pub fn allocate_frame() -> Option<u64> {
    pool().allocate()
}

/// Run `operation` with exclusive access to the installed pool.
pub fn with_pool<R>(operation: impl FnOnce(&mut KernelFrames) -> R) -> Option<R> {
    Some(operation(pool()))
}

/// Return a frame to the installed pool.
pub fn free_frame(frame: u64) -> Result<(), wuxia_core::Error> {
    pool().free(frame)
}
