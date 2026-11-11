//! Limine physical-memory discovery and a bootstrap bump allocator.
//!
//! The allocator owns normalized regions and never returns a frame twice. It
//! does not support freeing: reclaim requires per-frame ownership tracking.

use limine::memory_map::EntryType;

/// A page-aligned usable physical-memory region.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UsableRegion {
    /// First usable physical address.
    pub start: u64,
    /// Number of usable bytes, always page-aligned.
    pub length: u64,
}

/// A bounded, non-overlapping collection of physical memory regions.
#[derive(Clone, Copy, Debug)]
pub struct MemoryMap<const N: usize> {
    regions: [UsableRegion; N],
    len: usize,
}

impl<const N: usize> MemoryMap<N> {
    /// Construct an empty map.
    pub const fn new() -> Self {
        Self {
            regions: [UsableRegion {
                start: 0,
                length: 0,
            }; N],
            len: 0,
        }
    }

    /// Normalize a region to complete 4 KiB pages and record it.
    pub fn add(&mut self, base: u64, length: u64) -> Result<usize, wuxia_core::Error> {
        let start = base
            .checked_add(0xfff)
            .map(|start| start & !0xfff)
            .ok_or(wuxia_core::Error::OutOfRange)?;
        let end = base
            .checked_add(length)
            .ok_or(wuxia_core::Error::OutOfRange)?
            & !0xfff;
        if self.len >= N || end <= start {
            return Err(wuxia_core::Error::InvalidInput);
        }
        let length = end - start;
        if self.regions[..self.len]
            .iter()
            .any(|region| region.start < end && start < region.start + region.length)
        {
            return Err(wuxia_core::Error::AlreadyExists);
        }
        self.regions[self.len] = UsableRegion { start, length };
        self.len += 1;
        Ok(self.len)
    }

    /// Iterate over normalized usable regions.
    pub fn iter(&self) -> impl Iterator<Item = UsableRegion> + '_ {
        self.regions[..self.len].iter().copied()
    }
}

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

/// A bootstrap allocator over validated usable regions.
///
/// Frames cannot be released during bootstrap because ownership is permanent
/// for early page tables. General reclaim requires a later per-frame manager.
#[derive(Clone, Copy, Debug)]
pub struct BumpAllocator<const N: usize> {
    regions: [UsableRegion; N],
    cursors: [u64; N],
    len: usize,
}

impl<const N: usize> BumpAllocator<N> {
    /// Take a snapshot of a normalized map without allocating memory.
    pub fn new(map: &MemoryMap<N>) -> Self {
        let mut regions = [UsableRegion {
            start: 0,
            length: 0,
        }; N];
        for (index, region) in map.iter().enumerate() {
            regions[index] = region;
        }
        Self {
            regions,
            len: map.len,
            cursors: [0; N],
        }
    }

    /// Allocate the next unique physical frame.
    pub fn allocate_frame(&mut self) -> Option<u64> {
        for index in 0..self.len {
            if self.cursors[index] < self.regions[index].length {
                let address = self.regions[index].start + self.cursors[index];
                self.cursors[index] += 4096;
                return Some(address);
            }
        }
        None
    }
}
