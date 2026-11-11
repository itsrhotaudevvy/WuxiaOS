//! Host-testable physical-region normalization and bootstrap allocation.
//!
//! The bump allocator never returns a frame twice and never allocates page
//! zero. It intentionally cannot free frames; early page-table ownership is
//! permanent for the lifetime of bootstrap.

use crate::{Error, Result};

/// Physical page size used by the initial x86_64 allocator.
pub const FRAME_SIZE: u64 = 4096;

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
pub struct RegionMap<const N: usize> {
    regions: [UsableRegion; N],
    len: usize,
}

impl<const N: usize> RegionMap<N> {
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
    pub fn add(&mut self, base: u64, length: u64) -> Result<()> {
        let start = base
            .checked_add(FRAME_SIZE - 1)
            .map(|base| base & !(FRAME_SIZE - 1))
            .ok_or(Error::OutOfRange)?;
        let end = base
            .checked_add(length)
            .map(|end| end & !(FRAME_SIZE - 1))
            .ok_or(Error::OutOfRange)?;
        if self.len >= N || end <= start {
            return Err(Error::InvalidInput);
        }
        let length = end - start;
        if self.regions[..self.len]
            .iter()
            .any(|region| region.start < end && start < region.start + region.length)
        {
            return Err(Error::AlreadyExists);
        }
        self.regions[self.len] = UsableRegion { start, length };
        self.len += 1;
        Ok(())
    }

    /// Iterate over normalized regions.
    pub fn iter(&self) -> impl Iterator<Item = UsableRegion> + '_ {
        self.regions[..self.len].iter().copied()
    }
}

/// A bootstrap allocator that never reuses a frame.
#[derive(Clone, Copy, Debug)]
pub struct BumpAllocator<const N: usize> {
    regions: [UsableRegion; N],
    cursors: [u64; N],
    len: usize,
}

impl<const N: usize> BumpAllocator<N> {
    /// Take a snapshot of a normalized map without allocating memory.
    pub fn new(map: &RegionMap<N>) -> Self {
        Self {
            regions: map.regions,
            len: map.len,
            cursors: [0; N],
        }
    }

    /// Allocate the next unique, nonzero physical frame.
    pub fn allocate_frame(&mut self) -> Option<u64> {
        for index in 0..self.len {
            if self.regions[index].start == 0 && self.cursors[index] == 0 {
                self.cursors[index] = FRAME_SIZE;
            }
            if self.cursors[index] < self.regions[index].length {
                let address = self.regions[index].start + self.cursors[index];
                self.cursors[index] += FRAME_SIZE;
                return Some(address);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regions_round_to_whole_pages() {
        let mut map = RegionMap::<2>::new();
        assert_eq!(map.add(0x1234, 0x3000), Ok(()));
        assert_eq!(
            map.iter().next(),
            Some(UsableRegion {
                start: 0x2000,
                length: 0x2000
            })
        );
    }

    #[test]
    fn allocator_skips_zero_and_crosses_regions() {
        let mut map = RegionMap::<2>::new();
        map.add(0, 0x4000).unwrap();
        map.add(0x8000, 0x2000).unwrap();
        let mut allocator = BumpAllocator::new(&map);
        assert_eq!(allocator.allocate_frame(), Some(0x1000));
        assert_eq!(allocator.allocate_frame(), Some(0x2000));
        assert_eq!(allocator.allocate_frame(), Some(0x3000));
        assert_eq!(allocator.allocate_frame(), Some(0x8000));
        assert_eq!(allocator.allocate_frame(), Some(0x9000));
        assert_eq!(allocator.allocate_frame(), None);
    }

    #[test]
    fn invalid_ranges_and_overflow_are_rejected() {
        let mut map = RegionMap::<2>::new();
        assert_eq!(map.add(0x1000, 0xfff), Err(Error::InvalidInput));
        assert_eq!(map.add(u64::MAX, 2), Err(Error::OutOfRange));
        map.add(0x1000, 0x1000).unwrap();
        assert_eq!(map.add(0x1000, 0x1000), Err(Error::AlreadyExists));
    }

    #[test]
    fn allocation_exhaustion_is_deterministic() {
        let mut map = RegionMap::<1>::new();
        map.add(0x1000, 0x2000).unwrap();
        let mut allocator = BumpAllocator::new(&map);
        assert_eq!(allocator.allocate_frame(), Some(0x1000));
        assert_eq!(allocator.allocate_frame(), Some(0x2000));
        assert_eq!(allocator.allocate_frame(), None);
    }
}
