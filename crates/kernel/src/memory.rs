//! Limine physical-memory-map discovery and aligned region accounting.

use limine::memory_map::{Entry, EntryType};

/// A page-aligned physical memory range discovered by Limine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UsableRegion {
    /// Physical start address, aligned up to a page boundary.
    pub start: u64,
    /// Number of bytes in the region after page alignment.
    pub length: u64,
}

/// A bounded list of usable physical memory regions.
#[derive(Clone, Copy, Debug)]
pub struct MemoryMap<const N: usize> {
    regions: [Option<UsableRegion>; N],
    len: usize,
}

impl<const N: usize> MemoryMap<N> {
    /// Construct an empty region table.
    pub const fn new() -> Self {
        Self { regions: [UsableRegion { start: 0, length: 0 }; N], len: 0 }
    }

    /// Add a usable region, rejecting overflow and non-page-aligned inputs.
    pub fn add(&mut self, start: u64, length: u64) -> Result<usize, wuxia_core::Error> {
        let start = start.checked_add(0xfff).map(|address| address & !0xfff)
            .ok_or(wuxia_core::Error::OutOfRange)?;
        let length = length & !0xfff;
        if self.len >= N || start & 0xfff != 0 || length == 0 {
            return Err(wuxia_core::Error::InvalidInput);
        }
        let end = start.checked_add(length).ok_or(wuxia_core::Error::OutOfRange)?;
        if self.regions[..self.len].iter().any(|region| {
            region.start < end && start < region.start + region.length
        }) {
            return Err(wuxia_core::Error::AlreadyExists);
        }
        self.regions[self.len] = UsableRegion { start, length };
        self.len += 1;
        Ok(self.len)
    }

    /// Iterate over discovered regions.
    pub fn iter(&self) -> impl Iterator<Item = UsableRegion> + '_ {
        self.regions[..self.len].iter().map(|region| region.unwrap())
    }
}

/// Convert a Limine response into a validated bounded region list.
pub fn from_limine<const N: usize>(response: &limine::memory_map::Response) -> Result<MemoryMap<N>, wuxia_core::Error> {
    let mut map = MemoryMap::<N>::new();
    for entry in response.entries().iter() {
        if entry.entry_type != EntryType::USABLE {
            continue;
        }
        map.add(entry.base, entry.length)?;
    }
    Ok(map)
}
