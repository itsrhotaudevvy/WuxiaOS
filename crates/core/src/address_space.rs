//! Per-process virtual address-space model.
//!
//! This is the policy layer, not the hardware layer: it records which user
//! regions a process may touch and with what permissions. The kernel keeps the
//! model in sync with the page tables it installs, so a syscall can reject a
//! pointer before any page walk or memory access.

use crate::paging::{PAGE_SIZE, PagePermissions, USER_ADDRESS_LIMIT, is_user_address};
use crate::{Error, Result};

/// One mapped user region.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappedRegion {
    /// Page-aligned first address.
    pub start: u64,
    /// Page-multiple length in bytes.
    pub length: u64,
    /// Permissions granted to the whole region.
    pub permissions: PagePermissions,
}

impl MappedRegion {
    /// Construct the placeholder used to initialize fixed-capacity storage.
    const EMPTY: Self = Self {
        start: 0,
        length: 0,
        permissions: PagePermissions::KERNEL_READ_ONLY,
    };

    /// Address one past the last mapped byte.
    pub const fn end(self) -> u64 {
        self.start + self.length
    }

    /// Whether `address` falls inside this region.
    pub const fn contains(self, address: u64) -> bool {
        address >= self.start && address < self.end()
    }
}

/// A bounded set of non-overlapping user regions.
#[derive(Clone, Copy, Debug)]
pub struct AddressSpace<const N: usize> {
    regions: [MappedRegion; N],
    len: usize,
}

impl<const N: usize> Default for AddressSpace<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> AddressSpace<N> {
    /// Construct an address space with no mapped regions.
    pub const fn new() -> Self {
        Self {
            regions: [MappedRegion::EMPTY; N],
            len: 0,
        }
    }

    /// Map a page-aligned, page-multiple user region.
    pub fn map(&mut self, start: u64, length: u64, permissions: PagePermissions) -> Result<()> {
        if !is_user_address(start)
            || length == 0
            || !length.is_multiple_of(PAGE_SIZE)
            || permissions.is_writable_and_executable()
        {
            return Err(Error::InvalidInput);
        }
        let end = start.checked_add(length).ok_or(Error::OutOfRange)?;
        if end > USER_ADDRESS_LIMIT {
            return Err(Error::BadAddress);
        }
        if self.regions[..self.len]
            .iter()
            .any(|region| region.start < end && start < region.end())
        {
            return Err(Error::AlreadyExists);
        }
        if self.len >= N {
            return Err(Error::TableFull);
        }
        self.regions[self.len] = MappedRegion {
            start,
            length,
            permissions,
        };
        self.len += 1;
        Ok(())
    }

    /// Remove a region that exactly matches `start` and `length`.
    pub fn unmap(&mut self, start: u64, length: u64) -> Result<()> {
        let index = self.regions[..self.len]
            .iter()
            .position(|region| region.start == start && region.length == length)
            .ok_or(Error::NotFound)?;
        self.regions[index] = self.regions[self.len - 1];
        self.len -= 1;
        Ok(())
    }

    /// Return the region containing `address`, if any.
    pub fn region_at(&self, address: u64) -> Option<MappedRegion> {
        self.regions[..self.len]
            .iter()
            .copied()
            .find(|region| region.contains(address))
    }

    /// Whether the whole non-empty byte range is mapped by a single region.
    pub fn contains(&self, address: u64, length: u64) -> bool {
        if length == 0 {
            return false;
        }
        let Some(last) = address.checked_add(length) else {
            return false;
        };
        self.regions[..self.len]
            .iter()
            .any(|region| address >= region.start && last <= region.end())
    }

    /// Choose a page-aligned address above every mapped region for `length` bytes.
    pub fn top_gap(&self, length: u64) -> Result<u64> {
        if length == 0 || !length.is_multiple_of(PAGE_SIZE) {
            return Err(Error::InvalidInput);
        }
        let highest = self.regions[..self.len]
            .iter()
            .map(|region| region.start + region.length)
            .max()
            .unwrap_or(0);
        let start = highest
            .checked_add(PAGE_SIZE - 1)
            .ok_or(Error::OutOfRange)?
            & !(PAGE_SIZE - 1);
        let start = start.max(PAGE_SIZE);
        let end = start.checked_add(length).ok_or(Error::OutOfRange)?;
        if end > USER_ADDRESS_LIMIT {
            return Err(Error::BadAddress);
        }
        Ok(start)
    }

    /// Number of mapped regions.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether no region is mapped.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Iterate over mapped regions.
    pub fn iter(&self) -> impl Iterator<Item = MappedRegion> + '_ {
        self.regions[..self.len].iter().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x0080_0000_0000;

    #[test]
    fn mapping_requires_alignment_and_user_range() {
        let mut space = AddressSpace::<4>::new();
        assert!(
            space
                .map(BASE, PAGE_SIZE, PagePermissions::USER_READ_ONLY)
                .is_ok()
        );
        assert_eq!(
            space.map(BASE + PAGE_SIZE, 1, PagePermissions::USER_READ_ONLY),
            Err(Error::InvalidInput)
        );
        assert_eq!(
            space.map(0, PAGE_SIZE, PagePermissions::USER_READ_ONLY),
            Err(Error::InvalidInput)
        );
        assert_eq!(
            space.map(
                USER_ADDRESS_LIMIT,
                PAGE_SIZE,
                PagePermissions::USER_READ_ONLY
            ),
            Err(Error::InvalidInput)
        );
        assert_eq!(
            space.map(
                0x7fff_ffff_f000,
                0xffff_ffff_ffff_f000,
                PagePermissions::USER_READ_ONLY
            ),
            Err(Error::OutOfRange)
        );
        assert_eq!(
            space.map(BASE, 0xffff_ffff_f000, PagePermissions::USER_READ_ONLY),
            Err(Error::BadAddress)
        );
        assert_eq!(space.len(), 1);
    }

    #[test]
    fn writable_executable_regions_are_rejected() {
        let mut space = AddressSpace::<1>::new();
        let flags = PagePermissions {
            writable: true,
            user: true,
            executable: true,
            cache_disable: false,
        };
        assert_eq!(space.map(BASE, PAGE_SIZE, flags), Err(Error::InvalidInput));
    }

    #[test]
    fn top_gap_is_above_every_region_and_aligned() {
        let mut space = AddressSpace::<4>::new();
        assert_eq!(space.top_gap(PAGE_SIZE), Ok(PAGE_SIZE));

        space
            .map(0x8000_0000, 0x2000, PagePermissions::USER_CODE)
            .unwrap();
        space
            .map(0x8000_4000, PAGE_SIZE, PagePermissions::USER_READ_ONLY)
            .unwrap();
        assert_eq!(space.top_gap(PAGE_SIZE), Ok(0x8000_5000));
        assert_eq!(space.top_gap(0x2000), Ok(0x8000_5000));
        assert_eq!(space.top_gap(0), Err(Error::InvalidInput));
        assert_eq!(space.top_gap(0x1001), Err(Error::InvalidInput));
    }

    #[test]
    fn overlapping_regions_are_rejected() {
        let mut space = AddressSpace::<4>::new();
        space
            .map(BASE, PAGE_SIZE, PagePermissions::USER_READ_ONLY)
            .unwrap();
        assert_eq!(
            space.map(BASE, PAGE_SIZE, PagePermissions::USER_READ_ONLY),
            Err(Error::AlreadyExists)
        );
        assert_eq!(
            space.map(
                BASE - PAGE_SIZE,
                3 * PAGE_SIZE,
                PagePermissions::USER_READ_ONLY
            ),
            Err(Error::AlreadyExists)
        );
        assert!(
            space
                .map(
                    BASE + PAGE_SIZE,
                    PAGE_SIZE,
                    PagePermissions::USER_READ_WRITE
                )
                .is_ok()
        );
    }

    #[test]
    fn capacity_is_enforced() {
        let mut space = AddressSpace::<1>::new();
        space
            .map(BASE, PAGE_SIZE, PagePermissions::USER_READ_ONLY)
            .unwrap();
        assert_eq!(
            space.map(BASE + PAGE_SIZE, PAGE_SIZE, PagePermissions::USER_READ_ONLY),
            Err(Error::TableFull)
        );
    }

    #[test]
    fn containment_and_permissions_follow_the_region() {
        let mut space = AddressSpace::<2>::new();
        space
            .map(BASE, PAGE_SIZE, PagePermissions::USER_CODE)
            .unwrap();
        space
            .map(
                BASE + PAGE_SIZE,
                PAGE_SIZE,
                PagePermissions::USER_READ_WRITE,
            )
            .unwrap();

        assert!(space.contains(BASE, PAGE_SIZE));
        assert!(space.contains(BASE + PAGE_SIZE + 0x10, 0x20));
        assert!(!space.contains(BASE + PAGE_SIZE + 0x10, 0x2000));
        assert!(!space.contains(BASE - 1, 1));
        assert!(!space.contains(BASE, 0));

        assert_eq!(
            space.region_at(BASE + 1).map(|region| region.permissions),
            Some(PagePermissions::USER_CODE)
        );
        assert_eq!(
            space
                .region_at(BASE + PAGE_SIZE + 1)
                .map(|region| region.permissions),
            Some(PagePermissions::USER_READ_WRITE)
        );
        assert!(space.region_at(0).is_none());
    }

    #[test]
    fn unmap_removes_only_an_exact_region() {
        let mut space = AddressSpace::<2>::new();
        space
            .map(BASE, PAGE_SIZE, PagePermissions::USER_READ_ONLY)
            .unwrap();
        assert_eq!(space.unmap(BASE, 2 * PAGE_SIZE), Err(Error::NotFound));
        assert_eq!(space.unmap(BASE, PAGE_SIZE), Ok(()));
        assert!(space.is_empty());
    }
}
