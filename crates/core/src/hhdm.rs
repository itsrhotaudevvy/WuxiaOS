//! Higher-half direct map (HHDM) translation contract.
//!
//! Limine maps all usable physical memory at a fixed higher-half offset. The
//! kernel uses that mapping to touch freshly allocated frames before it owns a
//! page table of its own. This module validates the offset and performs
//! checked translations so no call site has to guess at pointer arithmetic.

use crate::paging::PAGE_SIZE;
use crate::{Error, Result};

/// Lowest canonical higher-half address used by the direct map.
pub const HIGHER_HALF_BASE: u64 = 0xffff_8000_0000_0000;

/// Largest byte address representable in a 52-bit page-table entry.
pub const MAX_PHYSICAL_ADDRESS: u64 = 0x000f_ffff_ffff_ffff;

/// A validated physical-to-virtual translation for the direct map.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectMap {
    offset: u64,
}

impl DirectMap {
    /// Accept only a page-aligned offset inside the canonical higher half.
    pub const fn new(offset: u64) -> Result<Self> {
        if offset < HIGHER_HALF_BASE || !offset.is_multiple_of(PAGE_SIZE) {
            return Err(Error::InvalidInput);
        }
        Ok(Self { offset })
    }

    /// Return the raw offset supplied by the bootloader.
    pub const fn offset(self) -> u64 {
        self.offset
    }

    /// Translate a physical address to its direct-map virtual address.
    pub const fn physical_to_virtual(self, physical: u64) -> Result<u64> {
        if physical > MAX_PHYSICAL_ADDRESS {
            return Err(Error::BadAddress);
        }
        match self.offset.checked_add(physical) {
            Some(virtual_address) if virtual_address >= HIGHER_HALF_BASE => Ok(virtual_address),
            _ => Err(Error::OutOfRange),
        }
    }

    /// Translate a direct-map virtual address back to its physical address.
    pub const fn virtual_to_physical(self, virtual_address: u64) -> Result<u64> {
        if virtual_address < self.offset || virtual_address < HIGHER_HALF_BASE {
            return Err(Error::BadAddress);
        }
        let physical = virtual_address - self.offset;
        if physical > MAX_PHYSICAL_ADDRESS {
            return Err(Error::BadAddress);
        }
        Ok(physical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFFSET: u64 = 0xffff_8000_0000_0000;

    #[test]
    fn offsets_must_be_aligned_and_in_the_higher_half() {
        assert!(DirectMap::new(OFFSET).is_ok());
        assert_eq!(DirectMap::new(0), Err(Error::InvalidInput));
        assert_eq!(DirectMap::new(0x1000), Err(Error::InvalidInput));
        assert_eq!(DirectMap::new(OFFSET + 1), Err(Error::InvalidInput));
        assert_eq!(
            DirectMap::new(HIGHER_HALF_BASE - PAGE_SIZE),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn physical_and_virtual_addresses_round_trip() {
        let map = DirectMap::new(OFFSET).unwrap();
        assert_eq!(map.offset(), OFFSET);
        // The offset leaves 0x0000_7fff_ffff_ffff bytes mappable below u64::MAX.
        for physical in [0, 0x1000, 0x7e000, 0x0000_7fff_ffff_f000] {
            let virtual_address = map.physical_to_virtual(physical).unwrap();
            assert_eq!(virtual_address, OFFSET + physical);
            assert_eq!(map.virtual_to_physical(virtual_address), Ok(physical));
        }
    }

    #[test]
    fn addresses_beyond_the_direct_map_are_rejected() {
        let map = DirectMap::new(OFFSET).unwrap();
        assert_eq!(
            map.physical_to_virtual(MAX_PHYSICAL_ADDRESS + 1),
            Err(Error::BadAddress)
        );
        assert_eq!(
            map.physical_to_virtual(MAX_PHYSICAL_ADDRESS),
            Err(Error::OutOfRange)
        );
        assert_eq!(map.virtual_to_physical(OFFSET - 1), Err(Error::BadAddress));
        assert_eq!(map.virtual_to_physical(0x400000), Err(Error::BadAddress));
    }

    #[test]
    fn an_offset_near_the_top_never_wraps() {
        let map = DirectMap::new(0xffff_ffff_ffff_f000).unwrap();
        assert_eq!(map.physical_to_virtual(0), Ok(0xffff_ffff_ffff_f000));
        assert_eq!(map.physical_to_virtual(0x1000), Err(Error::OutOfRange));
    }
}
