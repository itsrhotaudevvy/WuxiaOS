//! Validating a physical range a driver asks to map.
//!
//! A driver reaching `MmMapIoSpace` names a physical address and a length; the
//! kernel decides whether that request is mappable. Refusing early keeps a
//! malformed request from reaching the page tables, and keeping the rules here
//! means they are tested on the host instead of only observed at boot.
//!
//! The rules are deliberately narrow: the address must be page-aligned, the
//! length must be nonzero and no larger than one device window, and the range
//! must not wrap. Anything else is a driver bug, not a mapping the kernel
//! should improvise.

use crate::Error;
use crate::Result;
use crate::paging::PAGE_SIZE;

/// Largest span one request may map.
///
/// It matches the size of a window in the device address space, so a single
/// request can never exceed the space the kernel reserved for device mappings.
pub const MAX_BYTES: u64 = 0x20_0000;

/// Validate a mapping request and return the number of pages it needs.
///
/// Errors: `InvalidInput` for a zero length or an oversized span, `BadAddress`
/// for a null or unaligned physical address, and `OutOfRange` for a range that
/// does not fit in the address space.
pub fn map_request(physical: u64, length: u64) -> Result<u64> {
    if length == 0 || length > MAX_BYTES {
        return Err(Error::InvalidInput);
    }
    if physical == 0 || !physical.is_multiple_of(PAGE_SIZE) {
        return Err(Error::BadAddress);
    }
    let end = physical.checked_add(length).ok_or(Error::OutOfRange)?;
    let pages = end
        .checked_add(PAGE_SIZE - 1)
        .ok_or(Error::OutOfRange)?
        .div_euclid(PAGE_SIZE)
        - physical.div_euclid(PAGE_SIZE);
    Ok(pages)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_aligned_request_names_its_pages() {
        assert_eq!(map_request(0x1_0000, PAGE_SIZE), Ok(1));
        assert_eq!(map_request(0x1_0000, PAGE_SIZE + 1), Ok(2));
        assert_eq!(map_request(0x1_0000, MAX_BYTES), Ok(MAX_BYTES / PAGE_SIZE));
    }

    #[test]
    fn a_null_or_unaligned_address_is_refused() {
        assert_eq!(map_request(0, PAGE_SIZE), Err(Error::BadAddress));
        assert_eq!(map_request(0x1_0100, PAGE_SIZE), Err(Error::BadAddress));
    }

    #[test]
    fn a_zero_or_oversized_length_is_refused() {
        assert_eq!(map_request(0x1_0000, 0), Err(Error::InvalidInput));
        assert_eq!(
            map_request(0x1_0000, MAX_BYTES + PAGE_SIZE),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn a_range_that_wraps_is_refused() {
        assert_eq!(
            map_request(u64::MAX & !(PAGE_SIZE - 1), PAGE_SIZE),
            Err(Error::OutOfRange)
        );
    }
}
