//! Nonpaged pool bookkeeping.
//!
//! `ExAllocatePoolWithTag` hands a driver memory that outlives the call, and
//! `ExFreePoolWithTag` takes it back. A driver writes its own tag into the block so
//! a leak or a double free can be attributed later, which is why every allocation
//! carries a small header immediately before the pointer the driver receives.
//!
//! This module is the bookkeeping only: where a block starts, what its header says,
//! and whether a free is describing a block that is still allocated. The kernel maps
//! the region and owns the frames; nothing here touches memory.
//!
//! The header is deliberately not a Windows `POOL_HEADER`: the kernel compiles in
//! exactly one layout and it is checked on every free, so a driver cannot free a
//! pointer it did not receive.

use crate::Error;
use crate::Result;

/// Bytes in front of every allocation that describe it.
pub const HEADER_SIZE: usize = 16;

/// Magic in an allocated header. A freed block has its magic cleared.
pub const ALLOCATED_MAGIC: u32 = 0x5758_5041; // "WXPA"

/// Alignment of every payload the pool returns.
pub const ALIGNMENT: usize = 16;

/// Largest single allocation the pool will serve.
pub const MAX_ALLOCATION: usize = 64 * 1024;

/// Bytes the header and the payload occupy, including alignment padding.
pub const fn footprint(size: usize) -> usize {
    let unaligned = HEADER_SIZE + size;
    (unaligned + ALIGNMENT - 1) & !(ALIGNMENT - 1)
}

/// Offset of the payload for an allocation starting at `start`.
pub const fn payload_offset(start: usize) -> usize {
    start + HEADER_SIZE
}

/// Reserve `size` bytes at `next` and return the offset of the payload.
///
/// `limit` is the size of the pool region. A request that is empty, larger than
/// [`MAX_ALLOCATION`], or does not fit in the region is refused, so a driver never
/// receives a pointer past the end of the pool.
pub fn allocate(next: usize, size: usize, limit: usize) -> Result<usize> {
    if size == 0 || size > MAX_ALLOCATION {
        return Err(Error::InvalidInput);
    }
    let payload = payload_offset(next);
    let end = payload.checked_add(size).ok_or(Error::OutOfRange)?;
    if end > limit {
        // The pool is full. A driver treats that as a failed allocation, not as a
        // fault, so the error is `TableFull`.
        return Err(Error::TableFull);
    }
    Ok(payload)
}

/// Write the header describing an allocation whose payload starts at `payload`.
pub fn write_header(block: &mut [u8], payload: usize, size: usize, tag: [u8; 4]) -> Result<()> {
    let start = payload
        .checked_sub(HEADER_SIZE)
        .ok_or(Error::InvalidInput)?;
    let end = payload.checked_add(size).ok_or(Error::OutOfRange)?;
    if end > block.len() || size == 0 || size > MAX_ALLOCATION {
        return Err(Error::InvalidImage);
    }
    let header = &mut block[start..payload];
    header.fill(0);
    header[0..4].copy_from_slice(&ALLOCATED_MAGIC.to_le_bytes());
    header[4..8].copy_from_slice(&tag);
    header[8..12].copy_from_slice(&(size as u32).to_le_bytes());
    Ok(())
}

/// Read the header in front of `payload`.
///
/// Errors: `BadAddress` when the pointer is not the payload of a live allocation,
/// either because it is too close to the start of the region or because its header
/// magic is gone - which is also how a second free of the same block is refused.
pub fn parse_header(block: &[u8], payload: usize) -> Result<Header> {
    let start = payload.checked_sub(HEADER_SIZE).ok_or(Error::BadAddress)?;
    if start % ALIGNMENT != 0 || payload > block.len() {
        return Err(Error::BadAddress);
    }
    let magic = u32::from_le_bytes([
        block[start],
        block[start + 1],
        block[start + 2],
        block[start + 3],
    ]);
    if magic != ALLOCATED_MAGIC {
        return Err(Error::BadAddress);
    }
    let size = u32::from_le_bytes([
        block[start + 8],
        block[start + 9],
        block[start + 10],
        block[start + 11],
    ]);
    if size == 0 || size as usize > MAX_ALLOCATION {
        return Err(Error::InvalidImage);
    }
    Ok(Header {
        tag: [
            block[start + 4],
            block[start + 5],
            block[start + 6],
            block[start + 7],
        ],
        size,
    })
}

/// Mark a block as freed by clearing its magic, so a second free is refused.
pub fn release(block: &mut [u8], payload: usize) -> Result<()> {
    parse_header(block, payload)?;
    let start = payload - HEADER_SIZE;
    block[start..start + 4].fill(0);
    Ok(())
}

/// What an allocation's header says about it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    /// The tag the caller asked for.
    pub tag: [u8; 4],
    /// Payload size in bytes.
    pub size: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMIT: usize = 0x4000;

    #[test]
    fn a_payload_follows_its_header() {
        assert_eq!(payload_offset(0), HEADER_SIZE);
        assert_eq!(payload_offset(0x100), 0x100 + HEADER_SIZE);
    }

    #[test]
    fn an_allocation_fits_only_inside_the_region() {
        assert_eq!(allocate(0, 16, LIMIT), Ok(HEADER_SIZE));
        assert_eq!(allocate(LIMIT, 16, LIMIT), Err(Error::TableFull));
        assert_eq!(allocate(0, 0, LIMIT), Err(Error::InvalidInput));
        assert_eq!(
            allocate(0, MAX_ALLOCATION + 1, LIMIT),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn the_header_round_trips() {
        let mut block = [0u8; 0x100];
        write_header(&mut block, HEADER_SIZE, 32, *b"WUXA").unwrap();
        let header = parse_header(&block, HEADER_SIZE).unwrap();
        assert_eq!(header.tag, *b"WUXA");
        assert_eq!(header.size, 32);
    }

    #[test]
    fn a_freed_block_cannot_be_freed_again() {
        let mut block = [0u8; 0x100];
        write_header(&mut block, HEADER_SIZE, 32, *b"WUXA").unwrap();
        release(&mut block, HEADER_SIZE).unwrap();
        assert_eq!(parse_header(&block, HEADER_SIZE), Err(Error::BadAddress));
        assert_eq!(release(&mut block, HEADER_SIZE), Err(Error::BadAddress));
    }

    #[test]
    fn a_pointer_without_a_header_is_refused() {
        let block = [0u8; 0x100];
        assert_eq!(parse_header(&block, 0), Err(Error::BadAddress));
        assert_eq!(parse_header(&block, HEADER_SIZE), Err(Error::BadAddress));
        assert_eq!(parse_header(&block, 8), Err(Error::BadAddress));
    }

    #[test]
    fn a_header_that_does_not_fit_its_block_is_refused() {
        let mut block = [0u8; 0x40];
        assert_eq!(
            write_header(&mut block, HEADER_SIZE, 0x100, *b"WUXA"),
            Err(Error::InvalidImage)
        );
    }

    #[test]
    fn the_footprint_is_aligned() {
        assert_eq!(footprint(16), 0x20);
        assert_eq!(footprint(17), 0x30);
        assert_eq!(footprint(16) % ALIGNMENT, 0);
    }
}
