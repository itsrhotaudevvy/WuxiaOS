//! Device objects a driver creates.
//!
//! `IoCreateDevice` hands a driver a `DEVICE_OBJECT` with the extension the driver
//! asked for appended after it, links it at the head of the driver object's device
//! chain and returns it. Every driver's `DriverEntry` does exactly this, so the
//! layout is the first structure a driver reads back.
//!
//! As with the driver object, only the fields this kernel fills are described:
//! type and size, the reference count, the owning driver, the chain links, the
//! flags and characteristics, the extension and the device type. Everything else
//! stays zero. The extension follows the header on an eight-byte boundary and is
//! its own slice of the same page, so a driver can write to `DeviceExtension`
//! without reaching anything the kernel owns.

use crate::Error;
use crate::Result;

/// Size of a `DEVICE_OBJECT` header on x64.
pub const DEVICE_OBJECT_SIZE: usize = 0x150;

/// `Type` value for a device object.
pub const TYPE_DEVICE_OBJECT: u16 = 3;

/// Offset of `ReferenceCount`.
pub const REFERENCE_COUNT_OFFSET: usize = 0x04;

/// Offset of `DriverObject`.
pub const DRIVER_OBJECT_OFFSET: usize = 0x08;

/// Offset of `NextDevice`.
pub const NEXT_DEVICE_OFFSET: usize = 0x10;

/// Offset of `Flags`.
pub const FLAGS_OFFSET: usize = 0x30;

/// Offset of `Characteristics`.
pub const CHARACTERISTICS_OFFSET: usize = 0x34;

/// Offset of `DeviceExtension`.
pub const DEVICE_EXTENSION_OFFSET: usize = 0x40;

/// Offset of `DeviceType`.
pub const DEVICE_TYPE_OFFSET: usize = 0x48;

/// Largest device extension one device object may carry.
///
/// It is the rest of the page the object lives in, so the extension can never
/// reach into another object or another driver's memory.
pub const MAX_EXTENSION: usize = 0x1000 - DEVICE_OBJECT_SIZE;

/// A device object written into a block, and where its extension starts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Written {
    /// Offset of the device object in the block; always zero.
    pub device_object: usize,
    /// Offset of the extension in the block.
    pub extension: usize,
}

/// Write a device object and its extension into `block`.
///
/// `device_object_address` is the address the block is mapped at, so the driver
/// receives an address it can use. `driver_object` is the object that owns the
/// device; it is recorded but not dereferenced here.
///
/// Errors: `InvalidInput` for an extension larger than the rest of the page,
/// `BadAddress` for a null or unaligned block address, and `InvalidImage` for a
/// block too small to hold the header and the extension.
pub fn write(
    block: &mut [u8],
    device_object_address: u64,
    driver_object: u64,
    extension_size: u32,
    device_type: u32,
    characteristics: u32,
) -> Result<Written> {
    let extension_size = extension_size as usize;
    if extension_size > MAX_EXTENSION {
        return Err(Error::InvalidInput);
    }
    if device_object_address == 0 || !device_object_address.is_multiple_of(8) {
        return Err(Error::BadAddress);
    }
    let total = DEVICE_OBJECT_SIZE + extension_size;
    if total > block.len() {
        return Err(Error::InvalidImage);
    }
    let header = &mut block[..DEVICE_OBJECT_SIZE];
    header.fill(0);
    header[0..2].copy_from_slice(&TYPE_DEVICE_OBJECT.to_le_bytes());
    header[2..4].copy_from_slice(&(DEVICE_OBJECT_SIZE as u16).to_le_bytes());
    header[REFERENCE_COUNT_OFFSET..REFERENCE_COUNT_OFFSET + 4].copy_from_slice(&1u32.to_le_bytes());
    header[DRIVER_OBJECT_OFFSET..DRIVER_OBJECT_OFFSET + 8]
        .copy_from_slice(&driver_object.to_le_bytes());
    header[CHARACTERISTICS_OFFSET..CHARACTERISTICS_OFFSET + 4]
        .copy_from_slice(&characteristics.to_le_bytes());
    let extension_address = device_object_address
        .checked_add(DEVICE_OBJECT_SIZE as u64)
        .ok_or(Error::OutOfRange)?;
    header[DEVICE_EXTENSION_OFFSET..DEVICE_EXTENSION_OFFSET + 8]
        .copy_from_slice(&extension_address.to_le_bytes());
    header[DEVICE_TYPE_OFFSET..DEVICE_TYPE_OFFSET + 4].copy_from_slice(&device_type.to_le_bytes());
    block[DEVICE_OBJECT_SIZE..total].fill(0);
    Ok(Written {
        device_object: 0,
        extension: DEVICE_OBJECT_SIZE,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paging::PAGE_SIZE;

    const BLOCK_ADDRESS: u64 = 0xffff_9900_0000_0000;
    const DRIVER_OBJECT: u64 = 0xffff_9700_0000_8000;

    fn read_u16(bytes: &[u8], at: usize) -> u16 {
        u16::from_le_bytes([bytes[at], bytes[at + 1]])
    }

    fn read_u32(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
    }

    fn read_u64(bytes: &[u8], at: usize) -> u64 {
        let mut field = [0u8; 8];
        field.copy_from_slice(&bytes[at..at + 8]);
        u64::from_le_bytes(field)
    }

    #[test]
    fn the_device_object_names_its_driver_and_type() {
        let mut block = [0u8; PAGE_SIZE as usize];
        let written = write(&mut block, BLOCK_ADDRESS, DRIVER_OBJECT, 16, 0x22, 0x100)
            .expect("the device object is written");
        assert_eq!(written.device_object, 0);
        assert_eq!(read_u16(&block, 0), TYPE_DEVICE_OBJECT);
        assert_eq!(read_u16(&block, 2), DEVICE_OBJECT_SIZE as u16);
        assert_eq!(read_u32(&block, REFERENCE_COUNT_OFFSET), 1);
        assert_eq!(read_u64(&block, DRIVER_OBJECT_OFFSET), DRIVER_OBJECT);
        assert_eq!(
            read_u64(&block, NEXT_DEVICE_OFFSET),
            0,
            "no other device yet"
        );
        assert_eq!(read_u32(&block, CHARACTERISTICS_OFFSET), 0x100);
        assert_eq!(read_u32(&block, DEVICE_TYPE_OFFSET), 0x22);
    }

    #[test]
    fn the_extension_follows_the_header() {
        let mut block = [0u8; PAGE_SIZE as usize];
        let written = write(&mut block, BLOCK_ADDRESS, DRIVER_OBJECT, 0x40, 0x22, 0)
            .expect("the device object is written");
        assert_eq!(written.extension, DEVICE_OBJECT_SIZE);
        assert_eq!(
            read_u64(&block, DEVICE_EXTENSION_OFFSET),
            BLOCK_ADDRESS + DEVICE_OBJECT_SIZE as u64
        );
    }

    #[test]
    fn the_extension_is_zeroed_and_its_own_memory() {
        let mut block = [0xffu8; PAGE_SIZE as usize];
        write(&mut block, BLOCK_ADDRESS, DRIVER_OBJECT, 0x40, 0x22, 0).unwrap();
        let extension = &block[DEVICE_OBJECT_SIZE..DEVICE_OBJECT_SIZE + 0x40];
        assert!(extension.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn an_oversized_extension_is_refused() {
        let mut block = [0u8; PAGE_SIZE as usize];
        assert_eq!(
            write(
                &mut block,
                BLOCK_ADDRESS,
                DRIVER_OBJECT,
                (MAX_EXTENSION + 1) as u32,
                0x22,
                0
            ),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn an_unaligned_or_null_block_address_is_refused() {
        let mut block = [0u8; PAGE_SIZE as usize];
        assert_eq!(
            write(&mut block, BLOCK_ADDRESS + 4, DRIVER_OBJECT, 16, 0x22, 0),
            Err(Error::BadAddress)
        );
        assert_eq!(
            write(&mut block, 0, DRIVER_OBJECT, 16, 0x22, 0),
            Err(Error::BadAddress)
        );
    }

    #[test]
    fn a_block_too_small_for_the_extension_is_refused() {
        let mut block = [0u8; DEVICE_OBJECT_SIZE + 8];
        assert_eq!(
            write(&mut block, BLOCK_ADDRESS, DRIVER_OBJECT, 16, 0x22, 0),
            Err(Error::InvalidImage)
        );
    }
}
