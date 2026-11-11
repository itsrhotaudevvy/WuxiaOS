//! The objects a driver is handed when it is entered.
//!
//! A loaded driver is entered the way a real one is: `DriverEntry` receives a
//! `DRIVER_OBJECT` describing the image and a `UNICODE_STRING` naming the
//! service's registry key. This module writes both into one block the kernel
//! mapped, so the driver can read them without the kernel lending it any other
//! structure.
//!
//! The layout is the x64 one every driver already assumes: `Type` and `Size` at
//! the start, the image range, the driver name, and the major-function table.
//! Only the fields this kernel fills are described here; every other byte stays
//! zero, and a driver that reads one of them sees exactly that - an empty table,
//! not a stale pointer.
//!
//! Addresses are supervisor addresses, so the strings are written directly rather
//! than through the user `UNICODE_STRING` encoder, which deliberately refuses the
//! higher half.

use crate::Error;
use crate::Result;

/// Size of a `DRIVER_OBJECT` on x64.
pub const DRIVER_OBJECT_SIZE: usize = 0x150;

/// `Type` value for a driver object.
pub const TYPE_DRIVER_OBJECT: u16 = 4;

/// Number of entries in `MajorFunction`.
pub const MAJOR_FUNCTIONS: usize = 28;

/// Offset of `MajorFunction[0]`.
pub const MAJOR_FUNCTION_OFFSET: usize = 0x70;

/// Offset of `DeviceObject`.
pub const DEVICE_OBJECT_OFFSET: usize = 0x08;

/// Offset of `DriverStart`.
pub const DRIVER_START_OFFSET: usize = 0x18;

/// Offset of `DriverSize`.
pub const DRIVER_SIZE_OFFSET: usize = 0x20;

/// Offset of `DriverName`.
pub const DRIVER_NAME_OFFSET: usize = 0x38;

/// Size of a `UNICODE_STRING` on x64.
pub const UNICODE_STRING_SIZE: usize = 16;

/// Longest driver or service name this kernel writes.
pub const MAX_NAME_CHARS: usize = 64;

/// Offsets inside the block this module fills.
///
/// The block is one page: the driver object first, then the registry path's
/// `UNICODE_STRING`, then the code units both strings point at.
const REGISTRY_PATH_OFFSET: usize = DRIVER_OBJECT_SIZE;
const DRIVER_NAME_BUFFER_OFFSET: usize = 0x180;
const REGISTRY_BUFFER_OFFSET: usize = 0x280;

/// Where the pieces ended up, as offsets from the block's first byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Objects {
    /// Offset of the `DRIVER_OBJECT`.
    pub driver_object: usize,
    /// Offset of the registry path's `UNICODE_STRING`.
    pub registry_path: usize,
}

/// Write a driver object and its registry path into `block`.
///
/// `block_address` is the address the block is mapped at, so the strings the
/// kernel writes name addresses the driver can actually dereference. `driver_name`
/// and `service_name` are ASCII; a non-ASCII or over-long name is refused instead
/// of being truncated, because a truncated service key silently names another
/// service.
///
/// Errors: `InvalidInput` for a name that is empty, non-ASCII or longer than
/// [`MAX_NAME_CHARS`], and `InvalidImage` for a block too small to hold both
/// objects and their code units.
pub fn write(
    block: &mut [u8],
    block_address: u64,
    image_start: u64,
    image_size: u64,
    driver_name: &str,
    service_name: &str,
) -> Result<Objects> {
    let (driver_units, driver_length) = code_units(driver_name)?;
    let (service_units, service_length) = code_units(service_name)?;
    if REGISTRY_BUFFER_OFFSET + service_length > block.len() {
        return Err(Error::InvalidImage);
    }
    if block_address == 0 || !block_address.is_multiple_of(crate::paging::PAGE_SIZE) {
        return Err(Error::BadAddress);
    }
    let object = &mut block[..DRIVER_OBJECT_SIZE];
    object.fill(0);
    object[0..2].copy_from_slice(&TYPE_DRIVER_OBJECT.to_le_bytes());
    object[2..4].copy_from_slice(&(DRIVER_OBJECT_SIZE as u16).to_le_bytes());
    object[DRIVER_START_OFFSET..DRIVER_START_OFFSET + 8]
        .copy_from_slice(&image_start.to_le_bytes());
    object[DRIVER_SIZE_OFFSET..DRIVER_SIZE_OFFSET + 8].copy_from_slice(&image_size.to_le_bytes());
    let name_buffer = block_address
        .checked_add(DRIVER_NAME_BUFFER_OFFSET as u64)
        .ok_or(Error::OutOfRange)?;
    write_unicode_string(
        &mut object[DRIVER_NAME_OFFSET..DRIVER_NAME_OFFSET + UNICODE_STRING_SIZE],
        name_buffer,
        driver_length,
    )?;
    block[DRIVER_NAME_BUFFER_OFFSET..DRIVER_NAME_BUFFER_OFFSET + driver_length]
        .copy_from_slice(&driver_units[..driver_length]);

    let registry_buffer = block_address
        .checked_add(REGISTRY_BUFFER_OFFSET as u64)
        .ok_or(Error::OutOfRange)?;
    write_unicode_string(
        &mut block[REGISTRY_PATH_OFFSET..REGISTRY_PATH_OFFSET + UNICODE_STRING_SIZE],
        registry_buffer,
        service_length,
    )?;
    block[REGISTRY_BUFFER_OFFSET..REGISTRY_BUFFER_OFFSET + service_length]
        .copy_from_slice(&service_units[..service_length]);
    Ok(Objects {
        driver_object: 0,
        registry_path: REGISTRY_PATH_OFFSET,
    })
}

/// Widen an ASCII name into UTF-16 code units, returning them and their length.
fn code_units(name: &str) -> Result<([u8; MAX_NAME_CHARS * 2], usize)> {
    if name.is_empty() || name.len() > MAX_NAME_CHARS || !name.is_ascii() {
        return Err(Error::InvalidInput);
    }
    let mut units = [0u8; MAX_NAME_CHARS * 2];
    for (index, byte) in name.bytes().enumerate() {
        units[index * 2] = byte;
    }
    Ok((units, name.len() * 2))
}

/// Write one `UNICODE_STRING`: length, maximum length and buffer address.
fn write_unicode_string(field: &mut [u8], buffer: u64, units: usize) -> Result<()> {
    let length = u16::try_from(units).map_err(|_| Error::InvalidInput)?;
    let maximum = length.checked_add(2).ok_or(Error::OutOfRange)?;
    field[0..2].copy_from_slice(&length.to_le_bytes());
    field[2..4].copy_from_slice(&maximum.to_le_bytes());
    field[8..16].copy_from_slice(&buffer.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paging::PAGE_SIZE;

    const BLOCK_ADDRESS: u64 = 0xffff_9700_0000_8000;

    fn block() -> [u8; PAGE_SIZE as usize] {
        [0u8; PAGE_SIZE as usize]
    }

    fn read_u16(bytes: &[u8], at: usize) -> u16 {
        u16::from_le_bytes([bytes[at], bytes[at + 1]])
    }

    fn read_u64(bytes: &[u8], at: usize) -> u64 {
        let mut field = [0u8; 8];
        field.copy_from_slice(&bytes[at..at + 8]);
        u64::from_le_bytes(field)
    }

    /// The ASCII bytes of a UTF-16LE string, as written into the block.
    fn ascii(bytes: &[u8], at: usize, length: usize) -> [u8; MAX_NAME_CHARS] {
        let mut text = [0u8; MAX_NAME_CHARS];
        for index in 0..length / 2 {
            text[index] = bytes[at + index * 2];
        }
        text
    }

    #[test]
    fn the_object_describes_the_image() {
        let mut bytes = block();
        let objects = write(
            &mut bytes,
            BLOCK_ADDRESS,
            0x1234_0000,
            0x5000,
            "wuxia",
            "wuxia",
        )
        .expect("the objects are written");
        assert_eq!(objects.driver_object, 0);
        assert_eq!(read_u16(&bytes, 0), TYPE_DRIVER_OBJECT);
        assert_eq!(read_u16(&bytes, 2), DRIVER_OBJECT_SIZE as u16);
        assert_eq!(read_u64(&bytes, DRIVER_START_OFFSET), 0x1234_0000);
        assert_eq!(read_u64(&bytes, DRIVER_SIZE_OFFSET), 0x5000);
        assert_eq!(read_u64(&bytes, DEVICE_OBJECT_OFFSET), 0, "no device yet");
    }

    #[test]
    fn the_driver_name_points_into_the_block() {
        let mut bytes = block();
        write(
            &mut bytes,
            BLOCK_ADDRESS,
            0x1234_0000,
            0x5000,
            "wuxia",
            "wuxia",
        )
        .unwrap();
        let name = DRIVER_NAME_OFFSET;
        assert_eq!(read_u16(&bytes, name), 10, "five characters");
        assert_eq!(read_u16(&bytes, name + 2), 12, "with room for the NUL");
        assert_eq!(
            read_u64(&bytes, name + 8),
            BLOCK_ADDRESS + DRIVER_NAME_BUFFER_OFFSET as u64
        );
        assert_eq!(
            &ascii(&bytes, DRIVER_NAME_BUFFER_OFFSET, 10)[..5],
            b"wuxia",
            "the code units are the name"
        );
    }

    #[test]
    fn the_registry_path_points_at_the_service_name() {
        let mut bytes = block();
        let objects = write(
            &mut bytes,
            BLOCK_ADDRESS,
            0x1234_0000,
            0x5000,
            "wuxia",
            "wuxiadev",
        )
        .unwrap();
        let path = objects.registry_path;
        let length = read_u16(&bytes, path) as usize;
        assert_eq!(length, 16, "eight characters");
        assert_eq!(
            read_u64(&bytes, path + 8),
            BLOCK_ADDRESS + REGISTRY_BUFFER_OFFSET as u64
        );
        assert_eq!(
            &ascii(&bytes, REGISTRY_BUFFER_OFFSET, length)[..8],
            b"wuxiadev"
        );
    }

    #[test]
    fn the_major_function_table_stays_empty() {
        let mut bytes = block();
        write(
            &mut bytes,
            BLOCK_ADDRESS,
            0x1234_0000,
            0x5000,
            "wuxia",
            "wuxia",
        )
        .unwrap();
        let table = &bytes[MAJOR_FUNCTION_OFFSET..MAJOR_FUNCTION_OFFSET + MAJOR_FUNCTIONS * 8];
        assert!(table.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn a_non_ascii_or_over_long_name_is_refused() {
        let mut bytes = block();
        assert_eq!(
            write(&mut bytes, BLOCK_ADDRESS, 0x1234_0000, 0x5000, "wuxia", ""),
            Err(Error::InvalidInput)
        );
        assert_eq!(
            write(
                &mut bytes,
                BLOCK_ADDRESS,
                0x1234_0000,
                0x5000,
                "wuxia",
                "wuxiä"
            ),
            Err(Error::InvalidInput)
        );
        let long = "w".repeat(MAX_NAME_CHARS + 1);
        assert_eq!(
            write(
                &mut bytes,
                BLOCK_ADDRESS,
                0x1234_0000,
                0x5000,
                "wuxia",
                &long
            ),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn an_unaligned_block_address_is_refused() {
        let mut bytes = block();
        assert_eq!(
            write(
                &mut bytes,
                BLOCK_ADDRESS + 8,
                0x1234_0000,
                0x5000,
                "wuxia",
                "wuxia"
            ),
            Err(Error::BadAddress)
        );
        assert_eq!(
            write(&mut bytes, 0, 0x1234_0000, 0x5000, "wuxia", "wuxia"),
            Err(Error::BadAddress)
        );
    }

    #[test]
    fn a_block_too_small_for_the_strings_is_refused() {
        let mut bytes = [0u8; DRIVER_OBJECT_SIZE];
        assert_eq!(
            write(
                &mut bytes,
                BLOCK_ADDRESS,
                0x1234_0000,
                0x5000,
                "wuxia",
                "wuxia"
            ),
            Err(Error::InvalidImage)
        );
    }
}
