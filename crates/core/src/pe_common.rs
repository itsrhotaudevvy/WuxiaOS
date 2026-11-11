//! Helpers shared by the PE parsers.
//!
//! The import, export, TLS, exception and relocation parsers all translate
//! RVAs through a section table, read NUL-terminated names, decode
//! little-endian fields and walk the DOS, PE and optional headers. They share
//! these helpers so that the same malformed input yields the same error in
//! every parser.
//!
//! A read that leaves the image, or the containing section's raw data, is
//! `InvalidImage`. A name that is empty, over-long or not printable ASCII is
//! `InvalidName`.

use crate::error::{Error, Result};

/// Longest DLL, function or forwarder name accepted, excluding its NUL.
pub const MAX_NAME_LEN: usize = 255;

/// Size of the DOS header; the image must hold at least this many bytes.
const DOS_HEADER_SIZE: usize = 0x40;
/// Offset of `e_lfanew`, the file offset of the `PE\0\0` signature.
pub const LFANEW_OFFSET: usize = 0x3c;
/// Size of the `PE\0\0` signature.
const PE_SIGNATURE_SIZE: usize = 4;
/// Offset of `SizeOfOptionalHeader` from the start of the PE signature.
const SIZE_OF_OPTIONAL_OFFSET: usize = 20;
/// Offset of the optional header from the start of the PE signature.
pub const OPTIONAL_OFFSET: usize = 24;
/// Offset of `ImageBase` within a PE32+ optional header.
pub const IMAGE_BASE_OFFSET: usize = 24;
/// Offset of `SizeOfImage` within either optional header format.
pub const SIZE_OF_IMAGE_OFFSET: usize = 56;

/// One section's RVA-to-file mapping, taken from its section header.
///
/// Only the raw data is addressable: an RVA in the virtual tail beyond
/// `raw_size` has no bytes in the image and does not resolve.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SectionRange {
    /// Section virtual address relative to the image base.
    pub virtual_address: u32,
    /// Offset of the section's raw data in the image bytes.
    pub raw_offset: usize,
    /// Number of raw data bytes available in the image.
    pub raw_size: u32,
}

/// Translate an RVA to its file offset and the bytes readable from there.
///
/// Returns `(offset, available)` where `available` counts bytes up to the end
/// of the containing section's raw data, clipped to the image length.
pub fn resolve(bytes: &[u8], sections: &[SectionRange], rva: u32) -> Result<(usize, usize)> {
    for section in sections {
        let delta = match rva.checked_sub(section.virtual_address) {
            Some(delta) => delta,
            None => continue,
        };
        if delta >= section.raw_size {
            continue;
        }
        let offset = section
            .raw_offset
            .checked_add(delta as usize)
            .ok_or(Error::InvalidImage)?;
        let raw_end = section
            .raw_offset
            .checked_add(section.raw_size as usize)
            .ok_or(Error::InvalidImage)?;
        let limit = raw_end.min(bytes.len());
        if offset >= limit {
            return Err(Error::InvalidImage);
        }
        return Ok((offset, limit - offset));
    }
    Err(Error::InvalidImage)
}

/// Read a fixed-size value at an RVA, confined to one section's raw data.
pub fn read_array<const N: usize>(
    bytes: &[u8],
    sections: &[SectionRange],
    rva: u32,
) -> Result<[u8; N]> {
    let (offset, available) = resolve(bytes, sections, rva)?;
    if available < N {
        return Err(Error::InvalidImage);
    }
    array_at(bytes, offset)
}

/// Read a NUL-terminated printable ASCII name of at most `MAX_NAME_LEN` bytes.
///
/// The terminator must appear inside the containing section's raw data.
pub fn read_name<'a>(bytes: &'a [u8], sections: &[SectionRange], rva: u32) -> Result<&'a str> {
    let (offset, available) = resolve(bytes, sections, rva)?;
    // Scan at most one byte past the maximum so an over-long name is detected.
    let window = slice_at(bytes, offset, available.min(MAX_NAME_LEN + 1))?;
    let nul = window
        .iter()
        .position(|&b| b == 0)
        .ok_or(Error::InvalidName)?;
    if nul == 0 {
        return Err(Error::InvalidName);
    }
    let text = window.get(..nul).ok_or(Error::InvalidName)?;
    if !text.iter().all(|&b| is_printable(b)) {
        return Err(Error::InvalidName);
    }
    core::str::from_utf8(text).map_err(|_| Error::InvalidName)
}

/// Resolve a table of `len` bytes at an RVA, which must lie inside one
/// section's raw data.
pub fn table_bytes<'a>(
    bytes: &'a [u8],
    sections: &[SectionRange],
    rva: u32,
    len: usize,
) -> Result<&'a [u8]> {
    let (offset, available) = resolve(bytes, sections, rva)?;
    if available < len {
        return Err(Error::InvalidImage);
    }
    slice_at(bytes, offset, len)
}

/// Add a byte delta to an RVA with checked arithmetic.
pub fn rva_add(base: u32, delta: usize) -> Result<u32> {
    let delta = u32::try_from(delta).map_err(|_| Error::InvalidImage)?;
    base.checked_add(delta).ok_or(Error::InvalidImage)
}

/// Borrow `len` bytes at `offset`, failing if the range leaves `bytes`.
pub fn slice_at(bytes: &[u8], offset: usize, len: usize) -> Result<&[u8]> {
    let end = offset.checked_add(len).ok_or(Error::InvalidImage)?;
    bytes.get(offset..end).ok_or(Error::InvalidImage)
}

/// Read a little-endian `u16` at `offset`.
pub fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    array_at(bytes, offset).map(u16::from_le_bytes)
}

/// Read a little-endian `u32` at `offset`.
pub fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    array_at(bytes, offset).map(u32::from_le_bytes)
}

/// Read a little-endian `u64` at `offset`.
pub fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    array_at(bytes, offset).map(u64::from_le_bytes)
}

/// True for the printable ASCII range `0x20..=0x7e`.
pub fn is_printable(byte: u8) -> bool {
    (0x20..=0x7e).contains(&byte)
}

/// Return the optional header bytes of a PE image.
///
/// Checks the `MZ` marker, that `e_lfanew` names a `PE\0\0` signature, and that
/// the optional header lies inside the image. The slice is `SizeOfOptionalHeader`
/// bytes long. The magic is not checked here, so callers choose which
/// optional-header formats they accept.
pub fn optional_header(image: &[u8]) -> Result<&[u8]> {
    if image.len() < DOS_HEADER_SIZE || image.get(..2) != Some(b"MZ") {
        return Err(Error::InvalidImage);
    }
    let pe = read_u32(image, LFANEW_OFFSET)? as usize;
    let signature_end = pe
        .checked_add(PE_SIGNATURE_SIZE)
        .ok_or(Error::InvalidImage)?;
    if image.get(pe..signature_end) != Some(b"PE\0\0") {
        return Err(Error::InvalidImage);
    }
    let size_offset = pe
        .checked_add(SIZE_OF_OPTIONAL_OFFSET)
        .ok_or(Error::InvalidImage)?;
    let optional_size = read_u16(image, size_offset)? as usize;
    let start = pe.checked_add(OPTIONAL_OFFSET).ok_or(Error::InvalidImage)?;
    let end = start
        .checked_add(optional_size)
        .ok_or(Error::InvalidImage)?;
    image.get(start..end).ok_or(Error::InvalidImage)
}

/// Read `ImageBase` and `SizeOfImage` from a PE image's optional header.
pub fn image_base_and_size(image: &[u8]) -> Result<(u64, u32)> {
    let optional = optional_header(image)?;
    let image_base = read_u64(optional, IMAGE_BASE_OFFSET)?;
    let size_of_image = read_u32(optional, SIZE_OF_IMAGE_OFFSET)?;
    Ok((image_base, size_of_image))
}

/// Read exactly `N` bytes at `offset` as an array.
fn array_at<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    let raw = slice_at(bytes, offset, N)?;
    <[u8; N]>::try_from(raw).map_err(|_| Error::InvalidImage)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECTION: SectionRange = SectionRange {
        virtual_address: 0x1000,
        raw_offset: 0x40,
        raw_size: 0x10,
    };

    #[test]
    fn little_endian_reads_stay_inside_the_slice() {
        let bytes = [1u8, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(read_u16(&bytes, 0), Ok(0x0201));
        assert_eq!(read_u32(&bytes, 4), Ok(0x0807_0605));
        assert_eq!(read_u64(&bytes, 0), Ok(0x0807_0605_0403_0201));
        assert_eq!(read_u16(&bytes, 7), Err(Error::InvalidImage));
        assert_eq!(read_u32(&bytes, usize::MAX), Err(Error::InvalidImage));
    }

    #[test]
    fn section_reads_stop_at_the_raw_data_end() {
        let image = [0x5au8; 0x100];
        assert_eq!(read_array::<4>(&image, &[SECTION], 0x100c), Ok([0x5a; 4]));
        assert_eq!(
            read_array::<4>(&image, &[SECTION], 0x100e),
            Err(Error::InvalidImage)
        );
        assert_eq!(
            read_array::<4>(&image, &[SECTION], 0x1010),
            Err(Error::InvalidImage)
        );
    }

    #[test]
    fn names_need_a_terminator_inside_the_section() {
        let mut image = [0u8; 0x100];
        image[0x40..0x43].copy_from_slice(b"ab\0");
        image[0x4a..0x50].copy_from_slice(b"abcdef");
        assert_eq!(read_name(&image, &[SECTION], 0x1000), Ok("ab"));
        assert_eq!(
            read_name(&image, &[SECTION], 0x100a),
            Err(Error::InvalidName)
        );
    }

    #[test]
    fn optional_header_and_image_layout_come_from_the_pe_headers() {
        let mut image = [0u8; 0x200];
        image[..2].copy_from_slice(b"MZ");
        image[LFANEW_OFFSET..LFANEW_OFFSET + 4].copy_from_slice(&0x80u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        image[0x80 + SIZE_OF_OPTIONAL_OFFSET..0x80 + SIZE_OF_OPTIONAL_OFFSET + 2]
            .copy_from_slice(&240u16.to_le_bytes());
        let optional = 0x80 + OPTIONAL_OFFSET;
        image[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        image[optional + IMAGE_BASE_OFFSET..optional + IMAGE_BASE_OFFSET + 8]
            .copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        image[optional + SIZE_OF_IMAGE_OFFSET..optional + SIZE_OF_IMAGE_OFFSET + 4]
            .copy_from_slice(&0x3000u32.to_le_bytes());

        assert_eq!(optional_header(&image).map(<[u8]>::len), Ok(240));
        assert_eq!(image_base_and_size(&image), Ok((0x1_4000_0000, 0x3000)));

        image[..2].copy_from_slice(b"XX");
        assert_eq!(optional_header(&image), Err(Error::InvalidImage));
    }
}
