//! Bounds-checked PE32+ data directory and base relocation handling.
//!
//! The `.reloc` directory is a sequence of blocks. Each block names a 4 KiB
//! page by RVA and lists 16-bit entries whose high nibble is a relocation type
//! and whose low twelve bits are a byte offset inside that page. Parsing
//! validates container metadata only; applying patches the caller-owned image
//! buffer, and only after every entry has been validated.

use crate::error::{Error, Result};

/// Number of data directory slots the PE format can describe.
pub const DIRECTORY_ENTRY_COUNT: usize = 16;

/// Index of the base relocation directory (`IMAGE_DIRECTORY_ENTRY_BASERELOC`).
pub const BASE_RELOCATION_DIRECTORY: usize = 5;

/// Relocation type that is a no-op padding entry (`IMAGE_REL_BASED_ABSOLUTE`).
pub const REL_BASED_ABSOLUTE: u8 = 0;

/// Relocation type that adds the image delta to a 64-bit slot
/// (`IMAGE_REL_BASED_DIR64`).
pub const REL_BASED_DIR64: u8 = 10;

const PE32_MAGIC: u16 = 0x10b;
const PE32_PLUS_MAGIC: u16 = 0x20b;
const LFANEW_OFFSET: usize = 0x3c;
const SIZE_OF_OPTIONAL_OFFSET: usize = 20;
const OPTIONAL_OFFSET: usize = 24;
const NUMBER_OF_RVA_AND_SIZES_OFFSET: usize = 108;
const DIRECTORIES_OFFSET: usize = 112;
const DIRECTORY_SIZE: usize = 8;
const BLOCK_HEADER_SIZE: usize = 8;
const DIR64_SIZE: u64 = 8;

/// A data directory slot: the RVA and size of a table inside the image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataDirectory {
    /// Relative virtual address of the table; zero when the slot is empty.
    pub rva: u32,
    /// Size in bytes of the table; zero when the slot is empty.
    pub size: u32,
}

/// One relocation block: a 4 KiB page and the entries that patch it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelocationBlock<'a> {
    /// Page RVA that every entry offset is relative to.
    pub page_rva: u32,
    /// Raw little-endian entry words; the length is always even.
    entries: &'a [u8],
}

/// One decoded 16-bit relocation entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelocationEntry {
    /// Relocation type, taken from the high four bits.
    pub kind: u8,
    /// Byte offset inside the page, taken from the low twelve bits.
    pub offset: u16,
}

/// Iterator over the blocks of a `.reloc` directory.
///
/// After the first malformed block the iterator yields that error once and
/// then ends, so a caller can never loop on corrupt input.
#[derive(Clone, Copy, Debug)]
pub struct BaseRelocations<'a> {
    bytes: &'a [u8],
    offset: usize,
}

/// Iterator over the entries of one [`RelocationBlock`].
#[derive(Clone, Copy, Debug)]
pub struct RelocationEntries<'a> {
    bytes: &'a [u8],
}

/// Read one data directory slot from a PE32+ optional header.
///
/// `image` is the raw file or mapped image. The function checks `e_lfanew`,
/// the `PE\0\0` signature, the PE32+ optional-header magic, and that the
/// requested slot lies inside both `NumberOfRvaAndSizes` and
/// `SizeOfOptionalHeader`. Empty slots are returned as zeroes, not as errors.
///
/// Errors: `InvalidInput` for an index of 16 or more, `NotFound` when the
/// header declares fewer slots, `Unsupported` for a PE32 image, and
/// `InvalidImage` for any other malformed header.
pub fn data_directory(image: &[u8], index: usize) -> Result<DataDirectory> {
    if index >= DIRECTORY_ENTRY_COUNT {
        return Err(Error::InvalidInput);
    }
    if image.len() < 0x40 || image.get(..2) != Some(b"MZ") {
        return Err(Error::InvalidImage);
    }
    let pe = read_u32(image, LFANEW_OFFSET)? as usize;
    let signature_end = pe.checked_add(4).ok_or(Error::InvalidImage)?;
    if image.get(pe..signature_end) != Some(b"PE\0\0") {
        return Err(Error::InvalidImage);
    }
    let size_offset = offset_at(pe, SIZE_OF_OPTIONAL_OFFSET)?;
    let optional_size = read_u16(image, size_offset)? as usize;
    let optional_offset = offset_at(pe, OPTIONAL_OFFSET)?;
    let optional_end = optional_offset
        .checked_add(optional_size)
        .ok_or(Error::InvalidImage)?;
    let optional = image
        .get(optional_offset..optional_end)
        .ok_or(Error::InvalidImage)?;
    match read_u16(optional, 0)? {
        PE32_PLUS_MAGIC => {}
        PE32_MAGIC => return Err(Error::Unsupported),
        _ => return Err(Error::InvalidImage),
    }
    let declared = read_u32(optional, NUMBER_OF_RVA_AND_SIZES_OFFSET)? as usize;
    if index >= declared {
        return Err(Error::NotFound);
    }
    let entry = DIRECTORIES_OFFSET
        .checked_add(
            index
                .checked_mul(DIRECTORY_SIZE)
                .ok_or(Error::InvalidImage)?,
        )
        .ok_or(Error::InvalidImage)?;
    Ok(DataDirectory {
        rva: read_u32(optional, entry)?,
        size: read_u32(optional, entry + 4)?,
    })
}

impl<'a> BaseRelocations<'a> {
    /// Start iterating over a `.reloc` directory slice.
    ///
    /// An empty slice yields no blocks. The slice must be exactly the
    /// directory's declared size; trailing bytes are reported as errors.
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
}

impl<'a> Iterator for BaseRelocations<'a> {
    type Item = Result<RelocationBlock<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
            return None;
        }
        match parse_block(self.bytes, self.offset) {
            Ok((block, next)) => {
                self.offset = next;
                Some(Ok(block))
            }
            Err(error) => {
                self.offset = self.bytes.len();
                Some(Err(error))
            }
        }
    }
}

impl<'a> RelocationBlock<'a> {
    /// Iterate over the entries of this block, padding included.
    pub const fn entries(&self) -> RelocationEntries<'a> {
        RelocationEntries {
            bytes: self.entries,
        }
    }
}

impl Iterator for RelocationEntries<'_> {
    type Item = RelocationEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let (word, rest) = self.bytes.split_first_chunk::<2>()?;
        self.bytes = rest;
        let word = u16::from_le_bytes(*word);
        Some(RelocationEntry {
            kind: (word >> 12) as u8,
            offset: word & 0x0fff,
        })
    }
}

/// Apply base relocations to `image` for a load delta of `delta`.
///
/// `image` is laid out by RVA, so an RVA is an index into the slice and
/// `relocs` is the `.reloc` directory bytes. `REL_BASED_ABSOLUTE` entries are
/// skipped. `REL_BASED_DIR64` entries add `delta` to the little-endian `u64`
/// at `page_rva + offset` with wrapping arithmetic.
///
/// Every block, entry type and target range is validated before the first
/// write, so an error leaves `image` unchanged. Returns the number of DIR64
/// slots patched.
///
/// Errors: `InvalidImage` for a malformed block or a target outside `image`,
/// and `Unsupported` for any relocation type other than ABSOLUTE or DIR64.
pub fn apply(image: &mut [u8], relocs: &[u8], delta: i64) -> Result<usize> {
    let limit = image.len();
    for block in BaseRelocations::new(relocs) {
        let block = block?;
        for entry in block.entries() {
            match entry.kind {
                REL_BASED_ABSOLUTE => {}
                REL_BASED_DIR64 => {
                    dir64_target(limit, block.page_rva, entry.offset)?;
                }
                _ => return Err(Error::Unsupported),
            }
        }
    }

    let mut applied = 0usize;
    for block in BaseRelocations::new(relocs) {
        let block = block?;
        for entry in block.entries() {
            if entry.kind != REL_BASED_DIR64 {
                continue;
            }
            let start = dir64_target(limit, block.page_rva, entry.offset)?;
            let end = start
                .checked_add(DIR64_SIZE as usize)
                .ok_or(Error::InvalidImage)?;
            let slot = image.get_mut(start..end).ok_or(Error::InvalidImage)?;
            let mut raw = [0u8; 8];
            raw.copy_from_slice(slot);
            let value = u64::from_le_bytes(raw).wrapping_add_signed(delta);
            slot.copy_from_slice(&value.to_le_bytes());
            applied = applied.checked_add(1).ok_or(Error::OutOfRange)?;
        }
    }
    Ok(applied)
}

/// Parse the block at `offset`, returning it and the offset of the next block.
fn parse_block(bytes: &[u8], offset: usize) -> Result<(RelocationBlock<'_>, usize)> {
    if bytes.len().saturating_sub(offset) < BLOCK_HEADER_SIZE {
        return Err(Error::InvalidImage);
    }
    let page_rva = read_u32(bytes, offset)?;
    let block_size = read_u32(bytes, offset + 4)? as usize;
    if block_size < BLOCK_HEADER_SIZE || !block_size.is_multiple_of(2) {
        return Err(Error::InvalidImage);
    }
    let end = offset.checked_add(block_size).ok_or(Error::InvalidImage)?;
    let block = bytes.get(offset..end).ok_or(Error::InvalidImage)?;
    let entries = block.get(BLOCK_HEADER_SIZE..).ok_or(Error::InvalidImage)?;
    Ok((RelocationBlock { page_rva, entries }, end))
}

/// Return the start index of a DIR64 slot, checking that all 8 bytes fit.
fn dir64_target(limit: usize, page_rva: u32, offset: u16) -> Result<usize> {
    let start = u64::from(page_rva)
        .checked_add(u64::from(offset))
        .ok_or(Error::InvalidImage)?;
    let end = start.checked_add(DIR64_SIZE).ok_or(Error::InvalidImage)?;
    let limit = u64::try_from(limit).map_err(|_| Error::OutOfRange)?;
    if end > limit {
        return Err(Error::InvalidImage);
    }
    usize::try_from(start).map_err(|_| Error::InvalidImage)
}

fn offset_at(base: usize, delta: usize) -> Result<usize> {
    base.checked_add(delta).ok_or(Error::InvalidImage)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let end = offset.checked_add(2).ok_or(Error::InvalidImage)?;
    let bytes = bytes.get(offset..end).ok_or(Error::InvalidImage)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset.checked_add(4).ok_or(Error::InvalidImage)?;
    let bytes = bytes.get(offset..end).ok_or(Error::InvalidImage)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PE_OFFSET: usize = 0x40;
    const OPTIONAL: usize = PE_OFFSET + OPTIONAL_OFFSET;

    /// Build a PE32+ header with `count` directory slots declared.
    fn pe64(optional_size: u16, count: u32) -> [u8; 0x200] {
        let mut b = [0u8; 0x200];
        b[..2].copy_from_slice(b"MZ");
        b[LFANEW_OFFSET..LFANEW_OFFSET + 4].copy_from_slice(&(PE_OFFSET as u32).to_le_bytes());
        b[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");
        b[PE_OFFSET + 4..PE_OFFSET + 6].copy_from_slice(&0x8664u16.to_le_bytes());
        b[PE_OFFSET + 6..PE_OFFSET + 8].copy_from_slice(&1u16.to_le_bytes());
        b[PE_OFFSET + 20..PE_OFFSET + 22].copy_from_slice(&optional_size.to_le_bytes());
        b[OPTIONAL..OPTIONAL + 2].copy_from_slice(&PE32_PLUS_MAGIC.to_le_bytes());
        let count_at = OPTIONAL + NUMBER_OF_RVA_AND_SIZES_OFFSET;
        b[count_at..count_at + 4].copy_from_slice(&count.to_le_bytes());
        b
    }

    fn set_directory(b: &mut [u8], index: usize, rva: u32, size: u32) {
        let at = OPTIONAL + DIRECTORIES_OFFSET + index * DIRECTORY_SIZE;
        b[at..at + 4].copy_from_slice(&rva.to_le_bytes());
        b[at + 4..at + 8].copy_from_slice(&size.to_le_bytes());
    }

    const fn entry(kind: u16, offset: u16) -> u16 {
        (kind << 12) | offset
    }

    /// Write one block at `at` and return the offset just past it.
    fn write_block(out: &mut [u8], at: usize, page: u32, entries: &[u16]) -> usize {
        let size = BLOCK_HEADER_SIZE + entries.len() * 2;
        out[at..at + 4].copy_from_slice(&page.to_le_bytes());
        out[at + 4..at + 8].copy_from_slice(&(size as u32).to_le_bytes());
        for (i, word) in entries.iter().enumerate() {
            let p = at + BLOCK_HEADER_SIZE + i * 2;
            out[p..p + 2].copy_from_slice(&word.to_le_bytes());
        }
        at + size
    }

    #[test]
    fn reads_base_relocation_directory_from_pe32_plus() {
        let mut image = pe64(240, 16);
        set_directory(&mut image, BASE_RELOCATION_DIRECTORY, 0x5000, 0x20);
        assert_eq!(
            data_directory(&image, BASE_RELOCATION_DIRECTORY),
            Ok(DataDirectory {
                rva: 0x5000,
                size: 0x20
            })
        );
        assert_eq!(
            data_directory(&image, 0),
            Ok(DataDirectory { rva: 0, size: 0 })
        );
    }

    #[test]
    fn rejects_bad_dos_pe_and_magic_headers() {
        assert_eq!(data_directory(&[], 0), Err(Error::InvalidImage));

        let mut no_mz = pe64(240, 16);
        no_mz[0] = b'X';
        assert_eq!(data_directory(&no_mz, 0), Err(Error::InvalidImage));

        let mut bad_lfanew = pe64(240, 16);
        bad_lfanew[LFANEW_OFFSET..LFANEW_OFFSET + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(data_directory(&bad_lfanew, 0), Err(Error::InvalidImage));

        let mut bad_signature = pe64(240, 16);
        bad_signature[PE_OFFSET] = b'Q';
        assert_eq!(data_directory(&bad_signature, 0), Err(Error::InvalidImage));

        let mut pe32 = pe64(240, 16);
        pe32[OPTIONAL..OPTIONAL + 2].copy_from_slice(&PE32_MAGIC.to_le_bytes());
        assert_eq!(data_directory(&pe32, 0), Err(Error::Unsupported));

        let mut rom = pe64(240, 16);
        rom[OPTIONAL..OPTIONAL + 2].copy_from_slice(&0x107u16.to_le_bytes());
        assert_eq!(data_directory(&rom, 0), Err(Error::InvalidImage));
    }

    #[test]
    fn rejects_out_of_range_directory_indices() {
        let image = pe64(240, 5);
        assert_eq!(data_directory(&image, 16), Err(Error::InvalidInput));
        assert_eq!(data_directory(&image, usize::MAX), Err(Error::InvalidInput));
        assert_eq!(data_directory(&image, 5), Err(Error::NotFound));
        assert!(data_directory(&image, 4).is_ok());
    }

    #[test]
    fn rejects_directory_outside_optional_header() {
        // Room for slots 0..5 only; slot 5 lies past SizeOfOptionalHeader.
        let image = pe64(112 + 5 * 8, 16);
        assert_eq!(
            data_directory(&image, 4),
            Ok(DataDirectory { rva: 0, size: 0 })
        );
        assert_eq!(data_directory(&image, 5), Err(Error::InvalidImage));

        // An optional header that runs past the end of the slice.
        let truncated = pe64(0x1ff, 16);
        assert_eq!(data_directory(&truncated, 0), Err(Error::InvalidImage));
    }

    #[test]
    fn iterates_blocks_and_decodes_entries() {
        let mut relocs = [0u8; 64];
        let mid = write_block(
            &mut relocs,
            0,
            0x1000,
            &[entry(10, 0x008), entry(0, 0), entry(10, 0xfff)],
        );
        let end = write_block(&mut relocs, mid, 0x3000, &[entry(10, 0x10)]);
        let mut blocks = BaseRelocations::new(&relocs[..end]);

        let first = blocks.next().unwrap().unwrap();
        assert_eq!(first.page_rva, 0x1000);
        let kinds: [(u8, u16); 3] = [(10, 0x008), (0, 0), (10, 0xfff)];
        let mut entries = first.entries();
        for (kind, offset) in kinds {
            assert_eq!(entries.next(), Some(RelocationEntry { kind, offset }));
        }
        assert_eq!(entries.next(), None);

        let second = blocks.next().unwrap().unwrap();
        assert_eq!(second.page_rva, 0x3000);
        assert_eq!(
            second.entries().next(),
            Some(RelocationEntry {
                kind: 10,
                offset: 0x10
            })
        );
        assert_eq!(blocks.next(), None);
        assert_eq!(BaseRelocations::new(&[]).next(), None);
    }

    #[test]
    fn rejects_block_sizes_below_header_or_odd() {
        let mut small = [0u8; 8];
        small[..4].copy_from_slice(&0x1000u32.to_le_bytes());
        small[4..].copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(
            BaseRelocations::new(&small).next(),
            Some(Err(Error::InvalidImage))
        );

        let mut odd = [0u8; 16];
        odd[..4].copy_from_slice(&0x1000u32.to_le_bytes());
        odd[4..8].copy_from_slice(&9u32.to_le_bytes());
        assert_eq!(
            BaseRelocations::new(&odd).next(),
            Some(Err(Error::InvalidImage))
        );
    }

    #[test]
    fn rejects_overrunning_and_truncated_blocks() {
        let mut overrun = [0u8; 16];
        overrun[..4].copy_from_slice(&0x1000u32.to_le_bytes());
        overrun[4..8].copy_from_slice(&0x20u32.to_le_bytes());
        assert_eq!(
            BaseRelocations::new(&overrun).next(),
            Some(Err(Error::InvalidImage))
        );

        let mut huge = [0u8; 8];
        huge[..4].copy_from_slice(&0u32.to_le_bytes());
        huge[4..].copy_from_slice(&0xffff_fffeu32.to_le_bytes());
        assert_eq!(
            BaseRelocations::new(&huge).next(),
            Some(Err(Error::InvalidImage))
        );

        // Fewer than eight bytes after a valid block is a truncated header.
        let mut relocs = [0u8; 20];
        let end = write_block(&mut relocs, 0, 0x1000, &[entry(0, 0)]);
        assert_eq!(end, 10);
        let trailing = &relocs[..end + 4];
        let mut blocks = BaseRelocations::new(trailing);
        assert!(blocks.next().unwrap().is_ok());
        assert_eq!(blocks.next(), Some(Err(Error::InvalidImage)));
    }

    #[test]
    fn iterator_ends_after_reporting_an_error() {
        let mut relocs = [0u8; 8];
        relocs[..4].copy_from_slice(&0x1000u32.to_le_bytes());
        relocs[4..].copy_from_slice(&3u32.to_le_bytes());
        let mut blocks = BaseRelocations::new(&relocs);
        assert_eq!(blocks.next(), Some(Err(Error::InvalidImage)));
        assert_eq!(blocks.next(), None);
        assert_eq!(blocks.next(), None);
    }

    #[test]
    fn applies_dir64_with_wrapping_positive_and_negative_deltas() {
        let mut image = [0u8; 0x2000];
        image[0x110..0x118].copy_from_slice(&u64::MAX.to_le_bytes());
        image[0x2000 - 8..0x2000].copy_from_slice(&0x1000u64.to_le_bytes());
        // Targets are 0x100 + 0x10 = 0x110 and 0x1000 + 0xff8 = 0x1ff8.
        let mut relocs = [0u8; 32];
        let first_end = write_block(&mut relocs, 0, 0x100, &[entry(10, 0x10)]);
        let end = write_block(&mut relocs, first_end, 0x1000, &[entry(10, 0xff8)]);
        assert_eq!(end, 20);
        assert_eq!(apply(&mut image, &relocs[..end], 1), Ok(2));
        assert_eq!(
            u64::from_le_bytes(image[0x110..0x118].try_into().unwrap()),
            0
        );
        assert_eq!(
            u64::from_le_bytes(image[0x1ff8..0x2000].try_into().unwrap()),
            0x1001
        );

        // A negative delta wraps below zero.
        let mut down = [0u8; 0x200];
        down[0x10..0x18].copy_from_slice(&0u64.to_le_bytes());
        let mut one = [0u8; 16];
        let end = write_block(&mut one, 0, 0, &[entry(10, 0x10)]);
        assert_eq!(apply(&mut down, &one[..end], -1), Ok(1));
        assert_eq!(
            u64::from_le_bytes(down[0x10..0x18].try_into().unwrap()),
            u64::MAX
        );

        // i64::MIN is a valid delta and must not overflow.
        let mut min = [0u8; 0x200];
        assert_eq!(apply(&mut min, &one[..end], i64::MIN), Ok(1));
        assert_eq!(
            u64::from_le_bytes(min[0x10..0x18].try_into().unwrap()),
            1u64 << 63
        );
    }

    #[test]
    fn skips_absolute_padding_even_when_its_target_is_out_of_range() {
        let mut image = [0u8; 0x100];
        image[0x20..0x28].copy_from_slice(&7u64.to_le_bytes());
        let mut relocs = [0u8; 16];
        let end = write_block(&mut relocs, 0, 0x9000, &[entry(0, 0xfff), entry(0, 0)]);
        assert_eq!(apply(&mut image, &relocs[..end], 0x1234), Ok(0));
        assert_eq!(u64::from_le_bytes(image[0x20..0x28].try_into().unwrap()), 7);
    }

    #[test]
    fn empty_relocations_apply_nothing() {
        let mut image = [0xabu8; 0x40];
        assert_eq!(apply(&mut image, &[], 0x1000), Ok(0));
        assert!(image.iter().all(|&b| b == 0xab));
    }

    #[test]
    fn unsupported_type_rejects_without_partial_writes() {
        let mut image = [0u8; 0x100];
        image[0x10..0x18].copy_from_slice(&5u64.to_le_bytes());
        let original = image;
        let mut relocs = [0u8; 16];
        // HIGHLOW (3) is a 32-bit relocation and is not valid for PE32+.
        let end = write_block(&mut relocs, 0, 0, &[entry(10, 0x10), entry(3, 0x20)]);
        assert_eq!(
            apply(&mut image, &relocs[..end], 0x100),
            Err(Error::Unsupported)
        );
        assert_eq!(image, original);
    }

    #[test]
    fn out_of_bounds_target_rejects_without_partial_writes() {
        let mut image = [0u8; 0x100];
        image[0x10..0x18].copy_from_slice(&5u64.to_le_bytes());
        let original = image;
        let mut relocs = [0u8; 24];
        // The first entry is valid; the second's 8 bytes run past 0x100.
        let end = write_block(&mut relocs, 0, 0, &[entry(10, 0x10), entry(10, 0xf9)]);
        assert_eq!(
            apply(&mut image, &relocs[..end], 0x100),
            Err(Error::InvalidImage)
        );
        assert_eq!(image, original);
    }

    #[test]
    fn accepts_a_target_ending_exactly_at_the_image_end() {
        let mut image = [0u8; 0x100];
        let mut relocs = [0u8; 16];
        let end = write_block(&mut relocs, 0, 0, &[entry(10, 0xf8)]);
        assert_eq!(apply(&mut image, &relocs[..end], 1), Ok(1));
        assert_eq!(image[0xf8], 1);
    }

    #[test]
    fn rva_overflow_is_rejected_without_panicking() {
        let mut image = [0u8; 0x1000];
        let original = image;
        let mut relocs = [0u8; 16];
        let end = write_block(&mut relocs, 0, u32::MAX, &[entry(10, 0xfff)]);
        assert_eq!(
            apply(&mut image, &relocs[..end], 1),
            Err(Error::InvalidImage)
        );
        assert_eq!(image, original);
    }

    #[test]
    fn malformed_later_block_rejects_before_any_write() {
        let mut image = [0u8; 0x100];
        let mut relocs = [0u8; 32];
        let mid = write_block(&mut relocs, 0, 0, &[entry(10, 0x10)]);
        // Second block declares a size of 4, below the 8-byte header.
        relocs[mid..mid + 4].copy_from_slice(&0u32.to_le_bytes());
        relocs[mid + 4..mid + 8].copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(
            apply(&mut image, &relocs[..mid + 8], 1),
            Err(Error::InvalidImage)
        );
        assert_eq!(image, [0u8; 0x100]);
    }
}
