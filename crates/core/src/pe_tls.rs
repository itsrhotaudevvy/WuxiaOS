//! Bounds-checked PE32+ thread-local storage (TLS) directory parsing.
//!
//! Data directory 9 names an `IMAGE_TLS_DIRECTORY64`: the template that seeds
//! each thread's TLS block, the slot the loader writes the TLS index into, and
//! a NULL-terminated array of callbacks. Unlike most PE fields, the four address
//! fields of that structure are absolute virtual addresses (VAs) that include
//! the image base, so each one is converted to an RVA with checked subtraction
//! before any use.
//!
//! Parsing validates metadata only. It never runs a callback, allocates TLS
//! storage or writes memory. Callback entries are read lazily through the
//! section table, the same way [`crate::pe_import`] resolves its tables, and
//! each entry is range-checked before it is yielded.

use crate::error::{Error, Result};
use crate::pe_import::SectionRange;
use crate::pe_reloc::data_directory;

/// Data directory index of the TLS table (`IMAGE_DIRECTORY_ENTRY_TLS`).
pub const TLS_DIRECTORY: usize = 9;

/// Size in bytes of `IMAGE_TLS_DIRECTORY64`.
pub const TLS_DIRECTORY64_SIZE: usize = 40;

/// Largest accepted raw template, `EndAddressOfRawData - StartAddressOfRawData`.
pub const MAX_TLS_RAW_SIZE: u64 = 1 << 20;

/// Maximum number of callbacks accepted before the NULL terminator.
pub const MAX_TLS_CALLBACKS: usize = 64;

/// Bits 20 to 23 of `Characteristics` hold an alignment code.
const ALIGN_MASK: u32 = 0x00f0_0000;
const ALIGN_SHIFT: u32 = 20;
/// Largest defined alignment code (`IMAGE_SCN_ALIGN_8192BYTES`); 0 means default.
const ALIGN_CODE_MAX: u32 = 14;

const LFANEW_OFFSET: usize = 0x3c;
const PE_OPTIONAL_OFFSET: usize = 24;
const SIZE_OF_OPTIONAL_OFFSET: usize = 20;
/// `ImageBase` within a PE32+ optional header.
const IMAGE_BASE_OFFSET: usize = 24;
/// `SizeOfImage` within either optional header format.
const SIZE_OF_IMAGE_OFFSET: usize = 56;
const CALLBACK_SIZE: usize = 8;

/// A parsed and validated `IMAGE_TLS_DIRECTORY64`.
///
/// The address fields are VAs as stored in the image. Use the `image_base`
/// implied by the image header to interpret them; [`TlsDirectory::callbacks`]
/// performs that conversion for the callback array.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsDirectory<'a> {
    /// VA of the first byte of the initialization template.
    pub start_address_of_raw_data: u64,
    /// VA one past the last byte of the initialization template.
    pub end_address_of_raw_data: u64,
    /// VA of the 32-bit slot that receives the loader's TLS index.
    pub address_of_index: u64,
    /// VA of the NULL-terminated callback array; zero when there are none.
    pub address_of_callbacks: u64,
    /// Zero bytes that follow the template in each thread's TLS block.
    pub size_of_zero_fill: u32,
    /// Raw `Characteristics` word; bits 20 to 23 hold the alignment code.
    pub characteristics: u32,
    bytes: &'a [u8],
    sections: &'a [SectionRange],
    image_base: u64,
    size_of_image: u32,
    raw_size: u64,
    callbacks_rva: Option<u32>,
}

/// Iterator over the callback VAs of a TLS directory.
///
/// Each item is a validated VA inside the image. After the first error the
/// iterator yields that error once and then ends, so corrupt input cannot loop.
#[derive(Clone, Copy, Debug)]
pub struct TlsCallbacks<'a> {
    bytes: &'a [u8],
    sections: &'a [SectionRange],
    image_base: u64,
    size_of_image: u32,
    rva: u32,
    index: usize,
    done: bool,
}

impl<'a> TlsDirectory<'a> {
    /// Parse the TLS directory of a PE32+ image.
    ///
    /// `image` and `sections` are the inputs [`crate::pe_import::ImportDirectory`]
    /// takes. Returns `Ok(None)` when the image declares no TLS directory: fewer
    /// data directory slots, or a zero RVA in slot 9.
    ///
    /// Errors: `Unsupported` for a PE32 image; `InvalidImage` when the directory
    /// is shorter than 40 bytes or lies outside section raw data, when
    /// `StartAddressOfRawData` exceeds `EndAddressOfRawData`, when the template
    /// is larger than `MAX_TLS_RAW_SIZE`, when an address lies outside the image,
    /// or when the alignment code is undefined.
    pub fn parse(image: &'a [u8], sections: &'a [SectionRange]) -> Result<Option<Self>> {
        let slot = match data_directory(image, TLS_DIRECTORY) {
            Ok(slot) => slot,
            Err(Error::NotFound) => return Ok(None),
            Err(error) => return Err(error),
        };
        if slot.rva == 0 {
            return Ok(None);
        }
        if slot.size < TLS_DIRECTORY64_SIZE as u32 {
            return Err(Error::InvalidImage);
        }
        let (image_base, size_of_image) = image_layout(image)?;
        let raw: [u8; TLS_DIRECTORY64_SIZE] = read_array(image, sections, slot.rva)?;

        let start = read_u64(&raw, 0)?;
        let end = read_u64(&raw, 8)?;
        let index = read_u64(&raw, 16)?;
        let callbacks = read_u64(&raw, 24)?;
        let size_of_zero_fill = read_u32(&raw, 32)?;
        let characteristics = read_u32(&raw, 36)?;

        if start > end {
            return Err(Error::InvalidImage);
        }
        let raw_size = end - start;
        if raw_size > MAX_TLS_RAW_SIZE {
            return Err(Error::InvalidImage);
        }
        // The raw range is half-open, so its end may name the image end. Every
        // other address names a byte the loader reads or writes.
        image_rva(start, image_base, size_of_image, true)?;
        image_rva(end, image_base, size_of_image, true)?;
        image_rva(index, image_base, size_of_image, false)?;
        let callbacks_rva = if callbacks == 0 {
            None
        } else {
            Some(image_rva(callbacks, image_base, size_of_image, false)?)
        };
        if (characteristics & ALIGN_MASK) >> ALIGN_SHIFT > ALIGN_CODE_MAX {
            return Err(Error::InvalidImage);
        }

        Ok(Some(Self {
            start_address_of_raw_data: start,
            end_address_of_raw_data: end,
            address_of_index: index,
            address_of_callbacks: callbacks,
            size_of_zero_fill,
            characteristics,
            bytes: image,
            sections,
            image_base,
            size_of_image,
            raw_size,
            callbacks_rva,
        }))
    }

    /// Bytes of initialized template, `EndAddressOfRawData - StartAddressOfRawData`.
    pub const fn raw_size(&self) -> u64 {
        self.raw_size
    }

    /// Bytes in each thread's initial TLS block: the raw template plus zero fill.
    ///
    /// Errors: `OutOfRange` if the sum overflows `u64`.
    pub fn template_size(&self) -> Result<u64> {
        self.raw_size
            .checked_add(u64::from(self.size_of_zero_fill))
            .ok_or(Error::OutOfRange)
    }

    /// Required alignment of the TLS block in bytes, or `None` for the default.
    ///
    /// Only bits 20 to 23 of `Characteristics` are interpreted. Codes 1 to 14
    /// map to powers of two from 1 to 8192.
    pub const fn alignment(&self) -> Option<u32> {
        match (self.characteristics & ALIGN_MASK) >> ALIGN_SHIFT {
            0 => None,
            code => Some(1 << (code - 1)),
        }
    }

    /// Iterate the callback VAs, stopping at the NULL entry.
    ///
    /// Yields at most `MAX_TLS_CALLBACKS` entries; a further non-zero entry
    /// yields `Error::TableFull`. An image without callbacks yields nothing.
    pub fn callbacks(&self) -> TlsCallbacks<'a> {
        TlsCallbacks {
            bytes: self.bytes,
            sections: self.sections,
            image_base: self.image_base,
            size_of_image: self.size_of_image,
            rva: self.callbacks_rva.unwrap_or(0),
            index: 0,
            done: self.callbacks_rva.is_none(),
        }
    }
}

impl TlsCallbacks<'_> {
    fn read_next(&mut self) -> Result<Option<u64>> {
        let offset = self
            .index
            .checked_mul(CALLBACK_SIZE)
            .ok_or(Error::InvalidImage)?;
        let slot = rva_add(self.rva, offset)?;
        let va = u64::from_le_bytes(read_array(self.bytes, self.sections, slot)?);
        if va == 0 {
            return Ok(None);
        }
        if self.index >= MAX_TLS_CALLBACKS {
            return Err(Error::TableFull);
        }
        image_rva(va, self.image_base, self.size_of_image, false)?;
        self.index += 1;
        Ok(Some(va))
    }
}

impl Iterator for TlsCallbacks<'_> {
    type Item = Result<u64>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.read_next() {
            Ok(Some(va)) => Some(Ok(va)),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(error) => {
                self.done = true;
                Some(Err(error))
            }
        }
    }
}

/// Read `ImageBase` and `SizeOfImage` from a PE32+ image's optional header.
fn image_layout(image: &[u8]) -> Result<(u64, u32)> {
    let optional = optional_header(image)?;
    let image_base = read_u64(optional, IMAGE_BASE_OFFSET)?;
    let size_of_image = read_u32(optional, SIZE_OF_IMAGE_OFFSET)?;
    Ok((image_base, size_of_image))
}

/// Locate the optional header bytes, validating `MZ` and `PE\0\0` on the way.
fn optional_header(image: &[u8]) -> Result<&[u8]> {
    if image.len() < 0x40 || image.get(..2) != Some(b"MZ") {
        return Err(Error::InvalidImage);
    }
    let pe = read_u32(image, LFANEW_OFFSET)? as usize;
    let signature_end = pe.checked_add(4).ok_or(Error::InvalidImage)?;
    if image.get(pe..signature_end) != Some(b"PE\0\0") {
        return Err(Error::InvalidImage);
    }
    let size_offset = pe
        .checked_add(SIZE_OF_OPTIONAL_OFFSET)
        .ok_or(Error::InvalidImage)?;
    let optional_size = read_u16(image, size_offset)? as usize;
    let start = pe
        .checked_add(PE_OPTIONAL_OFFSET)
        .ok_or(Error::InvalidImage)?;
    let end = start
        .checked_add(optional_size)
        .ok_or(Error::InvalidImage)?;
    image.get(start..end).ok_or(Error::InvalidImage)
}

/// Convert a VA to an RVA inside `[image_base, image_base + size_of_image)`.
///
/// With `one_past_end`, the image end itself is also accepted, for exclusive
/// range bounds.
fn image_rva(va: u64, image_base: u64, size_of_image: u32, one_past_end: bool) -> Result<u32> {
    let rva = va.checked_sub(image_base).ok_or(Error::InvalidImage)?;
    let limit = u64::from(size_of_image);
    let inside = if one_past_end {
        rva <= limit
    } else {
        rva < limit
    };
    if !inside {
        return Err(Error::InvalidImage);
    }
    u32::try_from(rva).map_err(|_| Error::InvalidImage)
}

/// Translate an RVA to its file offset and the bytes readable from there.
///
/// Returns `(offset, available)` where `available` counts bytes up to the end
/// of the containing section's raw data, clipped to the image length.
fn resolve(bytes: &[u8], sections: &[SectionRange], rva: u32) -> Result<(usize, usize)> {
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
fn read_array<const N: usize>(
    bytes: &[u8],
    sections: &[SectionRange],
    rva: u32,
) -> Result<[u8; N]> {
    let (offset, available) = resolve(bytes, sections, rva)?;
    if available < N {
        return Err(Error::InvalidImage);
    }
    let end = offset.checked_add(N).ok_or(Error::InvalidImage)?;
    let source = bytes.get(offset..end).ok_or(Error::InvalidImage)?;
    <[u8; N]>::try_from(source).map_err(|_| Error::InvalidImage)
}

fn rva_add(base: u32, delta: usize) -> Result<u32> {
    let delta = u32::try_from(delta).map_err(|_| Error::InvalidImage)?;
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

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let end = offset.checked_add(8).ok_or(Error::InvalidImage)?;
    let bytes = bytes.get(offset..end).ok_or(Error::InvalidImage)?;
    let mut word = [0u8; 8];
    word.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(word))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x1_4000_0000;
    const IMAGE_SIZE: u32 = 0x3000;
    const SECTION: SectionRange = SectionRange {
        virtual_address: 0x1000,
        raw_offset: 0x200,
        raw_size: 0x400,
    };
    const TLS_RVA: u32 = 0x1000;
    const INDEX_RVA: u32 = 0x1200;
    const CALLBACKS_RVA: u32 = 0x1100;
    const TEMPLATE_RVA: u32 = 0x1300;
    /// File offset of data directory 9 in the test header built by `header`.
    const TLS_SLOT: usize = 0x58 + 112 + TLS_DIRECTORY * 8;
    /// File offset of `NumberOfRvaAndSizes` in the test header.
    const COUNT_OFFSET: usize = 0x58 + 108;

    /// A 0x600-byte PE32+ image: 0x200 header bytes, then one 0x400-byte section.
    fn header(size_of_image: u32) -> [u8; 0x600] {
        let mut b = [0u8; 0x600];
        b[..2].copy_from_slice(b"MZ");
        b[LFANEW_OFFSET..LFANEW_OFFSET + 4].copy_from_slice(&0x40u32.to_le_bytes());
        b[0x40..0x44].copy_from_slice(b"PE\0\0");
        b[0x54..0x56].copy_from_slice(&240u16.to_le_bytes());
        b[0x58..0x5a].copy_from_slice(&0x20bu16.to_le_bytes());
        b[0x58 + IMAGE_BASE_OFFSET..0x58 + IMAGE_BASE_OFFSET + 8]
            .copy_from_slice(&BASE.to_le_bytes());
        b[0x58 + SIZE_OF_IMAGE_OFFSET..0x58 + SIZE_OF_IMAGE_OFFSET + 4]
            .copy_from_slice(&size_of_image.to_le_bytes());
        b[COUNT_OFFSET..COUNT_OFFSET + 4].copy_from_slice(&16u32.to_le_bytes());
        b[TLS_SLOT..TLS_SLOT + 4].copy_from_slice(&TLS_RVA.to_le_bytes());
        b[TLS_SLOT + 4..TLS_SLOT + 8].copy_from_slice(&40u32.to_le_bytes());
        b
    }

    /// Write `data` at `rva`, which must lie inside `SECTION`.
    fn put(img: &mut [u8], rva: u32, data: &[u8]) {
        let at = (rva - SECTION.virtual_address) as usize + SECTION.raw_offset;
        img[at..at + data.len()].copy_from_slice(data);
    }

    fn put_u64s(img: &mut [u8], rva: u32, values: &[u64]) {
        for (i, value) in values.iter().enumerate() {
            put(img, rva + (i as u32) * 8, &value.to_le_bytes());
        }
    }

    /// An image whose TLS struct holds `vas` (start, end, index, callbacks).
    fn tls_image(size_of_image: u32, vas: [u64; 4], zero_fill: u32, chars: u32) -> [u8; 0x600] {
        let mut img = header(size_of_image);
        put_u64s(&mut img, TLS_RVA, &vas);
        put(&mut img, TLS_RVA + 32, &zero_fill.to_le_bytes());
        put(&mut img, TLS_RVA + 36, &chars.to_le_bytes());
        img
    }

    /// A valid 32-byte template at `TEMPLATE_RVA` with a 16-byte zero fill.
    fn valid_image() -> [u8; 0x600] {
        tls_image(
            IMAGE_SIZE,
            [
                BASE + u64::from(TEMPLATE_RVA),
                BASE + u64::from(TEMPLATE_RVA) + 0x20,
                BASE + u64::from(INDEX_RVA),
                0,
            ],
            0x10,
            0,
        )
    }

    #[test]
    fn absent_directory_yields_none() {
        let sections = [SECTION];

        let mut zero_rva = valid_image();
        zero_rva[TLS_SLOT..TLS_SLOT + 4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(TlsDirectory::parse(&zero_rva, &sections), Ok(None));

        let mut few_slots = valid_image();
        few_slots[COUNT_OFFSET..COUNT_OFFSET + 4].copy_from_slice(&9u32.to_le_bytes());
        assert_eq!(TlsDirectory::parse(&few_slots, &sections), Ok(None));
    }

    #[test]
    fn parses_fields_and_exposes_template_geometry() {
        let img = valid_image();
        let sections = [SECTION];
        let tls = TlsDirectory::parse(&img, &sections).unwrap().unwrap();
        assert_eq!(tls.start_address_of_raw_data, BASE + 0x1300);
        assert_eq!(tls.end_address_of_raw_data, BASE + 0x1320);
        assert_eq!(tls.address_of_index, BASE + 0x1200);
        assert_eq!(tls.address_of_callbacks, 0);
        assert_eq!(tls.size_of_zero_fill, 0x10);
        assert_eq!(tls.raw_size(), 0x20);
        assert_eq!(tls.template_size(), Ok(0x30));
        assert_eq!(tls.alignment(), None);
        assert_eq!(tls.callbacks().next(), None);
    }

    #[test]
    fn template_size_is_raw_plus_checked_zero_fill() {
        let sections = [SECTION];
        let big_fill = tls_image(
            IMAGE_SIZE,
            [BASE + 0x1300, BASE + 0x1320, BASE + 0x1200, 0],
            u32::MAX,
            0,
        );
        let tls = TlsDirectory::parse(&big_fill, &sections).unwrap().unwrap();
        assert_eq!(tls.template_size(), Ok(0x20 + u64::from(u32::MAX)));
    }

    #[test]
    fn rejects_start_after_end() {
        let sections = [SECTION];
        let img = tls_image(
            IMAGE_SIZE,
            [BASE + 0x1320, BASE + 0x1300, BASE + 0x1200, 0],
            0,
            0,
        );
        assert_eq!(
            TlsDirectory::parse(&img, &sections),
            Err(Error::InvalidImage)
        );
    }

    #[test]
    fn caps_raw_template_size() {
        let sections = [SECTION];
        // A larger image so the cap, not the image bound, decides.
        let at_cap = tls_image(
            0x20_0000,
            [
                BASE + 0x1000,
                BASE + 0x1000 + MAX_TLS_RAW_SIZE,
                BASE + 0x1200,
                0,
            ],
            0,
            0,
        );
        let tls = TlsDirectory::parse(&at_cap, &sections).unwrap().unwrap();
        assert_eq!(tls.raw_size(), MAX_TLS_RAW_SIZE);

        let over_cap = tls_image(
            0x20_0000,
            [
                BASE + 0x1000,
                BASE + 0x1000 + MAX_TLS_RAW_SIZE + 1,
                BASE + 0x1200,
                0,
            ],
            0,
            0,
        );
        assert_eq!(
            TlsDirectory::parse(&over_cap, &sections),
            Err(Error::InvalidImage)
        );
    }

    #[test]
    fn rejects_addresses_outside_the_image() {
        let sections = [SECTION];
        let end = BASE + u64::from(IMAGE_SIZE);
        let cases = [
            // Start below the image base.
            [BASE - 1, BASE + 0x1320, BASE + 0x1200, 0],
            // End past the image end.
            [BASE + 0x1300, end + 1, BASE + 0x1200, 0],
            // The index slot must name a byte, so the image end is refused.
            [BASE + 0x1300, BASE + 0x1320, end, 0],
            // A non-zero callback array outside the image.
            [BASE + 0x1300, BASE + 0x1320, BASE + 0x1200, end],
        ];
        for vas in cases {
            let img = tls_image(IMAGE_SIZE, vas, 0, 0);
            assert_eq!(
                TlsDirectory::parse(&img, &sections),
                Err(Error::InvalidImage),
                "{vas:x?}"
            );
        }

        // The image end is a valid exclusive bound for the raw template.
        let at_end = tls_image(IMAGE_SIZE, [end - 0x20, end, BASE + 0x1200, 0], 0, 0);
        assert!(TlsDirectory::parse(&at_end, &sections).unwrap().is_some());
    }

    #[test]
    fn alignment_code_is_validated_and_decoded() {
        let sections = [SECTION];
        let with_chars = |chars: u32| {
            let img = tls_image(
                IMAGE_SIZE,
                [BASE + 0x1300, BASE + 0x1320, BASE + 0x1200, 0],
                0,
                chars,
            );
            TlsDirectory::parse(&img, &sections).map(|tls| tls.and_then(|t| t.alignment()))
        };
        assert_eq!(with_chars(0), Ok(None));
        assert_eq!(with_chars(1 << 20), Ok(Some(1)));
        assert_eq!(with_chars(4 << 20), Ok(Some(8)));
        assert_eq!(with_chars(14 << 20), Ok(Some(8192)));
        // Bits outside the alignment field do not affect the decoded alignment.
        assert_eq!(with_chars(0x8000_0001), Ok(None));
        // Code 15 is not defined.
        assert_eq!(with_chars(15 << 20), Err(Error::InvalidImage));
    }

    #[test]
    fn iterates_callbacks_until_the_null_entry() {
        let sections = [SECTION];
        let mut img = tls_image(
            IMAGE_SIZE,
            [
                BASE + 0x1300,
                BASE + 0x1320,
                BASE + 0x1200,
                BASE + u64::from(CALLBACKS_RVA),
            ],
            0,
            0,
        );
        put_u64s(&mut img, CALLBACKS_RVA, &[BASE + 0x2000, BASE + 0x2010, 0]);
        let tls = TlsDirectory::parse(&img, &sections).unwrap().unwrap();
        let mut callbacks = tls.callbacks();
        assert_eq!(callbacks.next(), Some(Ok(BASE + 0x2000)));
        assert_eq!(callbacks.next(), Some(Ok(BASE + 0x2010)));
        assert_eq!(callbacks.next(), None);
        assert_eq!(callbacks.next(), None);
    }

    #[test]
    fn empty_callback_array_yields_nothing() {
        let sections = [SECTION];
        let mut img = tls_image(
            IMAGE_SIZE,
            [
                BASE + 0x1300,
                BASE + 0x1320,
                BASE + 0x1200,
                BASE + u64::from(CALLBACKS_RVA),
            ],
            0,
            0,
        );
        put_u64s(&mut img, CALLBACKS_RVA, &[0]);
        let tls = TlsDirectory::parse(&img, &sections).unwrap().unwrap();
        assert_eq!(tls.callbacks().next(), None);
    }

    #[test]
    fn rejects_callbacks_outside_the_image() {
        let sections = [SECTION];
        let end = BASE + u64::from(IMAGE_SIZE);
        for bad in [BASE - 8, 0x1000, end] {
            let mut img = tls_image(
                IMAGE_SIZE,
                [
                    BASE + 0x1300,
                    BASE + 0x1320,
                    BASE + 0x1200,
                    BASE + u64::from(CALLBACKS_RVA),
                ],
                0,
                0,
            );
            put_u64s(&mut img, CALLBACKS_RVA, &[BASE + 0x2000, bad, 0]);
            let tls = TlsDirectory::parse(&img, &sections).unwrap().unwrap();
            let mut callbacks = tls.callbacks();
            assert_eq!(callbacks.next(), Some(Ok(BASE + 0x2000)));
            assert_eq!(callbacks.next(), Some(Err(Error::InvalidImage)), "{bad:x}");
            assert_eq!(callbacks.next(), None);
        }
    }

    #[test]
    fn caps_callback_count_at_max_tls_callbacks() {
        let sections = [SECTION];
        let array_with = |count: usize| {
            let mut img = tls_image(
                IMAGE_SIZE,
                [
                    BASE + 0x1300,
                    BASE + 0x1320,
                    BASE + 0x1200,
                    BASE + u64::from(CALLBACKS_RVA),
                ],
                0,
                0,
            );
            for index in 0..count {
                put_u64s(
                    &mut img,
                    CALLBACKS_RVA + (index as u32) * 8,
                    &[BASE + 0x2000],
                );
            }
            img
        };

        let img = array_with(MAX_TLS_CALLBACKS);
        let tls = TlsDirectory::parse(&img, &sections).unwrap().unwrap();
        let mut callbacks = tls.callbacks();
        for _ in 0..MAX_TLS_CALLBACKS {
            assert_eq!(callbacks.next(), Some(Ok(BASE + 0x2000)));
        }
        assert_eq!(callbacks.next(), None);

        let img = array_with(MAX_TLS_CALLBACKS + 1);
        let tls = TlsDirectory::parse(&img, &sections).unwrap().unwrap();
        let mut callbacks = tls.callbacks();
        for _ in 0..MAX_TLS_CALLBACKS {
            assert!(callbacks.next().unwrap().is_ok());
        }
        assert_eq!(callbacks.next(), Some(Err(Error::TableFull)));
        assert_eq!(callbacks.next(), None);
    }

    #[test]
    fn callback_array_must_stay_inside_its_section() {
        let sections = [SECTION];
        // The array starts in the last slot of the section; the next slot is past it.
        let mut img = tls_image(
            IMAGE_SIZE,
            [BASE + 0x1300, BASE + 0x1320, BASE + 0x1200, BASE + 0x13f8],
            0,
            0,
        );
        put_u64s(&mut img, 0x13f8, &[BASE + 0x2000]);
        let tls = TlsDirectory::parse(&img, &sections).unwrap().unwrap();
        let mut callbacks = tls.callbacks();
        assert_eq!(callbacks.next(), Some(Ok(BASE + 0x2000)));
        assert_eq!(callbacks.next(), Some(Err(Error::InvalidImage)));
        assert_eq!(callbacks.next(), None);
    }

    #[test]
    fn rejects_directory_outside_section_or_too_short() {
        let sections = [SECTION];

        let mut outside = valid_image();
        outside[TLS_SLOT..TLS_SLOT + 4].copy_from_slice(&0x2000u32.to_le_bytes());
        assert_eq!(
            TlsDirectory::parse(&outside, &sections),
            Err(Error::InvalidImage)
        );

        let mut short = valid_image();
        short[TLS_SLOT + 4..TLS_SLOT + 8].copy_from_slice(&39u32.to_le_bytes());
        assert_eq!(
            TlsDirectory::parse(&short, &sections),
            Err(Error::InvalidImage)
        );
    }

    #[test]
    fn pe32_images_are_unsupported() {
        let sections = [SECTION];
        let mut img = valid_image();
        img[0x58..0x5a].copy_from_slice(&0x10bu16.to_le_bytes());
        assert_eq!(
            TlsDirectory::parse(&img, &sections),
            Err(Error::Unsupported)
        );
    }
}
