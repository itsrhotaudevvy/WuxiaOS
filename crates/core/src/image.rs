//! Bounds-checked PE/COFF parsing for the future NT image loader.
//!
//! Parsing validates container metadata; it does not map memory, trust an
//! image, resolve imports, or execute an entry point.

use crate::error::{Error, Result};

/// PE optional-header format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeKind {
    /// 32-bit PE32.
    Pe32,
    /// PE32+ (AMD64).
    Pe32Plus,
}

/// A parsed image whose section table is inside the supplied bytes.
#[derive(Clone, Copy, Debug)]
pub struct PeImage<'a> {
    bytes: &'a [u8],
    kind: PeKind,
    machine: u16,
    optional_offset: usize,
    sections_offset: usize,
    section_count: u16,
}

/// Header information needed to plan a mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeInfo {
    /// PE32 or PE32+ optional-header format.
    pub kind: PeKind,
    /// COFF machine identifier.
    pub machine: u16,
    /// Preferred image base.
    pub image_base: u64,
    /// Size of the virtual image.
    pub size_of_image: u32,
    /// Entry point relative virtual address.
    pub entry_rva: u32,
}

/// A section's validated file and virtual ranges.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Section {
    /// Section virtual address relative to the image base.
    pub virtual_address: u32,
    /// Size in memory before section alignment.
    pub virtual_size: u32,
    /// Offset to raw bytes in the file.
    pub raw_offset: usize,
    /// Number of initialized raw bytes available in the file.
    pub raw_size: u32,
    /// Section name, including trailing NUL bytes.
    pub name: [u8; 8],
    /// COFF section characteristics, including read/write/execute bits.
    pub characteristics: u32,
}

impl<'a> PeImage<'a> {
    /// Parse a PE image, checking every offset and section-table bound.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < 0x40 || bytes.get(..2) != Some(b"MZ") {
            return Err(Error::InvalidImage);
        }
        let pe = read_u32(bytes, 0x3c)? as usize;
        let signature_end = pe.checked_add(4).ok_or(Error::InvalidImage)?;
        if bytes.get(pe..signature_end) != Some(b"PE\0\0") {
            return Err(Error::InvalidImage);
        }
        let machine = read_u16(bytes, pe.checked_add(4).ok_or(Error::InvalidImage)?)?;
        if machine != 0x8664 && machine != 0x14c {
            return Err(Error::Unsupported);
        }
        let section_count = read_u16(bytes, pe.checked_add(6).ok_or(Error::InvalidImage)?)?;
        if section_count == 0 || section_count > 96 {
            return Err(Error::InvalidImage);
        }
        let optional_offset = pe.checked_add(24).ok_or(Error::InvalidImage)?;
        let optional_size =
            read_u16(bytes, pe.checked_add(20).ok_or(Error::InvalidImage)?)? as usize;
        let optional_end = optional_offset
            .checked_add(optional_size)
            .ok_or(Error::InvalidImage)?;
        let optional = bytes
            .get(optional_offset..optional_end)
            .ok_or(Error::InvalidImage)?;
        let kind = match read_u16(optional, 0)? {
            0x10b if machine == 0x14c => PeKind::Pe32,
            0x20b if machine == 0x8664 => PeKind::Pe32Plus,
            0x10b | 0x20b => return Err(Error::Unsupported),
            _ => return Err(Error::InvalidImage),
        };
        let minimum_optional_size = match kind {
            PeKind::Pe32 => 96,
            PeKind::Pe32Plus => 112,
        };
        if optional_size < minimum_optional_size {
            return Err(Error::InvalidImage);
        }
        // SectionAlignment (optional offset 32) must be a non-zero power of two.
        if !read_u32(optional, 32)?.is_power_of_two() {
            return Err(Error::InvalidImage);
        }
        let table_size = (section_count as usize)
            .checked_mul(40)
            .ok_or(Error::InvalidImage)?;
        let table_end = optional_end
            .checked_add(table_size)
            .ok_or(Error::InvalidImage)?;
        if bytes.get(optional_end..table_end).is_none() {
            return Err(Error::InvalidImage);
        }
        let image = Self {
            bytes,
            kind,
            machine,
            optional_offset,
            sections_offset: optional_end,
            section_count,
        };
        // Check every section's raw range now, so a truncated file is rejected
        // here instead of when a caller first asks for that section.
        for index in 0..section_count as usize {
            image.section(index)?;
        }
        Ok(image)
    }

    /// Return the validated PE format.
    pub const fn kind(&self) -> PeKind {
        self.kind
    }

    /// Return the COFF machine identifier.
    pub const fn machine(&self) -> u16 {
        self.machine
    }

    /// Return the number of declared sections.
    pub const fn section_count(&self) -> u16 {
        self.section_count
    }

    /// Read mapping metadata from the validated optional header.
    pub fn info(&self) -> Result<PeInfo> {
        let entry_rva = read_u32(self.bytes, self.optional_offset + 16)?;
        let size_of_image = read_u32(self.bytes, self.optional_offset + 56)?;
        if size_of_image == 0 || (entry_rva != 0 && entry_rva >= size_of_image) {
            return Err(Error::InvalidImage);
        }
        for index in 0..self.section_count as usize {
            let section = self.section(index)?;
            let end = section
                .virtual_address
                .checked_add(section.virtual_size.max(section.raw_size))
                .ok_or(Error::InvalidImage)?;
            if end > size_of_image {
                return Err(Error::InvalidImage);
            }
        }
        for first in 0..self.section_count as usize {
            let a = self.section(first)?;
            let a_virtual_len = a.virtual_size.max(a.raw_size);
            let a_virtual_end = a
                .virtual_address
                .checked_add(a_virtual_len)
                .ok_or(Error::InvalidImage)?;
            let a_raw_end = a
                .raw_offset
                .checked_add(a.raw_size as usize)
                .ok_or(Error::InvalidImage)?;
            for other_index in (first + 1)..self.section_count as usize {
                let b = self.section(other_index)?;
                let b_virtual_len = b.virtual_size.max(b.raw_size);
                let b_end = b
                    .virtual_address
                    .checked_add(b_virtual_len)
                    .ok_or(Error::InvalidImage)?;
                // An empty range covers no bytes, so it overlaps nothing.
                if a_virtual_len != 0
                    && b_virtual_len != 0
                    && a.virtual_address < b_end
                    && b.virtual_address < a_virtual_end
                {
                    return Err(Error::InvalidImage);
                }
                let b_raw_end = b
                    .raw_offset
                    .checked_add(b.raw_size as usize)
                    .ok_or(Error::InvalidImage)?;
                if a.raw_size != 0
                    && b.raw_size != 0
                    && a.raw_offset < b_raw_end
                    && b.raw_offset < a_raw_end
                {
                    return Err(Error::InvalidImage);
                }
            }
        }
        let image_base = match self.kind {
            PeKind::Pe32 => read_u32(self.bytes, self.optional_offset + 28)? as u64,
            PeKind::Pe32Plus => read_u64(self.bytes, self.optional_offset + 24)?,
        };
        Ok(PeInfo {
            kind: self.kind,
            machine: self.machine,
            image_base,
            size_of_image,
            entry_rva,
        })
    }

    /// Return one section header and its file bounds.
    pub fn section(&self, index: usize) -> Result<Section> {
        if index >= self.section_count as usize {
            return Err(Error::NotFound);
        }
        let offset = self
            .sections_offset
            .checked_add(index * 40)
            .ok_or(Error::InvalidImage)?;
        let end = offset.checked_add(40).ok_or(Error::InvalidImage)?;
        let header = self.bytes.get(offset..end).ok_or(Error::InvalidImage)?;
        let mut name = [0u8; 8];
        name.copy_from_slice(&header[..8]);
        let virtual_size = read_u32(header, 8)?;
        let virtual_address = read_u32(header, 12)?;
        let raw_size = read_u32(header, 16)?;
        let raw_offset = read_u32(header, 20)? as usize;
        let characteristics = read_u32(header, 36)?;
        let end = raw_offset
            .checked_add(raw_size as usize)
            .ok_or(Error::InvalidImage)?;
        if raw_size != 0 && raw_offset < self.sections_offset + self.section_count as usize * 40 {
            return Err(Error::InvalidImage);
        }
        if raw_size == 0 && raw_offset > self.bytes.len() {
            return Err(Error::InvalidImage);
        }
        if self.bytes.get(raw_offset..end).is_none() {
            return Err(Error::InvalidImage);
        }
        Ok(Section {
            virtual_address,
            virtual_size,
            raw_offset,
            raw_size,
            name,
            characteristics,
        })
    }

    /// Return the raw image bytes for later copying by a validated mapper.
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
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
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load::LoaderPlan;

    fn minimal_pe64() -> [u8; 0x400] {
        let mut b = [0u8; 0x400];
        b[..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        b[0x40..0x44].copy_from_slice(b"PE\0\0");
        b[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
        b[0x46..0x48].copy_from_slice(&1u16.to_le_bytes());
        b[0x54..0x56].copy_from_slice(&240u16.to_le_bytes());
        b[0x58..0x5a].copy_from_slice(&0x20b_u16.to_le_bytes());
        b[0x68..0x6c].copy_from_slice(&0x1000u32.to_le_bytes());
        b[0x70..0x78].copy_from_slice(&0x140000000u64.to_le_bytes());
        b[0x58 + 56..0x58 + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        b[0x58 + 32..0x58 + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        b[0x58 + 16..0x58 + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        b[0x148..0x150].copy_from_slice(b".text\0\0\0");
        b[0x148 + 8..0x148 + 12].copy_from_slice(&0x100u32.to_le_bytes());
        b[0x148 + 12..0x148 + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        b[0x148 + 16..0x148 + 20].copy_from_slice(&0x200u32.to_le_bytes());
        b[0x148 + 20..0x148 + 24].copy_from_slice(&0x200u32.to_le_bytes());
        b
    }

    #[test]
    fn accepts_a_bounded_pe64() {
        let image = minimal_pe64();
        let pe = PeImage::parse(&image).unwrap();
        assert_eq!(pe.kind(), PeKind::Pe32Plus);
        assert_eq!(pe.machine(), 0x8664);
        assert_eq!(pe.section_count(), 1);
        assert_eq!(pe.section(0).unwrap().virtual_size, 0x100);
    }

    #[test]
    fn rejects_short_and_bad_signature_images() {
        assert!(matches!(PeImage::parse(&[]), Err(Error::InvalidImage)));
        assert!(matches!(
            PeImage::parse(&[0; 0x400]),
            Err(Error::InvalidImage)
        ));
        let mut image = [0u8; 0x200];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        assert!(matches!(PeImage::parse(&image), Err(Error::InvalidImage)));
    }

    #[test]
    fn rejects_a_truncated_section_table() {
        let image = minimal_pe64();
        assert!(matches!(
            PeImage::parse(&image[..0x100]),
            Err(Error::InvalidImage)
        ));
    }

    /// Deterministic linear congruential generator for mutation tests.
    struct Lcg(u64);

    impl Lcg {
        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0 >> 16
        }

        fn below(&mut self, bound: usize) -> usize {
            (self.next_u64() % bound as u64) as usize
        }
    }

    fn set_u32(image: &mut [u8], offset: usize, value: u32) {
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// Offset of the single section header in `minimal_pe64`.
    const SECTION_HEADER: usize = 0x148;

    /// A PE32 image with a 96-byte optional header and the section table
    /// moved to the PE32 position.
    fn minimal_pe32() -> [u8; 0x400] {
        let mut b = minimal_pe64();
        b[0x44..0x46].copy_from_slice(&0x14cu16.to_le_bytes());
        b[0x54..0x56].copy_from_slice(&96u16.to_le_bytes());
        b[0x58..0x5a].copy_from_slice(&0x10b_u16.to_le_bytes());
        b[0x70..0x78].fill(0);
        set_u32(&mut b, 0x74, 0x40_0000);
        let header: [u8; 40] = b[SECTION_HEADER..SECTION_HEADER + 40].try_into().unwrap();
        b[SECTION_HEADER..SECTION_HEADER + 40].fill(0);
        b[0xb8..0xe0].copy_from_slice(&header);
        b
    }

    #[test]
    fn every_truncation_of_a_minimal_pe_is_invalid() {
        // Section raw data ends at 0x400, so every shorter prefix must fail at
        // parse time, not only when a section is later read.
        let image = minimal_pe64();
        for len in 0..image.len() {
            assert!(
                matches!(PeImage::parse(&image[..len]), Err(Error::InvalidImage)),
                "prefix of {len:#x} bytes"
            );
        }
        assert!(PeImage::parse(&image).is_ok());
    }

    #[test]
    fn pe_signature_offset_past_the_end_or_near_u32_max_is_rejected() {
        for lfanew in [
            0u32,
            0x3c,
            0x3fd,
            0x400,
            0x8000_0000,
            0xFFFF_FFF0,
            0xFFFF_FFFC,
            u32::MAX,
        ] {
            let mut image = minimal_pe64();
            set_u32(&mut image, 0x3c, lfanew);
            assert!(
                matches!(PeImage::parse(&image), Err(Error::InvalidImage)),
                "e_lfanew {lfanew:#x}"
            );
        }
    }

    #[test]
    fn machine_and_optional_magic_must_agree() {
        let cases: [(u16, u16, Error); 4] = [
            (0x8664, 0x10b, Error::Unsupported),
            (0x14c, 0x20b, Error::Unsupported),
            (0xaa64, 0x20b, Error::Unsupported),
            (0x8664, 0x107, Error::InvalidImage),
        ];
        for (machine, magic, expected) in cases {
            let mut image = minimal_pe64();
            image[0x44..0x46].copy_from_slice(&machine.to_le_bytes());
            image[0x58..0x5a].copy_from_slice(&magic.to_le_bytes());
            assert_eq!(
                PeImage::parse(&image).err(),
                Some(expected),
                "machine {machine:#x} magic {magic:#x}"
            );
        }
    }

    #[test]
    fn section_count_must_be_one_to_ninety_six_and_fit_the_file() {
        for count in [0u16, 97, 96, 0x7fff, u16::MAX] {
            let mut image = minimal_pe64();
            image[0x46..0x48].copy_from_slice(&count.to_le_bytes());
            assert!(
                matches!(PeImage::parse(&image), Err(Error::InvalidImage)),
                "section count {count}"
            );
        }
    }

    #[test]
    fn size_of_optional_header_must_cover_the_format_and_fit_the_file() {
        for size in [0u16, 1, 111, 0x1000, u16::MAX] {
            let mut image = minimal_pe64();
            image[0x54..0x56].copy_from_slice(&size.to_le_bytes());
            assert!(
                matches!(PeImage::parse(&image), Err(Error::InvalidImage)),
                "optional header size {size}"
            );
        }
    }

    #[test]
    fn pe32_uses_its_own_minimum_optional_header() {
        let image = minimal_pe32();
        let pe = PeImage::parse(&image).unwrap();
        assert_eq!(pe.kind(), PeKind::Pe32);
        assert_eq!(pe.info().unwrap().image_base, 0x40_0000);

        let mut short = minimal_pe32();
        short[0x54..0x56].copy_from_slice(&95u16.to_le_bytes());
        assert!(matches!(PeImage::parse(&short), Err(Error::InvalidImage)));
    }

    #[test]
    fn section_alignment_must_be_a_nonzero_power_of_two() {
        let cases: [(u32, bool); 7] = [
            (0, false),
            (3, false),
            (0x1800, false),
            (0x8000_0001, false),
            (u32::MAX, false),
            (0x200, true),
            (0x1000, true),
        ];
        for (alignment, valid) in cases {
            let mut image = minimal_pe64();
            set_u32(&mut image, 0x78, alignment);
            assert_eq!(
                PeImage::parse(&image).is_ok(),
                valid,
                "section alignment {alignment:#x}"
            );
        }
    }

    #[test]
    fn section_raw_ranges_that_overflow_or_leave_the_file_are_rejected() {
        let cases: [(u32, u32); 5] = [
            (0xFFFF_FFFF, 0x10),
            (0x200, 0xFFFF_FFFF),
            (0xFFFF_FFF0, 0),
            (0x40, 0x10),
            (0x200, 0x201),
        ];
        for (raw_offset, raw_size) in cases {
            let mut image = minimal_pe64();
            set_u32(&mut image, SECTION_HEADER + 16, raw_size);
            set_u32(&mut image, SECTION_HEADER + 20, raw_offset);
            assert!(
                matches!(PeImage::parse(&image), Err(Error::InvalidImage)),
                "raw {raw_offset:#x}+{raw_size:#x}"
            );
        }
    }

    #[test]
    fn section_virtual_ranges_must_not_wrap_and_must_fit_the_image() {
        let cases: [(u32, u32); 4] = [
            (0xFFFF_F000, 0x2000),
            (0x1000, 0xFFFF_FFFF),
            (0x1000, 0x2000),
            (0x2000, 0x100),
        ];
        for (address, size) in cases {
            let mut image = minimal_pe64();
            set_u32(&mut image, SECTION_HEADER + 8, size);
            set_u32(&mut image, SECTION_HEADER + 12, address);
            let pe = PeImage::parse(&image).unwrap();
            assert!(
                matches!(pe.info(), Err(Error::InvalidImage)),
                "virtual {address:#x}+{size:#x}"
            );
        }
    }

    #[test]
    fn size_of_image_and_entry_point_must_bound_the_sections() {
        // SizeOfImage is at optional+56 and AddressOfEntryPoint at optional+16.
        let mut image = minimal_pe64();
        set_u32(&mut image, 0x90, 0x11ff);
        assert!(matches!(
            PeImage::parse(&image).unwrap().info(),
            Err(Error::InvalidImage)
        ));

        let mut image = minimal_pe64();
        set_u32(&mut image, 0x90, 0);
        assert!(matches!(
            PeImage::parse(&image).unwrap().info(),
            Err(Error::InvalidImage)
        ));

        for entry in [0x2000, 0xFFFF_FFFF] {
            let mut image = minimal_pe64();
            set_u32(&mut image, 0x68, entry);
            assert!(matches!(
                PeImage::parse(&image).unwrap().info(),
                Err(Error::InvalidImage)
            ));
        }

        // .text spans max(VirtualSize, SizeOfRawData) = 0x200 from 0x1000, so
        // SizeOfImage of exactly 0x1200 is in bounds.
        let mut image = minimal_pe64();
        set_u32(&mut image, 0x90, 0x1200);
        assert!(PeImage::parse(&image).unwrap().info().is_ok());
    }

    #[test]
    fn overlapping_virtual_or_raw_ranges_are_rejected() {
        let second = SECTION_HEADER + 40;

        // Virtual overlap: [0x1080, 0x1180) against .text's [0x1000, 0x1100).
        let mut image = minimal_pe64();
        image[0x46..0x48].copy_from_slice(&2u16.to_le_bytes());
        set_u32(&mut image, second + 8, 0x100);
        set_u32(&mut image, second + 12, 0x1080);
        assert!(matches!(
            PeImage::parse(&image).unwrap().info(),
            Err(Error::InvalidImage)
        ));

        // Raw overlap: payload [0x280, 0x380) against .text's [0x200, 0x400).
        let mut image = minimal_pe64();
        image[0x46..0x48].copy_from_slice(&2u16.to_le_bytes());
        set_u32(&mut image, second + 8, 0x100);
        set_u32(&mut image, second + 12, 0x1800);
        set_u32(&mut image, second + 16, 0x100);
        set_u32(&mut image, second + 20, 0x280);
        assert!(matches!(
            PeImage::parse(&image).unwrap().info(),
            Err(Error::InvalidImage)
        ));

        // A disjoint second section is accepted.
        let mut image = minimal_pe64();
        image[0x46..0x48].copy_from_slice(&2u16.to_le_bytes());
        set_u32(&mut image, second + 8, 0x100);
        set_u32(&mut image, second + 12, 0x1800);
        assert!(PeImage::parse(&image).unwrap().info().is_ok());
    }

    /// `.text` from `minimal_pe64`, as a whole section header.
    fn text_header() -> [u8; 40] {
        let image = minimal_pe64();
        image[SECTION_HEADER..SECTION_HEADER + 40]
            .try_into()
            .unwrap()
    }

    /// A section header with the given sizes and addresses.
    fn section_header(
        virtual_size: u32,
        virtual_address: u32,
        raw_size: u32,
        raw_offset: u32,
    ) -> [u8; 40] {
        let mut header = [0u8; 40];
        header[..5].copy_from_slice(b".test");
        set_u32(&mut header, 8, virtual_size);
        set_u32(&mut header, 12, virtual_address);
        set_u32(&mut header, 16, raw_size);
        set_u32(&mut header, 20, raw_offset);
        header
    }

    /// `minimal_pe64` with its section table replaced by the two headers.
    fn two_section_image(first: [u8; 40], second: [u8; 40]) -> [u8; 0x400] {
        let mut image = minimal_pe64();
        image[0x46..0x48].copy_from_slice(&2u16.to_le_bytes());
        image[SECTION_HEADER..SECTION_HEADER + 40].copy_from_slice(&first);
        image[SECTION_HEADER + 40..SECTION_HEADER + 80].copy_from_slice(&second);
        image
    }

    fn info_is_accepted(image: &[u8]) -> bool {
        PeImage::parse(image).and_then(|pe| pe.info()).is_ok()
    }

    #[test]
    fn empty_sections_nested_inside_another_are_accepted() {
        // Zero VirtualSize and zero SizeOfRawData cover no bytes, so an empty
        // section inside .text's virtual or raw range is not an overlap.
        let empty = [
            section_header(0, 0x1050, 0, 0x250),
            section_header(0, 0x1000, 0, 0),
            section_header(0, 0x1199, 0, 0x3ff),
        ];
        for header in empty {
            assert!(info_is_accepted(&two_section_image(text_header(), header)));
            assert!(info_is_accepted(&two_section_image(header, text_header())));
        }

        // A zero raw range inside .text's raw bytes, with its virtual range
        // disjoint from .text, is accepted.
        let raw_empty = section_header(0x100, 0x1800, 0, 0x250);
        assert!(info_is_accepted(&two_section_image(
            text_header(),
            raw_empty
        )));
        assert!(info_is_accepted(&two_section_image(
            raw_empty,
            text_header()
        )));
    }

    #[test]
    fn one_byte_sections_inside_another_are_rejected() {
        let inside = [
            // One virtual byte inside .text's virtual range.
            section_header(1, 0x1050, 0, 0),
            // One raw byte and one virtual byte inside .text's ranges.
            section_header(0, 0x1050, 1, 0x250),
            // One raw byte inside .text's raw range, virtually disjoint.
            section_header(0, 0x1800, 1, 0x250),
        ];
        for header in inside {
            assert!(!info_is_accepted(&two_section_image(text_header(), header)));
            assert!(!info_is_accepted(&two_section_image(header, text_header())));
        }
    }

    #[test]
    fn adjacent_sections_are_accepted_and_one_byte_of_overlap_is_not() {
        // .text shrinks to virtual [0x1000, 0x1100) and raw [0x200, 0x300), so
        // the next section starts exactly where .text ends in both spaces.
        let mut text = text_header();
        set_u32(&mut text, 16, 0x100);
        let next = section_header(0x100, 0x1100, 0x100, 0x300);
        assert!(info_is_accepted(&two_section_image(text, next)));
        assert!(info_is_accepted(&two_section_image(next, text)));

        // Starting one virtual byte early overlaps .text by exactly one byte.
        let overlapping = section_header(0x100, 0x10ff, 0x100, 0x300);
        assert!(!info_is_accepted(&two_section_image(text, overlapping)));
        assert!(!info_is_accepted(&two_section_image(overlapping, text)));
    }

    #[test]
    fn mutated_pe_images_never_panic_or_overflow() {
        // Deterministic mutations of a valid image: random byte writes, biased
        // toward the headers, plus all-ones u32 and u64 fields. Each parse
        // result is either Ok or Err, and every accepted image is driven
        // through the accessors and the load-plan derivation.
        let base = minimal_pe64();
        let mut rng = Lcg(0x5045_3332_2b6d_7574);
        let (mut accepted, mut rejected) = (0usize, 0usize);
        for iteration in 0..2000 {
            let mut image = base;
            for _ in 0..1 + rng.below(4) {
                let span = if rng.below(2) == 0 {
                    SECTION_HEADER + 40
                } else {
                    image.len()
                };
                let at = rng.below(span);
                image[at] = rng.next_u64() as u8;
            }
            if iteration % 4 == 0 {
                let at = rng.below(SECTION_HEADER + 40 - 8);
                image[at..at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
            }
            if iteration % 3 == 0 {
                let at = rng.below(SECTION_HEADER + 40 - 4);
                set_u32(&mut image, at, u32::MAX);
            }
            match PeImage::parse(&image) {
                Ok(pe) => {
                    accepted += 1;
                    let _ = pe.info();
                    for index in 0..pe.section_count() as usize + 1 {
                        let _ = pe.section(index);
                    }
                    let _ = LoaderPlan::<4>::from_pe(&image);
                }
                Err(_) => rejected += 1,
            }
        }
        assert!(
            accepted > 0 && rejected > 0,
            "accepted {accepted}, rejected {rejected}"
        );
    }
}
