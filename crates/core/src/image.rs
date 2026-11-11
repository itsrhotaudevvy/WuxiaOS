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
        let table_size = (section_count as usize)
            .checked_mul(40)
            .ok_or(Error::InvalidImage)?;
        let table_end = optional_end
            .checked_add(table_size)
            .ok_or(Error::InvalidImage)?;
        if bytes.get(optional_end..table_end).is_none() {
            return Err(Error::InvalidImage);
        }
        Ok(Self {
            bytes,
            kind,
            machine,
            optional_offset,
            sections_offset: optional_end,
            section_count,
        })
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
}
