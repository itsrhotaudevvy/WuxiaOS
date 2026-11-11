//! Bounds-checked ELF64 parsing for the future POSIX image loader.
//!
//! Parsing validates container metadata only. It does not map memory, resolve
//! relocations, trust the entry point or execute anything.

use crate::{Error, Result};

/// ELF identification magic.
pub const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u8 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const HEADER_SIZE: usize = 64;
const PROGRAM_HEADER_SIZE: usize = 56;
const MAX_PROGRAM_HEADERS: u16 = 128;

/// Whether the image is a fixed-address executable or a position-independent one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfKind {
    /// `ET_EXEC`: segments are addressed at their absolute virtual addresses.
    Executable,
    /// `ET_DYN`: segments require a load bias chosen at map time.
    Dynamic,
}

/// Header information needed to plan a mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfInfo {
    /// Executable or position-independent image.
    pub kind: ElfKind,
    /// Entry-point virtual address before any load bias.
    pub entry: u64,
    /// Number of declared program headers.
    pub program_headers: usize,
}

/// One validated `PT_LOAD` segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProgramSegment {
    /// Virtual address of the first byte.
    pub virtual_address: u64,
    /// Bytes present in the file.
    pub file_size: u64,
    /// Bytes in memory, including zero-filled tail.
    pub memory_size: u64,
    /// File offset of the segment bytes.
    pub file_offset: usize,
    /// Program-header flags (`PF_X` is bit 0, `PF_W` bit 1).
    pub flags: u32,
    /// Required alignment, zero or a power of two.
    pub align: u64,
}

impl ProgramSegment {
    /// Whether the segment is executable.
    pub const fn is_executable(self) -> bool {
        self.flags & 1 != 0
    }

    /// Whether the segment is writable.
    pub const fn is_writable(self) -> bool {
        self.flags & 2 != 0
    }

    /// Whether the segment is both writable and executable.
    pub const fn is_writable_and_executable(self) -> bool {
        self.flags & 3 == 3
    }

    /// Address one past the last in-memory byte.
    pub const fn memory_end(self) -> Result<u64> {
        match self.virtual_address.checked_add(self.memory_size) {
            Some(end) => Ok(end),
            None => Err(Error::OutOfRange),
        }
    }
}

/// A validated ELF64 image borrowing its input bytes.
#[derive(Clone, Copy, Debug)]
pub struct Elf64Image<'a> {
    bytes: &'a [u8],
    kind: ElfKind,
    entry: u64,
    program_offset: usize,
    program_count: u16,
}

impl<'a> Elf64Image<'a> {
    /// Parse an ELF64 image and validate every `PT_LOAD` segment.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < HEADER_SIZE || bytes.get(..4) != Some(&ELF_MAGIC) {
            return Err(Error::InvalidImage);
        }
        if bytes[4] != ELFCLASS64 || bytes[5] != ELFDATA2LSB || bytes[6] != EV_CURRENT {
            return Err(Error::Unsupported);
        }
        let kind = match read_u16(bytes, 16)? {
            ET_EXEC => ElfKind::Executable,
            ET_DYN => ElfKind::Dynamic,
            _ => return Err(Error::Unsupported),
        };
        if read_u16(bytes, 18)? != EM_X86_64 || read_u32(bytes, 20)? != u32::from(EV_CURRENT) {
            return Err(Error::Unsupported);
        }
        let entry = read_u64(bytes, 24)?;
        if entry == 0 {
            return Err(Error::InvalidImage);
        }
        let program_offset =
            usize::try_from(read_u64(bytes, 32)?).map_err(|_| Error::InvalidImage)?;
        let program_entry_size = read_u16(bytes, 54)? as usize;
        let program_count = read_u16(bytes, 56)?;
        if program_count == 0
            || program_count > MAX_PROGRAM_HEADERS
            || program_entry_size < PROGRAM_HEADER_SIZE
        {
            return Err(Error::InvalidImage);
        }
        let table_size = (program_count as usize)
            .checked_mul(program_entry_size)
            .ok_or(Error::InvalidImage)?;
        let table_end = program_offset
            .checked_add(table_size)
            .ok_or(Error::InvalidImage)?;
        if bytes.get(program_offset..table_end).is_none() {
            return Err(Error::InvalidImage);
        }
        let image = Self {
            bytes,
            kind,
            entry,
            program_offset,
            program_count,
        };
        for index in 0..program_count as usize {
            // Non-loadable program headers are legal and simply skipped.
            match image.segment(index) {
                Ok(_) | Err(Error::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        image.check_overlaps()?;
        Ok(image)
    }

    /// Return mapping metadata.
    pub const fn info(&self) -> ElfInfo {
        ElfInfo {
            kind: self.kind,
            entry: self.entry,
            program_headers: self.program_count as usize,
        }
    }

    /// Return the entry-point virtual address.
    pub const fn entry(&self) -> u64 {
        self.entry
    }

    /// Return the number of declared program headers.
    pub const fn program_header_count(&self) -> usize {
        self.program_count as usize
    }

    /// Return one validated `PT_LOAD` segment.
    ///
    /// Non-loadable program headers (for example `PT_PHDR` or `PT_INTERP`)
    /// return [`Error::NotFound`] rather than failing the whole image.
    pub fn segment(&self, index: usize) -> Result<ProgramSegment> {
        if index >= self.program_count as usize {
            return Err(Error::NotFound);
        }
        let program_entry_size = read_u16(self.bytes, 54)? as usize;
        let offset = self
            .program_offset
            .checked_add(
                index
                    .checked_mul(program_entry_size)
                    .ok_or(Error::InvalidImage)?,
            )
            .ok_or(Error::InvalidImage)?;
        let end = offset
            .checked_add(PROGRAM_HEADER_SIZE)
            .ok_or(Error::InvalidImage)?;
        let header = self.bytes.get(offset..end).ok_or(Error::InvalidImage)?;
        if read_u32(header, 0)? != PT_LOAD {
            return Err(Error::NotFound);
        }
        let flags = read_u32(header, 4)?;
        let file_offset = usize::try_from(read_u64(header, 8)?).map_err(|_| Error::InvalidImage)?;
        let virtual_address = read_u64(header, 16)?;
        let file_size = read_u64(header, 32)?;
        let memory_size = read_u64(header, 40)?;
        let align = read_u64(header, 48)?;
        if memory_size == 0 || file_size > memory_size {
            return Err(Error::InvalidImage);
        }
        let raw_end = file_offset
            .checked_add(usize::try_from(file_size).map_err(|_| Error::InvalidImage)?)
            .ok_or(Error::InvalidImage)?;
        if self.bytes.get(file_offset..raw_end).is_none() {
            return Err(Error::InvalidImage);
        }
        if align != 0
            && (!align.is_power_of_two()
                || (virtual_address % align) != (file_offset as u64 % align))
        {
            return Err(Error::InvalidImage);
        }
        Ok(ProgramSegment {
            virtual_address,
            file_size,
            memory_size,
            file_offset,
            flags,
            align,
        })
    }

    /// Reject `PT_LOAD` segments whose in-memory ranges intersect.
    fn check_overlaps(&self) -> Result<()> {
        for first in 0..self.program_count as usize {
            let a = match self.segment(first) {
                Ok(segment) => segment,
                Err(Error::NotFound) => continue,
                Err(error) => return Err(error),
            };
            let a_end = a.memory_end()?;
            for other in (first + 1)..self.program_count as usize {
                let b = match self.segment(other) {
                    Ok(segment) => segment,
                    Err(Error::NotFound) => continue,
                    Err(error) => return Err(error),
                };
                if a.virtual_address < b.memory_end()? && b.virtual_address < a_end {
                    return Err(Error::InvalidImage);
                }
            }
        }
        Ok(())
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

    fn minimal_elf() -> [u8; 0x2000] {
        let mut bytes = [0u8; 0x2000];
        bytes[..4].copy_from_slice(&ELF_MAGIC);
        bytes[4] = ELFCLASS64;
        bytes[5] = ELFDATA2LSB;
        bytes[6] = EV_CURRENT;
        bytes[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        bytes[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x4010u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&0x40u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());

        let program = 0x40;
        bytes[program..program + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        bytes[program + 4..program + 8].copy_from_slice(&5u32.to_le_bytes());
        bytes[program + 8..program + 16].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes[program + 16..program + 24].copy_from_slice(&0x400000u64.to_le_bytes());
        bytes[program + 32..program + 40].copy_from_slice(&0x100u64.to_le_bytes());
        bytes[program + 40..program + 48].copy_from_slice(&0x200u64.to_le_bytes());
        bytes[program + 48..program + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes
    }

    #[test]
    fn accepts_a_bounded_elf64() {
        let image = minimal_elf();
        let elf = Elf64Image::parse(&image).unwrap();
        assert_eq!(elf.info().kind, ElfKind::Executable);
        assert_eq!(elf.entry(), 0x4010);
        assert_eq!(elf.program_header_count(), 1);
        let segment = elf.segment(0).unwrap();
        assert_eq!(segment.virtual_address, 0x400000);
        assert_eq!(segment.file_size, 0x100);
        assert_eq!(segment.memory_size, 0x200);
        assert!(segment.is_executable());
        assert!(!segment.is_writable());
    }

    #[test]
    fn rejects_bad_identity_and_machine() {
        assert!(matches!(Elf64Image::parse(&[]), Err(Error::InvalidImage)));

        let mut image = minimal_elf();
        image[4] = 1;
        assert!(matches!(Elf64Image::parse(&image), Err(Error::Unsupported)));

        let mut image = minimal_elf();
        image[18..20].copy_from_slice(&3u16.to_le_bytes());
        assert!(matches!(Elf64Image::parse(&image), Err(Error::Unsupported)));

        let mut image = minimal_elf();
        image[16..18].copy_from_slice(&1u16.to_le_bytes());
        assert!(matches!(Elf64Image::parse(&image), Err(Error::Unsupported)));
    }

    #[test]
    fn rejects_truncated_program_tables_and_segments() {
        let image = minimal_elf();
        assert!(matches!(
            Elf64Image::parse(&image[..0x60]),
            Err(Error::InvalidImage)
        ));

        let mut truncated = minimal_elf();
        truncated[32..40].copy_from_slice(&0x1ff0u64.to_le_bytes());
        assert!(matches!(
            Elf64Image::parse(&truncated),
            Err(Error::InvalidImage)
        ));
    }

    #[test]
    fn rejects_inconsistent_segment_sizes_and_alignment() {
        let mut image = minimal_elf();
        image[0x40 + 32..0x40 + 40].copy_from_slice(&0x300u64.to_le_bytes());
        assert!(matches!(
            Elf64Image::parse(&image),
            Err(Error::InvalidImage)
        ));

        let mut image = minimal_elf();
        image[0x40 + 48..0x40 + 56].copy_from_slice(&0x3000u64.to_le_bytes());
        assert!(matches!(
            Elf64Image::parse(&image),
            Err(Error::InvalidImage)
        ));
    }

    #[test]
    fn rejects_overlapping_load_segments() {
        let mut image = minimal_elf();
        image[56..58].copy_from_slice(&2u16.to_le_bytes());
        let second = 0x40 + 56;
        image[second..second + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        image[second + 8..second + 16].copy_from_slice(&0x1000u64.to_le_bytes());
        image[second + 16..second + 24].copy_from_slice(&0x400100u64.to_le_bytes());
        image[second + 32..second + 40].copy_from_slice(&0x100u64.to_le_bytes());
        image[second + 40..second + 48].copy_from_slice(&0x100u64.to_le_bytes());
        image[second + 48..second + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        assert!(matches!(
            Elf64Image::parse(&image),
            Err(Error::InvalidImage)
        ));
    }

    #[test]
    fn non_loadable_program_headers_are_skipped() {
        let mut image = minimal_elf();
        image[56..58].copy_from_slice(&2u16.to_le_bytes());
        let second = 0x40 + 56;
        // PT_NOTE carries no PT_LOAD segment and must not fail the parse.
        image[second..second + 4].copy_from_slice(&4u32.to_le_bytes());
        let elf = Elf64Image::parse(&image).unwrap();
        assert_eq!(elf.program_header_count(), 2);
        assert_eq!(elf.segment(0).unwrap().virtual_address, 0x400000);
        assert!(matches!(elf.segment(1), Err(Error::NotFound)));
    }

    #[test]
    fn writable_and_executable_segments_are_reported() {
        let mut image = minimal_elf();
        image[0x40 + 4..0x40 + 8].copy_from_slice(&7u32.to_le_bytes());
        let elf = Elf64Image::parse(&image).unwrap();
        let segment = elf.segment(0).unwrap();
        assert!(segment.is_executable());
        assert!(segment.is_writable());
        assert!(segment.is_writable_and_executable());
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

    /// Bytes the minimal image needs: its header, its program table and the
    /// file-backed `PT_LOAD` payload that ends at `0x1000 + 0x100`.
    const MINIMAL_ELF_LEN: usize = 0x1100;

    fn set_program_table(image: &mut [u8], offset: u64, count: u16, entry_size: u16) {
        image[32..40].copy_from_slice(&offset.to_le_bytes());
        image[54..56].copy_from_slice(&entry_size.to_le_bytes());
        image[56..58].copy_from_slice(&count.to_le_bytes());
    }

    #[test]
    fn every_truncation_of_a_minimal_image_is_invalid() {
        let image = minimal_elf();
        for len in 0..MINIMAL_ELF_LEN {
            assert!(
                matches!(Elf64Image::parse(&image[..len]), Err(Error::InvalidImage)),
                "prefix of {len:#x} bytes"
            );
        }
        assert!(Elf64Image::parse(&image[..MINIMAL_ELF_LEN]).is_ok());
    }

    #[test]
    fn program_table_arithmetic_cannot_wrap() {
        let cases: [(u64, u16, u16); 9] = [
            (u64::MAX, 1, 56),
            (u64::MAX - 0x20, 1, 56),
            (0x40, u16::MAX, 56),
            (0x40, 128, u16::MAX),
            (0x40, 129, 56),
            (0x40, 0, 56),
            (0x40, 1, 0),
            (0x40, 1, 55),
            (0x2000, 1, 56),
        ];
        for (offset, count, entry_size) in cases {
            let mut image = minimal_elf();
            set_program_table(&mut image, offset, count, entry_size);
            assert!(
                matches!(Elf64Image::parse(&image), Err(Error::InvalidImage)),
                "offset {offset:#x} count {count} entry size {entry_size}"
            );
        }
    }

    #[test]
    fn program_table_field_grid_never_panics() {
        let offsets = [
            0,
            0x40,
            0x1000,
            0x1fff,
            0x2000,
            1u64 << 63,
            u64::MAX - 1,
            u64::MAX,
        ];
        let counts = [0u16, 1, 2, 128, 129, u16::MAX];
        let entry_sizes = [0u16, 55, 56, 57, 64, u16::MAX];
        for offset in offsets {
            for count in counts {
                for entry_size in entry_sizes {
                    let mut image = minimal_elf();
                    set_program_table(&mut image, offset, count, entry_size);
                    if let Ok(elf) = Elf64Image::parse(&image) {
                        for index in 0..elf.program_header_count() + 1 {
                            let _ = elf.segment(index);
                        }
                        let _ = LoaderPlan::<4>::from_elf(&image);
                    }
                }
            }
        }
    }

    #[test]
    fn program_header_ranges_that_overflow_u64_are_rejected() {
        // p_offset + p_filesz wraps past u64::MAX.
        let mut image = minimal_elf();
        image[0x40 + 8..0x40 + 16].copy_from_slice(&(u64::MAX - 0x10).to_le_bytes());
        assert!(matches!(
            Elf64Image::parse(&image),
            Err(Error::InvalidImage)
        ));

        // p_vaddr + p_memsz wraps. The address is page aligned so the
        // alignment congruence holds and the overlap pass reports the overflow.
        let mut image = minimal_elf();
        image[0x40 + 16..0x40 + 24].copy_from_slice(&0xffff_ffff_ffff_f000u64.to_le_bytes());
        image[0x40 + 40..0x40 + 48].copy_from_slice(&0x2000u64.to_le_bytes());
        assert!(matches!(Elf64Image::parse(&image), Err(Error::OutOfRange)));

        // p_memsz itself is unrepresentable once the address is added.
        let mut image = minimal_elf();
        image[0x40 + 40..0x40 + 48].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(Elf64Image::parse(&image).is_err());
    }

    #[test]
    fn file_size_larger_than_memory_size_is_rejected() {
        for (filesz, memsz) in [
            (0x201u64, 0x200u64),
            (u64::MAX, u64::MAX - 1),
            (1, 0),
            (u64::MAX, 0),
            (1u64 << 63, 1u64 << 63),
        ] {
            let mut image = minimal_elf();
            image[0x40 + 32..0x40 + 40].copy_from_slice(&filesz.to_le_bytes());
            image[0x40 + 40..0x40 + 48].copy_from_slice(&memsz.to_le_bytes());
            assert!(
                Elf64Image::parse(&image).is_err(),
                "filesz {filesz:#x} memsz {memsz:#x}"
            );
        }
    }

    #[test]
    fn segment_alignment_must_be_zero_or_a_congruent_power_of_two() {
        let cases: [(u64, bool); 7] = [
            (0, true),
            (1, true),
            (0x1000, true),
            (3, false),
            (0x1800, false),
            (u64::MAX, false),
            (1u64 << 63, false),
        ];
        for (align, valid) in cases {
            let mut image = minimal_elf();
            image[0x40 + 48..0x40 + 56].copy_from_slice(&align.to_le_bytes());
            assert_eq!(
                Elf64Image::parse(&image).is_ok(),
                valid,
                "p_align {align:#x}"
            );
        }
    }

    #[test]
    fn zero_entry_point_is_rejected() {
        let mut image = minimal_elf();
        image[24..32].copy_from_slice(&0u64.to_le_bytes());
        assert!(matches!(
            Elf64Image::parse(&image),
            Err(Error::InvalidImage)
        ));
    }

    #[test]
    fn mutated_elf_images_never_panic_or_overflow() {
        // Deterministic mutations of a valid image: random byte writes, biased
        // toward the header and program table, plus all-ones u64 fields. Each
        // parse result is either Ok or Err, and every accepted image is driven
        // through the segment accessor and the load-plan derivation.
        let base = minimal_elf();
        let mut rng = Lcg(0x454c_4636_3462_6974);
        let (mut accepted, mut rejected) = (0usize, 0usize);
        for iteration in 0..2000 {
            let mut image = base;
            for _ in 0..1 + rng.below(4) {
                let span = if rng.below(2) == 0 { 0x78 } else { image.len() };
                let at = rng.below(span);
                image[at] = rng.next_u64() as u8;
            }
            if iteration % 4 == 0 {
                let at = rng.below(0x78 - 8);
                image[at..at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
            }
            match Elf64Image::parse(&image) {
                Ok(elf) => {
                    accepted += 1;
                    let _ = elf.info();
                    for index in 0..elf.program_header_count() + 1 {
                        let _ = elf.segment(index);
                    }
                    let _ = LoaderPlan::<4>::from_elf(&image);
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
