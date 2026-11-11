//! Validated load plans derived from executable images.
//!
//! A plan describes what a loader must map: page-aligned ranges, per-segment
//! permissions and where the stack can live. It never touches memory.

use crate::elf::{Elf64Image, ElfKind};
use crate::paging::{PAGE_SIZE, PagePermissions, USER_ADDRESS_LIMIT};
use crate::{Error, Result};

/// One page-aligned range a loader must map.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadSegment {
    /// Page-aligned virtual address of the first byte.
    pub address: u64,
    /// Bytes present in the file.
    pub file_size: u64,
    /// Bytes in memory, including the zero-filled tail.
    pub memory_size: u64,
    /// File offset of the segment bytes.
    pub file_offset: usize,
    /// Permissions to map the range with.
    pub permissions: PagePermissions,
}

impl LoadSegment {
    /// Number of pages the segment occupies.
    pub const fn page_count(self) -> u64 {
        self.memory_size.div_ceil(PAGE_SIZE)
    }

    /// Page-aligned address one past the last mapped byte.
    pub const fn end(self) -> u64 {
        self.address + self.page_count() * PAGE_SIZE
    }
}

/// A bounded, validated list of segments for one image.
#[derive(Clone, Copy, Debug)]
pub struct LoaderPlan<const N: usize> {
    entry: u64,
    segments: [Option<LoadSegment>; N],
}

impl<const N: usize> LoaderPlan<N> {
    /// Derive a plan from an ELF64 executable.
    ///
    /// Rejects writable-executable segments, unaligned ranges, ranges above
    /// the user limit and images with no loadable segment.
    pub fn from_elf(bytes: &[u8]) -> Result<Self> {
        let elf = Elf64Image::parse(bytes)?;
        if elf.info().kind != ElfKind::Executable {
            return Err(Error::Unsupported);
        }
        let mut segments = [None; N];
        let mut count = 0;
        for index in 0..elf.program_header_count() {
            let segment = match elf.segment(index) {
                Ok(segment) => segment,
                Err(Error::NotFound) => continue,
                Err(error) => return Err(error),
            };
            if segment.is_writable_and_executable() {
                return Err(Error::PermissionDenied);
            }
            if !segment.virtual_address.is_multiple_of(PAGE_SIZE) {
                return Err(Error::BadAddress);
            }
            if segment.memory_end()? > USER_ADDRESS_LIMIT {
                return Err(Error::BadAddress);
            }
            if count == N {
                return Err(Error::TableFull);
            }
            let permissions = if segment.is_writable() {
                PagePermissions::USER_READ_WRITE
            } else if segment.is_executable() {
                PagePermissions::USER_CODE
            } else {
                PagePermissions::USER_READ_ONLY
            };
            segments[count] = Some(LoadSegment {
                address: segment.virtual_address,
                file_size: segment.file_size,
                memory_size: segment.memory_size,
                file_offset: segment.file_offset,
                permissions,
            });
            count += 1;
        }
        if count == 0 {
            return Err(Error::InvalidImage);
        }
        Ok(Self {
            entry: elf.entry(),
            segments,
        })
    }

    /// Entry-point virtual address.
    pub const fn entry(&self) -> u64 {
        self.entry
    }

    /// The validated segments in image order.
    pub fn segments(&self) -> impl Iterator<Item = &LoadSegment> {
        self.segments.iter().flatten()
    }

    /// Number of loadable segments.
    pub fn len(&self) -> usize {
        self.segments.iter().flatten().count()
    }

    /// Whether the plan has no segments.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Page-aligned end of the highest segment.
    pub fn max_end(&self) -> Result<u64> {
        self.segments()
            .map(|segment| segment.end())
            .max()
            .ok_or(Error::InvalidImage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::ELF_MAGIC;

    fn tiny_elf(flags: u32, virtual_address: u64, memory_size: u64) -> [u8; 0x2000] {
        let mut bytes = [0u8; 0x2000];
        bytes[..4].copy_from_slice(&ELF_MAGIC);
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&virtual_address.to_le_bytes());
        bytes[32..40].copy_from_slice(&0x40u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());

        let program = 0x40;
        bytes[program..program + 4].copy_from_slice(&1u32.to_le_bytes());
        bytes[program + 4..program + 8].copy_from_slice(&flags.to_le_bytes());
        bytes[program + 8..program + 16].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes[program + 16..program + 24].copy_from_slice(&virtual_address.to_le_bytes());
        bytes[program + 32..program + 40].copy_from_slice(&0x100u64.to_le_bytes());
        bytes[program + 40..program + 48].copy_from_slice(&memory_size.to_le_bytes());
        bytes[program + 48..program + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes
    }

    #[test]
    fn maps_executable_and_read_only_segments_to_permissions() {
        let elf = tiny_elf(5, 0x8000_0000, 0x1000);
        let plan = LoaderPlan::<4>::from_elf(&elf).unwrap();
        assert_eq!(plan.entry(), 0x8000_0000);
        assert_eq!(plan.len(), 1);
        let segment = plan.segments().next().unwrap();
        assert_eq!(segment.permissions, PagePermissions::USER_CODE);
        assert_eq!(segment.page_count(), 1);
        assert_eq!(plan.max_end().unwrap(), 0x8000_1000);
    }

    #[test]
    fn writable_segments_are_not_executable() {
        let elf = tiny_elf(6, 0x8000_0000, 0x1000);
        let plan = LoaderPlan::<4>::from_elf(&elf).unwrap();
        let segment = plan.segments().next().unwrap();
        assert_eq!(segment.permissions, PagePermissions::USER_READ_WRITE);
        assert!(!segment.permissions.executable);
    }

    #[test]
    fn rejects_writable_and_executable_segments() {
        let elf = tiny_elf(7, 0x8000_0000, 0x1000);
        assert!(matches!(
            LoaderPlan::<4>::from_elf(&elf),
            Err(Error::PermissionDenied)
        ));
    }

    #[test]
    fn rejects_unaligned_and_out_of_range_segments() {
        // Keep the ELF p_align congruence valid so the plan, not the parser,
        // is what rejects the unaligned address.
        let mut elf = tiny_elf(5, 0x8000_0010, 0x1000);
        elf[0x48..0x50].copy_from_slice(&0x1010u64.to_le_bytes());
        assert!(matches!(
            LoaderPlan::<4>::from_elf(&elf),
            Err(Error::BadAddress)
        ));

        let elf = tiny_elf(5, USER_ADDRESS_LIMIT - PAGE_SIZE, 0x2000);
        assert!(matches!(
            LoaderPlan::<4>::from_elf(&elf),
            Err(Error::BadAddress)
        ));
    }

    #[test]
    fn rejects_plans_beyond_capacity() {
        let elf = tiny_elf(5, 0x8000_0000, 0x1000);
        assert!(matches!(
            LoaderPlan::<0>::from_elf(&elf),
            Err(Error::TableFull)
        ));
    }

    #[test]
    fn rounds_the_stack_base_up_to_a_page() {
        let elf = tiny_elf(5, 0x8000_0000, 0x1800);
        let plan = LoaderPlan::<4>::from_elf(&elf).unwrap();
        assert_eq!(plan.max_end().unwrap(), 0x8000_2000);
    }
}
