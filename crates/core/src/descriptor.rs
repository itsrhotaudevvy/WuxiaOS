//! POSIX-style descriptor table.
//!
//! Descriptors are process-local small integers. The table starts with the
//! standard streams open and never exposes a closed slot as valid, so a stale
//! descriptor number cannot silently refer to a different object.

use crate::vfs::FileId;
use crate::{Error, Result};

/// Number of descriptors preopened for a new process (stdin, stdout, stderr).
pub const STANDARD_DESCRIPTORS: u32 = 3;

/// A fixed-capacity set of open descriptor numbers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DescriptorTable<const N: usize> {
    open: [bool; N],
    files: [Option<FileId>; N],
    offsets: [u64; N],
}

impl<const N: usize> Default for DescriptorTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> DescriptorTable<N> {
    /// Construct a table with no open descriptors.
    pub const fn new() -> Self {
        Self {
            open: [false; N],
            files: [None; N],
            offsets: [0; N],
        }
    }

    /// Construct a table with stdin, stdout and stderr open.
    pub const fn with_standard_streams() -> Self {
        let mut open = [false; N];
        if N > 0 {
            open[0] = true;
        }
        if N > 1 {
            open[1] = true;
        }
        if N > 2 {
            open[2] = true;
        }
        Self {
            open,
            files: [None; N],
            offsets: [0; N],
        }
    }

    /// Whether `descriptor` currently refers to an open object.
    pub fn is_open(&self, descriptor: u32) -> bool {
        self.open.get(descriptor as usize).copied().unwrap_or(false)
    }

    /// Open the lowest free descriptor at or above the standard streams.
    pub fn open(&mut self) -> Result<u32> {
        self.open_slot(None)
    }

    /// Open a file and return the descriptor that refers to it.
    pub fn open_file(&mut self, file: FileId) -> Result<u32> {
        self.open_slot(Some(file))
    }

    fn open_slot(&mut self, file: Option<FileId>) -> Result<u32> {
        for (index, slot) in self
            .open
            .iter_mut()
            .enumerate()
            .skip(STANDARD_DESCRIPTORS as usize)
        {
            if !*slot {
                *slot = true;
                self.files[index] = file;
                self.offsets[index] = 0;
                return Ok(index as u32);
            }
        }
        Err(Error::TableFull)
    }

    /// The file a descriptor refers to, if it is not a standard stream.
    pub fn file(&self, descriptor: u32) -> Option<FileId> {
        self.open
            .get(descriptor as usize)
            .copied()
            .unwrap_or(false)
            .then(|| self.files.get(descriptor as usize).copied().flatten())
            .flatten()
    }

    /// Current read offset of a descriptor.
    pub fn offset(&self, descriptor: u32) -> u64 {
        self.offsets.get(descriptor as usize).copied().unwrap_or(0)
    }

    /// Advance the read offset of a descriptor by `count` bytes.
    pub fn advance(&mut self, descriptor: u32, count: u64) -> Result<()> {
        let index = descriptor as usize;
        if !self.is_open(descriptor) || self.files.get(index).copied().flatten().is_none() {
            return Err(Error::InvalidHandle);
        }
        self.offsets[index] = self.offsets[index]
            .checked_add(count)
            .ok_or(Error::OutOfRange)?;
        Ok(())
    }

    /// Set a descriptor's position relative to start, current position or end.
    /// Negative results, results beyond `i64::MAX` (POSIX `off_t`) and
    /// offsets on non-file streams are rejected without changing the position.
    pub fn seek(
        &mut self,
        descriptor: u32,
        offset: i64,
        whence: u32,
        file_length: u64,
    ) -> Result<u64> {
        let index = descriptor as usize;
        if !self.is_open(descriptor) || self.files.get(index).copied().flatten().is_none() {
            return Err(Error::InvalidHandle);
        }
        let base = match whence {
            0 => 0,
            1 => self.offsets[index],
            2 => file_length,
            _ => return Err(Error::InvalidInput),
        };
        self.offsets[index] = if offset >= 0 {
            base.checked_add(offset as u64)
        } else {
            base.checked_sub(offset.unsigned_abs())
        }
        .filter(|&position| position <= i64::MAX as u64)
        .ok_or(Error::OutOfRange)?;
        Ok(self.offsets[index])
    }

    /// Close an open descriptor, rejecting unknown or already closed slots.
    pub fn close(&mut self, descriptor: u32) -> Result<()> {
        match self.open.get_mut(descriptor as usize) {
            Some(slot) if *slot => {
                *slot = false;
                self.files[descriptor as usize] = None;
                self.offsets[descriptor as usize] = 0;
                Ok(())
            }
            _ => Err(Error::InvalidHandle),
        }
    }

    /// Number of open descriptors.
    pub fn count(&self) -> usize {
        self.open.iter().filter(|slot| **slot).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_streams_start_open() {
        let table = DescriptorTable::<4>::with_standard_streams();
        assert!(table.is_open(0));
        assert!(table.is_open(1));
        assert!(table.is_open(2));
        assert!(!table.is_open(3));
        assert_eq!(table.count(), 3);
    }

    #[test]
    fn open_returns_the_lowest_free_slot() {
        let mut table = DescriptorTable::<4>::with_standard_streams();
        assert_eq!(table.open(), Ok(3));
        assert_eq!(table.open(), Err(Error::TableFull));
        assert_eq!(table.count(), 4);
    }

    #[test]
    fn close_invalidates_the_descriptor() {
        let mut table = DescriptorTable::<4>::with_standard_streams();
        assert_eq!(table.close(1), Ok(()));
        assert!(!table.is_open(1));
        assert_eq!(table.close(1), Err(Error::InvalidHandle));
        assert_eq!(table.close(9), Err(Error::InvalidHandle));
    }

    #[test]
    fn file_descriptors_carry_identity_and_offsets() {
        let mut table = DescriptorTable::<6>::with_standard_streams();
        let file = FileId(1);
        let descriptor = table.open_file(file).unwrap();
        assert_eq!(descriptor, 3);
        assert_eq!(table.file(descriptor), Some(file));
        assert_eq!(table.file(1), None);
        assert_eq!(table.offset(descriptor), 0);
        table.advance(descriptor, 5).unwrap();
        assert_eq!(table.offset(descriptor), 5);
        assert_eq!(table.advance(1, 1), Err(Error::InvalidHandle));
        table.close(descriptor).unwrap();
        assert_eq!(table.file(descriptor), None);
        assert_eq!(table.offset(descriptor), 0);
        assert_eq!(table.open_file(FileId(2)), Ok(3));
    }

    #[test]
    fn file_seeks_are_signed_and_transactional() {
        let mut table = DescriptorTable::<5>::with_standard_streams();
        let descriptor = table.open_file(FileId(0)).unwrap();
        assert_eq!(table.seek(descriptor, 4, 0, 14), Ok(4));
        assert_eq!(table.seek(descriptor, -2, 1, 14), Ok(2));
        assert_eq!(table.seek(descriptor, -1, 2, 14), Ok(13));
        assert_eq!(table.seek(descriptor, -1, 0, 14), Err(Error::OutOfRange));
        assert_eq!(table.offset(descriptor), 13);
        assert_eq!(table.seek(descriptor, i64::MAX, 0, 14), Ok(i64::MAX as u64));
        assert_eq!(table.seek(descriptor, 1, 1, 14), Err(Error::OutOfRange));
        assert_eq!(table.offset(descriptor), i64::MAX as u64);
        assert_eq!(table.seek(descriptor, 0, 3, 14), Err(Error::InvalidInput));
        assert_eq!(table.seek(1, 0, 0, 14), Err(Error::InvalidHandle));
        table.close(descriptor).unwrap();
        assert_eq!(table.seek(descriptor, 0, 0, 14), Err(Error::InvalidHandle));
    }

    #[test]
    fn a_closed_slot_can_be_reused_but_standard_streams_are_reserved() {
        let mut table = DescriptorTable::<5>::with_standard_streams();
        assert_eq!(table.open(), Ok(3));
        assert_eq!(table.open(), Ok(4));
        assert_eq!(table.close(3), Ok(()));
        assert_eq!(table.open(), Ok(3));

        assert_eq!(table.close(2), Ok(()));
        assert_eq!(table.open(), Err(Error::TableFull));
    }
}
