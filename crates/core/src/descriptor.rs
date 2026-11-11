//! POSIX-style descriptor table.
//!
//! Descriptors are process-local small integers. The table starts with the
//! standard streams open and never exposes a closed slot as valid, so a stale
//! descriptor number cannot silently refer to a different object.

use crate::{Error, Result};

/// Number of descriptors preopened for a new process (stdin, stdout, stderr).
pub const STANDARD_DESCRIPTORS: u32 = 3;

/// A fixed-capacity set of open descriptor numbers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DescriptorTable<const N: usize> {
    open: [bool; N],
}

impl<const N: usize> Default for DescriptorTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> DescriptorTable<N> {
    /// Construct a table with no open descriptors.
    pub const fn new() -> Self {
        Self { open: [false; N] }
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
        Self { open }
    }

    /// Whether `descriptor` currently refers to an open object.
    pub fn is_open(&self, descriptor: u32) -> bool {
        self.open.get(descriptor as usize).copied().unwrap_or(false)
    }

    /// Open the lowest free descriptor at or above the standard streams.
    pub fn open(&mut self) -> Result<u32> {
        for (index, slot) in self
            .open
            .iter_mut()
            .enumerate()
            .skip(STANDARD_DESCRIPTORS as usize)
        {
            if !*slot {
                *slot = true;
                return Ok(index as u32);
            }
        }
        Err(Error::TableFull)
    }

    /// Close an open descriptor, rejecting unknown or already closed slots.
    pub fn close(&mut self, descriptor: u32) -> Result<()> {
        match self.open.get_mut(descriptor as usize) {
            Some(slot) if *slot => {
                *slot = false;
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
