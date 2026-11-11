//! Architecture-independent physical-memory accounting.
//!
//! This bounded frame pool is a foundation for page-table construction. It is
//! not yet a general-purpose heap or a complete physical-memory manager.

use crate::{Error, Result};

/// Physical page-frame size used by the initial x86_64 mapping layer.
pub const FRAME_SIZE: u64 = 4096;

/// A physical frame identifier with validated alignment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Frame(u64);

impl Frame {
    /// Construct a frame only from a page-aligned physical address.
    pub const fn new(address: u64) -> Result<Self> {
        if address % FRAME_SIZE == 0 { Ok(Self(address)) } else { Err(Error::InvalidInput) }
    }

    /// Return the physical address.
    pub const fn address(self) -> u64 { self.0 }
}

/// A fixed-size frame allocator with explicit allocation state.
#[derive(Clone, Copy, Debug)]
pub struct FrameAllocator<const N: usize> {
    frames: [u64; N],
    used: [bool; N],
    len: usize,
}

impl<const N: usize> FrameAllocator<N> {
    /// Create an empty fixed-capacity allocator.
    pub const fn new() -> Self {
        Self { frames: [0; N], used: [false; N], len: 0 }
    }

    /// Add a free physical frame without duplicating an existing one.
    pub fn add(&mut self, frame: Frame) -> Result<()> {
        if self.len >= N { return Err(Error::TableFull); }
        if self.frames[..self.len].contains(&frame.0) { return Err(Error::AlreadyExists); }
        self.frames[self.len] = frame.0;
        self.len += 1;
        Ok(())
    }

    /// Allocate one available frame.
    pub fn allocate(&mut self) -> Result<u64> {
        for index in 0..self.len {
            if !self.used[index] {
                self.used[index] = true;
                return Ok(self.frames[index]);
            }
        }
        Err(Error::TableFull)
    }

    /// Release a frame previously allocated by this allocator.
    pub fn release(&mut self, frame: Frame) -> Result<()> {
        let index = self.frames[..self.len].iter().position(|address| *address == frame.0)
            .ok_or(Error::InvalidHandle)?;
        if !self.used[index] { return Err(Error::InvalidState); }
        self.used[index] = false;
        Ok(())
    }

    /// Return the number of unallocated frames.
    pub fn available(&self) -> usize {
        self.len - self.used.iter().filter(|used| **used).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_alignment_is_required() {
        assert!(Frame::new(0).is_ok());
        assert!(Frame::new(1).is_err());
        assert!(Frame::new(FRAME_SIZE).is_ok());
    }

    #[test]
    fn reserve_and_release_are_accounted() {
        let mut allocator = FrameAllocator::<1>::new();
        let frame = Frame::new(0x1000).unwrap();
        allocator.add(frame).unwrap();
        assert_eq!(allocator.available(), 1);
        assert_eq!(allocator.allocate(), Ok(0x1000));
        assert_eq!(allocator.available(), 0);
        assert_eq!(allocator.allocate(), Err(Error::TableFull));
        allocator.release(frame).unwrap();
        assert_eq!(allocator.available(), 1);
    }
}
