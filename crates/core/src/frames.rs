//! Reclaimable pool of physical frames.
//!
//! Frames are stored as addresses, so the pool never assumes physical memory is
//! contiguous. Allocation is last-in-first-out, which keeps recently freed
//! frames hot in the direct map and makes reuse cheap to test.

use crate::paging::PAGE_SIZE;
use crate::{Error, Result};

/// A fixed-capacity set of free physical frames.
#[derive(Clone, Copy, Debug)]
pub struct FramePool<const N: usize> {
    frames: [u64; N],
    len: usize,
}

impl<const N: usize> Default for FramePool<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> FramePool<N> {
    /// Construct an empty pool.
    pub const fn new() -> Self {
        Self {
            frames: [0; N],
            len: 0,
        }
    }

    /// Add one free frame, rejecting the null and misaligned addresses.
    pub fn push(&mut self, frame: u64) -> Result<()> {
        if frame == 0 || !frame.is_multiple_of(PAGE_SIZE) {
            return Err(Error::InvalidInput);
        }
        if self.len == N {
            return Err(Error::TableFull);
        }
        self.frames[self.len] = frame;
        self.len += 1;
        Ok(())
    }

    /// Add every page-aligned frame in `[base, base + length)`.
    pub fn add_region(&mut self, base: u64, length: u64) -> Result<usize> {
        let mask = PAGE_SIZE - 1;
        let start = base.checked_add(mask).ok_or(Error::OutOfRange)? & !mask;
        let end = base.checked_add(length).ok_or(Error::OutOfRange)? & !mask;
        let mut added = 0;
        let mut frame = start;
        while frame < end {
            self.push(frame)?;
            frame += PAGE_SIZE;
            added += 1;
        }
        Ok(added)
    }

    /// Take the most recently added free frame.
    pub fn allocate(&mut self) -> Option<u64> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        Some(self.frames[self.len])
    }

    /// Return a frame to the pool, rejecting unknown or already free frames.
    pub fn free(&mut self, frame: u64) -> Result<()> {
        if frame == 0 || !frame.is_multiple_of(PAGE_SIZE) {
            return Err(Error::InvalidInput);
        }
        if self.contains(frame) {
            return Err(Error::AlreadyExists);
        }
        self.push(frame)
    }

    /// Whether `frame` is currently free.
    pub fn contains(&self, frame: u64) -> bool {
        self.frames[..self.len].contains(&frame)
    }

    /// Number of free frames.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether no frames are free.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Total capacity in frames.
    pub const fn capacity(&self) -> usize {
        N
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regions_are_page_aligned_and_bounded() {
        let mut pool = FramePool::<8>::new();
        assert_eq!(pool.add_region(0x1003, 0x3ffd).unwrap(), 3);
        assert_eq!(pool.len(), 3);
        let mut frames = [0u64; 3];
        for frame in &mut frames {
            *frame = pool.allocate().unwrap();
        }
        assert_eq!(frames, [0x4000, 0x3000, 0x2000]);
    }

    #[test]
    fn allocation_is_lifo_and_freed_frames_are_reused() {
        let mut pool = FramePool::<4>::new();
        pool.add_region(0x1000, 0x3000).unwrap();
        assert_eq!(pool.allocate(), Some(0x3000));
        assert_eq!(pool.allocate(), Some(0x2000));
        assert_eq!(pool.free(0x3000), Ok(()));
        assert_eq!(pool.allocate(), Some(0x3000));
        assert_eq!(pool.allocate(), Some(0x1000));
        assert_eq!(pool.allocate(), None);
    }

    #[test]
    fn invalid_and_duplicate_frames_are_rejected() {
        let mut pool = FramePool::<4>::new();
        assert_eq!(pool.push(0), Err(Error::InvalidInput));
        assert_eq!(pool.push(0x1001), Err(Error::InvalidInput));
        assert_eq!(pool.free(0x1000), Ok(()));
        assert_eq!(pool.free(0x1000), Err(Error::AlreadyExists));
        assert_eq!(pool.free(0), Err(Error::InvalidInput));
    }

    #[test]
    fn capacity_is_enforced() {
        let mut pool = FramePool::<1>::new();
        pool.push(0x1000).unwrap();
        assert_eq!(pool.push(0x2000), Err(Error::TableFull));
        assert!(!pool.is_empty());
        assert_eq!(pool.capacity(), 1);
    }

    #[test]
    fn an_empty_region_adds_nothing() {
        let mut pool = FramePool::<4>::new();
        assert_eq!(pool.add_region(0x1fff, 0x1).unwrap(), 0);
        assert!(pool.is_empty());
        assert_eq!(pool.allocate(), None);
    }
}
