//! Binary buddy allocator over physical page frames.
//!
//! Each seeded region becomes an *arena*: a page-aligned run of frames that is
//! carved greedily into the largest naturally aligned power-of-two blocks that
//! fit, capped at `ORDERS - 1`. A block of order `k` covers `2^k` frames and
//! starts at a physical address aligned to `PAGE_SIZE << k`, so its buddy is
//! found by flipping one address bit. Blocks never merge across arenas, even
//! when two seeded regions happen to be adjacent.
//!
//! The allocator keeps one state byte and two free-list links per frame in
//! fixed arrays sized by const generics, so it needs no heap. Every address
//! passed to [`BuddyAllocator::free`] is treated as untrusted: null,
//! misaligned, foreign, interior, wrongly sized and already free blocks are all
//! rejected without changing any state.

use crate::paging::PAGE_SIZE;
use crate::{Error, Result};

/// Number of orders the allocator can represent; a block of the highest order
/// spans `PAGE_SIZE << 51` bytes, the largest power of two below `2^64`.
/// Orders at or above this bound are ignored even if `ORDERS` is larger.
pub const MAX_SUPPORTED_ORDERS: usize = 52;

const NIL: u32 = u32::MAX;
const TAIL: u8 = 0;
const FREE: u8 = 0x40;
const USED: u8 = 0x80;
const ORDER_MASK: u8 = 0x3f;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Arena {
    /// Physical address of the first frame.
    base: u64,
    /// Index of the first frame in the per-frame arrays.
    first: u32,
    /// Number of frames.
    count: u32,
}

impl Arena {
    fn end(&self) -> u64 {
        // Cannot overflow: `add_region` only records ranges that it computed
        // without overflow.
        self.base + u64::from(self.count) * PAGE_SIZE
    }

    fn contains(&self, address: u64) -> bool {
        address >= self.base && address < self.end()
    }

    fn index_of(&self, address: u64) -> u32 {
        // The offset is below `count`, which fits in `u32`.
        self.first + ((address - self.base) / PAGE_SIZE) as u32
    }
}

/// A buddy allocator over at most `FRAMES` frames in at most `ARENAS` regions,
/// serving blocks of orders `0..ORDERS`.
#[derive(Clone, Debug)]
pub struct BuddyAllocator<const FRAMES: usize, const ARENAS: usize, const ORDERS: usize> {
    arenas: [Arena; ARENAS],
    arena_count: usize,
    state: [u8; FRAMES],
    next: [u32; FRAMES],
    prev: [u32; FRAMES],
    heads: [u32; ORDERS],
    free_blocks: [usize; ORDERS],
    used: usize,
    free_frames: usize,
}

impl<const FRAMES: usize, const ARENAS: usize, const ORDERS: usize> Default
    for BuddyAllocator<FRAMES, ARENAS, ORDERS>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const FRAMES: usize, const ARENAS: usize, const ORDERS: usize>
    BuddyAllocator<FRAMES, ARENAS, ORDERS>
{
    /// Construct an allocator that owns no frames.
    pub const fn new() -> Self {
        Self {
            arenas: [Arena {
                base: 0,
                first: 0,
                count: 0,
            }; ARENAS],
            arena_count: 0,
            state: [TAIL; FRAMES],
            next: [NIL; FRAMES],
            prev: [NIL; FRAMES],
            heads: [NIL; ORDERS],
            free_blocks: [0; ORDERS],
            used: 0,
            free_frames: 0,
        }
    }

    /// Number of usable orders: `ORDERS` capped at [`MAX_SUPPORTED_ORDERS`].
    pub const fn orders(&self) -> usize {
        if ORDERS < MAX_SUPPORTED_ORDERS {
            ORDERS
        } else {
            MAX_SUPPORTED_ORDERS
        }
    }

    /// Add every whole page in `[base, base + length)` as a new arena.
    ///
    /// Rounding matches [`crate::frames::FramePool::add_region`]: the start is
    /// rounded up and the end down to a page boundary. The null frame is never
    /// added. Returns the number of frames added; a region with no whole page
    /// adds nothing. The call is atomic: on error nothing changes. Overlap with
    /// an existing arena is `AlreadyExists`; running out of frame or arena
    /// slots is `TableFull`.
    pub fn add_region(&mut self, base: u64, length: u64) -> Result<usize> {
        let orders = self.orders();
        if orders == 0 {
            return Err(Error::Unsupported);
        }
        let mask = PAGE_SIZE - 1;
        let start = base.checked_add(mask).ok_or(Error::OutOfRange)? & !mask;
        let end = base.checked_add(length).ok_or(Error::OutOfRange)? & !mask;
        let start = start.max(PAGE_SIZE);
        if start >= end {
            return Ok(0);
        }
        if self.arenas[..self.arena_count]
            .iter()
            .any(|arena| start < arena.end() && arena.base < end)
        {
            return Err(Error::AlreadyExists);
        }
        if self.arena_count >= ARENAS {
            return Err(Error::TableFull);
        }
        let count = usize::try_from((end - start) / PAGE_SIZE).map_err(|_| Error::TableFull)?;
        let total = self.used.checked_add(count).ok_or(Error::TableFull)?;
        if total > FRAMES || total >= NIL as usize {
            return Err(Error::TableFull);
        }
        let first = self.used as u32;
        self.arenas[self.arena_count] = Arena {
            base: start,
            first,
            count: count as u32,
        };
        self.arena_count += 1;
        self.used = total;

        let mut address = start;
        let mut index = first as usize;
        while address < end {
            let mut order = orders - 1;
            while order > 0 {
                let size = PAGE_SIZE << order;
                if address & (size - 1) == 0 && end - address >= size {
                    break;
                }
                order -= 1;
            }
            let frames = 1usize << order;
            self.state[index + 1..index + frames].fill(TAIL);
            self.push_free(index as u32, order);
            index += frames;
            address += PAGE_SIZE << order;
        }
        self.free_frames += count;
        Ok(count)
    }

    /// Allocate a block of `2^order` contiguous frames and return its physical
    /// address, which is aligned to the block size.
    ///
    /// An order outside `0..orders()` is `InvalidInput`; exhaustion is
    /// `TableFull`.
    pub fn allocate(&mut self, order: usize) -> Result<u64> {
        if order >= self.orders() {
            return Err(Error::InvalidInput);
        }
        let mut current = order;
        while current < self.orders() && self.heads[current] == NIL {
            current += 1;
        }
        if current >= self.orders() {
            return Err(Error::TableFull);
        }
        let index = self.heads[current];
        self.remove_free(index, current);
        while current > order {
            current -= 1;
            self.push_free(index + (1u32 << current), current);
        }
        self.state[index as usize] = USED | order as u8;
        self.free_frames -= 1 << order;
        self.address_of(index).ok_or(Error::InvalidState)
    }

    /// Return the block at `address` that was allocated with `order`.
    ///
    /// The block is merged with its free buddy, repeatedly, up to the highest
    /// order. Null or misaligned addresses and blocks not starting at
    /// `address` are `InvalidInput`, as is an `order` that differs from the
    /// allocated one. An address outside every arena is `NotFound`; a block
    /// that is already free is `AlreadyExists`.
    pub fn free(&mut self, address: u64, order: usize) -> Result<()> {
        let (arena, mut index) = self.locate(address)?;
        if order >= self.orders() {
            return Err(Error::InvalidInput);
        }
        let state = self.state[index as usize];
        if state & FREE != 0 {
            return Err(Error::AlreadyExists);
        }
        if state & USED == 0 || usize::from(state & ORDER_MASK) != order {
            return Err(Error::InvalidInput);
        }
        self.state[index as usize] = TAIL;
        self.free_frames += 1 << order;

        let mut address = address;
        let mut order = order;
        while order + 1 < self.orders() {
            let size = PAGE_SIZE << order;
            let buddy = address ^ size;
            if buddy < arena.base || buddy.checked_add(size).is_none_or(|end| end > arena.end()) {
                break;
            }
            let buddy_index = arena.index_of(buddy);
            if self.state[buddy_index as usize] != FREE | order as u8 {
                break;
            }
            self.remove_free(buddy_index, order);
            self.state[buddy_index as usize] = TAIL;
            address = address.min(buddy);
            index = index.min(buddy_index);
            order += 1;
        }
        self.push_free(index, order);
        Ok(())
    }

    /// The order of the allocated block starting at `address`, if any.
    pub fn allocated_order(&self, address: u64) -> Option<usize> {
        let (_, index) = self.locate(address).ok()?;
        let state = self.state[index as usize];
        (state & USED != 0).then_some(usize::from(state & ORDER_MASK))
    }

    /// Whether `address` lies in a frame owned by this allocator.
    pub fn owns(&self, address: u64) -> bool {
        self.arenas[..self.arena_count]
            .iter()
            .any(|arena| arena.contains(address))
    }

    /// Number of free frames across all orders.
    pub fn free_frames(&self) -> usize {
        self.free_frames
    }

    /// Number of frames seeded into the allocator.
    pub fn total_frames(&self) -> usize {
        self.used
    }

    /// Number of free blocks of `order`; zero for an unsupported order.
    pub fn free_blocks(&self, order: usize) -> usize {
        if order < self.orders() {
            self.free_blocks[order]
        } else {
            0
        }
    }

    /// Number of seeded regions.
    pub fn arena_count(&self) -> usize {
        self.arena_count
    }

    /// Verify every structural invariant, returning `InvalidState` on the
    /// first violation.
    ///
    /// Checked: arenas tile the frames in order; each block is naturally
    /// aligned, lies inside its arena and is followed by exactly its tail
    /// frames; no free block has a free buddy of the same order; the free
    /// lists are consistent doubly linked lists of free blocks of their order;
    /// and the free-frame and per-order block counts match the tiling.
    pub fn check_invariants(&self) -> Result<()> {
        let orders = self.orders();
        let mut free_frames = 0usize;
        let mut blocks = [0usize; MAX_SUPPORTED_ORDERS];
        let mut expected_first = 0usize;
        for arena in &self.arenas[..self.arena_count] {
            if arena.first as usize != expected_first || arena.count == 0 {
                return Err(Error::InvalidState);
            }
            let end = expected_first + arena.count as usize;
            let mut index = expected_first;
            while index < end {
                let state = self.state[index];
                let order = usize::from(state & ORDER_MASK);
                let free = state & FREE != 0;
                if state & (FREE | USED) == 0 || (free && state & USED != 0) || order >= orders {
                    return Err(Error::InvalidState);
                }
                let frames = 1usize << order;
                let address = arena.base + (index - expected_first) as u64 * PAGE_SIZE;
                let size = PAGE_SIZE << order;
                if address & (size - 1) != 0 || index + frames > end {
                    return Err(Error::InvalidState);
                }
                if self.state[index + 1..index + frames]
                    .iter()
                    .any(|&tail| tail != TAIL)
                {
                    return Err(Error::InvalidState);
                }
                if free {
                    free_frames += frames;
                    blocks[order] += 1;
                    let buddy = address ^ size;
                    if order + 1 < orders
                        && buddy >= arena.base
                        && buddy.checked_add(size).is_some_and(|end| end <= arena.end())
                        && self.state[arena.index_of(buddy) as usize] == state
                    {
                        return Err(Error::InvalidState);
                    }
                }
                index += frames;
            }
            expected_first = end;
        }
        if expected_first != self.used || free_frames != self.free_frames {
            return Err(Error::InvalidState);
        }
        for order in 0..orders {
            let mut length = 0usize;
            let mut previous = NIL;
            let mut current = self.heads[order];
            while current != NIL {
                if current as usize >= self.used
                    || length >= self.used
                    || self.state[current as usize] != FREE | order as u8
                    || self.prev[current as usize] != previous
                {
                    return Err(Error::InvalidState);
                }
                length += 1;
                previous = current;
                current = self.next[current as usize];
            }
            if length != self.free_blocks[order] || length != blocks[order] {
                return Err(Error::InvalidState);
            }
        }
        Ok(())
    }

    fn locate(&self, address: u64) -> Result<(Arena, u32)> {
        if address == 0 || !address.is_multiple_of(PAGE_SIZE) {
            return Err(Error::InvalidInput);
        }
        self.arenas[..self.arena_count]
            .iter()
            .find(|arena| arena.contains(address))
            .map(|arena| (*arena, arena.index_of(address)))
            .ok_or(Error::NotFound)
    }

    fn address_of(&self, index: u32) -> Option<u64> {
        self.arenas[..self.arena_count]
            .iter()
            .find(|arena| index >= arena.first && index - arena.first < arena.count)
            .map(|arena| arena.base + u64::from(index - arena.first) * PAGE_SIZE)
    }

    fn push_free(&mut self, index: u32, order: usize) {
        let head = self.heads[order];
        self.state[index as usize] = FREE | order as u8;
        self.next[index as usize] = head;
        self.prev[index as usize] = NIL;
        if head != NIL {
            self.prev[head as usize] = index;
        }
        self.heads[order] = index;
        self.free_blocks[order] += 1;
    }

    fn remove_free(&mut self, index: u32, order: usize) {
        let next = self.next[index as usize];
        let prev = self.prev[index as usize];
        if prev == NIL {
            self.heads[order] = next;
        } else {
            self.next[prev as usize] = next;
        }
        if next != NIL {
            self.prev[next as usize] = prev;
        }
        self.next[index as usize] = NIL;
        self.prev[index as usize] = NIL;
        self.free_blocks[order] -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Small = BuddyAllocator<64, 4, 5>;

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, bound: u64) -> u64 {
            self.next() % bound
        }
    }

    #[test]
    fn regions_round_like_the_frame_pool_and_skip_the_null_frame() {
        let mut buddy = Small::new();
        assert_eq!(buddy.add_region(0x1003, 0x3ffd), Ok(3));
        assert_eq!(buddy.free_blocks(1), 1);
        assert_eq!(buddy.free_blocks(0), 1);
        assert_eq!(buddy.add_region(0, 0x1000), Ok(0));
        assert_eq!(buddy.add_region(0x7fff, 0x1), Ok(0));
        let mut low = Small::new();
        assert_eq!(low.add_region(0, 0x4000), Ok(3));
        assert!(!low.owns(0));
        assert_eq!(low.free(0, 0), Err(Error::InvalidInput));
        low.check_invariants().unwrap();
        buddy.check_invariants().unwrap();
    }

    #[test]
    fn seeding_uses_maximal_aligned_blocks() {
        let mut buddy = Small::new();
        // Frames 0x3000..0x2a000: 39 frames.
        assert_eq!(buddy.add_region(0x3000, 0x27000), Ok(39));
        buddy.check_invariants().unwrap();
        assert_eq!(buddy.free_frames(), 39);
        // 0x3000 (o0), 0x4000 (o2), 0x8000 (o3), 0x10000 (o4),
        // 0x20000 (o3), 0x28000 (o1).
        assert_eq!(buddy.free_blocks(4), 1);
        assert_eq!(buddy.free_blocks(3), 2);
        assert_eq!(buddy.free_blocks(2), 1);
        assert_eq!(buddy.free_blocks(1), 1);
        assert_eq!(buddy.free_blocks(0), 1);
    }

    #[test]
    fn allocation_splits_and_free_coalesces() {
        let mut buddy = Small::new();
        buddy.add_region(0x10000, 0x10000).unwrap();
        assert_eq!(buddy.free_blocks(4), 1);
        let a = buddy.allocate(0).unwrap();
        assert_eq!(a, 0x10000);
        for order in 0..4 {
            assert_eq!(buddy.free_blocks(order), 1);
        }
        assert_eq!(buddy.allocated_order(a), Some(0));
        let b = buddy.allocate(2).unwrap();
        assert_eq!(b, 0x14000);
        assert_eq!(b % (PAGE_SIZE << 2), 0);
        buddy.check_invariants().unwrap();
        buddy.free(a, 0).unwrap();
        buddy.check_invariants().unwrap();
        buddy.free(b, 2).unwrap();
        buddy.check_invariants().unwrap();
        assert_eq!(buddy.free_blocks(4), 1);
        assert_eq!(buddy.free_frames(), 16);
    }

    #[test]
    fn hostile_frees_are_rejected_without_side_effects() {
        let mut buddy = Small::new();
        buddy.add_region(0x10000, 0x10000).unwrap();
        let block = buddy.allocate(2).unwrap();
        let before = buddy.free_frames();
        assert_eq!(buddy.free(0, 0), Err(Error::InvalidInput));
        assert_eq!(buddy.free(block + 1, 2), Err(Error::InvalidInput));
        assert_eq!(buddy.free(0x9000, 0), Err(Error::NotFound));
        assert_eq!(buddy.free(0x40000, 0), Err(Error::NotFound));
        assert_eq!(buddy.free(u64::MAX & !0xfff, 0), Err(Error::NotFound));
        assert_eq!(buddy.free(block, 1), Err(Error::InvalidInput));
        assert_eq!(buddy.free(block, 99), Err(Error::InvalidInput));
        assert_eq!(buddy.free(block + PAGE_SIZE, 0), Err(Error::InvalidInput));
        assert_eq!(buddy.free(0x18000, 3), Err(Error::AlreadyExists));
        assert_eq!(buddy.free_frames(), before);
        buddy.check_invariants().unwrap();
        buddy.free(block, 2).unwrap();
        assert_eq!(buddy.free(block, 2), Err(Error::AlreadyExists));
        buddy.check_invariants().unwrap();
    }

    #[test]
    fn invalid_orders_and_exhaustion_are_reported() {
        let mut buddy = Small::new();
        assert_eq!(buddy.allocate(0), Err(Error::TableFull));
        assert_eq!(buddy.allocate(5), Err(Error::InvalidInput));
        buddy.add_region(0x1000, 0x3000).unwrap();
        assert_eq!(buddy.allocate(2), Err(Error::TableFull));
        assert!(buddy.allocate(1).is_ok());
        assert!(buddy.allocate(0).is_ok());
        assert_eq!(buddy.allocate(0), Err(Error::TableFull));
        assert_eq!(buddy.free_frames(), 0);
        let mut none = BuddyAllocator::<4, 1, 0>::new();
        assert_eq!(none.add_region(0x1000, 0x1000), Err(Error::Unsupported));
        assert_eq!(none.allocate(0), Err(Error::InvalidInput));
    }

    #[test]
    fn seeding_is_bounded_and_atomic() {
        let mut buddy = BuddyAllocator::<8, 2, 4>::new();
        assert_eq!(buddy.add_region(0x1000, 0x9000), Err(Error::TableFull));
        assert_eq!(buddy.total_frames(), 0);
        assert_eq!(buddy.arena_count(), 0);
        assert_eq!(buddy.add_region(u64::MAX, 2), Err(Error::OutOfRange));
        assert_eq!(buddy.add_region(0x1000, 0x4000), Ok(4));
        assert_eq!(buddy.add_region(0x4000, 0x1000), Err(Error::AlreadyExists));
        assert_eq!(buddy.add_region(0x0, 0x2000), Err(Error::AlreadyExists));
        assert_eq!(buddy.add_region(0x10000, 0x1000), Ok(1));
        assert_eq!(buddy.add_region(0x20000, 0x1000), Err(Error::TableFull));
        assert_eq!(buddy.total_frames(), 5);
        buddy.check_invariants().unwrap();
    }

    #[test]
    fn high_regions_do_not_overflow() {
        let mut buddy = BuddyAllocator::<8, 2, 64>::new();
        assert_eq!(buddy.orders(), MAX_SUPPORTED_ORDERS);
        assert_eq!(buddy.add_region(u64::MAX - 0x7fff, 0x8000), Err(Error::OutOfRange));
        // Frames 0x..8000 through 0x..e000; the last page is never whole.
        assert_eq!(buddy.add_region(u64::MAX - 0x7fff, 0x7fff), Ok(7));
        buddy.check_invariants().unwrap();
        let block = buddy.allocate(2).unwrap();
        assert_eq!(block, 0xffff_ffff_ffff_8000);
        let pair = buddy.allocate(1).unwrap();
        let last = buddy.allocate(0).unwrap();
        assert_eq!(last, 0xffff_ffff_ffff_e000);
        buddy.free(last, 0).unwrap();
        buddy.free(pair, 1).unwrap();
        buddy.free(block, 2).unwrap();
        buddy.check_invariants().unwrap();
        assert_eq!(buddy.free_frames(), 7);
    }

    #[test]
    fn adjacent_arenas_never_merge() {
        let mut buddy = Small::new();
        buddy.add_region(0x10000, 0x8000).unwrap();
        buddy.add_region(0x18000, 0x8000).unwrap();
        assert_eq!(buddy.free_blocks(3), 2);
        assert_eq!(buddy.free_blocks(4), 0);
        let a = buddy.allocate(3).unwrap();
        let b = buddy.allocate(3).unwrap();
        buddy.free(a, 3).unwrap();
        buddy.free(b, 3).unwrap();
        assert_eq!(buddy.free_blocks(3), 2);
        assert_eq!(buddy.allocate(4), Err(Error::TableFull));
        buddy.check_invariants().unwrap();
    }

    #[test]
    fn randomized_sequences_preserve_invariants() {
        const LIVE: usize = 96;
        for seed in 1..=24u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
            let mut buddy = BuddyAllocator::<256, 4, 6>::new();
            let mut base = 0x3000u64;
            for _ in 0..3 {
                let base_jitter = rng.below(PAGE_SIZE);
                let length = rng.below(80) * PAGE_SIZE + rng.below(PAGE_SIZE);
                buddy.add_region(base + base_jitter, length).unwrap();
                base += length + 0x40000;
            }
            buddy.check_invariants().unwrap();
            let total = buddy.total_frames();
            let seeded: [usize; 6] = core::array::from_fn(|order| buddy.free_blocks(order));
            let mut live = [(0u64, 0usize); LIVE];
            let mut live_len = 0usize;
            let mut last_freed: Option<(u64, usize)> = None;
            for _ in 0..600 {
                match rng.below(10) {
                    0..=4 if live_len < LIVE => {
                        let order = rng.below(6) as usize;
                        match buddy.allocate(order) {
                            Ok(address) => {
                                let size = PAGE_SIZE << order;
                                assert_eq!(address % size, 0);
                                assert!(buddy.owns(address) && buddy.owns(address + size - 1));
                                for &(other, other_order) in &live[..live_len] {
                                    let other_end = other + (PAGE_SIZE << other_order);
                                    assert!(address + size <= other || other_end <= address);
                                }
                                live[live_len] = (address, order);
                                live_len += 1;
                            }
                            Err(error) => {
                                assert_eq!(error, Error::TableFull);
                                assert!((order..6).all(|k| buddy.free_blocks(k) == 0));
                            }
                        }
                    }
                    5..=7 if live_len > 0 => {
                        let slot = rng.below(live_len as u64) as usize;
                        let (address, order) = live[slot];
                        live[slot] = live[live_len - 1];
                        live_len -= 1;
                        buddy.free(address, order).unwrap();
                        last_freed = Some((address, order));
                    }
                    8 => {
                        if let Some((address, order)) = last_freed
                            && !live[..live_len].contains(&(address, order))
                        {
                            let before = buddy.free_frames();
                            assert!(buddy.free(address, order).is_err());
                            assert_eq!(buddy.free_frames(), before);
                        }
                    }
                    _ => {
                        let before = buddy.free_frames();
                        let address = rng.next() & !0xfff;
                        let order = rng.below(8) as usize;
                        let legitimate = live[..live_len].contains(&(address, order));
                        if !legitimate {
                            assert!(buddy.free(address, order).is_err());
                            assert_eq!(buddy.free_frames(), before);
                        }
                    }
                }
                buddy.check_invariants().unwrap();
                let used: usize = live[..live_len].iter().map(|&(_, k)| 1usize << k).sum();
                assert_eq!(buddy.free_frames() + used, total);
            }
            for &(address, order) in &live[..live_len] {
                buddy.free(address, order).unwrap();
            }
            buddy.check_invariants().unwrap();
            assert_eq!(buddy.free_frames(), total);
            for (order, &count) in seeded.iter().enumerate() {
                assert_eq!(buddy.free_blocks(order), count);
            }
        }
    }
}
