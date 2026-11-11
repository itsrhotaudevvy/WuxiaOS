//! Fixed-capacity timer queue keyed by deadline tick.
//!
//! Timers form a binary min-heap ordered by `(deadline, insertion sequence)`,
//! so timers with equal deadlines fire in the order they were armed. Each slot
//! carries a generation that advances on every arm, and a [`TimerId`] names both
//! slot and generation. A stale id therefore cannot cancel the timer that later
//! reuses its slot. The queue never invokes callbacks: each timer stores an
//! opaque owner word that the caller interprets when the timer expires.

use crate::{Error, Result};

/// Handle to an armed timer. Ids of fired or cancelled timers become stale.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerId {
    slot: usize,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Slot {
    /// Advanced on every arm, so ids issued for earlier occupants never match.
    generation: u64,
    deadline: u64,
    sequence: u64,
    owner: u64,
    /// Position of this slot in the heap while the timer is armed.
    heap_index: Option<usize>,
}

impl Slot {
    const FREE: Self = Self {
        generation: 0,
        deadline: 0,
        sequence: 0,
        owner: 0,
        heap_index: None,
    };
}

/// A min-heap of up to `N` armed timers.
///
/// Every slot is in exactly one state: free (on the free stack), armed (in the
/// heap), or retired (its generation is exhausted, so it is never reused).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerQueue<const N: usize> {
    slots: [Slot; N],
    /// Slot indices in heap order; only `heap[..len]` is meaningful.
    heap: [usize; N],
    /// Slots available for arming; only `free[..free_len]` is meaningful.
    free: [usize; N],
    free_len: usize,
    len: usize,
    next_sequence: u64,
}

impl<const N: usize> Default for TimerQueue<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> TimerQueue<N> {
    /// Construct an empty queue.
    pub const fn new() -> Self {
        let mut free = [0usize; N];
        let mut index = 0;
        while index < N {
            free[index] = index;
            index += 1;
        }
        Self {
            slots: [Slot::FREE; N],
            heap: [0; N],
            free,
            free_len: N,
            len: 0,
            next_sequence: 0,
        }
    }

    /// Arm a timer that expires once `now >= deadline`, returning its id.
    ///
    /// Fails with [`Error::TableFull`] when every slot is armed or retired, and
    /// with [`Error::OutOfRange`] when the insertion sequence would overflow.
    pub fn arm(&mut self, deadline: u64, owner: u64) -> Result<TimerId> {
        let sequence = self.next_sequence;
        let next_sequence = sequence.checked_add(1).ok_or(Error::OutOfRange)?;
        let (slot, generation) = self.take_free_slot()?;
        self.next_sequence = next_sequence;
        self.slots[slot] = Slot {
            generation,
            deadline,
            sequence,
            owner,
            heap_index: None,
        };
        let pos = self.len;
        self.len += 1;
        self.set_heap(pos, slot);
        self.sift_up(pos);
        Ok(TimerId { slot, generation })
    }

    /// Cancel an armed timer in O(log N).
    ///
    /// Returns [`Error::InvalidHandle`] when the id is stale, was already
    /// cancelled or fired, or names no slot of this queue.
    pub fn cancel(&mut self, id: TimerId) -> Result<()> {
        let pos = self.live_position(id).ok_or(Error::InvalidHandle)?;
        let slot = self.remove_at(pos);
        self.free_slot(slot);
        Ok(())
    }

    /// Deadline of the timer that expires first, if any timer is armed.
    pub fn next_deadline(&self) -> Option<u64> {
        (self.len > 0).then(|| self.slots[self.heap[0]].deadline)
    }

    /// Remove and return the earliest timer whose deadline is at or before
    /// `now`, together with its owner.
    ///
    /// Returns `None` when the earliest timer is still in the future or the
    /// queue is empty. Call repeatedly to drain every expired timer.
    pub fn pop_expired(&mut self, now: u64) -> Option<(TimerId, u64)> {
        if self.len == 0 {
            return None;
        }
        let slot = self.heap[0];
        let entry = self.slots[slot];
        if entry.deadline > now {
            return None;
        }
        self.remove_at(0);
        self.free_slot(slot);
        Some((
            TimerId {
                slot,
                generation: entry.generation,
            },
            entry.owner,
        ))
    }

    /// Number of armed timers.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether no timer is armed.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Heap index of the timer named by `id`, if that timer is still armed.
    fn live_position(&self, id: TimerId) -> Option<usize> {
        let slot = self.slots.get(id.slot)?;
        if slot.generation == id.generation {
            slot.heap_index
        } else {
            None
        }
    }

    /// Pop a slot with a generation to issue, retiring any whose generation is
    /// exhausted. Fails with `TableFull` when no usable slot remains.
    fn take_free_slot(&mut self) -> Result<(usize, u64)> {
        while self.free_len > 0 {
            self.free_len -= 1;
            let slot = self.free[self.free_len];
            if let Some(generation) = self.slots[slot].generation.checked_add(1) {
                return Ok((slot, generation));
            }
        }
        Err(Error::TableFull)
    }

    fn free_slot(&mut self, slot: usize) {
        self.free[self.free_len] = slot;
        self.free_len += 1;
    }

    /// Remove the heap entry at `pos`, restore heap order, and return its slot.
    fn remove_at(&mut self, pos: usize) -> usize {
        let slot = self.heap[pos];
        self.len -= 1;
        self.slots[slot].heap_index = None;
        if pos != self.len {
            let moved = self.heap[self.len];
            self.set_heap(pos, moved);
            // Only one of these moves the element; the other is a no-op.
            self.sift_up(pos);
            self.sift_down(pos);
        }
        slot
    }

    fn before(&self, a: usize, b: usize) -> bool {
        let (left, right) = (self.slots[a], self.slots[b]);
        (left.deadline, left.sequence) < (right.deadline, right.sequence)
    }

    fn set_heap(&mut self, pos: usize, slot: usize) {
        self.heap[pos] = slot;
        self.slots[slot].heap_index = Some(pos);
    }

    fn swap_heap(&mut self, a: usize, b: usize) {
        let (slot_a, slot_b) = (self.heap[a], self.heap[b]);
        self.set_heap(a, slot_b);
        self.set_heap(b, slot_a);
    }

    fn sift_up(&mut self, mut pos: usize) {
        while pos > 0 {
            let parent = (pos - 1) / 2;
            if !self.before(self.heap[pos], self.heap[parent]) {
                break;
            }
            self.swap_heap(pos, parent);
            pos = parent;
        }
    }

    fn sift_down(&mut self, mut pos: usize) {
        loop {
            let left = pos * 2 + 1;
            let right = left + 1;
            let mut smallest = pos;
            if left < self.len && self.before(self.heap[left], self.heap[smallest]) {
                smallest = left;
            }
            if right < self.len && self.before(self.heap[right], self.heap[smallest]) {
                smallest = right;
            }
            if smallest == pos {
                break;
            }
            self.swap_heap(pos, smallest);
            pos = smallest;
        }
    }
}

/// Next deadline for a periodic timer that was due at `deadline` and is being
/// rearmed at tick `now`.
///
/// The result is the first point on the original grid `deadline + k * interval`
/// that lies strictly after `now`. Periods that were missed while the timer
/// waited are skipped rather than fired back to back. A timer not yet due keeps
/// its deadline. A zero interval is [`Error::InvalidInput`], and any overflow is
/// [`Error::OutOfRange`].
pub fn rearm_periodic(deadline: u64, interval: u64, now: u64) -> Result<u64> {
    if interval == 0 {
        return Err(Error::InvalidInput);
    }
    if now < deadline {
        return Ok(deadline);
    }
    let elapsed = now - deadline;
    let periods = (elapsed / interval)
        .checked_add(1)
        .ok_or(Error::OutOfRange)?;
    let offset = periods.checked_mul(interval).ok_or(Error::OutOfRange)?;
    deadline.checked_add(offset).ok_or(Error::OutOfRange)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic linear congruential generator for the model test.
    struct Lcg(u64);

    impl Lcg {
        fn step(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0 >> 33
        }

        fn below(&mut self, bound: u64) -> u64 {
            self.step() % bound
        }
    }

    /// Pop every timer expired at `now`, returning their owners in fire order.
    fn drain<const N: usize>(queue: &mut TimerQueue<N>, now: u64) -> ([u64; N], usize) {
        let mut owners = [0u64; N];
        let mut count = 0;
        while let Some((_, owner)) = queue.pop_expired(now) {
            owners[count] = owner;
            count += 1;
        }
        (owners, count)
    }

    #[test]
    fn an_empty_queue_has_no_deadline_and_pops_nothing() {
        let mut queue = TimerQueue::<4>::new();
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);
        assert_eq!(queue.next_deadline(), None);
        assert_eq!(queue.pop_expired(u64::MAX), None);
    }

    #[test]
    fn next_deadline_tracks_the_earliest_armed_timer() {
        let mut queue = TimerQueue::<4>::new();
        queue.arm(30, 1).unwrap();
        assert_eq!(queue.next_deadline(), Some(30));
        queue.arm(10, 2).unwrap();
        queue.arm(20, 3).unwrap();
        assert_eq!(queue.next_deadline(), Some(10));
        assert_eq!(queue.len(), 3);
    }

    #[test]
    fn timers_fire_in_deadline_order_regardless_of_arm_order() {
        let mut queue = TimerQueue::<8>::new();
        for (deadline, owner) in [(50, 1), (10, 2), (30, 3), (20, 4), (40, 5)] {
            queue.arm(deadline, owner).unwrap();
        }
        assert_eq!(queue.pop_expired(9), None);
        let (owners, count) = drain(&mut queue, 100);
        assert_eq!(&owners[..count], &[2, 4, 3, 5, 1]);
        assert!(queue.is_empty());
    }

    #[test]
    fn expiry_is_inclusive_of_the_deadline_tick() {
        let mut queue = TimerQueue::<2>::new();
        queue.arm(10, 7).unwrap();
        assert_eq!(queue.pop_expired(9), None);
        assert_eq!(queue.len(), 1);
        let (_, owner) = queue.pop_expired(10).unwrap();
        assert_eq!(owner, 7);
        assert_eq!(queue.pop_expired(10), None);
    }

    #[test]
    fn equal_deadlines_fire_in_insertion_order() {
        let mut queue = TimerQueue::<8>::new();
        for owner in [1, 2, 3] {
            queue.arm(5, owner).unwrap();
        }
        queue.arm(4, 4).unwrap();
        queue.arm(5, 5).unwrap();
        let (owners, count) = drain(&mut queue, 5);
        assert_eq!(&owners[..count], &[4, 1, 2, 3, 5]);
    }

    #[test]
    fn cancel_removes_a_timer_before_it_fires() {
        let mut queue = TimerQueue::<4>::new();
        queue.arm(10, 1).unwrap();
        let middle = queue.arm(20, 2).unwrap();
        queue.arm(30, 3).unwrap();
        assert_eq!(queue.cancel(middle), Ok(()));
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.cancel(middle), Err(Error::InvalidHandle));
        let (owners, count) = drain(&mut queue, 100);
        assert_eq!(&owners[..count], &[1, 3]);
    }

    #[test]
    fn cancelling_the_earliest_timer_exposes_the_next_one() {
        let mut queue = TimerQueue::<4>::new();
        let first = queue.arm(5, 1).unwrap();
        queue.arm(9, 2).unwrap();
        assert_eq!(queue.cancel(first), Ok(()));
        assert_eq!(queue.next_deadline(), Some(9));
    }

    #[test]
    fn a_stale_id_cannot_cancel_a_reused_slot() {
        let mut queue = TimerQueue::<1>::new();
        let first = queue.arm(10, 1).unwrap();
        queue.cancel(first).unwrap();
        let second = queue.arm(20, 2).unwrap();
        assert_eq!(first.slot, second.slot);
        assert_ne!(first, second);
        assert_eq!(queue.cancel(first), Err(Error::InvalidHandle));
        assert_eq!(queue.next_deadline(), Some(20));
        assert_eq!(queue.cancel(second), Ok(()));
        assert!(queue.is_empty());
    }

    #[test]
    fn a_fired_timer_id_is_stale_even_before_its_slot_is_reused() {
        let mut queue = TimerQueue::<2>::new();
        let fired = queue.arm(1, 1).unwrap();
        let (id, owner) = queue.pop_expired(1).unwrap();
        assert_eq!((id, owner), (fired, 1));
        assert_eq!(queue.cancel(fired), Err(Error::InvalidHandle));

        let reused = queue.arm(9, 2).unwrap();
        assert_eq!(queue.cancel(fired), Err(Error::InvalidHandle));
        assert_eq!(queue.next_deadline(), Some(9));
        assert_eq!(queue.cancel(reused), Ok(()));
    }

    #[test]
    fn a_full_queue_rejects_arms_until_a_slot_is_released() {
        let mut queue = TimerQueue::<2>::new();
        let first = queue.arm(1, 1).unwrap();
        queue.arm(2, 2).unwrap();
        assert_eq!(queue.arm(3, 3), Err(Error::TableFull));
        queue.cancel(first).unwrap();
        assert!(queue.arm(3, 3).is_ok());
        assert_eq!(queue.arm(4, 4), Err(Error::TableFull));
        let (_, count) = drain(&mut queue, 2);
        assert_eq!(count, 1);
        assert!(queue.arm(4, 4).is_ok());
    }

    #[test]
    fn a_zero_capacity_queue_is_always_full() {
        let mut queue = TimerQueue::<0>::new();
        assert_eq!(queue.arm(0, 0), Err(Error::TableFull));
        assert_eq!(queue.next_deadline(), None);
        assert_eq!(queue.pop_expired(u64::MAX), None);
        assert_eq!(
            queue.cancel(TimerId {
                slot: 0,
                generation: 0
            }),
            Err(Error::InvalidHandle)
        );
    }

    #[test]
    fn ids_that_name_no_armed_timer_are_rejected() {
        let mut queue = TimerQueue::<2>::new();
        let forged_slot = TimerId {
            slot: 99,
            generation: 0,
        };
        assert_eq!(queue.cancel(forged_slot), Err(Error::InvalidHandle));
        let unarmed = TimerId {
            slot: 0,
            generation: 0,
        };
        assert_eq!(queue.cancel(unarmed), Err(Error::InvalidHandle));
        queue.arm(5, 5).unwrap();
        assert_eq!(queue.cancel(unarmed), Err(Error::InvalidHandle));
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn cancellation_keeps_the_heap_ordered_under_churn() {
        const N: usize = 32;
        let mut queue = TimerQueue::<N>::new();
        let mut rng = Lcg(0x5eed);
        let mut ids = [TimerId {
            slot: 0,
            generation: 0,
        }; N];
        let mut deadlines = [0u64; N];
        for index in 0..N {
            deadlines[index] = rng.below(1000);
            ids[index] = queue.arm(deadlines[index], index as u64).unwrap();
        }
        for index in (0..N).step_by(3) {
            queue.cancel(ids[index]).unwrap();
            deadlines[index] = u64::MAX;
        }
        let mut previous = 0;
        let mut fired = 0;
        while let Some((_, owner)) = queue.pop_expired(u64::MAX) {
            let deadline = deadlines[owner as usize];
            assert_ne!(deadline, u64::MAX, "cancelled timer fired");
            assert!(deadline >= previous, "heap order broken");
            previous = deadline;
            fired += 1;
        }
        assert_eq!(fired, N - N.div_ceil(3));
    }

    #[test]
    fn exhausting_a_generation_retires_its_slot() {
        let mut queue = TimerQueue::<2>::new();
        queue.slots[0].generation = u64::MAX;
        let first = queue.arm(1, 1).unwrap();
        assert_ne!(first.slot, 0);
        assert_eq!(queue.arm(2, 2), Err(Error::TableFull));
        assert_eq!(queue.cancel(first), Ok(()));
        assert!(queue.arm(3, 3).is_ok());
    }

    #[test]
    fn exhausting_the_insertion_sequence_rejects_arms_without_changes() {
        let mut queue = TimerQueue::<2>::new();
        queue.next_sequence = u64::MAX;
        assert_eq!(queue.arm(1, 1), Err(Error::OutOfRange));
        assert!(queue.is_empty());
        assert_eq!(queue.free_len, 2);
    }

    #[test]
    fn rearming_steps_to_the_next_period_on_the_grid() {
        assert_eq!(rearm_periodic(10, 10, 10), Ok(20));
        assert_eq!(rearm_periodic(10, 10, 19), Ok(20));
        assert_eq!(rearm_periodic(10, 10, 20), Ok(30));
    }

    #[test]
    fn rearming_skips_missed_periods_instead_of_bursting() {
        assert_eq!(rearm_periodic(10, 10, 95), Ok(100));
        assert_eq!(rearm_periodic(0, 7, 1_000), Ok(1_001));
        for now in 0..200u64 {
            let next = rearm_periodic(10, 10, now).unwrap();
            assert!(next > now);
            assert!(next - now <= 10);
            assert_eq!((next - 10) % 10, 0);
        }
    }

    #[test]
    fn rearming_keeps_a_timer_that_is_not_yet_due() {
        assert_eq!(rearm_periodic(50, 10, 20), Ok(50));
        assert_eq!(rearm_periodic(50, 10, 49), Ok(50));
    }

    #[test]
    fn rearming_rejects_zero_intervals_and_overflow() {
        assert_eq!(rearm_periodic(0, 0, 0), Err(Error::InvalidInput));
        assert_eq!(rearm_periodic(0, 0, 9), Err(Error::InvalidInput));
        assert_eq!(
            rearm_periodic(u64::MAX - 5, 10, u64::MAX - 5),
            Err(Error::OutOfRange)
        );
        assert_eq!(rearm_periodic(0, u64::MAX, 1), Ok(u64::MAX));
        assert_eq!(
            rearm_periodic(0, u64::MAX, u64::MAX),
            Err(Error::OutOfRange)
        );
    }

    #[test]
    fn a_periodic_timer_drifts_neither_early_nor_late() {
        let interval = 7;
        let mut queue = TimerQueue::<1>::new();
        let mut rng = Lcg(42);
        let mut deadline = 3;
        queue.arm(deadline, 9).unwrap();
        let mut now = 0;
        for _ in 0..500 {
            now += rng.below(20);
            if let Some((_, owner)) = queue.pop_expired(now) {
                assert_eq!(owner, 9);
                deadline = rearm_periodic(deadline, interval, now).unwrap();
                assert!(deadline > now);
                assert!(deadline - now <= interval);
                assert_eq!((deadline - 3) % interval, 0);
                queue.arm(deadline, 9).unwrap();
            }
            assert_eq!(queue.next_deadline(), Some(deadline));
        }
    }

    /// One armed timer as the naive model sees it. The array is kept sorted by
    /// deadline, and insertion after equal deadlines models FIFO ordering.
    #[derive(Clone, Copy)]
    struct Entry {
        deadline: u64,
        owner: u64,
        id: TimerId,
    }

    const BLANK: Entry = Entry {
        deadline: 0,
        owner: 0,
        id: TimerId {
            slot: 0,
            generation: 0,
        },
    };

    /// Drive a queue and a sorted-array model through the same random mix of
    /// arms, cancels, pops and clock advances, comparing every observable.
    fn randomized_against_sorted_model<const N: usize>(seed: u64, ops: usize) {
        const MODEL_CAP: usize = 64;
        assert!(N <= MODEL_CAP);
        let mut rng = Lcg(seed);
        let mut queue = TimerQueue::<N>::new();
        let mut model = [BLANK; MODEL_CAP];
        let mut model_len = 0usize;
        let mut now = 0u64;
        let mut history = [BLANK.id; 32];
        let mut history_len = 0usize;

        for step in 0..ops {
            match rng.below(100) {
                0..=39 => {
                    let deadline = if rng.below(10) == 0 {
                        now.saturating_sub(rng.below(5))
                    } else {
                        now + rng.below(40)
                    };
                    let owner = rng.step();
                    let got = queue.arm(deadline, owner);
                    if model_len < N {
                        let id = got.unwrap_or_else(|error| panic!("step {step}: {error:?}"));
                        assert!(
                            !model[..model_len].iter().any(|entry| entry.id == id),
                            "step {step}: live id issued twice"
                        );
                        let at = model[..model_len].partition_point(|e| e.deadline <= deadline);
                        model.copy_within(at..model_len, at + 1);
                        model[at] = Entry {
                            deadline,
                            owner,
                            id,
                        };
                        model_len += 1;
                        history[history_len % history.len()] = id;
                        history_len += 1;
                    } else {
                        assert_eq!(got, Err(Error::TableFull), "step {step}");
                    }
                }
                40..=59 => {
                    let expected = if model_len > 0 && model[0].deadline <= now {
                        let front = model[0];
                        model.copy_within(1..model_len, 0);
                        model_len -= 1;
                        Some((front.id, front.owner))
                    } else {
                        None
                    };
                    assert_eq!(queue.pop_expired(now), expected, "step {step}");
                }
                60..=74 => {
                    if history_len == 0 {
                        continue;
                    }
                    let id = history[rng.below(history_len.min(history.len()) as u64) as usize];
                    let expected = match model[..model_len].iter().position(|e| e.id == id) {
                        Some(at) => {
                            model.copy_within(at + 1..model_len, at);
                            model_len -= 1;
                            Ok(())
                        }
                        None => Err(Error::InvalidHandle),
                    };
                    assert_eq!(queue.cancel(id), expected, "step {step}");
                }
                75..=84 => now += rng.below(15),
                _ => {}
            }
            assert_eq!(queue.len(), model_len, "step {step}");
            assert_eq!(queue.is_empty(), model_len == 0, "step {step}");
            let expected_next = (model_len > 0).then(|| model[0].deadline);
            assert_eq!(queue.next_deadline(), expected_next, "step {step}");
        }
    }

    #[test]
    fn randomized_operations_match_a_sorted_array_model() {
        randomized_against_sorted_model::<1>(1, 5_000);
        randomized_against_sorted_model::<3>(2, 5_000);
        randomized_against_sorted_model::<8>(3, 5_000);
        randomized_against_sorted_model::<32>(4, 5_000);
    }
}
