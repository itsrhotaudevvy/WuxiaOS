//! Fixed-capacity priority scheduling policy with starvation avoidance.
//!
//! Priorities run from 0 to 31, and a higher value runs first, as in the NT
//! dispatcher. Values 16 to 31 are realtime: those threads always run at their
//! base priority. Values 0 to 15 are dynamic. A dynamic thread that waits for
//! [`STARVATION_THRESHOLD`] ticks gains one level, up to
//! [`MAX_DYNAMIC_PRIORITY`], and each time it is picked it decays one level back
//! toward its base. Threads at the same current priority share the processor
//! round-robin.
//!
//! The policy only decides which thread runs; it does not switch contexts. The
//! caller must run the thread that [`PriorityScheduler::pick_next`] returns.

use crate::{Error, Result};

/// Number of priority levels; valid priorities are `0..PRIORITY_LEVELS`.
pub const PRIORITY_LEVELS: u8 = 32;
/// Lowest realtime priority. Realtime threads are never boosted or decayed.
pub const REALTIME_BASE: u8 = 16;
/// Highest current priority a dynamic thread can reach through boosting.
pub const MAX_DYNAMIC_PRIORITY: u8 = 15;
/// Ticks a runnable thread must wait before its current priority is boosted.
pub const STARVATION_THRESHOLD: u32 = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Slot {
    present: bool,
    runnable: bool,
    base_priority: u8,
    current_priority: u8,
    ticks_waiting: u32,
}

impl Slot {
    const EMPTY: Self = Self {
        present: false,
        runnable: false,
        base_priority: 0,
        current_priority: 0,
        ticks_waiting: 0,
    };
}

/// A fixed table of up to `N` threads, addressed by slot index.
///
/// New threads start blocked; call [`PriorityScheduler::set_runnable`] to make
/// them eligible. Out-of-range slots are rejected by the mutating methods and
/// reported as absent by the accessors.
#[derive(Clone, Copy, Debug)]
pub struct PriorityScheduler<const N: usize> {
    slots: [Slot; N],
    /// The thread most recently returned by `pick_next`, while it is runnable.
    running: Option<usize>,
}

impl<const N: usize> Default for PriorityScheduler<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> PriorityScheduler<N> {
    /// Construct a scheduler with no threads.
    pub const fn new() -> Self {
        Self {
            slots: [Slot::EMPTY; N],
            running: None,
        }
    }

    /// Register a blocked thread in `slot` with the given base priority.
    ///
    /// Rejects slots outside `0..N` and priorities of 32 or more, and refuses
    /// to replace a thread that is already present.
    pub fn add(&mut self, slot: usize, base_priority: u8) -> Result<()> {
        if base_priority >= PRIORITY_LEVELS {
            return Err(Error::InvalidInput);
        }
        let entry = self.slots.get_mut(slot).ok_or(Error::InvalidInput)?;
        if entry.present {
            return Err(Error::AlreadyExists);
        }
        *entry = Slot {
            present: true,
            runnable: false,
            base_priority,
            current_priority: base_priority,
            ticks_waiting: 0,
        };
        Ok(())
    }

    /// Remove the thread in `slot`, forgetting its priorities and wait count.
    pub fn remove(&mut self, slot: usize) -> Result<()> {
        let entry = self.slots.get_mut(slot).ok_or(Error::InvalidInput)?;
        if !entry.present {
            return Err(Error::NotFound);
        }
        *entry = Slot::EMPTY;
        if self.running == Some(slot) {
            self.running = None;
        }
        Ok(())
    }

    /// Make the thread in `slot` eligible or ineligible to run.
    ///
    /// A change of state resets the thread's wait count. A thread that stops
    /// being runnable is no longer considered running.
    pub fn set_runnable(&mut self, slot: usize, runnable: bool) -> Result<()> {
        let entry = self.slots.get_mut(slot).ok_or(Error::InvalidInput)?;
        if !entry.present {
            return Err(Error::NotFound);
        }
        if entry.runnable != runnable {
            entry.runnable = runnable;
            entry.ticks_waiting = 0;
        }
        if !runnable && self.running == Some(slot) {
            self.running = None;
        }
        Ok(())
    }

    /// Choose the thread to run next, or `None` when nothing is runnable.
    ///
    /// The candidates are the runnable threads holding the highest current
    /// priority. The first candidate after `current` in slot order wins,
    /// wrapping around, so `current` itself is chosen only when no other
    /// candidate exists. An out-of-range `current` counts as no current thread.
    ///
    /// The chosen thread's wait count resets and its current priority decays
    /// by one level toward its base. The chosen thread is then treated as
    /// running by [`PriorityScheduler::tick`].
    pub fn pick_next(&mut self, current: Option<usize>) -> Option<usize> {
        let picked = self.select(current);
        self.running = picked;
        if let Some(slot) = picked.and_then(|index| self.slots.get_mut(index)) {
            slot.ticks_waiting = 0;
            if slot.current_priority > slot.base_priority {
                slot.current_priority -= 1;
            }
        }
        picked
    }

    /// Advance the clock by one tick, aging the threads that are waiting.
    ///
    /// Every runnable thread except the running one increments its wait count.
    /// When the count reaches [`STARVATION_THRESHOLD`], the count resets and a
    /// dynamic thread below [`MAX_DYNAMIC_PRIORITY`] gains one level. Realtime
    /// threads are never boosted.
    pub fn tick(&mut self) {
        let running = self.running;
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if !slot.present || !slot.runnable || running == Some(index) {
                continue;
            }
            slot.ticks_waiting = slot.ticks_waiting.saturating_add(1);
            if slot.ticks_waiting >= STARVATION_THRESHOLD {
                slot.ticks_waiting = 0;
                if slot.base_priority < REALTIME_BASE
                    && slot.current_priority < MAX_DYNAMIC_PRIORITY
                {
                    slot.current_priority += 1;
                }
            }
        }
    }

    /// Base priority of the thread in `slot`, if one is present.
    pub fn base_priority(&self, slot: usize) -> Option<u8> {
        self.present(slot).map(|entry| entry.base_priority)
    }

    /// Current (possibly boosted) priority of the thread in `slot`, if present.
    pub fn current_priority(&self, slot: usize) -> Option<u8> {
        self.present(slot).map(|entry| entry.current_priority)
    }

    /// Ticks the thread in `slot` has waited since its last boost or pick.
    pub fn ticks_waiting(&self, slot: usize) -> Option<u32> {
        self.present(slot).map(|entry| entry.ticks_waiting)
    }

    /// Whether the thread in `slot` is runnable, if one is present.
    pub fn is_runnable(&self, slot: usize) -> Option<bool> {
        self.present(slot).map(|entry| entry.runnable)
    }

    fn present(&self, slot: usize) -> Option<&Slot> {
        self.slots.get(slot).filter(|entry| entry.present)
    }

    fn select(&self, current: Option<usize>) -> Option<usize> {
        let best = self
            .slots
            .iter()
            .filter(|entry| entry.present && entry.runnable)
            .map(|entry| entry.current_priority)
            .max()?;
        let start = match current {
            Some(index) if index < N => (index + 1) % N,
            _ => 0,
        };
        (0..N).map(|offset| (start + offset) % N).find(|&index| {
            self.slots
                .get(index)
                .is_some_and(|entry| entry.runnable && entry.current_priority == best)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready<const N: usize>(threads: &[(usize, u8)]) -> PriorityScheduler<N> {
        let mut scheduler = PriorityScheduler::new();
        for &(slot, priority) in threads {
            scheduler.add(slot, priority).unwrap();
            scheduler.set_runnable(slot, true).unwrap();
        }
        scheduler
    }

    #[test]
    fn rejects_invalid_slots_and_priorities() {
        let mut scheduler = PriorityScheduler::<2>::new();
        assert_eq!(scheduler.add(2, 5), Err(Error::InvalidInput));
        assert_eq!(scheduler.add(0, PRIORITY_LEVELS), Err(Error::InvalidInput));
        assert_eq!(scheduler.add(0, u8::MAX), Err(Error::InvalidInput));
        assert_eq!(scheduler.add(0, 5), Ok(()));
        assert_eq!(scheduler.add(0, 6), Err(Error::AlreadyExists));
        assert_eq!(scheduler.remove(1), Err(Error::NotFound));
        assert_eq!(scheduler.remove(9), Err(Error::InvalidInput));
        assert_eq!(scheduler.set_runnable(1, true), Err(Error::NotFound));
        assert_eq!(scheduler.set_runnable(9, true), Err(Error::InvalidInput));
        assert_eq!(scheduler.base_priority(9), None);
        assert_eq!(scheduler.current_priority(1), None);
        assert_eq!(scheduler.ticks_waiting(9), None);
        assert_eq!(scheduler.is_runnable(1), None);
    }

    #[test]
    fn zero_capacity_scheduler_is_always_idle() {
        let mut scheduler = PriorityScheduler::<0>::new();
        assert_eq!(scheduler.add(0, 1), Err(Error::InvalidInput));
        assert_eq!(scheduler.pick_next(None), None);
        assert_eq!(scheduler.pick_next(Some(3)), None);
        scheduler.tick();
    }

    #[test]
    fn highest_priority_runs_first() {
        let mut scheduler = ready::<3>(&[(0, 4), (1, 9), (2, 7)]);
        assert_eq!(scheduler.pick_next(None), Some(1));
        scheduler.set_runnable(1, false).unwrap();
        assert_eq!(scheduler.pick_next(Some(1)), Some(2));
        scheduler.set_runnable(2, false).unwrap();
        assert_eq!(scheduler.pick_next(Some(2)), Some(0));
    }

    #[test]
    fn equal_priorities_share_the_processor_round_robin() {
        let mut scheduler = ready::<4>(&[(0, 8), (1, 8), (2, 8), (3, 2)]);
        let mut current = None;
        let mut order = [0usize; 6];
        for slot in &mut order {
            current = scheduler.pick_next(current);
            *slot = current.unwrap();
        }
        assert_eq!(order, [0, 1, 2, 0, 1, 2]);
    }

    #[test]
    fn current_thread_is_the_last_equal_choice() {
        let mut scheduler = ready::<2>(&[(0, 5), (1, 5)]);
        assert_eq!(scheduler.pick_next(Some(0)), Some(1));
        assert_eq!(scheduler.pick_next(Some(1)), Some(0));
        assert_eq!(scheduler.pick_next(Some(7)), Some(0));
    }

    #[test]
    fn current_thread_keeps_the_processor_when_alone_at_the_top() {
        let mut scheduler = ready::<3>(&[(0, 3), (2, 12)]);
        assert_eq!(scheduler.pick_next(Some(2)), Some(2));
        assert_eq!(scheduler.pick_next(Some(2)), Some(2));
        assert_eq!(scheduler.pick_next(Some(0)), Some(2));
    }

    #[test]
    fn idle_scheduler_picks_nothing() {
        let mut scheduler = PriorityScheduler::<3>::new();
        scheduler.add(0, 3).unwrap();
        scheduler.add(1, 20).unwrap();
        assert_eq!(scheduler.pick_next(None), None);
        assert_eq!(scheduler.pick_next(Some(0)), None);
        scheduler.tick();

        scheduler.set_runnable(1, true).unwrap();
        assert_eq!(scheduler.pick_next(Some(0)), Some(1));
        scheduler.set_runnable(1, false).unwrap();
        assert_eq!(scheduler.pick_next(Some(1)), None);
    }

    #[test]
    fn starvation_boost_eventually_runs_a_low_thread() {
        let mut scheduler = ready::<2>(&[(0, 10), (1, 2)]);
        let mut current = None;
        let mut low_ran = false;
        for _ in 0..400 {
            current = scheduler.pick_next(current);
            if current == Some(1) {
                low_ran = true;
                break;
            }
            assert_eq!(current, Some(0));
            scheduler.tick();
        }
        assert!(low_ran, "low-priority thread starved");
        assert!(scheduler.current_priority(1).unwrap() <= MAX_DYNAMIC_PRIORITY);
    }

    #[test]
    fn boost_happens_exactly_at_the_threshold() {
        let mut scheduler = ready::<2>(&[(0, 12), (1, 3)]);
        assert_eq!(scheduler.pick_next(None), Some(0));

        for _ in 0..STARVATION_THRESHOLD - 1 {
            scheduler.tick();
        }
        assert_eq!(scheduler.current_priority(1), Some(3));
        assert_eq!(scheduler.ticks_waiting(1), Some(STARVATION_THRESHOLD - 1));

        scheduler.tick();
        assert_eq!(scheduler.current_priority(1), Some(4));
        assert_eq!(scheduler.ticks_waiting(1), Some(0));
        assert_eq!(scheduler.ticks_waiting(0), Some(0));
    }

    #[test]
    fn boost_is_capped_for_dynamic_threads() {
        let mut scheduler = ready::<3>(&[(0, 31), (1, 14), (2, 15)]);
        let mut current = None;
        for _ in 0..1000 {
            current = scheduler.pick_next(current);
            assert_eq!(current, Some(0));
            assert!(scheduler.current_priority(1).unwrap() <= MAX_DYNAMIC_PRIORITY);
            scheduler.tick();
        }
        assert_eq!(scheduler.current_priority(1), Some(MAX_DYNAMIC_PRIORITY));
        assert_eq!(scheduler.current_priority(2), Some(MAX_DYNAMIC_PRIORITY));
    }

    #[test]
    fn realtime_threads_are_never_boosted_or_decayed() {
        let mut scheduler = ready::<3>(&[(0, 20), (1, 25)]);
        let mut current = None;
        for _ in 0..200 {
            current = scheduler.pick_next(current);
            assert_eq!(current, Some(1));
            assert_eq!(scheduler.current_priority(0), Some(20));
            scheduler.tick();
        }
        assert_eq!(scheduler.current_priority(1), Some(25));

        scheduler.set_runnable(1, false).unwrap();
        for _ in 0..3 {
            assert_eq!(scheduler.pick_next(current), Some(0));
            assert_eq!(scheduler.current_priority(0), Some(20));
            current = Some(0);
        }
    }

    #[test]
    fn picked_thread_decays_back_toward_base() {
        let mut scheduler = ready::<2>(&[(0, 12), (1, 2)]);
        let mut current = scheduler.pick_next(None);
        for _ in 0..4 * STARVATION_THRESHOLD {
            scheduler.tick();
        }
        assert_eq!(scheduler.current_priority(1), Some(6));

        scheduler.set_runnable(0, false).unwrap();
        let mut levels = [0u8; 5];
        for level in &mut levels {
            current = scheduler.pick_next(current);
            assert_eq!(current, Some(1));
            assert_eq!(scheduler.ticks_waiting(1), Some(0));
            *level = scheduler.current_priority(1).unwrap();
        }
        assert_eq!(levels, [5, 4, 3, 2, 2]);
    }

    #[test]
    fn blocked_threads_are_not_boosted() {
        let mut scheduler = PriorityScheduler::<2>::new();
        scheduler.add(0, 2).unwrap();
        scheduler.add(1, 10).unwrap();
        scheduler.set_runnable(1, true).unwrap();
        assert_eq!(scheduler.pick_next(None), Some(1));
        for _ in 0..100 {
            scheduler.tick();
        }
        assert_eq!(scheduler.current_priority(0), Some(2));
        assert_eq!(scheduler.ticks_waiting(0), Some(0));
    }

    #[test]
    fn removed_threads_leave_the_table() {
        let mut scheduler = ready::<2>(&[(0, 9), (1, 4)]);
        assert_eq!(scheduler.pick_next(None), Some(0));
        scheduler.remove(0).unwrap();
        assert_eq!(scheduler.base_priority(0), None);
        assert_eq!(scheduler.pick_next(Some(0)), Some(1));
        assert_eq!(scheduler.add(0, 9), Ok(()));
        assert_eq!(scheduler.is_runnable(0), Some(false));
    }
}
