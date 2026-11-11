//! Linux-style futex wait-queue model without scheduler integration.
//!
//! A futex is named by an (address space, user address) pair, so the same
//! address in two address spaces names two unrelated futexes. Waiters live in a
//! fixed table and are served in first-in, first-out order: [`FutexTable::wake`]
//! releases the longest-waiting threads first, and [`FutexTable::requeue`]
//! appends moved waiters behind those already queued on the target address.
//!
//! The model never blocks or switches threads. [`FutexTable::wait`] records that
//! a thread must sleep. The scheduler that will eventually drive this table
//! suspends the thread, resumes each thread reported by a wake, and calls
//! [`FutexTable::cancel`] when a timeout or signal interrupts a wait. The caller
//! also reads the user word itself and passes the observed value to `wait`.

use crate::{Error, Result};

/// Size in bytes of a futex word. Futex addresses must be aligned to it.
pub const FUTEX_WORD_SIZE: u64 = 4;

/// Outcome of [`FutexTable::wait`] when the request was well formed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FutexWait {
    /// The thread is queued and must now sleep until a wake or cancellation.
    Queued,
    /// The observed word differed from the expected value (`EAGAIN`). Nothing
    /// was queued, and the thread should re-examine the word in user space.
    ValueMismatch,
}

/// Summary of a [`FutexTable::requeue`] call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Requeue {
    /// Number of waiters released through the wake callback.
    pub woken: usize,
    /// Number of waiters moved from the source address to the target address.
    pub requeued: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Waiter {
    space: u64,
    addr: u64,
    thread: u64,
    seq: u64,
}

/// A fixed table of up to `N` futex waiters.
///
/// Each thread may wait on at most one futex at a time. Sequence numbers are
/// drawn from a monotonic counter, so the smallest sequence number among the
/// waiters of one futex is always the one that has waited longest.
#[derive(Clone, Copy, Debug)]
pub struct FutexTable<const N: usize> {
    slots: [Option<Waiter>; N],
    next_seq: u64,
}

impl<const N: usize> Default for FutexTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> FutexTable<N> {
    /// Construct a table with no waiters.
    pub const fn new() -> Self {
        Self {
            slots: [None; N],
            next_seq: 0,
        }
    }

    /// Return how many threads are waiting on the futex at `addr` in `space`.
    pub fn waiters(&self, space: u64, addr: u64) -> usize {
        self.slots
            .iter()
            .flatten()
            .filter(|waiter| waiter.space == space && waiter.addr == addr)
            .count()
    }

    /// Queue `thread` on the futex at `addr` in `space` if the word still holds
    /// `expected`, given that the caller observed `observed`.
    ///
    /// Checks run in this order:
    ///
    /// 1. A null or misaligned address fails with `BadAddress`.
    /// 2. A thread that is already waiting fails with `AlreadyExists`.
    /// 3. If `observed != expected`, the result is `Ok(ValueMismatch)` and
    ///    nothing changes, even when the table is full.
    /// 4. A full table fails with `TableFull`.
    pub fn wait(
        &mut self,
        space: u64,
        addr: u64,
        thread: u64,
        expected: u32,
        observed: u32,
    ) -> Result<FutexWait> {
        check_address(addr)?;
        if self.is_waiting(thread) {
            return Err(Error::AlreadyExists);
        }
        if observed != expected {
            return Ok(FutexWait::ValueMismatch);
        }
        let index = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(Error::TableFull)?;
        let seq = self.reserve_seqs(1)?;
        self.slots[index] = Some(Waiter {
            space,
            addr,
            thread,
            seq,
        });
        Ok(FutexWait::Queued)
    }

    /// Release up to `n` waiters on the futex at `addr` in `space`, oldest first.
    ///
    /// `on_wake` receives each released thread identifier in FIFO order before
    /// this method returns. The callback cannot reach the table, because the
    /// table is mutably borrowed for the duration of the call. Returns the number
    /// of threads released, which is less than `n` when fewer waiters exist. A
    /// null or misaligned address fails with `BadAddress`.
    pub fn wake<F: FnMut(u64)>(
        &mut self,
        space: u64,
        addr: u64,
        n: usize,
        mut on_wake: F,
    ) -> Result<usize> {
        check_address(addr)?;
        let mut woken = 0;
        while woken < n {
            let Some(waiter) = self.take_oldest(space, addr) else {
                break;
            };
            on_wake(waiter.thread);
            woken += 1;
        }
        Ok(woken)
    }

    /// Wake up to `wake_n` waiters on `from`, then move up to `requeue_n` of the
    /// remaining waiters on `from` to `to`, all in `space`.
    ///
    /// Moved waiters keep their relative order and are placed behind any
    /// waiters already queued on `to`. Woken threads are reported through
    /// `on_wake` exactly as in [`FutexTable::wake`]. Requeue does not compare
    /// the futex word, so a caller that needs that check must perform it first.
    ///
    /// Fails with `BadAddress` for a null or misaligned address, with
    /// `InvalidInput` when `from == to`, and with `OutOfRange` if the sequence
    /// counter cannot cover the moved waiters. Each of these failures leaves the
    /// table and the callback untouched.
    pub fn requeue<F: FnMut(u64)>(
        &mut self,
        space: u64,
        from: u64,
        to: u64,
        wake_n: usize,
        requeue_n: usize,
        on_wake: F,
    ) -> Result<Requeue> {
        check_address(from)?;
        check_address(to)?;
        if from == to {
            return Err(Error::InvalidInput);
        }
        let available = self.waiters(space, from);
        let woken = wake_n.min(available);
        let moved = requeue_n.min(available - woken);
        let first = self.reserve_seqs(moved as u64)?;

        let woken = self.wake(space, from, woken, on_wake)?;
        for offset in 0..moved {
            let index = self.oldest_index(space, from).ok_or(Error::InvalidState)?;
            if let Some(waiter) = self.slots[index].as_mut() {
                waiter.addr = to;
                waiter.seq = first + offset as u64;
            }
        }
        Ok(Requeue {
            woken,
            requeued: moved,
        })
    }

    /// Remove `thread` from whichever futex it waits on.
    ///
    /// This serves timeouts and signals. Fails with `NotFound` when the thread
    /// is not waiting, which also covers a thread that a wake has already
    /// released, so the caller can tell that the wake won the race.
    pub fn cancel(&mut self, thread: u64) -> Result<()> {
        let index = self
            .slots
            .iter()
            .position(|slot| slot.is_some_and(|waiter| waiter.thread == thread))
            .ok_or(Error::NotFound)?;
        self.slots[index] = None;
        Ok(())
    }

    fn is_waiting(&self, thread: u64) -> bool {
        self.slots
            .iter()
            .flatten()
            .any(|waiter| waiter.thread == thread)
    }

    fn oldest_index(&self, space: u64, addr: u64) -> Option<usize> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| {
                slot.filter(|waiter| waiter.space == space && waiter.addr == addr)
                    .map(|waiter| (waiter.seq, index))
            })
            .min()
            .map(|(_, index)| index)
    }

    fn take_oldest(&mut self, space: u64, addr: u64) -> Option<Waiter> {
        let index = self.oldest_index(space, addr)?;
        self.slots[index].take()
    }

    /// Reserve `count` consecutive sequence numbers and return the first.
    fn reserve_seqs(&mut self, count: u64) -> Result<u64> {
        let first = self.next_seq;
        self.next_seq = first.checked_add(count).ok_or(Error::OutOfRange)?;
        Ok(first)
    }
}

fn check_address(addr: u64) -> Result<()> {
    if addr == 0 || !addr.is_multiple_of(FUTEX_WORD_SIZE) {
        Err(Error::BadAddress)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPACE: u64 = 1;
    const OTHER_SPACE: u64 = 2;
    const ADDR: u64 = 0x1000;
    const OTHER_ADDR: u64 = 0x2000;

    /// Collect the threads a wake releases, in callback order.
    fn wake_list<const N: usize>(
        table: &mut FutexTable<N>,
        space: u64,
        addr: u64,
        n: usize,
    ) -> ([u64; 8], usize) {
        let mut out = [0; 8];
        let mut len = 0;
        let count = table
            .wake(space, addr, n, |thread| {
                out[len] = thread;
                len += 1;
            })
            .unwrap();
        assert_eq!(count, len);
        (out, len)
    }

    fn queue<const N: usize>(table: &mut FutexTable<N>, space: u64, addr: u64, threads: &[u64]) {
        for &thread in threads {
            assert_eq!(table.wait(space, addr, thread, 7, 7), Ok(FutexWait::Queued));
        }
    }

    #[test]
    fn matching_value_queues_the_thread() {
        let mut table = FutexTable::<4>::new();
        assert_eq!(table.wait(SPACE, ADDR, 1, 7, 7), Ok(FutexWait::Queued));
        assert_eq!(table.waiters(SPACE, ADDR), 1);
    }

    #[test]
    fn value_mismatch_queues_nothing_and_leaves_the_thread_free() {
        let mut table = FutexTable::<4>::new();
        assert_eq!(
            table.wait(SPACE, ADDR, 1, 7, 8),
            Ok(FutexWait::ValueMismatch)
        );
        assert_eq!(table.waiters(SPACE, ADDR), 0);
        assert_eq!(table.wait(SPACE, ADDR, 1, 7, 7), Ok(FutexWait::Queued));
    }

    #[test]
    fn mismatch_wins_over_a_full_table() {
        let mut table = FutexTable::<1>::new();
        queue(&mut table, SPACE, ADDR, &[1]);
        assert_eq!(
            table.wait(SPACE, ADDR, 2, 7, 0),
            Ok(FutexWait::ValueMismatch)
        );
        assert_eq!(table.wait(SPACE, ADDR, 2, 7, 7), Err(Error::TableFull));
    }

    #[test]
    fn null_and_misaligned_addresses_are_rejected() {
        let mut table = FutexTable::<4>::new();
        for addr in [0, 1, 2, 3, 6, 0x1001] {
            assert_eq!(table.wait(SPACE, addr, 1, 7, 7), Err(Error::BadAddress));
            assert_eq!(table.wake(SPACE, addr, 1, |_| {}), Err(Error::BadAddress));
        }
        assert_eq!(table.wait(SPACE, 4, 1, 7, 7), Ok(FutexWait::Queued));
        assert_eq!(table.waiters(SPACE, 4), 1);
    }

    #[test]
    fn a_thread_cannot_wait_twice() {
        let mut table = FutexTable::<4>::new();
        queue(&mut table, SPACE, ADDR, &[1]);
        assert_eq!(
            table.wait(SPACE, OTHER_ADDR, 1, 7, 7),
            Err(Error::AlreadyExists)
        );
        assert_eq!(table.waiters(SPACE, OTHER_ADDR), 0);
        assert_eq!(table.waiters(SPACE, ADDR), 1);
    }

    #[test]
    fn full_table_returns_table_full_without_changes() {
        let mut table = FutexTable::<2>::new();
        queue(&mut table, SPACE, ADDR, &[1, 2]);
        assert_eq!(table.wait(SPACE, ADDR, 3, 7, 7), Err(Error::TableFull));
        assert_eq!(table.waiters(SPACE, ADDR), 2);
    }

    #[test]
    fn wake_releases_waiters_in_fifo_order() {
        let mut table = FutexTable::<8>::new();
        queue(&mut table, SPACE, ADDR, &[10, 20, 30]);

        let (woken, len) = wake_list(&mut table, SPACE, ADDR, 2);
        assert_eq!(&woken[..len], &[10, 20]);

        let (woken, len) = wake_list(&mut table, SPACE, ADDR, 5);
        assert_eq!(&woken[..len], &[30]);
        assert_eq!(table.waiters(SPACE, ADDR), 0);
    }

    #[test]
    fn fifo_order_survives_interleaved_waits_and_cancels() {
        let mut table = FutexTable::<8>::new();
        queue(&mut table, SPACE, ADDR, &[1, 2]);
        queue(&mut table, SPACE, OTHER_ADDR, &[9]);
        queue(&mut table, SPACE, ADDR, &[3]);
        assert_eq!(table.cancel(1), Ok(()));
        queue(&mut table, SPACE, ADDR, &[4]);

        let (woken, len) = wake_list(&mut table, SPACE, ADDR, 8);
        assert_eq!(&woken[..len], &[2, 3, 4]);
    }

    #[test]
    fn zero_or_empty_wakes_release_nothing() {
        let mut table = FutexTable::<4>::new();
        assert_eq!(wake_list(&mut table, SPACE, ADDR, 3).1, 0);
        queue(&mut table, SPACE, ADDR, &[1]);
        assert_eq!(wake_list(&mut table, SPACE, ADDR, 0).1, 0);
        assert_eq!(table.waiters(SPACE, ADDR), 1);
    }

    #[test]
    fn same_address_in_different_spaces_is_isolated() {
        let mut table = FutexTable::<4>::new();
        queue(&mut table, SPACE, ADDR, &[1]);
        queue(&mut table, OTHER_SPACE, ADDR, &[2]);

        assert_eq!(table.waiters(SPACE, ADDR), 1);
        assert_eq!(table.waiters(OTHER_SPACE, ADDR), 1);

        let (woken, len) = wake_list(&mut table, OTHER_SPACE, ADDR, 8);
        assert_eq!(&woken[..len], &[2]);
        assert_eq!(table.waiters(SPACE, ADDR), 1);
    }

    #[test]
    fn requeue_moves_waiters_behind_existing_target_waiters() {
        let mut table = FutexTable::<8>::new();
        queue(&mut table, SPACE, OTHER_ADDR, &[99]);
        queue(&mut table, SPACE, ADDR, &[1, 2, 3, 4]);

        let mut woken = [0; 4];
        let mut len = 0;
        let result = table
            .requeue(SPACE, ADDR, OTHER_ADDR, 1, 2, |thread| {
                woken[len] = thread;
                len += 1;
            })
            .unwrap();
        assert_eq!(
            result,
            Requeue {
                woken: 1,
                requeued: 2
            }
        );
        assert_eq!(&woken[..len], &[1]);
        assert_eq!(table.waiters(SPACE, ADDR), 1);
        assert_eq!(table.waiters(SPACE, OTHER_ADDR), 3);

        let (order, len) = wake_list(&mut table, SPACE, OTHER_ADDR, 8);
        assert_eq!(&order[..len], &[99, 2, 3]);
        let (order, len) = wake_list(&mut table, SPACE, ADDR, 8);
        assert_eq!(&order[..len], &[4]);
    }

    #[test]
    fn requeue_counts_are_capped_by_available_waiters() {
        let mut table = FutexTable::<4>::new();
        queue(&mut table, SPACE, ADDR, &[1, 2]);

        let result = table
            .requeue(SPACE, ADDR, OTHER_ADDR, 5, 5, |_| {})
            .unwrap();
        assert_eq!(
            result,
            Requeue {
                woken: 2,
                requeued: 0
            }
        );
        assert_eq!(table.waiters(SPACE, ADDR), 0);

        let mut table = FutexTable::<4>::new();
        queue(&mut table, SPACE, ADDR, &[1, 2]);
        let result = table
            .requeue(SPACE, ADDR, OTHER_ADDR, 0, 5, |_| {})
            .unwrap();
        assert_eq!(
            result,
            Requeue {
                woken: 0,
                requeued: 2
            }
        );
        assert_eq!(table.waiters(SPACE, OTHER_ADDR), 2);
    }

    #[test]
    fn requeue_stays_within_its_address_space() {
        let mut table = FutexTable::<4>::new();
        queue(&mut table, SPACE, ADDR, &[1]);
        queue(&mut table, OTHER_SPACE, ADDR, &[2]);

        let result = table
            .requeue(SPACE, ADDR, OTHER_ADDR, 0, 8, |_| {})
            .unwrap();
        assert_eq!(
            result,
            Requeue {
                woken: 0,
                requeued: 1
            }
        );
        assert_eq!(table.waiters(OTHER_SPACE, ADDR), 1);
        assert_eq!(table.waiters(OTHER_SPACE, OTHER_ADDR), 0);
    }

    #[test]
    fn invalid_requeue_arguments_change_nothing() {
        let mut table = FutexTable::<4>::new();
        queue(&mut table, SPACE, ADDR, &[1, 2]);

        assert_eq!(
            table.requeue(SPACE, ADDR, ADDR, 1, 1, |_| {}),
            Err(Error::InvalidInput)
        );
        assert_eq!(
            table.requeue(SPACE, ADDR, 0, 1, 1, |_| {}),
            Err(Error::BadAddress)
        );
        assert_eq!(
            table.requeue(SPACE, 3, OTHER_ADDR, 1, 1, |_| {}),
            Err(Error::BadAddress)
        );
        assert_eq!(table.waiters(SPACE, ADDR), 2);
        assert_eq!(table.waiters(SPACE, OTHER_ADDR), 0);
    }

    #[test]
    fn cancel_removes_only_the_named_thread() {
        let mut table = FutexTable::<4>::new();
        queue(&mut table, SPACE, ADDR, &[1, 2, 3]);

        assert_eq!(table.cancel(2), Ok(()));
        assert_eq!(table.cancel(2), Err(Error::NotFound));

        let (woken, len) = wake_list(&mut table, SPACE, ADDR, 8);
        assert_eq!(&woken[..len], &[1, 3]);
    }

    #[test]
    fn cancelled_slot_is_reusable() {
        let mut table = FutexTable::<1>::new();
        queue(&mut table, SPACE, ADDR, &[1]);
        assert_eq!(table.wait(SPACE, ADDR, 2, 7, 7), Err(Error::TableFull));
        assert_eq!(table.cancel(1), Ok(()));
        assert_eq!(table.wait(SPACE, ADDR, 2, 7, 7), Ok(FutexWait::Queued));
    }

    #[test]
    fn cancel_after_wake_reports_not_found() {
        let mut table = FutexTable::<2>::new();
        queue(&mut table, SPACE, ADDR, &[1]);
        let (_, len) = wake_list(&mut table, SPACE, ADDR, 1);
        assert_eq!(len, 1);
        assert_eq!(table.cancel(1), Err(Error::NotFound));
    }

    #[test]
    fn sequence_exhaustion_is_rejected_without_changes() {
        let mut table = FutexTable::<2> {
            slots: [None; 2],
            next_seq: u64::MAX,
        };
        assert_eq!(table.wait(SPACE, ADDR, 1, 7, 7), Err(Error::OutOfRange));
        assert_eq!(table.waiters(SPACE, ADDR), 0);
        assert_eq!(table.next_seq, u64::MAX);
    }
}
