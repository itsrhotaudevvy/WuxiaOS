//! Pure state machines for NT dispatcher (waitable) objects.
//!
//! These types define what a wait means for an object without a scheduler.
//! Satisfying a wait returns whether the waiter may proceed and mutates the
//! object accordingly. Blocking, wakeup and timeouts belong to the scheduler
//! that will eventually drive these machines.

use crate::{Error, Result};

/// Identity of the thread performing a wait, release or abandonment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadId(u64);

impl ThreadId {
    /// Wrap a kernel-assigned thread identifier.
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Return the kernel-assigned thread identifier.
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Outcome of attempting to satisfy a wait.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Acquisition {
    /// The wait was satisfied and the object is now held or consumed.
    Acquired,
    /// The wait was satisfied, but the previous owner terminated while
    /// holding the object (NT `STATUS_ABANDONED`).
    AcquiredAbandoned,
    /// The wait cannot be satisfied now. No object state changed.
    WouldBlock,
}

/// Behavior shared by every object that a wait can target.
///
/// Implementations must satisfy this contract: `satisfy` mutates state only
/// when it returns `Acquired` or `AcquiredAbandoned`, and it succeeds whenever
/// `is_satisfiable` returned `Ok(true)` for the same thread.
pub trait Waitable {
    /// Report whether `satisfy` would succeed for `thread`, without mutating
    /// state. Errors surface here so that `wait_all` can detect them before
    /// changing anything.
    fn is_satisfiable(&self, thread: ThreadId) -> Result<bool>;

    /// Satisfy a wait for `thread`, mutating state only on success.
    fn satisfy(&mut self, thread: ThreadId) -> Result<Acquisition>;
}

/// Whether satisfying a wait consumes the signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventKind {
    /// Stays signaled until explicitly reset and releases every waiter.
    Notification,
    /// Resets itself when it satisfies a wait and releases one waiter.
    Synchronization,
}

/// An NT event: a signal that threads wait on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Event {
    kind: EventKind,
    signaled: bool,
}

impl Event {
    /// Create an event in the given signal state.
    pub const fn new(kind: EventKind, signaled: bool) -> Self {
        Self { kind, signaled }
    }

    /// Return the reset behavior of this event.
    pub const fn kind(self) -> EventKind {
        self.kind
    }

    /// Return whether a wait would currently be satisfied.
    pub const fn is_signaled(self) -> bool {
        self.signaled
    }

    /// Signal the event and return whether it was already signaled.
    pub fn set(&mut self) -> bool {
        let previous = self.signaled;
        self.signaled = true;
        previous
    }

    /// Clear the signal and return whether it was previously signaled.
    pub fn reset(&mut self) -> bool {
        let previous = self.signaled;
        self.signaled = false;
        previous
    }

    /// Signal and immediately clear the event, returning the previous state.
    ///
    /// With no waiters modeled here, a pulse always leaves the event
    /// unsignaled, for both kinds.
    pub fn pulse(&mut self) -> bool {
        let previous = self.signaled;
        self.signaled = false;
        previous
    }

    /// Satisfy a wait if signaled. A synchronization event resets itself.
    pub fn try_acquire(&mut self) -> bool {
        if !self.signaled {
            return false;
        }
        if self.kind == EventKind::Synchronization {
            self.signaled = false;
        }
        true
    }
}

impl Waitable for Event {
    fn is_satisfiable(&self, _thread: ThreadId) -> Result<bool> {
        Ok(self.signaled)
    }

    fn satisfy(&mut self, _thread: ThreadId) -> Result<Acquisition> {
        Ok(if self.try_acquire() {
            Acquisition::Acquired
        } else {
            Acquisition::WouldBlock
        })
    }
}

/// An NT counting semaphore with a fixed upper bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Semaphore {
    count: u32,
    limit: u32,
}

impl Semaphore {
    /// Create a semaphore with `initial` permits and a maximum of `limit`.
    ///
    /// A zero limit is rejected, as is an initial count above the limit.
    pub const fn new(initial: u32, limit: u32) -> Result<Self> {
        if limit == 0 || initial > limit {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            count: initial,
            limit,
        })
    }

    /// Return the number of currently available permits.
    pub const fn count(self) -> u32 {
        self.count
    }

    /// Return the maximum permit count.
    pub const fn limit(self) -> u32 {
        self.limit
    }

    /// Add `permits` and return the previous count.
    ///
    /// Zero permits are rejected, matching NT's `ReleaseSemaphore`. Exceeding
    /// the limit, or overflowing, fails with `OutOfRange` and leaves the count
    /// unchanged.
    pub fn release(&mut self, permits: u32) -> Result<u32> {
        if permits == 0 {
            return Err(Error::InvalidInput);
        }
        let next = self
            .count
            .checked_add(permits)
            .filter(|next| *next <= self.limit)
            .ok_or(Error::OutOfRange)?;
        let previous = self.count;
        self.count = next;
        Ok(previous)
    }

    /// Take one permit if available.
    pub fn try_acquire(&mut self) -> bool {
        if self.count == 0 {
            return false;
        }
        self.count -= 1;
        true
    }
}

impl Waitable for Semaphore {
    fn is_satisfiable(&self, _thread: ThreadId) -> Result<bool> {
        Ok(self.count > 0)
    }

    fn satisfy(&mut self, _thread: ThreadId) -> Result<Acquisition> {
        Ok(if self.try_acquire() {
            Acquisition::Acquired
        } else {
            Acquisition::WouldBlock
        })
    }
}

/// An NT mutant (mutex) with recursive ownership and abandonment.
///
/// A thread that terminates while owning the mutant abandons it. The next
/// thread to acquire it is told so, once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mutant {
    owner: Option<ThreadId>,
    recursion: u32,
    abandoned: bool,
}

impl Mutant {
    /// Create an unowned, non-abandoned mutant.
    pub const fn new() -> Self {
        Self {
            owner: None,
            recursion: 0,
            abandoned: false,
        }
    }

    /// Return the owning thread, if any.
    pub const fn owner(self) -> Option<ThreadId> {
        self.owner
    }

    /// Return how many times the owner has acquired without releasing.
    pub const fn recursion(self) -> u32 {
        self.recursion
    }

    /// Return whether the last owner abandoned the mutant and no acquire has
    /// reported it yet.
    pub const fn is_abandoned(self) -> bool {
        self.abandoned
    }

    /// Acquire for `thread` if the mutant is free or already owned by it.
    ///
    /// Owner re-acquisition increments the recursion count, failing with
    /// `OutOfRange` at the maximum. A mutant owned by another thread yields
    /// `WouldBlock` and is not changed.
    pub fn try_acquire(&mut self, thread: ThreadId) -> Result<Acquisition> {
        match self.owner {
            None => {
                self.owner = Some(thread);
                self.recursion = 1;
                if self.abandoned {
                    self.abandoned = false;
                    Ok(Acquisition::AcquiredAbandoned)
                } else {
                    Ok(Acquisition::Acquired)
                }
            }
            Some(owner) if owner == thread => {
                self.recursion = self.recursion.checked_add(1).ok_or(Error::OutOfRange)?;
                Ok(Acquisition::Acquired)
            }
            Some(_) => Ok(Acquisition::WouldBlock),
        }
    }

    /// Release one level of ownership held by `thread`.
    ///
    /// Fails with `InvalidState` if `thread` is not the owner. The mutant
    /// becomes free when the recursion count returns to zero.
    pub fn release(&mut self, thread: ThreadId) -> Result<()> {
        if self.owner != Some(thread) {
            return Err(Error::InvalidState);
        }
        self.recursion = self.recursion.checked_sub(1).ok_or(Error::InvalidState)?;
        if self.recursion == 0 {
            self.owner = None;
        }
        Ok(())
    }

    /// Mark the mutant abandoned and free it, as when `thread` terminates.
    ///
    /// Fails with `InvalidState` if `thread` is not the owner.
    pub fn abandon(&mut self, thread: ThreadId) -> Result<()> {
        if self.owner != Some(thread) {
            return Err(Error::InvalidState);
        }
        self.owner = None;
        self.recursion = 0;
        self.abandoned = true;
        Ok(())
    }
}

impl Default for Mutant {
    fn default() -> Self {
        Self::new()
    }
}

impl Waitable for Mutant {
    fn is_satisfiable(&self, thread: ThreadId) -> Result<bool> {
        match self.owner {
            None => Ok(true),
            Some(owner) if owner == thread => {
                if self.recursion == u32::MAX {
                    Err(Error::OutOfRange)
                } else {
                    Ok(true)
                }
            }
            Some(_) => Ok(false),
        }
    }

    fn satisfy(&mut self, thread: ThreadId) -> Result<Acquisition> {
        self.try_acquire(thread)
    }
}

/// Satisfy a wait on every object, or on none of them.
///
/// Every object is checked before any is changed. If one cannot be satisfied,
/// the result is `WouldBlock` and no object changes. If a check fails, the
/// error is returned and no object changes. Otherwise every object is
/// satisfied, and the result is `AcquiredAbandoned` if any mutant was
/// abandoned.
///
/// An empty slice is rejected with `InvalidInput`.
pub fn wait_all(objects: &mut [&mut dyn Waitable], thread: ThreadId) -> Result<Acquisition> {
    if objects.is_empty() {
        return Err(Error::InvalidInput);
    }
    for object in objects.iter() {
        if !object.is_satisfiable(thread)? {
            return Ok(Acquisition::WouldBlock);
        }
    }
    let mut abandoned = false;
    for object in objects.iter_mut() {
        match object.satisfy(thread)? {
            Acquisition::Acquired => {}
            Acquisition::AcquiredAbandoned => abandoned = true,
            // The `Waitable` contract makes this unreachable: each object was
            // reported satisfiable, and distinct `&mut` references cannot
            // change one another's state between the two passes.
            Acquisition::WouldBlock => return Err(Error::InvalidState),
        }
    }
    Ok(if abandoned {
        Acquisition::AcquiredAbandoned
    } else {
        Acquisition::Acquired
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: ThreadId = ThreadId::new(1);
    const B: ThreadId = ThreadId::new(2);

    #[test]
    fn notification_event_stays_signaled() {
        let mut event = Event::new(EventKind::Notification, true);
        assert!(event.try_acquire());
        assert!(event.try_acquire());
        assert!(event.is_signaled());
    }

    #[test]
    fn synchronization_event_resets_when_it_satisfies_a_wait() {
        let mut event = Event::new(EventKind::Synchronization, false);
        assert!(!event.try_acquire());
        event.set();
        assert!(event.try_acquire());
        assert!(!event.is_signaled());
        assert!(!event.try_acquire());
    }

    #[test]
    fn set_and_reset_report_previous_state() {
        let mut event = Event::new(EventKind::Notification, false);
        assert!(!event.set());
        assert!(event.set());
        assert!(event.reset());
        assert!(!event.reset());
        assert!(!event.is_signaled());
    }

    #[test]
    fn pulse_leaves_event_unsignaled_for_both_kinds() {
        let mut notification = Event::new(EventKind::Notification, false);
        assert!(!notification.pulse());
        assert!(!notification.is_signaled());

        let mut synchronization = Event::new(EventKind::Synchronization, true);
        assert!(synchronization.pulse());
        assert!(!synchronization.is_signaled());
        assert!(!synchronization.try_acquire());
    }

    #[test]
    fn semaphore_rejects_invalid_bounds() {
        assert_eq!(Semaphore::new(0, 0), Err(Error::InvalidInput));
        assert_eq!(Semaphore::new(3, 2), Err(Error::InvalidInput));
        assert_eq!(Semaphore::new(2, 2), Ok(Semaphore { count: 2, limit: 2 }));
        assert_eq!(Semaphore::new(0, 1), Ok(Semaphore { count: 0, limit: 1 }));
    }

    #[test]
    fn semaphore_acquire_stops_at_zero() {
        let mut semaphore = Semaphore::new(2, 4).unwrap();
        assert!(semaphore.try_acquire());
        assert!(semaphore.try_acquire());
        assert!(!semaphore.try_acquire());
        assert_eq!(semaphore.count(), 0);
    }

    #[test]
    fn semaphore_release_reports_previous_count_and_enforces_limit() {
        let mut semaphore = Semaphore::new(1, 3).unwrap();
        assert_eq!(semaphore.release(2), Ok(1));
        assert_eq!(semaphore.count(), 3);
        assert_eq!(semaphore.release(1), Err(Error::OutOfRange));
        assert_eq!(semaphore.count(), 3);
        assert_eq!(semaphore.release(0), Err(Error::InvalidInput));
        assert_eq!(semaphore.count(), 3);
    }

    #[test]
    fn semaphore_release_detects_arithmetic_overflow_without_change() {
        let mut semaphore = Semaphore::new(1, u32::MAX).unwrap();
        assert_eq!(semaphore.release(u32::MAX), Err(Error::OutOfRange));
        assert_eq!(semaphore.count(), 1);
    }

    #[test]
    fn mutant_is_exclusive_to_its_owner() {
        let mut mutant = Mutant::new();
        assert_eq!(mutant.try_acquire(A), Ok(Acquisition::Acquired));
        assert_eq!(mutant.owner(), Some(A));
        assert_eq!(mutant.try_acquire(B), Ok(Acquisition::WouldBlock));
        assert_eq!(mutant.owner(), Some(A));
        assert_eq!(mutant.recursion(), 1);
    }

    #[test]
    fn owner_recursion_must_be_released_fully() {
        let mut mutant = Mutant::new();
        assert_eq!(mutant.try_acquire(A), Ok(Acquisition::Acquired));
        assert_eq!(mutant.try_acquire(A), Ok(Acquisition::Acquired));
        assert_eq!(mutant.recursion(), 2);

        assert_eq!(mutant.release(B), Err(Error::InvalidState));
        assert_eq!(mutant.recursion(), 2);

        assert_eq!(mutant.release(A), Ok(()));
        assert_eq!(mutant.owner(), Some(A));
        assert_eq!(mutant.release(A), Ok(()));
        assert_eq!(mutant.owner(), None);
        assert_eq!(mutant.release(A), Err(Error::InvalidState));
    }

    #[test]
    fn mutant_recursion_overflow_is_checked() {
        let mut mutant = Mutant {
            owner: Some(A),
            recursion: u32::MAX,
            abandoned: false,
        };
        assert_eq!(mutant.try_acquire(A), Err(Error::OutOfRange));
        assert_eq!(mutant.recursion(), u32::MAX);
    }

    #[test]
    fn abandoned_mutant_is_freed_and_reported_once() {
        let mut mutant = Mutant::new();
        assert_eq!(mutant.try_acquire(A), Ok(Acquisition::Acquired));
        assert_eq!(mutant.try_acquire(A), Ok(Acquisition::Acquired));
        assert_eq!(mutant.abandon(B), Err(Error::InvalidState));

        assert_eq!(mutant.abandon(A), Ok(()));
        assert_eq!(mutant.owner(), None);
        assert_eq!(mutant.recursion(), 0);
        assert!(mutant.is_abandoned());
        assert_eq!(mutant.release(A), Err(Error::InvalidState));

        assert_eq!(mutant.try_acquire(B), Ok(Acquisition::AcquiredAbandoned));
        assert!(!mutant.is_abandoned());
        assert_eq!(mutant.owner(), Some(B));
        assert_eq!(mutant.try_acquire(B), Ok(Acquisition::Acquired));
    }

    #[test]
    fn wait_all_leaves_everything_unchanged_when_one_object_blocks() {
        let mut event = Event::new(EventKind::Synchronization, true);
        let mut semaphore = Semaphore::new(0, 1).unwrap();
        let mut mutant = Mutant::new();
        assert_eq!(mutant.try_acquire(B), Ok(Acquisition::Acquired));

        let result = {
            let mut objects: [&mut dyn Waitable; 3] = [&mut event, &mut semaphore, &mut mutant];
            wait_all(&mut objects, A)
        };
        assert_eq!(result, Ok(Acquisition::WouldBlock));
        assert!(event.is_signaled());
        assert_eq!(semaphore.count(), 0);
        assert_eq!(mutant.owner(), Some(B));
    }

    #[test]
    fn wait_all_acquires_every_object_when_all_are_satisfiable() {
        let mut event = Event::new(EventKind::Synchronization, true);
        let mut semaphore = Semaphore::new(1, 1).unwrap();
        let mut mutant = Mutant::new();

        let result = {
            let mut objects: [&mut dyn Waitable; 3] = [&mut event, &mut semaphore, &mut mutant];
            wait_all(&mut objects, A)
        };
        assert_eq!(result, Ok(Acquisition::Acquired));
        assert!(!event.is_signaled());
        assert_eq!(semaphore.count(), 0);
        assert_eq!(mutant.owner(), Some(A));
        assert_eq!(mutant.recursion(), 1);
    }

    #[test]
    fn wait_all_checks_overflow_before_changing_any_object() {
        let mut event = Event::new(EventKind::Synchronization, true);
        let mut semaphore = Semaphore::new(1, 1).unwrap();
        let mut mutant = Mutant {
            owner: Some(A),
            recursion: u32::MAX,
            abandoned: false,
        };

        let result = {
            let mut objects: [&mut dyn Waitable; 3] = [&mut event, &mut semaphore, &mut mutant];
            wait_all(&mut objects, A)
        };
        assert_eq!(result, Err(Error::OutOfRange));
        assert!(event.is_signaled());
        assert_eq!(semaphore.count(), 1);
        assert_eq!(mutant.recursion(), u32::MAX);
    }

    #[test]
    fn wait_all_reports_abandonment_and_rejects_empty_sets() {
        let mut event = Event::new(EventKind::Notification, true);
        let mut mutant = Mutant::new();
        assert_eq!(mutant.try_acquire(B), Ok(Acquisition::Acquired));
        assert_eq!(mutant.abandon(B), Ok(()));

        let result = {
            let mut objects: [&mut dyn Waitable; 2] = [&mut event, &mut mutant];
            wait_all(&mut objects, A)
        };
        assert_eq!(result, Ok(Acquisition::AcquiredAbandoned));
        assert_eq!(mutant.owner(), Some(A));
        assert!(event.is_signaled());

        assert_eq!(wait_all(&mut [], A), Err(Error::InvalidInput));
    }
}
