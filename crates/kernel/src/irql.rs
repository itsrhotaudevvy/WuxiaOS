//! The processor's current interrupt request level.
//!
//! Everything that answers "may this be interrupted" reads this value, so it is one
//! atomic word rather than a copy per caller. The level only ever moves up when
//! something raises it and back down when the same code lowers it, which is why
//! `raise` returns the level it replaced.
//!
//! This kernel runs one processor, so there is no per-CPU array to index and no
//! interlocked exchange to perform; the ordering is what matters, and it is
//! `SeqCst` so a raise is visible to an interrupt handler before the protected
//! region begins.

use core::sync::atomic::{AtomicU8, Ordering};

use wuxia_core::irql;

/// The level the processor is at.
static CURRENT: AtomicU8 = AtomicU8::new(irql::PASSIVE_LEVEL);

/// The level the processor is at right now.
pub fn current() -> u8 {
    CURRENT.load(Ordering::SeqCst)
}

/// Raise to `level` and return the level that was replaced.
///
/// Returns `None` when the level cannot be raised to, in which case the processor
/// is left where it was. A refused raise is a bug in the caller, not a fault: the
/// DDI wrapper answers with the current level instead of pretending the raise
/// happened.
pub fn raise(level: u8) -> Option<u8> {
    let current = current();
    irql::check_raise(current, level).ok()?;
    CURRENT.store(level, Ordering::SeqCst);
    Some(current)
}

/// Lower to `level`, which must be a level that was returned by [`raise`].
pub fn lower(level: u8) -> bool {
    let current = current();
    if irql::check_lower(current, level).is_err() {
        return false;
    }
    CURRENT.store(level, Ordering::SeqCst);
    true
}

/// Run `body` with the processor raised to `level`, then lower it again.
///
/// The level is restored even when `body` does not return normally is not something
/// this kernel can promise - it has no unwinding - so callers keep the region small
/// and do not fault inside it.
pub fn with_level<T>(level: u8, body: impl FnOnce() -> T) -> T {
    let previous = raise(level).unwrap_or_else(current);
    let result = body();
    lower(previous);
    result
}
