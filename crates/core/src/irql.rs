//! Interrupt request levels.
//!
//! IRQL is the level a processor is running at, and it is the only thing that
//! decides whether an interrupt can be delivered: a processor at level *n* runs
//! until it is lowered, and an interrupt at or below the level it currently holds
//! waits. A driver raises the level to protect a region it must not be interrupted
//! in - a queue it shares with its own interrupt handler, for example - and lowers
//! it again.
//!
//! Only the software levels are modelled, because this kernel has one processor and
//! no interrupt controller priority arbitration beyond the local APIC's priority
//! register. [`PASSIVE_LEVEL`] is where ordinary code runs, [`APC_LEVEL`] is not yet
//! used for anything, and [`DISPATCH_LEVEL`] is where an interrupt handler and
//! anything reached from it runs. The levels above that belong to hardware.

use crate::Error;
use crate::Result;

/// Ordinary thread context: page faults and system services may run here.
pub const PASSIVE_LEVEL: u8 = 0;

/// Where deferred procedure calls run. Reserved; nothing raises it yet.
pub const APC_LEVEL: u8 = 1;

/// Where an interrupt handler and everything it calls runs.
pub const DISPATCH_LEVEL: u8 = 2;

/// Highest level this kernel names. The local APIC has 16 priorities.
pub const HIGH_LEVEL: u8 = 15;

/// Check that `level` is one a processor can hold.
///
/// Errors: `OutOfRange` for a level above [`HIGH_LEVEL`].
pub const fn check(level: u8) -> Result<()> {
    if level > HIGH_LEVEL {
        return Err(Error::OutOfRange);
    }
    Ok(())
}

/// Check that raising from `current` to `requested` is a raise at all.
///
/// Raising is one-way: a caller that asks for a level it already holds gets the
/// same level back and a caller that asks for a lower one is refused, because the
/// only way down is [`check_lower`] with the level that was returned to it.
///
/// Errors: `OutOfRange` for a level a processor cannot hold, and `InvalidState` for
/// a request that is not a raise.
pub const fn check_raise(current: u8, requested: u8) -> Result<()> {
    match check(requested) {
        Ok(()) => {}
        Err(error) => return Err(error),
    }
    if requested < current {
        return Err(Error::InvalidState);
    }
    Ok(())
}

/// Check that lowering from `current` to `requested` is a lower.
///
/// Errors: `OutOfRange` for a level a processor cannot hold, and `InvalidState` for
/// a request that would leave the processor at a level it never raised to.
pub const fn check_lower(current: u8, requested: u8) -> Result<()> {
    match check(requested) {
        Ok(()) => {}
        Err(error) => return Err(error),
    }
    if requested > current {
        return Err(Error::InvalidState);
    }
    Ok(())
}

/// Check that an interrupt at `level` may be delivered to a processor at `current`.
///
/// An interrupt is delivered when its level is above the level the processor holds;
/// at equal or lower level it waits. This is the predicate the dispatcher uses, and
/// it is checked rather than assumed so a handler cannot be entered at a level that
/// would let it interrupt itself.
pub fn deliverable(current: u8, level: u8) -> bool {
    level > current
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_levels_are_ordered() {
        assert!(PASSIVE_LEVEL < APC_LEVEL);
        assert!(APC_LEVEL < DISPATCH_LEVEL);
        assert!(DISPATCH_LEVEL < HIGH_LEVEL);
    }

    #[test]
    fn a_raise_must_not_lower() {
        assert_eq!(check_raise(PASSIVE_LEVEL, DISPATCH_LEVEL), Ok(()));
        assert_eq!(check_raise(DISPATCH_LEVEL, DISPATCH_LEVEL), Ok(()));
        assert_eq!(
            check_raise(DISPATCH_LEVEL, PASSIVE_LEVEL),
            Err(Error::InvalidState)
        );
    }

    #[test]
    fn a_lower_must_not_raise() {
        assert_eq!(check_lower(DISPATCH_LEVEL, PASSIVE_LEVEL), Ok(()));
        assert_eq!(check_lower(DISPATCH_LEVEL, DISPATCH_LEVEL), Ok(()));
        assert_eq!(
            check_lower(PASSIVE_LEVEL, DISPATCH_LEVEL),
            Err(Error::InvalidState)
        );
    }

    #[test]
    fn a_level_above_the_controller_is_refused() {
        assert_eq!(check(HIGH_LEVEL), Ok(()));
        assert_eq!(check(HIGH_LEVEL + 1), Err(Error::OutOfRange));
        assert_eq!(
            check_raise(PASSIVE_LEVEL, HIGH_LEVEL + 1),
            Err(Error::OutOfRange)
        );
    }

    #[test]
    fn an_interrupt_is_delivered_only_above_the_current_level() {
        assert!(deliverable(PASSIVE_LEVEL, DISPATCH_LEVEL));
        assert!(!deliverable(DISPATCH_LEVEL, DISPATCH_LEVEL));
        assert!(!deliverable(DISPATCH_LEVEL, APC_LEVEL));
    }
}
