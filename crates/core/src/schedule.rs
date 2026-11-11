//! Pure scheduling decisions shared by the kernel and host tests.

/// Return the next runnable thread after `current`, in round-robin order.
///
/// The current thread is never selected, so a lone runnable thread does not
/// pretend to switch to itself. `current` is reduced modulo the table length.
pub fn next_runnable(current: usize, runnable: &[bool]) -> Option<usize> {
    if runnable.is_empty() {
        return None;
    }
    let current = current % runnable.len();
    (1..runnable.len())
        .map(|offset| (current + offset) % runnable.len())
        .find(|index| runnable[*index])
}

/// Convert a millisecond duration to timer ticks, rounding up.
///
/// A non-zero duration always waits at least one tick, and `hz` of zero
/// reports an invalid configuration rather than dividing by zero.
pub fn ticks_for_millis(millis: u64, hz: u64) -> Option<u64> {
    if hz == 0 {
        return None;
    }
    if millis == 0 {
        return Some(0);
    }
    let scaled = millis.checked_mul(hz)?;
    Some(scaled.div_ceil(1000))
}

/// Deadline tick for a sleep of `millis` starting at `now`.
pub fn deadline(now: u64, millis: u64, hz: u64) -> Option<u64> {
    Some(now.saturating_add(ticks_for_millis(millis, hz)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_the_current_thread() {
        assert_eq!(next_runnable(0, &[true, true]), Some(1));
        assert_eq!(next_runnable(1, &[true, true]), Some(0));
    }

    #[test]
    fn wraps_and_skips_unrunnable_threads() {
        assert_eq!(next_runnable(2, &[true, false, true, true]), Some(3));
        assert_eq!(next_runnable(0, &[true, false, false, true]), Some(3));
    }

    #[test]
    fn returns_none_when_nothing_else_is_runnable() {
        assert_eq!(next_runnable(0, &[]), None);
        assert_eq!(next_runnable(0, &[true]), None);
        assert_eq!(next_runnable(1, &[false, true]), None);
        assert_eq!(next_runnable(0, &[false, false]), None);
    }

    #[test]
    fn millisecond_sleeps_convert_to_whole_ticks() {
        assert_eq!(ticks_for_millis(0, 100), Some(0));
        assert_eq!(ticks_for_millis(1000, 100), Some(100));
        assert_eq!(ticks_for_millis(10, 100), Some(1));
        assert_eq!(ticks_for_millis(1, 100), Some(1));
        assert_eq!(ticks_for_millis(5, 0), None);
        assert_eq!(deadline(70, 100, 100), Some(80));
        assert_eq!(deadline(0, 0, 100), Some(0));
        assert_eq!(deadline(u64::MAX - 1, 100, 100), Some(u64::MAX));
    }

    #[test]
    fn out_of_range_indices_are_reduced() {
        assert_eq!(next_runnable(5, &[true, false, true]), Some(0));
    }
}
