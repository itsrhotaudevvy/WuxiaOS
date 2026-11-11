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
    fn out_of_range_indices_are_reduced() {
        assert_eq!(next_runnable(5, &[true, false, true]), Some(0));
    }
}
