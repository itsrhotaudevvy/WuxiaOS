//! POSIX signal bookkeeping: numbering, default actions, dispositions, masks
//! and pending sets.
//!
//! This module models state only. Delivering a signal to a user handler, saving
//! and restoring context, and stopping or continuing threads belong to the
//! architecture-specific kernel.

use crate::{Error, Result};

/// Number of standard signals modeled, numbered 1 through 31.
pub const SIGNAL_COUNT: usize = 31;

/// A standard POSIX signal, numbered as on Linux x86_64.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signal(u8);

impl Signal {
    /// Hangup detected on controlling terminal or death of controlling process.
    pub const SIGHUP: Self = Self(1);
    /// Interrupt from keyboard.
    pub const SIGINT: Self = Self(2);
    /// Quit from keyboard.
    pub const SIGQUIT: Self = Self(3);
    /// Illegal instruction.
    pub const SIGILL: Self = Self(4);
    /// Trace or breakpoint trap.
    pub const SIGTRAP: Self = Self(5);
    /// Abort signal.
    pub const SIGABRT: Self = Self(6);
    /// Bus error.
    pub const SIGBUS: Self = Self(7);
    /// Floating-point exception.
    pub const SIGFPE: Self = Self(8);
    /// Kill signal. Cannot be caught, ignored or blocked.
    pub const SIGKILL: Self = Self(9);
    /// User-defined signal 1.
    pub const SIGUSR1: Self = Self(10);
    /// Invalid memory reference.
    pub const SIGSEGV: Self = Self(11);
    /// User-defined signal 2.
    pub const SIGUSR2: Self = Self(12);
    /// Write to a pipe with no readers.
    pub const SIGPIPE: Self = Self(13);
    /// Timer expired.
    pub const SIGALRM: Self = Self(14);
    /// Termination request.
    pub const SIGTERM: Self = Self(15);
    /// Stack fault on coprocessor.
    pub const SIGSTKFLT: Self = Self(16);
    /// Child stopped or terminated.
    pub const SIGCHLD: Self = Self(17);
    /// Continue if stopped.
    pub const SIGCONT: Self = Self(18);
    /// Stop process. Cannot be caught, ignored or blocked.
    pub const SIGSTOP: Self = Self(19);
    /// Stop typed at terminal.
    pub const SIGTSTP: Self = Self(20);
    /// Terminal input for background process.
    pub const SIGTTIN: Self = Self(21);
    /// Terminal output for background process.
    pub const SIGTTOU: Self = Self(22);
    /// Urgent condition on socket.
    pub const SIGURG: Self = Self(23);
    /// CPU time limit exceeded.
    pub const SIGXCPU: Self = Self(24);
    /// File size limit exceeded.
    pub const SIGXFSZ: Self = Self(25);
    /// Virtual alarm clock.
    pub const SIGVTALRM: Self = Self(26);
    /// Profiling timer expired.
    pub const SIGPROF: Self = Self(27);
    /// Window resize.
    pub const SIGWINCH: Self = Self(28);
    /// I/O now possible.
    pub const SIGIO: Self = Self(29);
    /// Power failure.
    pub const SIGPWR: Self = Self(30);
    /// Bad system call.
    pub const SIGSYS: Self = Self(31);

    /// Validate a raw signal number. Zero and numbers above 31 are rejected.
    pub fn from_raw(raw: u32) -> Result<Self> {
        match raw {
            1..=31 => Ok(Self(raw as u8)),
            _ => Err(Error::InvalidInput),
        }
    }

    /// Return the Linux x86_64 signal number.
    pub const fn number(self) -> u32 {
        self.0 as u32
    }

    /// Zero-based slot used by per-signal tables.
    const fn index(self) -> usize {
        (self.0 - 1) as usize
    }

    /// Signals whose disposition and blocking can never be changed.
    const fn is_forced(self) -> bool {
        matches!(self, Self::SIGKILL | Self::SIGSTOP)
    }
}

/// A set of standard signals, stored as one bit per signal number.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SignalSet {
    bits: u32,
}

impl SignalSet {
    /// Return the empty set.
    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    /// Add `signal` to the set. Adding a member twice has no further effect.
    pub fn add(&mut self, signal: Signal) {
        self.bits |= Self::bit(signal);
    }

    /// Remove `signal` from the set.
    pub fn remove(&mut self, signal: Signal) {
        self.bits &= !Self::bit(signal);
    }

    /// Whether `signal` is a member of the set.
    pub const fn contains(self, signal: Signal) -> bool {
        self.bits & Self::bit(signal) != 0
    }

    /// Members of either set.
    pub const fn union(self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }

    /// Members of `self` that are not members of `other`.
    pub const fn difference(self, other: Self) -> Self {
        Self {
            bits: self.bits & !other.bits,
        }
    }

    const fn bit(signal: Signal) -> u32 {
        1 << signal.index()
    }
}

/// The action the kernel takes when a signal's disposition is `Default`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DefaultAction {
    /// Terminate the process.
    Terminate,
    /// Terminate the process and write a core dump.
    CoreDump,
    /// Discard the signal.
    Ignore,
    /// Stop the process.
    Stop,
    /// Continue the process if it is stopped.
    Continue,
}

/// Default action for each signal, indexed by `number - 1`.
const DEFAULT_ACTIONS: [DefaultAction; SIGNAL_COUNT] = [
    DefaultAction::Terminate, // 1 SIGHUP
    DefaultAction::Terminate, // 2 SIGINT
    DefaultAction::CoreDump,  // 3 SIGQUIT
    DefaultAction::CoreDump,  // 4 SIGILL
    DefaultAction::CoreDump,  // 5 SIGTRAP
    DefaultAction::CoreDump,  // 6 SIGABRT
    DefaultAction::CoreDump,  // 7 SIGBUS
    DefaultAction::CoreDump,  // 8 SIGFPE
    DefaultAction::Terminate, // 9 SIGKILL
    DefaultAction::Terminate, // 10 SIGUSR1
    DefaultAction::CoreDump,  // 11 SIGSEGV
    DefaultAction::Terminate, // 12 SIGUSR2
    DefaultAction::Terminate, // 13 SIGPIPE
    DefaultAction::Terminate, // 14 SIGALRM
    DefaultAction::Terminate, // 15 SIGTERM
    DefaultAction::Terminate, // 16 SIGSTKFLT
    DefaultAction::Ignore,    // 17 SIGCHLD
    DefaultAction::Continue,  // 18 SIGCONT
    DefaultAction::Stop,      // 19 SIGSTOP
    DefaultAction::Stop,      // 20 SIGTSTP
    DefaultAction::Stop,      // 21 SIGTTIN
    DefaultAction::Stop,      // 22 SIGTTOU
    DefaultAction::Ignore,    // 23 SIGURG
    DefaultAction::CoreDump,  // 24 SIGXCPU
    DefaultAction::CoreDump,  // 25 SIGXFSZ
    DefaultAction::Terminate, // 26 SIGVTALRM
    DefaultAction::Terminate, // 27 SIGPROF
    DefaultAction::Ignore,    // 28 SIGWINCH
    DefaultAction::Terminate, // 29 SIGIO
    DefaultAction::Terminate, // 30 SIGPWR
    DefaultAction::CoreDump,  // 31 SIGSYS
];

/// Return the POSIX default action for `signal`.
pub const fn default_action(signal: Signal) -> DefaultAction {
    DEFAULT_ACTIONS[signal.index()]
}

/// How a process has asked to handle a signal.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Disposition {
    /// Use the POSIX default action for the signal.
    #[default]
    Default,
    /// Discard the signal when it is raised.
    Ignore,
    /// Invoke a user handler at this nonzero user address.
    Handler(u64),
}

impl Disposition {
    /// Build a handler disposition. The address must be nonzero.
    pub fn handler(address: u64) -> Result<Self> {
        if address == 0 {
            return Err(Error::InvalidInput);
        }
        Ok(Self::Handler(address))
    }
}

/// Per-process signal state: dispositions, blocked mask and pending set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignalState {
    dispositions: [Disposition; SIGNAL_COUNT],
    blocked: SignalSet,
    pending: SignalSet,
}

impl Default for SignalState {
    fn default() -> Self {
        Self::new()
    }
}

impl SignalState {
    /// Construct a state with every disposition at `Default`, nothing blocked
    /// and nothing pending.
    pub const fn new() -> Self {
        Self {
            dispositions: [Disposition::Default; SIGNAL_COUNT],
            blocked: SignalSet::new(),
            pending: SignalSet::new(),
        }
    }

    /// Return the current disposition of `signal`.
    pub const fn disposition(&self, signal: Signal) -> Disposition {
        self.dispositions[signal.index()]
    }

    /// Set the disposition of `signal`.
    ///
    /// SIGKILL and SIGSTOP cannot be changed, and a handler address must be
    /// nonzero. Rejected calls leave the state unchanged.
    pub fn set_disposition(&mut self, signal: Signal, disposition: Disposition) -> Result<()> {
        if signal.is_forced() {
            return Err(Error::InvalidInput);
        }
        if matches!(disposition, Disposition::Handler(0)) {
            return Err(Error::InvalidInput);
        }
        self.dispositions[signal.index()] = disposition;
        Ok(())
    }

    /// Return the blocked mask.
    pub const fn blocked(&self) -> SignalSet {
        self.blocked
    }

    /// Replace the blocked mask. SIGKILL and SIGSTOP are silently removed.
    pub fn set_blocked_mask(&mut self, mask: SignalSet) {
        let mut stripped = mask;
        stripped.remove(Signal::SIGKILL);
        stripped.remove(Signal::SIGSTOP);
        self.blocked = stripped;
    }

    /// Return the set of raised signals awaiting delivery.
    pub const fn pending(&self) -> SignalSet {
        self.pending
    }

    /// Raise `signal` for this process.
    ///
    /// A signal whose disposition is `Ignore`, or `Default` with a default
    /// action of `Ignore`, is discarded and never becomes pending. Any other
    /// signal is marked pending until it is delivered or the process exits.
    pub fn raise(&mut self, signal: Signal) {
        let discarded = match self.disposition(signal) {
            Disposition::Ignore => true,
            Disposition::Default => default_action(signal) == DefaultAction::Ignore,
            Disposition::Handler(_) => false,
        };
        if !discarded {
            self.pending.add(signal);
        }
    }

    /// Take the lowest-numbered pending signal that is not blocked.
    ///
    /// The signal is cleared from the pending set and returned with the
    /// disposition in effect at this moment. Returns `None` when nothing is
    /// deliverable.
    pub fn next_deliverable(&mut self) -> Option<(Signal, Disposition)> {
        let ready = self.pending.difference(self.blocked);
        if ready.bits == 0 {
            return None;
        }
        let index = ready.bits.trailing_zeros() as u8;
        let signal = Signal(index + 1);
        self.pending.remove(signal);
        Some((signal, self.disposition(signal)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_signals() -> SignalSet {
        let mut set = SignalSet::new();
        for raw in 1..=31 {
            set.add(Signal::from_raw(raw).unwrap());
        }
        set
    }

    fn mask_of(signals: &[Signal]) -> SignalSet {
        let mut set = SignalSet::new();
        for &signal in signals {
            set.add(signal);
        }
        set
    }

    #[test]
    fn numbers_follow_linux_x86_64() {
        assert_eq!(Signal::SIGHUP.number(), 1);
        assert_eq!(Signal::SIGKILL.number(), 9);
        assert_eq!(Signal::SIGCHLD.number(), 17);
        assert_eq!(Signal::SIGCONT.number(), 18);
        assert_eq!(Signal::SIGSTOP.number(), 19);
        assert_eq!(Signal::SIGSYS.number(), 31);
    }

    #[test]
    fn raw_numbers_outside_one_to_thirty_one_are_rejected() {
        assert_eq!(Signal::from_raw(0), Err(Error::InvalidInput));
        assert_eq!(Signal::from_raw(32), Err(Error::InvalidInput));
        assert_eq!(Signal::from_raw(u32::MAX), Err(Error::InvalidInput));
        for raw in 1..=31 {
            assert_eq!(Signal::from_raw(raw).unwrap().number(), raw);
        }
    }

    #[test]
    fn default_actions_follow_posix() {
        assert_eq!(default_action(Signal::SIGINT), DefaultAction::Terminate);
        assert_eq!(default_action(Signal::SIGQUIT), DefaultAction::CoreDump);
        assert_eq!(default_action(Signal::SIGSEGV), DefaultAction::CoreDump);
        assert_eq!(default_action(Signal::SIGCHLD), DefaultAction::Ignore);
        assert_eq!(default_action(Signal::SIGWINCH), DefaultAction::Ignore);
        assert_eq!(default_action(Signal::SIGCONT), DefaultAction::Continue);
        assert_eq!(default_action(Signal::SIGSTOP), DefaultAction::Stop);
        assert_eq!(default_action(Signal::SIGTSTP), DefaultAction::Stop);
    }

    #[test]
    fn sigkill_and_sigstop_dispositions_cannot_change() {
        let mut state = SignalState::new();
        let handler = Disposition::handler(0x40_0000).unwrap();
        for signal in [Signal::SIGKILL, Signal::SIGSTOP] {
            assert_eq!(
                state.set_disposition(signal, Disposition::Ignore),
                Err(Error::InvalidInput)
            );
            assert_eq!(
                state.set_disposition(signal, handler),
                Err(Error::InvalidInput)
            );
            assert_eq!(
                state.set_disposition(signal, Disposition::Default),
                Err(Error::InvalidInput)
            );
            assert_eq!(state.disposition(signal), Disposition::Default);
        }
    }

    #[test]
    fn sigkill_and_sigstop_cannot_be_blocked() {
        let mut state = SignalState::new();
        state.set_blocked_mask(all_signals());
        assert!(!state.blocked().contains(Signal::SIGKILL));
        assert!(!state.blocked().contains(Signal::SIGSTOP));
        assert!(state.blocked().contains(Signal::SIGUSR1));

        state.raise(Signal::SIGKILL);
        assert_eq!(
            state.next_deliverable(),
            Some((Signal::SIGKILL, Disposition::Default))
        );
    }

    #[test]
    fn ignored_signals_are_discarded() {
        let mut state = SignalState::new();
        state
            .set_disposition(Signal::SIGUSR1, Disposition::Ignore)
            .unwrap();
        state.raise(Signal::SIGUSR1);
        assert!(!state.pending().contains(Signal::SIGUSR1));
        assert_eq!(state.next_deliverable(), None);
    }

    #[test]
    fn default_ignored_signals_are_discarded() {
        let mut state = SignalState::new();
        state.raise(Signal::SIGCHLD);
        state.raise(Signal::SIGWINCH);
        assert_eq!(state.pending(), SignalSet::new());
        assert_eq!(state.next_deliverable(), None);
    }

    #[test]
    fn handler_keeps_a_default_ignored_signal_pending() {
        let mut state = SignalState::new();
        let handler = Disposition::handler(0x40_1000).unwrap();
        state.set_disposition(Signal::SIGCHLD, handler).unwrap();
        state.raise(Signal::SIGCHLD);
        assert_eq!(state.next_deliverable(), Some((Signal::SIGCHLD, handler)));
    }

    #[test]
    fn blocked_signals_stay_pending_until_unblocked() {
        let mut state = SignalState::new();
        state.set_blocked_mask(mask_of(&[Signal::SIGUSR1]));
        state.raise(Signal::SIGUSR1);

        assert!(state.pending().contains(Signal::SIGUSR1));
        assert_eq!(state.next_deliverable(), None);
        assert!(state.pending().contains(Signal::SIGUSR1));

        state.set_blocked_mask(SignalSet::new());
        assert_eq!(
            state.next_deliverable(),
            Some((Signal::SIGUSR1, Disposition::Default))
        );
        assert_eq!(state.next_deliverable(), None);
    }

    #[test]
    fn delivery_is_lowest_numbered_first() {
        let mut state = SignalState::new();
        state.raise(Signal::SIGTERM);
        state.raise(Signal::SIGHUP);
        state.raise(Signal::SIGUSR2);

        assert_eq!(state.next_deliverable().unwrap().0, Signal::SIGHUP);
        assert_eq!(state.next_deliverable().unwrap().0, Signal::SIGUSR2);
        assert_eq!(state.next_deliverable().unwrap().0, Signal::SIGTERM);
        assert_eq!(state.next_deliverable(), None);
    }

    #[test]
    fn delivery_skips_blocked_lower_signals() {
        let mut state = SignalState::new();
        state.set_blocked_mask(mask_of(&[Signal::SIGHUP]));
        state.raise(Signal::SIGHUP);
        state.raise(Signal::SIGINT);

        assert_eq!(state.next_deliverable().unwrap().0, Signal::SIGINT);
        assert_eq!(state.next_deliverable(), None);
        assert!(state.pending().contains(Signal::SIGHUP));
    }

    #[test]
    fn delivery_clears_the_pending_signal() {
        let mut state = SignalState::new();
        state.raise(Signal::SIGINT);
        assert!(state.next_deliverable().is_some());
        assert_eq!(state.pending(), SignalSet::new());
        assert_eq!(state.next_deliverable(), None);
    }

    #[test]
    fn delivery_reports_the_installed_handler() {
        let mut state = SignalState::new();
        let handler = Disposition::handler(0x40_1000).unwrap();
        state.set_disposition(Signal::SIGUSR1, handler).unwrap();
        state.raise(Signal::SIGUSR1);
        assert_eq!(state.next_deliverable(), Some((Signal::SIGUSR1, handler)));
    }

    #[test]
    fn handler_addresses_must_be_nonzero() {
        assert_eq!(Disposition::handler(0), Err(Error::InvalidInput));
        assert_eq!(
            Disposition::handler(0x1000),
            Ok(Disposition::Handler(0x1000))
        );

        let mut state = SignalState::new();
        assert_eq!(
            state.set_disposition(Signal::SIGUSR1, Disposition::Handler(0)),
            Err(Error::InvalidInput)
        );
        assert_eq!(state.disposition(Signal::SIGUSR1), Disposition::Default);
    }

    #[test]
    fn signal_set_operations() {
        let a = mask_of(&[Signal::SIGHUP, Signal::SIGINT]);
        let b = mask_of(&[Signal::SIGINT, Signal::SIGTERM]);

        let union = a.union(b);
        assert!(union.contains(Signal::SIGHUP));
        assert!(union.contains(Signal::SIGINT));
        assert!(union.contains(Signal::SIGTERM));

        let difference = a.difference(b);
        assert!(difference.contains(Signal::SIGHUP));
        assert!(!difference.contains(Signal::SIGINT));
        assert!(!difference.contains(Signal::SIGTERM));

        let mut set = SignalSet::new();
        set.add(Signal::SIGUSR2);
        set.add(Signal::SIGUSR2);
        set.remove(Signal::SIGUSR2);
        assert_eq!(set, SignalSet::new());
    }
}
