//! OpenBSD-style pledge(2) promises with monotonic attenuation.
//!
//! A process starts with every promise and may only narrow its set; a
//! narrowing request that regains a dropped promise is refused and leaves the
//! set unchanged. Each [`PosixCall`] needs one promise, and a call outside the
//! current set is denied before any side effect. Promise strings parse without
//! allocation, so the kernel accepts the same space-separated words userspace
//! passes to pledge.

use crate::syscall::PosixCall;
use crate::{Error, Result};

/// A set of promises a process may still exercise.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Promises(u16);

impl Promises {
    /// No promises: every call that needs a promise is denied.
    pub const NONE: Self = Self(0);
    /// Basic stdio: read, write, close, yield, sleep and identity queries.
    pub const STDIO: Self = Self(1 << 0);
    /// Read paths: open files by name for reading.
    pub const RPATH: Self = Self(1 << 1);
    /// Write paths: modify existing files. Reserved until open carries a mode.
    pub const WPATH: Self = Self(1 << 2);
    /// Create paths: create or remove files. Reserved; no call needs it yet.
    pub const CPATH: Self = Self(1 << 3);
    /// Process control beyond the caller. Reserved; no call needs it yet.
    pub const PROC: Self = Self(1 << 4);
    /// Anonymous memory: map and unmap.
    pub const VM: Self = Self(1 << 5);
    /// Every promise defined by this model.
    pub const ALL: Self = Self(
        Self::STDIO.0 | Self::RPATH.0 | Self::WPATH.0 | Self::CPATH.0 | Self::PROC.0 | Self::VM.0,
    );

    /// Accept only bits that name a defined promise.
    pub const fn from_bits(bits: u16) -> Option<Self> {
        if bits & !Self::ALL.0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// Return the raw mask for kernel-internal serialization.
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Check whether every promise in `requested` is present.
    pub const fn contains(self, requested: Self) -> bool {
        self.0 & requested.0 == requested.0
    }

    /// Return the union of two promise sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Parse a pledge string such as `"stdio rpath"`.
    ///
    /// Words are separated by ASCII whitespace and matched case-sensitively.
    /// An empty or blank string yields [`Promises::NONE`], as OpenBSD allows.
    /// An unknown word fails with [`Error::InvalidName`]; a repeated word fails
    /// with [`Error::InvalidInput`].
    pub fn parse(text: &str) -> Result<Self> {
        let mut parsed = Self::NONE;
        for word in text.split_ascii_whitespace() {
            let promise = NAMES
                .iter()
                .find(|(name, _)| *name == word)
                .map(|(_, promise)| *promise)
                .ok_or(Error::InvalidName)?;
            if parsed.contains(promise) {
                return Err(Error::InvalidInput);
            }
            parsed = parsed.union(promise);
        }
        Ok(parsed)
    }
}

/// Promise words in their canonical spelling.
const NAMES: [(&str, Promises); 6] = [
    ("stdio", Promises::STDIO),
    ("rpath", Promises::RPATH),
    ("wpath", Promises::WPATH),
    ("cpath", Promises::CPATH),
    ("proc", Promises::PROC),
    ("vm", Promises::VM),
];

/// The promise a call needs, or [`Promises::NONE`] when it is always permitted.
///
/// This match has no wildcard arm: adding a [`PosixCall`] variant fails to
/// compile until its promise requirement is decided here.
pub const fn required(call: PosixCall) -> Promises {
    match call {
        PosixCall::Read
        | PosixCall::Write
        | PosixCall::Close
        | PosixCall::Seek
        | PosixCall::FileSize
        | PosixCall::Yield
        | PosixCall::Sleep
        | PosixCall::GetPid => Promises::STDIO,
        // Opening for write would need WPATH once the ABI carries an open mode.
        PosixCall::Open => Promises::RPATH,
        PosixCall::Map | PosixCall::Unmap => Promises::VM,
        // Exiting must always succeed so a restricted process can still end.
        PosixCall::Exit => Promises::NONE,
        // A pledge can only remove promises, so it needs no promise itself.
        PosixCall::Pledge => Promises::NONE,
    }
}

/// A process's current promise set, which may only shrink.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pledge {
    promises: Promises,
}

impl Default for Pledge {
    fn default() -> Self {
        Self::new()
    }
}

impl Pledge {
    /// Construct a state holding every promise.
    pub const fn new() -> Self {
        Self {
            promises: Promises::ALL,
        }
    }

    /// Return the promises still held.
    pub const fn promises(&self) -> Promises {
        self.promises
    }

    /// Narrow to `requested`, which must be a subset of the current promises.
    ///
    /// A request that would regain a dropped promise fails with
    /// [`Error::PermissionDenied`] and leaves the state unchanged.
    pub fn restrict(&mut self, requested: Promises) -> Result<()> {
        if !self.promises.contains(requested) {
            return Err(Error::PermissionDenied);
        }
        self.promises = requested;
        Ok(())
    }

    /// Check whether the current promises allow `call`.
    pub const fn permits(&self, call: PosixCall) -> bool {
        self.promises.contains(required(call))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CALLS: [PosixCall; 13] = [
        PosixCall::Read,
        PosixCall::Write,
        PosixCall::Open,
        PosixCall::Close,
        PosixCall::Seek,
        PosixCall::FileSize,
        PosixCall::Map,
        PosixCall::Unmap,
        PosixCall::Yield,
        PosixCall::Sleep,
        PosixCall::GetPid,
        PosixCall::Exit,
        PosixCall::Pledge,
    ];

    #[test]
    fn parses_space_separated_words() {
        assert_eq!(
            Promises::parse("stdio rpath"),
            Ok(Promises::STDIO.union(Promises::RPATH))
        );
        assert_eq!(
            Promises::parse("  vm\tstdio  "),
            Ok(Promises::VM.union(Promises::STDIO))
        );
        assert_eq!(Promises::parse(""), Ok(Promises::NONE));
        assert_eq!(Promises::parse("   "), Ok(Promises::NONE));
        assert_eq!(
            Promises::parse("stdio rpath wpath cpath proc vm"),
            Ok(Promises::ALL)
        );
    }

    #[test]
    fn rejects_unknown_words() {
        assert_eq!(Promises::parse("stdio exec"), Err(Error::InvalidName));
        assert_eq!(Promises::parse("STDIO"), Err(Error::InvalidName));
        assert_eq!(Promises::parse("stdio,rpath"), Err(Error::InvalidName));
    }

    #[test]
    fn rejects_duplicate_words() {
        assert_eq!(Promises::parse("stdio stdio"), Err(Error::InvalidInput));
        assert_eq!(Promises::parse("rpath vm rpath"), Err(Error::InvalidInput));
    }

    #[test]
    fn new_pledge_holds_every_promise() {
        let pledge = Pledge::new();
        assert_eq!(pledge.promises(), Promises::ALL);
        assert_eq!(Pledge::default(), pledge);
    }

    #[test]
    fn restriction_is_monotonic() {
        let mut pledge = Pledge::new();
        let stdio = Promises::STDIO.union(Promises::RPATH);
        assert_eq!(pledge.restrict(stdio), Ok(()));
        assert_eq!(pledge.promises(), stdio);

        // Regaining a dropped promise fails and leaves the state untouched.
        assert_eq!(pledge.restrict(Promises::ALL), Err(Error::PermissionDenied));
        assert_eq!(pledge.restrict(Promises::VM), Err(Error::PermissionDenied));
        assert_eq!(pledge.promises(), stdio);

        // Equal and narrower requests remain valid, down to nothing.
        assert_eq!(pledge.restrict(stdio), Ok(()));
        assert_eq!(pledge.restrict(Promises::NONE), Ok(()));
        assert_eq!(
            pledge.restrict(Promises::STDIO),
            Err(Error::PermissionDenied)
        );
        assert_eq!(pledge.promises(), Promises::NONE);
    }

    #[test]
    fn exit_is_always_permitted() {
        let mut pledge = Pledge::new();
        assert_eq!(pledge.restrict(Promises::NONE), Ok(()));
        assert!(pledge.permits(PosixCall::Exit));
        assert!(!pledge.permits(PosixCall::GetPid));
    }

    #[test]
    fn every_call_is_checked_against_its_promise() {
        for call in CALLS {
            let need = required(call);
            if need == Promises::NONE {
                assert!(matches!(call, PosixCall::Exit | PosixCall::Pledge));
                assert!(Pledge::new().permits(call));
                continue;
            }

            let mut exact = Pledge::new();
            assert_eq!(exact.restrict(need), Ok(()));
            assert!(exact.permits(call), "{call:?} denied with its own promise");

            let without = Promises::from_bits(Promises::ALL.bits() & !need.bits())
                .expect("complement lies within ALL");
            let mut missing = Pledge::new();
            assert_eq!(missing.restrict(without), Ok(()));
            assert!(
                !missing.permits(call),
                "{call:?} allowed without its promise"
            );
        }
    }

    #[test]
    fn expected_promise_mapping() {
        assert_eq!(required(PosixCall::Read), Promises::STDIO);
        assert_eq!(required(PosixCall::Write), Promises::STDIO);
        assert_eq!(required(PosixCall::Close), Promises::STDIO);
        assert_eq!(required(PosixCall::Yield), Promises::STDIO);
        assert_eq!(required(PosixCall::Sleep), Promises::STDIO);
        assert_eq!(required(PosixCall::GetPid), Promises::STDIO);
        assert_eq!(required(PosixCall::Open), Promises::RPATH);
        assert_eq!(required(PosixCall::Map), Promises::VM);
        assert_eq!(required(PosixCall::Unmap), Promises::VM);
        assert_eq!(required(PosixCall::Exit), Promises::NONE);
        assert_eq!(required(PosixCall::Pledge), Promises::NONE);
    }

    #[test]
    fn pledging_stays_available_after_every_promise_is_dropped() {
        let mut pledge = Pledge::new();
        assert_eq!(pledge.restrict(Promises::NONE), Ok(()));
        assert!(pledge.permits(PosixCall::Pledge));
        assert!(pledge.permits(PosixCall::Exit));
        assert!(!pledge.permits(PosixCall::Write));
    }

    #[test]
    fn undefined_bits_are_rejected() {
        assert_eq!(Promises::from_bits(0x8000), None);
        assert_eq!(
            Promises::from_bits(Promises::ALL.bits()),
            Some(Promises::ALL)
        );
    }
}
