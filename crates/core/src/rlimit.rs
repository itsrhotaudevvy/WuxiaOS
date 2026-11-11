//! POSIX resource limits: per-process soft and hard ceilings.
//!
//! Resource numbers follow the Linux x86_64 `RLIMIT_*` values. Each limit is a
//! [`Limit`] with a soft value, which the kernel enforces, and a hard value,
//! which is the ceiling the soft value may be raised to. An unprivileged
//! process may lower its hard limit but never raise it. Lowering is
//! irreversible for that process, as in POSIX.
//!
//! [`Limits::inherit`] copies the table for `fork`, so the child starts with
//! the parent's limits and later changes on either side stay independent.

use crate::process::DESCRIPTOR_CAPACITY;
use crate::{Error, Result};

/// Value meaning "no limit" for both the soft and the hard ceiling.
pub const RLIM_INFINITY: u64 = u64::MAX;

/// Default soft stack size: 8 MiB, the traditional Linux default.
pub const DEFAULT_STACK_SOFT: u64 = 8 * 1024 * 1024;

/// Default soft and hard `MEMLOCK` size: 64 KiB.
pub const DEFAULT_MEMLOCK: u64 = 64 * 1024;

/// A POSIX resource that can be limited, numbered as on Linux x86_64.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resource {
    /// CPU time in seconds (`RLIMIT_CPU`).
    Cpu = 0,
    /// Largest file size that may be written, in bytes (`RLIMIT_FSIZE`).
    FileSize = 1,
    /// Data segment size in bytes (`RLIMIT_DATA`).
    Data = 2,
    /// Stack size in bytes (`RLIMIT_STACK`).
    Stack = 3,
    /// Core dump size in bytes (`RLIMIT_CORE`).
    Core = 4,
    /// Resident set size in bytes (`RLIMIT_RSS`).
    Rss = 5,
    /// Number of processes for the user (`RLIMIT_NPROC`).
    NProc = 6,
    /// Number of open descriptors (`RLIMIT_NOFILE`).
    NoFile = 7,
    /// Bytes that may be locked into memory (`RLIMIT_MEMLOCK`).
    MemLock = 8,
    /// Address-space size in bytes (`RLIMIT_AS`).
    Address = 9,
}

impl Resource {
    /// Number of resources, and the length of a [`Limits`] table.
    pub const COUNT: usize = 10;

    /// Every resource, in numeric order.
    pub const ALL: [Resource; Self::COUNT] = [
        Self::Cpu,
        Self::FileSize,
        Self::Data,
        Self::Stack,
        Self::Core,
        Self::Rss,
        Self::NProc,
        Self::NoFile,
        Self::MemLock,
        Self::Address,
    ];

    /// Decode a Linux x86_64 `RLIMIT_*` number. Unknown numbers are rejected.
    pub const fn from_raw(raw: u64) -> Result<Self> {
        Ok(match raw {
            0 => Self::Cpu,
            1 => Self::FileSize,
            2 => Self::Data,
            3 => Self::Stack,
            4 => Self::Core,
            5 => Self::Rss,
            6 => Self::NProc,
            7 => Self::NoFile,
            8 => Self::MemLock,
            9 => Self::Address,
            _ => return Err(Error::InvalidInput),
        })
    }

    /// The Linux x86_64 `RLIMIT_*` number of this resource.
    pub const fn raw(self) -> u64 {
        self as u64
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// A soft and hard limit pair. The soft value never exceeds the hard value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limit {
    soft: u64,
    hard: u64,
}

impl Limit {
    /// No limit at either ceiling.
    pub const UNLIMITED: Self = Self {
        soft: RLIM_INFINITY,
        hard: RLIM_INFINITY,
    };

    /// Build a limit. Returns [`Error::InvalidInput`] when `soft > hard`.
    pub const fn new(soft: u64, hard: u64) -> Result<Self> {
        if soft > hard {
            return Err(Error::InvalidInput);
        }
        Ok(Self { soft, hard })
    }

    /// The value the kernel enforces.
    pub const fn soft(self) -> u64 {
        self.soft
    }

    /// The ceiling the soft value may be raised to.
    pub const fn hard(self) -> u64 {
        self.hard
    }
}

/// The complete limit table of one process.
///
/// Fields are private, so every stored [`Limit`] satisfies its invariant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    limits: [Limit; Resource::COUNT],
}

impl Default for Limits {
    fn default() -> Self {
        Self::defaults()
    }
}

impl Limits {
    /// The defaults a new bootstrap process starts with.
    ///
    /// - `Cpu`, `FileSize`, `Data`, `Rss`, `NProc`, `Address`: unlimited.
    ///   There is no policy for them yet, so they are not enforced.
    /// - `Stack`: 8 MiB soft, unlimited hard.
    /// - `Core`: 0 soft, unlimited hard, so core dumps are off until raised.
    /// - `NoFile`: 16 soft and hard, equal to [`DESCRIPTOR_CAPACITY`], so the
    ///   descriptor table can always hold every descriptor the limit allows.
    /// - `MemLock`: 64 KiB soft and hard.
    pub const fn defaults() -> Self {
        const fn exact(value: u64) -> Limit {
            Limit {
                soft: value,
                hard: value,
            }
        }
        const fn bounded(soft: u64, hard: u64) -> Limit {
            Limit { soft, hard }
        }
        Self {
            limits: [
                Limit::UNLIMITED,                           // Cpu
                Limit::UNLIMITED,                           // FileSize
                Limit::UNLIMITED,                           // Data
                bounded(DEFAULT_STACK_SOFT, RLIM_INFINITY), // Stack
                bounded(0, RLIM_INFINITY),                  // Core
                Limit::UNLIMITED,                           // Rss
                Limit::UNLIMITED,                           // NProc
                exact(DESCRIPTOR_CAPACITY as u64),          // NoFile
                exact(DEFAULT_MEMLOCK),                     // MemLock
                Limit::UNLIMITED,                           // Address
            ],
        }
    }

    /// Return the current limit for `resource`.
    pub const fn get(&self, resource: Resource) -> Limit {
        self.limits[resource.index()]
    }

    /// Replace the limit for `resource`.
    ///
    /// An unprivileged caller may lower the hard limit or leave it unchanged,
    /// but raising it returns [`Error::PermissionDenied`]. The soft value may
    /// be raised freely up to the hard value. On error the table is unchanged.
    pub fn set(&mut self, resource: Resource, new: Limit, privileged: bool) -> Result<()> {
        let slot = &mut self.limits[resource.index()];
        if !privileged && new.hard > slot.hard {
            return Err(Error::PermissionDenied);
        }
        *slot = new;
        Ok(())
    }

    /// Check that a process may hold `requested_usage` of `resource`.
    ///
    /// Usage equal to the soft limit is allowed. Usage above it returns
    /// [`Error::OutOfRange`]. The hard limit is not consulted, because the
    /// soft limit is the enforced ceiling.
    pub const fn check(&self, resource: Resource, requested_usage: u64) -> Result<()> {
        if requested_usage <= self.get(resource).soft {
            Ok(())
        } else {
            Err(Error::OutOfRange)
        }
    }

    /// Copy the table for a forked child.
    pub const fn inherit(&self) -> Self {
        *self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_numbers_follow_linux_x86_64() {
        let expected = [
            (0, Resource::Cpu),
            (1, Resource::FileSize),
            (2, Resource::Data),
            (3, Resource::Stack),
            (4, Resource::Core),
            (5, Resource::Rss),
            (6, Resource::NProc),
            (7, Resource::NoFile),
            (8, Resource::MemLock),
            (9, Resource::Address),
        ];
        for (raw, resource) in expected {
            assert_eq!(Resource::from_raw(raw), Ok(resource));
            assert_eq!(resource.raw(), raw);
        }
        for (position, resource) in Resource::ALL.iter().enumerate() {
            assert_eq!(resource.raw(), position as u64);
        }
    }

    #[test]
    fn unknown_resource_numbers_are_rejected() {
        for raw in [10, 15, 16, 1 << 32, (1 << 32) | 7, RLIM_INFINITY] {
            assert_eq!(Resource::from_raw(raw), Err(Error::InvalidInput));
        }
    }

    #[test]
    fn a_limit_requires_soft_not_above_hard() {
        assert_eq!(Limit::new(10, 5), Err(Error::InvalidInput));
        assert_eq!(Limit::new(5, 5).map(Limit::soft), Ok(5));
        let limit = Limit::new(4, 16).unwrap();
        assert_eq!((limit.soft(), limit.hard()), (4, 16));
        assert_eq!(
            Limit::UNLIMITED,
            Limit::new(RLIM_INFINITY, RLIM_INFINITY).unwrap()
        );
    }

    #[test]
    fn every_default_satisfies_the_limit_invariant() {
        let limits = Limits::defaults();
        for resource in Resource::ALL {
            let limit = limits.get(resource);
            assert!(limit.soft() <= limit.hard(), "{resource:?}");
        }
        assert_eq!(Limits::default(), limits);
    }

    #[test]
    fn defaults_match_documented_values() {
        let limits = Limits::defaults();
        assert_eq!(
            limits.get(Resource::NoFile),
            Limit::new(16, 16).unwrap(),
            "NOFILE matches DESCRIPTOR_CAPACITY"
        );
        assert_eq!(
            limits.get(Resource::Stack),
            Limit::new(8 * 1024 * 1024, RLIM_INFINITY).unwrap()
        );
        assert_eq!(
            limits.get(Resource::Core),
            Limit::new(0, RLIM_INFINITY).unwrap()
        );
        assert_eq!(limits.get(Resource::Cpu), Limit::UNLIMITED);
        assert_eq!(
            limits.get(Resource::MemLock),
            Limit::new(65536, 65536).unwrap()
        );
    }

    #[test]
    fn unprivileged_callers_may_lower_the_hard_limit() {
        let mut limits = Limits::defaults();
        assert_eq!(
            limits.set(Resource::NoFile, Limit::new(8, 8).unwrap(), false),
            Ok(())
        );
        assert_eq!(limits.get(Resource::NoFile), Limit::new(8, 8).unwrap());
    }

    #[test]
    fn unprivileged_callers_may_not_raise_the_hard_limit() {
        let mut limits = Limits::defaults();
        let before = limits;
        assert_eq!(
            limits.set(Resource::NoFile, Limit::new(16, 17).unwrap(), false),
            Err(Error::PermissionDenied)
        );
        assert_eq!(limits, before);
    }

    #[test]
    fn unprivileged_callers_may_raise_soft_up_to_hard() {
        let mut limits = Limits::defaults();
        limits
            .set(Resource::NoFile, Limit::new(4, 16).unwrap(), false)
            .unwrap();
        assert_eq!(
            limits.set(Resource::NoFile, Limit::new(16, 16).unwrap(), false),
            Ok(())
        );
        assert_eq!(limits.get(Resource::NoFile).soft(), 16);
    }

    #[test]
    fn privileged_callers_may_raise_the_hard_limit() {
        let mut limits = Limits::defaults();
        assert_eq!(
            limits.set(Resource::NoFile, Limit::new(64, 64).unwrap(), true),
            Ok(())
        );
        assert_eq!(limits.get(Resource::NoFile), Limit::new(64, 64).unwrap());
    }

    #[test]
    fn setting_one_resource_leaves_the_others_alone() {
        let mut limits = Limits::defaults();
        let stack = limits.get(Resource::Stack);
        limits
            .set(Resource::NoFile, Limit::new(2, 2).unwrap(), false)
            .unwrap();
        assert_eq!(limits.get(Resource::Stack), stack);
    }

    #[test]
    fn check_allows_usage_up_to_the_soft_limit() {
        let limits = Limits::defaults();
        assert_eq!(limits.check(Resource::NoFile, 0), Ok(()));
        assert_eq!(limits.check(Resource::NoFile, 16), Ok(()));
        assert_eq!(limits.check(Resource::NoFile, 17), Err(Error::OutOfRange));
    }

    #[test]
    fn check_uses_the_soft_limit_not_the_hard_limit() {
        let mut limits = Limits::defaults();
        limits
            .set(Resource::NoFile, Limit::new(4, 16).unwrap(), false)
            .unwrap();
        assert_eq!(limits.check(Resource::NoFile, 4), Ok(()));
        assert_eq!(limits.check(Resource::NoFile, 5), Err(Error::OutOfRange));
    }

    #[test]
    fn check_never_refuses_an_unlimited_resource() {
        let limits = Limits::defaults();
        assert_eq!(limits.check(Resource::Address, u64::MAX), Ok(()));
        assert_eq!(limits.check(Resource::Cpu, RLIM_INFINITY), Ok(()));
    }

    #[test]
    fn a_fork_copy_is_independent_of_its_parent() {
        let mut parent = Limits::defaults();
        let child = parent.inherit();
        assert_eq!(child, parent);

        parent
            .set(Resource::NoFile, Limit::new(2, 2).unwrap(), false)
            .unwrap();
        assert_eq!(child.get(Resource::NoFile), Limit::new(16, 16).unwrap());
        assert_eq!(parent.get(Resource::NoFile), Limit::new(2, 2).unwrap());
    }
}
