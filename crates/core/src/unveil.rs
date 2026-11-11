//! Fixed-capacity visibility table modelled on OpenBSD `unveil(2)`.
//!
//! Before the first [`Unveil::add`] every path is visible. From then on only
//! paths covered by an entry are visible. Coverage is by whole component, and
//! the most specific (longest) matching entry decides the permissions. An entry
//! with no permissions hides its subtree even when a broader entry allows it.
//! [`Unveil::lock`] freezes the table so a process cannot widen its own view.
//!
//! Paths are validated with [`crate::path::validate_absolute`] and matched
//! lexically. Symbolic links must be resolved by the caller before a decision,
//! or a link could lead out of an unveiled tree.

use core::ops::BitOr;

use crate::path::{components, starts_with_components, validate_absolute};
use crate::{Error, Result};

/// Longest path, in bytes, that an entry can hold.
pub const MAX_PATH_LENGTH: usize = 256;

/// Permissions granted on an unveiled path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnveilPerms(u8);

impl UnveilPerms {
    /// No permissions. An entry carrying it hides its subtree.
    pub const NONE: Self = Self(0);
    /// Read file contents and directory listings (`r`).
    pub const READ: Self = Self(1 << 0);
    /// Modify existing file contents (`w`).
    pub const WRITE: Self = Self(1 << 1);
    /// Create, remove or rename entries (`c`).
    pub const CREATE: Self = Self(1 << 2);
    /// Execute files (`x`).
    pub const EXECUTE: Self = Self(1 << 3);

    /// Parse a permission string such as `"rwc"`.
    ///
    /// The empty string yields [`UnveilPerms::NONE`]. Unknown letters and
    /// repeated letters are rejected with [`Error::InvalidInput`].
    pub fn parse(spec: &str) -> Result<Self> {
        let mut perms = Self::NONE;
        for letter in spec.bytes() {
            let bit = match letter {
                b'r' => Self::READ,
                b'w' => Self::WRITE,
                b'c' => Self::CREATE,
                b'x' => Self::EXECUTE,
                _ => return Err(Error::InvalidInput),
            };
            if perms.contains(bit) {
                return Err(Error::InvalidInput);
            }
            perms = perms | bit;
        }
        Ok(perms)
    }

    /// Check whether every permission in `wanted` is present.
    pub const fn contains(self, wanted: Self) -> bool {
        self.0 & wanted.0 == wanted.0
    }
}

impl BitOr for UnveilPerms {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

/// A canonical path and its permissions, stored without allocation.
#[derive(Clone, Copy, Debug)]
struct Entry {
    path: [u8; MAX_PATH_LENGTH],
    path_length: usize,
    perms: UnveilPerms,
}

impl Entry {
    /// Validate `path` and store its canonical form: one `/` per component,
    /// with empty and `.` components removed. The root is stored as `/`.
    fn new(path: &str, perms: UnveilPerms) -> Result<Self> {
        validate_absolute(path, MAX_PATH_LENGTH)?;
        let mut entry = Self {
            path: [0; MAX_PATH_LENGTH],
            path_length: 0,
            perms,
        };
        for component in components(path) {
            entry.append(b"/")?;
            entry.append(component.as_bytes())?;
        }
        if entry.path_length == 0 {
            entry.append(b"/")?;
        }
        Ok(entry)
    }

    fn append(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self
            .path_length
            .checked_add(bytes.len())
            .ok_or(Error::InvalidName)?;
        self.path
            .get_mut(self.path_length..end)
            .ok_or(Error::InvalidName)?
            .copy_from_slice(bytes);
        self.path_length = end;
        Ok(())
    }

    fn canonical(&self) -> &[u8] {
        &self.path[..self.path_length]
    }

    /// Whether this entry's path is a component-prefix of `path`.
    fn covers(&self, path: &str) -> bool {
        // The canonical form is copied from a `&str` and only ever split at
        // ASCII `/`, so it is always valid UTF-8.
        core::str::from_utf8(self.canonical())
            .is_ok_and(|prefix| starts_with_components(path, prefix))
    }
}

/// A fixed-capacity table of unveiled paths.
#[derive(Clone, Copy, Debug)]
pub struct Unveil<const N: usize> {
    entries: [Option<Entry>; N],
    restricted: bool,
    locked: bool,
}

impl<const N: usize> Default for Unveil<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Unveil<N> {
    /// Construct an empty, unrestricted table.
    pub const fn new() -> Self {
        Self {
            entries: [None; N],
            restricted: false,
            locked: false,
        }
    }

    /// Whether the first `add` has restricted visibility.
    pub const fn is_restricted(&self) -> bool {
        self.restricted
    }

    /// Whether the table has been frozen by [`Unveil::lock`].
    pub const fn is_locked(&self) -> bool {
        self.locked
    }

    /// Unveil `path` with `perms`.
    ///
    /// Adding a path that is already present replaces its permissions and
    /// does not use another slot. Fails with [`Error::InvalidState`] once the
    /// table is locked, [`Error::InvalidName`] for a path that
    /// [`validate_absolute`] rejects, and [`Error::TableFull`] when a new
    /// entry has no free slot. A failed add changes nothing.
    pub fn add(&mut self, path: &str, perms: UnveilPerms) -> Result<()> {
        if self.locked {
            return Err(Error::InvalidState);
        }
        let candidate = Entry::new(path, perms)?;
        if let Some(existing) = self
            .entries
            .iter_mut()
            .flatten()
            .find(|entry| entry.canonical() == candidate.canonical())
        {
            existing.perms = perms;
        } else {
            let slot = self
                .entries
                .iter_mut()
                .find(|slot| slot.is_none())
                .ok_or(Error::TableFull)?;
            *slot = Some(candidate);
        }
        self.restricted = true;
        Ok(())
    }

    /// Freeze the table. Later calls to [`Unveil::add`] fail.
    pub fn lock(&mut self) {
        self.locked = true;
    }

    /// Check whether `path` is visible with the permissions `wanted`.
    ///
    /// Before any `add` every valid path passes. Afterwards a path with no
    /// covering entry, or whose most specific entry has no permissions, fails
    /// with [`Error::NotFound`]. A covering entry lacking any permission in
    /// `wanted` fails with [`Error::PermissionDenied`]. A path that
    /// [`validate_absolute`] rejects fails with [`Error::InvalidName`] in every
    /// state, so `..` can never reach the policy.
    pub fn check(&self, path: &str, wanted: UnveilPerms) -> Result<()> {
        validate_absolute(path, MAX_PATH_LENGTH)?;
        if !self.restricted {
            return Ok(());
        }
        let entry = self.most_specific(path).ok_or(Error::NotFound)?;
        if entry.perms == UnveilPerms::NONE {
            return Err(Error::NotFound);
        }
        if entry.perms.contains(wanted) {
            Ok(())
        } else {
            Err(Error::PermissionDenied)
        }
    }

    fn most_specific(&self, path: &str) -> Option<&Entry> {
        let mut best: Option<&Entry> = None;
        for entry in self.entries.iter().flatten() {
            // Every covering entry is a component-prefix of `path`, so the
            // longest canonical form is the most specific one.
            if entry.covers(path)
                && best.is_none_or(|current| entry.path_length > current.path_length)
            {
                best = Some(entry);
            }
        }
        best
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const READ: UnveilPerms = UnveilPerms::READ;
    const WRITE: UnveilPerms = UnveilPerms::WRITE;
    const NONE: UnveilPerms = UnveilPerms::NONE;

    #[test]
    fn permission_strings_parse_each_letter_once() {
        assert_eq!(UnveilPerms::parse(""), Ok(NONE));
        assert_eq!(UnveilPerms::parse("r"), Ok(READ));
        assert_eq!(UnveilPerms::parse("x"), Ok(UnveilPerms::EXECUTE));
        assert_eq!(
            UnveilPerms::parse("rwc"),
            Ok(READ | WRITE | UnveilPerms::CREATE)
        );
        assert_eq!(
            UnveilPerms::parse("cxwr"),
            Ok(READ | WRITE | UnveilPerms::CREATE | UnveilPerms::EXECUTE)
        );
    }

    #[test]
    fn permission_strings_reject_unknown_and_repeated_letters() {
        for spec in ["rr", "rwr", "R", "rz", "r ", "rw-", "rwcx "] {
            assert_eq!(
                UnveilPerms::parse(spec),
                Err(Error::InvalidInput),
                "{spec:?}"
            );
        }
    }

    #[test]
    fn everything_is_visible_until_the_first_add() {
        let table = Unveil::<4>::new();
        assert!(!table.is_restricted());
        assert_eq!(table.check("/etc/motd", READ | WRITE), Ok(()));
        assert_eq!(table.check("/", UnveilPerms::EXECUTE), Ok(()));
        assert_eq!(table.check("relative", READ), Err(Error::InvalidName));
    }

    #[test]
    fn after_the_first_add_only_unveiled_paths_are_visible() {
        let mut table = Unveil::<4>::new();
        table.add("/etc", READ).unwrap();
        assert!(table.is_restricted());
        assert_eq!(table.check("/etc", READ), Ok(()));
        assert_eq!(table.check("/etc/motd", READ), Ok(()));
        assert_eq!(table.check("/etcfoo", READ), Err(Error::NotFound));
        assert_eq!(table.check("/home/user", READ), Err(Error::NotFound));
        assert_eq!(table.check("/", READ), Err(Error::NotFound));
    }

    #[test]
    fn the_root_entry_covers_every_path() {
        let mut table = Unveil::<2>::new();
        table.add("/", UnveilPerms::EXECUTE).unwrap();
        assert_eq!(table.check("/bin/sh", UnveilPerms::EXECUTE), Ok(()));
        assert_eq!(table.check("/", UnveilPerms::EXECUTE), Ok(()));
        assert_eq!(table.check("/bin/sh", WRITE), Err(Error::PermissionDenied));
    }

    #[test]
    fn most_specific_entry_wins() {
        let mut table = Unveil::<4>::new();
        table.add("/srv", READ | WRITE).unwrap();
        table.add("/srv/public", READ).unwrap();
        table.add("/srv/private", NONE).unwrap();
        assert_eq!(table.check("/srv/data", WRITE), Ok(()));
        assert_eq!(table.check("/srv/public/index", READ), Ok(()));
        assert_eq!(
            table.check("/srv/public/index", WRITE),
            Err(Error::PermissionDenied)
        );
        assert_eq!(table.check("/srv/private/key", READ), Err(Error::NotFound));
        assert_eq!(table.check("/srv/private", READ), Err(Error::NotFound));
    }

    #[test]
    fn re_adding_a_path_replaces_its_permissions() {
        let mut table = Unveil::<1>::new();
        table.add("/data", READ).unwrap();
        assert_eq!(table.check("/data/x", WRITE), Err(Error::PermissionDenied));
        table.add("/data/", READ | WRITE).unwrap();
        assert_eq!(table.check("/data/x", WRITE), Ok(()));
        table.add("/data/./", NONE).unwrap();
        assert_eq!(table.check("/data/x", READ), Err(Error::NotFound));
    }

    #[test]
    fn a_full_table_rejects_new_paths_but_not_replacements() {
        let mut table = Unveil::<1>::new();
        table.add("/a", READ).unwrap();
        assert_eq!(table.add("/b", READ), Err(Error::TableFull));
        assert_eq!(table.check("/b", READ), Err(Error::NotFound));
        assert_eq!(table.add("/a", WRITE), Ok(()));
        assert_eq!(table.check("/a/x", WRITE), Ok(()));
    }

    #[test]
    fn lock_freezes_the_table() {
        let mut table = Unveil::<4>::new();
        table.add("/etc", READ).unwrap();
        table.lock();
        assert!(table.is_locked());
        assert_eq!(table.add("/tmp", READ | WRITE), Err(Error::InvalidState));
        assert_eq!(table.add("/etc", WRITE), Err(Error::InvalidState));
        assert_eq!(table.check("/tmp/x", READ), Err(Error::NotFound));
        assert_eq!(table.check("/etc/x", READ), Ok(()));
        assert_eq!(table.check("/etc/x", WRITE), Err(Error::PermissionDenied));
    }

    #[test]
    fn locking_before_any_add_keeps_everything_visible() {
        let mut table = Unveil::<4>::new();
        table.lock();
        assert_eq!(table.add("/etc", READ), Err(Error::InvalidState));
        assert!(!table.is_restricted());
        assert_eq!(table.check("/anything", WRITE), Ok(()));
    }

    #[test]
    fn dot_dot_is_refused_in_every_state() {
        let mut table = Unveil::<4>::new();
        assert_eq!(table.add("/srv/../etc", READ), Err(Error::InvalidName));
        assert!(!table.is_restricted());
        assert_eq!(table.check("/srv/../etc", READ), Err(Error::InvalidName));

        table.add("/srv", READ).unwrap();
        assert_eq!(
            table.check("/srv/../etc/passwd", READ),
            Err(Error::InvalidName)
        );
        assert_eq!(table.check("/srv/./x", READ), Ok(()));
        assert_eq!(table.check("relative/path", READ), Err(Error::InvalidName));
    }

    #[test]
    fn paths_are_bounded_by_the_entry_buffer() {
        let mut buffer = [b'a'; MAX_PATH_LENGTH + 1];
        buffer[0] = b'/';
        let exact = core::str::from_utf8(&buffer[..MAX_PATH_LENGTH]).unwrap();
        let over = core::str::from_utf8(&buffer).unwrap();

        let mut table = Unveil::<2>::new();
        assert_eq!(table.add(over, READ), Err(Error::InvalidName));
        assert!(!table.is_restricted());
        assert_eq!(table.add(exact, READ), Ok(()));
        assert_eq!(table.check(exact, READ), Ok(()));
    }
}
