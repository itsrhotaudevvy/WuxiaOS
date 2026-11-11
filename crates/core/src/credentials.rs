//! POSIX user and group credentials with permission checks.
//!
//! [`Credentials`] carries the real, effective and saved user and group IDs
//! plus up to [`MAX_GROUPS`] supplementary groups. The set operations follow
//! POSIX: a process with effective UID 0 may assign any ID, while any other
//! process may only move among the IDs it already holds. Every setter checks
//! its arguments before it mutates state, so a refused call changes nothing.
//!
//! The file checks in this module use the effective IDs, as POSIX access
//! checks do. The ID `u32::MAX` is reserved as the "unchanged" marker for
//! [`Credentials::setresuid`] and [`Credentials::setresgid`]; it is rejected
//! everywhere else.

use crate::{Error, Result};

/// The user ID with full privilege.
pub const ROOT: u32 = 0;

/// The reserved ID that means "leave this field unchanged" in `setres*` calls.
pub const UNCHANGED: u32 = u32::MAX;

/// Maximum number of supplementary groups a process may hold.
pub const MAX_GROUPS: usize = 32;

/// The real, effective and saved IDs of a process, plus its supplementary groups.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Credentials {
    ruid: u32,
    euid: u32,
    suid: u32,
    rgid: u32,
    egid: u32,
    sgid: u32,
    groups: [u32; MAX_GROUPS],
    group_count: usize,
}

impl Credentials {
    /// Create credentials whose real, effective and saved IDs are all set.
    ///
    /// The process starts with no supplementary groups. Fails with
    /// [`Error::InvalidInput`] when either ID is the reserved [`UNCHANGED`] value.
    pub fn new(uid: u32, gid: u32) -> Result<Self> {
        check_id(uid)?;
        check_id(gid)?;
        Ok(Self {
            ruid: uid,
            euid: uid,
            suid: uid,
            rgid: gid,
            egid: gid,
            sgid: gid,
            groups: [0; MAX_GROUPS],
            group_count: 0,
        })
    }

    /// Real user ID.
    pub const fn ruid(&self) -> u32 {
        self.ruid
    }

    /// Effective user ID, used for access checks.
    pub const fn euid(&self) -> u32 {
        self.euid
    }

    /// Saved set-user-ID, which lets a process regain privilege later.
    pub const fn suid(&self) -> u32 {
        self.suid
    }

    /// Real group ID.
    pub const fn rgid(&self) -> u32 {
        self.rgid
    }

    /// Effective group ID, used for access checks.
    pub const fn egid(&self) -> u32 {
        self.egid
    }

    /// Saved set-group-ID.
    pub const fn sgid(&self) -> u32 {
        self.sgid
    }

    /// Supplementary groups in the order they were set.
    pub fn groups(&self) -> &[u32] {
        &self.groups[..self.group_count]
    }

    /// Whether `gid` is the effective group or one of the supplementary groups.
    ///
    /// The real and saved group IDs do not count, matching POSIX access checks.
    pub fn in_group(&self, gid: u32) -> bool {
        self.egid == gid || self.groups().contains(&gid)
    }

    /// Whether the process has privilege, which is an effective UID of [`ROOT`].
    pub const fn privileged(&self) -> bool {
        self.euid == ROOT
    }

    /// Set the user ID as POSIX `setuid(2)` does.
    ///
    /// A privileged process sets the real, effective and saved IDs. Any other
    /// process sets only the effective ID, and only to its real or saved ID.
    /// Otherwise fails with [`Error::PermissionDenied`] and changes nothing.
    pub fn setuid(&mut self, uid: u32) -> Result<()> {
        check_id(uid)?;
        if self.privileged() {
            self.ruid = uid;
            self.euid = uid;
            self.suid = uid;
        } else if uid == self.ruid || uid == self.suid {
            self.euid = uid;
        } else {
            return Err(Error::PermissionDenied);
        }
        Ok(())
    }

    /// Set only the effective user ID.
    ///
    /// A privileged process may choose any value. Any other process may choose
    /// only its real, effective or saved ID.
    pub fn seteuid(&mut self, euid: u32) -> Result<()> {
        check_id(euid)?;
        if !self.privileged() && !self.holds_uid(euid) {
            return Err(Error::PermissionDenied);
        }
        self.euid = euid;
        Ok(())
    }

    /// Set the real, effective and saved user IDs at once.
    ///
    /// A value of [`UNCHANGED`] leaves that field alone. A privileged process
    /// may set any value. Any other process may set each new value only to one
    /// of its current real, effective or saved IDs. The call is all or nothing.
    pub fn setresuid(&mut self, ruid: u32, euid: u32, suid: u32) -> Result<()> {
        let [r, e, s] = merge_ids(
            self.privileged(),
            [self.ruid, self.euid, self.suid],
            [ruid, euid, suid],
        )?;
        self.ruid = r;
        self.euid = e;
        self.suid = s;
        Ok(())
    }

    /// Set the group ID as POSIX `setgid(2)` does.
    ///
    /// A privileged process sets the real, effective and saved group IDs. Any
    /// other process sets only the effective group ID, and only to its real or
    /// saved group ID. Otherwise fails with [`Error::PermissionDenied`].
    pub fn setgid(&mut self, gid: u32) -> Result<()> {
        check_id(gid)?;
        if self.privileged() {
            self.rgid = gid;
            self.egid = gid;
            self.sgid = gid;
        } else if gid == self.rgid || gid == self.sgid {
            self.egid = gid;
        } else {
            return Err(Error::PermissionDenied);
        }
        Ok(())
    }

    /// Set only the effective group ID, under the same rule as [`Self::setgid`].
    ///
    /// A privileged process may choose any value. Any other process may choose
    /// only its real, effective or saved group ID.
    pub fn setegid(&mut self, egid: u32) -> Result<()> {
        check_id(egid)?;
        if !self.privileged() && !self.holds_gid(egid) {
            return Err(Error::PermissionDenied);
        }
        self.egid = egid;
        Ok(())
    }

    /// Set the real, effective and saved group IDs at once.
    ///
    /// Follows the same rules as [`Self::setresuid`]: [`UNCHANGED`] leaves a
    /// field alone, a privileged process may set any value, and any other
    /// process is limited to its current group IDs. The call is all or nothing.
    pub fn setresgid(&mut self, rgid: u32, egid: u32, sgid: u32) -> Result<()> {
        let [r, e, s] = merge_ids(
            self.privileged(),
            [self.rgid, self.egid, self.sgid],
            [rgid, egid, sgid],
        )?;
        self.rgid = r;
        self.egid = e;
        self.sgid = s;
        Ok(())
    }

    /// Replace the supplementary groups. Only a privileged process may do this.
    ///
    /// Fails with [`Error::PermissionDenied`] for an unprivileged process,
    /// with [`Error::OutOfRange`] when there are more than [`MAX_GROUPS`]
    /// entries, and with [`Error::InvalidInput`] when an entry is [`UNCHANGED`].
    /// A refused call leaves the previous groups in place.
    pub fn setgroups(&mut self, groups: &[u32]) -> Result<()> {
        if !self.privileged() {
            return Err(Error::PermissionDenied);
        }
        if groups.len() > MAX_GROUPS {
            return Err(Error::OutOfRange);
        }
        if groups.contains(&UNCHANGED) {
            return Err(Error::InvalidInput);
        }
        self.groups = [0; MAX_GROUPS];
        self.groups[..groups.len()].copy_from_slice(groups);
        self.group_count = groups.len();
        Ok(())
    }

    fn holds_uid(&self, uid: u32) -> bool {
        uid == self.ruid || uid == self.euid || uid == self.suid
    }

    fn holds_gid(&self, gid: u32) -> bool {
        gid == self.rgid || gid == self.egid || gid == self.sgid
    }
}

/// A set of permission bits: the nine rwx bits plus setuid, setgid and sticky.
///
/// The value holds only the low twelve bits, which is the POSIX `st_mode`
/// permission range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileMode(u16);

impl FileMode {
    /// Set-user-ID on execution.
    pub const SETUID: Self = Self(0o4000);
    /// Set-group-ID on execution.
    pub const SETGID: Self = Self(0o2000);
    /// Sticky bit: restricts unlinking inside a directory.
    pub const STICKY: Self = Self(0o1000);

    /// Mask of every valid bit in a file mode.
    const VALID_BITS: u16 = 0o7777;

    /// Accept only the low twelve bits, which name the defined mode bits.
    pub const fn from_bits(bits: u16) -> Option<Self> {
        if bits & !Self::VALID_BITS == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// Return the raw mode bits.
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Check whether every bit in `other` is set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// The three permission bits for one class, shifted down to the low bits.
    const fn class_bits(self, shift: u32) -> u16 {
        (self.0 >> shift) & 0o7
    }
}

/// An access a caller wants to make to a file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Access {
    /// Read the file's contents.
    Read,
    /// Modify the file's contents.
    Write,
    /// Execute the file, or search a directory.
    Execute,
}

impl Access {
    /// The matching bit in a three-bit rwx triad.
    const fn triad_bit(self) -> u16 {
        match self {
            Self::Read => 0o4,
            Self::Write => 0o2,
            Self::Execute => 0o1,
        }
    }
}

/// Shift that selects the owner class of an rwx triad.
const OWNER_SHIFT: u32 = 6;
/// Shift that selects the group class of an rwx triad.
const GROUP_SHIFT: u32 = 3;
/// Shift that selects the other class of an rwx triad.
const OTHER_SHIFT: u32 = 0;

/// Decide whether `cred` may perform `want` on a file.
///
/// The effective UID and GID are checked. A process with effective UID
/// [`ROOT`] may read and write anything, and may execute only when some
/// execute bit is set. Any other process falls into exactly one class: owner
/// when its effective UID matches `owner_uid`, otherwise group when it is in
/// `owner_gid`, otherwise other. Only that class's bits are consulted, so a
/// narrower class never falls through to a more permissive one.
pub fn may_access(
    cred: &Credentials,
    owner_uid: u32,
    owner_gid: u32,
    mode: FileMode,
    want: Access,
) -> bool {
    if cred.privileged() {
        return match want {
            Access::Read | Access::Write => true,
            Access::Execute => mode.bits() & 0o111 != 0,
        };
    }
    let shift = if cred.euid() == owner_uid {
        OWNER_SHIFT
    } else if cred.in_group(owner_gid) {
        GROUP_SHIFT
    } else {
        OTHER_SHIFT
    };
    mode.class_bits(shift) & want.triad_bit() != 0
}

/// Decide whether `cred` may unlink or rename an entry in a directory.
///
/// Returns `true` when the directory lacks the sticky bit, because the sticky
/// restriction does not apply. Otherwise a sticky directory permits removal
/// only to a privileged process, the owner of the entry, or the owner of the
/// directory. The caller must still require write and search access on the
/// directory separately with [`may_access`].
pub fn may_unlink_in_sticky_dir(
    cred: &Credentials,
    dir_mode: FileMode,
    dir_owner_uid: u32,
    entry_owner_uid: u32,
) -> bool {
    if !dir_mode.contains(FileMode::STICKY) {
        return true;
    }
    cred.privileged() || cred.euid() == dir_owner_uid || cred.euid() == entry_owner_uid
}

/// Apply the credential changes that executing a file makes.
///
/// Unless `nosuid` is set, the effective UID becomes `file_uid` when the file
/// has [`FileMode::SETUID`], and the effective GID becomes `file_gid` when it
/// has [`FileMode::SETGID`]. Real IDs and supplementary groups never change.
/// The saved IDs then take the effective values. The caller should check
/// execute permission with [`may_access`] first.
///
/// Fails with [`Error::InvalidInput`] when a reserved [`UNCHANGED`] ID would
/// be installed, and leaves the credentials unchanged.
pub fn exec_transition(
    cred: &mut Credentials,
    file_uid: u32,
    file_gid: u32,
    mode: FileMode,
    nosuid: bool,
) -> Result<()> {
    let mut euid = cred.euid;
    let mut egid = cred.egid;
    if !nosuid {
        if mode.contains(FileMode::SETUID) {
            check_id(file_uid)?;
            euid = file_uid;
        }
        if mode.contains(FileMode::SETGID) {
            check_id(file_gid)?;
            egid = file_gid;
        }
    }
    cred.euid = euid;
    cred.egid = egid;
    cred.suid = euid;
    cred.sgid = egid;
    Ok(())
}

/// Reject the reserved [`UNCHANGED`] value as a concrete ID.
fn check_id(id: u32) -> Result<()> {
    if id == UNCHANGED {
        Err(Error::InvalidInput)
    } else {
        Ok(())
    }
}

/// Compute a `setres*` triple, validating every requested value before use.
///
/// [`UNCHANGED`] entries keep the current value. Unprivileged callers may only
/// request values already present in `current`.
fn merge_ids(privileged: bool, current: [u32; 3], requested: [u32; 3]) -> Result<[u32; 3]> {
    let mut next = current;
    for (slot, &value) in next.iter_mut().zip(requested.iter()) {
        if value == UNCHANGED {
            continue;
        }
        if !privileged && !current.contains(&value) {
            return Err(Error::PermissionDenied);
        }
        *slot = value;
    }
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(bits: u16) -> FileMode {
        FileMode::from_bits(bits).unwrap()
    }

    /// Credentials with the given real, effective and saved user IDs.
    fn uids(ruid: u32, euid: u32, suid: u32) -> Credentials {
        let mut cred = Credentials::new(ROOT, ROOT).unwrap();
        cred.setresuid(ruid, euid, suid).unwrap();
        cred
    }

    /// Unprivileged credentials (uid 1000) with the given group IDs.
    fn gids(rgid: u32, egid: u32, sgid: u32) -> Credentials {
        let mut cred = Credentials::new(ROOT, ROOT).unwrap();
        cred.setresgid(rgid, egid, sgid).unwrap();
        cred.setuid(1000).unwrap();
        cred
    }

    #[test]
    fn new_sets_every_id_and_starts_without_groups() {
        let cred = Credentials::new(1000, 100).unwrap();
        assert_eq!([cred.ruid(), cred.euid(), cred.suid()], [1000; 3]);
        assert_eq!([cred.rgid(), cred.egid(), cred.sgid()], [100; 3]);
        assert!(cred.groups().is_empty());
        assert!(!cred.privileged());
    }

    #[test]
    fn reserved_unchanged_value_is_never_a_concrete_id() {
        assert_eq!(Credentials::new(UNCHANGED, 0), Err(Error::InvalidInput));
        assert_eq!(Credentials::new(0, UNCHANGED), Err(Error::InvalidInput));
        let mut cred = Credentials::new(0, 0).unwrap();
        assert_eq!(cred.setuid(UNCHANGED), Err(Error::InvalidInput));
        assert_eq!(cred.seteuid(UNCHANGED), Err(Error::InvalidInput));
        assert_eq!(cred.setgid(UNCHANGED), Err(Error::InvalidInput));
        assert_eq!(cred.setegid(UNCHANGED), Err(Error::InvalidInput));
    }

    #[test]
    fn privileged_setuid_sets_all_three_ids() {
        let mut cred = Credentials::new(ROOT, 0).unwrap();
        cred.setuid(1000).unwrap();
        assert_eq!([cred.ruid(), cred.euid(), cred.suid()], [1000; 3]);
        // The process is no longer privileged, so it cannot return to root.
        assert_eq!(cred.setuid(ROOT), Err(Error::PermissionDenied));
    }

    #[test]
    fn unprivileged_setuid_moves_only_euid_within_real_or_saved() {
        let mut cred = uids(1000, 1000, 2000);
        cred.setuid(2000).unwrap();
        assert_eq!([cred.ruid(), cred.euid(), cred.suid()], [1000, 2000, 2000]);
        cred.setuid(1000).unwrap();
        assert_eq!(cred.euid(), 1000);
    }

    #[test]
    fn refused_setuid_leaves_state_unchanged() {
        let mut cred = uids(1000, 1000, 2000);
        let before = cred;
        assert_eq!(cred.setuid(3000), Err(Error::PermissionDenied));
        assert_eq!(cred, before);
    }

    #[test]
    fn privileged_seteuid_keeps_real_and_saved_for_later_restore() {
        let mut cred = Credentials::new(ROOT, 0).unwrap();
        cred.seteuid(1000).unwrap();
        assert_eq!([cred.ruid(), cred.euid(), cred.suid()], [0, 1000, 0]);
        cred.seteuid(ROOT).unwrap();
        assert!(cred.privileged());
    }

    #[test]
    fn unprivileged_seteuid_is_limited_to_held_uids() {
        let mut cred = uids(1000, 1000, 2000);
        cred.seteuid(2000).unwrap();
        assert_eq!(cred.seteuid(ROOT), Err(Error::PermissionDenied));
        assert_eq!(cred.euid(), 2000);
        cred.seteuid(1000).unwrap();
        assert_eq!(cred.euid(), 1000);
    }

    #[test]
    fn setresuid_unchanged_fields_keep_their_values() {
        let mut cred = Credentials::new(ROOT, 0).unwrap();
        cred.setresuid(1000, UNCHANGED, UNCHANGED).unwrap();
        assert_eq!([cred.ruid(), cred.euid(), cred.suid()], [1000, 0, 0]);
    }

    #[test]
    fn privileged_setresuid_accepts_any_values() {
        let mut cred = Credentials::new(ROOT, 0).unwrap();
        cred.setresuid(1000, 2000, 3000).unwrap();
        assert_eq!([cred.ruid(), cred.euid(), cred.suid()], [1000, 2000, 3000]);
    }

    #[test]
    fn unprivileged_setresuid_may_permute_held_ids() {
        let mut cred = uids(1000, 2000, 3000);
        cred.setresuid(2000, 3000, 1000).unwrap();
        assert_eq!([cred.ruid(), cred.euid(), cred.suid()], [2000, 3000, 1000]);
    }

    #[test]
    fn refused_setresuid_is_all_or_nothing() {
        let mut cred = uids(1000, 1000, 2000);
        let before = cred;
        // The first value is held, but the third is not, so nothing changes.
        assert_eq!(
            cred.setresuid(1000, 2000, 9999),
            Err(Error::PermissionDenied)
        );
        assert_eq!(cred, before);
    }

    #[test]
    fn privileged_setgid_sets_all_three_gids() {
        let mut cred = Credentials::new(ROOT, 0).unwrap();
        cred.setgid(100).unwrap();
        assert_eq!([cred.rgid(), cred.egid(), cred.sgid()], [100; 3]);
    }

    #[test]
    fn unprivileged_setgid_and_setegid_respect_held_gids() {
        let mut cred = gids(100, 100, 200);
        cred.setgid(200).unwrap();
        assert_eq!(cred.egid(), 200);
        assert_eq!(cred.setgid(300), Err(Error::PermissionDenied));
        assert_eq!(cred.setegid(300), Err(Error::PermissionDenied));
        cred.setegid(100).unwrap();
        assert_eq!(cred.egid(), 100);
    }

    #[test]
    fn setresgid_unprivileged_is_atomic_and_permutes() {
        let mut cred = gids(100, 200, 300);
        cred.setresgid(300, 100, 200).unwrap();
        assert_eq!([cred.rgid(), cred.egid(), cred.sgid()], [300, 100, 200]);

        let before = cred;
        assert_eq!(cred.setresgid(300, 400, 100), Err(Error::PermissionDenied));
        assert_eq!(cred, before);
    }

    #[test]
    fn setgroups_requires_privilege() {
        let mut cred = uids(1000, 1000, 1000);
        assert_eq!(cred.setgroups(&[10]), Err(Error::PermissionDenied));
        assert!(cred.groups().is_empty());
    }

    #[test]
    fn setgroups_accepts_up_to_capacity_and_rejects_more() {
        let mut cred = Credentials::new(ROOT, 0).unwrap();
        let full = [7u32; MAX_GROUPS];
        cred.setgroups(&full).unwrap();
        assert_eq!(cred.groups().len(), MAX_GROUPS);

        let too_many = [7u32; MAX_GROUPS + 1];
        assert_eq!(cred.setgroups(&too_many), Err(Error::OutOfRange));
        assert_eq!(cred.groups().len(), MAX_GROUPS);
    }

    #[test]
    fn setgroups_replacement_leaves_no_stale_entries() {
        let mut replaced = Credentials::new(ROOT, 0).unwrap();
        replaced.setgroups(&[1, 2, 3]).unwrap();
        replaced.setgroups(&[9]).unwrap();

        let mut fresh = Credentials::new(ROOT, 0).unwrap();
        fresh.setgroups(&[9]).unwrap();
        assert_eq!(replaced.groups(), &[9]);
        assert_eq!(replaced, fresh);
    }

    #[test]
    fn group_membership_uses_effective_and_supplementary_only() {
        let mut cred = Credentials::new(ROOT, 0).unwrap();
        cred.setgroups(&[300]).unwrap();
        cred.setresgid(100, 100, 400).unwrap();
        cred.setuid(1000).unwrap();
        assert!(cred.in_group(100));
        assert!(cred.in_group(300));
        assert!(!cred.in_group(400));
    }

    #[test]
    fn file_mode_rejects_bits_above_twelve() {
        assert_eq!(FileMode::from_bits(0o10000), None);
        assert_eq!(FileMode::from_bits(0o7777).unwrap().bits(), 0o7777);
        assert_eq!(mode(0o4755).bits(), 0o4755);
        assert!(mode(0o6755).contains(FileMode::SETUID));
        assert!(mode(0o6755).contains(FileMode::SETGID));
        assert!(!mode(0o2755).contains(FileMode::STICKY));
    }

    #[test]
    fn root_reads_and_writes_anything_but_executes_only_with_an_x_bit() {
        let root = Credentials::new(ROOT, ROOT).unwrap();
        assert!(may_access(&root, 1000, 100, mode(0), Access::Read));
        assert!(may_access(&root, 1000, 100, mode(0), Access::Write));
        assert!(!may_access(&root, 1000, 100, mode(0), Access::Execute));
        assert!(!may_access(&root, 1000, 100, mode(0o600), Access::Execute));
        assert!(may_access(&root, 1000, 100, mode(0o610), Access::Execute));
    }

    #[test]
    fn owner_class_does_not_fall_through_to_group_or_other() {
        // Owner bits are empty, but group and other are full. The owner must
        // still be denied, since the owner class is the only one consulted.
        let cred = uids(1000, 1000, 1000);
        let m = mode(0o077);
        assert!(!may_access(&cred, 1000, 100, m, Access::Read));
        assert!(!may_access(&cred, 1000, 100, m, Access::Write));
        assert!(!may_access(&cred, 1000, 100, m, Access::Execute));
    }

    #[test]
    fn group_class_matches_egid_or_supplementary_without_falling_through() {
        let mut member = Credentials::new(ROOT, ROOT).unwrap();
        member.setgroups(&[300]).unwrap();
        member.setresgid(100, 100, 100).unwrap();
        member.setuid(2000).unwrap();

        // Group bits grant read to a supplementary-group member.
        assert!(may_access(&member, 1000, 300, mode(0o040), Access::Read));
        assert!(!may_access(&member, 1000, 300, mode(0o040), Access::Write));
        // Other bits grant read, but the group class was chosen and denies it.
        assert!(!may_access(&member, 1000, 300, mode(0o007), Access::Read));
    }

    #[test]
    fn other_class_applies_to_unrelated_callers() {
        // The caller is uid 1000, gid 100. The file is owned by uid 2000, gid 300.
        let cred = gids(100, 100, 100);
        let m = mode(0o604);
        assert!(may_access(&cred, 2000, 300, m, Access::Read));
        assert!(!may_access(&cred, 2000, 300, m, Access::Write));
        assert!(!may_access(&cred, 2000, 300, m, Access::Execute));
    }

    #[test]
    fn group_check_ignores_saved_gid() {
        // The saved GID is 300, but only the effective GID counts for access.
        // Counting it would select the group class and grant read.
        let cred = gids(100, 100, 300);
        assert!(!may_access(&cred, 2000, 300, mode(0o040), Access::Read));
    }

    #[test]
    fn sticky_directory_allows_only_entry_owner_dir_owner_or_root() {
        let sticky = mode(0o1777);
        let owner_of_entry = uids(1000, 1000, 1000);
        assert!(may_unlink_in_sticky_dir(
            &owner_of_entry,
            sticky,
            3000,
            1000
        ));

        let owner_of_dir = uids(1000, 1000, 1000);
        assert!(may_unlink_in_sticky_dir(&owner_of_dir, sticky, 1000, 2000));

        let stranger = uids(1000, 1000, 1000);
        assert!(!may_unlink_in_sticky_dir(&stranger, sticky, 3000, 2000));

        let root = Credentials::new(ROOT, ROOT).unwrap();
        assert!(may_unlink_in_sticky_dir(&root, sticky, 3000, 2000));
    }

    #[test]
    fn non_sticky_directory_does_not_restrict_unlink() {
        let stranger = uids(1000, 1000, 1000);
        assert!(may_unlink_in_sticky_dir(
            &stranger,
            mode(0o0777),
            3000,
            2000
        ));
    }

    #[test]
    fn exec_applies_setuid_and_setgid_and_saves_effective_ids() {
        let mut cred = Credentials::new(ROOT, 100).unwrap();
        cred.setgroups(&[7]).unwrap();
        cred.setuid(1000).unwrap();

        exec_transition(&mut cred, ROOT, 50, mode(0o6755), false).unwrap();
        assert_eq!([cred.ruid(), cred.euid(), cred.suid()], [1000, ROOT, ROOT]);
        assert_eq!([cred.rgid(), cred.egid(), cred.sgid()], [100, 50, 50]);
        assert_eq!(cred.groups(), &[7]);
    }

    #[test]
    fn exec_with_nosuid_ignores_setid_bits_but_still_saves_effective() {
        let mut cred = uids(1000, 1000, 2000);
        exec_transition(&mut cred, ROOT, ROOT, mode(0o6755), true).unwrap();
        assert_eq!([cred.euid(), cred.suid()], [1000, 1000]);
        assert_eq!([cred.egid(), cred.sgid()], [0, 0]);
    }

    #[test]
    fn exec_without_setid_bits_resets_saved_to_effective() {
        let mut cred = uids(1000, 1000, 2000);
        exec_transition(&mut cred, ROOT, ROOT, mode(0o755), false).unwrap();
        assert_eq!(cred.euid(), 1000);
        assert_eq!(cred.suid(), 1000);
    }

    #[test]
    fn exec_refuses_reserved_owner_without_changing_state() {
        let mut cred = uids(1000, 1000, 1000);
        let before = cred;
        assert_eq!(
            exec_transition(&mut cred, UNCHANGED, ROOT, mode(0o4755), false),
            Err(Error::InvalidInput)
        );
        assert_eq!(cred, before);
    }
}
