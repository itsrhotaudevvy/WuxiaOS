//! Copy-on-write bookkeeping for `fork`.
//!
//! A fork lets the child share every present leaf with its parent. A writable
//! private leaf is downgraded to read-only in both address spaces and tagged
//! with [`COW`]. The first write from either side faults, and the fault is
//! resolved by copying the frame, or by reclaiming it in place when the writer
//! is the last owner. Read-only and executable leaves are shared unchanged, and
//! no entry this module produces is ever both writable and executable.
//!
//! Entries are raw 64-bit x86_64 leaf entries, as encoded by
//! [`crate::paging::leaf`]. Frame numbers are physical addresses divided by
//! [`PAGE_SIZE`]. Per leaf, the kernel follows this protocol:
//!
//! 1. Call [`fork_leaf`], install both returned entries, and call
//!    [`FrameRefs::share`] once for the child's new reference.
//! 2. On a write fault, call [`resolve_write_fault`] with the frame's count.
//! 3. For [`FaultAction::CopyThenMapWritable`], copy into a fresh frame,
//!    `share` that frame, `release` the old one, and install
//!    [`restore_writable`] of the entry retargeted to the copy. For
//!    [`FaultAction::ReuseInPlace`], install [`restore_writable`] of the entry.
//! 4. On exit, `release` each frame. [`Release::Freed`] returns it to the pool.

use crate::paging::{is_executable, is_present, is_writable};
use crate::{Error, Result};

/// Software-defined leaf bit marking a read-only page that becomes writable on
/// a copy-on-write fault.
///
/// Bit 9 is one of the three bits (9 through 11) that x86_64 leaves to
/// software; the MMU ignores it. A page carries this bit only while it is
/// read-only because of a fork. Executable pages never carry it.
pub const COW: u64 = 1 << 9;

/// Hardware write-permission bit of a leaf entry, matching `paging.rs`.
const WRITABLE: u64 = 1 << 1;

/// Outcome of dropping one reference to a frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Release {
    /// The last reference was dropped, so the frame may return to the pool.
    Freed,
    /// Other references remain, so the frame must stay allocated.
    StillShared,
}

/// Reference counts for the frames `[first_frame, first_frame + N)`.
///
/// Frames outside that range are rejected with [`Error::InvalidInput`], so
/// bookkeeping cannot silently spread into memory it does not own.
#[derive(Clone, Copy, Debug)]
pub struct FrameRefs<const N: usize> {
    first_frame: u64,
    counts: [u32; N],
}

impl<const N: usize> FrameRefs<N> {
    /// Track `N` consecutive frame numbers starting at `first_frame`, all with
    /// a count of zero.
    pub const fn new(first_frame: u64) -> Self {
        Self {
            first_frame,
            counts: [0; N],
        }
    }

    /// Add one reference to `frame` and return the new count.
    ///
    /// A count of zero means the frame is unowned, so the first `share` makes
    /// it one. The increment is checked and fails with [`Error::OutOfRange`]
    /// rather than wrapping.
    pub fn share(&mut self, frame: u64) -> Result<u32> {
        let slot = self.slot(frame)?;
        let next = self.counts[slot].checked_add(1).ok_or(Error::OutOfRange)?;
        self.counts[slot] = next;
        Ok(next)
    }

    /// Drop one reference to `frame`.
    ///
    /// Releasing a frame whose count is already zero fails with
    /// [`Error::InvalidState`] and leaves the count at zero, so a double release
    /// can never underflow.
    pub fn release(&mut self, frame: u64) -> Result<Release> {
        let slot = self.slot(frame)?;
        match self.counts[slot] {
            0 => Err(Error::InvalidState),
            1 => {
                self.counts[slot] = 0;
                Ok(Release::Freed)
            }
            remaining => {
                self.counts[slot] = remaining - 1;
                Ok(Release::StillShared)
            }
        }
    }

    /// Current number of references to `frame`.
    pub fn count(&self, frame: u64) -> Result<u32> {
        Ok(self.counts[self.slot(frame)?])
    }

    fn slot(&self, frame: u64) -> Result<usize> {
        let offset = frame
            .checked_sub(self.first_frame)
            .ok_or(Error::InvalidInput)?;
        let slot = usize::try_from(offset).map_err(|_| Error::InvalidInput)?;
        if slot < N {
            Ok(slot)
        } else {
            Err(Error::InvalidInput)
        }
    }
}

/// Entries for the parent and the child after a fork shares a leaf.
///
/// A writable private page becomes read-only and [`COW`] in both entries.
/// A read-only page is returned unchanged. An executable page is never
/// writable, so it is shared without [`COW`], and any write permission in the
/// input is dropped. An absent entry is returned unchanged, so no mapping is
/// created for it. Address bits pass through untouched, so both sides keep
/// pointing at the same frame.
pub const fn fork_leaf(entry: u64) -> (u64, u64) {
    if !is_present(entry) {
        (entry, entry)
    } else if is_executable(entry) {
        let shared = entry & !(WRITABLE | COW);
        (shared, shared)
    } else if is_writable(entry) {
        let cow = (entry & !WRITABLE) | COW;
        (cow, cow)
    } else {
        (entry, entry)
    }
}

/// What the kernel must do to resolve a write fault.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultAction {
    /// The frame is shared. Copy it into a fresh frame, map that writable, and
    /// release the old reference.
    CopyThenMapWritable,
    /// The writer is the last owner. Make the existing frame writable again
    /// without copying.
    ReuseInPlace,
    /// The page is not copy-on-write, so the fault is a real protection fault.
    NotCow,
}

/// Decide how to resolve a write to `entry` when its frame has `refcount`
/// references.
///
/// Only a present, read-only, non-executable entry with [`COW`] set is
/// resolvable. A `refcount` of zero means the bookkeeping has lost a mapped
/// frame. That fault is reported as [`FaultAction::NotCow`] rather than
/// guessed at.
pub const fn resolve_write_fault(entry: u64, refcount: u32) -> FaultAction {
    let is_cow =
        is_present(entry) && (entry & COW) != 0 && !is_writable(entry) && !is_executable(entry);
    if !is_cow {
        return FaultAction::NotCow;
    }
    match refcount {
        0 => FaultAction::NotCow,
        1 => FaultAction::ReuseInPlace,
        _ => FaultAction::CopyThenMapWritable,
    }
}

/// The entry a faulting writer receives once its page is resolved: writable,
/// private, and no longer [`COW`].
///
/// Absent entries fail with [`Error::InvalidState`] and executable entries with
/// [`Error::PermissionDenied`], so W^X is enforced at the point where write
/// permission is granted.
pub const fn restore_writable(entry: u64) -> Result<u64> {
    if !is_present(entry) {
        return Err(Error::InvalidState);
    }
    if is_executable(entry) {
        return Err(Error::PermissionDenied);
    }
    Ok((entry | WRITABLE) & !COW)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paging::{PAGE_SIZE, PagePermissions, is_user, leaf, physical_address};

    const PRESENT: u64 = 1 << 0;
    const USER: u64 = 1 << 2;
    const NO_EXECUTE: u64 = 1 << 63;
    const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
    const VA: u64 = 0x0040_0000;
    const FIRST: u64 = 0x100;

    fn addr(frame: u64) -> u64 {
        frame * PAGE_SIZE
    }

    fn retarget(entry: u64, frame: u64) -> u64 {
        (entry & !ADDRESS_MASK) | addr(frame)
    }

    fn assert_w_xor_x(entry: u64) {
        assert!(
            !(is_writable(entry) && is_executable(entry)),
            "W^X violated by {entry:#x}"
        );
    }

    /// Kernel side of a write fault on a COW entry. Returns the private
    /// writable entry the faulting process should now use.
    fn write_fault(refs: &mut FrameRefs<8>, entry: u64, spare_frame: u64) -> u64 {
        let frame = physical_address(entry) / PAGE_SIZE;
        match resolve_write_fault(entry, refs.count(frame).unwrap()) {
            FaultAction::CopyThenMapWritable => {
                assert_eq!(refs.share(spare_frame), Ok(1));
                assert_eq!(refs.release(frame), Ok(Release::StillShared));
                restore_writable(retarget(entry, spare_frame)).unwrap()
            }
            FaultAction::ReuseInPlace => restore_writable(entry).unwrap(),
            FaultAction::NotCow => panic!("a write to a copy-on-write page faulted"),
        }
    }

    /// Parent and child entries after the parent's private page at `frame` is
    /// forked. The frame is shared once for the child.
    fn forked(refs: &mut FrameRefs<8>, frame: u64) -> (u64, u64) {
        let original = leaf(VA, addr(frame), PagePermissions::USER_READ_WRITE).unwrap();
        assert_eq!(refs.share(frame), Ok(1));
        let (parent, child) = fork_leaf(original);
        assert_eq!(refs.share(frame), Ok(2));
        (parent, child)
    }

    #[test]
    fn share_counts_from_zero_and_rejects_untracked_frames() {
        let mut refs = FrameRefs::<4>::new(FIRST);
        assert_eq!(refs.count(FIRST), Ok(0));
        assert_eq!(refs.share(FIRST), Ok(1));
        assert_eq!(refs.share(FIRST), Ok(2));
        assert_eq!(refs.count(FIRST), Ok(2));
        assert_eq!(refs.share(FIRST + 4), Err(Error::InvalidInput));
        assert_eq!(refs.share(FIRST - 1), Err(Error::InvalidInput));
        assert_eq!(refs.count(FIRST + 4), Err(Error::InvalidInput));
        assert_eq!(refs.release(FIRST - 1), Err(Error::InvalidInput));
        assert_eq!(refs.count(FIRST + 3), Ok(0));
    }

    #[test]
    fn release_reports_freed_only_for_the_last_reference() {
        let mut refs = FrameRefs::<2>::new(FIRST);
        refs.share(FIRST).unwrap();
        refs.share(FIRST).unwrap();
        assert_eq!(refs.release(FIRST), Ok(Release::StillShared));
        assert_eq!(refs.count(FIRST), Ok(1));
        assert_eq!(refs.release(FIRST), Ok(Release::Freed));
        assert_eq!(refs.count(FIRST), Ok(0));
    }

    #[test]
    fn releasing_an_unowned_frame_is_an_error_that_cannot_underflow() {
        let mut refs = FrameRefs::<2>::new(FIRST);
        assert_eq!(refs.release(FIRST), Err(Error::InvalidState));
        assert_eq!(refs.count(FIRST), Ok(0));

        refs.share(FIRST).unwrap();
        assert_eq!(refs.release(FIRST), Ok(Release::Freed));
        assert_eq!(refs.release(FIRST), Err(Error::InvalidState));
        assert_eq!(refs.count(FIRST), Ok(0));
    }

    #[test]
    fn increments_are_checked() {
        let mut refs = FrameRefs::<1>::new(FIRST);
        refs.counts[0] = u32::MAX;
        assert_eq!(refs.share(FIRST), Err(Error::OutOfRange));
        assert_eq!(refs.count(FIRST), Ok(u32::MAX));
    }

    #[test]
    fn writable_private_page_becomes_read_only_cow_in_both_processes() {
        let writable = leaf(VA, addr(FIRST), PagePermissions::USER_READ_WRITE).unwrap();
        let (parent, child) = fork_leaf(writable);
        assert_eq!(parent, child);
        assert!(!is_writable(parent));
        assert_ne!(parent & COW, 0);
        assert_eq!(physical_address(parent), addr(FIRST));
        assert!(is_user(parent));
        assert!(!is_executable(parent));
        assert_w_xor_x(parent);
    }

    #[test]
    fn read_only_pages_are_shared_unchanged() {
        let read_only = leaf(VA, addr(FIRST), PagePermissions::USER_READ_ONLY).unwrap();
        assert_eq!(fork_leaf(read_only), (read_only, read_only));

        let cow = read_only | COW;
        assert_eq!(fork_leaf(cow), (cow, cow));
    }

    #[test]
    fn executable_pages_are_never_made_writable() {
        let code = leaf(VA, addr(FIRST), PagePermissions::USER_CODE).unwrap();
        assert_eq!(fork_leaf(code), (code, code));
        assert_eq!(fork_leaf(code | COW), (code, code));

        // A writable and executable input is invalid. The fork must not carry
        // the write permission into either side.
        let (parent, child) = fork_leaf(code | WRITABLE);
        assert_eq!((parent, child), (code, code));
        assert_w_xor_x(parent);
    }

    #[test]
    fn absent_entries_are_not_turned_into_mappings() {
        assert_eq!(fork_leaf(0), (0, 0));
        let absent = addr(FIRST) | WRITABLE | USER;
        assert_eq!(fork_leaf(absent), (absent, absent));
    }

    #[test]
    fn a_shared_cow_page_is_copied_on_write() {
        let writable = leaf(VA, addr(FIRST), PagePermissions::USER_READ_WRITE).unwrap();
        let (cow, _) = fork_leaf(writable);
        assert_eq!(
            resolve_write_fault(cow, 2),
            FaultAction::CopyThenMapWritable
        );
        assert_eq!(
            resolve_write_fault(cow, 5),
            FaultAction::CopyThenMapWritable
        );
    }

    #[test]
    fn a_sole_owner_cow_page_is_reused_in_place() {
        let writable = leaf(VA, addr(FIRST), PagePermissions::USER_READ_WRITE).unwrap();
        let (cow, _) = fork_leaf(writable);
        assert_eq!(resolve_write_fault(cow, 1), FaultAction::ReuseInPlace);

        let restored = restore_writable(cow).unwrap();
        assert!(is_writable(restored));
        assert_eq!(restored & COW, 0);
        assert_eq!(physical_address(restored), addr(FIRST));
        assert!(is_user(restored));
        assert_w_xor_x(restored);
    }

    #[test]
    fn faults_on_ordinary_pages_are_protection_faults() {
        let read_only = leaf(VA, addr(FIRST), PagePermissions::USER_READ_ONLY).unwrap();
        let writable = leaf(VA, addr(FIRST), PagePermissions::USER_READ_WRITE).unwrap();
        let code = leaf(VA, addr(FIRST), PagePermissions::USER_CODE).unwrap();
        let (cow, _) = fork_leaf(writable);

        assert_eq!(resolve_write_fault(read_only, 2), FaultAction::NotCow);
        assert_eq!(resolve_write_fault(writable, 2), FaultAction::NotCow);
        assert_eq!(resolve_write_fault(code | COW, 2), FaultAction::NotCow);
        assert_eq!(resolve_write_fault(0, 2), FaultAction::NotCow);
        assert_eq!(resolve_write_fault(cow, 0), FaultAction::NotCow);

        assert_eq!(restore_writable(code), Err(Error::PermissionDenied));
        assert_eq!(restore_writable(0), Err(Error::InvalidState));
    }

    #[test]
    fn fork_then_parent_then_child_write_ends_with_exact_counts() {
        let (f, g) = (FIRST, FIRST + 1);
        let mut refs = FrameRefs::<8>::new(FIRST);
        let (mut parent, mut child) = forked(&mut refs, f);
        assert_eq!(refs.count(f), Ok(2));

        // F is shared, so the parent copies into G.
        parent = write_fault(&mut refs, parent, g);
        assert_eq!(physical_address(parent), addr(g));
        assert!(is_writable(parent));
        assert_eq!(refs.count(f), Ok(1));
        assert_eq!(refs.count(g), Ok(1));
        assert_w_xor_x(parent);

        // F now belongs to the child alone, so the child reuses it in place.
        child = write_fault(&mut refs, child, FIRST + 2);
        assert_eq!(physical_address(child), addr(f));
        assert!(is_writable(child));
        assert_eq!(refs.count(f), Ok(1));
        assert_eq!(refs.count(g), Ok(1));
        assert_w_xor_x(child);

        // Exit releases each frame, and the last reference frees it.
        assert_eq!(refs.release(f), Ok(Release::Freed));
        assert_eq!(refs.release(g), Ok(Release::Freed));
        assert_eq!(refs.count(f), Ok(0));
        assert_eq!(refs.count(g), Ok(0));
    }

    #[test]
    fn fork_then_child_then_parent_write_swaps_the_roles() {
        let (f, g) = (FIRST, FIRST + 1);
        let mut refs = FrameRefs::<8>::new(FIRST);
        let (mut parent, mut child) = forked(&mut refs, f);

        // The child copies into G, and the parent reuses F in place.
        child = write_fault(&mut refs, child, g);
        assert_eq!(physical_address(child), addr(g));
        assert_eq!(refs.count(f), Ok(1));
        assert_eq!(refs.count(g), Ok(1));

        parent = write_fault(&mut refs, parent, FIRST + 2);
        assert_eq!(physical_address(parent), addr(f));
        assert_eq!(refs.count(f), Ok(1));
        assert_eq!(refs.count(g), Ok(1));
        assert_w_xor_x(parent);
        assert_w_xor_x(child);

        assert_eq!(refs.release(f), Ok(Release::Freed));
        assert_eq!(refs.release(g), Ok(Release::Freed));
    }

    #[test]
    fn a_page_forked_twice_before_any_write_keeps_three_references() {
        let (a, b, c, d) = (FIRST, FIRST + 1, FIRST + 2, FIRST + 3);
        let mut refs = FrameRefs::<8>::new(FIRST);
        let (mut a_entry, mut b_entry) = forked(&mut refs, a);

        // A second fork of the still-COW page shares it again with C.
        let (a_after, mut c_entry) = fork_leaf(a_entry);
        assert_eq!(refs.share(a), Ok(3));
        assert_eq!(a_after, a_entry);
        assert_eq!(refs.count(a), Ok(3));

        c_entry = write_fault(&mut refs, c_entry, c);
        assert_eq!(refs.count(a), Ok(2));
        b_entry = write_fault(&mut refs, b_entry, b);
        assert_eq!(refs.count(a), Ok(1));
        a_entry = write_fault(&mut refs, a_entry, d);

        assert_eq!(physical_address(a_entry), addr(a));
        assert_eq!(physical_address(b_entry), addr(b));
        assert_eq!(physical_address(c_entry), addr(c));
        assert_eq!(refs.count(a), Ok(1));
        assert_eq!(refs.count(b), Ok(1));
        assert_eq!(refs.count(c), Ok(1));
        assert_eq!(refs.count(d), Ok(0));
        for entry in [a_entry, b_entry, c_entry] {
            assert!(is_writable(entry));
            assert_w_xor_x(entry);
        }
    }

    #[test]
    fn every_flag_combination_keeps_w_xor_x_and_consistent_faults() {
        for bits in 0u64..(1 << 5) {
            let mut entry = addr(FIRST);
            if bits & 1 != 0 {
                entry |= PRESENT;
            }
            if bits & 2 != 0 {
                entry |= WRITABLE;
            }
            if bits & 4 != 0 {
                entry |= USER;
            }
            if bits & 8 != 0 {
                entry |= NO_EXECUTE;
            }
            if bits & 16 != 0 {
                entry |= COW;
            }

            let (parent, child) = fork_leaf(entry);
            assert_eq!(parent, child);
            // Absent entries are not mappings, so W^X applies to present leaves only.
            if is_present(entry) {
                assert_w_xor_x(parent);
            }

            for refcount in 0..=3 {
                let action = resolve_write_fault(entry, refcount);
                if action == FaultAction::NotCow {
                    continue;
                }
                // Only a present, read-only, non-executable COW entry can be
                // resolved, and the result is writable and not executable.
                assert!(is_present(entry) && (entry & COW) != 0);
                assert!(!is_writable(entry) && !is_executable(entry));
                let restored = restore_writable(entry).unwrap();
                assert!(is_writable(restored));
                assert_w_xor_x(restored);
            }
        }
    }
}
