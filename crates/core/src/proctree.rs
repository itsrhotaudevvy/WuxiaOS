//! POSIX process hierarchy and `waitpid` semantics.
//!
//! The tree records which process forked which, each process's process group,
//! and whether a process is still running or is a zombie waiting for its parent
//! to reap its exit status. Pid 1 is init: it is always present, it never exits,
//! and it adopts the children of any process that exits.
//!
//! This module models bookkeeping only. Signal delivery, sessions and the
//! address-space copy performed by `fork` belong to the kernel. A `wait` that
//! would block reports `WouldBlock`, and the scheduler retries it, the same
//! convention the pipe model uses.

use crate::signal::Signal;
use crate::{Error, Result};

/// Process identifier. Zero never names a live process.
pub type Pid = u32;

/// The init process: always present, parent of orphans, and never exits.
pub const INIT_PID: Pid = 1;

/// First pid handed out by `fork`.
pub const FIRST_PID: Pid = 2;

/// Largest pid handed out before allocation wraps back to `FIRST_PID`.
pub const PID_MAX: Pid = 32_767;

/// Parent recorded for init, which has none.
const NO_PARENT: Pid = 0;

/// A termination status encoded as `waitpid(2)` reports it on Linux x86_64.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitStatus(u32);

impl WaitStatus {
    /// Normal exit with `code`. Only the low eight bits of the code are kept.
    pub const fn exited(code: u32) -> Self {
        Self((code & 0xff) << 8)
    }

    /// Termination by `signal`, stored in the low seven bits.
    pub const fn signaled(signal: Signal) -> Self {
        Self(signal.number() & 0x7f)
    }

    /// The raw status word, as written through a user `wstatus` pointer.
    pub const fn raw(self) -> u32 {
        self.0
    }
}

/// Lifecycle of a process entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryState {
    /// The process has not exited.
    Running,
    /// The process has exited. Its pid stays reserved until a parent reaps it.
    Zombie(WaitStatus),
}

/// One process as the tree records it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Entry {
    pid: Pid,
    parent: Pid,
    pgid: Pid,
    state: EntryState,
}

impl Entry {
    /// The process identifier.
    pub const fn pid(self) -> Pid {
        self.pid
    }

    /// The parent's pid. Init records zero.
    pub const fn parent(self) -> Pid {
        self.parent
    }

    /// The process group identifier.
    pub const fn pgid(self) -> Pid {
        self.pgid
    }

    /// Whether the process is running or a zombie.
    pub const fn state(self) -> EntryState {
        self.state
    }
}

/// Which children a `wait` call may reap, as in `waitpid(2)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitSelector {
    /// Any child (`-1`).
    Any,
    /// The child with this pid.
    Pid(Pid),
    /// Any child whose process group is this one.
    Group(Pid),
}

impl WaitSelector {
    fn matches(self, entry: &Entry) -> bool {
        match self {
            Self::Any => true,
            Self::Pid(pid) => entry.pid == pid,
            Self::Group(pgid) => entry.pgid == pgid,
        }
    }
}

/// Outcome of a `wait` call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitResult {
    /// A zombie child was reaped. Its slot and pid are free again.
    Reaped {
        /// Pid of the reaped child.
        pid: Pid,
        /// Termination status the child left behind.
        status: WaitStatus,
    },
    /// A matching child exists but has not exited. Retry after it does.
    WouldBlock,
    /// No child matches the selector (`ECHILD`).
    NoChildren,
}

/// A fixed-capacity process hierarchy with `N` slots, init included.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessTree<const N: usize> {
    slots: [Option<Entry>; N],
    next_pid: Pid,
}

impl<const N: usize> ProcessTree<N> {
    /// Create a tree that holds only init. A table with no room for init is
    /// rejected with `TableFull`.
    pub fn new() -> Result<Self> {
        if N == 0 {
            return Err(Error::TableFull);
        }
        let mut slots = [None; N];
        slots[0] = Some(Entry {
            pid: INIT_PID,
            parent: NO_PARENT,
            pgid: INIT_PID,
            state: EntryState::Running,
        });
        Ok(Self {
            slots,
            next_pid: FIRST_PID,
        })
    }

    /// The entry for `pid`, whether it is running or a zombie.
    pub fn entry(&self, pid: Pid) -> Option<Entry> {
        self.get(pid).copied()
    }

    /// Create a running child of `parent`. The child joins the parent's process
    /// group. Fails with `NotFound` for an unknown parent, `InvalidState` for a
    /// zombie parent, and `TableFull` when no slot or pid is free.
    pub fn fork(&mut self, parent: Pid) -> Result<Pid> {
        let pgid = self.running_mut(parent)?.pgid;
        let slot = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(Error::TableFull)?;
        let pid = self.allocate_pid()?;
        self.slots[slot] = Some(Entry {
            pid,
            parent,
            pgid,
            state: EntryState::Running,
        });
        Ok(pid)
    }

    /// Terminate `pid` with `status`, turning it into a zombie. Its children
    /// are reparented to init. Init itself cannot exit, and a process exits
    /// exactly once.
    pub fn exit(&mut self, pid: Pid, status: WaitStatus) -> Result<()> {
        if pid == INIT_PID {
            return Err(Error::InvalidState);
        }
        self.running_mut(pid)?.state = EntryState::Zombie(status);
        for child in self.slots.iter_mut().flatten() {
            if child.parent == pid {
                child.parent = INIT_PID;
            }
        }
        Ok(())
    }

    /// Reap one zombie child of `parent` that matches `selector`, or report why
    /// none can be reaped. When several zombies match, the lowest pid goes
    /// first. Reaping frees the slot and the pid's reservation.
    ///
    /// `nohang` does not change the outcome in this model: both forms report
    /// `WouldBlock`. The kernel uses the flag to choose between returning zero
    /// to userspace and parking the calling thread.
    pub fn wait(&mut self, parent: Pid, selector: WaitSelector, nohang: bool) -> WaitResult {
        let _ = nohang;
        let mut matched = false;
        let mut oldest_zombie: Option<(Pid, WaitStatus)> = None;
        for child in self.slots.iter().flatten() {
            if child.parent != parent || !selector.matches(child) {
                continue;
            }
            matched = true;
            if let EntryState::Zombie(status) = child.state
                && oldest_zombie.is_none_or(|(oldest, _)| child.pid < oldest)
            {
                oldest_zombie = Some((child.pid, status));
            }
        }
        match oldest_zombie {
            Some((pid, status)) => {
                if let Some(index) = self
                    .slots
                    .iter()
                    .position(|slot| matches!(slot, Some(entry) if entry.pid == pid))
                {
                    self.slots[index] = None;
                }
                WaitResult::Reaped { pid, status }
            }
            None if matched => WaitResult::WouldBlock,
            None => WaitResult::NoChildren,
        }
    }

    /// Move `target` into process group `pgid` on behalf of `caller`. Zero
    /// stands for the caller as `target` and for the target's own pid as
    /// `pgid`.
    ///
    /// The target must be the caller or one of its children, or the call fails
    /// with `NotFound`. The group must either be the target's own pid, which
    /// creates a new group, or already have members, otherwise the call fails
    /// with `PermissionDenied`. A zombie target fails with `InvalidState`.
    pub fn setpgid(&mut self, caller: Pid, target: Pid, pgid: Pid) -> Result<()> {
        let target = if target == 0 { caller } else { target };
        let pgid = if pgid == 0 { target } else { pgid };
        if target != caller {
            let child = self.get(target).ok_or(Error::NotFound)?;
            if child.parent != caller {
                return Err(Error::NotFound);
            }
        }
        let group_exists =
            pgid == target || self.slots.iter().flatten().any(|entry| entry.pgid == pgid);
        if !group_exists {
            return Err(Error::PermissionDenied);
        }
        self.running_mut(target)?.pgid = pgid;
        Ok(())
    }

    fn get(&self, pid: Pid) -> Option<&Entry> {
        self.slots.iter().flatten().find(|entry| entry.pid == pid)
    }

    fn get_mut(&mut self, pid: Pid) -> Option<&mut Entry> {
        self.slots
            .iter_mut()
            .flatten()
            .find(|entry| entry.pid == pid)
    }

    fn running_mut(&mut self, pid: Pid) -> Result<&mut Entry> {
        let entry = self.get_mut(pid).ok_or(Error::NotFound)?;
        if entry.state == EntryState::Running {
            Ok(entry)
        } else {
            Err(Error::InvalidState)
        }
    }

    fn pid_in_use(&self, pid: Pid) -> bool {
        self.get(pid).is_some()
    }

    /// Hand out the next free pid at or after `next_pid`, wrapping after
    /// `PID_MAX`. At most `N` pids are in use, so a free one turns up within
    /// `N + 1` candidates when one exists at all.
    fn allocate_pid(&mut self) -> Result<Pid> {
        let mut candidate = self.next_pid;
        for _ in 0..=N {
            if !self.pid_in_use(candidate) {
                self.next_pid = successor(candidate);
                return Ok(candidate);
            }
            candidate = successor(candidate);
        }
        Err(Error::TableFull)
    }
}

/// The pid after `pid` in the allocation cycle.
const fn successor(pid: Pid) -> Pid {
    if pid >= PID_MAX { FIRST_PID } else { pid + 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Tree = ProcessTree<8>;

    fn tree() -> Tree {
        Tree::new().unwrap()
    }

    fn state_of(tree: &Tree, pid: Pid) -> EntryState {
        tree.entry(pid).unwrap().state()
    }

    #[test]
    fn a_new_tree_holds_only_init() {
        let tree = tree();
        let init = tree.entry(INIT_PID).unwrap();
        assert_eq!(init.parent(), NO_PARENT);
        assert_eq!(init.pgid(), INIT_PID);
        assert_eq!(init.state(), EntryState::Running);
        assert!(tree.entry(FIRST_PID).is_none());
    }

    #[test]
    fn a_table_without_room_for_init_is_rejected() {
        assert_eq!(ProcessTree::<0>::new(), Err(Error::TableFull));
    }

    #[test]
    fn fork_hands_out_pids_from_two_in_order() {
        let mut tree = tree();
        assert_eq!(tree.fork(INIT_PID), Ok(2));
        assert_eq!(tree.fork(INIT_PID), Ok(3));
        assert_eq!(tree.fork(2), Ok(4));
        assert_eq!(tree.entry(4).unwrap().parent(), 2);
    }

    #[test]
    fn a_child_joins_its_parents_process_group() {
        let mut tree = tree();
        let child = tree.fork(INIT_PID).unwrap();
        tree.setpgid(INIT_PID, child, child).unwrap();
        let grandchild = tree.fork(child).unwrap();
        assert_eq!(tree.entry(grandchild).unwrap().pgid(), child);
    }

    #[test]
    fn fork_requires_a_running_parent() {
        let mut tree = tree();
        assert_eq!(tree.fork(99), Err(Error::NotFound));
        let child = tree.fork(INIT_PID).unwrap();
        tree.exit(child, WaitStatus::exited(0)).unwrap();
        assert_eq!(tree.fork(child), Err(Error::InvalidState));
    }

    #[test]
    fn a_full_table_refuses_fork_without_consuming_a_pid() {
        let mut tree = ProcessTree::<3>::new().unwrap();
        let a = tree.fork(INIT_PID).unwrap();
        let b = tree.fork(INIT_PID).unwrap();
        assert_eq!((a, b), (2, 3));
        assert_eq!(tree.fork(INIT_PID), Err(Error::TableFull));
        tree.exit(a, WaitStatus::exited(0)).unwrap();
        assert_eq!(tree.fork(INIT_PID), Err(Error::TableFull));
        assert_eq!(
            tree.wait(INIT_PID, WaitSelector::Pid(a), false),
            WaitResult::Reaped {
                pid: a,
                status: WaitStatus::exited(0),
            }
        );
        assert_eq!(tree.fork(INIT_PID), Ok(4));
    }

    #[test]
    fn pids_wrap_around_and_skip_pids_in_use() {
        let mut tree = tree();
        let live = tree.fork(INIT_PID).unwrap();
        assert_eq!(live, 2);
        tree.next_pid = PID_MAX;
        assert_eq!(tree.fork(INIT_PID), Ok(PID_MAX));
        assert_eq!(tree.fork(INIT_PID), Ok(3));
    }

    #[test]
    fn a_zombie_keeps_its_pid_reserved_until_reaped() {
        let mut tree = tree();
        let child = tree.fork(INIT_PID).unwrap();
        tree.exit(child, WaitStatus::exited(0)).unwrap();
        tree.next_pid = child;
        assert_eq!(tree.fork(INIT_PID), Ok(3));
        tree.wait(INIT_PID, WaitSelector::Pid(child), false);
        tree.next_pid = child;
        assert_eq!(tree.fork(INIT_PID), Ok(child));
    }

    #[test]
    fn exit_records_a_zombie_and_only_succeeds_once() {
        let mut tree = tree();
        let child = tree.fork(INIT_PID).unwrap();
        tree.exit(child, WaitStatus::exited(1)).unwrap();
        assert_eq!(
            state_of(&tree, child),
            EntryState::Zombie(WaitStatus::exited(1))
        );
        assert_eq!(
            tree.exit(child, WaitStatus::exited(2)),
            Err(Error::InvalidState)
        );
        assert_eq!(
            state_of(&tree, child),
            EntryState::Zombie(WaitStatus::exited(1))
        );
        assert_eq!(tree.exit(77, WaitStatus::exited(0)), Err(Error::NotFound));
    }

    #[test]
    fn init_never_exits() {
        let mut tree = tree();
        assert_eq!(
            tree.exit(INIT_PID, WaitStatus::exited(0)),
            Err(Error::InvalidState)
        );
        assert_eq!(state_of(&tree, INIT_PID), EntryState::Running);
    }

    #[test]
    fn orphans_are_reparented_to_init() {
        let mut tree = tree();
        let parent = tree.fork(INIT_PID).unwrap();
        let running_child = tree.fork(parent).unwrap();
        let zombie_child = tree.fork(parent).unwrap();
        tree.exit(zombie_child, WaitStatus::exited(0)).unwrap();
        let sibling = tree.fork(INIT_PID).unwrap();
        let cousin = tree.fork(sibling).unwrap();

        tree.exit(parent, WaitStatus::exited(0)).unwrap();

        assert_eq!(tree.entry(running_child).unwrap().parent(), INIT_PID);
        assert_eq!(tree.entry(zombie_child).unwrap().parent(), INIT_PID);
        assert_eq!(tree.entry(cousin).unwrap().parent(), sibling);
    }

    #[test]
    fn init_reaps_the_zombies_it_inherits_lowest_pid_first() {
        let mut tree = tree();
        let parent = tree.fork(INIT_PID).unwrap();
        let child = tree.fork(parent).unwrap();
        tree.exit(child, WaitStatus::exited(4)).unwrap();
        tree.exit(parent, WaitStatus::exited(0)).unwrap();

        assert_eq!(
            tree.wait(INIT_PID, WaitSelector::Any, false),
            WaitResult::Reaped {
                pid: parent,
                status: WaitStatus::exited(0),
            }
        );
        assert_eq!(
            tree.wait(INIT_PID, WaitSelector::Any, false),
            WaitResult::Reaped {
                pid: child,
                status: WaitStatus::exited(4),
            }
        );
        assert_eq!(
            tree.wait(INIT_PID, WaitSelector::Any, false),
            WaitResult::NoChildren
        );
    }

    #[test]
    fn wait_reaps_a_zombie_and_frees_its_slot() {
        let mut tree = ProcessTree::<2>::new().unwrap();
        let child = tree.fork(INIT_PID).unwrap();
        tree.exit(child, WaitStatus::exited(5)).unwrap();
        assert_eq!(
            tree.wait(INIT_PID, WaitSelector::Any, false),
            WaitResult::Reaped {
                pid: child,
                status: WaitStatus::exited(5),
            }
        );
        assert!(tree.entry(child).is_none());
        assert!(tree.fork(INIT_PID).is_ok());
    }

    #[test]
    fn wait_reports_would_block_while_a_matching_child_runs() {
        let mut tree = tree();
        tree.fork(INIT_PID).unwrap();
        assert_eq!(
            tree.wait(INIT_PID, WaitSelector::Any, true),
            WaitResult::WouldBlock
        );
        assert_eq!(
            tree.wait(INIT_PID, WaitSelector::Any, false),
            WaitResult::WouldBlock
        );
    }

    #[test]
    fn wait_reports_echild_without_matching_children() {
        let mut tree = tree();
        assert_eq!(
            tree.wait(INIT_PID, WaitSelector::Any, false),
            WaitResult::NoChildren
        );
        let child = tree.fork(INIT_PID).unwrap();
        assert_eq!(
            tree.wait(child, WaitSelector::Any, false),
            WaitResult::NoChildren
        );
        assert_eq!(
            tree.wait(42, WaitSelector::Any, false),
            WaitResult::NoChildren
        );
    }

    #[test]
    fn a_grandparent_cannot_reap_a_grandchild() {
        let mut tree = tree();
        let child = tree.fork(INIT_PID).unwrap();
        let grandchild = tree.fork(child).unwrap();
        tree.exit(grandchild, WaitStatus::exited(0)).unwrap();
        assert_eq!(
            tree.wait(INIT_PID, WaitSelector::Pid(grandchild), false),
            WaitResult::NoChildren
        );
        assert_eq!(
            tree.wait(INIT_PID, WaitSelector::Any, false),
            WaitResult::WouldBlock
        );
    }

    #[test]
    fn pid_selector_matches_only_that_child() {
        let mut tree = tree();
        let a = tree.fork(INIT_PID).unwrap();
        let b = tree.fork(INIT_PID).unwrap();
        let grandchild = tree.fork(a).unwrap();
        tree.exit(b, WaitStatus::exited(9)).unwrap();
        assert_eq!(
            tree.wait(INIT_PID, WaitSelector::Pid(a), false),
            WaitResult::WouldBlock
        );
        assert_eq!(
            tree.wait(INIT_PID, WaitSelector::Pid(grandchild), false),
            WaitResult::NoChildren
        );
        assert_eq!(
            tree.wait(INIT_PID, WaitSelector::Pid(b), false),
            WaitResult::Reaped {
                pid: b,
                status: WaitStatus::exited(9),
            }
        );
        assert_eq!(
            tree.wait(INIT_PID, WaitSelector::Pid(b), false),
            WaitResult::NoChildren
        );
    }

    #[test]
    fn group_selector_matches_by_process_group() {
        let mut tree = tree();
        let a = tree.fork(INIT_PID).unwrap();
        let b = tree.fork(INIT_PID).unwrap();
        tree.setpgid(INIT_PID, b, b).unwrap();
        tree.exit(a, WaitStatus::exited(1)).unwrap();
        tree.exit(b, WaitStatus::exited(2)).unwrap();
        assert_eq!(
            tree.wait(INIT_PID, WaitSelector::Group(50), false),
            WaitResult::NoChildren
        );
        assert_eq!(
            tree.wait(INIT_PID, WaitSelector::Group(b), false),
            WaitResult::Reaped {
                pid: b,
                status: WaitStatus::exited(2),
            }
        );
        assert_eq!(
            tree.wait(INIT_PID, WaitSelector::Group(INIT_PID), false),
            WaitResult::Reaped {
                pid: a,
                status: WaitStatus::exited(1),
            }
        );
    }

    #[test]
    fn setpgid_accepts_only_self_and_children() {
        let mut tree = tree();
        let child = tree.fork(INIT_PID).unwrap();
        let grandchild = tree.fork(child).unwrap();
        assert_eq!(tree.setpgid(child, 0, 0), Ok(()));
        assert_eq!(tree.entry(child).unwrap().pgid(), child);
        assert_eq!(
            tree.setpgid(INIT_PID, grandchild, grandchild),
            Err(Error::NotFound)
        );
        assert_eq!(tree.setpgid(grandchild, child, child), Err(Error::NotFound));
        assert_eq!(tree.setpgid(INIT_PID, 77, 77), Err(Error::NotFound));
    }

    #[test]
    fn setpgid_needs_a_new_leader_or_an_existing_group() {
        let mut tree = tree();
        let a = tree.fork(INIT_PID).unwrap();
        let b = tree.fork(INIT_PID).unwrap();
        assert_eq!(tree.setpgid(INIT_PID, a, 99), Err(Error::PermissionDenied));
        tree.setpgid(INIT_PID, a, a).unwrap();
        tree.setpgid(INIT_PID, b, a).unwrap();
        assert_eq!(tree.entry(b).unwrap().pgid(), a);
    }

    #[test]
    fn setpgid_rejects_a_zombie_target() {
        let mut tree = tree();
        let child = tree.fork(INIT_PID).unwrap();
        tree.exit(child, WaitStatus::exited(0)).unwrap();
        assert_eq!(
            tree.setpgid(INIT_PID, child, child),
            Err(Error::InvalidState)
        );
    }

    #[test]
    fn wait_status_uses_the_linux_encoding() {
        assert_eq!(WaitStatus::exited(0).raw(), 0);
        assert_eq!(WaitStatus::exited(3).raw(), 0x300);
        assert_eq!(WaitStatus::exited(0x1ff).raw(), 0xff00);
        assert_eq!(WaitStatus::signaled(Signal::SIGKILL).raw(), 9);
        assert_eq!(WaitStatus::signaled(Signal::SIGTERM).raw(), 15);
    }

    #[test]
    fn a_signalled_child_reports_its_signal_on_reap() {
        let mut tree = tree();
        let child = tree.fork(INIT_PID).unwrap();
        tree.exit(child, WaitStatus::signaled(Signal::SIGTERM))
            .unwrap();
        assert_eq!(
            tree.wait(INIT_PID, WaitSelector::Any, true),
            WaitResult::Reaped {
                pid: child,
                status: WaitStatus::signaled(Signal::SIGTERM),
            }
        );
    }
}
