//! Per-process state: identity, personality, address space and exit status.

use crate::address_space::AddressSpace;
use crate::descriptor::DescriptorTable;
use crate::personality::Personality;
use crate::{Error, Result};

/// Identifier assigned to the first bootstrap process.
pub const FIRST_PROCESS_ID: u64 = 1;

/// Descriptor capacity reserved for each process.
pub const DESCRIPTOR_CAPACITY: usize = 16;

/// Lifecycle state of a process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessState {
    /// The process may run or be scheduled.
    Runnable,
    /// The process terminated with this status.
    Exited {
        /// Status reported to a future parent.
        code: u64,
    },
}

/// A process with its own address-space model.
#[derive(Clone, Copy, Debug)]
pub struct Process<const N: usize> {
    id: u64,
    personality: Personality,
    space: AddressSpace<N>,
    descriptors: DescriptorTable<DESCRIPTOR_CAPACITY>,
    state: ProcessState,
}

impl<const N: usize> Process<N> {
    /// Create a runnable process. Identifier zero is reserved and rejected.
    pub fn new(id: u64, personality: Personality) -> Result<Self> {
        if id == 0 {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            id,
            personality,
            space: AddressSpace::new(),
            descriptors: DescriptorTable::with_standard_streams(),
            state: ProcessState::Runnable,
        })
    }

    /// Return the process identifier.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Return the selected personality.
    pub fn personality(&self) -> Personality {
        self.personality
    }

    /// Borrow the process address space.
    pub fn space(&self) -> &AddressSpace<N> {
        &self.space
    }

    /// Mutably borrow the process address space.
    pub fn space_mut(&mut self) -> &mut AddressSpace<N> {
        &mut self.space
    }

    /// Borrow the process descriptor table.
    pub fn descriptors(&self) -> &DescriptorTable<DESCRIPTOR_CAPACITY> {
        &self.descriptors
    }

    /// Mutably borrow the process descriptor table.
    pub fn descriptors_mut(&mut self) -> &mut DescriptorTable<DESCRIPTOR_CAPACITY> {
        &mut self.descriptors
    }

    /// Return the current lifecycle state.
    pub fn state(&self) -> ProcessState {
        self.state
    }

    /// Whether the process may still run.
    pub fn is_runnable(&self) -> bool {
        matches!(self.state, ProcessState::Runnable)
    }

    /// Terminate the process, recording the status exactly once.
    pub fn exit(&mut self, code: u64) -> Result<()> {
        if !self.is_runnable() {
            return Err(Error::InvalidState);
        }
        self.state = ProcessState::Exited { code };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paging::PagePermissions;

    #[test]
    fn identifiers_must_be_nonzero() {
        assert!(Process::<1>::new(0, Personality::Posix).is_err());
        assert!(Process::<1>::new(FIRST_PROCESS_ID, Personality::Posix).is_ok());
    }

    #[test]
    fn a_process_exits_exactly_once() {
        let mut process = Process::<1>::new(FIRST_PROCESS_ID, Personality::Nt).unwrap();
        assert!(process.is_runnable());
        assert_eq!(process.exit(7), Ok(()));
        assert_eq!(process.state(), ProcessState::Exited { code: 7 });
        assert!(!process.is_runnable());
        assert_eq!(process.exit(8), Err(Error::InvalidState));
        assert_eq!(process.state(), ProcessState::Exited { code: 7 });
    }

    #[test]
    fn standard_streams_are_open_for_a_new_process() {
        let process = Process::<1>::new(FIRST_PROCESS_ID, Personality::Posix).unwrap();
        assert!(process.descriptors().is_open(0));
        assert!(process.descriptors().is_open(1));
        assert!(process.descriptors().is_open(2));
        assert!(!process.descriptors().is_open(3));
    }

    #[test]
    fn personality_and_address_space_are_preserved() {
        let mut process = Process::<2>::new(FIRST_PROCESS_ID, Personality::Posix).unwrap();
        assert_eq!(process.id(), FIRST_PROCESS_ID);
        assert_eq!(process.personality(), Personality::Posix);
        process
            .space_mut()
            .map(0x400000, 0x1000, PagePermissions::USER_READ_ONLY)
            .unwrap();
        assert!(process.space().contains(0x400000, 0x10));
    }
}
