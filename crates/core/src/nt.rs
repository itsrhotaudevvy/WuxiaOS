//! Small NT vocabulary types used by the future native personality.

/// NT object classes used by the executive object-manager design.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ObjectType {
    /// A process and its address space.
    Process = 0,
    /// A scheduler thread.
    Thread = 1,
    /// A file or I/O target.
    File = 2,
    /// An event.
    Event = 3,
    /// A mutex-like synchronization object.
    Mutant = 4,
    /// A memory section.
    Section = 5,
    /// A registry key.
    Key = 6,
    /// A device object.
    Device = 7,
    /// A driver object.
    Driver = 8,
    /// An access token.
    Token = 9,
    /// A job object.
    Job = 10,
    /// An object-manager directory.
    Directory = 11,
    /// An NT symbolic link.
    SymbolicLink = 12,
}

impl ObjectType {
    /// Decode an object type from an untrusted integer.
    pub const fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            0 => Some(Self::Process),
            1 => Some(Self::Thread),
            2 => Some(Self::File),
            3 => Some(Self::Event),
            4 => Some(Self::Mutant),
            5 => Some(Self::Section),
            6 => Some(Self::Key),
            7 => Some(Self::Device),
            8 => Some(Self::Driver),
            9 => Some(Self::Token),
            10 => Some(Self::Job),
            11 => Some(Self::Directory),
            12 => Some(Self::SymbolicLink),
            _ => None,
        }
    }
}

/// NT status values are distinct from POSIX errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct NtStatus(pub u32);

impl NtStatus {
    /// STATUS_SUCCESS.
    pub const SUCCESS: Self = Self(0);
    /// STATUS_INVALID_PARAMETER.
    pub const INVALID_PARAMETER: Self = Self(0xc000_000d);
    /// STATUS_NOT_IMPLEMENTED.
    pub const NOT_IMPLEMENTED: Self = Self(0xc000_0002);
    /// STATUS_ACCESS_DENIED.
    pub const ACCESS_DENIED: Self = Self(0xc000_0022);

    /// Test the NTSTATUS severity bit.
    pub const fn is_success(self) -> bool {
        self.0 & 0x8000_0000 == 0
    }
}

/// IRQL vocabulary used when defining a future driver execution model.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Irql {
    /// PASSIVE_LEVEL, where normal thread-context work may sleep.
    Passive,
    /// APC_LEVEL.
    Apc,
    /// DISPATCH_LEVEL; paged memory and blocking are prohibited.
    Dispatch,
    /// Device interrupt level.
    Device(u8),
}

impl Irql {
    /// Whether blocking waits are legal at this IRQL.
    pub const fn may_wait(self) -> bool {
        matches!(self, Self::Passive)
    }

    /// Whether pageable memory may be accessed at this IRQL.
    pub const fn may_page_fault(self) -> bool {
        matches!(self, Self::Passive | Self::Apc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nt_status_severity_is_explicit() {
        assert!(NtStatus::SUCCESS.is_success());
        assert!(!NtStatus::ACCESS_DENIED.is_success());
    }

    #[test]
    fn dispatch_level_disallows_waiting() {
        assert!(Irql::Passive.may_wait());
        assert!(!Irql::Dispatch.may_wait());
        assert!(Irql::Passive.may_page_fault());
        assert!(!Irql::Dispatch.may_page_fault());
    }
}
