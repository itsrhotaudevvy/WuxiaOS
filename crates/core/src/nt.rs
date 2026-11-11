//! Small NT vocabulary types used by the future native personality.

use crate::syscall::{MAX_READ_LENGTH, MAX_WRITE_LENGTH, Registers, UserBuffer};
use crate::{Error, Result};

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
    /// STATUS_INVALID_HANDLE.
    pub const INVALID_HANDLE: Self = Self(0xc000_0008);
    /// STATUS_BUFFER_TOO_SMALL.
    pub const BUFFER_TOO_SMALL: Self = Self(0xc000_0023);

    /// Test the NTSTATUS severity bit.
    pub const fn is_success(self) -> bool {
        self.0 & 0x8000_0000 == 0
    }
}

/// Native services the NT personality understands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum NtCall {
    /// Close an object handle.
    Close = 0x0f,
    /// Reserve and commit user virtual memory.
    AllocateVirtualMemory = 0x18,
    /// Terminate the calling process.
    TerminateProcess = 0x29,
    /// Read from a file handle.
    ReadFile = 0x06,
    /// Write to a file handle.
    WriteFile = 0x08,
}

impl NtCall {
    /// Decode a service number, rejecting anything unknown.
    pub const fn from_raw(raw: u64) -> Option<Self> {
        match raw {
            0x0f => Some(Self::Close),
            0x18 => Some(Self::AllocateVirtualMemory),
            0x29 => Some(Self::TerminateProcess),
            0x06 => Some(Self::ReadFile),
            0x08 => Some(Self::WriteFile),
            _ => None,
        }
    }
}

/// A decoded NT request with validated arguments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtRequest {
    /// Close a handle.
    Close {
        /// Process-local handle number.
        handle: u32,
    },
    /// Reserve user virtual memory of the requested length.
    AllocateVirtualMemory {
        /// Requested byte length.
        length: u64,
    },
    /// Terminate the process with an NTSTATUS exit code.
    TerminateProcess {
        /// Exit status recorded for the process.
        status: u32,
    },
    /// Read into a user buffer.
    ReadFile {
        /// File handle.
        handle: u32,
        /// Validated destination range.
        buffer: UserBuffer,
    },
    /// Write from a user buffer.
    WriteFile {
        /// File handle.
        handle: u32,
        /// Validated source range.
        buffer: UserBuffer,
    },
}

impl NtRequest {
    /// Decode a service number and register block without trusting pointers.
    pub fn decode(call: u64, registers: &Registers) -> Result<Self> {
        match NtCall::from_raw(call).ok_or(Error::InvalidInput)? {
            NtCall::Close => Ok(Self::Close {
                handle: decode_handle(registers.args[0])?,
            }),
            NtCall::AllocateVirtualMemory => {
                let length = registers.args[1];
                if length == 0 || length > crate::syscall::MAX_MAP_LENGTH {
                    return Err(Error::InvalidInput);
                }
                Ok(Self::AllocateVirtualMemory { length })
            }
            NtCall::TerminateProcess => Ok(Self::TerminateProcess {
                status: u32::try_from(registers.args[0]).map_err(|_| Error::InvalidInput)?,
            }),
            NtCall::ReadFile => Ok(Self::ReadFile {
                handle: decode_handle(registers.args[0])?,
                buffer: decode_buffer(registers.args[1], registers.args[2], MAX_READ_LENGTH)?,
            }),
            NtCall::WriteFile => Ok(Self::WriteFile {
                handle: decode_handle(registers.args[0])?,
                buffer: decode_buffer(registers.args[1], registers.args[2], MAX_WRITE_LENGTH)?,
            }),
        }
    }
}

fn decode_handle(raw: u64) -> Result<u32> {
    let handle = u32::try_from(raw).map_err(|_| Error::InvalidHandle)?;
    if handle == 0 || handle as usize >= crate::process::DESCRIPTOR_CAPACITY {
        return Err(Error::InvalidHandle);
    }
    Ok(handle)
}

fn decode_buffer(address: u64, length: u64, bound: u64) -> Result<UserBuffer> {
    if address == 0 || length == 0 || length > bound {
        return Err(Error::BadAddress);
    }
    address.checked_add(length).ok_or(Error::OutOfRange)?;
    Ok(UserBuffer { address, length })
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
    fn nt_requests_are_decoded_with_validated_arguments() {
        let mut registers = Registers {
            args: [3, 0x8000_1000, 64, 0, 0, 0],
        };
        assert_eq!(
            NtRequest::decode(0x08, &registers),
            Ok(NtRequest::WriteFile {
                handle: 3,
                buffer: UserBuffer {
                    address: 0x8000_1000,
                    length: 64
                }
            })
        );
        assert_eq!(
            NtRequest::decode(0x0f, &registers),
            Ok(NtRequest::Close { handle: 3 })
        );
        assert_eq!(
            NtRequest::decode(0x29, &registers),
            Ok(NtRequest::TerminateProcess { status: 3 })
        );

        registers.args[0] = 0;
        assert_eq!(
            NtRequest::decode(0x0f, &registers),
            Err(Error::InvalidHandle)
        );
        registers.args = [3, 0x8000_1000, MAX_READ_LENGTH + 1, 0, 0, 0];
        assert_eq!(NtRequest::decode(0x06, &registers), Err(Error::BadAddress));
        registers.args = [4, 4096, 0, 0, 0, 0];
        assert_eq!(
            NtRequest::decode(0x18, &registers),
            Ok(NtRequest::AllocateVirtualMemory { length: 4096 })
        );
        assert_eq!(
            NtRequest::decode(0x99, &registers),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn dispatch_level_disallows_waiting() {
        assert!(Irql::Passive.may_wait());
        assert!(!Irql::Dispatch.may_wait());
        assert!(Irql::Passive.may_page_fault());
        assert!(!Irql::Dispatch.may_page_fault());
    }
}
