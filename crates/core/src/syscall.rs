//! Shared syscall ABI vocabulary. Raw register arguments are untrusted.

use crate::{Error, Result};

/// Largest buffer a single POSIX write may reference.
pub const MAX_WRITE_LENGTH: u64 = 1024 * 1024;

/// The calling convention selected by a process's personality.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallAbi {
    /// Wuxia POSIX ABI, with explicit register and pointer validation.
    Posix,
    /// NT native syscall service selected by the NT personality.
    Nt,
}

/// Six untyped argument slots at the architecture syscall boundary.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Registers {
    /// Six machine-word arguments, not trusted pointers.
    pub args: [u64; 6],
}

/// Operations selected by the initial Wuxia POSIX ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum PosixCall {
    /// Write bytes from a validated userspace buffer.
    Write = 1,
    /// Close a process-local handle.
    Close = 3,
    /// Return the process identifier.
    GetPid = 39,
    /// Terminate the calling thread or process.
    Exit = 60,
}

impl PosixCall {
    /// Decode a raw number. Unknown calls return an error rather than being guessed.
    pub const fn from_raw(raw: u64) -> Option<Self> {
        match raw {
            1 => Some(Self::Write),
            3 => Some(Self::Close),
            39 => Some(Self::GetPid),
            60 => Some(Self::Exit),
            _ => None,
        }
    }
}

/// A byte range supplied by an untrusted process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserBuffer {
    /// First userspace address, never zero.
    pub address: u64,
    /// Number of bytes, never zero and bounded by [`MAX_WRITE_LENGTH`].
    pub length: u64,
}

/// A decoded POSIX request with validated arguments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PosixRequest {
    /// Write from a validated user buffer to a process-local descriptor.
    Write {
        /// Process-local file descriptor.
        descriptor: u32,
        /// Validated source range.
        buffer: UserBuffer,
    },
    /// Close a process-local descriptor.
    Close {
        /// Descriptor to close.
        descriptor: u32,
    },
    /// Return the process identifier.
    GetPid,
    /// Terminate the calling process with a status code.
    Exit {
        /// Exit status reported to the parent.
        code: u64,
    },
}

impl PosixRequest {
    /// Decode a call number and register block without trusting any pointer.
    pub fn decode(call: u64, registers: &Registers) -> Result<Self> {
        match PosixCall::from_raw(call).ok_or(Error::InvalidInput)? {
            PosixCall::Write => Ok(Self::Write {
                descriptor: decode_descriptor(registers.args[0])?,
                buffer: decode_buffer(registers.args[1], registers.args[2])?,
            }),
            PosixCall::Close => Ok(Self::Close {
                descriptor: decode_descriptor(registers.args[0])?,
            }),
            PosixCall::GetPid => Ok(Self::GetPid),
            PosixCall::Exit => Ok(Self::Exit {
                code: registers.args[0],
            }),
        }
    }
}

fn decode_descriptor(raw: u64) -> Result<u32> {
    u32::try_from(raw).map_err(|_| Error::InvalidHandle)
}

fn decode_buffer(address: u64, length: u64) -> Result<UserBuffer> {
    if address == 0 || length == 0 || length > MAX_WRITE_LENGTH {
        return Err(Error::BadAddress);
    }
    address.checked_add(length).ok_or(Error::OutOfRange)?;
    Ok(UserBuffer { address, length })
}

/// A raw NT service number. Dispatch tables must be per OS version/build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct NtCall(pub u32);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_registers_are_not_assumed_to_be_pointers() {
        let regs = Registers {
            args: [1, 2, 3, 4, 5, 6],
        };
        assert_eq!(regs.args[5], 6);
    }

    #[test]
    fn unknown_posix_calls_are_rejected() {
        assert_eq!(PosixCall::from_raw(u64::MAX), None);
        assert_eq!(PosixCall::from_raw(60), Some(PosixCall::Exit));
    }

    #[test]
    fn write_requests_validate_the_user_buffer() {
        let registers = Registers {
            args: [1, 0x400000, 16, 0, 0, 0],
        };
        assert_eq!(
            PosixRequest::decode(1, &registers),
            Ok(PosixRequest::Write {
                descriptor: 1,
                buffer: UserBuffer {
                    address: 0x400000,
                    length: 16
                }
            })
        );

        for args in [
            [1, 0, 16, 0, 0, 0],
            [1, 0x400000, 0, 0, 0, 0],
            [1, 0x400000, MAX_WRITE_LENGTH + 1, 0, 0, 0],
            [1, u64::MAX, 2, 0, 0, 0],
            [u64::from(u32::MAX) + 1, 0x400000, 1, 0, 0, 0],
        ] {
            assert!(PosixRequest::decode(1, &Registers { args }).is_err());
        }
    }

    #[test]
    fn simple_requests_decode_without_pointers() {
        let getpid = Registers::default();
        assert_eq!(PosixRequest::decode(39, &getpid), Ok(PosixRequest::GetPid));
        assert_eq!(
            PosixRequest::decode(
                60,
                &Registers {
                    args: [7, 0, 0, 0, 0, 0]
                }
            ),
            Ok(PosixRequest::Exit { code: 7 })
        );
        assert_eq!(
            PosixRequest::decode(
                3,
                &Registers {
                    args: [2, 0, 0, 0, 0, 0]
                }
            ),
            Ok(PosixRequest::Close { descriptor: 2 })
        );
        assert_eq!(
            PosixRequest::decode(999, &Registers::default()),
            Err(Error::InvalidInput)
        );
    }
}
