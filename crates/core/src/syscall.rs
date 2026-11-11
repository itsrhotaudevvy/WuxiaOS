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
    /// Read bytes into a validated userspace buffer.
    Read = 0,
    /// Write bytes from a validated userspace buffer.
    Write = 1,
    /// Open a file by name.
    Open = 2,
    /// Close a process-local handle.
    Close = 3,
    /// Reposition a file descriptor relative to start, current position or end.
    Seek = 8,
    /// Map anonymous writable memory.
    Map = 9,
    /// Unmap a previously mapped anonymous range.
    Unmap = 11,
    /// Yield the processor to another runnable thread.
    Yield = 24,
    /// Sleep for a bounded number of milliseconds.
    Sleep = 35,
    /// Return the process identifier.
    GetPid = 39,
    /// Terminate the calling thread or process.
    Exit = 60,
    /// Return the length of an open file.
    FileSize = 61,
    /// Narrow the process's promise set; the number matches OpenBSD `pledge`.
    Pledge = 108,
}

impl PosixCall {
    /// Decode a raw number. Unknown calls return an error rather than being guessed.
    pub const fn from_raw(raw: u64) -> Option<Self> {
        match raw {
            0 => Some(Self::Read),
            1 => Some(Self::Write),
            2 => Some(Self::Open),
            3 => Some(Self::Close),
            8 => Some(Self::Seek),
            9 => Some(Self::Map),
            11 => Some(Self::Unmap),
            24 => Some(Self::Yield),
            35 => Some(Self::Sleep),
            39 => Some(Self::GetPid),
            60 => Some(Self::Exit),
            61 => Some(Self::FileSize),
            108 => Some(Self::Pledge),
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

/// Largest anonymous mapping request accepted from userspace.
pub const MAX_MAP_LENGTH: u64 = 64 * 1024;

/// Longest file path accepted by the open call.
pub const MAX_PATH_LENGTH: u64 = crate::vfs::MAX_NAME_LENGTH as u64;

/// Longest sleep a single call may request.
pub const MAX_SLEEP_MILLIS: u64 = 5000;

/// Largest buffer a single POSIX read may fill.
pub const MAX_READ_LENGTH: u64 = 256;

/// A decoded POSIX request with validated arguments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PosixRequest {
    /// Read from a process-local descriptor into a user buffer.
    Read {
        /// Process-local file descriptor.
        descriptor: u32,
        /// Validated destination range.
        buffer: UserBuffer,
    },
    /// Open a file by name.
    Open {
        /// Validated path bytes, bounded by [`MAX_PATH_LENGTH`].
        path: UserBuffer,
    },
    /// Write from a validated user buffer to a process-local descriptor.
    Write {
        /// Process-local file descriptor.
        descriptor: u32,
        /// Validated source range.
        buffer: UserBuffer,
    },
    /// Reposition a file descriptor using SEEK_SET, SEEK_CUR or SEEK_END.
    Seek {
        /// Descriptor to reposition.
        descriptor: u32,
        /// Signed byte displacement.
        offset: i64,
        /// 0=start, 1=current position, 2=end of file.
        whence: u32,
    },
    /// Return the size of a descriptor's underlying file.
    FileSize {
        /// Descriptor to inspect.
        descriptor: u32,
    },
    /// Map anonymous writable memory and return its address.
    Map {
        /// Requested byte length, bounded by [`MAX_MAP_LENGTH`].
        length: u64,
    },
    /// Unmap a page-aligned anonymous range.
    Unmap {
        /// First page-aligned address.
        address: u64,
        /// Length in bytes, a page multiple.
        length: u64,
    },
    /// Close a process-local descriptor.
    Close {
        /// Descriptor to close.
        descriptor: u32,
    },
    /// Yield the processor to another runnable thread.
    Yield,
    /// Sleep for a bounded number of milliseconds.
    Sleep {
        /// Requested duration, at most [`MAX_SLEEP_MILLIS`].
        millis: u64,
    },
    /// Return the process identifier.
    GetPid,
    /// Terminate the calling process with a status code.
    Exit {
        /// Exit status reported to the parent.
        code: u64,
    },
    /// Narrow the promise set; the request can only remove promises.
    Pledge {
        /// Requested promises, already checked against the known bits.
        promises: crate::pledge::Promises,
    },
}

impl PosixRequest {
    /// Decode a call number and register block without trusting any pointer.
    pub fn decode(call: u64, registers: &Registers) -> Result<Self> {
        match PosixCall::from_raw(call).ok_or(Error::InvalidInput)? {
            PosixCall::Read => Ok(Self::Read {
                descriptor: decode_descriptor(registers.args[0])?,
                buffer: decode_bounded_buffer(
                    registers.args[1],
                    registers.args[2],
                    MAX_READ_LENGTH,
                )?,
            }),
            PosixCall::Open => Ok(Self::Open {
                path: decode_bounded_buffer(registers.args[0], registers.args[1], MAX_PATH_LENGTH)?,
            }),
            PosixCall::Write => Ok(Self::Write {
                descriptor: decode_descriptor(registers.args[0])?,
                buffer: decode_buffer(registers.args[1], registers.args[2])?,
            }),
            PosixCall::Map => Ok(Self::Map {
                length: decode_map_length(registers.args[0])?,
            }),
            PosixCall::Seek => Ok(Self::Seek {
                descriptor: decode_descriptor(registers.args[0])?,
                offset: registers.args[1] as i64,
                whence: decode_whence(registers.args[2])?,
            }),
            PosixCall::FileSize => Ok(Self::FileSize {
                descriptor: decode_descriptor(registers.args[0])?,
            }),
            PosixCall::Unmap => Ok(Self::Unmap {
                address: decode_unmap_address(registers.args[0])?,
                length: decode_map_length(registers.args[1])?,
            }),
            PosixCall::Close => Ok(Self::Close {
                descriptor: decode_descriptor(registers.args[0])?,
            }),
            PosixCall::Yield => Ok(Self::Yield),
            PosixCall::Sleep => Ok(Self::Sleep {
                millis: decode_sleep_millis(registers.args[0])?,
            }),
            PosixCall::GetPid => Ok(Self::GetPid),
            PosixCall::Exit => Ok(Self::Exit {
                code: registers.args[0],
            }),
            PosixCall::Pledge => Ok(Self::Pledge {
                promises: decode_promises(registers.args[0])?,
            }),
        }
    }

    /// The call this request was decoded from.
    ///
    /// Policy checks such as [`crate::pledge::required`] need the call even
    /// though the decoded request already carries validated arguments.
    pub const fn call(&self) -> PosixCall {
        match self {
            Self::Read { .. } => PosixCall::Read,
            Self::Open { .. } => PosixCall::Open,
            Self::Write { .. } => PosixCall::Write,
            Self::Seek { .. } => PosixCall::Seek,
            Self::FileSize { .. } => PosixCall::FileSize,
            Self::Map { .. } => PosixCall::Map,
            Self::Unmap { .. } => PosixCall::Unmap,
            Self::Close { .. } => PosixCall::Close,
            Self::Yield => PosixCall::Yield,
            Self::Sleep { .. } => PosixCall::Sleep,
            Self::GetPid => PosixCall::GetPid,
            Self::Exit { .. } => PosixCall::Exit,
            Self::Pledge { .. } => PosixCall::Pledge,
        }
    }
}

/// Decode a promise mask, rejecting bits the vocabulary does not define.
fn decode_promises(raw: u64) -> Result<crate::pledge::Promises> {
    let bits = u16::try_from(raw).map_err(|_| Error::InvalidInput)?;
    crate::pledge::Promises::from_bits(bits).ok_or(Error::InvalidInput)
}

fn decode_sleep_millis(raw: u64) -> Result<u64> {
    if raw > MAX_SLEEP_MILLIS {
        return Err(Error::InvalidInput);
    }
    Ok(raw)
}

fn decode_unmap_address(raw: u64) -> Result<u64> {
    if raw == 0
        || !raw.is_multiple_of(crate::paging::PAGE_SIZE)
        || raw >= crate::paging::USER_ADDRESS_LIMIT
    {
        return Err(Error::BadAddress);
    }
    Ok(raw)
}

fn decode_map_length(raw: u64) -> Result<u64> {
    if raw == 0 || raw > MAX_MAP_LENGTH || !raw.is_multiple_of(crate::paging::PAGE_SIZE) {
        return Err(Error::InvalidInput);
    }
    Ok(raw)
}

fn decode_whence(raw: u64) -> Result<u32> {
    u32::try_from(raw)
        .ok()
        .filter(|&whence| whence <= 2)
        .ok_or(Error::InvalidInput)
}

fn decode_descriptor(raw: u64) -> Result<u32> {
    u32::try_from(raw).map_err(|_| Error::InvalidHandle)
}

fn decode_buffer(address: u64, length: u64) -> Result<UserBuffer> {
    decode_bounded_buffer(address, length, MAX_WRITE_LENGTH)
}

fn decode_bounded_buffer(address: u64, length: u64, bound: u64) -> Result<UserBuffer> {
    if address == 0 || length == 0 || length > bound {
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
    use crate::pledge::Promises;

    #[test]
    fn raw_registers_are_not_assumed_to_be_pointers() {
        let regs = Registers {
            args: [1, 2, 3, 4, 5, 6],
        };
        assert_eq!(regs.args[5], 6);
    }

    #[test]
    fn yield_decodes_without_arguments() {
        let registers = Registers {
            args: [0, 0, 0, 0, 0, 0],
        };
        assert_eq!(
            PosixRequest::decode(24, &registers),
            Ok(PosixRequest::Yield)
        );
    }

    #[test]
    fn map_requests_are_bounded() {
        let mut registers = Registers {
            args: [4096, 0, 0, 0, 0, 0],
        };
        assert_eq!(
            PosixRequest::decode(9, &registers),
            Ok(PosixRequest::Map { length: 4096 })
        );
        registers.args[0] = 0;
        assert_eq!(
            PosixRequest::decode(9, &registers),
            Err(Error::InvalidInput)
        );
        registers.args[0] = MAX_MAP_LENGTH + 1;
        assert_eq!(
            PosixRequest::decode(9, &registers),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn sleep_durations_are_bounded() {
        let mut registers = Registers {
            args: [100, 0, 0, 0, 0, 0],
        };
        assert_eq!(
            PosixRequest::decode(35, &registers),
            Ok(PosixRequest::Sleep { millis: 100 })
        );
        registers.args[0] = MAX_SLEEP_MILLIS + 1;
        assert_eq!(
            PosixRequest::decode(35, &registers),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn open_paths_and_read_buffers_are_bounded() {
        let mut registers = Registers {
            args: [0x8000_0000, 5, 0, 0, 0, 0],
        };
        assert_eq!(
            PosixRequest::decode(2, &registers),
            Ok(PosixRequest::Open {
                path: UserBuffer {
                    address: 0x8000_0000,
                    length: 5
                }
            })
        );
        registers.args[1] = MAX_PATH_LENGTH + 1;
        assert_eq!(PosixRequest::decode(2, &registers), Err(Error::BadAddress));

        registers.args = [3, 0x8000_1000, 32, 0, 0, 0];
        assert_eq!(
            PosixRequest::decode(0, &registers),
            Ok(PosixRequest::Read {
                descriptor: 3,
                buffer: UserBuffer {
                    address: 0x8000_1000,
                    length: 32
                }
            })
        );
        registers.args[2] = MAX_READ_LENGTH + 1;
        assert_eq!(PosixRequest::decode(0, &registers), Err(Error::BadAddress));
    }

    #[test]
    fn unmap_requests_require_aligned_ranges() {
        let mut registers = Registers {
            args: [0x8000_1000, 4096, 0, 0, 0, 0],
        };
        assert_eq!(
            PosixRequest::decode(11, &registers),
            Ok(PosixRequest::Unmap {
                address: 0x8000_1000,
                length: 4096
            })
        );
        registers.args[0] = 0x8000_1001;
        assert_eq!(PosixRequest::decode(11, &registers), Err(Error::BadAddress));
        registers.args[0] = 0x8000_1000;
        registers.args[1] = 0x1001;
        assert_eq!(
            PosixRequest::decode(11, &registers),
            Err(Error::InvalidInput)
        );
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
    fn seek_and_file_size_validate_their_arguments() {
        let mut registers = Registers {
            args: [3, (-1i64) as u64, 2, 0, 0, 0],
        };
        assert_eq!(
            PosixRequest::decode(8, &registers),
            Ok(PosixRequest::Seek {
                descriptor: 3,
                offset: -1,
                whence: 2,
            })
        );
        registers.args[2] = 3;
        assert_eq!(
            PosixRequest::decode(8, &registers),
            Err(Error::InvalidInput)
        );
        assert_eq!(
            PosixRequest::decode(61, &registers),
            Ok(PosixRequest::FileSize { descriptor: 3 })
        );
        assert_eq!(PosixCall::from_raw(8), Some(PosixCall::Seek));
        assert_eq!(PosixCall::from_raw(19), None);
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

    #[test]
    fn pledge_decodes_a_known_mask_and_rejects_stray_bits() {
        let mask = Promises::STDIO.union(Promises::RPATH);
        let request = PosixRequest::decode(
            108,
            &Registers {
                args: [u64::from(mask.bits()), 0, 0, 0, 0, 0],
            },
        );
        assert_eq!(request, Ok(PosixRequest::Pledge { promises: mask }));
        assert_eq!(
            PosixRequest::decode(108, &Registers::default()),
            Ok(PosixRequest::Pledge {
                promises: Promises::NONE
            })
        );

        // Bits outside the vocabulary are rejected before any policy runs.
        assert_eq!(
            PosixRequest::decode(
                108,
                &Registers {
                    args: [0x8000, 0, 0, 0, 0, 0]
                }
            ),
            Err(Error::InvalidInput)
        );
        assert_eq!(
            PosixRequest::decode(
                108,
                &Registers {
                    args: [u64::from(u16::MAX) + 1, 0, 0, 0, 0, 0]
                }
            ),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn every_request_reports_the_call_it_came_from() {
        let cases = [
            (
                0,
                Registers {
                    args: [1, 0x1000, 1, 0, 0, 0],
                },
                PosixCall::Read,
            ),
            (
                1,
                Registers {
                    args: [1, 0x1000, 1, 0, 0, 0],
                },
                PosixCall::Write,
            ),
            (
                2,
                Registers {
                    args: [0x1000, 5, 0, 0, 0, 0],
                },
                PosixCall::Open,
            ),
            (
                3,
                Registers {
                    args: [1, 0, 0, 0, 0, 0],
                },
                PosixCall::Close,
            ),
            (
                8,
                Registers {
                    args: [1, 0, 0, 0, 0, 0],
                },
                PosixCall::Seek,
            ),
            (
                9,
                Registers {
                    args: [0x1000, 0, 0, 0, 0, 0],
                },
                PosixCall::Map,
            ),
            (
                11,
                Registers {
                    args: [0x1000, 0x1000, 0, 0, 0, 0],
                },
                PosixCall::Unmap,
            ),
            (24, Registers::default(), PosixCall::Yield),
            (
                35,
                Registers {
                    args: [1, 0, 0, 0, 0, 0],
                },
                PosixCall::Sleep,
            ),
            (39, Registers::default(), PosixCall::GetPid),
            (60, Registers::default(), PosixCall::Exit),
            (
                61,
                Registers {
                    args: [1, 0, 0, 0, 0, 0],
                },
                PosixCall::FileSize,
            ),
            (108, Registers::default(), PosixCall::Pledge),
        ];
        for (call, registers, expected) in cases {
            let request = PosixRequest::decode(call, &registers).expect("decodes");
            assert_eq!(request.call(), expected, "call {call}");
        }
    }
}
