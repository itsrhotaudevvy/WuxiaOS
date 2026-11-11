//! POSIX errno values and the mapping from core errors to each personality.
//!
//! POSIX errors and NT status values are separate vocabularies. This module
//! is the only place where a core [`Error`] is translated into either one, so
//! that every new variant forces a deliberate decision for both personalities.

use crate::Error;
use crate::nt::NtStatus;

/// A POSIX errno value, using the Linux x86_64 numbering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct Errno(pub u16);

impl Errno {
    /// Operation not permitted.
    pub const EPERM: Self = Self(1);
    /// No such file or directory.
    pub const ENOENT: Self = Self(2);
    /// I/O error.
    pub const EIO: Self = Self(5);
    /// Exec format error.
    pub const ENOEXEC: Self = Self(8);
    /// Bad file descriptor.
    pub const EBADF: Self = Self(9);
    /// Resource temporarily unavailable; the operation would block.
    pub const EAGAIN: Self = Self(11);
    /// Cannot allocate memory.
    pub const ENOMEM: Self = Self(12);
    /// Permission denied.
    pub const EACCES: Self = Self(13);
    /// Bad address.
    pub const EFAULT: Self = Self(14);
    /// File exists.
    pub const EEXIST: Self = Self(17);
    /// Invalid argument.
    pub const EINVAL: Self = Self(22);
    /// Too many open files in the system.
    pub const ENFILE: Self = Self(23);
    /// Too many open files in the process.
    pub const EMFILE: Self = Self(24);
    /// No space left on device.
    pub const ENOSPC: Self = Self(28);
    /// Illegal seek.
    pub const ESPIPE: Self = Self(29);
    /// Numerical result out of range.
    pub const ERANGE: Self = Self(34);
    /// File name too long.
    pub const ENAMETOOLONG: Self = Self(36);
    /// Function not implemented.
    pub const ENOSYS: Self = Self(38);
    /// Value too large for defined data type.
    pub const EOVERFLOW: Self = Self(75);

    /// The raw return value of a failed syscall: `-errno` as a two's-complement
    /// machine word, which userspace recognizes in the range `-4095..=-1`.
    pub const fn as_negative_return(self) -> u64 {
        (self.0 as u64).wrapping_neg()
    }
}

// NTSTATUS values needed by the mapping below that `nt.rs` does not define.
// Every value carries the error severity (top two bits `0b11`).

/// STATUS_OBJECT_NAME_INVALID.
pub const STATUS_OBJECT_NAME_INVALID: NtStatus = NtStatus(0xc000_0033);
/// STATUS_OBJECT_NAME_NOT_FOUND.
pub const STATUS_OBJECT_NAME_NOT_FOUND: NtStatus = NtStatus(0xc000_0034);
/// STATUS_OBJECT_NAME_COLLISION.
pub const STATUS_OBJECT_NAME_COLLISION: NtStatus = NtStatus(0xc000_0035);
/// STATUS_INSUFFICIENT_RESOURCES.
pub const STATUS_INSUFFICIENT_RESOURCES: NtStatus = NtStatus(0xc000_009a);
/// STATUS_INTEGER_OVERFLOW.
pub const STATUS_INTEGER_OVERFLOW: NtStatus = NtStatus(0xc000_0095);
/// STATUS_DEVICE_NOT_READY.
pub const STATUS_DEVICE_NOT_READY: NtStatus = NtStatus(0xc000_00a3);
/// STATUS_NOT_SUPPORTED.
pub const STATUS_NOT_SUPPORTED: NtStatus = NtStatus(0xc000_00bb);
/// STATUS_INVALID_IMAGE_FORMAT.
pub const STATUS_INVALID_IMAGE_FORMAT: NtStatus = NtStatus(0xc000_007b);
/// STATUS_ACCESS_VIOLATION.
pub const STATUS_ACCESS_VIOLATION: NtStatus = NtStatus(0xc000_0005);
/// STATUS_INVALID_DEVICE_STATE.
pub const STATUS_INVALID_DEVICE_STATE: NtStatus = NtStatus(0xc000_0184);

/// Map a core error to the POSIX errno returned to a POSIX process.
///
/// Choices where the core variant is broader than one errno:
/// - `InvalidState` is `EINVAL`: the call is well formed but the object cannot
///   accept it in its current state, and no more specific POSIX value fits.
/// - `InvalidName` is `EINVAL`: a name with bad syntax or excessive length is
///   an invalid argument; callers that know the length bound was exceeded may
///   report `ENAMETOOLONG` themselves.
/// - `OutOfRange` is `EOVERFLOW`: the variant covers arithmetic overflow and
///   capacity overflow, matching `EOVERFLOW` for values that do not fit.
/// - `TableFull` is `EMFILE`: the exhausted tables are per-process descriptor
///   tables; `ENFILE` is reserved for a system-wide limit.
/// - `Unsupported` is `ENOSYS`: the feature is absent from this kernel.
/// - `WouldBlock` is `EAGAIN`, which equals `EWOULDBLOCK` on Linux.
pub const fn errno_for(error: Error) -> Errno {
    match error {
        Error::InvalidInput => Errno::EINVAL,
        Error::OutOfRange => Errno::EOVERFLOW,
        Error::PermissionDenied => Errno::EACCES,
        Error::NotFound => Errno::ENOENT,
        Error::AlreadyExists => Errno::EEXIST,
        Error::TableFull => Errno::EMFILE,
        Error::InvalidHandle => Errno::EBADF,
        Error::InvalidImage => Errno::ENOEXEC,
        Error::Unsupported => Errno::ENOSYS,
        Error::InvalidState => Errno::EINVAL,
        Error::InvalidName => Errno::EINVAL,
        Error::WouldBlock => Errno::EAGAIN,
        Error::BadAddress => Errno::EFAULT,
    }
}

/// Map a core error to the NTSTATUS returned to an NT process.
///
/// Choices where the core variant is broader than one status:
/// - `InvalidState` is `STATUS_INVALID_DEVICE_STATE`, the NT code for a request
///   that is valid but not allowed in the object's current state.
/// - `InvalidName` is `STATUS_OBJECT_NAME_INVALID`, which covers both bad
///   syntax and excessive length, the same breadth as the core variant.
/// - `OutOfRange` is `STATUS_INTEGER_OVERFLOW`, the arithmetic case; NT has no
///   separate capacity-overflow status that fits better.
/// - `TableFull` is `STATUS_INSUFFICIENT_RESOURCES`.
/// - `WouldBlock` is `STATUS_DEVICE_NOT_READY`. NT's retry signal
///   `STATUS_PENDING` (0x103) has success severity and so cannot satisfy this
///   mapping's error contract; an NT wait path should produce it directly.
/// - `BadAddress` is `STATUS_ACCESS_VIOLATION`, the NT code for an invalid
///   user pointer.
pub const fn nt_status_for(error: Error) -> NtStatus {
    match error {
        Error::InvalidInput => NtStatus::INVALID_PARAMETER,
        Error::OutOfRange => STATUS_INTEGER_OVERFLOW,
        Error::PermissionDenied => NtStatus::ACCESS_DENIED,
        Error::NotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        Error::AlreadyExists => STATUS_OBJECT_NAME_COLLISION,
        Error::TableFull => STATUS_INSUFFICIENT_RESOURCES,
        Error::InvalidHandle => NtStatus::INVALID_HANDLE,
        Error::InvalidImage => STATUS_INVALID_IMAGE_FORMAT,
        Error::Unsupported => STATUS_NOT_SUPPORTED,
        Error::InvalidState => STATUS_INVALID_DEVICE_STATE,
        Error::InvalidName => STATUS_OBJECT_NAME_INVALID,
        Error::WouldBlock => STATUS_DEVICE_NOT_READY,
        Error::BadAddress => STATUS_ACCESS_VIOLATION,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `Error` variant. Keep in step with `error.rs`: `errno_for` and
    /// `nt_status_for` fail to compile on a new variant until it is mapped here.
    const ALL_ERRORS: [Error; 13] = [
        Error::InvalidInput,
        Error::OutOfRange,
        Error::PermissionDenied,
        Error::NotFound,
        Error::AlreadyExists,
        Error::TableFull,
        Error::InvalidHandle,
        Error::InvalidImage,
        Error::Unsupported,
        Error::InvalidState,
        Error::InvalidName,
        Error::WouldBlock,
        Error::BadAddress,
    ];

    #[test]
    fn errno_values_match_linux_x86_64() {
        assert_eq!(Errno::EPERM.0, 1);
        assert_eq!(Errno::ENOENT.0, 2);
        assert_eq!(Errno::EIO.0, 5);
        assert_eq!(Errno::ENOEXEC.0, 8);
        assert_eq!(Errno::EBADF.0, 9);
        assert_eq!(Errno::EAGAIN.0, 11);
        assert_eq!(Errno::ENOMEM.0, 12);
        assert_eq!(Errno::EACCES.0, 13);
        assert_eq!(Errno::EFAULT.0, 14);
        assert_eq!(Errno::EEXIST.0, 17);
        assert_eq!(Errno::EINVAL.0, 22);
        assert_eq!(Errno::ENFILE.0, 23);
        assert_eq!(Errno::EMFILE.0, 24);
        assert_eq!(Errno::ENOSPC.0, 28);
        assert_eq!(Errno::ESPIPE.0, 29);
        assert_eq!(Errno::ERANGE.0, 34);
        assert_eq!(Errno::ENAMETOOLONG.0, 36);
        assert_eq!(Errno::ENOSYS.0, 38);
        assert_eq!(Errno::EOVERFLOW.0, 75);
    }

    #[test]
    fn every_error_maps_to_a_nonzero_errno() {
        for error in ALL_ERRORS {
            assert_ne!(errno_for(error).0, 0, "{error:?} mapped to zero");
        }
    }

    #[test]
    fn every_error_maps_to_an_error_severity_ntstatus() {
        for error in ALL_ERRORS {
            let status = nt_status_for(error);
            assert_eq!(status.0 >> 30, 0b11, "{error:?} mapped to {:#x}", status.0);
            assert!(!status.is_success(), "{error:?} mapped to success");
        }
    }

    #[test]
    fn negative_return_is_twos_complement_errno() {
        assert_eq!(Errno::EPERM.as_negative_return(), u64::MAX);
        assert_eq!(Errno::ENOENT.as_negative_return(), (-2i64) as u64);
        assert_eq!(Errno::EOVERFLOW.as_negative_return(), (-75i64) as u64);
        assert_eq!(Errno::EINVAL.as_negative_return() as i64, -22);
    }

    #[test]
    fn negative_returns_fall_in_the_syscall_error_window() {
        for error in ALL_ERRORS {
            let raw = errno_for(error).as_negative_return() as i64;
            assert!((-4095..=-1).contains(&raw), "{error:?} encodes as {raw}");
        }
    }

    #[test]
    fn specific_mappings_follow_the_documented_choices() {
        assert_eq!(errno_for(Error::NotFound), Errno::ENOENT);
        assert_eq!(
            nt_status_for(Error::NotFound),
            NtStatus(0xc000_0034),
            "STATUS_OBJECT_NAME_NOT_FOUND"
        );

        assert_eq!(errno_for(Error::BadAddress), Errno::EFAULT);
        assert_eq!(nt_status_for(Error::BadAddress), NtStatus(0xc000_0005));

        assert_eq!(errno_for(Error::InvalidHandle), Errno::EBADF);
        assert_eq!(
            nt_status_for(Error::InvalidHandle),
            NtStatus::INVALID_HANDLE
        );

        assert_eq!(errno_for(Error::OutOfRange), Errno::EOVERFLOW);
        assert_eq!(nt_status_for(Error::OutOfRange), NtStatus(0xc000_0095));

        assert_eq!(errno_for(Error::TableFull), Errno::EMFILE);
        assert_eq!(
            nt_status_for(Error::PermissionDenied),
            NtStatus::ACCESS_DENIED
        );
        assert_eq!(
            nt_status_for(Error::InvalidInput),
            NtStatus::INVALID_PARAMETER
        );
        assert_eq!(nt_status_for(Error::Unsupported), NtStatus(0xc000_00bb));
    }
}
