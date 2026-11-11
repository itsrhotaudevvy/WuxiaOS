//! Stable errors shared by personalities and architecture-independent code.

/// Errors returned by host-testable kernel contracts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A supplied index, offset, size or encoding is invalid.
    InvalidInput,
    /// Arithmetic or a buffer capacity would overflow.
    OutOfRange,
    /// The capability lacks a required right.
    PermissionDenied,
    /// The requested entry is absent.
    NotFound,
    /// A live object with the same identity exists.
    AlreadyExists,
    /// A fixed-capacity table is exhausted.
    TableFull,
    /// A handle does not refer to a live object.
    InvalidHandle,
    /// An image does not satisfy its declared format.
    InvalidImage,
    /// A valid image requires an unsupported feature.
    Unsupported,
    /// An operation is not available for this object state.
    InvalidState,
    /// A name has invalid syntax or exceeds its bound.
    InvalidName,
    /// An operation would block and may be retried or awaited.
    WouldBlock,
    /// A user address failed validation.
    BadAddress,
}

/// Result used by the kernel-independent core.
pub type Result<T> = core::result::Result<T, Error>;
