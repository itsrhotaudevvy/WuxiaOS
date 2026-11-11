//! Explicit process personalities and executable formats.

/// The userspace ABI selected for a process at creation time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Personality {
    /// POSIX process, file-descriptor namespace and signal semantics.
    Posix,
    /// NT process, object namespace, thread context and native syscall ABI.
    Nt,
}

impl Personality {
    /// A short diagnostic name, stable across releases.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Posix => "posix",
            Self::Nt => "nt",
        }
    }
}

/// Executable container recognized by a loader.
///
/// Detection is not a security boundary: validation, image mapping and process
/// policy remain separate operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageFormat {
    /// 64-bit little-endian ELF, used by POSIX programs.
    Elf64,
    /// PE32+ image, used by 64-bit Windows programs and drivers.
    Pe32Plus,
    /// PE32 images require the future x86 compatibility address space.
    Pe32,
    /// 16-bit DOS images require an optional, separately sandboxed emulator.
    DosMz,
}
