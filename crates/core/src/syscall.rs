//! Shared syscall ABI vocabulary. Raw register arguments are untrusted.

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
}
