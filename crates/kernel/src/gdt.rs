//! x86_64 global descriptor table definitions.

/// Kernel code selector in the bootstrap GDT.
pub const KERNEL_CODE_SELECTOR: u16 = 0x08;

/// Kernel data selector for the bootstrap flat address space.
pub const KERNEL_DATA_SELECTOR: u16 = 0x10;

/// User code selector reserved for a later userspace transition.
pub const USER_CODE_SELECTOR: u16 = 0x1b;

/// A flat 64-bit segment descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct SegmentDescriptor(pub u64);

impl SegmentDescriptor {
    /// Construct a long-mode, present, executable/readable code descriptor.
    pub const fn code(privilege: u8) -> Self {
        Self((1u64 << 43) | (1u64 << 44) | (1u64 << 47) | ((privilege as u64) << 45) | (1u64 << 53))
    }
}
