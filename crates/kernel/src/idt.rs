//! x86_64 interrupt descriptor table encoding.

/// A 64-bit interrupt gate descriptor in the hardware-required layout.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
pub struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    attributes: u8,
    offset_middle: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    /// Construct a present interrupt gate without installing it in the CPU.
    pub const fn interrupt(handler: usize, selector: u16, privilege: u8) -> Self {
        Self {
            offset_low: handler as u16,
            offset_middle: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            selector: 0x08,
            ist: 0,
            attributes: 0x8e | (privilege << 5),
            reserved: 0,
        }
    }
}

/// A small IDT that can be initialized once the handler path exists.
#[derive(Clone, Copy, Debug)]
#[repr(C, align(16))]
pub struct Idt {
    entries: [IdtEntry; 256],
}

impl Idt {
    /// Construct an empty IDT with all descriptors marked not-present.
    pub const fn new() -> Self {
        Self { entries: [IdtEntry::default(); 256] }
    }
}
