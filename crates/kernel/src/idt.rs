//! x86_64 interrupt descriptor table encoding and loading.

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
    pub const fn missing() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            attributes: 0,
            offset_middle: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

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

/// The IDT pointer consumed by `lidt`.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
pub struct IdtPointer {
    /// One less than the size of the IDT in bytes.
    pub limit: u16,
    /// Linear address of the table.
    pub base: u64,
}

/// A 256-entry table of interrupt and exception gates.
#[derive(Clone, Copy, Debug)]
#[repr(C, align(16))]
pub struct Idt {
    entries: [IdtEntry; 256],
}

impl Idt {
    /// Construct an empty IDT with all descriptors marked not-present.
    pub const fn new() -> Self {
        Self {
            entries: [IdtEntry {
                offset_low: 0,
                selector: 0,
                ist: 0,
                attributes: 0,
                offset_middle: 0,
                offset_high: 0,
                reserved: 0,
            }; 256],
        }
    }

    /// Set one exception vector's descriptor.
    pub fn set_handler(&mut self, vector: u8, handler: usize, privilege: u8) {
        self.entries[vector as usize] = IdtEntry::interrupt(handler, 0x08, privilege);
    }

    /// Install the table after all required exception stubs are present.
    pub fn load(&self) {
        // SAFETY: This routine is called only after the caller has populated a
        // complete static IDT and validated its handler addresses.
        unsafe {
            core::arch::asm!("lidt [{0}]", in(reg) &self, options(readonly, nostack, preserves_flags))
        };
    }
}
