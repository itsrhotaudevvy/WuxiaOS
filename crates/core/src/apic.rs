//! Local and I/O advanced programmable interrupt controller registers.
//!
//! The bootstrap talks to the local APIC by memory-mapped registers and to the
//! I/O APIC through an indirect register window. This module owns the layouts and
//! the value builders, so the shapes that decide whether an interrupt is
//! delivered can be checked on the host instead of guessed at from a serial log.

use crate::{Error, Result};

/// Physical base of the local APIC register window.
pub const LOCAL_APIC_BASE: u64 = 0xfee0_0000;

/// Physical base of the I/O APIC register window.
pub const IO_APIC_BASE: u64 = 0xfec0_0000;

/// Register offset of the local APIC identifier.
pub const LAPIC_ID: u32 = 0x0020;
/// Register offset of the local APIC version.
pub const LAPIC_VERSION: u32 = 0x0030;
/// Register offset of the task priority register.
pub const LAPIC_TPR: u32 = 0x0080;
/// Register offset of the end-of-interrupt register.
pub const LAPIC_EOI: u32 = 0x00b0;
/// Register offset of the spurious interrupt vector register.
pub const LAPIC_SVR: u32 = 0x00f0;
/// Register offset of the low half of the interrupt command register.
pub const LAPIC_ICR_LOW: u32 = 0x0300;
/// Register offset of the high half of the interrupt command register.
pub const LAPIC_ICR_HIGH: u32 = 0x0310;
/// Register offset of the timer local vector table entry.
pub const LAPIC_LVT_TIMER: u32 = 0x0320;
/// Register offset of the first lint local vector table entry.
pub const LAPIC_LVT_LINT0: u32 = 0x0350;
/// Register offset of the second lint local vector table entry.
pub const LAPIC_LVT_LINT1: u32 = 0x0360;
/// Register offset of the error local vector table entry.
pub const LAPIC_LVT_ERROR: u32 = 0x0370;

/// Highest register offset the bootstrap touches.
pub const LAPIC_WINDOW: u32 = 0x0400;

/// `SVR.APIC_ENABLE`: route interrupts through this APIC.
pub const SVR_ENABLE: u32 = 1 << 8;

/// `LVT.MASKED`: the entry delivers nothing.
pub const LVT_MASKED: u32 = 1 << 16;
/// `LVT` delivery mode field: external interrupt, the mode the legacy 8259 uses
/// when it is wired to a local vector table entry.
pub const LVT_EXTINT: u32 = 0b111 << 8;
/// `LVT` polarity bit: the input is active low.
pub const LVT_ACTIVE_LOW: u32 = 1 << 13;
/// `LVT` trigger bit: the input is level triggered.
pub const LVT_LEVEL_TRIGGERED: u32 = 1 << 15;

/// `ICR.DELIVERY_STATUS`: set while a send is in flight.
pub const ICR_DELIVERY_PENDING: u32 = 1 << 12;

/// `ICR` destination shorthand: send to the issuing APIC.
pub const ICR_SHORTHAND_SELF: u32 = 1 << 18;

/// Fixed-delivery mode value in `ICR` bits 8:10.
pub const ICR_DELIVERY_FIXED: u32 = 0;

/// Highest vector number, leaving the ones above it for special purposes.
pub const MAX_VECTOR: u8 = 0xfe;
/// Vector reserved for spurious interrupts.
pub const SPURIOUS_VECTOR: u8 = 0xff;

/// Offset of the I/O APIC identifier register.
pub const IOAPIC_ID: u32 = 0x00;
/// Offset of the I/O APIC version register.
pub const IOAPIC_VERSION: u32 = 0x01;
/// Offset of the I/O APIC indirect register selector.
pub const IOAPIC_SELECT: u32 = 0x00;
/// Offset of the I/O APIC indirect register window.
pub const IOAPIC_WINDOW: u32 = 0x10;

/// First indirect register holding a redirection entry.
pub const IOAPIC_REDIRECTION_START: u32 = 0x10;

/// Validate a local APIC register offset.
///
/// Every register is 32-bit and 16-byte aligned, and the window is one page.
pub const fn lapic_register(offset: u32) -> Result<u32> {
    if !offset.is_multiple_of(16) || offset >= LAPIC_WINDOW {
        return Err(Error::BadAddress);
    }
    Ok(offset)
}

/// Build the value written to the spurious vector register.
pub const fn spurious_vector_register() -> u32 {
    SVR_ENABLE | SPURIOUS_VECTOR as u32
}

/// Build the local vector table entry that hands the legacy 8259 to the APIC.
///
/// Masking this entry is what disconnects an 8259 whose output is wired to the
/// APIC, so the entry is unmasked and set to external-interrupt delivery. The
/// vector is supplied by the 8259 itself, not by this entry.
pub const fn extint_entry() -> u32 {
    LVT_EXTINT
}

/// Build the low half of an interrupt command that targets this APIC.
///
/// Errors: [`Error::OutOfRange`] for a vector that the local APIC reserves,
/// because a self-interrupt on such a vector is not a test of anything.
pub const fn self_interrupt(vector: u8) -> Result<u32> {
    if vector < 0x20 || vector > MAX_VECTOR {
        return Err(Error::OutOfRange);
    }
    Ok(ICR_DELIVERY_FIXED | ICR_SHORTHAND_SELF | vector as u32)
}

/// Extract the identifier from a local APIC identifier register.
pub const fn lapic_identifier(register: u32) -> u8 {
    (register >> 24) as u8
}

/// Extract the identifier from an I/O APIC identifier register.
pub const fn ioapic_identifier(register: u32) -> u8 {
    (register >> 24) as u8
}

/// Extract the highest redirection entry index from the I/O APIC version register.
pub const fn ioapic_max_redirection(version: u32) -> u32 {
    (version >> 16) & 0xff
}

/// Build the two halves of an I/O APIC redirection entry.
///
/// The entry is fixed-delivery with a physical destination. A legacy PCI
/// interrupt line is level triggered and active low, which is the form set by
/// `level_triggered` and `active_low`; a message-signalled interrupt does not use
/// an entry at all. The destination APIC identifier occupies bits 56:63 of the
/// entry, which is the high half's top byte.
pub const fn ioapic_redirection(
    vector: u8,
    destination: u8,
    level_triggered: bool,
    active_low: bool,
) -> [u32; 2] {
    let mut low = vector as u32;
    if level_triggered {
        low |= LVT_LEVEL_TRIGGERED;
    }
    if active_low {
        low |= LVT_ACTIVE_LOW;
    }
    let high = (destination as u32) << 24;
    [low, high]
}

/// Whether an I/O APIC exposes the redirection entry for `index`.
pub const fn ioapic_has_entry(version: u32, index: u32) -> bool {
    index <= ioapic_max_redirection(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_offsets_must_be_aligned_and_inside_the_window() {
        assert_eq!(lapic_register(LAPIC_EOI), Ok(0xb0));
        assert_eq!(lapic_register(LAPIC_ICR_LOW), Ok(0x300));
        assert_eq!(lapic_register(0x20 + 8), Err(Error::BadAddress));
        assert_eq!(lapic_register(LAPIC_WINDOW), Err(Error::BadAddress));
    }

    #[test]
    fn the_spurious_vector_enables_the_apic_and_names_the_vector() {
        let value = spurious_vector_register();
        assert_ne!(value & SVR_ENABLE, 0);
        assert_eq!(value as u8, SPURIOUS_VECTOR);
        assert_eq!(value >> 8 & 1, 1);
    }

    #[test]
    fn the_legacy_pic_is_handed_to_the_apic_unmasked() {
        let entry = extint_entry();
        assert_eq!(entry & LVT_MASKED, 0);
        assert_eq!((entry >> 8) & 0b111, 0b111);
    }

    #[test]
    fn self_interrupts_refuse_reserved_vectors() {
        assert_eq!(self_interrupt(0x40).unwrap() & 0xff, 0x40);
        assert_ne!(self_interrupt(0x40).unwrap() & ICR_SHORTHAND_SELF, 0);
        assert_eq!(self_interrupt(0x10), Err(Error::OutOfRange));
        assert_eq!(self_interrupt(0xff), Err(Error::OutOfRange));
    }

    #[test]
    fn identifiers_and_redirection_entries_land_in_the_documented_bits() {
        assert_eq!(lapic_identifier(0x0300_0000), 3);
        assert_eq!(ioapic_identifier(0x0000_0000), 0);
        assert_eq!(ioapic_max_redirection(0x0017_0011), 0x17);
        assert!(ioapic_has_entry(0x0017_0011, 0x17));
        assert!(!ioapic_has_entry(0x0017_0011, 0x18));

        let [low, high] = ioapic_redirection(0x40, 3, false, false);
        assert_eq!(low, 0x40);
        assert_eq!(high >> 24, 3);
        // Masked entries are built by the caller ORing `LVT_MASKED` into the low
        // half; both halves stay aligned with the documented layout.
        assert_eq!(low | LVT_MASKED, 0x1_0040);

        // A legacy PCI line: level triggered and active low.
        let [low, _] = ioapic_redirection(0x40, 0, true, true);
        assert_eq!(low & LVT_LEVEL_TRIGGERED, LVT_LEVEL_TRIGGERED);
        assert_eq!(low & LVT_ACTIVE_LOW, LVT_ACTIVE_LOW);
        assert_eq!(low & 0xff, 0x40);
    }
}
