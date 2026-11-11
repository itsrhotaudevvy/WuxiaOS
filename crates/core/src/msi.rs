//! Message-signalled interrupt capabilities.
//!
//! A device that supports message-signalled interrupts does not need an
//! interrupt line: it writes a small message to the local APIC's address window
//! and the APIC raises the vector carried in that message. This module owns the
//! part that can be checked without hardware: walking a function's capability
//! list, decoding the MSI capability's layout (which differs between 32-bit and
//! 64-bit address forms), and composing the message for a destination APIC and
//! vector. The kernel performs the configuration writes.

use crate::{Error, Result};

/// Status register.
pub const STATUS: u8 = 0x04;
/// Status bit 4: the function implements a capability list.
pub const STATUS_CAPABILITIES: u16 = 1 << 4;

/// Configuration offset of the capability pointer.
pub const CAPABILITY_POINTER: u8 = 0x34;

/// Capability identifier of message-signalled interrupts.
pub const CAP_ID_MSI: u8 = 0x05;
/// Capability identifier of the extended message-signalled interrupt table.
pub const CAP_ID_MSIX: u8 = 0x11;

/// Lowest configuration offset a capability may start at.
pub const LOWEST_CAPABILITY: u8 = 0x40;

/// Highest number of links followed before the list is called malformed.
///
/// The configuration space is 256 bytes and every capability occupies at least
/// eight, so a well-formed list is far shorter than this bound. The bound is what
/// makes a loop in the list fail instead of hanging the boot.
pub const MAX_CAPABILITIES: usize = 32;

/// Base of the local APIC address window interrupts are delivered to.
pub const MESSAGE_ADDRESS_BASE: u32 = 0xfee0_0000;

/// One entry of a capability list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capability {
    /// Capability identifier.
    pub id: u8,
    /// Configuration offset where the capability starts.
    pub offset: u8,
}

/// Extract the byte at `offset` from a 32-bit register read.
pub const fn byte(register: u32, offset: u8) -> u8 {
    (register >> (offset as u32 % 4 * 8)) as u8
}

/// Find the first capability with `wanted` in a function's capability list.
///
/// `read` returns the 32-bit register at a given offset, as everywhere else in
/// this crate. Returns `None` when the function has no capability list, when the
/// list ends, or when it does not contain the wanted identifier; a malformed list
/// (a pointer below [`LOWEST_CAPABILITY`], misaligned, or beyond the 256-byte
/// configuration space) also yields `None` rather than a fabricated offset.
pub fn find_capability(read: impl Fn(u8) -> u32, wanted: u8) -> Option<Capability> {
    let status = (read(STATUS) >> 16) as u16;
    if status & STATUS_CAPABILITIES == 0 {
        return None;
    }
    let mut offset = byte(read(CAPABILITY_POINTER), 0);
    for _ in 0..MAX_CAPABILITIES {
        if offset < LOWEST_CAPABILITY || !offset.is_multiple_of(4) {
            return None;
        }
        let entry = read(offset);
        let id = byte(entry, offset);
        if id == wanted {
            return Some(Capability { id, offset });
        }
        let next = byte(entry, offset + 1);
        if next == 0 {
            return None;
        }
        offset = next;
    }
    None
}

/// A decoded MSI capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Msi {
    /// Configuration offset of the capability.
    pub offset: u8,
    /// Message control word.
    pub control: u16,
    /// Message address, 32 or 64 bits wide depending on the control word.
    pub address: u64,
    /// Message data word.
    pub data: u16,
}

/// Message control bit 0: enable.
pub const MSI_ENABLE: u16 = 1 << 0;
/// Message control bit 7: the capability supplies a 64-bit address.
pub const MSI_ADDRESS_64: u16 = 1 << 7;

impl Msi {
    /// Decode the MSI capability starting at `offset`.
    ///
    /// Errors: [`Error::Unsupported`] when the capability does not fit inside the
    /// 256-byte configuration space, which means the capability pointer is
    /// wrong rather than the hardware being unusual.
    pub fn decode(read: impl Fn(u8) -> u32, offset: u8) -> Result<Self> {
        if offset < LOWEST_CAPABILITY || offset as u16 + 12 > 0x100 {
            return Err(Error::Unsupported);
        }
        let header = read(offset & !3);
        let shift = (offset % 4) as u32 * 8;
        let control = (header >> (shift + 16)) as u16;
        let address_low = read(offset + 4);
        let wide = control & MSI_ADDRESS_64 != 0;
        let address_high = match wide {
            true => read(offset + 8),
            false => 0,
        };
        let data_offset = match wide {
            true => offset + 12,
            false => offset + 8,
        };
        let data = (read(data_offset & !3) >> (((data_offset % 4) as u32) * 8)) as u16;
        Ok(Self {
            offset,
            control,
            address: (u64::from(address_high) << 32) | u64::from(address_low),
            data,
        })
    }

    /// Whether the capability currently has interrupts enabled.
    pub const fn is_enabled(&self) -> bool {
        self.control & MSI_ENABLE != 0
    }
}

/// Compose the message a function writes to signal `vector` on `apic_id`.
///
/// A fixed-delivery, physical-destination, edge-triggered message is the only
/// form a driver needs: the address names the destination APIC and the data word
/// carries the vector in its low byte.
pub const fn msi_message(apic_id: u8, vector: u8) -> (u64, u16) {
    let address = (MESSAGE_ADDRESS_BASE as u64) | ((apic_id as u64) << 12);
    (address, vector as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Space([u32; 64]);

    impl Space {
        fn new() -> Self {
            Self([0; 64])
        }

        fn write16(&mut self, offset: u8, value: u16) {
            let index = (offset >> 2) as usize;
            let shift = (offset % 4) as u32 * 8;
            self.0[index] = (self.0[index] & !(0xffff << shift)) | (u32::from(value) << shift);
        }

        fn write32(&mut self, offset: u8, value: u32) {
            self.0[(offset >> 2) as usize] = value;
        }

        fn read(&self) -> impl Fn(u8) -> u32 + Copy + '_ {
            move |offset| self.0[(offset >> 2) as usize]
        }
    }

    #[test]
    fn capability_lists_are_followed_to_the_wanted_entry() {
        let mut space = Space::new();
        space.write16(STATUS + 2, STATUS_CAPABILITIES);
        space.write32(CAPABILITY_POINTER, 0x40);
        // First capability: power management (0x01) pointing at 0x50.
        space.write32(0x40, 0x50_01);
        // Second capability: MSI pointing at 0x70.
        space.write32(0x50, 0x70_05);
        // Third capability: MSI-X, list ends.
        space.write32(0x70, 0x00_11);
        let read = space.read();
        assert_eq!(
            find_capability(read, CAP_ID_MSI),
            Some(Capability {
                id: CAP_ID_MSI,
                offset: 0x50
            })
        );
        assert_eq!(find_capability(read, CAP_ID_MSIX).unwrap().offset, 0x70);
        assert_eq!(find_capability(read, 0x10), None);
    }

    #[test]
    fn functions_without_a_capability_list_or_with_a_bad_pointer_yield_none() {
        let mut space = Space::new();
        assert_eq!(find_capability(space.read(), CAP_ID_MSI), None);

        space.write16(STATUS + 2, STATUS_CAPABILITIES);
        // A pointer below the first legal capability is malformed.
        space.write32(CAPABILITY_POINTER, 0x10);
        assert_eq!(find_capability(space.read(), CAP_ID_MSI), None);

        // A misaligned pointer is malformed too.
        space.write32(CAPABILITY_POINTER, 0x42);
        assert_eq!(find_capability(space.read(), CAP_ID_MSI), None);

        // A self-referencing entry must not loop forever.
        space.write32(CAPABILITY_POINTER, 0x40);
        space.write32(0x40, 0x40_10);
        assert_eq!(find_capability(space.read(), CAP_ID_MSI), None);
    }

    #[test]
    fn the_thirty_two_bit_msi_form_fits_in_twelve_bytes() {
        let mut space = Space::new();
        space.write16(0x50 + 2, MSI_ENABLE);
        space.write32(0x50 + 4, MESSAGE_ADDRESS_BASE);
        space.write16(0x50 + 8, 0x40);
        let msi = Msi::decode(space.read(), 0x50).unwrap();
        assert_eq!(msi.offset, 0x50);
        assert!(msi.is_enabled());
        assert_eq!(msi.address, u64::from(MESSAGE_ADDRESS_BASE));
        assert_eq!(msi.data, 0x40);

        // The same data word read through the widened form.
        space.write16(0x50 + 2, MSI_ENABLE | MSI_ADDRESS_64);
        space.write32(0x50 + 8, 0x0);
        space.write16(0x50 + 12, 0x41);
        let wide = Msi::decode(space.read(), 0x50).unwrap();
        assert_eq!(wide.address, u64::from(MESSAGE_ADDRESS_BASE));
        assert_eq!(wide.data, 0x41);
    }

    #[test]
    fn a_capability_that_cannot_fit_is_refused() {
        let space = Space::new();
        assert_eq!(Msi::decode(space.read(), 0x10), Err(Error::Unsupported));
        assert_eq!(Msi::decode(space.read(), 0xfc), Err(Error::Unsupported));
    }

    #[test]
    fn messages_name_the_destination_apic_and_carry_the_vector() {
        let (address, data) = msi_message(3, 0x40);
        assert_eq!(address, 0xfee0_3000);
        assert_eq!(data, 0x40);
        let (address, data) = msi_message(0, 0xff);
        assert_eq!(address, u64::from(MESSAGE_ADDRESS_BASE));
        assert_eq!(data, 0xff);
        assert_eq!(byte(0x1234_5678, 0), 0x78);
        assert_eq!(byte(0x1234_5678, 3), 0x12);
    }
}
