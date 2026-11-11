//! Vocabulary for the Intel 8254x network controller family.
//!
//! The bootstrap drives exactly one function: the emulated `e1000` that QEMU's
//! `q35` machine exposes. This module owns the parts of that contract that can
//! be checked without a device: register offsets, the reset and transmit bits,
//! the sixteen-byte transmit descriptor layout and the two ways the controller
//! reports its MAC address. The kernel performs the port accesses.
//!
//! Only what is used is modelled. Descriptor rings here are one page of
//! eight descriptors, receive is not implemented, and nothing about the
//! hardware's scatter-gather, checksum offload or multi-queue modes is claimed.

use crate::{Error, Result};

/// Size of one legacy transmit or receive descriptor.
pub const DESCRIPTOR_SIZE: usize = 16;

/// Highest number of descriptors one ring page can hold.
pub const MAX_DESCRIPTORS: usize = 256;

/// Descriptor ring length the bootstrap programs, in bytes.
///
/// The controller requires a multiple of 128 bytes.
pub const RING_BYTES: u32 = 128;

/// Number of descriptors in [`RING_BYTES`].
pub const RING_DESCRIPTORS: u32 = RING_BYTES / DESCRIPTOR_SIZE as u32;

/// Highest register offset the bootstrap touches inside BAR0.
pub const BAR_SIZE: u32 = 0x2_0000;

/// Device control register.
pub const CTRL: u32 = 0x0000;
/// Device status register.
pub const STATUS: u32 = 0x0008;
/// EEPROM read register.
pub const EERD: u32 = 0x0014;
/// Receive control register.
pub const RCTL: u32 = 0x0100;
/// Transmit control register.
pub const TCTL: u32 = 0x0400;
/// Receive descriptor base, low half.
pub const RDBAL: u32 = 0x2800;
/// Receive descriptor base, high half.
pub const RDBAH: u32 = 0x2804;
/// Receive descriptor ring length in bytes.
pub const RDLEN: u32 = 0x2808;
/// Receive descriptor head.
pub const RDH: u32 = 0x2810;
/// Receive descriptor tail.
pub const RDT: u32 = 0x2818;
/// Transmit descriptor base, low half.
pub const TDBAL: u32 = 0x3800;
/// Transmit descriptor base, high half.
pub const TDBAH: u32 = 0x3804;
/// Transmit descriptor ring length in bytes.
pub const TDLEN: u32 = 0x3808;
/// Transmit descriptor head.
pub const TDH: u32 = 0x3810;
/// Transmit descriptor tail.
pub const TDT: u32 = 0x3818;
/// Receive address low: bytes 0-3 of the MAC address.
pub const RAL: u32 = 0x5400;
/// Receive address high: bytes 4-5 of the MAC address.
pub const RAH: u32 = 0x5404;

/// `CTRL.RST`: reset the controller.
pub const CTRL_RST: u32 = 1 << 26;
/// `CTRL.SLU`: set link up.
pub const CTRL_SLU: u32 = 1 << 6;
/// `CTRL.ASDE`: auto-speed detection.
pub const CTRL_ASDE: u32 = 1 << 5;

/// `STATUS.LU`: link is up.
pub const STATUS_LU: u32 = 1 << 1;

/// `TCTL.EN`: enable the transmit path.
pub const TCTL_EN: u32 = 1 << 1;
/// `TCTL.PSP`: pad short packets.
pub const TCTL_PSP: u32 = 1 << 3;

/// Collision distance field shift in `TCTL`.
pub const TCTL_COLD_SHIFT: u32 = 4;
/// Collision threshold field shift in `TCTL`.
pub const TCTL_CT_SHIFT: u32 = 12;

/// Transmit descriptor command: end of packet.
pub const TX_CMD_EOP: u8 = 1 << 0;
/// Transmit descriptor command: insert an Ethernet FCS.
pub const TX_CMD_IFCS: u8 = 1 << 1;
/// Transmit descriptor command: report completion in the status byte.
pub const TX_CMD_RS: u8 = 1 << 3;

/// Transmit descriptor status: descriptor done.
pub const TX_STATUS_DD: u8 = 1 << 0;

/// Smallest Ethernet frame the controller must be willing to send.
pub const MIN_FRAME: usize = 60;
/// Largest frame the bootstrap reserves room for.
pub const MAX_FRAME: usize = 1514;

/// `EERD.START`: begin an EEPROM read.
pub const EERD_START: u32 = 1 << 0;
/// `EERD.DONE`: the read finished.
pub const EERD_DONE: u32 = 1 << 4;

/// A validated 32-bit register access inside BAR0.
///
/// The controller ignores writes above its implemented register file and a
/// misaligned access faults or wraps depending on the platform, so the offset is
/// checked before any port or mapping is used.
pub const fn register(offset: u32) -> Result<u32> {
    if !offset.is_multiple_of(4) || offset >= BAR_SIZE {
        return Err(Error::BadAddress);
    }
    Ok(offset)
}

/// One legacy transmit descriptor.
///
/// The legacy layout is a 64-bit buffer address, a 16-bit length, two checksum
/// offsets, a command byte, a status byte, and a 16-bit special field. The
/// bootstrap only sets address, length and command and only reads status, so the
/// remaining fields are always encoded as zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxDescriptor {
    /// Physical address of the frame bytes.
    pub buffer: u64,
    /// Number of bytes to send.
    pub length: u16,
    /// Command bits, built from the `TX_CMD_*` constants.
    pub command: u8,
}

impl TxDescriptor {
    /// Build a descriptor by validating the frame length and the buffer address.
    ///
    /// Errors: [`Error::InvalidInput`] for a length outside
    /// [`MIN_FRAME`]..=[`MAX_FRAME`], and [`Error::BadAddress`] for a buffer
    /// address that is not 16-byte aligned, since the controller requires that
    /// alignment for legacy descriptors.
    pub const fn new(buffer: u64, length: usize, command: u8) -> Result<Self> {
        if length < MIN_FRAME || length > MAX_FRAME {
            return Err(Error::InvalidInput);
        }
        if buffer == 0 || !buffer.is_multiple_of(DESCRIPTOR_SIZE as u64) {
            return Err(Error::BadAddress);
        }
        Ok(Self {
            buffer,
            length: length as u16,
            command,
        })
    }

    /// Encode the descriptor as the sixteen bytes the controller reads.
    pub const fn encode(self) -> [u8; DESCRIPTOR_SIZE] {
        let address = self.buffer.to_le_bytes();
        let length = self.length.to_le_bytes();
        [
            address[0],
            address[1],
            address[2],
            address[3],
            address[4],
            address[5],
            address[6],
            address[7],
            length[0],
            length[1],
            0,
            self.command,
            0,
            0,
            0,
            0,
        ]
    }

    /// Whether the descriptor's status byte reports completion.
    pub const fn is_done(descriptor: &[u8; DESCRIPTOR_SIZE]) -> bool {
        descriptor[12] & TX_STATUS_DD != 0
    }
}

/// Decode the MAC address from the receive-address registers.
///
/// The controller stores the first four bytes in [`RAL`] and the last two in
/// [`RAH`]. A value that is all zeroes or all ones describes no station, so it is
/// refused rather than logged as an address.
///
/// Errors: [`Error::InvalidInput`] for an unspecified or broadcast address.
pub fn mac_from_registers(ral: u32, rah: u32) -> Result<[u8; 6]> {
    let low = ral.to_le_bytes();
    let high = rah.to_le_bytes();
    if ral == 0 && rah == 0 {
        return Err(Error::InvalidInput);
    }
    if ral == u32::MAX && (rah & 0xffff) == 0xffff {
        return Err(Error::InvalidInput);
    }
    let mac = [low[0], low[1], low[2], low[3], high[0], high[1]];
    if mac[0] & 1 != 0 {
        // A multicast or broadcast station address cannot be this controller's
        // own address.
        return Err(Error::InvalidInput);
    }
    Ok(mac)
}

/// Assemble a MAC address from three EEPROM words.
///
/// The `e1000` stores the station address in the first three words of its
/// serial EEPROM, least-significant word first.
pub fn mac_from_eeprom(words: [u16; 3]) -> [u8; 6] {
    let first = words[0].to_le_bytes();
    let second = words[1].to_le_bytes();
    let third = words[2].to_le_bytes();
    [first[0], first[1], second[0], second[1], third[0], third[1]]
}

/// Encode the `EERD` register for reading one EEPROM word.
pub const fn eeprom_read_command(address: u8) -> u32 {
    EERD_START | ((address as u32) << 8)
}

/// Extract the data word from an `EERD` readback.
pub const fn eeprom_read_data(value: u32) -> u16 {
    (value >> 16) as u16
}

/// Build the value written to [`TCTL`] to enable transmission.
///
/// The collision distance and threshold are fixed at the values the datasheet
/// recommends for a 1000 Mb/s link, because the bootstrap does not negotiate.
pub const fn transmit_control() -> u32 {
    let distance = 0x40 << TCTL_COLD_SHIFT;
    let threshold = 0x10 << TCTL_CT_SHIFT;
    distance | threshold | TCTL_PSP | TCTL_EN
}

/// Build the value written to [`CTRL`] to bring the link up with autonegotiation.
pub const fn link_up_control() -> u32 {
    CTRL_SLU | CTRL_ASDE
}

/// Format a MAC address as lowercase hex without separators.
///
/// The bootstrap logs three 16-bit groups, which is exactly a `MAC:` free
/// representation that fits the log's hex writer.
pub fn mac_words(mac: [u8; 6]) -> [u16; 3] {
    [
        u16::from_le_bytes([mac[0], mac[1]]),
        u16::from_le_bytes([mac[2], mac[3]]),
        u16::from_le_bytes([mac[4], mac[5]]),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_must_be_aligned_and_inside_the_bar() {
        assert_eq!(register(CTRL), Ok(0));
        assert_eq!(register(RAH), Ok(0x5404));
        assert_eq!(register(0x5402), Err(Error::BadAddress));
        assert_eq!(register(BAR_SIZE), Err(Error::BadAddress));
    }

    #[test]
    fn transmit_descriptors_encode_address_length_and_command() {
        let descriptor =
            TxDescriptor::new(0x1_f000, 60, TX_CMD_EOP | TX_CMD_IFCS | TX_CMD_RS).unwrap();
        let bytes = descriptor.encode();
        assert_eq!(&bytes[..8], &0x1_f000u64.to_le_bytes());
        assert_eq!(&bytes[8..10], &60u16.to_le_bytes());
        assert_eq!(bytes[10], 0);
        assert_eq!(bytes[11], TX_CMD_EOP | TX_CMD_IFCS | TX_CMD_RS);
        assert_eq!(bytes[12], 0);
        assert_eq!(bytes[13..16], [0, 0, 0]);
        assert!(!TxDescriptor::is_done(&bytes));

        let mut done = bytes;
        done[12] |= TX_STATUS_DD;
        assert!(TxDescriptor::is_done(&done));
    }

    #[test]
    fn transmit_descriptors_refuse_short_long_and_misaligned_frames() {
        assert_eq!(TxDescriptor::new(0x1000, 59, 0), Err(Error::InvalidInput));
        assert_eq!(
            TxDescriptor::new(0x1000, MAX_FRAME + 1, 0),
            Err(Error::InvalidInput)
        );
        assert_eq!(TxDescriptor::new(0, 60, 0), Err(Error::BadAddress));
        assert_eq!(TxDescriptor::new(0x1001, 60, 0), Err(Error::BadAddress));
    }

    #[test]
    fn mac_addresses_come_from_the_receive_address_registers() {
        // 52:54:00:12:34:56 as QEMU programs it.
        assert_eq!(
            mac_from_registers(0x1200_5452, 0x0000_5634),
            Ok([0x52, 0x54, 0x00, 0x12, 0x34, 0x56])
        );
        assert_eq!(mac_from_registers(0, 0), Err(Error::InvalidInput));
        assert_eq!(
            mac_from_registers(u32::MAX, 0xffff),
            Err(Error::InvalidInput)
        );
        // A multicast station address is not a station address.
        assert_eq!(
            mac_from_registers(0x1200_5453, 0x0000_5634),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn eeprom_words_assemble_into_the_same_address() {
        let words = [0x5452u16, 0x1200, 0x5634];
        assert_eq!(mac_from_eeprom(words), [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        assert_eq!(mac_words([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]), words);
        assert_eq!(eeprom_read_command(2), EERD_START | 0x200);
        assert_eq!(eeprom_read_data(0x1234_abcd), 0x1234);
    }

    #[test]
    fn transmit_control_enables_the_path() {
        let control = transmit_control();
        assert_ne!(control & TCTL_EN, 0);
        assert_ne!(control & TCTL_PSP, 0);
        assert_eq!(control >> TCTL_CT_SHIFT & 0xf, 0x10 >> 0 & 0xf);
        assert_eq!((control >> TCTL_COLD_SHIFT) & 0xff, 0x40);
        assert_ne!(link_up_control() & CTRL_SLU, 0);
        assert_eq!(RING_BYTES / DESCRIPTOR_SIZE as u32, RING_DESCRIPTORS);
        assert_eq!(RING_DESCRIPTORS, 8);
    }
}
