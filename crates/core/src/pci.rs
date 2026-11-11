//! PCI configuration-space vocabulary.
//!
//! A PCI function is addressed by bus, device, function and register offset.
//! The kernel reads that space through the legacy 0xCF8/0xCFC pair, but the
//! address format and the field decoding live here so a host test can exercise
//! the bit layout without a QEMU instance.
//!
//! Nothing in this module trusts a device: a function that reports a vendor of
//! `0xffff` does not exist, and a BAR is only accepted when its type, width and
//! alignment describe a range the bus can actually decode.

use crate::{Error, Result};

/// Offset of the vendor identifier in a function's header.
pub const VENDOR_ID: u8 = 0x00;
/// Offset of the device identifier in a function's header.
pub const DEVICE_ID: u8 = 0x02;
/// Offset of the dword holding revision, programming interface, subclass and class.
///
/// The four bytes are read as one register because the class bytes are not
/// dword-aligned on their own.
pub const CLASS_REGISTERS: u8 = 0x08;
/// Offset of the dword whose third byte is the header type.
///
/// The byte itself lives at 0x0e, which is not dword-aligned, so the register
/// is read as a whole like the class bytes.
pub const HEADER_REGISTERS: u8 = 0x0c;
/// Vendor identifier reported by an absent function.
pub const NO_VENDOR: u16 = 0xffff;

/// Validated configuration address of one 32-bit register.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigAddress(u32);

impl ConfigAddress {
    /// Encode a bus/device/function/offset address.
    ///
    /// Errors:
    /// - [`Error::InvalidInput`]: `function` is above 7 or `offset` is not
    ///   dword-aligned or does not fit the 8-bit register field.
    pub fn new(bus: u8, device: u8, function: u8, offset: u8) -> Result<Self> {
        if device > 31 {
            return Err(Error::InvalidInput);
        }
        if function > 7 {
            return Err(Error::InvalidInput);
        }
        if !offset.is_multiple_of(4) || offset > 0xfc {
            return Err(Error::InvalidInput);
        }
        Ok(Self(
            0x8000_0000
                | (u32::from(bus) << 16)
                | (u32::from(device) << 11)
                | (u32::from(function) << 8)
                | u32::from(offset),
        ))
    }

    /// The 32-bit value to write to the configuration-address port.
    pub const fn raw(self) -> u32 {
        self.0
    }
}

/// A decoded base address register on a type-0 function.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bar {
    /// Whether the register describes an I/O port range.
    pub is_io: bool,
    /// Whether the range is prefetchable (memory BARs only).
    pub prefetchable: bool,
    /// Number of 32-bit words the BAR occupies, either 1 or 2 for a 64-bit BAR.
    pub words: u8,
    /// Base address with the type bits removed.
    pub base: u64,
}

impl Bar {
    /// Decode one BAR from its low and (for 64-bit memory BARs) high halves.
    ///
    /// Errors:
    /// - [`Error::InvalidInput`]: the BAR uses the reserved type 0b10 or claims
    ///   a 64-bit range whose high half is missing.
    pub fn decode(low: u32, high: Option<u32>) -> Result<Self> {
        if low & 0x1 != 0 {
            // I/O space: bit 0 is the type, bit 1 is reserved.
            if low & 0x2 != 0 {
                return Err(Error::InvalidInput);
            }
            return Ok(Self {
                is_io: true,
                prefetchable: false,
                words: 1,
                base: u64::from(low & !0x3),
            });
        }
        // Bits 2:1 select the memory BAR width: 0 is 32-bit, 2 is 64-bit.
        // The legacy 20-bit form (1) and the reserved form (3) are refused.
        let kind = (low >> 1) & 0x3;
        let prefetchable = low & 0x8 != 0;
        match kind {
            0x0 => Ok(Self {
                is_io: false,
                prefetchable,
                words: 1,
                base: u64::from(low & !0xf),
            }),
            0x2 => {
                let high = high.ok_or(Error::InvalidInput)?;
                Ok(Self {
                    is_io: false,
                    prefetchable,
                    words: 2,
                    base: u64::from(low & !0xf) | (u64::from(high) << 32),
                })
            }
            _ => Err(Error::InvalidInput),
        }
    }
}

/// What a function's header says about itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Header {
    /// A normal function with six BARs.
    Device,
    /// A bridge with BARs 0 and 1 and bus-number registers.
    Bridge,
    /// A cardbus bridge.
    CardBus,
    /// A type this kernel does not describe.
    Other(u8),
}

impl Header {
    /// Decode the low seven bits of the header-type register.
    pub const fn from_raw(raw: u8) -> Self {
        match raw & 0x7f {
            0x00 => Self::Device,
            0x01 => Self::Bridge,
            0x02 => Self::CardBus,
            other => Self::Other(other),
        }
    }

    /// Whether this header has the six-BAR layout.
    pub const fn has_bars(self) -> bool {
        matches!(self, Self::Device)
    }
}

/// A field read from a function's configuration space.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Function {
    /// Bus number the function answered on.
    pub bus: u8,
    /// Device number the function answered on.
    pub device: u8,
    /// Function number the function answered on.
    pub function: u8,
    /// Reported vendor.
    pub vendor: u16,
    /// Reported device.
    pub device_id: u16,
    /// Class code base byte.
    pub class: u8,
    /// Class subclass byte.
    pub subclass: u8,
    /// Programming interface byte.
    pub prog_if: u8,
    /// Decoded header type.
    pub header: Header,
}

impl Function {
    /// Read the identifying registers of a function through `read`.
    ///
    /// `read` must return the 32-bit register at the given offset. A function
    /// whose vendor reads as [`NO_VENDOR`] does not exist and yields `None`
    /// rather than a fabricated device.
    pub fn probe(bus: u8, device: u8, function: u8, read: impl Fn(u8) -> u32) -> Option<Self> {
        let identity = read(0x00);
        let vendor = (identity & 0xffff) as u16;
        if vendor == NO_VENDOR {
            return None;
        }
        let device_id = (identity >> 16) as u16;
        let class_registers = read(CLASS_REGISTERS);
        let class = (class_registers >> 24) as u8;
        let subclass = (class_registers >> 16) as u8;
        let header = Header::from_raw((read(HEADER_REGISTERS) >> 16) as u8);
        Some(Self {
            bus,
            device,
            function,
            vendor,
            device_id,
            class,
            subclass,
            prog_if: (class_registers >> 8) as u8,
            header,
        })
    }

    /// Whether this function is a mass-storage controller.
    pub const fn is_storage(self) -> bool {
        self.class == 0x01
    }

    /// Whether this function is a display controller.
    pub const fn is_display(self) -> bool {
        self.class == 0x03
    }

    /// Whether this function is a bridge of any kind.
    pub const fn is_bridge(self) -> bool {
        self.class == 0x06
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_address_encodes_the_documented_layout() {
        let address = ConfigAddress::new(1, 2, 3, 0x10).unwrap();
        assert_eq!(
            address.raw(),
            0x8000_0000 | (1 << 16) | (2 << 11) | (3 << 8) | 0x10
        );
        let zero = ConfigAddress::new(0, 0, 0, 0).unwrap();
        assert_eq!(zero.raw(), 0x8000_0000);
    }

    #[test]
    fn configuration_address_rejects_unreachable_requests() {
        assert_eq!(ConfigAddress::new(0, 32, 0, 0), Err(Error::InvalidInput));
        assert_eq!(ConfigAddress::new(0, 0, 8, 0), Err(Error::InvalidInput));
        assert_eq!(ConfigAddress::new(0, 0, 0, 2), Err(Error::InvalidInput));
        assert_eq!(ConfigAddress::new(0, 0, 0, 0xfe), Err(Error::InvalidInput));
    }

    #[test]
    fn io_bars_drop_the_type_bits() {
        let bar = Bar::decode(0xc001, None).unwrap();
        assert!(bar.is_io);
        assert_eq!(bar.words, 1);
        assert_eq!(bar.base, 0xc000);
        assert_eq!(Bar::decode(0xc003, None), Err(Error::InvalidInput));
    }

    #[test]
    fn memory_bars_keep_thirty_two_and_sixty_four_bit_shapes() {
        let bar = Bar::decode(0xfebf_f008, None).unwrap();
        assert!(!bar.is_io);
        assert!(bar.prefetchable);
        assert_eq!(bar.words, 1);
        assert_eq!(bar.base, 0xfebf_f000);

        let bar = Bar::decode(0xf000_0004, Some(0x0000_0001)).unwrap();
        assert_eq!(bar.words, 2);
        assert_eq!(bar.base, 0x0000_0001_f000_0000);

        // A 64-bit type without its high half cannot be decoded.
        assert_eq!(Bar::decode(0x0000_0004, None), Err(Error::InvalidInput));
        // The legacy 20-bit form and the reserved form are refused.
        assert_eq!(Bar::decode(0x0000_0002, None), Err(Error::InvalidInput));
        assert_eq!(Bar::decode(0x0000_0006, None), Err(Error::InvalidInput));
    }

    #[test]
    fn header_types_are_classified_and_gated() {
        assert_eq!(Header::from_raw(0x00), Header::Device);
        assert_eq!(Header::from_raw(0x80), Header::Device);
        assert_eq!(Header::from_raw(0x01), Header::Bridge);
        assert_eq!(Header::from_raw(0x02), Header::CardBus);
        assert_eq!(Header::from_raw(0x7f), Header::Other(0x7f));
        assert!(Header::Device.has_bars());
        assert!(!Header::Bridge.has_bars());
    }

    fn fake_function() -> impl Fn(u8) -> u32 {
        |offset| match offset {
            0x00 => 0x29c0_8086,
            0x08 => 0x0600_0000,
            0x0c => 0x0000_0000,
            _ => 0,
        }
    }

    #[test]
    fn probe_reads_identity_and_classification() {
        let function = Function::probe(0, 0, 0, fake_function()).unwrap();
        assert_eq!(function.vendor, 0x8086);
        assert_eq!(function.device_id, 0x29c0);
        assert_eq!(function.class, 0x06);
        assert!(function.is_bridge());
        assert!(!function.is_storage());
    }

    #[test]
    fn an_absent_function_reports_no_vendor() {
        let absent = |_offset: u8| 0xffff_ffff;
        assert_eq!(Function::probe(0, 31, 7, absent), None);
    }
}
