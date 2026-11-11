//! PCI configuration-space access through the legacy 0xCF8/0xCFC pair.
//!
//! The bootstrap only needs to know what is on the bus, so this module reads
//! function headers and stops there: no BAR assignment, no Command register
//! writes and no interrupt routing. Everything it learns is validated by
//! `wuxia_core::pci`, which cannot see a device that reads as absent.

use core::arch::asm;

use wuxia_core::pci::{ConfigAddress, Function};

const CONFIG_ADDRESS: u16 = 0x0cf8;
const CONFIG_DATA: u16 = 0x0cfc;

/// Buses scanned during bootstrap.
///
/// QEMU's q35 machine puts every emulated function on bus 0 and real firmware
/// requires per-bus information that this bootstrap does not consume yet, so a
/// deeper walk would only add latency.
const SCANNED_BUSES: u8 = 1;

/// Highest number of functions reported to the log.
const MAX_REPORTED: usize = 4;

/// Read a 32-bit configuration register.
fn read_config(bus: u8, device: u8, function: u8, offset: u8) -> Option<u32> {
    let address = ConfigAddress::new(bus, device, function, offset).ok()?;
    // SAFETY: the configuration ports are fixed legacy ports, no other code in
    // the bootstrap touches them, and the address was validated above.
    unsafe {
        outl(CONFIG_ADDRESS, address.raw());
        Some(inl(CONFIG_DATA))
    }
}

/// Probe one function through the validated configuration address.
fn probe(bus: u8, device: u8, function: u8) -> Option<Function> {
    Function::probe(bus, device, function, |offset| {
        read_config(bus, device, function, offset).unwrap_or(u32::MAX)
    })
}

/// Class code of a network controller, as used by the bootstrap.
pub const CLASS_NETWORK: u8 = 0x02;

/// The first memory BAR of a function, which is where its registers live.
pub fn mmio_base(function: &Function) -> Option<u64> {
    bars(function)
        .into_iter()
        .flatten()
        .find(|bar| !bar.is_io)
        .map(|bar| bar.base)
}

/// Walk the scanned buses and report what was found through `report`.
///
/// Returns the number of functions present. Function 0 of a device must exist
/// before its siblings are probed, as the PCI specification requires, so a
/// device cannot advertise phantom functions.
pub fn enumerate(mut report: impl FnMut(&Function)) -> usize {
    let mut found = 0;
    let mut reported = 0;
    for bus in 0..SCANNED_BUSES {
        for device in 0..32 {
            let Some(first) = probe(bus, device, 0) else {
                continue;
            };
            report(&first);
            reported += 1;
            found += 1;
            let functions = match multifunction(bus, device) {
                true => 8,
                false => 1,
            };
            for function in 1..functions {
                let Some(other) = probe(bus, device, function) else {
                    continue;
                };
                if reported < MAX_REPORTED {
                    report(&other);
                    reported += 1;
                }
                found += 1;
            }
        }
    }
    found
}

/// Whether a device answered on more than one function.
fn multifunction(bus: u8, device: u8) -> bool {
    read_config(bus, device, 0, wuxia_core::pci::HEADER_REGISTERS)
        .map(|value| (value >> 16) as u8 & 0x80 != 0)
        .unwrap_or(false)
}

/// Decode the six base address registers of a type-0 function.
///
/// A 64-bit memory BAR consumes two register slots; the second one is skipped
/// in the result so its index does not appear as a bogus base address.
pub fn bars(function: &Function) -> [Option<wuxia_core::pci::Bar>; 6] {
    let mut decoded = [None; 6];
    if !function.header.has_bars() {
        return decoded;
    }
    let mut index = 0;
    while index < 6 {
        let offset = 0x10 + (index as u8) * 4;
        let Some(low) = read_config(function.bus, function.device, function.function, offset)
        else {
            index += 1;
            continue;
        };
        if low == 0 {
            // A register that reads as zero names no range: the function does
            // not implement this BAR.
            index += 1;
            continue;
        }
        let high = read_config(function.bus, function.device, function.function, offset + 4);
        match wuxia_core::pci::Bar::decode(low, high) {
            Ok(bar) => {
                decoded[index] = Some(bar);
                index += usize::from(bar.words);
            }
            // An absent or reserved BAR describes no range; skip its slot.
            Err(_) => index += 1,
        }
    }
    decoded
}

/// Write `value` to a 32-bit port.
///
/// # Safety
///
/// The caller must own `port`.
unsafe fn outl(port: u16, value: u32) {
    // SAFETY: the caller guarantees ownership of the port.
    unsafe {
        asm!(
            "out dx, eax",
            in("dx") port,
            in("eax") value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// Read a 32-bit port.
///
/// # Safety
///
/// The caller must own `port`.
unsafe fn inl(port: u16) -> u32 {
    let value: u32;
    // SAFETY: the caller guarantees ownership of the port.
    unsafe {
        asm!(
            "in eax, dx",
            in("dx") port,
            out("eax") value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}
