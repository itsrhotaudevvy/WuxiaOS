//! PCI configuration-space access through the legacy 0xCF8/0xCFC pair.
//!
//! The bootstrap reads function headers, measures BARs, enables decoding and, for
//! a function that offers it, turns on message-signalled interrupts. BAR
//! *assignment* is not implemented: the firmware's addresses are used as found.
//! Everything it learns is validated by `wuxia_core::pci` and
//! `wuxia_core::msi`, which cannot see a device that reads as absent.

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

/// Configuration offset of the Command register.
const COMMAND: u8 = 0x04;
/// Command bit 1: respond to memory-space accesses.
pub const COMMAND_MEMORY: u16 = 1 << 1;
/// Command bit 2: act as a bus master.
pub const COMMAND_BUS_MASTER: u16 = 1 << 2;

/// Read the Command register of a function.
fn read_command(function: &Function) -> Option<u16> {
    read_config(function.bus, function.device, function.function, COMMAND).map(|value| value as u16)
}

/// Write a 32-bit configuration register.
fn write_config(bus: u8, device: u8, function: u8, offset: u8, value: u32) -> Option<()> {
    let address = ConfigAddress::new(bus, device, function, offset).ok()?;
    // SAFETY: as for `read_config`; the address was validated above.
    unsafe {
        outl(CONFIG_ADDRESS, address.raw());
        outl(CONFIG_DATA, value);
    }
    Some(())
}

/// Write the Command register of a function.
fn write_command(function: &Function, value: u16) -> Option<()> {
    let address =
        ConfigAddress::new(function.bus, function.device, function.function, COMMAND).ok()?;
    // The upper half of the register belongs to the Status register and must be
    // preserved, so read-modify-write instead of overwriting both halves.
    let current = read_config(function.bus, function.device, function.function, COMMAND)?;
    let merged = (current & 0xffff_0000) | u32::from(value);
    // SAFETY: the configuration ports are fixed legacy ports and the address was
    // validated above.
    unsafe {
        outl(CONFIG_ADDRESS, address.raw());
        outl(CONFIG_DATA, merged);
    }
    Some(())
}

/// Enable memory-space decoding and bus mastering for a function.
///
/// DMA and memory-mapped register access both require these bits, and neither
/// is useful before the ranges are known. Returns the command register before
/// and after the change so the caller can log them.
pub fn enable(function: &Function) -> Option<(u16, u16)> {
    let before = read_command(function)?;
    let wanted = before | COMMAND_MEMORY | COMMAND_BUS_MASTER;
    if wanted != before {
        write_command(function, wanted)?;
    }
    let after = read_command(function)?;
    Some((before, after))
}

/// Measure one BAR by writing all ones and restoring the original value.
///
/// The Command register is read, memory and port decoding are disabled for the
/// duration of the probe, and the original value is restored afterwards. A
/// 64-bit memory BAR is probed through both halves. Returns the range length in
/// bytes, or zero when the register implements no addresses.
///
/// The probe is skipped for a function with no BARs and refuses an index that
/// the function does not expose.
pub fn size_bar(function: &Function, index: u8) -> Option<u64> {
    if !function.header.has_bars() || index >= 6 {
        return None;
    }
    let offset = 0x10 + index * 4;
    let save = read_config(function.bus, function.device, function.function, COMMAND)?;
    let original_low = read_config(function.bus, function.device, function.function, offset)?;
    let is_io = original_low & 1 != 0;
    let words = match is_io {
        true => 1,
        // Bits 2:1 of a memory BAR select the width; 64-bit BARs use two words.
        false if (original_low >> 1) & 0x3 == 0x2 => 2,
        false => 1,
    };
    let original_high = match words {
        2 => read_config(function.bus, function.device, function.function, offset + 4)?,
        _ => 0,
    };
    // Disable decoding so the all-ones value cannot reach the bus.
    write_command(function, (save & 0xffff) as u16 & !0x3)?;
    let address = |register: u8| {
        ConfigAddress::new(function.bus, function.device, function.function, register).ok()
    };
    // SAFETY: the ports are the fixed legacy configuration pair and both
    // addresses were validated.
    unsafe {
        outl(CONFIG_ADDRESS, address(offset)?.raw());
        outl(CONFIG_DATA, u32::MAX);
        if words == 2 {
            outl(CONFIG_ADDRESS, address(offset + 4)?.raw());
            outl(CONFIG_DATA, u32::MAX);
        }
    }
    let mask_low = read_config(function.bus, function.device, function.function, offset)?;
    let mask_high = match words {
        2 => read_config(function.bus, function.device, function.function, offset + 4)?,
        _ => 0,
    };
    // SAFETY: restore the original base and the original command word.
    unsafe {
        outl(CONFIG_ADDRESS, address(offset)?.raw());
        outl(CONFIG_DATA, original_low);
        if words == 2 {
            outl(CONFIG_ADDRESS, address(offset + 4)?.raw());
            outl(CONFIG_DATA, original_high);
        }
    }
    write_command(function, save as u16)?;
    // Truncate the readback to the register's address width: hardware answers
    // with ones above the implemented width, and a 32-bit BAR cannot describe
    // an address above 4 GiB.
    let width_bits = match (is_io, words) {
        (true, _) => 16,
        (false, 2) => 52,
        (false, _) => 32,
    };
    let address_mask = if width_bits == 52 {
        (1u64 << 52) - 1
    } else {
        (1u64 << width_bits) - 1
    };
    let low_mask = if is_io {
        u64::from(mask_low & 0xfffc)
    } else {
        u64::from(mask_low & !0xf)
    };
    let mask = (low_mask | (u64::from(mask_high) << 32)) & address_mask;
    wuxia_core::pci::bar_size(mask, is_io, width_bits).ok()
}

/// Whether a function advertises the MSI capability, and where it starts.
pub fn msi_capability(function: &Function) -> Option<wuxia_core::msi::Msi> {
    let captured = |offset: u8| {
        read_config(function.bus, function.device, function.function, offset).unwrap_or(u32::MAX)
    };
    let capability = wuxia_core::msi::find_capability(captured, wuxia_core::msi::CAP_ID_MSI)?;
    wuxia_core::msi::Msi::decode(captured, capability.offset).ok()
}

/// Write one byte of configuration space.
fn write_config_byte(bus: u8, device: u8, function: u8, offset: u8, value: u8) -> Option<()> {
    // Configuration transfers are dword-wide, so the address names the register
    // containing the byte and the byte position selects within it.
    let address = ConfigAddress::new(bus, device, function, offset & !3).ok()?;
    let current = read_config(bus, device, function, offset & !3)?;
    let shift = u32::from(offset % 4) * 8;
    let merged = (current & !(0xff << shift)) | (u32::from(value) << shift);
    // SAFETY: the configuration ports are fixed legacy ports and the address was
    // validated above.
    unsafe {
        outl(CONFIG_ADDRESS, address.raw());
        outl(CONFIG_DATA, merged);
    }
    Some(())
}

/// Probe one function without enumerating the bus.
pub fn function(bus: u8, device: u8, function: u8) -> Option<Function> {
    probe(bus, device, function)
}

/// Point a chipset's four PCI interrupt lines at the given interrupt controller
/// lines.
///
/// On this chipset each of the four lines is described by one byte in the LPC
/// bridge's configuration space: bit 7 selects the advanced interrupt controller
/// instead of the legacy 8259, and the low four bits carry the line number. Writing
/// these is what makes a PCI function's interrupt reach the I/O APIC at all; the
/// firmware normally leaves them pointing at the 8259. Returns the four bytes that
/// were written, in line order.
pub fn route_pci_lines(lpc: &Function, lines: [u8; 4]) -> Option<[u8; 4]> {
    let mut written = [0u8; 4];
    for (index, line) in lines.iter().enumerate() {
        // The high bit selects the advanced controller with a numbered line above
        // the legacy range; a plain line number keeps the line on the 8259.
        let value = *line;
        write_config_byte(lpc.bus, lpc.device, lpc.function, 0x60 + index as u8, value)?;
        written[index] = value;
    }
    Some(written)
}

/// Read the four PCI interrupt line routing bytes.
pub fn pci_line_routing(lpc: &Function) -> [u8; 4] {
    let register = read_config(lpc.bus, lpc.device, lpc.function, 0x60).unwrap_or(0);
    register.to_le_bytes()
}

/// Read the interrupt line and pin a function reports.
///
/// Returns `(line, pin)`. A pin of zero means the function raises no interrupt;
/// a non-zero pin is 1 for INTA through 4 for INTD. The line is the firmware's
/// suggestion and is not authoritative on a machine that routes PCI lines through
/// an I/O APIC, which is why the caller logs it rather than trusting it.
pub fn interrupt_line(function: &Function) -> (u8, u8) {
    let register = read_config(function.bus, function.device, function.function, 0x3c).unwrap_or(0);
    (register as u8, (register >> 8) as u8)
}

/// Enable message-signalled interrupts on a function.
///
/// The message names the destination APIC and the vector the local APIC should
/// raise. The address and data words are written before the enable bit, so a
/// half-configured message can never be delivered. Returns the decoded capability
/// after the writes, so the caller logs what the function actually accepted
/// rather than what was requested.
pub fn enable_msi(function: &Function, apic: u8, vector: u8) -> Option<wuxia_core::msi::Msi> {
    let msi = msi_capability(function)?;
    let (address, data) = wuxia_core::msi::msi_message(apic, vector);
    let bus = function.bus;
    let device = function.device;
    let function_number = function.function;
    let offset = msi.offset;
    write_config(bus, device, function_number, offset + 4, address as u32)?;
    if msi.control & wuxia_core::msi::MSI_ADDRESS_64 != 0 {
        write_config(
            bus,
            device,
            function_number,
            offset + 8,
            (address >> 32) as u32,
        )?;
        let high = offset + 12;
        let current = read_config(bus, device, function_number, high & !3)?;
        let shift = u32::from(high % 4) * 8;
        let merged = (current & !(0xffff << shift)) | (u32::from(data) << shift);
        write_config(bus, device, function_number, high & !3, merged)?;
    } else {
        let data_offset = offset + 8;
        let current = read_config(bus, device, function_number, data_offset & !3)?;
        let shift = u32::from(data_offset % 4) * 8;
        let merged = (current & !(0xffff << shift)) | (u32::from(data) << shift);
        write_config(bus, device, function_number, data_offset & !3, merged)?;
    }
    // Read-modify-write the control word so the multiple-message bits the firmware
    // set are preserved, then set the enable bit last.
    let header = read_config(bus, device, function_number, offset & !3)?;
    let shift = u32::from(offset % 4) * 8;
    let control = (header >> (shift + 16)) as u16 | wuxia_core::msi::MSI_ENABLE;
    let merged = (header & !(0xffff << (shift + 16))) | (u32::from(control) << (shift + 16));
    write_config(bus, device, function_number, offset & !3, merged)?;
    msi_capability(function)
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
