//! Device interrupt bookkeeping.
//!
//! The interrupt handler runs inside the trap frame, so it may not allocate,
//! block or take a lock another context could hold. It does the three things it
//! must: count the interrupt, acknowledge the controller that raised it, and end
//! the interrupt at the local APIC. Everything else is deferred to the boot thread
//! that polls [`count`].
//!
//! The local APIC is published once, before any device is allowed to send a
//! message; a second publish would lose the window the first one mapped.

use wuxia_core::Result;

use crate::apic::Local;

/// Local APIC the handler acknowledges, once interrupt delivery is enabled.
static mut LOCAL: Option<Local> = None;

/// Device interrupts taken since boot.
static mut COUNT: u64 = 0;

/// Publish the local APIC the handler must acknowledge.
pub fn install(local: Local) {
    // SAFETY: the bootstrap is single-threaded and this runs before any device
    // interrupt can be raised.
    unsafe {
        LOCAL = Some(local);
    }
}

/// End the interrupt currently being serviced at the local APIC.
///
/// The 8259 vectors are delivered through the local APIC once its spurious
/// vector register enables it, so a handler for a legacy line must acknowledge
/// both controllers. Without this the APIC's in-service bit stays set and blocks
/// every interrupt at or below that priority, which looks exactly like the timer
/// stopping.
pub fn end_of_interrupt() {
    // SAFETY: single-threaded publication before any interrupt was unmasked.
    if let Some(local) = unsafe { LOCAL } {
        let _ = local.end_of_interrupt();
    }
}

/// Service one interrupt raised through a legacy 8259 line.
///
/// The device is acknowledged before the line: a level-triggered line stays
/// asserted until its cause is cleared, so acknowledging the controller first is
/// what stops the handler from being entered again immediately.
pub fn service_line(line: u8) -> Result<()> {
    // SAFETY: only the handler writes the counter.
    unsafe {
        let counter = core::ptr::addr_of_mut!(COUNT);
        core::ptr::write_volatile(counter, core::ptr::read_volatile(counter).wrapping_add(1));
    }
    let cause = crate::net::acknowledge_interrupt();
    let seen = count();
    crate::log::write_str(if seen == 1 {
        "WUXIA_IRQ_DEVICE\n"
    } else {
        "WUXIA_IRQ\n"
    });
    crate::log::write_hex(u64::from(cause));
    crate::log::write_hex(u64::from(line));
    crate::interrupts::end_of_interrupt(line);
    end_of_interrupt();
    Ok(())
}

/// Number of device interrupts taken so far.
pub fn count() -> u64 {
    // SAFETY: a single 64-bit load of a value only the handler writes.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(COUNT)) }
}

/// Service one device interrupt.
///
/// The device is acknowledged first and the local APIC last: an interrupt that
/// arrived while this one was being handled must stay pending until the cause is
/// cleared, or the APIC redelivers it forever.
pub fn service() -> Result<u32> {
    // SAFETY: only the handler writes the counter.
    unsafe {
        let counter = core::ptr::addr_of_mut!(COUNT);
        core::ptr::write_volatile(counter, core::ptr::read_volatile(counter).wrapping_add(1));
    }
    let cause = crate::net::acknowledge_interrupt();
    let seen = count();
    crate::log::write_str(if seen == 1 {
        "WUXIA_IRQ_DEVICE\n"
    } else {
        "WUXIA_IRQ\n"
    });
    crate::log::write_hex(u64::from(cause));
    // SAFETY: single-threaded publication before any interrupt was unmasked.
    if let Some(local) = unsafe { LOCAL } {
        local.end_of_interrupt()?;
    }
    Ok(cause)
}
