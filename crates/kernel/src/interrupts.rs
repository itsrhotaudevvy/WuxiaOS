//! Legacy 8259 PIC and 8254 PIT setup for the bootstrap timer.
//!
//! The PIC is remapped away from the processor exception vectors and only IRQ0
//! is unmasked. The timer handler itself lives in [`crate::idt`].

use core::arch::asm;
use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

const PIC1_COMMAND: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_COMMAND: u16 = 0xa0;
const PIC2_DATA: u16 = 0xa1;

/// First vector the remapped master PIC raises.
const PIC1_VECTOR: u8 = 0x20;
/// First vector the remapped slave PIC raises.
const PIC2_VECTOR: u8 = 0x28;

const PIT_CHANNEL0: u16 = 0x40;
const PIT_COMMAND: u16 = 0x43;
const PIT_FREQUENCY: u32 = 1_193_182;

/// Tick rate programmed into the PIT.
pub const TIMER_HZ: u64 = 100;

/// Timer ticks since the PIT was started.
static mut TICKS: u64 = 0;

/// Remap the PIC, program a periodic timer and enable interrupts.
pub fn init(frequency_hz: u32) {
    remap_pic();
    program_pit(frequency_hz);
    unmask_timer();
    // SAFETY: every gate the PIC can raise is installed before interrupts are
    // enabled, and the timer handler only increments a counter and sends EOI.
    unsafe {
        asm!("sti", options(nomem, nostack));
    }
}

/// Number of timer ticks observed so far.
pub fn ticks() -> u64 {
    // SAFETY: the counter is written by the interrupt handler and read here;
    // both are single 64-bit accesses on x86_64.
    unsafe { read_volatile(addr_of!(TICKS)) }
}

/// Wait until at least `count` timer ticks have arrived.
pub fn wait_for_ticks(count: u64) {
    while ticks() < count {
        // SAFETY: interrupts are enabled, so `hlt` wakes on the next timer tick.
        unsafe {
            asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

/// Record one tick and acknowledge the master PIC.
pub fn tick() {
    // SAFETY: bootstrap is single-threaded; the handler runs with interrupts
    // disabled and is the only writer while ring 3 is active.
    unsafe {
        let ticks = addr_of_mut!(TICKS);
        write_volatile(ticks, read_volatile(ticks).wrapping_add(1));
    }
    end_of_interrupt(0);
    // Once the local APIC is enabled the 8259 vectors arrive through it, so the
    // in-service bit has to be cleared there as well.
    crate::irq::end_of_interrupt();
}

fn remap_pic() {
    // SAFETY: the PIC ports are fixed legacy ports owned by the bootstrap.
    unsafe {
        outb(PIC1_COMMAND, 0x11);
        io_wait();
        outb(PIC2_COMMAND, 0x11);
        io_wait();
        outb(PIC1_DATA, PIC1_VECTOR);
        io_wait();
        outb(PIC2_DATA, PIC2_VECTOR);
        io_wait();
        outb(PIC1_DATA, 4);
        io_wait();
        outb(PIC2_DATA, 2);
        io_wait();
        outb(PIC1_DATA, 1);
        io_wait();
        outb(PIC2_DATA, 1);
        io_wait();
        // Mask everything, then unmask only the timer below.
        outb(PIC1_DATA, 0xff);
        outb(PIC2_DATA, 0xff);
    }
}

fn program_pit(frequency_hz: u32) {
    let divisor = PIT_FREQUENCY / frequency_hz.max(1);
    let divisor = u16::try_from(divisor).unwrap_or(u16::MAX);
    // SAFETY: channel 0 drives the timer interrupt and is unused elsewhere.
    unsafe {
        outb(PIT_COMMAND, 0x36);
        outb(PIT_CHANNEL0, divisor as u8);
        outb(PIT_CHANNEL0, (divisor >> 8) as u8);
    }
}

fn unmask_timer() {
    // SAFETY: only IRQ0 is cleared; every other line stays masked.
    unsafe {
        let mask = inb(PIC1_DATA);
        outb(PIC1_DATA, mask & !1);
    }
}

/// Unmask one interrupt line on the 8259 pair.
///
/// Errors: [`wuxia_core::Error::OutOfRange`] for a line the pair does not have,
/// and [`wuxia_core::Error::Unsupported`] for the cascade line, which the pair
/// owns itself.
pub fn unmask(irq: u8) -> Result<(), wuxia_core::Error> {
    if irq > 15 {
        return Err(wuxia_core::Error::OutOfRange);
    }
    if irq == 2 {
        return Err(wuxia_core::Error::Unsupported);
    }
    let (port, bit) = if irq < 8 {
        (PIC1_DATA, irq)
    } else {
        (PIC2_DATA, irq - 8)
    };
    // SAFETY: the mask registers of the remapped pair are owned by this module.
    unsafe {
        let mask = inb(port);
        outb(port, mask & !(1 << bit));
    }
    Ok(())
}

/// Send an end-of-interrupt for `irq` to the master or slave PIC.
pub fn end_of_interrupt(irq: u8) {
    // SAFETY: the PIC command ports are fixed and this runs in the handler.
    unsafe {
        if irq >= 8 {
            outb(PIC2_COMMAND, 0x20);
        }
        outb(PIC1_COMMAND, 0x20);
    }
}

unsafe fn outb(port: u16, value: u8) {
    // SAFETY: the caller passes a known legacy port.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
    }
}

unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: the caller passes a known legacy port.
    unsafe {
        asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags));
        value
    }
}

fn io_wait() {
    // SAFETY: port 0x80 is the conventional POST delay port and has no effect.
    unsafe { outb(0x80, 0) };
}
