//! TSC calibration and the kernel's monotonic time source.
//!
//! The programmable interval timer is the trustworthy reference: it counts at
//! [`crate::interrupts::TIMER_HZ`] and the interrupt handler has already proven
//! it arrives. The timestamp counter is the fast one. This module measures the
//! fast counter against the slow one once at boot and afterwards answers every
//! time query with one `rdtsc`, so neither personality pays an interrupt to read
//! a clock.

use core::arch::asm;
use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

use wuxia_core::time::{Frequency, Instant};

/// Number of timer ticks used for calibration.
///
/// Five ticks at the bootstrap rate is a fiftieth of a second: long enough for
/// the interval timer's granularity to be a small fraction of the measurement,
/// short enough not to delay the boot.
const CALIBRATION_TICKS: u64 = 5;

/// Measured timestamp-counter rate, zero until calibration succeeds.
static mut TSC_FREQUENCY: u64 = 0;

/// Timestamp-counter value at the start of the monotonic epoch.
static mut BOOT_TSC: u64 = 0;

/// Read the timestamp counter.
fn rdtsc() -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: `rdtsc` is available on every CPU this kernel supports and has no
    // memory side effects.
    unsafe {
        asm!(
            "rdtsc",
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
    (u64::from(high) << 32) | u64::from(low)
}

/// Calibrate the timestamp counter against the interval timer.
///
/// Returns the measured frequency, or `None` when the timer produced too few
/// ticks to make a measurement. The caller decides whether that is fatal; the
/// bootstrap treats it as a boot failure, because a kernel without a clock
/// cannot answer `clock_gettime` honestly.
pub fn calibrate() -> Option<Frequency> {
    let start_ticks = crate::interrupts::ticks();
    let start_tsc = rdtsc();
    crate::interrupts::wait_for_ticks(start_ticks + CALIBRATION_TICKS);
    let elapsed_ticks = crate::interrupts::ticks() - start_ticks;
    let elapsed_tsc = rdtsc() - start_tsc;
    if elapsed_ticks == 0 || elapsed_tsc == 0 {
        return None;
    }
    let hertz = (u128::from(elapsed_tsc) * u128::from(crate::interrupts::TIMER_HZ)
        / u128::from(elapsed_ticks)) as u64;
    let frequency = Frequency::new(hertz).ok()?;
    // SAFETY: calibration runs once during bootstrap before ring 3 starts.
    unsafe {
        write_volatile(addr_of_mut!(TSC_FREQUENCY), frequency.hertz());
        write_volatile(addr_of_mut!(BOOT_TSC), start_tsc);
    }
    Some(frequency)
}

/// The calibrated timestamp-counter rate, or `None` before calibration.
pub fn frequency() -> Option<Frequency> {
    // SAFETY: written once at boot and read afterwards.
    let hertz = unsafe { read_volatile(addr_of!(TSC_FREQUENCY)) };
    Frequency::new(hertz).ok()
}

/// Timestamp-counter ticks since the monotonic epoch.
pub fn counter() -> Option<u64> {
    frequency()?;
    // SAFETY: written once at boot and read afterwards.
    let boot = unsafe { read_volatile(addr_of!(BOOT_TSC)) };
    Some(rdtsc().wrapping_sub(boot))
}

/// The monotonic instant, or `None` before calibration.
pub fn monotonic() -> Option<Instant> {
    let frequency = frequency()?;
    Some(Instant::from_ticks(frequency, counter()?))
}

/// The realtime instant.
///
/// The bootstrap has no battery-backed clock and no network, so it cannot know
/// the wall-clock time. It reports the monotonic epoch instead of inventing a
/// date: a caller that needs calendar time must wait for a realtime source.
pub fn realtime() -> Option<Instant> {
    monotonic()
}
