//! Kernel log: a static `wuxia_core::klog` ring mirrored to the serial console.
//!
//! Every kernel diagnostic line written through [`write_str`] or
//! [`write_hex`] is sent to COM1 unchanged and then appended to the ring as one
//! record carrying a sequence number, the current timer tick and a severity.
//! The serial bytes are exactly those the console printed before the ring
//! existed, so the `WUXIA_*` markers the boot test looks for are unchanged.
//!
//! [`console`] exposes the same function names as the raw serial module, so a
//! trap or scheduler module routes its diagnostics through the log by importing
//! `crate::log::console as serial`. Raw bytes copied from user buffers are not
//! recorded: they are untrusted process output, not kernel log lines.
//!
//! Appends run with interrupts disabled. A reentrant append (for example from
//! a fault raised while the ring is being written) still reaches the serial
//! console but is counted as dropped instead of touching the ring.

use core::arch::asm;
use core::ptr::addr_of_mut;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use wuxia_core::klog::{KernelLog, Level, MAX_MESSAGE, ReadResult, Reader};

use crate::serial;

/// Ring capacity in bytes. A full boot writes about a hundred short records
/// (roughly 4 KiB), so no record is evicted during the self-test.
const LOG_BYTES: usize = 16 * 1024;

/// The kernel log ring. Accessed only while `BUSY` is held with interrupts
/// disabled.
static mut LOG: KernelLog<LOG_BYTES> = KernelLog::new();

/// Set while a caller owns `LOG`.
static BUSY: AtomicBool = AtomicBool::new(false);

/// Lines that reached the console but not the ring.
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// Records stored truncated because they exceeded `MAX_MESSAGE`.
static TRUNCATED: AtomicU64 = AtomicU64::new(0);

/// Markers the end-of-run check expects to find in the ring.
const EXPECTED: &[&[u8]] = &[
    b"WUXIA_BOOT_OK: Limine entered the high-half kernel",
    b"WUXIA_GDT_OK",
    b"WUXIA_BREAKPOINT_OK",
    b"WUXIA_TIMER_OK",
    b"WUXIA_MEMORY_MAP_READY",
    b"WUXIA_FS_OK",
    b"WUXIA_ENTER_USER",
    b"WUXIA_SYSCALL_WRITE_OK",
    b"WUXIA_SYSCALL_EXIT",
    b"WUXIA_NT_EXIT",
    b"WUXIA_USER_FAULT_KILLED",
    b"WUXIA_TEARDOWN_OK",
];

/// Write `text` to the console and record it as one informational line.
///
/// One trailing newline is not stored in the record.
pub fn write_str(text: &str) {
    serial::write_str(text);
    let bytes = text.as_bytes();
    record(Level::Info, bytes.strip_suffix(b"\n").unwrap_or(bytes));
}

/// Write raw bytes to the console and record them as one informational line.
///
/// This is how a loaded driver's `DbgPrint` reaches the log: the bytes are not
/// trusted to be UTF-8, so they are copied verbatim.
pub fn write_bytes(bytes: &[u8]) {
    for byte in bytes {
        serial::write_byte(*byte);
    }
    record(Level::Info, bytes.strip_suffix(b"\n").unwrap_or(bytes));
}

/// Write `value` as `0x` and 16 hex digits, and record the same line.
pub fn write_hex(value: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    serial::write_hex(value);
    let mut line = [0u8; 18];
    line[0] = b'0';
    line[1] = b'x';
    for (i, slot) in line[2..].iter_mut().enumerate() {
        let shift = (15 - i) * 4;
        *slot = HEX[((value >> shift) & 0xf) as usize];
    }
    record(Level::Info, &line);
}

/// Serial-compatible facade for modules that print through `serial::`.
pub mod console {
    pub use super::{write_hex, write_str};

    /// Forward one raw user byte to the console without recording it.
    pub fn write_byte(byte: u8) {
        crate::serial::write_byte(byte);
    }

    /// Signal the QEMU isa-debug-exit device.
    pub fn debug_exit(value: u8) {
        crate::serial::debug_exit(value);
    }
}

/// Append one record stamped with the current tick.
fn record(level: Level, message: &[u8]) {
    with_log(
        |log| {
            if message.len() > MAX_MESSAGE {
                TRUNCATED.fetch_add(1, Ordering::Relaxed);
            }
            if log
                .append(crate::interrupts::ticks(), level, message)
                .is_err()
            {
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        },
        || {
            DROPPED.fetch_add(1, Ordering::Relaxed);
        },
    );
}

/// Run `body` with exclusive access to the ring and interrupts disabled, or
/// `busy` if the ring is already in use.
fn with_log<R>(body: impl FnOnce(&mut KernelLog<LOG_BYTES>) -> R, busy: impl FnOnce() -> R) -> R {
    let interrupts = disable_interrupts();
    let result = if BUSY.swap(true, Ordering::Acquire) {
        busy()
    } else {
        // SAFETY: `BUSY` was clear and is now held, and interrupts are off on
        // this single CPU, so no other reference to `LOG` exists.
        let log = unsafe { &mut *addr_of_mut!(LOG) };
        let result = body(log);
        BUSY.store(false, Ordering::Release);
        result
    };
    if interrupts {
        enable_interrupts();
    }
    result
}

/// Loss counters for the ring.
#[derive(Clone, Copy)]
struct Stats {
    records: u64,
    evicted: u64,
    dropped: u64,
    truncated: u64,
}

/// Check the ring after the run and print `WUXIA_KLOG_OK` with loss counters.
///
/// The check reads every retained record, requires contiguous sequence
/// numbers and non-decreasing ticks, and requires each expected marker to be
/// present. A failed check prints `WUXIA_KLOG_FAIL` instead, which the boot
/// test treats as a missing `WUXIA_KLOG_OK`.
pub fn verify() {
    let outcome = with_log(
        |log| {
            let mut found = [false; EXPECTED.len()];
            let mut reader = Reader::new();
            let mut message = [0u8; MAX_MESSAGE];
            let mut expected_seq = log.oldest_seq();
            let mut last_tick = 0;
            let mut ordered = true;
            loop {
                match reader.read(log, &mut message) {
                    ReadResult::Record { seq, tick, len, .. } => {
                        ordered &= seq == expected_seq && tick >= last_tick;
                        expected_seq = seq + 1;
                        last_tick = tick;
                        for (slot, marker) in found.iter_mut().zip(EXPECTED) {
                            *slot |= &message[..len] == *marker;
                        }
                    }
                    ReadResult::Lost { .. } => {}
                    ReadResult::Empty => break,
                }
            }
            let stats = Stats {
                records: log.next_seq(),
                evicted: log.oldest_seq(),
                dropped: DROPPED.load(Ordering::Relaxed),
                truncated: TRUNCATED.load(Ordering::Relaxed),
            };
            (ordered && found.iter().all(|&hit| hit), stats)
        },
        || {
            (
                false,
                Stats {
                    records: 0,
                    evicted: 0,
                    dropped: DROPPED.load(Ordering::Relaxed),
                    truncated: TRUNCATED.load(Ordering::Relaxed),
                },
            )
        },
    );
    let (passed, stats) = outcome;
    let mut line = Line::new();
    line.put(if passed {
        b"WUXIA_KLOG_OK"
    } else {
        b"WUXIA_KLOG_FAIL"
    });
    line.field(b" records=", stats.records);
    line.field(b" evicted=", stats.evicted);
    line.field(b" dropped=", stats.dropped);
    line.field(b" truncated=", stats.truncated);
    // The summary is built from ASCII literals and decimal digits only.
    let text = core::str::from_utf8(line.bytes()).unwrap_or("WUXIA_KLOG_FAIL");
    serial::write_str(text);
    serial::write_str("\n");
    record(Level::Notice, line.bytes());
}

/// Small fixed buffer for the summary line.
struct Line {
    buffer: [u8; 128],
    len: usize,
}

impl Line {
    const fn new() -> Self {
        Self {
            buffer: [0; 128],
            len: 0,
        }
    }

    fn put(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if self.len < self.buffer.len() {
                self.buffer[self.len] = byte;
                self.len += 1;
            }
        }
    }

    fn field(&mut self, name: &[u8], value: u64) {
        self.put(name);
        let mut digits = [0u8; 20];
        let mut at = digits.len();
        let mut rest = value;
        loop {
            at -= 1;
            digits[at] = b'0' + (rest % 10) as u8;
            rest /= 10;
            if rest == 0 {
                break;
            }
        }
        self.put(&digits[at..]);
    }

    fn bytes(&self) -> &[u8] {
        &self.buffer[..self.len]
    }
}

/// Clear IF and report whether it was set.
fn disable_interrupts() -> bool {
    let flags: u64;
    // SAFETY: reading RFLAGS and clearing IF have no memory effects.
    unsafe {
        asm!("pushfq", "pop {}", "cli", out(reg) flags, options(nomem, preserves_flags));
    }
    flags & 0x200 != 0
}

fn enable_interrupts() {
    // SAFETY: called only to restore IF that `disable_interrupts` cleared.
    unsafe { asm!("sti", options(nomem, nostack)) };
}
