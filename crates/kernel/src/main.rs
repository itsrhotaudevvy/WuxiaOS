#![no_std]
#![no_main]

//! Minimal x86_64 Limine bootstrap with a headless serial console.
//!
//! This milestone proves a real high-half kernel entry. It does not yet load
//! Windows applications or drivers; those require separate ABI and mapping work.

use core::arch::asm;
use core::panic::PanicInfo;
use limine::BaseRevision;
use limine::request::{RequestsEndMarker, RequestsStartMarker, StackSizeRequest};

mod idt;

#[used]
#[unsafe(link_section = ".requests")]
static BASE_REVISION: BaseRevision = BaseRevision::new();

#[used]
#[unsafe(link_section = ".requests_start_marker")]
static REQUESTS_START_MARKER: RequestsStartMarker = RequestsStartMarker::new();

#[used]
#[unsafe(link_section = ".requests")]
static STACK_SIZE_REQUEST: StackSizeRequest = StackSizeRequest::new().with_size(0x100000);

#[used]
#[unsafe(link_section = ".requests_end_marker")]
static REQUESTS_END_MARKER: RequestsEndMarker = RequestsEndMarker::new();

/// Limine's documented kernel entry point.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    if !BASE_REVISION.is_supported() {
        panic!("Limine base revision 3 is unsupported");
    }
    serial::init();
    serial::write_str("WUXIA_BOOT_OK: Limine entered the high-half kernel\n");
    halt_forever()
}

/// Panic handler for early bootstrap failures.
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    serial::write_str("WuxiaOS bootstrap panic\n");
    halt_forever()
}

fn halt_forever() -> ! {
    loop {
        // SAFETY: Limine enters with interrupts disabled. `hlt` idles without
        // touching memory and returns only if a later milestone enables interrupts.
        unsafe { asm!("hlt") };
    }
}

mod serial {
    use core::arch::asm;

    const COM1: u16 = 0x3f8;

    /// Initialize the PC-compatible 16550 UART for headless diagnostics.
    pub fn init() {
        // SAFETY: COM1 is the fixed PC-compatible legacy port and this bootstrap
        // owns it before the interrupt driver exists.
        unsafe {
            outb(COM1 + 1, 0x00);
            outb(COM1 + 3, 0x80);
            outb(COM1, 0x03);
            outb(COM1 + 1, 0x00);
            outb(COM1 + 3, 0x03);
            outb(COM1 + 2, 0xc7);
            outb(COM1 + 4, 0x0b);
        }
    }

    /// Write a string to the legacy COM1 port, including CRLF line endings.
    pub fn write_str(text: &str) {
        for byte in text.bytes() {
            if byte == b'\n' {
                put_byte(b'\r');
            }
            put_byte(byte);
        }
    }

    fn put_byte(byte: u8) {
        // SAFETY: The bootstrap owns COM1; no interrupt handler races this write.
        unsafe { outb(COM1, byte) };
    }

    unsafe fn outb(port: u16, value: u8) {
        // SAFETY: x86_64 port I/O is used only for known 16550 registers.
        unsafe {
            asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
        }
    }
}
