//! Second scheduler participant: writes one message and exits.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

core::arch::global_asm!(
    ".section .text._start, \"ax\"",
    ".global _start",
    "_start:",
    // write(1, message, 15)
    "mov rax, 1",
    "mov rdi, 1",
    "lea rsi, [rip + {message}]",
    "mov rdx, 15",
    "int 0x80",
    // yield back to the first process
    "mov rax, 24",
    "int 0x80",
    // exit(0)
    "mov rax, 60",
    "xor rdi, rdi",
    "int 0x80",
    "ud2",
    message = sym MESSAGE,
);

/// Message proving the second process ran between the first process's yields.
#[used]
static MESSAGE: [u8; 15] = *b"SECOND PROCESS\n";

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
