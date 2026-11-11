//! Minimal ring-3 POSIX program used by the bootstrap loader.
//!
//! Every syscall is issued with the numbered `int 0x80` ABI. The program
//! deliberately exercises a rejected write, an accepted write and exit.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

core::arch::global_asm!(
    ".section .text._start, \"ax\"",
    ".global _start",
    "_start:",
    // getpid
    "mov rax, 39",
    "int 0x80",
    // write(1, 0x1000, 8): outside the mapped image and must be rejected
    "mov rax, 1",
    "mov rdi, 1",
    "mov esi, 0x1000",
    "mov rdx, 8",
    "int 0x80",
    // write(1, message, 16): succeeds
    "mov rax, 1",
    "mov rdi, 1",
    "lea rsi, [rip + {message}]",
    "mov rdx, 16",
    "int 0x80",
    // exit(0)
    "mov rax, 60",
    "xor rdi, rdi",
    "int 0x80",
    "ud2",
    message = sym MESSAGE,
);

/// Greeting written to the serial console through `write(1, …)`.
#[used]
static MESSAGE: [u8; 16] = *b"HELLO FROM USER\n";

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
