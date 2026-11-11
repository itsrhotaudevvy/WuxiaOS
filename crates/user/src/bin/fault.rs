//! Fault self-test: the first instruction store must raise a page fault at
//! CPL3, which the kernel turns into a controlled process termination.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

core::arch::global_asm!(
    ".section .text._start, \"ax\"",
    ".global _start",
    "_start:",
    // Store through an address the process must not be able to write.
    "mov rax, 0x1000",
    "mov qword ptr [rax], 1",
    // Reached only if the store unexpectedly succeeded.
    "ud2",
);

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
