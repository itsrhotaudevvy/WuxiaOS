//! Second scheduler participant: writes one message and exits.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

core::arch::global_asm!(
    ".section .text._start, \"ax\"",
    ".global _start",
    "_start:",
    // getpid: this process must be the second one
    "mov rax, 39",
    "int 0x80",
    "cmp rax, 2",
    "jne 3f",
    // write(1, message, 15)
    "mov rax, 1",
    "mov rdi, 1",
    "lea rsi, [rip + {message}]",
    "mov rdx, 15",
    "int 0x80",
    // open("motd"), read it and print the contents from a second process
    "mov rax, 2",
    "lea rdi, [rip + {path}]",
    "mov rsi, 4",
    "int 0x80",
    "test rax, rax",
    "js 4f",
    "mov rbx, rax",
    "sub rsp, 32",
    "xor eax, eax",
    "mov rdi, rbx",
    "mov rsi, rsp",
    "mov rdx, 16",
    "int 0x80",
    "test rax, rax",
    "jle 4f",
    "mov rdx, rax",
    "mov rsi, rsp",
    "mov edi, 1",
    "mov eax, 1",
    "int 0x80",
    "add rsp, 32",
    "jmp 5f",
    "4:",
    "ud2",
    "5:",
    // yield back to the first process
    "mov rax, 24",
    "int 0x80",
    // exit(0)
    "mov rax, 60",
    "xor rdi, rdi",
    "int 0x80",
    "3:",
    "ud2",
    message = sym MESSAGE,
    path = sym MOTD_PATH,
);

/// Name of the second file, opened from this process.
#[used]
static MOTD_PATH: [u8; 4] = *b"motd";

/// Message proving the second process ran between the first process's yields.
#[used]
static MESSAGE: [u8; 15] = *b"SECOND PROCESS\n";

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
