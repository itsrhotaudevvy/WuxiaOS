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
    // Busy loop: long enough for the timer to preempt this process.
    "mov rcx, 50000000",
    "2:",
    "dec rcx",
    "jnz 2b",
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
    // map 4096 writable bytes and write a message into the new page
    "mov rax, 9",
    "mov rdi, 4096",
    "int 0x80",
    "cmp rax, 0",
    "jle 4f",
    "mov r12, rax",
    "mov rsi, rax",
    "mov rbx, 0x50414d2052455355",
    "mov qword ptr [rsi], rbx",
    "mov byte ptr [rsi + 8], 10",
    "mov rdx, 9",
    "mov rax, 1",
    "mov edi, 1",
    "int 0x80",
    "jmp 5f",
    "4:",
    "ud2",
    "5:",
    // unmap the page, then prove a write to it is now rejected
    "mov rax, 11",
    "mov rdi, r12",
    "mov rsi, 4096",
    "int 0x80",
    "mov rax, 1",
    "mov edi, 1",
    "mov rsi, r12",
    "mov rdx, 8",
    "int 0x80",
    // map 8192 bytes and print a message straddling the page boundary
    "mov rax, 9",
    "mov rdi, 8192",
    "int 0x80",
    "cmp rax, 0",
    "jle 9f",
    "mov r12, rax",
    "lea rsi, [r12 + 4088]",
    "mov rbx, 0x41502053534f5243",
    "mov qword ptr [rsi], rbx",
    "mov rbx, 0x000a465542204547",
    "mov qword ptr [rsi + 8], rbx",
    "mov rax, 1",
    "mov edi, 1",
    "mov rdx, 15",
    "int 0x80",
    "mov rax, 11",
    "mov rdi, r12",
    "mov rsi, 8192",
    "int 0x80",
    "jmp 10f",
    "9:",
    "ud2",
    "10:",
    // open("hello") from a stack-built path, read it and print the contents
    "sub rsp, 96",
    "mov dword ptr [rsp], 0x6c6c6568",
    "mov word ptr [rsp + 4], 0x6f",
    "mov rax, 2",
    "mov rdi, rsp",
    "mov rsi, 5",
    "int 0x80",
    "cmp rax, 0",
    "jl 6f",
    "mov r12, rax",
    "mov eax, 0",
    "mov rdi, r12",
    "lea rsi, [rsp + 16]",
    "mov rdx, 32",
    "int 0x80",
    "test rax, rax",
    "jle 6f",
    "mov rdx, rax",
    "lea rsi, [rsp + 16]",
    "mov edi, 1",
    "mov eax, 1",
    "int 0x80",
    "jmp 7f",
    "6:",
    "ud2",
    "7:",
    // close the file, then prove a read on the closed descriptor fails
    "mov rax, 3",
    "mov rdi, r12",
    "int 0x80",
    "xor eax, eax",
    "mov rdi, r12",
    "lea rsi, [rsp + 16]",
    "mov rdx, 16",
    "int 0x80",
    "add rsp, 96",
    // open("motd"), overwrite its first 8 bytes and read it back
    "sub rsp, 96",
    "mov dword ptr [rsp], 0x64746f6d",
    "mov rax, 2",
    "mov rdi, rsp",
    "mov rsi, 4",
    "int 0x80",
    "cmp rax, 0",
    "jl 11f",
    "mov r12, rax",
    "mov rbx, 0x534f204149585557",
    "mov qword ptr [rsp + 32], rbx",
    "mov rbx, 0x00000a454c494620",
    "mov qword ptr [rsp + 40], rbx",
    "mov rax, 1",
    "mov rdi, r12",
    "lea rsi, [rsp + 32]",
    "mov rdx, 14",
    "int 0x80",
    "mov rax, 3",
    "mov rdi, r12",
    "int 0x80",
    "mov rax, 2",
    "mov rdi, rsp",
    "mov rsi, 4",
    "int 0x80",
    "cmp rax, 0",
    "jl 11f",
    "mov r12, rax",
    "xor eax, eax",
    "mov rdi, r12",
    "lea rsi, [rsp + 48]",
    "mov rdx, 14",
    "int 0x80",
    "test rax, rax",
    "jle 11f",
    "mov rdx, rax",
    "lea rsi, [rsp + 48]",
    "mov edi, 1",
    "mov eax, 1",
    "int 0x80",
    "jmp 12f",
    "11:",
    "ud2",
    "12:",
    "add rsp, 96",
    // yield: the scheduler runs the second process, then resumes here
    "mov rax, 24",
    "int 0x80",
    // busy loop long enough that the timer preempts this process
    "mov rcx, 0x40000000",
    "8:",
    "dec rcx",
    "jnz 8b",
    // write(1, second, 15): proves this process resumed
    "mov rax, 1",
    "mov rdi, 1",
    "lea rsi, [rip + {second}]",
    "mov rdx, 15",
    "int 0x80",
    // exit(0)
    "mov rax, 60",
    "xor rdi, rdi",
    "int 0x80",
    "ud2",
    message = sym MESSAGE,
    second = sym SECOND,

);

/// Greeting written to the serial console through `write(1, …)`.
#[used]
static MESSAGE: [u8; 16] = *b"HELLO FROM USER\n";

/// Written after the yield resumes, proving the saved frame was restored.
#[used]
static SECOND: [u8; 15] = *b"A SECOND PHASE\n";

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
