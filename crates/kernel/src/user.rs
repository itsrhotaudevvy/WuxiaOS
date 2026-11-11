//! Ring-3 entry and the bootstrap process record.
//!
//! The process owns the address-space model, so syscalls validate pointers
//! against the same regions the page tables were built from.

use core::arch::asm;
use core::ptr::{addr_of, addr_of_mut, read_volatile};

use wuxia_core::process::Process;

use crate::gdt::{USER_CODE_SELECTOR, USER_DATA_SELECTOR};

const INTERRUPTS_ENABLED: u64 = 1 << 1;

/// The single bootstrap process.
static mut PROCESS: Option<Process<4>> = None;

/// Install the bootstrap process after its address space is populated.
pub fn set_process(process: Process<4>) {
    // SAFETY: written once before ring 3 starts and read only afterwards.
    unsafe {
        *addr_of_mut!(PROCESS) = Some(process);
    }
}

/// Return the current process identifier, or zero before installation.
pub fn process_id() -> u64 {
    // SAFETY: the process is written once before ring 3 starts.
    match unsafe { read_volatile(addr_of!(PROCESS)) } {
        Some(process) => process.id(),
        None => 0,
    }
}

/// Whether `[address, address + length)` lies inside one mapped user region.
pub fn region_contains(address: u64, length: u64) -> bool {
    // SAFETY: the process is written once before ring 3 starts.
    match unsafe { read_volatile(addr_of!(PROCESS)) } {
        Some(process) => process.space().contains(address, length),
        None => false,
    }
}

/// Mark the current process exited. Returns false if it is absent or already
/// terminated, so a second `exit` is rejected rather than silently ignored.
pub fn exit_process(code: u64) -> bool {
    // SAFETY: bootstrap is single-threaded and the slot is written once.
    unsafe {
        match &mut *addr_of_mut!(PROCESS) {
            Some(process) => process.exit(code).is_ok(),
            None => false,
        }
    }
}

/// Enter CPL3 at `entry` with `stack_pointer` and never return.
pub fn enter(entry: u64, stack_pointer: u64) -> ! {
    // SAFETY: both virtual addresses are mapped for user access by the active
    // page tables, and the user descriptors are present in the loaded GDT.
    unsafe {
        asm!(
            "push {ss}",
            "push {rsp}",
            "push {rflags}",
            "push {cs}",
            "push {rip}",
            "iretq",
            ss = in(reg) USER_DATA_SELECTOR as u64,
            rsp = in(reg) stack_pointer,
            rflags = in(reg) INTERRUPTS_ENABLED,
            cs = in(reg) USER_CODE_SELECTOR as u64,
            rip = in(reg) entry,
            options(noreturn),
        );
    }
}
