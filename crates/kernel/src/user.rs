//! Ring-3 entry.
//!
//! Returning to CPL3 uses `iretq`, which pops `SS`, `RSP`, `RFLAGS`, `CS` and
//! `RIP` from the current kernel stack. The segment selectors carry RPL 3 and
//! refer to the user descriptors installed by [`crate::gdt`].

use core::arch::asm;
use core::ptr::{addr_of, addr_of_mut, read_volatile};

use crate::gdt::{USER_CODE_SELECTOR, USER_DATA_SELECTOR};

const INTERRUPTS_ENABLED: u64 = 1 << 1;

/// Inclusive-exclusive bounds of the mapped user image.
static mut REGION: (u64, u64) = (0, 0);

/// Record the mapped user region so syscalls can reject foreign pointers.
pub fn set_region(start: u64, end: u64) {
    // SAFETY: written once before ring 3 starts and read only afterwards.
    unsafe {
        *addr_of_mut!(REGION) = (start, end);
    }
}

/// Whether `[address, address + length)` lies inside the mapped user image.
pub fn region_contains(address: u64, length: u64) -> bool {
    // SAFETY: the tuple is written once before ring 3 starts.
    let (start, end) = unsafe { read_volatile(addr_of!(REGION)) };
    match address.checked_add(length) {
        Some(last) => address >= start && last <= end,
        None => false,
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
