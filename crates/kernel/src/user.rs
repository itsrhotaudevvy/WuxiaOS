//! Ring-3 entry.
//!
//! Returning to CPL3 uses `iretq`, which pops `SS`, `RSP`, `RFLAGS`, `CS` and
//! `RIP` from the current kernel stack. The segment selectors carry RPL 3 and
//! refer to the user descriptors installed by [`crate::gdt`].

use core::arch::asm;
use core::ptr::{addr_of, addr_of_mut, read_volatile};

use wuxia_core::address_space::AddressSpace;

use crate::gdt::{USER_CODE_SELECTOR, USER_DATA_SELECTOR};

const INTERRUPTS_ENABLED: u64 = 1 << 1;

/// Per-process region model kept in sync with the installed page tables.
static mut SPACE: Option<AddressSpace<4>> = None;

/// Record the mapped user regions so syscalls can reject foreign pointers.
pub fn set_space(space: AddressSpace<4>) {
    // SAFETY: written once before ring 3 starts and read only afterwards.
    unsafe {
        *addr_of_mut!(SPACE) = Some(space);
    }
}

/// Whether `[address, address + length)` lies inside one mapped user region.
pub fn region_contains(address: u64, length: u64) -> bool {
    // SAFETY: the model is written once before ring 3 starts.
    match unsafe { read_volatile(addr_of!(SPACE)) } {
        Some(space) => space.contains(address, length),
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
