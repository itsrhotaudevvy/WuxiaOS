//! Ring-3 entry.

use core::arch::asm;

use crate::gdt::{USER_CODE_SELECTOR, USER_DATA_SELECTOR};

/// RFLAGS for the first ring-3 entry: IF (bit 9) set plus the reserved bit 1.
const INTERRUPTS_ENABLED: u64 = (1 << 9) | (1 << 1);

/// Enter CPL3 at `entry` with `stack_pointer` and never return.
pub fn enter(entry: u64, stack_pointer: u64) -> ! {
    // SAFETY: both virtual addresses are mapped for user access by the active
    // page tables, the user descriptors are present in the loaded GDT, and the
    // IDT gates and TSS trap stack are installed. The PIC is already remapped
    // and IRQ0 unmasked, so a timer interrupt taken in ring 3 is serviced.
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
