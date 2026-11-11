//! Ring-3 entry and the image started after the bootstrap process ends.

use core::arch::asm;
use core::ptr::{addr_of, addr_of_mut, read_volatile};

use crate::gdt::{USER_CODE_SELECTOR, USER_DATA_SELECTOR};
use crate::paging::UserImage;

const INTERRUPTS_ENABLED: u64 = 1 << 1;

/// The image started after the bootstrap process exits.
static mut NEXT_IMAGE: Option<UserImage> = None;

/// Store the image started after the bootstrap process exits.
pub fn set_next_image(image: UserImage) {
    // SAFETY: written once before ring 3 starts.
    unsafe {
        *addr_of_mut!(NEXT_IMAGE) = Some(image);
    }
}

/// Return the image started after the bootstrap process exits.
pub fn next_image() -> Option<UserImage> {
    // SAFETY: the image is written once before ring 3 starts.
    unsafe { read_volatile(addr_of!(NEXT_IMAGE)) }
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
