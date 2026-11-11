//! x86_64 descriptor tables: GDT, segment descriptors and the TSS.
//!
//! Long mode ignores code and data base/limit fields but honours the access
//! bits, DPL and the long-mode flag. The TSS is required to supply `RSP0` when
//! an interrupt or trap arrives while the CPU is at CPL3.

use core::arch::asm;
use core::mem::size_of;
use core::ptr::{addr_of, addr_of_mut};

/// Kernel code selector in the bootstrap GDT.
pub const KERNEL_CODE_SELECTOR: u16 = 0x08;
/// Kernel data selector for the bootstrap flat address space.
pub const KERNEL_DATA_SELECTOR: u16 = 0x10;
/// Ring-3 code selector.
pub const USER_CODE_SELECTOR: u16 = 0x1b;
/// Ring-3 data selector.
pub const USER_DATA_SELECTOR: u16 = 0x23;
/// Selector of the 64-bit task state segment.
pub const TSS_SELECTOR: u16 = 0x28;

const GDT_ENTRIES: usize = 7;

/// A flat 64-bit segment descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct SegmentDescriptor(pub u64);

impl SegmentDescriptor {
    /// Construct a long-mode, present, executable/readable code descriptor.
    pub const fn code(privilege: u8) -> Self {
        Self(
            (1u64 << 41)          // readable
                | (1u64 << 43)    // executable
                | (1u64 << 44)    // code/data descriptor
                | (1u64 << 47)    // present
                | (1u64 << 53)    // long mode
                | ((privilege as u64 & 0x3) << 45),
        )
    }

    /// Construct a flat present, writable data descriptor.
    pub const fn data(privilege: u8) -> Self {
        Self(
            (1u64 << 41)          // writable
                | (1u64 << 44)    // code/data descriptor
                | (1u64 << 47)    // present
                | ((privilege as u64 & 0x3) << 45),
        )
    }

    /// Encode a 64-bit available TSS descriptor as its two GDT slots.
    pub const fn tss(base: u64, limit: u32) -> (u64, u64) {
        let low = (limit as u64 & 0xffff)
            | ((base & 0x00ff_ffff) << 16)
            | (0x9u64 << 40)               // available 64-bit TSS
            | (1u64 << 47)                 // present
            | (((limit as u64) >> 16 & 0xf) << 48)
            | (((base >> 24) & 0xff) << 56);
        let high = (base >> 32) & 0xffff_ffff;
        (low, high)
    }
}

/// A minimal GDT with null, kernel, user and TSS descriptors.
#[derive(Clone, Copy, Debug)]
#[repr(C, align(16))]
pub struct Gdt {
    entries: [u64; GDT_ENTRIES],
}

impl Gdt {
    /// Construct the fixed descriptor layout used by the bootstrap.
    pub const fn new() -> Self {
        Self {
            entries: [
                0,
                SegmentDescriptor::code(0).0,
                SegmentDescriptor::data(0).0,
                SegmentDescriptor::code(3).0,
                SegmentDescriptor::data(3).0,
                0,
                0,
            ],
        }
    }

    /// Return the selector for the first executable kernel segment.
    pub const fn kernel_code_selector(&self) -> u16 {
        KERNEL_CODE_SELECTOR
    }
}

/// The 64-bit task state segment.
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct TaskStateSegment {
    reserved0: u32,
    /// Stack pointer loaded when a trap from CPL3 enters the kernel.
    pub rsp0: u64,
    rsp1: u64,
    rsp2: u64,
    reserved1: u64,
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    iomap_base: u16,
}

impl TaskStateSegment {
    /// Construct an empty TSS with the I/O bitmap disabled.
    pub const fn new() -> Self {
        Self {
            reserved0: 0,
            rsp0: 0,
            rsp1: 0,
            rsp2: 0,
            reserved1: 0,
            ist: [0; 7],
            reserved2: 0,
            reserved3: 0,
            iomap_base: size_of::<Self>() as u16,
        }
    }
}

/// The pointer consumed by `lgdt`.
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

static mut GDT: Gdt = Gdt::new();
static mut TSS: TaskStateSegment = TaskStateSegment::new();

/// A dedicated kernel stack for traps taken from CPL3.
#[repr(align(16))]
struct TrapStack([u8; 16 * 1024]);

static mut TRAP_STACK: TrapStack = TrapStack([0; 16 * 1024]);

/// Load the GDT, reload the segment registers and install the TSS.
///
/// A dedicated 16 KiB trap stack becomes `RSP0`; the bootstrap stack stays
/// untouched when ring-3 code faults into the kernel.
pub fn init() {
    // SAFETY: bootstrap is single-threaded and no other code reads or writes
    // these statics. The addresses are stable for the whole kernel lifetime.
    unsafe {
        let tss = &mut *addr_of_mut!(TSS);
        tss.rsp0 = addr_of!(TRAP_STACK) as u64 + size_of::<TrapStack>() as u64;
        let (low, high) =
            SegmentDescriptor::tss(addr_of!(TSS) as u64, size_of::<TaskStateSegment>() as u32);
        let gdt = &mut *addr_of_mut!(GDT);
        gdt.entries[5] = low;
        gdt.entries[6] = high;

        let pointer = DescriptorTablePointer {
            limit: (size_of::<Gdt>() - 1) as u16,
            base: addr_of!(GDT) as u64,
        };
        asm!("lgdt [{0}]", in(reg) &pointer, options(readonly, nostack, preserves_flags));
    }
    reload_data_segments();
    // SAFETY: the GDT is loaded and the selector is valid.
    unsafe { reload_cs() };
    load_task_register();
}

/// Read the current stack pointer for diagnostics.
pub fn stack_pointer() -> u64 {
    let rsp: u64;
    // SAFETY: reading RSP has no side effects.
    unsafe {
        asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags));
    }
    rsp
}

fn reload_data_segments() {
    // SAFETY: the selectors index the GDT loaded by `init`.
    unsafe {
        asm!(
            "mov ax, 0x10",
            "mov ds, ax",
            "mov es, ax",
            "mov ss, ax",
            "mov fs, ax",
            "mov gs, ax",
            out("ax") _,
            options(nomem, nostack, preserves_flags),
        );
    }
}

fn load_task_register() {
    // SAFETY: the TSS descriptor was installed at `TSS_SELECTOR` before `ltr`.
    unsafe {
        asm!("mov ax, 0x28", "ltr ax", out("ax") _, options(nomem, nostack, preserves_flags));
    }
}

/// Reload CS with the kernel code selector through a far return.
#[unsafe(naked)]
unsafe extern "C" fn reload_cs() {
    core::arch::naked_asm!(
        "push 0x08",
        "lea rax, [rip + 2f]",
        "push rax",
        "retfq",
        "2:",
        "ret",
    );
}
