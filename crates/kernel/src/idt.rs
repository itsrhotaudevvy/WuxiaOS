//! x86_64 interrupt descriptor table: gates, stubs and dispatch.
//!
//! Every gate funnels into one naked stub that saves general-purpose
//! registers, calls a Rust dispatcher with a stable frame layout, restores the
//! registers and returns with `iretq`. The same path serves CPL0 and CPL3
//! traps because the CPU-supplied frame differs only by the extra `RSP`/`SS`.

use core::arch::asm;
use core::mem::size_of;
use core::ptr::addr_of_mut;

use crate::gdt::KERNEL_CODE_SELECTOR;
use crate::serial;

/// A 64-bit interrupt gate descriptor in the hardware-required layout.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
pub struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    attributes: u8,
    offset_middle: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    /// Construct a not-present gate.
    pub const fn missing() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            attributes: 0,
            offset_middle: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    /// Construct a present 64-bit interrupt gate.
    pub const fn interrupt(handler: usize, selector: u16, privilege: u8) -> Self {
        Self {
            offset_low: handler as u16,
            offset_middle: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            selector,
            ist: 0,
            attributes: 0x8e | ((privilege & 0x3) << 5),
            reserved: 0,
        }
    }
}

/// The 10-byte pointer consumed by `lidt`.
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct IdtPointer {
    limit: u16,
    base: u64,
}

/// A 256-entry table of interrupt and exception gates.
#[derive(Clone, Copy, Debug)]
#[repr(C, align(16))]
pub struct Idt {
    entries: [IdtEntry; 256],
}

impl Idt {
    /// Construct an empty IDT with all descriptors marked not-present.
    pub const fn new() -> Self {
        Self {
            entries: [IdtEntry::missing(); 256],
        }
    }

    /// Set one vector's descriptor.
    pub fn set_handler(&mut self, vector: u8, handler: usize, privilege: u8) {
        self.entries[vector as usize] =
            IdtEntry::interrupt(handler, KERNEL_CODE_SELECTOR, privilege);
    }

    /// Load the table with `lidt`.
    pub fn load(&self) {
        let pointer = IdtPointer {
            limit: (size_of::<Self>() - 1) as u16,
            base: self as *const Self as u64,
        };
        // SAFETY: `pointer` describes this static table, which outlives the CPU
        // configuration and was fully populated before the call.
        unsafe {
            asm!("lidt [{0}]", in(reg) &pointer, options(readonly, nostack, preserves_flags));
        }
    }
}

/// Registers and trap frame as laid out by [`common_stub`].
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct InterruptFrame {
    /// Saved general-purpose registers, lowest address first.
    pub r15: u64,
    /// See `r15`.
    pub r14: u64,
    /// See `r15`.
    pub r13: u64,
    /// See `r15`.
    pub r12: u64,
    /// See `r15`.
    pub r11: u64,
    /// See `r15`.
    pub r10: u64,
    /// See `r15`.
    pub r9: u64,
    /// See `r15`.
    pub r8: u64,
    /// See `r15`.
    pub rdi: u64,
    /// See `r15`.
    pub rsi: u64,
    /// See `r15`.
    pub rbp: u64,
    /// See `r15`.
    pub rbx: u64,
    /// See `r15`.
    pub rdx: u64,
    /// See `r15`.
    pub rcx: u64,
    /// See `r15`.
    pub rax: u64,
    /// Interrupt vector number.
    pub vector: u64,
    /// Hardware error code, or zero for vectors that do not push one.
    pub error: u64,
    /// Faulting instruction pointer.
    pub rip: u64,
    /// Code selector at the time of the trap.
    pub cs: u64,
    /// Saved flags.
    pub rflags: u64,
}

/// Install handlers for the vectors the bootstrap can currently service.
pub fn init() {
    // SAFETY: bootstrap is single-threaded; the static IDT is written once.
    unsafe {
        let idt = &mut *addr_of_mut!(IDT);
        idt.set_handler(3, breakpoint as usize, 3);
        idt.set_handler(6, invalid_opcode as usize, 0);
        idt.set_handler(13, general_protection as usize, 0);
        idt.set_handler(14, page_fault as usize, 0);
        idt.set_handler(0x80, syscall_gate as usize, 3);
        idt.load();
    }
}

static mut IDT: Idt = Idt::new();

macro_rules! isr {
    ($name:ident, $vector:expr) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $name() {
            core::arch::naked_asm!(
                "push 0",
                "push {vector}",
                "jmp {common}",
                vector = const $vector,
                common = sym common_stub,
            )
        }
    };
}

macro_rules! isr_error {
    ($name:ident, $vector:expr) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $name() {
            core::arch::naked_asm!(
                "push {vector}",
                "jmp {common}",
                vector = const $vector,
                common = sym common_stub,
            )
        }
    };
}

isr!(breakpoint, 3);
isr!(invalid_opcode, 6);
isr_error!(general_protection, 13);
isr_error!(page_fault, 14);
isr!(syscall_gate, 0x80);

#[unsafe(naked)]
unsafe extern "C" fn common_stub() {
    core::arch::naked_asm!(
        "push rax",
        "push rcx",
        "push rdx",
        "push rbx",
        "push rbp",
        "push rsi",
        "push rdi",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov rdi, rsp",
        "mov rbp, rsp",
        "and rsp, -16",
        "call {dispatcher}",
        "mov rsp, rbp",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rdi",
        "pop rsi",
        "pop rbp",
        "pop rbx",
        "pop rdx",
        "pop rcx",
        "pop rax",
        "add rsp, 16",
        "iretq",
        dispatcher = sym dispatch,
    );
}

extern "C" fn dispatch(frame: *mut InterruptFrame) {
    // SAFETY: the stub builds a complete frame and passes its address; no other
    // reference to the frame exists during the call.
    let frame = unsafe { &mut *frame };
    match frame.vector {
        3 => serial::write_str("WUXIA_BREAKPOINT_OK\n"),
        6 => {
            serial::write_str("WUXIA_TEST_FAIL: unexpected user fault\n");
            serial::write_hex(frame.rip);
            serial::debug_exit(1);
            halt();
        }
        13 => {
            serial::write_str("WUXIA_GP_FAULT\n");
            serial::write_hex(frame.error);
            serial::write_hex(frame.rip);
            serial::debug_exit(1);
            halt();
        }
        14 => {
            let address = read_cr2();
            serial::write_str("WUXIA_PAGE_FAULT\n");
            serial::write_hex(frame.error);
            serial::write_hex(address);
            serial::write_hex(frame.rip);
            serial::debug_exit(1);
            halt();
        }
        0x80 => service_syscall(frame),
        _ => {
            serial::write_str("WUXIA_UNEXPECTED_VECTOR\n");
            serial::write_hex(frame.vector);
        }
    }
}

fn service_syscall(frame: &mut InterruptFrame) {
    let registers = wuxia_core::syscall::Registers {
        args: [
            frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9,
        ],
    };
    match wuxia_core::syscall::PosixRequest::decode(frame.rax, &registers) {
        Ok(wuxia_core::syscall::PosixRequest::GetPid) => {
            serial::write_str("WUXIA_SYSCALL_GETPID\n");
            frame.rax = crate::user::process_id();
            serial::write_hex(frame.rax);
        }
        Ok(wuxia_core::syscall::PosixRequest::Exit { code }) => {
            if !crate::user::exit_process(code) {
                serial::write_str("WUXIA_SYSCALL_INVALID\n");
                frame.rax = u64::MAX;
                return;
            }
            serial::write_str("WUXIA_SYSCALL_EXIT\n");
            serial::write_hex(code);
            serial::write_str("WUXIA_TEST_PASS\n");
            serial::debug_exit(0x10);
            halt();
        }
        Ok(wuxia_core::syscall::PosixRequest::Write { descriptor, buffer }) => {
            if descriptor != 1 || !crate::user::region_contains(buffer.address, buffer.length) {
                serial::write_str("WUXIA_SYSCALL_REJECTED\n");
                frame.rax = u64::MAX;
                return;
            }
            match copy_user_to_serial(buffer.address, buffer.length) {
                Ok(()) => {
                    serial::write_str("WUXIA_SYSCALL_WRITE_OK\n");
                    frame.rax = buffer.length;
                }
                Err(_) => {
                    serial::write_str("WUXIA_SYSCALL_FAULT\n");
                    frame.rax = u64::MAX;
                }
            }
        }
        Ok(_) => {
            serial::write_str("WUXIA_SYSCALL_OK\n");
            serial::write_hex(frame.rax);
            // Unimplemented requests report a successful no-op result.
            frame.rax = 0;
        }
        Err(_) => {
            serial::write_str("WUXIA_SYSCALL_INVALID\n");
            serial::write_hex(frame.rax);
            frame.rax = u64::MAX;
        }
    }
}

fn read_cr2() -> u64 {
    let value: u64;
    // SAFETY: reading CR2 has no side effects.
    unsafe {
        asm!("mov {}, cr2", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

/// Forward a validated user buffer to the serial console through the HHDM.
///
/// Reading through the direct map avoids relying on supervisor access to the
/// active user mapping and refuses any leaf that is not CPL3-accessible.
fn copy_user_to_serial(address: u64, length: u64) -> Result<(), wuxia_core::Error> {
    let map = crate::paging::current_direct_map().ok_or(wuxia_core::Error::InvalidState)?;
    let entry = crate::paging::resolve(map, address)?;
    if !wuxia_core::paging::is_user(entry) {
        return Err(wuxia_core::Error::PermissionDenied);
    }
    let frame = wuxia_core::paging::physical_address(entry);
    let offset = address % wuxia_core::paging::PAGE_SIZE;
    if offset + length > wuxia_core::paging::PAGE_SIZE {
        return Err(wuxia_core::Error::InvalidInput);
    }
    let source = map.physical_to_virtual(frame + offset)? as *const u8;
    for index in 0..length as usize {
        // SAFETY: the leaf is present and user-accessible, and the bounded
        // range stays inside one 4 KiB frame.
        let byte = unsafe { source.add(index).read_volatile() };
        serial::write_byte(byte);
    }
    Ok(())
}

fn halt() -> ! {
    loop {
        // SAFETY: disabling interrupts and halting has no memory effects.
        unsafe {
            asm!("cli", "hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

/// Load the IDT and immediately trigger a breakpoint to prove the path works.
pub fn self_test() {
    init();
    // SAFETY: the breakpoint gate is installed and its handler returns cleanly.
    unsafe { asm!("int3", options(nomem, nostack)) };
}
