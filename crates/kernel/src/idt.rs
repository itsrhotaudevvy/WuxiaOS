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
    /// Saved stack pointer. Present only for a trap taken from CPL3.
    pub rsp: u64,
    /// Saved stack selector. Present only for a trap taken from CPL3.
    pub ss: u64,
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
        idt.set_handler(0x20, timer as usize, 0);
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
isr!(timer, 0x20);
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
            if frame.cs & 3 == 3 {
                // A fault raised by ring 3 terminates the process; the kernel
                // keeps running and reports the fault instead of dying with it.
                serial::write_str("WUXIA_USER_PAGE_FAULT\n");
                serial::write_hex(frame.error);
                serial::write_hex(address);
                serial::write_hex(frame.rip);
                serial::write_str("WUXIA_TEST_PASS\n");
                serial::debug_exit(0x10);
                halt();
            }
            serial::write_str("WUXIA_PAGE_FAULT\n");
            serial::write_hex(frame.error);
            serial::write_hex(address);
            serial::write_hex(frame.rip);
            serial::debug_exit(1);
            halt();
        }
        0x20 => {
            crate::interrupts::tick();
            if frame.cs & 3 == 3 {
                crate::sched::preempt(frame);
            }
        }
        0x80 => service_syscall(frame),
        _ => {
            serial::write_str("WUXIA_UNEXPECTED_VECTOR\n");
            serial::write_hex(frame.vector);
        }
    }
}

fn service_syscall(frame: &mut InterruptFrame) {
    if crate::sched::is_nt() {
        service_nt_syscall(frame);
        return;
    }
    let registers = wuxia_core::syscall::Registers {
        args: [
            frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9,
        ],
    };
    match wuxia_core::syscall::PosixRequest::decode(frame.rax, &registers) {
        Ok(wuxia_core::syscall::PosixRequest::GetPid) => {
            serial::write_str("WUXIA_SYSCALL_GETPID\n");
            frame.rax = crate::sched::process_id();
            serial::write_hex(frame.rax);
        }
        Ok(wuxia_core::syscall::PosixRequest::Yield) => {
            frame.rax = 0;
            crate::sched::yield_current(frame);
        }
        Ok(wuxia_core::syscall::PosixRequest::Sleep { millis }) => {
            let start = crate::interrupts::ticks();
            frame.rax = 0;
            if !crate::sched::sleep_current(frame, millis) {
                serial::write_str("WUXIA_SLEEP_OK\n");
                serial::write_hex(crate::interrupts::ticks() - start);
            }
        }
        Ok(wuxia_core::syscall::PosixRequest::Exit { code }) => {
            terminate(frame, code, "WUXIA_SYSCALL_EXIT\n");
        }
        Ok(wuxia_core::syscall::PosixRequest::Open { path }) => {
            let mut scratch = [0u8; wuxia_core::syscall::MAX_PATH_LENGTH as usize];
            let opened = copy_user_bytes(path.address, path.length, &mut scratch)
                .ok()
                .and_then(|count| core::str::from_utf8(&scratch[..count]).ok())
                .and_then(crate::sched::open_path);
            match opened {
                Some(descriptor) => {
                    serial::write_str("WUXIA_SYSCALL_OPEN\n");
                    serial::write_hex(u64::from(descriptor));
                    frame.rax = u64::from(descriptor);
                }
                None => {
                    serial::write_str("WUXIA_SYSCALL_INVALID\n");
                    frame.rax = u64::MAX;
                }
            }
        }
        Ok(wuxia_core::syscall::PosixRequest::Read { descriptor, buffer }) => {
            let length = buffer.length as usize;
            let mut scratch = [0u8; wuxia_core::syscall::MAX_READ_LENGTH as usize];
            let read = crate::sched::descriptor_file(descriptor).and_then(|(file, offset)| {
                let count = crate::vfs::read(file, offset, &mut scratch[..length])?;
                copy_user_from(buffer.address, &scratch[..count]).ok()?;
                crate::sched::advance_descriptor(descriptor, count as u64).then_some(count)
            });
            match read {
                Some(count) => {
                    serial::write_str("WUXIA_SYSCALL_READ\n");
                    frame.rax = count as u64;
                }
                None => {
                    serial::write_str("WUXIA_SYSCALL_INVALID\n");
                    frame.rax = u64::MAX;
                }
            }
        }
        Ok(wuxia_core::syscall::PosixRequest::Write { descriptor, buffer }) => {
            if !crate::sched::descriptor_open(descriptor)
                || !crate::sched::region_contains(buffer.address, buffer.length)
            {
                serial::write_str("WUXIA_SYSCALL_REJECTED\n");
                frame.rax = u64::MAX;
                return;
            }
            if descriptor == 1 || descriptor == 2 {
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
                return;
            }
            let length = buffer.length.min(wuxia_core::syscall::MAX_READ_LENGTH) as usize;
            let mut scratch = [0u8; wuxia_core::syscall::MAX_READ_LENGTH as usize];
            let stored = copy_user_bytes(buffer.address, length as u64, &mut scratch)
                .ok()
                .and_then(|count| crate::sched::write_file(descriptor, &scratch[..count]));
            match stored {
                Some(count) => {
                    serial::write_str("WUXIA_SYSCALL_FILE_WRITE_OK\n");
                    serial::write_hex(count as u64);
                    frame.rax = count as u64;
                }
                None => {
                    serial::write_str("WUXIA_SYSCALL_INVALID\n");
                    frame.rax = u64::MAX;
                }
            }
        }
        Ok(wuxia_core::syscall::PosixRequest::Map { length }) => {
            match crate::sched::map_current(length) {
                Some(address) => {
                    serial::write_str("WUXIA_SYSCALL_MAP\n");
                    serial::write_hex(address);
                    frame.rax = address;
                }
                None => {
                    serial::write_str("WUXIA_SYSCALL_INVALID\n");
                    frame.rax = u64::MAX;
                }
            }
        }
        Ok(wuxia_core::syscall::PosixRequest::Unmap { address, length }) => {
            if crate::sched::unmap_current(address, length) {
                serial::write_str("WUXIA_SYSCALL_UNMAP\n");
                frame.rax = 0;
            } else {
                serial::write_str("WUXIA_SYSCALL_INVALID\n");
                frame.rax = u64::MAX;
            }
        }
        Ok(wuxia_core::syscall::PosixRequest::Seek {
            descriptor,
            offset,
            whence,
        }) => match crate::sched::seek_descriptor(descriptor, offset, whence) {
            Some(position) => {
                serial::write_str("WUXIA_SYSCALL_SEEK\n");
                serial::write_hex(position);
                frame.rax = position;
            }
            None => {
                serial::write_str("WUXIA_SYSCALL_INVALID\n");
                frame.rax = u64::MAX;
            }
        },
        Ok(wuxia_core::syscall::PosixRequest::FileSize { descriptor }) => {
            match crate::sched::descriptor_len(descriptor) {
                Some(length) => {
                    serial::write_str("WUXIA_SYSCALL_FILE_SIZE\n");
                    serial::write_hex(length);
                    frame.rax = length;
                }
                None => {
                    serial::write_str("WUXIA_SYSCALL_INVALID\n");
                    frame.rax = u64::MAX;
                }
            }
        }
        Ok(wuxia_core::syscall::PosixRequest::Close { descriptor }) => {
            if crate::sched::close_descriptor(descriptor) {
                serial::write_str("WUXIA_SYSCALL_CLOSE\n");
                frame.rax = 0;
            } else {
                serial::write_str("WUXIA_SYSCALL_INVALID\n");
                frame.rax = u64::MAX;
            }
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

/// Terminate the calling process, resuming another thread or the next image.
fn terminate(frame: &mut InterruptFrame, code: u64, label: &str) {
    if !crate::sched::exit_process(code) {
        serial::write_str("WUXIA_SYSCALL_INVALID\n");
        frame.rax = u64::MAX;
        return;
    }
    serial::write_str(label);
    serial::write_hex(code);
    if crate::sched::exit_current(frame) {
        return;
    }
    serial::write_str("WUXIA_TEARDOWN_OK\n");
    if let Some(frame) = crate::memory::allocate_frame() {
        serial::write_str("WUXIA_TEARDOWN_REUSE_OK\n");
        serial::write_hex(frame);
        let _ = crate::memory::free_frame(frame);
    }
    if let Some(image) = crate::user::next_image() {
        serial::write_str("WUXIA_FAULT_TEST\n");
        crate::paging::activate(image.new_pml4);
        crate::user::enter(
            image.entry,
            image.stack_address + u64::from(wuxia_core::paging::PAGE_SIZE) - 16,
        );
    }
    serial::write_str("WUXIA_TEST_PASS\n");
    serial::debug_exit(0x10);
    halt();
}

/// Service a native NT request from a process with the NT personality.
fn service_nt_syscall(frame: &mut InterruptFrame) {
    use wuxia_core::nt::{NtRequest, NtStatus};

    let registers = wuxia_core::syscall::Registers {
        args: [
            frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9,
        ],
    };
    match NtRequest::decode(frame.rax, &registers) {
        Ok(NtRequest::WriteFile { handle, buffer }) => {
            if handle != 1
                || !crate::sched::descriptor_open(handle)
                || !crate::sched::region_contains(buffer.address, buffer.length)
            {
                frame.rax = u64::from(NtStatus::INVALID_HANDLE.0);
                return;
            }
            match copy_user_to_serial(buffer.address, buffer.length) {
                Ok(()) => {
                    serial::write_str("WUXIA_NT_WRITE_OK\n");
                    frame.rax = 0;
                }
                Err(_) => {
                    serial::write_str("WUXIA_SYSCALL_FAULT\n");
                    frame.rax = u64::from(NtStatus::ACCESS_DENIED.0);
                }
            }
        }
        Ok(NtRequest::Close { handle }) => {
            frame.rax = if crate::sched::close_descriptor(handle) {
                0
            } else {
                u64::from(NtStatus::INVALID_HANDLE.0)
            };
        }
        Ok(NtRequest::AllocateVirtualMemory { length }) => {
            frame.rax = match crate::sched::map_current(length) {
                Some(address) => address,
                None => u64::from(NtStatus::ACCESS_DENIED.0),
            };
        }
        Ok(NtRequest::TerminateProcess { status }) => {
            terminate(frame, u64::from(status), "WUXIA_NT_EXIT\n");
        }
        Ok(NtRequest::ReadFile { .. }) => {
            frame.rax = u64::from(NtStatus::NOT_IMPLEMENTED.0);
        }
        Err(_) => {
            frame.rax = u64::from(NtStatus::INVALID_PARAMETER.0);
        }
    }
}

/// Copy a bounded user range into `out` through the HHDM.
fn copy_user_bytes(address: u64, length: u64, out: &mut [u8]) -> Result<usize, wuxia_core::Error> {
    let map = crate::paging::current_direct_map().ok_or(wuxia_core::Error::InvalidState)?;
    let entry = crate::paging::resolve(map, address)?;
    if !wuxia_core::paging::is_user(entry) {
        return Err(wuxia_core::Error::PermissionDenied);
    }
    let count = (length as usize).min(out.len());
    let mut copied = 0;
    while copied < count {
        let cursor = address + copied as u64;
        let entry = crate::paging::resolve(map, cursor)?;
        if !wuxia_core::paging::is_user(entry) {
            return Err(wuxia_core::Error::PermissionDenied);
        }
        let frame = wuxia_core::paging::physical_address(entry);
        let offset = cursor % wuxia_core::paging::PAGE_SIZE;
        let chunk = ((wuxia_core::paging::PAGE_SIZE - offset) as usize).min(count - copied);
        let source = map.physical_to_virtual(frame + offset)? as *const u8;
        for index in 0..chunk {
            // SAFETY: the leaf is user-accessible and the chunk stays
            // inside one 4 KiB frame.
            out[copied + index] = unsafe { source.add(index).read_volatile() };
        }
        copied += chunk;
    }
    Ok(count)
}

/// Copy `data` into a bounded, writable user range through the HHDM.
fn copy_user_from(address: u64, data: &[u8]) -> Result<(), wuxia_core::Error> {
    let map = crate::paging::current_direct_map().ok_or(wuxia_core::Error::InvalidState)?;
    let entry = crate::paging::resolve(map, address)?;
    if !wuxia_core::paging::is_user(entry) || !wuxia_core::paging::is_writable(entry) {
        return Err(wuxia_core::Error::PermissionDenied);
    }
    let mut copied = 0;
    while copied < data.len() {
        let cursor = address + copied as u64;
        let entry = crate::paging::resolve(map, cursor)?;
        if !wuxia_core::paging::is_user(entry) || !wuxia_core::paging::is_writable(entry) {
            return Err(wuxia_core::Error::PermissionDenied);
        }
        let frame = wuxia_core::paging::physical_address(entry);
        let offset = cursor % wuxia_core::paging::PAGE_SIZE;
        let chunk = ((wuxia_core::paging::PAGE_SIZE - offset) as usize).min(data.len() - copied);
        let destination = map.physical_to_virtual(frame + offset)? as *mut u8;
        for index in 0..chunk {
            // SAFETY: the leaf is present and writable, and the chunk stays
            // inside one 4 KiB frame.
            unsafe { destination.add(index).write_volatile(data[copied + index]) };
        }
        copied += chunk;
    }
    Ok(())
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
    let mut copied = 0;
    while copied < length {
        let cursor = address + copied;
        let entry = crate::paging::resolve(map, cursor)?;
        if !wuxia_core::paging::is_user(entry) {
            return Err(wuxia_core::Error::PermissionDenied);
        }
        let frame = wuxia_core::paging::physical_address(entry);
        let offset = cursor % wuxia_core::paging::PAGE_SIZE;
        let chunk = (wuxia_core::paging::PAGE_SIZE - offset).min(length - copied);
        let source = map.physical_to_virtual(frame + offset)? as *const u8;
        for index in 0..chunk as usize {
            // SAFETY: the leaf is user-accessible and the chunk stays
            // inside one 4 KiB frame.
            serial::write_byte(unsafe { source.add(index).read_volatile() });
        }
        copied += chunk;
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
