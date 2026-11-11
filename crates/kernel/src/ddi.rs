//! The kernel-mode services a loaded driver may import.
//!
//! A Windows driver does not call the system through a trap: it links against
//! `ntoskrnl.exe` and calls exported routines directly, because it already runs
//! at CPL0. So the loader binds each import address table slot to the address of
//! one of the functions below instead of generating a syscall stub, and the
//! driver's call is an ordinary call with the documented calling convention.
//!
//! Each export is reachable through a thunk that also translates the calling
//! convention. A Windows driver passes its first integer arguments in
//! `rcx`/`rdx`/`r8`/`r9`; the kernel's Rust code uses the System V registers
//! `rdi`/`rsi`/`rdx`/`rcx`, so the thunk moves them and then calls the routine.
//!
//! Only routines whose whole contract can be honoured are exported. Each one
//! takes arguments from a driver the loader validated, so pointers are read with
//! volatile accesses and every length is bounded. A driver that passes a bad
//! pointer faults; that is the same contract a real kernel offers.

use crate::log;

/// Longest message `DbgPrint` will transcribe.
const MAX_MESSAGE: usize = 128;

/// Names a driver may import, in the order they are offered.
pub const EXPORT_NAMES: [&str; 3] = ["DbgPrint", "RtlZeroMemory", "KeGetCurrentIrql"];

/// The module whose imports the loader can serve.
pub const SERVED_MODULE: &str = "ntoskrnl.exe";

/// The exported entry points, in the Windows x64 calling convention.
///
/// A driver reaches these through its import address table, so their addresses
/// are what the loader binds.
unsafe extern "C" {
    fn wuxia_ddi_dbg_print(message: *const u8) -> u64;
    fn wuxia_ddi_rtl_zero_memory(destination: *mut u8, length: usize) -> u64;
    fn wuxia_ddi_ke_get_current_irql() -> u64;
}

// Each thunk moves the Windows argument registers into the System V ones and
// keeps the stack 16-byte aligned across the call.
core::arch::global_asm!(
    ".globl wuxia_ddi_dbg_print",
    ".p2align 4",
    "wuxia_ddi_dbg_print:",
    "sub rsp, 0x28",
    "mov rdi, rcx",
    "call {dbg_print}",
    "add rsp, 0x28",
    "ret",
    ".globl wuxia_ddi_rtl_zero_memory",
    ".p2align 4",
    "wuxia_ddi_rtl_zero_memory:",
    "sub rsp, 0x28",
    "mov rdi, rcx",
    "mov rsi, rdx",
    "call {zero_memory}",
    "add rsp, 0x28",
    "ret",
    ".globl wuxia_ddi_ke_get_current_irql",
    ".p2align 4",
    "wuxia_ddi_ke_get_current_irql:",
    "sub rsp, 0x28",
    "call {irql}",
    "add rsp, 0x28",
    "ret",
    dbg_print = sym dbg_print,
    zero_memory = sym rtl_zero_memory,
    irql = sym ke_get_current_irql,
);

/// Append NUL-terminated `message` to the kernel log and report success.
extern "sysv64" fn dbg_print(message: *const u8) -> u64 {
    let mut buffer = [0u8; MAX_MESSAGE];
    let mut length = 0;
    while length < buffer.len() {
        // SAFETY: the driver passes a NUL-terminated string in its own image, and
        // the copy stops at the first NUL or at the buffer limit.
        let byte = unsafe { core::ptr::read_volatile(message.add(length)) };
        if byte == 0 {
            break;
        }
        buffer[length] = byte;
        length += 1;
    }
    log::write_bytes(&buffer[..length]);
    0
}

/// Zero `length` bytes at `destination`.
extern "sysv64" fn rtl_zero_memory(destination: *mut u8, length: usize) -> u64 {
    let mut index = 0;
    while index < length {
        // SAFETY: the destination belongs to the calling driver, which owns the
        // writable section it names.
        unsafe {
            core::ptr::write_volatile(destination.add(index), 0);
        }
        index += 1;
    }
    0
}

/// Report the interrupt request level as passive, which is where the loader runs.
extern "sysv64" fn ke_get_current_irql() -> u64 {
    0
}

/// Resolve `module!name` to the address a driver should call.
///
/// Errors: `NotFound` for a module this kernel does not serve or a name it does
/// not export. Refusing here means an import address table is never patched with
/// a target that does nothing.
pub fn resolve(module: &str, name: &str) -> Result<u64, wuxia_core::Error> {
    if !module.eq_ignore_ascii_case(SERVED_MODULE) {
        return Err(wuxia_core::Error::NotFound);
    }
    match name {
        "DbgPrint" => Ok(wuxia_ddi_dbg_print as usize as u64),
        "RtlZeroMemory" => Ok(wuxia_ddi_rtl_zero_memory as usize as u64),
        "KeGetCurrentIrql" => Ok(wuxia_ddi_ke_get_current_irql as usize as u64),
        _ => Err(wuxia_core::Error::NotFound),
    }
}

/// How many routines are exported.
pub fn export_count() -> usize {
    EXPORT_NAMES.len()
}
