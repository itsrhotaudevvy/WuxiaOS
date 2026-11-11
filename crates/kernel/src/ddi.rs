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

use core::sync::atomic::{AtomicU64, Ordering};

use crate::log;

/// Longest message `DbgPrint` will transcribe.
const MAX_MESSAGE: usize = 128;

/// Names a driver may import, in the order they are offered.
pub const EXPORT_NAMES: [&str; 4] = [
    "DbgPrint",
    "RtlZeroMemory",
    "KeGetCurrentIrql",
    "MmMapIoSpace",
];

/// Where driver device mappings start.
///
/// It is its own page-map slot, so a driver's window can never alias the
/// kernel's own device windows or the kernel image.
pub const DRIVER_MMIO_BASE: u64 = 0xffff_9800_0000_0000;

/// Next free byte in the driver device window.
static MMIO_NEXT: AtomicU64 = AtomicU64::new(0);

/// The module whose imports the loader can serve.
pub const SERVED_MODULE: &str = "ntoskrnl.exe";

// The exported entry points, in the Windows x64 calling convention: a driver
// reaches these through its import address table, so these addresses are what
// the loader binds.
unsafe extern "C" {
    fn wuxia_ddi_dbg_print(message: *const u8) -> u64;
    fn wuxia_ddi_rtl_zero_memory(destination: *mut u8, length: usize) -> u64;
    fn wuxia_ddi_ke_get_current_irql() -> u64;
    fn wuxia_ddi_mm_map_io_space(physical: u64, length: u64, cache: u32) -> u64;
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
    ".globl wuxia_ddi_mm_map_io_space",
    ".p2align 4",
    "wuxia_ddi_mm_map_io_space:",
    "sub rsp, 0x28",
    "mov rdi, rcx",
    "mov rsi, rdx",
    "mov edx, r8d",
    "call {map_io_space}",
    "add rsp, 0x28",
    "ret",
    dbg_print = sym dbg_print,
    zero_memory = sym rtl_zero_memory,
    irql = sym ke_get_current_irql,
    map_io_space = sym mm_map_io_space,
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

/// Map a device's registers into the supervisor address space.
///
/// A driver cannot reach I/O memory through an ordinary pointer: the physical
/// range has to become a kernel virtual address, uncached, and location-wise the
/// kernel decides, not the driver. Returns the mapped base, or zero when the
/// request is refused, which is the failure a driver already knows how to check.
extern "sysv64" fn mm_map_io_space(physical: u64, length: u64, cache: u32) -> u64 {
    // Only noncached mappings exist: caching device registers would let the
    // processor reorder or suppress reads with side effects.
    if cache != 0 {
        return 0;
    }
    let pages = match wuxia_core::mmio::map_request(physical, length) {
        Ok(pages) => pages,
        Err(_) => return 0,
    };
    let bytes = match pages.checked_mul(wuxia_core::paging::PAGE_SIZE) {
        Some(bytes) => bytes,
        None => return 0,
    };
    // Reserve the window before mapping it, so two drivers can never be handed
    // the same addresses.
    let offset = MMIO_NEXT.fetch_add(bytes, Ordering::AcqRel);
    let base = match DRIVER_MMIO_BASE
        .checked_add(offset)
        .filter(|base| base.checked_add(bytes).is_some())
    {
        Some(base) => base,
        None => return 0,
    };
    let Some(direct_map) = crate::paging::current_direct_map() else {
        return 0;
    };
    match crate::paging::map_mmio_at(crate::memory::pool(), direct_map, base, physical, pages) {
        Ok(base) => base,
        Err(_) => 0,
    }
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
    if !EXPORT_NAMES.contains(&name) {
        return Err(wuxia_core::Error::NotFound);
    }
    match name {
        "DbgPrint" => Ok(wuxia_ddi_dbg_print as usize as u64),
        "RtlZeroMemory" => Ok(wuxia_ddi_rtl_zero_memory as usize as u64),
        "KeGetCurrentIrql" => Ok(wuxia_ddi_ke_get_current_irql as usize as u64),
        "MmMapIoSpace" => Ok(wuxia_ddi_mm_map_io_space as usize as u64),
        _ => Err(wuxia_core::Error::NotFound),
    }
}
