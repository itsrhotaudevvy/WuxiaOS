//! Control-register hardening.
//!
//! The bootstrap never trusted the firmware's control-register state. This
//! module turns the features the *hardware* advertises into enforced policy:
//!
//! * `CR0.WP` makes the supervisor honor read-only page-table leaves, so the
//!   W^X mapping the loader builds cannot be bypassed by a kernel write.
//! * `EFER.NXE` makes the no-execute bit in a leaf meaningful; without it the
//!   loader's NX data pages would happily execute.
//! * `CR4.SMEP` stops the kernel from fetching instructions out of a user page.
//! * `CR4.SMAP` stops the kernel from reading or writing a user page by
//!   accident. The kernel only touches user memory through the direct map,
//!   whose leaves are supervisor pages, so the copy helpers keep working.
//! * `CR4.UMIP` stops ring 3 from reading descriptor-table state with `sgdt`
//!   and friends.
//!
//! Every bit is applied only when CPUID advertises it, because writing an
//! unsupported bit to CR4 raises a general-protection fault.

use core::arch::{asm, x86_64::__cpuid_count};

/// CR0 bit that makes writes to read-only pages fault in ring 0.
const CR0_WRITE_PROTECT: u64 = 1 << 16;
/// CR4 bit that forbids executing user pages from ring 0.
const CR4_SMEP: u64 = 1 << 20;
/// CR4 bit that forbids supervisor access to user pages.
const CR4_SMAP: u64 = 1 << 21;
/// CR4 bit that forbids ring 3 from reading descriptor tables.
const CR4_UMIP: u64 = 1 << 11;
/// `EFER` model-specific register selector.
const EFER_MSR: u32 = 0xc000_0080;
/// `EFER` bit that enables the page-table no-execute bit.
const EFER_NO_EXECUTE: u64 = 1 << 11;

/// CPU features enabled by [`harden`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Hardening {
    /// `CR0.WP` is set.
    pub write_protect: bool,
    /// `EFER.NXE` is set.
    pub no_execute: bool,
    /// `CR4.SMEP` is set.
    pub smep: bool,
    /// `CR4.SMAP` is set.
    pub smap: bool,
    /// `CR4.UMIP` is set.
    pub umip: bool,
}

impl Hardening {
    /// Bit mask of the applied features, for the serial log.
    pub fn bits(self) -> u64 {
        u64::from(self.write_protect)
            | u64::from(self.no_execute) << 1
            | u64::from(self.smep) << 2
            | u64::from(self.smap) << 3
            | u64::from(self.umip) << 4
    }
}

/// Apply every hardening feature the CPU supports.
pub fn harden() -> Hardening {
    let mut applied = Hardening::default();

    // SAFETY: reading and writing the control registers is privileged and the
    // kernel owns them at this point; every written bit is CPUID-checked.
    unsafe {
        let cr0 = read_cr0();
        write_cr0(cr0 | CR0_WRITE_PROTECT);
        applied.write_protect = read_cr0() & CR0_WRITE_PROTECT != 0;

        let efer = read_msr(EFER_MSR);
        write_msr(EFER_MSR, efer | EFER_NO_EXECUTE);
        applied.no_execute = read_msr(EFER_MSR) & EFER_NO_EXECUTE != 0;

        let mut cr4 = read_cr4();
        if supports_smep() {
            cr4 |= CR4_SMEP;
        }
        if supports_smap() {
            cr4 |= CR4_SMAP;
        }
        if supports_umip() {
            cr4 |= CR4_UMIP;
        }
        write_cr4(cr4);
        let cr4 = read_cr4();
        applied.smep = cr4 & CR4_SMEP != 0;
        applied.smap = cr4 & CR4_SMAP != 0;
        applied.umip = cr4 & CR4_UMIP != 0;
    }

    applied
}

/// Whether the CPU advertises supervisor-mode execution prevention.
fn supports_smep() -> bool {
    // SAFETY: CPUID is available in every ring and reads no memory.
    unsafe { __cpuid_count(7, 0).ebx & (1 << 7) != 0 }
}

/// Whether the CPU advertises supervisor-mode access prevention.
fn supports_smap() -> bool {
    // SAFETY: CPUID is available in every ring and reads no memory.
    unsafe { __cpuid_count(7, 0).ebx & (1 << 20) != 0 }
}

/// Whether the CPU advertises user-mode instruction prevention.
fn supports_umip() -> bool {
    // SAFETY: CPUID is available in every ring and reads no memory.
    unsafe { __cpuid_count(7, 0).ecx & (1 << 2) != 0 }
}

/// Read `CR0`.
fn read_cr0() -> u64 {
    let value: u64;
    // SAFETY: the caller guarantees ring 0 and the register is readable.
    unsafe { asm!("mov {}, cr0", out(reg) value, options(nomem, nostack, preserves_flags)) };
    value
}

/// Write `CR0`.
fn write_cr0(value: u64) {
    // SAFETY: the caller passes a value with only documented bits set.
    unsafe { asm!("mov cr0, {}", in(reg) value, options(nostack, preserves_flags)) };
}

/// Read `CR4`.
fn read_cr4() -> u64 {
    let value: u64;
    // SAFETY: the caller guarantees ring 0 and the register is readable.
    unsafe { asm!("mov {}, cr4", out(reg) value, options(nomem, nostack, preserves_flags)) };
    value
}

/// Write `CR4`.
fn write_cr4(value: u64) {
    // SAFETY: the caller passes a value with only CPUID-checked bits set.
    unsafe { asm!("mov cr4, {}", in(reg) value, options(nostack, preserves_flags)) };
}

/// Read a model-specific register.
fn read_msr(register: u32) -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: `EFER` is architecturally readable in ring 0.
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") register,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
    (u64::from(high) << 32) | u64::from(low)
}

/// Write a model-specific register.
fn write_msr(register: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    // SAFETY: the caller passes a value with only documented bits set.
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") register,
            in("eax") low,
            in("edx") high,
            options(nostack, preserves_flags)
        );
    }
}
