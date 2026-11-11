//! Local and I/O APIC bring-up.
//!
//! The bootstrap starts on the legacy 8259 pair, which is enough for the timer
//! but cannot route a message-signalled interrupt: only the local APIC can
//! receive one. This module maps both APIC windows uncached, enables the local
//! APIC with a spurious vector, and programs the I/O APIC's redirection entries
//! when a device still uses a legacy line.
//!
//! The windows are mapped in their own slots below [`paging::MMIO_BASE`], one per
//! controller, and mapping fails loudly instead of silently leaving the APIC
//! unmapped. Interrupt delivery is then a property of hardware state the boot can
//! test: a self-interrupt arrives at [`DEVICE_VECTOR`] or it does not.

use wuxia_core::Error;
use wuxia_core::Result;
use wuxia_core::apic;
use wuxia_core::frames::FramePool;
use wuxia_core::hhdm::DirectMap;

use crate::paging;

/// Vector this kernel uses for device interrupts.
///
/// It sits above the remapped 8259 vectors (0x20/0x28), the legacy syscall gate
/// (0x80) and the processor exceptions, and below the local APIC's spurious
/// vector.
pub const DEVICE_VECTOR: u8 = 0x40;

/// Slot below [`paging::MMIO_BASE`] holding the local APIC window.
const LOCAL_WINDOW: u64 = 1;
/// Slot below [`paging::MMIO_BASE`] holding the I/O APIC window.
const IO_WINDOW: u64 = 2;

/// The local APIC.
#[derive(Clone, Copy)]
pub struct Local {
    base: u64,
    /// Identifier of this APIC, from the identifier register.
    pub id: u8,
    /// Version register.
    pub version: u32,
}

/// One local APIC register as read during bring-up.
fn read_local(base: u64, offset: u32) -> Result<u32> {
    let offset = apic::lapic_register(offset)?;
    // SAFETY: the caller mapped the register window as uncached supervisor
    // memory, and the offset was validated against it.
    Ok(unsafe { core::ptr::read_volatile((base + u64::from(offset)) as *const u32) })
}

fn write_local(base: u64, offset: u32, value: u32) -> Result<()> {
    let offset = apic::lapic_register(offset)?;
    // SAFETY: as for reads.
    unsafe {
        core::ptr::write_volatile((base + u64::from(offset)) as *mut u32, value);
    }
    Ok(())
}

impl Local {
    /// Map and inspect the local APIC without enabling it yet.
    pub fn map<const N: usize>(
        allocator: &mut FramePool<N>,
        direct_map: DirectMap,
        physical: u64,
    ) -> Result<Self> {
        let base = paging::map_mmio(allocator, direct_map, LOCAL_WINDOW, physical, 1)?;
        let id = read_local(base, apic::LAPIC_ID)?;
        let version = read_local(base, apic::LAPIC_VERSION)?;
        Ok(Self {
            base,
            id: apic::lapic_identifier(id),
            version,
        })
    }

    /// Enable the APIC, raise its task priority to zero and mask every local
    /// vector table entry the bootstrap does not use.
    pub fn enable(&self) -> Result<()> {
        write_local(self.base, apic::LAPIC_SVR, apic::spurious_vector_register())?;
        write_local(self.base, apic::LAPIC_TPR, 0)?;
        // The 8259 is wired to the first lint entry, so that entry is what keeps
        // the timer and any other unmasked legacy line working; masking it would
        // silently stop every legacy interrupt.
        write_local(self.base, apic::LAPIC_LVT_LINT0, apic::extint_entry())?;
        for entry in [
            apic::LAPIC_LVT_TIMER,
            apic::LAPIC_LVT_LINT1,
            apic::LAPIC_LVT_ERROR,
        ] {
            write_local(self.base, entry, apic::LVT_MASKED)?;
        }
        Ok(())
    }

    /// Read the spurious vector register, so the caller can log what took effect.
    pub fn control(&self) -> Result<u32> {
        read_local(self.base, apic::LAPIC_SVR)
    }

    /// Send one interrupt to this APIC and wait until the delivery is accepted.
    ///
    /// Errors: [`Error::WouldBlock`] when the APIC never clears the pending bit,
    /// which means the enable above did not take effect.
    pub fn interrupt_self(&self, vector: u8) -> Result<()> {
        write_local(
            self.base,
            apic::LAPIC_ICR_LOW,
            apic::self_interrupt(vector)?,
        )?;
        for _ in 0..(1 << 20) {
            let value = read_local(self.base, apic::LAPIC_ICR_LOW)?;
            if value & apic::ICR_DELIVERY_PENDING == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(Error::WouldBlock)
    }

    /// Acknowledge the interrupt currently being serviced.
    pub fn end_of_interrupt(&self) -> Result<()> {
        write_local(self.base, apic::LAPIC_EOI, 0)
    }
}

/// The I/O APIC.
#[derive(Clone, Copy)]
pub struct Io {
    select: u64,
    window: u64,
    /// Identifier of this I/O APIC.
    pub id: u8,
    /// Version register, whose top byte counts the redirection entries.
    pub version: u32,
}

impl Io {
    /// Map and inspect the I/O APIC.
    pub fn map<const N: usize>(
        allocator: &mut FramePool<N>,
        direct_map: DirectMap,
        physical: u64,
    ) -> Result<Self> {
        let base = paging::map_mmio(allocator, direct_map, IO_WINDOW, physical, 1)?;
        let select = base + u64::from(apic::IOAPIC_SELECT);
        let window = base + u64::from(apic::IOAPIC_WINDOW);
        // SAFETY: both offsets are inside the mapped one-page window.
        let id = unsafe { core::ptr::read_volatile(select as *const u32) };
        // Reading the identifier register first is not required; select the
        // version register and read it through the indirect window.
        unsafe {
            core::ptr::write_volatile(select as *mut u32, apic::IOAPIC_VERSION);
        }
        let version = unsafe { core::ptr::read_volatile(window as *const u32) };
        Ok(Self {
            select,
            window,
            id: apic::ioapic_identifier(id),
            version,
        })
    }

    /// Highest redirection entry index this controller implements.
    pub fn max_redirection(&self) -> u32 {
        apic::ioapic_max_redirection(self.version)
    }

    fn read(&self, index: u32) -> u32 {
        // SAFETY: the indirect register pair lives in the mapped window; the
        // index was checked by `route` before any write is made.
        unsafe {
            core::ptr::write_volatile(self.select as *mut u32, index);
            core::ptr::read_volatile(self.window as *const u32)
        }
    }

    fn write(&self, index: u32, value: u32) {
        // SAFETY: as for reads.
        unsafe {
            core::ptr::write_volatile(self.select as *mut u32, index);
            core::ptr::write_volatile(self.window as *mut u32, value);
        }
    }

    /// Route an interrupt line to `vector` on the APIC identified by
    /// `destination`.
    ///
    /// Errors: [`Error::OutOfRange`] when the controller implements no such
    /// redirection entry.
    pub fn route(
        &self,
        line: u32,
        vector: u8,
        destination: u8,
        level_triggered: bool,
        active_low: bool,
    ) -> Result<()> {
        if !apic::ioapic_has_entry(self.version, line) {
            return Err(Error::OutOfRange);
        }
        let [low, high] =
            apic::ioapic_redirection(vector, destination, level_triggered, active_low);
        self.write(apic::IOAPIC_REDIRECTION_START + line * 2, low);
        self.write(apic::IOAPIC_REDIRECTION_START + line * 2 + 1, high);
        Ok(())
    }

    /// Mask one redirection entry.
    pub fn mask(&self, line: u32) -> Result<()> {
        if !apic::ioapic_has_entry(self.version, line) {
            return Err(Error::OutOfRange);
        }
        let low = self.read(apic::IOAPIC_REDIRECTION_START + line * 2);
        self.write(
            apic::IOAPIC_REDIRECTION_START + line * 2,
            low | apic::LVT_MASKED,
        );
        Ok(())
    }
}

/// Physical window each controller sits in, as the firmware leaves it.
pub const LOCAL_APIC_PHYSICAL: u64 = apic::LOCAL_APIC_BASE;
/// Physical window of the I/O APIC.
pub const IO_APIC_PHYSICAL: u64 = apic::IO_APIC_BASE;
