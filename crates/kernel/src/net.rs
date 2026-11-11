//! A minimal transmit path for the Intel 8254x controller on QEMU's `q35`.
//!
//! The driver does the four things a device needs before it can be trusted to
//! move data: it resets the controller and waits for the reset bit to clear, it
//! reads the station address out of the receive-address registers (falling back
//! to the serial EEPROM), it brings the link up, and it hands one frame to the
//! transmit engine through a descriptor ring that lives in physical memory the
//! device fetches by DMA. Completion is observed by polling the descriptor's
//! done bit, which proves the DMA read of both the descriptor and the frame
//! happened.
//!
//! Everything the device touches is physical memory the bootstrap owns for the
//! lifetime of the process: the ring and the frame are never freed, descriptors
//! are 16-byte aligned, and the ring length is the multiple of 128 bytes the
//! controller requires. There is no receive path and no interrupt path yet.

use wuxia_core::Error;
use wuxia_core::Result;
use wuxia_core::frames::FramePool;
use wuxia_core::hhdm::DirectMap;
use wuxia_core::net::{
    CTRL, CTRL_RST, DESCRIPTOR_SIZE, EERD, EERD_DONE, MAX_FRAME, MIN_FRAME, RAH, RAL, RING_BYTES,
    STATUS, STATUS_LU, TCTL, TDBAH, TDBAL, TDH, TDLEN, TDT, TX_CMD_EOP, TX_CMD_IFCS, TX_CMD_RS,
    TxDescriptor, eeprom_read_command, eeprom_read_data, link_up_control, mac_from_eeprom,
    mac_from_registers, register, transmit_control,
};

/// Highest number of polls spent waiting for the controller.
const POLL_LIMIT: usize = 1 << 20;

/// A mapped controller register window.
#[derive(Clone, Copy)]
pub struct Device {
    base: u64,
}

impl Device {
    /// Wrap a mapped BAR0 base address.
    ///
    /// The caller must have mapped at least the register file up to the highest
    /// offset this module touches and must keep that mapping for the lifetime of
    /// the value.
    pub const fn new(base: u64) -> Self {
        Self { base }
    }

    fn read(&self, offset: u32) -> Result<u32> {
        let offset = register(offset)?;
        // SAFETY: the caller mapped the register file and the offset was
        // validated against it. Device reads have side effects, so the access is
        // volatile and never reordered away.
        Ok(unsafe { core::ptr::read_volatile((self.base + u64::from(offset)) as *const u32) })
    }

    fn write(&self, offset: u32, value: u32) -> Result<()> {
        let offset = register(offset)?;
        // SAFETY: as for reads; the pointer is a mapped, uncached device page.
        unsafe {
            core::ptr::write_volatile((self.base + u64::from(offset)) as *mut u32, value);
        }
        Ok(())
    }

    /// Read the device control register.
    pub fn control(&self) -> Result<u32> {
        self.read(CTRL)
    }

    /// Read the device status register.
    pub fn status(&self) -> Result<u32> {
        self.read(STATUS)
    }

    /// Reset the controller and wait until it leaves the reset state.
    ///
    /// Errors: [`Error::WouldBlock`] if the controller never clears the reset
    /// bit, which means the mapping is not reaching a controller.
    pub fn reset(&self) -> Result<()> {
        self.write(CTRL, CTRL_RST)?;
        for _ in 0..POLL_LIMIT {
            if self.control()? & CTRL_RST == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(Error::WouldBlock)
    }

    /// Bring the link up with autonegotiation and report whether it is up.
    pub fn bring_up(&self) -> Result<bool> {
        self.write(CTRL, link_up_control())?;
        for _ in 0..POLL_LIMIT {
            if self.status()? & STATUS_LU != 0 {
                return Ok(true);
            }
            core::hint::spin_loop();
        }
        Ok(false)
    }

    /// Read one serial EEPROM word.
    ///
    /// Errors: [`Error::WouldBlock`] when the controller never reports done.
    pub fn eeprom_word(&self, address: u8) -> Result<u16> {
        self.write(EERD, eeprom_read_command(address))?;
        for _ in 0..POLL_LIMIT {
            let value = self.read(EERD)?;
            if value & EERD_DONE != 0 {
                return Ok(eeprom_read_data(value));
            }
            core::hint::spin_loop();
        }
        Err(Error::WouldBlock)
    }

    /// Read the station address.
    ///
    /// The receive-address registers hold it after reset; the serial EEPROM is
    /// the fallback for a controller that has not loaded them yet.
    pub fn mac(&self) -> Result<[u8; 6]> {
        let ral = self.read(RAL)?;
        let rah = self.read(RAH)?;
        if let Ok(mac) = mac_from_registers(ral, rah) {
            return Ok(mac);
        }
        let words = [
            self.eeprom_word(0)?,
            self.eeprom_word(1)?,
            self.eeprom_word(2)?,
        ];
        Ok(mac_from_eeprom(words))
    }

    /// Send one frame through the transmit descriptor ring.
    ///
    /// The ring and the frame are freshly allocated frames, zeroed through the
    /// direct map, filled in order and published with a store fence before the
    /// tail pointer moves. Returns the descriptor bytes read back from the ring
    /// after completion, so the caller can inspect the done bit rather than trust
    /// the loop to have succeeded.
    ///
    /// Errors: `InvalidInput` for a frame outside the supported length,
    /// `TableFull` when the frame pool is exhausted and `WouldBlock` when the
    /// controller never completes the descriptor.
    pub fn transmit<const N: usize>(
        &self,
        allocator: &mut FramePool<N>,
        direct_map: DirectMap,
        frame: &[u8],
    ) -> Result<[u8; DESCRIPTOR_SIZE]> {
        if frame.len() < MIN_FRAME || frame.len() > MAX_FRAME {
            return Err(Error::InvalidInput);
        }
        let ring = allocator.allocate().ok_or(Error::TableFull)?;
        let packet = allocator.allocate().ok_or(Error::TableFull)?;
        let ring_bytes = direct_map.physical_to_virtual(ring)? as *mut u8;
        let packet_bytes = direct_map.physical_to_virtual(packet)? as *mut u8;
        // SAFETY: both frames are owned by this driver for the rest of the boot,
        // are page-aligned and are large enough for one ring page and one frame.
        unsafe {
            core::ptr::write_bytes(ring_bytes, 0, RING_BYTES as usize);
            core::ptr::write_bytes(packet_bytes, 0, MAX_FRAME);
            core::ptr::copy_nonoverlapping(frame.as_ptr(), packet_bytes, frame.len());
        }

        let descriptor =
            TxDescriptor::new(packet, frame.len(), TX_CMD_EOP | TX_CMD_IFCS | TX_CMD_RS)?;
        let encoded = descriptor.encode();
        // SAFETY: the ring page holds at least one descriptor.
        unsafe {
            core::ptr::copy_nonoverlapping(encoded.as_ptr(), ring_bytes, DESCRIPTOR_SIZE);
        }

        self.write(TDBAL, (ring & 0xffff_ffff) as u32)?;
        self.write(TDBAH, (ring >> 32) as u32)?;
        self.write(TDLEN, RING_BYTES)?;
        self.write(TDH, 0)?;
        self.write(TDT, 0)?;
        self.write(TCTL, transmit_control())?;

        // Publish the descriptor and frame before the device may fetch them.
        // SAFETY: `sfence` orders stores and has no memory side effects.
        unsafe {
            core::arch::asm!("sfence", options(nostack, preserves_flags));
        }
        self.write(TDT, 1)?;

        for _ in 0..POLL_LIMIT {
            let head = self.read(TDH)?;
            // SAFETY: the descriptor lives in the ring frame owned above.
            let current = unsafe { core::ptr::read_volatile(ring_bytes.add(12)) };
            if head == 1 || current & wuxia_core::net::TX_STATUS_DD != 0 {
                let mut readback = [0u8; DESCRIPTOR_SIZE];
                // SAFETY: as above; the ring is one page and the descriptor is
                // the first sixteen bytes.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        ring_bytes,
                        readback.as_mut_ptr(),
                        DESCRIPTOR_SIZE,
                    );
                }
                return Ok(readback);
            }
            core::hint::spin_loop();
        }
        Err(Error::WouldBlock)
    }
}
