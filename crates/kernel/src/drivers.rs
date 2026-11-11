//! Loading a kernel-mode image.
//!
//! A Windows driver is a PE32+ image with a native subsystem, writable data and
//! read-only executable code. Loading one means four things, in this order: derive
//! a plan that gives every section its own permissions, map the plan at an address
//! the kernel chooses, apply the image's base relocations for that address, and
//! transfer control to the entry point.
//!
//! The image is placed at a window of the supervisor address space that the
//! bootstrap reserves for drivers and that nothing else maps into. Only images
//! whose preferred base differs from the load base exercise the relocation path,
//! and the loader always applies it, so an image that was linked for a different
//! address is loaded correctly rather than faulting on its first absolute
//! reference.
//!
//! Imports are not resolved yet: an image that names any is refused instead of
//! being entered with a table full of zeros.

use wuxia_core::Error;
use wuxia_core::Result;
use wuxia_core::frames::FramePool;
use wuxia_core::hhdm::DirectMap;
use wuxia_core::load::LoaderPlan;

use crate::paging;

/// Address every driver image is loaded at.
///
/// It sits below the kernel image and above the device windows, in a page-map slot
/// nothing else in the bootstrap claims.
pub const DRIVER_BASE: u64 = 0xffff_9700_0000_0000;

/// Highest number of sections a driver image may have.
pub const MAX_SECTIONS: usize = 8;

/// A loaded image's entry point.
#[derive(Clone, Copy)]
pub struct Loaded {
    /// Address the image was mapped at.
    pub base: u64,
    /// Address of the entry point.
    pub entry: u64,
    /// Number of relocation slots patched.
    pub relocations: usize,
}

/// Load a kernel-mode image and return where it was mapped and where to enter it.
///
/// Errors: whatever [`LoaderPlan::from_kernel_pe`] and the mapper report, plus
/// [`Error::Unsupported`] for an image that names imports, since an entry point
/// that runs with an unresolved import table would call into address zero.
pub fn load<const N: usize>(
    allocator: &mut FramePool<N>,
    direct_map: DirectMap,
    image: &[u8],
) -> Result<Loaded> {
    let imports = wuxia_core::pe_reloc::data_directory(image, 1)?;
    if imports.rva != 0 || imports.size != 0 {
        return Err(Error::Unsupported);
    }
    let plan = LoaderPlan::<MAX_SECTIONS>::from_kernel_pe(image, DRIVER_BASE)?;
    paging::map_kernel_image(allocator, direct_map, &plan, image)?;
    let relocations =
        paging::apply_pe_relocations_at(direct_map, paging::read_cr3(), image, DRIVER_BASE)?;
    Ok(Loaded {
        base: DRIVER_BASE,
        entry: plan.entry(),
        relocations,
    })
}
