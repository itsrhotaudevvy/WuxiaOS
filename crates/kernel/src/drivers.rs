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
//! Imports are bound here, not stubbed. A driver already runs at CPL0, so it
//! calls `ntoskrnl.exe` exports directly; each import address table slot is
//! rewritten with the address of the kernel routine that serves that name, and a
//! name this kernel does not export refuses the whole image instead of leaving a
//! slot pointing at zeros.

use wuxia_core::Error;
use wuxia_core::Result;
use wuxia_core::frames::FramePool;
use wuxia_core::hhdm::DirectMap;
use wuxia_core::image::PeImage;
use wuxia_core::load::LoaderPlan;
use wuxia_core::pe_common::SectionRange;
use wuxia_core::pe_import::{Import, ImportDirectory};
use wuxia_core::pe_reloc::data_directory;

use crate::ddi;
use crate::paging;
use wuxia_core::paging::PAGE_SIZE;

/// Data directory index of the import table.
const IMPORT_DIRECTORY: usize = 1;

/// Highest number of import descriptors a driver image may resolve.
const MAX_IMPORTS: usize = 64;

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
    /// Number of import address table slots bound to kernel routines.
    pub imports: usize,
}

/// Load a kernel-mode image and return where it was mapped and where to enter it.
///
/// Errors: whatever [`LoaderPlan::from_kernel_pe`] and the mapper report, plus
/// [`Error::NotFound`] for an import no routine here serves and `InvalidImage`
/// for an ordinal import or a table that does not fit.
pub fn load<const N: usize>(
    allocator: &mut FramePool<N>,
    direct_map: DirectMap,
    image: &[u8],
) -> Result<Loaded> {
    let plan = LoaderPlan::<MAX_SECTIONS>::from_kernel_pe(image, DRIVER_BASE)?;
    paging::map_kernel_image(allocator, direct_map, &plan, image)?;
    let relocations =
        paging::apply_pe_relocations_at(direct_map, paging::read_cr3(), image, DRIVER_BASE)?;
    let imports = bind_imports(&plan, image, DRIVER_BASE)?;
    // The contents are final, so the image takes its real permissions: code
    // read-only and executable, data writable and non-executable.
    paging::protect_kernel_image(direct_map, &plan)?;
    Ok(Loaded {
        base: DRIVER_BASE,
        entry: plan.entry(),
        relocations,
        imports,
    })
}

/// Point every import address table slot at the routine that serves its name.
///
/// Returns the number of slots written. An image without an import table returns
/// zero; an image with one is never entered with an unbound slot.
fn bind_imports(plan: &LoaderPlan<MAX_SECTIONS>, image: &[u8], base: u64) -> Result<usize> {
    let directory = match data_directory(image, IMPORT_DIRECTORY) {
        Ok(directory) => directory,
        Err(Error::NotFound) => return Ok(0),
        Err(error) => return Err(error),
    };
    if directory.size == 0 {
        return Ok(0);
    }
    let pe = PeImage::parse(image)?;
    let mut ranges = [SectionRange {
        virtual_address: 0,
        raw_offset: 0,
        raw_size: 0,
    }; MAX_SECTIONS];
    let mut count = 0;
    while count < MAX_SECTIONS && (count as u16) < pe.section_count() {
        let section = pe.section(count)?;
        ranges[count] = SectionRange {
            virtual_address: section.virtual_address,
            raw_offset: section.raw_offset,
            raw_size: section.raw_size,
        };
        count += 1;
    }
    if (count as u16) < pe.section_count() {
        return Err(Error::TableFull);
    }
    let imports = ImportDirectory::new(image, &ranges[..count], directory.rva, directory.size);

    let mut bound = 0;
    for module in imports.modules() {
        let module = module?;
        let mut thunk_index = 0u64;
        for thunk in module.thunks() {
            let name = match thunk? {
                Import::Ordinal(_) => return Err(Error::InvalidImage),
                Import::Name(import) => import.name,
            };
            let address = ddi::resolve(module.name, name)?;
            let slot = base
                .checked_add(u64::from(module.iat_rva))
                .and_then(|iat| iat.checked_add(thunk_index * 8))
                .ok_or(Error::OutOfRange)?;
            thunk_index += 1;
            if bound == MAX_IMPORTS {
                return Err(Error::TableFull);
            }
            write_slot(plan, slot, address)?;
            bound += 1;
        }
    }
    Ok(bound)
}

/// Write one resolved address into an import slot of the mapped image.
///
/// The slot must fall inside a mapped segment, so a malformed table can never make
/// the loader write outside the image it is loading. The pages are still mapped
/// writable here: [`paging::protect_kernel_image`] runs afterwards.
fn write_slot(plan: &LoaderPlan<MAX_SECTIONS>, slot: u64, address: u64) -> Result<()> {
    if slot % 8 != 0 {
        return Err(Error::BadAddress);
    }
    let inside = plan.segments().any(|segment| {
        slot >= segment.address
            && slot
                < segment
                    .address
                    .saturating_add(segment.page_count() * PAGE_SIZE)
    });
    if !inside {
        return Err(Error::BadAddress);
    }
    // SAFETY: the slot is inside a segment this loader mapped in the active
    // address space, the segment is still mapped writable at this point, and the
    // slot is eight-byte aligned.
    unsafe {
        (slot as *mut u64).write_volatile(address);
    }
    Ok(())
}
