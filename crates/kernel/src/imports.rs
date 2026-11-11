//! Resolve a PE32+ image's imports against the syscall stubs this kernel offers.
//!
//! A real Windows binary does not issue system calls itself: it calls a name
//! exported by `ntdll.dll`, and the loader decides where that name lives. The
//! bootstrap has no DLL to load yet, so it synthesises the far side of that
//! contract: every imported name it can serve becomes a twelve-byte stub in one
//! executable user page, and each import address table slot is rebound to that
//! stub. The image therefore reaches the kernel by name through its IAT, which
//! is the mechanism a real `ntdll` would provide, instead of through a
//! hard-coded system-call number.
//!
//! Nothing about the image is trusted: descriptors, names and thunk tables are
//! parsed by `wuxia_core::pe_import`, unknown DLL names and unknown imports are
//! refused, ordinal imports are refused because no ordinal space exists yet,
//! and IAT slots are written only after the address resolves inside a mapped
//! frame of the image.

use wuxia_core::Error;
use wuxia_core::frames::FramePool;
use wuxia_core::hhdm::DirectMap;
use wuxia_core::image::PeImage;
use wuxia_core::paging::PagePermissions;
use wuxia_core::pe_common::SectionRange;
use wuxia_core::pe_import::{Import, ImportDirectory};
use wuxia_core::pe_reloc::data_directory;

use crate::paging::{self, UserImage};

/// Data directory index of the import table.
const IMPORT_DIRECTORY: usize = 1;

/// The one module this bootstrap can serve.
const SERVED_MODULE: &str = "ntdll.dll";

/// Size of one generated syscall stub.
///
/// `mov rax, imm32` (7) + `int 0x80` (2) + `ret` (1) is ten bytes; two `nop`
/// bytes pad the stub to twelve so every stub offset is 4-byte aligned.
pub const STUB_SIZE: usize = 12;

/// Highest number of distinct imports a single image may reach.
const MAX_IMPORTS: usize = 64;

/// Highest number of section ranges the resolver builds.
const MAX_SECTIONS: usize = 8;

/// One resolved import: the name the image asked for and its stub offset.
#[derive(Clone, Copy)]
struct Resolved<'a> {
    name: &'a str,
    offset: usize,
}

/// Map the image's imports onto generated stubs and rebind their IAT slots.
///
/// Returns the number of IAT slots patched. An image without an import table
/// returns zero and changes nothing.
///
/// Errors: `NotFound` for an import the bootstrap cannot serve, `InvalidImage`
/// for an ordinal import or a table that does not fit, and the paging errors of
/// [`paging::map_user_range`] and [`paging::write_user_bytes`].
pub fn resolve<const N: usize>(
    allocator: &mut FramePool<N>,
    direct_map: DirectMap,
    image: &mut UserImage,
    bytes: &[u8],
    delta: i64,
) -> Result<usize, Error> {
    let directory = match data_directory(bytes, IMPORT_DIRECTORY) {
        Ok(directory) => directory,
        Err(Error::NotFound) => return Ok(0),
        Err(error) => return Err(error),
    };
    if directory.size == 0 {
        return Ok(0);
    }
    let (image_base, _) = wuxia_core::pe_common::image_base_and_size(bytes)?;
    let base = image_base
        .checked_add_signed(delta)
        .ok_or(Error::OutOfRange)?;

    let pe = PeImage::parse(bytes)?;
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
    let imports = ImportDirectory::new(bytes, &ranges[..count], directory.rva, directory.size);

    let mut resolved: [Option<Resolved<'_>>; MAX_IMPORTS] = [None; MAX_IMPORTS];
    let mut resolved_count = 0;
    let mut slots = [(0u64, 0usize); MAX_IMPORTS];
    let mut slot_count = 0;

    for module in imports.modules() {
        let module = module?;
        if !module.name.eq_ignore_ascii_case(SERVED_MODULE) {
            return Err(Error::NotFound);
        }
        let mut thunk_index = 0u64;
        for thunk in module.thunks() {
            let slot = thunk?;
            let name = match slot {
                Import::Ordinal(_) => return Err(Error::InvalidImage),
                Import::Name(import) => import.name,
            };
            // The name must be one the bootstrap can serve; refusing here
            // means the IAT is never patched with a target that does nothing.
            syscall_number(name).ok_or(Error::NotFound)?;
            let offset = match stub_offset(&resolved[..resolved_count], name) {
                Some(offset) => offset,
                None => {
                    if resolved_count == MAX_IMPORTS {
                        return Err(Error::TableFull);
                    }
                    let offset = resolved_count * STUB_SIZE;
                    resolved[resolved_count] = Some(Resolved { name, offset });
                    resolved_count += 1;
                    offset
                }
            };
            let iat = base
                .checked_add(u64::from(module.iat_rva))
                .and_then(|iat| iat.checked_add(thunk_index * 8))
                .ok_or(Error::OutOfRange)?;
            thunk_index += 1;
            if slot_count == MAX_IMPORTS {
                return Err(Error::TableFull);
            }
            slots[slot_count] = (iat, offset);
            slot_count += 1;
        }
    }
    if slot_count == 0 {
        return Ok(0);
    }

    // Build the stub page before mapping it: each stub sets rax to its call
    // number, traps and returns, so the imported call is an ordinary call.
    let mut page = [0u8; wuxia_core::paging::PAGE_SIZE as usize];
    let mut stubs = 0;
    for entry in resolved[..resolved_count].iter().flatten() {
        let number = syscall_number(entry.name).ok_or(Error::NotFound)?;
        let stub = &mut page[entry.offset..entry.offset + STUB_SIZE];
        stub[0..3].copy_from_slice(&[0x48, 0xc7, 0xc0]);
        stub[3..7].copy_from_slice(&number.to_le_bytes());
        stub[7] = 0xcd;
        stub[8] = 0x80;
        stub[9] = 0xc3;
        stub[10] = 0x90;
        stub[11] = 0x90;
        stubs += 1;
    }
    if stubs == 0 {
        return Ok(0);
    }

    // The stub page follows the stack page: both live in the image's PML4 slot
    // and nothing else is mapped there.
    let address = image
        .stack_address
        .checked_add(wuxia_core::paging::PAGE_SIZE)
        .ok_or(Error::OutOfRange)?;
    paging::map_user_range(
        allocator,
        direct_map,
        &mut image.frames,
        image.new_pml4,
        address,
        wuxia_core::paging::PAGE_SIZE,
        PagePermissions::USER_CODE,
    )?;
    paging::write_user_bytes(direct_map, image.new_pml4, address, &page)?;

    let mut patched = 0;
    for (iat, offset) in slots[..slot_count].iter() {
        let target = address
            .checked_add(*offset as u64)
            .ok_or(Error::OutOfRange)?;
        paging::write_user_u64(direct_map, image.new_pml4, *iat, target)?;
        patched += 1;
    }
    Ok(patched)
}

/// Return the stub offset already assigned to `name`.
fn stub_offset(resolved: &[Option<Resolved<'_>>], name: &str) -> Option<usize> {
    resolved
        .iter()
        .flatten()
        .find(|entry| entry.name == name)
        .map(|entry| entry.offset)
}

/// Map an imported function name onto the system-call number it stands for.
fn syscall_number(name: &str) -> Option<u32> {
    Some(match name {
        "NtClose" => 0x0f,
        "NtReadFile" => 0x06,
        "NtWriteFile" => 0x08,
        "NtAllocateVirtualMemory" => 0x16,
        "NtTerminateProcess" => 0x29,
        "NtQueryPerformanceCounter" => 0x31,
        "NtCreateFile" => 0x34,
        _ => return None,
    })
}
