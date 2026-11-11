//! Bounds-checked PE32+ import directory parsing.
//!
//! The parser walks `IMAGE_IMPORT_DESCRIPTOR` entries and their 64-bit thunks
//! from caller-supplied image bytes. It never resolves a name to an address,
//! loads a library, or writes memory: it only reports what the image declares.
//!
//! RVAs are translated through a caller-supplied section table. An RVA resolves
//! only when it lies inside a section's raw data, and every read is confined to
//! that section and to the image bytes. Descriptor, thunk and name reads are
//! each resolved independently, so a table or name may not straddle a section
//! boundary without the parser noticing.

use crate::error::{Error, Result};

/// Maximum number of import descriptors accepted before the terminator.
pub const MAX_IMPORT_MODULES: usize = 256;

/// Maximum number of thunks accepted in one lookup table before its terminator.
pub const MAX_IMPORT_THUNKS: usize = 4096;

/// Maximum length in bytes of a DLL or function name, excluding its NUL.
pub const MAX_NAME_LEN: usize = 255;

const DESCRIPTOR_SIZE: usize = 20;
const THUNK_SIZE: usize = 8;
const ORDINAL_FLAG: u64 = 1 << 63;

/// One section's RVA-to-file mapping, taken from its section header.
///
/// Only the raw data is addressable: an RVA in the virtual tail beyond
/// `raw_size` has no bytes in the image and does not resolve.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SectionRange {
    /// Section virtual address relative to the image base.
    pub virtual_address: u32,
    /// Offset of the section's raw data in the image bytes.
    pub raw_offset: usize,
    /// Number of raw data bytes available in the image.
    pub raw_size: u32,
}

/// The import data directory of one image: its RVA, size and section map.
#[derive(Clone, Copy, Debug)]
pub struct ImportDirectory<'a> {
    bytes: &'a [u8],
    sections: &'a [SectionRange],
    rva: u32,
    size: u32,
}

/// Iterator over the descriptors of an import directory.
///
/// After the first error the iterator yields `None`, so a hostile table
/// produces one error and then stops.
#[derive(Clone, Copy, Debug)]
pub struct ImportModules<'a> {
    bytes: &'a [u8],
    sections: &'a [SectionRange],
    rva: u32,
    size: u32,
    index: usize,
    done: bool,
}

/// One import descriptor (DLL) with its validated name and table RVAs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportModule<'a> {
    /// DLL name, printable ASCII and at most `MAX_NAME_LEN` bytes.
    pub name: &'a str,
    /// RVA of the lookup table: OriginalFirstThunk, or FirstThunk when that is zero.
    pub lookup_rva: u32,
    /// RVA of the import address table (FirstThunk).
    pub iat_rva: u32,
    bytes: &'a [u8],
    sections: &'a [SectionRange],
}

/// Iterator over the thunks of one import descriptor's lookup table.
#[derive(Clone, Copy, Debug)]
pub struct ImportThunks<'a> {
    bytes: &'a [u8],
    sections: &'a [SectionRange],
    rva: u32,
    index: usize,
    done: bool,
}

/// One entry of a lookup table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Import<'a> {
    /// Import by ordinal, taken from the low 16 bits of an ordinal thunk.
    Ordinal(u16),
    /// Import by name, with the loader's hint and the function name.
    Name(ImportByName<'a>),
}

/// A function imported by name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportByName<'a> {
    /// Loader hint: the export-table index the loader should try first.
    pub hint: u16,
    /// Function name, printable ASCII and at most `MAX_NAME_LEN` bytes.
    pub name: &'a str,
}

impl<'a> ImportDirectory<'a> {
    /// Describe the import directory at `rva` spanning `size` bytes.
    ///
    /// An `rva` of zero describes an image without imports and yields no
    /// descriptors. The caller supplies `size` from the optional header's
    /// import data directory; it bounds the descriptor table.
    pub const fn new(bytes: &'a [u8], sections: &'a [SectionRange], rva: u32, size: u32) -> Self {
        Self {
            bytes,
            sections,
            rva,
            size,
        }
    }

    /// Iterate the descriptors, stopping at the all-zero terminator.
    ///
    /// Yields at most `MAX_IMPORT_MODULES` descriptors; a further non-zero
    /// descriptor yields `Error::TableFull`.
    pub const fn modules(&self) -> ImportModules<'a> {
        ImportModules {
            bytes: self.bytes,
            sections: self.sections,
            rva: self.rva,
            size: self.size,
            index: 0,
            done: self.rva == 0,
        }
    }
}

impl<'a> ImportModules<'a> {
    fn read_next(&mut self) -> Result<Option<ImportModule<'a>>> {
        let table_offset = self
            .index
            .checked_mul(DESCRIPTOR_SIZE)
            .ok_or(Error::InvalidImage)?;
        let table_end = table_offset
            .checked_add(DESCRIPTOR_SIZE)
            .ok_or(Error::InvalidImage)?;
        // A table without its terminator inside the directory size is truncated.
        if table_end > self.size as usize {
            return Err(Error::InvalidImage);
        }
        let rva = rva_add(self.rva, table_offset)?;
        let raw: [u8; DESCRIPTOR_SIZE] = read_array(self.bytes, self.sections, rva)?;
        if raw.iter().all(|&b| b == 0) {
            return Ok(None);
        }
        if self.index >= MAX_IMPORT_MODULES {
            return Err(Error::TableFull);
        }
        self.index += 1;

        // Descriptor layout: OriginalFirstThunk, TimeDateStamp,
        // ForwarderChain, Name, FirstThunk.
        let original_first_thunk = le_u32(&raw, 0);
        let name_rva = le_u32(&raw, 12);
        let first_thunk = le_u32(&raw, 16);
        let lookup_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        if lookup_rva == 0 || first_thunk == 0 {
            return Err(Error::InvalidImage);
        }
        let name = read_name(self.bytes, self.sections, name_rva)?;
        Ok(Some(ImportModule {
            name,
            lookup_rva,
            iat_rva: first_thunk,
            bytes: self.bytes,
            sections: self.sections,
        }))
    }
}

impl<'a> Iterator for ImportModules<'a> {
    type Item = Result<ImportModule<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.read_next() {
            Ok(Some(module)) => Some(Ok(module)),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(error) => {
                self.done = true;
                Some(Err(error))
            }
        }
    }
}

impl<'a> ImportModule<'a> {
    /// Iterate this module's lookup table, stopping at the zero thunk.
    ///
    /// Yields at most `MAX_IMPORT_THUNKS` entries; a further non-zero thunk
    /// yields `Error::TableFull`.
    pub const fn thunks(&self) -> ImportThunks<'a> {
        ImportThunks {
            bytes: self.bytes,
            sections: self.sections,
            rva: self.lookup_rva,
            index: 0,
            done: false,
        }
    }
}

impl<'a> ImportThunks<'a> {
    fn read_next(&mut self) -> Result<Option<Import<'a>>> {
        let offset = self
            .index
            .checked_mul(THUNK_SIZE)
            .ok_or(Error::InvalidImage)?;
        let rva = rva_add(self.rva, offset)?;
        let value = u64::from_le_bytes(read_array(self.bytes, self.sections, rva)?);
        if value == 0 {
            return Ok(None);
        }
        if self.index >= MAX_IMPORT_THUNKS {
            return Err(Error::TableFull);
        }
        self.index += 1;

        if value & ORDINAL_FLAG != 0 {
            // Intentional truncation: the ordinal is the low 16 bits.
            return Ok(Some(Import::Ordinal(value as u16)));
        }
        let hint_name_rva = u32::try_from(value).map_err(|_| Error::InvalidImage)?;
        let hint = u16::from_le_bytes(read_array(self.bytes, self.sections, hint_name_rva)?);
        let name_rva = hint_name_rva.checked_add(2).ok_or(Error::InvalidImage)?;
        let name = read_name(self.bytes, self.sections, name_rva)?;
        Ok(Some(Import::Name(ImportByName { hint, name })))
    }
}

impl<'a> Iterator for ImportThunks<'a> {
    type Item = Result<Import<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.read_next() {
            Ok(Some(import)) => Some(Ok(import)),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(error) => {
                self.done = true;
                Some(Err(error))
            }
        }
    }
}

/// Translate an RVA to its file offset and the bytes readable from there.
///
/// Returns `(offset, available)` where `available` counts bytes up to the end
/// of the containing section's raw data, clipped to the image length.
fn resolve(bytes: &[u8], sections: &[SectionRange], rva: u32) -> Result<(usize, usize)> {
    for section in sections {
        let delta = match rva.checked_sub(section.virtual_address) {
            Some(delta) => delta,
            None => continue,
        };
        if delta >= section.raw_size {
            continue;
        }
        let offset = section
            .raw_offset
            .checked_add(delta as usize)
            .ok_or(Error::InvalidImage)?;
        let raw_end = section
            .raw_offset
            .checked_add(section.raw_size as usize)
            .ok_or(Error::InvalidImage)?;
        let limit = raw_end.min(bytes.len());
        if offset >= limit {
            return Err(Error::InvalidImage);
        }
        return Ok((offset, limit - offset));
    }
    Err(Error::InvalidImage)
}

/// Read a fixed-size value at an RVA, confined to one section's raw data.
fn read_array<const N: usize>(
    bytes: &[u8],
    sections: &[SectionRange],
    rva: u32,
) -> Result<[u8; N]> {
    let (offset, available) = resolve(bytes, sections, rva)?;
    if available < N {
        return Err(Error::InvalidImage);
    }
    let end = offset.checked_add(N).ok_or(Error::InvalidImage)?;
    let source = bytes.get(offset..end).ok_or(Error::InvalidImage)?;
    <[u8; N]>::try_from(source).map_err(|_| Error::InvalidImage)
}

/// Read a NUL-terminated printable ASCII name of at most `MAX_NAME_LEN` bytes.
///
/// The terminator must appear inside the containing section's raw data.
fn read_name<'a>(bytes: &'a [u8], sections: &[SectionRange], rva: u32) -> Result<&'a str> {
    let (offset, available) = resolve(bytes, sections, rva)?;
    // Scan at most one byte past the maximum so an over-long name is detected.
    let window_len = available.min(MAX_NAME_LEN + 1);
    let end = offset.checked_add(window_len).ok_or(Error::InvalidImage)?;
    let window = bytes.get(offset..end).ok_or(Error::InvalidImage)?;
    let nul = window
        .iter()
        .position(|&b| b == 0)
        .ok_or(Error::InvalidName)?;
    if nul == 0 {
        return Err(Error::InvalidName);
    }
    let text = window.get(..nul).ok_or(Error::InvalidName)?;
    if !text.iter().all(|&b| (0x20..=0x7e).contains(&b)) {
        return Err(Error::InvalidName);
    }
    core::str::from_utf8(text).map_err(|_| Error::InvalidName)
}

fn rva_add(base: u32, delta: usize) -> Result<u32> {
    let delta = u32::try_from(delta).map_err(|_| Error::InvalidImage)?;
    base.checked_add(delta).ok_or(Error::InvalidImage)
}

fn le_u32(bytes: &[u8; DESCRIPTOR_SIZE], offset: usize) -> u32 {
    let mut value = [0u8; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMALL: SectionRange = SectionRange {
        virtual_address: 0x2000,
        raw_offset: 0x200,
        raw_size: 0x400,
    };

    const BIG: SectionRange = SectionRange {
        virtual_address: 0x1000,
        raw_offset: 0,
        raw_size: 0xb000,
    };

    /// Write `data` at `rva`, which must lie inside `section`.
    fn put(img: &mut [u8], section: SectionRange, rva: u32, data: &[u8]) {
        let at = (rva - section.virtual_address) as usize + section.raw_offset;
        img[at..at + data.len()].copy_from_slice(data);
    }

    fn put_u32(img: &mut [u8], section: SectionRange, rva: u32, value: u32) {
        put(img, section, rva, &value.to_le_bytes());
    }

    fn put_u64(img: &mut [u8], section: SectionRange, rva: u32, value: u64) {
        put(img, section, rva, &value.to_le_bytes());
    }

    fn descriptor(original_first_thunk: u32, name: u32, first_thunk: u32) -> [u8; 20] {
        let mut d = [0u8; 20];
        d[0..4].copy_from_slice(&original_first_thunk.to_le_bytes());
        d[12..16].copy_from_slice(&name.to_le_bytes());
        d[16..20].copy_from_slice(&first_thunk.to_le_bytes());
        d
    }

    #[test]
    fn parses_named_and_ordinal_imports() {
        let mut img = [0u8; 0x600];
        put(&mut img, SMALL, 0x2000, &descriptor(0x2100, 0x2300, 0x2180));
        put(&mut img, SMALL, 0x2014, &descriptor(0x2140, 0x2320, 0x21c0));
        put_u64(&mut img, SMALL, 0x2100, 0x2200);
        put_u64(&mut img, SMALL, 0x2108, 0x2220);
        put_u64(&mut img, SMALL, 0x2140, (1 << 63) | 7);
        put_u64(&mut img, SMALL, 0x2148, 0x2240);
        put_u32(&mut img, SMALL, 0x2200, 0x10);
        put(&mut img, SMALL, 0x2202, b"CreateFileW\0");
        put(&mut img, SMALL, 0x2220, b"\0\0ExitProcess\0");
        put_u32(&mut img, SMALL, 0x2240, 3);
        put(&mut img, SMALL, 0x2242, b"MessageBoxW\0");
        put(&mut img, SMALL, 0x2300, b"KERNEL32.dll\0");
        put(&mut img, SMALL, 0x2320, b"USER32.dll\0");

        let mut modules = ImportDirectory::new(&img, &[SMALL], 0x2000, 60).modules();

        let kernel = modules.next().unwrap().unwrap();
        assert_eq!(kernel.name, "KERNEL32.dll");
        assert_eq!(kernel.lookup_rva, 0x2100);
        assert_eq!(kernel.iat_rva, 0x2180);
        let mut thunks = kernel.thunks();
        assert_eq!(
            thunks.next().unwrap().unwrap(),
            Import::Name(ImportByName {
                hint: 0x10,
                name: "CreateFileW"
            })
        );
        assert_eq!(
            thunks.next().unwrap().unwrap(),
            Import::Name(ImportByName {
                hint: 0,
                name: "ExitProcess"
            })
        );
        assert_eq!(thunks.next(), None);

        let user = modules.next().unwrap().unwrap();
        assert_eq!(user.name, "USER32.dll");
        assert_eq!(user.lookup_rva, 0x2140);
        assert_eq!(user.iat_rva, 0x21c0);
        let mut thunks = user.thunks();
        assert_eq!(thunks.next().unwrap().unwrap(), Import::Ordinal(7));
        assert_eq!(
            thunks.next().unwrap().unwrap(),
            Import::Name(ImportByName {
                hint: 3,
                name: "MessageBoxW"
            })
        );
        assert_eq!(thunks.next(), None);

        assert_eq!(modules.next(), None);
    }

    #[test]
    fn falls_back_to_first_thunk_when_original_is_zero() {
        let mut img = [0u8; 0x600];
        put(&mut img, SMALL, 0x2000, &descriptor(0, 0x2300, 0x2100));
        put(&mut img, SMALL, 0x2300, b"ntdll.dll\0");
        let module = ImportDirectory::new(&img, &[SMALL], 0x2000, 40)
            .modules()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(module.lookup_rva, 0x2100);
        assert_eq!(module.iat_rva, 0x2100);
    }

    #[test]
    fn ordinal_thunk_uses_low_sixteen_bits() {
        let mut img = [0u8; 0x600];
        put(&mut img, SMALL, 0x2000, &descriptor(0x2100, 0x2300, 0x2100));
        put(&mut img, SMALL, 0x2300, b"a.dll\0");
        put_u64(&mut img, SMALL, 0x2100, (1 << 63) | 0xffff);
        let module = ImportDirectory::new(&img, &[SMALL], 0x2000, 40)
            .modules()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(
            module.thunks().next().unwrap().unwrap(),
            Import::Ordinal(0xffff)
        );
    }

    #[test]
    fn rejects_empty_dll_name() {
        let mut img = [0u8; 0x600];
        put(&mut img, SMALL, 0x2000, &descriptor(0x2100, 0x2300, 0x2100));
        put(&mut img, SMALL, 0x2300, b"\0");
        let mut modules = ImportDirectory::new(&img, &[SMALL], 0x2000, 40).modules();
        assert_eq!(modules.next(), Some(Err(Error::InvalidName)));
        assert_eq!(modules.next(), None);
    }

    #[test]
    fn rejects_name_not_terminated_within_section() {
        let mut img = [0u8; 0x600];
        put(&mut img, SMALL, 0x2000, &descriptor(0x2100, 0x23fa, 0x2100));
        // Six bytes fill the section to its last byte; no NUL follows.
        put(&mut img, SMALL, 0x23fa, b"KERNEL");
        let mut modules = ImportDirectory::new(&img, &[SMALL], 0x2000, 40).modules();
        assert_eq!(modules.next(), Some(Err(Error::InvalidName)));
    }

    #[test]
    fn name_length_is_bounded_at_255() {
        let mut img = [0u8; 0x600];
        put(&mut img, SMALL, 0x2000, &descriptor(0x2100, 0x2300, 0x2100));
        let mut name = [b'A'; 256];
        name[255] = 0;
        put(&mut img, SMALL, 0x2300, &name);
        let module = ImportDirectory::new(&img, &[SMALL], 0x2000, 40)
            .modules()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(module.name.len(), 255);

        // 256 printable bytes with no terminator inside the section.
        let mut img = [0u8; 0x600];
        put(&mut img, SMALL, 0x2000, &descriptor(0x2100, 0x2200, 0x2100));
        put(&mut img, SMALL, 0x2200, &[b'A'; 256]);
        let mut modules = ImportDirectory::new(&img, &[SMALL], 0x2000, 40).modules();
        assert_eq!(modules.next(), Some(Err(Error::InvalidName)));
    }

    #[test]
    fn rejects_non_printable_names() {
        let mut img = [0u8; 0x600];
        put(&mut img, SMALL, 0x2000, &descriptor(0x2100, 0x2300, 0x2100));
        put(&mut img, SMALL, 0x2300, b"bad\x01name\0");
        let mut modules = ImportDirectory::new(&img, &[SMALL], 0x2000, 40).modules();
        assert_eq!(modules.next(), Some(Err(Error::InvalidName)));

        let mut img = [0u8; 0x600];
        put(&mut img, SMALL, 0x2000, &descriptor(0x2100, 0x2300, 0x2100));
        put(&mut img, SMALL, 0x2300, b"caf\xc3\xa9\0");
        let mut modules = ImportDirectory::new(&img, &[SMALL], 0x2000, 40).modules();
        assert_eq!(modules.next(), Some(Err(Error::InvalidName)));
    }

    #[test]
    fn rejects_rvas_outside_every_section() {
        let mut img = [0u8; 0x600];
        put(&mut img, SMALL, 0x2000, &descriptor(0x2100, 0x9000, 0x2100));
        let mut modules = ImportDirectory::new(&img, &[SMALL], 0x2000, 40).modules();
        assert_eq!(modules.next(), Some(Err(Error::InvalidImage)));

        // A lookup table outside every section fails when its thunks are read.
        let mut img = [0u8; 0x600];
        put(&mut img, SMALL, 0x2000, &descriptor(0x1000, 0x2300, 0x1000));
        put(&mut img, SMALL, 0x2300, b"a.dll\0");
        let module = ImportDirectory::new(&img, &[SMALL], 0x2000, 40)
            .modules()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(module.thunks().next(), Some(Err(Error::InvalidImage)));
    }

    #[test]
    fn rejects_descriptor_table_without_terminator_in_directory() {
        let mut img = [0u8; 0x600];
        put(&mut img, SMALL, 0x2000, &descriptor(0x2100, 0x2300, 0x2100));
        put(&mut img, SMALL, 0x2300, b"a.dll\0");
        // The directory covers one descriptor, so the terminator is outside it.
        let mut modules = ImportDirectory::new(&img, &[SMALL], 0x2000, 20).modules();
        assert!(modules.next().unwrap().is_ok());
        assert_eq!(modules.next(), Some(Err(Error::InvalidImage)));
        assert_eq!(modules.next(), None);
    }

    #[test]
    fn rejects_descriptor_table_running_past_its_section() {
        let mut img = [0u8; 0x600];
        // Only 16 bytes of the table remain in the section.
        put(&mut img, SMALL, 0x23f0, &[0u8; 16]);
        let mut modules = ImportDirectory::new(&img, &[SMALL], 0x23f0, 0x100).modules();
        assert_eq!(modules.next(), Some(Err(Error::InvalidImage)));
    }

    #[test]
    fn rejects_thunk_table_running_past_its_section() {
        let mut img = [0u8; 0x600];
        put(&mut img, SMALL, 0x2000, &descriptor(0x23f8, 0x2300, 0x23f8));
        put(&mut img, SMALL, 0x2300, b"a.dll\0");
        // The first thunk names an entry at 0x2300; the next thunk is past the section.
        put_u64(&mut img, SMALL, 0x23f8, 0x2310);
        put(&mut img, SMALL, 0x2310, b"\0\0f\0");
        let module = ImportDirectory::new(&img, &[SMALL], 0x2000, 40)
            .modules()
            .next()
            .unwrap()
            .unwrap();
        let mut thunks = module.thunks();
        assert!(thunks.next().unwrap().is_ok());
        assert_eq!(thunks.next(), Some(Err(Error::InvalidImage)));
        assert_eq!(thunks.next(), None);
    }

    /// A BIG-section image holding `count` identical descriptors, then zero.
    fn module_image(count: usize) -> [u8; 0xb000] {
        let mut img = [0u8; 0xb000];
        for index in 0..count {
            let entry = descriptor(0x2f80, 0x2f00, 0x2f80);
            put(&mut img, BIG, 0x1000 + (index * 20) as u32, &entry);
        }
        put(&mut img, BIG, 0x2f00, b"a.dll\0");
        img
    }

    #[test]
    fn caps_module_count_at_max_import_modules() {
        // MAX_IMPORT_MODULES descriptors, then the zero terminator.
        let img = module_image(MAX_IMPORT_MODULES);
        let size = ((MAX_IMPORT_MODULES + 1) * 20) as u32;
        let mut modules = ImportDirectory::new(&img, &[BIG], 0x1000, size).modules();
        for _ in 0..MAX_IMPORT_MODULES {
            assert!(modules.next().unwrap().is_ok());
        }
        assert_eq!(modules.next(), None);

        // One more non-zero descriptor after the cap is refused.
        let img = module_image(MAX_IMPORT_MODULES + 1);
        let size = ((MAX_IMPORT_MODULES + 2) * 20) as u32;
        let mut modules = ImportDirectory::new(&img, &[BIG], 0x1000, size).modules();
        for _ in 0..MAX_IMPORT_MODULES {
            assert!(modules.next().unwrap().is_ok());
        }
        assert_eq!(modules.next(), Some(Err(Error::TableFull)));
        assert_eq!(modules.next(), None);
    }

    /// A BIG-section image whose one module has `count` ordinal thunks, then zero.
    fn thunk_image(count: usize) -> [u8; 0xb000] {
        let mut img = [0u8; 0xb000];
        put(&mut img, BIG, 0x1000, &descriptor(0x2000, 0x1100, 0x2000));
        put(&mut img, BIG, 0x1100, b"a.dll\0");
        for index in 0..count {
            put_u64(&mut img, BIG, 0x2000 + (index * 8) as u32, (1 << 63) | 1);
        }
        img
    }

    #[test]
    fn caps_thunk_count_at_max_import_thunks() {
        // MAX_IMPORT_THUNKS thunks, then the zero terminator.
        let img = thunk_image(MAX_IMPORT_THUNKS);
        let module = ImportDirectory::new(&img, &[BIG], 0x1000, 40)
            .modules()
            .next()
            .unwrap()
            .unwrap();
        let mut thunks = module.thunks();
        for _ in 0..MAX_IMPORT_THUNKS {
            assert_eq!(thunks.next().unwrap().unwrap(), Import::Ordinal(1));
        }
        assert_eq!(thunks.next(), None);

        // One more non-zero thunk after the cap is refused.
        let img = thunk_image(MAX_IMPORT_THUNKS + 1);
        let module = ImportDirectory::new(&img, &[BIG], 0x1000, 40)
            .modules()
            .next()
            .unwrap()
            .unwrap();
        let mut thunks = module.thunks();
        for _ in 0..MAX_IMPORT_THUNKS {
            assert!(thunks.next().unwrap().is_ok());
        }
        assert_eq!(thunks.next(), Some(Err(Error::TableFull)));
        assert_eq!(thunks.next(), None);
    }

    #[test]
    fn zero_rva_describes_an_image_without_imports() {
        let img = [0u8; 0x600];
        assert_eq!(
            ImportDirectory::new(&img, &[SMALL], 0, 0).modules().next(),
            None
        );
    }
}
