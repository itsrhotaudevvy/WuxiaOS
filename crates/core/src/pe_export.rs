//! Bounds-checked PE32+ export directory parsing.
//!
//! The export directory (`IMAGE_EXPORT_DIRECTORY`, 40 bytes) names the module
//! and gives an ordinal base. It points at three parallel tables: one RVA per
//! function, one name RVA per named export, and one function index per name.
//! The name table must be strictly ascending, which makes lookup by name a
//! binary search.
//!
//! Every table is confined to one section's raw data, and the whole name table
//! is validated when the directory is parsed. An export whose RVA lies inside
//! the export directory itself is a forwarder: its string is validated and
//! returned, but the forwarded module is never loaded or resolved here. Other
//! function RVAs are returned as declared, without checking that they fall
//! inside a section.

use crate::error::{Error, Result};
use crate::pe_import::{MAX_NAME_LEN, SectionRange};
use crate::pe_reloc;
use core::cmp::Ordering;

/// Index of the export data directory (`IMAGE_DIRECTORY_ENTRY_EXPORT`).
pub const EXPORT_DIRECTORY_INDEX: usize = 0;

/// Size in bytes of `IMAGE_EXPORT_DIRECTORY`.
pub const EXPORT_DIRECTORY_SIZE: usize = 40;

/// Maximum number of function entries, and of named exports, accepted.
pub const MAX_EXPORTS: u32 = 65536;

/// Maximum length in bytes of a forwarder string, excluding its NUL.
pub const MAX_FORWARDER_LEN: usize = 2 * MAX_NAME_LEN + 1;

/// Exclusive upper bound for biased ordinals, which are 16-bit values.
const ORDINAL_LIMIT: u32 = 0x1_0000;

/// Longest decimal ordinal accepted in a `DLL.#n` forwarder.
const MAX_FORWARDER_ORDINAL_DIGITS: usize = 5;

/// Where an export points.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Export<'a> {
    /// The function's RVA, outside the export directory.
    Rva(u32),
    /// A forwarder such as `"NTDLL.RtlAllocateHeap"` or `"KERNEL32.#123"`.
    Forwarder(&'a str),
}

/// One named export, as yielded by [`ExportDirectory::named_exports`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamedExport<'a> {
    /// Export name, printable ASCII and at most `MAX_NAME_LEN` bytes.
    pub name: &'a str,
    /// Biased ordinal: the function index plus the directory's `base`.
    pub ordinal: u32,
    /// Where the export points.
    pub export: Export<'a>,
}

/// A validated export directory and its tables.
#[derive(Clone, Copy, Debug)]
pub struct ExportDirectory<'a> {
    bytes: &'a [u8],
    sections: &'a [SectionRange],
    dir_rva: u32,
    dir_size: u32,
    /// DLL name, printable ASCII and at most `MAX_NAME_LEN` bytes. Empty when
    /// the image has no export directory.
    pub name: &'a str,
    /// Ordinal assigned to the first function table entry.
    pub base: u32,
    /// Entries in the function table.
    pub number_of_functions: u32,
    /// Entries in the name table. Each names one function table entry.
    pub number_of_names: u32,
    functions: &'a [u8],
    names: &'a [u8],
    ordinals: &'a [u8],
}

/// Iterator over the named exports, in name-table (ascending name) order.
///
/// After the first error the iterator yields `None`, so a broken forwarder
/// produces one error and then stops.
#[derive(Clone, Copy, Debug)]
pub struct NamedExports<'a> {
    directory: ExportDirectory<'a>,
    index: usize,
    done: bool,
}

impl<'a> ExportDirectory<'a> {
    /// Parse the export directory at `rva` spanning `size` bytes.
    ///
    /// An `rva` of zero describes an image without exports and yields an
    /// empty directory. Otherwise the 40-byte header, the DLL name, all three
    /// tables and every name are validated before the directory is returned.
    ///
    /// Errors: `InvalidImage` for a header or table outside one section's raw
    /// data, a `size` below 40, a name table that is not strictly ascending,
    /// a name ordinal outside the function table, more names than functions,
    /// or a biased ordinal range past 16 bits. `InvalidName` for a DLL name or
    /// export name that is empty, non-printable or over-long. `TableFull` when
    /// either count exceeds `MAX_EXPORTS`.
    pub fn parse(
        bytes: &'a [u8],
        sections: &'a [SectionRange],
        rva: u32,
        size: u32,
    ) -> Result<Self> {
        if rva == 0 {
            return Ok(Self {
                bytes,
                sections,
                dir_rva: 0,
                dir_size: 0,
                name: "",
                base: 0,
                number_of_functions: 0,
                number_of_names: 0,
                functions: &[],
                names: &[],
                ordinals: &[],
            });
        }
        if (size as usize) < EXPORT_DIRECTORY_SIZE {
            return Err(Error::InvalidImage);
        }
        let raw: [u8; EXPORT_DIRECTORY_SIZE] = read_array(bytes, sections, rva)?;
        // Layout: Characteristics, TimeDateStamp, Version (4 bytes), Name, Base,
        // NumberOfFunctions, NumberOfNames, AddressOfFunctions, AddressOfNames,
        // AddressOfNameOrdinals.
        let name_rva = header_u32(&raw, 12);
        let base = header_u32(&raw, 16);
        let number_of_functions = header_u32(&raw, 20);
        let number_of_names = header_u32(&raw, 24);
        let functions_rva = header_u32(&raw, 28);
        let names_rva = header_u32(&raw, 32);
        let ordinals_rva = header_u32(&raw, 36);

        if number_of_functions > MAX_EXPORTS || number_of_names > MAX_EXPORTS {
            return Err(Error::TableFull);
        }
        if number_of_names > number_of_functions
            || u64::from(base) + u64::from(number_of_functions) > u64::from(ORDINAL_LIMIT)
        {
            return Err(Error::InvalidImage);
        }
        let name = read_name(bytes, sections, name_rva)?;
        let functions = table(bytes, sections, functions_rva, number_of_functions, 4)?;
        let names = table(bytes, sections, names_rva, number_of_names, 4)?;
        let ordinals = table(bytes, sections, ordinals_rva, number_of_names, 2)?;

        let directory = Self {
            bytes,
            sections,
            dir_rva: rva,
            dir_size: size,
            name,
            base,
            number_of_functions,
            number_of_names,
            functions,
            names,
            ordinals,
        };
        directory.check_names()?;
        Ok(directory)
    }

    /// Parse the directory from a PE32+ image's export data directory slot.
    ///
    /// Errors: those of `pe_reloc::data_directory` (including `NotFound` when
    /// the optional header declares no export slot), then those of [`parse`].
    ///
    /// [`parse`]: ExportDirectory::parse
    pub fn from_image(image: &'a [u8], sections: &'a [SectionRange]) -> Result<Self> {
        let slot = pe_reloc::data_directory(image, EXPORT_DIRECTORY_INDEX)?;
        Self::parse(image, sections, slot.rva, slot.size)
    }

    /// Find an export by exact, case-sensitive name.
    ///
    /// Binary search over the name table. Returns `NotFound` when no name
    /// matches, or when the matching function slot is empty (RVA zero).
    pub fn lookup_name(&self, name: &str) -> Result<Export<'a>> {
        let needle = name.as_bytes();
        let mut low = 0usize;
        let mut high = self.name_count();
        while low < high {
            let mid = low + (high - low) / 2;
            match self.name_at(mid)?.as_bytes().cmp(needle) {
                Ordering::Less => low = mid + 1,
                Ordering::Greater => high = mid,
                Ordering::Equal => return self.export_at(self.ordinal_index(mid)?),
            }
        }
        Err(Error::NotFound)
    }

    /// Find an export by biased ordinal, which is `base` plus its function index.
    ///
    /// Returns `NotFound` for an ordinal below `base`, one past the function
    /// table, or one whose function slot is empty.
    pub fn lookup_ordinal(&self, ordinal: u32) -> Result<Export<'a>> {
        let index = ordinal.checked_sub(self.base).ok_or(Error::NotFound)?;
        if index >= self.number_of_functions {
            return Err(Error::NotFound);
        }
        self.export_at(index as usize)
    }

    /// Iterate the named exports in ascending name order.
    ///
    /// Ordinal-only exports, which have no name, are reached through
    /// [`lookup_ordinal`](Self::lookup_ordinal) instead.
    pub fn named_exports(&self) -> NamedExports<'a> {
        NamedExports {
            directory: *self,
            index: 0,
            done: false,
        }
    }

    fn name_count(&self) -> usize {
        self.number_of_names as usize
    }

    fn function_count(&self) -> usize {
        self.number_of_functions as usize
    }

    /// Validate the name table: each name is well formed, names are strictly
    /// ascending, and each name's ordinal index is a function table entry.
    fn check_names(&self) -> Result<()> {
        let mut previous: Option<&'a str> = None;
        for index in 0..self.name_count() {
            let current = self.name_at(index)?;
            if previous.is_some_and(|prev| current.as_bytes() <= prev.as_bytes()) {
                return Err(Error::InvalidImage);
            }
            if self.ordinal_index(index)? >= self.function_count() {
                return Err(Error::InvalidImage);
            }
            previous = Some(current);
        }
        Ok(())
    }

    fn name_at(&self, index: usize) -> Result<&'a str> {
        read_name(self.bytes, self.sections, u32_at(self.names, index)?)
    }

    fn ordinal_index(&self, index: usize) -> Result<usize> {
        Ok(usize::from(u16_at(self.ordinals, index)?))
    }

    fn export_at(&self, index: usize) -> Result<Export<'a>> {
        let rva = u32_at(self.functions, index)?;
        if rva == 0 {
            return Err(Error::NotFound);
        }
        if self.in_directory(rva) {
            return Ok(Export::Forwarder(self.forwarder(rva)?));
        }
        Ok(Export::Rva(rva))
    }

    fn in_directory(&self, rva: u32) -> bool {
        let end = u64::from(self.dir_rva) + u64::from(self.dir_size);
        rva >= self.dir_rva && u64::from(rva) < end
    }

    /// Read and validate the forwarder string at `rva`.
    ///
    /// The string must be NUL-terminated inside both its section and the
    /// export directory, so a forwarder cannot run into data outside it.
    fn forwarder(&self, rva: u32) -> Result<&'a str> {
        let bytes: &'a [u8] = self.bytes;
        let (offset, available) = resolve(bytes, self.sections, rva)?;
        let end = u64::from(self.dir_rva) + u64::from(self.dir_size);
        let room = usize::try_from(end - u64::from(rva)).map_err(|_| Error::InvalidImage)?;
        let window_len = available.min(MAX_FORWARDER_LEN + 1).min(room);
        let window = slice_at(bytes, offset, window_len)?;
        let nul = window
            .iter()
            .position(|&b| b == 0)
            .ok_or(Error::InvalidName)?;
        let text = window.get(..nul).ok_or(Error::InvalidName)?;
        check_forwarder(text)?;
        core::str::from_utf8(text).map_err(|_| Error::InvalidName)
    }
}

impl<'a> NamedExports<'a> {
    fn read_next(&mut self) -> Result<Option<NamedExport<'a>>> {
        if self.index >= self.directory.name_count() {
            return Ok(None);
        }
        let index = self.index;
        let name = self.directory.name_at(index)?;
        let function = self.directory.ordinal_index(index)?;
        let ordinal = self
            .directory
            .base
            .checked_add(u32::try_from(function).map_err(|_| Error::InvalidImage)?)
            .ok_or(Error::InvalidImage)?;
        let export = self.directory.export_at(function)?;
        self.index += 1;
        Ok(Some(NamedExport {
            name,
            ordinal,
            export,
        }))
    }
}

impl<'a> Iterator for NamedExports<'a> {
    type Item = Result<NamedExport<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.read_next() {
            Ok(Some(export)) => Some(Ok(export)),
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

/// Check a forwarder: `MODULE.SYMBOL` or `MODULE.#ORDINAL`.
///
/// The split is at the last dot, because module names may contain dots while
/// symbol names do not. The module must be non-empty, at most `MAX_NAME_LEN`
/// bytes and free of `#`. The symbol must be a name of the same bound, or
/// `#` followed by a decimal ordinal below 65536.
fn check_forwarder(text: &[u8]) -> Result<()> {
    if !text.iter().all(|&b| is_printable(b)) {
        return Err(Error::InvalidName);
    }
    let dot = text
        .iter()
        .rposition(|&b| b == b'.')
        .ok_or(Error::InvalidName)?;
    let module = text.get(..dot).ok_or(Error::InvalidName)?;
    let symbol = text.get(dot + 1..).ok_or(Error::InvalidName)?;
    if module.is_empty() || module.len() > MAX_NAME_LEN || module.contains(&b'#') {
        return Err(Error::InvalidName);
    }
    match symbol.split_first() {
        Some((&b'#', digits)) => check_forwarder_ordinal(digits),
        _ if symbol.is_empty() || symbol.len() > MAX_NAME_LEN => Err(Error::InvalidName),
        _ => Ok(()),
    }
}

fn check_forwarder_ordinal(digits: &[u8]) -> Result<()> {
    if digits.is_empty() || digits.len() > MAX_FORWARDER_ORDINAL_DIGITS {
        return Err(Error::InvalidName);
    }
    let mut value = 0u32;
    for &digit in digits {
        if !digit.is_ascii_digit() {
            return Err(Error::InvalidName);
        }
        value = value * 10 + u32::from(digit - b'0');
    }
    if value >= ORDINAL_LIMIT {
        return Err(Error::InvalidName);
    }
    Ok(())
}

fn is_printable(byte: u8) -> bool {
    (0x20..=0x7e).contains(&byte)
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
    let source = slice_at(bytes, offset, N)?;
    <[u8; N]>::try_from(source).map_err(|_| Error::InvalidImage)
}

/// Resolve a table of `count` entries of `entry` bytes each.
///
/// A zero count yields an empty table without touching `rva`. Otherwise the
/// whole table must lie inside one section's raw data.
fn table<'a>(
    bytes: &'a [u8],
    sections: &[SectionRange],
    rva: u32,
    count: u32,
    entry: usize,
) -> Result<&'a [u8]> {
    if count == 0 {
        return Ok(&[]);
    }
    let len = (count as usize)
        .checked_mul(entry)
        .ok_or(Error::InvalidImage)?;
    let (offset, available) = resolve(bytes, sections, rva)?;
    if available < len {
        return Err(Error::InvalidImage);
    }
    slice_at(bytes, offset, len)
}

/// Read a NUL-terminated printable ASCII name of at most `MAX_NAME_LEN` bytes.
///
/// The terminator must appear inside the containing section's raw data.
fn read_name<'a>(bytes: &'a [u8], sections: &[SectionRange], rva: u32) -> Result<&'a str> {
    let (offset, available) = resolve(bytes, sections, rva)?;
    // Scan at most one byte past the maximum so an over-long name is detected.
    let window = slice_at(bytes, offset, available.min(MAX_NAME_LEN + 1))?;
    let nul = window
        .iter()
        .position(|&b| b == 0)
        .ok_or(Error::InvalidName)?;
    if nul == 0 {
        return Err(Error::InvalidName);
    }
    let text = window.get(..nul).ok_or(Error::InvalidName)?;
    if !text.iter().all(|&b| is_printable(b)) {
        return Err(Error::InvalidName);
    }
    core::str::from_utf8(text).map_err(|_| Error::InvalidName)
}

fn slice_at(bytes: &[u8], offset: usize, len: usize) -> Result<&[u8]> {
    let end = offset.checked_add(len).ok_or(Error::InvalidImage)?;
    bytes.get(offset..end).ok_or(Error::InvalidImage)
}

fn le_at<const N: usize>(table: &[u8], index: usize) -> Result<[u8; N]> {
    let offset = index.checked_mul(N).ok_or(Error::InvalidImage)?;
    let raw = slice_at(table, offset, N)?;
    <[u8; N]>::try_from(raw).map_err(|_| Error::InvalidImage)
}

fn u32_at(table: &[u8], index: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(le_at(table, index)?))
}

fn u16_at(table: &[u8], index: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(le_at(table, index)?))
}

fn header_u32(raw: &[u8; EXPORT_DIRECTORY_SIZE], offset: usize) -> u32 {
    let mut value = [0u8; 4];
    value.copy_from_slice(&raw[offset..offset + 4]);
    u32::from_le_bytes(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMAGE_LEN: usize = 0x800;
    /// Section RVA 0x1000..0x1600, backed by image bytes 0x200..0x800.
    const SECTION: SectionRange = SectionRange {
        virtual_address: 0x1000,
        raw_offset: 0x200,
        raw_size: 0x600,
    };
    const SECTIONS: &[SectionRange] = &[SECTION];
    const DIR: u32 = 0x1000;
    const DIR_SIZE: u32 = 0x100;
    const DLL_RVA: u32 = 0x1040;
    const FUNCS: u32 = 0x1200;
    const NAMES: u32 = 0x1240;
    const ORDS: u32 = 0x1280;
    const STRINGS: u32 = 0x1300;

    fn put(img: &mut [u8], rva: u32, data: &[u8]) {
        let at = (rva - SECTION.virtual_address) as usize + SECTION.raw_offset;
        img[at..at + data.len()].copy_from_slice(data);
    }

    /// Write `text` followed by a NUL terminator.
    fn put_str(img: &mut [u8], rva: u32, text: &str) {
        put(img, rva, text.as_bytes());
        put(img, rva + text.len() as u32, &[0]);
    }

    fn put_u32(img: &mut [u8], rva: u32, value: u32) {
        put(img, rva, &value.to_le_bytes());
    }

    fn put_u16(img: &mut [u8], rva: u32, value: u16) {
        put(img, rva, &value.to_le_bytes());
    }

    /// Minimal PE32+ headers whose export slot points at the directory.
    fn pe_header(img: &mut [u8]) {
        img[0..2].copy_from_slice(b"MZ");
        img[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        img[0x80..0x84].copy_from_slice(b"PE\0\0");
        img[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
        img[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        img[0x98 + 108..0x98 + 112].copy_from_slice(&16u32.to_le_bytes());
        img[0x98 + 112..0x98 + 116].copy_from_slice(&DIR.to_le_bytes());
        img[0x98 + 116..0x98 + 120].copy_from_slice(&DIR_SIZE.to_le_bytes());
    }

    /// Build a directory with the given function RVAs and `(name, function index)`
    /// pairs. Names are written in the order given, so callers control sorting.
    fn build(dll: &str, base: u32, functions: &[u32], names: &[(&str, u16)]) -> [u8; IMAGE_LEN] {
        let mut img = [0u8; IMAGE_LEN];
        pe_header(&mut img);
        put_str(&mut img, DLL_RVA, dll);
        for (i, &rva) in functions.iter().enumerate() {
            put_u32(&mut img, FUNCS + 4 * i as u32, rva);
        }
        let mut cursor = STRINGS;
        for (i, &(name, ordinal)) in names.iter().enumerate() {
            put_str(&mut img, cursor, name);
            put_u32(&mut img, NAMES + 4 * i as u32, cursor);
            put_u16(&mut img, ORDS + 2 * i as u32, ordinal);
            cursor += name.len() as u32 + 1;
        }
        put_u32(&mut img, DIR + 12, DLL_RVA);
        put_u32(&mut img, DIR + 16, base);
        put_u32(&mut img, DIR + 20, functions.len() as u32);
        put_u32(&mut img, DIR + 24, names.len() as u32);
        put_u32(&mut img, DIR + 28, FUNCS);
        put_u32(&mut img, DIR + 32, NAMES);
        put_u32(&mut img, DIR + 36, ORDS);
        img
    }

    fn parse(img: &[u8]) -> Result<ExportDirectory<'_>> {
        ExportDirectory::parse(img, SECTIONS, DIR, DIR_SIZE)
    }

    fn lookup<'a>(img: &'a [u8], name: &str) -> Result<Export<'a>> {
        parse(img)?.lookup_name(name)
    }

    #[test]
    fn parses_and_resolves_named_exports() {
        let img = build(
            "KERNEL32.dll",
            1,
            &[0x2000, 0x2010, 0x2020],
            &[("CreateFileW", 0), ("ExitProcess", 2), ("Sleep", 1)],
        );
        let dir = parse(&img).unwrap();
        assert_eq!(dir.name, "KERNEL32.dll");
        assert_eq!(
            (dir.base, dir.number_of_functions, dir.number_of_names),
            (1, 3, 3)
        );
        assert_eq!(dir.lookup_name("CreateFileW"), Ok(Export::Rva(0x2000)));
        assert_eq!(dir.lookup_name("ExitProcess"), Ok(Export::Rva(0x2020)));
        assert_eq!(dir.lookup_name("Sleep"), Ok(Export::Rva(0x2010)));
        for missing in ["CreateFile", "Aardvark", "Zzz", "sleep"] {
            assert_eq!(dir.lookup_name(missing), Err(Error::NotFound), "{missing}");
        }
    }

    #[test]
    fn lookup_ordinal_applies_the_base() {
        let img = build(
            "KERNEL32.dll",
            1,
            &[0x2000, 0x2010, 0x2020],
            &[("Sleep", 1)],
        );
        let dir = parse(&img).unwrap();
        assert_eq!(dir.lookup_ordinal(1), Ok(Export::Rva(0x2000)));
        assert_eq!(dir.lookup_ordinal(3), Ok(Export::Rva(0x2020)));
        // Ordinal 0 lies below the base; ordinal 4 lies past the table.
        assert_eq!(dir.lookup_ordinal(0), Err(Error::NotFound));
        assert_eq!(dir.lookup_ordinal(4), Err(Error::NotFound));
    }

    #[test]
    fn ordinal_out_of_range_is_not_found() {
        let img = build("A.dll", 16, &[0x2000, 0x2010], &[("Sym", 0)]);
        let dir = parse(&img).unwrap();
        assert_eq!(dir.lookup_ordinal(15), Err(Error::NotFound));
        assert_eq!(dir.lookup_ordinal(16), Ok(Export::Rva(0x2000)));
        assert_eq!(dir.lookup_ordinal(17), Ok(Export::Rva(0x2010)));
        assert_eq!(dir.lookup_ordinal(18), Err(Error::NotFound));
        assert_eq!(dir.lookup_ordinal(u32::MAX), Err(Error::NotFound));
    }

    #[test]
    fn forwarders_by_name_and_ordinal_are_returned() {
        let mut img = build(
            "KERNEL32.dll",
            1,
            &[0x2000, 0x1060, 0x1080, 0x10a0],
            &[("Alloc", 1), ("Free", 2), ("Init", 0), ("Last", 3)],
        );
        put_str(&mut img, 0x1060, "NTDLL.RtlAllocateHeap");
        put_str(&mut img, 0x1080, "KERNEL32.#123");
        put_str(&mut img, 0x10a0, "A.#65535");
        assert_eq!(
            lookup(&img, "Alloc"),
            Ok(Export::Forwarder("NTDLL.RtlAllocateHeap"))
        );
        assert_eq!(lookup(&img, "Free"), Ok(Export::Forwarder("KERNEL32.#123")));
        assert_eq!(lookup(&img, "Init"), Ok(Export::Rva(0x2000)));
        assert_eq!(lookup(&img, "Last"), Ok(Export::Forwarder("A.#65535")));
        assert_eq!(
            parse(&img).unwrap().lookup_ordinal(2),
            Ok(Export::Forwarder("NTDLL.RtlAllocateHeap"))
        );
    }

    #[test]
    fn malformed_forwarder_strings_are_rejected() {
        let texts = [
            "",
            "NODOT",
            ".Sym",
            "DLL.",
            "DLL.#",
            "DLL.#x1",
            "DLL.#12a",
            "DLL.#65536",
            "DLL.#123456",
            "DL#L.Sym",
            "A.B.#",
            "DLL.Sym\x01",
        ];
        for text in texts {
            let mut img = build("KERNEL32.dll", 1, &[0x1060], &[("Fwd", 0)]);
            put_str(&mut img, 0x1060, text);
            assert_eq!(lookup(&img, "Fwd"), Err(Error::InvalidName), "{text:?}");
        }
    }

    #[test]
    fn forwarder_must_end_inside_the_directory() {
        // The NUL at 0x10ff lies inside the directory [0x1000, 0x1100).
        let mut img = build("KERNEL32.dll", 1, &[0x10fc], &[("Fwd", 0)]);
        put_str(&mut img, 0x10fc, "A.B");
        assert_eq!(lookup(&img, "Fwd"), Ok(Export::Forwarder("A.B")));

        // The NUL at 0x1100 lies in the section but one byte past the directory.
        let mut img = build("KERNEL32.dll", 1, &[0x10fd], &[("Fwd", 0)]);
        put_str(&mut img, 0x10fd, "A.B");
        assert_eq!(lookup(&img, "Fwd"), Err(Error::InvalidName));
    }

    #[test]
    fn unsorted_or_duplicate_names_are_rejected() {
        let img = build("A.dll", 1, &[0x2000, 0x2010], &[("Zeta", 0), ("Alpha", 1)]);
        assert_eq!(parse(&img).err(), Some(Error::InvalidImage));

        let img = build("A.dll", 1, &[0x2000, 0x2010], &[("Alpha", 0), ("Alpha", 1)]);
        assert_eq!(parse(&img).err(), Some(Error::InvalidImage));
    }

    #[test]
    fn name_ordinal_outside_the_function_table_is_rejected() {
        let img = build("A.dll", 1, &[0x2000], &[("Only", 1)]);
        assert_eq!(parse(&img).err(), Some(Error::InvalidImage));
    }

    #[test]
    fn truncated_function_table_is_rejected() {
        let mut img = build("A.dll", 1, &[0x2000], &[("Only", 0)]);
        // 0x200 entries need 0x800 bytes; the section has 0x400 left at 0x1200.
        put_u32(&mut img, DIR + 20, 0x200);
        assert_eq!(parse(&img).err(), Some(Error::InvalidImage));
    }

    #[test]
    fn truncated_name_tables_are_rejected() {
        let funcs = [0x2000, 0x2010];
        let names = [("A", 0), ("B", 1)];

        // Two name RVAs need 8 bytes; only 4 remain in the section.
        let mut img = build("A.dll", 1, &funcs, &names);
        put_u32(&mut img, DIR + 32, 0x15fc);
        assert_eq!(parse(&img).err(), Some(Error::InvalidImage));

        // Two ordinals need 4 bytes; only 1 remains in the section.
        let mut img = build("A.dll", 1, &funcs, &names);
        put_u32(&mut img, DIR + 36, 0x15ff);
        assert_eq!(parse(&img).err(), Some(Error::InvalidImage));
    }

    #[test]
    fn truncated_directory_header_is_rejected() {
        let img = build("A.dll", 1, &[0x2000], &[("Only", 0)]);
        // A 39-byte directory cannot hold the 40-byte header.
        assert_eq!(
            ExportDirectory::parse(&img, SECTIONS, DIR, 39).err(),
            Some(Error::InvalidImage)
        );
        // A header that starts 16 bytes before the section's end is cut short.
        assert_eq!(
            ExportDirectory::parse(&img, SECTIONS, 0x15f0, 40).err(),
            Some(Error::InvalidImage)
        );
        // A header outside every section does not resolve.
        assert_eq!(
            ExportDirectory::parse(&img, SECTIONS, 0x3000, 40).err(),
            Some(Error::InvalidImage)
        );
    }

    #[test]
    fn counts_are_capped_and_biased_ordinals_fit_sixteen_bits() {
        let mut img = build("A.dll", 0, &[0x2000], &[]);
        put_u32(&mut img, DIR + 20, MAX_EXPORTS + 1);
        assert_eq!(parse(&img).err(), Some(Error::TableFull));

        let img = build("A.dll", 0xffff, &[0x2000, 0x2010], &[]);
        assert_eq!(parse(&img).err(), Some(Error::InvalidImage));

        let img = build("A.dll", 0xfffe, &[0x2000, 0x2010], &[]);
        assert!(parse(&img).is_ok());
    }

    #[test]
    fn dll_name_is_validated() {
        let img = build("", 1, &[0x2000], &[]);
        assert_eq!(parse(&img).err(), Some(Error::InvalidName));

        let img = build("bad\x01name.dll", 1, &[0x2000], &[]);
        assert_eq!(parse(&img).err(), Some(Error::InvalidName));

        let long_bytes = [b'A'; 256];
        let long = core::str::from_utf8(&long_bytes).unwrap();
        let img = build(long, 1, &[0x2000], &[]);
        assert_eq!(parse(&img).err(), Some(Error::InvalidName));

        let img = build(&long[..255], 1, &[0x2000], &[]);
        assert_eq!(parse(&img).unwrap().name.len(), 255);

        let mut img = build("A.dll", 1, &[0x2000], &[]);
        put_u32(&mut img, DIR + 12, 0);
        assert_eq!(parse(&img).err(), Some(Error::InvalidImage));
    }

    #[test]
    fn more_names_than_functions_is_rejected() {
        let img = build("A.dll", 1, &[0x2000], &[("A", 0), ("B", 0)]);
        assert_eq!(parse(&img).err(), Some(Error::InvalidImage));
    }

    #[test]
    fn empty_directory_has_no_exports() {
        let img = [0u8; IMAGE_LEN];
        let dir = ExportDirectory::parse(&img, SECTIONS, 0, 0).unwrap();
        assert_eq!(dir.name, "");
        assert_eq!(dir.lookup_name("X"), Err(Error::NotFound));
        assert_eq!(dir.lookup_ordinal(0), Err(Error::NotFound));
        assert!(dir.named_exports().next().is_none());
    }

    #[test]
    fn zero_function_slot_is_not_an_export() {
        let img = build("A.dll", 1, &[0, 0x2010], &[("Hole", 0), ("Real", 1)]);
        let dir = parse(&img).unwrap();
        assert_eq!(dir.lookup_name("Hole"), Err(Error::NotFound));
        assert_eq!(dir.lookup_ordinal(1), Err(Error::NotFound));
        assert_eq!(dir.lookup_name("Real"), Ok(Export::Rva(0x2010)));
        assert_eq!(dir.lookup_ordinal(2), Ok(Export::Rva(0x2010)));
    }

    #[test]
    fn named_exports_iterator_yields_name_order() {
        let mut img = build(
            "KERNEL32.dll",
            1,
            &[0x2000, 0x1060],
            &[("Alloc", 1), ("Init", 0)],
        );
        put_str(&mut img, 0x1060, "NTDLL.RtlAllocateHeap");
        let mut exports = parse(&img).unwrap().named_exports();
        assert_eq!(
            exports.next(),
            Some(Ok(NamedExport {
                name: "Alloc",
                ordinal: 2,
                export: Export::Forwarder("NTDLL.RtlAllocateHeap"),
            }))
        );
        assert_eq!(
            exports.next(),
            Some(Ok(NamedExport {
                name: "Init",
                ordinal: 1,
                export: Export::Rva(0x2000),
            }))
        );
        assert_eq!(exports.next(), None);
        assert_eq!(exports.next(), None);
    }

    #[test]
    fn named_exports_iterator_stops_after_an_error() {
        let mut img = build(
            "KERNEL32.dll",
            1,
            &[0x2000, 0x1060],
            &[("Alloc", 1), ("Init", 0)],
        );
        put_str(&mut img, 0x1060, "NODOT");
        let mut exports = parse(&img).unwrap().named_exports();
        assert_eq!(exports.next(), Some(Err(Error::InvalidName)));
        assert_eq!(exports.next(), None);
    }

    #[test]
    fn binary_search_finds_every_name_and_no_others() {
        let names = [
            ("alpha", 0),
            ("bravo", 1),
            ("charlie", 2),
            ("delta", 3),
            ("echo", 4),
            ("foxtrot", 5),
            ("golf", 6),
        ];
        let funcs = [0x2000, 0x2010, 0x2020, 0x2030, 0x2040, 0x2050, 0x2060];
        let img = build("A.dll", 1, &funcs, &names);
        let dir = parse(&img).unwrap();
        for (i, (name, _)) in names.iter().enumerate() {
            assert_eq!(dir.lookup_name(name), Ok(Export::Rva(funcs[i])), "{name}");
        }
        for missing in ["", "aaa", "bravo2", "Alpha", "golf!", "zulu", "charli"] {
            assert_eq!(dir.lookup_name(missing), Err(Error::NotFound), "{missing}");
        }
    }

    #[test]
    fn from_image_reads_the_export_slot() {
        let img = build("KERNEL32.dll", 1, &[0x2000], &[("Sleep", 0)]);
        let dir = ExportDirectory::from_image(&img, SECTIONS).unwrap();
        assert_eq!(dir.name, "KERNEL32.dll");
        assert_eq!(dir.lookup_name("Sleep"), Ok(Export::Rva(0x2000)));
        assert_eq!(dir.lookup_ordinal(1), Ok(Export::Rva(0x2000)));

        let bare = [0u8; IMAGE_LEN];
        assert_eq!(
            ExportDirectory::from_image(&bare, SECTIONS).err(),
            Some(Error::InvalidImage)
        );
    }
}
