//! Bounds-checked ELF64 dynamic-section parsing and x86_64 RELA relocations.
//!
//! The dynamic section is a sequence of 16-byte `{d_tag, d_val}` records ended
//! by `DT_NULL`. Parsing reads only the tags a position-independent loader
//! needs and rejects the ones it cannot honour safely. Applying relocations
//! patches a caller-owned image buffer, and only after every entry has been
//! validated, so an error leaves the image unchanged.

use crate::error::{Error, Result};

/// Upper bound on dynamic records scanned, including the `DT_NULL` terminator.
pub const MAX_DYNAMIC_ENTRIES: usize = 256;

/// Size of one `Elf64_Dyn` record.
const DYNAMIC_ENTRY_SIZE: usize = 16;
const DYNAMIC_VALUE_OFFSET: usize = 8;

/// Size of one `Elf64_Rela` record.
pub const RELA_ENTRY_SIZE: usize = 24;

/// Terminates the dynamic section (`DT_NULL`).
pub const DT_NULL: i64 = 0;
/// Virtual address of the RELA table (`DT_RELA`).
pub const DT_RELA: i64 = 7;
/// Byte size of the RELA table (`DT_RELASZ`).
pub const DT_RELASZ: i64 = 8;
/// Size of one RELA record (`DT_RELAENT`), which must be [`RELA_ENTRY_SIZE`].
pub const DT_RELAENT: i64 = 9;
/// Declares text relocations (`DT_TEXTREL`), which are incompatible with W^X.
pub const DT_TEXTREL: i64 = 22;
/// Extended loader flags (`DT_FLAGS_1`).
pub const DT_FLAGS_1: i64 = 0x6fff_fffb;

/// No-op relocation (`R_X86_64_NONE`).
pub const R_X86_64_NONE: u32 = 0;
/// Symbol plus addend, 64-bit (`R_X86_64_64`).
pub const R_X86_64_64: u32 = 1;
/// Global offset table entry (`R_X86_64_GLOB_DAT`).
pub const R_X86_64_GLOB_DAT: u32 = 6;
/// PLT slot (`R_X86_64_JUMP_SLOT`).
pub const R_X86_64_JUMP_SLOT: u32 = 7;
/// Load bias plus addend (`R_X86_64_RELATIVE`).
pub const R_X86_64_RELATIVE: u32 = 8;

const RELA_ENTRY_SIZE_U64: u64 = RELA_ENTRY_SIZE as u64;
const SLOT_SIZE: u64 = 8;

/// Dynamic-section values a position-independent loader needs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DynamicInfo {
    /// Virtual address of the RELA table (`DT_RELA`), if the image has one.
    pub rela_address: Option<u64>,
    /// Byte length of the RELA table (`DT_RELASZ`); zero without `DT_RELA`.
    pub rela_size: u64,
    /// Value of `DT_FLAGS_1`; zero when absent.
    pub flags_1: u64,
}

/// One `Elf64_Rela` record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rela {
    /// Virtual address of the 64-bit slot to patch.
    pub offset: u64,
    /// Symbol index in the high 32 bits, relocation type in the low 32 bits.
    pub info: u64,
    /// Signed constant combined with the load bias.
    pub addend: i64,
}

impl Rela {
    /// Relocation type (low 32 bits of `r_info`).
    pub const fn kind(self) -> u32 {
        self.info as u32
    }

    /// Symbol table index (high 32 bits of `r_info`).
    pub const fn symbol(self) -> u32 {
        (self.info >> 32) as u32
    }
}

/// Iterator over a RELA table whose length has been validated.
#[derive(Clone, Copy, Debug)]
pub struct RelaIterator<'a> {
    bytes: &'a [u8],
}

impl<'a> RelaIterator<'a> {
    /// Start iterating over the `DT_RELASZ` bytes of a RELA table.
    ///
    /// Errors: `InvalidImage` when the length is not a multiple of 24.
    pub fn new(bytes: &'a [u8]) -> Result<Self> {
        if !bytes.len().is_multiple_of(RELA_ENTRY_SIZE) {
            return Err(Error::InvalidImage);
        }
        Ok(Self { bytes })
    }
}

impl Iterator for RelaIterator<'_> {
    type Item = Rela;

    fn next(&mut self) -> Option<Self::Item> {
        let (entry, rest) = self.bytes.split_first_chunk::<RELA_ENTRY_SIZE>()?;
        self.bytes = rest;
        let (offset, entry) = entry.split_first_chunk::<8>()?;
        let (info, entry) = entry.split_first_chunk::<8>()?;
        let addend = entry.first_chunk::<8>()?;
        Some(Rela {
            offset: u64::from_le_bytes(*offset),
            info: u64::from_le_bytes(*info),
            addend: i64::from_le_bytes(*addend),
        })
    }
}

/// Parse the dynamic section and extract the values a loader needs.
///
/// `bytes` is the contents of `PT_DYNAMIC`. Scanning stops at the first
/// `DT_NULL`; bytes after it are ignored. Unknown tags are skipped. Each of
/// `DT_RELA`, `DT_RELASZ`, `DT_RELAENT` and `DT_FLAGS_1` may appear at most
/// once. `DT_RELASZ` must be a multiple of 24, `DT_RELAENT` must be 24 when
/// present, and a RELA size or entry size requires a `DT_RELA`.
///
/// Errors: `InvalidImage` for a missing terminator, more than
/// [`MAX_DYNAMIC_ENTRIES`] records before it, a truncated record, a duplicate
/// tag, or an inconsistent RELA description. `Unsupported` for `DT_TEXTREL`.
pub fn parse_dynamic(bytes: &[u8]) -> Result<DynamicInfo> {
    let mut rela = None;
    let mut rela_size = None;
    let mut rela_entry_size = None;
    let mut flags_1 = None;
    let mut terminated = false;

    for index in 0..MAX_DYNAMIC_ENTRIES {
        let offset = index * DYNAMIC_ENTRY_SIZE;
        let tag = read_u64(bytes, offset)? as i64;
        let value = read_u64(bytes, offset + DYNAMIC_VALUE_OFFSET)?;
        match tag {
            DT_NULL => {
                terminated = true;
                break;
            }
            DT_RELA => set_once(&mut rela, value)?,
            DT_RELASZ => set_once(&mut rela_size, value)?,
            DT_RELAENT => set_once(&mut rela_entry_size, value)?,
            DT_FLAGS_1 => set_once(&mut flags_1, value)?,
            DT_TEXTREL => return Err(Error::Unsupported),
            _ => {}
        }
    }
    if !terminated {
        return Err(Error::InvalidImage);
    }

    if rela.is_none() && (rela_size.is_some() || rela_entry_size.is_some()) {
        return Err(Error::InvalidImage);
    }
    if rela.is_some() && rela_size.is_none() {
        return Err(Error::InvalidImage);
    }
    if rela_entry_size.is_some_and(|size| size != RELA_ENTRY_SIZE_U64) {
        return Err(Error::InvalidImage);
    }
    let size = rela_size.unwrap_or(0);
    if !size.is_multiple_of(RELA_ENTRY_SIZE_U64) {
        return Err(Error::InvalidImage);
    }

    Ok(DynamicInfo {
        rela_address: rela,
        rela_size: size,
        flags_1: flags_1.unwrap_or(0),
    })
}

/// Apply RELA relocations to an image mapped at `image_vaddr_base`.
///
/// `image` holds the bytes of the virtual range starting at
/// `image_vaddr_base`, so each `r_offset` must be at or above that base and
/// its 8-byte slot must lie inside `image`. `R_X86_64_NONE` entries are
/// skipped. `R_X86_64_RELATIVE` entries write `load_bias + addend` as a
/// little-endian `u64` at `r_offset`. Every other type, including the
/// symbol-referencing types, is `Unsupported`.
///
/// Every entry is validated before the first write, so an error leaves
/// `image` unchanged. Returns the number of RELATIVE slots written.
///
/// Errors: `InvalidImage` for an offset below the base or outside `image`,
/// or for a `load_bias + addend` that overflows `u64`. `Unsupported` for any
/// relocation type other than NONE or RELATIVE.
pub fn apply(
    image: &mut [u8],
    image_vaddr_base: u64,
    load_bias: u64,
    relas: RelaIterator<'_>,
) -> Result<usize> {
    let limit = u64::try_from(image.len()).map_err(|_| Error::OutOfRange)?;

    let mut relative = 0usize;
    for rela in relas {
        match rela.kind() {
            R_X86_64_NONE => {}
            R_X86_64_RELATIVE => {
                slot_range(limit, image_vaddr_base, rela.offset)?;
                relative_value(load_bias, rela.addend)?;
                relative = relative.checked_add(1).ok_or(Error::OutOfRange)?;
            }
            _ => return Err(Error::Unsupported),
        }
    }

    for rela in relas {
        if rela.kind() != R_X86_64_RELATIVE {
            continue;
        }
        let start = slot_range(limit, image_vaddr_base, rela.offset)?;
        let value = relative_value(load_bias, rela.addend)?;
        let end = start
            .checked_add(SLOT_SIZE as usize)
            .ok_or(Error::InvalidImage)?;
        let slot = image.get_mut(start..end).ok_or(Error::InvalidImage)?;
        slot.copy_from_slice(&value.to_le_bytes());
    }
    Ok(relative)
}

/// Return the start index of a 64-bit slot at vaddr `offset`.
fn slot_range(limit: u64, image_vaddr_base: u64, offset: u64) -> Result<usize> {
    let relative = offset
        .checked_sub(image_vaddr_base)
        .ok_or(Error::InvalidImage)?;
    let end = relative.checked_add(SLOT_SIZE).ok_or(Error::InvalidImage)?;
    if end > limit {
        return Err(Error::InvalidImage);
    }
    usize::try_from(relative).map_err(|_| Error::InvalidImage)
}

/// Compute the value a RELATIVE entry stores, rejecting `u64` overflow.
fn relative_value(load_bias: u64, addend: i64) -> Result<u64> {
    load_bias
        .checked_add_signed(addend)
        .ok_or(Error::InvalidImage)
}

/// Store `value` at `slot`, which the caller has already bounds-checked.
fn set_once(slot: &mut Option<u64>, value: u64) -> Result<()> {
    if slot.is_some() {
        return Err(Error::InvalidImage);
    }
    *slot = Some(value);
    Ok(())
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let end = offset.checked_add(8).ok_or(Error::InvalidImage)?;
    let raw = bytes.get(offset..end).ok_or(Error::InvalidImage)?;
    let mut word = [0u8; 8];
    word.copy_from_slice(raw);
    Ok(u64::from_le_bytes(word))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write one `{d_tag, d_val}` record at `index`.
    fn put_entry(out: &mut [u8], index: usize, tag: i64, value: u64) {
        let at = index * DYNAMIC_ENTRY_SIZE;
        out[at..at + 8].copy_from_slice(&tag.to_le_bytes());
        out[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
    }

    fn put_dynamic(out: &mut [u8], entries: &[(i64, u64)]) {
        for (index, (tag, value)) in entries.iter().enumerate() {
            put_entry(out, index, *tag, *value);
        }
    }

    /// Write one `Elf64_Rela` record at `index`.
    fn put_rela(out: &mut [u8], index: usize, offset: u64, info: u64, addend: i64) {
        let at = index * RELA_ENTRY_SIZE;
        out[at..at + 8].copy_from_slice(&offset.to_le_bytes());
        out[at + 8..at + 16].copy_from_slice(&info.to_le_bytes());
        out[at + 16..at + 24].copy_from_slice(&addend.to_le_bytes());
    }

    fn info(symbol: u32, kind: u32) -> u64 {
        (u64::from(symbol) << 32) | u64::from(kind)
    }

    fn slot(image: &[u8], at: usize) -> u64 {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&image[at..at + 8]);
        u64::from_le_bytes(raw)
    }

    #[test]
    fn parses_rela_table_and_flags() {
        let mut dynamic = [0u8; 16 * 8];
        put_dynamic(
            &mut dynamic,
            &[
                (DT_RELA, 0x2000),
                (DT_RELASZ, 48),
                (DT_RELAENT, 24),
                (DT_FLAGS_1, 0x0800_0000),
                (DT_NULL, 0),
            ],
        );
        assert_eq!(
            parse_dynamic(&dynamic),
            Ok(DynamicInfo {
                rela_address: Some(0x2000),
                rela_size: 48,
                flags_1: 0x0800_0000,
            })
        );
    }

    #[test]
    fn unknown_tags_and_bytes_after_null_are_ignored() {
        // DT_NEEDED (1), DT_SONAME (14) are unrelated to relocation.
        let mut dynamic = [0xffu8; 16 * 5];
        put_dynamic(&mut dynamic, &[(1, 0x10), (14, 0x20), (DT_NULL, 0)]);
        assert_eq!(parse_dynamic(&dynamic), Ok(DynamicInfo::default()));
    }

    #[test]
    fn missing_terminator_is_rejected() {
        assert_eq!(parse_dynamic(&[]), Err(Error::InvalidImage));

        // Two records and no DT_NULL: the scan runs off the end.
        let mut dynamic = [0u8; 32];
        put_dynamic(&mut dynamic, &[(DT_RELA, 0x1000), (DT_FLAGS_1, 1)]);
        assert_eq!(parse_dynamic(&dynamic), Err(Error::InvalidImage));

        // A record cut short by the slice end is also invalid.
        assert_eq!(parse_dynamic(&dynamic[..24]), Err(Error::InvalidImage));
    }

    #[test]
    fn dynamic_scan_is_capped() {
        // MAX-1 unrelated records followed by DT_NULL: exactly MAX records.
        let mut within = [0u8; MAX_DYNAMIC_ENTRIES * DYNAMIC_ENTRY_SIZE];
        for index in 0..MAX_DYNAMIC_ENTRIES - 1 {
            put_entry(&mut within, index, 1, 0);
        }
        put_entry(&mut within, MAX_DYNAMIC_ENTRIES - 1, DT_NULL, 0);
        assert_eq!(parse_dynamic(&within), Ok(DynamicInfo::default()));

        // MAX unrelated records: the terminator lies beyond the cap.
        let mut beyond = [0u8; (MAX_DYNAMIC_ENTRIES + 1) * DYNAMIC_ENTRY_SIZE];
        for index in 0..MAX_DYNAMIC_ENTRIES {
            put_entry(&mut beyond, index, 1, 0);
        }
        put_entry(&mut beyond, MAX_DYNAMIC_ENTRIES, DT_NULL, 0);
        assert_eq!(parse_dynamic(&beyond), Err(Error::InvalidImage));
    }

    #[test]
    fn duplicate_tags_are_rejected() {
        let mut twice_rela = [0u8; 16 * 4];
        put_dynamic(
            &mut twice_rela,
            &[(DT_RELA, 0x1000), (DT_RELA, 0x2000), (DT_NULL, 0)],
        );
        assert_eq!(parse_dynamic(&twice_rela), Err(Error::InvalidImage));

        let mut twice_flags = [0u8; 16 * 4];
        put_dynamic(
            &mut twice_flags,
            &[(DT_FLAGS_1, 1), (DT_FLAGS_1, 1), (DT_NULL, 0)],
        );
        assert_eq!(parse_dynamic(&twice_flags), Err(Error::InvalidImage));
    }

    #[test]
    fn textrel_is_unsupported() {
        let mut dynamic = [0u8; 16 * 3];
        put_dynamic(&mut dynamic, &[(DT_TEXTREL, 0), (DT_NULL, 0)]);
        assert_eq!(parse_dynamic(&dynamic), Err(Error::Unsupported));
    }

    #[test]
    fn rela_size_and_entry_size_are_validated() {
        let check = |entries: &[(i64, u64)]| {
            let mut dynamic = [0u8; 16 * 6];
            put_dynamic(&mut dynamic, entries);
            parse_dynamic(&dynamic)
        };

        // DT_RELA without DT_RELASZ.
        assert_eq!(
            check(&[(DT_RELA, 0x1000), (DT_NULL, 0)]),
            Err(Error::InvalidImage)
        );
        // DT_RELASZ or DT_RELAENT without DT_RELA.
        assert_eq!(
            check(&[(DT_RELASZ, 24), (DT_NULL, 0)]),
            Err(Error::InvalidImage)
        );
        assert_eq!(
            check(&[(DT_RELAENT, 24), (DT_NULL, 0)]),
            Err(Error::InvalidImage)
        );
        // Size not a whole number of records.
        assert_eq!(
            check(&[(DT_RELA, 0x1000), (DT_RELASZ, 25), (DT_NULL, 0)]),
            Err(Error::InvalidImage)
        );
        // Entry size other than 24.
        assert_eq!(
            check(&[
                (DT_RELA, 0x1000),
                (DT_RELASZ, 48),
                (DT_RELAENT, 16),
                (DT_NULL, 0)
            ]),
            Err(Error::InvalidImage)
        );
        // An absent DT_RELAENT is accepted; the only supported size is 24.
        assert_eq!(
            check(&[(DT_RELA, 0x1000), (DT_RELASZ, 48), (DT_NULL, 0)]),
            Ok(DynamicInfo {
                rela_address: Some(0x1000),
                rela_size: 48,
                flags_1: 0,
            })
        );
    }

    #[test]
    fn rela_iterator_decodes_entries() {
        let mut table = [0u8; 2 * RELA_ENTRY_SIZE];
        put_rela(&mut table, 0, 0x1000, info(3, R_X86_64_RELATIVE), -16);
        put_rela(&mut table, 1, 0x1008, info(0, R_X86_64_NONE), 5);

        let mut iter = RelaIterator::new(&table).unwrap();
        let first = iter.next().unwrap();
        assert_eq!(first.offset, 0x1000);
        assert_eq!(first.kind(), R_X86_64_RELATIVE);
        assert_eq!(first.symbol(), 3);
        assert_eq!(first.addend, -16);

        let second = iter.next().unwrap();
        assert_eq!(second.offset, 0x1008);
        assert_eq!(second.kind(), R_X86_64_NONE);
        assert_eq!(second.addend, 5);

        assert_eq!(iter.next(), None);
        assert_eq!(RelaIterator::new(&[]).unwrap().next(), None);
    }

    #[test]
    fn rela_iterator_rejects_partial_records() {
        assert_eq!(
            RelaIterator::new(&[0u8; RELA_ENTRY_SIZE + 1]).err(),
            Some(Error::InvalidImage)
        );
        assert_eq!(
            RelaIterator::new(&[0u8; RELA_ENTRY_SIZE - 1]).err(),
            Some(Error::InvalidImage)
        );
    }

    #[test]
    fn relative_writes_load_bias_plus_addend() {
        // Image covers vaddrs 0x1000..0x1100.
        let mut image = [0u8; 0x100];
        let mut table = [0u8; 2 * RELA_ENTRY_SIZE];
        put_rela(&mut table, 0, 0x1010, info(0, R_X86_64_RELATIVE), 0x20);
        // The last 8-byte slot ends exactly at the image end.
        put_rela(&mut table, 1, 0x10f8, info(0, R_X86_64_RELATIVE), -1);
        let relas = RelaIterator::new(&table).unwrap();

        assert_eq!(apply(&mut image, 0x1000, 0x40_0000, relas), Ok(2));
        assert_eq!(slot(&image, 0x10), 0x40_0020);
        assert_eq!(slot(&image, 0xf8), 0x3f_ffff);
    }

    #[test]
    fn none_entries_are_skipped_and_not_counted() {
        let mut image = [0u8; 0x100];
        let mut table = [0u8; 2 * RELA_ENTRY_SIZE];
        // NONE is a no-op, so its target is never bounds-checked.
        put_rela(&mut table, 0, 0xdead_0000, info(0, R_X86_64_NONE), 7);
        put_rela(&mut table, 1, 0x1000, info(0, R_X86_64_RELATIVE), 9);
        let relas = RelaIterator::new(&table).unwrap();

        assert_eq!(apply(&mut image, 0x1000, 0, relas), Ok(1));
        assert_eq!(slot(&image, 0), 9);
    }

    #[test]
    fn unsupported_types_reject_without_partial_writes() {
        // Symbol-referencing types, and an undefined type 64 that falls under
        // the catch-all, must all be rejected.
        for kind in [R_X86_64_64, R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT, 64, 37] {
            let mut image = [0u8; 0x100];
            image[0x20..0x28].copy_from_slice(&5u64.to_le_bytes());
            let original = image;
            let mut table = [0u8; 2 * RELA_ENTRY_SIZE];
            // The RELATIVE entry is valid and comes first; the bad one follows.
            put_rela(&mut table, 0, 0x10, info(0, R_X86_64_RELATIVE), 1);
            put_rela(&mut table, 1, 0x20, info(1, kind), 0);
            let relas = RelaIterator::new(&table).unwrap();
            assert_eq!(apply(&mut image, 0, 0x100, relas), Err(Error::Unsupported));
            assert_eq!(image, original, "type {kind} wrote to the image");
        }
    }

    #[test]
    fn out_of_range_offsets_reject_without_partial_writes() {
        // Image covers vaddrs 0x1000..0x1100.
        let mut image = [0u8; 0x100];
        let original = image;

        // Below the image base.
        let mut below = [0u8; RELA_ENTRY_SIZE];
        put_rela(&mut below, 0, 0xfff, info(0, R_X86_64_RELATIVE), 1);
        let relas = RelaIterator::new(&below).unwrap();
        assert_eq!(
            apply(&mut image, 0x1000, 0, relas),
            Err(Error::InvalidImage)
        );
        assert_eq!(image, original);

        // A valid entry followed by a slot that runs one byte past the end.
        let mut table = [0u8; 2 * RELA_ENTRY_SIZE];
        put_rela(&mut table, 0, 0x1010, info(0, R_X86_64_RELATIVE), 1);
        put_rela(&mut table, 1, 0x10f9, info(0, R_X86_64_RELATIVE), 1);
        let relas = RelaIterator::new(&table).unwrap();
        assert_eq!(
            apply(&mut image, 0x1000, 0, relas),
            Err(Error::InvalidImage)
        );
        assert_eq!(image, original);
    }

    #[test]
    fn load_bias_overflow_rejects_without_partial_writes() {
        let mut image = [0u8; 0x100];
        let original = image;
        let mut table = [0u8; 2 * RELA_ENTRY_SIZE];
        put_rela(&mut table, 0, 0x10, info(0, R_X86_64_RELATIVE), 1);
        put_rela(&mut table, 1, 0x20, info(0, R_X86_64_RELATIVE), 1);
        let relas = RelaIterator::new(&table).unwrap();
        assert_eq!(
            apply(&mut image, 0, u64::MAX, relas),
            Err(Error::InvalidImage)
        );
        assert_eq!(image, original);

        // A negative addend that drops below zero is also an overflow.
        let mut negative = [0u8; RELA_ENTRY_SIZE];
        put_rela(&mut negative, 0, 0x10, info(0, R_X86_64_RELATIVE), -1);
        let relas = RelaIterator::new(&negative).unwrap();
        assert_eq!(apply(&mut image, 0, 0, relas), Err(Error::InvalidImage));
        assert_eq!(image, original);
    }

    #[test]
    fn extreme_offsets_do_not_overflow() {
        let mut image = [0u8; 0x100];
        let mut huge = [0u8; RELA_ENTRY_SIZE];
        put_rela(&mut huge, 0, u64::MAX, info(0, R_X86_64_RELATIVE), 0);
        let relas = RelaIterator::new(&huge).unwrap();
        assert_eq!(apply(&mut image, 0, 0, relas), Err(Error::InvalidImage));

        // A base above every offset: the subtraction itself must not wrap.
        let mut low = [0u8; RELA_ENTRY_SIZE];
        put_rela(&mut low, 0, 0x10, info(0, R_X86_64_RELATIVE), 0);
        let relas = RelaIterator::new(&low).unwrap();
        assert_eq!(
            apply(&mut image, u64::MAX, 0, relas),
            Err(Error::InvalidImage)
        );
    }

    #[test]
    fn empty_table_applies_nothing() {
        let mut image = [0xabu8; 0x40];
        let relas = RelaIterator::new(&[]).unwrap();
        assert_eq!(apply(&mut image, 0x1000, 0x400000, relas), Ok(0));
        assert!(image.iter().all(|&b| b == 0xab));
    }
}
