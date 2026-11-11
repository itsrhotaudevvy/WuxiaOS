//! Bounds-checked x64 exception directory (`.pdata`) and `UNWIND_INFO` headers.
//!
//! The exception directory (data directory 3) is an array of 12-byte
//! `RUNTIME_FUNCTION` records: begin RVA, end RVA and the RVA of an
//! `UNWIND_INFO` structure. A record covers `[begin, end)`. The whole table is
//! validated when it is constructed: every record must be non-empty, name
//! unwind information, and be sorted by `begin` without overlapping its
//! neighbours. Lookups by RVA rely on that order.
//!
//! [`UnwindInfo::parse`] reads only the four-byte header and the raw code
//! array. Interpreting the unwind codes, and any handler or chained-record
//! trailer, belongs to the unwinder.

use crate::error::{Error, Result};
use crate::pe_import::SectionRange;

/// Index of the exception directory (`IMAGE_DIRECTORY_ENTRY_EXCEPTION`).
pub const EXCEPTION_DIRECTORY: usize = 3;

/// Size in bytes of one `RUNTIME_FUNCTION` record.
const RUNTIME_FUNCTION_SIZE: usize = 12;

/// Size in bytes of the fixed `UNWIND_INFO` header.
const UNWIND_HEADER_SIZE: usize = 4;

/// The function has a language-specific exception handler (`UNW_FLAG_EHANDLER`).
pub const UNW_FLAG_EHANDLER: u8 = 0x1;

/// The function has a language-specific termination handler (`UNW_FLAG_UHANDLER`).
pub const UNW_FLAG_UHANDLER: u8 = 0x2;

/// The record chains to another `RUNTIME_FUNCTION` (`UNW_FLAG_CHAININFO`).
pub const UNW_FLAG_CHAININFO: u8 = 0x4;

/// One `RUNTIME_FUNCTION` record. Every address is an RVA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeFunction {
    /// First RVA covered by the function.
    pub begin: u32,
    /// RVA one past the last byte covered by the function.
    pub end: u32,
    /// RVA of the function's `UNWIND_INFO`; never zero in a validated table.
    pub unwind_info: u32,
}

/// A validated exception directory borrowed from the image bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeFunctions<'a> {
    /// Raw table bytes; the length is always a multiple of 12.
    bytes: &'a [u8],
}

/// The fixed header of an `UNWIND_INFO` structure, with its raw code array.
///
/// Only version 1 and version 2 are accepted; version 2 differs from version 1
/// in how epilogs are encoded among the codes, which this header does not
/// interpret.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnwindInfo<'a> {
    /// Structure version, 1 or 2.
    pub version: u8,
    /// Flag bits such as [`UNW_FLAG_EHANDLER`]; the field is five bits wide.
    pub flags: u8,
    /// Number of prolog bytes described by the codes.
    pub prolog_size: u8,
    /// Number of 2-byte unwind codes that follow the header.
    pub code_count: u8,
    /// Frame pointer register number (0 when the function uses no frame pointer).
    pub frame_register: u8,
    /// Scaled offset of the frame register; multiply by 16 to get bytes.
    pub frame_offset: u8,
    /// The `code_count` raw unwind codes, uninterpreted.
    codes: &'a [u8],
}

impl<'a> RuntimeFunctions<'a> {
    /// Locate and validate the exception directory at `rva` spanning `size` bytes.
    ///
    /// `sections` maps RVAs to raw image bytes, as for the import directory.
    /// A zero `size` describes an image without exception data and yields an
    /// empty table. The whole table must lie inside one section's raw data.
    ///
    /// Errors: `InvalidImage` when the size is not a multiple of 12, the table
    /// is not contained in one section, any record is empty or reversed, any
    /// record has a zero `UnwindInfoAddress`, or records are unsorted or overlap.
    pub fn new(image: &'a [u8], sections: &[SectionRange], rva: u32, size: u32) -> Result<Self> {
        if size == 0 {
            return Ok(Self { bytes: &[] });
        }
        if !(size as usize).is_multiple_of(RUNTIME_FUNCTION_SIZE) {
            return Err(Error::InvalidImage);
        }
        let table = Self {
            bytes: table_bytes(image, sections, rva, size)?,
        };
        let mut previous: Option<RuntimeFunction> = None;
        for index in 0..table.len() {
            let entry = table.get(index).ok_or(Error::InvalidImage)?;
            if entry.begin >= entry.end || entry.unwind_info == 0 {
                return Err(Error::InvalidImage);
            }
            if let Some(prev) = previous {
                if entry.begin < prev.begin {
                    return Err(Error::InvalidImage);
                }
                if entry.begin < prev.end {
                    return Err(Error::InvalidImage);
                }
            }
            previous = Some(entry);
        }
        Ok(table)
    }

    /// Number of validated records in the table.
    pub const fn len(&self) -> usize {
        self.bytes.len() / RUNTIME_FUNCTION_SIZE
    }

    /// True when the image declares no exception records.
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Return record `index`, or `None` when it is out of range.
    pub fn get(&self, index: usize) -> Option<RuntimeFunction> {
        if index >= self.len() {
            return None;
        }
        let base = index.checked_mul(RUNTIME_FUNCTION_SIZE)?;
        Some(RuntimeFunction {
            begin: u32_at(self.bytes, base)?,
            end: u32_at(self.bytes, base + 4)?,
            unwind_info: u32_at(self.bytes, base + 8)?,
        })
    }

    /// Find the record whose `[begin, end)` range contains `rva`.
    ///
    /// Runs a binary search over the validated, non-overlapping records.
    /// Returns `None` for RVAs in gaps, before the first record and after the last.
    pub fn find(&self, rva: u32) -> Option<RuntimeFunction> {
        // Count the records that start at or before `rva`; the only candidate
        // containing `rva` is the last of them.
        let mut low = 0;
        let mut high = self.len();
        while low < high {
            let mid = low + (high - low) / 2;
            let entry = self.get(mid)?;
            if entry.begin <= rva {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        let candidate = self.get(low.checked_sub(1)?)?;
        (rva < candidate.end).then_some(candidate)
    }
}

impl<'a> UnwindInfo<'a> {
    /// Parse the `UNWIND_INFO` structure at the start of `bytes`.
    ///
    /// `bytes` may extend past the structure; only the header and the
    /// `2 * code_count` bytes of codes are read. The codes are not interpreted.
    ///
    /// Errors: `Unsupported` for a version other than 1 or 2, and `InvalidImage`
    /// when the header or the code array extends past `bytes`.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let header: [u8; UNWIND_HEADER_SIZE] = bytes
            .get(..UNWIND_HEADER_SIZE)
            .and_then(|header| header.try_into().ok())
            .ok_or(Error::InvalidImage)?;
        let [version_flags, prolog_size, code_count, frame] = header;
        let version = version_flags & 0x07;
        if !matches!(version, 1 | 2) {
            return Err(Error::Unsupported);
        }
        let codes_end = UNWIND_HEADER_SIZE + 2 * usize::from(code_count);
        let codes = bytes
            .get(UNWIND_HEADER_SIZE..codes_end)
            .ok_or(Error::InvalidImage)?;
        Ok(Self {
            version,
            flags: version_flags >> 3,
            prolog_size,
            code_count,
            frame_register: frame & 0x0f,
            frame_offset: frame >> 4,
            codes,
        })
    }

    /// The raw unwind codes, exactly `2 * code_count` bytes, uninterpreted.
    pub const fn raw_codes(&self) -> &'a [u8] {
        self.codes
    }

    /// True when the function names an exception or termination handler.
    pub const fn has_handler(&self) -> bool {
        self.flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0
    }

    /// True when the record chains to a primary `RUNTIME_FUNCTION`.
    pub const fn is_chained(&self) -> bool {
        self.flags & UNW_FLAG_CHAININFO != 0
    }
}

/// Translate a table RVA and size into the bytes it occupies in the image.
///
/// The table must start inside a section's raw data and end no later than that
/// section's raw data; the arithmetic is widened so no RVA range can overflow.
fn table_bytes<'a>(
    image: &'a [u8],
    sections: &[SectionRange],
    rva: u32,
    size: u32,
) -> Result<&'a [u8]> {
    for section in sections {
        let delta = match rva.checked_sub(section.virtual_address) {
            Some(delta) => delta,
            None => continue,
        };
        if delta >= section.raw_size {
            continue;
        }
        if u64::from(delta) + u64::from(size) > u64::from(section.raw_size) {
            return Err(Error::InvalidImage);
        }
        let start = section
            .raw_offset
            .checked_add(delta as usize)
            .ok_or(Error::InvalidImage)?;
        let end = start
            .checked_add(size as usize)
            .ok_or(Error::InvalidImage)?;
        return image.get(start..end).ok_or(Error::InvalidImage);
    }
    Err(Error::InvalidImage)
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let raw: [u8; 4] = bytes.get(offset..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: SectionRange = SectionRange {
        virtual_address: 0x1000,
        raw_offset: 0x200,
        raw_size: 0x400,
    };

    /// Write `(begin, end, unwind)` records for a table starting at `rva` in `TEXT`.
    fn put_table(img: &mut [u8], rva: u32, records: &[(u32, u32, u32)]) {
        let mut at = (rva - TEXT.virtual_address) as usize + TEXT.raw_offset;
        for &(begin, end, unwind) in records {
            img[at..at + 4].copy_from_slice(&begin.to_le_bytes());
            img[at + 4..at + 8].copy_from_slice(&end.to_le_bytes());
            img[at + 8..at + 12].copy_from_slice(&unwind.to_le_bytes());
            at += RUNTIME_FUNCTION_SIZE;
        }
    }

    const VALID: [(u32, u32, u32); 3] = [
        (0x1100, 0x1180, 0x2000),
        (0x1180, 0x1200, 0x2010),
        (0x1300, 0x1400, 0x2020),
    ];

    /// Build an image holding `records` at the start of `TEXT` and validate it.
    fn validate(records: &[(u32, u32, u32)]) -> Result<()> {
        let mut img = [0u8; 0x800];
        put_table(&mut img, 0x1000, records);
        let size = (records.len() * RUNTIME_FUNCTION_SIZE) as u32;
        RuntimeFunctions::new(&img, &[TEXT], 0x1000, size).map(|_| ())
    }

    #[test]
    fn parses_sorted_table_and_indexes_records() {
        let mut img = [0u8; 0x800];
        put_table(&mut img, 0x1000, &VALID);
        let table = RuntimeFunctions::new(&img, &[TEXT], 0x1000, 36).unwrap();
        assert_eq!(table.len(), 3);
        assert!(!table.is_empty());
        assert_eq!(
            table.get(0),
            Some(RuntimeFunction {
                begin: 0x1100,
                end: 0x1180,
                unwind_info: 0x2000
            })
        );
        assert_eq!(table.get(1).map(|e| e.begin), Some(0x1180));
        assert_eq!(table.get(2).map(|e| e.unwind_info), Some(0x2020));
        assert_eq!(table.get(3), None);
    }

    #[test]
    fn empty_directory_is_valid_and_finds_nothing() {
        let img = [0u8; 0x800];
        for rva in [0, 0x1000] {
            let table = RuntimeFunctions::new(&img, &[TEXT], rva, 0).unwrap();
            assert_eq!(table.len(), 0);
            assert!(table.is_empty());
            assert_eq!(table.get(0), None);
            assert_eq!(table.find(0x1100), None);
        }
    }

    #[test]
    fn rejects_size_that_is_not_a_multiple_of_twelve() {
        let img = [0u8; 0x800];
        assert_eq!(
            RuntimeFunctions::new(&img, &[TEXT], 0x1000, 35),
            Err(Error::InvalidImage)
        );
        assert_eq!(
            RuntimeFunctions::new(&img, &[TEXT], 0x1000, 13),
            Err(Error::InvalidImage)
        );
    }

    #[test]
    fn rejects_empty_or_reversed_ranges() {
        assert_eq!(validate(&[(0x1100, 0x1100, 1)]), Err(Error::InvalidImage));
        assert_eq!(validate(&[(0x1180, 0x1100, 1)]), Err(Error::InvalidImage));
    }

    #[test]
    fn rejects_zero_unwind_info_address() {
        assert_eq!(validate(&[(0x1100, 0x1180, 0)]), Err(Error::InvalidImage));
    }

    #[test]
    fn rejects_unsorted_records() {
        let records = [(0x1300, 0x1400, 1), (0x1100, 0x1180, 2)];
        assert_eq!(validate(&records), Err(Error::InvalidImage));
    }

    #[test]
    fn rejects_overlapping_records() {
        let records = [(0x1100, 0x1180, 1), (0x1170, 0x1200, 2)];
        assert_eq!(validate(&records), Err(Error::InvalidImage));
    }

    #[test]
    fn accepts_adjacent_records_that_touch_exactly() {
        // VALID already places one record's end exactly at the next begin.
        assert!(validate(&VALID).is_ok());
    }

    #[test]
    fn rejects_table_that_is_not_inside_one_section() {
        let img = [0u8; 0x800];
        // Starts inside the raw data but runs past its end (0x1400).
        assert_eq!(
            RuntimeFunctions::new(&img, &[TEXT], 0x13f0, 24),
            Err(Error::InvalidImage)
        );
        // Starts exactly at the end of the raw data.
        assert_eq!(
            RuntimeFunctions::new(&img, &[TEXT], 0x1400, 12),
            Err(Error::InvalidImage)
        );
        // No section maps the RVA at all.
        assert_eq!(
            RuntimeFunctions::new(&img, &[TEXT], 0x9000, 12),
            Err(Error::InvalidImage)
        );
        // The table's raw bytes are cut short by a truncated image.
        assert_eq!(
            RuntimeFunctions::new(&img[..0x300], &[TEXT], 0x1100, 36),
            Err(Error::InvalidImage)
        );
    }

    #[test]
    fn huge_size_is_rejected_without_overflow() {
        let img = [0u8; 0x800];
        assert_eq!(
            RuntimeFunctions::new(&img, &[TEXT], 0x1000, 0xffff_fff0),
            Err(Error::InvalidImage)
        );
        assert_eq!(
            RuntimeFunctions::new(&img, &[TEXT], u32::MAX - 3, 12),
            Err(Error::InvalidImage)
        );
    }

    #[test]
    fn find_locates_containing_record_and_rejects_gaps() {
        let mut img = [0u8; 0x800];
        put_table(&mut img, 0x1000, &VALID);
        let table = RuntimeFunctions::new(&img, &[TEXT], 0x1000, 36).unwrap();
        let first = table.get(0);
        let second = table.get(1);
        let third = table.get(2);
        assert_eq!(table.find(0x1100), first);
        assert_eq!(table.find(0x117f), first);
        assert_eq!(table.find(0x1180), second);
        assert_eq!(table.find(0x11ff), second);
        assert_eq!(table.find(0x1300), third);
        assert_eq!(table.find(0x13ff), third);
        // Before the first record, in the gap, and at or after the last end.
        assert_eq!(table.find(0x1000), None);
        assert_eq!(table.find(0x10ff), None);
        assert_eq!(table.find(0x1200), None);
        assert_eq!(table.find(0x12ff), None);
        assert_eq!(table.find(0x1400), None);
        assert_eq!(table.find(u32::MAX), None);
    }

    #[test]
    fn binary_search_matches_a_linear_scan_over_many_records() {
        let mut records = [(0u32, 0u32, 0u32); 20];
        for (i, record) in records.iter_mut().enumerate() {
            let begin = 0x1000 + 0x20 * i as u32;
            *record = (begin, begin + 0x10, 0x3000 + i as u32);
        }
        let mut img = [0u8; 0x800];
        put_table(&mut img, 0x1000, &records);
        let table = RuntimeFunctions::new(&img, &[TEXT], 0x1000, 20 * 12).unwrap();
        for rva in 0x0fe0u32..0x1300 {
            let offset = rva.wrapping_sub(0x1000);
            let expected = if offset < 0x280 && offset % 0x20 < 0x10 {
                table.get((offset / 0x20) as usize)
            } else {
                None
            };
            assert_eq!(table.find(rva), expected, "rva {rva:#x}");
        }
    }

    #[test]
    fn unwind_info_v1_parses_header_and_raw_codes() {
        // Version 1, no flags; prolog 8; two codes; frame RBP at 5 * 16 bytes.
        let bytes = [0x01, 0x08, 0x02, 0x51, 0x01, 0x02, 0x03, 0x04, 0xaa];
        let info = UnwindInfo::parse(&bytes).unwrap();
        assert_eq!(info.version, 1);
        assert_eq!(info.flags, 0);
        assert_eq!(info.prolog_size, 8);
        assert_eq!(info.code_count, 2);
        assert_eq!(info.frame_register, 1);
        assert_eq!(info.frame_offset, 5);
        // Trailing bytes past the declared codes are not part of the codes.
        assert_eq!(info.raw_codes(), &[1, 2, 3, 4]);
        assert!(!info.has_handler());
        assert!(!info.is_chained());
    }

    #[test]
    fn unwind_info_v2_reports_handler_and_chain_flags() {
        // Version 2 with EHANDLER | UHANDLER: flags 3 live in bits 3..8.
        let with_handlers = UnwindInfo::parse(&[0x02 | (3 << 3), 0, 0, 0]).unwrap();
        assert_eq!(with_handlers.version, 2);
        assert_eq!(with_handlers.flags, UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER);
        assert!(with_handlers.has_handler());
        assert!(!with_handlers.is_chained());
        assert!(with_handlers.raw_codes().is_empty());

        // Version 1 with CHAININFO: flags 4.
        let chained = UnwindInfo::parse(&[0x01 | (4 << 3), 0, 0, 0]).unwrap();
        assert!(chained.is_chained());
        assert!(!chained.has_handler());
    }

    #[test]
    fn unwind_info_rejects_unknown_versions() {
        for version in [0x00u8, 0x03, 0x07] {
            assert_eq!(
                UnwindInfo::parse(&[version, 0, 0, 0]),
                Err(Error::Unsupported),
                "version byte {version:#x}"
            );
        }
    }

    #[test]
    fn unwind_info_rejects_short_header_and_truncated_codes() {
        assert_eq!(UnwindInfo::parse(&[0x01, 0, 0]), Err(Error::InvalidImage));
        assert_eq!(UnwindInfo::parse(&[]), Err(Error::InvalidImage));
        // Declares two codes (4 bytes) but supplies only three.
        assert_eq!(
            UnwindInfo::parse(&[0x01, 0, 2, 0, 1, 2, 3]),
            Err(Error::InvalidImage)
        );
    }

    #[test]
    fn unwind_info_accepts_header_with_no_codes() {
        let info = UnwindInfo::parse(&[0x01, 0, 0, 0]).unwrap();
        assert_eq!(info.code_count, 0);
        assert!(info.raw_codes().is_empty());
    }
}
