//! Allocation-free x86_64 paging contracts.
//!
//! This module validates virtual addresses and encodes page-table entries. It
//! does not dereference physical memory or modify the processor's active CR3.
//! Actual table construction and mapping belong to the architecture-specific
//! kernel, which owns the frames and the higher-half direct map.

use crate::{Error, Result};

/// Size of a four-kibibyte page and one hardware page table.
pub const PAGE_SIZE: u64 = 4096;
/// Number of entries in each of the four x86_64 paging levels.
pub const ENTRIES_PER_TABLE: usize = 512;
/// Number of paging levels implemented by x86_64 long mode.
pub const LEVELS: usize = 4;
/// The first lower-half address that is no longer mappable for CPL3.
///
/// Addresses below this limit are canonical, page-aligned and free of the
/// hardware sign extension that marks kernel virtual addresses.
pub const USER_ADDRESS_LIMIT: u64 = 0x0000_8000_0000_0000;

/// Physical-address bits present in a page-table entry (`MAXPHYADDR` of 52).
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const HUGE: u64 = 1 << 7;
const CACHE_DISABLE: u64 = 1 << 4;
const NO_EXECUTE: u64 = 1 << 63;

/// The first canonical higher-half address, where supervisor mappings start.
pub const KERNEL_ADDRESS_START: u64 = 0xffff_8000_0000_0000;

/// Permissions for a four-kibibyte leaf mapping.
///
/// The kernel enforces W^X: a mapping may be writable or executable, never
/// both. Data pages therefore carry NX, and code pages are read-only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PagePermissions {
    /// Whether supervisor or user writes are permitted.
    pub writable: bool,
    /// Whether CPL3 may access the page.
    pub user: bool,
    /// Whether instruction fetches are permitted.
    pub executable: bool,
    /// Whether the page must bypass the caches.
    ///
    /// Set for device registers, whose reads and writes have side effects that
    /// caching would reorder or suppress. It is orthogonal to W^X.
    pub cache_disable: bool,
}

impl PagePermissions {
    /// A user-accessible, read-only, non-executable data page.
    pub const USER_READ_ONLY: Self = Self {
        writable: false,
        user: true,
        executable: false,
        cache_disable: false,
    };

    /// A user-accessible, writable, non-executable data page.
    pub const USER_READ_WRITE: Self = Self {
        writable: true,
        user: true,
        executable: false,
        cache_disable: false,
    };

    /// A user-accessible, read-only, executable code page.
    pub const USER_CODE: Self = Self {
        writable: false,
        user: true,
        executable: true,
        cache_disable: false,
    };

    /// A supervisor-only, read-only, non-executable page.
    pub const KERNEL_READ_ONLY: Self = Self {
        writable: false,
        user: false,
        executable: false,
        cache_disable: false,
    };

    /// A supervisor-only, writable, non-executable, uncached device window.
    pub const KERNEL_MMIO: Self = Self {
        writable: true,
        user: false,
        executable: false,
        cache_disable: true,
    };

    /// Encode the raw flag bits of this permission set.
    pub const fn bits(self) -> u64 {
        PRESENT
            | if self.writable { WRITABLE } else { 0 }
            | if self.user { USER } else { 0 }
            | if self.executable { 0 } else { NO_EXECUTE }
            | if self.cache_disable { CACHE_DISABLE } else { 0 }
    }

    /// Whether this permission set violates W^X.
    pub const fn is_writable_and_executable(self) -> bool {
        self.writable && self.executable
    }
}

/// Validate a page-aligned, canonical, lower-half userspace address.
pub const fn user_page(address: u64) -> Result<u64> {
    if is_user_address(address) {
        Ok(address)
    } else {
        Err(Error::BadAddress)
    }
}

/// Whether an address is page-aligned, nonzero, canonical and user-accessible.
pub const fn is_user_address(address: u64) -> bool {
    address != 0 && address.is_multiple_of(PAGE_SIZE) && address < USER_ADDRESS_LIMIT
}

/// Encode a 4 KiB leaf mapping after checking bounds and W^X.
pub const fn leaf(
    virtual_address: u64,
    physical_address: u64,
    permissions: PagePermissions,
) -> Result<u64> {
    if !is_user_address(virtual_address) || !is_physical_page(physical_address) {
        return Err(Error::BadAddress);
    }
    if permissions.is_writable_and_executable() {
        return Err(Error::PermissionDenied);
    }
    Ok(physical_address | permissions.bits())
}

/// Encode a 4 KiB supervisor leaf mapping in the higher half.
///
/// The user leaf encoder refuses higher-half addresses, so device and other
/// kernel mappings use this one. The checks are the same shape: the virtual
/// address must be page-aligned and canonical, the frame page-aligned and
/// physically addressable, and the permissions must not break W^X. A mapping
/// that asks for CPL3 access is refused: kernel ranges are not user-visible.
pub const fn kernel_leaf(
    virtual_address: u64,
    physical_address: u64,
    permissions: PagePermissions,
) -> Result<u64> {
    if virtual_address < KERNEL_ADDRESS_START || !virtual_address.is_multiple_of(PAGE_SIZE) {
        return Err(Error::BadAddress);
    }
    if !is_physical_page(physical_address) {
        return Err(Error::BadAddress);
    }
    if permissions.user {
        return Err(Error::BadAddress);
    }
    if permissions.is_writable_and_executable() {
        return Err(Error::PermissionDenied);
    }
    Ok(physical_address | permissions.bits())
}

/// Encode an intermediate entry pointing at a zeroed next-level table.
///
/// The zero frame is rejected because the null page is never valid storage for
/// a page table.
pub const fn table_entry(frame: u64, user: bool) -> Result<u64> {
    if !is_physical_page(frame) {
        return Err(Error::BadAddress);
    }
    Ok(frame | PRESENT | WRITABLE | if user { USER } else { 0 })
}

/// Return the table index for one of the four levels (`0` is PML4).
///
/// Only the index bits matter, so an address inside a page is as valid as the
/// page base. Callers that map memory still validate alignment separately.
pub const fn table_index(virtual_address: u64, level: usize) -> Result<usize> {
    if virtual_address == 0 || virtual_address >= USER_ADDRESS_LIMIT || level >= LEVELS {
        return Err(Error::BadAddress);
    }
    Ok(((virtual_address >> (39 - level * 9)) & 0x1ff) as usize)
}

/// Return the table index of a higher-half address.
///
/// [`table_index`] refuses every supervisor address, so device and other kernel
/// mappings use this variant. The arithmetic is identical; only the accepted
/// range differs.
pub const fn kernel_table_index(virtual_address: u64, level: usize) -> Result<usize> {
    if virtual_address < KERNEL_ADDRESS_START || level >= LEVELS {
        return Err(Error::BadAddress);
    }
    Ok(((virtual_address >> (39 - level * 9)) & 0x1ff) as usize)
}

/// Decode a present entry's physical address.
pub const fn physical_address(entry: u64) -> u64 {
    entry & ADDRESS_MASK
}

/// Whether an entry refers to another table rather than a leaf.
pub const fn is_table(entry: u64) -> bool {
    entry & PRESENT != 0 && entry & HUGE == 0
}

/// Whether a page-table entry permits instruction fetches.
pub const fn is_executable(entry: u64) -> bool {
    entry & NO_EXECUTE == 0
}

/// Whether a page-table entry is present in the hierarchy.
pub const fn is_present(entry: u64) -> bool {
    entry & PRESENT != 0
}

/// Whether a leaf entry is accessible from CPL3.
pub const fn is_user(entry: u64) -> bool {
    entry & USER != 0
}

/// Whether a leaf entry permits writes.
pub const fn is_writable(entry: u64) -> bool {
    entry & WRITABLE != 0
}

/// Read-only access to a physical page-table entry.
///
/// Implementations translate a physical table frame through whatever mapping
/// is active; the walker itself never dereferences memory.
pub trait PageTableReader {
    /// Return the raw entry at `index` in the table stored at `table_frame`.
    fn read_entry(&self, table_frame: u64, index: usize) -> u64;
}

/// Resolve a four-kibibyte user page to its present leaf entry.
///
/// Huge intermediate entries and 2 MiB leaves are rejected with
/// [`Error::Unsupported`] because the bootstrap map is 4 KiB only. Absent
/// entries return [`Error::NotFound`].
pub fn walk<R: PageTableReader>(reader: &R, root: u64, virtual_address: u64) -> Result<u64> {
    // An address inside a mapped page resolves through the same indices as the
    // page base, so only the range is validated here.
    if virtual_address == 0 || virtual_address >= USER_ADDRESS_LIMIT {
        return Err(Error::BadAddress);
    }
    let mut table = root;
    for level in 0..3 {
        let entry = reader.read_entry(table, table_index(virtual_address, level)?);
        if !is_present(entry) {
            return Err(Error::NotFound);
        }
        if entry & HUGE != 0 {
            return Err(Error::Unsupported);
        }
        table = physical_address(entry);
        if table == 0 {
            return Err(Error::InvalidState);
        }
    }
    let leaf_entry = reader.read_entry(table, table_index(virtual_address, 3)?);
    if !is_present(leaf_entry) {
        return Err(Error::NotFound);
    }
    if leaf_entry & HUGE != 0 {
        return Err(Error::Unsupported);
    }
    Ok(leaf_entry)
}

/// Whether a physical address is a usable, nonzero 4 KiB page frame.
const fn is_physical_page(address: u64) -> bool {
    address != 0 && address.is_multiple_of(PAGE_SIZE) && address & !ADDRESS_MASK == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_addresses_are_page_aligned_and_lower_half() {
        assert_eq!(user_page(0x400000), Ok(0x400000));
        assert_eq!(user_page(0), Err(Error::BadAddress));
        assert_eq!(user_page(0x1001), Err(Error::BadAddress));
        assert_eq!(user_page(USER_ADDRESS_LIMIT), Err(Error::BadAddress));
        assert_eq!(user_page(0xffff_8000_0000_0000), Err(Error::BadAddress));
        assert_eq!(user_page(0xffff_ffff_8000_0000), Err(Error::BadAddress));
    }

    #[test]
    fn user_read_only_pages_are_non_executable() {
        let entry = leaf(0x400000, 0x123000, PagePermissions::USER_READ_ONLY).unwrap();
        assert_eq!(entry & 0xfff, 0x005);
        assert_eq!(entry & NO_EXECUTE, NO_EXECUTE);
        assert_eq!(entry & ADDRESS_MASK, 0x123000);
        assert_eq!(entry & WRITABLE, 0);
        assert_ne!(entry & USER, 0);
        assert!(!is_executable(entry));
    }

    #[test]
    fn user_code_pages_are_read_only_and_executable() {
        let entry = leaf(0x400000, 0x2000, PagePermissions::USER_CODE).unwrap();
        assert_eq!(entry & WRITABLE, 0);
        assert_ne!(entry & USER, 0);
        assert_eq!(entry & NO_EXECUTE, 0);
        assert!(is_executable(entry));
    }

    #[test]
    fn writable_executable_pages_are_rejected() {
        let flags = PagePermissions {
            writable: true,
            user: true,
            executable: true,
            cache_disable: false,
        };
        assert!(flags.is_writable_and_executable());
        assert_eq!(leaf(0x400000, 0x3000, flags), Err(Error::PermissionDenied));
    }

    #[test]
    fn kernel_leaves_map_higher_half_windows_without_caching() {
        let window = 0xffff_9600_0000_0000;
        let entry = kernel_leaf(window, 0xfeb8_0000, PagePermissions::KERNEL_MMIO).unwrap();
        assert_eq!(entry & WRITABLE, WRITABLE);
        assert_eq!(entry & USER, 0);
        assert_eq!(entry & NO_EXECUTE, NO_EXECUTE);
        assert_eq!(entry & CACHE_DISABLE, CACHE_DISABLE);
        assert_eq!(entry & ADDRESS_MASK, 0xfeb8_0000);
        assert_eq!(kernel_table_index(window, 0), Ok(300));
        assert_eq!(kernel_table_index(0x400000, 0), Err(Error::BadAddress));

        assert_eq!(
            kernel_leaf(0x400000, 0x1000, PagePermissions::KERNEL_MMIO),
            Err(Error::BadAddress)
        );
        assert_eq!(
            kernel_leaf(window + 1, 0x1000, PagePermissions::KERNEL_MMIO),
            Err(Error::BadAddress)
        );
        assert_eq!(
            kernel_leaf(window, 0x1234, PagePermissions::KERNEL_MMIO),
            Err(Error::BadAddress)
        );
        assert_eq!(
            kernel_leaf(window, 0x1000, PagePermissions::USER_READ_WRITE),
            Err(Error::BadAddress)
        );
        let writable_executable = PagePermissions {
            writable: true,
            user: false,
            executable: true,
            cache_disable: false,
        };
        assert_eq!(
            kernel_leaf(window, 0x1000, writable_executable),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn kernel_and_null_frames_are_not_leaf_targets() {
        assert_eq!(
            leaf(0, 0x1000, PagePermissions::KERNEL_READ_ONLY),
            Err(Error::BadAddress)
        );
        assert_eq!(
            leaf(
                USER_ADDRESS_LIMIT,
                0x2000,
                PagePermissions::KERNEL_READ_ONLY
            ),
            Err(Error::BadAddress)
        );
        assert_eq!(
            leaf(
                0xffff_ffff_8000_0000,
                0x2000,
                PagePermissions::KERNEL_READ_ONLY
            ),
            Err(Error::BadAddress)
        );
        assert_eq!(
            leaf(0x400000, 0, PagePermissions::USER_READ_ONLY),
            Err(Error::BadAddress)
        );
        assert_eq!(
            leaf(0x400000, 1, PagePermissions::USER_READ_ONLY),
            Err(Error::BadAddress)
        );
        assert_eq!(
            leaf(
                0x400000,
                0x0010_0000_0000_0000,
                PagePermissions::USER_READ_ONLY
            ),
            Err(Error::BadAddress)
        );
    }

    #[test]
    fn table_entries_are_present_writable_and_optional_user() {
        assert_eq!(table_entry(0x2000, true), Ok(0x2007));
        assert_eq!(table_entry(0x2000, false), Ok(0x2003));
        assert_eq!(table_entry(0, true), Err(Error::BadAddress));
        assert_eq!(table_entry(0x2001, true), Err(Error::BadAddress));
    }

    #[test]
    fn table_indices_follow_the_hardware_layout() {
        let address = 0x0000_7f12_3456_7000;
        assert_eq!(table_index(address, 0), Ok(254));
        assert_eq!(table_index(address, 1), Ok(72));
        assert_eq!(table_index(address, 2), Ok(418));
        assert_eq!(table_index(address, 3), Ok(359));
        assert_eq!(table_index(address, 4), Err(Error::BadAddress));
        assert_eq!(table_index(0, 0), Err(Error::BadAddress));
        assert_eq!(
            table_index(0x0000_7f12_3456_700f, 3),
            Ok(table_index(0x0000_7f12_3456_7000, 3).unwrap())
        );
    }

    #[test]
    fn every_user_address_indexes_within_a_table() {
        for address in [PAGE_SIZE, 0x400000, 0x7fff_ffff_f000] {
            for level in 0..LEVELS {
                let index = table_index(address, level).unwrap();
                assert!(index < ENTRIES_PER_TABLE);
            }
        }
    }

    #[test]
    fn physical_address_ignores_flags() {
        let entry = leaf(0x400000, 0xabc000, PagePermissions::USER_READ_WRITE).unwrap();
        assert_eq!(physical_address(entry), 0xabc000);
        assert_eq!(physical_address(0xdead_beef), 0xdead_b000);
    }

    #[test]
    fn leaves_expose_user_and_execute_permission() {
        let user = leaf(0x400000, 0x2000, PagePermissions::USER_READ_ONLY).unwrap();
        assert!(is_user(user));
        assert!(!is_executable(user));

        let kernel = leaf(0x400000, 0x2000, PagePermissions::KERNEL_READ_ONLY).unwrap();
        assert!(!is_user(kernel));

        let writable = leaf(0x400000, 0x2000, PagePermissions::USER_READ_WRITE).unwrap();
        assert!(is_writable(writable));
        assert!(!is_executable(writable));

        let code = leaf(0x400000, 0x3000, PagePermissions::USER_CODE).unwrap();
        assert!(is_user(code));
        assert!(is_executable(code));
        assert!(!is_writable(code));
    }

    #[test]
    fn huge_and_absent_entries_are_not_tables() {
        assert!(is_table(table_entry(0x2000, true).unwrap()));
        assert!(!is_table(0));
        assert!(!is_table(PRESENT | HUGE | 0x2000));
    }

    /// A sparse four-entry reader used to exercise the walker without memory.
    struct Sparse {
        entries: [(u64, usize, u64); 4],
    }

    impl PageTableReader for Sparse {
        fn read_entry(&self, table_frame: u64, index: usize) -> u64 {
            self.entries
                .iter()
                .find(|(frame, slot, _)| *frame == table_frame && *slot == index)
                .map_or(0, |(_, _, value)| *value)
        }
    }

    #[test]
    fn walker_resolves_a_populated_chain() {
        // 0x400000 indexes PML4[0], PDPT[0], PD[2], PT[0].
        let leaf_entry = leaf(0x400000, 0x9000, PagePermissions::USER_READ_ONLY).unwrap();
        let reader = Sparse {
            entries: [
                (0x1000, 0, table_entry(0x2000, true).unwrap()),
                (0x2000, 0, table_entry(0x3000, true).unwrap()),
                (0x3000, 2, table_entry(0x4000, true).unwrap()),
                (0x4000, 0, leaf_entry),
            ],
        };
        assert_eq!(walk(&reader, 0x1000, 0x400000), Ok(leaf_entry));
        assert_eq!(
            walk(&reader, 0x1000, 0x400fff),
            Ok(leaf_entry),
            "an address inside a mapped page must resolve"
        );
    }

    #[test]
    fn walker_reports_absent_and_unsupported_levels() {
        let missing = Sparse {
            entries: [
                (0x1000, 0, table_entry(0x2000, true).unwrap()),
                (0x2000, 0, 0),
                (0, 0, 0),
                (0, 0, 0),
            ],
        };
        assert_eq!(walk(&missing, 0x1000, 0x400000), Err(Error::NotFound));

        let huge = Sparse {
            entries: [
                (0x1000, 0, PRESENT | HUGE | 0x2000),
                (0, 0, 0),
                (0, 0, 0),
                (0, 0, 0),
            ],
        };
        assert_eq!(walk(&huge, 0x1000, 0x400000), Err(Error::Unsupported));

        let null_table = Sparse {
            entries: [(0x1000, 0, PRESENT), (0, 0, 0), (0, 0, 0), (0, 0, 0)],
        };
        assert_eq!(
            walk(&null_table, 0x1000, 0x400000),
            Err(Error::InvalidState)
        );
        assert_eq!(walk(&null_table, 0x1000, 0), Err(Error::BadAddress));
        assert_eq!(
            walk(&null_table, 0x1000, USER_ADDRESS_LIMIT),
            Err(Error::BadAddress)
        );
    }
}
