//! Bootstrap page tables: build a user subtree, clone the bootloader root and
//! switch CR3.
//!
//! Cloning the active PML4 keeps every bootloader mapping (kernel image, HHDM,
//! stack) reachable after the switch. Only one previously absent lower-half
//! slot is replaced, so the new root is a strict superset of the old one.

use core::arch::asm;

use wuxia_core::Error;
use wuxia_core::frames::FramePool;
use wuxia_core::hhdm::DirectMap;
use wuxia_core::load::{LoadSegment, LoaderPlan};
use wuxia_core::paging::{
    ENTRIES_PER_TABLE, PAGE_SIZE, PagePermissions, PageTableReader, USER_ADDRESS_LIMIT, is_present,
    leaf, physical_address, table_entry, table_index, walk,
};

/// Maximum `PT_LOAD` segments the bootstrap loader tracks.
pub const MAX_USER_SEGMENTS: usize = 8;

/// Maximum physical frames a single user image can own.
pub const MAX_IMAGE_FRAMES: usize = 64;

/// Records every frame an image allocation took, so teardown can return them.
#[derive(Clone, Copy, Debug)]
pub struct FrameTracker {
    frames: [u64; MAX_IMAGE_FRAMES],
    len: usize,
}

impl FrameTracker {
    /// Construct an empty tracker.
    pub const fn new() -> Self {
        Self {
            frames: [0; MAX_IMAGE_FRAMES],
            len: 0,
        }
    }

    /// Take a frame from the pool and remember it.
    fn allocate<const N: usize>(&mut self, allocator: &mut FramePool<N>) -> Result<u64, Error> {
        if self.len == MAX_IMAGE_FRAMES {
            return Err(Error::TableFull);
        }
        let frame = allocator.allocate().ok_or(Error::TableFull)?;
        self.frames[self.len] = frame;
        self.len += 1;
        Ok(frame)
    }

    /// Drop a frame that has already been returned to the pool.
    pub fn forget(&mut self, frame: u64) -> bool {
        let Some(index) = self.frames[..self.len].iter().position(|&f| f == frame) else {
            return false;
        };
        self.frames[index] = self.frames[self.len - 1];
        self.len -= 1;
        true
    }

    /// The recorded frames.
    pub fn frames(&self) -> &[u64] {
        &self.frames[..self.len]
    }
}

/// One loaded user segment and its representative leaf entry.
#[derive(Clone, Copy, Debug)]
pub struct UserSegment {
    /// Page-aligned start of the mapped range.
    pub address: u64,
    /// Length in bytes, a multiple of the page size.
    pub length: u64,
    /// Leaf entry of the first page, useful for post-switch verification.
    pub entry: u64,
    /// Permissions the range was mapped with.
    pub permissions: PagePermissions,
}

/// Details of the installed and activated user image.
#[derive(Clone, Copy, Debug)]
pub struct UserImage {
    /// Physical root that was active before the switch.
    pub old_pml4: u64,
    /// Physical root loaded into CR3.
    pub new_pml4: u64,
    /// Entry-point virtual address taken from the ELF header.
    pub entry: u64,
    /// Virtual address of the writable stack page.
    pub stack_address: u64,
    /// Encoded leaf entry for the stack page.
    pub stack_entry: u64,
    /// Loaded segments in image order.
    pub segments: [Option<UserSegment>; MAX_USER_SEGMENTS],
    /// Frames owned by this image, released when the process exits.
    pub frames: FrameTracker,
}

impl UserImage {
    /// Iterate over the loaded segments.
    pub fn segments(&self) -> impl Iterator<Item = &UserSegment> {
        self.segments.iter().flatten()
    }
}

/// Map an ELF64 executable into a fresh user subtree and load it into CR3.
///
/// Every loadable segment gets independently allocated frames, so the image
/// never aliases kernel memory. Writable and executable segments are rejected
/// by the load plan before any page is mapped.
pub fn load_user_image<const N: usize>(
    allocator: &mut FramePool<N>,
    direct_map: DirectMap,
    bytes: &[u8],
) -> Result<UserImage, Error> {
    let plan = LoaderPlan::<MAX_USER_SEGMENTS>::from_elf(bytes)?;
    load_image_plan(allocator, direct_map, &plan, bytes)
}

/// Build an address space from a PE32+ image and its validated plan.
pub fn load_pe_image<const N: usize>(
    allocator: &mut FramePool<N>,
    direct_map: DirectMap,
    bytes: &[u8],
    delta: i64,
) -> Result<UserImage, Error> {
    let plan = LoaderPlan::<MAX_USER_SEGMENTS>::from_pe(bytes)?.relocate(delta)?;
    let image = load_image_plan(allocator, direct_map, &plan, bytes)?;
    let patched = apply_pe_relocations(direct_map, image.new_pml4, bytes, delta)?;
    if delta != 0 && patched == 0 {
        // A moved image with no relocation slots can only run at its preferred
        // base, so refuse instead of handing ring 3 a pointer into nothing.
        return Err(Error::Unsupported);
    }
    Ok(image)
}

/// Map a validated plan and its file bytes into a fresh address space.
pub fn load_image_plan<const N: usize>(
    allocator: &mut FramePool<N>,
    direct_map: DirectMap,
    plan: &LoaderPlan<MAX_USER_SEGMENTS>,
    bytes: &[u8],
) -> Result<UserImage, Error> {
    let old_pml4 = read_cr3();
    let old_root = frame_pointer(direct_map, old_pml4)?;

    let first = plan.segments().next().ok_or(Error::InvalidImage)?;
    let slot = table_index(first.address, 0)?;
    if is_present(read_entry(old_root, slot)) {
        return Err(Error::AlreadyExists);
    }

    let mut tracker = FrameTracker::new();
    let pdpt = tracker.allocate(allocator)?;
    zero_frame(direct_map, pdpt)?;

    let mut segments = [None; MAX_USER_SEGMENTS];
    for (index, segment) in plan.segments().enumerate() {
        if table_index(segment.address, 0)? != slot {
            return Err(Error::Unsupported);
        }
        let pages = segment.page_count();
        let mut first_entry = 0;
        for page in 0..pages {
            let address = segment
                .address
                .checked_add(page * PAGE_SIZE)
                .ok_or(Error::OutOfRange)?;
            if table_index(address, 0)? != slot || address >= USER_ADDRESS_LIMIT {
                return Err(Error::BadAddress);
            }
            let frame = tracker.allocate(allocator)?;
            zero_frame(direct_map, frame)?;
            copy_segment_bytes(direct_map, frame, address, segment, bytes)?;
            let entry = map_page(
                allocator,
                direct_map,
                &mut tracker,
                pdpt,
                address,
                frame,
                segment.permissions,
            )?;
            if page == 0 {
                first_entry = entry;
            }
        }
        segments[index] = Some(UserSegment {
            address: segment.address,
            length: pages * PAGE_SIZE,
            entry: first_entry,
            permissions: segment.permissions,
        });
    }

    let stack_address = plan.max_end()?;
    if stack_address >= USER_ADDRESS_LIMIT || table_index(stack_address, 0)? != slot {
        return Err(Error::BadAddress);
    }
    let stack_physical = tracker.allocate(allocator)?;
    zero_frame(direct_map, stack_physical)?;
    let stack_entry = map_page(
        allocator,
        direct_map,
        &mut tracker,
        pdpt,
        stack_address,
        stack_physical,
        PagePermissions::USER_READ_WRITE,
    )?;

    let new_pml4 = tracker.allocate(allocator)?;
    zero_frame(direct_map, new_pml4)?;
    let new_root = frame_pointer(direct_map, new_pml4)?;
    for index in 0..ENTRIES_PER_TABLE {
        write_entry(new_root, index, read_entry(old_root, index));
    }
    write_entry(new_root, slot, table_entry(pdpt, true)?);

    Ok(UserImage {
        old_pml4,
        new_pml4,
        entry: plan.entry(),
        stack_address,
        stack_entry,
        segments,
        frames: tracker,
    })
}

/// Load a physical PML4 into CR3 and flush the non-global TLB.
pub fn activate(pml4: u64) {
    // SAFETY: `pml4` is a present, page-aligned root built by this module. The
    // new tree keeps every bootloader mapping, so the stack and kernel image
    // stay valid across the switch.
    unsafe {
        asm!("mov cr3, {}", in(reg) pml4, options(nostack, preserves_flags));
    }
}

/// Read the active page-table root, discarding PCID bits.
pub fn read_cr3() -> u64 {
    let value: u64;
    // SAFETY: reading CR3 has no side effects.
    unsafe {
        asm!("mov {}, cr3", out(reg) value, options(nostack, preserves_flags));
    }
    value & !0xfff
}

/// Record the bootloader direct-map offset for later syscall paths.
pub fn record_direct_map(map: DirectMap) {
    // SAFETY: written once during bootstrap before ring 3 starts.
    unsafe {
        *core::ptr::addr_of_mut!(DIRECT_MAP_OFFSET) = map.offset();
    }
}

/// Return the recorded direct map, if bootstrap recorded one.
pub fn current_direct_map() -> Option<DirectMap> {
    // SAFETY: the offset is written once before ring 3 starts.
    let offset = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DIRECT_MAP_OFFSET)) };
    if offset == 0 {
        None
    } else {
        DirectMap::new(offset).ok()
    }
}

static mut DIRECT_MAP_OFFSET: u64 = 0;

/// Base of the supervisor-only device window.
///
/// It sits in PML4 slot 300, above the direct map (slot 256) and below the
/// kernel image (slot 511), so a device mapping cannot alias either and the
/// window stays out of reach of CPL3.
pub const MMIO_BASE: u64 = 0xffff_9600_0000_0000;

/// Base of the linked kernel image, which the device window must not cover.
const KERNEL_VIRTUAL_START: u64 = 0xffff_ffff_8000_0000;

/// Size of one device window, which is also the span of one page table.
pub const MMIO_WINDOW_SIZE: u64 = 0x20_0000;

/// Map `pages` device pages into a fixed supervisor window.
///
/// `window` selects a 2 MiB-aligned slot below [`MMIO_BASE`] and `physical`
/// must be a page-aligned device base such as a PCI BAR. Leaves are writable,
/// non-executable and cache-disabled so register accesses reach the device in
/// program order. Missing intermediate tables are allocated from `allocator`
/// and zeroed through the direct map.
///
/// The mapping is installed in the active (boot) root. User roots created
/// afterwards copy the top-level entries, so the window is shared rather than
/// duplicated; a window mapped after a root was built is invisible to it.
///
/// Errors: `InvalidInput` for a zero or oversized request, `BadAddress` for an
/// unaligned base, `AlreadyExists` when the chosen slot is already mapped, and
/// `OutOfRange`/`TableFull` when a table cannot be allocated.
pub fn map_mmio<const N: usize>(
    allocator: &mut FramePool<N>,
    direct_map: DirectMap,
    window: u64,
    physical: u64,
    pages: u64,
) -> Result<u64, Error> {
    let window_pages = MMIO_WINDOW_SIZE / PAGE_SIZE;
    if pages == 0 || pages > window_pages {
        return Err(Error::InvalidInput);
    }
    if !physical.is_multiple_of(PAGE_SIZE) {
        return Err(Error::BadAddress);
    }
    let base = MMIO_BASE
        .checked_add(
            window
                .checked_mul(MMIO_WINDOW_SIZE)
                .ok_or(Error::OutOfRange)?,
        )
        .ok_or(Error::OutOfRange)?;
    if base >= KERNEL_VIRTUAL_START {
        return Err(Error::OutOfRange);
    }
    let mut table = read_cr3();
    for level in 0..3usize {
        let slot = wuxia_core::paging::kernel_table_index(base, level)?;
        let pointer = frame_pointer(direct_map, table)?;
        let entry = read_entry(pointer, slot);
        if is_present(entry) {
            if is_huge(entry) {
                return Err(Error::AlreadyExists);
            }
            table = physical_address(entry);
            continue;
        }
        let frame = allocator.allocate().ok_or(Error::OutOfRange)?;
        zero_frame(direct_map, frame)?;
        write_entry(pointer, slot, table_entry(frame, false)?);
        table = frame;
    }
    let leaves = frame_pointer(direct_map, table)?;
    for page in 0..pages {
        let address = base + page * PAGE_SIZE;
        let frame = physical + page * PAGE_SIZE;
        let slot = wuxia_core::paging::kernel_table_index(address, 3)?;
        if is_present(read_entry(leaves, slot)) {
            return Err(Error::AlreadyExists);
        }
        let entry = wuxia_core::paging::kernel_leaf(
            address,
            frame,
            wuxia_core::paging::PagePermissions::KERNEL_MMIO,
        )?;
        write_entry(leaves, slot, entry);
    }
    invalidate(base);
    Ok(base)
}

/// Apply the image's base relocations to already mapped pages.
///
/// The image was mapped at `preferred_base + delta`, so every DIR64 slot the
/// `.reloc` directory names needs `delta` added. Slots are patched through the
/// direct map, which keeps the operation independent of the page permissions
/// the plan chose, but each target must still resolve in `root`: a slot that
/// names an address the loader did not map is rejected rather than written
/// somewhere else.
///
/// Errors: `InvalidImage` for a malformed directory or a slot that straddles a
/// page, and `NotFound` for a slot outside the mapped image.
pub fn apply_pe_relocations(
    direct_map: DirectMap,
    root: u64,
    bytes: &[u8],
    delta: i64,
) -> Result<usize, Error> {
    let relocations = wuxia_core::pe_reloc::relocation_directory(bytes)?;
    if relocations.is_empty() {
        return Ok(0);
    }
    let (preferred, _) = wuxia_core::pe_common::image_base_and_size(bytes)?;
    let mut patched = 0usize;
    for slot in wuxia_core::pe_reloc::dir64_slots(relocations) {
        let rva = slot?;
        let address = preferred
            .checked_add(u64::from(rva))
            .and_then(|address| address.checked_add_signed(delta))
            .ok_or(Error::OutOfRange)?;
        if address % PAGE_SIZE > PAGE_SIZE - 8 {
            return Err(Error::InvalidImage);
        }
        let (table, index) = leaf_slot(direct_map, root, address)?;
        let entry = read_entry(table, index);
        if !is_present(entry) || is_huge(entry) {
            return Err(Error::NotFound);
        }
        let frame = physical_address(entry);
        let offset = address % PAGE_SIZE;
        let target = direct_map.physical_to_virtual(frame + offset)? as *mut u64;
        // SAFETY: the slot lies inside a mapped 4 KiB frame of the image, the
        // page tables were just validated, and traps do not nest here.
        unsafe {
            let value = target.read_volatile();
            target.write_volatile(value.wrapping_add_signed(delta));
        }
        patched += 1;
    }
    Ok(patched)
}

/// Write one 8-byte value to a mapped user address.
///
/// The address must already resolve in `root` to a writable-capable frame; the
/// write goes through the direct map so it does not depend on the leaf's
/// permission bits while the image is being prepared.
///
/// Errors: `NotFound` when the address is not mapped and `InvalidImage` when
/// the value does not fit inside one page.
pub fn write_user_u64(
    direct_map: DirectMap,
    root: u64,
    address: u64,
    value: u64,
) -> Result<(), Error> {
    if address % PAGE_SIZE > PAGE_SIZE - 8 {
        return Err(Error::InvalidImage);
    }
    let (table, index) = leaf_slot(direct_map, root, address)?;
    let entry = read_entry(table, index);
    if !is_present(entry) || is_huge(entry) {
        return Err(Error::NotFound);
    }
    let frame = physical_address(entry);
    let target = direct_map.physical_to_virtual(frame + address % PAGE_SIZE)? as *mut u64;
    // SAFETY: the slot lies inside a mapped frame of the image and the callers
    // prepare images before ring 3 can race the write.
    unsafe {
        target.write_volatile(value);
    }
    Ok(())
}

/// Write a byte range to a mapped user address.
///
/// The whole range must lie inside one page that resolves in `root`.
pub fn write_user_bytes(
    direct_map: DirectMap,
    root: u64,
    address: u64,
    bytes: &[u8],
) -> Result<(), Error> {
    let offset = address % PAGE_SIZE;
    if offset as usize + bytes.len() > PAGE_SIZE as usize {
        return Err(Error::InvalidImage);
    }
    let (table, index) = leaf_slot(direct_map, root, address)?;
    let entry = read_entry(table, index);
    if !is_present(entry) || is_huge(entry) {
        return Err(Error::NotFound);
    }
    let frame = physical_address(entry);
    let start = direct_map.physical_to_virtual(frame + offset)? as *mut u8;
    // SAFETY: the range was bounds-checked against one mapped frame.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), start, bytes.len());
    }
    Ok(())
}

/// Resolve a user address through the currently active root.
pub fn resolve(direct_map: DirectMap, virtual_address: u64) -> Result<u64, Error> {
    let reader = DirectMapReader { direct_map };
    walk(&reader, read_cr3(), virtual_address)
}

/// Whether an entry maps a large page rather than a subtable.
fn is_huge(entry: u64) -> bool {
    entry & (1 << 7) != 0
}

/// Invalidate one page-table entry in the translation lookaside buffer.
fn invalidate(address: u64) {
    // SAFETY: invlpg only affects the current address space's cached mapping.
    unsafe {
        core::arch::asm!("invlpg [{0}]", in(reg) address, options(nostack, preserves_flags));
    }
}

/// Resolve the leaf slot for `address` without changing anything.
fn leaf_slot(direct_map: DirectMap, root: u64, address: u64) -> Result<(*mut u64, usize), Error> {
    let mut table = root;
    for level in 0..3usize {
        let entry = read_entry(
            frame_pointer(direct_map, table)?,
            table_index(address, level)?,
        );
        if !is_present(entry) || is_huge(entry) {
            return Err(Error::NotFound);
        }
        table = physical_address(entry);
    }
    Ok((frame_pointer(direct_map, table)?, table_index(address, 3)?))
}

/// Clear `length` mapped pages, releasing each frame through `release`.
///
/// The caller must have validated that the range is one contiguous region of
/// the running process.
pub fn unmap_user_range(
    direct_map: DirectMap,
    root: u64,
    tracker: &mut FrameTracker,
    address: u64,
    length: u64,
    mut release: impl FnMut(u64),
) -> Result<(), Error> {
    if !address.is_multiple_of(PAGE_SIZE) || length == 0 || !length.is_multiple_of(PAGE_SIZE) {
        return Err(Error::InvalidInput);
    }
    for page in 0..length / PAGE_SIZE {
        let page_address = address
            .checked_add(page * PAGE_SIZE)
            .ok_or(Error::OutOfRange)?;
        let (table, index) = leaf_slot(direct_map, root, page_address)?;
        let entry = read_entry(table, index);
        if !is_present(entry) || is_huge(entry) {
            return Err(Error::NotFound);
        }
        write_entry(table, index, 0);
        invalidate(page_address);
        let frame = physical_address(entry);
        tracker.forget(frame);
        release(frame);
    }
    Ok(())
}

/// Map a fresh writable range into an existing user root at runtime.
///
/// The root's user subtree must already exist, as it does for a loaded process.
pub fn map_user_range<const N: usize>(
    allocator: &mut FramePool<N>,
    direct_map: DirectMap,
    tracker: &mut FrameTracker,
    root: u64,
    address: u64,
    length: u64,
    permissions: PagePermissions,
) -> Result<(), Error> {
    if !address.is_multiple_of(PAGE_SIZE)
        || length == 0
        || !length.is_multiple_of(PAGE_SIZE)
        || address >= USER_ADDRESS_LIMIT
    {
        return Err(Error::InvalidInput);
    }
    let slot = table_index(address, 0)?;
    let entry = read_entry(frame_pointer(direct_map, root)?, slot);
    if !is_present(entry) {
        return Err(Error::NotFound);
    }
    let pdpt = physical_address(entry);
    for page in 0..length / PAGE_SIZE {
        let page_address = address
            .checked_add(page * PAGE_SIZE)
            .ok_or(Error::OutOfRange)?;
        if table_index(page_address, 0)? != slot || page_address >= USER_ADDRESS_LIMIT {
            return Err(Error::BadAddress);
        }
        let frame = tracker.allocate(allocator)?;
        zero_frame(direct_map, frame)?;
        map_page(
            allocator,
            direct_map,
            tracker,
            pdpt,
            page_address,
            frame,
            permissions,
        )?;
    }
    Ok(())
}

/// Copy one frame's worth of a segment's file bytes into a physical frame.
fn copy_segment_bytes(
    direct_map: DirectMap,
    frame: u64,
    page_address: u64,
    segment: &LoadSegment,
    bytes: &[u8],
) -> Result<(), Error> {
    let segment_end = segment
        .address
        .checked_add(segment.file_size)
        .ok_or(Error::OutOfRange)?;
    let page_end = page_address + PAGE_SIZE;
    let copy_start = segment.address.max(page_address);
    let copy_end = segment_end.min(page_end);
    if copy_start >= copy_end {
        return Ok(());
    }
    let offset = (copy_start - page_address) as usize;
    let file_start = segment.file_offset + (copy_start - segment.address) as usize;
    let length = (copy_end - copy_start) as usize;
    let source = bytes
        .get(file_start..file_start + length)
        .ok_or(Error::InvalidImage)?;
    write_frame_at(direct_map, frame, offset, source)
}

/// Write bytes into a physical frame at a byte offset through the direct map.
fn write_frame_at(
    direct_map: DirectMap,
    frame: u64,
    offset: usize,
    bytes: &[u8],
) -> Result<(), Error> {
    if offset + bytes.len() > PAGE_SIZE as usize {
        return Err(Error::InvalidInput);
    }
    let destination = direct_map.physical_to_virtual(frame)? as *mut u8;
    for (index, byte) in bytes.iter().enumerate() {
        // SAFETY: the frame is a 4 KiB direct-mapped page and the bound above
        // keeps every write inside it.
        unsafe {
            destination.add(offset + index).write_volatile(*byte);
        }
    }
    Ok(())
}

/// Ensure a present subtable at `index`, allocating and zeroing one if absent.
fn ensure_table<const N: usize>(
    allocator: &mut FramePool<N>,
    direct_map: DirectMap,
    tracker: &mut FrameTracker,
    table: *mut u64,
    index: usize,
) -> Result<u64, Error> {
    let current = read_entry(table, index);
    if is_present(current) {
        return Ok(physical_address(current));
    }
    let frame = tracker.allocate(allocator)?;
    zero_frame(direct_map, frame)?;
    write_entry(table, index, table_entry(frame, true)?);
    Ok(frame)
}

/// Map one 4 KiB user page, creating intermediate tables on demand.
fn map_page<const N: usize>(
    allocator: &mut FramePool<N>,
    direct_map: DirectMap,
    tracker: &mut FrameTracker,
    pdpt: u64,
    address: u64,
    frame: u64,
    permissions: PagePermissions,
) -> Result<u64, Error> {
    let pd = ensure_table(
        allocator,
        direct_map,
        tracker,
        frame_pointer(direct_map, pdpt)?,
        table_index(address, 1)?,
    )?;
    let pt = ensure_table(
        allocator,
        direct_map,
        tracker,
        frame_pointer(direct_map, pd)?,
        table_index(address, 2)?,
    )?;
    let entry = leaf(address, frame, permissions)?;
    write_entry(
        frame_pointer(direct_map, pt)?,
        table_index(address, 3)?,
        entry,
    );
    Ok(entry)
}

fn zero_frame(direct_map: DirectMap, frame: u64) -> Result<(), Error> {
    let pointer = frame_pointer(direct_map, frame)?;
    for index in 0..ENTRIES_PER_TABLE {
        write_entry(pointer, index, 0);
    }
    Ok(())
}

fn frame_pointer(direct_map: DirectMap, frame: u64) -> Result<*mut u64, Error> {
    let virtual_address = direct_map.physical_to_virtual(frame)?;
    Ok(virtual_address as *mut u64)
}

fn write_entry(pointer: *mut u64, index: usize, value: u64) {
    // SAFETY: the frame is a 4 KiB direct-mapped table and `index` is bounded
    // by `ENTRIES_PER_TABLE`, so the write stays inside one page.
    unsafe {
        pointer.add(index).write_volatile(value);
    }
}

fn read_entry(pointer: *const u64, index: usize) -> u64 {
    // SAFETY: the frame is a 4 KiB direct-mapped table and `index` is bounded
    // by `ENTRIES_PER_TABLE`, so the read stays inside one page.
    unsafe { pointer.add(index).read_volatile() }
}

/// A [`PageTableReader`] that reads physical frames through the HHDM.
struct DirectMapReader {
    direct_map: DirectMap,
}

impl PageTableReader for DirectMapReader {
    fn read_entry(&self, table_frame: u64, index: usize) -> u64 {
        match frame_pointer(self.direct_map, table_frame) {
            Ok(pointer) => read_entry(pointer, index),
            Err(_) => 0,
        }
    }
}
