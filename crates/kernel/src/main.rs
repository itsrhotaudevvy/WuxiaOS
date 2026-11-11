#![no_std]
#![no_main]

//! Minimal x86_64 Limine bootstrap with a headless serial console.
//!
//! This milestone proves a real high-half kernel entry. It does not yet load
//! Windows applications or drivers; those require separate ABI and mapping work.

use core::arch::asm;
use core::panic::PanicInfo;
use limine::BaseRevision;
use limine::request::{
    HhdmRequest, MemoryMapRequest, RequestsEndMarker, RequestsStartMarker, StackSizeRequest,
};

mod gdt;
mod idt;
mod interrupts;
mod memory;
mod paging;
mod user;

#[used]
#[unsafe(link_section = ".requests")]
static BASE_REVISION: BaseRevision = BaseRevision::new();

#[used]
#[unsafe(link_section = ".requests_start_marker")]
static REQUESTS_START_MARKER: RequestsStartMarker = RequestsStartMarker::new();

#[used]
#[unsafe(link_section = ".requests")]
static STACK_SIZE_REQUEST: StackSizeRequest = StackSizeRequest::new().with_size(0x100000);

#[used]
#[unsafe(link_section = ".requests")]
static MEMORY_MAP_REQUEST: MemoryMapRequest = MemoryMapRequest::new();

#[used]
#[unsafe(link_section = ".requests")]
static HHDM_REQUEST: HhdmRequest = HhdmRequest::new();

#[used]
#[unsafe(link_section = ".requests_end_marker")]
static REQUESTS_END_MARKER: RequestsEndMarker = RequestsEndMarker::new();

/// Ring-3 ELF program embedded by the build script.
static USER_ELF: &[u8] = include_bytes!(env!("WUXIA_USER_ELF_PATH"));

/// Ring-3 fault self-test embedded by the build script.
static FAULT_ELF: &[u8] = include_bytes!(env!("WUXIA_FAULT_ELF_PATH"));

/// Limine's documented kernel entry point.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    if !BASE_REVISION.is_supported() {
        panic!("Limine base revision 3 is unsupported");
    }
    serial::init();
    serial::write_str("WUXIA_BOOT_OK: Limine entered the high-half kernel\n");
    gdt::init();
    serial::write_str("WUXIA_GDT_OK\n");
    idt::self_test();
    interrupts::init(100);
    serial::write_str("WUXIA_TIMER_STARTED\n");
    interrupts::wait_for_ticks(5);
    serial::write_str("WUXIA_TIMER_OK\n");
    let response = MEMORY_MAP_REQUEST
        .get_response()
        .expect("Limine did not provide a memory map");
    let map =
        memory::from_limine::<32>(response).expect("invalid or oversized physical memory map");
    let mut allocator = memory::frame_pool::<65536, 32>(&map)
        .expect("the usable memory map exceeds the frame pool");
    let first = allocator.allocate().expect("no usable physical frame");
    assert_ne!(first, 0, "the bootstrap must not allocate the null page");
    let second = allocator
        .allocate()
        .expect("a second usable frame is required");
    assert_ne!(first, second, "frame allocator returned a duplicate");
    serial::write_str("WUXIA_MEMORY_MAP_READY\n");
    serial::write_str("WUXIA_FRAME_ALLOC_OK\n");
    serial::write_hex(first);
    serial::write_hex(second);

    let hhdm = HHDM_REQUEST
        .get_response()
        .expect("Limine did not provide a direct map");
    let direct_map = wuxia_core::DirectMap::new(hhdm.offset())
        .expect("the direct-map offset is not aligned higher-half memory");
    serial::write_str("WUXIA_HHDM_OK\n");
    serial::write_hex(direct_map.offset());
    paging::record_direct_map(direct_map);

    let image = paging::load_user_image(&mut allocator, direct_map, USER_ELF)
        .expect("cannot load the user ELF image");
    serial::write_str("WUXIA_ELF_OK\n");
    serial::write_str("WUXIA_USER_IMAGE_OK\n");
    serial::write_hex(image.old_pml4);
    serial::write_hex(image.new_pml4);
    serial::write_hex(image.entry);
    serial::write_hex(image.stack_address);
    for segment in image.segments() {
        serial::write_hex(segment.address);
    }

    let fault = paging::load_user_image(&mut allocator, direct_map, FAULT_ELF)
        .expect("cannot load the fault self-test image");

    let reclaimed = allocator.allocate().expect("no frame to reclaim");
    allocator
        .free(reclaimed)
        .expect("a freshly allocated frame is not free");
    assert_eq!(
        allocator.allocate(),
        Some(reclaimed),
        "the frame pool did not reuse a freed frame"
    );
    serial::write_str("WUXIA_FRAME_RECLAIM_OK\n");

    paging::activate(image.new_pml4);
    serial::write_str("WUXIA_CR3_OK\n");
    serial::write_hex(paging::read_cr3());

    let entry = paging::resolve(direct_map, image.entry)
        .expect("the new root does not resolve the entry point");
    for segment in image.segments() {
        let leaf = paging::resolve(direct_map, segment.address)
            .expect("the new root does not resolve a user segment");
        assert_eq!(leaf, segment.entry, "a user leaf changed after activation");
    }
    let stack_leaf = paging::resolve(direct_map, image.stack_address)
        .expect("the new root does not resolve the user stack page");
    assert_eq!(
        stack_leaf, image.stack_entry,
        "the stack leaf changed after activation"
    );
    serial::write_str("WUXIA_POST_SWITCH_PASS\n");
    serial::write_hex(entry);
    serial::write_hex(stack_leaf);

    let mut process = wuxia_core::Process::<8>::new(
        wuxia_core::process::FIRST_PROCESS_ID,
        wuxia_core::Personality::Posix,
    )
    .expect("the bootstrap process cannot be created");
    for segment in image.segments() {
        process
            .space_mut()
            .map(segment.address, segment.length, segment.permissions)
            .expect("a user segment cannot be modeled");
    }
    process
        .space_mut()
        .map(
            image.stack_address,
            u64::from(wuxia_core::paging::PAGE_SIZE),
            wuxia_core::PagePermissions::USER_READ_WRITE,
        )
        .expect("the user stack cannot be modeled");
    user::set_process(process);
    user::set_next_image(fault);
    serial::write_str("WUXIA_ENTER_USER\n");
    user::enter(
        image.entry,
        image.stack_address + u64::from(wuxia_core::paging::PAGE_SIZE) - 16,
    );
}

/// Panic handler for early bootstrap failures.
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    serial::write_str("WUXIA_TEST_FAIL: bootstrap panic\n");
    serial::debug_exit(1);
    halt_forever()
}

fn halt_forever() -> ! {
    loop {
        // SAFETY: Limine enters with interrupts disabled. `hlt` idles without
        // touching memory and returns only if a later milestone enables interrupts.
        unsafe { asm!("hlt") };
    }
}

mod serial {
    use core::arch::asm;

    const COM1: u16 = 0x3f8;

    /// Initialize the PC-compatible 16550 UART for headless diagnostics.
    pub fn init() {
        // SAFETY: COM1 is the fixed PC-compatible legacy port and this bootstrap
        // owns it before the interrupt driver exists.
        unsafe {
            outb(COM1 + 1, 0x00);
            outb(COM1 + 3, 0x80);
            outb(COM1, 0x03);
            outb(COM1 + 1, 0x00);
            outb(COM1 + 3, 0x03);
            outb(COM1 + 2, 0xc7);
            outb(COM1 + 4, 0x0b);
        }
    }

    /// Write a physical address as hexadecimal with a trailing newline.
    pub fn write_hex(value: u64) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        write_str("0x");
        for shift in (0..16).rev() {
            let digit = ((value >> (shift * 4)) & 0xf) as usize;
            put_byte(HEX[digit]);
        }
        write_str("\n");
    }

    /// Write a string to the legacy COM1 port, including CRLF line endings.
    /// Signal the QEMU isa-debug-exit device with a test result.
    pub fn debug_exit(value: u8) {
        // SAFETY: The debug-exit device is configured by the test harness.
        unsafe { outb(0xf4, value) };
    }

    pub fn write_str(text: &str) {
        for byte in text.bytes() {
            if byte == b'\n' {
                put_byte(b'\r');
            }
            put_byte(byte);
        }
    }

    /// Write one raw byte, used when forwarding an untrusted user buffer.
    pub fn write_byte(byte: u8) {
        put_byte(byte);
    }

    fn put_byte(byte: u8) {
        // SAFETY: The bootstrap owns COM1; no interrupt handler races this write.
        unsafe { outb(COM1, byte) };
    }

    unsafe fn outb(port: u16, value: u8) {
        // SAFETY: x86_64 port I/O is used only for known 16550 registers.
        unsafe {
            asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
        }
    }
}
