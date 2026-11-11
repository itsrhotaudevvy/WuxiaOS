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

mod cpu;
mod gdt;
mod idt;
mod imports;
mod interrupts;
mod log;
mod memory;
mod net;
mod paging;
mod pci;
mod sched;
mod time;
mod user;
mod vfs;

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

/// Second scheduler participant embedded by the build script.
static SECOND_ELF: &[u8] = include_bytes!(env!("WUXIA_SECOND_ELF_PATH"));

/// Minimal PE32+ program exercised through the NT personality.
static PE_IMAGE: &[u8] = include_bytes!(env!("WUXIA_PE_IMAGE_PATH"));

/// Highest displacement the PE self-test image is mapped away from its base.
const PE_DISPLACEMENT_WINDOW: u64 = 0x40_0000;

/// Limine's documented kernel entry point.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    if !BASE_REVISION.is_supported() {
        panic!("Limine base revision 3 is unsupported");
    }
    serial::init();
    log::write_str("WUXIA_BOOT_OK: Limine entered the high-half kernel\n");
    gdt::init();
    log::write_str("WUXIA_GDT_OK\n");
    let hardening = cpu::harden();
    log::write_str("WUXIA_CPU_HARDENING_OK\n");
    log::write_hex(hardening.bits());
    if hardening.write_protect {
        log::write_str("WUXIA_WP_OK\n");
    }
    if hardening.no_execute {
        log::write_str("WUXIA_NX_OK\n");
    }
    if hardening.smep {
        log::write_str("WUXIA_SMEP_OK\n");
    }
    if hardening.smap {
        log::write_str("WUXIA_SMAP_OK\n");
    }
    if hardening.umip {
        log::write_str("WUXIA_UMIP_OK\n");
    }
    idt::self_test();
    interrupts::init(interrupts::TIMER_HZ as u32);
    log::write_str("WUXIA_TIMER_STARTED\n");
    interrupts::wait_for_ticks(5);
    log::write_str("WUXIA_TIMER_OK\n");
    let frequency = time::calibrate().expect("the timestamp counter cannot be calibrated");
    log::write_str("WUXIA_TSC_OK\n");
    log::write_hex(frequency.hertz());
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
    log::write_str("WUXIA_MEMORY_MAP_READY\n");
    log::write_str("WUXIA_FRAME_ALLOC_OK\n");
    log::write_hex(first);
    log::write_hex(second);

    let hhdm = HHDM_REQUEST
        .get_response()
        .expect("Limine did not provide a direct map");
    let direct_map = wuxia_core::DirectMap::new(hhdm.offset())
        .expect("the direct-map offset is not aligned higher-half memory");
    log::write_str("WUXIA_HHDM_OK\n");
    log::write_hex(direct_map.offset());
    paging::record_direct_map(direct_map);

    let mut network = None;
    let devices = pci::enumerate(|function| {
        log::write_str("WUXIA_PCI_DEVICE\n");
        log::write_hex(u64::from(function.vendor));
        log::write_hex(u64::from(function.device_id));
        log::write_hex(u64::from(function.class));
        for bar in pci::bars(function).into_iter().flatten() {
            log::write_str("WUXIA_PCI_BAR\n");
            log::write_hex(u64::from(bar.is_io));
            log::write_hex(bar.base);
        }
        for index in 0..8u8 {
            if let Some(size) = pci::size_bar(function, index) {
                log::write_str("WUXIA_PCI_BAR_SIZE\n");
                log::write_hex(u64::from(index));
                log::write_hex(size);
            }
        }
        if network.is_none() && function.class == pci::CLASS_NETWORK {
            network = pci::mmio_base(function);
            if let Some((before, after)) = pci::enable(function) {
                log::write_str("WUXIA_PCI_COMMAND\n");
                log::write_hex(u64::from(before));
                log::write_hex(u64::from(after));
            }
        }
    });
    log::write_str("WUXIA_PCI_OK\n");
    log::write_hex(devices as u64);
    if let Some(physical) = network {
        // The register file spans more than one page: transmit descriptors and
        // the receive address registers are several pages into BAR0.
        let pages = u64::from(wuxia_core::net::BAR_SIZE) / wuxia_core::paging::PAGE_SIZE;
        let window = paging::map_mmio(&mut allocator, direct_map, 0, physical, pages)
            .expect("the network device window cannot be mapped");
        log::write_str("WUXIA_MMIO_OK\n");
        log::write_hex(window);
        let device = net::Device::new(window);
        log::write_str("WUXIA_MMIO_CTRL\n");
        log::write_hex(u64::from(
            device.control().expect("the controller has no CTRL"),
        ));
        device.reset().expect("the controller does not leave reset");
        log::write_str("WUXIA_NET_RESET\n");
        log::write_hex(u64::from(
            device.control().expect("the controller has no CTRL"),
        ));
        let mac = device.mac().expect("the controller has no station address");
        log::write_str("WUXIA_NET_MAC\n");
        for word in wuxia_core::net::mac_words(mac) {
            log::write_hex(u64::from(word));
        }
        let link = device
            .bring_up()
            .expect("the controller does not answer the link request");
        log::write_str("WUXIA_NET_LINK\n");
        log::write_hex(u64::from(link));
        log::write_hex(u64::from(
            device.status().expect("the controller has no STATUS"),
        ));

        // A broadcast frame with a locally administered ethertype. Nothing
        // answers it; the point is that the transmit engine fetched the
        // descriptor and the frame and reported completion.
        let mut frame = [0u8; wuxia_core::net::MIN_FRAME];
        frame[..6].fill(0xff);
        frame[6..12].copy_from_slice(&mac);
        frame[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
        frame[14..19].copy_from_slice(b"wuxia");
        match device.transmit(&mut allocator, direct_map, &frame) {
            Ok(descriptor) => {
                log::write_str("WUXIA_NET_TX_OK\n");
                log::write_hex(u64::from(descriptor[12]));
                log::write_hex(u64::from(descriptor[11]));
            }
            Err(error) => {
                log::write_str("WUXIA_NET_TX_FAILED\n");
                log::write_hex(error as u64);
            }
        }

        // Ask the emulated network stack for the gateway's hardware address. A
        // reply proves the receive ring, the descriptor handshake and the frame
        // buffers, not just the transmit engine.
        let request = wuxia_core::net::arp_request(mac, [10, 0, 2, 15], [10, 0, 2, 2]);
        let mut padded = [0u8; wuxia_core::net::MIN_FRAME];
        padded[..request.len()].copy_from_slice(&request);
        device
            .transmit(&mut allocator, direct_map, &padded)
            .expect("the address-resolution request cannot be sent");
        let mut received = [0u8; wuxia_core::net::MAX_FRAME];
        match device.receive(&mut allocator, direct_map, &mut received) {
            Ok(length) => {
                log::write_str("WUXIA_NET_RX_OK\n");
                log::write_hex(length as u64);
                let ethertype = u16::from_be_bytes([received[12], received[13]]);
                log::write_hex(u64::from(ethertype));
                let operation = u16::from_be_bytes([received[20], received[21]]);
                log::write_hex(u64::from(operation));
                // The reply must be addressed to this controller, which is the
                // only claim about its contents worth making here.
                let reply_is_addressed_to_us = received[..6] == mac;
                log::write_str("WUXIA_NET_RX_ADDRESSED\n");
                log::write_hex(u64::from(reply_is_addressed_to_us));
                // The sender protocol address names the peer that answered.
                log::write_str("WUXIA_NET_RX_SENDER\n");
                log::write_hex(u64::from(u32::from_be_bytes([
                    received[28],
                    received[29],
                    received[30],
                    received[31],
                ])));
            }
            Err(error) => {
                log::write_str("WUXIA_NET_RX_FAILED\n");
                log::write_hex(error as u64);
            }
        }
    }

    let image = paging::load_user_image(&mut allocator, direct_map, USER_ELF)
        .expect("cannot load the user ELF image");
    log::write_str("WUXIA_ELF_OK\n");
    log::write_str("WUXIA_USER_IMAGE_OK\n");
    log::write_hex(image.old_pml4);
    log::write_hex(image.new_pml4);
    log::write_hex(image.entry);
    log::write_hex(image.stack_address);
    for segment in image.segments() {
        log::write_hex(segment.address);
    }

    let fault = paging::load_user_image(&mut allocator, direct_map, FAULT_ELF)
        .expect("cannot load the fault self-test image");

    let second = paging::load_user_image(&mut allocator, direct_map, SECOND_ELF)
        .expect("cannot load the second process image");

    let reclaimed = allocator.allocate().expect("no frame to reclaim");
    allocator
        .free(reclaimed)
        .expect("a freshly allocated frame is not free");
    assert_eq!(
        allocator.allocate(),
        Some(reclaimed),
        "the frame pool did not reuse a freed frame"
    );
    log::write_str("WUXIA_FRAME_RECLAIM_OK\n");

    let pe_delta = pe_displacement();
    let mut pe = paging::load_pe_image(&mut allocator, direct_map, PE_IMAGE, pe_delta)
        .expect("the PE self-test image cannot be loaded");
    log::write_str("WUXIA_PE_IMAGE_OK\n");
    log::write_hex(pe.entry);
    log::write_str("WUXIA_PE_RELOCATED\n");
    log::write_hex(pe_delta as u64);
    log::write_hex(pe.entry);
    let imports = imports::resolve(&mut allocator, direct_map, &mut pe, PE_IMAGE, pe_delta)
        .expect("the PE self-test image has an import that cannot be resolved");
    log::write_str("WUXIA_IMPORTS_OK\n");
    log::write_hex(imports as u64);
    memory::install_pool(allocator);

    let mut files = vfs::KernelFs::new();
    assert!(
        files.create("hello", b"hello from wuxia fs\n").is_ok(),
        "the bootstrap file cannot be created"
    );
    assert!(
        files.create("motd", b"WuxiaOS files\n").is_ok(),
        "the second bootstrap file cannot be created"
    );
    vfs::install(files);
    let mut probe = [0u8; 32];
    assert!(
        matches!(
            vfs::read(wuxia_core::vfs::FileId(0), 0, &mut probe),
            Some(20)
        ),
        "the bootstrap file cannot be read back"
    );
    log::write_str("WUXIA_FS_OK\n");

    paging::activate(image.new_pml4);
    log::write_str("WUXIA_CR3_OK\n");
    log::write_hex(paging::read_cr3());

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
    log::write_str("WUXIA_POST_SWITCH_PASS\n");
    log::write_hex(entry);
    log::write_hex(stack_leaf);

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

    let mut second_process = wuxia_core::Process::<8>::new(2, wuxia_core::Personality::Posix)
        .expect("the second process cannot be created");
    for segment in second.segments() {
        second_process
            .space_mut()
            .map(segment.address, segment.length, segment.permissions)
            .expect("a second-process segment cannot be modeled");
    }
    second_process
        .space_mut()
        .map(
            second.stack_address,
            u64::from(wuxia_core::paging::PAGE_SIZE),
            wuxia_core::PagePermissions::USER_READ_WRITE,
        )
        .expect("the second-process stack cannot be modeled");

    let mut pe_process = wuxia_core::Process::<8>::new(3, wuxia_core::Personality::Nt)
        .expect("the PE process cannot be created");
    for segment in pe.segments() {
        pe_process
            .space_mut()
            .map(segment.address, segment.length, segment.permissions)
            .expect("a PE segment cannot be modeled");
    }
    pe_process
        .space_mut()
        .map(
            pe.stack_address,
            u64::from(wuxia_core::paging::PAGE_SIZE),
            wuxia_core::PagePermissions::USER_READ_WRITE,
        )
        .expect("the PE stack cannot be modeled");

    let stack_top = image.stack_address + u64::from(wuxia_core::paging::PAGE_SIZE) - 16;
    let second_stack_top = second.stack_address + u64::from(wuxia_core::paging::PAGE_SIZE) - 16;
    let mut fault_process = wuxia_core::Process::<8>::new(4, wuxia_core::Personality::Posix)
        .expect("the fault process cannot be created");
    for segment in fault.segments() {
        fault_process
            .space_mut()
            .map(segment.address, segment.length, segment.permissions)
            .expect("a fault-process segment cannot be modeled");
    }
    fault_process
        .space_mut()
        .map(
            fault.stack_address,
            u64::from(wuxia_core::paging::PAGE_SIZE),
            wuxia_core::PagePermissions::USER_READ_WRITE,
        )
        .expect("the fault-process stack cannot be modeled");

    let pe_stack_top = pe.stack_address + u64::from(wuxia_core::paging::PAGE_SIZE) - 16;
    let fault_stack_top = fault.stack_address + u64::from(wuxia_core::paging::PAGE_SIZE) - 16;
    assert_eq!(
        sched::register(
            image.new_pml4,
            image.entry,
            stack_top,
            process,
            image.frames
        ),
        Some(0),
        "the bootstrap thread cannot be registered"
    );
    assert!(
        sched::register(
            second.new_pml4,
            second.entry,
            second_stack_top,
            second_process,
            second.frames
        )
        .is_some(),
        "the second thread cannot be registered"
    );
    assert!(
        sched::register_deferred(
            pe.new_pml4,
            pe.entry,
            pe_stack_top,
            pe_process,
            pe.frames,
            "WUXIA_NT_ENTER\n"
        )
        .is_some(),
        "the PE thread cannot be registered"
    );
    // Registered last so it starts only after the PE thread has exited, and
    // a CPL3 fault in it terminates only this process.
    assert!(
        sched::register_deferred(
            fault.new_pml4,
            fault.entry,
            fault_stack_top,
            fault_process,
            fault.frames,
            "WUXIA_FAULT_TEST\n"
        )
        .is_some(),
        "the fault thread cannot be registered"
    );
    sched::activate_first_stack();
    log::write_str("WUXIA_ENTER_USER\n");
    user::enter(image.entry, stack_top);
}

/// Choose a page-aligned displacement for the PE self-test image.
///
/// The image is mapped away from its preferred base so the relocations the
/// build emits are exercised on every boot, and the displacement is drawn from
/// a ChaCha20 stream seeded with the invariant timestamp counter so two boots
/// differ.
///
/// This is address-space layout randomisation as a mechanism, not yet as a
/// security boundary: a TSC seed is observable but not secret, and the
/// bootstrap has no hardware entropy source to reseed from. It is documented
/// here and in `docs/ARCHITECTURE.md` so nobody mistakes it for an ASLR
/// guarantee.
fn pe_displacement() -> i64 {
    if wuxia_core::pe_common::image_base_and_size(PE_IMAGE).is_err() {
        return 0;
    }
    let mut seed = [0u8; 32];
    for chunk in seed.chunks_mut(8) {
        // SAFETY: reading the timestamp counter has no side effects.
        let ticks = unsafe { core::arch::x86_64::_rdtsc() };
        chunk.copy_from_slice(&ticks.to_le_bytes());
    }
    let mut rng = wuxia_core::random::ChaChaRng::from_seed(seed);
    let slots = PE_DISPLACEMENT_WINDOW / wuxia_core::paging::PAGE_SIZE;
    let slot = match rng.below(slots) {
        Ok(slot) => slot,
        Err(_) => return 0,
    };
    (slot as i64) * (wuxia_core::paging::PAGE_SIZE as i64)
}

/// Panic handler for early bootstrap failures.
#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    serial::write_str("WUXIA_TEST_FAIL: bootstrap panic\n");
    if let Some(location) = info.location() {
        serial::write_str("WUXIA_PANIC_AT\n");
        log::write_hex(location.line() as u64);
        log::write_hex(location.column() as u64);
    }
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
