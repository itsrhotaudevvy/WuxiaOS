//! Cooperative round-robin scheduling over saved interrupt frames.
//!
//! A `yield` or `exit` syscall saves the caller's trap frame, switches CR3 to
//! the next runnable thread and lets the shared stub restore that frame, so the
//! resumed thread continues exactly where it stopped.

use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

use wuxia_core::process::Process;

use crate::gdt::{USER_CODE_SELECTOR, USER_DATA_SELECTOR};
use crate::idt::InterruptFrame;
use crate::log::console as serial;

/// Maximum number of registered threads.
pub const MAX_THREADS: usize = 4;

/// Interrupts enabled in a synthesized user frame.
const INITIAL_RFLAGS: u64 = 0x202;

/// One runnable user thread.
#[derive(Clone, Copy, Debug)]
pub struct Thread {
    /// Physical root loaded into CR3 while the thread runs.
    pub root: u64,
    /// Saved trap frame used to resume the thread.
    pub frame: InterruptFrame,
    /// Whether the thread can still be scheduled.
    pub runnable: bool,
    /// Tick at which a sleeping thread becomes ready; zero when awake.
    pub wake_at: u64,
    /// Tick at which the thread was last resumed, so a pending timer
    /// interrupt cannot preempt it before its first instruction.
    pub resume_tick: u64,
    /// Whether the thread waits for an explicit start after boot.
    pub deferred: bool,
    /// Line written to the serial console when a deferred thread starts.
    pub start_label: &'static str,
    /// Process identity, address space and descriptors for this thread.
    pub process: Process<8>,
    /// Frames owned by the thread's image.
    pub frames: crate::paging::FrameTracker,
    /// Pledge promises for the thread's process; only ever narrowed.
    pub pledge: wuxia_core::pledge::Pledge,
}

static mut THREADS: [Option<Thread>; MAX_THREADS] = [None; MAX_THREADS];
static mut CURRENT: usize = 0;
static mut COUNT: usize = 0;

/// A zeroed frame that enters `entry` on `stack_top` at CPL3.
pub const fn initial_frame(entry: u64, stack_top: u64) -> InterruptFrame {
    InterruptFrame {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        r11: 0,
        r10: 0,
        r9: 0,
        r8: 0,
        rdi: 0,
        rsi: 0,
        rbp: 0,
        rbx: 0,
        rdx: 0,
        rcx: 0,
        rax: 0,
        vector: 0,
        error: 0,
        rip: entry,
        cs: USER_CODE_SELECTOR as u64,
        rflags: INITIAL_RFLAGS,
        rsp: stack_top,
        ss: USER_DATA_SELECTOR as u64,
    }
}

/// Register a runnable thread and return its index.
pub fn register(
    root: u64,
    entry: u64,
    stack_top: u64,
    process: Process<8>,
    frames: crate::paging::FrameTracker,
) -> Option<usize> {
    // SAFETY: bootstrap registration happens once, before ring 3 starts.
    unsafe {
        let threads = &mut *addr_of_mut!(THREADS);
        let count = read_volatile(addr_of!(COUNT));
        if count >= MAX_THREADS {
            return None;
        }
        threads[count] = Some(Thread {
            root,
            frame: initial_frame(entry, stack_top),
            runnable: true,
            wake_at: 0,
            resume_tick: 0,
            deferred: false,
            start_label: "",
            pledge: wuxia_core::pledge::Pledge::new(),
            process,
            frames,
        });
        write_volatile(addr_of_mut!(COUNT), count + 1);
        Some(count)
    }
}

/// Register a thread that starts, printing `start_label`, only after every
/// earlier thread has exited. Deferred threads start in registration order.
pub fn register_deferred(
    root: u64,
    entry: u64,
    stack_top: u64,
    process: Process<8>,
    frames: crate::paging::FrameTracker,
    start_label: &'static str,
) -> Option<usize> {
    let index = register(root, entry, stack_top, process, frames)?;
    // SAFETY: registration happens once, before ring 3 starts.
    unsafe {
        let threads = &mut *addr_of_mut!(THREADS);
        threads[index] = threads[index].map(|thread| Thread {
            runnable: false,
            deferred: true,
            start_label,
            ..thread
        });
    }
    Some(index)
}

/// Whether the running process selected the NT personality.
pub fn is_nt() -> bool {
    current_thread().is_some_and(|thread| {
        thread.process.personality() == wuxia_core::personality::Personality::Nt
    })
}

/// Process identifier of the running thread.
pub fn process_id() -> u64 {
    current_thread().map_or(0, |thread| thread.process.id())
}

/// Whether the running process's promises allow `call`.
///
/// A thread without a process (only before ring 3 starts) is not restricted.
pub fn permits(call: wuxia_core::syscall::PosixCall) -> bool {
    current_thread().is_none_or(|thread| thread.pledge.permits(call))
}

/// Narrow the running process's promise set, which can only shrink.
pub fn restrict_promises(promises: wuxia_core::pledge::Promises) -> bool {
    // SAFETY: traps are non-nesting, so the current thread is stable.
    unsafe {
        let threads = &mut *addr_of_mut!(THREADS);
        let current = read_volatile(addr_of!(CURRENT));
        threads[current]
            .as_mut()
            .is_some_and(|thread| thread.pledge.restrict(promises).is_ok())
    }
}

/// Whether the running process has `descriptor` open.
pub fn descriptor_open(descriptor: u32) -> bool {
    current_thread().is_some_and(|thread| thread.process.descriptors().is_open(descriptor))
}

/// Close a descriptor of the running process.
pub fn close_descriptor(descriptor: u32) -> bool {
    // SAFETY: traps are non-nesting and the current index is stable here.
    unsafe {
        let threads = &mut *addr_of_mut!(THREADS);
        let current = read_volatile(addr_of!(CURRENT));
        threads[current]
            .as_mut()
            .is_some_and(|thread| thread.process.descriptors_mut().close(descriptor).is_ok())
    }
}

/// Resolve a path and open it on the running process.
pub fn open_path(name: &str) -> Option<u32> {
    let file = crate::vfs::lookup(name)?;
    // SAFETY: traps are non-nesting, so the current thread is stable.
    unsafe {
        let threads = &mut *addr_of_mut!(THREADS);
        let current = read_volatile(addr_of!(CURRENT));
        threads[current]
            .as_mut()?
            .process
            .descriptors_mut()
            .open_file(file)
            .ok()
    }
}

/// File and current offset behind an open descriptor.
pub fn descriptor_file(descriptor: u32) -> Option<(wuxia_core::vfs::FileId, u64)> {
    let thread = current_thread()?;
    let descriptors = thread.process.descriptors();
    let file = descriptors.file(descriptor)?;
    Some((file, descriptors.offset(descriptor)))
}

/// Advance the read offset of an open file descriptor.
pub fn advance_descriptor(descriptor: u32, count: u64) -> bool {
    // SAFETY: traps are non-nesting, so the current thread is stable.
    unsafe {
        let threads = &mut *addr_of_mut!(THREADS);
        let current = read_volatile(addr_of!(CURRENT));
        threads[current].as_mut().is_some_and(|thread| {
            thread
                .process
                .descriptors_mut()
                .advance(descriptor, count)
                .is_ok()
        })
    }
}

/// Write into the file behind an open descriptor at its current offset.
pub fn write_file(descriptor: u32, data: &[u8]) -> Option<usize> {
    // SAFETY: traps are non-nesting, so the current thread is stable.
    unsafe {
        let threads = &mut *addr_of_mut!(THREADS);
        let current = read_volatile(addr_of!(CURRENT));
        let thread = threads[current].as_mut()?;
        let file = thread.process.descriptors().file(descriptor)?;
        let offset = thread.process.descriptors().offset(descriptor);
        let count = crate::vfs::write(file, offset, data)?;
        thread
            .process
            .descriptors_mut()
            .advance(descriptor, count as u64)
            .ok()?;
        Some(count)
    }
}

/// Reposition an open file descriptor.
pub fn seek_descriptor(descriptor: u32, offset: i64, whence: u32) -> Option<u64> {
    let (file, _) = descriptor_file(descriptor)?;
    let length = crate::vfs::len(file)?;
    // SAFETY: traps are non-nesting, so the current thread is stable.
    unsafe {
        let threads = &mut *addr_of_mut!(THREADS);
        let current = read_volatile(addr_of!(CURRENT));
        threads[current]
            .as_mut()?
            .process
            .descriptors_mut()
            .seek(descriptor, offset, whence, length)
            .ok()
    }
}

/// Return the length behind an open file descriptor.
pub fn descriptor_len(descriptor: u32) -> Option<u64> {
    crate::vfs::len(current_thread()?.process.descriptors().file(descriptor)?)
}

/// Whether `[address, address + length)` is mapped by the running process.
pub fn region_contains(address: u64, length: u64) -> bool {
    current_thread().is_some_and(|thread| thread.process.space().contains(address, length))
}

/// Map `length` anonymous writable bytes into the running process.
pub fn map_current(length: u64) -> Option<u64> {
    // SAFETY: traps are non-nesting, so the current thread is stable.
    unsafe {
        let threads = &mut *addr_of_mut!(THREADS);
        let current = read_volatile(addr_of!(CURRENT));
        let thread = threads[current].as_mut()?;
        let length = length.checked_add(wuxia_core::paging::PAGE_SIZE - 1)?
            & !(wuxia_core::paging::PAGE_SIZE - 1);
        if length == 0 {
            return None;
        }
        let address = thread.process.space().top_gap(length).ok()?;
        let root = thread.root;
        let direct_map = crate::paging::current_direct_map()?;
        let mapped = crate::memory::with_pool(|pool| {
            crate::paging::map_user_range(
                pool,
                direct_map,
                &mut thread.frames,
                root,
                address,
                length,
                wuxia_core::PagePermissions::USER_READ_WRITE,
            )
        });
        if !matches!(mapped, Some(Ok(()))) {
            return None;
        }
        thread
            .process
            .space_mut()
            .map(
                address,
                length,
                wuxia_core::PagePermissions::USER_READ_WRITE,
            )
            .ok()?;
        Some(address)
    }
}

/// Unmap a previously mapped anonymous range from the running process.
pub fn unmap_current(address: u64, length: u64) -> bool {
    // SAFETY: traps are non-nesting, so the current thread is stable.
    unsafe {
        let threads = &mut *addr_of_mut!(THREADS);
        let current = read_volatile(addr_of!(CURRENT));
        let Some(thread) = threads[current].as_mut() else {
            return false;
        };
        let Some(region) = thread.process.space().region_at(address) else {
            return false;
        };
        if region.start != address || region.length != length {
            return false;
        }
        let direct_map = match crate::paging::current_direct_map() {
            Some(direct_map) => direct_map,
            None => return false,
        };
        let root = thread.root;
        let mut released = 0u64;
        let result = crate::paging::unmap_user_range(
            direct_map,
            root,
            &mut thread.frames,
            address,
            length,
            |frame| {
                if crate::memory::free_frame(frame).is_ok() {
                    released += 1;
                }
            },
        );
        if result.is_err() || released != length / wuxia_core::paging::PAGE_SIZE {
            return false;
        }
        thread.process.space_mut().unmap(address, length).is_ok()
    }
}

/// Mark the running process exited, rejecting a second exit.
pub fn exit_process(code: u64) -> bool {
    // SAFETY: traps are non-nesting and the current index is stable here.
    unsafe {
        let threads = &mut *addr_of_mut!(THREADS);
        let current = read_volatile(addr_of!(CURRENT));
        threads[current]
            .as_mut()
            .is_some_and(|thread| thread.process.exit(code).is_ok())
    }
}

fn current_thread() -> Option<Thread> {
    // SAFETY: the thread table is written during bootstrap and by the
    // scheduler between traps; `Option<Thread>` is copied out atomically.
    unsafe {
        let threads = &*addr_of!(THREADS);
        let current = read_volatile(addr_of!(CURRENT));
        threads.get(current).copied().flatten()
    }
}

/// Clear wake deadlines that have passed.
fn refresh(threads: &mut [Option<Thread>; MAX_THREADS], now: u64) {
    for slot in threads.iter_mut() {
        if let Some(thread) = slot {
            if thread.wake_at != 0 && now >= thread.wake_at {
                thread.wake_at = 0;
            }
        }
    }
}

/// Whether each thread is ready to run now.
fn ready_flags(threads: &[Option<Thread>; MAX_THREADS]) -> [bool; MAX_THREADS] {
    let mut ready = [false; MAX_THREADS];
    for (index, slot) in threads.iter().enumerate() {
        ready[index] = slot.is_some_and(|thread| thread.runnable && thread.wake_at == 0);
    }
    ready
}

/// Wait, without spinning, until a sleeping thread's deadline passes.
///
/// Returns false when no blocked thread is left to wake.
fn idle_until_wakeup(threads: &[Option<Thread>; MAX_THREADS]) -> bool {
    let earliest = threads
        .iter()
        .flatten()
        .filter(|thread| thread.runnable && thread.wake_at != 0)
        .map(|thread| thread.wake_at)
        .min();
    let Some(earliest) = earliest else {
        return false;
    };
    while crate::interrupts::ticks() < earliest {
        // SAFETY: enabling interrupts lets the PIT arrive and halting wakes
        // on that interrupt.
        unsafe {
            core::arch::asm!(
                "sti",
                "hlt",
                "cli",
                options(nomem, nostack, preserves_flags)
            );
        }
    }
    true
}

/// Save `frame` and resume another ready thread.
///
/// Returns false when no other thread is ready, leaving `frame` untouched.
pub fn yield_current(frame: &mut InterruptFrame) -> bool {
    switch(frame, "WUXIA_YIELD_SWITCH\n")
}

/// Preempt the running thread from the timer interrupt.
///
/// Returns false when no other thread is runnable, leaving `frame` untouched.
pub fn preempt(frame: &mut InterruptFrame) -> bool {
    // SAFETY: traps are non-nesting, so the scheduler is the only writer.
    unsafe {
        let threads = &*addr_of!(THREADS);
        let current = read_volatile(addr_of!(CURRENT));
        let now = crate::interrupts::ticks();
        if threads[current].is_some_and(|thread| now <= thread.resume_tick) {
            return false;
        }
    }
    switch(frame, "WUXIA_PREEMPT_SWITCH\n")
}

/// Mark the running thread asleep until `millis` have elapsed.
///
/// Switches to another ready thread when one exists; otherwise the kernel
/// halts until the deadline and the call returns in place.
pub fn sleep_current(frame: &mut InterruptFrame, millis: u64) -> bool {
    let Some(target) = wuxia_core::schedule::deadline(
        crate::interrupts::ticks(),
        millis,
        crate::interrupts::TIMER_HZ,
    ) else {
        return false;
    };
    // SAFETY: traps are non-nesting, so the scheduler is the only writer.
    unsafe {
        let threads = &mut *addr_of_mut!(THREADS);
        let current = read_volatile(addr_of!(CURRENT));
        if let Some(thread) = threads[current].as_mut() {
            thread.wake_at = target.max(1);
        }
    }
    if switch(frame, "WUXIA_SLEEP_BLOCK\n") {
        return true;
    }
    while crate::interrupts::ticks() < target {
        // SAFETY: enabling interrupts lets the PIT arrive and halting wakes
        // on that interrupt.
        unsafe {
            core::arch::asm!(
                "sti",
                "hlt",
                "cli",
                options(nomem, nostack, preserves_flags)
            );
        }
    }
    // SAFETY: traps are non-nesting, so the scheduler is the only writer.
    unsafe {
        let threads = &mut *addr_of_mut!(THREADS);
        let current = read_volatile(addr_of!(CURRENT));
        if let Some(thread) = threads[current].as_mut() {
            thread.wake_at = 0;
        }
    }
    false
}

fn switch(frame: &mut InterruptFrame, label: &str) -> bool {
    // SAFETY: traps are non-nesting, so the scheduler is the only writer.
    unsafe {
        let threads = &mut *addr_of_mut!(THREADS);
        let current = read_volatile(addr_of!(CURRENT));
        if let Some(thread) = threads[current].as_mut() {
            thread.frame = *frame;
        }
        let now = crate::interrupts::ticks();
        refresh(threads, now);
        let ready = ready_flags(threads);
        let Some(next) = wuxia_core::schedule::next_runnable(current, &ready) else {
            return false;
        };
        let thread = threads[next].expect("a ready thread exists");
        *frame = thread.frame;
        // A saved trap frame may carry the cleared interrupt flag of the
        // syscall gate; user code must always resume with interrupts enabled.
        frame.rflags |= 0x200;
        write_volatile(addr_of_mut!(CURRENT), next);
        crate::paging::activate(thread.root);
        if let Some(thread) = threads[next].as_mut() {
            thread.resume_tick = now.saturating_add(1);
        }
        serial::write_str(label);
        serial::write_hex(next as u64);
        true
    }
}

/// Mark the running thread exited and resume the next runnable one.
///
/// Returns false when no runnable thread remains.
pub fn exit_current(frame: &mut InterruptFrame) -> bool {
    // SAFETY: traps are non-nesting, so the scheduler is the only writer.
    unsafe {
        let threads = &mut *addr_of_mut!(THREADS);
        let current = read_volatile(addr_of!(CURRENT));
        if let Some(thread) = threads[current].as_mut() {
            thread.runnable = false;
            let mut failures = 0;
            for &frame in thread.frames.frames() {
                if crate::memory::free_frame(frame).is_err() {
                    failures += 1;
                }
            }
            assert_eq!(failures, 0, "process teardown could not return every frame");
        }
        loop {
            refresh(threads, crate::interrupts::ticks());
            let ready = ready_flags(threads);
            if let Some(next) = wuxia_core::schedule::next_runnable(current, &ready) {
                let thread = threads[next].expect("a ready thread exists");
                *frame = thread.frame;
                write_volatile(addr_of_mut!(CURRENT), next);
                crate::paging::activate(thread.root);
                serial::write_str("WUXIA_WAKE_SWITCH\n");
                serial::write_hex(next as u64);
                return true;
            }
            if !idle_until_wakeup(threads) {
                let deferred = threads
                    .iter()
                    .position(|slot| slot.is_some_and(|thread| thread.deferred));
                let Some(index) = deferred else {
                    return false;
                };
                let thread = threads[index].expect("a deferred thread exists");
                *frame = thread.frame;
                frame.rflags |= 0x200;
                write_volatile(addr_of_mut!(CURRENT), index);
                crate::paging::activate(thread.root);
                if let Some(thread) = threads[index].as_mut() {
                    thread.runnable = true;
                    thread.deferred = false;
                    thread.resume_tick = crate::interrupts::ticks().saturating_add(1);
                }
                serial::write_str(thread.start_label);
                serial::write_hex(index as u64);
                return true;
            }
        }
    }
}
