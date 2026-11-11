//! Cooperative round-robin scheduling over saved interrupt frames.
//!
//! A `yield` or `exit` syscall saves the caller's trap frame, switches CR3 to
//! the next runnable thread and lets the shared stub restore that frame, so the
//! resumed thread continues exactly where it stopped.

use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

use wuxia_core::process::Process;

use crate::gdt::{USER_CODE_SELECTOR, USER_DATA_SELECTOR};
use crate::idt::InterruptFrame;
use crate::serial;

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
    /// Process identity, address space and descriptors for this thread.
    pub process: Process<8>,
    /// Frames owned by the thread's image.
    pub frames: crate::paging::FrameTracker,
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
            process,
            frames,
        });
        write_volatile(addr_of_mut!(COUNT), count + 1);
        Some(count)
    }
}

/// Process identifier of the running thread.
pub fn process_id() -> u64 {
    current_thread().map_or(0, |thread| thread.process.id())
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

/// Whether `[address, address + length)` is mapped by the running process.
pub fn region_contains(address: u64, length: u64) -> bool {
    current_thread().is_some_and(|thread| thread.process.space().contains(address, length))
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

/// Save `frame`, switch to the next runnable thread and load its frame.
///
/// Returns false when no other thread is runnable, leaving `frame` untouched.
pub fn yield_current(frame: &mut InterruptFrame) -> bool {
    switch(frame, false)
}

/// Preempt the running thread from the timer interrupt.
///
/// Returns false when no other thread is runnable, leaving `frame` untouched.
pub fn preempt(frame: &mut InterruptFrame) -> bool {
    switch(frame, true)
}

fn switch(frame: &mut InterruptFrame, preempted: bool) -> bool {
    // SAFETY: traps are non-nesting, so the scheduler is the only writer.
    unsafe {
        let threads = &mut *addr_of_mut!(THREADS);
        let current = read_volatile(addr_of!(CURRENT));
        if let Some(thread) = threads[current].as_mut() {
            thread.frame = *frame;
        }
        let mut runnable = [false; MAX_THREADS];
        for (index, slot) in threads.iter().enumerate() {
            runnable[index] = slot.is_some_and(|thread| thread.runnable);
        }
        let Some(next) = wuxia_core::schedule::next_runnable(current, &runnable) else {
            return false;
        };
        let thread = threads[next].expect("a runnable thread exists");
        *frame = thread.frame;
        write_volatile(addr_of_mut!(CURRENT), next);
        crate::paging::activate(thread.root);
        if preempted {
            serial::write_str("WUXIA_PREEMPT_SWITCH\n");
        } else {
            serial::write_str("WUXIA_YIELD_SWITCH\n");
        }
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
        let mut runnable = [false; MAX_THREADS];
        for (index, slot) in threads.iter().enumerate() {
            runnable[index] = slot.is_some_and(|thread| thread.runnable);
        }
        let Some(next) = wuxia_core::schedule::next_runnable(current, &runnable) else {
            return false;
        };
        let thread = threads[next].expect("a runnable thread exists");
        *frame = thread.frame;
        write_volatile(addr_of_mut!(CURRENT), next);
        crate::paging::activate(thread.root);
        true
    }
}
