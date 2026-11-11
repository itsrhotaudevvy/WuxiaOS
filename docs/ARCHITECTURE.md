# WuxiaOS architecture and status

## Objective

WuxiaOS aims to run Windows applications and drivers in a UNIX/POSIX-compatible OS, built in Rust and licensed AGPL-3.0. Windows XP-era interfaces are a staged compatibility target, not a claim that modern interfaces are interchangeable. Compatibility must be specified per Windows architecture, release and build.

## Executive and personalities

The executive owns physical memory, page tables, threads, scheduling, synchronization and object lifetimes. A process explicitly selects either `Personality::Posix` or `Personality::Nt`. Each personality owns its namespace, syscall ABI and error/status mapping. POSIX file descriptors and NT handles are not interchangeable numeric values.

NT support requires per-build syscall tables, NT object namespaces, handles, access tokens, registry keys, process/thread context, IRQL and synchronization semantics. POSIX requires file-descriptor namespaces, signals, fork-like process behavior and a separately documented syscall ABI. Shared internals do not collapse these semantics into a single lowest-common-denominator API.

## Current execution boundary

`crates/core` is `no_std` and `forbid(unsafe_code)`. It contains host-testable contracts, not an executing compatibility layer. `crates/kernel` is a real `no_std` x86_64 kernel with a Limine high-half entry, COM1 serial output, memory-map ingestion and a bootstrap bump allocator.

Paging contracts in `crates/core/src/paging.rs` validate lower-half, page-aligned user addresses and encode PML4-through-PT entries. Leaves reject the null frame, addresses beyond 52-bit physical addressing, and any writable-executable combination. These functions only produce `u64` entries; they do not dereference memory.

`crates/core/src/hhdm.rs` validates Limine's higher-half direct-map offset and performs checked physical-to-virtual and virtual-to-physical translation. The kernel uses it to zero and write allocated frames. The bootstrap builder links a PML4/PDPT/PD/PT chain for an executable code page and a writable stack page in a previously absent lower-half slot, clones the active PML4 into a fresh frame, installs the subtree, and loads the clone into CR3. Because every bootloader entry is copied, the kernel image, direct map and stack remain reachable after the switch. `paging::resolve` then walks both user addresses through the now-active root.

Userspace runs under a round-robin scheduler: `yield` and the timer interrupt save the full trap frame (including user `rsp`/`ss`), switches CR3 to the next runnable thread and restores that thread's frame, so the shared stub resumes it exactly where it stopped. `exit` marks the current thread unrunnable and resumes the next one. Each thread owns a `Process` record, so `getpid`, descriptor lookup and exit act on the running thread rather than on a single bootstrap process. The `map` syscall chooses a page-aligned gap above every mapped region, allocates frames from the published pool, inserts 4 KiB writable leaves into the running root's existing user subtree and records the frames for teardown. The loader records every frame an image allocates (tables, leaves and root), and exit returns all of them to the published frame pool before the scheduler switches roots, so a terminated process leaks nothing and its frames are immediately reusable. The bootstrap remaps the 8259 PIC away from the exception vectors, programs the 8254 PIT for periodic IRQ0 ticks, unmasks only the timer line and waits for a bounded number of ticks before continuing; the timer handler increments a counter and acknowledges the PIC. The `wuxia-user` crate is linked at a fixed 512 GiB base and embedded into the kernel by its build script. The host-tested `LoaderPlan` parses the ELF64 program headers, rejects writable-executable segments and unaligned or out-of-range addresses, and the loader then allocates a zeroed frame per page, copies each segment's file bytes, maps read-only data, executable code and a writable stack with distinct permissions, and clones the bootloader root before entering. The kernel then enters CPL3 with `iretq` using the ring-3 code/data descriptors. A dedicated 16 KiB trap stack is installed as `TSS.RSP0`, so a ring-3 `int 0x80` arrives on kernel memory the bootstrap stack does not own. The shared stub saves all general-purpose registers, dispatches to Rust and returns with `iretq`. Syscall numbers are decoded by the host-tested `PosixRequest::decode`, which rejects unknown numbers, invalid descriptors, null buffers, oversized transfers and overflowing ranges before any pointer is used. The kernel records the process (identifier, personality, address space, lifecycle) in a host-tested `Process` model at boot and rejects any `write` buffer outside them before touching memory; accepted buffers are read through the direct map by walking the active hierarchy and checking the leaf's user bit, so a supervisor-only or absent page is refused. `write(1, …)` checks that descriptor 1 is open in the process descriptor table, forwards the bytes to the serial console and `getpid` returns the recorded identifier and `exit` moves the process to `Exited` exactly once. The kernel then starts a second embedded image that writes through an unmapped address; the page-fault handler detects the CPL3 frame, reports the error code, faulting address and instruction pointer and terminates the process without unwinding into the kernel. There is still no scheduler, no switching between multiple processes and no file system.

The bootstrap bump allocator owns a bounded normalized map and never returns a frame twice. It does not free frames; early page tables are permanent for the lifetime of bootstrap. General reclaim requires ownership and reference tracking, not simply changing the cursor backward.

## Memory and isolation roadmap

1. Discover and normalize Limine usable regions, excluding firmware, kernel, framebuffer and reserved memory.
2. Allocate distinct physical frames for page-table roots and lower-level tables.
3. Establish an explicit higher-half direct-map (HHDM) physical-to-virtual translation contract.
4. Construct x86_64 page tables with canonical-address checks, NX on writable data and no executable writable mappings.
5. Add protected userspace transitions, syscall entry and per-process address spaces.
6. Implement ELF64 and then PE32+ mapping, imports, relocations and process initialization.
7. Implement POSIX userspace services and an NT native ABI, then Win32 subsystem services.
8. Stage 32-bit PE32/WOW64 compatibility only after the x86_64 kernel, userspace and sandboxing contracts are validated.
9. Driver compatibility starts with a narrow XP-era contract in a controlled process/address-space environment before considering trusted in-kernel execution.

## Security boundaries

All pointers, offsets, lengths and service numbers crossing a personality boundary are untrusted. PE and ELF64 parsing does not map or execute images; both feed the same validated load plan, so a future NT loader inherits the same W^X, alignment and address-limit checks. Handle tables use generations and rights attenuation; NT status values and POSIX errors are not interchangeable. The bootstrap allocates physical frames from a validated pool: regions are page-aligned, the null frame and misaligned addresses are rejected, allocation is last-in-first-out and a freed frame is reused rather than leaked.

A future NT driver personality must preserve IRQL rules, nonpaged-memory restrictions, IRP completion ownership, cancellation and synchronization behavior. Arbitrary native drivers must not execute in the kernel address space until address-space isolation, exception containment and explicit memory protections are implemented.

## Research references

- Microsoft, *Dispatch Routines and IRQLs*: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/dispatch-routines-and-irqls
- Beck, *A Pledge and Unveil for Userland Security*: https://www.openbsd.org/papers/BeckPledgeUnveilBSDCan2018.pdf
- OpenBSD, *W^X: A New Approach to Code Page Security*: https://www.openbsd.org/papers/hackfest2015-w-xor-x.pdf
- Hunt et al., *Rethinking the Library OS from the Top Down* / Singularity sealed processes: https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/EuroSys2007_SealedProcesses.pdf

The documents above guide implementation decisions; they are not evidence that the unimplemented compatibility layers already work.
