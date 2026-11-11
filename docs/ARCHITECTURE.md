# WuxiaOS architecture and status

## Objective

WuxiaOS aims to run Windows applications and drivers in a UNIX/POSIX-compatible OS, built in Rust and licensed AGPL-3.0. Windows XP-era interfaces are a staged compatibility target, not a claim that modern interfaces are interchangeable. Compatibility must be specified per Windows architecture, release and build.

## Executive and personalities

The executive owns physical memory, page tables, threads, scheduling, synchronization and object lifetimes. A process explicitly selects either `Personality::Posix` or `Personality::Nt`. Each personality owns its namespace, syscall ABI and error/status mapping. POSIX file descriptors and NT handles are not interchangeable numeric values.

Current state: the personality is recorded per process, and an NT thread decodes NT service numbers. Separate namespaces and handle spaces are not implemented. The NT calls in the kernel index the same per-process descriptor table as the POSIX calls, so an NT handle and a POSIX descriptor are the same number today. The separation described above is the target.

NT support requires per-build syscall tables, NT object namespaces, handles, access tokens, registry keys, process/thread context, IRQL and synchronization semantics. POSIX requires file-descriptor namespaces, signals, fork-like process behavior and a separately documented syscall ABI. Shared internals do not collapse these semantics into a single lowest-common-denominator API.

## Current execution boundary

The sub-sections describe the bootstrap kernel as it runs today. Anything not described here is not implemented.

### Core and kernel split

`crates/core` is `no_std` and `forbid(unsafe_code)`. It holds host-testable contracts, not an executing compatibility layer. `crates/kernel` is a `no_std` x86_64 kernel with a Limine high-half entry, COM1 serial output, memory-map ingestion, a reclaimable frame pool, and a set of embedded test images. The kernel calls `wuxia_core` for validation and bookkeeping. The core modules it does not call are listed in the section "Host-tested models not yet used by the kernel".

### Boot and paging

- `crates/core/src/paging.rs` validates lower-half, page-aligned user addresses and encodes PML4-through-PT entries. Leaf entries reject the null frame, physical addresses beyond 52-bit physical addressing, and any writable-executable combination. These functions only produce `u64` entries and do not dereference memory.
- `crates/core/src/hhdm.rs` validates Limine's higher-half direct-map offset and performs checked physical-to-virtual and virtual-to-physical translation. The kernel uses it to zero and write frames and to walk page tables.
- `crates/kernel/src/paging.rs` builds a PML4/PDPT/PD/PT chain for an image's segments and stack inside one previously absent lower-half PML4 slot; a present slot is refused. It clones the active PML4 into a fresh frame, installs the subtree and loads the clone into CR3. Every bootloader entry is copied, so the kernel image, direct map and stack remain reachable after the switch. `paging::resolve` then walks the entry point, each segment and the stack through the active root.
- Boot runs an `int3` self-test through the full trap stub, remaps the 8259 PIC away from the exception vectors, programs the 8254 PIT at 100 Hz, unmasks only IRQ0 and waits for five ticks before continuing. The timer handler increments a counter and acknowledges the PIC.
- Kernel log lines are stored in a static `wuxia_core::klog` ring and mirrored to COM1 by `crates/kernel/src/log.rs`.

### User entry and syscalls

- The kernel build script embeds four test images: `wuxia-user`, which is linked at a fixed 512 GiB base (`0x8000000000`), `wuxia-fault`, `wuxia-second`, and a hand-built PE32+ image.
- `crates/core/src/load.rs` builds a `LoaderPlan` from an ELF64 or PE32+ image. Planning rejects writable-executable segments, unaligned or out-of-range addresses, and an entry point outside an executable segment. The kernel loader then allocates a zeroed frame per page, copies each segment's file bytes, and maps read-only data, executable code and a writable stack with distinct permissions.
- `user::enter` returns to CPL3 with `iretq` on the ring-3 code and data selectors. It pushes RFLAGS `0x202`, so the first user thread runs with interrupts enabled and the timer can preempt it even if it never traps. The scheduler's switch path also forces IF on in the frame it restores. The TSS `RSP0` points to a dedicated 16 KiB trap stack, so a ring-3 `int 0x80` or interrupt arrives on kernel memory that the bootstrap stack does not own. The shared stub saves all general-purpose registers, dispatches to Rust and returns with `iretq`.
- Syscall numbers are decoded by `wuxia_core::syscall::PosixRequest::decode`, which rejects unknown numbers and malformed arguments before the kernel dereferences any pointer.
- POSIX calls implemented in the kernel: `getpid`, `yield`, `sleep`, `exit`, `open`, `read`, `write`, `seek`, file size, `close`, `map`, `unmap` and `pledge`.
- `pledge` narrows the process's promise set through `wuxia_core::pledge::Pledge`, which can only shrink. The dispatcher checks `wuxia_core::pledge::required` for the decoded call before running it, so a dropped promise turns the call into a logged `WUXIA_PLEDGE_DENIED` and `u64::MAX`; `exit` and a further `pledge` are always permitted. The embedded user image narrows to `stdio rpath`, proves `map` is then refused, writes after the restriction, drops every promise and exits.
- NT calls implemented for threads of the NT personality: `NtWriteFile` (handle 1 only), `NtClose`, `NtAllocateVirtualMemory` and `NtTerminateProcess`. `NtReadFile` returns `NOT_IMPLEMENTED`.
- `write` on a descriptor that is not open, or on a buffer outside the process's modeled regions, is rejected before any memory is touched. Accepted buffers are copied through the direct map after walking the active hierarchy. Each leaf must have its user bit set, and copies into user memory also need the writable bit, so supervisor-only or absent pages are refused. Descriptors 1 and 2 go to the serial console; other descriptors write to the file store.
- A page fault raised from CPL3 terminates only the faulting process. The handler prints the error code, faulting address and instruction pointer, then exits the process through the same path as `exit`: it logs `WUXIA_USER_FAULT_KILLED`, reclaims the process's frames and resumes the next runnable thread. When no thread is left, the run ends with the same teardown and `WUXIA_TEST_PASS` as a normal exit, and QEMU exits through the debug-exit port. A page fault at CPL0 still halts. The fault self-test image stores to unmapped address `0x1000`; it is the last deferred thread, so it starts only after every other thread has exited.

### Scheduling

- The scheduler is round-robin over saved trap frames. A `yield`, a timer tick from CPL3, a `sleep` or an `exit` saves the running frame, selects the next runnable thread with `wuxia_core::schedule::next_runnable`, loads that thread's CR3 root and restores its frame with interrupts enabled. A thread is not preempted in the tick in which it was resumed.
- Up to four threads (`MAX_THREADS`) are registered at boot; no syscall creates processes or threads at run time. Each thread owns a `Process<8>` with its own identifier, personality, address space and descriptor table, so `getpid`, descriptor lookups and `exit` act on the running thread.
- Two POSIX threads start runnable. Two threads are registered deferred, the NT thread and then the fault self-test, and each starts only after the threads before it have exited.
- `sleep` converts milliseconds to timer ticks, rounding up, and marks the thread with a wake tick. Another thread runs if one is ready; otherwise the kernel halts until the deadline. A process that exits while a thread sleeps waits for that thread and then resumes it.
- `exit` marks the process `Exited` through the host-tested `Process` model. A second exit is rejected. The thread's frames are then reclaimed (see below).
- Not implemented: priority scheduling in the kernel (`wuxia_core::priority` is host-tested only), SMP, and any blocking I/O beyond `sleep`.

### Memory reclaim

- The kernel allocates physical frames from `wuxia_core::frames::FramePool<65536>` (`crates/kernel/src/memory.rs`). Its regions come from Limine's `USABLE` entries, page-aligned and normalized. The pool is last-in-first-out, rejects the null and misaligned frames, and rejects frees of frames it does not own or that are already free.
- Each image's `FrameTracker` records every frame the image takes: PDPT, page tables, leaves, stack and root, up to 64 per image. When a thread exits, its recorded frames return to the pool before the next root is loaded. Once no runnable thread remains, the kernel allocates and frees one frame to confirm that the pool can reuse returned frames.
- `map` takes zeroed frames from the pool, records them and maps 4 KiB writable leaves above every existing mapping. `unmap` requires the exact range of one mapped region, clears its leaves, invalidates each page with `invlpg` and returns the frames to the pool. An access to the range afterwards faults.
- Limits: page-table frames of an unmapped region stay allocated until the thread exits. A process killed by a page fault has its frames reclaimed like an exiting one. `region::BumpAllocator` (which cannot free frames) remains in `crates/core` for its own tests only; the kernel does not use it.

### Files

- The kernel holds one boot-time, flat, in-memory store (`crates/kernel/src/vfs.rs`, `wuxia_core::vfs::MemFs<4, 512>`): room for four files and 512 bytes of contents. It is populated before ring 3 starts with `hello` and `motd`, and every process shares it.
- POSIX `open`, `read`, `write`, `seek`, file size and `close` operate on per-process descriptors with per-process offsets over the shared contents. A write may extend a file only when that file ends the used data area; otherwise the write is clipped to the current length.
- Userspace cannot create, delete or rename files, and there are no directories. The inode directory tree in `wuxia_core::dirtree` is host-tested only.
- Nothing is persisted across boots.

## Host-tested models not yet used by the kernel

The following `crates/core` modules have host tests but no reference in `crates/kernel`. Each was checked with `grep -rn "wuxia_core::<module>" crates/kernel`, which found no match for any of them. Some of them are reached only through a type that the kernel does call: `Process` owns `AddressSpace` and `DescriptorTable`, `LoaderPlan` parses ELF through `elf` and PE through `image`, and `wuxia_core::Error` is defined in `error`. Those five modules (`address_space`, `descriptor`, `elf`, `image`, `error`) run in the kernel and are not listed here.

- Image formats and loader support: `elf_reloc` (ELF dynamic RELATIVE relocations), `initstack` (System V initial stacks), `pe_export`, `pe_import`, `pe_pdata`, `pe_reloc` (including DIR64 slot enumeration) and `pe_resource` (resource directories), `pe_tls`, and `initramfs` (cpio `newc`/`crc` and ustar archives). The `pe_*` modules reference only each other, so the kernel cannot reach them.
- `security_descriptor` (self-relative `SECURITY_DESCRIPTOR` read/write over the ACL, SID and token models) and `nt_service` (per-build NT service tables).
- NT object model and names: `acl`, `dispatcher`, `dospath`, `nt_string`, `object_namespace`, `path`, `registry`, `security_descriptor` and `sid`.
- POSIX process and I/O: `credentials`, `cow` (copy-on-write bookkeeping), `dirtree`, `futex`, `pipe`, `proctree`, `rlimit` and `signal`.
- Policy and capabilities: `capability` (generational handle tables with rights attenuation) and `unveil`. `pledge` is enforced in the kernel; `unveil` is not.
- Status codes: `errno` (errno and NTSTATUS mapping).
- Scheduling, time and services: `priority`, `timer` and `random` (ChaCha20 RNG with ASLR base selection).
- Memory: `memory`, a bounded frame pool that the kernel superseded with `frames`, and `buddy`, a binary buddy allocator over seeded page-frame regions.

## Memory and isolation roadmap

1. Discover and normalize Limine usable regions, excluding firmware, kernel, framebuffer and reserved memory. *Status:* done for the bootstrap; only Limine `USABLE` entries are kept.
2. Allocate distinct physical frames for page-table roots and lower-level tables. *Status:* done; every frame is tracked per image and returned on exit.
3. Establish an explicit higher-half direct-map (HHDM) physical-to-virtual translation contract. *Status:* done.
4. Construct x86_64 page tables with canonical-address checks, NX on writable data and no executable writable mappings. *Status:* done for user mappings built by the loader and `map`.
5. Add protected userspace transitions, syscall entry and per-process address spaces. *Status:* implemented in bootstrap form: CPL3 entry, `int 0x80`, and one CR3 root per thread.
6. Implement ELF64 and then PE32+ mapping, imports, relocations and process initialization. *Status:* ELF64 and a hand-built PE32+ image are mapped and run. The kernel does not apply imports, relocations or TLS.
7. Implement POSIX userspace services and an NT native ABI, then Win32 subsystem services. *Status:* not started beyond the kernel-side syscall subsets listed above. There are no POSIX userspace services and no Win32 subsystem.
8. Stage 32-bit PE32/WOW64 compatibility only after the x86_64 kernel, userspace and sandboxing contracts are validated. *Status:* not started.
9. Driver compatibility starts with a narrow XP-era contract in a controlled process/address-space environment before considering trusted in-kernel execution. *Status:* not started.

## Security boundaries

The kernel does not trust the bootloader's control-register state. `crates/kernel/src/cpu.rs` enables every hardening feature the CPU advertises before ring 3 starts and logs the result: `CR0.WP` so supervisor writes honor read-only leaves, `EFER.NXE` so the loader's no-execute data pages actually fault, `CR4.SMEP` so the kernel cannot fetch from a user page, `CR4.SMAP` so the kernel cannot touch a user page by accident, and `CR4.UMIP` so ring 3 cannot read descriptor-table state. User buffers are only copied through the direct map, whose leaves are supervisor pages, so SMAP leaves the copy helpers intact while blocking stray dereferences of user virtual addresses. The trap stack carries a guard word (`WUXIA_TRAP_STACK_OVERFLOW`) because scheduler helpers work with multi-KiB thread records. `qemu-test` runs with `-cpu max` so these paths are exercised on every checkpoint rather than skipped. POSIX confinement is enforced twice: `pledge` promises in the syscall dispatcher and an `unveil` visibility table in the store lookup.

All pointers, offsets, lengths and service numbers crossing a personality boundary are untrusted. PE and ELF64 parsing does not map or execute images; both feed the same validated load plan, so a future NT loader inherits the same W^X, alignment and address-limit checks. The host-tested capability tables in `wuxia_core::capability` use generations and rights attenuation, but the kernel does not use them yet. NT status values and POSIX errors are not interchangeable. The bootstrap allocates physical frames from a validated pool: regions are page-aligned, the null frame and misaligned addresses are rejected, allocation is last-in-first-out and a freed frame is reused rather than leaked.

A future NT driver personality must preserve IRQL rules, nonpaged-memory restrictions, IRP completion ownership, cancellation and synchronization behavior. Arbitrary native drivers must not execute in the kernel address space until address-space isolation, exception containment and explicit memory protections are implemented.

## Research references

- Microsoft, *Dispatch Routines and IRQLs*: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/dispatch-routines-and-irqls
- Beck, *A Pledge and Unveil for Userland Security*: https://www.openbsd.org/papers/BeckPledgeUnveilBSDCan2018.pdf
- OpenBSD, *W^X: A New Approach to Code Page Security*: https://www.openbsd.org/papers/hackfest2015-w-xor-x.pdf
- Hunt et al., *Rethinking the Library OS from the Top Down* / Singularity sealed processes: https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/EuroSys2007_SealedProcesses.pdf

The documents above guide implementation decisions; they are not evidence that the unimplemented compatibility layers already work.
