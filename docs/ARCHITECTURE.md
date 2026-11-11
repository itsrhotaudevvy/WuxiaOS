# WuxiaOS architecture and status

## Objective

WuxiaOS aims to run Windows applications and drivers in a UNIX/POSIX-compatible OS, built in Rust and licensed AGPL-3.0. Windows XP-era interfaces are a staged compatibility target, not a claim that modern interfaces are interchangeable. Compatibility must be specified per Windows architecture, release and build.

## Executive and personalities

The executive owns physical memory, page tables, threads, scheduling, synchronization and object lifetimes. A process explicitly selects either `Personality::Posix` or `Personality::Nt`. Each personality owns its namespace, syscall ABI and error/status mapping. POSIX file descriptors and NT handles are not interchangeable numeric values.

NT support requires per-build syscall tables, NT object namespaces, handles, access tokens, registry keys, process/thread context, IRQL and synchronization semantics. POSIX requires file-descriptor namespaces, signals, fork-like process behavior and a separately documented syscall ABI. Shared internals do not collapse these semantics into a single lowest-common-denominator API.

## Current execution boundary

`crates/core` is `no_std` and `forbid(unsafe_code)`. It contains host-testable contracts, not an executing compatibility layer. `crates/kernel` is a real `no_std` x86_64 kernel with a Limine high-half entry, COM1 serial output, memory-map ingestion and a bootstrap bump allocator.

Paging contracts in `crates/core/src/paging.rs` validate lower-half, page-aligned user addresses and encode PML4-through-PT entries. Leaves reject the null frame, addresses beyond 52-bit physical addressing, and any writable-executable combination. These functions only produce `u64` entries; they do not dereference memory.

`crates/core/src/hhdm.rs` validates Limine's higher-half direct-map offset and performs checked physical-to-virtual and virtual-to-physical translation. The kernel uses it to zero and write allocated frames. The bootstrap builder links a PML4/PDPT/PD/PT chain for one user page in a previously absent lower-half slot, clones the active PML4 into a fresh frame, installs the subtree, and loads the clone into CR3. Because every bootloader entry is copied, the kernel image, direct map and stack remain reachable after the switch. `paging::resolve` then walks the user address through the now-active root. The kernel still does not enter CPL3: userspace transitions and syscall entry remain future work.

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

All pointers, offsets, lengths and service numbers crossing a personality boundary are untrusted. PE parsing does not map or execute images. Handle tables use generations and rights attenuation; NT status values and POSIX errors are not interchangeable. The bootstrap bump allocator has permanent ownership semantics and does not pretend to support freeing.

A future NT driver personality must preserve IRQL rules, nonpaged-memory restrictions, IRP completion ownership, cancellation and synchronization behavior. Arbitrary native drivers must not execute in the kernel address space until address-space isolation, exception containment and explicit memory protections are implemented.

## Research references

- Microsoft, *Dispatch Routines and IRQLs*: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/dispatch-routines-and-irqls
- Beck, *A Pledge and Unveil for Userland Security*: https://www.openbsd.org/papers/BeckPledgeUnveilBSDCan2018.pdf
- OpenBSD, *W^X: A New Approach to Code Page Security*: https://www.openbsd.org/papers/hackfest2015-w-xor-x.pdf
- Hunt et al., *Rethinking the Library OS from the Top Down* / Singularity sealed processes: https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/EuroSys2007_SealedProcesses.pdf

The documents above guide implementation decisions; they are not evidence that the unimplemented compatibility layers already work.
