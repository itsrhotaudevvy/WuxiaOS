# WuxiaOS

An experimental Rust operating-system kernel with two explicit userspace personalities: POSIX and Windows/NT. WuxiaOS is AGPL-3.0 licensed and aims for OpenBSD-inspired security discipline and Linux-inspired performance. It does **not** contain Microsoft source code and is not affiliated with Microsoft.

**Current status: bootstrap only.** The kernel boots on x86_64, discovers physical memory with Limine, and allocates distinct bootstrap frames. It cannot yet run Windows applications or drivers and is not a complete POSIX system.

## Repository layout

- `crates/core`: `no_std`, allocator-independent contracts and host tests: capabilities, PE and ELF64 metadata parsing, reclaimable physical frames, HHDM translation, x86_64 paging encoding, a table walker, a per-process address-space model, a process lifecycle model, a POSIX descriptor table, a validated ELF load plan, a reclaimable frame pool and syscall vocabulary. Host-tested models that the kernel does not call yet: PE32+ relocations, DIR64 relocation-slot enumeration, imports, exports, TLS, x64 exception tables and resource directories; ELF dynamic RELATIVE relocations and System V initial stacks; NT dispatcher objects, object namespace, registry, SIDs, ACL access checks, self-relative security descriptors, UNICODE_STRING encoding, per-build NT service tables and Win32 path translation; cpio/ustar boot archives; POSIX pipes, signals, credentials, resource limits, process tree and waitpid, an inode directory tree, futexes and copy-on-write bookkeeping; an unveil policy, timespec conversion; a priority scheduler policy, a timer heap, a kernel log ring, a binary buddy frame allocator, a ChaCha20 RNG with ASLR base selection, and errno/NTSTATUS mapping.
- `crates/kernel`: the real `no_std` x86_64 Limine kernel, bootstrap serial console, descriptor tables, physical-memory allocator and bootstrap page-table construction.
- `crates/xtask`: host-side build, test, ISO and QEMU orchestration.
- `docs`: architecture, security, compatibility and research decisions.
- `limine.conf`: bootloader configuration.

## Verified current state

- A Limine ISO boots in QEMU and reaches the high-half kernel at `0xffffffff80000000`.
- The kernel receives Limine's physical-memory map and allocates two distinct usable frames.
- The kernel validates Limine's HHDM offset, builds a four-level page-table chain for a user code page and stack, clones the active PML4 into a fresh root, loads that root into CR3 and re-resolves both pages through the active tables.
- `wuxia-core` paging contracts validate user virtual addresses and encode page-table and 4 KiB leaf entries with enforced W^X.
- Over 690 `wuxia-core` host tests pass, including truncation and mutation tests that drive the ELF and PE parsers with hostile images.
- PE32+ and ELF64 parsing validate container metadata, segment ranges and per-section permissions; both produce the same bounded load plan, and a hand-built PE32+ image runs under the NT personality through `NtWriteFile` and `NtTerminateProcess`. The PE32+ image is loaded at a displaced base, its DIR64 relocations are applied, and its imports are resolved by name into generated syscall stubs, so the loader is position-independent and the image calls the kernel through its import address table; PCI functions on bus 0 are enumerated, their BARs decoded, a device BAR is sized and the network function has memory decoding and bus mastering enabled, a device BAR is mapped as an uncached supervisor window, and the first driver resets the network controller, reads its station address, brings the link up and completes a transmit descriptor by DMA. No Windows driver is executed yet.
- The GDT, user segments, TSS and an IDT with CPL0/CPL3 gates are loaded; the `int3` self-test returns through the full stub path.
- A separate `wuxia-user` crate is linked at 512 GiB and embedded in the kernel. The loader parses its ELF64 program headers, allocates and zero-fills frames per segment, applies per-segment permissions and maps the entry point.
- The 8259 PIC is remapped and the 8254 PIT raises periodic IRQ0 ticks through the IDT while the bootstrap waits for a bounded number of them.
- The kernel enters CPL3 with `iretq` at the ELF entry point, rejects an out-of-region `write` pointer, copies a real message from user memory to the serial console through `write(1, …)` and ends on `exit(0)`.
- After the other embedded processes exit, a last embedded image faults on an unmapped write. The page-fault handler recognises a CPL3 fault, reports the error code, faulting address and instruction pointer, terminates only that process (logging `WUXIA_USER_FAULT_KILLED` and reclaiming its frames) and resumes the next runnable thread while the kernel stays alive.
- The bootstrap uses a reclaimable frame pool: freed frames are returned and reused, unlike the earlier one-way bump allocator.
- A round-robin scheduler switches between two user processes on `yield` and on timer preemption, saving and restoring full trap frames and CR3 roots. The next-thread decision is a host-tested core function, and each thread owns its own process (identifier, address space, descriptors), so `getpid`, `exit` and descriptor checks act on the running thread, and a process with the NT personality decodes NT service numbers instead of POSIX calls. User buffers may span pages: every chunk is resolved through the active page tables and checked for user access. A boot-time in-memory file store answers `open` and `read`, so two independent processes open files, read them and print the contents; closing a descriptor makes a later read fail, and writing through an open descriptor updates the shared file for the other process. `sleep` converts a bounded millisecond request into timer ticks and blocks: the scheduler runs another thread, the deadline is rechecked on every tick, and a process that exits while a thread sleeps waits for that thread and then resumes it. `map` and `unmap` allocate and clear anonymous pages in the running process's live page tables, invalidating the TLB and returning frames to the pool. When a thread exits, every frame its image owned is returned to the pool, and the kernel proves one is immediately reusable.
- The models listed under `crates/core` are contracts only until the kernel calls them. No POSIX userspace, hierarchical filesystem in the kernel, priority scheduling in the kernel, SMP, network stack, Windows application or Windows driver support exists yet.

## Build and test

Prerequisites:

- Rust via `rustup`, with the toolchain selected by `rust-toolchain.toml`.
- GNU `ld.lld` and `xorriso`.
- Limine 12.x binaries and `limine` command.
- QEMU (`qemu-system-x86_64`) for boot tests.
- macOS Homebrew users can install `rustup llvm limine xorriso qemu`. Set `WUXIA_LLD` to a GNU-flavor LLD if `ld.lld` is not on the PATH.

```sh
rustup show                 # install/select the committed toolchain
cargo test -p wuxia-core
cargo run -p wuxia-xtask -- iso
```

The ISO is written to `target/wuxia.iso`.

One command builds the ISO, boots it headless, checks the serial log for every required marker and fails on a missing marker, a hang or a non-zero QEMU exit:

```sh
cargo run -p wuxia-xtask -- qemu-test
```

`elf-info` parses a built ELF64 image with the in-tree loader and fails if any segment is both writable and executable. `qemu-run` builds the ISO and keeps serial output on the terminal for interactive inspection. Because the bootstrap ends with `exit(0)`, it terminates on its own; `qemu-run` is mainly useful while debugging. `ci` runs the host tests and then the self-checking boot.

A passing serial log contains:

```text
WUXIA_BOOT_OK: Limine entered the high-half kernel
WUXIA_GDT_OK
WUXIA_BREAKPOINT_OK
WUXIA_MEMORY_MAP_READY
WUXIA_FRAME_ALLOC_OK
WUXIA_HHDM_OK
WUXIA_USER_IMAGE_OK
WUXIA_CR3_OK
WUXIA_POST_SWITCH_PASS
WUXIA_ENTER_USER
WUXIA_SYSCALL_REJECTED
HELLO FROM USER
WUXIA_SYSCALL_WRITE_OK
WUXIA_SYSCALL_EXIT
WUXIA_TEST_PASS
```

On Apple Silicon Homebrew, `xtask` selects `rustup which rustc` and Homebrew LLD if present because Homebrew's compiler does not share rustup's target sysroot. Set `WUXIA_LLD` to override the linker.

`iso` locates the Limine data files (`limine-bios.sys`, `limine-bios-cd.bin`, `limine-uefi-cd.bin` and `BOOTX64.EFI`) by taking the first location that contains all of them, checked in this order:

1. `WUXIA_LIMINE_DIR`, if set. If it is set but lacks any of those files, the build fails instead of falling back.
2. The directory printed by `limine --print-datadir` (Limine 8 and later).
3. `<prefix>/share/limine`, where `<prefix>/bin/limine` is the `limine` binary found on `PATH`.
4. `/opt/homebrew/share/limine`, `/usr/local/share/limine` and `/usr/share/limine`.

If no location qualifies, the error lists every location tried. To use a Limine installation outside these locations, set `WUXIA_LIMINE_DIR` to its data directory:

```sh
WUXIA_LIMINE_DIR=/path/to/limine/share/limine cargo run -p wuxia-xtask -- iso
```

## Design direction

WuxiaOS has an architecture-independent executive with separate POSIX and NT personalities. POSIX and NT share objects, memory and scheduling primitives but retain their own names, status codes, handles and process semantics. Compatibility is staged: PE metadata and NT vocabulary exist; Windows application and driver execution do not yet exist.

Security design takes inspiration from OpenBSD's attack-surface reduction, least privilege, pledge/unveil-style confinement and W^X. Every boot enables the hardware the CPU offers: `CR0.WP`, `EFER.NXE`, `CR4.SMEP`, `CR4.SMAP` and `CR4.UMIP`, checked with CPUID before use and verified from the serial log; `qemu-test` selects `-cpu max` so those paths always run. Performance work is guided by measured Linux designs and batching/NUMA/cache behavior, not slogans. No system is "bulletproof"; security claims are tied to concrete implementation and test coverage.

## License

AGPL-3.0-only. WuxiaOS is independent work and does not contain Microsoft source code. Windows compatibility does not grant a Windows application or driver license.

## Development checkpoints

Substantive checkpoints are committed and pushed to the public `main` branch. The scheduled hourly checkpoint series begins after 10:00 local time, as requested. Empty commits and no-op changes are not used as checkpoints.
