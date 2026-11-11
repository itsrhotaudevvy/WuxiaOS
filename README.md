# WuxiaOS

An experimental Rust operating-system kernel with two explicit userspace personalities: POSIX and Windows/NT. WuxiaOS is AGPL-3.0 licensed and aims for OpenBSD-inspired security discipline and Linux-inspired performance. It does **not** contain Microsoft source code and is not affiliated with Microsoft.

**Current status: bootstrap only.** The kernel boots on x86_64, discovers physical memory with Limine, and allocates distinct bootstrap frames. It cannot yet run Windows applications or drivers and is not a complete POSIX system.

## Repository layout

- `crates/core`: `no_std`, allocator-independent contracts and host tests: capabilities, PE metadata parsing, physical frames, HHDM translation, x86_64 paging encoding and a table walker, and syscall vocabulary.
- `crates/kernel`: the real `no_std` x86_64 Limine kernel, bootstrap serial console, descriptor tables, physical-memory allocator and bootstrap page-table construction.
- `crates/xtask`: host-side build, test, ISO and QEMU orchestration.
- `docs`: architecture, security, compatibility and research decisions.
- `limine.conf`: bootloader configuration.

## Verified current state

- A Limine ISO boots in QEMU and reaches the high-half kernel at `0xffffffff80000000`.
- The kernel receives Limine's physical-memory map and allocates two distinct usable frames.
- The kernel validates Limine's HHDM offset and builds a four-level page-table chain for one user page, then walks it back to confirm every entry resolves.
- `wuxia-core` paging contracts validate user virtual addresses and encode page-table and 4 KiB leaf entries with enforced W^X; CR3 is not yet loaded.
- 34 `wuxia-core` host tests pass.
- PE parsing validates container metadata only. No Windows program or driver is executed yet.
- IDT/GDT definitions are scaffolding; CPU interrupt installation and userspace transitions are not complete.
- No POSIX userspace, filesystem, scheduler, network stack, Windows application or Windows driver support exists yet.

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

To watch the kernel boot interactively:

```sh
cargo run -p wuxia-xtask -- qemu-test
```

The bootstrap kernel deliberately halts, so an interactive QEMU session does not exit on its own. Stop it with your terminal's timeout/interrupt command. A passing serial log contains:

```text
WUXIA_BOOT_OK: Limine entered the high-half kernel
WUXIA_MEMORY_MAP_READY
WUXIA_FRAME_ALLOC_OK
WUXIA_HHDM_OK
WUXIA_PAGE_TABLE_OK
WUXIA_TEST_PASS
```

On Apple Silicon Homebrew, `xtask` selects `rustup which rustc` and Homebrew LLD if present because Homebrew's compiler does not share rustup's target sysroot. Set `WUXIA_LLD` to override the linker. The build currently assumes a standard Limine installation under `/opt/homebrew/share/limine`; a portable Limine-data discovery mechanism is planned.

## Design direction

WuxiaOS has an architecture-independent executive with separate POSIX and NT personalities. POSIX and NT share objects, memory and scheduling primitives but retain their own names, status codes, handles and process semantics. Compatibility is staged: PE metadata and NT vocabulary exist; Windows application and driver execution do not yet exist.

Security design takes inspiration from OpenBSD's attack-surface reduction, least privilege, pledge/unveil-style confinement and W^X. Performance work is guided by measured Linux designs and batching/NUMA/cache behavior, not slogans. No system is "bulletproof"; security claims are tied to concrete implementation and test coverage.

## License

AGPL-3.0-only. WuxiaOS is independent work and does not contain Microsoft source code. Windows compatibility does not grant a Windows application or driver license.

## Development checkpoints

Substantive checkpoints are committed and pushed to the public `main` branch. The scheduled hourly checkpoint series begins after 10:00 local time, as requested. Empty commits and no-op changes are not used as checkpoints.
