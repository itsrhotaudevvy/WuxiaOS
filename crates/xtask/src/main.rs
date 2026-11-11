//! Host-side build, test, ISO and QEMU orchestration for WuxiaOS.

mod host;

use host::{HostOs, Tool};
use std::env;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// Markers every successful boot must print, in order-independent presence.
const BOOT_MARKERS: &[&str] = &[
    "WUXIA_CPU_HARDENING_OK",
    "WUXIA_WP_OK",
    "WUXIA_NX_OK",
    "WUXIA_SMEP_OK",
    "WUXIA_SMAP_OK",
    "WUXIA_UMIP_OK",
    "WUXIA_BOOT_OK",
    "WUXIA_GDT_OK",
    "WUXIA_BREAKPOINT_OK",
    "WUXIA_TIMER_OK",
    "WUXIA_SLEEP_BLOCK",
    "WUXIA_WAKE_SWITCH",
    "WUXIA_MEMORY_MAP_READY",
    "WUXIA_FRAME_ALLOC_OK",
    "WUXIA_FRAME_RECLAIM_OK",
    "WUXIA_HHDM_OK",
    "WUXIA_ELF_OK",
    "WUXIA_FS_OK",
    "WUXIA_PCI_OK",
    "WUXIA_PCI_DEVICE",
    "WUXIA_PCI_BAR",
    "WUXIA_PCI_BAR_SIZE",
    "WUXIA_PCI_COMMAND",
    "WUXIA_MMIO_OK",
    "WUXIA_MMIO_CTRL",
    "WUXIA_NET_RESET",
    "WUXIA_NET_MAC",
    "WUXIA_NET_TX_OK",
    "WUXIA_NET_RX_OK",
    "WUXIA_NET_RX_ADDRESSED",
    "WUXIA_NET_RX_SENDER",
    "WUXIA_APIC_LOCAL",
    "WUXIA_APIC_SELF_IPI",
    "WUXIA_APIC_IOAPIC",
    "WUXIA_IOAPIC_MASKED",
    "WUXIA_IRQ_DEVICE",
    "WUXIA_IRQ_OK",
    "WUXIA_DRIVER_IMAGE_OK",
    "WUXIA_DRIVER_IMPORTS",
    "WUXIA_DRIVER_PRINT",
    "WUXIA_DDI_ZERO_OK",
    "WUXIA_DDI_REJECTED",
    "WUXIA_DRIVER_ENTRY",
    "WUXIA_IRQ_LINES",
    "WUXIA_PE_IMAGE_OK",
    "WUXIA_PE_RELOCATED",
    "WUXIA_IMPORTS_OK",
    "WUXIA_USER_IMAGE_OK",
    "WUXIA_CR3_OK",
    "WUXIA_POST_SWITCH_PASS",
    "WUXIA_ENTER_USER",
    "WUXIA_SYSCALL_GETPID",
    "WUXIA_SYSCALL_REJECTED",
    "WUXIA_SYSCALL_INVALID",
    "WUXIA_SYSCALL_UNMAP",
    "WUXIA_PLEDGE_OK",
    "WUXIA_PLEDGE_DENIED",
    "PLEDGED",
    "WUXIA_UNVEIL_OK",
    "WUXIA_UNVEIL_DENIED",
    "VEILED",
    "WUXIA_TSC_OK",
    "WUXIA_CLOCK_OK",
    "CLOCKED",
    "WUXIA_SYSCALL_INVALID",
    "WUXIA_NT_QPC_OK",
    "WUXIA_NT_CREATE_OK",
    "WUXIA_NT_READ_OK",
    "WUXIA_SYSCALL_OPEN",
    "WUXIA_SYSCALL_READ",
    "WUXIA_SYSCALL_SEEK",
    "WUXIA_SYSCALL_FILE_SIZE",
    "WUXIA_SYSCALL_FILE_WRITE_OK",
    "WUXIA_SYSCALL_WRITE_OK",
    "HELLO FROM USER",
    "USER MAP",
    "hello from wuxia fs",
    "CROSS PAGE BUF",
    "WUXIA OS FILE",
    "SLEPT",
    "A SECOND PHASE",
    "SECOND PROCESS",
    "WUXIA_YIELD_SWITCH",
    "WUXIA_PREEMPT_SWITCH",
    "WUXIA_SYSCALL_EXIT",
    "WUXIA_NT_ENTER",
    "WUXIA_NT_WRITE_OK",
    "WUXIA_NT_EXIT",
    "WUXIA_TEARDOWN_OK",
    "WUXIA_TEARDOWN_REUSE_OK",
    "WUXIA_DRIVER_IMAGE_OK",
    "WUXIA_DRIVER_IMPORTS",
    "WUXIA_DRIVER_PRINT",
    "WUXIA_DDI_ZERO_OK",
    "WUXIA_DDI_REJECTED",
    "WUXIA_DRIVER_ENTRY",
    "WUXIA_FAULT_TEST",
    "WUXIA_USER_PAGE_FAULT",
    "WUXIA_USER_FAULT_KILLED",
    "WUXIA_KLOG_OK",
    "WUXIA_TEST_PASS",
];

fn main() -> ExitCode {
    let command = env::args().nth(1).unwrap_or_else(|| "help".into());
    match command.as_str() {
        "test" => run_tests(),
        "build-kernel" => build_kernel(),
        "iso" => build_iso(),
        "qemu-test" => qemu_test(),
        "qemu-run" => qemu_run(),
        "elf-info" => elf_info(),
        "ci" => ci(),
        "help" | "--help" | "-h" => {
            println!(
                "Usage: cargo run -p wuxia-xtask -- <test|build-kernel|iso|qemu-test|qemu-run|elf-info|ci>"
            );
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!(
                "unknown command {command:?}; use test, build-kernel, iso, qemu-test, qemu-run, ci"
            );
            ExitCode::FAILURE
        }
    }
}

fn run(command: &mut Command) -> bool {
    match command.status() {
        Ok(status) if status.success() => true,
        Ok(status) => {
            eprintln!("command failed: {status}");
            false
        }
        Err(error) => {
            eprintln!("cannot run command: {error}");
            false
        }
    }
}

fn run_tests() -> ExitCode {
    let mut command = Command::new("cargo");
    command.args(["test", "-p", "wuxia-core", "--target-dir", "target/test"]);
    if run(&mut command) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Parse a real ELF64 binary with the in-tree loader and print its segments.
fn elf_info() -> ExitCode {
    let path = env::args()
        .nth(2)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target/kernel/x86_64-unknown-none/debug/wuxia-kernel"));
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("read {}: {error}", path.display());
            return ExitCode::FAILURE;
        }
    };
    let elf = match wuxia_core::elf::Elf64Image::parse(&bytes) {
        Ok(elf) => elf,
        Err(error) => {
            eprintln!("parse {}: {error:?}", path.display());
            return ExitCode::FAILURE;
        }
    };
    let info = elf.info();
    println!(
        "{}: {:?}, entry {:#x}, {} program headers",
        path.display(),
        info.kind,
        info.entry,
        info.program_headers
    );
    let mut writable_and_executable = false;
    for index in 0..elf.program_header_count() {
        match elf.segment(index) {
            Ok(segment) => {
                let mode = format!(
                    "{}{}{}",
                    if segment.flags & 4 != 0 { 'r' } else { '-' },
                    if segment.is_writable() { 'w' } else { '-' },
                    if segment.is_executable() { 'x' } else { '-' },
                );
                println!(
                    "  PT_LOAD vaddr {:#x} filesz {:#x} memsz {:#x} {mode} align {:#x}",
                    segment.virtual_address, segment.file_size, segment.memory_size, segment.align
                );
                writable_and_executable |= segment.is_writable_and_executable();
            }
            Err(wuxia_core::error::Error::NotFound) => {}
            Err(error) => {
                eprintln!("  segment {index}: {error:?}");
                return ExitCode::FAILURE;
            }
        }
    }
    if writable_and_executable {
        eprintln!("writable and executable segment present: W^X violated");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// The linker for the bare-metal build and whether it is rustup's `rust-lld`.
///
/// A host without LLVM installed still has `rust-lld` in the selected
/// toolchain, so a missing `ld.lld` falls back to it instead of failing.
fn linker_tool(rustc: &str) -> (PathBuf, bool) {
    match tool(Tool::Lld) {
        host::Resolved::At(path) => (PathBuf::from(path), false),
        host::Resolved::OnPath(name) => match find_on_path(&name) {
            Some(path) => (path, false),
            None => match rust_lld(rustc) {
                Some(path) => (path, true),
                None => (PathBuf::from(name), false),
            },
        },
    }
}

/// The `rust-lld` shipped beside the selected compiler.
fn rust_lld(rustc: &str) -> Option<PathBuf> {
    let verbose = Command::new(rustc).arg("-vV").output().ok()?;
    if !verbose.status.success() {
        return None;
    }
    let host = host::host_triple_from_rustc_verbose(&String::from_utf8_lossy(&verbose.stdout))?;
    let sysroot = Command::new(rustc)
        .args(["--print", "sysroot"])
        .output()
        .ok()?;
    if !sysroot.status.success() {
        return None;
    }
    let sysroot = String::from_utf8_lossy(&sysroot.stdout).trim().to_owned();
    let path = host::rust_lld_path(&sysroot, &host, HostOs::current());
    Path::new(&path).is_file().then(|| PathBuf::from(path))
}

fn build_kernel() -> ExitCode {
    let rustc = Command::new("rustup")
        .args(["which", "rustc"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned());
    let Some(rustc) = rustc else {
        eprintln!("rustup is required to select the x86_64 kernel toolchain");
        return ExitCode::FAILURE;
    };
    let (linker, rust_lld) = linker_tool(&rustc);
    let linker = linker.to_string_lossy().into_owned();
    let rustflags = host::encoded_linker_rustflags(&linker, rust_lld);
    let mut user = Command::new("cargo");
    user.env("RUSTC", &rustc);
    user.args([
        "build",
        "-p",
        "wuxia-user",
        "--target",
        "x86_64-unknown-none",
        "--target-dir",
        "target/user",
    ]);
    user.env("CARGO_ENCODED_RUSTFLAGS", &rustflags);
    if !run(&mut user) {
        return ExitCode::FAILURE;
    }

    let mut command = Command::new("cargo");
    command.env("RUSTC", rustc);
    let user_dir = env::current_dir()
        .unwrap_or_default()
        .join("target/user/x86_64-unknown-none/debug");
    command.env("WUXIA_USER_ELF", user_dir.join("wuxia-user"));
    command.env("WUXIA_FAULT_ELF", user_dir.join("wuxia-fault"));
    command.env("WUXIA_SECOND_ELF", user_dir.join("wuxia-second"));
    command.args([
        "build",
        "-p",
        "wuxia-kernel",
        "--target",
        "x86_64-unknown-none",
        "--target-dir",
        "target/kernel",
    ]);
    command.env("CARGO_ENCODED_RUSTFLAGS", &rustflags);
    if run(&mut command) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Limine files copied into the ISO's `boot/limine` directory.
const LIMINE_BOOT_FILES: &[&str] = &[
    "limine-bios.sys",
    "limine-bios-cd.bin",
    "limine-uefi-cd.bin",
];
/// UEFI loader copied into `EFI/BOOT` on the ISO.
const LIMINE_UEFI_LOADER: &str = "BOOTX64.EFI";
/// Environment lookups for the host rules; empty values count as unset.
fn getenv(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
}

/// The directories of `PATH`, split as the host OS does.
fn path_dirs(os: HostOs) -> Vec<String> {
    env::var_os("PATH")
        .map(|value| host::split_search_path(&value.to_string_lossy(), os))
        .unwrap_or_default()
}

/// Decide how to run a host tool, including Windows install locations.
fn tool(tool: Tool) -> host::Resolved {
    let os = HostOs::current();
    host::resolve_tool(tool, os, &getenv, &path_dirs(os), |path| {
        Path::new(path).is_file()
    })
}

/// Installation data directories the host OS uses for Limine.
fn well_known_limine_dirs() -> Vec<String> {
    host::well_known_limine_dirs(HostOs::current(), &getenv)
}

/// Every Limine data file the ISO step needs, in copy order.
fn limine_required_files() -> impl Iterator<Item = &'static str> {
    LIMINE_BOOT_FILES
        .iter()
        .copied()
        .chain(std::iter::once(LIMINE_UEFI_LOADER))
}

/// One place where Limine data may live.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Candidate {
    /// How this location was obtained; shown in error messages.
    source: String,
    /// The data directory, or `None` when this step produced no location.
    dir: Option<PathBuf>,
}

#[derive(Debug, PartialEq, Eq)]
enum DiscoveryError {
    /// `WUXIA_LIMINE_DIR` is set but the directory lacks required files.
    EnvMissingFiles {
        dir: PathBuf,
        missing: Vec<&'static str>,
    },
    /// No location qualified; `tried` lists every location in checked order.
    NotFound { tried: Vec<String> },
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnvMissingFiles { dir, missing } => write!(
                f,
                "WUXIA_LIMINE_DIR={} does not contain the required Limine files: {}\n\
                 unset WUXIA_LIMINE_DIR to use automatic discovery, or point it at a \
                 directory that contains all of them",
                dir.display(),
                missing.join(", ")
            ),
            Self::NotFound { tried } => {
                writeln!(
                    f,
                    "cannot find the Limine data files ({}); locations tried, in order:",
                    limine_required_files().collect::<Vec<_>>().join(", ")
                )?;
                for line in tried {
                    writeln!(f, "  - {line}")?;
                }
                write!(
                    f,
                    "install Limine 12.x, or set WUXIA_LIMINE_DIR to the directory that holds \
                     these files, for example:\n  \
                     WUXIA_LIMINE_DIR=/path/to/limine/share/limine cargo run -p wuxia-xtask -- iso"
                )
            }
        }
    }
}

/// Names of required files that `dir` does not contain. Empty means it qualifies.
fn missing_files<F>(dir: &Path, has_file: &F) -> Vec<&'static str>
where
    F: Fn(&Path, &str) -> bool,
{
    limine_required_files()
        .filter(|&file| !has_file(dir, file))
        .collect()
}

/// Pick the Limine data directory.
///
/// An explicit `env_dir` is authoritative: if it lacks required files the
/// result is an error rather than a fallback. Otherwise the first candidate,
/// in order, that qualifies wins. `has_file(dir, name)` reports whether `dir`
/// contains the file `name`.
fn select_limine_dir<F>(
    env_dir: Option<PathBuf>,
    candidates: &[Candidate],
    has_file: F,
) -> Result<PathBuf, DiscoveryError>
where
    F: Fn(&Path, &str) -> bool,
{
    let mut tried = Vec::new();
    match env_dir {
        Some(dir) => {
            let missing = missing_files(&dir, &has_file);
            if missing.is_empty() {
                return Ok(dir);
            }
            return Err(DiscoveryError::EnvMissingFiles { dir, missing });
        }
        None => tried.push("WUXIA_LIMINE_DIR: not set".to_owned()),
    }
    for candidate in candidates {
        let Some(dir) = &candidate.dir else {
            tried.push(format!("{}: no location", candidate.source));
            continue;
        };
        let missing = missing_files(dir, &has_file);
        if missing.is_empty() {
            return Ok(dir.clone());
        }
        tried.push(format!(
            "{}: {} (missing {})",
            candidate.source,
            dir.display(),
            missing.join(", ")
        ));
    }
    Err(DiscoveryError::NotFound { tried })
}

/// Candidate order after the environment override: the `--print-datadir`
/// result, the PATH-derived location, then the well-known directories.
fn discovery_candidates(
    datadir: Candidate,
    path_binary: Candidate,
    well_known: &[String],
) -> Vec<Candidate> {
    let mut candidates = vec![datadir, path_binary];
    candidates.extend(well_known.iter().map(|dir| Candidate {
        source: "well-known location".to_owned(),
        dir: Some(PathBuf::from(dir)),
    }));
    candidates
}

/// Map `<prefix>/bin/limine` to `<prefix>/share/limine`.
fn prefix_data_dir(binary: &Path) -> Option<PathBuf> {
    host::prefix_data_dir(&binary.to_string_lossy(), HostOs::current()).map(PathBuf::from)
}

/// Ask the `limine` command for its data directory. Failure is not an error:
/// older Limine releases lack `--print-datadir`.
fn probe_datadir_command() -> Candidate {
    let dir = Command::new(tool(Tool::Limine).program())
        .arg("--print-datadir")
        .stderr(Stdio::null())
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|text| !text.is_empty())
        .map(PathBuf::from);
    Candidate {
        source: "limine --print-datadir".to_owned(),
        dir,
    }
}

/// Find the first `name` on PATH, as the shell would run it.
fn find_on_path(name: &str) -> Option<PathBuf> {
    let os = HostOs::current();
    host::find_in_dirs(name, &path_dirs(os), os, |path| Path::new(path).is_file())
        .map(PathBuf::from)
}

/// Derive the data directory from the `limine` binary on PATH.
fn probe_path_binary() -> Candidate {
    match find_on_path("limine") {
        Some(binary) => Candidate {
            source: format!("limine binary {}", binary.display()),
            dir: prefix_data_dir(&binary),
        },
        None => Candidate {
            source: "limine on PATH: not found".to_owned(),
            dir: None,
        },
    }
}

/// Discover the Limine data directory for the ISO step.
fn discover_limine_dir() -> Result<PathBuf, DiscoveryError> {
    let env_dir = env::var_os("WUXIA_LIMINE_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    let candidates = discovery_candidates(
        probe_datadir_command(),
        probe_path_binary(),
        &well_known_limine_dirs(),
    );
    select_limine_dir(env_dir, &candidates, |dir, file| dir.join(file).is_file())
}

fn build_iso() -> ExitCode {
    let source = match discover_limine_dir() {
        Ok(dir) => dir,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    if build_kernel() != ExitCode::SUCCESS {
        return ExitCode::FAILURE;
    }
    let root = PathBuf::from("target/iso-root");
    if root.exists() {
        let _ = fs::remove_dir_all(&root);
    }
    let boot = root.join("boot");
    let limine_dir = boot.join("limine");
    let efi = root.join("EFI/BOOT");
    if fs::create_dir_all(&limine_dir).is_err() {
        return ExitCode::FAILURE;
    }
    if fs::create_dir_all(&efi).is_err() {
        return ExitCode::FAILURE;
    }
    if fs::copy(
        "target/kernel/x86_64-unknown-none/debug/wuxia-kernel",
        root.join("boot/wuxia-kernel"),
    )
    .is_err()
    {
        eprintln!("kernel is not built");
        return ExitCode::FAILURE;
    }
    if fs::copy("limine.conf", root.join("boot/limine/limine.conf")).is_err() {
        eprintln!("cannot copy limine.conf");
        return ExitCode::FAILURE;
    }
    for file in LIMINE_BOOT_FILES {
        if fs::copy(source.join(file), limine_dir.join(file)).is_err() {
            eprintln!("missing Limine data files; install the limine package");
            return ExitCode::FAILURE;
        }
    }
    if fs::copy(
        source.join(LIMINE_UEFI_LOADER),
        efi.join(LIMINE_UEFI_LOADER),
    )
    .is_err()
    {
        eprintln!("cannot copy UEFI loader");
        return ExitCode::FAILURE;
    }
    let mut xorriso = Command::new(tool(Tool::Xorriso).program());
    xorriso.args([
        "-as",
        "mkisofs",
        "-b",
        "boot/limine/limine-bios-cd.bin",
        "-no-emul-boot",
        "-boot-load-size",
        "4",
        "-boot-info-table",
        "--efi-boot",
        "boot/limine/limine-uefi-cd.bin",
        "-efi-boot-part",
        "--efi-boot-image",
        "--protective-msdos-label",
        "target/iso-root",
        "-o",
        "target/wuxia.iso",
    ]);
    if !run(&mut xorriso) {
        return ExitCode::FAILURE;
    }
    let mut limine = Command::new(tool(Tool::Limine).program());
    limine.args(["bios-install", "target/wuxia.iso"]);
    if run(&mut limine) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Build the ISO, boot it headless and require every marker to appear.
fn qemu_test() -> ExitCode {
    if build_iso() != ExitCode::SUCCESS {
        return ExitCode::FAILURE;
    }
    let log = PathBuf::from("target/serial.log");
    let _ = fs::remove_file(&log);
    let serial = format!("file:{}", log.display());
    let child = Command::new(tool(Tool::Qemu).program())
        .args([
            "-M",
            "q35",
            // A CPU model with SMEP, SMAP and UMIP lets the boot exercise the
            // hardening path instead of silently skipping it.
            "-cpu",
            "max",
            "-m",
            "128M",
            "-display",
            "none",
            "-serial",
            &serial,
            "-device",
            "isa-debug-exit,iobase=0xf4,iosize=0x04",
            // A user-mode network backend, so a frame the guest sends reaches a
            // peer that answers it. Without an explicit backend the machine's
            // default NIC is present but connected to nothing, and the boot
            // cannot prove the receive path works.
            "-netdev",
            "user,id=net0",
            "-device",
            "e1000,netdev=net0",
            "-cdrom",
            "target/wuxia.iso",
            "-boot",
            "d",
            "-no-reboot",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(error) => {
            eprintln!("cannot run QEMU: {error}");
            return ExitCode::FAILURE;
        }
    };
    let status = match wait_with_timeout(&mut child, Duration::from_secs(60)) {
        Ok(status) => status,
        Err(error) => {
            eprintln!("{error}");
            let _ = child.kill();
            return ExitCode::FAILURE;
        }
    };
    let serial_text = host::normalize_serial(&fs::read(&log).unwrap_or_default());
    let missing = host::missing_markers(&serial_text, BOOT_MARKERS);
    if !missing.is_empty() {
        eprintln!("boot log is missing markers: {missing:?}");
        eprintln!("--- serial log ---\n{serial_text}");
        return ExitCode::FAILURE;
    }
    match status.code() {
        Some(33) => {
            println!("QEMU boot verified: {} markers present", BOOT_MARKERS.len());
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("QEMU test failed with status {status}");
            eprintln!("--- serial log ---\n{serial_text}");
            ExitCode::FAILURE
        }
    }
}

/// Run QEMU interactively with serial output on the terminal.
fn qemu_run() -> ExitCode {
    if build_iso() != ExitCode::SUCCESS {
        return ExitCode::FAILURE;
    }
    let mut command = Command::new(tool(Tool::Qemu).program());
    command.args([
        "-M",
        "q35",
        // Keep the interactive runner on the same CPU features as the test.
        "-cpu",
        "max",
        "-m",
        "128M",
        "-display",
        "none",
        "-serial",
        "stdio",
        "-device",
        "isa-debug-exit,iobase=0xf4,iosize=0x04",
        "-netdev",
        "user,id=net0",
        "-device",
        "e1000,netdev=net0",
        "-cdrom",
        "target/wuxia.iso",
        "-boot",
        "d",
        "-no-reboot",
    ]);
    match command.status() {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("cannot run QEMU: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Host tests followed by a self-checking boot.
fn ci() -> ExitCode {
    if run_tests() != ExitCode::SUCCESS {
        return ExitCode::FAILURE;
    }
    qemu_test()
}

fn wait_with_timeout(
    child: &mut Child,
    timeout: Duration,
) -> Result<std::process::ExitStatus, String> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() >= deadline => {
                return Err(format!("QEMU did not exit within {timeout:?}"));
            }
            Ok(None) => sleep(Duration::from_millis(100)),
            Err(error) => return Err(format!("cannot wait for QEMU: {error}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake filesystem built from per-directory entry lists.
    fn has_file_in(dirs: Vec<Vec<(PathBuf, &'static str)>>) -> impl Fn(&Path, &str) -> bool {
        let entries: Vec<(PathBuf, &'static str)> = dirs.into_iter().flatten().collect();
        move |dir, file| entries.iter().any(|(d, f)| d == dir && *f == file)
    }

    /// The files of a directory at `path`, all required files except `absent`.
    fn dir_entries(path: &str, absent: Option<&str>) -> Vec<(PathBuf, &'static str)> {
        limine_required_files()
            .filter(|f| Some(*f) != absent)
            .map(|f| (PathBuf::from(path), f))
            .collect()
    }

    /// A directory that holds every required Limine file.
    fn complete(path: &str) -> Vec<(PathBuf, &'static str)> {
        dir_entries(path, None)
    }

    /// A directory that holds every required file except `absent`.
    fn incomplete(path: &str, absent: &str) -> Vec<(PathBuf, &'static str)> {
        dir_entries(path, Some(absent))
    }

    fn at(source: &str, dir: &str) -> Candidate {
        Candidate {
            source: source.to_owned(),
            dir: Some(PathBuf::from(dir)),
        }
    }

    fn no_location(source: &str) -> Candidate {
        Candidate {
            source: source.to_owned(),
            dir: None,
        }
    }

    #[test]
    fn required_files_match_the_iso_copy_list() {
        let files: Vec<&str> = limine_required_files().collect();
        assert_eq!(
            files,
            [
                "limine-bios.sys",
                "limine-bios-cd.bin",
                "limine-uefi-cd.bin",
                "BOOTX64.EFI",
            ]
        );
    }

    #[test]
    fn qualification_requires_every_file() {
        let fs = has_file_in(vec![incomplete("/limine", "limine-uefi-cd.bin")]);
        assert_eq!(
            missing_files(Path::new("/limine"), &fs),
            ["limine-uefi-cd.bin"]
        );

        let fs = has_file_in(vec![complete("/limine")]);
        assert!(missing_files(Path::new("/limine"), &fs).is_empty());
    }

    #[test]
    fn nonexistent_directory_qualifies_as_missing_everything() {
        let fs = has_file_in(Vec::new());
        assert_eq!(
            missing_files(Path::new("/nowhere"), &fs),
            limine_required_files().collect::<Vec<_>>()
        );
    }

    #[test]
    fn env_override_wins_when_it_qualifies() {
        let fs = has_file_in(vec![complete("/env"), complete("/a")]);
        let candidates = [at("datadir", "/a")];
        let chosen = select_limine_dir(Some(PathBuf::from("/env")), &candidates, &fs);
        assert_eq!(chosen, Ok(PathBuf::from("/env")));
    }

    #[test]
    fn env_override_with_missing_file_is_a_hard_error() {
        let fs = has_file_in(vec![incomplete("/env", "BOOTX64.EFI"), complete("/a")]);
        let candidates = [at("datadir", "/a")];
        let result = select_limine_dir(Some(PathBuf::from("/env")), &candidates, &fs);
        assert_eq!(
            result,
            Err(DiscoveryError::EnvMissingFiles {
                dir: PathBuf::from("/env"),
                missing: vec!["BOOTX64.EFI"],
            })
        );
    }

    #[test]
    fn first_qualifying_candidate_wins() {
        let fs = has_file_in(vec![complete("/x"), complete("/y")]);
        let candidates = [at("first", "/x"), at("second", "/y")];
        assert_eq!(
            select_limine_dir(None, &candidates, &fs),
            Ok(PathBuf::from("/x"))
        );
    }

    #[test]
    fn non_qualifying_and_locationless_candidates_are_skipped_in_order() {
        let fs = has_file_in(vec![
            incomplete("/x", "limine-bios-cd.bin"),
            complete("/y"),
            complete("/z"),
        ]);
        let candidates = [
            at("partial", "/x"),
            no_location("nothing"),
            at("complete", "/y"),
            at("later", "/z"),
        ];
        assert_eq!(
            select_limine_dir(None, &candidates, &fs),
            Ok(PathBuf::from("/y"))
        );
    }

    #[test]
    fn not_found_lists_every_location_in_checked_order() {
        let fs = has_file_in(vec![incomplete("/p/share/limine", "BOOTX64.EFI")]);
        let candidates = [
            no_location("limine --print-datadir"),
            at("limine binary /p/bin/limine", "/p/share/limine"),
            at("well-known location", "/w"),
        ];
        let Err(DiscoveryError::NotFound { tried }) = select_limine_dir(None, &candidates, &fs)
        else {
            panic!("expected NotFound");
        };
        assert_eq!(tried.len(), 4);
        assert_eq!(tried[0], "WUXIA_LIMINE_DIR: not set");
        assert_eq!(tried[1], "limine --print-datadir: no location");
        assert_eq!(
            tried[2],
            "limine binary /p/bin/limine: /p/share/limine (missing BOOTX64.EFI)"
        );
        assert_eq!(
            tried[3],
            "well-known location: /w (missing limine-bios.sys, limine-bios-cd.bin, \
             limine-uefi-cd.bin, BOOTX64.EFI)"
        );
    }

    #[test]
    fn not_found_message_names_the_override() {
        let error = DiscoveryError::NotFound {
            tried: vec!["WUXIA_LIMINE_DIR: not set".to_owned()],
        };
        let text = error.to_string();
        assert!(text.contains("WUXIA_LIMINE_DIR"));
        assert!(text.contains("locations tried"));
    }

    #[test]
    fn candidate_order_is_datadir_then_path_then_well_known() {
        let well_known = ["/w/one".to_owned(), "/w/two".to_owned()];
        let candidates = discovery_candidates(at("datadir", "/d"), at("path", "/p"), &well_known);
        let dirs: Vec<Option<&str>> = candidates
            .iter()
            .map(|c| c.dir.as_deref().and_then(Path::to_str))
            .collect();
        assert_eq!(
            dirs,
            [Some("/d"), Some("/p"), Some("/w/one"), Some("/w/two")]
        );
        assert_eq!(candidates[0].source, "datadir");
    }

    #[test]
    fn prefix_data_dir_maps_bin_to_share() {
        assert_eq!(
            prefix_data_dir(Path::new("/opt/homebrew/bin/limine")),
            Some(PathBuf::from("/opt/homebrew/share/limine"))
        );
        assert_eq!(
            prefix_data_dir(Path::new("/usr/local/bin/limine")),
            Some(PathBuf::from("/usr/local/share/limine"))
        );
        assert_eq!(
            prefix_data_dir(Path::new("/opt/homebrew/Cellar/limine/12.9.6/bin/limine")),
            Some(PathBuf::from(
                "/opt/homebrew/Cellar/limine/12.9.6/share/limine"
            ))
        );
    }

    #[test]
    fn prefix_data_dir_rejects_binaries_outside_bin() {
        assert_eq!(prefix_data_dir(Path::new("/tmp/limine")), None);
        assert_eq!(prefix_data_dir(Path::new("limine")), None);
    }
}
