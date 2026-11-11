//! Host-side build, test, ISO and QEMU orchestration for WuxiaOS.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let command = env::args().nth(1).unwrap_or_else(|| "help".into());
    match command.as_str() {
        "test" => run_tests(),
        "build-kernel" => build_kernel(),
        "iso" => build_iso(),
        "qemu-test" => qemu_test(),
        "help" | "--help" | "-h" => {
            println!("Usage: cargo run -p wuxia-xtask -- <test|build-kernel|iso|qemu-test>");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("unknown command {command:?}; use test, build-kernel, iso, qemu-test");
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
    let mut command = Command::new("cargo");
    command.env("RUSTC", rustc);
    command.args([
        "build",
        "-p",
        "wuxia-kernel",
        "--target",
        "x86_64-unknown-none",
        "--target-dir",
        "target/kernel",
    ]);
    let lld = env::var("WUXIA_LLD").unwrap_or_else(|_| {
        if Path::new("/opt/homebrew/bin/ld.lld").exists() {
            "/opt/homebrew/bin/ld.lld".into()
        } else {
            "ld.lld".into()
        }
    });
    command.env("RUSTFLAGS", format!("-C linker={lld}"));
    if run(&mut command) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn build_iso() -> ExitCode {
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
    let source = PathBuf::from(
        env::var("WUXIA_LIMINE_DIR").unwrap_or_else(|_| "/opt/homebrew/share/limine".into()),
    );
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
    for file in [
        "limine-bios.sys",
        "limine-bios-cd.bin",
        "limine-uefi-cd.bin",
    ] {
        if fs::copy(source.join(file), limine_dir.join(file)).is_err() {
            eprintln!("missing Limine data files; install the limine package");
            return ExitCode::FAILURE;
        }
    }
    if fs::copy(source.join("BOOTX64.EFI"), efi.join("BOOTX64.EFI")).is_err() {
        eprintln!("cannot copy UEFI loader");
        return ExitCode::FAILURE;
    }
    let mut xorriso = Command::new("xorriso");
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
    let mut limine = Command::new("limine");
    limine.args(["bios-install", "target/wuxia.iso"]);
    if run(&mut limine) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn qemu_test() -> ExitCode {
    let mut command = Command::new("qemu-system-x86_64");
    command.args(["-display", "none"]);
    command.args([
        "-M",
        "q35",
        "-m",
        "128M",
        "-display",
        "none",
        "-serial",
        "stdio",
        "-device",
        "isa-debug-exit,iobase=0xf4,iosize=0x04",
        "-cdrom",
        "target/wuxia.iso",
        "-boot",
        "d",
        "-no-reboot",
    ]);
    match command.status() {
        Ok(status) if status.code() == Some(33) => ExitCode::SUCCESS,
        Ok(status) => {
            eprintln!("QEMU test failed with status {status}");
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("cannot run QEMU: {error}");
            ExitCode::FAILURE
        }
    }
}
