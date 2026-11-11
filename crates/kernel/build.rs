//! Link the no_std kernel with its x86_64 high-half linker script.

use std::fs;
use std::path::PathBuf;

fn main() {
    let target = std::env::var("TARGET").expect("target triple");
    assert_eq!(
        target, "x86_64-unknown-none",
        "the kernel must be built for x86_64-unknown-none"
    );
    let linker = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"))
        .join("linker-x86_64.ld");
    println!("cargo:rerun-if-changed=linker-x86_64.ld");
    println!("cargo:rustc-link-arg=-T{}", linker.display());
    println!("cargo:rustc-link-arg=-no-pie");
    println!("cargo:rustc-link-arg=-static");

    // Embed the ring-3 programs so the kernel has no dependency on a file system.
    // Build scripts run from the package directory, so resolve against the workspace.
    let workspace =
        PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest")).join("../..");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("out directory"));
    let user = embed(
        &out,
        "user_elf.bin",
        "WUXIA_USER_ELF",
        &workspace.join("target/user/x86_64-unknown-none/debug/wuxia-user"),
    );
    let fault = embed(
        &out,
        "fault_elf.bin",
        "WUXIA_FAULT_ELF",
        &workspace.join("target/user/x86_64-unknown-none/debug/wuxia-fault"),
    );
    let second = embed(
        &out,
        "second_elf.bin",
        "WUXIA_SECOND_ELF",
        &workspace.join("target/user/x86_64-unknown-none/debug/wuxia-second"),
    );
    println!("cargo:rustc-env=WUXIA_USER_ELF_PATH={}", user.display());
    println!("cargo:rustc-env=WUXIA_FAULT_ELF_PATH={}", fault.display());
    println!("cargo:rustc-env=WUXIA_SECOND_ELF_PATH={}", second.display());
}

/// Copy a program into the build directory and return the embedded path.
fn embed(out: &std::path::Path, name: &str, variable: &str, default: &std::path::Path) -> PathBuf {
    let target = out.join(name);
    let candidate = std::env::var_os(variable)
        .map(PathBuf::from)
        .unwrap_or_else(|| default.to_owned());
    if candidate.exists() {
        fs::copy(&candidate, &target).expect("cannot embed the user program");
        println!("cargo:rerun-if-changed={}", candidate.display());
    } else {
        fs::write(&target, []).expect("cannot write an empty user program placeholder");
        println!(
            "cargo:warning=user program not found at {}; the boot self-test cannot run",
            candidate.display()
        );
    }
    target
}
