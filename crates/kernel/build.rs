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

    // Embed the ring-3 program so the kernel has no dependency on a file system.
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("out directory"));
    let embedded = out.join("user_elf.bin");
    // Build scripts run from the package directory, so resolve against the workspace.
    let workspace =
        PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest")).join("../..");
    let candidate = std::env::var_os("WUXIA_USER_ELF")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace.join("target/user/x86_64-unknown-none/debug/wuxia-user"));
    if candidate.exists() {
        fs::copy(&candidate, &embedded).expect("cannot embed the user ELF");
        println!("cargo:rerun-if-changed={}", candidate.display());
    } else {
        fs::write(&embedded, []).expect("cannot write an empty user ELF placeholder");
        println!(
            "cargo:warning=user ELF not found at {}; the boot self-test cannot run",
            candidate.display()
        );
    }
    println!("cargo:rustc-env=WUXIA_USER_ELF_PATH={}", embedded.display());
}
