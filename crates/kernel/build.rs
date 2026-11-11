//! Link the no_std kernel with its x86_64 high-half linker script.

use std::path::PathBuf;

fn main() {
    let target = std::env::var("TARGET").expect("target triple");
    assert_eq!(target, "x86_64-unknown-none", "the kernel must be built for x86_64-unknown-none");
    let linker = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory")).join("linker-x86_64.ld");
    println!("cargo:rerun-if-changed=linker-x86_64.ld");
    println!("cargo:rustc-link-arg=-T{}", linker.display());
    println!("cargo:rustc-link-arg=-no-pie");
    println!("cargo:rustc-link-arg=-static");
}
