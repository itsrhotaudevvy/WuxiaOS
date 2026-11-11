//! Place the user program at a fixed low-half virtual base.

use std::path::PathBuf;

fn main() {
    let script = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"))
        .join("user-x86_64.ld");
    println!("cargo:rerun-if-changed=user-x86_64.ld");
    println!("cargo:rustc-link-arg=-T{}", script.display());
    println!("cargo:rustc-link-arg=-no-pie");
    println!("cargo:rustc-link-arg=-static");
    println!("cargo:rustc-link-arg=--build-id=none");
}
