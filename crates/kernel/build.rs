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
    let pe = write_pe_image(&out);
    println!("cargo:rustc-env=WUXIA_PE_IMAGE_PATH={}", pe.display());
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

/// Write a minimal PE32+ image: a read-only code section that opens a store
/// file through the NT services, reads it, echoes it to the console and then
/// terminates the process, plus a writable data section as the read target.
fn write_pe_image(out: &std::path::Path) -> PathBuf {
    let target = out.join("pe_image.bin");
    let mut image = vec![0u8; 0x600];

    image[0..2].copy_from_slice(b"MZ");
    image[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());

    image[0x40..0x44].copy_from_slice(b"PE\0\0");
    image[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
    // Two sections: .text and a writable .data used as the read buffer.
    image[0x46..0x48].copy_from_slice(&2u16.to_le_bytes());
    image[0x54..0x56].copy_from_slice(&240u16.to_le_bytes());
    image[0x56..0x58].copy_from_slice(&0x22u16.to_le_bytes());

    let optional = 0x58;
    image[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
    // SizeOfCode, then SizeOfInitializedData.
    image[optional + 4..optional + 8].copy_from_slice(&0x200u32.to_le_bytes());
    image[optional + 8..optional + 12].copy_from_slice(&0x200u32.to_le_bytes());
    image[optional + 16..optional + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    image[optional + 20..optional + 24].copy_from_slice(&0x1000u32.to_le_bytes());
    image[optional + 24..optional + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
    // SectionAlignment, FileAlignment.
    image[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    image[optional + 36..optional + 40].copy_from_slice(&0x200u32.to_le_bytes());
    image[optional + 40..optional + 42].copy_from_slice(&6u16.to_le_bytes());
    image[optional + 48..optional + 50].copy_from_slice(&6u16.to_le_bytes());
    // SizeOfImage covers both sections.
    image[optional + 56..optional + 60].copy_from_slice(&0x3000u32.to_le_bytes());
    image[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
    image[optional + 68..optional + 70].copy_from_slice(&3u16.to_le_bytes());
    image[optional + 72..optional + 80].copy_from_slice(&0x10_0000u64.to_le_bytes());
    image[optional + 80..optional + 88].copy_from_slice(&0x1000u64.to_le_bytes());
    image[optional + 88..optional + 96].copy_from_slice(&0x10_0000u64.to_le_bytes());
    image[optional + 96..optional + 104].copy_from_slice(&0x1000u64.to_le_bytes());

    let section = optional + 240;
    image[section..section + 5].copy_from_slice(b".text");
    image[section + 8..section + 12].copy_from_slice(&0x200u32.to_le_bytes());
    image[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    image[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
    image[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
    // IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE.
    image[section + 36..section + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

    let data = section + 40;
    image[data..data + 5].copy_from_slice(b".data");
    image[data + 8..data + 12].copy_from_slice(&0x200u32.to_le_bytes());
    image[data + 12..data + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    image[data + 16..data + 20].copy_from_slice(&0x200u32.to_le_bytes());
    image[data + 20..data + 24].copy_from_slice(&0x400u32.to_le_bytes());
    // IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA.
    image[data + 36..data + 40].copy_from_slice(&0xc000_0040u32.to_le_bytes());

    // NtCreateFile(&name), NtReadFile(handle, data, 0x40),
    // NtWriteFile(1, data, bytes_read), NtTerminateProcess(0).
    let code: [u8; 88] = [
        0x48, 0xc7, 0xc0, 0x34, 0x00, 0x00, 0x00, // mov rax, 0x34 (NtCreateFile)
        0x48, 0x8d, 0x3d, 0xf2, 0x00, 0x00, 0x00, // lea rdi, [rip + 0xf2]
        0xcd, 0x80, // int 0x80
        0x49, 0x89, 0xc4, // mov r12, rax
        0x48, 0xc7, 0xc0, 0x06, 0x00, 0x00, 0x00, // mov rax, 6 (NtReadFile)
        0x4c, 0x89, 0xe7, // mov rdi, r12
        0x48, 0x8d, 0x35, 0xdc, 0x0f, 0x00, 0x00, // lea rsi, [rip + 0xfdc]
        0x48, 0xc7, 0xc2, 0x40, 0x00, 0x00, 0x00, // mov rdx, 0x40
        0xcd, 0x80, // int 0x80
        0x49, 0x89, 0xc5, // mov r13, rax
        0x48, 0xc7, 0xc0, 0x08, 0x00, 0x00, 0x00, // mov rax, 8 (NtWriteFile)
        0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00, // mov rdi, 1
        0x48, 0x8d, 0x35, 0xbb, 0x0f, 0x00, 0x00, // lea rsi, [rip + 0xfbb]
        0x4c, 0x89, 0xea, // mov rdx, r13
        0xcd, 0x80, // int 0x80
        0x48, 0xc7, 0xc0, 0x29, 0x00, 0x00, 0x00, // mov rax, 0x29 (terminate)
        0x48, 0x31, 0xff, // xor rdi, rdi
        0xcd, 0x80, // int 0x80
        0x0f, 0x0b, // ud2
    ];
    image[0x200..0x200 + code.len()].copy_from_slice(&code);

    // A UNICODE_STRING at 0x140001100 naming L"hello" at 0x140001110.
    // The image is loaded at its preferred base, so the Buffer field is an
    // absolute address and needs no relocation.
    image[0x300..0x302].copy_from_slice(&10u16.to_le_bytes());
    image[0x302..0x304].copy_from_slice(&12u16.to_le_bytes());
    image[0x308..0x310].copy_from_slice(&0x1_4000_1110u64.to_le_bytes());
    for (index, unit) in "hello".encode_utf16().enumerate() {
        let offset = 0x310 + index * 2;
        image[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
    }
    fs::write(&target, image).expect("cannot write the PE test image");
    target
}
