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
    let driver = write_driver_image(&out);
    println!("cargo:rustc-env=WUXIA_PE_IMAGE_PATH={}", pe.display());
    println!(
        "cargo:rustc-env=WUXIA_DRIVER_IMAGE_PATH={}",
        driver.display()
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

/// Write a minimal kernel-mode PE32+ image: an executable `.text`, a writable
/// `.data` holding one absolute pointer and one constant, and a `.reloc` section
/// naming that pointer.
///
/// The entry point returns the constant it reached through the pointer. That makes
/// one call prove three things at once: the image was mapped with executable code
/// and writable data, the relocation was applied for the address it was mapped at,
/// and the processor actually transferred control into the loaded image. A loader
/// that skipped the relocation would jump through the image's preferred-base
/// address, which is not mapped, and fault instead of returning.
fn write_driver_image(out: &std::path::Path) -> PathBuf {
    let target = out.join("driver_image.bin");
    let mut image = vec![0u8; 0x800];

    image[0..2].copy_from_slice(b"MZ");
    image[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    image[0x40..0x44].copy_from_slice(b"PE\0\0");
    image[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
    image[0x46..0x48].copy_from_slice(&3u16.to_le_bytes());
    image[0x54..0x56].copy_from_slice(&240u16.to_le_bytes());
    image[0x56..0x58].copy_from_slice(&0x22u16.to_le_bytes());

    let optional = 0x58;
    image[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
    image[optional + 4..optional + 8].copy_from_slice(&0x200u32.to_le_bytes());
    image[optional + 8..optional + 12].copy_from_slice(&0x400u32.to_le_bytes());
    image[optional + 16..optional + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    image[optional + 20..optional + 24].copy_from_slice(&0x1000u32.to_le_bytes());
    // A preferred base the loader will not use, so the relocation is exercised.
    image[optional + 24..optional + 32].copy_from_slice(&0x1_4002_0000u64.to_le_bytes());
    image[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    image[optional + 36..optional + 40].copy_from_slice(&0x200u32.to_le_bytes());
    // Subsystem 1 is native: a kernel-mode image, not a console program.
    image[optional + 40..optional + 42].copy_from_slice(&1u16.to_le_bytes());
    image[optional + 68..optional + 70].copy_from_slice(&1u16.to_le_bytes());
    image[optional + 72..optional + 80].copy_from_slice(&0x10_0000u64.to_le_bytes());
    image[optional + 80..optional + 88].copy_from_slice(&0x1000u64.to_le_bytes());
    image[optional + 88..optional + 96].copy_from_slice(&0x10_0000u64.to_le_bytes());
    image[optional + 96..optional + 104].copy_from_slice(&0x1000u64.to_le_bytes());
    image[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
    // SizeOfImage, then the base-relocation directory at index 5.
    image[optional + 56..optional + 60].copy_from_slice(&0x4000u32.to_le_bytes());
    let reloc_directory = optional + 112 + 5 * 8;
    image[reloc_directory..reloc_directory + 4].copy_from_slice(&0x3000u32.to_le_bytes());
    image[reloc_directory + 4..reloc_directory + 8].copy_from_slice(&12u32.to_le_bytes());

    let section = optional + 240;
    image[section..section + 5].copy_from_slice(b".text");
    image[section + 8..section + 12].copy_from_slice(&0x200u32.to_le_bytes());
    image[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    image[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
    image[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
    image[section + 36..section + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

    let data = section + 40;
    image[data..data + 5].copy_from_slice(b".data");
    image[data + 8..data + 12].copy_from_slice(&0x200u32.to_le_bytes());
    image[data + 12..data + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    image[data + 16..data + 20].copy_from_slice(&0x200u32.to_le_bytes());
    image[data + 20..data + 24].copy_from_slice(&0x400u32.to_le_bytes());
    image[data + 36..data + 40].copy_from_slice(&0xc000_0040u32.to_le_bytes());

    let reloc = data + 40;
    image[reloc..reloc + 6].copy_from_slice(b".reloc");
    image[reloc + 8..reloc + 12].copy_from_slice(&0x200u32.to_le_bytes());
    image[reloc + 12..reloc + 16].copy_from_slice(&0x3000u32.to_le_bytes());
    image[reloc + 16..reloc + 20].copy_from_slice(&0x200u32.to_le_bytes());
    image[reloc + 20..reloc + 24].copy_from_slice(&0x600u32.to_le_bytes());
    image[reloc + 36..reloc + 40].copy_from_slice(&0x4200_0040u32.to_le_bytes());

    // The pointer sits at RVA 0x2010 and this instruction ends at RVA 0x1007, so
    // the displacement is 0x1009.
    // mov rax, [rip + 0x1009] ; mov rax, [rax] ; ret
    let code: [u8; 10] = [0x48, 0x8b, 0x05, 0x09, 0x10, 0x00, 0x00, 0x48, 0x8b, 0x00];
    image[0x200..0x200 + code.len()].copy_from_slice(&code);
    image[0x200 + code.len()] = 0xc3;

    // The pointer at RVA 0x2010 names the constant at RVA 0x2020; the relocation
    // block below patches it to the address the image was actually mapped at.
    image[0x410..0x418].copy_from_slice(&0x1_4002_2020u64.to_le_bytes());
    image[0x420..0x428].copy_from_slice(&0x1234u64.to_le_bytes());

    // One IMAGE_REL_BASED_DIR64 entry for the pointer at page offset 0x10.
    image[0x600..0x604].copy_from_slice(&0x2000u32.to_le_bytes());
    image[0x604..0x608].copy_from_slice(&12u32.to_le_bytes());
    image[0x608..0x60a].copy_from_slice(&0xa010u16.to_le_bytes());

    fs::write(&target, image).expect("cannot write the driver test image");
    target
}

/// Write a minimal PE32+ image: a read-only code section that opens a store
/// file through the NT services, reads it, echoes it to the console and then
/// terminates the process, plus a writable data section as the read target.
fn write_pe_image(out: &std::path::Path) -> PathBuf {
    let target = out.join("pe_image.bin");
    let mut image = vec![0u8; 0xa00];

    image[0..2].copy_from_slice(b"MZ");
    image[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());

    image[0x40..0x44].copy_from_slice(b"PE\0\0");
    image[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
    // Four sections: .text, a writable .data used as the read buffer, a
    // .reloc section naming the absolute addresses in .data and an .idata
    // section holding the import table the kernel resolves.
    image[0x46..0x48].copy_from_slice(&4u16.to_le_bytes());
    image[0x54..0x56].copy_from_slice(&240u16.to_le_bytes());
    image[0x56..0x58].copy_from_slice(&0x22u16.to_le_bytes());

    let optional = 0x58;
    image[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
    // SizeOfCode, then SizeOfInitializedData.
    image[optional + 4..optional + 8].copy_from_slice(&0x200u32.to_le_bytes());
    image[optional + 8..optional + 12].copy_from_slice(&0x600u32.to_le_bytes());
    image[optional + 16..optional + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    image[optional + 20..optional + 24].copy_from_slice(&0x1000u32.to_le_bytes());
    image[optional + 24..optional + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
    // SectionAlignment, FileAlignment.
    image[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    image[optional + 36..optional + 40].copy_from_slice(&0x200u32.to_le_bytes());
    image[optional + 40..optional + 42].copy_from_slice(&6u16.to_le_bytes());
    image[optional + 48..optional + 50].copy_from_slice(&6u16.to_le_bytes());
    // SizeOfImage covers all four sections.
    image[optional + 56..optional + 60].copy_from_slice(&0x5000u32.to_le_bytes());
    image[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
    image[optional + 68..optional + 70].copy_from_slice(&3u16.to_le_bytes());
    image[optional + 72..optional + 80].copy_from_slice(&0x10_0000u64.to_le_bytes());
    image[optional + 80..optional + 88].copy_from_slice(&0x1000u64.to_le_bytes());
    image[optional + 88..optional + 96].copy_from_slice(&0x10_0000u64.to_le_bytes());
    image[optional + 96..optional + 104].copy_from_slice(&0x1000u64.to_le_bytes());
    // NumberOfRvaAndSizes, then the base-relocation directory at index 5.
    image[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
    let reloc_directory = optional + 112 + 5 * 8;
    image[reloc_directory..reloc_directory + 4].copy_from_slice(&0x3000u32.to_le_bytes());
    image[reloc_directory + 4..reloc_directory + 8].copy_from_slice(&12u32.to_le_bytes());
    // The import directory sits at index 1 and spans a descriptor plus its
    // all-zero terminator.
    let import_directory = optional + 112 + 8;
    image[import_directory..import_directory + 4].copy_from_slice(&0x4000u32.to_le_bytes());
    image[import_directory + 4..import_directory + 8].copy_from_slice(&40u32.to_le_bytes());

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

    let reloc = data + 40;
    image[reloc..reloc + 6].copy_from_slice(b".reloc");
    image[reloc + 8..reloc + 12].copy_from_slice(&0x200u32.to_le_bytes());
    image[reloc + 12..reloc + 16].copy_from_slice(&0x3000u32.to_le_bytes());
    image[reloc + 16..reloc + 20].copy_from_slice(&0x200u32.to_le_bytes());
    image[reloc + 20..reloc + 24].copy_from_slice(&0x600u32.to_le_bytes());
    // IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_CNT_INITIALIZED_DATA.
    image[reloc + 36..reloc + 40].copy_from_slice(&0x4200_0040u32.to_le_bytes());

    let idata = reloc + 40;
    image[idata..idata + 6].copy_from_slice(b".idata");
    image[idata + 8..idata + 12].copy_from_slice(&0x200u32.to_le_bytes());
    image[idata + 12..idata + 16].copy_from_slice(&0x4000u32.to_le_bytes());
    image[idata + 16..idata + 20].copy_from_slice(&0x200u32.to_le_bytes());
    image[idata + 20..idata + 24].copy_from_slice(&0x800u32.to_le_bytes());
    // IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA:
    // the loader rewrites the import address table, so it must be writable.
    image[idata + 36..idata + 40].copy_from_slice(&0xc000_0040u32.to_le_bytes());

    // One IMAGE_REL_BASED_DIR64 block covering the UNICODE_STRING Buffer field
    // at RVA 0x1108: page RVA, block size and the entry, then a pad word that
    // keeps the block a multiple of four bytes.
    image[0x600..0x604].copy_from_slice(&0x1000u32.to_le_bytes());
    image[0x604..0x608].copy_from_slice(&12u32.to_le_bytes());
    image[0x608..0x60a].copy_from_slice(&0xa108u16.to_le_bytes());

    // NtCreateFile(&name), NtReadFile(handle, data, 0x40), the query-counter
    // call, then NtWriteFile and NtTerminateProcess reached through the import
    // address table at RVA 0x4040.
    let code: [u8; 97] = [
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
        0x48, 0xc7, 0xc0, 0x31, 0x00, 0x00, 0x00, // mov rax, 0x31 (query counter)
        0x48, 0x8d, 0x3d, 0x82, 0x10, 0x00, 0x00, // lea rdi, [rip + 0x1082]
        0xcd, 0x80, // int 0x80
        0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00, // mov rdi, 1
        0x48, 0x8d, 0x35, 0xb2, 0x0f, 0x00, 0x00, // lea rsi, [rip + 0xfb2]
        0x4c, 0x89, 0xea, // mov rdx, r13
        0xff, 0x15, 0xe9, 0x2f, 0x00, 0x00, // call [rip + 0x2fe9] (NtWriteFile)
        0x31, 0xff, // xor edi, edi
        0xff, 0x15, 0xe9, 0x2f, 0x00, 0x00, // call [rip + 0x2fe9] (NtTerminateProcess)
        0x0f, 0x0b, // ud2
    ];
    image[0x200..0x200 + code.len()].copy_from_slice(&code);

    // A UNICODE_STRING at 0x140001100 naming L"hello" at 0x140001110. The
    // Buffer field holds an absolute preferred-base address, so the .reloc
    // entry above moves it whenever the image is loaded elsewhere.
    image[0x300..0x302].copy_from_slice(&10u16.to_le_bytes());
    image[0x302..0x304].copy_from_slice(&12u16.to_le_bytes());
    image[0x308..0x310].copy_from_slice(&0x1_4000_1110u64.to_le_bytes());
    for (index, unit) in "hello".encode_utf16().enumerate() {
        let offset = 0x310 + index * 2;
        image[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
    }
    // One import descriptor for ntdll.dll: ILT at 0x4028, IAT at 0x4040, the
    // module name at 0x4058 and two hint/name entries. The descriptor table is
    // terminated by an all-zero 20-byte entry.
    image[0x800..0x804].copy_from_slice(&0x4028u32.to_le_bytes());
    image[0x80c..0x810].copy_from_slice(&0x4058u32.to_le_bytes());
    image[0x810..0x814].copy_from_slice(&0x4040u32.to_le_bytes());
    image[0x828..0x82c].copy_from_slice(&0x4064u32.to_le_bytes());
    image[0x830..0x834].copy_from_slice(&0x4072u32.to_le_bytes());
    image[0x840..0x844].copy_from_slice(&0x4064u32.to_le_bytes());
    image[0x848..0x84c].copy_from_slice(&0x4072u32.to_le_bytes());
    image[0x858..0x862].copy_from_slice(b"ntdll.dll\0");
    image[0x864..0x872].copy_from_slice(b"\0\0NtWriteFile\0");
    image[0x872..0x887].copy_from_slice(b"\0\0NtTerminateProcess\0");

    fs::write(&target, image).expect("cannot write the PE test image");
    target
}
