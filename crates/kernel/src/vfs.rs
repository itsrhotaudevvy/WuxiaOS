//! Boot-time file store shared by every process.
//!
//! The store is installed once before ring 3 starts. Afterwards it is mutated
//! only by the write syscall. Interrupt gates clear `IF` on entry, so traps do
//! not nest and each access finishes before the next one begins.

use wuxia_core::vfs::{FileId, MemFs};

/// Capacity of the bootstrap file store.
pub type KernelFs = MemFs<4, 512>;

static mut FS: Option<KernelFs> = None;

/// Publish the boot-time file store.
pub fn install(store: KernelFs) {
    // SAFETY: installed once, before any process can call a syscall.
    unsafe {
        *core::ptr::addr_of_mut!(FS) = Some(store);
    }
}

/// Resolve a path in the boot-time store.
pub fn lookup(name: &str) -> Option<FileId> {
    // SAFETY: the store is installed before any syscall runs, and traps do not
    // nest, so no write is in progress while this shared reference is live.
    unsafe { (*core::ptr::addr_of_mut!(FS)).as_ref()?.lookup(name).ok() }
}

/// Return the length of an existing file.
pub fn len(file: FileId) -> Option<u64> {
    // SAFETY: the store is installed before any syscall runs, and traps do not
    // nest, so no write is in progress while this shared reference is live.
    unsafe {
        (*core::ptr::addr_of_mut!(FS))
            .as_ref()?
            .len(file)
            .ok()
            .map(|length| length as u64)
    }
}

/// Write into a file at `offset` and return the byte count stored.
pub fn write(file: FileId, offset: u64, data: &[u8]) -> Option<usize> {
    // SAFETY: syscalls are the only writer and traps never nest, so no other
    // reference to the store is live while this mutable one exists.
    unsafe {
        (*core::ptr::addr_of_mut!(FS))
            .as_mut()?
            .write(file, offset, data)
            .ok()
    }
}

/// Read from a file at `offset` into `out`.
pub fn read(file: FileId, offset: u64, out: &mut [u8]) -> Option<usize> {
    // SAFETY: the store is installed before any syscall runs, and traps do not
    // nest, so no write is in progress while this shared reference is live.
    unsafe {
        (*core::ptr::addr_of_mut!(FS))
            .as_ref()?
            .read(file, offset, out)
            .ok()
    }
}
