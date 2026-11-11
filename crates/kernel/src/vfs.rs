//! Boot-time file store shared by every process.
//!
//! The store is installed once before ring 3 starts and is only read
//! afterwards, so lookups never race with a writer.

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
    // SAFETY: the store is installed once and never mutated afterwards.
    unsafe { (*core::ptr::addr_of_mut!(FS)).as_ref()?.lookup(name).ok() }
}

/// Read from a file at `offset` into `out`.
pub fn read(file: FileId, offset: u64, out: &mut [u8]) -> Option<usize> {
    // SAFETY: the store is installed once and never mutated afterwards.
    unsafe {
        (*core::ptr::addr_of_mut!(FS))
            .as_ref()?
            .read(file, offset, out)
            .ok()
    }
}
