#![no_std]
#![forbid(unsafe_code)]
//! Host-testable contracts for WuxiaOS.
//!
//! The core has no allocator, standard library, or architecture assumptions.
//! Executable parsers validate untrusted metadata without executing it; actual
//! mapping and ABI emulation belong to the architecture-specific kernel.

pub mod address_space;
pub mod capability;
pub mod descriptor;
pub mod dispatcher;
pub mod elf;
pub mod errno;
pub mod error;
pub mod frames;
pub mod hhdm;
pub mod image;
pub mod load;
pub mod memory;
pub mod nt;
pub mod paging;
pub mod personality;
pub mod pledge;
pub mod process;
pub mod region;
pub mod schedule;
pub mod signal;
pub mod syscall;
pub mod vfs;

pub use address_space::AddressSpace;
pub use capability::{Handle, HandleTable, Rights};
pub use descriptor::DescriptorTable;
pub use elf::{Elf64Image, ElfInfo, ElfKind};
pub use error::{Error, Result};
pub use frames::FramePool;
pub use hhdm::DirectMap;
pub use load::{LoadSegment, LoaderPlan};
pub use nt::ObjectType;
pub use paging::PagePermissions;
pub use personality::{ImageFormat, Personality};
pub use process::{Process, ProcessState};
