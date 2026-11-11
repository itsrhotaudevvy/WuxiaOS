#![no_std]
#![forbid(unsafe_code)]
//! Host-testable contracts for WuxiaOS.
//!
//! The core has no allocator, standard library, or architecture assumptions.
//! Executable parsers validate untrusted metadata without executing it; actual
//! mapping and ABI emulation belong to the architecture-specific kernel.

pub mod address_space;
pub mod capability;
pub mod error;
pub mod hhdm;
pub mod image;
pub mod memory;
pub mod nt;
pub mod paging;
pub mod personality;
pub mod region;
pub mod syscall;

pub use address_space::AddressSpace;
pub use capability::{Handle, HandleTable, Rights};
pub use error::{Error, Result};
pub use hhdm::DirectMap;
pub use nt::ObjectType;
pub use paging::PagePermissions;
pub use personality::{ImageFormat, Personality};
