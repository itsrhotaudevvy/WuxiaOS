#![no_std]
#![forbid(unsafe_code)]
//! Host-testable contracts for WuxiaOS.
//!
//! The core has no allocator, standard library, or architecture assumptions.
//! Executable parsers validate untrusted metadata without executing it; actual
//! mapping and ABI emulation belong to the architecture-specific kernel.

pub mod capability;
pub mod error;
pub mod image;
pub mod memory;
pub mod nt;
pub mod personality;
pub mod syscall;

pub use capability::{Handle, HandleTable, Rights};
pub use error::{Error, Result};
pub use nt::ObjectType;
pub use personality::{ImageFormat, Personality};
