//! Fixed-capacity capability tables with rights attenuation.

use crate::{Error, Result};

/// Permissions attached to a single kernel object handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rights(u32);

impl Rights {
    /// No permissions.
    pub const NONE: Self = Self(0);
    /// Read data or metadata.
    pub const READ: Self = Self(1 << 0);
    /// Modify data.
    pub const WRITE: Self = Self(1 << 1);
    /// Execute mapped code.
    pub const EXECUTE: Self = Self(1 << 2);
    /// Traverse a namespace.
    pub const TRAVERSE: Self = Self(1 << 3);
    /// Modify namespace entries.
    pub const MODIFY_NAMESPACE: Self = Self(1 << 4);
    /// Wait for an object to become signalled.
    pub const WAIT: Self = Self(1 << 5);
    /// Duplicate this capability.
    pub const DUPLICATE: Self = Self(1 << 6);
    /// Change object policy and security metadata.
    pub const ADMINISTER: Self = Self(1 << 7);
    /// All currently defined permissions.
    pub const ALL: Self = Self((1 << 8) - 1);

    /// Accept only known permission bits.
    pub const fn from_bits(bits: u32) -> Option<Self> {
        if bits & !Self::ALL.0 == 0 { Some(Self(bits)) } else { None }
    }

    /// Check whether every requested permission is present.
    pub const fn contains(self, requested: Self) -> bool {
        self.0 & requested.0 == requested.0
    }

    /// Return the intersection of two permission sets.
    pub const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Return the raw mask for kernel-internal serialization.
    pub const fn bits(self) -> u32 {
        self.0
    }
}

impl core::ops::BitOr for Rights {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

/// A process-local object reference, not a user-controlled pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Handle(u64);

impl Handle {
    /// Construct a raw token for deserialization. No rights are inferred.
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Return the token passed through the syscall ABI.
    pub const fn raw(self) -> u64 {
        self.0
    }

    const fn new(index: usize, generation: u32) -> Self {
        Self(((generation as u64) << 32) | index as u64)
    }

    const fn index(self) -> usize {
        self.0 as u32 as usize
    }

    const fn generation(self) -> u32 {
        (self.0 >> 32) as u32
    }
}

struct Entry<T> {
    generation: u32,
    object: Option<(T, Rights)>,
}

/// A bounded table of kernel-owned objects and their granted capabilities.
///
/// Table indices are never exposed as pointers. Closing advances the slot's
/// generation, so a saved stale handle cannot access a replacement object.
pub struct HandleTable<T, const N: usize> {
    entries: [Entry<T>; N],
}

impl<T, const N: usize> HandleTable<T, N> {
    /// Construct an empty table with valid nonzero generations.
    pub const fn new() -> Self {
        Self {
            entries: [const { Entry { generation: 1, object: None } }; N],
        }
    }

    /// Insert an object, failing rather than overwriting a live capability.
    /// A slot whose generation wrapped is permanently retired.
    pub fn insert(&mut self, object: T, rights: Rights) -> Result<Handle> {
        let index = self.entries.iter().position(|entry| entry.object.is_none() && entry.generation != 0)
            .ok_or(Error::TableFull)?;
        let generation = self.entries[index].generation;
        self.entries[index].object = Some((object, rights));
        Ok(Handle::new(index, generation))
    }

    /// Resolve a capability after checking every requested permission.
    pub fn get(&self, handle: Handle, required: Rights) -> Result<&T> {
        let entry = self.entry(handle)?;
        let (value, rights) = entry.object.as_ref().ok_or(Error::InvalidHandle)?;
        if rights.contains(required) { Ok(value) } else { Err(Error::PermissionDenied) }
    }

    /// Mutably resolve a capability after checking its rights.
    pub fn get_mut(&mut self, handle: Handle, required: Rights) -> Result<&mut T> {
        let entry = self.entry_mut(handle)?;
        let object = entry.object.as_mut().ok_or(Error::InvalidHandle)?;
        if !object.1.contains(required) {
            return Err(Error::PermissionDenied);
        }
        Ok(&mut object.0)
    }

    /// Duplicate an object with no more rights than the source capability.
    pub fn duplicate(&mut self, source: Handle, requested: Rights) -> Result<Handle>
    where
        T: Clone,
    {
        let (value, rights) = self.resolve(source)?;
        if !rights.contains(Rights::DUPLICATE) {
            return Err(Error::PermissionDenied);
        }
        if !rights.contains(requested) {
            return Err(Error::PermissionDenied);
        }
        self.insert(value.clone(), requested)
    }

    /// Close a capability and invalidate its old generation.
    pub fn close(&mut self, handle: Handle) -> Result<T> {
        let index = handle.index();
        let entry = self.entries.get_mut(index).ok_or(Error::InvalidHandle)?;
        if entry.generation != handle.generation() || entry.object.is_none() {
            return Err(Error::InvalidHandle);
        }
        // A wrapped generation would eventually revive an ancient handle.
        // Retire the slot permanently instead of reissuing an old token.
        entry.generation = entry.generation.checked_add(1).unwrap_or(0);
        entry.object.take().map(|(value, _)| value).ok_or(Error::InvalidHandle)
    }

    /// Return the rights on one particular handle.
    pub fn rights(&self, handle: Handle) -> Result<Rights> {
        Ok(self.resolve(handle)?.1)
    }

    /// Return the number of live objects.
    pub fn len(&self) -> usize {
        self.entries.iter().filter(|entry| entry.object.is_some()).count()
    }

    /// Test whether no capabilities have been allocated.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn resolve(&self, handle: Handle) -> Result<(&T, Rights)> {
        let entry = self.entry(handle)?;
        let object = entry.object.as_ref().ok_or(Error::InvalidHandle)?;
        Ok((&object.0, object.1))
    }

    fn entry(&self, handle: Handle) -> Result<&Entry<T>> {
        let index = handle.index();
        let entry = self.entries.get(index).ok_or(Error::InvalidHandle)?;
        if entry.generation != handle.generation() {
            return Err(Error::InvalidHandle);
        }
        Ok(entry)
    }

    fn entry_mut(&mut self, handle: Handle) -> Result<&mut Entry<T>> {
        let index = handle.index();
        let generation = handle.generation();
        let entry = self.entries.get_mut(index).ok_or(Error::InvalidHandle)?;
        if entry.generation != generation {
            return Err(Error::InvalidHandle);
        }
        Ok(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_handles_are_rejected() {
        let mut table = HandleTable::<u32, 2>::new();
        let old = table.insert(7, Rights::READ | Rights::DUPLICATE).unwrap();
        assert_eq!(*table.get(old, Rights::READ).unwrap(), 7);
        assert_eq!(table.get(old, Rights::WRITE), Err(Error::PermissionDenied));
        assert_eq!(table.close(old), Ok(7));
        assert_eq!(table.get(old, Rights::NONE), Err(Error::InvalidHandle));
        assert_eq!(table.get(Handle::from_raw(u64::MAX), Rights::NONE), Err(Error::InvalidHandle));
    }

    #[test]
    fn slot_reuse_changes_generation() {
        let mut table = HandleTable::<u32, 1>::new();
        let old = table.insert(1, Rights::READ).unwrap();
        assert_eq!(table.close(old), Ok(1));
        let new = table.insert(8, Rights::READ).unwrap();
        assert_ne!(old, new);
        assert_eq!(table.get(old, Rights::NONE), Err(Error::InvalidHandle));
        assert_eq!(table.get(new, Rights::READ), Ok(&8));
    }

    #[test]
    fn duplicate_cannot_gain_rights() {
        let mut table = HandleTable::<u32, 2>::new();
        let read = table.insert(42, Rights::READ | Rights::DUPLICATE).unwrap();
        assert_eq!(table.duplicate(read, Rights::READ | Rights::WRITE), Err(Error::PermissionDenied));
        let copy = table.duplicate(read, Rights::READ).unwrap();
        assert_eq!(table.rights(copy), Ok(Rights::READ));
        assert_eq!(table.get(copy, Rights::READ), Ok(&42));
    }

    #[test]
    fn full_table_does_not_overwrite() {
        let mut table = HandleTable::<u8, 1>::new();
        table.insert(1, Rights::READ).unwrap();
        assert_eq!(table.insert(2, Rights::READ), Err(Error::TableFull));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn unknown_rights_are_rejected() {
        assert!(Rights::from_bits(u32::MAX).is_none());
        assert_eq!(Rights::from_bits(0), Some(Rights::NONE));
    }
}
