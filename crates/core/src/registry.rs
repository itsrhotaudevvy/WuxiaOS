//! Fixed-capacity model of an NT registry hive.
//!
//! A [`Registry`] holds a tree of keys, each carrying named values. Keys and
//! values occupy slots of const-sized tables, and the bytes of every value
//! live in one shared fixed arena, so no operation allocates.
//!
//! Paths are backslash-separated and relative to the hive root. The path `\`
//! or the empty string names the root, and a leading `\` is optional, so
//! `\Machine\Software` and `Machine\Software` name the same key. The root
//! stands for the hive's mount point: `\Registry\Machine\Software\Wuxia` is
//! addressed as `\Machine\Software\Wuxia`. Keys sit at most [`MAX_DEPTH`]
//! components below the root.
//!
//! Names are ASCII. Key and value names are compared with ASCII case folding,
//! as the object namespace does, while each name keeps the spelling it was last
//! written with. Value names are not paths, so they may contain `\`. The
//! default value has the empty name.
//!
//! Value data is reclaimed by compaction. When a value is replaced or deleted,
//! the data after it in the arena slides down to close the gap, so live data
//! always forms a packed prefix of the arena and never fragments. Each change
//! moves at most `BYTES` bytes, and a failed write changes nothing.
//!
//! A [`KeyId`] records the generation of the slot it was issued for. Deleting
//! a key advances the generation, so a stale identifier is rejected with
//! [`Error::InvalidHandle`] rather than addressing whatever key reuses the slot.

use crate::{Error, Result};

/// Longest key component or value name, in bytes.
pub const MAX_NAME_LENGTH: usize = 255;

/// Deepest key, in components below the root.
pub const MAX_DEPTH: usize = 32;

/// Slot index of the root key. It is always the first key slot.
const ROOT: usize = 0;

const SEPARATOR: char = '\\';

/// Data type of a value, using the numbers NT assigns to them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ValueType {
    /// Untyped data. Any length, including empty.
    None = 0,
    /// A UTF-16LE string. The data length must be even.
    Sz = 1,
    /// A UTF-16LE string with unexpanded environment references. The data
    /// length must be even.
    ExpandSz = 2,
    /// Arbitrary bytes.
    Binary = 3,
    /// A little-endian 32-bit integer. The data is exactly four bytes.
    Dword = 4,
    /// A sequence of UTF-16LE strings. The data length must be even.
    MultiSz = 7,
    /// A little-endian 64-bit integer. The data is exactly eight bytes.
    Qword = 11,
}

impl ValueType {
    /// Decode a value type from an untrusted number.
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::None),
            1 => Some(Self::Sz),
            2 => Some(Self::ExpandSz),
            3 => Some(Self::Binary),
            4 => Some(Self::Dword),
            7 => Some(Self::MultiSz),
            11 => Some(Self::Qword),
            _ => None,
        }
    }
}

/// Identifier of a key, valid until that key is deleted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyId {
    index: usize,
    generation: u32,
}

/// A value as returned by queries and enumeration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValueRef<'a> {
    name: &'a str,
    value_type: ValueType,
    data: &'a [u8],
}

impl<'a> ValueRef<'a> {
    /// The name, in the spelling it was last written with. The default value
    /// is empty.
    pub fn name(&self) -> &'a str {
        self.name
    }

    /// The declared type of the data.
    pub fn value_type(&self) -> ValueType {
        self.value_type
    }

    /// The data bytes, borrowed from the registry arena.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }
}

#[derive(Clone, Copy, Debug)]
struct KeySlot {
    name: [u8; MAX_NAME_LENGTH],
    name_length: usize,
    parent: usize,
    depth: usize,
    generation: u32,
    present: bool,
}

impl KeySlot {
    const VACANT: Self = Self {
        name: [0; MAX_NAME_LENGTH],
        name_length: 0,
        parent: ROOT,
        depth: 0,
        generation: 0,
        present: false,
    };

    fn new(name: &[u8], parent: usize, depth: usize, generation: u32) -> Self {
        let mut stored = [0u8; MAX_NAME_LENGTH];
        stored[..name.len()].copy_from_slice(name);
        Self {
            name: stored,
            name_length: name.len(),
            parent,
            depth,
            generation,
            present: true,
        }
    }

    fn name(&self) -> &[u8] {
        &self.name[..self.name_length]
    }
}

#[derive(Clone, Copy, Debug)]
struct ValueSlot {
    owner: usize,
    name: [u8; MAX_NAME_LENGTH],
    name_length: usize,
    value_type: ValueType,
    /// Start of the data in the arena. Zero when `length` is zero.
    offset: usize,
    length: usize,
    present: bool,
}

impl ValueSlot {
    const VACANT: Self = Self {
        owner: ROOT,
        name: [0; MAX_NAME_LENGTH],
        name_length: 0,
        value_type: ValueType::None,
        offset: 0,
        length: 0,
        present: false,
    };

    fn new(owner: usize, name: &[u8], value_type: ValueType, offset: usize, length: usize) -> Self {
        let mut stored = [0u8; MAX_NAME_LENGTH];
        stored[..name.len()].copy_from_slice(name);
        Self {
            owner,
            name: stored,
            name_length: name.len(),
            value_type,
            offset,
            length,
            present: true,
        }
    }

    fn name(&self) -> &[u8] {
        &self.name[..self.name_length]
    }
}

/// A registry hive with `KEYS` key slots, `VALUES` value slots and a shared
/// arena of `BYTES` bytes for value data.
///
/// The root key occupies slot 0 and counts against `KEYS`. With `KEYS == 0`
/// no key exists, so every path operation fails with [`Error::NotFound`].
#[derive(Clone, Debug)]
pub struct Registry<const KEYS: usize, const VALUES: usize, const BYTES: usize> {
    keys: [KeySlot; KEYS],
    values: [ValueSlot; VALUES],
    data: [u8; BYTES],
    /// Bytes of the arena in use. Live data occupies `data[..used]`.
    used: usize,
}

impl<const KEYS: usize, const VALUES: usize, const BYTES: usize> Default
    for Registry<KEYS, VALUES, BYTES>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const KEYS: usize, const VALUES: usize, const BYTES: usize> Registry<KEYS, VALUES, BYTES> {
    /// Construct a registry holding only the root key.
    pub const fn new() -> Self {
        let mut keys = [KeySlot::VACANT; KEYS];
        if KEYS > 0 {
            keys[ROOT] = KeySlot {
                name: [0; MAX_NAME_LENGTH],
                name_length: 0,
                parent: ROOT,
                depth: 0,
                generation: 0,
                present: true,
            };
        }
        Self {
            keys,
            values: [ValueSlot::VACANT; VALUES],
            data: [0; BYTES],
            used: 0,
        }
    }

    /// Create a key whose parent already exists.
    ///
    /// Errors:
    /// - [`Error::InvalidName`]: the path is malformed, a component or the
    ///   path is too long, or the key would be deeper than [`MAX_DEPTH`].
    /// - [`Error::AlreadyExists`]: the path is the root, or a sibling with the
    ///   same name exists, ignoring ASCII case.
    /// - [`Error::NotFound`]: the parent key does not exist.
    /// - [`Error::TableFull`]: no free key slot remains.
    pub fn create_key(&mut self, path: &str) -> Result<KeyId> {
        let body = validate_path(path)?;
        if body.is_empty() {
            return Err(Error::AlreadyExists);
        }
        let (parent_path, name) = body.rsplit_once(SEPARATOR).unwrap_or(("", body));
        let parent = self.resolve_body(parent_path)?;
        if self.find_child(parent, name.as_bytes()).is_some() {
            return Err(Error::AlreadyExists);
        }
        let slot = self.free_key_slot().ok_or(Error::TableFull)?;
        let depth = self.keys[parent].depth + 1;
        let index = self.occupy_key(slot, name, parent, depth);
        Ok(self.key_id(index))
    }

    /// Create a key and any missing ancestors, returning the key at `path`.
    ///
    /// A key that already exists is returned unchanged. The operation is
    /// all-or-nothing: if the free key slots cannot hold every missing
    /// component, nothing is created.
    ///
    /// Errors: [`Error::InvalidName`] for a malformed or too-deep path,
    /// [`Error::NotFound`] when the root slot is absent, and
    /// [`Error::TableFull`] when the missing components do not fit.
    pub fn create_key_recursive(&mut self, path: &str) -> Result<KeyId> {
        let body = validate_path(path)?;
        self.live(ROOT).ok_or(Error::NotFound)?;

        let mut current = ROOT;
        let mut matched = 0usize;
        let mut descending = true;
        for component in components(body) {
            if !descending {
                break;
            }
            match self.find_child(current, component.as_bytes()) {
                Some(child) => {
                    current = child;
                    matched += 1;
                }
                None => descending = false,
            }
        }

        let total = components(body).count();
        if total - matched > self.free_key_slots() {
            return Err(Error::TableFull);
        }
        for component in components(body).skip(matched) {
            let slot = self.free_key_slot().ok_or(Error::TableFull)?;
            let depth = self.keys[current].depth + 1;
            current = self.occupy_key(slot, component, current, depth);
        }
        Ok(self.key_id(current))
    }

    /// Resolve a path to an existing key.
    ///
    /// Errors: [`Error::InvalidName`] for a malformed path and
    /// [`Error::NotFound`] when a component does not resolve.
    pub fn open_key(&self, path: &str) -> Result<KeyId> {
        let body = validate_path(path)?;
        let index = self.resolve_body(body)?;
        Ok(self.key_id(index))
    }

    /// Delete a key and all of its values, reclaiming their data.
    ///
    /// Errors:
    /// - [`Error::InvalidHandle`]: the identifier is stale or foreign.
    /// - [`Error::PermissionDenied`]: the key is the root.
    /// - [`Error::InvalidState`]: the key still has subkeys.
    pub fn delete_key(&mut self, key: KeyId) -> Result<()> {
        let index = self.key_index(key)?;
        if index == ROOT {
            return Err(Error::PermissionDenied);
        }
        if self.has_children(index) {
            return Err(Error::InvalidState);
        }
        while let Some(slot) = self
            .values
            .iter()
            .position(|value| value.present && value.owner == index)
        {
            self.remove_value_slot(slot);
        }
        let key = &mut self.keys[index];
        key.present = false;
        key.name_length = 0;
        key.generation = key.generation.wrapping_add(1);
        Ok(())
    }

    /// The name of a key, in the spelling it was created with. The root is
    /// named by the empty string.
    ///
    /// Errors: [`Error::InvalidHandle`] for a stale or foreign identifier.
    pub fn key_name(&self, key: KeyId) -> Result<&str> {
        let index = self.key_index(key)?;
        name_str(self.keys[index].name())
    }

    /// The `index`-th subkey of `key`, counted in slot order.
    ///
    /// Indexes are positional: deleting a subkey shifts the indexes of the
    /// subkeys after it, so enumerate in one pass and stop at
    /// [`Error::NotFound`].
    ///
    /// Errors: [`Error::InvalidHandle`] for a stale identifier and
    /// [`Error::NotFound`] when `index` is past the last subkey.
    pub fn subkey_at(&self, key: KeyId, index: usize) -> Result<KeyId> {
        let parent = self.key_index(key)?;
        let child = self
            .keys
            .iter()
            .enumerate()
            .filter(|(i, slot)| *i != ROOT && slot.present && slot.parent == parent)
            .nth(index)
            .map(|(i, _)| i)
            .ok_or(Error::NotFound)?;
        Ok(self.key_id(child))
    }

    /// Create or replace a value on `key`.
    ///
    /// Names are compared ignoring ASCII case. Replacing a value reuses its
    /// slot, takes the new spelling of the name and new data, and reclaims the
    /// old data before the new data is stored.
    ///
    /// Errors:
    /// - [`Error::InvalidHandle`]: the key identifier is stale or foreign.
    /// - [`Error::InvalidName`]: the name exceeds [`MAX_NAME_LENGTH`] bytes,
    ///   is not ASCII, or contains NUL.
    /// - [`Error::InvalidInput`]: the data does not fit the value type.
    /// - [`Error::TableFull`]: no free value slot remains.
    /// - [`Error::OutOfRange`]: the arena cannot hold the data after
    ///   reclaiming the old value.
    pub fn set_value(
        &mut self,
        key: KeyId,
        name: &str,
        value_type: ValueType,
        data: &[u8],
    ) -> Result<()> {
        let owner = self.key_index(key)?;
        let name_bytes = check_name(name)?;
        check_data(value_type, data)?;

        let existing = self.find_value(owner, name_bytes);
        let slot = match existing {
            Some(slot) => slot,
            None => self
                .values
                .iter()
                .position(|value| !value.present)
                .ok_or(Error::TableFull)?,
        };
        let reclaimed = existing.map_or(0, |slot| self.values[slot].length);
        let kept = self.used.saturating_sub(reclaimed);
        let total = kept.checked_add(data.len()).ok_or(Error::OutOfRange)?;
        if total > BYTES {
            return Err(Error::OutOfRange);
        }

        if let Some(slot) = existing {
            let ValueSlot { offset, length, .. } = self.values[slot];
            self.release(offset, length);
        }
        let offset = if data.is_empty() { 0 } else { self.used };
        let start = self.used;
        self.data[start..start + data.len()].copy_from_slice(data);
        self.used = start + data.len();
        self.values[slot] = ValueSlot::new(owner, name_bytes, value_type, offset, data.len());
        Ok(())
    }

    /// Read a value by name. The empty name reads the default value.
    ///
    /// Errors: [`Error::InvalidHandle`], [`Error::InvalidName`] for a name
    /// that is not a legal value name, and [`Error::NotFound`] when the value
    /// does not exist.
    pub fn query_value(&self, key: KeyId, name: &str) -> Result<ValueRef<'_>> {
        let owner = self.key_index(key)?;
        let slot = self
            .find_value(owner, check_name(name)?)
            .ok_or(Error::NotFound)?;
        self.value_ref(slot)
    }

    /// Delete a value by name, reclaiming its data.
    ///
    /// Errors: [`Error::InvalidHandle`], [`Error::InvalidName`], and
    /// [`Error::NotFound`] when the value does not exist.
    pub fn delete_value(&mut self, key: KeyId, name: &str) -> Result<()> {
        let owner = self.key_index(key)?;
        let slot = self
            .find_value(owner, check_name(name)?)
            .ok_or(Error::NotFound)?;
        self.remove_value_slot(slot);
        Ok(())
    }

    /// The `index`-th value of `key`, counted in slot order.
    ///
    /// The same positional caveat as [`subkey_at`](Self::subkey_at) applies.
    ///
    /// Errors: [`Error::InvalidHandle`] for a stale identifier and
    /// [`Error::NotFound`] when `index` is past the last value.
    pub fn value_at(&self, key: KeyId, index: usize) -> Result<ValueRef<'_>> {
        let owner = self.key_index(key)?;
        let slot = self
            .values
            .iter()
            .enumerate()
            .filter(|(_, value)| value.present && value.owner == owner)
            .nth(index)
            .map(|(slot, _)| slot)
            .ok_or(Error::NotFound)?;
        self.value_ref(slot)
    }

    fn live(&self, index: usize) -> Option<&KeySlot> {
        self.keys.get(index).filter(|slot| slot.present)
    }

    fn key_index(&self, key: KeyId) -> Result<usize> {
        match self.keys.get(key.index) {
            Some(slot) if slot.present && slot.generation == key.generation => Ok(key.index),
            _ => Err(Error::InvalidHandle),
        }
    }

    fn key_id(&self, index: usize) -> KeyId {
        KeyId {
            index,
            generation: self.keys[index].generation,
        }
    }

    fn resolve_body(&self, body: &str) -> Result<usize> {
        self.live(ROOT).ok_or(Error::NotFound)?;
        let mut current = ROOT;
        for component in components(body) {
            current = self
                .find_child(current, component.as_bytes())
                .ok_or(Error::NotFound)?;
        }
        Ok(current)
    }

    /// Find a live child of `parent` whose name matches ignoring ASCII case.
    fn find_child(&self, parent: usize, name: &[u8]) -> Option<usize> {
        self.keys
            .iter()
            .enumerate()
            .find(|(i, slot)| {
                *i != ROOT
                    && slot.present
                    && slot.parent == parent
                    && slot.name().eq_ignore_ascii_case(name)
            })
            .map(|(i, _)| i)
    }

    fn has_children(&self, index: usize) -> bool {
        self.keys
            .iter()
            .enumerate()
            .any(|(i, slot)| i != index && slot.present && slot.parent == index)
    }

    fn free_key_slot(&self) -> Option<usize> {
        self.keys.iter().position(|slot| !slot.present)
    }

    fn free_key_slots(&self) -> usize {
        self.keys.iter().filter(|slot| !slot.present).count()
    }

    /// Fill a free key slot, keeping its generation so that identifiers
    /// issued for earlier occupants stay invalid.
    fn occupy_key(&mut self, slot: usize, name: &str, parent: usize, depth: usize) -> usize {
        let generation = self.keys[slot].generation;
        self.keys[slot] = KeySlot::new(name.as_bytes(), parent, depth, generation);
        slot
    }

    fn find_value(&self, owner: usize, name: &[u8]) -> Option<usize> {
        self.values.iter().position(|value| {
            value.present && value.owner == owner && value.name().eq_ignore_ascii_case(name)
        })
    }

    fn value_ref(&self, slot: usize) -> Result<ValueRef<'_>> {
        let value = self
            .values
            .get(slot)
            .filter(|value| value.present)
            .ok_or(Error::NotFound)?;
        let end = value
            .offset
            .checked_add(value.length)
            .ok_or(Error::InvalidState)?;
        let data = self
            .data
            .get(value.offset..end)
            .ok_or(Error::InvalidState)?;
        Ok(ValueRef {
            name: name_str(value.name())?,
            value_type: value.value_type,
            data,
        })
    }

    fn remove_value_slot(&mut self, slot: usize) {
        let ValueSlot { offset, length, .. } = self.values[slot];
        self.values[slot].present = false;
        self.release(offset, length);
    }

    /// Reclaim `length` bytes at `offset` by sliding later data down.
    ///
    /// Live data occupies `data[..used]` with no gaps, so the bytes after the
    /// released range move down to `offset` and every later value moves with
    /// them. Values of zero length keep offset zero and are not moved.
    fn release(&mut self, offset: usize, length: usize) {
        if length == 0 {
            return;
        }
        let end = offset + length;
        self.data.copy_within(end..self.used, offset);
        self.used -= length;
        for value in self.values.iter_mut() {
            if value.present && value.length > 0 && value.offset >= end {
                value.offset -= length;
            }
        }
    }
}

/// Split a path into its body and check every component.
///
/// The body has its single optional leading separator removed. An empty body
/// names the root. Trailing and doubled separators produce empty components,
/// which are rejected.
fn validate_path(path: &str) -> Result<&str> {
    let body = path.strip_prefix(SEPARATOR).unwrap_or(path);
    let mut depth = 0usize;
    for component in components(body) {
        check_component(component)?;
        depth += 1;
        if depth > MAX_DEPTH {
            return Err(Error::InvalidName);
        }
    }
    Ok(body)
}

/// The components of a body; an empty body has none.
fn components(body: &str) -> impl Iterator<Item = &str> {
    body.split(SEPARATOR).filter(move |_| !body.is_empty())
}

fn check_component(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidName);
    }
    check_name(name).map(|_| ())
}

/// Check a value name, which may be empty for the default value.
fn check_name(name: &str) -> Result<&[u8]> {
    let bytes = name.as_bytes();
    if bytes.len() > MAX_NAME_LENGTH || !name.is_ascii() || bytes.contains(&0) {
        return Err(Error::InvalidName);
    }
    Ok(bytes)
}

fn check_data(value_type: ValueType, data: &[u8]) -> Result<()> {
    let valid = match value_type {
        ValueType::None | ValueType::Binary => true,
        ValueType::Dword => data.len() == 4,
        ValueType::Qword => data.len() == 8,
        ValueType::Sz | ValueType::ExpandSz | ValueType::MultiSz => data.len().is_multiple_of(2),
    };
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidInput)
    }
}

fn name_str(bytes: &[u8]) -> Result<&str> {
    core::str::from_utf8(bytes).map_err(|_| Error::InvalidInput)
}

#[cfg(test)]
mod tests {
    use super::*;

    type Small = Registry<8, 8, 64>;

    #[test]
    fn root_is_addressed_by_backslash_or_empty_and_is_protected() {
        let mut reg = Small::new();
        let root = reg.open_key("\\").unwrap();
        assert_eq!(reg.open_key(""), Ok(root));
        assert_eq!(reg.key_name(root), Ok(""));
        assert_eq!(reg.create_key("\\"), Err(Error::AlreadyExists));
        assert_eq!(reg.delete_key(root), Err(Error::PermissionDenied));
        assert_eq!(reg.open_key("\\"), Ok(root));
    }

    #[test]
    fn leading_separator_is_optional_for_paths() {
        let mut reg = Small::new();
        let software = {
            reg.create_key("\\Machine").unwrap();
            reg.create_key("Machine\\Software").unwrap()
        };
        assert_eq!(reg.open_key("\\Machine\\Software"), Ok(software));
        assert_eq!(reg.open_key("Machine\\Software"), Ok(software));
    }

    #[test]
    fn create_key_requires_an_existing_parent() {
        let mut reg = Small::new();
        assert_eq!(reg.create_key("\\Machine\\Software"), Err(Error::NotFound));
        let machine = reg.create_key("\\Machine").unwrap();
        let software = reg.create_key("\\Machine\\Software").unwrap();
        assert_eq!(reg.open_key("\\Machine\\Software"), Ok(software));
        assert_eq!(reg.subkey_at(machine, 0), Ok(software));
        assert_eq!(reg.create_key("\\Machine"), Err(Error::AlreadyExists));
    }

    #[test]
    fn create_key_recursive_builds_missing_ancestors_and_reuses_existing() {
        let mut reg = Small::new();
        let wuxia = reg
            .create_key_recursive("\\Machine\\Software\\Wuxia")
            .unwrap();
        assert_eq!(reg.key_name(wuxia), Ok("Wuxia"));
        assert_eq!(
            reg.create_key_recursive("\\Machine\\Software\\Wuxia"),
            Ok(wuxia)
        );

        let boot = reg.create_key_recursive("\\Machine\\Kernel\\Boot").unwrap();
        let kernel = reg.open_key("\\Machine\\Kernel").unwrap();
        assert_eq!(reg.subkey_at(kernel, 0), Ok(boot));
        assert_eq!(reg.key_name(kernel), Ok("Kernel"));
    }

    #[test]
    fn create_key_recursive_is_all_or_nothing_when_slots_run_out() {
        let mut reg = Registry::<4, 1, 8>::new();
        reg.create_key("\\Machine").unwrap();
        // Root and Machine use two of four slots, so three new keys do not fit.
        assert_eq!(reg.create_key_recursive("\\A\\B\\C"), Err(Error::TableFull));
        assert_eq!(reg.open_key("\\A"), Err(Error::NotFound));
        assert!(reg.create_key_recursive("\\A\\B").is_ok());
    }

    #[test]
    fn key_names_fold_ascii_case_but_keep_spelling() {
        let mut reg = Small::new();
        let key = reg.create_key("\\Machine").unwrap();
        assert_eq!(reg.open_key("\\MACHINE"), Ok(key));
        assert_eq!(reg.key_name(key), Ok("Machine"));
        assert_eq!(reg.create_key("\\machine"), Err(Error::AlreadyExists));
        assert_eq!(reg.key_name(key), Ok("Machine"));
    }

    #[test]
    fn name_length_limit_is_enforced_for_components_and_values() {
        let mut reg = Registry::<4, 4, 16>::new();
        // A separator followed by MAX_NAME_LENGTH + 1 'a' bytes.
        let mut buffer = [b'a'; MAX_NAME_LENGTH + 2];
        buffer[0] = b'\\';
        let max_path = core::str::from_utf8(&buffer[..=MAX_NAME_LENGTH]).unwrap();
        let over_path = core::str::from_utf8(&buffer[..]).unwrap();
        let max_name = &max_path[1..];
        let over_name = &over_path[1..];

        let key = reg.create_key(max_path).unwrap();
        assert_eq!(reg.key_name(key), Ok(max_name));
        assert_eq!(reg.create_key(over_path), Err(Error::InvalidName));

        assert_eq!(reg.set_value(key, max_name, ValueType::None, &[]), Ok(()));
        assert_eq!(
            reg.set_value(key, over_name, ValueType::None, &[]),
            Err(Error::InvalidName)
        );
        assert_eq!(reg.query_value(key, over_name), Err(Error::InvalidName));
    }

    #[test]
    fn depth_limit_is_enforced() {
        let mut reg = Registry::<40, 1, 1>::new();
        let mut deep = [0u8; 2 * (MAX_DEPTH + 1)];
        for (index, byte) in deep.iter_mut().enumerate() {
            *byte = if index % 2 == 0 { b'\\' } else { b'k' };
        }
        let at_limit = core::str::from_utf8(&deep[..2 * MAX_DEPTH]).unwrap();
        let too_deep = core::str::from_utf8(&deep[..]).unwrap();

        let leaf = reg.create_key_recursive(at_limit).unwrap();
        assert_eq!(reg.open_key(at_limit), Ok(leaf));
        assert_eq!(reg.open_key(too_deep), Err(Error::InvalidName));
        assert_eq!(reg.create_key_recursive(too_deep), Err(Error::InvalidName));
    }

    #[test]
    fn malformed_paths_are_rejected_without_mutation() {
        let mut reg = Small::new();
        reg.create_key("\\Machine").unwrap();
        let invalid = [
            "\\\\",
            "\\Machine\\",
            "\\Machine\\\\Software",
            "\\Mach\0ine",
            "\\\u{c4}rger",
        ];
        for path in invalid {
            assert_eq!(reg.open_key(path), Err(Error::InvalidName), "open {path:?}");
            assert_eq!(
                reg.create_key(path),
                Err(Error::InvalidName),
                "create {path:?}"
            );
            assert_eq!(
                reg.create_key_recursive(path),
                Err(Error::InvalidName),
                "recursive {path:?}"
            );
        }
        assert_eq!(reg.free_key_slots(), 6);
    }

    #[test]
    fn delete_key_is_refused_while_subkeys_exist() {
        let mut reg = Small::new();
        let machine = reg.create_key("\\Machine").unwrap();
        let software = reg.create_key("\\Machine\\Software").unwrap();
        assert_eq!(reg.delete_key(machine), Err(Error::InvalidState));
        assert_eq!(reg.open_key("\\Machine\\Software"), Ok(software));

        reg.delete_key(software).unwrap();
        reg.delete_key(machine).unwrap();
        assert_eq!(reg.open_key("\\Machine"), Err(Error::NotFound));
    }

    #[test]
    fn stale_key_ids_are_rejected_after_slot_reuse() {
        let mut reg = Small::new();
        let first = reg.create_key("\\First").unwrap();
        reg.delete_key(first).unwrap();
        assert_eq!(reg.key_name(first), Err(Error::InvalidHandle));
        assert_eq!(
            reg.set_value(first, "x", ValueType::Binary, &[1]),
            Err(Error::InvalidHandle)
        );

        let second = reg.create_key("\\Second").unwrap();
        assert_eq!(second.index, first.index);
        assert_ne!(first, second);
        assert_eq!(reg.delete_key(first), Err(Error::InvalidHandle));
        assert_eq!(reg.key_name(second), Ok("Second"));
    }

    #[test]
    fn value_data_is_validated_by_type() {
        let mut reg = Small::new();
        let key = reg.create_key("\\K").unwrap();

        assert_eq!(
            reg.set_value(key, "d", ValueType::Dword, &[1, 2, 3]),
            Err(Error::InvalidInput)
        );
        assert_eq!(
            reg.set_value(key, "d", ValueType::Dword, &[1, 2, 3, 4]),
            Ok(())
        );
        assert_eq!(
            reg.set_value(key, "q", ValueType::Qword, &[0; 7]),
            Err(Error::InvalidInput)
        );
        assert_eq!(reg.set_value(key, "q", ValueType::Qword, &[0; 8]), Ok(()));
        for value_type in [ValueType::Sz, ValueType::ExpandSz, ValueType::MultiSz] {
            assert_eq!(
                reg.set_value(key, "s", value_type, &[0x41]),
                Err(Error::InvalidInput)
            );
            assert_eq!(reg.set_value(key, "s", value_type, &[0x41, 0]), Ok(()));
        }
        assert_eq!(
            reg.set_value(key, "b", ValueType::Binary, &[1, 2, 3]),
            Ok(())
        );
        assert_eq!(reg.set_value(key, "n", ValueType::None, &[]), Ok(()));

        assert_eq!(ValueType::from_raw(11), Some(ValueType::Qword));
        assert_eq!(ValueType::from_raw(7), Some(ValueType::MultiSz));
        assert_eq!(ValueType::from_raw(5), None);
        assert_eq!(ValueType::Qword as u32, 11);
    }

    #[test]
    fn replacing_a_value_reclaims_its_space() {
        let mut reg = Registry::<4, 4, 8>::new();
        let key = reg.create_key("\\K").unwrap();
        reg.set_value(key, "A", ValueType::Binary, &[1; 8]).unwrap();
        assert_eq!(
            reg.set_value(key, "B", ValueType::Binary, &[9]),
            Err(Error::OutOfRange)
        );

        // The old eight bytes are reclaimed first, so an eight-byte replacement
        // fits even though the arena is full. The name matches ignoring case.
        reg.set_value(key, "a", ValueType::Binary, &[2; 8]).unwrap();
        let value = reg.query_value(key, "A").unwrap();
        assert_eq!(value.name(), "a");
        assert_eq!(value.data(), &[2u8; 8][..]);

        // A replacement that cannot fit fails and leaves the old value intact.
        assert_eq!(
            reg.set_value(key, "A", ValueType::Binary, &[3; 9]),
            Err(Error::OutOfRange)
        );
        assert_eq!(reg.query_value(key, "a").unwrap().data(), &[2u8; 8][..]);
    }

    #[test]
    fn delete_value_compacts_and_keeps_other_values_intact() {
        let mut reg = Registry::<4, 8, 12>::new();
        let one = reg.create_key("\\One").unwrap();
        let two = reg.create_key("\\Two").unwrap();
        reg.set_value(one, "a", ValueType::Binary, b"aaaa").unwrap();
        reg.set_value(two, "b", ValueType::Binary, b"bbbb").unwrap();
        reg.set_value(one, "c", ValueType::Binary, b"cccc").unwrap();
        assert_eq!(
            reg.set_value(one, "d", ValueType::Binary, b"d"),
            Err(Error::OutOfRange)
        );

        reg.delete_value(one, "a").unwrap();
        assert_eq!(reg.query_value(two, "b").unwrap().data(), b"bbbb");
        assert_eq!(reg.query_value(one, "c").unwrap().data(), b"cccc");
        assert_eq!(reg.query_value(one, "a"), Err(Error::NotFound));

        reg.set_value(two, "d", ValueType::Binary, b"dddd").unwrap();
        assert_eq!(reg.query_value(two, "d").unwrap().data(), b"dddd");
        assert_eq!(reg.query_value(one, "c").unwrap().data(), b"cccc");
        assert_eq!(reg.query_value(two, "b").unwrap().data(), b"bbbb");
    }

    #[test]
    fn delete_key_reclaims_its_values() {
        let mut reg = Registry::<4, 4, 8>::new();
        let key = reg.create_key("\\K").unwrap();
        let other = reg.create_key("\\J").unwrap();
        reg.set_value(key, "v", ValueType::Binary, &[1; 8]).unwrap();
        assert_eq!(
            reg.set_value(other, "x", ValueType::Binary, &[0]),
            Err(Error::OutOfRange)
        );

        reg.delete_key(key).unwrap();
        reg.set_value(other, "x", ValueType::Binary, &[9; 8])
            .unwrap();
        assert_eq!(reg.query_value(other, "x").unwrap().data(), &[9u8; 8][..]);
    }

    #[test]
    fn default_value_has_an_empty_name_distinct_from_named_values() {
        let mut reg = Small::new();
        let key = reg.create_key("\\K").unwrap();
        reg.set_value(key, "", ValueType::Sz, &[b'h', 0, b'i', 0])
            .unwrap();
        reg.set_value(key, "Label", ValueType::Dword, &[7, 0, 0, 0])
            .unwrap();

        let default = reg.query_value(key, "").unwrap();
        assert_eq!(default.name(), "");
        assert_eq!(default.value_type(), ValueType::Sz);
        assert_eq!(default.data(), &[b'h', 0, b'i', 0][..]);

        let named = reg.query_value(key, "LABEL").unwrap();
        assert_eq!(named.name(), "Label");
        assert_eq!(named.value_type(), ValueType::Dword);

        reg.delete_value(key, "").unwrap();
        assert_eq!(reg.query_value(key, ""), Err(Error::NotFound));
        assert!(reg.query_value(key, "Label").is_ok());
    }

    #[test]
    fn enumeration_by_index_covers_subkeys_and_values() {
        let mut reg = Small::new();
        let root = reg.open_key("\\").unwrap();
        let a = reg.create_key("\\A").unwrap();
        let b = reg.create_key("\\B").unwrap();
        let c = reg.create_key("\\C").unwrap();
        assert_eq!(reg.subkey_at(root, 0), Ok(a));
        assert_eq!(reg.subkey_at(root, 1), Ok(b));
        assert_eq!(reg.subkey_at(root, 2), Ok(c));
        assert_eq!(reg.subkey_at(root, 3), Err(Error::NotFound));

        reg.delete_key(b).unwrap();
        assert_eq!(reg.subkey_at(root, 1), Ok(c));
        assert_eq!(reg.subkey_at(b, 0), Err(Error::InvalidHandle));

        reg.set_value(a, "x", ValueType::Binary, &[1]).unwrap();
        reg.set_value(a, "y", ValueType::Binary, &[2]).unwrap();
        reg.set_value(c, "z", ValueType::Binary, &[3]).unwrap();
        assert_eq!(reg.value_at(a, 0).unwrap().name(), "x");
        assert_eq!(reg.value_at(a, 1).unwrap().name(), "y");
        assert_eq!(reg.value_at(a, 2), Err(Error::NotFound));
        assert_eq!(reg.value_at(c, 0).unwrap().name(), "z");
    }

    #[test]
    fn table_exhaustion_reports_table_full_and_replacement_still_works() {
        let mut reg = Registry::<3, 2, 16>::new();
        let key = reg.create_key("\\A").unwrap();
        reg.create_key("\\B").unwrap();
        assert_eq!(reg.create_key("\\C"), Err(Error::TableFull));

        reg.set_value(key, "x", ValueType::Binary, &[1]).unwrap();
        reg.set_value(key, "y", ValueType::Binary, &[2]).unwrap();
        assert_eq!(
            reg.set_value(key, "z", ValueType::Binary, &[3]),
            Err(Error::TableFull)
        );
        // Replacing an existing value needs no free value slot.
        assert_eq!(reg.set_value(key, "x", ValueType::Binary, &[4]), Ok(()));
        assert_eq!(reg.query_value(key, "x").unwrap().data(), &[4]);
    }

    #[test]
    fn zero_capacity_registries_fail_without_panicking() {
        let mut none = Registry::<0, 0, 0>::new();
        assert_eq!(none.open_key("\\"), Err(Error::NotFound));
        assert_eq!(none.open_key("\\A"), Err(Error::NotFound));
        assert_eq!(none.create_key("\\A"), Err(Error::NotFound));
        assert_eq!(none.create_key_recursive("\\A"), Err(Error::NotFound));

        let mut no_values = Registry::<2, 0, 0>::new();
        let key = no_values.create_key("\\A").unwrap();
        assert_eq!(
            no_values.set_value(key, "", ValueType::None, &[]),
            Err(Error::TableFull)
        );
        assert_eq!(no_values.query_value(key, ""), Err(Error::NotFound));

        let mut no_bytes = Registry::<2, 2, 0>::new();
        let key = no_bytes.create_key("\\A").unwrap();
        assert_eq!(
            no_bytes.set_value(key, "x", ValueType::Binary, &[1]),
            Err(Error::OutOfRange)
        );
        assert_eq!(no_bytes.set_value(key, "x", ValueType::None, &[]), Ok(()));
    }

    #[test]
    fn arena_matches_a_shadow_model_under_churn() {
        const NAMES: [&str; 4] = ["a", "B", "c", "D"];
        const BYTES: usize = 16;
        let mut reg = Registry::<2, 4, BYTES>::new();
        let key = reg.create_key("\\Churn").unwrap();
        let mut shadow: [Option<(usize, [u8; 8])>; 4] = [None; 4];
        let mut seed: u64 = 0x2545_F491_4F6C_DD1D;

        for step in 0..4000u32 {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let pick = (seed >> 33) as usize;
            let slot = pick % 4;
            let name = NAMES[slot];

            if (pick / 4).is_multiple_of(3) {
                let expected = if shadow[slot].is_some() {
                    Ok(())
                } else {
                    Err(Error::NotFound)
                };
                assert_eq!(reg.delete_value(key, name), expected);
                shadow[slot] = None;
            } else {
                let length = (pick / 12) % 9;
                let mut bytes = [0u8; 8];
                for (i, byte) in bytes.iter_mut().enumerate().take(length) {
                    *byte = (step as u8).wrapping_add(i as u8).wrapping_mul(3);
                }
                let total: usize = shadow.iter().flatten().map(|(len, _)| *len).sum();
                let old = shadow[slot].map_or(0, |(len, _)| len);
                let result = reg.set_value(key, name, ValueType::Binary, &bytes[..length]);
                if total - old + length <= BYTES {
                    assert_eq!(result, Ok(()));
                    shadow[slot] = Some((length, bytes));
                } else {
                    assert_eq!(result, Err(Error::OutOfRange));
                }
            }

            let mut live = 0usize;
            for (i, name) in NAMES.iter().enumerate() {
                match shadow[i] {
                    Some((length, bytes)) => {
                        let value = reg.query_value(key, name).unwrap();
                        assert_eq!(value.data(), &bytes[..length], "step {step}");
                        live += length;
                    }
                    None => assert_eq!(reg.query_value(key, name), Err(Error::NotFound)),
                }
            }
            assert_eq!(reg.used, live, "step {step}");
        }
    }
}
