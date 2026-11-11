//! Bounds-checked PE32+ resource directory parsing.
//!
//! The resource directory (`.rsrc`, data directory index 2) is a tree of
//! exactly three levels: resource type, resource name, and language. Each
//! level is an `IMAGE_RESOURCE_DIRECTORY` (16 bytes) followed by its entries
//! (8 bytes each): the named entries first, then the integer IDs. A named
//! entry points at a length-prefixed UTF-16LE string. The third level points
//! at an `IMAGE_RESOURCE_DATA_ENTRY` (16 bytes) holding the data's RVA, size
//! and code page.
//!
//! Every offset inside the tree is relative to the start of the directory and
//! must stay inside the declared directory size, which itself must lie in one
//! section's raw data. Data RVAs are resolved through the section table, and
//! the whole data block must lie in one section's raw data.
//!
//! The tree is validated when the directory is parsed. Entries must point at a
//! subdirectory on the first two levels and at a data entry on the third, so
//! the walk never goes deeper than three levels. A subdirectory that points
//! back at one of its ancestors is a cycle and is rejected. Subdirectories may
//! be shared, so the number of entries visited is capped at
//! [`MAX_RESOURCE_ENTRIES`]. Entry order is not checked; lookup is a linear
//! scan, and names compare with ASCII case folding as `FindResource` does.

use crate::error::{Error, Result};
use crate::pe_common::{MAX_NAME_LEN, SectionRange, read_u16, read_u32, slice_at, table_bytes};
use crate::pe_reloc;

/// Index of the resource data directory (`IMAGE_DIRECTORY_ENTRY_RESOURCE`).
pub const RESOURCE_DIRECTORY_INDEX: usize = 2;

/// Size in bytes of `IMAGE_RESOURCE_DIRECTORY`, the header of each level.
pub const RESOURCE_DIRECTORY_SIZE: usize = 16;

/// Size in bytes of `IMAGE_RESOURCE_DIRECTORY_ENTRY`.
pub const RESOURCE_ENTRY_SIZE: usize = 8;

/// Size in bytes of `IMAGE_RESOURCE_DATA_ENTRY`.
pub const RESOURCE_DATA_ENTRY_SIZE: usize = 16;

/// Maximum number of directory entries visited while validating the tree.
pub const MAX_RESOURCE_ENTRIES: u32 = 65536;

/// Predefined resource types (`RT_*`).
pub const RT_CURSOR: u16 = 1;
/// Bitmap resource type.
pub const RT_BITMAP: u16 = 2;
/// Icon resource type.
pub const RT_ICON: u16 = 3;
/// Menu resource type.
pub const RT_MENU: u16 = 4;
/// Dialog resource type.
pub const RT_DIALOG: u16 = 5;
/// String table resource type.
pub const RT_STRING: u16 = 6;
/// Font directory resource type.
pub const RT_FONTDIR: u16 = 7;
/// Font resource type.
pub const RT_FONT: u16 = 8;
/// Accelerator table resource type.
pub const RT_ACCELERATOR: u16 = 9;
/// Raw data resource type.
pub const RT_RCDATA: u16 = 10;
/// Message table resource type.
pub const RT_MESSAGETABLE: u16 = 11;
/// Cursor group resource type.
pub const RT_GROUP_CURSOR: u16 = 12;
/// Icon group resource type.
pub const RT_GROUP_ICON: u16 = 14;
/// Version information resource type.
pub const RT_VERSION: u16 = 16;
/// Side-by-side manifest resource type.
pub const RT_MANIFEST: u16 = 24;

/// `dwSignature` of a `VS_FIXEDFILEINFO`.
pub const VS_FFI_SIGNATURE: u32 = 0xfeef_04bd;

/// Size in bytes of `VS_FIXEDFILEINFO`.
pub const FIXED_FILE_INFO_SIZE: usize = 52;

/// Set in an entry's name field for a named entry, and in its data field for a
/// subdirectory.
const HIGH_BIT: u32 = 0x8000_0000;

/// Key of a `VS_VERSIONINFO` block.
const VERSION_KEY: &str = "VS_VERSION_INFO";

/// Offset of `szKey` in a `VS_VERSIONINFO` block, after the three length and
/// type words.
const VERSION_KEY_OFFSET: usize = 6;

/// A length-prefixed UTF-16LE resource name, at most `MAX_NAME_LEN` units.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceName<'a> {
    raw: &'a [u8],
}

impl<'a> ResourceName<'a> {
    /// Number of UTF-16 code units; never zero.
    pub fn len(&self) -> usize {
        self.raw.len() / 2
    }

    /// Always false: empty names are rejected while parsing.
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// The name's UTF-16 code units.
    pub fn units(&self) -> impl Iterator<Item = u16> + 'a {
        self.raw
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
    }

    /// Decode the name, yielding an error for each unpaired surrogate.
    pub fn chars(&self) -> impl Iterator<Item = core::result::Result<char, core::char::DecodeUtf16Error>> + 'a {
        char::decode_utf16(self.units())
    }

    /// Compare with `name`, folding ASCII letters to upper case.
    pub fn matches(&self, name: &str) -> bool {
        let mut stored = self.units();
        let mut wanted = name.encode_utf16();
        loop {
            match (stored.next(), wanted.next()) {
                (None, None) => return true,
                (Some(a), Some(b)) if fold(a) == fold(b) => {}
                _ => return false,
            }
        }
    }
}

/// Fold an ASCII lower-case UTF-16 unit to upper case.
fn fold(unit: u16) -> u16 {
    if (u16::from(b'a')..=u16::from(b'z')).contains(&unit) {
        unit - 0x20
    } else {
        unit
    }
}

/// The key of one directory entry: a name or an integer ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceKey<'a> {
    /// An integer ID, such as `RT_VERSION` or a language ID.
    Id(u16),
    /// A string name.
    Name(ResourceName<'a>),
}

/// What to look for at one level of the tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceId<'q> {
    /// Match an entry with this integer ID.
    Id(u16),
    /// Match a named entry, ignoring ASCII case.
    Name(&'q str),
}

impl ResourceKey<'_> {
    /// True when this key is the one `id` asks for.
    pub fn matches(&self, id: ResourceId<'_>) -> bool {
        match (self, id) {
            (ResourceKey::Id(have), ResourceId::Id(want)) => *have == want,
            (ResourceKey::Name(have), ResourceId::Name(want)) => have.matches(want),
            _ => false,
        }
    }
}

/// One `IMAGE_RESOURCE_DATA_ENTRY` and the bytes it describes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceData<'a> {
    /// RVA of the data.
    pub rva: u32,
    /// Size of the data in bytes.
    pub size: u32,
    /// Code page used to decode code point values in the data.
    pub code_page: u32,
    /// The data, inside one section's raw data.
    pub bytes: &'a [u8],
}

/// One leaf of the tree with the keys on its path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Resource<'a> {
    /// First-level key, such as `ResourceKey::Id(RT_ICON)`.
    pub type_key: ResourceKey<'a>,
    /// Second-level key, the resource's name or ID.
    pub name: ResourceKey<'a>,
    /// Third-level key, normally a language ID.
    pub language: ResourceKey<'a>,
    /// The data entry.
    pub data: ResourceData<'a>,
}

/// A validated resource directory tree.
#[derive(Clone, Copy, Debug)]
pub struct ResourceDirectory<'a> {
    bytes: &'a [u8],
    sections: &'a [SectionRange],
    tree: &'a [u8],
    /// Number of data entries (leaves) in the tree, counting shared ones once
    /// per path.
    pub resource_count: u32,
}

/// Iterator over every leaf, in entry order at each level.
///
/// After the first error the iterator yields `None`.
#[derive(Clone, Copy, Debug)]
pub struct Resources<'a> {
    directory: ResourceDirectory<'a>,
    indices: [usize; 3],
    done: bool,
}

/// One level's header: where it starts and how many entries it has.
#[derive(Clone, Copy, Debug)]
struct Level {
    offset: usize,
    named: usize,
    count: usize,
}

/// Where an entry's data field points.
#[derive(Clone, Copy, Debug)]
enum Target {
    Directory(usize),
    Data(usize),
}

#[derive(Clone, Copy, Debug)]
struct Entry<'a> {
    key: ResourceKey<'a>,
    target: Target,
}

impl<'a> ResourceDirectory<'a> {
    /// Parse the resource directory at `rva` spanning `size` bytes.
    ///
    /// An `rva` of zero describes an image without resources and yields an
    /// empty directory. Otherwise the whole tree is walked and validated.
    ///
    /// Errors: `InvalidImage` for a directory outside one section's raw data,
    /// an offset or entry table that leaves the directory, a named entry in
    /// the ID range or the reverse, an ID above 16 bits, a data entry above the
    /// third level or a subdirectory on it, a subdirectory that points at an
    /// ancestor, or data outside one section's raw data. `InvalidName` for a
    /// name that is empty or longer than `MAX_NAME_LEN` units. `TableFull`
    /// when the walk visits more than `MAX_RESOURCE_ENTRIES` entries.
    pub fn parse(
        bytes: &'a [u8],
        sections: &'a [SectionRange],
        rva: u32,
        size: u32,
    ) -> Result<Self> {
        let mut directory = Self {
            bytes,
            sections,
            tree: &[],
            resource_count: 0,
        };
        if rva == 0 {
            return Ok(directory);
        }
        directory.tree = table_bytes(bytes, sections, rva, size as usize)?;
        directory.resource_count = directory.validate()?;
        Ok(directory)
    }

    /// Parse the directory from a PE32+ image's resource data directory slot.
    ///
    /// Errors: those of `pe_reloc::data_directory` (including `NotFound` when
    /// the optional header declares no resource slot), then those of
    /// [`parse`].
    ///
    /// [`parse`]: ResourceDirectory::parse
    pub fn from_image(image: &'a [u8], sections: &'a [SectionRange]) -> Result<Self> {
        let slot = pe_reloc::data_directory(image, RESOURCE_DIRECTORY_INDEX)?;
        Self::parse(image, sections, slot.rva, slot.size)
    }

    /// Find the data for an exact `(type, name, language)` path.
    ///
    /// Returns `NotFound` when any level has no matching entry.
    pub fn lookup(
        &self,
        type_id: ResourceId<'_>,
        name: ResourceId<'_>,
        language: ResourceId<'_>,
    ) -> Result<ResourceData<'a>> {
        let langs = self.languages(type_id, name)?;
        self.leaf(self.find(langs, language)?)
    }

    /// Find the data for `(type, name)` in its first language entry.
    ///
    /// Returns `NotFound` when either level has no matching entry or the
    /// language level is empty.
    pub fn lookup_any_language(
        &self,
        type_id: ResourceId<'_>,
        name: ResourceId<'_>,
    ) -> Result<ResourceData<'a>> {
        let langs = self.languages(type_id, name)?;
        self.leaf(self.first(langs)?)
    }

    /// Parse the fixed part of the first `RT_VERSION` resource.
    ///
    /// Errors: `NotFound` when the image has no version resource or the block
    /// carries no fixed part; otherwise those of
    /// [`FixedFileInfo::from_version_info`].
    pub fn fixed_file_info(&self) -> Result<FixedFileInfo> {
        let root = self.root()?;
        let type_entry = self.find(root, ResourceId::Id(RT_VERSION))?;
        let names = self.subdirectory(type_entry, &[root.offset])?;
        let name_entry = self.first(names)?;
        let langs = self.subdirectory(name_entry, &[root.offset, names.offset])?;
        let data = self.leaf(self.first(langs)?)?;
        FixedFileInfo::from_version_info(data.bytes)
    }

    /// Iterate every resource in entry order.
    pub fn resources(&self) -> Resources<'a> {
        Resources {
            directory: *self,
            indices: [0; 3],
            done: false,
        }
    }

    /// Walk the whole tree once, returning the number of leaves.
    fn validate(&self) -> Result<u32> {
        let mut visited = 0u32;
        let mut leaves = 0u32;
        let mut visit = || {
            visited += 1;
            if visited > MAX_RESOURCE_ENTRIES {
                Err(Error::TableFull)
            } else {
                Ok(())
            }
        };
        let root = self.level(0)?;
        for t in 0..root.count {
            visit()?;
            let names = self.subdirectory(self.entry(root, t)?, &[root.offset])?;
            for n in 0..names.count {
                visit()?;
                let ancestors = [root.offset, names.offset];
                let langs = self.subdirectory(self.entry(names, n)?, &ancestors)?;
                for l in 0..langs.count {
                    visit()?;
                    self.leaf(self.entry(langs, l)?)?;
                    leaves += 1;
                }
            }
        }
        Ok(leaves)
    }

    /// The root level, or `NotFound` for an image without resources.
    fn root(&self) -> Result<Level> {
        if self.tree.is_empty() {
            return Err(Error::NotFound);
        }
        self.level(0)
    }

    /// Resolve the name and language levels for `(type, name)`.
    fn languages(&self, type_id: ResourceId<'_>, name: ResourceId<'_>) -> Result<Level> {
        let root = self.root()?;
        let names = self.subdirectory(self.find(root, type_id)?, &[root.offset])?;
        self.subdirectory(self.find(names, name)?, &[root.offset, names.offset])
    }

    /// Read the level header at `offset` and check its entries fit.
    fn level(&self, offset: usize) -> Result<Level> {
        let header = slice_at(self.tree, offset, RESOURCE_DIRECTORY_SIZE)?;
        let named = usize::from(read_u16(header, 12)?);
        let ids = usize::from(read_u16(header, 14)?);
        let count = named + ids;
        let len = count
            .checked_mul(RESOURCE_ENTRY_SIZE)
            .and_then(|entries| entries.checked_add(RESOURCE_DIRECTORY_SIZE))
            .ok_or(Error::InvalidImage)?;
        slice_at(self.tree, offset, len)?;
        Ok(Level {
            offset,
            named,
            count,
        })
    }

    /// Decode entry `index` of `level`.
    fn entry(&self, level: Level, index: usize) -> Result<Entry<'a>> {
        if index >= level.count {
            return Err(Error::NotFound);
        }
        let at = index
            .checked_mul(RESOURCE_ENTRY_SIZE)
            .and_then(|delta| delta.checked_add(RESOURCE_DIRECTORY_SIZE))
            .and_then(|delta| delta.checked_add(level.offset))
            .ok_or(Error::InvalidImage)?;
        let name_field = read_u32(self.tree, at)?;
        let data_field = read_u32(self.tree, at + 4)?;
        let key = if index < level.named {
            if name_field & HIGH_BIT == 0 {
                return Err(Error::InvalidImage);
            }
            ResourceKey::Name(self.name((name_field & !HIGH_BIT) as usize)?)
        } else {
            let id = u16::try_from(name_field).map_err(|_| Error::InvalidImage)?;
            ResourceKey::Id(id)
        };
        let offset = (data_field & !HIGH_BIT) as usize;
        let target = if data_field & HIGH_BIT != 0 {
            Target::Directory(offset)
        } else {
            Target::Data(offset)
        };
        Ok(Entry { key, target })
    }

    /// Read the length-prefixed UTF-16LE name at `offset`.
    fn name(&self, offset: usize) -> Result<ResourceName<'a>> {
        let units = usize::from(read_u16(self.tree, offset)?);
        if units == 0 || units > MAX_NAME_LEN {
            return Err(Error::InvalidName);
        }
        let start = offset.checked_add(2).ok_or(Error::InvalidImage)?;
        let raw = slice_at(self.tree, start, units * 2)?;
        Ok(ResourceName { raw })
    }

    /// Follow a subdirectory entry, rejecting data entries and cycles.
    fn subdirectory(&self, entry: Entry<'a>, ancestors: &[usize]) -> Result<Level> {
        match entry.target {
            Target::Directory(offset) if !ancestors.contains(&offset) => self.level(offset),
            _ => Err(Error::InvalidImage),
        }
    }

    /// Follow a data entry, rejecting subdirectories below the third level.
    fn leaf(&self, entry: Entry<'a>) -> Result<ResourceData<'a>> {
        let Target::Data(offset) = entry.target else {
            return Err(Error::InvalidImage);
        };
        let raw = slice_at(self.tree, offset, RESOURCE_DATA_ENTRY_SIZE)?;
        let rva = read_u32(raw, 0)?;
        let size = read_u32(raw, 4)?;
        let code_page = read_u32(raw, 8)?;
        let bytes = table_bytes(self.bytes, self.sections, rva, size as usize)?;
        Ok(ResourceData {
            rva,
            size,
            code_page,
            bytes,
        })
    }

    /// Linear search of one level.
    fn find(&self, level: Level, id: ResourceId<'_>) -> Result<Entry<'a>> {
        for index in 0..level.count {
            let entry = self.entry(level, index)?;
            if entry.key.matches(id) {
                return Ok(entry);
            }
        }
        Err(Error::NotFound)
    }

    fn first(&self, level: Level) -> Result<Entry<'a>> {
        self.entry(level, 0)
    }
}

impl<'a> Resources<'a> {
    fn read_next(&mut self) -> Result<Option<Resource<'a>>> {
        let directory = self.directory;
        if directory.tree.is_empty() {
            return Ok(None);
        }
        let root = directory.level(0)?;
        loop {
            let [t, n, l] = self.indices;
            if t >= root.count {
                return Ok(None);
            }
            let type_entry = directory.entry(root, t)?;
            let names = directory.subdirectory(type_entry, &[root.offset])?;
            if n >= names.count {
                self.indices = [t + 1, 0, 0];
                continue;
            }
            let name_entry = directory.entry(names, n)?;
            let langs = directory.subdirectory(name_entry, &[root.offset, names.offset])?;
            if l >= langs.count {
                self.indices = [t, n + 1, 0];
                continue;
            }
            let lang_entry = directory.entry(langs, l)?;
            let data = directory.leaf(lang_entry)?;
            self.indices = [t, n, l + 1];
            return Ok(Some(Resource {
                type_key: type_entry.key,
                name: name_entry.key,
                language: lang_entry.key,
                data,
            }));
        }
    }
}

impl<'a> Iterator for Resources<'a> {
    type Item = Result<Resource<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.read_next() {
            Ok(Some(resource)) => Some(Ok(resource)),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(error) => {
                self.done = true;
                Some(Err(error))
            }
        }
    }
}

/// The fixed part of a version resource (`VS_FIXEDFILEINFO`).
///
/// Versions are `[major, minor, build, revision]`, taken from the high and low
/// words of the most and least significant doublewords.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedFileInfo {
    /// `dwStrucVersion`.
    pub struct_version: u32,
    /// `dwFileVersionMS` and `dwFileVersionLS`.
    pub file_version: [u16; 4],
    /// `dwProductVersionMS` and `dwProductVersionLS`.
    pub product_version: [u16; 4],
    /// `dwFileFlagsMask`.
    pub file_flags_mask: u32,
    /// `dwFileFlags`.
    pub file_flags: u32,
    /// `dwFileOS`.
    pub file_os: u32,
    /// `dwFileType`.
    pub file_type: u32,
    /// `dwFileSubtype`.
    pub file_subtype: u32,
    /// `dwFileDateMS` and `dwFileDateLS` as one 64-bit value.
    pub file_date: u64,
}

impl FixedFileInfo {
    /// Parse a bare 52-byte `VS_FIXEDFILEINFO`.
    ///
    /// Errors: `InvalidImage` when `bytes` is too short or the signature is
    /// not `VS_FFI_SIGNATURE`.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let raw = slice_at(bytes, 0, FIXED_FILE_INFO_SIZE)?;
        let field = |index: usize| read_u32(raw, index * 4);
        if field(0)? != VS_FFI_SIGNATURE {
            return Err(Error::InvalidImage);
        }
        Ok(Self {
            struct_version: field(1)?,
            file_version: version(field(2)?, field(3)?),
            product_version: version(field(4)?, field(5)?),
            file_flags_mask: field(6)?,
            file_flags: field(7)?,
            file_os: field(8)?,
            file_type: field(9)?,
            file_subtype: field(10)?,
            file_date: (u64::from(field(11)?) << 32) | u64::from(field(12)?),
        })
    }

    /// Parse the fixed part of a `VS_VERSIONINFO` block, the data of an
    /// `RT_VERSION` resource.
    ///
    /// The block's `wLength` must fit in `bytes`, its key must be the
    /// NUL-terminated UTF-16 string `VS_VERSION_INFO`, and its value, aligned
    /// to four bytes, must be exactly one `VS_FIXEDFILEINFO`.
    ///
    /// Errors: `NotFound` when `wValueLength` is zero. `InvalidImage` for a
    /// truncated block, a wrong key, a value of any other length, or a bad
    /// signature.
    pub fn from_version_info(bytes: &[u8]) -> Result<Self> {
        let length = usize::from(read_u16(bytes, 0)?);
        let block = slice_at(bytes, 0, length)?;
        let value_length = usize::from(read_u16(block, 2)?);
        let mut at = VERSION_KEY_OFFSET;
        for unit in VERSION_KEY.encode_utf16().chain(core::iter::once(0)) {
            if read_u16(block, at)? != unit {
                return Err(Error::InvalidImage);
            }
            at += 2;
        }
        if value_length == 0 {
            return Err(Error::NotFound);
        }
        if value_length != FIXED_FILE_INFO_SIZE {
            return Err(Error::InvalidImage);
        }
        let value = (at + 3) & !3;
        Self::parse(slice_at(block, value, FIXED_FILE_INFO_SIZE)?)
    }
}

/// Split a version's two doublewords into four words.
fn version(ms: u32, ls: u32) -> [u16; 4] {
    [
        (ms >> 16) as u16,
        ms as u16,
        (ls >> 16) as u16,
        ls as u16,
    ]
}
