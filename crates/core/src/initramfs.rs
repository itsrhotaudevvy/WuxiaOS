//! Allocation-free parsing of boot archives (initramfs images).
//!
//! A boot loader can hand the kernel a module holding a packed file tree. This
//! module reads three archive formats from an untrusted byte slice:
//!
//! - cpio "newc" (magic `070701`), the format Linux uses for initramfs;
//! - cpio "crc" (magic `070702`), which adds a per-file checksum that is
//!   verified here;
//! - POSIX ustar, including the `prefix` field. GNU tar headers (magic
//!   `"ustar  \0"`) are accepted, but their `prefix` area is ignored because
//!   GNU stores timestamps there.
//!
//! [`Archive`] iterates the entries in order. Every header field is bounds- and
//! syntax-checked; a truncated or malformed header yields one error and ends
//! the iteration. Parsing stops at the cpio `TRAILER!!!` entry or at the two
//! zero blocks that end a tar archive, and bytes after that end are ignored.
//! An archive that runs out of bytes before its end marker is an error, so a
//! truncated module is never mistaken for a complete one.
//!
//! Each [`Entry`] carries a normalized relative path: leading `./` components
//! and, for directories, one trailing `/` are removed. The archive root (`.` or
//! `./`) is reported with the empty path and must be a directory. Absolute
//! paths, empty components (`a//b`), `.` or `..` components after the leading
//! ones, NUL bytes and non-UTF-8 names are refused with [`Error::InvalidName`].
//!
//! Directories, regular files and symbolic links are fully supported. Hard
//! links, character and block devices, FIFOs and sockets are reported with
//! their [`EntryKind`] so that the caller can decide; [`populate`] refuses
//! them unless told to skip them. Tar extension headers (pax `x`/`g`, GNU long
//! names) and base-256 numeric fields are refused with [`Error::Unsupported`].
//!
//! [`populate`] builds a [`DirTree`] from an archive. File contents are not
//! stored by the tree; a callback receives every created inode with its entry
//! so the caller can keep the bytes, which stay borrowed from the archive.
//!
//! Errors:
//! - [`Error::InvalidImage`]: bad magic, malformed or truncated header, data
//!   past the end of the input, checksum mismatch, a missing end marker, or a
//!   field that contradicts the entry kind.
//! - [`Error::InvalidName`]: a path or link target that fails normalization.
//! - [`Error::Unsupported`]: a well-formed feature this parser does not handle.

use crate::dirtree::{DirTree, FileKind, InodeId, MAX_PATH_LENGTH};
use crate::path::MAX_COMPONENT_LENGTH;
use crate::{Error, Result};

/// Magic of a cpio "newc" header.
const NEWC_MAGIC: &[u8; 6] = b"070701";
/// Magic of a cpio "crc" header.
const CRC_MAGIC: &[u8; 6] = b"070702";
/// Length of a cpio ASCII header, including the magic.
const CPIO_HEADER_LENGTH: usize = 110;
/// Name of the entry that ends a cpio archive.
const CPIO_TRAILER: &str = "TRAILER!!!";

/// Size of a tar header or data block.
const BLOCK: usize = 512;
/// Longest tar path: a 155-byte prefix, a `/` and a 100-byte name.
pub const MAX_TAR_PATH_LENGTH: usize = 256;

/// Longest normalized path, in bytes, that an entry may carry. One byte is
/// reserved so that the absolute form `/path` fits in a [`DirTree`] path.
pub const MAX_ENTRY_PATH_LENGTH: usize = MAX_PATH_LENGTH - 1;

/// File-type bits of a POSIX mode.
const S_IFMT: u32 = 0o170_000;
const S_IFSOCK: u32 = 0o140_000;
const S_IFLNK: u32 = 0o120_000;
const S_IFREG: u32 = 0o100_000;
const S_IFBLK: u32 = 0o060_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFCHR: u32 = 0o020_000;
const S_IFIFO: u32 = 0o010_000;
/// Permission, set-id and sticky bits.
const PERMISSION_BITS: u32 = 0o7777;

/// An archive container format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Format {
    /// cpio "newc" (`070701`).
    CpioNewc,
    /// cpio "crc" (`070702`), with a verified per-file checksum.
    CpioCrc,
    /// POSIX ustar, or a GNU tar header in the same layout.
    Ustar,
}

/// The kind of object an archive entry describes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryKind {
    /// A regular file whose contents are [`Entry::data`].
    Regular,
    /// A directory.
    Directory,
    /// A symbolic link whose target is [`Entry::link`].
    Symlink,
    /// A hard link. In tar, [`Entry::link`] names the earlier entry. In cpio,
    /// a regular file whose link count exceeds one; its data may be empty
    /// because cpio stores the contents only with the last link.
    HardLink,
    /// A character device.
    CharDevice,
    /// A block device.
    BlockDevice,
    /// A named pipe.
    Fifo,
    /// A socket (cpio only).
    Socket,
}

/// Where an entry's normalized path is stored.
///
/// `Joined` inlines a whole path buffer, so it is much larger than
/// `Borrowed`. The core has no allocator and an `Entry` lives on the caller's
/// stack for one archive walk, so the asymmetry is deliberate.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug)]
enum StoredPath<'a> {
    /// A slice of the archive itself.
    Borrowed(&'a str),
    /// A tar `prefix/name` joined into a local buffer; `start..end` is the
    /// normalized part.
    Joined {
        bytes: [u8; MAX_TAR_PATH_LENGTH],
        start: usize,
        end: usize,
    },
}

/// One validated archive entry.
#[derive(Clone, Copy, Debug)]
pub struct Entry<'a> {
    path: StoredPath<'a>,
    /// The kind of object.
    pub kind: EntryKind,
    /// Permission, set-id and sticky bits (`mode & 0o7777`).
    pub mode: u32,
    /// Number of content bytes, always equal to `data.len()`.
    pub size: usize,
    /// File contents: present for [`EntryKind::Regular`] and possibly for a
    /// cpio [`EntryKind::HardLink`], empty otherwise.
    pub data: &'a [u8],
    /// Target of a symbolic link or a tar hard link; empty otherwise. It is
    /// non-empty, free of NUL and valid UTF-8, but not normalized.
    pub link: &'a str,
}

impl Entry<'_> {
    /// The normalized relative path. The archive root is the empty string.
    pub fn path(&self) -> &str {
        match &self.path {
            StoredPath::Borrowed(path) => path,
            StoredPath::Joined { bytes, start, end } => bytes
                .get(*start..*end)
                .and_then(|slice| core::str::from_utf8(slice).ok())
                .unwrap_or(""),
        }
    }
}

/// Identify the format of `data` from its first header.
///
/// An input that begins with a zero block is treated as an (empty) ustar
/// archive. Errors: [`Error::InvalidImage`] when no format matches.
pub fn detect(data: &[u8]) -> Result<Format> {
    match data.get(..NEWC_MAGIC.len()) {
        Some(magic) if magic == NEWC_MAGIC => return Ok(Format::CpioNewc),
        Some(magic) if magic == CRC_MAGIC => return Ok(Format::CpioCrc),
        _ => {}
    }
    let block = data.get(..BLOCK).ok_or(Error::InvalidImage)?;
    if is_zero(block) || tar_flavor(block).is_some() {
        Ok(Format::Ustar)
    } else {
        Err(Error::InvalidImage)
    }
}

/// An iterator over the entries of an archive.
///
/// Each item is either a validated [`Entry`] or the first error encountered;
/// after an error or the end marker the iterator yields nothing more.
#[derive(Clone, Debug)]
pub struct Archive<'a> {
    data: &'a [u8],
    format: Format,
    offset: usize,
    done: bool,
}

impl<'a> Archive<'a> {
    /// Open `data`, detecting its format with [`detect`].
    pub fn new(data: &'a [u8]) -> Result<Self> {
        Ok(Self::with_format(data, detect(data)?))
    }

    /// Open `data` as an archive of the given format, without detection.
    pub const fn with_format(data: &'a [u8], format: Format) -> Self {
        Self {
            data,
            format,
            offset: 0,
            done: false,
        }
    }

    /// The archive's format.
    pub const fn format(&self) -> Format {
        self.format
    }

    fn step(&mut self) -> Result<Option<Entry<'a>>> {
        match self.format {
            Format::CpioNewc | Format::CpioCrc => self.next_cpio(),
            Format::Ustar => self.next_tar(),
        }
    }

    fn next_cpio(&mut self) -> Result<Option<Entry<'a>>> {
        let start = self.offset;
        let header_end = start
            .checked_add(CPIO_HEADER_LENGTH)
            .ok_or(Error::InvalidImage)?;
        let header = self
            .data
            .get(start..header_end)
            .ok_or(Error::InvalidImage)?;
        let crc = match header.get(..6) {
            Some(magic) if magic == NEWC_MAGIC && self.format == Format::CpioNewc => false,
            Some(magic) if magic == CRC_MAGIC && self.format == Format::CpioCrc => true,
            _ => return Err(Error::InvalidImage),
        };
        // Thirteen 8-digit hexadecimal fields follow the magic.
        let field = |index: usize| -> Result<u32> {
            let at = 6 + index * 8;
            parse_hex(header.get(at..at + 8).ok_or(Error::InvalidImage)?)
        };
        let raw_mode = field(1)?;
        let nlink = field(4)?;
        let file_size = usize::try_from(field(6)?).map_err(|_| Error::InvalidImage)?;
        let name_size = usize::try_from(field(11)?).map_err(|_| Error::InvalidImage)?;
        let check = field(12)?;

        let name_end = header_end
            .checked_add(name_size)
            .ok_or(Error::InvalidImage)?;
        let name_field = self
            .data
            .get(header_end..name_end)
            .ok_or(Error::InvalidImage)?;
        // The name size counts a terminating NUL, which must be the only one.
        let (&terminator, name) = name_field.split_last().ok_or(Error::InvalidImage)?;
        if terminator != 0 {
            return Err(Error::InvalidImage);
        }
        if name.contains(&0) {
            return Err(Error::InvalidName);
        }
        let name = core::str::from_utf8(name).map_err(|_| Error::InvalidName)?;
        if name == CPIO_TRAILER {
            return Ok(None);
        }

        let data_start = align(name_end, 4)?;
        let data_end = data_start
            .checked_add(file_size)
            .ok_or(Error::InvalidImage)?;
        let contents = self
            .data
            .get(data_start..data_end)
            .ok_or(Error::InvalidImage)?;
        self.offset = align(data_end, 4)?;

        let kind = match raw_mode & S_IFMT {
            S_IFREG if nlink > 1 => EntryKind::HardLink,
            S_IFREG => EntryKind::Regular,
            S_IFDIR => EntryKind::Directory,
            S_IFLNK => EntryKind::Symlink,
            S_IFCHR => EntryKind::CharDevice,
            S_IFBLK => EntryKind::BlockDevice,
            S_IFIFO => EntryKind::Fifo,
            S_IFSOCK => EntryKind::Socket,
            _ => return Err(Error::InvalidImage),
        };
        if crc {
            let sum = contents
                .iter()
                .fold(0u32, |sum, &byte| sum.wrapping_add(u32::from(byte)));
            let verified = match kind {
                EntryKind::Regular | EntryKind::HardLink => check == sum,
                // Writers differ on whether non-file entries are summed.
                _ => check == sum || check == 0,
            };
            if !verified {
                return Err(Error::InvalidImage);
            }
        }

        let (data, link) = match kind {
            EntryKind::Regular | EntryKind::HardLink => (contents, ""),
            EntryKind::Symlink => (&[][..], check_link(contents)?),
            _ if contents.is_empty() => (&[][..], ""),
            _ => return Err(Error::InvalidImage),
        };
        let path = normalize(name, kind)?;
        Ok(Some(Entry {
            path: StoredPath::Borrowed(path),
            kind,
            mode: raw_mode & PERMISSION_BITS,
            size: data.len(),
            data,
            link,
        }))
    }

    fn next_tar(&mut self) -> Result<Option<Entry<'a>>> {
        let start = self.offset;
        let header = block_at(self.data, start)?;
        if is_zero(header) {
            // The end marker is two consecutive zero blocks.
            let second = block_at(
                self.data,
                start.checked_add(BLOCK).ok_or(Error::InvalidImage)?,
            )?;
            return if is_zero(second) {
                Ok(None)
            } else {
                Err(Error::InvalidImage)
            };
        }
        let flavor = tar_flavor(header).ok_or(Error::InvalidImage)?;
        let stored_sum = parse_octal(field(header, 148, 8)?)?;
        let actual_sum = header
            .iter()
            .enumerate()
            .map(|(index, &byte)| {
                if (148..156).contains(&index) {
                    u64::from(b' ')
                } else {
                    u64::from(byte)
                }
            })
            .sum::<u64>();
        if stored_sum != actual_sum {
            return Err(Error::InvalidImage);
        }

        let typeflag = header.get(156).copied().ok_or(Error::InvalidImage)?;
        let kind = match typeflag {
            b'0' | 0 | b'7' => EntryKind::Regular,
            b'1' => EntryKind::HardLink,
            b'2' => EntryKind::Symlink,
            b'3' => EntryKind::CharDevice,
            b'4' => EntryKind::BlockDevice,
            b'5' => EntryKind::Directory,
            b'6' => EntryKind::Fifo,
            _ => return Err(Error::Unsupported),
        };
        let mode = u32::try_from(parse_octal(field(header, 100, 8)?)? & u64::from(PERMISSION_BITS))
            .map_err(|_| Error::InvalidImage)?;
        let size = usize::try_from(parse_octal(field(header, 124, 12)?)?)
            .map_err(|_| Error::InvalidImage)?;

        let data_start = start.checked_add(BLOCK).ok_or(Error::InvalidImage)?;
        let data_end = data_start.checked_add(size).ok_or(Error::InvalidImage)?;
        let contents = self
            .data
            .get(data_start..data_end)
            .ok_or(Error::InvalidImage)?;
        if kind != EntryKind::Regular && size != 0 {
            return Err(Error::InvalidImage);
        }
        let link = match kind {
            EntryKind::Symlink | EntryKind::HardLink => {
                check_link(until_nul(field(header, 157, 100)?))?
            }
            _ => "",
        };

        let name = until_nul(field(header, 0, 100)?);
        let prefix = match flavor {
            TarFlavor::Posix => until_nul(field(header, 345, 155)?),
            TarFlavor::Gnu => &[],
        };
        let path = if prefix.is_empty() {
            let name = utf8_name(name)?;
            StoredPath::Borrowed(normalize(name, kind)?)
        } else {
            let mut bytes = [0u8; MAX_TAR_PATH_LENGTH];
            let total = prefix.len() + 1 + name.len();
            let joined = bytes.get_mut(..total).ok_or(Error::InvalidName)?;
            let (head, tail) = joined.split_at_mut(prefix.len());
            head.copy_from_slice(prefix);
            let (slash, rest) = tail.split_first_mut().ok_or(Error::InvalidName)?;
            *slash = b'/';
            rest.copy_from_slice(name);
            let text = utf8_name(joined)?;
            let (start, end) = normalized_range(text, kind)?;
            StoredPath::Joined { bytes, start, end }
        };

        self.offset = align(data_end, BLOCK)?;
        Ok(Some(Entry {
            path,
            kind,
            mode,
            size,
            data: contents,
            link,
        }))
    }
}

impl<'a> Iterator for Archive<'a> {
    type Item = Result<Entry<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.step() {
            Ok(Some(entry)) => Some(Ok(entry)),
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

/// Bounds applied by [`populate`] in addition to the tree's own capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Most entries the archive may contain, the root entry included.
    pub max_entries: usize,
    /// Most bytes of regular-file contents, summed over all files.
    pub max_total_size: usize,
    /// Skip hard links, devices, FIFOs and sockets instead of refusing the
    /// archive with [`Error::Unsupported`].
    pub skip_unsupported: bool,
}

/// Counts reported by a successful [`populate`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Summary {
    /// Entries read from the archive, skipped ones included.
    pub entries: usize,
    /// Directories created, including ones implied by a deeper path.
    pub directories: usize,
    /// Regular files created.
    pub files: usize,
    /// Symbolic links created.
    pub symlinks: usize,
    /// Entries skipped because `skip_unsupported` was set.
    pub skipped: usize,
    /// Sum of regular-file sizes.
    pub total_size: usize,
}

/// Populate `tree` from the archive in `data`.
///
/// The whole archive is validated against `limits` before the tree is touched,
/// so a malformed, oversized or (without `skip_unsupported`) unsupported
/// archive leaves the tree unchanged. Each entry's path is created below `/`;
/// missing parent directories are created, and a directory entry for a
/// directory that already exists is accepted. `on_inode` is called once for
/// every entry that names an inode, the root entry included, with that
/// inode's identifier; the caller keeps the file contents and modes it needs.
///
/// Errors: those of [`Archive`], [`Error::OutOfRange`] when `limits` is
/// exceeded, [`Error::Unsupported`] for refused kinds, and the [`DirTree`]
/// errors (notably [`Error::TableFull`] and [`Error::AlreadyExists`] for a
/// duplicate path) or any error returned by `on_inode`. Those last errors can
/// occur after part of the archive has been applied, so the caller should
/// discard the tree when `populate` fails.
pub fn populate<const INODES: usize, const ENTRIES: usize, F>(
    tree: &mut DirTree<INODES, ENTRIES>,
    data: &[u8],
    limits: &Limits,
    mut on_inode: F,
) -> Result<Summary>
where
    F: FnMut(InodeId, &Entry<'_>) -> Result<()>,
{
    // First pass: validate the archive completely.
    let mut entries = 0usize;
    let mut total_size = 0usize;
    for entry in Archive::new(data)? {
        let entry = entry?;
        entries += 1;
        if entries > limits.max_entries {
            return Err(Error::OutOfRange);
        }
        if entry.kind == EntryKind::Regular {
            total_size = total_size
                .checked_add(entry.size)
                .filter(|&total| total <= limits.max_total_size)
                .ok_or(Error::OutOfRange)?;
        }
        if entry.path().is_empty() && entry.kind != EntryKind::Directory {
            return Err(Error::InvalidName);
        }
        if !supported(entry.kind) && !limits.skip_unsupported {
            return Err(Error::Unsupported);
        }
    }

    // Second pass: apply it.
    let mut summary = Summary {
        entries,
        total_size,
        ..Summary::default()
    };
    let mut buffer = [0u8; MAX_PATH_LENGTH];
    for entry in Archive::new(data)? {
        let entry = entry?;
        if !supported(entry.kind) {
            summary.skipped += 1;
            continue;
        }
        let relative = entry.path();
        if relative.is_empty() {
            on_inode(InodeId::ROOT, &entry)?;
            continue;
        }
        let absolute = absolute_path(&mut buffer, relative)?;
        summary.directories += create_parents(tree, absolute)?;
        let id = match entry.kind {
            EntryKind::Directory => match tree.resolve(absolute) {
                Ok(id) if tree.stat(id)?.kind == FileKind::Directory => id,
                Ok(_) => return Err(Error::AlreadyExists),
                Err(Error::NotFound) => {
                    summary.directories += 1;
                    tree.mkdir(absolute)?
                }
                Err(error) => return Err(error),
            },
            EntryKind::Regular => {
                summary.files += 1;
                tree.create(absolute)?
            }
            EntryKind::Symlink => {
                summary.symlinks += 1;
                tree.symlink(entry.link, absolute)?
            }
            _ => return Err(Error::Unsupported),
        };
        on_inode(id, &entry)?;
    }
    Ok(summary)
}

/// Whether [`populate`] can represent an entry of this kind.
fn supported(kind: EntryKind) -> bool {
    matches!(
        kind,
        EntryKind::Regular | EntryKind::Directory | EntryKind::Symlink
    )
}

/// Write `/relative` into `buffer` and return it.
fn absolute_path<'b>(buffer: &'b mut [u8; MAX_PATH_LENGTH], relative: &str) -> Result<&'b str> {
    let total = relative.len().checked_add(1).ok_or(Error::InvalidName)?;
    let out = buffer.get_mut(..total).ok_or(Error::InvalidName)?;
    let (slash, rest) = out.split_first_mut().ok_or(Error::InvalidName)?;
    *slash = b'/';
    rest.copy_from_slice(relative.as_bytes());
    core::str::from_utf8(out).map_err(|_| Error::InvalidName)
}

/// Create every missing ancestor directory of `absolute`; return how many.
fn create_parents<const I: usize, const E: usize>(
    tree: &mut DirTree<I, E>,
    absolute: &str,
) -> Result<usize> {
    let mut created = 0;
    for (index, byte) in absolute.bytes().enumerate().skip(1) {
        if byte != b'/' {
            continue;
        }
        let parent = absolute.get(..index).ok_or(Error::InvalidName)?;
        match tree.resolve(parent) {
            Ok(id) if tree.stat(id)?.kind == FileKind::Directory => {}
            Ok(_) => return Err(Error::InvalidState),
            Err(Error::NotFound) => {
                tree.mkdir(parent)?;
                created += 1;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(created)
}

/// Normalize an archive path for an entry of `kind`.
///
/// Leading `.` components are dropped, and a directory may end in one `/`.
/// What remains must be empty (the root) or a sequence of non-empty
/// components other than `.` and `..`, each at most
/// [`MAX_COMPONENT_LENGTH`] bytes, with no NUL.
fn normalize(path: &str, kind: EntryKind) -> Result<&str> {
    let (start, end) = normalized_range(path, kind)?;
    path.get(start..end).ok_or(Error::InvalidName)
}

/// The byte range of `path` that [`normalize`] keeps.
fn normalized_range(path: &str, kind: EntryKind) -> Result<(usize, usize)> {
    if path.is_empty() || path.starts_with('/') || path.contains('\0') {
        return Err(Error::InvalidName);
    }
    let mut start = 0;
    let mut end = path.len();
    while path
        .get(start..end)
        .is_some_and(|rest| rest.starts_with("./"))
    {
        start += 2;
    }
    if path.get(start..end) == Some(".") {
        start = end;
    }
    if start < end && path.as_bytes().get(end - 1) == Some(&b'/') {
        if kind != EntryKind::Directory {
            return Err(Error::InvalidName);
        }
        end -= 1;
    }
    if start >= end {
        return Ok((end, end));
    }
    let rest = path.get(start..end).ok_or(Error::InvalidName)?;
    if rest.len() > MAX_ENTRY_PATH_LENGTH {
        return Err(Error::InvalidName);
    }
    for component in rest.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.len() > MAX_COMPONENT_LENGTH
        {
            return Err(Error::InvalidName);
        }
    }
    Ok((start, end))
}

/// Validate a link target: non-empty, NUL-free UTF-8 of bounded length.
fn check_link(bytes: &[u8]) -> Result<&str> {
    if bytes.is_empty() || bytes.len() > MAX_ENTRY_PATH_LENGTH || bytes.contains(&0) {
        return Err(Error::InvalidName);
    }
    core::str::from_utf8(bytes).map_err(|_| Error::InvalidName)
}

fn utf8_name(bytes: &[u8]) -> Result<&str> {
    core::str::from_utf8(bytes).map_err(|_| Error::InvalidName)
}

/// Round `value` up to a multiple of `alignment`, a power of two.
fn align(value: usize, alignment: usize) -> Result<usize> {
    value
        .checked_add(alignment - 1)
        .map(|sum| sum & !(alignment - 1))
        .ok_or(Error::InvalidImage)
}

/// Parse exactly eight ASCII hexadecimal digits.
fn parse_hex(digits: &[u8]) -> Result<u32> {
    if digits.len() != 8 {
        return Err(Error::InvalidImage);
    }
    digits.iter().try_fold(0u32, |value, &digit| {
        let nibble = char::from(digit).to_digit(16).ok_or(Error::InvalidImage)?;
        Ok((value << 4) | nibble)
    })
}

/// Parse a tar octal field: optional leading spaces, octal digits, then only
/// NUL or space. An empty field is zero. Base-256 fields are unsupported.
fn parse_octal(field: &[u8]) -> Result<u64> {
    if field.first().is_some_and(|&byte| byte & 0x80 != 0) {
        return Err(Error::Unsupported);
    }
    let mut bytes = field.iter().skip_while(|&&byte| byte == b' ').peekable();
    let mut value = 0u64;
    while let Some(&&digit) = bytes.peek() {
        if !(b'0'..=b'7').contains(&digit) {
            break;
        }
        value = value
            .checked_mul(8)
            .and_then(|value| value.checked_add(u64::from(digit - b'0')))
            .ok_or(Error::InvalidImage)?;
        bytes.next();
    }
    if bytes.all(|&byte| byte == 0 || byte == b' ') {
        Ok(value)
    } else {
        Err(Error::InvalidImage)
    }
}

/// The header dialect of a tar block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TarFlavor {
    /// POSIX ustar: magic `"ustar\0"`, version `"00"`.
    Posix,
    /// GNU tar: magic `"ustar "`, version `" \0"`.
    Gnu,
}

fn tar_flavor(header: &[u8]) -> Option<TarFlavor> {
    match header.get(257..265)? {
        b"ustar\x0000" => Some(TarFlavor::Posix),
        b"ustar  \x00" => Some(TarFlavor::Gnu),
        _ => None,
    }
}

fn block_at(data: &[u8], offset: usize) -> Result<&[u8]> {
    let end = offset.checked_add(BLOCK).ok_or(Error::InvalidImage)?;
    data.get(offset..end).ok_or(Error::InvalidImage)
}

fn field(header: &[u8], offset: usize, length: usize) -> Result<&[u8]> {
    header
        .get(offset..offset + length)
        .ok_or(Error::InvalidImage)
}

/// The bytes of a NUL-terminated (or full-width) tar string field.
fn until_nul(field: &[u8]) -> &[u8] {
    let end = field
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(field.len());
    field.get(..end).unwrap_or(field)
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&byte| byte == 0)
}
