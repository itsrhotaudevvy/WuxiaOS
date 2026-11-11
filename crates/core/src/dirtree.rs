//! Fixed-capacity hierarchical POSIX inode tree, holding metadata only.
//!
//! The tree models directories, regular files and symbolic links as inodes
//! linked by directory entries. Each entry records its parent directory, its
//! name and the inode it names. Inode 0 is the root `/`. Regular files carry no
//! bytes here: they exist as named, counted inodes so that hard links, unlinks
//! and renames can be checked before a file system stores any data.
//!
//! Names are case-sensitive and may not be empty, `.` or `..`, nor contain `/`
//! or NUL. `.` and `..` are never stored, so `readdir` reports only real
//! entries.
//!
//! Paths are not resolved through symbolic links. Traversing a symbolic link
//! as a directory fails with [`Error::InvalidState`]; a caller that wants to
//! follow one reads it with [`DirTree::readlink`] and resolves again.
//!
//! An [`InodeId`] carries the generation of its slot. When an inode is freed
//! and its slot reused, earlier identifiers are refused with [`Error::NotFound`]
//! rather than silently naming the new inode.
//!
//! Errors reuse the shared vocabulary:
//! - [`Error::NotFound`]: a component, entry or identifier is absent.
//! - [`Error::InvalidName`]: a path, name or symbolic-link target is malformed
//!   or too long.
//! - [`Error::InvalidState`]: an operation does not fit the object's kind, such
//!   as unlinking a directory, traversing a file or removing a non-empty one.
//! - [`Error::InvalidInput`]: a rename would move a directory into its own
//!   subtree.
//! - [`Error::PermissionDenied`]: an operation targets the protected root, or
//!   hard-links a directory.
//! - [`Error::AlreadyExists`], [`Error::TableFull`] and [`Error::OutOfRange`]:
//!   as elsewhere in the core.

use crate::path::{MAX_COMPONENT_LENGTH, components, validate_absolute};
use crate::{Error, Result};

/// Longest name, in bytes, that a directory entry can hold.
pub const MAX_NAME_LENGTH: usize = MAX_COMPONENT_LENGTH;

/// Longest path, in bytes, that the tree accepts.
pub const MAX_PATH_LENGTH: usize = 4096;

/// Longest symbolic-link target, in bytes, that an inode can hold.
pub const MAX_TARGET_LENGTH: usize = 255;

/// Slot index of the root directory.
const ROOT: usize = 0;

/// The kind of object an inode represents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileKind {
    /// A directory, which can contain entries.
    Directory,
    /// A regular file.
    Regular,
    /// A symbolic link whose target is stored in the inode.
    Symlink,
}

/// Identifier of an inode, valid until that inode is freed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InodeId {
    index: usize,
    generation: u64,
}

impl InodeId {
    /// Identifier of the root directory `/`, which is always present.
    pub const ROOT: Self = Self {
        index: ROOT,
        generation: 0,
    };
}

/// Metadata reported by [`DirTree::stat`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stat {
    /// The kind of object.
    pub kind: FileKind,
    /// Number of directory entries that name this inode.
    pub nlink: u32,
    /// Generation of the slot holding this inode.
    pub generation: u64,
}

/// One directory entry returned by [`DirTree::readdir`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirEntry<'a> {
    /// The entry's name, in the case it was created with.
    pub name: &'a str,
    /// The inode the entry names.
    pub inode: InodeId,
}

#[derive(Clone, Copy, Debug)]
struct Inode {
    live: bool,
    kind: FileKind,
    nlink: u32,
    generation: u64,
    target: [u8; MAX_TARGET_LENGTH],
    target_length: usize,
}

impl Inode {
    const VACANT: Self = Self {
        live: false,
        kind: FileKind::Regular,
        nlink: 0,
        generation: 0,
        target: [0; MAX_TARGET_LENGTH],
        target_length: 0,
    };
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    used: bool,
    parent: usize,
    child: usize,
    name: [u8; MAX_NAME_LENGTH],
    name_length: usize,
}

impl Entry {
    const VACANT: Self = Self {
        used: false,
        parent: ROOT,
        child: ROOT,
        name: [0; MAX_NAME_LENGTH],
        name_length: 0,
    };

    fn name(&self) -> &[u8] {
        self.name.get(..self.name_length).unwrap_or(&[])
    }
}

/// A fixed-capacity inode tree with `INODES` inode slots and `ENTRIES`
/// directory-entry slots.
///
/// The root occupies inode slot 0 and counts against `INODES`. With
/// `INODES == 0` no object exists, so every lookup fails. Every directory
/// entry names exactly one inode, and every directory is named by exactly one
/// entry, because directories cannot be hard-linked.
#[derive(Clone, Copy, Debug)]
pub struct DirTree<const INODES: usize, const ENTRIES: usize> {
    inodes: [Inode; INODES],
    entries: [Entry; ENTRIES],
}

impl<const INODES: usize, const ENTRIES: usize> Default for DirTree<INODES, ENTRIES> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const INODES: usize, const ENTRIES: usize> DirTree<INODES, ENTRIES> {
    /// Construct a tree holding only the root directory `/`.
    ///
    /// The root's `nlink` is fixed at 1, since no entry names it.
    pub const fn new() -> Self {
        let mut inodes = [Inode::VACANT; INODES];
        if INODES > 0 {
            inodes[ROOT] = Inode {
                live: true,
                kind: FileKind::Directory,
                nlink: 1,
                generation: 0,
                target: [0; MAX_TARGET_LENGTH],
                target_length: 0,
            };
        }
        Self {
            inodes,
            entries: [Entry::VACANT; ENTRIES],
        }
    }

    /// Resolve an absolute path to its inode without following symbolic links.
    ///
    /// A symbolic link at the end of the path is returned as itself. A path
    /// with a trailing `/` must name a directory.
    ///
    /// Errors: [`Error::InvalidName`] for a malformed path, [`Error::NotFound`]
    /// when a component is absent, and [`Error::InvalidState`] when a component
    /// before the end is not a directory.
    pub fn resolve(&self, path: &str) -> Result<InodeId> {
        let index = self.walk(path)?;
        self.id_of(index)
    }

    /// Create a directory at `path`.
    ///
    /// Errors: [`Error::AlreadyExists`] when the name is taken or the path is
    /// the root, plus those of [`resolve`](Self::resolve) for the parent, and
    /// [`Error::TableFull`] when no entry or inode slot remains.
    pub fn mkdir(&mut self, path: &str) -> Result<InodeId> {
        let (dir, name) = self.new_name(path)?;
        let slot = self.free_entry()?;
        let child = self.allocate(FileKind::Directory, &[])?;
        self.fill_entry(slot, dir, child, name.as_bytes());
        self.id_of(child)
    }

    /// Create an empty regular file at `path`.
    ///
    /// Errors are those of [`mkdir`](Self::mkdir).
    pub fn create(&mut self, path: &str) -> Result<InodeId> {
        let (dir, name) = self.new_name(path)?;
        let slot = self.free_entry()?;
        let child = self.allocate(FileKind::Regular, &[])?;
        self.fill_entry(slot, dir, child, name.as_bytes());
        self.id_of(child)
    }

    /// Create a symbolic link at `path` whose target is `target`.
    ///
    /// The target is stored verbatim and is not checked against the tree. It
    /// must be non-empty, free of NUL, and at most [`MAX_TARGET_LENGTH`] bytes;
    /// otherwise the call fails with [`Error::InvalidName`].
    ///
    /// Other errors are those of [`mkdir`](Self::mkdir).
    pub fn symlink(&mut self, target: &str, path: &str) -> Result<InodeId> {
        check_target(target)?;
        let (dir, name) = self.new_name(path)?;
        let slot = self.free_entry()?;
        let child = self.allocate(FileKind::Symlink, target.as_bytes())?;
        self.fill_entry(slot, dir, child, name.as_bytes());
        self.id_of(child)
    }

    /// Add a hard link named `path` to the existing non-directory at `existing`.
    ///
    /// Errors: [`Error::PermissionDenied`] when `existing` is a directory,
    /// [`Error::AlreadyExists`] when `path` is taken, [`Error::OutOfRange`] when
    /// the link count would overflow, plus those of [`resolve`](Self::resolve).
    pub fn link(&mut self, existing: &str, path: &str) -> Result<()> {
        let source = self.walk(existing)?;
        if self.node(source)?.kind == FileKind::Directory {
            return Err(Error::PermissionDenied);
        }
        let (dir, name) = self.new_name(path)?;
        let slot = self.free_entry()?;
        let links = self
            .node(source)?
            .nlink
            .checked_add(1)
            .ok_or(Error::OutOfRange)?;
        self.fill_entry(slot, dir, source, name.as_bytes());
        self.node_mut(source)?.nlink = links;
        Ok(())
    }

    /// Remove the name `path` and free its inode once no names remain.
    ///
    /// Errors: [`Error::InvalidState`] when `path` is a directory or the root,
    /// [`Error::NotFound`] when the name is absent, plus those of
    /// [`resolve`](Self::resolve).
    pub fn unlink(&mut self, path: &str) -> Result<()> {
        let (dir, name) = self.locate(path)?.ok_or(Error::InvalidState)?;
        let slot = self
            .find_entry(dir, name.as_bytes())?
            .ok_or(Error::NotFound)?;
        let child = self.entry(slot)?.child;
        if self.node(child)?.kind == FileKind::Directory {
            return Err(Error::InvalidState);
        }
        self.remove_entry(slot);
        self.release_link(child)
    }

    /// Remove the empty directory at `path`.
    ///
    /// Errors: [`Error::PermissionDenied`] for the root, [`Error::InvalidState`]
    /// when the target is not a directory or is not empty, and [`Error::NotFound`]
    /// when the name is absent.
    pub fn rmdir(&mut self, path: &str) -> Result<()> {
        let (dir, name) = self.locate(path)?.ok_or(Error::PermissionDenied)?;
        let slot = self
            .find_entry(dir, name.as_bytes())?
            .ok_or(Error::NotFound)?;
        let child = self.entry(slot)?.child;
        if self.node(child)?.kind != FileKind::Directory || self.has_children(child) {
            return Err(Error::InvalidState);
        }
        self.remove_entry(slot);
        self.release_link(child)
    }

    /// Move the name `old` to `new`, replacing an existing `new` when allowed.
    ///
    /// Rules:
    /// - Renaming a name to a link of the same inode succeeds and changes nothing,
    ///   as POSIX requires.
    /// - A directory cannot move into its own subtree, nor onto itself:
    ///   [`Error::InvalidInput`].
    /// - A file may replace an existing file, and a directory may replace an
    ///   empty directory. Replacing across kinds, or replacing a non-empty
    ///   directory, fails with [`Error::InvalidState`].
    /// - The replacement is a single change to the tree, so a failure leaves
    ///   the old name in place and the new name unchanged.
    ///
    /// Errors: [`Error::PermissionDenied`] when either path is the root,
    /// [`Error::NotFound`] when `old` is absent, plus those of
    /// [`resolve`](Self::resolve) for either path.
    pub fn rename(&mut self, old: &str, new: &str) -> Result<()> {
        let (old_dir, old_name) = self.locate(old)?.ok_or(Error::PermissionDenied)?;
        let old_slot = self
            .find_entry(old_dir, old_name.as_bytes())?
            .ok_or(Error::NotFound)?;
        let source = self.entry(old_slot)?.child;
        let source_is_dir = self.node(source)?.kind == FileKind::Directory;

        let (new_dir, new_name) = self.locate(new)?.ok_or(Error::PermissionDenied)?;
        check_name(new_name)?;
        let new_slot = self.find_entry(new_dir, new_name.as_bytes())?;
        if let Some(slot) = new_slot
            && self.entry(slot)?.child == source
        {
            return Ok(());
        }
        if source_is_dir && self.is_within(new_dir, source) {
            return Err(Error::InvalidInput);
        }

        match new_slot {
            Some(target_slot) => {
                let target = self.entry(target_slot)?.child;
                let target_is_dir = self.node(target)?.kind == FileKind::Directory;
                if source_is_dir != target_is_dir {
                    return Err(Error::InvalidState);
                }
                if target_is_dir && self.has_children(target) {
                    return Err(Error::InvalidState);
                }
                self.fill_entry(target_slot, new_dir, source, new_name.as_bytes());
                self.remove_entry(old_slot);
                self.release_link(target)
            }
            None => {
                self.fill_entry(old_slot, new_dir, source, new_name.as_bytes());
                Ok(())
            }
        }
    }

    /// Return the `index`-th entry of directory `dir`, or `None` past the end.
    ///
    /// Entries are reported in slot order, which changes when entries are
    /// removed, so an index is only meaningful until the directory changes.
    /// `.` and `..` are not reported because they are never stored.
    ///
    /// Errors: [`Error::NotFound`] for a stale or unknown identifier and
    /// [`Error::InvalidState`] when `dir` is not a directory.
    pub fn readdir(&self, dir: InodeId, index: usize) -> Result<Option<DirEntry<'_>>> {
        let dir = self.index_of(dir)?;
        if self.node(dir)?.kind != FileKind::Directory {
            return Err(Error::InvalidState);
        }
        let Some(entry) = self
            .entries
            .iter()
            .filter(|entry| entry.used && entry.parent == dir)
            .nth(index)
        else {
            return Ok(None);
        };
        let name = core::str::from_utf8(entry.name()).map_err(|_| Error::InvalidInput)?;
        Ok(Some(DirEntry {
            name,
            inode: self.id_of(entry.child)?,
        }))
    }

    /// Report the kind, link count and generation of an inode.
    ///
    /// Errors: [`Error::NotFound`] for a stale or unknown identifier.
    pub fn stat(&self, id: InodeId) -> Result<Stat> {
        let node = self.node(self.index_of(id)?)?;
        Ok(Stat {
            kind: node.kind,
            nlink: node.nlink,
            generation: node.generation,
        })
    }

    /// The target of a symbolic link.
    ///
    /// Errors: [`Error::NotFound`] for a stale or unknown identifier and
    /// [`Error::InvalidState`] when the inode is not a symbolic link.
    pub fn readlink(&self, id: InodeId) -> Result<&str> {
        let node = self.node(self.index_of(id)?)?;
        if node.kind != FileKind::Symlink {
            return Err(Error::InvalidState);
        }
        let bytes = node
            .target
            .get(..node.target_length)
            .ok_or(Error::InvalidState)?;
        core::str::from_utf8(bytes).map_err(|_| Error::InvalidInput)
    }

    /// Resolve an absolute path to a slot index, following only directories.
    fn walk(&self, path: &str) -> Result<usize> {
        validate_absolute(path, MAX_PATH_LENGTH)?;
        let mut current = ROOT;
        for name in components(path) {
            let slot = self
                .find_entry(current, name.as_bytes())?
                .ok_or(Error::NotFound)?;
            current = self.entry(slot)?.child;
        }
        let node = self.node(current)?;
        if path.ends_with('/') && node.kind != FileKind::Directory {
            return Err(Error::InvalidState);
        }
        Ok(current)
    }

    /// Split a mutable path into its parent directory slot and final name.
    ///
    /// Returns `None` for the root, which no mutation may replace. Trailing
    /// slashes and a final `.` are refused, because they name a directory
    /// rather than a storable entry.
    fn locate<'a>(&self, path: &'a str) -> Result<Option<(usize, &'a str)>> {
        validate_absolute(path, MAX_PATH_LENGTH)?;
        if components(path).next().is_none() {
            return Ok(None);
        }
        if path.ends_with('/') || path.rsplit('/').next() == Some(".") {
            return Err(Error::InvalidName);
        }
        let mut parts = components(path).peekable();
        let mut dir = ROOT;
        while let Some(name) = parts.next() {
            if parts.peek().is_none() {
                return Ok(Some((dir, name)));
            }
            let slot = self
                .find_entry(dir, name.as_bytes())?
                .ok_or(Error::NotFound)?;
            dir = self.entry(slot)?.child;
        }
        Ok(None)
    }

    /// Locate a path whose final name must not yet exist.
    fn new_name<'a>(&self, path: &'a str) -> Result<(usize, &'a str)> {
        let (dir, name) = self.locate(path)?.ok_or(Error::AlreadyExists)?;
        check_name(name)?;
        if self.find_entry(dir, name.as_bytes())?.is_some() {
            return Err(Error::AlreadyExists);
        }
        Ok((dir, name))
    }

    /// Find the entry slot of `name` inside directory `dir`.
    ///
    /// Fails if `dir` is absent or not a directory.
    fn find_entry(&self, dir: usize, name: &[u8]) -> Result<Option<usize>> {
        if self.node(dir)?.kind != FileKind::Directory {
            return Err(Error::InvalidState);
        }
        Ok(self
            .entries
            .iter()
            .position(|entry| entry.used && entry.parent == dir && entry.name() == name))
    }

    fn entry(&self, slot: usize) -> Result<&Entry> {
        self.entries
            .get(slot)
            .filter(|entry| entry.used)
            .ok_or(Error::NotFound)
    }

    fn free_entry(&self) -> Result<usize> {
        self.entries
            .iter()
            .position(|entry| !entry.used)
            .ok_or(Error::TableFull)
    }

    /// Write an entry into a slot that [`free_entry`](Self::free_entry) or an
    /// existing entry supplied. Callers have already validated `name`.
    fn fill_entry(&mut self, slot: usize, parent: usize, child: usize, name: &[u8]) {
        let mut stored = [0u8; MAX_NAME_LENGTH];
        let length = name.len().min(MAX_NAME_LENGTH);
        for (dest, byte) in stored.iter_mut().zip(name) {
            *dest = *byte;
        }
        if let Some(entry) = self.entries.get_mut(slot) {
            *entry = Entry {
                used: true,
                parent,
                child,
                name: stored,
                name_length: length,
            };
        }
    }

    fn remove_entry(&mut self, slot: usize) {
        if let Some(entry) = self.entries.get_mut(slot) {
            entry.used = false;
        }
    }

    /// Claim a free inode slot, bumping its generation, with one link.
    fn allocate(&mut self, kind: FileKind, target: &[u8]) -> Result<usize> {
        let mut stored = [0u8; MAX_TARGET_LENGTH];
        let length = target.len().min(MAX_TARGET_LENGTH);
        for (dest, byte) in stored.iter_mut().zip(target) {
            *dest = *byte;
        }
        let (index, inode) = self
            .inodes
            .iter_mut()
            .enumerate()
            .find(|(_, inode)| !inode.live)
            .ok_or(Error::TableFull)?;
        *inode = Inode {
            live: true,
            kind,
            nlink: 1,
            generation: inode.generation.wrapping_add(1),
            target: stored,
            target_length: length,
        };
        Ok(index)
    }

    /// Drop one name from an inode, freeing the slot when none remain.
    fn release_link(&mut self, index: usize) -> Result<()> {
        let node = self.node_mut(index)?;
        node.nlink = node.nlink.checked_sub(1).ok_or(Error::InvalidState)?;
        if node.nlink == 0 {
            node.live = false;
        }
        Ok(())
    }

    fn has_children(&self, dir: usize) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.used && entry.parent == dir)
    }

    /// Whether `start` is `ancestor` or lies beneath it.
    ///
    /// A parent chain longer than the table can only come from corruption, so
    /// it is reported as containment; refusing a move is the safe answer.
    fn is_within(&self, start: usize, ancestor: usize) -> bool {
        let mut cursor = start;
        for _ in 0..=INODES {
            if cursor == ancestor {
                return true;
            }
            let parent = self
                .entries
                .iter()
                .find(|entry| entry.used && entry.child == cursor)
                .map(|entry| entry.parent);
            match parent {
                Some(parent) => cursor = parent,
                None => return false,
            }
        }
        true
    }

    fn node(&self, index: usize) -> Result<&Inode> {
        self.inodes
            .get(index)
            .filter(|inode| inode.live)
            .ok_or(Error::NotFound)
    }

    fn node_mut(&mut self, index: usize) -> Result<&mut Inode> {
        self.inodes
            .get_mut(index)
            .filter(|inode| inode.live)
            .ok_or(Error::NotFound)
    }

    fn id_of(&self, index: usize) -> Result<InodeId> {
        let node = self.node(index)?;
        Ok(InodeId {
            index,
            generation: node.generation,
        })
    }

    /// Check an identifier against its slot's live generation.
    fn index_of(&self, id: InodeId) -> Result<usize> {
        let node = self.node(id.index)?;
        if node.generation != id.generation {
            return Err(Error::NotFound);
        }
        Ok(id.index)
    }
}

/// Check that a single name is storable in a directory entry.
fn check_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > MAX_NAME_LENGTH
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\0')
    {
        return Err(Error::InvalidName);
    }
    Ok(())
}

/// Check that a symbolic-link target fits its fixed buffer.
fn check_target(target: &str) -> Result<()> {
    if target.is_empty() || target.len() > MAX_TARGET_LENGTH || target.contains('\0') {
        return Err(Error::InvalidName);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    type Tree = DirTree<16, 32>;

    fn kind(tree: &Tree, path: &str) -> FileKind {
        tree.stat(tree.resolve(path).unwrap()).unwrap().kind
    }

    /// Write `/` followed by `name_length` `n` bytes into `buffer`.
    fn absolute_with_name(buffer: &mut [u8], name_length: usize) -> &str {
        buffer[0] = b'/';
        for byte in &mut buffer[1..=name_length] {
            *byte = b'n';
        }
        core::str::from_utf8(&buffer[..=name_length]).unwrap()
    }

    /// Every live non-root inode is named by exactly `nlink` entries, and every
    /// entry names a live inode under a live directory.
    fn assert_consistent<const I: usize, const E: usize>(tree: &DirTree<I, E>) {
        for (index, inode) in tree.inodes.iter().enumerate() {
            if !inode.live || index == ROOT {
                continue;
            }
            let names = tree
                .entries
                .iter()
                .filter(|entry| entry.used && entry.child == index)
                .count();
            assert!(names > 0, "inode {index} has no name");
            assert_eq!(names, inode.nlink as usize, "inode {index}");
        }
        for entry in tree.entries.iter().filter(|entry| entry.used) {
            assert_eq!(
                tree.node(entry.parent).unwrap().kind,
                FileKind::Directory,
                "parent of {:?}",
                entry.name()
            );
            assert!(tree.node(entry.child).is_ok());
        }
    }

    #[test]
    fn root_is_a_directory_with_a_stable_identifier() {
        let mut tree = Tree::new();
        assert_eq!(tree.resolve("/"), Ok(InodeId::ROOT));
        let stat = tree.stat(InodeId::ROOT).unwrap();
        assert_eq!(stat.kind, FileKind::Directory);
        assert_eq!(stat.nlink, 1);
        assert_eq!(stat.generation, 0);
        assert_eq!(tree.mkdir("/"), Err(Error::AlreadyExists));
        assert_eq!(tree.rmdir("/"), Err(Error::PermissionDenied));
        assert_eq!(tree.unlink("/"), Err(Error::InvalidState));
        assert_eq!(tree.resolve("/"), Ok(InodeId::ROOT));
    }

    #[test]
    fn nested_directories_and_files_resolve() {
        let mut tree = Tree::new();
        let a = tree.mkdir("/a").unwrap();
        let b = tree.mkdir("/a/b").unwrap();
        let file = tree.create("/a/b/c").unwrap();
        assert_eq!(tree.resolve("/a"), Ok(a));
        assert_eq!(tree.resolve("/a/b"), Ok(b));
        assert_eq!(tree.resolve("/a/b/c"), Ok(file));
        assert_eq!(tree.resolve("/a/./b//c"), Ok(file));
        assert_eq!(kind(&tree, "/a/b"), FileKind::Directory);
        assert_eq!(kind(&tree, "/a/b/c"), FileKind::Regular);
        assert_consistent(&tree);
    }

    #[test]
    fn names_are_case_sensitive() {
        let mut tree = Tree::new();
        let upper = tree.create("/File").unwrap();
        let lower = tree.create("/file").unwrap();
        assert_ne!(upper, lower);
        assert_eq!(tree.resolve("/File"), Ok(upper));
        assert_eq!(tree.resolve("/FILE"), Err(Error::NotFound));
        assert!(tree.create("/FILE").is_ok());
    }

    #[test]
    fn duplicate_names_are_rejected_whatever_their_kind() {
        let mut tree = Tree::new();
        tree.create("/f").unwrap();
        tree.mkdir("/d").unwrap();
        assert_eq!(tree.create("/f"), Err(Error::AlreadyExists));
        assert_eq!(tree.mkdir("/f"), Err(Error::AlreadyExists));
        assert_eq!(tree.mkdir("/d"), Err(Error::AlreadyExists));
        assert_eq!(tree.symlink("/x", "/d"), Err(Error::AlreadyExists));
        assert_consistent(&tree);
    }

    #[test]
    fn dot_and_dot_dot_are_never_storable() {
        let mut tree = Tree::new();
        // "/." names the root itself, so creating it is AlreadyExists instead.
        assert_eq!(tree.mkdir("/."), Err(Error::AlreadyExists));
        for path in ["/a/.", "/..", "/a/.."] {
            assert_eq!(tree.mkdir(path), Err(Error::InvalidName), "{path}");
            assert_eq!(tree.create(path), Err(Error::InvalidName), "{path}");
        }
        tree.mkdir("/a").unwrap();
        assert_eq!(tree.mkdir("/a/."), Err(Error::InvalidName));
        assert_eq!(tree.resolve("/a/."), tree.resolve("/a"));
        assert_eq!(check_name("."), Err(Error::InvalidName));
        assert_eq!(check_name(".."), Err(Error::InvalidName));
        assert_eq!(check_name("a/b"), Err(Error::InvalidName));
        assert_eq!(check_name("a\0b"), Err(Error::InvalidName));
        assert_eq!(check_name(""), Err(Error::InvalidName));
        assert_eq!(
            check_name(&"n".repeat(MAX_NAME_LENGTH + 1)),
            Err(Error::InvalidName)
        );
        assert_eq!(check_name("ok name"), Ok(()));
    }

    #[test]
    fn names_are_bounded_to_255_bytes() {
        let mut tree = Tree::new();
        let mut buffer = [0u8; MAX_NAME_LENGTH + 2];
        let longest = absolute_with_name(&mut buffer, MAX_NAME_LENGTH);
        let created = tree.create(longest).unwrap();
        assert_eq!(tree.resolve(longest), Ok(created));

        let mut buffer = [0u8; MAX_NAME_LENGTH + 2];
        let too_long = absolute_with_name(&mut buffer, MAX_NAME_LENGTH + 1);
        assert_eq!(tree.create(too_long), Err(Error::InvalidName));
        assert_eq!(tree.resolve(too_long), Err(Error::InvalidName));
    }

    #[test]
    fn missing_or_non_directory_parents_are_reported() {
        let mut tree = Tree::new();
        assert_eq!(tree.mkdir("/x/y"), Err(Error::NotFound));
        assert_eq!(tree.resolve("/x/y"), Err(Error::NotFound));
        tree.create("/f").unwrap();
        assert_eq!(tree.mkdir("/f/g"), Err(Error::InvalidState));
        assert_eq!(tree.resolve("/f/g"), Err(Error::InvalidState));
        assert_eq!(tree.resolve("/f/"), Err(Error::InvalidState));
        assert_eq!(tree.resolve("/"), Ok(InodeId::ROOT));
        assert_consistent(&tree);
    }

    #[test]
    fn symlinks_are_returned_not_followed() {
        let mut tree = Tree::new();
        tree.mkdir("/dir").unwrap();
        let link = tree.symlink("/dir", "/l").unwrap();
        assert_eq!(tree.resolve("/l"), Ok(link));
        assert_eq!(kind(&tree, "/l"), FileKind::Symlink);
        assert_eq!(tree.readlink(link), Ok("/dir"));
        assert_eq!(tree.resolve("/l/x"), Err(Error::InvalidState));
        assert_eq!(tree.resolve("/l/"), Err(Error::InvalidState));
        assert_eq!(
            tree.readlink(tree.resolve("/dir").unwrap()),
            Err(Error::InvalidState)
        );
        assert_consistent(&tree);
    }

    #[test]
    fn symlink_targets_are_bounded() {
        let mut tree = Tree::new();
        assert_eq!(tree.symlink("", "/a"), Err(Error::InvalidName));
        assert_eq!(tree.symlink("a\0b", "/a"), Err(Error::InvalidName));
        let longest = "t".repeat(MAX_TARGET_LENGTH);
        let too_long = "t".repeat(MAX_TARGET_LENGTH + 1);
        assert_eq!(tree.symlink(&too_long, "/a"), Err(Error::InvalidName));
        let link = tree.symlink(&longest, "/a").unwrap();
        assert_eq!(tree.readlink(link), Ok(longest.as_str()));
    }

    #[test]
    fn hard_links_share_an_inode_and_count_names() {
        let mut tree = Tree::new();
        let file = tree.create("/f").unwrap();
        tree.link("/f", "/g").unwrap();
        assert_eq!(tree.resolve("/g"), Ok(file));
        assert_eq!(tree.stat(file).unwrap().nlink, 2);
        assert_eq!(tree.link("/f", "/g"), Err(Error::AlreadyExists));
        assert_eq!(tree.link("/missing", "/h"), Err(Error::NotFound));
        assert_consistent(&tree);
    }

    #[test]
    fn directories_cannot_be_hard_linked() {
        let mut tree = Tree::new();
        tree.mkdir("/d").unwrap();
        assert_eq!(tree.link("/d", "/e"), Err(Error::PermissionDenied));
        assert_eq!(tree.link("/", "/e"), Err(Error::PermissionDenied));
        assert_eq!(tree.resolve("/e"), Err(Error::NotFound));
    }

    #[test]
    fn unlink_frees_the_inode_at_zero_links() {
        let mut tree = Tree::new();
        let file = tree.create("/f").unwrap();
        tree.link("/f", "/g").unwrap();

        tree.unlink("/f").unwrap();
        assert_eq!(tree.stat(file).unwrap().nlink, 1);
        assert_eq!(tree.resolve("/g"), Ok(file));
        assert_eq!(tree.resolve("/f"), Err(Error::NotFound));

        tree.unlink("/g").unwrap();
        assert_eq!(tree.resolve("/g"), Err(Error::NotFound));
        assert_eq!(tree.stat(file), Err(Error::NotFound));
        assert_eq!(tree.unlink("/g"), Err(Error::NotFound));
        assert_consistent(&tree);
    }

    #[test]
    fn unlink_refuses_directories_and_the_root() {
        let mut tree = Tree::new();
        tree.mkdir("/d").unwrap();
        assert_eq!(tree.unlink("/d"), Err(Error::InvalidState));
        assert_eq!(tree.unlink("/"), Err(Error::InvalidState));
        assert!(tree.resolve("/d").is_ok());
    }

    #[test]
    fn rmdir_requires_an_empty_directory() {
        let mut tree = Tree::new();
        tree.mkdir("/d").unwrap();
        tree.create("/d/f").unwrap();
        assert_eq!(tree.rmdir("/d"), Err(Error::InvalidState));
        tree.unlink("/d/f").unwrap();
        tree.rmdir("/d").unwrap();
        assert_eq!(tree.resolve("/d"), Err(Error::NotFound));
        assert_consistent(&tree);
    }

    #[test]
    fn rmdir_refuses_the_root_files_and_links() {
        let mut tree = Tree::new();
        assert_eq!(tree.rmdir("/"), Err(Error::PermissionDenied));
        tree.create("/f").unwrap();
        assert_eq!(tree.rmdir("/f"), Err(Error::InvalidState));
        tree.symlink("/f", "/l").unwrap();
        assert_eq!(tree.rmdir("/l"), Err(Error::InvalidState));
        assert_eq!(tree.rmdir("/missing"), Err(Error::NotFound));
    }

    #[test]
    fn rename_moves_a_file_between_directories() {
        let mut tree = Tree::new();
        tree.mkdir("/a").unwrap();
        tree.mkdir("/b").unwrap();
        let file = tree.create("/a/f").unwrap();
        tree.rename("/a/f", "/b/g").unwrap();
        assert_eq!(tree.resolve("/a/f"), Err(Error::NotFound));
        assert_eq!(tree.resolve("/b/g"), Ok(file));
        assert_eq!(tree.stat(file).unwrap().nlink, 1);
        assert_consistent(&tree);
    }

    #[test]
    fn rename_replaces_an_existing_file_in_one_step() {
        let mut tree = Tree::new();
        let x = tree.create("/x").unwrap();
        let y = tree.create("/y").unwrap();
        tree.rename("/x", "/y").unwrap();
        assert_eq!(tree.resolve("/y"), Ok(x));
        assert_eq!(tree.resolve("/x"), Err(Error::NotFound));
        assert_eq!(tree.stat(y), Err(Error::NotFound));
        assert_eq!(tree.stat(x).unwrap().nlink, 1);
        assert_consistent(&tree);
    }

    #[test]
    fn rename_replacing_a_file_keeps_other_links_to_the_old_target() {
        let mut tree = Tree::new();
        let target = tree.create("/t").unwrap();
        tree.link("/t", "/other").unwrap();
        let source = tree.create("/s").unwrap();
        tree.rename("/s", "/t").unwrap();
        assert_eq!(tree.resolve("/t"), Ok(source));
        assert_eq!(tree.resolve("/other"), Ok(target));
        assert_eq!(tree.stat(target).unwrap().nlink, 1);
        assert_consistent(&tree);
    }

    #[test]
    fn rename_onto_a_link_of_the_same_inode_changes_nothing() {
        let mut tree = Tree::new();
        let file = tree.create("/f").unwrap();
        tree.link("/f", "/g").unwrap();
        assert_eq!(tree.rename("/f", "/g"), Ok(()));
        assert_eq!(tree.rename("/f", "/f"), Ok(()));
        assert_eq!(tree.resolve("/f"), Ok(file));
        assert_eq!(tree.resolve("/g"), Ok(file));
        assert_eq!(tree.stat(file).unwrap().nlink, 2);
        assert_consistent(&tree);
    }

    #[test]
    fn rename_refuses_a_directory_into_its_own_subtree() {
        let mut tree = Tree::new();
        let a = tree.mkdir("/a").unwrap();
        tree.mkdir("/a/b").unwrap();
        assert_eq!(tree.rename("/a", "/a/b/c"), Err(Error::InvalidInput));
        assert_eq!(tree.rename("/a", "/a/x"), Err(Error::InvalidInput));
        assert_eq!(tree.resolve("/a"), Ok(a));
        assert_consistent(&tree);
    }

    #[test]
    fn rename_directory_replaces_an_empty_directory_only() {
        let mut tree = Tree::new();
        let src = tree.mkdir("/src").unwrap();
        tree.create("/src/child").unwrap();
        let empty = tree.mkdir("/empty").unwrap();
        tree.rename("/src", "/empty").unwrap();
        assert_eq!(tree.resolve("/empty"), Ok(src));
        assert!(tree.resolve("/empty/child").is_ok());
        assert_eq!(tree.stat(empty), Err(Error::NotFound));

        tree.mkdir("/other").unwrap();
        tree.create("/other/keep").unwrap();
        tree.mkdir("/victim").unwrap();
        assert_eq!(tree.rename("/victim", "/other"), Err(Error::InvalidState));
        assert!(tree.resolve("/other/keep").is_ok());
        assert_consistent(&tree);
    }

    #[test]
    fn rename_never_replaces_across_kinds() {
        let mut tree = Tree::new();
        tree.create("/f").unwrap();
        tree.mkdir("/d").unwrap();
        assert_eq!(tree.rename("/d", "/f"), Err(Error::InvalidState));
        assert_eq!(tree.rename("/f", "/d"), Err(Error::InvalidState));
        assert_eq!(kind(&tree, "/f"), FileKind::Regular);
        assert_eq!(kind(&tree, "/d"), FileKind::Directory);
        assert_consistent(&tree);
    }

    #[test]
    fn rename_refuses_the_root_and_missing_sources() {
        let mut tree = Tree::new();
        tree.create("/f").unwrap();
        assert_eq!(tree.rename("/", "/x"), Err(Error::PermissionDenied));
        assert_eq!(tree.rename("/f", "/"), Err(Error::PermissionDenied));
        assert_eq!(tree.rename("/missing", "/x"), Err(Error::NotFound));
        assert_eq!(tree.rename("/f", "/no/such/dir"), Err(Error::NotFound));
    }

    #[test]
    fn readdir_lists_entries_in_order_and_ends_with_none() {
        let mut tree = Tree::new();
        let d = tree.mkdir("/d").unwrap();
        tree.create("/d/Alpha").unwrap();
        tree.create("/d/beta").unwrap();
        tree.mkdir("/d/gamma").unwrap();
        tree.create("/outside").unwrap();

        let mut names = [""; 3];
        for (index, slot) in names.iter_mut().enumerate() {
            *slot = tree.readdir(d, index).unwrap().unwrap().name;
        }
        assert_eq!(names, ["Alpha", "beta", "gamma"]);
        assert_eq!(tree.readdir(d, 3), Ok(None));
        assert_eq!(tree.readdir(d, usize::MAX), Ok(None));

        let entry = tree.readdir(d, 2).unwrap().unwrap();
        assert_eq!(entry.inode, tree.resolve("/d/gamma").unwrap());
        assert_eq!(tree.readdir(InodeId::ROOT, 0).unwrap().unwrap().name, "d");
    }

    #[test]
    fn readdir_rejects_files_and_stale_identifiers() {
        let mut tree = Tree::new();
        let file = tree.create("/f").unwrap();
        assert_eq!(tree.readdir(file, 0), Err(Error::InvalidState));
        let dir = tree.mkdir("/d").unwrap();
        tree.rmdir("/d").unwrap();
        assert_eq!(tree.readdir(dir, 0), Err(Error::NotFound));
    }

    #[test]
    fn freed_slots_are_reused_under_a_new_generation() {
        let mut tree = DirTree::<2, 2>::new();
        let first = tree.create("/a").unwrap();
        tree.unlink("/a").unwrap();
        let second = tree.create("/b").unwrap();
        assert_eq!(first.index, second.index);
        assert_ne!(first.generation, second.generation);
        assert_eq!(tree.stat(first), Err(Error::NotFound));
        assert_eq!(tree.stat(second).unwrap().generation, second.generation);
        assert_eq!(tree.readlink(first), Err(Error::NotFound));
    }

    #[test]
    fn capacity_is_reported_without_leaking_slots() {
        let mut tree = DirTree::<3, 1>::new();
        tree.create("/a").unwrap();
        assert_eq!(tree.create("/b"), Err(Error::TableFull));
        assert_eq!(tree.symlink("/t", "/c"), Err(Error::TableFull));
        tree.unlink("/a").unwrap();
        tree.create("/b").unwrap();
        assert_consistent(&tree);

        let mut tree = DirTree::<2, 4>::new();
        tree.create("/a").unwrap();
        assert_eq!(tree.create("/b"), Err(Error::TableFull));
        assert_eq!(tree.link("/a", "/c"), Ok(()));
        assert_consistent(&tree);
    }

    #[test]
    fn zero_capacity_tree_resolves_nothing() {
        let mut tree = DirTree::<0, 0>::new();
        assert_eq!(tree.resolve("/"), Err(Error::NotFound));
        assert_eq!(tree.create("/a"), Err(Error::NotFound));
        assert_eq!(tree.mkdir("/a"), Err(Error::NotFound));
        assert_eq!(tree.stat(InodeId::ROOT), Err(Error::NotFound));
        assert_eq!(tree.readdir(InodeId::ROOT, 0), Err(Error::NotFound));
    }

    #[test]
    fn hostile_inputs_fail_without_panicking() {
        let mut tree = Tree::new();
        tree.mkdir("/a").unwrap();
        let mut buffer = [0u8; 5002];
        let long = absolute_with_name(&mut buffer, 5000);
        let inputs = [
            "",
            "a",
            "//",
            "/\0",
            "/a\0",
            "/a/../b",
            "/./..",
            "/a/\u{7f}",
            "\u{10ffff}",
            long,
        ];
        for input in inputs {
            let _ = tree.resolve(input);
            let _ = tree.mkdir(input);
            let _ = tree.create(input);
            let _ = tree.symlink(input, "/s");
            let _ = tree.link(input, "/h");
            let _ = tree.link("/a", input);
            let _ = tree.unlink(input);
            let _ = tree.rmdir(input);
            let _ = tree.rename(input, "/z");
            let _ = tree.rename("/a", input);
            let _ = tree.readdir(
                InodeId {
                    index: usize::MAX,
                    generation: 9,
                },
                0,
            );
            let _ = tree.stat(InodeId {
                index: 999,
                generation: 0,
            });
        }
        assert_consistent(&tree);
    }

    #[test]
    fn invariants_hold_across_a_mixed_sequence() {
        let mut tree = Tree::new();
        tree.mkdir("/a").unwrap();
        tree.mkdir("/a/b").unwrap();
        tree.create("/a/b/f").unwrap();
        tree.link("/a/b/f", "/a/g").unwrap();
        tree.symlink("/a/g", "/s").unwrap();
        assert_consistent(&tree);
        tree.rename("/a/b", "/moved").unwrap();
        assert_consistent(&tree);
        tree.rename("/a/g", "/moved/f").unwrap();
        assert_consistent(&tree);
        tree.unlink("/s").unwrap();
        tree.unlink("/moved/f").unwrap();
        tree.rmdir("/moved").unwrap();
        assert_consistent(&tree);
        assert_eq!(tree.resolve("/a/b"), Err(Error::NotFound));
    }
}
