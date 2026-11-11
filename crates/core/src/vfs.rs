//! Minimal in-memory file system shared by every personality.
//!
//! The store has a fixed capacity and never allocates, so both userspace
//! personalities can resolve the same files without a heap. Names and contents
//! are validated once at creation, which keeps every later read infallible
//! apart from an unknown file identifier.

use crate::{Error, Result};

/// Longest file name the store accepts.
pub const MAX_NAME_LENGTH: usize = 32;

/// A file identifier, valid only for the store that produced it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileId(pub u16);

#[derive(Clone, Copy, Debug)]
struct File {
    name: [u8; MAX_NAME_LENGTH],
    name_length: usize,
    start: usize,
    length: usize,
}

/// A fixed-capacity in-memory file store. Writes update a file in place; only
/// the file that ends the store can grow, up to the store's byte capacity.
#[derive(Clone, Copy, Debug)]
pub struct MemFs<const FILES: usize, const BYTES: usize> {
    files: [Option<File>; FILES],
    data: [u8; BYTES],
    used: usize,
}

impl<const FILES: usize, const BYTES: usize> Default for MemFs<FILES, BYTES> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const FILES: usize, const BYTES: usize> MemFs<FILES, BYTES> {
    /// Construct an empty store.
    pub const fn new() -> Self {
        Self {
            files: [None; FILES],
            data: [0; BYTES],
            used: 0,
        }
    }

    /// Add a file and return its identifier.
    pub fn create(&mut self, name: &str, contents: &[u8]) -> Result<FileId> {
        let name_length = name.len();
        if name_length == 0 || name_length > MAX_NAME_LENGTH || name.contains('\0') {
            return Err(Error::InvalidInput);
        }
        if self.lookup(name).is_ok() {
            return Err(Error::AlreadyExists);
        }
        let index = self
            .files
            .iter()
            .position(|file| file.is_none())
            .ok_or(Error::TableFull)?;
        let end = self
            .used
            .checked_add(contents.len())
            .ok_or(Error::OutOfRange)?;
        if end > BYTES {
            return Err(Error::TableFull);
        }

        let mut stored_name = [0u8; MAX_NAME_LENGTH];
        stored_name[..name_length].copy_from_slice(name.as_bytes());
        self.data[self.used..end].copy_from_slice(contents);
        self.files[index] = Some(File {
            name: stored_name,
            name_length,
            start: self.used,
            length: contents.len(),
        });
        self.used = end;
        Ok(FileId(index as u16))
    }

    /// Resolve a file name to its identifier.
    pub fn lookup(&self, name: &str) -> Result<FileId> {
        let name = name.as_bytes();
        if name.is_empty() || name.len() > MAX_NAME_LENGTH {
            return Err(Error::NotFound);
        }
        self.files
            .iter()
            .enumerate()
            .find(|(_, file)| {
                file.is_some_and(|file| {
                    file.name_length == name.len() && &file.name[..name.len()] == name
                })
            })
            .map(|(index, _)| FileId(index as u16))
            .ok_or(Error::NotFound)
    }

    /// Name of a file.
    pub fn name(&self, file: FileId) -> Result<&str> {
        let stored = self
            .files
            .get(file.0 as usize)
            .and_then(|file| file.as_ref())
            .ok_or(Error::NotFound)?;
        core::str::from_utf8(&stored.name[..stored.name_length]).map_err(|_| Error::InvalidInput)
    }

    /// Length of a file in bytes.
    pub fn len(&self, file: FileId) -> Result<usize> {
        Ok(self.file(file)?.length)
    }

    /// Whether the store holds no files.
    pub fn is_empty(&self) -> bool {
        self.files.iter().all(|file| file.is_none())
    }

    /// Number of files held.
    pub fn count(&self) -> usize {
        self.files.iter().filter(|file| file.is_some()).count()
    }

    /// Read up to `out.len()` bytes starting at `offset`.
    ///
    /// A read at or past the end of the file returns zero bytes.
    pub fn read(&self, file: FileId, offset: u64, out: &mut [u8]) -> Result<usize> {
        let file = self.file(file)?;
        let offset = usize::try_from(offset).map_err(|_| Error::BadAddress)?;
        if offset >= file.length {
            return Ok(0);
        }
        let available = file.length - offset;
        let count = available.min(out.len());
        let start = file.start + offset;
        out[..count].copy_from_slice(&self.data[start..start + count]);
        Ok(count)
    }

    /// Write at `offset` and return the number of bytes stored.
    ///
    /// A file only grows when its data ends the store, so growth can never
    /// overwrite a later file; otherwise the write is clipped to the current
    /// length.
    pub fn write(&mut self, file: FileId, offset: u64, data: &[u8]) -> Result<usize> {
        let index = file.0 as usize;
        let stored = self
            .files
            .get(index)
            .copied()
            .flatten()
            .ok_or(Error::NotFound)?;
        let offset = usize::try_from(offset).map_err(|_| Error::BadAddress)?;
        if offset > stored.length {
            return Err(Error::BadAddress);
        }
        let can_grow = stored.start + stored.length == self.used;
        let limit = if can_grow {
            BYTES - stored.start
        } else {
            stored.length
        };
        let count = data.len().min(limit.saturating_sub(offset));
        if count == 0 {
            return Err(Error::TableFull);
        }
        let start = stored.start + offset;
        self.data[start..start + count].copy_from_slice(&data[..count]);
        let length = stored.length.max(offset + count);
        if can_grow {
            self.used = stored.start + length;
        }
        self.files[index] = Some(File { length, ..stored });
        Ok(count)
    }

    fn file(&self, file: FileId) -> Result<File> {
        self.files
            .get(file.0 as usize)
            .copied()
            .flatten()
            .ok_or(Error::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_are_created_and_looked_up_by_name() {
        let mut fs = MemFs::<4, 64>::new();
        assert!(fs.is_empty());
        let hello = fs.create("hello", b"hello from vfs\n").unwrap();
        let motd = fs.create("motd", b"WuxiaOS\n").unwrap();
        assert_ne!(hello, motd);
        assert_eq!(fs.lookup("hello"), Ok(hello));
        assert_eq!(fs.lookup("motd"), Ok(motd));
        assert_eq!(fs.lookup("missing"), Err(Error::NotFound));
        assert_eq!(fs.name(hello), Ok("hello"));
        assert_eq!(fs.len(hello), Ok(15));
        assert_eq!(fs.count(), 2);
    }

    #[test]
    fn reads_honour_offsets_and_end_of_file() {
        let mut fs = MemFs::<4, 64>::new();
        let file = fs.create("data", b"abcdef").unwrap();
        let mut out = [0u8; 4];
        assert_eq!(fs.read(file, 0, &mut out), Ok(4));
        assert_eq!(&out, b"abcd");
        assert_eq!(fs.read(file, 4, &mut out), Ok(2));
        assert_eq!(&out[..2], b"ef");
        assert_eq!(fs.read(file, 6, &mut out), Ok(0));
        assert_eq!(fs.read(file, 99, &mut out), Ok(0));
    }

    #[test]
    fn writes_update_bytes_and_can_grow_the_last_file() {
        let mut fs = MemFs::<4, 16>::new();
        let file = fs.create("data", b"abc").unwrap();
        assert_eq!(fs.write(file, 1, b"XY"), Ok(2));
        let mut out = [0u8; 8];
        assert_eq!(fs.read(file, 0, &mut out), Ok(3));
        assert_eq!(&out[..3], b"aXY");

        assert_eq!(fs.write(file, 3, b"defgh"), Ok(5));
        assert_eq!(fs.len(file), Ok(8));
        assert_eq!(fs.read(file, 3, &mut out), Ok(5));
        assert_eq!(&out[..5], b"defgh");

        assert_eq!(fs.write(file, 8, b"ijkl"), Ok(4));
        assert_eq!(fs.write(file, 12, b"more"), Ok(4));
        assert_eq!(fs.len(file), Ok(16));
        assert_eq!(fs.write(file, 16, b"!"), Err(Error::TableFull));
        assert_eq!(fs.write(file, 17, b"!"), Err(Error::BadAddress));
        assert_eq!(fs.write(FileId(9), 0, b"x"), Err(Error::NotFound));
    }

    #[test]
    fn a_file_followed_by_another_cannot_grow() {
        let mut fs = MemFs::<4, 32>::new();
        let first = fs.create("one", b"abc").unwrap();
        fs.create("two", b"xyz").unwrap();
        assert_eq!(fs.write(first, 0, b"12345"), Ok(3));
        assert_eq!(fs.len(first), Ok(3));
        let mut out = [0u8; 8];
        assert_eq!(fs.read(first, 0, &mut out), Ok(3));
        assert_eq!(&out[..3], b"123");
        assert_eq!(fs.read(FileId(1), 0, &mut out), Ok(3));
        assert_eq!(&out[..3], b"xyz");
    }

    #[test]
    fn invalid_names_and_exhausted_capacity_are_rejected() {
        let mut fs = MemFs::<1, 4>::new();
        assert_eq!(fs.create("", b"x"), Err(Error::InvalidInput));
        assert_eq!(fs.create("a\0b", b"x"), Err(Error::InvalidInput));
        assert_eq!(
            fs.create(&"n".repeat(MAX_NAME_LENGTH + 1), b"x"),
            Err(Error::InvalidInput)
        );
        fs.create("one", b"abcd").unwrap();
        assert_eq!(fs.create("one", b"x"), Err(Error::AlreadyExists));
        assert_eq!(fs.create("two", b"x"), Err(Error::TableFull));
        assert_eq!(fs.len(FileId(9)), Err(Error::NotFound));
        let mut out = [0u8; 4];
        assert_eq!(fs.read(FileId(9), 0, &mut out), Err(Error::NotFound));
    }
}
