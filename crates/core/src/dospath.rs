//! Allocation-free Win32 (DOS) path classification and translation.
//!
//! [`classify`] sorts a path by the Win32 prefix rules. [`to_nt`] and
//! [`to_posix`] normalize the path component by component into a buffer the
//! caller supplies. Normalization is purely lexical: `..` is resolved against
//! the text of the path and may never climb above the root of its drive or
//! share. Verbatim `\\?\` paths are the exception: they pass through unchanged.

use crate::path::{MAX_COMPONENT_LENGTH, validate_absolute};
use crate::{Error, Result};

/// Longest POSIX prefix, in bytes, that a [`DriveMap`] stores for one drive.
pub const MAX_PREFIX_LENGTH: usize = 64;

/// Number of drive letters a [`DriveMap`] holds, `A` through `Z`.
pub const DRIVE_COUNT: usize = 26;

const NT_DEVICE_PREFIX: &[u8] = b"\\??\\";
const NT_UNC_PREFIX: &[u8] = b"\\??\\UNC";

/// Type of a Win32 path, decided by its prefix alone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathType {
    /// `C:\x`: a drive letter followed by a separator.
    DriveAbsolute,
    /// `C:x`: a drive letter followed by a path relative to that drive's
    /// current directory.
    DriveRelative,
    /// `\x`: rooted on the current drive.
    Rooted,
    /// `x\y`: relative to the current directory.
    Relative,
    /// `\\server\share\x`: a network share.
    Unc,
    /// `\\.\COM1`: the DOS device namespace.
    LocalDevice,
    /// `\\?\C:\x`: a verbatim path that bypasses Win32 normalization.
    RootLocalDevice,
}

/// Classify a path with the Win32 prefix rules.
///
/// Both `\` and `/` act as separators. A path that starts with two separators
/// is a device path only when a `?` or `.` follows and a separator after that;
/// any other double-separator prefix is a UNC path.
pub fn classify(path: &str) -> PathType {
    let bytes = path.as_bytes();
    if separator_at(bytes, 0) && separator_at(bytes, 1) {
        return match bytes.get(2).copied() {
            Some(b'?') if separator_at(bytes, 3) => PathType::RootLocalDevice,
            Some(b'.') if separator_at(bytes, 3) => PathType::LocalDevice,
            _ => PathType::Unc,
        };
    }
    if separator_at(bytes, 0) {
        return PathType::Rooted;
    }
    match (bytes.first().copied(), bytes.get(1).copied()) {
        (Some(letter), Some(b':')) if letter.is_ascii_alphabetic() => {
            if separator_at(bytes, 2) {
                PathType::DriveAbsolute
            } else {
                PathType::DriveRelative
            }
        }
        _ => PathType::Relative,
    }
}

/// Return whether `name` is a reserved DOS device name in any case.
///
/// The reserved names are `CON`, `PRN`, `AUX`, `NUL` and `COM1` through
/// `COM9` and `LPT1` through `LPT9`. Only the part before the first `.` or `:`
/// counts, so `nul.txt` and `NUL:` are reserved. Trailing spaces in that part
/// are ignored, so `aux ` is reserved as well.
pub fn is_reserved_name(name: &str) -> bool {
    let stem = name.split(['.', ':']).next().unwrap_or("");
    let stem = stem.trim_end_matches(' ').as_bytes();

    let fixed = [&b"CON"[..], &b"PRN"[..], &b"AUX"[..], &b"NUL"[..]];
    if fixed.iter().any(|device| stem.eq_ignore_ascii_case(device)) {
        return true;
    }
    if let [a, b, c, digit] = stem {
        let port = [*a, *b, *c];
        let numbered = port.eq_ignore_ascii_case(b"COM") || port.eq_ignore_ascii_case(b"LPT");
        return numbered && (b'1'..=b'9').contains(digit);
    }
    false
}

/// Translate a Win32 path into the NT object-manager namespace.
///
/// The result is written into `buf` and borrowed from it. The rules are:
///
/// - `C:\x` becomes `\??\C:\x`. The drive letter is upper-cased, and a
///   drive root keeps its trailing `\`.
/// - `\\server\share\x` becomes `\??\UNC\server\share\x`.
/// - `\\?\...` and `\\.\...` pass through verbatim, with `\??\` in place of the
///   prefix and nothing else changed.
/// - Components are normalized: `/` becomes `\`, empty and `.` components are
///   dropped, `..` removes the previous component, and trailing dots and spaces
///   are stripped. A component that is empty after stripping is dropped.
///
/// Errors:
/// - [`Error::InvalidName`]: the path contains NUL, a `..` climbs above the
///   drive root or share, a UNC path lacks a server or share, or a component is
///   a reserved device name, is longer than [`MAX_COMPONENT_LENGTH`], or is
///   otherwise malformed.
/// - [`Error::InvalidState`]: the path is rooted, relative or drive-relative,
///   so it needs a current directory this module does not hold.
/// - [`Error::OutOfRange`]: `buf` is too small for the result.
pub fn to_nt<'a>(path: &str, buf: &'a mut [u8]) -> Result<&'a str> {
    reject_nul(path)?;
    let mut out = Writer::new(buf);
    match classify(path) {
        PathType::LocalDevice | PathType::RootLocalDevice => {
            out.push(NT_DEVICE_PREFIX)?;
            out.push(&path.as_bytes()[4..])?;
        }
        PathType::DriveAbsolute => {
            let bytes = path.as_bytes();
            out.push(NT_DEVICE_PREFIX)?;
            out.push(&[bytes[0].to_ascii_uppercase(), b':'])?;
            let floor = out.len;
            walk(path[2..].split(is_separator), b'\\', floor, &mut out)?;
            out.close_root(floor, b'\\')?;
        }
        PathType::Unc => {
            let mut segments = path[2..].split(is_separator);
            let server = next_name(&mut segments)?;
            let share = next_name(&mut segments)?;
            out.push(NT_UNC_PREFIX)?;
            out.push_byte(b'\\')?;
            out.push(server.as_bytes())?;
            out.push_byte(b'\\')?;
            out.push(share.as_bytes())?;
            let floor = out.len;
            walk(segments, b'\\', floor, &mut out)?;
            out.close_root(floor, b'\\')?;
        }
        PathType::DriveRelative | PathType::Rooted | PathType::Relative => {
            return Err(Error::InvalidState);
        }
    }
    out.finish()
}

/// Translate a drive-absolute Win32 path into a POSIX path under its drive's
/// mapped prefix.
///
/// `C:\Users\x` with `C` mapped to `/wuxia/c` becomes `/wuxia/c/Users/x`. The
/// components are normalized as in [`to_nt`], and `..` may not climb above the
/// mapped prefix. A drive root maps to its prefix without a trailing `/`.
///
/// Errors:
/// - [`Error::NotFound`]: the drive letter has no mapping in `map`.
/// - [`Error::Unsupported`]: the path is a UNC or device path, which has no
///   POSIX mapping.
/// - [`Error::InvalidState`]: the path lacks a drive, so it needs a current
///   directory this module does not hold.
/// - [`Error::InvalidName`] and [`Error::OutOfRange`]: as for [`to_nt`].
pub fn to_posix<'a>(path: &str, map: &DriveMap, buf: &'a mut [u8]) -> Result<&'a str> {
    reject_nul(path)?;
    match classify(path) {
        PathType::DriveAbsolute => {}
        PathType::DriveRelative | PathType::Rooted | PathType::Relative => {
            return Err(Error::InvalidState);
        }
        PathType::Unc | PathType::LocalDevice | PathType::RootLocalDevice => {
            return Err(Error::Unsupported);
        }
    }
    let prefix = map.get(path.as_bytes()[0]).ok_or(Error::NotFound)?;
    let mut out = Writer::new(buf);
    out.push(prefix.as_bytes())?;
    let floor = out.len;
    walk(path[2..].split(is_separator), b'/', floor, &mut out)?;
    if out.len == 0 {
        out.push_byte(b'/')?;
    }
    out.finish()
}

/// Extract the final component of a Win32, NT or device path.
///
/// The bootstrap store is flat, so `\??\C:\hello`, `C:\hello` and `hello`
/// all name the same entry. Trailing separators are ignored. A path whose last
/// component is `.` or `..`, or that has no component at all, is rejected: the
/// caller must not be able to turn a name into a directory jump.
///
/// Errors:
/// - [`Error::InvalidName`]: `path` contains a NUL.
/// - [`Error::InvalidInput`]: `path` has no component at all.
/// - [`Error::InvalidState`]: the final component is `..`.
pub fn store_name(path: &str) -> Result<&str> {
    reject_nul(path)?;
    let mut name = None;
    for component in path.split(is_separator) {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." {
            name = Some(component);
            continue;
        }
        name = Some(component);
    }
    match name {
        Some("..") => Err(Error::InvalidState),
        Some(component) => Ok(component),
        None => Err(Error::InvalidInput),
    }
}

/// Map from drive letters to POSIX root prefixes, with room for all 26 drives.
///
/// Letters are case-insensitive. A prefix is an absolute POSIX path with no
/// empty, `.` or `..` components and no trailing `/`, except that `/` itself
/// is accepted and means the filesystem root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DriveMap {
    slots: [Option<Prefix>; DRIVE_COUNT],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Prefix {
    bytes: [u8; MAX_PREFIX_LENGTH],
    length: usize,
}

impl Default for DriveMap {
    fn default() -> Self {
        Self::new()
    }
}

impl DriveMap {
    /// Construct a map in which no drive is mapped.
    pub const fn new() -> Self {
        Self {
            slots: [None; DRIVE_COUNT],
        }
    }

    /// Map a drive letter to a POSIX prefix, replacing any earlier mapping.
    ///
    /// Errors:
    /// - [`Error::InvalidInput`]: `letter` is not an ASCII letter.
    /// - [`Error::InvalidName`]: `prefix` is not a canonical absolute path of at
    ///   most [`MAX_PREFIX_LENGTH`] bytes. The map is unchanged on error.
    pub fn set(&mut self, letter: u8, prefix: &str) -> Result<()> {
        let index = drive_slot(letter).ok_or(Error::InvalidInput)?;
        let canonical = canonical_prefix(prefix)?;
        let mut bytes = [0u8; MAX_PREFIX_LENGTH];
        bytes[..canonical.len()].copy_from_slice(canonical.as_bytes());
        self.slots[index] = Some(Prefix {
            bytes,
            length: canonical.len(),
        });
        Ok(())
    }

    /// The POSIX prefix mapped to a drive letter, or `None` if it is unmapped.
    pub fn get(&self, letter: u8) -> Option<&str> {
        let index = drive_slot(letter)?;
        let prefix = self.slots.get(index)?.as_ref()?;
        core::str::from_utf8(&prefix.bytes[..prefix.length]).ok()
    }
}

/// Write-once-forward buffer that tracks how many bytes are in use.
struct Writer<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> Writer<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    fn push(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self.len.checked_add(bytes.len()).ok_or(Error::OutOfRange)?;
        let destination = self.buf.get_mut(self.len..end).ok_or(Error::OutOfRange)?;
        destination.copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    fn push_byte(&mut self, byte: u8) -> Result<()> {
        self.push(&[byte])
    }

    /// Terminate a root that has no components with its separator.
    fn close_root(&mut self, floor: usize, separator: u8) -> Result<()> {
        if self.len == floor {
            self.push_byte(separator)?;
        }
        Ok(())
    }

    fn finish(self) -> Result<&'a str> {
        let shared: &'a [u8] = self.buf;
        core::str::from_utf8(&shared[..self.len]).map_err(|_| Error::InvalidInput)
    }
}

/// Outcome of normalizing one raw path segment.
enum Step<'s> {
    /// The segment is empty, `.` or consists only of stripped characters.
    Skip,
    /// The segment is `..`.
    Parent,
    /// The segment is a normalized name.
    Name(&'s str),
}

fn step(raw: &str) -> Result<Step<'_>> {
    let core = raw.trim_end_matches(' ');
    if core == ".." {
        return Ok(Step::Parent);
    }
    let name = core.trim_end_matches(['.', ' ']);
    if name.is_empty() {
        return Ok(Step::Skip);
    }
    check_component(name)?;
    Ok(Step::Name(name))
}

/// Return the next normalized name, which must not be `..` or absent.
fn next_name<'s>(segments: &mut impl Iterator<Item = &'s str>) -> Result<&'s str> {
    for raw in segments {
        match step(raw)? {
            Step::Skip => {}
            Step::Parent => return Err(Error::InvalidName),
            Step::Name(name) => return Ok(name),
        }
    }
    Err(Error::InvalidName)
}

/// Append normalized components below `floor`, which marks the root that
/// `..` may not remove.
fn walk<'s>(
    segments: impl Iterator<Item = &'s str>,
    separator: u8,
    floor: usize,
    out: &mut Writer<'_>,
) -> Result<()> {
    for raw in segments {
        match step(raw)? {
            Step::Skip => {}
            Step::Parent => pop(out, separator, floor)?,
            Step::Name(name) => {
                out.push_byte(separator)?;
                out.push(name.as_bytes())?;
            }
        }
    }
    Ok(())
}

/// Remove the last component written above `floor`.
fn pop(out: &mut Writer<'_>, separator: u8, floor: usize) -> Result<()> {
    let start = out.buf[floor..out.len]
        .iter()
        .rposition(|&byte| byte == separator)
        .ok_or(Error::InvalidName)?;
    out.len = floor + start;
    Ok(())
}

fn check_component(name: &str) -> Result<()> {
    if name.len() > MAX_COMPONENT_LENGTH || name.contains('\0') || is_reserved_name(name) {
        return Err(Error::InvalidName);
    }
    Ok(())
}

fn reject_nul(path: &str) -> Result<()> {
    if path.contains('\0') {
        return Err(Error::InvalidName);
    }
    Ok(())
}

fn canonical_prefix(prefix: &str) -> Result<&str> {
    if prefix == "/" {
        return Ok("");
    }
    validate_absolute(prefix, MAX_PREFIX_LENGTH)?;
    if prefix.split('/').skip(1).any(|c| c.is_empty() || c == ".") {
        return Err(Error::InvalidName);
    }
    Ok(prefix)
}

fn drive_slot(letter: u8) -> Option<usize> {
    let upper = letter.to_ascii_uppercase();
    if upper.is_ascii_uppercase() {
        Some(usize::from(upper - b'A'))
    } else {
        None
    }
}

fn is_separator(c: char) -> bool {
    c == '\\' || c == '/'
}

fn is_separator_byte(byte: u8) -> bool {
    byte == b'\\' || byte == b'/'
}

fn separator_at(bytes: &[u8], index: usize) -> bool {
    matches!(bytes.get(index), Some(&byte) if is_separator_byte(byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_nt(path: &str, expected: Result<&str>) {
        let mut buf = [0u8; 128];
        assert_eq!(to_nt(path, &mut buf), expected, "{path:?}");
    }

    fn wuxia_map() -> DriveMap {
        let mut map = DriveMap::new();
        map.set(b'C', "/wuxia/c").unwrap();
        map
    }

    fn assert_posix(path: &str, expected: Result<&str>) {
        let mut buf = [0u8; 128];
        assert_eq!(to_posix(path, &wuxia_map(), &mut buf), expected, "{path:?}");
    }

    #[test]
    fn classifies_drive_paths() {
        assert_eq!(classify("C:\\Windows"), PathType::DriveAbsolute);
        assert_eq!(classify("c:/x"), PathType::DriveAbsolute);
        assert_eq!(classify("C:\\"), PathType::DriveAbsolute);
        assert_eq!(classify("C:"), PathType::DriveRelative);
        assert_eq!(classify("C:x"), PathType::DriveRelative);
    }

    #[test]
    fn classifies_rooted_and_relative_paths() {
        assert_eq!(classify("\\x"), PathType::Rooted);
        assert_eq!(classify("/x"), PathType::Rooted);
        assert_eq!(classify("\\"), PathType::Rooted);
        assert_eq!(classify("x\\y"), PathType::Relative);
        assert_eq!(classify(""), PathType::Relative);
        assert_eq!(classify(".\\x"), PathType::Relative);
        assert_eq!(classify("C"), PathType::Relative);
        assert_eq!(classify("1:\\x"), PathType::Relative);
    }

    #[test]
    fn classifies_unc_and_double_separator_prefixes() {
        assert_eq!(classify("\\\\server\\share"), PathType::Unc);
        assert_eq!(classify("//server/share"), PathType::Unc);
        assert_eq!(classify("\\\\server"), PathType::Unc);
        assert_eq!(classify("\\\\?x"), PathType::Unc);
        assert_eq!(classify("\\\\"), PathType::Unc);
    }

    #[test]
    fn classifies_device_namespaces() {
        assert_eq!(classify("\\\\.\\COM1"), PathType::LocalDevice);
        assert_eq!(classify("\\\\.\\"), PathType::LocalDevice);
        assert_eq!(classify("\\\\?\\C:\\x"), PathType::RootLocalDevice);
        assert_eq!(classify("//?/C:/x"), PathType::RootLocalDevice);
    }

    #[test]
    fn reserved_names_are_recognized_in_any_case_with_extensions() {
        for name in [
            "nul",
            "Nul.txt",
            "con",
            "PRN:",
            "aux ",
            "COM9",
            "lpt1.tar.gz",
            "LPT5 .log",
        ] {
            assert!(is_reserved_name(name), "{name:?}");
        }
        for name in [
            "COM0", "LPT0", "COM10", "console", "nul_", "nul2", " nul", "",
        ] {
            assert!(!is_reserved_name(name), "{name:?}");
        }
    }

    #[test]
    fn to_nt_maps_drive_paths_and_uppercases_the_letter() {
        assert_nt("C:\\Windows\\a.txt", Ok("\\??\\C:\\Windows\\a.txt"));
        assert_nt("C:\\", Ok("\\??\\C:\\"));
        assert_nt("c:\\x", Ok("\\??\\C:\\x"));
    }

    #[test]
    fn to_nt_normalizes_separators_and_dot_components() {
        assert_nt("C:/a//b/./c/", Ok("\\??\\C:\\a\\b\\c"));
    }

    #[test]
    fn to_nt_resolves_dot_dot_lexically() {
        assert_nt("C:\\a\\b\\..\\c", Ok("\\??\\C:\\a\\c"));
        assert_nt("C:\\a\\..", Ok("\\??\\C:\\"));
        assert_nt("C:\\a\\.. \\b", Ok("\\??\\C:\\b"));
    }

    #[test]
    fn to_nt_refuses_to_climb_above_the_drive_root() {
        assert_nt("C:\\..", Err(Error::InvalidName));
        assert_nt("C:\\a\\..\\..\\x", Err(Error::InvalidName));
    }

    #[test]
    fn to_nt_strips_trailing_dots_and_spaces_from_components() {
        assert_nt("C:\\a.txt. ", Ok("\\??\\C:\\a.txt"));
        assert_nt("C:\\dir . \\f  ", Ok("\\??\\C:\\dir\\f"));
        assert_nt("C:\\...\\x", Ok("\\??\\C:\\x"));
    }

    #[test]
    fn to_nt_translates_unc_paths_and_keeps_the_share_as_the_root() {
        assert_nt(
            "\\\\server\\share\\dir\\f.txt",
            Ok("\\??\\UNC\\server\\share\\dir\\f.txt"),
        );
        assert_nt("//server/share/a/../b", Ok("\\??\\UNC\\server\\share\\b"));
        assert_nt("\\\\server\\share", Ok("\\??\\UNC\\server\\share\\"));
        assert_nt("\\\\server\\share\\..\\..\\x", Err(Error::InvalidName));
        assert_nt("\\\\server", Err(Error::InvalidName));
        assert_nt("\\\\server\\..\\x", Err(Error::InvalidName));
    }

    #[test]
    fn to_nt_passes_verbatim_and_local_device_paths_through() {
        assert_nt("\\\\?\\C:\\a/b..\\c", Ok("\\??\\C:\\a/b..\\c"));
        assert_nt("\\\\?\\UNC\\srv\\shr\\x", Ok("\\??\\UNC\\srv\\shr\\x"));
        assert_nt("\\\\.\\C:\\x", Ok("\\??\\C:\\x"));
        // Verbatim paths bypass Win32 name rules, so a device name passes.
        assert_nt("\\\\?\\C:\\nul", Ok("\\??\\C:\\nul"));
    }

    #[test]
    fn to_nt_rejects_reserved_device_names_as_components() {
        for path in [
            "C:\\nul.txt",
            "C:\\dir\\CON",
            "C:\\com1.log",
            "C:\\Lpt9",
            "C:\\aux ",
            "C:\\NUL:",
            "C:\\con..\\x",
            "\\\\server\\share\\PRN",
        ] {
            assert_nt(path, Err(Error::InvalidName));
        }
        assert_nt(
            "C:\\CONSOLE\\COM10\\nulx\\LPT0",
            Ok("\\??\\C:\\CONSOLE\\COM10\\nulx\\LPT0"),
        );
    }

    #[test]
    fn to_nt_rejects_paths_that_need_a_current_directory() {
        assert_nt("\\x", Err(Error::InvalidState));
        assert_nt("x\\y", Err(Error::InvalidState));
        assert_nt("C:x", Err(Error::InvalidState));
        assert_nt("", Err(Error::InvalidState));
    }

    #[test]
    fn to_nt_rejects_nul_bytes() {
        assert_nt("C:\\a\0b", Err(Error::InvalidName));
        assert_nt("\\\\?\\C:\\a\0", Err(Error::InvalidName));
    }

    #[test]
    fn to_nt_bounds_component_length() {
        let mut raw = [b'a'; 300];
        raw[..3].copy_from_slice(b"C:\\");
        let exact = core::str::from_utf8(&raw[..3 + MAX_COMPONENT_LENGTH]).unwrap();
        let over = core::str::from_utf8(&raw[..4 + MAX_COMPONENT_LENGTH]).unwrap();
        let mut buf = [0u8; 400];
        assert!(to_nt(exact, &mut buf).is_ok());
        assert_eq!(to_nt(over, &mut buf), Err(Error::InvalidName));
    }

    #[test]
    fn to_nt_reports_a_full_buffer_as_out_of_range() {
        let mut short = [0u8; 13];
        assert_eq!(to_nt("C:\\Windows", &mut short), Err(Error::OutOfRange));
        let mut exact = [0u8; 14];
        assert_eq!(to_nt("C:\\Windows", &mut exact), Ok("\\??\\C:\\Windows"));
    }

    #[test]
    fn to_posix_maps_drive_paths_under_the_drive_prefix() {
        assert_posix("C:\\Users\\x", Ok("/wuxia/c/Users/x"));
        assert_posix("c:/Users//x/", Ok("/wuxia/c/Users/x"));
        assert_posix("C:\\", Ok("/wuxia/c"));
        assert_posix("C:\\a\\..\\b", Ok("/wuxia/c/b"));
    }

    #[test]
    fn to_posix_refuses_to_climb_above_the_prefix() {
        assert_posix("C:\\..", Err(Error::InvalidName));
        assert_posix("C:\\a\\..\\..\\x", Err(Error::InvalidName));
    }

    #[test]
    fn to_posix_rejects_unmapped_drives_and_non_drive_paths() {
        assert_posix("D:\\x", Err(Error::NotFound));
        assert_posix("\\x", Err(Error::InvalidState));
        assert_posix("C:x", Err(Error::InvalidState));
        assert_posix("x", Err(Error::InvalidState));
        assert_posix("\\\\server\\share\\x", Err(Error::Unsupported));
        assert_posix("\\\\?\\C:\\x", Err(Error::Unsupported));
        assert_posix("\\\\.\\COM1", Err(Error::Unsupported));
    }

    #[test]
    fn to_posix_applies_the_name_rules() {
        assert_posix("C:\\nul", Err(Error::InvalidName));
        assert_posix("C:\\a\\b\0", Err(Error::InvalidName));
    }

    #[test]
    fn to_posix_root_prefix_maps_to_the_filesystem_root() {
        let mut map = DriveMap::new();
        map.set(b'C', "/").unwrap();
        let mut buf = [0u8; 32];
        assert_eq!(to_posix("C:\\x", &map, &mut buf), Ok("/x"));
        assert_eq!(to_posix("C:\\", &map, &mut buf), Ok("/"));
    }

    #[test]
    fn to_posix_reports_a_full_buffer_as_out_of_range() {
        // "/wuxia/c/Users/x" is 16 bytes.
        let map = wuxia_map();
        let mut short = [0u8; 15];
        assert_eq!(
            to_posix("C:\\Users\\x", &map, &mut short),
            Err(Error::OutOfRange)
        );
        let mut exact = [0u8; 16];
        assert_eq!(
            to_posix("C:\\Users\\x", &map, &mut exact),
            Ok("/wuxia/c/Users/x")
        );
    }

    #[test]
    fn drive_map_stores_letters_case_insensitively() {
        let mut map = DriveMap::new();
        map.set(b'c', "/wuxia/c").unwrap();
        assert_eq!(map.get(b'C'), Some("/wuxia/c"));
        assert_eq!(map.get(b'c'), Some("/wuxia/c"));
        assert_eq!(map.get(b'D'), None);
        assert_eq!(map.get(b'1'), None);
        assert_eq!(map.set(b'1', "/x"), Err(Error::InvalidInput));
    }

    #[test]
    fn drive_map_rejects_non_canonical_prefixes_and_keeps_the_old_mapping() {
        let mut map = wuxia_map();
        for prefix in ["", "relative", "/a//b", "/a/", "/a/./b", "/a/../b", "/a/."] {
            assert_eq!(map.set(b'C', prefix), Err(Error::InvalidName), "{prefix:?}");
            assert_eq!(map.get(b'C'), Some("/wuxia/c"), "{prefix:?}");
        }
        map.set(b'D', "/a/.b").unwrap();
        assert_eq!(map.get(b'D'), Some("/a/.b"));
    }

    #[test]
    fn drive_map_bounds_prefix_length() {
        let mut raw = [b'a'; MAX_PREFIX_LENGTH + 1];
        raw[0] = b'/';
        let exact = core::str::from_utf8(&raw[..MAX_PREFIX_LENGTH]).unwrap();
        let over = core::str::from_utf8(&raw).unwrap();
        let mut map = DriveMap::new();
        assert_eq!(map.set(b'C', exact), Ok(()));
        assert_eq!(map.get(b'C'), Some(exact));
        assert_eq!(map.set(b'C', over), Err(Error::InvalidName));
    }

    #[test]
    fn store_name_uses_the_final_component() {
        assert_eq!(store_name("hello"), Ok("hello"));
        assert_eq!(store_name("\\??\\C:\\hello"), Ok("hello"));
        assert_eq!(store_name("C:\\Users\\x\\motd.txt"), Ok("motd.txt"));
        assert_eq!(store_name("a/b//c/"), Ok("c"));
        assert_eq!(store_name("C:\\a\\..\\b"), Ok("b"));
    }

    #[test]
    fn store_name_rejects_jumps_and_empty_paths() {
        assert_eq!(store_name(""), Err(Error::InvalidInput));
        assert_eq!(store_name("\\\\"), Err(Error::InvalidInput));
        assert_eq!(store_name("C:\\a\\.."), Err(Error::InvalidState));
        assert_eq!(store_name("a\0b"), Err(Error::InvalidName));
    }

    #[test]
    fn drive_map_holds_all_twenty_six_letters() {
        let mut map = DriveMap::new();
        for letter in b'A'..=b'Z' {
            map.set(letter, "/d").unwrap();
        }
        for letter in b'a'..=b'z' {
            assert_eq!(map.get(letter), Some("/d"));
        }
    }
}
