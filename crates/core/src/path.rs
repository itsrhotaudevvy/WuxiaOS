//! Allocation-free POSIX path validation and component comparison.
//!
//! Paths are split on `/` only. Empty and `.` components are ignored, so
//! `/etc/./motd` and `/etc/motd` name the same file. A `..` component is
//! refused rather than resolved: lexical resolution can disagree with what the
//! file system does, and a policy checked against the resolved path could then
//! be bypassed. Symbolic links are outside this module; the caller must resolve
//! them before asking a policy decision.

use crate::{Error, Result};

/// Longest single path component, in bytes, that the core accepts.
pub const MAX_COMPONENT_LENGTH: usize = 255;

/// Iterator over the meaningful components of a path.
#[derive(Clone, Debug)]
pub struct Components<'a> {
    rest: &'a str,
}

impl<'a> Iterator for Components<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        loop {
            let trimmed = self.rest.trim_start_matches('/');
            if trimmed.is_empty() {
                self.rest = trimmed;
                return None;
            }
            let end = trimmed.find('/').unwrap_or(trimmed.len());
            let (component, rest) = trimmed.split_at(end);
            self.rest = rest;
            if component != "." {
                return Some(component);
            }
        }
    }
}

/// Iterate the components of `path`, skipping empty and `.` components.
///
/// `..` is yielded unchanged so callers can see it; validate with
/// [`validate_absolute`] before acting on a path.
pub fn components(path: &str) -> Components<'_> {
    Components { rest: path }
}

/// Check that `path` is a bounded absolute path that is safe to match lexically.
///
/// The path must start with `/`, contain no NUL byte, contain no `..`
/// component, and have no component longer than [`MAX_COMPONENT_LENGTH`]. Its
/// total length in bytes must not exceed `max_length`.
pub fn validate_absolute(path: &str, max_length: usize) -> Result<()> {
    if path.len() > max_length || !path.starts_with('/') || path.contains('\0') {
        return Err(Error::InvalidName);
    }
    for component in components(path) {
        if component == ".." || component.len() > MAX_COMPONENT_LENGTH {
            return Err(Error::InvalidName);
        }
    }
    Ok(())
}

/// Return whether `path` lies at or below `prefix`, comparing whole components.
///
/// `"/etc/motd"` is under `"/etc"`, but `"/etcfoo"` is not. Both paths must be
/// absolute, otherwise the answer is `false`. The comparison is purely lexical,
/// so callers making a security decision must validate both paths first;
/// otherwise `"/etc/../x"` would compare as being under `"/etc"`.
pub fn starts_with_components(path: &str, prefix: &str) -> bool {
    if !path.starts_with('/') || !prefix.starts_with('/') {
        return false;
    }
    let mut path_components = components(path);
    components(prefix).all(|expected| path_components.next() == Some(expected))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn components_skip_empty_and_dot_components() {
        let mut parts = components("//a/./b//c/.");
        assert_eq!(parts.next(), Some("a"));
        assert_eq!(parts.next(), Some("b"));
        assert_eq!(parts.next(), Some("c"));
        assert_eq!(parts.next(), None);
        assert_eq!(components("/").next(), None);
        assert_eq!(components("/./.").next(), None);
        assert_eq!(components("/a/../b").nth(1), Some(".."));
    }

    #[test]
    fn validation_accepts_normal_absolute_paths() {
        for path in ["/", "/etc/motd", "/a//b/./c", "/a/b/", "/a..b/..c"] {
            assert_eq!(validate_absolute(path, 64), Ok(()), "{path}");
        }
    }

    #[test]
    fn validation_rejects_relative_paths_and_nul_bytes() {
        for path in ["", "etc/motd", "./etc", "/etc\0/motd", "/\0"] {
            assert_eq!(
                validate_absolute(path, 64),
                Err(Error::InvalidName),
                "{path:?}"
            );
        }
    }

    #[test]
    fn validation_refuses_dot_dot_instead_of_resolving_it() {
        for path in ["/..", "/a/../b", "/a/b/..", "/a/./../b"] {
            assert_eq!(
                validate_absolute(path, 64),
                Err(Error::InvalidName),
                "{path}"
            );
        }
    }

    #[test]
    fn validation_bounds_total_length() {
        assert_eq!(validate_absolute("/abc", 4), Ok(()));
        assert_eq!(validate_absolute("/abcd", 4), Err(Error::InvalidName));
    }

    #[test]
    fn validation_bounds_component_length() {
        let mut buffer = [b'a'; MAX_COMPONENT_LENGTH + 2];
        buffer[0] = b'/';
        let exact = core::str::from_utf8(&buffer[..MAX_COMPONENT_LENGTH + 1]).unwrap();
        let over = core::str::from_utf8(&buffer).unwrap();
        assert_eq!(validate_absolute(exact, 1024), Ok(()));
        assert_eq!(validate_absolute(over, 1024), Err(Error::InvalidName));
    }

    #[test]
    fn prefixes_match_whole_components_only() {
        assert!(starts_with_components("/etc/motd", "/etc"));
        assert!(starts_with_components("/etc", "/etc"));
        assert!(starts_with_components("/etc/", "/etc/"));
        assert!(starts_with_components("/anything", "/"));
        assert!(!starts_with_components("/etcfoo", "/etc"));
        assert!(!starts_with_components("/etc", "/etc/motd"));
        assert!(!starts_with_components("/etc/motd", "/etc/motd2"));
    }

    #[test]
    fn prefix_matching_ignores_empty_and_dot_components() {
        assert!(starts_with_components("/etc//./motd", "/./etc/"));
    }

    #[test]
    fn prefix_matching_requires_absolute_paths() {
        assert!(!starts_with_components("etc/motd", "/etc"));
        assert!(!starts_with_components("/etc/motd", "etc"));
    }
}
