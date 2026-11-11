//! Host-platform rules for locating tools and data files.
//!
//! Everything here is a pure function of an explicit [`HostOs`] and of
//! caller-supplied environment lookups, so the Windows rules are unit-tested on
//! macOS and Linux and the Unix rules on Windows. Candidate paths are built as
//! strings with the separator of the OS passed in, not the separator of the
//! machine running the tests.

use std::path::PathBuf;

/// The host operating-system family, as far as tool discovery cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOs {
    /// Windows 10/11 (x86_64 or ARM64).
    Windows,
    /// macOS.
    MacOs,
    /// Linux and other Unix-like hosts.
    Unix,
}

impl HostOs {
    /// The OS this `xtask` binary was compiled for.
    pub const fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Unix
        }
    }

    /// Separator between directories in a path.
    pub const fn dir_separator(self) -> char {
        match self {
            Self::Windows => '\\',
            Self::MacOs | Self::Unix => '/',
        }
    }

    /// Separator between entries of `PATH`.
    pub const fn search_path_separator(self) -> char {
        match self {
            Self::Windows => ';',
            Self::MacOs | Self::Unix => ':',
        }
    }

    fn is_separator(self, c: char) -> bool {
        match self {
            // Windows accepts both, and MSYS2/Git tools often print `/`.
            Self::Windows => c == '\\' || c == '/',
            Self::MacOs | Self::Unix => c == '/',
        }
    }
}

/// An environment lookup: `getenv("NAME")` returns the value if set and non-empty.
pub type GetEnv<'a> = &'a dyn Fn(&str) -> Option<String>;

/// The file name an executable called `name` has on `os`.
///
/// Windows executables carry `.exe`; a name that already ends in `.exe` (any
/// case) is kept as is.
pub fn exe_file_name(name: &str, os: HostOs) -> String {
    match os {
        HostOs::Windows if !name.to_ascii_lowercase().ends_with(".exe") => format!("{name}.exe"),
        _ => name.to_owned(),
    }
}

/// Join path components with the separator of `os`, without doubling a
/// trailing separator on `base`.
pub fn join(os: HostOs, base: &str, parts: &[&str]) -> String {
    let sep = os.dir_separator();
    let mut out = base.to_owned();
    for part in parts {
        while out.len() > 1 && out.ends_with(|c| os.is_separator(c)) && !is_drive_root(os, &out) {
            out.pop();
        }
        if !out.is_empty() && !out.ends_with(|c| os.is_separator(c)) {
            out.push(sep);
        }
        out.push_str(part);
    }
    out
}

/// `C:\` keeps its separator: `C:` alone means "current directory on C:".
fn is_drive_root(os: HostOs, path: &str) -> bool {
    os == HostOs::Windows && path.len() == 3 && path.as_bytes()[1] == b':'
}

/// Split a `PATH`-style value into directories, as `os` would.
///
/// Empty entries are dropped. On Windows, double quotes around an entry (used
/// for entries that contain `;`) are removed.
pub fn split_search_path(value: &str, os: HostOs) -> Vec<String> {
    let mut dirs = Vec::new();
    match os {
        HostOs::Windows => {
            let mut current = String::new();
            let mut quoted = false;
            for c in value.chars() {
                match c {
                    '"' => quoted = !quoted,
                    ';' if !quoted => dirs.push(std::mem::take(&mut current)),
                    _ => current.push(c),
                }
            }
            dirs.push(current);
        }
        HostOs::MacOs | HostOs::Unix => {
            dirs.extend(value.split(os.search_path_separator()).map(str::to_owned));
        }
    }
    dirs.retain(|dir| !dir.is_empty());
    dirs
}

/// Split a path into its parent directory and final component.
fn split_last(path: &str, os: HostOs) -> Option<(&str, &str)> {
    let trimmed = path.trim_end_matches(|c| os.is_separator(c));
    let index = trimmed.rfind(|c| os.is_separator(c))?;
    let parent = &trimmed[..index];
    let name = &trimmed[index + 1..];
    // Keep the root: `/bin` has parent `/`, `C:\bin` has parent `C:\`.
    let parent = if parent.is_empty() || (os == HostOs::Windows && parent.ends_with(':')) {
        &trimmed[..=index]
    } else {
        parent
    };
    Some((parent, name))
}

/// Map `<prefix>/bin/limine[.exe]` to `<prefix>/share/limine`.
pub fn prefix_data_dir(binary: &str, os: HostOs) -> Option<String> {
    let (bin, _) = split_last(binary, os)?;
    let (prefix, bin_name) = split_last(bin, os)?;
    let is_bin = match os {
        HostOs::Windows => bin_name.eq_ignore_ascii_case("bin"),
        HostOs::MacOs | HostOs::Unix => bin_name == "bin",
    };
    is_bin.then(|| join(os, prefix, &["share", "limine"]))
}

/// The first `name` found in `dirs`, using the executable file name for `os`.
pub fn find_in_dirs<F>(name: &str, dirs: &[String], os: HostOs, is_file: F) -> Option<String>
where
    F: Fn(&str) -> bool,
{
    let file = exe_file_name(name, os);
    dirs.iter()
        .map(|dir| join(os, dir, &[&file]))
        .find(|candidate| is_file(candidate))
}

/// `%ProgramFiles%`, defaulting to the standard location.
fn program_files(getenv: GetEnv<'_>) -> String {
    getenv("ProgramFiles").unwrap_or_else(|| r"C:\Program Files".to_owned())
}

/// The scoop root: `%SCOOP%`, else `%USERPROFILE%\scoop`.
fn scoop_root(getenv: GetEnv<'_>) -> Option<String> {
    getenv("SCOOP")
        .or_else(|| getenv("USERPROFILE").map(|home| join(HostOs::Windows, &home, &["scoop"])))
}

/// The Chocolatey root: `%ChocolateyInstall%`, else its default.
fn chocolatey_root(getenv: GetEnv<'_>) -> String {
    getenv("ChocolateyInstall").unwrap_or_else(|| r"C:\ProgramData\chocolatey".to_owned())
}

/// MSYS2 environment prefixes, most common first. `clangarm64` serves ARM64 hosts.
const MSYS2_ENVIRONMENTS: &[&str] = &["ucrt64", "clang64", "mingw64", "clangarm64"];

/// The MSYS2 root: `%MSYS2_ROOT%`, else the installer default.
fn msys2_root(getenv: GetEnv<'_>) -> String {
    getenv("MSYS2_ROOT").unwrap_or_else(|| r"C:\msys64".to_owned())
}

/// `<msys2>\<env>\<parts...>` for every MSYS2 environment.
fn msys2_paths(getenv: GetEnv<'_>, parts: &[&str]) -> Vec<String> {
    let root = msys2_root(getenv);
    MSYS2_ENVIRONMENTS
        .iter()
        .map(|env| {
            let mut all = vec![*env];
            all.extend_from_slice(parts);
            join(HostOs::Windows, &root, &all)
        })
        .collect()
}

/// Installation data directories for Limine, checked after PATH discovery.
pub fn well_known_limine_dirs(os: HostOs, getenv: GetEnv<'_>) -> Vec<String> {
    match os {
        HostOs::MacOs | HostOs::Unix => [
            "/opt/homebrew/share/limine",
            "/usr/local/share/limine",
            "/usr/share/limine",
        ]
        .map(str::to_owned)
        .to_vec(),
        HostOs::Windows => {
            let w = HostOs::Windows;
            let mut dirs = vec![join(w, &program_files(getenv), &["limine"])];
            if let Some(local) = getenv("LOCALAPPDATA") {
                dirs.push(join(w, &local, &["limine"]));
            }
            if let Some(scoop) = scoop_root(getenv) {
                dirs.push(join(w, &scoop, &["apps", "limine", "current"]));
                dirs.push(join(
                    w,
                    &scoop,
                    &["apps", "limine", "current", "share", "limine"],
                ));
            }
            dirs.push(join(
                w,
                &chocolatey_root(getenv),
                &["lib", "limine", "tools"],
            ));
            dirs.extend(msys2_paths(getenv, &["share", "limine"]));
            dirs
        }
    }
}

/// Full paths where a host tool may be installed outside `PATH`.
///
/// On macOS and Linux the package managers put tools on `PATH`, so only
/// Windows has entries; the one exception is Homebrew LLD, which is keg-only.
pub fn well_known_tool_paths(tool: Tool, os: HostOs, getenv: GetEnv<'_>) -> Vec<String> {
    let w = HostOs::Windows;
    match (os, tool) {
        (HostOs::MacOs, Tool::Lld) => vec!["/opt/homebrew/bin/ld.lld".to_owned()],
        (HostOs::MacOs | HostOs::Unix, _) => Vec::new(),
        (HostOs::Windows, Tool::Lld) => {
            let exe = exe_file_name("ld.lld", w);
            let mut paths = vec![join(w, &program_files(getenv), &["LLVM", "bin", &exe])];
            if let Some(scoop) = scoop_root(getenv) {
                paths.push(join(w, &scoop, &["apps", "llvm", "current", "bin", &exe]));
            }
            paths.extend(msys2_paths(getenv, &["bin", &exe]));
            paths
        }
        (HostOs::Windows, Tool::Qemu) => {
            let exe = exe_file_name("qemu-system-x86_64", w);
            // The official installer and Chocolatey both use %ProgramFiles%\qemu.
            let mut paths = vec![join(w, &program_files(getenv), &["qemu", &exe])];
            if let Some(scoop) = scoop_root(getenv) {
                paths.push(join(w, &scoop, &["apps", "qemu", "current", &exe]));
            }
            paths.extend(msys2_paths(getenv, &["bin", &exe]));
            paths
        }
        (HostOs::Windows, Tool::Xorriso) => {
            let exe = exe_file_name("xorriso", w);
            let mut paths = vec![join(w, &msys2_root(getenv), &["usr", "bin", &exe])];
            paths.extend(msys2_paths(getenv, &["bin", &exe]));
            paths.push(join(w, r"C:\cygwin64", &["bin", &exe]));
            if let Some(scoop) = scoop_root(getenv) {
                paths.push(join(w, &scoop, &["apps", "xorriso", "current", &exe]));
            }
            paths
        }
        (HostOs::Windows, Tool::Limine) => {
            let exe = exe_file_name("limine", w);
            well_known_limine_dirs(w, getenv)
                .into_iter()
                .flat_map(|dir| {
                    // Binary releases ship limine.exe beside the data files;
                    // `share\limine` layouts keep it in `<prefix>\bin`.
                    let mut paths = vec![join(w, &dir, &[&exe])];
                    if let Some(prefix) = dir
                        .strip_suffix(r"\share\limine")
                        .filter(|prefix| !prefix.is_empty())
                    {
                        paths.push(join(w, prefix, &["bin", &exe]));
                    }
                    paths
                })
                .collect()
        }
    }
}

/// A host tool that `xtask` runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    /// GNU-flavour LLD (`ld.lld`).
    Lld,
    /// `xorriso`, for the ISO image.
    Xorriso,
    /// The `limine` host utility.
    Limine,
    /// `qemu-system-x86_64`.
    Qemu,
}

impl Tool {
    /// The command name, without any executable suffix.
    pub const fn command(self) -> &'static str {
        match self {
            Self::Lld => "ld.lld",
            Self::Xorriso => "xorriso",
            Self::Limine => "limine",
            Self::Qemu => "qemu-system-x86_64",
        }
    }

    /// The environment variable that overrides discovery.
    pub const fn override_var(self) -> &'static str {
        match self {
            Self::Lld => "WUXIA_LLD",
            Self::Xorriso => "WUXIA_XORRISO",
            Self::Limine => "WUXIA_LIMINE",
            Self::Qemu => "WUXIA_QEMU",
        }
    }
}

/// How a tool will be invoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    /// Run the bare command name and let the OS search `PATH`.
    OnPath(String),
    /// Run this exact file.
    At(String),
}

impl Resolved {
    /// The program to pass to `Command::new`.
    pub fn program(&self) -> PathBuf {
        match self {
            Self::OnPath(name) | Self::At(name) => PathBuf::from(name),
        }
    }
}

/// Decide how to run `tool`.
///
/// Order: the override variable; on macOS for LLD only, the Homebrew keg
/// (kept ahead of `PATH` as before); `PATH`; the remaining well-known
/// locations. If nothing is found the bare name is returned so the spawn error
/// names the missing command.
pub fn resolve_tool<F>(
    tool: Tool,
    os: HostOs,
    getenv: GetEnv<'_>,
    path_dirs: &[String],
    is_file: F,
) -> Resolved
where
    F: Fn(&str) -> bool,
{
    if let Some(value) = getenv(tool.override_var()) {
        return Resolved::At(value);
    }
    let well_known = well_known_tool_paths(tool, os, getenv);
    let (before_path, after_path): (&[String], &[String]) = match (os, tool) {
        (HostOs::MacOs, Tool::Lld) => (&well_known, &[]),
        _ => (&[], &well_known),
    };
    if let Some(found) = before_path.iter().find(|p| is_file(p)) {
        return Resolved::At(found.clone());
    }
    if find_in_dirs(tool.command(), path_dirs, os, &is_file).is_some() {
        return Resolved::OnPath(tool.command().to_owned());
    }
    if let Some(found) = after_path.iter().find(|p| is_file(p)) {
        return Resolved::At(found.clone());
    }
    Resolved::OnPath(tool.command().to_owned())
}

/// The `rust-lld` shipped with a rustup toolchain:
/// `<sysroot>/lib/rustlib/<host triple>/bin/rust-lld[.exe]`.
pub fn rust_lld_path(sysroot: &str, host_triple: &str, os: HostOs) -> String {
    join(
        os,
        sysroot,
        &[
            "lib",
            "rustlib",
            host_triple,
            "bin",
            &exe_file_name("rust-lld", os),
        ],
    )
}

/// The `host:` triple from `rustc -vV` output (LF or CRLF line endings).
pub fn host_triple_from_rustc_verbose(output: &str) -> Option<String> {
    output
        .lines()
        .find_map(|line| line.trim_end_matches('\r').strip_prefix("host:"))
        .map(|host| host.trim().to_owned())
        .filter(|host| !host.is_empty())
}

/// Turn raw serial bytes into text with `\n` line endings.
///
/// QEMU on Windows, or a guest that writes `\r\n`, produces CRLF; a lone `\r`
/// is treated as a line break too. Invalid UTF-8 is replaced, not fatal, so a
/// garbled byte cannot hide every marker.
pub fn normalize_serial(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .replace("\r\n", "\n")
        .replace('\r', "\n")
}

/// Markers absent from the normalized serial `text`, in `markers` order.
pub fn missing_markers<'a>(text: &str, markers: &[&'a str]) -> Vec<&'a str> {
    markers
        .iter()
        .copied()
        .filter(|marker| !text.contains(marker))
        .collect()
}

/// Rust flags for the bare-metal build, encoded for `CARGO_ENCODED_RUSTFLAGS`.
///
/// The encoded form separates flags with `0x1f`, so a linker path with spaces
/// (`C:\Program Files\LLVM\bin\ld.lld.exe`) survives intact; plain `RUSTFLAGS`
/// would split it. `rust-lld` is told explicitly to act as GNU `ld.lld`
/// (rustc then passes `-flavor gnu`).
pub fn encoded_linker_rustflags(linker: &str, rust_lld: bool) -> String {
    let mut flags = vec!["-C".to_owned(), format!("linker={linker}")];
    if rust_lld {
        flags.push("-C".to_owned());
        flags.push("linker-flavor=ld.lld".to_owned());
    }
    flags.join("\u{1f}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: HostOs = HostOs::Windows;
    const M: HostOs = HostOs::MacOs;
    const U: HostOs = HostOs::Unix;

    fn env_of(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| (*value).to_owned())
        }
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn files(list: &'static [&'static str]) -> impl Fn(&str) -> bool {
        move |path| list.contains(&path)
    }

    #[test]
    fn exe_suffix_only_on_windows() {
        assert_eq!(exe_file_name("rustc", W), "rustc.exe");
        assert_eq!(exe_file_name("ld.lld", W), "ld.lld.exe");
        assert_eq!(exe_file_name("limine.EXE", W), "limine.EXE");
        assert_eq!(exe_file_name("rustc", M), "rustc");
        assert_eq!(exe_file_name("ld.lld", U), "ld.lld");
    }

    #[test]
    fn join_uses_the_target_separator() {
        assert_eq!(
            join(W, r"C:\Program Files", &["qemu", "x.exe"]),
            r"C:\Program Files\qemu\x.exe"
        );
        assert_eq!(join(W, r"C:\tools\", &["a"]), r"C:\tools\a");
        assert_eq!(join(W, r"C:\", &["a"]), r"C:\a");
        assert_eq!(join(W, "C:/msys64/", &["usr"]), r"C:/msys64\usr");
        assert_eq!(join(U, "/usr/", &["share", "limine"]), "/usr/share/limine");
        assert_eq!(join(U, "/", &["bin"]), "/bin");
    }

    #[test]
    fn search_path_splitting_follows_the_os() {
        assert_eq!(
            split_search_path(r#"C:\a;;"C:\semi;colon";C:\Program Files\qemu"#, W),
            [r"C:\a", r"C:\semi;colon", r"C:\Program Files\qemu"]
        );
        assert_eq!(
            split_search_path("/usr/bin::/opt/homebrew/bin", M),
            ["/usr/bin", "/opt/homebrew/bin"]
        );
        // A Windows drive letter is not a separator on Windows.
        assert_eq!(split_search_path(r"C:\bin", W), [r"C:\bin"]);
    }

    #[test]
    fn prefix_data_dir_maps_bin_to_share_on_every_os() {
        assert_eq!(
            prefix_data_dir("/opt/homebrew/bin/limine", M).as_deref(),
            Some("/opt/homebrew/share/limine")
        );
        assert_eq!(
            prefix_data_dir("/opt/homebrew/Cellar/limine/12.9.6/bin/limine", M).as_deref(),
            Some("/opt/homebrew/Cellar/limine/12.9.6/share/limine")
        );
        assert_eq!(
            prefix_data_dir("/bin/limine", U).as_deref(),
            Some("/share/limine")
        );
        assert_eq!(
            prefix_data_dir(r"C:\msys64\ucrt64\bin\limine.exe", W).as_deref(),
            Some(r"C:\msys64\ucrt64\share\limine")
        );
        assert_eq!(
            prefix_data_dir(r"C:\Tools\Limine\BIN\limine.exe", W).as_deref(),
            Some(r"C:\Tools\Limine\share\limine")
        );
        assert_eq!(
            prefix_data_dir("C:/msys64/usr/bin/limine.exe", W).as_deref(),
            Some(r"C:/msys64/usr\share\limine")
        );
    }

    #[test]
    fn prefix_data_dir_rejects_binaries_outside_bin() {
        assert_eq!(prefix_data_dir("/tmp/limine", U), None);
        assert_eq!(prefix_data_dir("limine", U), None);
        assert_eq!(prefix_data_dir(r"C:\limine\limine.exe", W), None);
        // A backslash is an ordinary character on Unix.
        assert_eq!(prefix_data_dir(r"C:\x\bin\limine", U), None);
    }

    #[test]
    fn find_in_dirs_appends_exe_on_windows() {
        let dirs = vec![r"C:\a".to_owned(), r"C:\b".to_owned()];
        let found = find_in_dirs(
            "limine",
            &dirs,
            W,
            files(&[r"C:\b\limine.exe", r"C:\a\limine"]),
        );
        assert_eq!(found.as_deref(), Some(r"C:\b\limine.exe"));

        let dirs = vec!["/a".to_owned(), "/b".to_owned()];
        let found = find_in_dirs("limine", &dirs, U, files(&["/b/limine", "/a/limine.exe"]));
        assert_eq!(found.as_deref(), Some("/b/limine"));
    }

    #[test]
    fn unix_limine_dirs_are_unchanged() {
        assert_eq!(
            well_known_limine_dirs(M, &no_env),
            [
                "/opt/homebrew/share/limine",
                "/usr/local/share/limine",
                "/usr/share/limine"
            ]
        );
        assert_eq!(
            well_known_limine_dirs(U, &no_env),
            well_known_limine_dirs(M, &no_env)
        );
    }

    #[test]
    fn windows_limine_dirs_cover_installers_and_package_managers() {
        let env = env_of(&[
            ("ProgramFiles", r"D:\Apps"),
            ("LOCALAPPDATA", r"C:\Users\dev\AppData\Local"),
            ("USERPROFILE", r"C:\Users\dev"),
        ]);
        assert_eq!(
            well_known_limine_dirs(W, &env),
            [
                r"D:\Apps\limine",
                r"C:\Users\dev\AppData\Local\limine",
                r"C:\Users\dev\scoop\apps\limine\current",
                r"C:\Users\dev\scoop\apps\limine\current\share\limine",
                r"C:\ProgramData\chocolatey\lib\limine\tools",
                r"C:\msys64\ucrt64\share\limine",
                r"C:\msys64\clang64\share\limine",
                r"C:\msys64\mingw64\share\limine",
                r"C:\msys64\clangarm64\share\limine",
            ]
        );
    }

    #[test]
    fn windows_defaults_apply_without_environment() {
        let dirs = well_known_limine_dirs(W, &no_env);
        assert_eq!(dirs[0], r"C:\Program Files\limine");
        assert!(dirs.iter().all(|dir| !dir.contains("scoop")));
        assert!(dirs.contains(&r"C:\ProgramData\chocolatey\lib\limine\tools".to_owned()));
    }

    #[test]
    fn scoop_and_msys2_roots_can_be_overridden() {
        let env = env_of(&[
            ("SCOOP", r"E:\scoop"),
            ("MSYS2_ROOT", r"E:\msys2"),
            ("USERPROFILE", r"C:\Users\x"),
        ]);
        let qemu = well_known_tool_paths(Tool::Qemu, W, &env);
        assert!(qemu.contains(&r"E:\scoop\apps\qemu\current\qemu-system-x86_64.exe".to_owned()));
        assert!(qemu.contains(&r"E:\msys2\clangarm64\bin\qemu-system-x86_64.exe".to_owned()));
        assert!(qemu.iter().all(|p| !p.contains(r"C:\Users\x")));
    }

    #[test]
    fn windows_qemu_prefers_program_files() {
        let paths = well_known_tool_paths(Tool::Qemu, W, &no_env);
        assert_eq!(paths[0], r"C:\Program Files\qemu\qemu-system-x86_64.exe");
        assert!(paths.contains(&r"C:\msys64\ucrt64\bin\qemu-system-x86_64.exe".to_owned()));
        assert!(paths.iter().all(|p| p.ends_with(".exe")));
    }

    #[test]
    fn windows_tool_lists_cover_lld_xorriso_and_limine() {
        let lld = well_known_tool_paths(Tool::Lld, W, &no_env);
        assert_eq!(lld[0], r"C:\Program Files\LLVM\bin\ld.lld.exe");
        let xorriso = well_known_tool_paths(Tool::Xorriso, W, &no_env);
        assert_eq!(xorriso[0], r"C:\msys64\usr\bin\xorriso.exe");
        assert!(xorriso.contains(&r"C:\cygwin64\bin\xorriso.exe".to_owned()));
        let limine = well_known_tool_paths(Tool::Limine, W, &no_env);
        assert_eq!(limine[0], r"C:\Program Files\limine\limine.exe");
        assert!(limine.contains(&r"C:\msys64\ucrt64\bin\limine.exe".to_owned()));
    }

    #[test]
    fn unix_tools_rely_on_path_except_homebrew_lld() {
        for tool in [Tool::Xorriso, Tool::Limine, Tool::Qemu] {
            assert!(well_known_tool_paths(tool, M, &no_env).is_empty());
            assert!(well_known_tool_paths(tool, U, &no_env).is_empty());
        }
        assert_eq!(
            well_known_tool_paths(Tool::Lld, M, &no_env),
            ["/opt/homebrew/bin/ld.lld"]
        );
        assert!(well_known_tool_paths(Tool::Lld, U, &no_env).is_empty());
    }

    #[test]
    fn override_variable_wins() {
        let env = env_of(&[("WUXIA_QEMU", r"D:\q\qemu.exe")]);
        let resolved = resolve_tool(Tool::Qemu, W, &env, &[], |_| false);
        assert_eq!(resolved, Resolved::At(r"D:\q\qemu.exe".to_owned()));
    }

    #[test]
    fn path_beats_well_known_on_windows() {
        let dirs = vec![r"C:\bin".to_owned()];
        let fs = files(&[
            r"C:\bin\qemu-system-x86_64.exe",
            r"C:\Program Files\qemu\qemu-system-x86_64.exe",
        ]);
        assert_eq!(
            resolve_tool(Tool::Qemu, W, &no_env, &dirs, fs),
            Resolved::OnPath("qemu-system-x86_64".to_owned())
        );
    }

    #[test]
    fn well_known_used_when_not_on_path() {
        let fs = files(&[r"C:\Program Files\qemu\qemu-system-x86_64.exe"]);
        assert_eq!(
            resolve_tool(Tool::Qemu, W, &no_env, &[], fs),
            Resolved::At(r"C:\Program Files\qemu\qemu-system-x86_64.exe".to_owned())
        );
    }

    #[test]
    fn missing_tool_falls_back_to_bare_name() {
        assert_eq!(
            resolve_tool(Tool::Xorriso, U, &no_env, &["/usr/bin".to_owned()], |_| {
                false
            }),
            Resolved::OnPath("xorriso".to_owned())
        );
    }

    #[test]
    fn homebrew_lld_stays_ahead_of_path_on_macos() {
        let dirs = vec!["/usr/bin".to_owned()];
        let fs = files(&["/usr/bin/ld.lld", "/opt/homebrew/bin/ld.lld"]);
        assert_eq!(
            resolve_tool(Tool::Lld, M, &no_env, &dirs, fs),
            Resolved::At("/opt/homebrew/bin/ld.lld".to_owned())
        );
        // Linux never looks at the Homebrew path.
        let fs = files(&["/opt/homebrew/bin/ld.lld"]);
        assert_eq!(
            resolve_tool(Tool::Lld, U, &no_env, &dirs, fs),
            Resolved::OnPath("ld.lld".to_owned())
        );
    }

    #[test]
    fn rust_lld_lives_in_the_host_rustlib() {
        assert_eq!(
            rust_lld_path(
                r"C:\Users\dev\.rustup\toolchains\1.91.0-aarch64-pc-windows-msvc",
                "aarch64-pc-windows-msvc",
                W
            ),
            r"C:\Users\dev\.rustup\toolchains\1.91.0-aarch64-pc-windows-msvc\lib\rustlib\aarch64-pc-windows-msvc\bin\rust-lld.exe"
        );
        assert_eq!(
            rust_lld_path(
                "/home/dev/.rustup/toolchains/x",
                "x86_64-unknown-linux-gnu",
                U
            ),
            "/home/dev/.rustup/toolchains/x/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld"
        );
    }

    #[test]
    fn host_triple_parses_lf_and_crlf() {
        let lf = "rustc 1.91.0 (f8297e351 2025-10-28)\nbinary: rustc\nhost: aarch64-apple-darwin\nrelease: 1.91.0\n";
        assert_eq!(
            host_triple_from_rustc_verbose(lf).as_deref(),
            Some("aarch64-apple-darwin")
        );
        let crlf = "rustc 1.91.0\r\nhost: x86_64-pc-windows-msvc\r\nrelease: 1.91.0\r\n";
        assert_eq!(
            host_triple_from_rustc_verbose(crlf).as_deref(),
            Some("x86_64-pc-windows-msvc")
        );
        assert_eq!(host_triple_from_rustc_verbose("release: 1\n"), None);
    }

    #[test]
    fn serial_normalization_accepts_crlf_cr_and_bad_utf8() {
        assert_eq!(normalize_serial(b"A\r\nB\rC\nD"), "A\nB\nC\nD");
        assert_eq!(normalize_serial(b"OK\xff\r\n"), "OK\u{fffd}\n");
    }

    #[test]
    fn markers_found_regardless_of_line_endings() {
        let markers = ["WUXIA_BOOT_OK", "HELLO FROM USER", "WUXIA_TEST_PASS"];
        let crlf = normalize_serial(b"WUXIA_BOOT_OK: x\r\nHELLO FROM USER\r\nWUXIA_TEST_PASS\r\n");
        assert!(missing_markers(&crlf, &markers).is_empty());
        let partial = normalize_serial(b"WUXIA_BOOT_OK\r\n");
        assert_eq!(
            missing_markers(&partial, &markers),
            ["HELLO FROM USER", "WUXIA_TEST_PASS"]
        );
    }

    #[test]
    fn rustflags_are_unit_separated_and_keep_spaces() {
        let flags = encoded_linker_rustflags(r"C:\Program Files\LLVM\bin\ld.lld.exe", false);
        assert_eq!(
            flags.split('\u{1f}').collect::<Vec<_>>(),
            ["-C", r"linker=C:\Program Files\LLVM\bin\ld.lld.exe"]
        );
        let flags = encoded_linker_rustflags("/x/rust-lld", true);
        assert_eq!(
            flags.split('\u{1f}').collect::<Vec<_>>(),
            ["-C", "linker=/x/rust-lld", "-C", "linker-flavor=ld.lld"]
        );
    }
}
