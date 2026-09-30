//! Files in a package's payload that run, or grant privileges, on their own:
//! without the install scriptlet, pacman hooks run on later transactions,
//! sudoers and polkit rules grant root, enabled systemd units, udev and
//! modprobe rules, tmpfiles and sysusers entries run at boot or on events,
//! and login scripts, autostart entries, cron jobs and D-Bus system services
//! run on their own schedule. The pacman gate reviews these with the AI
//! alongside the scriptlet; the rest of the payload is not reviewed.
//!
//! The archive is listed (only the matching entries) before anything is
//! extracted, so sizes and counts are checked first, and extraction goes into
//! a private temporary directory that is removed afterwards.

use std::ffi::OsString;
use std::fs;
use std::path::Path;

use crate::error::Error;
use crate::sandbox::Workspace;
use crate::scan::MAX_TEXT_FILE_SIZE;
use crate::tools::{self, Limits};

/// Single files that act on their own.
const FILES: &[&str] = &["etc/sudoers", "etc/ld.so.preload"];

/// Directories whose every file acts on its own.
const DIRECTORIES: &[&str] = &[
    "usr/share/libalpm/hooks/",
    "etc/pacman.d/hooks/",
    "etc/sudoers.d/",
    "etc/polkit-1/rules.d/",
    "usr/share/polkit-1/rules.d/",
    "etc/pam.d/",
    "usr/lib/pam.d/",
    "etc/systemd/system/",
    "etc/systemd/user/",
    "usr/lib/systemd/system-preset/",
    "usr/lib/systemd/user-preset/",
    "usr/lib/systemd/system-generators/",
    "usr/lib/systemd/user-generators/",
    "usr/lib/tmpfiles.d/",
    "etc/tmpfiles.d/",
    "usr/lib/sysusers.d/",
    "etc/sysusers.d/",
    "usr/lib/binfmt.d/",
    "etc/binfmt.d/",
    "usr/lib/udev/rules.d/",
    "etc/udev/rules.d/",
    "usr/lib/modprobe.d/",
    "etc/modprobe.d/",
    "usr/lib/environment.d/",
    "etc/environment.d/",
    "etc/ld.so.conf.d/",
    "etc/profile.d/",
    "etc/xdg/autostart/",
    "etc/X11/xinit/xinitrc.d/",
    "etc/cron.d/",
    "etc/cron.hourly/",
    "etc/cron.daily/",
    "etc/cron.weekly/",
    "etc/cron.monthly/",
    "usr/share/dbus-1/system-services/",
    "usr/share/dbus-1/system.d/",
    "etc/dbus-1/system.d/",
];

/// Unit directories where a package enables units itself, through
/// `<target>.wants/`, `.requires/` or `.upholds/` links.
const UNIT_DIRECTORIES: &[&str] = &["usr/lib/systemd/system/", "usr/lib/systemd/user/"];
const ENABLING: &[&str] = &[".wants", ".requires", ".upholds"];

/// More matching files than any real package ships; a payload beyond these
/// limits is not reviewed, and the review is incomplete.
const MAX_FILES: usize = 2000;
const MAX_TOTAL: u64 = 32 * 1024 * 1024;

const LIMITS: Limits = Limits {
    timeout_secs: 120,
    max_output: 4 * 1024 * 1024,
};
const C_LOCALE: &[(&str, &str)] = &[("LC_ALL", "C")];

/// Whether the file at `path` (relative, as stored in the archive) runs or
/// grants privileges on its own.
pub fn is_auto_run(path: &str) -> bool {
    if path
        .split('/')
        .any(|component| matches!(component, "" | "." | ".."))
    {
        return false;
    }
    FILES.contains(&path)
        || DIRECTORIES
            .iter()
            .any(|directory| path.starts_with(directory))
        || UNIT_DIRECTORIES.iter().any(|directory| {
            path.strip_prefix(directory)
                .and_then(|rest| rest.split_once('/'))
                .is_some_and(|(parent, unit)| {
                    ENABLING.iter().any(|suffix| parent.ends_with(suffix)) && !unit.contains('/')
                })
        })
}

/// `bsdtar --include` patterns for `is_auto_run`, which every listed entry
/// is checked against again.
fn include_patterns() -> Vec<String> {
    FILES
        .iter()
        .map(|file| (*file).to_string())
        .chain(DIRECTORIES.iter().map(|directory| format!("{directory}*")))
        .chain(UNIT_DIRECTORIES.iter().flat_map(|directory| {
            ENABLING
                .iter()
                .map(move |suffix| format!("{directory}*{suffix}/*"))
        }))
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Kind {
    File,
    Symlink(String),
    /// A hard link to an earlier entry of the archive.
    HardLink(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    path: String,
    size: u64,
    kind: Kind,
}

/// Parses `bsdtar -tv` output in the C locale: mode, links, owner, group,
/// size, three date fields, then the name, with ` -> target` for symbolic
/// links and ` link to target` for hard links. Directories and other types
/// are skipped.
fn parse_listing(text: &str) -> Vec<Entry> {
    text.lines()
        .filter_map(|line| {
            let mut rest = line;
            let mut fields = Vec::with_capacity(8);
            for _ in 0..8 {
                rest = rest.trim_start();
                let end = rest.find(char::is_whitespace)?;
                fields.push(&rest[..end]);
                rest = &rest[end..];
            }
            let name = rest.strip_prefix(' ')?;
            let size = fields[4].parse().ok()?;
            let (path, kind) = match fields[0].chars().next()? {
                '-' => (name.to_string(), Kind::File),
                'l' => {
                    let (path, target) = name.split_once(" -> ")?;
                    (path.to_string(), Kind::Symlink(target.to_string()))
                }
                'h' => {
                    let (path, target) = name.split_once(" link to ")?;
                    (path.to_string(), Kind::HardLink(target.to_string()))
                }
                _ => return None,
            };
            Some(Entry { path, size, kind })
        })
        .collect()
}

/// A link's target as a package path, when it stays inside the package's
/// tree (absolute targets are package paths too, since the package is
/// installed at `/`).
fn resolve_link(link: &str, target: &str) -> Option<String> {
    let mut parts: Vec<&str> = if target.starts_with('/') {
        Vec::new()
    } else {
        link.split('/').collect()
    };
    if !target.starts_with('/') {
        parts.pop();
    }
    for component in target.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            name => parts.push(name),
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

/// bsdtar exits non-zero when an include pattern matches nothing; that alone
/// is not a failure.
fn only_unmatched_patterns(stderr: &[u8]) -> bool {
    String::from_utf8_lossy(stderr).lines().all(|line| {
        line.trim().is_empty()
            || line.contains("Not found in archive")
            || line.contains("Error exit delayed from previous errors")
    })
}

fn bsdtar(args: &[OsString], archive: &Path) -> Result<Vec<u8>, Error> {
    let captured = tools::run(Path::new(tools::BSDTAR), args, None, C_LOCALE, LIMITS)?;
    if captured.status.success() || only_unmatched_patterns(&captured.stderr) {
        Ok(captured.stdout)
    } else {
        Err(Error::ToolFailed {
            tool: "bsdtar".into(),
            detail: format!("{}: {}", archive.display(), captured.failure_detail()),
        })
    }
}

/// One payload file for the review: its package path and text, or `None`
/// for a binary that cannot be reviewed as text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadFile {
    pub path: String,
    pub text: Option<String>,
    /// The file as shipped: its bytes, or its link target for a symbolic
    /// link, to compare with what is installed.
    shipped: Shipped,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Shipped {
    Bytes(Vec<u8>),
    Link(String),
    Unknown,
}

impl PayloadFile {
    /// Whether the same file is already installed under `root` (`/` in
    /// production): identical bytes, or a link with the same target. Such a
    /// file adds nothing new, so an upgrade does not review it again. A file
    /// that cannot be read (for example root-only) counts as changed.
    pub fn is_installed_unchanged(&self, root: &Path) -> bool {
        let installed = root.join(&self.path);
        match &self.shipped {
            Shipped::Bytes(bytes) => {
                fs::symlink_metadata(&installed).is_ok_and(|metadata| {
                    metadata.is_file() && metadata.len() == bytes.len() as u64
                }) && fs::read(&installed).is_ok_and(|current| current == *bytes)
            }
            Shipped::Link(target) => {
                fs::read_link(&installed).is_ok_and(|current| current == Path::new(target))
            }
            Shipped::Unknown => false,
        }
    }
}

/// The auto-run files of `archive`. Errors (a listing or extraction that
/// fails, or a payload past the limits) make the review incomplete.
pub fn auto_run_files(archive: &Path) -> Result<Vec<PayloadFile>, Error> {
    let mut listing: Vec<OsString> = vec!["-tvf".into(), archive.into()];
    for pattern in include_patterns() {
        listing.push("--include".into());
        listing.push(pattern.into());
    }
    let listed = bsdtar(&listing, archive)?;
    let mut entries: Vec<Entry> = parse_listing(&String::from_utf8_lossy(&listed))
        .into_iter()
        .filter(|entry| is_auto_run(&entry.path))
        .collect();
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    if entries.is_empty() {
        return Ok(Vec::new());
    }

    let total: u64 = entries.iter().map(|entry| entry.size).sum();
    if entries.len() > MAX_FILES || total > MAX_TOTAL {
        return Err(Error::Refused(format!(
            "{}: {} auto-run files ({} KiB) exceed the review limits",
            archive.display(),
            entries.len(),
            total / 1024
        )));
    }
    if let Some(entry) = entries.iter().find(|entry| entry.size > MAX_TEXT_FILE_SIZE) {
        return Err(Error::Refused(format!(
            "{}: auto-run file {} exceeds the 2 MiB review limit",
            archive.display(),
            entry.path
        )));
    }

    // Everything to extract: the entries, and link targets inside the
    // package so a link is reviewed by what it points at.
    let mut wanted: Vec<String> = Vec::new();
    for entry in &entries {
        wanted.push(entry.path.clone());
        if let Kind::Symlink(target) | Kind::HardLink(target) = &entry.kind {
            let resolved = match &entry.kind {
                Kind::HardLink(_) => Some(target.clone()),
                _ => resolve_link(&entry.path, target),
            };
            wanted.extend(resolved);
        }
    }
    wanted.sort();
    wanted.dedup();

    let workspace = Workspace::create("payload")?;
    let mut extract: Vec<OsString> = vec![
        "-xf".into(),
        archive.into(),
        "-C".into(),
        workspace.path().into(),
        "--no-same-owner".into(),
        "--no-same-permissions".into(),
    ];
    for path in &wanted {
        extract.push("--include".into());
        extract.push(escape_pattern(path).into());
    }
    bsdtar(&extract, archive)?;

    Ok(entries
        .iter()
        .map(|entry| read_entry(workspace.path(), entry))
        .collect())
}

/// Glob characters in a file name are matched literally.
fn escape_pattern(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for character in path.chars() {
        if matches!(character, '*' | '?' | '[' | ']' | '\\') {
            out.push('\\');
        }
        out.push(character);
    }
    out
}

/// Reads an extracted regular file without following links, bounded by the
/// review size limit. `None` when it is missing, not a regular file or
/// not text.
fn read_text(root: &Path, path: &str) -> Option<String> {
    let full = root.join(path);
    let metadata = fs::symlink_metadata(&full).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_TEXT_FILE_SIZE {
        return None;
    }
    let bytes = fs::read(&full).ok()?;
    let text = String::from_utf8(bytes).ok()?;
    (!text.contains('\0')).then_some(text)
}

fn read_entry(root: &Path, entry: &Entry) -> PayloadFile {
    let shipped = match &entry.kind {
        Kind::File => read_bytes(root, &entry.path).map_or(Shipped::Unknown, Shipped::Bytes),
        Kind::HardLink(target) => read_bytes(root, target).map_or(Shipped::Unknown, Shipped::Bytes),
        Kind::Symlink(target) => Shipped::Link(target.clone()),
    };
    let text = match &entry.kind {
        Kind::File => read_text(root, &entry.path),
        Kind::HardLink(target) => read_text(root, target),
        Kind::Symlink(target) => Some(match resolve_link(&entry.path, target) {
            Some(resolved) => match read_text(root, &resolved) {
                Some(content) => format!(
                    "# {} is a symbolic link to {target}, whose content follows.\n{content}",
                    entry.path
                ),
                None => format!(
                    "# {} is a symbolic link to {target}, which this package does not ship as a text file.\n",
                    entry.path
                ),
            },
            None => format!(
                "# {} is a symbolic link to {target}, outside the package tree.\n",
                entry.path
            ),
        }),
    };
    PayloadFile {
        path: entry.path.clone(),
        text,
        shipped,
    }
}

fn read_bytes(root: &Path, path: &str) -> Option<Vec<u8>> {
    let full = root.join(path);
    let metadata = fs::symlink_metadata(&full).ok()?;
    (metadata.is_file() && metadata.len() <= MAX_TEXT_FILE_SIZE)
        .then(|| fs::read(&full).ok())
        .flatten()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::process::Command;

    use super::{Entry, Kind, auto_run_files, is_auto_run, parse_listing, resolve_link};
    use crate::test_support::{TempDir, tool_available};

    #[test]
    fn auto_run_locations() {
        for path in [
            "usr/share/libalpm/hooks/foo.hook",
            "etc/sudoers",
            "etc/sudoers.d/foo",
            "usr/share/polkit-1/rules.d/50-foo.rules",
            "etc/pam.d/foo",
            "usr/lib/systemd/system/multi-user.target.wants/foo.service",
            "usr/lib/systemd/user/default.target.wants/foo.service",
            "usr/lib/systemd/system-generators/foo",
            "usr/lib/tmpfiles.d/foo.conf",
            "usr/lib/udev/rules.d/99-foo.rules",
            "etc/profile.d/foo.sh",
            "etc/xdg/autostart/foo.desktop",
            "etc/cron.daily/foo",
            "usr/share/dbus-1/system-services/org.foo.service",
            "etc/ld.so.preload",
        ] {
            assert!(is_auto_run(path), "{path}");
        }
        for path in [
            "usr/bin/foo",
            "usr/lib/systemd/system/foo.service",
            "usr/share/doc/foo/README",
            "usr/share/applications/foo.desktop",
            "usr/lib/systemd/system/a.wants/b/c.service",
            "etc/sudoers.d/../../usr/bin/x",
            "usr/share/libalpm/hooks/",
        ] {
            assert!(!is_auto_run(path), "{path}");
        }
    }

    #[test]
    fn parses_bsdtar_listings() {
        let listing = "\
drwxr-xr-x  0 root   root        0 Sep 30 14:48 usr/share/libalpm/hooks/
-rw-r--r--  0 root   root      254 Sep 30 14:48 usr/share/libalpm/hooks/a b.hook
lrwxrwxrwx  0 root   root        0 Sep 30  2025 usr/lib/systemd/system/multi-user.target.wants/x.service -> ../x.service
hrw-r--r--  0 root   root        0 Sep 30 14:48 etc/pam.d/y link to etc/pam.d/x
";
        assert_eq!(
            parse_listing(listing),
            [
                Entry {
                    path: "usr/share/libalpm/hooks/a b.hook".into(),
                    size: 254,
                    kind: Kind::File
                },
                Entry {
                    path: "usr/lib/systemd/system/multi-user.target.wants/x.service".into(),
                    size: 0,
                    kind: Kind::Symlink("../x.service".into())
                },
                Entry {
                    path: "etc/pam.d/y".into(),
                    size: 0,
                    kind: Kind::HardLink("etc/pam.d/x".into())
                },
            ]
        );
    }

    #[test]
    fn links_resolve_inside_the_package() {
        let wants = "usr/lib/systemd/system/multi-user.target.wants/x.service";
        assert_eq!(
            resolve_link(wants, "../x.service").as_deref(),
            Some("usr/lib/systemd/system/x.service")
        );
        assert_eq!(
            resolve_link(wants, "/usr/lib/systemd/system/x.service").as_deref(),
            Some("usr/lib/systemd/system/x.service")
        );
        assert_eq!(resolve_link("a/b", "../../../../etc/shadow"), None);
    }

    #[test]
    fn extracts_auto_run_files_and_follows_enabling_links() {
        if !tool_available("/usr/bin/bsdtar") {
            return;
        }
        let dir = TempDir::new("payload");
        let root = dir.path().join("root");
        let units = root.join("usr/lib/systemd/system");
        fs::create_dir_all(units.join("multi-user.target.wants")).unwrap();
        fs::create_dir_all(root.join("etc/sudoers.d")).unwrap();
        fs::create_dir_all(root.join("usr/bin")).unwrap();
        fs::write(units.join("x.service"), "[Service]\nExecStart=/usr/bin/x\n").unwrap();
        symlink(
            "../x.service",
            units.join("multi-user.target.wants/x.service"),
        )
        .unwrap();
        fs::write(root.join("etc/sudoers.d/x"), "x ALL=(ALL) NOPASSWD: ALL\n").unwrap();
        fs::write(root.join("usr/bin/x"), [0_u8, 1, 2]).unwrap();
        let archive = dir.path().join("x-1-1-any.pkg.tar");
        let status = Command::new("/usr/bin/bsdtar")
            .arg("-cf")
            .arg(&archive)
            .args(["usr", "etc"])
            .current_dir(&root)
            .status()
            .unwrap();
        assert!(status.success());

        let files = auto_run_files(&archive).unwrap();
        let paths: Vec<&str> = files.iter().map(|file| file.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "etc/sudoers.d/x",
                "usr/lib/systemd/system/multi-user.target.wants/x.service"
            ]
        );
        assert_eq!(
            files[0].text.as_deref(),
            Some("x ALL=(ALL) NOPASSWD: ALL\n")
        );
        let unit = files[1].text.as_deref().unwrap();
        assert!(unit.contains("symbolic link to ../x.service"), "{unit}");
        assert!(unit.contains("ExecStart=/usr/bin/x"), "{unit}");

        // Installed copies that match are recognised; a changed one is not.
        let installed = dir.path().join("installed");
        fs::create_dir_all(installed.join("etc/sudoers.d")).unwrap();
        fs::create_dir_all(installed.join("usr/lib/systemd/system/multi-user.target.wants"))
            .unwrap();
        fs::write(
            installed.join("etc/sudoers.d/x"),
            "x ALL=(ALL) NOPASSWD: ALL\n",
        )
        .unwrap();
        symlink(
            "../x.service",
            installed.join("usr/lib/systemd/system/multi-user.target.wants/x.service"),
        )
        .unwrap();
        assert!(
            files
                .iter()
                .all(|file| file.is_installed_unchanged(&installed))
        );
        fs::write(installed.join("etc/sudoers.d/x"), "x ALL=(ALL) ALL\n").unwrap();
        assert!(!files[0].is_installed_unchanged(&installed));
        assert!(!files[0].is_installed_unchanged(&dir.path().join("nowhere")));

        // A package with none of these files lists nothing.
        let plain = dir.path().join("plain-1-1-any.pkg.tar");
        let status = Command::new("/usr/bin/bsdtar")
            .arg("-cf")
            .arg(&plain)
            .arg("usr/bin")
            .current_dir(&root)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(auto_run_files(&plain).unwrap().is_empty());
    }
}
