//! Looking at installed files without ever following a link into them or
//! running them: a file is opened with `O_NOFOLLOW`, hashed in full and kept
//! only up to the text review limit; a link is read, never opened.
//!
//! Paths are relative to a root (`/` on a real system, a fixture in tests),
//! so the package index (keyed by paths relative to `/`) applies directly.

use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use crate::payload::{O_NOFOLLOW, O_NONBLOCK};
use crate::scan::{MAX_HASHED_FILE_SIZE, MAX_TEXT_FILE_SIZE};
use crate::sha256::{Digest, Sha256};

/// Directories deeper than this under a location are not looked into.
const MAX_DEPTH: usize = 6;
/// Entries one location may hold before the rest is reported, not read.
pub const MAX_ENTRIES: usize = 20_000;
/// Links followed when resolving one.
const MAX_HOPS: usize = 8;

/// What is at a path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Found {
    File {
        sha256: Digest,
        /// Permission bits including set-id bits.
        mode: u32,
        size: u64,
        /// The first `MAX_TEXT_FILE_SIZE + 1` bytes.
        head: Vec<u8>,
    },
    Link(String),
    /// Neither a regular file nor a link (a FIFO, a device, a directory).
    Other,
    /// Could not be read (usually: only root can).
    Unreadable(String),
}

/// Looks at `rel` under `root` without following a final link.
pub fn look(root: &Path, rel: &str) -> Found {
    let path = root.join(rel);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) => return Found::Unreadable(error.to_string()),
    };
    let kind = metadata.file_type();
    if kind.is_symlink() {
        return match fs::read_link(&path) {
            Ok(target) => match target.to_str() {
                Some(target) => Found::Link(target.to_string()),
                None => Found::Unreadable("link target is not UTF-8".into()),
            },
            Err(error) => Found::Unreadable(error.to_string()),
        };
    }
    if !kind.is_file() {
        return Found::Other;
    }
    if metadata.len() > MAX_HASHED_FILE_SIZE {
        return Found::Unreadable("larger than the hash limit".into());
    }
    match read_file(&path, &metadata) {
        Ok(found) => found,
        Err(error) => Found::Unreadable(error.to_string()),
    }
}

fn read_file(path: &Path, expected: &fs::Metadata) -> io::Result<Found> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.ino() != expected.ino() || opened.dev() != expected.dev() {
        return Err(io::Error::other("changed while it was being read"));
    }
    let mut hasher = Sha256::new();
    let mut head = Vec::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut size = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        size += read as u64;
        if size > MAX_HASHED_FILE_SIZE {
            return Err(io::Error::other("grew past the hash limit"));
        }
        hasher.update(&buffer[..read]);
        let keep = usize::try_from(MAX_TEXT_FILE_SIZE + 1)
            .unwrap_or(usize::MAX)
            .saturating_sub(head.len())
            .min(read);
        head.extend_from_slice(&buffer[..keep]);
    }
    Ok(Found::File {
        sha256: hasher.finalize(),
        mode: opened.mode() & 0o7777,
        size,
        head,
    })
}

/// Whether file `name` has extension `extension` (any case).
pub fn has_extension(name: &str, extension: &str) -> bool {
    Path::new(name)
        .extension()
        .is_some_and(|found| found.eq_ignore_ascii_case(extension))
}

/// What a directory walk found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Listing {
    /// Every non-directory entry, sorted.
    pub files: Vec<String>,
    /// The walk stopped at a limit.
    pub truncated: bool,
    /// Directories that exist but could not be listed (only root can).
    pub unreadable: Vec<String>,
}

/// Every non-directory entry under directory `rel` (relative to `root`),
/// without entering linked directories.
pub fn entries(root: &Path, rel: &str) -> Listing {
    let mut files = Vec::new();
    let mut unreadable = Vec::new();
    let mut truncated = false;
    let mut pending = vec![(rel.trim_end_matches('/').to_string(), 0)];
    while let Some((directory, depth)) = pending.pop() {
        let listing = match fs::read_dir(root.join(&directory)) {
            Ok(listing) => listing,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => {
                unreadable.push(directory);
                continue;
            }
        };
        for entry in listing.filter_map(Result::ok) {
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let child = format!("{directory}/{name}");
            let is_directory = entry.file_type().is_ok_and(|kind| kind.is_dir());
            if is_directory {
                if depth + 1 < MAX_DEPTH {
                    pending.push((child, depth + 1));
                } else {
                    truncated = true;
                }
            } else if files.len() < MAX_ENTRIES {
                files.push(child);
            } else {
                truncated = true;
            }
        }
    }
    files.sort();
    unreadable.sort();
    Listing {
        files,
        truncated,
        unreadable,
    }
}

/// Where the link at `rel` with text `target` finally points, relative to
/// `root`, following further links; `None` when it leaves `root`, loops or
/// points at nothing.
pub fn resolve(root: &Path, rel: &str, target: &str) -> Option<String> {
    let mut current = rel.to_string();
    let mut target = target.to_string();
    for _ in 0..MAX_HOPS {
        let base = if target.starts_with('/') {
            PathBuf::new()
        } else {
            Path::new(&current).parent()?.to_path_buf()
        };
        let next = normalize(&base.join(target.trim_start_matches('/')))?;
        match fs::symlink_metadata(root.join(&next)) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                target = fs::read_link(root.join(&next)).ok()?.to_str()?.to_string();
                current = next;
            }
            Ok(_) => return Some(next),
            Err(_) => return None,
        }
    }
    None
}

/// `rel` with every directory link on the way resolved (`bin/sh` is
/// `usr/bin/sh` on Arch, where `/bin` links to `usr/bin`); the last
/// component is kept as is. `None` when it leaves `root`.
pub fn canonical(root: &Path, rel: &str) -> Option<String> {
    let (parent, name) = rel.rsplit_once('/').unwrap_or(("", rel));
    let real_root = fs::canonicalize(root).ok()?;
    let real_parent = fs::canonicalize(root.join(parent)).ok()?;
    let inside = real_parent.strip_prefix(&real_root).ok()?.to_str()?;
    Some(if inside.is_empty() {
        name.to_string()
    } else {
        format!("{inside}/{name}")
    })
}

/// `path` without `.` and `..`, refusing to climb above the root.
fn normalize(path: &Path) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_str()?),
            Component::ParentDir => {
                parts.pop()?;
            }
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
        }
    }
    Some(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::{Found, entries, look, resolve};
    use crate::sha256::Sha256;
    use crate::test_support::TempDir;

    #[test]
    fn files_are_hashed_and_links_are_read_not_followed() {
        let dir = TempDir::new("sweep-read");
        let root = dir.path();
        fs::create_dir_all(root.join("etc/x")).unwrap();
        fs::write(root.join("etc/x/a"), "abc").unwrap();
        fs::set_permissions(root.join("etc/x/a"), fs::Permissions::from_mode(0o4755)).unwrap();
        symlink("/etc/x/a", root.join("etc/x/link")).unwrap();
        assert_eq!(
            look(root, "etc/x/a"),
            Found::File {
                sha256: Sha256::digest(b"abc"),
                mode: 0o4755,
                size: 3,
                head: b"abc".to_vec()
            }
        );
        assert_eq!(look(root, "etc/x/link"), Found::Link("/etc/x/a".into()));
        assert_eq!(look(root, "etc/x"), Found::Other);
        assert!(matches!(look(root, "etc/missing"), Found::Unreadable(_)));
    }

    #[test]
    fn walks_stay_inside_and_links_resolve_inside_the_root() {
        let dir = TempDir::new("sweep-walk");
        let root = dir.path();
        fs::create_dir_all(root.join("usr/lib/systemd/system")).unwrap();
        fs::create_dir_all(root.join("etc/systemd/system/multi-user.target.wants")).unwrap();
        fs::write(root.join("usr/lib/systemd/system/a.service"), "[Unit]").unwrap();
        symlink(
            "/usr/lib/systemd/system/a.service",
            root.join("etc/systemd/system/multi-user.target.wants/a.service"),
        )
        .unwrap();
        symlink(
            "../../../usr/lib/systemd",
            root.join("etc/systemd/system/linked"),
        )
        .unwrap();
        symlink(
            "../../../../../../../etc/passwd",
            root.join("etc/systemd/system/escape"),
        )
        .unwrap();
        symlink("loop", root.join("etc/systemd/system/loop")).unwrap();

        let listing = entries(root, "etc/systemd/system/");
        assert!(!listing.truncated && listing.unreadable.is_empty());
        assert_eq!(
            listing.files,
            [
                "etc/systemd/system/escape",
                "etc/systemd/system/linked",
                "etc/systemd/system/loop",
                "etc/systemd/system/multi-user.target.wants/a.service"
            ]
        );
        assert_eq!(
            resolve(
                root,
                "etc/systemd/system/multi-user.target.wants/a.service",
                "/usr/lib/systemd/system/a.service"
            )
            .as_deref(),
            Some("usr/lib/systemd/system/a.service")
        );
        assert_eq!(
            resolve(
                root,
                "etc/systemd/system/escape",
                "../../../../../../../etc/passwd"
            ),
            None
        );
        assert_eq!(resolve(root, "etc/systemd/system/loop", "loop"), None);
        symlink("usr/lib", root.join("lib")).unwrap();
        assert_eq!(
            super::canonical(root, "lib/systemd/system/a.service").as_deref(),
            Some("usr/lib/systemd/system/a.service")
        );
        assert_eq!(super::canonical(root, "etc/systemd/system/escape/x"), None);
    }
}
