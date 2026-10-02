//! Looking at installed files without ever following a link into them or
//! running them: a file is opened with `O_NOFOLLOW`, hashed in full and kept
//! only up to the text review limit; a link is read, never opened.
//!
//! Paths are relative to a root (`/` on a real system, a fixture in tests),
//! so the package index (keyed by paths relative to `/`) applies directly.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
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

/// Why a file past the hash limit was not read.
pub const TOO_LARGE: &str = "larger than the hash limit";

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
        return Found::Unreadable(TOO_LARGE.into());
    }
    match read_file(&path, &metadata) {
        Ok(found) => found,
        Err(error) => Found::Unreadable(error.to_string()),
    }
}

/// What a pinned walk found at a path.
pub enum Public {
    /// A regular file, opened.
    File(File),
    /// A link (anyone who can reach a link can read it), with its text.
    Link(String),
    /// A directory, opened.
    Directory(File),
    /// A special file.
    Other,
}

/// Whose view a pinned walk takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum View {
    /// What anyone may see: every directory on the way may be entered by
    /// anyone and a file may be read by anyone. The view the root collector
    /// takes of a path somebody else chose.
    Everyone,
    /// What the reader may see, for a path the reader found itself.
    Pinned,
    /// What the reader may see for as long as the way is the root owner's
    /// alone, and what anyone may see past the first directory somebody
    /// else owns or may write: the view of a path that root named but that
    /// leads through somebody else's directory, who decides what is there.
    Trusted,
}

/// What a pinned walk reached, and the path it really took.
pub struct Seen {
    /// `rel` with every link on the way resolved (`bin/sh` is `usr/bin/sh`
    /// on Arch); the last component is kept as is.
    pub path: String,
    pub what: Public,
    /// Every directory on the way is the root owner's and nobody else may
    /// write it: what is at this path is there by the root owner's doing.
    pub kept: bool,
}

/// What is at `rel` under `root`. `None` for a path that is not there or
/// that `view` does not show, and for `/proc` and `/sys`, where the kernel
/// decides per reader.
///
/// Each directory is opened, checked as opened, and the next name looked
/// up inside that open directory, so nothing swapped in while this runs
/// (a directory for a link elsewhere) is ever followed. A link on the way
/// is followed, by its text and from the top, only where the owner of the
/// root alone could have put it (`/bin`, `/usr/sbin`): it is theirs, and
/// nobody else may write the directory it sits in or any above that.
pub fn seen(root: &Path, rel: &str, view: View) -> Option<Seen> {
    let open = |path: &Path| {
        OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW | O_NONBLOCK)
            .open(path)
    };
    let allowed = |metadata: &fs::Metadata, bit: u32, kept: bool| match view {
        View::Pinned => true,
        View::Trusted if kept => true,
        View::Trusted | View::Everyone => metadata.mode() & bit != 0,
    };
    let same = |left: &fs::Metadata, right: &fs::Metadata| {
        (left.dev(), left.ino()) == (right.dev(), right.ino())
    };
    let inside = |directory: &File, name: &str| {
        PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd())).join(name)
    };
    let top = open(root).ok()?.metadata().ok()?;
    let owner = top.uid();
    let kept = |metadata: &fs::Metadata| metadata.uid() == owner && metadata.mode() & 0o022 == 0;

    let mut names: Vec<String> = rel.split('/').map(str::to_string).collect();
    'walk: for _ in 0..=MAX_HOPS {
        if matches!(names.first().map(String::as_str), Some("proc" | "sys")) {
            return None;
        }
        let mut directory = open(root).ok()?;
        let mut kept_here = kept(&top);
        for (index, name) in names.iter().enumerate() {
            if matches!(name.as_str(), "" | "." | "..") {
                return None;
            }
            let last = index + 1 == names.len();
            let here = inside(&directory, name);
            let found = fs::symlink_metadata(&here).ok()?;
            if found.file_type().is_symlink() {
                let target = fs::read_link(&here).ok()?;
                let target = target.to_str()?;
                if last {
                    return Some(Seen {
                        path: names.join("/"),
                        what: Public::Link(target.to_string()),
                        kept: kept_here,
                    });
                }
                if !(kept_here && found.uid() == owner) {
                    return None;
                }
                let base = if target.starts_with('/') {
                    PathBuf::new()
                } else {
                    PathBuf::from(names[..index].join("/"))
                };
                let resolved = normalize(&base.join(target.trim_start_matches('/')))?;
                let rest = names.split_off(index + 1);
                names = resolved
                    .split('/')
                    .filter(|part| !part.is_empty())
                    .map(str::to_string)
                    .chain(rest)
                    .collect();
                continue 'walk;
            }
            if last && !found.is_file() && !found.is_dir() {
                return Some(Seen {
                    path: names.join("/"),
                    what: Public::Other,
                    kept: kept_here,
                });
            }
            let next = open(&here).ok()?;
            let opened = next.metadata().ok()?;
            if !same(&opened, &found) {
                return None;
            }
            if last {
                let what = if opened.is_file() && allowed(&opened, 0o004, kept_here) {
                    Public::File(next)
                } else if opened.is_dir() && allowed(&opened, 0o001, kept_here) {
                    Public::Directory(next)
                } else {
                    return None;
                };
                return Some(Seen {
                    path: names.join("/"),
                    what,
                    kept: kept_here,
                });
            }
            if !(opened.is_dir() && allowed(&opened, 0o001, kept_here)) {
                return None;
            }
            // Under a directory of somebody else's, nothing is the root
            // owner's alone: it can be moved there, and moved away.
            kept_here = kept_here && kept(&opened);
            directory = next;
        }
        return None;
    }
    None
}

/// What everyone may see at `rel` (see `View::Everyone`).
pub fn public(root: &Path, rel: &str) -> Option<Public> {
    seen(root, rel, View::Everyone).map(|seen| seen.what)
}

/// `look` through a pinned walk: `None` where `seen` shows nothing.
pub fn look_as(root: &Path, rel: &str, view: View) -> Option<Found> {
    Some(match seen(root, rel, view)?.what {
        Public::Link(target) => Found::Link(target),
        Public::Directory(_) | Public::Other => Found::Other,
        Public::File(file) => match file.metadata() {
            Ok(metadata) if metadata.len() > MAX_HASHED_FILE_SIZE => {
                Found::Unreadable(TOO_LARGE.into())
            }
            Ok(metadata) => {
                hash(file, &metadata).unwrap_or_else(|error| Found::Unreadable(error.to_string()))
            }
            Err(error) => Found::Unreadable(error.to_string()),
        },
    })
}

fn read_file(path: &Path, expected: &fs::Metadata) -> io::Result<Found> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.ino() != expected.ino() || opened.dev() != expected.dev() {
        return Err(io::Error::other("changed while it was being read"));
    }
    hash(file, &opened)
}

/// Hashes an open regular file, keeping its first bytes.
fn hash(mut file: File, opened: &fs::Metadata) -> io::Result<Found> {
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
    /// Entries whose name is not UTF-8, as far as it can be shown: a
    /// shell, udev or pacman reads them all the same, and the sweep cannot.
    pub unnamed: Vec<String>,
}

/// Every non-directory entry under directory `rel` (relative to `root`),
/// without entering linked directories.
pub fn entries(root: &Path, rel: &str) -> Listing {
    let mut files = Vec::new();
    let mut unreadable = Vec::new();
    let mut unnamed = Vec::new();
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
                unnamed.push(format!(
                    "{directory}/{}",
                    entry.file_name().to_string_lossy()
                ));
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
    unnamed.sort();
    Listing {
        files,
        truncated,
        unreadable,
        unnamed,
    }
}

/// Where the link at `rel` with text `target` finally points, relative to
/// `root`, following further links; `None` when it leaves `root`, loops or
/// points at nothing.
#[cfg(test)]
pub fn resolve(root: &Path, rel: &str, target: &str) -> Option<String> {
    resolve_where(rel, target, &|hop| plain_hop(root, hop))
}

/// What a hop of a link chain is, for `resolve_where`: nothing to go on
/// (`None`), the end of the chain (`Some(None)`), or a further link with
/// its text.
pub type Hop = Option<Option<String>>;

/// A hop as `symlink_metadata` and `read_link` see it.
pub fn plain_hop(root: &Path, hop: &str) -> Hop {
    match fs::symlink_metadata(root.join(hop)) {
        Ok(metadata) if metadata.file_type().is_symlink() => Some(Some(
            fs::read_link(root.join(hop)).ok()?.to_str()?.to_string(),
        )),
        Ok(_) => Some(None),
        Err(_) => None,
    }
}

/// A hop as anyone may see it (see `public`).
pub fn public_hop(root: &Path, hop: &str) -> Hop {
    Some(match public(root, hop)? {
        Public::Link(target) => Some(target),
        Public::File(_) | Public::Directory(_) | Public::Other => None,
    })
}

/// `resolve`, with the caller looking at each hop: a chain through a hop
/// it does not show leads nowhere.
pub fn resolve_where(rel: &str, target: &str, look: &dyn Fn(&str) -> Hop) -> Option<String> {
    let mut current = rel.to_string();
    let mut target = target.to_string();
    for _ in 0..MAX_HOPS {
        let base = if target.starts_with('/') {
            PathBuf::new()
        } else {
            Path::new(&current).parent()?.to_path_buf()
        };
        let next = normalize(&base.join(target.trim_start_matches('/')))?;
        match look(&next)? {
            Some(further) => {
                target = further;
                current = next;
            }
            None => return Some(next),
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
    fn a_path_someone_else_chose_is_seen_only_as_everyone_may_see_it() {
        use super::{Public, View, look_as, public, public_hop, resolve_where, seen};
        let look_public = |root, path| look_as(root, path, View::Everyone);
        let dir = TempDir::new("sweep-public");
        let root = dir.path();
        let mode = |path: &str, mode: u32| {
            fs::set_permissions(root.join(path), fs::Permissions::from_mode(mode)).unwrap();
        };
        fs::create_dir_all(root.join("open/sub")).unwrap();
        fs::create_dir_all(root.join("closed")).unwrap();
        fs::create_dir_all(root.join("usr/bin")).unwrap();
        fs::write(root.join("open/a"), "abc").unwrap();
        fs::write(root.join("open/secret"), "pin").unwrap();
        fs::write(root.join("closed/a"), "abc").unwrap();
        fs::write(root.join("usr/bin/tool"), "tool").unwrap();
        symlink("open", root.join("via")).unwrap();
        fs::create_dir_all(root.join("shared")).unwrap();
        symlink("../open", root.join("shared/via")).unwrap();
        mode("shared", 0o777);
        symlink("/closed/a", root.join("open/link")).unwrap();
        mode("open/secret", 0o600);
        mode("closed", 0o700);

        assert!(matches!(public(root, "open/a"), Some(Public::File(_))));
        assert!(matches!(
            public(root, "open/sub"),
            Some(Public::Directory(_))
        ));
        assert!(
            matches!(public(root, "open/link"), Some(Public::Link(target)) if target == "/closed/a")
        );
        assert_eq!(
            look_public(root, "open/a"),
            Some(Found::File {
                sha256: Sha256::digest(b"abc"),
                mode: 0o644,
                size: 3,
                head: b"abc".to_vec()
            })
        );
        // Not for everyone, not there, or not what it says: all the same.
        for path in [
            "open/secret",
            "closed/a",
            "closed/missing",
            "open/missing",
            "shared/via/a",
            "open/../open/a",
            "proc/1/cwd",
            "sys/x",
            "",
        ] {
            assert!(public(root, path).is_none(), "{path:?}");
            assert_eq!(look_public(root, path), None, "{path:?}");
        }

        // A link on the way is followed where nobody else could have put
        // it, and the path that was taken is told.
        let via = seen(root, "via/a", View::Everyone).unwrap();
        assert_eq!(via.path, "open/a");
        assert!(matches!(via.what, Public::File(_)));
        assert!(seen(root, "via/secret", View::Everyone).is_none());
        // The reader's own view is pinned the same way, without the rest.
        for path in ["open/secret", "closed/a", "via/secret"] {
            assert!(
                matches!(look_as(root, path, View::Pinned), Some(Found::File { .. })),
                "{path:?}"
            );
        }
        // Root's own naming is trusted up to somebody else's directory.
        fs::create_dir_all(root.join("shared/closed")).unwrap();
        fs::write(root.join("shared/closed/a"), "abc").unwrap();
        fs::write(root.join("shared/a"), "abc").unwrap();
        mode("shared/closed", 0o700);
        for (path, there) in [
            ("closed/a", true),
            ("open/secret", true),
            ("shared/a", true),
            ("shared/closed/a", false),
        ] {
            assert_eq!(
                look_as(root, path, View::Trusted).is_some(),
                there,
                "{path:?}"
            );
        }
        for path in ["shared/via/a", "closed/missing", "open/../open/a"] {
            assert_eq!(look_as(root, path, View::Pinned), None, "{path:?}");
        }

        // A chain is followed only through hops anyone may see.
        symlink("/open/a", root.join("open/hop")).unwrap();
        symlink("/closed/hop", root.join("open/hidden")).unwrap();
        symlink("/open/a", root.join("closed/hop")).unwrap();
        let hop = |hop: &str| public_hop(root, hop);
        assert_eq!(
            resolve_where("start", "/open/hop", &hop).as_deref(),
            Some("open/a")
        );
        assert_eq!(resolve_where("start", "/open/hidden", &hop), None);
        assert_eq!(
            resolve(root, "start", "/open/hidden").as_deref(),
            Some("open/a")
        );
    }

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
