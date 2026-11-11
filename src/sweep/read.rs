//! Looking at installed files without ever following a link into them or
//! running them: a file is opened with `O_NOFOLLOW`, hashed in full and kept
//! only up to the text review limit; a link is read, never opened.
//!
//! Paths are relative to a root (`/` on a real system, a fixture in tests),
//! so the package index (keyed by paths relative to `/`) applies directly.

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use crate::files::{O_DIRECTORY, O_NOFOLLOW, O_NONBLOCK};
use crate::scan::{MAX_HASHED_FILE_SIZE, MAX_TEXT_FILE_SIZE};
use crate::sha256::{Digest, Sha256};

/// Directories deeper than this under a location are not looked into.
const MAX_DEPTH: usize = 6;
/// Entries one location may hold before the rest is reported, not read.
pub(crate) const MAX_ENTRIES: usize = 20_000;
/// Links followed when resolving one.
pub(super) const MAX_HOPS: usize = 8;

/// Why a file past the hash limit was not read.
pub(super) const TOO_LARGE: &str = "larger than the hash limit";
/// Why a regular file the view may read was not: it would not open (see
/// `Public::Unopened`).
pub(super) const UNOPENED: &str = "there, and would not open";

/// What is at a path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Found {
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

/// A link's target, or a name, as text, a byte that is not UTF-8 written
/// `\xNN` and a backslash `\\`, so that no two read the same. An unreadable
/// link would keep the fingerprint it had before, so one moved to such a
/// target would never be told as changed. `link_path` undoes it.
pub(super) fn link_text(target: &Path) -> String {
    use std::os::unix::ffi::OsStrExt as _;

    let mut text = String::new();
    for chunk in target.as_os_str().as_bytes().utf8_chunks() {
        text.push_str(&chunk.valid().replace('\\', "\\\\"));
        for byte in chunk.invalid() {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            text.push_str("\\x");
            text.push(char::from(HEX[usize::from(byte >> 4)]));
            text.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    text
}

/// Looks at `rel` under `root` without following a final link.
pub(super) fn look(root: &Path, rel: &str) -> Found {
    let path = root.join(rel);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) => return Found::Unreadable(error.to_string()),
    };
    let kind = metadata.file_type();
    if kind.is_symlink() {
        return match fs::read_link(&path) {
            Ok(target) => Found::Link(link_text(&target)),
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
        // An open that does not wait fails so while its owner holds a lease
        // on the file (see `Public::Unopened`).
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            Found::Unreadable(UNOPENED.into())
        }
        Err(error) => Found::Unreadable(error.to_string()),
    }
}

/// What a pinned walk found at a path.
pub(crate) enum Public {
    /// A regular file, opened.
    File(File),
    /// A link (anyone who can reach a link can read it), with its target
    /// as the kernel keeps it, which need not be UTF-8.
    Link(PathBuf),
    /// A directory, opened.
    Directory(File),
    /// A special file.
    Other,
    /// A regular file `view` may read, that would not open: why. Its owner
    /// can make every open of it fail at once (a lease it holds, which an
    /// open without waiting breaks with `EWOULDBLOCK`) and let go of it
    /// for the server: it is there, and not shown as absent.
    Unopened(String),
    /// A part of the way the walk could not go past, though the view may,
    /// with why: `lstat` failed other than because nothing is there (a
    /// FUSE mount root may not enter, which an account can make over its
    /// own `~/.ssh`), a directory the view may enter would not open (NFS
    /// with `root_squash`), what was opened is not what was looked at (it
    /// was swapped meanwhile), or only its group may use it. The account,
    /// and the server as the account, may see past it. The path is the
    /// whole path walked, as for the other kinds.
    Refused(String),
}

/// Whose view a pinned walk takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum View {
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
    /// What the account with this user id may see by itself: a directory
    /// it may enter and a file it may read as their owner, or as anyone.
    /// The view the root collector takes of an account's own files (its
    /// keys, its units) when the results go to that account: it learns
    /// nothing it could not have read.
    Owner(u32),
}

impl View {
    /// Whether this view may use what `metadata` describes: read a file
    /// (`bit` 0o004) or enter a directory (0o001). `kept`: the way to it is
    /// the root owner's alone.
    fn allows(self, metadata: &fs::Metadata, bit: u32, kept: bool) -> bool {
        match self {
            Self::Pinned => true,
            Self::Trusted if kept => true,
            // As the kernel checks: the owner by the owner's bits alone,
            // anyone else by the bits for others. Group rights are left out:
            // who is in which group is not asked (see `group_may`).
            Self::Owner(uid) if metadata.uid() == uid => metadata.mode() & (bit << 6) != 0,
            Self::Trusted | Self::Everyone | Self::Owner(_) => metadata.mode() & bit != 0,
        }
    }

    /// Whether this view may list the directory `metadata` describes, by
    /// its owner's bits or the bits for others: one only its group may list
    /// is not listed, since who is in the group is not asked.
    pub(super) fn may_list(self, metadata: &fs::Metadata) -> bool {
        self.allows(metadata, 0o004, false)
    }

    /// Whether this view may use what `metadata` describes, or may as a
    /// member of its group (see `group_may`).
    fn may_use(self, metadata: &fs::Metadata, bit: u32, kept: bool) -> bool {
        self.allows(metadata, bit, kept) || self.group_may(metadata, bit)
    }

    /// Whether, as an account, its group bits alone may allow what `allows`
    /// refused: the account may be in that group.
    fn group_may(self, metadata: &fs::Metadata, bit: u32) -> bool {
        matches!(self, Self::Owner(uid) if metadata.uid() != uid)
            && metadata.mode() & (bit << 3) != 0
    }
}

/// What a pinned walk reached, and the path it really took.
pub(crate) struct Seen {
    /// `rel` with every link on the way resolved (`bin/sh` is `usr/bin/sh`
    /// on Arch); the last component is kept as is.
    pub(crate) path: String,
    pub(crate) what: Public,
    /// Every directory on the way is the root owner's and nobody else may
    /// write it: what is at this path is there by the root owner's doing.
    pub(crate) kept: bool,
}

/// Opens what is at `path` itself (no link followed, no waiting on a
/// pipe), as a directory only when it is expected to be one.
fn open_entry(path: &Path, directory: bool) -> io::Result<File> {
    let flags = O_NOFOLLOW | O_NONBLOCK | if directory { O_DIRECTORY } else { 0 };
    OpenOptions::new().read(true).custom_flags(flags).open(path)
}

impl Seen {
    /// What a walk found at the part of the way `names` ends with.
    fn at(names: &[String], what: Public, kept: bool) -> Self {
        Self {
            path: names.join("/"),
            what,
            kept,
        }
    }
}

/// Why a part of the way is told as not looked at: it was swapped for
/// something else between the look and the open.
const CHANGED: &str = "changed while it was looked at";
/// Why a file or directory is told as not read: its group may use it, and
/// who is in which group is not asked.
const BY_GROUP: &str = "its group may use it, and who is in the group is not asked";

/// Whether `error` says nothing is at a path: the walk shows nothing there.
fn is_absent(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
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
pub(crate) fn seen(root: &Path, rel: &str, view: View) -> Option<Seen> {
    seen_or_why(root, rel, view).ok()
}

/// Why `seen` shows nothing at a path.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Unseen {
    /// Nothing is there, or nothing the view shows.
    Nothing,
    /// A part on the way is a link that is not followed, or no directory.
    Through,
}

/// `seen`, saying why it shows nothing.
pub(crate) fn seen_or_why(root: &Path, rel: &str, view: View) -> Result<Seen, Unseen> {
    let open = |path: &Path| open_entry(path, false);
    let inside = |directory: &File, name: &str| {
        PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd())).join(name)
    };
    let top = open(root)
        .and_then(|top| top.metadata())
        .map_err(|_| Unseen::Nothing)?;
    let owner = top.uid();
    let kept = |metadata: &fs::Metadata| metadata.uid() == owner && metadata.mode() & 0o022 == 0;

    let mut names: Vec<String> = rel.split('/').map(str::to_string).collect();
    'walk: for _ in 0..=MAX_HOPS {
        if matches!(names.first().map(String::as_str), Some("proc" | "sys")) {
            return Err(Unseen::Nothing);
        }
        let mut directory = open(root).map_err(|_| Unseen::Nothing)?;
        let mut kept_here = kept(&top);
        for (index, name) in names.iter().enumerate() {
            if matches!(name.as_str(), "" | "." | "..") {
                return Err(Unseen::Nothing);
            }
            let last = index + 1 == names.len();
            let here = inside(&directory, name);
            let found = match fs::symlink_metadata(&here) {
                Ok(found) => found,
                Err(error) if is_absent(&error) => return Err(Unseen::Nothing),
                Err(error) => {
                    return Ok(Seen::at(
                        &names,
                        Public::Refused(error.to_string()),
                        kept_here,
                    ));
                }
            };
            if found.file_type().is_symlink() {
                // It was a link a moment ago: one that cannot be read now
                // was swapped meanwhile, which is not nothing there.
                let target = fs::read_link(&here).map_err(|_| Unseen::Through)?;
                if last {
                    return Ok(Seen::at(&names, Public::Link(target), kept_here));
                }
                // A name that is not UTF-8 is not followed: its escaped text
                // (`link_text`) could name another file an account made.
                let target = target.to_str().ok_or(Unseen::Through)?;
                if !(kept_here && found.uid() == owner) || goes_up_after_a_name(target) {
                    return Err(Unseen::Through);
                }
                names = through_link(&names, index, target).ok_or(Unseen::Nothing)?;
                continue 'walk;
            }
            if last && !found.is_file() && !found.is_dir() {
                return Ok(Seen::at(&names, Public::Other, kept_here));
            }
            // Only a directory is passed through, and it is opened as
            // one: opening a device or a pipe on the way can itself do
            // something, whatever is checked afterwards.
            if !last && !found.is_dir() {
                return Err(Unseen::Through);
            }
            let (next, opened) = match open_part(&here, &found, last, view, kept_here) {
                Part::Open(next, opened) => (next, opened),
                Part::Shows(what) => return Ok(Seen::at(&names, what, kept_here)),
                Part::Unseen(why) => return Err(why),
            };
            if last {
                let what = if opened.is_file() {
                    Public::File(next)
                } else {
                    Public::Directory(next)
                };
                return Ok(Seen::at(&names, what, kept_here));
            }
            // Under a directory of somebody else's, nothing is the root
            // owner's alone: it can be moved there, and moved away.
            kept_here = kept_here && kept(&opened);
            directory = next;
        }
        return Err(Unseen::Nothing);
    }
    Err(Unseen::Nothing)
}

/// What opening one part of a walk in `seen_or_why` gave.
enum Part {
    /// The part, opened, and its metadata as opened: the walk goes on.
    Open(File, fs::Metadata),
    /// The walk ends at the part, which shows as this.
    Shows(Public),
    /// The walk ends at the part, which shows nothing.
    Unseen(Unseen),
}

/// Opens the part at `here`, which `found` is the `lstat` of and which is
/// a file or directory, as `view` may use it; `last` where it is the end
/// of the path.
fn open_part(here: &Path, found: &fs::Metadata, last: bool, view: View, kept_here: bool) -> Part {
    // What may be read of a file, entered of a directory.
    let bit = if found.is_dir() { 0o001 } else { 0o004 };
    let next = match open_entry(here, found.is_dir()) {
        Ok(next) => next,
        Err(error) if last && found.is_file() && view.may_use(found, bit, kept_here) => {
            return Part::Shows(Public::Unopened(error.to_string()));
        }
        // A directory the view may enter that root may not open:
        // something keeps root out (NFS with `root_squash`).
        Err(error) if found.is_dir() && view.may_use(found, bit, kept_here) => {
            return Part::Shows(Public::Refused(error.to_string()));
        }
        Err(_) => return Part::Unseen(Unseen::Nothing),
    };
    // Swapped for something else since it was looked at: told, not
    // taken for nothing there, or swapping it in a loop would hide
    // what the server reads.
    let opened = match next.metadata() {
        Ok(opened) if (opened.dev(), opened.ino()) == (found.dev(), found.ino()) => opened,
        _ => return Part::Shows(Public::Refused(CHANGED.into())),
    };
    if !view.allows(&opened, bit, kept_here) {
        // Who is in a group is not asked, so what its group may use
        // is told as not read rather than left out.
        if !view.group_may(&opened, bit) {
            return Part::Unseen(Unseen::Nothing);
        }
        let why = BY_GROUP.to_string();
        return Part::Shows(if last && opened.is_file() {
            Public::Unopened(why)
        } else {
            Public::Refused(why)
        });
    }
    Part::Open(next, opened)
}

/// `look` through a pinned walk: `None` where `seen` shows nothing.
pub(super) fn look_as(root: &Path, rel: &str, view: View) -> Option<Found> {
    seen(root, rel, view).map(look_pinned)
}

/// `names` with the link at `index` replaced by its `target`, from the
/// link's directory or from the top; `None` where it leads above the top.
fn through_link(names: &[String], index: usize, target: &str) -> Option<Vec<String>> {
    let base = if target.starts_with('/') {
        PathBuf::new()
    } else {
        PathBuf::from(names[..index].join("/"))
    };
    let resolved = normalize(&base.join(target.trim_start_matches('/')))?;
    Some(
        resolved
            .split('/')
            .filter(|part| !part.is_empty())
            .map(str::to_string)
            .chain(names[index + 1..].iter().cloned())
            .collect(),
    )
}

/// `look` at what a pinned walk reached.
pub(super) fn look_pinned(seen: Seen) -> Found {
    look_pinned_within(seen, MAX_HASHED_FILE_SIZE)
}

/// `look_pinned`, for a file of at most `most` bytes: a larger one is
/// `TOO_LARGE`, and is not read.
pub(super) fn look_pinned_within(seen: Seen, most: u64) -> Found {
    match seen.what {
        Public::Link(target) => Found::Link(link_text(&target)),
        Public::Directory(_) | Public::Other => Found::Other,
        Public::Unopened(_) => Found::Unreadable(UNOPENED.into()),
        Public::Refused(why) => Found::Unreadable(why),
        Public::File(file) => look_open(file, most),
    }
}

/// What the regular file `file`, opened to be read, holds when it is at
/// most `most` bytes: hashed, or why not.
pub(super) fn look_open(file: File, most: u64) -> Found {
    match file.metadata() {
        Ok(metadata) if metadata.len() > most => Found::Unreadable(TOO_LARGE.into()),
        Ok(metadata) => {
            hash(file, &metadata, most).unwrap_or_else(|error| Found::Unreadable(error.to_string()))
        }
        Err(error) => Found::Unreadable(error.to_string()),
    }
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
    hash(file, &opened, MAX_HASHED_FILE_SIZE)
}

/// Hashes an open regular file of at most `most` bytes, keeping its first
/// bytes.
fn hash(mut file: File, opened: &fs::Metadata, most: u64) -> io::Result<Found> {
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
        // One that grows past the limit while it is read is too large,
        // as one that was already: a key file grown that way is told.
        if size > most {
            return Ok(Found::Unreadable(TOO_LARGE.into()));
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
pub(super) fn has_extension(name: &str, extension: &str) -> bool {
    Path::new(name)
        .extension()
        .is_some_and(|found| found.eq_ignore_ascii_case(extension))
}

/// What a directory walk found.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Listing {
    /// Every non-directory entry, sorted.
    pub(super) files: Vec<String>,
    /// The walk stopped at a limit.
    pub(super) truncated: bool,
    /// Directories that exist but could not be listed (only root can).
    pub(super) unreadable: Vec<String>,
    /// Entries whose name is not UTF-8, as far as it can be shown: a
    /// shell, udev or pacman reads them all the same, and the sweep cannot.
    pub(super) unnamed: Vec<String>,
}

/// Every non-directory entry under directory `rel` (relative to `root`),
/// without entering linked directories.
pub(super) fn entries(root: &Path, rel: &str) -> Listing {
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

/// What a pattern matched.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Matches {
    /// The paths that match, sorted.
    pub(crate) files: Vec<String>,
    /// More matched than are kept.
    pub(crate) truncated: bool,
    /// Entries whose name is not UTF-8 where a match was looked for.
    pub(super) unnamed: Vec<String>,
    /// Directories that exist but could not be listed.
    pub(crate) unreadable: Vec<String>,
    /// Directories that were listed to look for a match.
    pub(super) listed: Vec<String>,
}

/// The most paths one pattern may match.
const MAX_MATCHES: usize = 500;

/// Every path under `root` that `pattern` matches: in each name of it, `*`
/// stands for any run of characters. Directories are listed only where a
/// name has one; linked directories are not entered.
pub(crate) fn matching(root: &Path, pattern: &str) -> Matches {
    let mut found = Matches::default();
    let mut bases = vec![String::new()];
    let names: Vec<&str> = pattern.split('/').collect();
    for (index, name) in names.iter().enumerate() {
        let last = index + 1 == names.len();
        let mut next = Vec::new();
        for base in bases {
            let under = |name: &str| {
                if base.is_empty() {
                    name.to_string()
                } else {
                    format!("{base}/{name}")
                }
            };
            if !name.contains('*') {
                next.push(under(name));
                continue;
            }
            let listing = match fs::read_dir(root.join(&base)) {
                Ok(listing) => listing,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => {
                    found.unreadable.push(base.clone());
                    continue;
                }
            };
            found.listed.push(base.clone());
            for entry in listing.filter_map(Result::ok) {
                let Some(entry_name) = entry.file_name().to_str().map(str::to_string) else {
                    found
                        .unnamed
                        .push(under(&entry.file_name().to_string_lossy()));
                    continue;
                };
                let directory = entry.file_type().is_ok_and(|kind| kind.is_dir());
                if crate::autorun::name_matches(name, &entry_name) && last != directory {
                    next.push(under(&entry_name));
                }
            }
        }
        if next.len() > MAX_MATCHES {
            next.sort();
            next.truncate(MAX_MATCHES);
            found.truncated = true;
        }
        bases = next;
    }
    bases.retain(|path| fs::symlink_metadata(root.join(path)).is_ok());
    bases.sort();
    found.unnamed.sort();
    found.files = bases;
    found
}

/// Where the link at `rel` with text `target` finally points, relative to
/// `root`, following further links; `None` when it leaves `root`, loops or
/// points at nothing.
#[cfg(test)]
fn resolve(root: &Path, rel: &str, target: &str) -> Option<String> {
    resolve_where(rel, target, &|hop| plain_hop(root, hop))
}

/// What one hop of a link chain is, for `resolve_where`. Only what kind
/// of file it is: a hop is opened (`hop_as`) but never read, since a walk
/// may pass the same large file many times (`a/f/../f/../…`).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Hop {
    /// Nothing to go on: there is nothing there, or it is not shown.
    Hidden,
    /// A further link, with its text as `link_text` writes it.
    Link(String),
    /// A directory: the end of a chain, or a part a `..` goes up from.
    Directory,
    /// Anything else: the end of a chain, and no part a `..` goes up from
    /// (the kernel refuses `file/..`).
    Other,
    /// What the view could not look at, though something may be there (see
    /// `Public::Refused`): a chain through it is not followed to its end.
    Refused,
}

/// A hop as `symlink_metadata` and `read_link` see it.
pub(super) fn plain_hop(root: &Path, hop: &str) -> Hop {
    match fs::symlink_metadata(root.join(hop)) {
        Ok(metadata) if metadata.file_type().is_symlink() => match fs::read_link(root.join(hop)) {
            Ok(target) => Hop::Link(link_text(&target)),
            Err(_) => Hop::Hidden,
        },
        Ok(metadata) if metadata.is_dir() => Hop::Directory,
        Ok(_) => Hop::Other,
        Err(_) => Hop::Hidden,
    }
}

/// A hop as `view` may see it (see `seen`).
pub(super) fn hop_as(root: &Path, hop: &str, view: View) -> Hop {
    seen(root, hop, view).map_or(Hop::Hidden, |seen| hop_of(seen.what))
}

/// The hop `what` is.
fn hop_of(what: Public) -> Hop {
    match what {
        Public::Link(target) => Hop::Link(link_text(&target)),
        Public::Directory(_) => Hop::Directory,
        Public::File(_) | Public::Other | Public::Unopened(_) => Hop::Other,
        Public::Refused(_) => Hop::Refused,
    }
}

/// A hop of a path walked part by part (`resolve_path`), as `view` may
/// see it: every part before it was just seen as a directory, so one that
/// is now a link or no directory was swapped meanwhile, and is told
/// (`Hop::Refused`) rather than taken for nothing there.
pub(super) fn hop_below(root: &Path, hop: &str, view: View) -> Hop {
    match seen_or_why(root, hop, view) {
        Ok(seen) => hop_of(seen.what),
        Err(Unseen::Through) => Hop::Refused,
        Err(Unseen::Nothing) => Hop::Hidden,
    }
}

/// A hop as anyone may see it (see `View::Everyone`).
pub(super) fn public_hop(root: &Path, hop: &str) -> Hop {
    hop_as(root, hop, View::Everyone)
}

/// `resolve`, with the caller looking at each hop: a chain through a hop
/// it does not show leads nowhere.
pub(super) fn resolve_where(rel: &str, target: &str, look: &dyn Fn(&str) -> Hop) -> Option<String> {
    walk_links(rel, target, look).ok().flatten()
}

/// Whether the chain of links from `rel` was not followed to its end (see
/// `walk_links`): where it ends was not looked at, which is not the same
/// as it leading nowhere.
pub(super) fn chain_too_long(rel: &str, target: &str, look: &dyn Fn(&str) -> Hop) -> bool {
    walk_links(rel, target, look).is_err()
}

/// `resolve_where`; `Err` when the chain was not followed to its end: it
/// is longer than `MAX_HOPS`, a name on it is not UTF-8, or following it
/// looks at more than `MAX_LOOKED_PARTS`.
pub(super) fn walk_links(
    rel: &str,
    target: &str,
    look: &dyn Fn(&str) -> Hop,
) -> Result<Option<String>, ()> {
    Walk {
        look,
        left: MAX_LOOKED_PARTS,
    }
    .from(rel, target)
}

/// Where `rel` leads with every link on the way followed, the one at its
/// end too, as the kernel follows them and as `look` shows each part:
/// `Err` where more than `MAX_HOPS` links or `MAX_LOOKED_PARTS` named parts
/// are walked, a link's text is not UTF-8, or the way goes through `/proc`
/// or `/sys`; `None` where it leads nowhere.
/// Each part is looked at by its whole path, so it is for short paths (a
/// key file in a home).
pub(super) fn resolve_path(rel: &str, look: &dyn Fn(&str) -> Hop) -> Result<Option<String>, ()> {
    Walk {
        look,
        left: MAX_LOOKED_PARTS,
    }
    .path(rel)
}

/// The parts of the paths one chain of links may look at, in all: each
/// `..` after a link follows that link's own chain (`Walk::physical`), so
/// without one budget for the whole walk, links whose targets go back
/// through each other (`L1` to `L2/../L2/../…`) cost about (number of `..`)
/// to the power of the depth. A look is counted by its parts, since root's
/// public view opens each of them (`public_hop`): a target of 4 KiB names
/// a path some 2,000 parts deep. It also bounds how deep `from` and
/// `physical` call each other. The chains on a real system take at most
/// nine looks and 57 parts (measured over the 58,000 links of one Arch
/// system); 256 is arbitrary above that. `resolve_path` counts one for
/// each named part it walks, though the look at a path `d` parts deep
/// opens `d` parts: its walk opens at most 256 * 257 / 2 (about 33,000)
/// parts in all, some 200 ms.
const MAX_LOOKED_PARTS: usize = 256;

/// One walk along a chain of links, with what it may still look at.
struct Walk<'a> {
    look: &'a dyn Fn(&str) -> Hop,
    left: usize,
}

impl Walk<'_> {
    /// `look`, while the budget lasts.
    fn look(&mut self, path: &str) -> Result<Hop, ()> {
        let parts = path.split('/').count();
        self.left = self.left.checked_sub(parts).ok_or(())?;
        Ok((self.look)(path))
    }

    /// `resolve_path`, as the kernel walks a path: each part in turn, from
    /// where the walk physically is. A link's target takes its place among
    /// the parts still to walk, from the link's directory or from the root,
    /// so `..` goes up from where the link led and the way is not walked
    /// again from its start after each link. A named part costs one of the
    /// budget (see `MAX_LOOKED_PARTS` for what that bounds).
    fn path(&mut self, rel: &str) -> Result<Option<String>, ()> {
        let mut at: Vec<String> = Vec::new();
        let mut directory = true;
        let mut links = 0;
        let mut parts: VecDeque<String> = rel.split('/').map(str::to_string).collect();
        while let Some(part) = parts.pop_front() {
            // Past what is not a directory the kernel goes no further
            // (ENOTDIR), a trailing `/` included.
            if !directory {
                return Ok(None);
            }
            match part.as_str() {
                "" | "." => continue,
                ".." => {
                    at.pop();
                    continue;
                }
                _ => at.push(part),
            }
            self.left = self.left.checked_sub(1).ok_or(())?;
            match (self.look)(&at.join("/")) {
                Hop::Link(target) => {
                    links += 1;
                    let Some(target) = link_path(&target).filter(|_| links <= MAX_HOPS) else {
                        return Err(());
                    };
                    at.pop();
                    if target.starts_with('/') {
                        at.clear();
                    }
                    for part in target.split('/').rev() {
                        parts.push_front(part.to_string());
                    }
                }
                Hop::Directory => {}
                Hop::Other => directory = false,
                // The view shows nothing of `/proc` and `/sys`, whose files
                // are not files; the kernel follows `/proc/self/root` all the
                // same, and the server with it, so the way is not followed.
                Hop::Hidden if matches!(at.first().map(String::as_str), Some("proc" | "sys")) => {
                    return Err(());
                }
                Hop::Hidden => return Ok(None),
                Hop::Refused => return Err(()),
            }
        }
        Ok(Some(at.join("/")))
    }

    /// Where the link at `rel` with `target` leads.
    fn from(&mut self, rel: &str, target: &str) -> Result<Option<String>, ()> {
        let mut current = rel.to_string();
        let mut target = target.to_string();
        for _ in 0..MAX_HOPS {
            // The text is `link_text`'s. A name that is not UTF-8 cannot be
            // looked up by its text, which names some other file an account
            // could have made.
            let Some(path) = link_path(&target) else {
                return Err(());
            };
            let base = if path.starts_with('/') {
                PathBuf::new()
            } else {
                match Path::new(&current).parent() {
                    Some(parent) => parent.to_path_buf(),
                    None => return Ok(None),
                }
            };
            let joined = base.join(path.trim_start_matches('/'));
            let Some(next) = self.physical(&joined)? else {
                return Ok(None);
            };
            match self.look(&next)? {
                Hop::Link(further) => {
                    target = further;
                    current = next;
                }
                Hop::Directory | Hop::Other => return Ok(Some(next)),
                Hop::Hidden => return Ok(None),
                Hop::Refused => return Err(()),
            }
        }
        Err(())
    }

    /// `path` without `.` and `..`, as the kernel takes them: a `..` after
    /// a link goes up from where the link leads, not from its name (with
    /// `d` a link to `far/deep`, `d/../x` is `far/x`), and a `..` at the
    /// root stays there. `None` where a part before a `..` is not shown, or
    /// is not a directory: the kernel refuses `file/..`.
    fn physical(&mut self, path: &Path) -> Result<Option<String>, ()> {
        let mut parts: Vec<String> = Vec::new();
        for component in path.components() {
            match component {
                Component::Normal(part) => match part.to_str() {
                    Some(part) => parts.push(part.to_string()),
                    None => return Ok(None),
                },
                Component::ParentDir if parts.is_empty() => {}
                Component::ParentDir => {
                    let here = parts.join("/");
                    match self.look(&here)? {
                        Hop::Link(further) => {
                            let Some(real) = self.from(&here, &further)? else {
                                return Ok(None);
                            };
                            parts = real.split('/').map(str::to_string).collect();
                        }
                        Hop::Directory => {}
                        Hop::Other | Hop::Hidden => return Ok(None),
                        Hop::Refused => return Err(()),
                    }
                    parts.pop();
                }
                Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
            }
        }
        Ok(Some(parts.join("/")))
    }
}

/// The path a link's text (`link_text`) names, where it is UTF-8.
pub(crate) fn link_path(text: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(text.len());
    let mut rest = text.as_bytes();
    while let Some((&first, after)) = rest.split_first() {
        rest = after;
        if first != b'\\' {
            bytes.push(first);
            continue;
        }
        // Only a byte that is not UTF-8 is written `\xNN`, so a name with
        // one cannot be looked up by text.
        let [b'\\', after @ ..] = rest else {
            return None;
        };
        bytes.push(b'\\');
        rest = after;
    }
    String::from_utf8(bytes).ok()
}

/// `rel` with every directory link on the way resolved (`bin/sh` is
/// `usr/bin/sh` on Arch, where `/bin` links to `usr/bin`); the last
/// component is kept as is. `None` when it leaves `root`.
pub(super) fn canonical(root: &Path, rel: &str) -> Option<String> {
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

/// Whether a `..` follows a name in a link's `target` (`a/../x`). That
/// name may itself be a link, and the kernel goes up from where it leads,
/// not from its name, so such a target cannot be resolved by its text
/// (`normalize`).
pub(crate) fn goes_up_after_a_name(target: &str) -> bool {
    let mut named = false;
    Path::new(target)
        .components()
        .any(|component| match component {
            Component::Normal(_) => {
                named = true;
                false
            }
            Component::ParentDir => named,
            Component::CurDir | Component::RootDir | Component::Prefix(_) => false,
        })
}

/// `path` without `.` and `..`, refusing to climb above the root.
pub(crate) fn normalize(path: &Path) -> Option<String> {
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
    use std::fs::{self, File};
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::{
        Found, Hop, MAX_LOOKED_PARTS, Public, TOO_LARGE, View, chain_too_long, entries,
        goes_up_after_a_name, hash, hop_as, hop_below, look, look_as, matching, plain_hop,
        public_hop, resolve, resolve_path, resolve_where, seen,
    };
    use crate::sha256::Sha256;
    use crate::test_support::TempDir;

    /// What everyone may see at `rel` (see `View::Everyone`).
    fn public(root: &std::path::Path, rel: &str) -> Option<Public> {
        seen(root, rel, View::Everyone).map(|seen| seen.what)
    }

    #[test]
    fn a_path_someone_else_chose_is_seen_only_as_everyone_may_see_it() {
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
            matches!(public(root, "open/link"), Some(Public::Link(target)) if target == std::path::Path::new("/closed/a"))
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
    fn a_link_to_a_name_that_is_not_utf8_is_still_a_link() {
        use std::os::unix::ffi::OsStrExt as _;

        let dir = TempDir::new("sweep-link-bytes");
        let target = std::ffi::OsStr::from_bytes(b"/tmp/\xff/evil");
        symlink(target, dir.path().join("a")).unwrap();
        match look(dir.path(), "a") {
            Found::Link(text) => assert_eq!(text, "/tmp/\\xff/evil"),
            _ => panic!("not read as a link"),
        }
        // The root sweep's pinned walk reads it the same way.
        for view in [View::Pinned, View::Everyone] {
            assert_eq!(
                look_as(dir.path(), "a", view),
                Some(Found::Link("/tmp/\\xff/evil".into()))
            );
        }
        // It is not followed, not even to a file its escaped text names.
        symlink(std::ffi::OsStr::from_bytes(b"c\xff"), dir.path().join("b")).unwrap();
        fs::write(dir.path().join("c\\xff"), "").unwrap();
        assert_eq!(public_hop(dir.path(), "b"), Hop::Link("c\\xff".into()));
        assert_eq!(plain_hop(dir.path(), "b"), Hop::Link("c\\xff".into()));
        assert_eq!(
            resolve_where("x", "b", &|hop| public_hop(dir.path(), hop)),
            None
        );
        // Where it ends was not looked at, which is said.
        assert!(chain_too_long("x", "b", &|hop| public_hop(dir.path(), hop)));
        // Nor is the text `look` gives of it, which names the decoy.
        let Some(Found::Link(text)) = look_as(dir.path(), "b", View::Everyone) else {
            panic!("not read as a link");
        };
        assert_eq!(text, "c\\xff");
        assert_eq!(
            resolve_where("b", &text, &|hop| public_hop(dir.path(), hop)),
            None
        );
        assert_eq!(
            resolve_where("b", &text, &|hop| plain_hop(dir.path(), hop)),
            None
        );
        // A link to that decoy by its own name reads otherwise, and is
        // followed to it.
        symlink("c\\xff", dir.path().join("d")).unwrap();
        let Found::Link(text) = look(dir.path(), "d") else {
            panic!("not read as a link");
        };
        assert_eq!(text, "c\\\\xff");
        for hop in [plain_hop, public_hop] {
            assert_eq!(
                resolve_where("d", &text, &|next| hop(dir.path(), next)).as_deref(),
                Some("c\\xff")
            );
        }
    }

    #[test]
    fn a_parent_after_a_link_is_where_the_link_leads() {
        let dir = TempDir::new("sweep-link-parent");
        let root = dir.path();
        fs::create_dir_all(root.join("far/evil/deep")).unwrap();
        fs::create_dir_all(root.join("home/u/.config/hypr")).unwrap();
        fs::write(root.join("far/evil/decoy.conf"), "exec-once = /tmp/evil").unwrap();
        fs::write(root.join("home/u/decoy.conf"), "harmless").unwrap();
        symlink("../../far/evil/deep", root.join("home/u/d")).unwrap();
        // The kernel goes up from `far/evil/deep`, not from `home/u/d`.
        let target = "../d/../decoy.conf";
        for hop in [plain_hop, public_hop] {
            let look = |next: &str| hop(root, next);
            assert_eq!(
                resolve_where("home/u/.config/x.conf", target, &look).as_deref(),
                Some("far/evil/decoy.conf")
            );
            assert!(!chain_too_long("home/u/.config/x.conf", target, &look));
        }
        // A part before a `..` that is not shown does not let the chain go
        // on by its text, which here would reach a file anyone may see.
        fs::create_dir_all(root.join("hidden")).unwrap();
        fs::create_dir_all(root.join("pub")).unwrap();
        fs::write(root.join("pub/x"), "").unwrap();
        symlink("../far/evil/deep", root.join("hidden/d")).unwrap();
        fs::set_permissions(root.join("hidden"), fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            resolve_where("a", "hidden/d/../../pub/x", &|next| public_hop(root, next)),
            None
        );
        fs::set_permissions(root.join("hidden"), fs::Permissions::from_mode(0o755)).unwrap();
        // A `..` at the root stays there, as the kernel's does.
        fs::write(root.join("x"), "").unwrap();
        assert_eq!(
            resolve_where("a", "../../x", &|next| plain_hop(root, next)).as_deref(),
            Some("x")
        );
    }

    #[test]
    fn a_file_is_not_gone_up_from_and_links_on_the_way_are_followed() {
        let dir = TempDir::new("sweep-link-way");
        let root = dir.path();
        fs::create_dir_all(root.join("home/u/dot/ssh")).unwrap();
        fs::write(root.join("home/u/b"), "a file").unwrap();
        fs::write(root.join("home/u/dot/ssh/keys"), "").unwrap();
        // The kernel refuses `b/..` where `b` is a file.
        for hop in [plain_hop, public_hop] {
            let look = |next: &str| hop(root, next);
            assert_eq!(resolve_where("home/u/k", "b/../dot/ssh/keys", &look), None);
            assert_eq!(
                resolve_where("home/u/k", "dot/../dot/ssh/keys", &look).as_deref(),
                Some("home/u/dot/ssh/keys")
            );
        }
        // A link on the way is followed, and one in where it leads too.
        symlink("dot", root.join("home/u/d")).unwrap();
        symlink("d/ssh", root.join("home/u/.ssh")).unwrap();
        let look = |next: &str| plain_hop(root, next);
        assert_eq!(
            resolve_path("home/u/.ssh/keys", &look),
            Ok(Some("home/u/dot/ssh/keys".into()))
        );
        assert_eq!(resolve_path("home/u/.ssh/none", &look), Ok(None));
        assert_eq!(resolve_path("home/u/b/keys", &look), Ok(None));
        symlink("loop", root.join("home/u/loop")).unwrap();
        assert_eq!(resolve_path("home/u/loop/keys", &look), Err(()));
        // So they are as the account sees them, in a home that is not the
        // root owner's alone (`seen` follows no link of its own there):
        // in a link's target too, before a `..` and to the root.
        fs::set_permissions(root.join("home/u"), fs::Permissions::from_mode(0o775)).unwrap();
        let uid = std::os::unix::fs::MetadataExt::uid(&fs::metadata(root).unwrap());
        let as_account = |next: &str| hop_as(root, next, View::Owner(uid));
        symlink("../d/ssh/keys", root.join("home/u/dot/k")).unwrap();
        symlink("d/x/../ssh", root.join("home/u/up")).unwrap();
        fs::create_dir_all(root.join("home/u/dot/x")).unwrap();
        symlink("/", root.join("home/u/top")).unwrap();
        symlink("b/", root.join("home/u/slash")).unwrap();
        let deep = "a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t";
        fs::create_dir_all(root.join("home/u").join(deep)).unwrap();
        symlink(
            format!("/home/u/{deep}/{}ssh", "../".repeat(20) + "dot/"),
            root.join("home/u/deep"),
        )
        .unwrap();
        for (path, end) in [
            ("home/u/.ssh/keys", Some("home/u/dot/ssh/keys")),
            ("home/u/dot/k", Some("home/u/dot/ssh/keys")),
            ("home/u/up/keys", Some("home/u/dot/ssh/keys")),
            ("home/u/top/home/u/b", Some("home/u/b")),
            ("home/u/top", Some("")),
            // A trailing `/` asks for a directory.
            ("home/u/slash", None),
            // A deep target costs each part once.
            ("home/u/deep/keys", Some("home/u/dot/ssh/keys")),
        ] {
            assert_eq!(
                resolve_path(path, &as_account),
                Ok(end.map(str::to_string)),
                "{path}"
            );
        }
        // The kernel follows a way through `/proc`, which the view does not
        // show: it is not followed, and so told.
        symlink(
            "/proc/self/root/home/u/dot/ssh/keys",
            root.join("home/u/proc"),
        )
        .unwrap();
        assert_eq!(resolve_path("home/u/proc", &as_account), Err(()));

        // Each part is looked at again from the top: a part seen as a
        // directory that is a link (or a file) by the next look was swapped
        // meanwhile, and is told, not taken for nothing there.
        let below = |next: &str| hop_below(root, next, View::Owner(uid));
        assert_eq!(below("home/u/.ssh/keys"), Hop::Refused);
        assert_eq!(below("home/u/b/keys"), Hop::Refused);
        assert_eq!(below("home/u/dot/ssh/none"), Hop::Hidden);
        assert_eq!(below("home/u/dot/ssh/keys"), Hop::Other);
        assert_eq!(
            hop_as(root, "home/u/.ssh/keys", View::Owner(uid)),
            Hop::Hidden
        );
    }

    #[test]
    fn the_owner_of_a_file_is_shown_it_by_the_owner_bits_alone() {
        use std::os::unix::fs::MetadataExt;
        let dir = TempDir::new("sweep-owner-bits");
        let root = dir.path();
        fs::write(root.join("f"), "x").unwrap();
        let uid = fs::metadata(root).unwrap().uid();
        let shown = |mode: u32, view: View| {
            fs::set_permissions(root.join("f"), fs::Permissions::from_mode(mode)).unwrap();
            matches!(
                seen(root, "f", view).map(|seen| seen.what),
                Some(Public::File(_) | Public::Unopened(_))
            )
        };
        // Readable by others and not by its owner: the owner cannot read it.
        // (Shown to another, it may not open for the test: either counts.)
        assert!(!shown(0o044, View::Owner(uid)));
        assert!(shown(0o044, View::Owner(uid + 1)));
        assert!(shown(0o400, View::Owner(uid)));
        assert!(!shown(0o400, View::Owner(uid + 1)));
        // Only its group may read it, and the open fails (the owner bits keep
        // the test out): told as not opened, not as nothing there. So is a
        // directory only its group may enter.
        fs::set_permissions(root.join("f"), fs::Permissions::from_mode(0o040)).unwrap();
        if File::open(root.join("f")).is_err() {
            assert!(matches!(
                seen(root, "f", View::Owner(uid + 1)).map(|seen| seen.what),
                Some(Public::Unopened(_))
            ));
            fs::create_dir(root.join("d")).unwrap();
            fs::set_permissions(root.join("d"), fs::Permissions::from_mode(0o010)).unwrap();
            let what = seen(root, "d", View::Owner(uid + 1)).map(|seen| seen.what);
            fs::set_permissions(root.join("d"), fs::Permissions::from_mode(0o755)).unwrap();
            assert!(matches!(what, Some(Public::Refused(_))));
        }
        fs::set_permissions(root.join("f"), fs::Permissions::from_mode(0o644)).unwrap();
    }

    #[test]
    fn a_file_that_would_not_open_is_told_apart() {
        let seen = super::Seen {
            path: "f".into(),
            what: Public::Unopened("Resource temporarily unavailable".into()),
            kept: true,
        };
        assert_eq!(
            super::look_pinned(seen),
            Found::Unreadable(super::UNOPENED.into())
        );
    }

    #[test]
    fn a_file_read_past_its_limit_is_too_large() {
        let dir = TempDir::new("sweep-hash-most");
        let path = dir.path().join("f");
        fs::write(&path, "0123456789").unwrap();
        let file = File::open(&path).unwrap();
        // The size it had when opened is under the limit; what is read is not.
        let opened = file.metadata().unwrap();
        assert_eq!(
            hash(file, &opened, 4).unwrap(),
            Found::Unreadable(TOO_LARGE.into())
        );
    }

    #[test]
    fn a_chain_through_a_part_the_walk_was_kept_out_of_is_not_followed() {
        // Where a link leads, and a `..` after a link.
        let look = |path: &str| match path {
            "a" | "l" => Hop::Link(String::new()),
            "kept-out" => Hop::Refused,
            _ => Hop::Directory,
        };
        assert_eq!(super::walk_links("a", "kept-out", &look), Err(()));
        assert_eq!(super::walk_links("l", "kept-out/../x", &look), Err(()));
        assert_eq!(
            super::walk_links("l", "open/../x", &look),
            Ok(Some("x".into()))
        );
    }

    #[test]
    fn a_target_that_goes_up_after_a_name_is_told_apart() {
        for target in ["a/../x", "/usr/lib/../x", "../a/../x", "./a/.."] {
            assert!(goes_up_after_a_name(target), "{target}");
        }
        for target in ["../../usr/lib/x", "/usr/lib/x", "./x", "x/./y", "../x"] {
            assert!(!goes_up_after_a_name(target), "{target}");
        }
    }

    #[test]
    fn links_that_go_back_through_each_other_are_followed_in_bounded_time() {
        let dir = TempDir::new("sweep-link-budget");
        let root = dir.path();
        fs::create_dir_all(root.join("d/sub")).unwrap();
        // `Lk` leads to `L{k+1}/../` many times over, then `sub`: each `..`
        // follows the next link's whole chain again.
        symlink("sub", root.join("d/L9")).unwrap();
        for k in 1..9 {
            let target = format!("{}sub", format!("L{}/../", k + 1).repeat(200));
            symlink(target, root.join(format!("d/L{k}"))).unwrap();
        }
        let parts = std::cell::Cell::new(0_usize);
        let look = |next: &str| {
            parts.set(parts.get() + next.split('/').count());
            plain_hop(root, next)
        };
        let target = fs::read_link(root.join("d/L1")).unwrap();
        let target = target.to_str().unwrap();
        assert!(chain_too_long("d/L1", target, &look));
        assert_eq!(resolve_where("d/L1", target, &look), None);
        assert!(parts.get() <= 2 * MAX_LOOKED_PARTS, "{} parts", parts.get());
        // A short chain of the same shape is still followed to its end.
        assert_eq!(
            resolve_where("d/L8", "L9/../L9/../sub", &look).as_deref(),
            Some("d/sub")
        );

        // A deep path costs each look its parts: going down 600 directories
        // and back up would look at 600 paths of up to 600 parts; the
        // budget stops it after a few.
        let deep = "a/".repeat(600);
        fs::create_dir_all(root.join(&deep)).unwrap();
        fs::write(root.join("x"), "").unwrap();
        let target = format!("{deep}{}x", "../".repeat(600));
        parts.set(0);
        assert!(chain_too_long("l", &target, &look));
        assert!(parts.get() <= MAX_LOOKED_PARTS, "{} parts", parts.get());
    }

    /// `link_text` undone, for the test below.
    fn link_bytes(text: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut rest = text.as_bytes();
        while let Some((&first, after)) = rest.split_first() {
            match (first, after) {
                (b'\\', [b'\\', after @ ..]) => {
                    bytes.push(b'\\');
                    rest = after;
                }
                (b'\\', [b'x', high, low, after @ ..]) => {
                    let hex = std::str::from_utf8(&[*high, *low]).unwrap().to_owned();
                    bytes.push(u8::from_str_radix(&hex, 16).unwrap());
                    rest = after;
                }
                (b'\\', _) => panic!("a lone backslash in {text:?}"),
                (byte, after) => {
                    bytes.push(byte);
                    rest = after;
                }
            }
        }
        bytes
    }

    #[test]
    fn no_two_link_targets_read_the_same() {
        use std::os::unix::ffi::OsStrExt as _;

        // Arbitrary bytes, heavy in backslashes, `x`, hex digits and bytes
        // that are not UTF-8, from a fixed xorshift sequence.
        let alphabet = [b'\\', b'x', b'f', b'0', b'/', b'a', 0xff, 0xc3, 0xa9, 0x80];
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        for _ in 0..20_000 {
            let mut target = Vec::new();
            for _ in 0..(state % 12) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                target.push(alphabet[usize::try_from(state % 10).unwrap()]);
            }
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let text = super::link_text(std::path::Path::new(std::ffi::OsStr::from_bytes(&target)));
            assert_eq!(link_bytes(&text), target, "{text:?}");
        }
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

    #[test]
    fn a_pattern_matches_names_one_directory_at_a_time() {
        use crate::autorun::name_matches;
        for (pattern, name, matches) in [
            ("*.pth", "x.pth", true),
            ("*.pth", ".pth", true),
            ("*.pth", "x.pth.bak", false),
            ("python*", "python3.13", true),
            ("python*", "pypy", false),
            ("a*b*c", "aXbYc", true),
            ("a*b*c", "aXc", false),
            ("plain", "plain", true),
            ("plain", "plainer", false),
        ] {
            assert_eq!(name_matches(pattern, name), matches, "{pattern} {name}");
        }

        let dir = TempDir::new("sweep-matching");
        let root = dir.path();
        for path in [
            "lib/python3.13/site-packages/a.pth",
            "lib/python3.13/site-packages/pkg/deep.pth",
            "lib/python3.13/site-packages/b.py",
            "lib/python3.12/site-packages/c.pth",
            "lib/perl/site-packages/d.pth",
        ] {
            fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
            fs::write(root.join(path), "import x\n").unwrap();
        }
        // A linked directory is not entered.
        symlink("python3.13", root.join("lib/python3")).unwrap();
        let found = matching(root, "lib/python*/site-packages/*.pth");
        assert_eq!(
            found.files,
            [
                "lib/python3.12/site-packages/c.pth",
                "lib/python3.13/site-packages/a.pth"
            ]
        );
        assert!(!found.truncated);
        // A directory is not a file of that name.
        fs::create_dir_all(root.join("lib/python3.13/site-packages/dir.pth")).unwrap();
        assert_eq!(
            matching(root, "lib/python*/site-packages/*.pth")
                .files
                .len(),
            2
        );
        for (pattern, name, matches) in [
            ("a*a", "a", false),
            ("a*a", "aa", true),
            ("*", "anything", true),
            ("**", "", true),
            ("*a*a", "a", false),
            ("", "", true),
            ("", "x", false),
        ] {
            assert_eq!(name_matches(pattern, name), matches, "{pattern:?} {name:?}");
        }
        assert!(
            matching(root, "lib/python*/site-packages/sitecustomize.py")
                .files
                .is_empty()
        );
        assert!(matching(root, "none/*/x").files.is_empty());
    }

    #[test]
    fn a_part_swapped_between_the_look_and_the_open_is_told() {
        use super::{CHANGED, Part, open_part};
        let dir = TempDir::new("sweep-read-swap");
        let root = dir.path();
        fs::write(root.join("looked"), "a").unwrap();
        fs::write(root.join("swapped"), "b").unwrap();
        // The look saw `looked`; what is opened at the name is another
        // file, as when one is renamed over it in between.
        let found = fs::symlink_metadata(root.join("looked")).unwrap();
        let part = open_part(&root.join("swapped"), &found, true, View::Everyone, false);
        assert!(
            matches!(&part, Part::Shows(Public::Refused(why)) if why == CHANGED),
            "not told as changed"
        );
        let part = open_part(&root.join("looked"), &found, true, View::Everyone, false);
        assert!(matches!(part, Part::Open(..)), "the file looked at opens");
    }
}
