//! A listed directory's entries, held where they are for the set-id walk:
//! asked about through the directory held open, never by a path walked
//! again from the root.
//!
//! Something can be mounted on an entry after the walk read the mount
//! table: an account's FUSE mount over a file or directory it owns
//! (`fusermount3` takes either). Any question that reaches such a mount
//! (opening a directory, reading an attribute, a `stat`) is answered by
//! the account's program, which can leave it unanswered for good. So an
//! entry is first held with `O_PATH`, which asks its filesystem nothing,
//! and the mount it is on is read from `/proc/self/fdinfo`, which asks
//! nothing either; the walk asks about it only where that is its
//! directory's own mount, or where the walk's own table (`mount_table`) shows a mount
//! there that is not an account's FUSE mount. In the host's namespace an
//! account mounts only through `fusermount3`, which writes `user_id=`;
//! every other mount is root's, whose filesystem answers. A file is then
//! read through the file held, not by its path walked again from the root,
//! which could reach a mount made on the way since: a mount stacked on a
//! held entry is not followed from it.

use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io;
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

use crate::files::{O_DIRECTORY, O_NOFOLLOW, O_NONBLOCK};

/// `O_PATH`, the same on every target the crate builds for
/// (asm-generic/fcntl.h, and Arm's).
const O_PATH: i32 = 0o10_000_000;

/// An entry of a directory, held with `O_PATH`.
#[derive(Debug)]
pub(super) enum Held {
    /// On the directory's own mount.
    Here(fs::File),
    /// Something is mounted on it, the mount with this id (`mount_of`):
    /// nothing about it has been asked yet.
    Mounted(fs::File, u64),
}

/// The entry `name` of `directory`, which is on mount `mount`
/// (`mount_of`), held without following a link.
pub(super) fn hold(directory: &fs::File, mount: u64, name: &OsStr) -> io::Result<Held> {
    let mut path = format!("/proc/self/fd/{}/", directory.as_raw_fd()).into_bytes();
    path.extend_from_slice(name.as_bytes());
    let held = OpenOptions::new()
        .read(true)
        .custom_flags(O_PATH | O_NOFOLLOW)
        .open(OsStr::from_bytes(&path))?;
    let on = mount_of(&held)?;
    if on == mount {
        Ok(Held::Here(held))
    } else {
        Ok(Held::Mounted(held, on))
    }
}

/// The regular file `held` holds, opened to be read. Not past a link: it
/// is held as the link, and `/proc/self/fd` leads to what it holds.
pub(super) fn open_file(held: &fs::File) -> io::Result<fs::File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK)
        .open(format!("/proc/self/fd/{}", held.as_raw_fd()))
}

/// What a mount on an entry is, in the walk's own table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MountKind {
    /// An account's own FUSE mount, where set-id bits have no effect
    /// (`fusermount3` mounts with `nosuid`): never asked about.
    Accounts,
    /// Root's: any other mount, asked about.
    Roots,
    /// Not in the table: unmounted since the entry was held (a lazy
    /// `umount -l` leaves the held mount's id to the held file). What it
    /// was cannot be told, so it is not asked about; held again by its
    /// name, the entry is what was under it.
    Gone,
}

/// One line of a `mountinfo`, as far as the walk reads it.
pub(super) struct Line<'a> {
    pub(super) id: u64,
    /// Where it is mounted, as the kernel writes it (`\040` for a blank).
    pub(super) place: &'a str,
    /// The mount's own options (`nosuid`).
    pub(super) mount_options: &'a str,
    /// The filesystem's type and its own options.
    kind: &'a str,
    options: &'a str,
}

impl Line<'_> {
    /// Whether this is an account's FUSE mount: `fusermount3` writes the id
    /// of the account that mounted it as `user_id=`.
    pub(super) fn is_accounts(&self) -> bool {
        let fuse = self.kind == "fuse" || self.kind == "fuseblk" || self.kind.starts_with("fuse.");
        fuse && self
            .options
            .split(',')
            .any(|option| option.strip_prefix("user_id=").is_some_and(|id| id != "0"))
    }
}

/// Reads one line of a `mountinfo` (`proc_pid_mountinfo(5)`): the fields
/// up to the optional ones, a ` - `, then the filesystem's. A mount point
/// with a blank in it is written `\040`, so no field holds ` - `.
pub(super) fn line(text: &str) -> Option<Line<'_>> {
    let (mount, filesystem) = text.split_once(" - ")?;
    let mut mount = mount.split(' ');
    let id = mount.next()?.parse().ok()?;
    // Past the parent's id, the device and the root within it.
    let place = mount.nth(3)?;
    let mount_options = mount.next()?;
    let mut filesystem = filesystem.split(' ');
    let kind = filesystem.next()?;
    let options = filesystem.nth(1)?;
    Some(Line {
        id,
        place,
        mount_options,
        kind,
        options,
    })
}

/// What a listing showed of an entry: its device, inode and kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Identity {
    dev: u64,
    ino: u64,
    kind: fs::FileType,
}

impl Identity {
    pub(super) fn of(metadata: &fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            kind: metadata.file_type(),
        }
    }
}

/// Whether `held` is still what the listing showed (`listed`). Asks its
/// filesystem: only for an entry the caller may ask about (see the module
/// docs).
pub(super) fn is_listed(held: &fs::File, listed: Identity) -> io::Result<bool> {
    Ok(Identity::of(&held.metadata()?) == listed)
}

/// The directory `held` holds, opened to be listed.
pub(super) fn open_directory(held: &fs::File) -> io::Result<fs::File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY | O_NONBLOCK)
        .open(format!("/proc/self/fd/{}", held.as_raw_fd()))
}

/// The id of the mount `file` is on, as `/proc/self/fdinfo` gives it.
pub(super) fn mount_of(file: &fs::File) -> io::Result<u64> {
    let info = fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?;
    info.lines()
        .find_map(|line| line.strip_prefix("mnt_id:"))
        .and_then(|id| id.trim().parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "fdinfo has no mnt_id"))
}
