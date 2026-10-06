//! Opening, reading and replacing files with care: the open(2) flags the
//! standard library does not name, a bounded read that follows no link,
//! and a write that replaces a file in one step.

use std::fs::{self, OpenOptions, Permissions};
use std::io::{self, Read, Write as _};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt as _, chown};
use std::path::{Path, PathBuf};

/// `O_NOFOLLOW`, `O_DIRECTORY` and `O_NONBLOCK`. The generic Linux ABI
/// (`x86_64`, `riscv64`) and Arm's give the first two different bits.
#[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
pub const O_NOFOLLOW: i32 = 0o400_000;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub const O_NOFOLLOW: i32 = 0o100_000;
#[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
pub const O_DIRECTORY: i32 = 0o200_000;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub const O_DIRECTORY: i32 = 0o40_000;
/// The same on all of them (`x86_64`, `aarch64`, `arm`, `riscv64`). A path
/// swapped for a FIFO between `lstat` and `open` then fails the identity check
/// instead of blocking the open; it has no effect on regular files.
pub const O_NONBLOCK: i32 = 0o4000;

/// The text of a regular file of at most `max` bytes, opened without
/// following a link or waiting on a pipe.
pub fn read_small_file(path: &Path, max: u64) -> Option<String> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > max {
        return None;
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(path)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() as u64 <= max).then(|| String::from_utf8_lossy(&bytes).into_owned())
}

/// How `write_atomic` makes the new file.
pub struct AtomicWrite {
    /// The new file's name until it is moved into place, in the directory
    /// of the file it replaces. Whatever is under that name is removed
    /// first. Each writer keeps a name of its own: another process may see
    /// it, and two writers of one file must not share it unless they did.
    pub temporary: PathBuf,
    /// The mode the file is made with, less what the umask takes away.
    pub mode: u32,
    /// Gives the file exactly `mode` before anything is written, whatever
    /// the umask.
    pub exact_mode: bool,
    /// Whom the written file is handed to before it is moved into place.
    pub owner: Option<Owner>,
    /// Waits for the text to reach the disk before the move.
    pub sync: bool,
}

/// The owner and group a written file is given, and the mode it has then.
pub struct Owner {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

impl AtomicWrite {
    /// A file of the user's own (mode 0600 at most), not waited for.
    pub fn private(temporary: PathBuf) -> Self {
        Self {
            temporary,
            mode: 0o600,
            exact_mode: false,
            owner: None,
            sync: false,
        }
    }
}

/// Saves `bytes` as `path`, all of them or none: they are written to a new
/// file beside it, which is then moved over it, so a reader never sees half.
/// The new file is made new, never written through a link left under its
/// name, and does not stay behind where any step fails.
pub fn write_atomic(path: &Path, bytes: &[u8], options: &AtomicWrite) -> io::Result<()> {
    let temporary = &options.temporary;
    drop(fs::remove_file(temporary));
    let written = fill(bytes, options).and_then(|()| fs::rename(temporary, path));
    if written.is_err() {
        drop(fs::remove_file(temporary));
    }
    written
}

fn fill(bytes: &[u8], options: &AtomicWrite) -> io::Result<()> {
    let temporary = &options.temporary;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(options.mode)
        .open(temporary)?;
    if options.exact_mode {
        file.set_permissions(Permissions::from_mode(options.mode))?;
    }
    file.write_all(bytes)?;
    if options.sync {
        file.sync_all()?;
    }
    drop(file);
    if let Some(owner) = &options.owner {
        chown(temporary, Some(owner.uid), Some(owner.gid))?;
        fs::set_permissions(temporary, Permissions::from_mode(owner.mode))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
    use std::path::Path;

    use super::{
        AtomicWrite, O_DIRECTORY, O_NOFOLLOW, O_NONBLOCK, Owner, read_small_file, write_atomic,
    };
    use crate::test_support::TempDir;

    #[test]
    fn the_open_flags_mean_what_their_names_say_on_this_target() {
        let dir = TempDir::new("open-flags");
        let file = dir.path().join("file");
        let link = dir.path().join("link");
        fs::write(&file, "x").unwrap();
        symlink(&file, &link).unwrap();
        let open =
            |path: &Path, flags: i32| OpenOptions::new().read(true).custom_flags(flags).open(path);

        assert!(open(&file, O_NOFOLLOW | O_NONBLOCK).is_ok());
        assert!(open(&link, O_NONBLOCK).is_ok());
        // ELOOP: the last component is a link.
        assert_eq!(
            open(&link, O_NOFOLLOW).unwrap_err().raw_os_error(),
            Some(40)
        );
        assert!(open(dir.path(), O_DIRECTORY).is_ok());
        // ENOTDIR.
        assert_eq!(
            open(&file, O_DIRECTORY).unwrap_err().raw_os_error(),
            Some(20)
        );
    }

    #[test]
    fn a_small_file_is_read_whole_or_not_at_all() {
        let dir = TempDir::new("small-file");
        let file = dir.path().join("file");
        fs::write(&file, "12345").unwrap();
        assert_eq!(read_small_file(&file, 5).as_deref(), Some("12345"));
        assert_eq!(read_small_file(&file, 6).as_deref(), Some("12345"));
        assert_eq!(read_small_file(&file, 4), None);

        let empty = dir.path().join("empty");
        fs::write(&empty, "").unwrap();
        assert_eq!(read_small_file(&empty, 0).as_deref(), Some(""));

        // What is not text is shown as far as it can be, never refused.
        let binary = dir.path().join("binary");
        fs::write(&binary, [b'a', 0xff, b'b']).unwrap();
        assert_eq!(read_small_file(&binary, 8).as_deref(), Some("a\u{fffd}b"));
    }

    #[test]
    fn only_a_regular_file_itself_is_read_as_a_small_file() {
        let dir = TempDir::new("small-file-kind");
        let file = dir.path().join("file");
        fs::write(&file, "x").unwrap();
        let link = dir.path().join("link");
        symlink(&file, &link).unwrap();
        assert_eq!(read_small_file(&link, 8), None);
        assert_eq!(read_small_file(dir.path(), 8), None);
        assert_eq!(read_small_file(&dir.path().join("missing"), 8), None);
        // A file reached through a linked directory is still that file.
        let through = dir.path().join("through");
        symlink(dir.path(), &through).unwrap();
        assert_eq!(
            read_small_file(&through.join("file"), 8).as_deref(),
            Some("x")
        );
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    fn names(directory: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn an_atomic_write_replaces_the_file_and_leaves_nothing_else() {
        let dir = TempDir::new("atomic-write");
        let path = dir.path().join("record.json");
        let temporary = dir.path().join("record.tmp");
        // A leftover under the temporary name is not written through.
        let elsewhere = dir.path().join("elsewhere");
        fs::write(&elsewhere, "keep").unwrap();
        symlink(&elsewhere, &temporary).unwrap();

        let options = AtomicWrite::private(temporary);
        write_atomic(&path, b"one", &options).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "one");
        assert_eq!(mode(&path) & 0o177, 0);
        write_atomic(&path, b"two", &options).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "two");
        assert_eq!(fs::read_to_string(&elsewhere).unwrap(), "keep");
        assert_eq!(names(dir.path()), ["elsewhere", "record.json"]);
    }

    #[test]
    fn a_failed_atomic_write_leaves_the_old_file_and_no_new_one() {
        let dir = TempDir::new("atomic-write-fails");
        // A directory cannot be replaced by a file.
        let path = dir.path().join("taken");
        fs::create_dir(&path).unwrap();
        let options = AtomicWrite::private(dir.path().join("taken.tmp"));
        assert!(write_atomic(&path, b"text", &options).is_err());
        assert!(path.is_dir());
        assert_eq!(names(dir.path()), ["taken"]);

        // Nor can a file be made where there is no directory.
        let missing = dir.path().join("none/file");
        let options = AtomicWrite::private(dir.path().join("none/file.tmp"));
        assert!(write_atomic(&missing, b"text", &options).is_err());
        assert_eq!(names(dir.path()), ["taken"]);
    }

    #[test]
    fn an_atomic_write_gives_the_mode_and_owner_it_is_asked_for() {
        let dir = TempDir::new("atomic-write-mode");
        let made = |name: &str| {
            (
                dir.path().join(name),
                dir.path().join(format!("{name}.tmp")),
            )
        };

        // The mode at creation is at most the one asked for.
        let (path, temporary) = made("created");
        let options = AtomicWrite {
            mode: 0o644,
            sync: true,
            ..AtomicWrite::private(temporary)
        };
        write_atomic(&path, b"x", &options).unwrap();
        assert_eq!(mode(&path) & !0o644, 0);

        // An exact mode is not narrowed by the umask.
        let (path, temporary) = made("exact");
        let options = AtomicWrite {
            mode: 0o666,
            exact_mode: true,
            ..AtomicWrite::private(temporary)
        };
        write_atomic(&path, b"x", &options).unwrap();
        assert_eq!(mode(&path), 0o666);

        // Handed over (here to its owner already), it has the owner's mode.
        let (path, temporary) = made("owned");
        let metadata = fs::metadata(dir.path()).unwrap();
        let options = AtomicWrite {
            owner: Some(Owner {
                uid: metadata.uid(),
                gid: metadata.gid(),
                mode: 0o640,
            }),
            ..AtomicWrite::private(temporary)
        };
        write_atomic(&path, b"x", &options).unwrap();
        assert_eq!(mode(&path), 0o640);
        assert_eq!(fs::metadata(&path).unwrap().uid(), metadata.uid());
        assert_eq!(names(dir.path()), ["created", "exact", "owned"]);
    }
}
