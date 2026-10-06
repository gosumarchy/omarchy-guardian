//! Opening, reading and replacing files with care: the open(2) flags the
//! standard library does not name, and a bounded read that follows no link.

use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

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

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::{OpenOptionsExt, symlink};

    use super::{O_DIRECTORY, O_NOFOLLOW, O_NONBLOCK, read_small_file};
    use crate::test_support::TempDir;

    #[test]
    fn the_open_flags_mean_what_their_names_say_on_this_target() {
        let dir = TempDir::new("open-flags");
        let file = dir.path().join("file");
        let link = dir.path().join("link");
        fs::write(&file, "x").unwrap();
        symlink(&file, &link).unwrap();
        let open = |path: &std::path::Path, flags: i32| {
            OpenOptions::new().read(true).custom_flags(flags).open(path)
        };

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
}
