//! Opening, reading and replacing files with care: the open(2) flags the
//! standard library does not name.

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

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::{OpenOptionsExt, symlink};

    use super::{O_DIRECTORY, O_NOFOLLOW, O_NONBLOCK};
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
}
