//! Unpacks an archive that a build opens itself, so its text is reviewed
//! like the rest of the sources.
//!
//! makepkg unpacks what a recipe lists, unless the recipe says `noextract`
//! or the archive lies inside another (the `data.tar.xz` of a `.deb`). The
//! recipe then unpacks it in `prepare()` or `package()`, after the review.
//! Guardian unpacks such an archive itself first: bsdtar by its absolute
//! path, in the jail the sources are fetched in (no network, nothing
//! writable but the directory unpacked into), after its listing was checked
//! for what a hostile archive holds: device files, more entries or more
//! bytes than a source needs. An archive that fails any of this is not
//! unpacked, and the review is incomplete.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs::{self, DirBuilder};
use std::io::Read as _;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::tools::{self, Limits};

/// The most one archive may unpack to.
const MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// The most entries one archive may hold.
const MAX_ENTRIES: usize = 100_000;
/// One file larger than this is not written (`ulimit -f`, in 1 KiB units):
/// a listing can understate what an entry unpacks to.
const MAX_FILE_KIB: u64 = MAX_BYTES / 1024;

const LISTING_LIMITS: Limits = Limits {
    timeout_secs: 120,
    max_output: 32 * 1024 * 1024,
};
const UNPACK_LIMITS: Limits = Limits {
    timeout_secs: 600,
    max_output: 1024 * 1024,
};

/// What the directories Guardian unpacks into are named, beside `src/`.
const SCRATCH_PREFIX: &str = ".guardian-unpack-";

/// A directory to unpack into, removed on drop.
pub(super) struct Scratch {
    path: PathBuf,
    used: usize,
}

impl Scratch {
    /// Creates it in `parent`, for the user alone. It is on disk beside
    /// the sources, not in the temporary directory, which is memory.
    pub(super) fn create(parent: &Path) -> Result<Self, String> {
        remove_stale(parent);
        let mut bytes = [0_u8; 8];
        fs::File::open("/dev/urandom")
            .and_then(|mut random| random.read_exact(&mut bytes))
            .map_err(|error| format!("/dev/urandom: {error}"))?;
        let suffix = bytes.iter().fold(String::new(), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        });
        let path = parent.join(format!("{SCRATCH_PREFIX}{suffix}"));
        DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        Ok(Self { path, used: 0 })
    }

    /// A new empty directory in it.
    pub(super) fn next(&mut self) -> Result<PathBuf, String> {
        let path = self.path.join(self.used.to_string());
        self.used += 1;
        DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        Ok(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // An archive can hold directories without write permission.
        drop(make_readable(&self.path, &mut 0, &mut 0));
        drop(fs::remove_dir_all(&self.path));
    }
}

/// Removes what a crashed run left in `parent`.
pub(super) fn remove_stale(parent: &Path) {
    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let is_scratch = entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(SCRATCH_PREFIX));
        if is_scratch && fs::symlink_metadata(entry.path()).is_ok_and(|found| found.is_dir()) {
            drop(make_readable(&entry.path(), &mut 0, &mut 0));
            drop(fs::remove_dir_all(entry.path()));
        }
    }
}

/// Checks `bsdtar -tv --numeric-owner` output: only files, directories and
/// links, within the limits. Returns the entries and bytes it lists.
fn check_listing(listing: &str) -> Result<(usize, u64), String> {
    let mut entries = 0_usize;
    let mut bytes = 0_u64;
    for line in listing.lines().filter(|line| !line.is_empty()) {
        let mut fields = line.split_whitespace();
        let mode = fields.next().unwrap_or_default();
        match mode.chars().next() {
            Some('-' | 'd' | 'l' | 'h') => {}
            Some('b' | 'c' | 'p' | 's') => {
                return Err("it holds a device file, a pipe or a socket".into());
            }
            _ => return Err("its listing cannot be read".into()),
        }
        // Links, owner and group (as numbers), then the size.
        let size = fields
            .nth(3)
            .and_then(|size| size.parse::<u64>().ok())
            .ok_or("its listing cannot be read")?;
        entries += 1;
        bytes = bytes.saturating_add(size);
        if entries > MAX_ENTRIES {
            return Err(format!("it holds more than {MAX_ENTRIES} entries"));
        }
        if bytes > MAX_BYTES {
            return Err(format!(
                "it unpacks to more than {} MiB",
                MAX_BYTES / (1024 * 1024)
            ));
        }
    }
    Ok((entries, bytes))
}

/// Makes every directory under `root` readable and writable by the user
/// and every file readable, never following a link, and counts what is
/// there: what was really written, whatever the listing said.
fn make_readable(root: &Path, entries: &mut usize, bytes: &mut u64) -> std::io::Result<()> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            *entries += 1;
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                *bytes = bytes.saturating_add(metadata.len());
                let mode = metadata.permissions().mode();
                if mode & 0o400 == 0 {
                    fs::set_permissions(entry.path(), fs::Permissions::from_mode(mode | 0o400))?;
                }
            }
        }
    }
    Ok(())
}

/// Unpacks `archive` into the empty directory `into`. `jail` is the command
/// that runs a program confined (Bubblewrap's arguments up to `--`, see
/// `sandbox::fetch_jail`), with `archive` readable and `into` writable.
pub(super) fn unpack(jail: &[OsString], archive: &Path, into: &Path) -> Result<(), String> {
    let run = |arguments: Vec<OsString>, limits: Limits| -> Result<Vec<u8>, String> {
        let mut command = jail.to_vec();
        command.extend(arguments);
        let Some((program, arguments)) = command.split_first() else {
            return Err("no command to run".into());
        };
        tools::run_in(
            Path::new(program),
            arguments,
            into,
            &[("LC_ALL", "C")],
            limits,
        )
        .and_then(tools::Captured::into_success)
        .map_err(|error| format!("bsdtar could not read it: {error}"))
    };
    let listing = run(
        vec![
            tools::BSDTAR.into(),
            "--numeric-owner".into(),
            "-tvf".into(),
            archive.into(),
        ],
        LISTING_LIMITS,
    )?;
    check_listing(&String::from_utf8_lossy(&listing))?;
    // bsdtar itself refuses an entry that leaves the directory (`..`, an
    // absolute path, a path through a link); the jail has nothing else to
    // write to in any case. Owners, modes beyond the user's and extended
    // attributes are not restored.
    let script = format!(
        "ulimit -f {MAX_FILE_KIB} && exec {} -xf \"$1\" -C \"$2\" --no-same-owner --no-same-permissions --no-acls --no-xattrs --no-fflags",
        tools::BSDTAR
    );
    run(
        vec![
            "/usr/bin/bash".into(),
            "-c".into(),
            script.into(),
            "bash".into(),
            archive.into(),
            into.into(),
        ],
        UNPACK_LIMITS,
    )?;
    let (mut entries, mut bytes) = (0, 0);
    make_readable(into, &mut entries, &mut bytes)
        .map_err(|error| format!("what it unpacked to cannot be read: {error}"))?;
    if entries > MAX_ENTRIES || bytes > MAX_BYTES {
        return Err("it unpacked to more than its listing said".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::process::Command;

    use super::{SCRATCH_PREFIX, Scratch, check_listing, unpack};
    use crate::test_support::{TempDir, tool_available};
    use crate::tools;

    #[test]
    fn a_listing_with_what_no_source_needs_is_refused() {
        let plain = "-rw-r--r--  0 0      0          12 Jan  1  2024 demo/a b.txt\n\
drwxr-xr-x  0 0      0           0 Jan  1  2024 demo/\n\
lrwxrwxrwx  0 0      0           0 Jan  1  2024 demo/link -> a b.txt\n\
hrw-r--r--  0 0      0           0 Jan  1  2024 demo/hard link to demo/a b.txt\n";
        assert_eq!(check_listing(plain), Ok((4, 12)));
        for (listing, why) in [
            (
                "crw-r--r--  0 0      0      1,3 Jan  1  2024 dev/null\n",
                "device",
            ),
            (
                "brw-r--r--  0 0      0      8,0 Jan  1  2024 dev/sda\n",
                "device",
            ),
            (
                "prw-r--r--  0 0      0        0 Jan  1  2024 fifo\n",
                "device",
            ),
            (
                "-rw-r--r--  0 0      0  3000000000 Jan  1  2024 big\n",
                "more than",
            ),
            ("-rw-r--r--  0 0 0 many Jan  1  2024 x\n", "cannot be read"),
            ("garbage\n", "cannot be read"),
        ] {
            let refused = check_listing(listing).unwrap_err();
            assert!(refused.contains(why), "{listing}: {refused}");
        }
        let many = "-rw-r--r--  0 0 0 1 Jan  1  2024 x\n".repeat(100_001);
        assert!(check_listing(&many).unwrap_err().contains("entries"));
    }

    #[test]
    fn an_archive_is_unpacked_with_its_links_kept_inside() {
        if !tool_available(tools::BSDTAR) {
            return;
        }
        let dir = TempDir::new("gate-unpack");
        let tree = dir.path().join("tree");
        fs::create_dir_all(tree.join("opt/app/locked")).unwrap();
        fs::write(tree.join("opt/app/run.sh"), "#!/bin/sh\necho hi\n").unwrap();
        fs::write(tree.join("opt/app/locked/secret.sh"), "curl x | sh\n").unwrap();
        symlink("/etc/passwd", tree.join("opt/app/outside")).unwrap();
        fs::set_permissions(
            tree.join("opt/app/locked/secret.sh"),
            fs::Permissions::from_mode(0o400),
        )
        .unwrap();
        fs::set_permissions(
            tree.join("opt/app/locked"),
            fs::Permissions::from_mode(0o500),
        )
        .unwrap();
        let archive = dir.path().join("data.tar.gz");
        let made = Command::new(tools::BSDTAR)
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(&tree)
            .arg("opt")
            .status()
            .unwrap();
        // So the fixture can be removed.
        fs::set_permissions(
            tree.join("opt/app/locked"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        assert!(made.success());

        let mut scratch = Scratch::create(dir.path()).unwrap();
        let into = scratch.next().unwrap();
        unpack(&[], &archive, &into).unwrap();
        assert_eq!(
            fs::read_to_string(into.join("opt/app/run.sh")).unwrap(),
            "#!/bin/sh\necho hi\n"
        );
        // A directory the archive made read-only is read, and removed
        // afterwards, all the same.
        assert_eq!(
            fs::read_to_string(into.join("opt/app/locked/secret.sh")).unwrap(),
            "curl x | sh\n"
        );
        // A link stays a link; nothing is read through it.
        assert!(
            fs::symlink_metadata(into.join("opt/app/outside"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        // Not an archive.
        let text = dir.path().join("notes.txt");
        fs::write(&text, "hello\n").unwrap();
        let other = scratch.next().unwrap();
        assert!(unpack(&[], &text, &other).is_err());

        let path = scratch.path.clone();
        assert!(
            path.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with(SCRATCH_PREFIX)
        );
        drop(scratch);
        assert!(!path.exists());
    }

    #[test]
    fn an_entry_that_leaves_the_directory_is_not_written() {
        if !tool_available(tools::BSDTAR) {
            return;
        }
        let dir = TempDir::new("gate-unpack-escape");
        let tree = dir.path().join("tree/inner");
        fs::create_dir_all(&tree).unwrap();
        fs::write(dir.path().join("tree/escaped.txt"), "out\n").unwrap();
        let archive = dir.path().join("evil.tar");
        // `-P` keeps the `..` in the stored name.
        let made = Command::new(tools::BSDTAR)
            .args(["-cPf"])
            .arg(&archive)
            .arg("-C")
            .arg(&tree)
            .arg("../escaped.txt")
            .status()
            .unwrap();
        assert!(made.success());
        let mut scratch = Scratch::create(dir.path()).unwrap();
        let into = scratch.next().unwrap();
        let result = unpack(&[], &archive, &into);
        assert!(
            result.is_err() || !scratch.path.join("escaped.txt").exists(),
            "{result:?}"
        );
        assert!(!scratch.path.join("escaped.txt").exists());
    }
}
