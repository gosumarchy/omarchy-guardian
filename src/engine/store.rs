//! The review memory's store under the user's state directory:
//! content-addressed blobs, baseline manifests and cached verdicts. Only
//! user-level classes use it; the root pacman gate never opens it.

use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Error, IoContext};
use crate::files::{AtomicWrite, write_atomic};
use crate::paths::{self, Accept};
use crate::sha256::{Digest, Sha256};
use crate::user;

pub(super) const BLOBS: &str = "blobs";
pub(super) const BASELINES: &str = "baselines";
pub(super) const VERDICTS: &str = "verdicts";

const TEMP_PREFIX: &str = ".tmp-";

/// Age in seconds beyond which a leftover `.tmp-*` file is swept: a run
/// killed between opening its temp file and renaming it into place
/// otherwise leaves that file behind forever.
const STALE_TEMP_SECS: u64 = 3_600;

/// Numbers this process's temp names. One counter for the whole process,
/// not one per `Store`: `write_atomic` removes whatever is under its temp
/// name first, so two stores on one root with their own counters would
/// delete each other's half-written files.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(crate) struct Store {
    root: PathBuf,
}

impl Store {
    /// `$XDG_STATE_HOME/omarchy-guardian`, else `~/.local/state/omarchy-guardian`.
    pub(crate) fn default_root() -> Option<PathBuf> {
        let base = paths::state_home(Accept::Absolute, Accept::Absolute)?;
        Some(base.join("omarchy-guardian"))
    }

    /// Opens the store, creating it with mode 0700. A store owned by another
    /// user, or open to group or others, is refused: whoever can write it
    /// can plant cached verdicts. A missing store (and missing parents) is
    /// created only under an existing real directory owned by the effective
    /// user, so a run under `sudo -E` (which keeps the user's HOME) cannot
    /// leave root-owned directories in it.
    pub(crate) fn open(root: PathBuf) -> Result<Self, Error> {
        let uid = user::effective_uid()?;
        paths::private_dir(&root, uid)?;

        for name in [BLOBS, BASELINES, VERDICTS] {
            let path = root.join(name);
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => return Err(Error::Io { path, source }),
            }
            if !fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_dir()) {
                return Err(Error::Message(format!(
                    "{} is not a directory",
                    path.display()
                )));
            }
        }
        Ok(Self { root })
    }

    fn path(&self, dir: &str, name: &str) -> PathBuf {
        self.root.join(dir).join(name)
    }

    /// Writes through a new temporary file in the same directory, then
    /// renames it into place, so a reader never sees half a file.
    pub(super) fn write(&self, dir: &str, name: &str, bytes: &[u8]) -> Result<(), Error> {
        let target = self.path(dir, name);
        // Unique to this process and this write, so whatever is under it
        // was left by a killed run that had this pid: `write_atomic`
        // removes it first.
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temporary = self.path(dir, &format!("{TEMP_PREFIX}{}-{counter}", process::id()));
        let options = AtomicWrite {
            sync: true,
            ..AtomicWrite::private(temporary)
        };
        write_atomic(&target, bytes, &options).at(&target)
    }

    /// Deletes `.tmp-*` files older than an hour from every store directory:
    /// leftovers from a run killed mid-write that `write` itself never
    /// cleans up.
    pub(super) fn sweep_stale_temp_files(&self, now: u64) -> Result<(), Error> {
        for dir in [BLOBS, BASELINES, VERDICTS] {
            let path = self.root.join(dir);
            for entry in fs::read_dir(&path).at(&path)? {
                let entry = entry.at(&path)?;
                let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                    continue;
                };
                if !name.starts_with(TEMP_PREFIX) {
                    continue;
                }
                let entry_path = path.join(&name);
                let modified = entry
                    .metadata()
                    .and_then(|metadata| metadata.modified())
                    .at(&entry_path)?;
                let age = now.saturating_sub(unix_secs(modified));
                if age >= STALE_TEMP_SECS {
                    fs::remove_file(&entry_path).at(&entry_path)?;
                }
            }
        }
        Ok(())
    }

    pub(super) fn read(&self, dir: &str, name: &str) -> Result<Option<Vec<u8>>, Error> {
        let path = self.path(dir, name);
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(Error::Io { path, source }),
        }
    }

    pub(super) fn remove(&self, dir: &str, name: &str) -> Result<(), Error> {
        let path = self.path(dir, name);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(Error::Io { path, source }),
        }
    }

    /// Entry names in one of the store's directories, sorted, leaving out
    /// temporary files.
    pub(super) fn list(&self, dir: &str) -> Result<Vec<String>, Error> {
        let path = self.root.join(dir);
        let mut names = Vec::new();
        for entry in fs::read_dir(&path).at(&path)? {
            let entry = entry.at(&path)?;
            if let Some(name) = entry
                .file_name()
                .to_str()
                .filter(|name| !name.starts_with(TEMP_PREFIX))
            {
                names.push(name.to_string());
            }
        }
        names.sort();
        Ok(names)
    }

    /// Total bytes of the store's files.
    pub(super) fn size(&self) -> Result<u64, Error> {
        let mut total = 0;
        for dir in [BLOBS, BASELINES, VERDICTS] {
            for name in self.list(dir)? {
                let path = self.path(dir, &name);
                match fs::symlink_metadata(&path) {
                    Ok(metadata) => total += metadata.len(),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(source) => return Err(Error::Io { path, source }),
                }
            }
        }
        Ok(total)
    }

    /// Stores `bytes` under their SHA-256 and returns it.
    pub(super) fn put_blob(&self, bytes: &[u8]) -> Result<Digest, Error> {
        let digest = Sha256::digest(bytes);
        let name = digest.to_string();
        if !self.path(BLOBS, &name).exists() {
            self.write(BLOBS, &name, bytes)?;
        }
        Ok(digest)
    }

    /// The blob with this digest, or `None` when it is missing or no longer
    /// matches its digest; a corrupt blob is deleted.
    pub(super) fn get_blob(&self, digest: Digest) -> Result<Option<Vec<u8>>, Error> {
        let name = digest.to_string();
        let Some(bytes) = self.read(BLOBS, &name)? else {
            return Ok(None);
        };
        if Sha256::digest(&bytes) == digest {
            Ok(Some(bytes))
        } else {
            self.remove(BLOBS, &name)?;
            Ok(None)
        }
    }
}

/// A read-only summary for `config show`: the number of baselines and the
/// store's bytes, or `None` when there is no store yet.
pub(crate) fn summary(root: &Path) -> Option<(usize, u64)> {
    if !root.is_dir() {
        return None;
    }
    let store = Store {
        root: root.to_path_buf(),
    };
    Some((
        store.list(BASELINES).map_or(0, |names| names.len()),
        store.size().unwrap_or(0),
    ))
}

/// Unix seconds for a file's modification time; a time before the epoch
/// (not expected on a real filesystem) is treated as maximally stale.
fn unix_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::{BASELINES, BLOBS, Store, VERDICTS, summary};
    use crate::test_support::TempDir;

    #[test]
    fn opening_creates_private_directories() {
        let dir = TempDir::new("store-open");
        let root = dir.path().join("state").join("omarchy-guardian");
        Store::open(root.clone()).unwrap();

        for path in [
            root.clone(),
            root.join(BLOBS),
            root.join(BASELINES),
            root.join(VERDICTS),
        ] {
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{}", path.display());
        }
    }

    #[test]
    fn missing_parents_are_created_under_a_directory_the_user_owns() {
        let dir = TempDir::new("store-missing-parent");
        let state = dir.path().join("local").join("state");
        let root = state.join("omarchy-guardian");

        Store::open(root.clone()).unwrap();

        for path in [dir.path().join("local"), state, root.clone()] {
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert!(metadata.file_type().is_dir(), "{}", path.display());
            assert_eq!(
                metadata.permissions().mode() & 0o777,
                0o700,
                "{}",
                path.display()
            );
        }
        assert!(root.join(BASELINES).is_dir());
    }

    #[test]
    fn a_symlinked_ancestor_counts_as_its_target() {
        let dir = TempDir::new("store-symlink-parent");
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        Store::open(link.join("state").join("omarchy-guardian")).unwrap();
        assert!(
            real.join("state")
                .join("omarchy-guardian")
                .join(BASELINES)
                .is_dir()
        );
    }

    #[test]
    fn a_store_is_not_created_under_a_file() {
        let dir = TempDir::new("store-file-parent");
        let file = dir.path().join("file");
        fs::write(&file, b"x").unwrap();

        let error = Store::open(file.join("state").join("omarchy-guardian"))
            .err()
            .unwrap()
            .to_string();
        // The kernel refuses the path itself (ENOTDIR) before any ancestor
        // check; either way nothing is created.
        assert!(error.to_lowercase().contains("not a directory"), "{error}");
    }

    #[test]
    fn a_store_open_to_others_is_refused() {
        let dir = TempDir::new("store-mode");
        let root = dir.path().join("store");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o770)).unwrap();

        let error = Store::open(root).err().unwrap().to_string();
        assert!(error.contains("group or others"), "{error}");
    }

    #[test]
    fn writes_are_atomic_and_private() {
        let dir = TempDir::new("store-write");
        let store = Store::open(dir.path().join("store")).unwrap();

        store.write(VERDICTS, "k", b"one").unwrap();
        store.write(VERDICTS, "k", b"two").unwrap();

        assert_eq!(
            store.read(VERDICTS, "k").unwrap().as_deref(),
            Some(&b"two"[..])
        );
        assert_eq!(store.read(VERDICTS, "missing").unwrap(), None);
        assert_eq!(store.list(VERDICTS).unwrap(), ["k"]);
        let mode = fs::metadata(dir.path().join("store").join(VERDICTS).join("k"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);

        store.remove(VERDICTS, "k").unwrap();
        store.remove(VERDICTS, "k").unwrap();
        assert!(store.list(VERDICTS).unwrap().is_empty());
    }

    #[test]
    fn two_stores_on_one_root_do_not_remove_each_others_writes() {
        let dir = TempDir::new("store-two");
        let root = dir.path().join("store");
        let stores = [Store::open(root.clone()).unwrap(), Store::open(root).unwrap()];

        // Each write first removes whatever is under its temp name; with a
        // counter per store, both would use the same names and one could
        // remove the other's file before its rename.
        std::thread::scope(|scope| {
            for (index, store) in stores.iter().enumerate() {
                scope.spawn(move || {
                    for round in 0..1000 {
                        store
                            .write(VERDICTS, &format!("{index}-{round}"), b"value")
                            .unwrap();
                    }
                });
            }
        });
        assert_eq!(stores[0].list(VERDICTS).unwrap().len(), 2000);
    }

    #[test]
    fn blobs_are_addressed_by_content_and_corrupt_ones_are_dropped() {
        let dir = TempDir::new("store-blob");
        let store = Store::open(dir.path().join("store")).unwrap();

        let digest = store.put_blob(b"hello\n").unwrap();
        assert_eq!(store.put_blob(b"hello\n").unwrap(), digest);
        assert_eq!(
            store.get_blob(digest).unwrap().as_deref(),
            Some(&b"hello\n"[..])
        );

        fs::write(
            dir.path()
                .join("store")
                .join(BLOBS)
                .join(digest.to_string()),
            "tampered",
        )
        .unwrap();
        assert_eq!(store.get_blob(digest).unwrap(), None);
        assert!(store.list(BLOBS).unwrap().is_empty());
    }

    #[test]
    fn size_and_summary_count_the_stores_files() {
        let dir = TempDir::new("store-size");
        let root = dir.path().join("store");
        assert_eq!(summary(&root), None);

        let store = Store::open(root.clone()).unwrap();
        store.write(BASELINES, "aur.x", b"12345").unwrap();
        store.put_blob(b"abc").unwrap();

        assert_eq!(store.size().unwrap(), 8);
        assert_eq!(summary(&root), Some((1, 8)));
    }

    #[test]
    fn default_root_uses_home_or_xdg_state_home() {
        if let Some(root) = Store::default_root() {
            assert!(root.ends_with("omarchy-guardian"));
        }
    }
}
