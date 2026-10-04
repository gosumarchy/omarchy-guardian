//! What the AUR gate remembers of a build between its makepkg calls, and
//! from one build to the next: what the user confirmed, which binaries the
//! sources held, and what the sources were when Guardian extracted them
//! itself.
//!
//! yay calls makepkg several times for one build, and each call is a new
//! Guardian. Without this a question would be asked on every call, and a
//! later call could not tell whether the sources it finds are the ones an
//! earlier call fetched and reviewed. It lives beside the review memory, in
//! a directory only the user can read or write; with no such directory
//! nothing is remembered and every question is asked again.

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use crate::engine::store;
use crate::sha256::Sha256;

/// The directory under the review memory's root.
const DIRECTORY: &str = "aur-gate";
/// The most confirmations kept for one package; the oldest go first.
const MAX_CONFIRMATIONS: usize = 32;
/// The most a remembered file may hold: a source tree's file list.
const MAX_BYTES: u64 = 64 * 1024 * 1024;
/// Hex characters of a hash kept per file: enough to tell a change.
const DIGEST_CHARS: usize = 32;

/// What a makepkg call that extracts left for the calls after it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Extraction {
    /// Where the sources were extracted.
    pub srcdir: String,
    /// Which directory that was (see `identity`), when it can be told.
    pub identity: Option<String>,
    /// The build removes and re-creates that directory (`--cleanbuild`).
    pub cleanbuild: bool,
    /// The downloaded files linked into it, with their hashes.
    pub downloads: BTreeMap<String, String>,
    /// Every file in it, with its hash.
    pub files: BTreeMap<String, String>,
}

/// What tells one directory from another made later under the same name:
/// its device, its number and when it was made. `None` where the
/// filesystem does not record the last.
pub fn identity(directory: &Path) -> Option<String> {
    let metadata = fs::symlink_metadata(directory).ok()?;
    let made = metadata.created().ok()?.duration_since(UNIX_EPOCH).ok()?;
    Some(format!(
        "{}:{}:{}",
        metadata.dev(),
        metadata.ino(),
        made.as_nanos()
    ))
}

fn short(digest: &str) -> &str {
    digest.get(..DIGEST_CHARS).unwrap_or(digest)
}

/// What a later call found different from an `Extraction`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Drift {
    /// The build did not extract into the directory Guardian reviewed.
    Elsewhere,
    /// Downloads that are new or not the ones Guardian fetched.
    Downloads(Vec<String>),
    /// Files new or changed in the source tree, as a build's own
    /// `prepare()` leaves them.
    Files(HashSet<String>),
}

impl Extraction {
    /// Compares the sources as they are now with what Guardian extracted.
    pub fn drift(
        &self,
        identity: Option<&str>,
        downloads: &BTreeMap<String, String>,
        files: &BTreeMap<String, String>,
    ) -> Drift {
        // A build that cleans first makes the directory anew. One that is
        // still the directory Guardian made was not touched by the build:
        // it extracted and prepared somewhere else.
        if self.cleanbuild && self.identity.is_some() && self.identity.as_deref() == identity {
            return Drift::Elsewhere;
        }
        let differs = |known: &BTreeMap<String, String>, path: &String, digest: &String| {
            let kept = known.get(&path.escape_default().to_string());
            digest.is_empty() || kept.map(|kept| short(kept)) != Some(short(digest))
        };
        let changed: Vec<String> = downloads
            .iter()
            .filter(|(name, digest)| differs(&self.downloads, name, digest))
            .map(|(name, _)| name.clone())
            .collect();
        if !changed.is_empty() {
            return Drift::Downloads(changed);
        }
        Drift::Files(
            files
                .iter()
                .filter(|(path, digest)| differs(&self.files, path, digest))
                .map(|(path, _)| path.clone())
                .collect(),
        )
    }

    fn to_text(&self) -> String {
        let mut text = format!(
            "srcdir {}\nidentity {}\ncleanbuild {}\n",
            self.srcdir.escape_default(),
            self.identity.as_deref().unwrap_or("-"),
            u8::from(self.cleanbuild)
        );
        for (kind, entries) in [("D", &self.downloads), ("F", &self.files)] {
            for (path, digest) in entries {
                let digest = if digest.is_empty() {
                    "-"
                } else {
                    short(digest)
                };
                let _ = writeln!(text, "{kind} {digest} {}", path.escape_default());
            }
        }
        text
    }

    fn parse(text: &str) -> Option<Self> {
        let mut lines = text.lines();
        let mut header = |name: &str| -> Option<String> {
            Some(
                lines
                    .next()?
                    .strip_prefix(name)?
                    .strip_prefix(' ')?
                    .to_string(),
            )
        };
        let mut extraction = Self {
            srcdir: header("srcdir")?,
            identity: Some(header("identity")?).filter(|identity| identity != "-"),
            cleanbuild: header("cleanbuild")? == "1",
            ..Self::default()
        };
        for line in lines {
            let mut fields = line.splitn(3, ' ');
            let (kind, digest, path) = (fields.next()?, fields.next()?, fields.next()?);
            let digest = if digest == "-" { "" } else { digest };
            match kind {
                "D" => &mut extraction.downloads,
                "F" => &mut extraction.files,
                _ => return None,
            }
            .insert(path.to_string(), digest.to_string());
        }
        Some(extraction)
    }

    /// The paths as they are kept: written so that each stays one line.
    pub fn keyed(entries: &BTreeMap<String, String>) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(path, digest)| (path.escape_default().to_string(), digest.clone()))
            .collect()
    }
}

/// The gate's memory of one package. Without a directory it remembers
/// nothing: every read is empty and every write is dropped.
pub struct State {
    directory: Option<PathBuf>,
    name: String,
}

impl State {
    /// Opens the memory of the package `key` under the review memory's
    /// `root`, creating its directory for the user alone.
    pub fn open(root: Option<&Path>, key: &str) -> Self {
        let directory = root.and_then(|root| {
            let uid = store::effective_uid().ok()?;
            store::private_dir(root, uid).ok()?;
            let directory = root.join(DIRECTORY);
            match DirBuilder::new().mode(0o700).create(&directory) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return None,
            }
            store::private_dir(&directory, uid).ok()?;
            Some(directory)
        });
        Self {
            directory,
            name: Sha256::digest(key.as_bytes()).to_string(),
        }
    }

    fn path(&self, what: &str) -> Option<PathBuf> {
        Some(
            self.directory
                .as_ref()?
                .join(format!("{}.{what}", self.name)),
        )
    }

    fn read(&self, what: &str) -> Option<String> {
        let path = self.path(what)?;
        let metadata = fs::symlink_metadata(&path).ok()?;
        (metadata.is_file() && metadata.len() <= MAX_BYTES)
            .then(|| fs::read_to_string(&path).ok())
            .flatten()
    }

    /// Writes through a new file and a rename, so a reader never sees half.
    fn write(&self, what: &str, text: &str) {
        let Some(path) = self.path(what) else { return };
        let temporary = path.with_extension(format!("{what}.{}.tmp", std::process::id()));
        drop(fs::remove_file(&temporary));
        let written = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .and_then(|mut file| file.write_all(text.as_bytes()))
            .and_then(|()| fs::rename(&temporary, &path));
        if written.is_err() {
            drop(fs::remove_file(&temporary));
        }
    }

    /// Whether the user said yes to `what` (a hash of exactly what was
    /// asked) for this package before.
    pub fn is_confirmed(&self, what: &str) -> bool {
        self.read("confirmed")
            .is_some_and(|text| text.lines().any(|line| line == what))
    }

    pub fn remember_confirmed(&self, what: &str) {
        let known = self.read("confirmed").unwrap_or_default();
        let mut lines: Vec<&str> = known.lines().filter(|line| *line != what).collect();
        lines.push(what);
        let from = lines.len().saturating_sub(MAX_CONFIRMATIONS);
        self.write("confirmed", &(lines[from..].join("\n") + "\n"));
    }

    /// The binaries the sources held at the last build that passed.
    pub fn binaries(&self) -> Option<BTreeMap<String, String>> {
        let text = self.read("binaries")?;
        text.lines()
            .map(|line| {
                let (digest, path) = line.split_once(' ')?;
                Some((path.to_string(), digest.to_string()))
            })
            .collect()
    }

    pub fn record_binaries(&self, binaries: &BTreeMap<String, String>) {
        let mut text = String::new();
        for (path, digest) in Extraction::keyed(binaries) {
            let digest = if digest.is_empty() { "-" } else { &digest };
            let _ = writeln!(text, "{digest} {path}");
        }
        self.write("binaries", &text);
    }

    pub fn extraction(&self) -> Option<Extraction> {
        Extraction::parse(&self.read("extraction")?)
    }

    pub fn record_extraction(&self, extraction: &Extraction) {
        self.write("extraction", &extraction.to_text());
    }
}

/// How the binaries now differ from the ones remembered, as names for the
/// user: `(new or changed, gone)`.
pub fn binary_changes(
    known: &BTreeMap<String, String>,
    now: &BTreeMap<String, String>,
) -> (Vec<String>, Vec<String>) {
    let now = Extraction::keyed(now);
    let changed = now
        .iter()
        .filter(|(path, digest)| {
            let digest = if digest.is_empty() {
                "-"
            } else {
                digest.as_str()
            };
            digest == "-" || known.get(*path).map(String::as_str) != Some(digest)
        })
        .map(|(path, _)| path.clone())
        .collect();
    let gone = known
        .keys()
        .filter(|path| !now.contains_key(*path))
        .cloned()
        .collect();
    (changed, gone)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashSet};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::{Drift, Extraction, State, binary_changes, identity};
    use crate::test_support::TempDir;

    fn map(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(path, digest)| ((*path).to_string(), (*digest).to_string()))
            .collect()
    }

    #[test]
    fn confirmations_are_kept_per_package_and_only_in_a_private_directory() {
        let dir = TempDir::new("gate-state");
        let root = dir.path().join("state");
        let state = State::open(Some(&root), "demo");
        assert!(!state.is_confirmed("prebuilt abc"));
        state.remember_confirmed("prebuilt abc");
        assert!(state.is_confirmed("prebuilt abc"));
        assert!(!state.is_confirmed("prebuilt abd"));
        assert!(!State::open(Some(&root), "other").is_confirmed("prebuilt abc"));
        // A new Guardian, as on yay's next makepkg call, still knows.
        assert!(State::open(Some(&root), "demo").is_confirmed("prebuilt abc"));
        let kept = root.join("aur-gate");
        assert_eq!(
            fs::metadata(&kept).unwrap().permissions().mode() & 0o777,
            0o700
        );
        // Only so many are kept.
        for index in 0..40 {
            state.remember_confirmed(&format!("sources {index}"));
        }
        assert!(!state.is_confirmed("prebuilt abc"));
        assert!(state.is_confirmed("sources 39"));

        // Without a directory, or with one open to others, nothing is
        // remembered: the question is asked again.
        let nowhere = State::open(None, "demo");
        nowhere.remember_confirmed("x");
        assert!(!nowhere.is_confirmed("x"));
        let open = dir.path().join("open");
        fs::create_dir(&open).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o755)).unwrap();
        let state = State::open(Some(&open), "demo");
        state.remember_confirmed("x");
        assert!(!state.is_confirmed("x"));
    }

    #[test]
    fn binaries_and_extractions_round_trip() {
        let dir = TempDir::new("gate-state-files");
        let state = State::open(Some(&dir.path().join("state")), "demo");
        assert_eq!(state.binaries(), None);
        let binaries = map(&[
            ("src/a b/tool", "11"),
            ("src/odd\nname", ""),
            ("src/x", "22"),
        ]);
        state.record_binaries(&binaries);
        let known = state.binaries().unwrap();
        assert_eq!(known.len(), 3);
        assert_eq!(binary_changes(&known, &binaries).1, Vec::<String>::new());
        // A file without a hash always counts as changed.
        assert_eq!(binary_changes(&known, &binaries).0, ["src/odd\\nname"]);
        let now = map(&[("src/a b/tool", "99"), ("src/new", "33")]);
        let (changed, gone) = binary_changes(&known, &now);
        assert_eq!(changed, ["src/a b/tool", "src/new"]);
        assert_eq!(gone, ["src/odd\\nname", "src/x"]);

        let extraction = Extraction {
            srcdir: "/build/demo/src".into(),
            identity: Some("1:2:3".into()),
            cleanbuild: true,
            downloads: Extraction::keyed(&map(&[("demo.tar.gz", &"a".repeat(64))])),
            files: Extraction::keyed(&map(&[("src/demo/a.c", &"b".repeat(64)), ("src/x y", "")])),
        };
        state.record_extraction(&extraction);
        let read = state.extraction().unwrap();
        assert_eq!(read.srcdir, extraction.srcdir);
        assert_eq!(read.identity, extraction.identity);
        assert!(read.cleanbuild);
        assert_eq!(read.downloads["demo.tar.gz"], "a".repeat(32));
        assert_eq!(read.files["src/x y"], "");
    }

    #[test]
    fn a_later_call_sees_what_changed_since_guardian_extracted() {
        let downloads = map(&[("demo.tar.gz", &"a".repeat(64))]);
        let files = map(&[
            ("src/demo/a.c", &"b".repeat(64)),
            ("src/demo/b.c", &"c".repeat(64)),
        ]);
        let dir = TempDir::new("gate-drift");
        let state = State::open(Some(&dir.path().join("state")), "demo");
        state.record_extraction(&Extraction {
            srcdir: "/x".into(),
            identity: Some("1:2:3".into()),
            cleanbuild: true,
            downloads: Extraction::keyed(&downloads),
            files: Extraction::keyed(&files),
        });
        let extraction = state.extraction().unwrap();
        // The build made the directory anew and left the files alone.
        assert_eq!(
            extraction.drift(Some("1:9:9"), &downloads, &files),
            Drift::Files(HashSet::new())
        );
        // Still the directory Guardian made: the build worked elsewhere.
        assert_eq!(
            extraction.drift(Some("1:2:3"), &downloads, &files),
            Drift::Elsewhere
        );
        // A download that changed, and one the listing did not show.
        let mut other = downloads.clone();
        other.insert("demo.tar.gz".into(), "f".repeat(64));
        other.insert("extra.bin".into(), "e".repeat(64));
        assert_eq!(
            extraction.drift(Some("1:9:9"), &other, &files),
            Drift::Downloads(vec!["demo.tar.gz".into(), "extra.bin".into()])
        );
        // What prepare() patched or added.
        let mut patched = files.clone();
        patched.insert("src/demo/a.c".into(), "d".repeat(64));
        patched.insert("src/demo/new.sh".into(), "e".repeat(64));
        patched.remove("src/demo/b.c");
        let Drift::Files(changed) = extraction.drift(None, &downloads, &patched) else {
            panic!("files");
        };
        let mut changed: Vec<String> = changed.into_iter().collect();
        changed.sort();
        assert_eq!(changed, ["src/demo/a.c", "src/demo/new.sh"]);
        // Without `--cleanbuild` the directory is the same one either way.
        let kept = Extraction {
            cleanbuild: false,
            ..extraction
        };
        assert_eq!(
            kept.drift(Some("1:2:3"), &downloads, &files),
            Drift::Files(HashSet::new())
        );
    }

    #[test]
    fn a_directory_made_again_under_the_same_name_is_another_one() {
        let dir = TempDir::new("gate-identity");
        let src = dir.path().join("src");
        fs::create_dir(&src).unwrap();
        let Some(first) = identity(&src) else {
            // A filesystem that does not record when a directory was made.
            return;
        };
        assert_eq!(identity(&src).as_deref(), Some(first.as_str()));
        fs::remove_dir(&src).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        fs::create_dir(&src).unwrap();
        assert_ne!(identity(&src), Some(first));
        assert_eq!(identity(&dir.path().join("missing")), None);
    }
}
