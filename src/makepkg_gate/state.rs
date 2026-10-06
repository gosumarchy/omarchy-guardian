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
use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use crate::error::{Error, IoContext};
use crate::files::{AtomicWrite, write_atomic};
use crate::paths;
use crate::sha256::Sha256;
use crate::user;

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
pub(super) struct Extraction {
    /// Where the sources were extracted.
    pub(super) srcdir: String,
    /// Which directory that was (see `identity`), when it can be told.
    pub(super) identity: Option<String>,
    /// The build removes and re-creates that directory (`--cleanbuild`).
    pub(super) cleanbuild: bool,
    /// The downloaded files linked into it, with their hashes. The names
    /// here and the paths below are as they are, not as they are written.
    pub(super) downloads: BTreeMap<String, String>,
    /// Every file in it, with its hash.
    pub(super) files: BTreeMap<String, String>,
}

/// What tells one directory from another made later under the same name:
/// its device, its number and when it was made. `None` where the
/// filesystem does not record the last.
pub(super) fn identity(directory: &Path) -> Option<String> {
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

/// Whether `text` may stand for a name that is not text: such a name is
/// kept with the replacement character where its bytes were not UTF-8, so
/// it reads the same as other names and as the one really written so. It
/// is never taken for the name of what was extracted.
fn is_lossy(text: &str) -> bool {
    text.contains(char::REPLACEMENT_CHARACTER)
}

/// `text` as `str::escape_default` wrote it, plain again. Only what that
/// writes is read, and only the one way it writes it, so two texts never
/// read as the same name; anything else is `None`.
fn unescaped(text: &str) -> Option<String> {
    let mut plain = String::with_capacity(text.len());
    let mut rest = text.chars();
    while let Some(character) = rest.next() {
        if character != '\\' {
            plain.push(character);
            continue;
        }
        plain.push(match rest.next()? {
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            '\\' => '\\',
            '\'' => '\'',
            '"' => '"',
            'u' => {
                let (hex, after) = rest.as_str().strip_prefix('{')?.split_once('}')?;
                rest = after.chars();
                char::from_u32(u32::from_str_radix(hex, 16).ok()?)?
            }
            _ => return None,
        });
    }
    (plain.escape_default().to_string() == text).then_some(plain)
}

/// What a later call found different from an `Extraction`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Drift {
    /// The build did not extract into the directory Guardian reviewed.
    Elsewhere,
    /// Downloads that are new or not the ones Guardian fetched.
    Downloads(Vec<String>),
    /// Files new or changed in the source tree, as a build's own
    /// `prepare()` leaves them.
    Files(HashSet<String>),
}

impl Extraction {
    /// Whether this is the record of the sources in `srcdir`.
    pub(super) fn is_of(&self, srcdir: &Path) -> bool {
        !is_lossy(&self.srcdir) && Path::new(&self.srcdir) == srcdir
    }

    /// Compares the sources as they are now with what Guardian extracted.
    pub(super) fn drift(
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
            let kept = known.get(path);
            digest.is_empty()
                || is_lossy(path)
                || kept.map(|kept| short(kept)) != Some(short(digest))
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

    /// The record as it is kept: a line each for the directory, its
    /// identity and whether the build cleans, then one for each download
    /// (`D`) and file (`F`) with its hash and its path. A path is written
    /// escaped, once, here, so that it stays one line of plain ASCII, and
    /// `parse` reads it back as it was.
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

    /// Reads what `to_text` wrote. A record that is cut short, holds a
    /// path not escaped the way `to_text` escapes it, or names a path
    /// twice is no record.
    fn parse(text: &str) -> Option<Self> {
        let mut lines = text.strip_suffix('\n')?.split('\n');
        let mut header =
            |name: &str| -> Option<&str> { lines.next()?.strip_prefix(name)?.strip_prefix(' ') };
        let mut extraction = Self {
            srcdir: unescaped(header("srcdir")?)?,
            identity: Some(header("identity")?)
                .filter(|identity| *identity != "-")
                .map(str::to_string),
            cleanbuild: match header("cleanbuild")? {
                "0" => false,
                "1" => true,
                _ => return None,
            },
            ..Self::default()
        };
        for line in lines {
            let mut fields = line.splitn(3, ' ');
            let (kind, digest, path) = (fields.next()?, fields.next()?, fields.next()?);
            let digest = if digest == "-" { "" } else { digest };
            let entries = match kind {
                "D" => &mut extraction.downloads,
                "F" => &mut extraction.files,
                _ => return None,
            };
            if entries
                .insert(unescaped(path)?, digest.to_string())
                .is_some()
            {
                return None;
            }
        }
        Some(extraction)
    }
}

/// The paths as the record of the binaries keeps them: written so that
/// each stays one line.
fn one_line(entries: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|(path, digest)| (path.escape_default().to_string(), digest.clone()))
        .collect()
}

/// The gate's memory of one package. Without a directory it remembers
/// nothing: every read is empty and every write is dropped.
pub(super) struct State {
    directory: Option<PathBuf>,
    name: String,
}

impl State {
    /// Opens the memory of the package `key` under the review memory's
    /// `root`, creating its directory for the user alone.
    pub(super) fn open(root: Option<&Path>, key: &str) -> Self {
        let directory = root.and_then(|root| {
            let uid = user::effective_uid().ok()?;
            paths::private_dir(root, uid).ok()?;
            let directory = root.join(DIRECTORY);
            match DirBuilder::new().mode(0o700).create(&directory) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return None,
            }
            paths::private_dir(&directory, uid).ok()?;
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
        drop(write_atomic(
            &path,
            text.as_bytes(),
            &AtomicWrite::private(temporary),
        ));
    }

    /// Whether the user said yes to `what` (a hash of exactly what was
    /// asked) for this package before.
    pub(super) fn is_confirmed(&self, what: &str) -> bool {
        self.read("confirmed")
            .is_some_and(|text| text.lines().any(|line| line == what))
    }

    pub(super) fn remember_confirmed(&self, what: &str) {
        let known = self.read("confirmed").unwrap_or_default();
        let mut lines: Vec<&str> = known.lines().filter(|line| *line != what).collect();
        lines.push(what);
        let from = lines.len().saturating_sub(MAX_CONFIRMATIONS);
        self.write("confirmed", &(lines[from..].join("\n") + "\n"));
    }

    /// The binaries the sources held at the last build that passed.
    pub(super) fn binaries(&self) -> Option<BTreeMap<String, String>> {
        let text = self.read("binaries")?;
        text.lines()
            .map(|line| {
                let (digest, path) = line.split_once(' ')?;
                Some((path.to_string(), digest.to_string()))
            })
            .collect()
    }

    pub(super) fn record_binaries(&self, binaries: &BTreeMap<String, String>) {
        let mut text = String::new();
        for (path, digest) in one_line(binaries) {
            let digest = if digest.is_empty() { "-" } else { &digest };
            let _ = writeln!(text, "{digest} {path}");
        }
        self.write("binaries", &text);
    }

    pub(super) fn extraction(&self) -> Option<Extraction> {
        Extraction::parse(&self.read("extraction")?)
    }

    pub(super) fn record_extraction(&self, extraction: &Extraction) {
        self.write("extraction", &extraction.to_text());
    }
}

/// The records a `State` keeps of one package.
const RECORDS: [&str; 3] = ["confirmed", "binaries", "extraction"];

/// Removes what is remembered of the package `key` under the review
/// memory's `root`; returns how many records there were.
pub(super) fn forget(root: &Path, key: &str) -> Result<usize, Error> {
    let name = Sha256::digest(key.as_bytes()).to_string();
    let mut removed = 0;
    for what in RECORDS {
        let path = root.join(DIRECTORY).join(format!("{name}.{what}"));
        match fs::remove_file(&path) {
            Ok(()) => removed += 1,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(Error::Io { path, source }),
        }
    }
    Ok(removed)
}

/// Removes everything the gate remembers under `root`: the files of its
/// directory, which stays. Returns how many there were. A directory that
/// is a link somewhere is left alone.
pub(super) fn forget_all(root: &Path) -> Result<usize, Error> {
    let directory = root.join(DIRECTORY);
    match fs::symlink_metadata(&directory) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => {
            return Err(Error::Refused(format!(
                "{} is not a directory",
                directory.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error).at(&directory),
    }
    let mut removed = 0;
    for entry in fs::read_dir(&directory).at(&directory)? {
        let path = entry.at(&directory)?.path();
        if fs::symlink_metadata(&path).is_ok_and(|metadata| !metadata.is_dir()) {
            fs::remove_file(&path).at(&path)?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// How the binaries now differ from the ones remembered, as names for the
/// user: `(new or changed, gone)`.
pub(super) fn binary_changes(
    known: &BTreeMap<String, String>,
    now: &BTreeMap<String, String>,
) -> (Vec<String>, Vec<String>) {
    let now = one_line(now);
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
mod forget_tests;

#[cfg(test)]
mod record_tests;

#[cfg(test)]
mod tests;
