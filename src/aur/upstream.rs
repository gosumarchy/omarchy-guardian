//! The walk over the unpacked upstream tree: which files the build runs or
//! reads, which archives and images it holds, and what of all that is
//! reviewed within the budget.

use std::collections::{BTreeMap, HashSet};
use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use super::lockfile;
use crate::content::{self, Content};
use crate::engine::baseline::Unread;
use crate::git_state;
use crate::image;
use crate::paths::file_name;
use crate::scan::{Limits, MAX_HASHED_FILE_SIZE, MAX_TEXT_FILE_SIZE};
use crate::sha256::{Digest, Sha256};

/// Upstream text that fits one full review; larger sources are reviewed by
/// their build files only.
pub const FULL_REVIEW_BYTES: u64 = 1024 * 1024;
/// The most text sent when a source is reviewed in part: its build files
/// and scripts first, then its other code, shallowest first.
pub const PARTIAL_REVIEW_BYTES: u64 = 1024 * 1024;
const MAX_DEPTH: usize = 16;
const MAX_ENTRIES: usize = 200_000;
/// Scripts deeper than this are not treated as build files.
const SCRIPT_DEPTH: usize = 3;

/// Version-control metadata, which a build does not run.
const SKIPPED_DIRECTORIES: &[&str] = &[".git", ".hg", ".svn", ".bzr"];
/// The files git itself keeps at the top of its directory.
const GIT_OWN_FILES: &[&str] = &[
    "HEAD",
    "ORIG_HEAD",
    "FETCH_HEAD",
    "MERGE_HEAD",
    "CHERRY_PICK_HEAD",
    "REVERT_HEAD",
    "AUTO_MERGE",
    "COMMIT_EDITMSG",
    "MERGE_MSG",
    "config",
    "config.worktree",
    "commondir",
    "gitdir",
    "description",
    "index",
    "packed-refs",
    "shallow",
    "SQUASH_MSG",
    "TAG_EDITMSG",
    "MERGE_MODE",
    "MERGE_RR",
    "REBASE_HEAD",
    "BISECT_LOG",
    "BISECT_START",
    "BISECT_TERMS",
    "BISECT_EXPECTED_REV",
    "BISECT_NAMES",
    "gc.log",
    "index.lock",
];
/// The most archives named one by one as not unpacked (a Java project
/// ships dozens of jars).
const MAX_ARCHIVES_NAMED: usize = 5;
/// Directories whose code rarely runs during a build: reviewed, but after
/// everything else.
const LATE_DIRECTORIES: &[&str] = &[
    "node_modules",
    "__pycache__",
    ".venv",
    ".github",
    ".gitlab",
    ".circleci",
    ".devcontainer",
    "vendor",
    "third_party",
    "test",
    "tests",
    "doc",
    "docs",
];

/// Files that drive or run during a build.
const BUILD_NAMES: &[&str] = &[
    "makefile",
    "gnumakefile",
    "makefile.in",
    "makefile.am",
    "cmakelists.txt",
    "configure",
    "configure.ac",
    "configure.in",
    "bootstrap",
    "autogen.sh",
    "meson.build",
    "meson_options.txt",
    "meson.options",
    "build.rs",
    "cargo.toml",
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
    "package.json",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
    "pom.xml",
    "rakefile",
    "build.zig",
    "justfile",
    "sconstruct",
    "build",
    "build.bazel",
    "workspace",
    "taskfile.yml",
];
const BUILD_EXTENSIONS: &[&str] = &[
    "mk", "cmake", "m4", "am", "in", "ac", "ninja", "gn", "bzl", "cabal",
];
/// Data and documentation, which neither run nor build anything; left out
/// of the review so the budget goes to code, unless they are build-critical
/// (a shebang, the execute bit, or named by the recipe).
const DATA_EXTENSIONS: &[&str] = &[
    "json", "md", "markdown", "rst", "txt", "csv", "tsv", "svg", "po", "pot", "lock", "sum",
    "adoc", "html", "css",
];
const SCRIPT_EXTENSIONS: &[&str] = &["sh", "bash", "zsh", "py", "pl"];
/// Code a build runs when a build file names it, however deep it lies: a
/// `package.json` script that runs `node tools/a/b/gen.js`, a makefile
/// that runs `lua`, `ruby` or `awk` on a file.
const NAMED_EXTENSIONS: &[&str] = &[
    "js", "mjs", "cjs", "ts", "lua", "rb", "php", "awk", "inc", "py", "pl", "sh", "bash", "zsh",
];
/// Words a makefile reads another file in with.
const INCLUDES: &[&str] = &["include", "-include", "sinclude"];
/// Manifests deeper than this, or under a directory of bundled code, are a
/// dependency's own and say nothing about what this build downloads.
const MANIFEST_DEPTH: usize = 3;
/// The most archives Guardian unpacks itself for one build.
pub const MAX_UNPACKED_ARCHIVES: usize = 8;

/// Why a text file was not sent for review.
pub const NOT_REVIEWED_DATA: &str =
    "data or documentation, which Guardian does not send for review";
pub const NOT_REVIEWED_BUDGET: &str = "left out past the review budget";
pub const NOT_REVIEWED_LOCKFILE: &str =
    "a lockfile too large to send, which Guardian scanned itself for where it fetches from";
const NOT_UNPACKED: &str =
    "an archive that is not unpacked for review: what the build takes from it is not reviewed";

/// One upstream text file, by its path under the build directory's `src/`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamFile {
    pub path: String,
    pub text: String,
    depth: usize,
    /// Build-critical: must be reviewed, or the review is incomplete.
    critical: bool,
    /// Under a directory whose code rarely runs during a build.
    late: bool,
    /// New or changed since Guardian extracted the sources itself.
    changed: bool,
}

/// An archive among the sources that makepkg did not unpack: the build
/// opens it itself, if at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Archive {
    /// Its path under `src/`.
    pub rel: String,
    /// Where its bytes are.
    pub file: PathBuf,
    /// The recipe names it (`noextract`, or by its name in a function), so
    /// the build certainly opens it.
    pub named: bool,
}

/// A data file kept back from the review, which is read after all if a
/// build file turns out to name it.
struct DataFile {
    child: String,
    read_from: PathBuf,
    depth: usize,
    late: bool,
}

/// What was taken from the extracted sources for the review.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Upstream {
    pub files: Vec<UpstreamFile>,
    /// Every text file was taken and nothing was omitted.
    pub whole: bool,
    /// Text files left out past the budget (never build-critical ones).
    pub left_out: usize,
    /// Text files other than data and documentation.
    pub text_files: usize,
    /// Data and documentation files, not reviewed.
    pub data_files: usize,
    /// Binary files, which cannot be reviewed.
    pub binary_files: usize,
    /// Executable binaries (up to 20), named to the AI.
    pub executables: Vec<String>,
    /// The binary files with their hashes, for the review memory (see
    /// `baseline::Unread`).
    pub unread: Unread,
    /// Links to recipe files, which the recipe review covered.
    pub recipe_links: usize,
    /// Files skipped without harm to the review, with the reason.
    pub omitted: Vec<(String, &'static str)>,
    /// Build-critical files that could not be reviewed: the review is
    /// incomplete.
    pub gaps: Vec<String>,
    /// Whether `src` existed and had entries.
    pub found: bool,
    /// Text files that were not sent for review, by path, with why: data
    /// and documentation, and code past the budget. A reviewed line that
    /// runs or reads one in makes the review incomplete.
    pub unreviewed: Vec<(String, &'static str)>,
    /// Every program among the binaries (ELF and the like), with its hash.
    pub programs: BTreeMap<String, String>,
    /// Every file the walk read, with its hash: what the sources were when
    /// Guardian looked.
    pub seen: BTreeMap<String, String>,
    /// The downloaded files makepkg linked into `src/`, with their hashes.
    pub downloads: BTreeMap<String, String>,
    /// What a local scan of each lockfile found, in Guardian's words.
    pub lockfiles: Vec<String>,
    /// The ecosystems whose manifests or lockfiles the sources hold.
    pub ecosystems: Vec<lockfile::Ecosystem>,
    /// Archives Guardian unpacked itself and reviewed like the rest.
    pub unpacked: Vec<String>,
    /// Files new or changed since Guardian extracted the sources: how many
    /// there are, and how many of them were sent for review.
    pub changed: (usize, usize),
}

impl Upstream {
    /// Whether the file at `path` came out of an archive Guardian unpacked
    /// itself. A directory of the sources whose own name ends in `!` is
    /// not one.
    pub fn is_unpacked(&self, path: &str) -> bool {
        self.unpacked.iter().any(|archive| {
            path.strip_prefix(archive.as_str())
                .is_some_and(|inside| inside.starts_with("!/"))
        })
    }
}

/// File names of what is installed and run as it comes, whatever its
/// bytes look like: an archive of code (a Java archive, an Electron
/// application, a browser extension) or a package for another packager.
const CODE_ARCHIVES: &[&str] = &[
    "jar", "war", "ear", "aar", "apk", "asar", "deb", "rpm", "whl", "egg", "gem", "nupkg", "phar",
    "pex", "pyz", "xpi", "crx", "vsix", "appimage", "snap", "flatpak", "msi",
];

/// Whether the file `name` is code nobody reviewed by its name alone (see
/// `CODE_ARCHIVES`), or a built pacman package.
fn carries_code(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains(".pkg.tar")
        || lower
            .rsplit_once('.')
            .is_some_and(|(_, extension)| CODE_ARCHIVES.contains(&extension))
}

/// Where makepkg keeps what a build uses: the recipe directory, and the
/// download directory (`SRCDEST`), which `src/` links into.
pub struct Roots<'a> {
    pub build_dir: &'a Path,
    pub srcdest: Option<&'a Path>,
}

fn is_build_file(name: &str, depth: usize, text: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let extension = lower
        .rsplit_once('.')
        .map_or("", |(_, extension)| extension);
    BUILD_NAMES.contains(&lower.as_str())
        || BUILD_EXTENSIONS.contains(&extension)
        || (depth <= SCRIPT_DEPTH
            && (SCRIPT_EXTENSIONS.contains(&extension) || text.starts_with("#!")))
}

/// A file the build certainly runs or that the recipe refers to.
fn is_critical(name: &str, depth: usize, text: &str, executable: bool, recipe: &str) -> bool {
    is_build_file(name, depth, text)
        || text.starts_with("#!")
        || executable
        || (name.len() >= 4 && recipe.contains(name))
}

struct Walk<'a> {
    src: PathBuf,
    /// What the paths under `src` start with: nothing for `src/` itself,
    /// `demo/data.tar.xz!` for an archive Guardian unpacked.
    start: String,
    /// The depth `src` counts as: a link at the top of `src/` is one of
    /// makepkg's own, one at the top of an unpacked archive is not.
    base_depth: usize,
    /// The listing's `noextract` names.
    noextract: &'a [String],
    /// What the recipe gives to commands that unpack (`unpack_patterns`).
    unpacks: Vec<String>,
    archives: Vec<Archive>,
    data: Vec<DataFile>,
    roots: &'a Roots<'a>,
    recipe: &'a str,
    visited: usize,
    max_entries: usize,
    stopped: bool,
    /// Bytes of large binaries hashed from disk.
    hashed_bytes: u64,
    /// The file being read is a top-level link to a downloaded source.
    download: bool,
    all: Vec<UpstreamFile>,
    upstream: Upstream,
    /// Directories laid out as git repositories under another name.
    git_dirs: HashSet<PathBuf>,
    /// Where files are run in the sources (see `Collected::surroundings`).
    surroundings: image::Surroundings,
    /// The whole images, with their hashes (see `Collected::images`).
    images: Vec<(String, String)>,
}

impl Walk<'_> {
    /// Notes what the walk saw of one file: its hash, for telling later
    /// whether the build's sources are still the ones Guardian looked at.
    /// A file too large to hash is told by its size and when it was last
    /// written, which an extraction of the same archive gives it again.
    fn note(&mut self, child: &str, read_from: &Path, digest: Option<&Digest>) {
        let written = |found: fs::Metadata| {
            format!(
                "size-{}-{}-{}",
                found.len(),
                found.mtime(),
                found.mtime_nsec()
            )
        };
        let digest = match digest {
            Some(digest) => digest.to_string(),
            None => fs::metadata(read_from).map(written).unwrap_or_default(),
        };
        if self.download {
            self.upstream
                .downloads
                .insert(child.to_string(), digest.clone());
        }
        self.upstream.seen.insert(format!("src/{child}"), digest);
    }

    /// A lockfile is read here for where it fetches from, whatever its
    /// size (see `lockfile`). Returns whether it is small enough to be
    /// sent whole as well.
    fn lockfile(&mut self, child: &str, ecosystem: lockfile::Ecosystem, text: &str) -> bool {
        let scan = lockfile::scan(ecosystem, text);
        self.upstream
            .lockfiles
            .push(format!("src/{child}: {}", scan.summary(ecosystem)));
        let whole = text.len() <= lockfile::WHOLE_BYTES;
        if !whole {
            self.upstream
                .unreviewed
                .push((format!("src/{child}"), NOT_REVIEWED_LOCKFILE));
        }
        whole
    }

    /// A text file too large to read whole.
    fn large(&mut self, read_from: &Path, child: &str, name: &str, critical: bool) {
        let digest = self.hash_file(read_from);
        self.note(child, read_from, digest.as_ref());
        if let Some(ecosystem) = lockfile::lockfile(name) {
            let mut bytes = Vec::new();
            let read = fs::File::open(read_from).and_then(|file| {
                file.take(lockfile::MAX_SCANNED_BYTES + 1)
                    .read_to_end(&mut bytes)
            });
            if read.is_ok() && bytes.len() as u64 <= lockfile::MAX_SCANNED_BYTES {
                self.lockfile(child, ecosystem, &String::from_utf8_lossy(&bytes));
                return;
            }
            // Not read at all: where it fetches from is not known.
            self.upstream.gaps.push(format!(
                "src/{child}: a lockfile too large to read (over 64 MiB) says where dependencies come from"
            ));
            return;
        }
        if critical {
            self.upstream.gaps.push(format!(
                "src/{child}: a build file larger than 2 MiB cannot be reviewed"
            ));
        } else {
            self.upstream
                .omitted
                .push((child.to_string(), "larger than 2 MiB"));
        }
    }

    fn file(&mut self, read_from: &Path, child: &str, name: &str, depth: usize, late: bool) {
        let Ok(metadata) = fs::metadata(read_from) else {
            self.upstream
                .omitted
                .push((child.to_string(), "unreadable"));
            return;
        };
        let executable = metadata.mode() & 0o111 != 0;
        self.surroundings
            .note_file(&format!("src/{child}"), executable);
        let name_critical = is_critical(name, depth, "", executable, self.recipe);
        if !late
            && depth <= MANIFEST_DEPTH
            && let Some(ecosystem) = lockfile::manifest(name)
            && !self.upstream.ecosystems.contains(&ecosystem)
        {
            self.upstream.ecosystems.push(ecosystem);
        }
        if metadata.len() > MAX_TEXT_FILE_SIZE {
            let prefix = fs::File::open(read_from)
                .and_then(|file| {
                    let mut head = Vec::new();
                    file.take(content::PROBE_SIZE as u64)
                        .read_to_end(&mut head)?;
                    Ok(head)
                })
                .unwrap_or_default();
            match content::classify_prefix(child, executable, &prefix) {
                content::Prefix::Binary(format) => {
                    self.binary(child, format, executable, read_from, None);
                }
                _ => self.large(read_from, child, name, name_critical),
            }
            return;
        }
        let Ok(bytes) = fs::read(read_from) else {
            self.upstream
                .omitted
                .push((child.to_string(), "unreadable"));
            return;
        };
        let text = match content::classify(child, executable, false, &bytes) {
            Content::Text(text) | Content::Lossy { text, .. } => text,
            Content::Binary(format) => {
                return self.binary(child, format, executable, read_from, Some(&bytes));
            }
            Content::Undecodable => {
                self.note(child, read_from, Some(&Sha256::digest(&bytes)));
                if name_critical {
                    self.upstream.gaps.push(format!(
                        "src/{child}: a build file or script holds binary data"
                    ));
                } else {
                    self.upstream
                        .omitted
                        .push((child.to_string(), "binary data"));
                }
                return;
            }
        };
        self.note(child, read_from, Some(&Sha256::digest(&bytes)));
        let mut critical = is_critical(name, depth, &text, executable, self.recipe);
        if let Some(ecosystem) = lockfile::lockfile(name) {
            // Read here whatever its size; sent as well when it is small.
            if !self.lockfile(child, ecosystem, &text) {
                return;
            }
            critical = true;
        }
        let data = !critical
            && name
                .to_ascii_lowercase()
                .rsplit_once('.')
                .is_some_and(|(_, extension)| DATA_EXTENSIONS.contains(&extension));
        if data {
            self.upstream.data_files += 1;
            self.data.push(DataFile {
                child: child.to_string(),
                read_from: read_from.to_path_buf(),
                depth,
                late,
            });
            return;
        }
        self.all.push(UpstreamFile {
            path: format!("src/{child}"),
            text,
            depth,
            critical,
            late,
            changed: false,
        });
    }
    /// `bytes` is the whole file when it was read; a larger one is hashed
    /// from disk, and one that cannot be is listed without a hash, which
    /// no approved version matches.
    fn binary(
        &mut self,
        child: &str,
        format: content::Format,
        executable: bool,
        read_from: &Path,
        bytes: Option<&[u8]>,
    ) {
        let digest = match bytes {
            Some(bytes) => Some(Sha256::digest(bytes)),
            None => self.hash_file(read_from),
        };
        // A whole image away from where files are run is not the review
        // memory's concern (see `review::is_plain_image_among`), nor is a
        // downloaded archive: what it
        // unpacks to is what is reviewed, and its name changes with every
        // version. A downloaded program is.
        let image = !executable
            && format.is_media()
            && image::is_named(child)
            && match (bytes, &digest) {
                (Some(bytes), _) => image::is_whole(bytes),
                (None, Some(digest)) => image::is_whole_file(read_from, digest),
                (None, None) => false,
            };
        let is_archive = format.label().contains("archive");
        let archive = self.download && is_archive;
        // An archive makepkg was told not to unpack, or one inside the
        // sources, is opened by the build itself if at all. Guardian
        // unpacks the ones the recipe names (see `Collected::to_unpack`);
        // of the others the review says that they are not reviewed.
        let name = file_name(child);
        if is_archive && (!self.download || self.not_extracted(name)) {
            let inside = child[self.start.len()..].trim_start_matches('/');
            let top_of_unpacked = self.base_depth > 0 && !inside.contains('/');
            self.archives.push(Archive {
                rel: child.to_string(),
                file: read_from.to_path_buf(),
                named: self.download
                    || top_of_unpacked
                    || names_file(self.recipe, name)
                    || self
                        .unpacks
                        .iter()
                        .any(|pattern| matches_pattern(pattern, name)),
            });
        }
        self.note(child, read_from, digest.as_ref());
        let digest = digest.map(|digest| digest.to_string()).unwrap_or_default();
        // A download makepkg unpacks is reviewed as what comes out of it.
        let packaged = name
            .rsplit_once('.')
            .is_some_and(|(_, extension)| matches!(extension, "deb" | "rpm"));
        let unpacked_by_makepkg =
            self.download && !self.not_extracted(name) && (is_archive || packaged);
        if format.executable() || (carries_code(name) && !unpacked_by_makepkg) {
            self.upstream
                .programs
                .insert(format!("src/{child}"), digest.clone());
        }
        if image && !archive {
            // Whether it is passed over is known once the walk has seen
            // what stands around it (see `Collected::settle_images`).
            self.images.push((format!("src/{child}"), digest));
        } else if !archive {
            self.upstream.unread.insert(format!("src/{child}"), digest);
        }
        self.upstream.binary_files += 1;
        if format.executable() && self.upstream.executables.len() < 20 {
            self.upstream
                .executables
                .push(format!("src/{child} ({})", format.label()));
        }
    }

    /// Whether makepkg was told not to unpack the download `name`: the
    /// listing's `noextract` names it, or the recipe's names it or
    /// something through a variable, which could be any download.
    fn not_extracted(&self, name: &str) -> bool {
        self.noextract.iter().any(|listed| listed == name)
            || self.recipe.split("noextract").skip(1).any(|rest| {
                rest.split(')')
                    .next()
                    .is_some_and(|list| list.contains(name) || list.contains('$'))
            })
    }

    /// The hash of a large binary, within the limits a scan hashes under.
    fn hash_file(&mut self, path: &Path) -> Option<Digest> {
        let mut file = fs::File::open(path).ok()?;
        let size = file.metadata().ok()?.len();
        self.hashed_bytes = self.hashed_bytes.saturating_add(size);
        if size > MAX_HASHED_FILE_SIZE || self.hashed_bytes > Limits::DEFAULT.hashed_bytes {
            return None;
        }
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            match file.read(&mut buffer).ok()? {
                0 => return Some(hasher.finalize()),
                count => hasher.update(&buffer[..count]),
            }
        }
    }

    /// makepkg links every downloaded or local file source into `src/`.
    fn link(&mut self, path: &Path, child: &str, name: &str, depth: usize, late: bool) {
        let target = fs::canonicalize(path).ok();
        let inside = |root: Option<&Path>| {
            root.and_then(|root| fs::canonicalize(root).ok())
                .zip(target.as_ref())
                .is_some_and(|(root, target)| target.starts_with(root))
        };
        let file = target.as_ref().is_some_and(|target| target.is_file());
        if file && (inside(Some(&self.src)) || inside(self.roots.srcdest)) {
            if let Some(target) = target.clone() {
                // makepkg links a source under its own name, by its full
                // path. Any other link at the top (one `prepare()` made to
                // a file beside the recipe) is a file of the sources, not
                // a download.
                let as_makepkg = fs::read_link(path).is_ok_and(|written| {
                    written.is_absolute() && written.file_name() == Some(OsStr::new(name))
                });
                self.download = depth == 0 && !inside(Some(&self.src)) && as_makepkg;
                self.file(&target, child, name, depth, late);
                self.download = false;
            }
        } else if file && inside(Some(self.roots.build_dir)) {
            self.upstream.recipe_links += 1;
        } else if depth == 0 || is_build_file(name, depth, "") {
            self.upstream.gaps.push(format!(
                "src/{child}: a link to something outside the build that cannot be reviewed"
            ));
        } else {
            self.upstream
                .omitted
                .push((child.to_string(), "link outside the build"));
        }
    }

    /// A version-control directory in the sources is not source, but git
    /// and Mercurial run what its configuration and hooks say on the
    /// commands a build often runs (`git describe`, `git status`). A
    /// checkout makepkg made has neither; an unpacked archive can ship
    /// both.
    fn version_control(&mut self, directory: &Path, child: &str, name: &str, depth: usize) {
        match name {
            ".git" => {
                self.git_directory(directory, child, 0);
                // A file git does not keep there is one a build put, or
                // would read, there: it is reviewed like any other.
                let mut extra: Vec<_> = fs::read_dir(directory)
                    .map(|entries| entries.flatten().collect())
                    .unwrap_or_default();
                extra.sort_by_key(fs::DirEntry::file_name);
                for entry in extra {
                    if self.stopped {
                        break;
                    }
                    let file_name = entry.file_name().to_string_lossy().into_owned();
                    if GIT_OWN_FILES.contains(&file_name.as_str()) {
                        continue;
                    }
                    self.visited += 1;
                    if self.visited > self.max_entries {
                        self.upstream.gaps.push(format!(
                            "the sources have more than {} entries; the rest cannot be reviewed",
                            self.max_entries
                        ));
                        self.stopped = true;
                        break;
                    }
                    if fs::symlink_metadata(entry.path()).is_ok_and(|metadata| metadata.is_file()) {
                        self.file(
                            &entry.path(),
                            &format!("{child}/{file_name}"),
                            &file_name,
                            depth + 1,
                            false,
                        );
                    }
                }
            }
            ".hg" => {
                let text = fs::read(directory.join("hgrc"))
                    .map(|bytes| String::from_utf8_lossy(&bytes).to_lowercase())
                    .unwrap_or_default();
                if text.lines().map(str::trim).any(|line| {
                    [
                        "[hooks]",
                        "[extensions]",
                        "[alias]",
                        "[extdiff]",
                        "[merge-tools]",
                        "%include",
                    ]
                    .iter()
                    .any(|section| line.starts_with(section))
                }) {
                    self.upstream.gaps.push(format!(
                        "src/{child}: its hgrc sets hooks, extensions or aliases Mercurial runs, or includes another file"
                    ));
                }
            }
            _ => {}
        }
    }

    /// A submodule's git directory under `modules`, or, for a submodule at
    /// a nested path (`vendor/lib`), the directories on the way to it.
    fn git_module(&mut self, directory: &Path, child: &str, depth: usize) {
        if depth >= MAX_DEPTH {
            self.upstream.gaps.push(format!(
                "src/{child}: submodule directories nested too deep to review"
            ));
            return;
        }
        // A submodule named `a/b` lives below the one named `a`, so a git
        // directory is looked into as well.
        let is_git = ["HEAD", "config"]
            .iter()
            .any(|part| fs::symlink_metadata(directory.join(part)).is_ok());
        if is_git {
            self.git_directory(directory, child, depth);
        }
        let Ok(entries) = fs::read_dir(directory) else {
            self.upstream
                .gaps
                .push(format!("src/{child}: a submodule directory cannot be read"));
            return;
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let name = entry.file_name().to_string_lossy().into_owned();
            if is_git && git_state::OWN_DIRECTORIES.contains(&name.as_str()) {
                continue;
            }
            let shown = format!("{child}/{}", name.escape_debug());
            match fs::symlink_metadata(entry.path()) {
                Ok(metadata) if metadata.is_dir() => {
                    self.git_module(&entry.path(), &shown, depth + 1);
                }
                // Inside a git directory only a link to a directory can
                // be a submodule (an old `HEAD` is a link to a file).
                Ok(metadata)
                    if metadata.file_type().is_symlink()
                        && (!is_git
                            || fs::metadata(entry.path()).is_ok_and(|target| target.is_dir())) =>
                {
                    self.upstream.gaps.push(format!(
                        "src/{shown}: a linked submodule cannot be reviewed"
                    ));
                }
                _ => {}
            }
        }
    }

    /// The checks of one git directory: `.git` itself, and each submodule
    /// kept under its `modules`, which git enters on `status` too.
    fn git_directory(&mut self, directory: &Path, child: &str, depth: usize) {
        let mut gap = |what: String| {
            self.upstream.gaps.push(format!("src/{child}: {what}"));
        };
        if fs::symlink_metadata(directory.join("commondir")).is_ok() {
            gap(
                "its commondir makes git read the configuration and hooks of another directory"
                    .into(),
            );
        }
        for config in ["config", "config.worktree"] {
            let path = directory.join(config);
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                continue;
            };
            let text = (metadata.is_file() && metadata.len() <= MAX_TEXT_FILE_SIZE)
                .then(|| fs::read(&path).ok())
                .flatten()
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
            match text {
                Some(text) => {
                    if let Some((line, _)) = git_state::executing_keys(&text).first() {
                        gap(format!(
                            "its {config} names a command git runs, or another address for git to fetch from (line {line})"
                        ));
                    }
                }
                None => gap(format!(
                    "its {config} cannot be read as a git configuration"
                )),
            }
        }
        let hooks = directory.join("hooks");
        match fs::symlink_metadata(&hooks) {
            Ok(metadata) if metadata.is_dir() => {
                let live = fs::read_dir(&hooks).map(|entries| {
                    entries
                        .flatten()
                        .any(|entry| !entry.file_name().to_string_lossy().ends_with(".sample"))
                });
                if live.unwrap_or(true) {
                    gap("it holds hooks git runs (a checkout gets them from a git template directory, an archive brings its own)".into());
                }
            }
            Ok(_) => gap("its hooks are not a directory".into()),
            Err(_) => {}
        }
        let modules = directory.join("modules");
        match fs::symlink_metadata(&modules) {
            Ok(metadata) if metadata.is_dir() && depth < MAX_DEPTH => {
                let Ok(entries) = fs::read_dir(&modules) else {
                    return gap("its submodules cannot be listed".into());
                };
                let mut names: Vec<_> = entries.flatten().map(|entry| entry.file_name()).collect();
                names.sort();
                for name in names {
                    let submodule = modules.join(&name);
                    let shown =
                        format!("{child}/modules/{}", name.to_string_lossy().escape_debug());
                    match fs::symlink_metadata(&submodule) {
                        Ok(metadata) if metadata.is_dir() => {
                            self.git_module(&submodule, &shown, depth + 1);
                        }
                        // Git follows a link here; the checks do not.
                        Ok(metadata) if metadata.file_type().is_symlink() => {
                            self.upstream.gaps.push(format!(
                                "src/{shown}: a linked submodule cannot be reviewed"
                            ));
                        }
                        _ => {}
                    }
                }
            }
            Ok(_) => gap("its submodules are not a directory, or are nested too deep".into()),
            Err(_) => {}
        }
    }

    fn walk(&mut self) {
        let mut pending = vec![(self.src.clone(), self.start.clone(), self.base_depth, false)];
        while let Some((directory, rel, depth, late)) = pending.pop() {
            if self.stopped {
                return;
            }
            let Ok(entries) = fs::read_dir(&directory) else {
                self.upstream
                    .gaps
                    .push(format!("src/{rel}: unreadable directory"));
                continue;
            };
            let mut entries: Vec<_> = entries.flatten().collect();
            entries.sort_by_key(fs::DirEntry::file_name);
            for entry in entries {
                self.visited += 1;
                if self.visited > self.max_entries {
                    self.upstream.gaps.push(format!(
                        "the sources have more than {} entries; the rest cannot be reviewed",
                        self.max_entries
                    ));
                    self.stopped = true;
                    return;
                }
                self.upstream.found = true;
                // A name that is not UTF-8 is read all the same, as a build
                // reads it, and shown with the bytes that are no text
                // written out (`caf\xe9.c`), so that two such names stay
                // two: nothing under such a name is passed over.
                let name = match entry.file_name().to_str() {
                    Some(name) => name.to_string(),
                    None => entry
                        .file_name()
                        .as_encoded_bytes()
                        .escape_ascii()
                        .to_string(),
                };
                let child = if rel.is_empty() {
                    name.clone()
                } else {
                    format!("{rel}/{name}")
                };
                let Ok(metadata) = fs::symlink_metadata(entry.path()) else {
                    continue;
                };
                // A `.git` that is a file or a link points git at a
                // directory of its own choosing, wherever that is.
                if name == ".git" && !metadata.is_dir() {
                    self.upstream.gaps.push(format!(
                        "src/{child}: a git directory given as a file or a link cannot be reviewed"
                    ));
                    continue;
                }
                if metadata.file_type().is_symlink() {
                    self.link(&entry.path(), &child, &name, depth, late);
                } else if metadata.is_dir() {
                    if SKIPPED_DIRECTORIES.contains(&name.as_str()) {
                        self.version_control(&entry.path(), &child, &name, depth);
                        // git's own directory is its objects and state,
                        // read above for what git would run from it. The
                        // others are walked like any directory: a build
                        // can read a file from there as from anywhere.
                        if name == ".git" {
                            continue;
                        }
                    } else if ["HEAD", "objects", "refs"]
                        .iter()
                        .all(|part| fs::symlink_metadata(entry.path().join(part)).is_ok())
                    {
                        // Laid out as a git repository under another name
                        // (a bare one, or where a `commondir` points).
                        self.git_directory(&entry.path(), &child, 0);
                        self.git_dirs.insert(entry.path());
                    }
                    if depth + 1 >= MAX_DEPTH {
                        self.upstream
                            .gaps
                            .push(format!("src/{child}: nested too deep to review"));
                        continue;
                    }
                    // Another tool's metadata holds a copy of every file:
                    // it comes after the sources themselves.
                    let late = late
                        || LATE_DIRECTORIES.contains(&name.as_str())
                        || SKIPPED_DIRECTORIES.contains(&name.as_str());
                    pending.push((entry.path(), child, depth + 1, late));
                } else if metadata.is_file() {
                    // Such a directory's configuration, checked above as
                    // git reads it, is reviewed like any file without the
                    // tokens its remote addresses may carry.
                    let git_config = matches!(name.as_str(), "config" | "config.worktree")
                        && self.git_dirs.contains(&directory);
                    let before = self.all.len();
                    self.file(&entry.path(), &child, &name, depth, late);
                    if git_config {
                        for file in &mut self.all[before..] {
                            file.text = git_state::without_url_credentials(&file.text);
                        }
                    }
                }
            }
        }
    }
}

/// Whether `recipe` names the file `name`: by its whole name, or by its
/// name up to the last extension (`data.tar.` for `data.tar.zst`, as in
/// `tar xf data.tar.*`).
fn names_file(recipe: &str, name: &str) -> bool {
    let stem = name.rsplit_once('.').map_or(name, |(stem, _)| stem);
    name.len() >= 4 && (recipe.contains(name) || (stem.len() >= 5 && recipe.contains(stem)))
}

/// Commands that open an archive they are given.
const UNPACKERS: &[&str] = &[
    "bsdtar",
    "tar",
    "unzip",
    "7z",
    "7za",
    "7zr",
    "unrar",
    "unar",
    "gunzip",
    "gzip",
    "unxz",
    "xz",
    "unzstd",
    "zstd",
    "bunzip2",
    "bzip2",
    "ar",
    "cpio",
    "bsdcpio",
    "dpkg-deb",
    "rpm2cpio",
    "rpmextract.sh",
    "unsquashfs",
    "jar",
    "asar",
];

/// The files a recipe gives to a command that unpacks, by name as written:
/// `bsdtar -xf data.tar.xz`, `tar xf "$srcdir"/payload-*.tar.gz`. A name
/// may hold `*` or a variable, which stand for anything.
pub fn unpack_patterns(recipe: &str) -> Vec<String> {
    let mut patterns = Vec::new();
    for line in recipe.lines() {
        let mut words = line
            .split(|c: char| c.is_whitespace() || matches!(c, ';' | '|' | '&' | '(' | ')' | '<'))
            .map(|word| word.trim_matches(['"', '\'']))
            .skip_while(|word| !UNPACKERS.contains(&file_name(word)));
        if words.next().is_none() {
            continue;
        }
        // The word after these options is where to unpack to.
        let mut is_directory = false;
        for word in words.filter(|word| !word.is_empty()) {
            if std::mem::take(&mut is_directory) {
                continue;
            }
            if word.starts_with('-') {
                is_directory = matches!(word, "-C" | "-d" | "--directory" | "-o");
                continue;
            }
            let name = word.replace(['"', '\''], "");
            let name = file_name(&name);
            // An option's letters (`xf`) and makepkg's directories are no
            // archive.
            let directory = ["pkgdir", "srcdir", "startdir"]
                .iter()
                .any(|known| name.trim_matches(['$', '{', '}']) == *known);
            if name.contains(['.', '$', '*'])
                && !directory
                && !patterns.iter().any(|known| known == name)
            {
                patterns.push(name.to_string());
            }
        }
    }
    patterns
}

/// Whether the file name `name` is one `pattern` stands for (see
/// `unpack_patterns`).
pub(super) fn matches_pattern(pattern: &str, name: &str) -> bool {
    // Variables become `*`.
    let mut plain = String::new();
    let mut characters = pattern.chars().peekable();
    while let Some(character) = characters.next() {
        if character != '$' {
            plain.push(if character == '?' { '*' } else { character });
            continue;
        }
        plain.push('*');
        if characters.next_if_eq(&'{').is_some() {
            for skipped in characters.by_ref() {
                if skipped == '}' {
                    break;
                }
            }
        } else {
            while characters
                .next_if(|next| next.is_ascii_alphanumeric() || *next == '_')
                .is_some()
            {}
        }
    }
    let parts: Vec<&str> = plain.split('*').collect();
    let (Some(first), Some(last)) = (parts.first(), parts.last()) else {
        return false;
    };
    if parts.len() == 1 {
        return name == *first;
    }
    if !name.starts_with(first) || !name[first.len()..].ends_with(last) {
        return false;
    }
    let mut rest = &name[first.len()..name.len() - last.len()];
    parts[1..parts.len() - 1]
        .iter()
        .all(|part| match rest.find(part) {
            Some(at) => {
                rest = &rest[at + part.len()..];
                true
            }
            None => false,
        })
}

/// The files the lines of a recipe file run or read in as code, as (line
/// number, the line, the file as written without what a variable or `./`
/// puts before it): `./helper`, `sh "$srcdir/tools/gen.sh"`.
pub fn recipe_runs(text: &str, variables: &[(String, String)]) -> Vec<(usize, String, String)> {
    let mut runs = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let written = crate::rules::with_variables(line, variables);
        for target in crate::rules::run_targets(&written) {
            let path = named_path(&target);
            if !path.is_empty() {
                runs.push((index + 1, line.trim().chars().take(200).collect(), path));
            }
        }
    }
    runs
}

/// Whether the file at `path` (under `src/`, or inside an archive under
/// it) is the one a recipe writes as `target`: the recipe's functions move
/// between directories of the sources, so any directory may stand before.
pub fn is_target(path: &str, target: &str) -> bool {
    let inside = path.rsplit_once("!/").map_or(path, |(_, inside)| inside);
    [path, inside].iter().any(|path| {
        path.strip_suffix(target)
            .is_some_and(|before| before.is_empty() || before.ends_with('/'))
    })
}

/// A path as a build file writes it, without what stands before it there:
/// `./`, `../`, and parts given by a variable (`$(srcdir)/tools/gen.js`).
fn named_path(word: &str) -> String {
    word.split('/')
        .skip_while(|part| matches!(*part, "" | "." | "..") || part.contains(['$', '@']))
        .collect::<Vec<_>>()
        .join("/")
}

/// The files the build files in `files` name: code by its extension
/// wherever it stands, and whatever a makefile reads in with `include`.
fn named_by_build_files(files: &[UpstreamFile]) -> (HashSet<String>, HashSet<String>) {
    let mut code = HashSet::new();
    let mut included = HashSet::new();
    let part = |c: char| c.is_ascii_alphanumeric() || "._/-+$@{}()".contains(c);
    for file in files.iter().filter(|file| file.critical) {
        for line in file.text.lines() {
            let mut words = line.split_whitespace();
            if words.next().is_some_and(|first| INCLUDES.contains(&first)) {
                included.extend(words.map(named_path).filter(|path| !path.is_empty()));
            }
            for word in line.split(|c: char| !part(c)) {
                let word = word.trim_matches(['(', ')', '{', '}']);
                let extension = word
                    .rsplit_once('.')
                    .map(|(_, extension)| extension.to_ascii_lowercase());
                if extension.is_some_and(|extension| NAMED_EXTENSIONS.contains(&extension.as_str()))
                {
                    let path = named_path(word);
                    if !path.is_empty() {
                        code.insert(path);
                    }
                }
            }
        }
    }
    (code, included)
}

/// Whether the file at `path` (under `src/`) is one `named` holds: by its
/// whole path under some directory, as a build file writes it.
fn is_named(path: &str, named: &HashSet<String>) -> bool {
    let mut rest = path;
    // Every tail of the path: `a/b/c.js`, `b/c.js`, `c.js`.
    loop {
        if named.contains(rest) {
            return true;
        }
        match rest.split_once('/') {
            Some((_, tail)) => rest = tail,
            None => return false,
        }
    }
}

/// What a walk of the sources found, before it is decided what of it is
/// sent for review: Guardian may still unpack archives into it and mark
/// what changed since an earlier look.
pub struct Collected {
    all: Vec<UpstreamFile>,
    data: Vec<DataFile>,
    archives: Vec<Archive>,
    upstream: Upstream,
    max_entries: usize,
    /// Where files are run in the whole source tree, what Guardian
    /// unpacked included: the scripts every walk came by.
    surroundings: image::Surroundings,
    /// The images that are whole by their own bytes, with their hashes:
    /// kept until every walk is done, since a script beside one may be
    /// read after it.
    images: Vec<(String, String)>,
}

impl Collected {
    /// Walks `src`, whose paths start with `start`, into what is collected.
    fn walk(
        &mut self,
        src: &Path,
        start: String,
        roots: &Roots<'_>,
        recipe: &str,
        noextract: &[String],
    ) {
        let mut walk = Walk {
            src: src.to_path_buf(),
            base_depth: usize::from(!start.is_empty()),
            start,
            noextract,
            unpacks: unpack_patterns(recipe),
            archives: std::mem::take(&mut self.archives),
            data: std::mem::take(&mut self.data),
            roots,
            recipe,
            visited: 0,
            max_entries: self.max_entries,
            stopped: false,
            hashed_bytes: 0,
            download: false,
            all: std::mem::take(&mut self.all),
            upstream: std::mem::take(&mut self.upstream),
            git_dirs: HashSet::new(),
            surroundings: std::mem::take(&mut self.surroundings),
            images: std::mem::take(&mut self.images),
        };
        if src.is_dir() {
            walk.walk();
        }
        self.surroundings = walk.surroundings;
        self.images = walk.images;
        self.all = walk.all;
        self.data = walk.data;
        self.archives = walk.archives;
        self.upstream = walk.upstream;
    }

    /// The archives Guardian should unpack itself: the ones the recipe
    /// names, at most one archive deep inside another.
    pub fn to_unpack(&self) -> Vec<Archive> {
        self.archives
            .iter()
            .filter(|archive| archive.named && archive.rel.matches('!').count() < 2)
            .take(MAX_UNPACKED_ARCHIVES.saturating_sub(self.upstream.unpacked.len()))
            .cloned()
            .collect()
    }

    /// Takes in what Guardian unpacked of `archive` into `unpacked`: its
    /// files are reviewed like the rest of `src/`, under the archive's
    /// path followed by `!`.
    pub fn add_unpacked(
        &mut self,
        archive: &Archive,
        unpacked: &Path,
        roots: &Roots<'_>,
        recipe: &str,
    ) {
        self.archives.retain(|known| known.rel != archive.rel);
        // Its files are named `archive!/...`: a directory of that very
        // name beside it would have its files taken for the archive's.
        let inside = format!("src/{}!/", archive.rel);
        if self
            .upstream
            .seen
            .keys()
            .any(|path| path.starts_with(&inside))
        {
            self.upstream.gaps.push(format!(
                "src/{}: the recipe opens this archive itself, and a directory beside it has its name followed by `!`, so its files cannot be told apart for review",
                archive.rel
            ));
            return;
        }
        let path = format!("src/{}", archive.rel);
        // Reviewed as what came out of it, not as one program.
        self.upstream.programs.remove(&path);
        self.upstream.unpacked.push(path);
        self.walk(unpacked, format!("{}!", archive.rel), roots, recipe, &[]);
    }

    /// `archive` could not be unpacked for review: the build opens it, so
    /// the review is incomplete.
    pub fn not_unpacked(&mut self, archive: &Archive, why: &str) {
        self.archives.retain(|known| known.rel != archive.rel);
        self.upstream.gaps.push(format!(
            "src/{}: the recipe opens this archive itself, and Guardian could not unpack it for review ({why})",
            archive.rel
        ));
    }

    /// What the walk saw: every file with its hash, and the downloads.
    pub fn upstream(&self) -> &Upstream {
        &self.upstream
    }

    /// Marks the files at `paths` as new or changed since Guardian
    /// extracted the sources: they are sent for review before other code.
    pub fn mark_changed(&mut self, paths: &HashSet<String>) {
        self.upstream.changed.0 = paths.len();
        for file in &mut self.all {
            file.changed = paths.contains(&file.path);
        }
    }

    /// Code and data a build file names is build-critical however deep it
    /// lies; data nothing names is not sent.
    fn settle_named(&mut self) {
        let (code, included) = named_by_build_files(&self.all);
        for file in self.all.iter_mut().filter(|file| !file.critical) {
            let relative = file.path.strip_prefix("src/").unwrap_or(&file.path);
            file.critical = is_named(relative, &code) || is_named(relative, &included);
        }
        for data in std::mem::take(&mut self.data) {
            let text = is_named(&data.child, &included)
                .then(|| fs::read(&data.read_from).ok())
                .flatten()
                .and_then(
                    |bytes| match content::classify(&data.child, false, false, &bytes) {
                        Content::Text(text) | Content::Lossy { text, .. } => Some(text),
                        _ => None,
                    },
                );
            match text {
                Some(text) => {
                    self.upstream.data_files -= 1;
                    self.all.push(UpstreamFile {
                        path: format!("src/{}", data.child),
                        text,
                        depth: data.depth,
                        critical: true,
                        late: data.late,
                        changed: false,
                    });
                }
                None => self
                    .upstream
                    .unreviewed
                    .push((format!("src/{}", data.child), NOT_REVIEWED_DATA)),
            }
        }
    }

    /// A whole image is passed over only away from where files are run
    /// (see `image::Surroundings`): one beside a script, or in a directory
    /// whose files a reviewed line runs, is an unread file like any other,
    /// so a new or changed one makes the review a full one.
    fn settle_images(&mut self) {
        for file in &self.all {
            self.surroundings.note_text(&file.path, &file.text);
        }
        for (path, digest) in std::mem::take(&mut self.images) {
            if !self.surroundings.leaves_alone(&path) {
                self.upstream.unread.insert(path, digest);
            }
        }
    }

    /// An archive left packed: the review says that what the build takes
    /// from it is not reviewed, and it is incomplete when the recipe
    /// certainly opens it.
    fn settle_archives(&mut self) {
        for (index, archive) in std::mem::take(&mut self.archives).into_iter().enumerate() {
            if archive.named {
                self.upstream.gaps.push(format!(
                    "src/{}: the recipe opens this archive itself, and it was not unpacked for review",
                    archive.rel
                ));
            } else if index < MAX_ARCHIVES_NAMED {
                self.upstream.omitted.push((archive.rel, NOT_UNPACKED));
            }
        }
    }

    /// Decides what is sent. A source whose code fits `FULL_REVIEW_BYTES`
    /// is taken whole; otherwise every build-critical file first (the
    /// review is incomplete when they alone exceed `budget`), then what
    /// changed since Guardian extracted the sources, then other code,
    /// shallowest and outside rarely-run directories first, up to
    /// `budget`. What is left out is listed in `unreviewed`.
    pub fn select(mut self, budget: u64) -> Upstream {
        self.settle_named();
        self.settle_archives();
        self.settle_images();
        let Self {
            mut all,
            mut upstream,
            ..
        } = self;

        let total: u64 = all.iter().map(|file| file.text.len() as u64).sum();
        upstream.text_files = all.len();
        if total <= FULL_REVIEW_BYTES {
            all.sort_by(|left, right| left.path.cmp(&right.path));
            upstream.whole = upstream.omitted.is_empty() && upstream.gaps.is_empty();
            upstream.changed.1 = all.iter().filter(|file| file.changed).count();
            upstream.files = all;
            return upstream;
        }

        all.sort_by(|left, right| {
            right
                .critical
                .cmp(&left.critical)
                .then(right.changed.cmp(&left.changed))
                .then(left.late.cmp(&right.late))
                .then(left.depth.cmp(&right.depth))
                .then(left.path.cmp(&right.path))
        });
        let critical: u64 = all
            .iter()
            .filter(|file| file.critical)
            .map(|file| file.text.len() as u64)
            .sum();
        if critical > budget {
            upstream.gaps.push(format!(
                "the build files and scripts ({} KiB) exceed what one review can take ({} KiB)",
                critical / 1024,
                budget / 1024
            ));
        }
        let mut used = 0_u64;
        for file in all {
            let size = file.text.len() as u64;
            if !file.critical && used + size > budget {
                upstream.left_out += 1;
                upstream.unreviewed.push((file.path, NOT_REVIEWED_BUDGET));
                continue;
            }
            used += size;
            upstream.changed.1 += usize::from(file.changed);
            upstream.files.push(file);
        }
        upstream
            .files
            .sort_by(|left, right| left.path.cmp(&right.path));
        upstream.whole = false;
        upstream
    }
}

/// Walks the upstream code under `src`. `noextract` holds the downloads the
/// listing says makepkg does not unpack.
pub fn walk_upstream(
    src: &Path,
    roots: &Roots<'_>,
    recipe: &str,
    noextract: &[String],
) -> Collected {
    walk_with_cap(src, roots, recipe, noextract, MAX_ENTRIES)
}

fn walk_with_cap(
    src: &Path,
    roots: &Roots<'_>,
    recipe: &str,
    noextract: &[String],
    max_entries: usize,
) -> Collected {
    let mut collected = Collected {
        all: Vec::new(),
        data: Vec::new(),
        archives: Vec::new(),
        upstream: Upstream::default(),
        max_entries,
        surroundings: image::Surroundings::default(),
        images: Vec::new(),
    };
    collected.walk(src, String::new(), roots, recipe, noextract);
    collected
}

/// Collects upstream code under `src` as it is, unpacking nothing (see
/// `Collected::select` for what is taken).
#[cfg(test)]
pub fn collect_upstream(src: &Path, roots: &Roots<'_>, recipe: &str, budget: u64) -> Upstream {
    walk_upstream(src, roots, recipe, &[]).select(budget)
}

#[cfg(test)]
pub(super) fn collect_with_cap(
    src: &Path,
    roots: &Roots<'_>,
    recipe: &str,
    budget: u64,
    max_entries: usize,
) -> Upstream {
    walk_with_cap(src, roots, recipe, &[], max_entries).select(budget)
}
