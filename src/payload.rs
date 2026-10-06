//! What a package archive holds, and the files in it that run, or grant
//! privileges, on their own: without the install scriptlet, pacman hooks and
//! their scripts run on later transactions, sudoers and polkit rules grant
//! root, enabled systemd units, drop-ins, udev, sysctl and modprobe rules,
//! tmpfiles and sysusers entries run at boot or on events, initcpio and
//! kernel-install hooks run at every kernel update, and login scripts,
//! autostart entries, cron jobs and D-Bus services run on their own
//! schedule. The pacman gate reviews these with the AI alongside the
//! scriptlet, and with them the package's own text files that the scriptlet
//! or one of those files names (a script a hook hands to an interpreter, a
//! file a login script sources); the rest of the payload is not reviewed.
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
//! file, and its path must still name it, with the same bytes, once the
//! review is over (see `Fingerprint`).

mod model;
mod review;

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use self::model::{Attribute, attributes_in_tar, parse_model};
pub(crate) use self::model::{
    OWNED_BY_OTHER, SETGID_OTHER, SETUID_OTHER, WITH_ACL, WITH_CAPABILITIES, WRITABLE_BY_ALL,
    WRITABLE_BY_GROUP, already_granted, unescape,
};
pub(crate) use self::review::{GUARDIAN_PACKAGE, PayloadFile, annotated, review};
use crate::autorun::named_words;
use crate::content::{self, PROBE_SIZE, Prefix};
use crate::error::{Error, IoContext};
use crate::files::{O_NOFOLLOW, O_NONBLOCK};
use crate::sandbox::Workspace;
use crate::scan::MAX_TEXT_FILE_SIZE;
use crate::sha256::{Digest, Sha256};
use crate::tools::{self, Limits};

#[cfg(test)]
use self::model::{open_to_others, root_set_id};
#[cfg(test)]
use self::review::{
    MAX_NAMED_DEPTH, claim_violation, lexical_target, name_violation, protected_violation,
    sweep_only_effect,
};

/// The archive's own metadata; any other name starting with `.` is refused.
const METADATA: &[&str] = &[".PKGINFO", ".BUILDINFO", ".MTREE", ".INSTALL", ".CHANGELOG"];

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

/// The directory links every system has (`/bin` is `usr/bin`): an entry
/// listed under one would replace the link with a directory of its own.
const ROOT_LINKS: &[&str] = &["bin/", "sbin/", "lib/", "lib64/"];
/// The same inside `/usr`: `usr/sbin` is `bin` and `usr/lib64` is `lib`.
/// The `filesystem` package ships the links themselves, never an entry
/// under one.
const USR_LINKS: &[&str] = &["usr/sbin/", "usr/lib64/"];

/// `path` (relative to `/`) as the system reads it through those links:
/// `bin/sh` and `usr/sbin/sh` are `usr/bin/sh`.
pub(crate) fn through_root_links(path: &str) -> String {
    for (link, leads) in [
        ("bin/", "usr/bin/"),
        ("sbin/", "usr/bin/"),
        ("lib/", "usr/lib/"),
        ("lib64/", "usr/lib/"),
        ("usr/sbin/", "usr/bin/"),
        ("usr/lib64/", "usr/lib/"),
    ] {
        if let Some(rest) = path.strip_prefix(link) {
            return format!("{leads}{rest}");
        }
    }
    path.to_string()
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
    /// A regular file installed setuid or setgid root (it runs as root for
    /// whoever starts it, with no scriptlet involved), or one under `/usr`,
    /// `/etc` or `/opt` that everyone may write (whoever writes it decides
    /// what the next one to run or read it gets).
    root_set_id: Option<&'static str>,
}

/// Where a symbolic link leads, resolved inside the archive model.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Resolution {
    /// A regular file the package ships.
    Regular(String),
    /// Somewhere the package does not ship (another package's file).
    Outside(String),
}

/// What an archive ships at a path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InArchive {
    Absent,
    /// A directory, a link, or a file that could not be read.
    Other,
    File(Vec<u8>),
}

/// A package archive opened once and modelled exactly.
pub(crate) struct Archive {
    path: PathBuf,
    file: File,
    identity: Identity,
    entries: Vec<Entry>,
    index: HashMap<String, usize>,
    /// The file capabilities the archive gives its entries, by path, as
    /// the base64 of the attribute's value.
    capabilities: HashMap<String, String>,
}

/// Which file a path names, and when it was last written or changed. The
/// change time is the kernel's own: a write in place moves it, and nobody
/// but root (by setting the clock) can move it back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl Identity {
    fn of(metadata: &Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            size: metadata.len(),
            mtime: (metadata.mtime(), metadata.mtime_nsec()),
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

/// What an archive was when its review began: the file its path named and
/// the SHA-256 of its bytes. The AI review takes minutes, and an archive
/// given to `pacman -U` may lie where its owner can rewrite it in place
/// meanwhile; `verify` is asked again once the review is over. The digest
/// is also what the audit trail records and a permit is bound to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Fingerprint {
    path: PathBuf,
    identity: Identity,
    digest: Digest,
    /// Whether `verify` hashes the bytes again: not for a file only root
    /// can write (see `root_alone`).
    rehash: bool,
}

/// Whether only root can write the file at `path` or put another in its
/// place: it and every directory above it are root's, and not writable by
/// a group or by everyone. That is pacman's own cache, where a system
/// upgrade keeps gigabytes of archives: whoever rewrites one of those is
/// root already, so once hashed they are told apart by the file and its
/// change time alone, without hashing each twice.
fn root_alone(path: &Path, file: &Metadata) -> bool {
    let roots = |metadata: &Metadata| metadata.uid() == 0 && metadata.mode() & 0o022 == 0;
    roots(file)
        && path.is_absolute()
        && path.ancestors().skip(1).all(|directory| {
            fs::symlink_metadata(directory)
                .is_ok_and(|metadata| metadata.is_dir() && roots(&metadata))
        })
}

impl Fingerprint {
    /// The SHA-256 of the archive's bytes as they were reviewed.
    pub(crate) const fn digest(&self) -> &Digest {
        &self.digest
    }

    /// The archive by its file name without `.pkg.tar.*`: the package's
    /// name, version, build and architecture.
    pub(crate) fn name(&self) -> String {
        let name = self
            .path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        name.split_once(".pkg.tar")
            .map_or(name.as_str(), |(stem, _)| stem)
            .to_string()
    }

    /// The path must still name the same file, unchanged, holding the same
    /// bytes.
    pub(crate) fn verify(&self) -> Result<(), Error> {
        let changed = || {
            Error::Refused(format!(
                "{} changed while it was being reviewed",
                self.path.display()
            ))
        };
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW | O_NONBLOCK)
            .open(&self.path)
            .map_err(|_| changed())?;
        let same = |metadata: io::Result<Metadata>| {
            metadata.is_ok_and(|metadata| {
                metadata.is_file() && Identity::of(&metadata) == self.identity
            })
        };
        if !same(file.metadata()) || (self.rehash && digest_of(&file).ok() != Some(self.digest)) {
            return Err(changed());
        }
        // Hashing took its time too: still that file, not written since.
        if same(fs::symlink_metadata(&self.path)) {
            Ok(())
        } else {
            Err(changed())
        }
    }
}

/// The SHA-256 of everything `file` holds from where it stands, read in
/// pieces: an archive may be gigabytes.
fn digest_of(mut file: &File) -> io::Result<Digest> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1 << 16];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => return Ok(hasher.finalize()),
            Ok(count) => hasher.update(&buffer[..count]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

/// What an archive puts where a link on the system leads (see
/// `Archive::replacement`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Replacement {
    /// A file small enough to read, with its bytes.
    File(Vec<u8>),
    /// A larger file that is no text, by what it is.
    Binary(&'static str),
    /// Text of this archive over the review limit: unread, but its bytes
    /// are the archive's.
    TooLarge,
    /// Something that cannot be read, and why.
    Unreadable(&'static str),
}

impl Archive {
    /// Opens `path` (not following a link), lists it twice and builds the
    /// model; any listing that is not a clean package fails.
    pub(crate) fn open(path: &Path) -> Result<Self, Error> {
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
            capabilities: HashMap::new(),
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
        // What the listing does not show: file capabilities and access
        // control lists, which libalpm restores with the file.
        for (path, what, capability) in archive.attributes()? {
            let index = archive.index.get(&path).copied().ok_or_else(|| {
                Error::Refused(format!(
                    "{}: its attributes name {path:?}, which its listing does not",
                    archive.path.display()
                ))
            })?;
            archive.entries[index].root_set_id.get_or_insert(what);
            if let Some(capability) = capability {
                archive.capabilities.insert(path, capability);
            }
        }
        Ok(archive)
    }

    /// The entries that carry rights beside their mode, read from the
    /// archive rewritten as an uncompressed tar stream: there every such
    /// attribute stands in a header before its entry, whatever compression
    /// and tar dialect the package uses.
    fn attributes(&self) -> Result<Vec<Attribute>, Error> {
        let failed = |detail: String| Error::ToolFailed {
            tool: "bsdtar".into(),
            detail: format!("{}: {detail}", self.path.display()),
        };
        let stdin = File::open(format!("/proc/self/fd/{}", self.file.as_raw_fd())).at(&self.path)?;
        let mut child = std::process::Command::new(tools::TIMEOUT)
            .arg("--signal=TERM")
            .arg("--kill-after=5s")
            .arg(format!("{}s", LISTING_LIMITS.timeout_secs))
            .arg(tools::BSDTAR)
            .args(["-cf", "-", "--format=pax", "@-"])
            .env("LC_ALL", "C")
            .stdin(stdin)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|source| Error::Spawn {
                tool: "bsdtar".into(),
                source,
            })?;
        let found = child
            .stdout
            .take()
            .ok_or_else(|| failed("no output".into()))
            .and_then(|stdout| {
                attributes_in_tar(io::BufReader::with_capacity(1 << 16, stdout)).map_err(failed)
            });
        let status = child
            .wait()
            .map_err(|error| failed(format!("could not wait for exit: {error}")))?;
        let found = found?;
        if !status.success() {
            return Err(failed(
                "could not be read through for its attributes".into(),
            ));
        }
        Ok(found)
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

    /// The first `PROBE_SIZE` bytes of each of `paths` (regular files of
    /// the model), enough to tell text from a compiled program, in one
    /// pass over the archive and without writing a large file anywhere:
    /// bsdtar prints the files one after another in archive order, and
    /// the model says how long each is.
    fn heads(&self, paths: &[String]) -> Result<HashMap<String, Vec<u8>>, Error> {
        if paths.is_empty() {
            return Ok(HashMap::new());
        }
        let failed = |detail: String| Error::ToolFailed {
            tool: "bsdtar".into(),
            detail: format!("{}: {detail}", self.path.display()),
        };
        let mut ordered: Vec<(usize, &String)> = paths
            .iter()
            .filter_map(|path| Some((*self.index.get(path)?, path)))
            .collect();
        ordered.sort();
        ordered.dedup();
        let stdin = File::open(format!("/proc/self/fd/{}", self.file.as_raw_fd())).at(&self.path)?;
        let mut command = std::process::Command::new(tools::TIMEOUT);
        command
            .arg("--signal=TERM")
            .arg("--kill-after=5s")
            .arg(format!("{}s", EXTRACT_LIMITS.timeout_secs))
            .arg(tools::BSDTAR)
            .args(["-x", "-O", "-f", "-"]);
        for (_, path) in &ordered {
            command.arg("--include").arg(escape_pattern(path));
        }
        let mut child = command
            .env("LC_ALL", "C")
            .stdin(stdin)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|source| Error::Spawn {
                tool: "bsdtar".into(),
                source,
            })?;
        let heads = child
            .stdout
            .take()
            .ok_or_else(|| "no output".to_string())
            .and_then(|stdout| {
                let mut stream = io::BufReader::with_capacity(1 << 16, stdout);
                let mut heads = HashMap::new();
                for (index, path) in &ordered {
                    let size = self.entries[*index].size;
                    let mut head = Vec::new();
                    let kept = (&mut stream)
                        .take(size.min(PROBE_SIZE as u64))
                        .read_to_end(&mut head)
                        .map_err(|error| error.to_string())?;
                    let skipped =
                        io::copy(&mut (&mut stream).take(size - kept as u64), &mut io::sink())
                            .map_err(|error| error.to_string())?;
                    if kept as u64 + skipped != size {
                        return Err(format!("/{path} is shorter than listed"));
                    }
                    heads.insert((*path).clone(), head);
                }
                // Anything more is a file the model does not know.
                let mut more = [0_u8; 1];
                match stream.read(&mut more) {
                    Ok(0) => Ok(heads),
                    _ => Err("more was extracted than the listing names".to_string()),
                }
            });
        let status = child
            .wait()
            .map_err(|error| failed(format!("could not wait for exit: {error}")))?;
        let heads = heads.map_err(failed)?;
        if !status.success() {
            return Err(failed("could not be read through for its files".into()));
        }
        Ok(heads)
    }

    /// The archive as it is now, to compare with once the review is over.
    /// The whole of it is hashed, through the descriptor it was opened
    /// with; unless the file is root's alone, it is hashed again then.
    pub(crate) fn fingerprint(&self) -> Result<Fingerprint, Error> {
        let rehash = !root_alone(&self.path, &self.file.metadata().at(&self.path)?);
        let file = File::open(format!("/proc/self/fd/{}", self.file.as_raw_fd())).at(&self.path)?;
        Ok(Fingerprint {
            path: self.path.clone(),
            identity: self.identity,
            digest: digest_of(&file).at(&self.path)?,
            rehash,
        })
    }

    /// The regular file whose content is installed at `path`: itself, the
    /// original of a hard link, or what a symbolic link leads to inside
    /// the package.
    fn regular_at(&self, path: &str) -> Option<String> {
        match &self.entry(path)?.kind {
            Kind::File => Some(path.to_string()),
            Kind::HardLink(original) => Some(original.clone()),
            Kind::Symlink(target) => match self.resolve(path, target) {
                Ok(Resolution::Regular(resolved)) => Some(resolved),
                _ => None,
            },
            Kind::Directory => None,
        }
    }

    /// The regular files of this archive that `text` names: by a path
    /// (`/usr/lib/pkg/setup.sh`, also behind a variable or a prefix, as in
    /// `$pkgdir/usr/lib/pkg/setup.sh` or `-/usr/lib/pkg/pre`), or by a bare
    /// name the package ships in `usr/bin`.
    fn named_in(&self, text: &str) -> Vec<String> {
        let mut found = Vec::new();
        let mut seen = HashSet::new();
        let links = self
            .entries
            .iter()
            .any(|entry| matches!(entry.kind, Kind::Symlink(_)));
        // A path as written, or else as the system walks it: only one
        // with `.`, `..` or `//` in it, or in a package that ships links,
        // can be another path than it says.
        let shipped = |tail: &str| {
            self.regular_at(&through_root_links(tail)).or_else(|| {
                let indirect = links
                    || tail
                        .split('/')
                        .any(|component| matches!(component, "" | "." | ".."));
                indirect
                    .then(|| self.walked(tail))
                    .flatten()
                    .and_then(|path| self.regular_at(&path))
            })
        };
        for word in named_words(text) {
            // The end of a sentence, or of a directory's name.
            let word = word.trim_end_matches(['.', '/']);
            let named = if word.contains('/') {
                // The word itself, then every tail of it that starts
                // after a `/`: the longest that the package ships.
                std::iter::once(word)
                    .chain(word.match_indices('/').map(|(at, _)| &word[at + 1..]))
                    .filter(|tail| tail.contains('/'))
                    .find_map(shipped)
            } else {
                self.regular_at(&format!("usr/bin/{word}"))
            };
            if let Some(path) = named
                && seen.insert(path.clone())
            {
                found.push(path);
            }
        }
        found
    }

    /// `path` (relative to `/`) as the system walks it: `.` and `..` taken
    /// out, and the usual root links (`/lib`) and the directory links this
    /// package ships followed, so `usr/lib/../share/x` and `opt/pkg/current/x`
    /// (with `current -> releases/1`) name the file that is run. The last
    /// name is left as it is. `None` for a path that climbs above the root
    /// or goes through more links than are followed.
    fn walked(&self, path: &str) -> Option<String> {
        let reversed =
            |text: &str| -> Vec<String> { text.split('/').rev().map(str::to_string).collect() };
        let mut pending = reversed(path);
        let mut parts: Vec<String> = Vec::new();
        let mut hops = 0;
        while let Some(component) = pending.pop() {
            match component.as_str() {
                "" | "." => continue,
                ".." => {
                    parts.pop()?;
                    continue;
                }
                name => parts.push(name.to_string()),
            }
            if pending.iter().all(|rest| matches!(rest.as_str(), "" | ".")) {
                continue;
            }
            let here = parts.join("/");
            let target = match self.entry(&here).map(|entry| &entry.kind) {
                Some(Kind::Symlink(target)) => target.clone(),
                Some(_) => continue,
                None => {
                    let directory = format!("{here}/");
                    let leads = through_root_links(&directory);
                    if leads == directory {
                        continue;
                    }
                    format!("/{leads}")
                }
            };
            hops += 1;
            if hops > MAX_HOPS {
                return None;
            }
            parts.pop();
            if target.starts_with('/') {
                parts.clear();
            }
            pending.extend(reversed(&target));
        }
        Some(parts.join("/"))
    }

    /// What this archive installs at `path` (no leading `/`), for a link
    /// on the system that leads there and is read as an auto-run file:
    /// `None` when it ships no file there.
    pub(crate) fn replacement(&self, path: &str) -> Option<Replacement> {
        let regular = match &self.entry(path)?.kind {
            Kind::Directory => return None,
            Kind::Symlink(_) => match self.regular_at(path) {
                Some(regular) => regular,
                None => {
                    return Some(Replacement::Unreadable(
                        "is a symbolic link out of the package",
                    ));
                }
            },
            Kind::File | Kind::HardLink(_) => self.regular_source(path),
        };
        let size = self.entry(&regular).map_or(0, |entry| entry.size);
        if size <= MAX_TEXT_FILE_SIZE {
            return Some(
                self.extract(std::slice::from_ref(&regular))
                    .ok()
                    .and_then(|mut read| read.remove(&regular))
                    .map_or(
                        Replacement::Unreadable("could not be read from the archive"),
                        Replacement::File,
                    ),
            );
        }
        let heads = self.heads(std::slice::from_ref(&regular)).ok();
        let head = heads.as_ref().and_then(|heads| heads.get(&regular));
        Some(
            match head.map(|head| content::classify_prefix(path, false, head)) {
                Some(Prefix::Binary(format)) => Replacement::Binary(format.label()),
                Some(Prefix::Text | Prefix::Undecodable) => Replacement::TooLarge,
                None => Replacement::Unreadable("could not be read from the archive"),
            },
        )
    }

    /// The file capabilities the archive gives `path` (see
    /// `capabilities`), when those are all its attributes grant.
    pub(crate) fn shipped_capability(&self, path: &str) -> Option<&str> {
        self.capabilities.get(path).map(String::as_str)
    }

    /// The path must still name the file that was reviewed.
    pub(crate) fn verify_unchanged(&self) -> Result<(), Error> {
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
                        // `/lib` is `usr/lib` where it is the usual link
                        // and the package does not ship it as something
                        // else: what follows is looked for there, `..`
                        // included.
                        if parts.len() == 1
                            && ROOT_LINKS.contains(&format!("{name}/").as_str())
                            && self.entry(name).is_none()
                        {
                            let leads = if name.starts_with("lib") {
                                "lib"
                            } else {
                                "bin"
                            };
                            parts = vec!["usr".to_string(), leads.to_string()];
                        }
                        // The same for `/usr/sbin` and `/usr/lib64`.
                        if parts.len() == 2
                            && parts[0] == "usr"
                            && USR_LINKS.contains(&format!("usr/{name}/").as_str())
                            && self.entry(&format!("usr/{name}")).is_none()
                        {
                            parts[1] = if name.starts_with("lib") {
                                "lib"
                            } else {
                                "bin"
                            }
                            .to_string();
                        }
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

    /// The paths of everything this archive ships (no leading `/`).
    pub(crate) fn paths(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|entry| entry.path.as_str())
    }

    /// What this archive ships at `path` (no leading `/`).
    pub(crate) fn shipped_file(&self, path: &str) -> InArchive {
        let Some(entry) = self.entry(path) else {
            return InArchive::Absent;
        };
        let path = match &entry.kind {
            Kind::File => path.to_string(),
            Kind::HardLink(original) => original.clone(),
            Kind::Directory | Kind::Symlink(_) => return InArchive::Other,
        };
        self.extract(std::slice::from_ref(&path))
            .ok()
            .and_then(|mut read| read.remove(&path))
            .map_or(InArchive::Other, InArchive::File)
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
fn read_extracted(root: &Path, rel: &str) -> io::Result<Vec<u8>> {
    let mut path = root.to_path_buf();
    let components: Vec<&str> = rel.split('/').collect();
    for (index, component) in components.iter().enumerate() {
        path.push(component);
        let metadata = fs::symlink_metadata(&path)?;
        let last = index + 1 == components.len();
        if metadata.file_type().is_symlink() || (!last && !metadata.is_dir()) {
            return Err(io::Error::other("not a plain path in the extraction"));
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(&path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_TEXT_FILE_SIZE + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests;
