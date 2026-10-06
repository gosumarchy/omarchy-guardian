//! What of a package is reviewed: the paths no package but their owner may
//! ship, the files that run or grant privileges on their own, the files
//! those name, and what the package grants.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use super::{Archive, Entry, Kind, METADATA, ROOT_LINKS, Resolution, USR_LINKS};
use crate::autorun::{
    Location, is_alias_of_reviewed_directory, is_auto_run_directory, is_reviewed,
    sweep_only_location,
};
use crate::config::model::SourceClass;
use crate::content::{self, Content, Prefix};
use crate::error::Error;
use crate::rules;
use crate::scan::MAX_TEXT_FILE_SIZE;

/// More matching files than any real package ships; a payload beyond these
/// limits is not reviewed, and the review is incomplete.
const MAX_FILES: usize = 2000;
const MAX_TOTAL: u64 = 32 * 1024 * 1024;
/// How far the package's own files are followed from its scriptlet and
/// auto-run files (a hook names a script, which sources another), and how
/// many of them: past either, the review is incomplete. Guardian's own
/// package is five deep (hook, script, interceptor, theme gate, program).
pub(super) const MAX_NAMED_DEPTH: usize = 8;
const MAX_NAMED_FILES: usize = 500;

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
    // Root's own mark that the gate is on (see the hook script), and the
    // hook libalpm always loads.
    ("etc/pacman.d/hooks/omarchy-guardian.hook", Owner::Nobody),
    (
        "usr/share/libalpm/hooks/omarchy-guardian.hook",
        Owner::Guardian,
    ),
    ("usr/bin/omarchy-guardian", Owner::Guardian),
    ("usr/lib/omarchy-guardian/", Owner::Guardian),
    ("usr/share/omarchy-guardian/", Owner::Guardian),
    // What only root's halves write: the user's permits and the sweep's
    // allow list. A file a package put there would be root's as well.
    ("var/lib/omarchy-guardian/", Owner::Nobody),
    ("usr/bin/opencode", Owner::Packages(&["opencode"])),
    ("usr/local/bin/opencode", Owner::Packages(&["opencode"])),
    ("usr/bin/claude", Owner::Packages(&["claude-code"])),
    ("usr/local/bin/claude", Owner::Packages(&["claude-code"])),
    ("opt/claude-code/", Owner::Packages(&["claude-code"])),
    // What the reviewer reads as its own instructions and settings: the
    // system-wide configuration of either CLI (neither package ships one),
    // and the project files a CLI started in `/usr` or `/` would pick up.
    // A name starting with `.` at the top of an archive is refused with
    // the model already.
    ("etc/opencode/", Owner::Nobody),
    ("etc/claude-code/", Owner::Nobody),
    ("usr/AGENTS.md", Owner::Nobody),
    ("usr/CLAUDE.md", Owner::Nobody),
    ("usr/CLAUDE.local.md", Owner::Nobody),
    ("usr/CONTEXT.md", Owner::Nobody),
    ("usr/opencode.json", Owner::Nobody),
    ("usr/opencode.jsonc", Owner::Nobody),
    ("usr/.mcp.json", Owner::Nobody),
    ("usr/.opencode/", Owner::Nobody),
    ("usr/.claude/", Owner::Nobody),
    ("AGENTS.md", Owner::Nobody),
    ("CLAUDE.md", Owner::Nobody),
    ("CLAUDE.local.md", Owner::Nobody),
    ("CONTEXT.md", Owner::Nobody),
    ("opencode.json", Owner::Nobody),
    ("opencode.jsonc", Owner::Nobody),
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
    // What the root half of the hook script runs.
    ("usr/bin/sh", Owner::Official),
    ("usr/bin/bash", Owner::Official),
    ("usr/bin/readlink", Owner::Official),
    ("usr/bin/id", Owner::Official),
    ("usr/bin/getent", Owner::Official),
    ("usr/bin/cut", Owner::Official),
    // Reads what pacman recorded of the installed packages' links.
    ("usr/bin/gzip", Owner::Official),
    // Write and read the audit trail.
    ("usr/bin/logger", Owner::Official),
    ("usr/bin/journalctl", Owner::Official),
];

/// Top-level directories no package installs files into: runtime and
/// temporary file systems, and the home directories. A unit or generator
/// under `/run/systemd`, or a key in `/root/.ssh`, would act like any
/// auto-run file with nothing here looking at it.
const NOT_FOR_PACKAGES: &[&str] = &["run/", "tmp/", "dev/", "proc/", "sys/", "root/", "home/"];

/// Guardian's own package. What other packages a `.PKGINFO` may not claim
/// to replace, conflict with or provide: pacman would then remove Guardian
/// for it.
pub const GUARDIAN_PACKAGE: &str = "omarchy-guardian";
/// What a package of that name must ship to be Guardian: an "upgrade" to
/// one without its program or hook script takes the gate away.
const GUARDIAN_FILES: &[&str] = &[
    "usr/bin/omarchy-guardian",
    "usr/lib/omarchy-guardian/guardian-pacman-hook",
];
/// The packages of the reviewer CLIs, as `PROTECTED` names them.
const REVIEWERS: &[&str] = &["opencode", "claude-code"];

/// Why a package named `package` (of `class`) may not be installed at all:
/// a package of Guardian's name, or of its reviewer's, replaces the
/// installed one whatever it ships, an empty one included.
pub(super) fn name_violation(
    package: &str,
    class: SourceClass,
    trusted: &[String],
) -> Option<String> {
    if package == GUARDIAN_PACKAGE && class == SourceClass::ThirdPartyRepo {
        return Some(format!(
            "{package} is offered by a third-party repository: Guardian is installed from a local archive or an official repository only, and a package of its name would replace it"
        ));
    }
    if REVIEWERS.contains(&package)
        && class != SourceClass::Official
        && !trusted.iter().any(|name| name == package)
    {
        return Some(format!(
            "{package} does not come from an official repository: a package of that name would replace Guardian's reviewer (name it in trusted_reviewer_packages to allow it)"
        ));
    }
    None
}

/// The first line of `pkginfo` by which `package` claims the place of
/// Guardian or of its reviewer (`replaces`, `conflict`, `provides`), with
/// what it would take away. Guardian is nobody else's to claim; a reviewer
/// may be claimed by a package that could ship it (see `PROTECTED`).
pub(super) fn claim_violation<'a>(
    pkginfo: &'a str,
    package: &str,
    class: SourceClass,
    trusted: &[String],
) -> Option<(&'a str, &'static str)> {
    let may_ship_reviewer =
        class == SourceClass::Official || trusted.iter().any(|name| name == package);
    pkginfo.lines().find_map(|line| {
        let claimed = ["replaces = ", "conflict = ", "provides = "]
            .iter()
            .find_map(|key| line.strip_prefix(key))?
            .trim()
            .split(['<', '>', '='])
            .next()
            .map(str::trim)?;
        if claimed == package {
            None
        } else if claimed == GUARDIAN_PACKAGE {
            Some((line.trim(), "Guardian"))
        } else if (REVIEWERS.contains(&claimed) || trusted.iter().any(|name| name == claimed))
            && !may_ship_reviewer
        {
            Some((line.trim(), "Guardian's reviewer"))
        } else {
            None
        }
    })
}

/// Whether `package` (of `class`) may ship `path`; `trusted` names extra
/// reviewer packages the root-owned system configuration allows.
pub(super) fn protected_violation(
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
            "{package} ships /{path}, which {} may provide: it could disarm Guardian",
            match owner {
                Owner::Nobody => "no package".to_string(),
                Owner::Guardian =>
                    "only the omarchy-guardian package, installed from a local archive or an official repository,"
                        .to_string(),
                Owner::Packages(packages) => format!(
                    "only {} from an official repository (or a package named in trusted_reviewer_packages)",
                    packages.join(" or ")
                ),
                Owner::Official => "only a package from an official repository".to_string(),
            },
            path = protected.trim_end_matches('/')
        )
    })
}

/// One payload file for the review, with its content as classified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadFile {
    pub path: String,
    pub content: Content,
    /// For a file of the package that reviewed files name (a script a hook
    /// runs, a file a login script sources): those files, `.INSTALL` for
    /// the scriptlet. Empty for an auto-run file.
    pub run_by: Vec<String>,
    /// For a link to a file this package does not ship: that file's path,
    /// for the caller to find where the transaction or the system has it.
    pub leads_outside: Option<String>,
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
    /// Not read: a compiled program, or a link out of the package.
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

/// The files of `archive` where only the sweep looks, by path, with what
/// a file there does (see `Review::misplaced`); none for an official
/// package.
fn misplaced(archive: &Archive, official: bool) -> Vec<(String, &'static str)> {
    let mut misplaced: Vec<(String, &'static str)> = archive
        .entries
        .iter()
        .filter(|entry| !official && !matches!(entry.kind, Kind::Directory))
        .filter_map(|entry| {
            let location = sweep_only_location(&entry.path)?;
            Some((entry.path.clone(), sweep_only_effect(location)))
        })
        .collect();
    misplaced.sort();
    misplaced
}

/// What the pacman gate reviews in one archive.
pub struct Review {
    /// The install scriptlet, classified (see `content::classify`).
    pub install: Option<Content>,
    pub files: Vec<PayloadFile>,
    /// Files installed setuid or setgid root, with which of the two, but
    /// for the sandbox helper of a Chromium-based program.
    pub root_set_id: Vec<(String, &'static str)>,
    /// What of the package was not read, each as a sentence: a scriptlet
    /// or auto-run file over the limits, and what the scriptlet or an
    /// auto-run file names and could not be followed to. The review is
    /// incomplete; the bytes are still the archive's.
    pub unfollowed: Vec<String>,
    /// For a package that is not from an official repository: its files
    /// where only the sweep looks (a PAM module, the boot loader's
    /// configuration, `/etc/hosts`), with what a file there does.
    pub misplaced: Vec<(String, &'static str)>,
    /// The regular files read as auto-run files: those themselves, and
    /// what the package's auto-run links lead to inside it.
    pub read_as_auto_run: HashSet<String>,
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
    if let Some(reason) = name_violation(package, class, trusted) {
        return Err(refuse(reason));
    }
    if package == GUARDIAN_PACKAGE
        && let Some(missing) = GUARDIAN_FILES.iter().find(|path| {
            !archive
                .entry(path)
                .is_some_and(|entry| entry.kind == Kind::File)
        })
    {
        return Err(refuse(format!(
            "{package} does not ship /{missing}: installing it would take Guardian away"
        )));
    }
    for entry in &archive.entries {
        if let Some(reason) = protected_violation(&entry.path, package, class, trusted) {
            return Err(refuse(reason));
        }
        if !matches!(entry.kind, Kind::Directory)
            && let Some(place) = NOT_FOR_PACKAGES.iter().find(|place| {
                entry.path.starts_with(**place) || entry.path == place.trim_end_matches('/')
            })
        {
            return Err(refuse(format!(
                "{package} installs /{} under /{place} where no package's files belong",
                entry.path
            )));
        }
        if let Some(link) = ROOT_LINKS
            .iter()
            .chain(USR_LINKS)
            .find(|link| entry.path.starts_with(**link))
        {
            return Err(refuse(format!(
                "{package} lists /{} under /{}, which is a link to a directory in /usr on this system",
                entry.path,
                link.trim_end_matches('/')
            )));
        }
    }

    let official = class == SourceClass::Official;
    let Plan {
        wanted,
        sources,
        unread,
    } = plan_reads(archive, official).map_err(refuse)?;
    let mut read = archive.extract(&wanted)?;

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
    if let Some((claim, what)) = claim_violation(&pkginfo, package, class, trusted) {
        return Err(refuse(format!(
            "{package} declares `{claim}`: installing it would remove or stand in for {what}"
        )));
    }

    // The package's own files that the scriptlet and the auto-run files
    // name are reviewed with them (read in further, bounded passes).
    let (named, unfollowed) = named_files(archive, &sources, &wanted, &mut read)?;
    let unfollowed = unread.into_iter().chain(unfollowed).collect();

    let install = read
        .get(".INSTALL")
        .map(|bytes| content::classify(".INSTALL", false, true, bytes));
    let mut files = payload_files(&sources, &read);
    files.extend(named);
    files.sort_by(|left, right| left.path.cmp(&right.path));
    // By path, like `files`: the order of an archive's entries is whatever
    // order it was packed in, and the report should not follow that.
    let mut root_set_id: Vec<(String, &'static str)> = archive
        .entries
        .iter()
        .filter(|entry| !is_chromium_helper(archive, &entry.path))
        .filter_map(|entry| Some((entry.path.clone(), entry.root_set_id?)))
        .collect();
    root_set_id.sort();
    Ok(Review {
        install,
        files,
        root_set_id,
        unfollowed,
        misplaced: misplaced(archive, official),
        read_as_auto_run: wanted
            .into_iter()
            .filter(|path| !METADATA.contains(&path.as_str()))
            .collect(),
    })
}

/// Where the link at `link` with `target` leads, by its text alone
/// (relative to `/`). `None` when it climbs above the root, or steps back
/// (`..`) after a name: that name may be a link on the system, and the
/// text would then say one place while the system goes to another.
pub(super) fn lexical_target(link: &str, target: &str) -> Option<String> {
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

/// What a file in a sweep-only location does, for the finding a package
/// that is not from an official repository gets for shipping one. The
/// category says it for most; these are not what their category's other
/// files are.
pub(super) fn sweep_only_effect(location: &Location) -> &'static str {
    match location.path {
        "var/lib/flatpak/overrides/" => {
            "decides what every Flatpak app may reach outside its sandbox"
        }
        "etc/containers/systemd/" => "becomes a systemd unit at every boot",
        "etc/fstab" | "etc/crypttab" => "decides what is mounted and unlocked at every boot",
        "etc/hosts" => "decides which address a name leads to, without asking DNS",
        "usr/local/share/ca-certificates/" => "adds a certificate authority to the system's own",
        _ => location.category.when(),
    }
}

/// What `review` reads from an archive.
struct Plan<'a> {
    /// The files to extract: `.PKGINFO`, `.INSTALL`, the auto-run entries
    /// and what their links resolve to.
    wanted: Vec<String>,
    /// Each auto-run entry that is read, with its source.
    sources: Vec<Source<'a>>,
    /// What is over the limits and so left unread, each as a sentence.
    unread: Vec<String>,
}

/// Plans the reads within the limits, from the model, before anything is
/// extracted. A scriptlet or auto-run file over a limit is left out and
/// said (`unread`) rather than refused: the checks that refuse a package
/// still run on the rest, and the archive's digest covers what was not
/// read.
fn plan_reads(archive: &Archive, official: bool) -> Result<Plan<'_>, String> {
    let mut wanted: Vec<String> = Vec::new();
    let mut unread = Vec::new();
    match archive.entry(".PKGINFO") {
        Some(entry) if entry.size <= MAX_TEXT_FILE_SIZE => wanted.push(".PKGINFO".into()),
        Some(_) => return Err(".PKGINFO is too large".into()),
        None => return Err("the package has no .PKGINFO".into()),
    }
    if let Some(entry) = archive.entry(".INSTALL") {
        if entry.size > MAX_TEXT_FILE_SIZE {
            unread.push("the install scriptlet exceeds the 2 MiB review limit".into());
        } else {
            wanted.push(".INSTALL".into());
        }
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
        if matches!(entry.kind, Kind::Directory) || !is_reviewed(&entry.path, official) {
            continue;
        }
        let source = match &entry.kind {
            Kind::Symlink(target) => archive.resolve(&entry.path, target)?,
            _ => Resolution::Regular(archive.regular_source(&entry.path)),
        };
        if let Resolution::Regular(path) = &source {
            let size = archive.entry(path).map_or(0, |entry| entry.size);
            if size > MAX_TEXT_FILE_SIZE {
                unread.push(format!(
                    "auto-run file /{} exceeds the 2 MiB review limit",
                    entry.path
                ));
                continue;
            }
            wanted.push(path.clone());
        }
        sources.push((entry, source));
    }
    wanted.sort();
    wanted.dedup();
    let total: u64 = wanted
        .iter()
        .filter_map(|path| archive.entry(path))
        .map(|entry| entry.size)
        .sum();
    if sources.len() > MAX_FILES || total > MAX_TOTAL {
        unread.push(format!(
            "{} auto-run files ({} KiB) exceed the review limits: none of them was reviewed",
            sources.len(),
            total / 1024
        ));
        sources.clear();
        wanted.retain(|path| METADATA.contains(&path.as_str()));
    }
    Ok(Plan {
        wanted,
        sources,
        unread,
    })
}

/// The package's own files that its scriptlet and auto-run files name, and
/// the files those name in turn: text is read (into `read`) and returned
/// for the review, a compiled program is returned as what it is. The
/// second list says what could not be followed: text over the size limit,
/// more files or more steps than the bounds allow.
fn named_files(
    archive: &Archive,
    sources: &[Source<'_>],
    wanted: &[String],
    read: &mut HashMap<String, Vec<u8>>,
) -> Result<(Vec<PayloadFile>, Vec<String>), Error> {
    // What is reviewed as itself already.
    let mut known: HashSet<&str> = wanted.iter().map(String::as_str).collect();
    known.extend(sources.iter().map(|(entry, _)| entry.path.as_str()));
    // Who names, and the file its text was read from.
    let mut naming: Vec<(String, String)> = read
        .contains_key(".INSTALL")
        .then(|| (".INSTALL".to_string(), ".INSTALL".to_string()))
        .into_iter()
        .collect();
    naming.extend(sources.iter().filter_map(|(entry, source)| match source {
        Resolution::Regular(path) => Some((entry.path.clone(), path.clone())),
        Resolution::Outside(_) => None,
    }));

    let mut total: u64 = wanted
        .iter()
        .filter_map(|path| archive.entry(path))
        .map(|entry| entry.size)
        .sum();
    let mut by: HashMap<String, Vec<String>> = HashMap::new();
    let mut found: Vec<(String, Content, Shipped)> = Vec::new();
    let mut unfollowed = Vec::new();
    for depth in 0..=MAX_NAMED_DEPTH {
        let mut fresh = newly_named(archive, &naming, read, &known, &mut by);
        if fresh.is_empty() {
            break;
        }
        let first_namer = |path: &str| {
            by.get(path)
                .and_then(|namers| namers.first())
                .map_or_else(String::new, |namer| shown(namer))
        };
        let room = if depth == MAX_NAMED_DEPTH {
            unfollowed.push(format!(
                "/{}, which {} names, is more than {MAX_NAMED_DEPTH} files away from what runs on its own: it and {} more were not followed",
                fresh[0],
                first_namer(&fresh[0]),
                fresh.len() - 1
            ));
            0
        } else {
            MAX_NAMED_FILES.saturating_sub(found.len())
        };
        if fresh.len() > room && depth < MAX_NAMED_DEPTH {
            unfollowed.push(format!(
                "the scriptlet and auto-run files name more than {MAX_NAMED_FILES} of the package's own files: /{} and {} more were not looked at",
                fresh[room],
                fresh.len() - room - 1
            ));
        }
        fresh.truncate(room);

        // Text or not, by the first bytes; only text is read whole.
        let heads = archive.heads(&fresh)?;
        let mut texts = Vec::new();
        for path in &fresh {
            let size = archive.entry(path).map_or(0, |entry| entry.size);
            let head = heads.get(path).map_or(&[][..], Vec::as_slice);
            let too_much = match content::classify_prefix(path, false, head) {
                Prefix::Binary(format) => {
                    found.push((path.clone(), Content::Binary(format), Shipped::Unknown));
                    continue;
                }
                Prefix::Text | Prefix::Undecodable if size > MAX_TEXT_FILE_SIZE => {
                    "is text over the 2 MiB review limit"
                }
                Prefix::Text | Prefix::Undecodable if total + size > MAX_TOTAL => {
                    "would take the package past the size all its reviewed files may have"
                }
                Prefix::Text | Prefix::Undecodable => {
                    total += size;
                    texts.push(path.clone());
                    continue;
                }
            };
            unfollowed.push(format!(
                "/{path}, which {} names, {too_much}",
                first_namer(path)
            ));
        }
        read.extend(archive.extract(&texts)?);
        naming.clear();
        for path in texts {
            let bytes = read.get(&path).cloned().unwrap_or_default();
            let content = content::classify(&path, false, false, &bytes);
            if matches!(content, Content::Text(_) | Content::Lossy { .. }) {
                naming.push((path.clone(), path.clone()));
            }
            found.push((path, content, Shipped::Bytes(bytes)));
        }
    }

    let files = found
        .into_iter()
        .map(|(path, content, shipped)| {
            let run_by = by.remove(&path).unwrap_or_default();
            named_file(path, content, shipped, run_by)
        })
        .collect();
    Ok((files, unfollowed))
}

/// The files of the archive that the texts in `naming` (who names, and the
/// file its text was read from) name for the first time, sorted; `by`
/// records who names each. What is `known` is reviewed as itself already.
fn newly_named(
    archive: &Archive,
    naming: &[(String, String)],
    read: &HashMap<String, Vec<u8>>,
    known: &HashSet<&str>,
    by: &mut HashMap<String, Vec<String>>,
) -> Vec<String> {
    let mut fresh: Vec<String> = Vec::new();
    for (namer, source) in naming {
        let Some(bytes) = read.get(source) else {
            continue;
        };
        for path in archive.named_in(&String::from_utf8_lossy(bytes)) {
            // An empty file holds nothing to run.
            let empty = archive.entry(&path).is_none_or(|entry| entry.size == 0);
            if empty || known.contains(path.as_str()) || path == *source {
                continue;
            }
            let namers = by.entry(path.clone()).or_default();
            if namers.is_empty() {
                fresh.push(path);
            }
            if !namers.contains(namer) {
                namers.push(namer.clone());
            }
        }
    }
    fresh.sort();
    fresh
}

/// A file the reviewed ones name (`run_by`) as a payload file: its text
/// starts with a line that says who names it.
fn named_file(
    path: String,
    content: Content,
    shipped: Shipped,
    run_by: Vec<String>,
) -> PayloadFile {
    let namers: Vec<String> = run_by.iter().take(3).map(|namer| shown(namer)).collect();
    let header = format!(
        "# /{path} is a file of this package named in {}{}, which may run or read it.\n",
        namers.join(", "),
        if run_by.len() > namers.len() {
            " and others"
        } else {
            ""
        }
    );
    PayloadFile {
        content: annotated(content, &header),
        path,
        run_by,
        leads_outside: None,
        shipped,
    }
}

/// How a file that names another is called in a sentence.
fn shown(namer: &str) -> String {
    if namer == ".INSTALL" {
        "the install scriptlet".to_string()
    } else {
        format!("/{namer}")
    }
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
                run_by: Vec::new(),
                leads_outside: match (&entry.kind, source) {
                    (Kind::Symlink(_), Resolution::Outside(resolved)) => Some(resolved.clone()),
                    _ => None,
                },
                shipped,
            }
        })
        .collect()
}

/// `content` with `header` before its text.
pub fn annotated(content: Content, header: &str) -> Content {
    match content {
        Content::Text(text) => Content::Text(format!("{header}{text}")),
        Content::Lossy { text, replaced } => Content::Lossy {
            text: format!("{header}{text}"),
            replaced,
        },
        other => other,
    }
}
