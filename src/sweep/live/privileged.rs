//! Setuid and setgid files, and files with capabilities, that no package
//! vouches for: the walk that finds them, and what `getcap` says.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::ExitStatus;

use super::{Found, packaged};
use crate::autorun::Category;
use crate::rules::RuleId;
use crate::sweep::collect::{self, Body, Origin, Scope};
use crate::sweep::read::{self, View};
use crate::sweep::tier::Tier;
use crate::tools::{self, Limits};

const GETCAP: &str = "/usr/bin/getcap";
/// Where setuid and capability files are looked for.
/// The home directories last: they hold the most files, and the walk stops
/// at a limit.
const PRIVILEGED_ROOTS: &[&str] = &["usr", "opt", "etc", "var", "srv", "root", "home"];
/// Under those, what holds other systems' files (containers, snapshots).
const PRIVILEGED_SKIPPED: &[&str] = &[
    "var/lib/docker",
    "var/lib/containers",
    "var/lib/machines",
    "var/lib/flatpak",
    "var/cache",
];
/// Capabilities that amount to root, or to reading or changing what only
/// root may. The others are reported one step lower.
pub(super) const ROOT_CAPABILITIES: &[&str] = &[
    "cap_setuid",
    "cap_setgid",
    "cap_sys_admin",
    "cap_sys_ptrace",
    "cap_sys_module",
    "cap_dac_override",
    "cap_dac_read_search",
    "cap_chown",
    "cap_fowner",
    "cap_sys_rawio",
    "cap_setfcap",
    "cap_setpcap",
    "cap_mknod",
    "cap_bpf",
    "cap_sys_boot",
    "cap_sys_chroot",
    "cap_mac_admin",
    "cap_mac_override",
    "cap_linux_immutable",
    "cap_net_admin",
];
/// Every other capability the kernel has a name for. One that is in
/// neither list (a number, a newer kernel's) is judged like a root one.
pub(super) const OTHER_CAPABILITIES: &[&str] = &[
    "cap_fsetid",
    "cap_kill",
    "cap_net_bind_service",
    "cap_net_broadcast",
    "cap_net_raw",
    "cap_ipc_lock",
    "cap_ipc_owner",
    "cap_sys_pacct",
    "cap_sys_nice",
    "cap_sys_resource",
    "cap_sys_time",
    "cap_sys_tty_config",
    "cap_lease",
    "cap_audit_write",
    "cap_audit_control",
    "cap_audit_read",
    "cap_syslog",
    "cap_wake_alarm",
    "cap_block_suspend",
    "cap_perfmon",
    "cap_checkpoint_restore",
];
/// The capabilities repository packages give their own programs, in their
/// install steps or in the package itself, each list sorted. Pacman
/// records none of them, so any other capability on a packaged file was
/// set afterwards.
pub(super) const EXPECTED_CAPABILITIES: &[(&str, &[&str])] = &[
    ("usr/bin/newuidmap", &["cap_setuid"]),
    ("usr/bin/newgidmap", &["cap_setgid"]),
    ("usr/bin/gsr-kms-server", &["cap_sys_admin"]),
    ("usr/bin/btop", &["cap_dac_read_search", "cap_perfmon"]),
    ("usr/bin/rcp", &["cap_net_bind_service"]),
    ("usr/bin/rlogin", &["cap_net_bind_service"]),
    ("usr/bin/rsh", &["cap_net_bind_service"]),
    ("usr/lib/gvfsd-nfs", &["cap_net_bind_service"]),
    (
        "usr/lib/gstreamer-1.0/gst-ptp-helper",
        &["cap_net_admin", "cap_net_bind_service"],
    ),
    ("usr/bin/ping", &["cap_net_raw"]),
    ("usr/bin/mtr-packet", &["cap_net_raw"]),
    ("usr/bin/fping", &["cap_net_raw"]),
    ("usr/bin/dumpcap", &["cap_net_admin", "cap_net_raw"]),
    ("usr/bin/nethogs", &["cap_net_admin", "cap_net_raw"]),
    ("usr/bin/gnome-keyring-daemon", &["cap_ipc_lock"]),
    ("usr/bin/kwin_wayland", &["cap_sys_nice"]),
    ("usr/bin/gamescope", &["cap_sys_nice"]),
    ("usr/bin/intel_gpu_top", &["cap_perfmon"]),
];
/// Entries the privileged-file walk looks at before it stops and says so.
const MAX_WALK: usize = 2_000_000;

/// The directories the search for set-id files could not list, or not in
/// full: how many, and the first of them by name.
#[derive(Default)]
pub(super) struct Closed {
    pub(super) count: usize,
    pub(super) first: Option<String>,
    /// The places closed to root on a mount where set-id bits have no
    /// effect (a user's own FUSE mount): how many, and the first by name.
    pub(super) covered: usize,
    pub(super) covered_first: Option<String>,
    /// Every mount, without its leading `/`, and whether it is `nosuid`;
    /// only read for root's search of the real system.
    pub(super) mounts: Vec<(String, bool)>,
}

/// The mount points of a `/proc/self/mountinfo`, without their leading
/// `/`, each with whether it is mounted `nosuid`, in the file's order.
pub(super) fn mounts(mountinfo: &str) -> Vec<(String, bool)> {
    mountinfo
        .lines()
        .filter_map(|line| {
            let mut fields = line.split(' ').skip(4);
            let place = fields.next()?;
            let nosuid = fields.next()?.split(',').any(|option| option == "nosuid");
            Some((
                mount_path(place).trim_start_matches('/').to_string(),
                nosuid,
            ))
        })
        .collect()
}

/// A mount point as the kernel writes it, with its `\040`-style escapes
/// read back.
fn mount_path(written: &str) -> String {
    let mut bytes = Vec::with_capacity(written.len());
    let mut rest = written.as_bytes();
    while let Some((&byte, after)) = rest.split_first() {
        let escaped = (byte == b'\\')
            .then(|| after.get(..3))
            .flatten()
            .and_then(|digits| std::str::from_utf8(digits).ok())
            .filter(|digits| digits.bytes().all(|digit| (b'0'..=b'7').contains(&digit)))
            .and_then(|digits| u8::from_str_radix(digits, 8).ok());
        if let Some(escaped) = escaped {
            bytes.push(escaped);
            rest = &after[3..];
        } else {
            bytes.push(byte);
            rest = after;
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

impl Closed {
    /// For a search of the real system by root, with the mounts read once.
    /// A mount point may be named in any bytes, so the file is read as
    /// bytes.
    fn of(scope: &Scope<'_>) -> Self {
        let mountinfo = if scope.root == Path::new("/") && scope.origin == Origin::Root {
            fs::read("/proc/self/mountinfo").unwrap_or_default()
        } else {
            Vec::new()
        };
        Self {
            mounts: mounts(&String::from_utf8_lossy(&mountinfo)),
            ..Self::default()
        }
    }

    /// Whether `place` is on a mount where set-id bits have no effect:
    /// the mount it is on is the deepest one above it, and of two at one
    /// place the later.
    pub(super) fn without_set_id(&self, place: &str) -> bool {
        let mut on: Option<&(String, bool)> = None;
        for mount in &self.mounts {
            let above = mount.0.is_empty()
                || place
                    .strip_prefix(mount.0.as_str())
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'));
            if above && on.is_none_or(|deepest| mount.0.len() >= deepest.0.len()) {
                on = Some(mount);
            }
        }
        on.is_some_and(|mount| mount.1)
    }

    pub(super) fn add(&mut self, directory: &str) {
        let (count, first) = if self.without_set_id(directory) {
            (&mut self.covered, &mut self.covered_first)
        } else {
            (&mut self.count, &mut self.first)
        };
        *count += 1;
        if first.as_deref().is_none_or(|first| directory < first) {
            *first = Some(directory.to_string());
        }
    }

    /// Says it in one sentence, however many there are. A user's sweep
    /// cannot list much of the system (`/root`, other homes), which is
    /// what the root checks are for; root, which nothing stands behind,
    /// leaves them unchecked and names one.
    pub(super) fn say(self, scope: &Scope<'_>, found: &mut Found) {
        // Nothing on such a mount is set-id to anyone, so the search is
        // whole without it; but the mount covers a directory that is not
        // on it, and that is said.
        if let Some(first) = &self.covered_first {
            found.notes.push(format!(
                "{} place(s) on mounts closed to root were not looked into (/{} among them): set-id bits have no effect on such a mount, but what its mount point covers cannot be seen",
                self.covered,
                first.escape_debug()
            ));
        }
        let Some(first) = self.first else {
            return;
        };
        let count = self.count;
        if scope.origin == Origin::Root {
            found.unchecked.push(format!(
                "setuid programs were not looked for in {count} place(s) that could not be listed (/{} among them)",
                first.escape_debug()
            ));
        } else {
            found.notes.push(format!(
                "setuid programs were not looked for in {count} place(s) that could not be listed; the root checks cover them"
            ));
        }
    }
}

/// Setuid and setgid files that no package vouches for.
fn set_id_files(scope: &Scope<'_>, found: &mut Found) {
    let mut looked_at = 0;
    let mut closed = Closed::of(scope);
    let root = scope.origin == Origin::Root;
    'walk: for start in PRIVILEGED_ROOTS {
        let mut pending = vec![(*start).to_string()];
        while let Some(directory) = pending.pop() {
            // Listed through the directory as opened, link by no link: a
            // directory swapped for a link elsewhere is not walked into.
            let opened =
                match read::seen(scope.root, &directory, View::Pinned).map(|seen| seen.what) {
                    Some(read::Public::Directory(opened)) => opened,
                    Some(read::Public::Link(_)) if directory == *start => {
                        found.unchecked.push(format!(
                            "/{directory} is a link: setuid programs were not looked for there"
                        ));
                        continue;
                    }
                    // No directory (any more): a link or a file.
                    Some(_) => continue,
                    // The pinned walk does not say why it shows nothing:
                    // what is gone is nothing, what is still there was
                    // not looked into.
                    None => {
                        let gone = fs::symlink_metadata(scope.root.join(&directory)).map_or_else(
                            |error| error.kind() == io::ErrorKind::NotFound,
                            |metadata| !metadata.is_dir(),
                        );
                        if !gone {
                            closed.add(&directory);
                        }
                        continue;
                    }
                };
            let Ok(listing) = fs::read_dir(format!("/proc/self/fd/{}", opened.as_raw_fd())) else {
                closed.add(&directory);
                continue;
            };
            let mut whole = true;
            for entry in listing {
                looked_at += 1;
                if looked_at > MAX_WALK {
                    found.unchecked.push(format!(
                        "more than {MAX_WALK} files: setuid programs were not looked for everywhere"
                    ));
                    break 'walk;
                }
                // An entry that went away meanwhile is nothing; one that
                // is there and cannot be asked about may be anything.
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(error) => {
                        whole = whole && error.kind() == io::ErrorKind::NotFound;
                        continue;
                    }
                };
                let metadata = match entry.metadata() {
                    Ok(metadata) => metadata,
                    Err(error) => {
                        // A mount closed to root shows here, not when it
                        // is opened, and is counted by its own name; any
                        // other entry leaves its directory not whole.
                        let path = format!("{directory}/{}", entry.file_name().to_string_lossy());
                        if error.kind() == io::ErrorKind::NotFound {
                        } else if closed.without_set_id(&path) {
                            closed.add(&path);
                        } else {
                            whole = false;
                        }
                        continue;
                    }
                };
                let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                    // A directory may hold set-id files; a file may be one.
                    if metadata.is_dir() || (metadata.is_file() && metadata.mode() & 0o6000 != 0) {
                        found.unchecked.push(collect::not_utf8(&format!(
                            "{directory}/{}",
                            entry.file_name().to_string_lossy()
                        )));
                    }
                    continue;
                };
                let path = format!("{directory}/{name}");
                if metadata.is_dir() {
                    if name != ".snapshots" && !PRIVILEGED_SKIPPED.contains(&path.as_str()) {
                        pending.push(path);
                    }
                } else if metadata.is_file() && metadata.mode() & 0o6000 != 0 {
                    let looked = collect::look(scope, Category::Setuid, &path, None);
                    // Root reports the file it opened, if that is the
                    // set-id file the listing showed.
                    let swapped = root
                        && !matches!(&looked, read::Found::File { mode, .. } if mode & 0o6000 != 0)
                        && !matches!(&looked, read::Found::Unreadable(reason) if reason == read::TOO_LARGE);
                    if !swapped {
                        privileged(scope, found, &path, &looked, "setuid or setgid", None);
                    }
                }
            }
            if !whole {
                closed.add(&directory);
            }
        }
    }
    closed.say(scope, found);
}

/// Setuid and setgid files, and files with capabilities, that no package
/// vouches for.
pub(super) fn privileged_files(scope: &Scope<'_>, found: &mut Found) {
    set_id_files(scope, found);
    match capability_files(scope) {
        Ok(files) => {
            // A name that is not UTF-8 comes out of getcap unreadable.
            found.unchecked.extend(
                files
                    .iter()
                    .filter(|(path, _)| path.contains('\u{fffd}'))
                    .map(|(path, _)| collect::not_utf8(path)),
            );
            for (path, capabilities) in files {
                // A name with a newline in it forges a line of getcap's
                // output, naming any path; only real files count, and the
                // file itself, not what a link of that name leads to.
                let Some(looked) = capable(scope, &path, &mut found.unchecked) else {
                    continue;
                };
                privileged(
                    scope,
                    found,
                    &path,
                    &looked,
                    &format!("capabilities {capabilities}"),
                    Some(&capabilities),
                );
            }
        }
        Err(reason) => found
            .unchecked
            .push(format!("file capabilities were not checked ({reason})")),
    }
}

/// What is at `path`, which getcap named, if it is a regular file. Root
/// looks at a path anyone can read as anyone would, and at one only root
/// can read once getcap, asked about it by itself, names it again: a forged
/// line then says nothing about a file its author cannot read.
fn capable(scope: &Scope<'_>, path: &str, unchecked: &mut Vec<String>) -> Option<read::Found> {
    let looked = if scope.origin == Origin::Root {
        read::look_as(scope.root, path, View::Everyone).or_else(|| {
            let Some(confirmed) = has_capabilities(path) else {
                // Which file is not said: the line may be forged.
                unchecked.push("a file getcap named could not be asked about again".into());
                return None;
            };
            confirmed
                .then(|| read::look_as(scope.root, path, View::Pinned))
                .flatten()
        })?
    } else {
        read::look(scope.root, path)
    };
    match looked {
        read::Found::Link(_) | read::Found::Other => None,
        // Root's pinned look says this only of a regular file; the user's
        // own sweep asks again.
        read::Found::Unreadable(_)
            if scope.origin != Origin::Root
                && !fs::symlink_metadata(scope.root.join(path))
                    .is_ok_and(|metadata| metadata.is_file()) =>
        {
            None
        }
        looked => Some(looked),
    }
}

pub(super) fn privileged(
    scope: &Scope<'_>,
    found: &mut Found,
    path: &str,
    looked: &read::Found,
    what: &str,
    capabilities: Option<&str>,
) {
    let item = collect::item_of(scope, Category::Setuid, path.to_string(), None, looked);
    // A package's set-id file only root can read cannot be hashed here; the
    // root checks hash it. Its owner and mode are what can be checked now.
    if matches!(item.body, Body::Unreadable(_)) && packaged(scope, path) {
        return;
    }
    // A copy of a packaged program with extra rights is the classic
    // backdoor (a setuid copy of a shell), so a copy is not trusted here.
    let vouched = matches!(item.tier, Tier::Vendor | Tier::Inert | Tier::Allowed);
    // Capabilities are not part of what pacman records, so a packaged
    // program given some (`setcap cap_setuid+ep python`, or all of them
    // with `=ep`) is only trusted with exactly those its package is known
    // to set.
    let (rule, why) = if vouched {
        match capabilities.and_then(|capabilities| unexpected_capabilities(path, capabilities)) {
            Some(RuleId::UnknownPrivilegedFile) => (
                RuleId::UnknownPrivilegedFile,
                "root-like rights its package does not set",
            ),
            Some(rule) => (rule, "rights its package does not set"),
            None => return,
        }
    } else {
        (RuleId::UnknownPrivilegedFile, "no package vouches for it")
    };
    found.items.entry(path.to_string()).or_insert(item);
    found.add(
        scope,
        Category::Setuid,
        path,
        format!("{what}; {why}"),
        Some(rule),
    );
}

/// The capabilities getcap's clauses give a file: every one (`=ep`,
/// `all=ep`), or those named, sorted. A clause lists names, then `=`, `+`
/// or `-` and the sets (`e`, `i`, `p`) it puts them in or takes them from;
/// one that only takes away, or puts them in no set, gives nothing.
pub(super) fn capability_names(clauses: &str) -> Option<Vec<String>> {
    let mut names = Vec::new();
    for clause in clauses.split_whitespace() {
        // `[rootid=1000]`: whose root the capabilities are for.
        if clause.starts_with('[') {
            continue;
        }
        let split = clause.find(['=', '+', '-']).unwrap_or(clause.len());
        let (named, sets) = clause.split_at(split);
        // Only `=` and `+` followed by a set give something.
        let mut taking = false;
        let mut gives = false;
        for c in sets.chars() {
            match c {
                '-' => taking = true,
                '=' | '+' => taking = false,
                'e' | 'i' | 'p' if !taking => gives = true,
                _ => {}
            }
        }
        if !gives {
            continue;
        }
        if named.is_empty() || named.eq_ignore_ascii_case("all") {
            return None;
        }
        names.extend(named.split(',').map(str::to_ascii_lowercase));
    }
    names.sort();
    names.dedup();
    Some(names)
}

/// The alert for capabilities on the packaged file at `path` that its
/// package is not known to set, by how far they go; none where they are
/// exactly the expected ones.
pub(super) fn unexpected_capabilities(path: &str, clauses: &str) -> Option<RuleId> {
    let Some(names) = capability_names(clauses) else {
        // Every capability there is.
        return Some(RuleId::UnknownPrivilegedFile);
    };
    let expected = EXPECTED_CAPABILITIES
        .iter()
        .any(|(known, capabilities)| *known == path && names == *capabilities);
    if names.is_empty() || expected {
        return None;
    }
    let root_like = names.iter().any(|name| {
        ROOT_CAPABILITIES.contains(&name.as_str()) || !OTHER_CAPABILITIES.contains(&name.as_str())
    });
    Some(if root_like {
        RuleId::UnknownPrivilegedFile
    } else {
        RuleId::UnexpectedCapability
    })
}

/// Whether getcap, asked about `path` alone, reports capabilities on it.
fn has_capabilities(path: &str) -> Option<bool> {
    let limits = Limits {
        timeout_secs: 30,
        max_output: 64 * 1024,
    };
    let arguments = [OsString::from(format!("/{path}"))];
    tools::run(
        Path::new(GETCAP),
        &arguments,
        None,
        &[("LC_ALL", "C")],
        limits,
    )
    .ok()
    .filter(|captured| getcap_failure(captured.status).is_none())
    .map(|captured| {
        parse_getcap(&String::from_utf8_lossy(&captured.stdout))
            .iter()
            .any(|(reported, _)| reported == path)
    })
}

/// How a getcap that did not give a whole answer ended. It exits with 0
/// whatever it found or could not open, so anything else (a time-out, a
/// signal, a failure) leaves part of the answer out.
pub(super) fn getcap_failure(status: ExitStatus) -> Option<String> {
    if status.success() {
        None
    } else if status.code() == Some(124) {
        // GNU timeout exits 124 when it had to stop the command.
        Some("getcap timed out".into())
    } else {
        Some(format!("getcap failed: {status}"))
    }
}

/// Files with capabilities, from `getcap -r` (on the real system only).
fn capability_files(scope: &Scope<'_>) -> Result<Vec<(String, String)>, String> {
    if scope.root != Path::new("/") {
        return Ok(Vec::new());
    }
    let roots: Vec<OsString> = PRIVILEGED_ROOTS
        .iter()
        .map(|root| OsString::from(format!("/{root}")))
        .filter(|root| Path::new(root).is_dir())
        .collect();
    capabilities_below(Path::new(GETCAP), &roots)
}

/// What `getcap -r` reports below `roots`. A getcap that is missing,
/// cannot be started or does not finish is an error: what it printed until
/// then is not the whole list.
pub(super) fn capabilities_below(
    getcap: &Path,
    roots: &[OsString],
) -> Result<Vec<(String, String)>, String> {
    if !getcap.is_file() {
        return Err(format!("{} is not installed", getcap.display()));
    }
    let mut args = vec![OsString::from("-r")];
    args.extend(roots.iter().cloned());
    let captured = tools::run(
        getcap,
        &args,
        None,
        &[("LC_ALL", "C")],
        Limits {
            timeout_secs: 300,
            max_output: 4 * 1024 * 1024,
        },
    )
    .map_err(|error| error.to_string())?;
    if let Some(failure) = getcap_failure(captured.status) {
        return Err(failure);
    }
    Ok(parse_getcap(&String::from_utf8_lossy(&captured.stdout)))
}

/// Whether `word` is a clause of getcap's output: names (or numbers, for
/// capabilities getcap has no name for), then the sets they are in.
pub(super) fn is_clause(word: &str) -> bool {
    if word.starts_with("[rootid=") && word.ends_with(']') {
        return true;
    }
    let Some(split) = word.find(['=', '+', '-']) else {
        return false;
    };
    let (names, sets) = word.split_at(split);
    names
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | ','))
        && sets.chars().all(|c| "=+-eip".contains(c))
}

/// `getcap` lines: the path, then capability clauses (`cap_x,cap_y=ep`,
/// `=ep`, `cap_x+ep cap_y+i`, ` [rootid=N]`); a path may hold spaces, so
/// the clauses are taken from the end of the line.
pub(super) fn parse_getcap(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let mut split = line.len();
            while let Some((before, word)) = line[..split].rsplit_once(' ')
                && is_clause(word)
            {
                split = before.len();
            }
            let (path, capabilities) = line.split_at(split);
            (!capabilities.is_empty()).then_some(())?;
            Some((
                path.strip_prefix('/')?.to_string(),
                capabilities.trim().to_string(),
            ))
        })
        .collect()
}
