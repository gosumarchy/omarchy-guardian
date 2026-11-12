//! Setuid and setgid files, and files with capabilities, that no package
//! vouches for, and the walk that finds them.

use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt;
use std::rc::Rc;

use super::capability::{self, Capabilities};
use super::mount_table::MountTable;
use super::pinned::{self, Held, Identity};
use super::{Chooser, Found, NOT_READ_PAST_LIMIT, Source, packaged, source};
use crate::autorun::Category;
use crate::rules::RuleId;
use crate::sweep::collect::{self, Body, Origin, Scope};
use crate::sweep::read::{self, View};
use crate::sweep::tier::Tier;

/// Where setuid and capability files are looked for.
/// The home directories last: they hold the most files, and the walk stops
/// at a limit.
const PRIVILEGED_ROOTS: &[&str] = &["usr", "opt", "etc", "var", "srv", "root", "home"];
/// Under those, what holds other systems' files (containers, packages
/// not installed). A snapshot directory is skipped too (`Walk::skipped`).
///
/// The Trash (`~/.local/share/Trash`) is not skipped: a file moved there
/// keeps its set-id bits and capabilities and still runs by its path, and
/// any program of the account may write there. A folder of many such files
/// is shown as one row instead (`layout::by_folder`).
const PRIVILEGED_SKIPPED: &[&str] = &[
    "var/lib/docker",
    "var/lib/containers",
    "var/lib/machines",
    "var/lib/flatpak",
    "var/cache/pacman",
];
/// The inode number of a btrfs subvolume's root (`BTRFS_FIRST_FREE_OBJECTID`,
/// `linux/btrfs_tree.h`), which snapper's `.snapshots` is.
const SUBVOLUME_ROOT: u64 = 256;
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
/// How much the walk reads before it stops and says so.
#[derive(Debug, Clone, Copy)]
pub(super) struct Budget {
    /// The entries one run looks at.
    pub(super) files: usize,
    /// The bytes of the accounts' privileged files hashed; past it, each is
    /// listed unhashed. An account can make as many large set-id files as
    /// its quota holds, each read in full (up to `MAX_HASHED_FILE_SIZE`).
    pub(super) hashed: u64,
}

impl Budget {
    /// The sweep's. The bytes are arbitrary: eight times the largest file
    /// hashed, far above what the set-id files of a system come to (tens
    /// of MiB).
    pub(super) const SWEEP: Self = Self {
        files: 2_000_000,
        hashed: 8 * crate::scan::MAX_HASHED_FILE_SIZE,
    };
}

/// Why an account's privileged file past `Budget::hashed` is not hashed.
const UNHASHED: &str = "not hashed: the accounts' privileged files hashed came to the limit";

/// Whether a privileged file was left unread for a bound (its size, the
/// accounts' hashed bytes, or the live checks' files read), not for what it
/// is: such a file is not vouched for.
fn is_left_unread(reason: &str) -> bool {
    reason == read::TOO_LARGE || reason == UNHASHED || reason == NOT_READ_PAST_LIMIT
}
/// How many directories below a start the walk goes. Arbitrary: four
/// times the deepest seen on a desktop (21, in a home). It bounds the
/// directories held open at once, one for each level, and the length of
/// the paths reported.
const MAX_DEPTH: usize = 64;
/// How the walk reads the capabilities of a file it holds
/// (`capability::capabilities`); tests give it another.
pub(super) type ReadCapabilities = fn(&fs::File) -> io::Result<Option<Capabilities>>;
/// The mount table set-id bits are judged by: that of process 1, the
/// service manager, which is the one every account's programs run under.
/// The collector's own table does not say: in the namespace systemd makes
/// for a unit with `NoNewPrivileges=yes` and `ProtectSystem=strict`, every
/// mount is `nosuid` (seen in such a unit's own `/proc/self/mountinfo`),
/// so every file there is on such a mount.
const HOST_MOUNTS: &str = "proc/1/mountinfo";

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
    /// Those the walk of the accounts' places could not list, or not in
    /// full: how many, and the first by name.
    pub(super) accounts: usize,
    pub(super) accounts_first: Option<String>,
    /// Every mount of the host's table (`HOST_MOUNTS`). `None` where the
    /// table was not read: a user's search, which does not rank files, or a
    /// root one that could not read it, where no file is then known to be
    /// on a mount where set-id bits take effect.
    pub(super) mounts: Option<Vec<Mount>>,
}

/// One mount of the host's table.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Mount {
    /// Where it is, without the leading `/`.
    pub(super) place: String,
    /// Whether it is mounted `nosuid`.
    pub(super) nosuid: bool,
}

/// The mounts of a `/proc/self/mountinfo`, in the file's order.
pub(super) fn mounts(mountinfo: &str) -> Vec<Mount> {
    mountinfo
        .lines()
        .filter_map(pinned::line)
        .map(|line| Mount {
            place: mount_path(line.place).trim_start_matches('/').to_string(),
            nosuid: line
                .mount_options
                .split(',')
                .any(|option| option == "nosuid"),
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

/// Whether the walk may ask about an entry it holds (`askable`).
#[derive(Debug)]
pub(super) enum Asked {
    /// It may, through this file.
    File(fs::File),
    /// It is on a mount where set-id bits have no effect, and is not asked
    /// about.
    Covered,
    /// It is on a mount that may not be asked about: it may be anything.
    Unknown,
    /// Something was mounted on it each time it was held, and was gone from
    /// the walk's table each time it was looked up (`hold_asked`). Not
    /// asked about.
    Gone,
}

/// The entry `name` of `directory` (on mount `mount`), held and judged
/// (see `askable`), with `kind` telling what a mount on it is. One whose
/// mount is gone from the walk's table since it was held is held again,
/// by its name, up to `MAX_HOLDS` times in all, and is `Asked::Gone` if
/// it is gone each time.
///
/// A mount of root's that expires once during the walk (autofs) is gone
/// at most once: held again, the entry is what is there now. Gone at
/// every hold takes something mounting and unmounting there over and over,
/// in step with the walk, which an honest system does not do. An account
/// does it on an entry it may write with `fusermount3`, and wins often:
/// measured in a user namespace, with a table read for each question and
/// 1,000 other mounts in it, 957 of 3,000 visits saw three misses where
/// each mount stayed 3 ms. So the caller counts it among the places
/// accounts may write, by the entry's path, and does not mark root's place
/// not checked; the cost is that a mount of root's churned that way is
/// only a note too.
///
/// What is under the mount cannot be judged instead: a copy of the
/// directory's mount without submounts (`open_tree`) would show it, but
/// the collector's unit allows neither `CAP_SYS_ADMIN` nor the mount
/// system calls, and keeps it that way.
pub(super) fn hold_asked(
    directory: &fs::File,
    mount: u64,
    name: &OsStr,
    kind: &mut dyn FnMut(u64) -> io::Result<pinned::MountKind>,
) -> io::Result<Asked> {
    for _ in 0..MAX_HOLDS {
        if let Some(asked) = askable(pinned::hold(directory, mount, name)?, &mut *kind) {
            return Ok(asked);
        }
    }
    Ok(Asked::Gone)
}

/// How many times `hold_asked` holds an entry whose mount is gone.
/// Arbitrary: two absorb one expiry of a mount of root's, and the third
/// one more.
pub(super) const MAX_HOLDS: usize = 3;

/// How the walk holds and asks about what it meets; tests give it other
/// answers.
pub(super) struct Ask<'a> {
    /// Reads the capabilities of a file held.
    pub(super) capabilities: ReadCapabilities,
    /// Holds the entry `name` of a directory on mount `mount` and tells
    /// whether it may be asked about (`hold_asked`).
    pub(super) entry: &'a mut dyn FnMut(&fs::File, u64, &OsStr) -> io::Result<Asked>,
}

/// Whether the walk may ask about the entry `held` holds (see `pinned`),
/// with `kind` telling what a mount on it is in the walk's own table
/// (`MountTable::kind`): on its directory's own mount, or on a mount of
/// root's, it may; on an account's own FUSE mount, never. Where the table
/// cannot be read nothing is asked, since an account's mount may never
/// answer. `None` where the mount is gone from the table since the entry
/// was held: held again, its name leads to what was under it.
///
/// The host's table is not asked: a mount root made after it was read (a
/// home activated during the sweep) would be left out, and an account's
/// mount on top of one it named would be asked about.
pub(super) fn askable(
    held: Held,
    kind: impl FnOnce(u64) -> io::Result<pinned::MountKind>,
) -> Option<Asked> {
    let (file, mount) = match held {
        Held::Here(file) => return Some(Asked::File(file)),
        Held::Mounted(file, mount) => (file, mount),
    };
    let asked = match kind(mount) {
        Ok(pinned::MountKind::Accounts) => Asked::Covered,
        Ok(pinned::MountKind::Roots) => Asked::File(file),
        Ok(pinned::MountKind::Gone) => return None,
        Err(_) => Asked::Unknown,
    };
    Some(asked)
}

impl Closed {
    /// For a search by root, with the host's mounts (`HOST_MOUNTS`) read
    /// once. A table that is not there or cannot be read is said in
    /// `found`, and leaves every file an account's. A mount point may be
    /// named in any bytes, so the file is read as bytes.
    fn of(scope: &Scope<'_>, found: &mut Found) -> Self {
        if scope.origin != Origin::Root {
            return Self::default();
        }
        let why = match source(fs::read(scope.root.join(HOST_MOUNTS))) {
            Source::Read(mountinfo) => {
                return Self {
                    mounts: Some(mounts(&String::from_utf8_lossy(&mountinfo))),
                    ..Self::default()
                };
            }
            Source::Absent => "is not there".to_string(),
            Source::Unreadable(reason) => format!("could not be read ({reason})"),
        };
        found.not_checked(
            scope,
            format!(
                "/{HOST_MOUNTS} {why}: which mounts let set-id bits take effect is not known, so \
                 every setuid file and file with capabilities counts as an account's item"
            ),
        );
        Self::default()
    }

    /// Whether `place` is on a mount without set-id (`nosuid`): `None`
    /// where that is not known, the table not read or no mount above it.
    /// The mount it is on is the deepest one above it, and of two at one
    /// place the later.
    fn nosuid(&self, place: &str) -> Option<bool> {
        let mut on: Option<&Mount> = None;
        for mount in self.mounts.as_deref()? {
            let above = mount.place.is_empty()
                || place
                    .strip_prefix(mount.place.as_str())
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'));
            if above && on.is_none_or(|deepest| mount.place.len() >= deepest.place.len()) {
                on = Some(mount);
            }
        }
        on.map(|mount| mount.nosuid)
    }

    /// Whether `place` is known to be on a mount where set-id bits have no
    /// effect.
    pub(super) fn without_set_id(&self, place: &str) -> bool {
        self.nosuid(place) == Some(true)
    }

    /// Whether `place` is known to be on a mount where set-id bits and
    /// capabilities take effect.
    fn with_set_id(&self, place: &str) -> bool {
        self.nosuid(place) == Some(false)
    }

    pub(super) fn add(&mut self, directory: &str) {
        let (count, first) = if self.without_set_id(directory) {
            (&mut self.covered, &mut self.covered_first)
        } else {
            (&mut self.count, &mut self.first)
        };
        count_first(count, first, directory);
    }

    /// Counts `place` among those on a mount where set-id bits have no
    /// effect, which is not asked about.
    fn add_covered(&mut self, place: &str) {
        count_first(&mut self.covered, &mut self.covered_first, place);
    }

    /// `add` for a place accounts may write, which only a note tells: an
    /// account can keep root out of its own directories.
    fn add_accounts(&mut self, directory: &str) {
        let (count, first) = if self.without_set_id(directory) {
            (&mut self.covered, &mut self.covered_first)
        } else {
            (&mut self.accounts, &mut self.accounts_first)
        };
        count_first(count, first, directory);
    }

    /// Says it in one sentence, however many there are. A user's sweep
    /// cannot list much of the system (`/root`, other homes), which is
    /// what the root checks are for; root, which nothing stands behind,
    /// leaves them unchecked and names one.
    pub(super) fn say(&self, scope: &Scope<'_>, found: &mut Found) {
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
        if let Some(first) = &self.accounts_first {
            found.notes.push(format!(
                "setuid programs and files with capabilities were not looked for in {} place(s) \
                 accounts may write that could not be listed (/{} among them)",
                self.accounts,
                first.escape_debug()
            ));
        }
        let Some(first) = &self.first else {
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

/// Counts `directory` in `count`, keeping the first by name in `first`.
fn count_first(count: &mut usize, first: &mut Option<String>, directory: &str) {
    *count += 1;
    if first.as_deref().is_none_or(|first| directory < first) {
        *first = Some(directory.to_string());
    }
}

/// Setuid and setgid files, and files with capabilities, that no package
/// vouches for.
pub(super) fn privileged_files(scope: &Scope<'_>, found: &mut Found) {
    let mut closed = Closed::of(scope, found);
    privileged_walk(
        scope,
        found,
        &mut closed,
        Budget::SWEEP,
        capability::capabilities,
    );
}

/// Walks `PRIVILEGED_ROOTS` for set-id files and files with capabilities
/// (read from each regular file's attribute, see `capability`).
///
/// In root's search, the directories only root names files in are walked
/// first, and every other directory (`/home/u`, `/var/tmp`,
/// `/var/spool/mail`) after, with a `budget` of files of its own: an
/// account that fills one with files must not keep the walk from root's
/// places, nor mark root's results incomplete, so running out there, or a
/// directory there that cannot be listed, is a note. A user's search,
/// which cannot tell where set-id bits take effect, is one run.
///
/// Names that are not UTF-8 are told by `OddNames`. Of a file with more
/// than one name, only the first the walk meets is looked at, so one file
/// is one item; the accounts' files are hashed up to `budget.hashed`, so
/// no account can make the walk read without bound. A directory below a
/// start is opened through the one that listed it, held open (`pinned`):
/// walked to again from the root, a chain an account makes as deep as it
/// likes would cost the square of its depth.
pub(super) fn privileged_walk(
    scope: &Scope<'_>,
    found: &mut Found,
    closed: &mut Closed,
    budget: Budget,
    read: ReadCapabilities,
) {
    let mut table = MountTable::default();
    let mut entry = |directory: &fs::File, mount, name: &OsStr| {
        hold_asked(directory, mount, name, &mut |id| table.kind(id))
    };
    let ask = Ask {
        capabilities: read,
        entry: &mut entry,
    };
    privileged_walk_asking(scope, found, closed, budget, ask);
}

/// `privileged_walk`, holding and asking as `ask` says.
pub(super) fn privileged_walk_asking<'a>(
    scope: &Scope<'_>,
    found: &mut Found,
    closed: &'a mut Closed,
    budget: Budget,
    ask: Ask<'a>,
) {
    let owner = fs::metadata(scope.root).ok().map(|metadata| metadata.uid());
    let mut walk = Walk {
        closed,
        odd_names: OddNames::default(),
        accounts: Vec::new(),
        owner,
        budget,
        places: Places::Roots,
        ask,
        named: HashSet::new(),
        counts: Counts::default(),
    };
    let roots: Vec<Pending> = PRIVILEGED_ROOTS
        .iter()
        .map(|start| Pending::Start((*start).to_string()))
        .collect();
    if walk.from(scope, found, roots, Places::Roots).is_some() {
        found.unchecked.push(format!(
            "more than {} files: setuid programs and files with capabilities were not \
             looked for everywhere",
            budget.files
        ));
    }
    let accounts = std::mem::take(&mut walk.accounts);
    if let Some(at) = walk.from(scope, found, accounts, Places::Accounts) {
        found.notes.push(format!(
            "more than {} files in places accounts may write: setuid programs and files \
             with capabilities were not looked for in all of them (the walk stopped in /{})",
            budget.files,
            at.escape_debug()
        ));
    }
    walk.odd_names.say(scope, found);
    walk.counts.say(found);
    walk.closed.say(scope, found);
}

/// Which places one run of `Walk::from` walks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Places {
    /// Root's own: in root's search, a directory where not only root
    /// names files is put off (`Walk::accounts`).
    Roots,
    /// What was put off.
    Accounts,
}

/// The walk's state across its runs.
struct Walk<'c> {
    closed: &'c mut Closed,
    odd_names: OddNames,
    /// The directories where not only root names files that root's run
    /// reached, put off to a run of their own.
    accounts: Vec<Pending>,
    /// Who owns the root: the owner a directory only root may write has.
    owner: Option<u32>,
    budget: Budget,
    /// The run under way.
    places: Places,
    ask: Ask<'c>,
    /// The device and inode of each privileged file with more than one
    /// name that was looked at.
    named: HashSet<(u64, u64)>,
    counts: Counts,
}

/// What the walk left out, counted, each told in a note.
#[derive(Debug, Default)]
struct Counts {
    /// Privileged files named again (hard links), not looked at again.
    renamed: usize,
    /// Files with capabilities for a user namespace's root, not the host's.
    namespaced: usize,
    /// The bytes of the accounts' files hashed, and how many were not.
    hashed: u64,
    unhashed: usize,
    /// Directories past `MAX_DEPTH` not walked into: in root's places,
    /// and in the accounts'.
    deep: usize,
    deep_accounts: usize,
    /// The accounts' own set-id files looked at, by owner where owners are
    /// real (`Counts::keep`), and how many past `MAX_ACCOUNTS_ITEMS` were
    /// counted instead.
    kept: HashMap<Owner, usize>,
    cut: usize,
}

/// Whose bound one of the accounts' own set-id files counts against
/// (`Counts::keep`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Owner {
    /// Its owner's, by uid: on a mount where set-id bits take effect,
    /// owners are real and an account makes files only of its own.
    Real(u32),
    /// The one all share: elsewhere owners are what the filesystem says.
    Shared,
}

impl Owner {
    /// Whose bound a file of `uid` counts against, on a mount that is
    /// `nosuid` (`None` where that is not known: there, as on a nosuid
    /// mount, an account's own FUSE mount may say any owner).
    fn of(nosuid: Option<bool>, uid: u32) -> Self {
        if nosuid == Some(false) {
            Self::Real(uid)
        } else {
            Self::Shared
        }
    }
}

/// The most of the accounts' own set-id files looked at under one `Owner`,
/// each an item unless its package vouches for it; past it each is
/// counted. Kept in all: this many for each owner with files on a mount
/// where set-id bits take effect (an account makes files only of its own
/// uid there, so these are as many as the accounts), and this many shared.
/// Arbitrary, as `MAX_ODD`: well above what is shown of an account's
/// items, and each holds a path an account can make some 16 KiB long (64
/// levels of 255-byte names), so they are not kept without bound.
pub(super) const MAX_ACCOUNTS_ITEMS: usize = 1_000;

impl Counts {
    /// Whether one more of the accounts' own set-id files is looked at; one
    /// past `MAX_ACCOUNTS_ITEMS` under `owner` (see `Owner`) is counted, so
    /// one account's files cannot cut another's.
    fn keep(&mut self, owner: Owner) -> bool {
        let kept = self.kept.entry(owner).or_default();
        if *kept < MAX_ACCOUNTS_ITEMS {
            *kept += 1;
            true
        } else {
            self.cut += 1;
            false
        }
    }

    fn say(&self, found: &mut Found) {
        if self.cut > 0 {
            found.notes.push(format!(
                "{} more setuid or setgid file(s) of the accounts' own in places they may write \
                 were counted, not looked at: past {MAX_ACCOUNTS_ITEMS} of one owner's, or of \
                 those on mounts where set-id bits have no effect",
                self.cut
            ));
        }
        if self.renamed > 0 {
            found.notes.push(format!(
                "{} more name(s) of setuid files or files with capabilities already looked at \
                 were not looked at again",
                self.renamed
            ));
        }
        if self.namespaced > 0 {
            found.notes.push(format!(
                "{} name(s) of files with capabilities for a user namespace, which give \
                 nothing outside it, were not listed",
                self.namespaced
            ));
        }
        if self.deep > 0 {
            found.unchecked.push(format!(
                "{} directory(ies) more than {MAX_DEPTH} below where the walk starts were not \
                 looked into for setuid programs",
                self.deep
            ));
        }
        if self.deep_accounts > 0 {
            found.notes.push(format!(
                "{} directory(ies) more than {MAX_DEPTH} below where the walk starts, in places \
                 accounts may write, were not looked into for setuid programs",
                self.deep_accounts
            ));
        }
        if self.unhashed > 0 {
            found.notes.push(format!(
                "{} setuid file(s) or file(s) with capabilities in places accounts may write \
                 were listed without a hash: the accounts' files hashed came to the limit",
                self.unhashed
            ));
        }
    }
}

/// A directory the walk lists.
struct Listed {
    /// Its path below the root.
    path: String,
    /// The directory as opened, through which its entries are asked about.
    opened: fs::File,
    /// The mount it is on (`pinned::mount_of`).
    mount: u64,
    /// Whether only root names what it holds (see `Walk::open`).
    roots: bool,
    /// How many directories below a start it is.
    depth: usize,
}

/// An entry of a listed directory, held and asked about (`Walk::hold_entry`).
struct HeldEntry {
    held: fs::File,
    metadata: fs::Metadata,
    /// Whether set-id bits have no effect where it stands, as far as the
    /// host's table tells.
    nosuid: Option<bool>,
    /// The host's capabilities on it.
    capabilities: Option<Capabilities>,
}

/// A directory the walk is to list.
enum Pending {
    /// A start, by its path below the root, which is walked to from the
    /// root; every directory above it is root's alone.
    Start(String),
    /// A directory below a start, by where it was listed. Its path is
    /// built when it is listed: the directories still to be listed hold
    /// only their names, which an account can make as many of as it likes.
    Below(Below),
}

impl Pending {
    /// Its path below the root.
    fn path(&self) -> String {
        match self {
            Self::Start(path) => path.clone(),
            Self::Below(below) => {
                format!("{}/{}", below.parent.path, below.name.to_string_lossy())
            }
        }
    }

    /// Whether every directory above it is root's alone.
    fn above(&self) -> bool {
        match self {
            Self::Start(_) => true,
            Self::Below(below) => below.parent.roots,
        }
    }
}

/// Where a directory below a start was listed.
struct Below {
    /// The directory that listed it, held open while any of its
    /// directories is still to be listed.
    parent: Rc<Listed>,
    /// Its name there, and what the listing showed.
    name: OsString,
    listed: Identity,
}

/// What one entry of a listing is to the walk.
pub(super) enum Entry {
    /// A directory to walk: its name, and what the listing showed.
    Directory(OsString, Identity),
    /// Looked at, or gone meanwhile.
    Done,
    /// There, and could not be asked about: it may be anything.
    Unknown,
}

impl Walk<'_> {
    /// Walks `starts`, each with whether every directory above it is
    /// root's alone; the directory it stopped in where it looked at
    /// `budget` files.
    fn from(
        &mut self,
        scope: &Scope<'_>,
        found: &mut Found,
        starts: Vec<Pending>,
        places: Places,
    ) -> Option<String> {
        self.places = places;
        let mut looked_at = 0;
        for start in starts {
            let mut pending = vec![start];
            while let Some(next) = pending.pop() {
                let Some((listed, listing)) = self.open(scope, found, &next) else {
                    continue;
                };
                if places == Places::Roots && !listed.roots && scope.origin == Origin::Root {
                    self.accounts.push(next);
                    continue;
                }
                let listed = Rc::new(listed);
                let mut whole = true;
                for entry in listing {
                    looked_at += 1;
                    if looked_at > self.budget.files {
                        return Some(listed.path.clone());
                    }
                    match self.entry(scope, found, &listed, entry) {
                        Entry::Directory(..) if listed.depth >= MAX_DEPTH => self.deep(),
                        Entry::Directory(name, identity) => pending.push(Pending::Below(Below {
                            parent: Rc::clone(&listed),
                            name,
                            listed: identity,
                        })),
                        Entry::Done => {}
                        Entry::Unknown => whole = false,
                    }
                }
                if !whole {
                    self.close(&listed.path);
                }
            }
        }
        None
    }

    /// Counts a directory past `MAX_DEPTH`: in the accounts' run, among
    /// theirs.
    fn deep(&mut self) {
        match self.places {
            Places::Roots => self.counts.deep += 1,
            Places::Accounts => self.counts.deep_accounts += 1,
        }
    }

    /// Counts `directory` among those not listed, or not in full: in the
    /// accounts' run, among theirs.
    fn close(&mut self, directory: &str) {
        match self.places {
            Places::Roots => self.closed.add(directory),
            Places::Accounts => self.closed.add_accounts(directory),
        }
    }

    /// `next`, a place of `PRIVILEGED_ROOTS` or below one, as opened and
    /// listed. Only root names what it holds where root owns it, nobody
    /// else may write it (as opened, not as its path says now), every
    /// directory above is root's alone too, and, in root's search, set-id
    /// bits take effect on its mount; a user's search, which cannot read
    /// the host's mounts, goes by owner and mode. `None` where it is not
    /// walked.
    fn open(
        &mut self,
        scope: &Scope<'_>,
        found: &mut Found,
        next: &Pending,
    ) -> Option<(Listed, fs::ReadDir)> {
        let path = next.path();
        let directory = path.as_str();
        let (opened, depth) = match next {
            Pending::Start(_) => (self.open_start(scope, found, directory)?, 0),
            Pending::Below(below) => (self.open_below(directory, below)?, below.parent.depth + 1),
        };
        let (Ok(mount), Ok(listing)) = (
            pinned::mount_of(&opened),
            fs::read_dir(format!("/proc/self/fd/{}", opened.as_raw_fd())),
        ) else {
            self.close(directory);
            return None;
        };
        let roots = next.above()
            && opened.metadata().is_ok_and(|metadata| {
                Some(metadata.uid()) == self.owner && metadata.mode() & 0o022 == 0
            })
            && (scope.origin != Origin::Root || self.closed.with_set_id(directory));
        let listed = Listed {
            path,
            opened,
            mount,
            roots,
            depth,
        };
        Some((listed, listing))
    }

    /// The start `directory`, walked to from the root, link by no link: a
    /// start that is a link is not walked into.
    fn open_start(
        &mut self,
        scope: &Scope<'_>,
        found: &mut Found,
        directory: &str,
    ) -> Option<fs::File> {
        match read::seen(scope.root, directory, View::Pinned).map(|seen| seen.what) {
            Some(read::Public::Directory(opened)) => Some(opened),
            Some(read::Public::Link(_)) => {
                found.unchecked.push(format!(
                    "/{directory} is a link: setuid programs were not looked for there"
                ));
                None
            }
            // No directory: it holds nothing.
            Some(_) => None,
            // The pinned walk does not say why it shows nothing: what is
            // gone is nothing, what is still there was not looked into.
            None => {
                let gone = fs::symlink_metadata(scope.root.join(directory)).map_or_else(
                    |error| error.kind() == io::ErrorKind::NotFound,
                    |metadata| !metadata.is_dir(),
                );
                if !gone {
                    self.close(directory);
                }
                None
            }
        }
    }

    /// The directory at `directory`, opened through the directory that
    /// listed it (`below`) if it is still what that listing showed, or, in
    /// a directory only root names files in, whatever root put there since
    /// (a package upgrade replaces what it installs). One swapped
    /// meanwhile anywhere else is not looked into, nor one with something
    /// on it that may not be asked about (see `askable`).
    fn open_below(&mut self, directory: &str, below: &Below) -> Option<fs::File> {
        let parent = &below.parent;
        let held = match (self.ask.entry)(&parent.opened, parent.mount, &below.name) {
            Ok(Asked::File(held)) => held,
            Ok(Asked::Covered) => {
                self.closed.add_covered(directory);
                return None;
            }
            Ok(Asked::Unknown) => {
                self.close(directory);
                return None;
            }
            // As in `hold_entry`.
            Ok(Asked::Gone) => {
                self.closed.add_accounts(directory);
                return None;
            }
            Err(error) => return self.unopened(directory, parent, &error),
        };
        match pinned::is_listed(&held, below.listed) {
            Ok(listed) if listed || parent.roots => {}
            Ok(_) => {
                self.close(directory);
                return None;
            }
            Err(error) => return self.unopened(directory, parent, &error),
        }
        pinned::open_directory(&held)
            .map_or_else(|error| self.unopened(directory, parent, &error), Some)
    }

    /// Where `directory` in `parent` could not be opened for `error`. Gone
    /// meanwhile from where only root names files: nothing there. Anywhere
    /// else it may have been moved away while it was looked at, with what
    /// it holds (see `unasked`).
    fn unopened(
        &mut self,
        directory: &str,
        parent: &Listed,
        error: &io::Error,
    ) -> Option<fs::File> {
        if !(parent.roots && error.kind() == io::ErrorKind::NotFound) {
            self.close(directory);
        }
        None
    }

    /// Looks at one entry of `listed`: a set-id file or one with
    /// capabilities is an item, a directory is walked.
    fn entry(
        &mut self,
        scope: &Scope<'_>,
        found: &mut Found,
        listed: &Listed,
        entry: io::Result<fs::DirEntry>,
    ) -> Entry {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => return unasked(&error, listed.roots),
        };
        let name = entry.file_name();
        // As the mount table is read: lossily.
        let lossy = format!("{}/{}", listed.path, name.to_string_lossy());
        let HeldEntry {
            held,
            metadata,
            nosuid,
            capabilities,
        } = match self.hold_entry(listed, &name, &lossy) {
            Ok(looked) => looked,
            Err(done) => return done,
        };
        let Some(name) = name.to_str() else {
            self.odd_names
                .add(listed, name.as_bytes(), &metadata, capabilities);
            return Entry::Done;
        };
        // A name that is UTF-8 reads as itself.
        let path = lossy;
        if metadata.is_dir() {
            if self.skipped(name, &path, &metadata) {
                return Entry::Done;
            }
            return Entry::Directory(entry.file_name(), Identity::of(&metadata));
        }
        let set_id = metadata.is_file() && metadata.mode() & 0o6000 != 0;
        if !(set_id || capabilities.is_some()) || !self.first_name(&metadata) {
            return Entry::Done;
        }
        let alone = self.alone(listed, &metadata, &path);
        // Only an account's own set-id files can be made without bound: a
        // file of root's or with the host's capabilities, on a mount where
        // set-id bits take effect, is never cut, so decoys cannot hide one
        // (each inode is looked at once). Elsewhere owners are what the
        // filesystem says (an account's own disk image), and bits have no
        // effect. Root is uid 0 itself here, not the tree's owner as
        // `alone` takes it, since in a test tree every file is the owner's.
        let bounded = nosuid == Some(false) && (metadata.uid() == 0 || capabilities.is_some());
        let owner = Owner::of(nosuid, metadata.uid());
        if !alone && !bounded && !self.counts.keep(owner) {
            return Entry::Done;
        }
        let looked = self.look(found, &held, alone);
        let chooser = Chooser::of(alone);
        // The bits were read from the held file before it was read through
        // it, and an account can clear them on its own file in between
        // (`chmod` in a loop): root reports a file still set-id when read.
        // Any account can set the set-id bits on its own files, as many as
        // it likes. One root could not read (a lease, NFS with
        // `root_squash`, a bound) is reported as not read.
        let bits_gone = scope.origin == Origin::Root
            && match &looked {
                read::Found::File { mode, .. } => mode & 0o6000 == 0,
                read::Found::Unreadable(_) => false,
                read::Found::Link(_) | read::Found::Other => true,
            };
        if set_id && !bits_gone {
            found.through(chooser, |found| {
                privileged(scope, found, &path, &looked, "setuid or setgid", None);
            });
        }
        // An account's file whose bits were cleared while it was read is not
        // taken for no set-id file.
        let unseen = set_id && bits_gone && !listed.roots;
        // The capabilities were read from the held file too.
        if let Some(capabilities) = &capabilities {
            found.through(chooser, |found| {
                let what = format!("capabilities {capabilities}");
                privileged(scope, found, &path, &looked, &what, Some(capabilities));
            });
        }
        if unseen { Entry::Unknown } else { Entry::Done }
    }

    /// The entry `name` of `listed`, which stands at `lossy`, held and
    /// asked about where it may be (see `askable`): its metadata, whether
    /// set-id bits take effect where it stands, and the host's
    /// capabilities on it. `Err` where the entry is done with as it is.
    fn hold_entry(
        &mut self,
        listed: &Listed,
        name: &OsStr,
        lossy: &str,
    ) -> Result<HeldEntry, Entry> {
        // Held before anything is asked about it: a `stat` by its name
        // would reach a mount made on it since the table was read (see
        // `pinned`).
        let held = match (self.ask.entry)(&listed.opened, listed.mount, name) {
            Ok(Asked::File(held)) => held,
            Ok(Asked::Covered) => {
                self.closed.add_covered(lossy);
                return Err(Entry::Done);
            }
            Ok(Asked::Unknown) => return Err(Entry::Unknown),
            // An account's mount loop, as far as is known: see `hold_asked`.
            Ok(Asked::Gone) => {
                self.closed.add_accounts(lossy);
                return Err(Entry::Done);
            }
            Err(error) => return Err(unasked(&error, listed.roots)),
        };
        // Whether set-id bits take effect where the entry stands, by its
        // own place, since a file can be a mount point. A name that is not
        // UTF-8 reads lossily, as the host's table does, and an account
        // could pick one that reads as a mount point without set-id named
        // there; such a name is judged by its directory's mount, which an
        // account's mount on the entry itself never is (`askable`).
        let place = if name.to_str().is_some() {
            lossy
        } else {
            &listed.path
        };
        let nosuid = self.closed.nosuid(place);
        let metadata = match held.metadata() {
            Ok(metadata) => metadata,
            // A mount of root's on the entry that root may not ask about
            // (an NFS export that squashes root) refuses here, and where
            // set-id bits have no effect is counted by its own name.
            Err(_) if nosuid == Some(true) => {
                self.closed.add(lossy);
                return Err(Entry::Done);
            }
            Err(error) => return Err(unasked(&error, listed.roots)),
        };
        // Capabilities take no effect on a mount without set-id.
        let capabilities = if metadata.is_file() && nosuid != Some(true) {
            match (self.ask.capabilities)(&held) {
                Ok(capabilities) => self.of_host(capabilities),
                Err(error) => return Err(unasked(&error, listed.roots)),
            }
        } else {
            None
        };
        Ok(HeldEntry {
            held,
            metadata,
            nosuid,
            capabilities,
        })
    }

    /// `capabilities` where they are the host's; a user namespace's are
    /// counted. Any account can give its own files those (`unshare -Ur
    /// setcap`), and they give nothing outside a namespace it owns, where
    /// it holds every capability anyway.
    fn of_host(&mut self, capabilities: Option<Capabilities>) -> Option<Capabilities> {
        let capabilities = capabilities?;
        if capabilities.root_id != 0 {
            self.counts.namespaced += 1;
            return None;
        }
        Some(capabilities)
    }

    /// Whether the directory `name` at `path` holds other systems' files:
    /// one of `PRIVILEGED_SKIPPED`, or a snapshot directory, which is a
    /// subvolume of root's. Any account can name a directory `.snapshots`.
    fn skipped(&self, name: &str, path: &str, metadata: &fs::Metadata) -> bool {
        PRIVILEGED_SKIPPED.contains(&path)
            || (name == ".snapshots"
                && metadata.ino() == SUBVOLUME_ROOT
                && Some(metadata.uid()) == self.owner)
    }

    /// Whether the privileged file `metadata` describes is met for the
    /// first time; a name it was met by before is counted. Any account
    /// can give its own file as many names as it likes.
    fn first_name(&mut self, metadata: &fs::Metadata) -> bool {
        if metadata.nlink() < 2 || self.named.insert((metadata.dev(), metadata.ino())) {
            return true;
        }
        self.counts.renamed += 1;
        false
    }

    /// Whether the privileged file `metadata` describes, at `path` in
    /// `listed`, is root's alone: root's own, in a directory only root names
    /// files in (the walk follows no link, see `Walk::open`), on a mount
    /// known to let set-id bits and capabilities take effect (see `mounts`):
    /// no account can make more of those. On a `nosuid` mount they take
    /// none, and the owner and modes there are what the mount says (a
    /// user's FUSE mount, which `fusermount` and udisks always mount
    /// `nosuid`), so a file there counts as an account's. So does one in a
    /// directory an account may write or rename (`/home/u/d`, though `d`
    /// is root's): which file is at that path is the account's to choose.
    ///
    /// Root is whoever owns the root the checks run against: on a system
    /// that is root, and in a test tree the user who made it, so that a
    /// test can tell the two apart as any user, root included.
    fn alone(&self, listed: &Listed, metadata: &fs::Metadata, path: &str) -> bool {
        listed.roots && Some(metadata.uid()) == self.owner && self.closed.with_set_id(path)
    }

    /// The privileged file `held` holds, read through it, unless it is an
    /// account's (not root's `alone`) and the accounts' files hashed so far
    /// come to `Budget::hashed`, or the live checks' files read come to
    /// their limit (`Found::may_look`). Read by its path walked again from
    /// the root, it could be reached through a mount an account made on the
    /// way since it was listed (see `pinned`).
    fn look(&mut self, found: &mut Found, held: &fs::File, alone: bool) -> read::Found {
        if !alone && self.counts.hashed >= self.budget.hashed {
            self.counts.unhashed += 1;
            return read::Found::Unreadable(UNHASHED.to_string());
        }
        // Only the accounts' files count toward the live checks' limit:
        // root's own are never cut, so an account that runs many programs
        // cannot leave them unread.
        if !alone && !found.may_look() {
            return read::Found::Unreadable(NOT_READ_PAST_LIMIT.to_string());
        }
        let looked = match pinned::open_file(held) {
            Ok(file) => read::look_open(file, crate::scan::MAX_HASHED_FILE_SIZE),
            Err(error) => read::Found::Unreadable(error.to_string()),
        };
        if let (false, read::Found::File { size, .. }) = (alone, &looked) {
            self.counts.hashed += size;
        }
        looked
    }
}

/// What an entry the listing showed that could not be asked about is, in
/// a directory where only root names files (`roots`) or not. Gone meanwhile
/// from root's own is done with. Anywhere else an account may have moved it
/// away while it is looked at (`rename` in a loop), so it may be anything,
/// as is whatever else failed.
pub(super) fn unasked(error: &io::Error, roots: bool) -> Entry {
    if roots && error.kind() == io::ErrorKind::NotFound {
        Entry::Done
    } else {
        Entry::Unknown
    }
}

/// The most of the accounts' items for names that are not UTF-8 that are
/// kept; past it each is counted. Arbitrary, well above what is shown of
/// an account's items: each holds its directory's path, which an account
/// can make long, so they are not kept without bound.
const MAX_ODD: usize = 1_000;

/// Names that are not UTF-8, which the walk does not follow: read lossily,
/// each would name another file. A name an account chose must not mark
/// root's results incomplete (as `read_in_part`).
#[derive(Debug, Default)]
struct OddNames {
    /// What only root could have named, as its path's bytes: not checked.
    roots: Vec<Vec<u8>>,
    /// The accounts' set-id files and files with capabilities: the
    /// directory, the name, and what it is; each an alert.
    alerts: Vec<(String, Vec<u8>, String)>,
    /// The accounts' items past `MAX_ODD`.
    cut: usize,
    /// The accounts' directories, which were not walked into.
    directories: usize,
}

impl OddNames {
    /// Notes `name` in `listed`, of what `metadata` describes, with the
    /// `capabilities` read for it. Where only root names what `listed`
    /// holds, a directory, set-id file or file with capabilities is left
    /// unchecked. Anywhere else it is the accounts'.
    fn add(
        &mut self,
        listed: &Listed,
        name: &[u8],
        metadata: &fs::Metadata,
        capabilities: Option<Capabilities>,
    ) {
        let set_id = metadata.is_file() && metadata.mode() & 0o6000 != 0;
        if listed.roots {
            if metadata.is_dir() || set_id || capabilities.is_some() {
                let mut path = format!("{}/", listed.path).into_bytes();
                path.extend_from_slice(name);
                self.roots.push(path);
            }
            return;
        }
        if metadata.is_dir() {
            self.directories += 1;
            return;
        }
        let what = match (set_id, capabilities) {
            (false, None) => return,
            (true, None) => "a setuid or setgid file".to_string(),
            (false, Some(capabilities)) => format!("a file with capabilities ({capabilities})"),
            (true, Some(capabilities)) => {
                format!("a setuid or setgid file with capabilities ({capabilities})")
            }
        };
        if self.alerts.len() < MAX_ODD {
            self.alerts.push((listed.path.clone(), name.to_vec(), what));
        } else {
            self.cut += 1;
        }
    }

    /// Says what was noted.
    fn say(self, scope: &Scope<'_>, found: &mut Found) {
        for path in &self.roots {
            found.unchecked.push(collect::not_utf8_bytes(path));
        }
        for (directory, name, what) in &self.alerts {
            let note = format!(
                "/{directory}/{}: {what} whose name is not UTF-8, not looked at",
                name.escape_ascii()
            );
            odd_item(scope, found, directory, name, note);
        }
        if self.cut > 0 {
            found.notes.push(format!(
                "{} more setuid file(s) or file(s) with capabilities whose names are not UTF-8, \
                 in places accounts may write, were not listed",
                self.cut
            ));
        }
        if self.directories > 0 {
            found.notes.push(format!(
                "{} directory(ies) whose names are not UTF-8, in places accounts may write, were \
                 not looked into for setuid programs",
                self.directories
            ));
        }
    }
}

/// The accounts' alert for a privileged file named `name` in `directory`,
/// a name that is not UTF-8: named by a digest of the name's bytes, which
/// names no file.
fn odd_item(scope: &Scope<'_>, found: &mut Found, directory: &str, name: &[u8], note: String) {
    let digest = crate::sha256::Sha256::digest(name).to_string();
    found.through(Chooser::Account, |found| {
        found.add_missing(
            scope,
            Category::Setuid,
            &format!("{directory}#not-utf8-{}", &digest[..12]),
            "a name that is not UTF-8",
            note,
            RuleId::UnknownPrivilegedFile,
        );
    });
}
/// Lists the file at `path` as privileged, unless its package vouches for
/// it and its rights; the caller's chooser (see `Found::through`) ranks it.
pub(super) fn privileged(
    scope: &Scope<'_>,
    found: &mut Found,
    path: &str,
    looked: &read::Found,
    what: &str,
    capabilities: Option<&Capabilities>,
) {
    let item = collect::item_of(scope, Category::Setuid, path.to_string(), None, looked);
    // A package's set-id file only root can read cannot be hashed in a
    // user's sweep; the root checks hash it. One left unhashed for its size,
    // or past the accounts' budget or the live checks' limit, is not vouched for.
    let unhashed = matches!(
        looked,
        read::Found::Unreadable(reason) if is_left_unread(reason)
    );
    if matches!(item.body, Body::Unreadable(_)) && !unhashed && packaged(scope, path) {
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

/// The alert for capabilities on the packaged file at `path` that its
/// package is not known to set, by how far they go; none where they are
/// exactly the expected ones.
pub(super) fn unexpected_capabilities(path: &str, capabilities: &Capabilities) -> Option<RuleId> {
    let names = capabilities.names();
    let expected = EXPECTED_CAPABILITIES
        .iter()
        .any(|(known, expected)| *known == path && names == *expected);
    if expected {
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::fs;

    use super::{Closed, Counts, MAX_ACCOUNTS_ITEMS, Owner};
    use crate::sweep::collect::{Origin, Scope};
    use crate::sweep::index::PackageIndex;
    use crate::sweep::live::Found;
    use crate::test_support::TempDir;

    #[test]
    fn an_owner_is_real_only_where_set_id_bits_are_known_to_take_effect() {
        assert_eq!(Owner::of(Some(false), 1000), Owner::Real(1000));
        assert_eq!(Owner::of(Some(false), 0), Owner::Real(0));
        assert_eq!(Owner::of(Some(true), 1000), Owner::Shared);
        assert_eq!(Owner::of(None, 1000), Owner::Shared);
    }

    #[test]
    fn the_hosts_table_is_read_as_bytes() {
        let dir = TempDir::new("live-host-table");
        let root = dir.path();
        fs::create_dir_all(root.join("proc/1")).unwrap();
        let mut mountinfo = b"22 1 0:21 / / rw - ext4 /dev/sda1 rw\n".to_vec();
        mountinfo.extend_from_slice(b"40 22 0:40 / /mnt/\xff rw - tmpfs tmpfs rw\n");
        mountinfo.extend_from_slice(b"41 22 0:41 / /usr/local rw,nosuid - tmpfs tmpfs rw\n");
        fs::write(root.join("proc/1/mountinfo"), mountinfo).unwrap();
        let index = PackageIndex::with_foreign(HashSet::new());
        let scope = Scope {
            root,
            home: None,
            index: &index,
            origin: Origin::Root,
        };
        let mut found = Found::default();
        let closed = Closed::of(&scope, &mut found);
        assert!(closed.without_set_id("usr/local/x"));
        assert!(closed.with_set_id("usr/bin/x"));
        assert!(found.unchecked.is_empty(), "{:?}", found.unchecked);
    }

    #[test]
    fn one_accounts_set_id_files_do_not_use_up_anothers_bound() {
        let mut counts = Counts::default();
        for _ in 0..MAX_ACCOUNTS_ITEMS {
            assert!(counts.keep(Owner::Real(1000)));
        }
        assert!(!counts.keep(Owner::Real(1000)));
        assert!(counts.keep(Owner::Real(1001)));
        // Where owners are not real, all share one bound.
        for _ in 0..MAX_ACCOUNTS_ITEMS {
            assert!(counts.keep(Owner::Shared));
        }
        assert!(!counts.keep(Owner::Shared));
        assert_eq!(counts.cut, 2);
    }
}
