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
mod tests;
