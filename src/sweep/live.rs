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
//! - `process` reads the processes from `/proc`, and `program` tells what
//!   each one runs: its script, its module, where it was started.
//! - `preload` looks at what is preloaded, at programs running from
//!   temporary directories, and at who reads the keyboard or a camera.
//! - `modules` checks the loaded kernel modules against the packaged ones.
//! - `privileged` looks for setuid, setgid and capability files.

mod files;
mod kernel;
mod modules;
mod net;
mod preload;
mod privileged;
mod process;
mod program;

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use super::collect::{self, Body, Item, Origin, Scope};
use super::programs::is_interpreter;
#[cfg(test)]
use super::programs::script_arguments;
use super::tier::Tier;
use crate::autorun::Category;
use crate::paths::file_name;
use crate::rules::RuleId;

use modules::{kernel, kernel_installed, kernel_release, module_name};
#[cfg(test)]
use preload::{Preload, preloaded, searched};
use preload::{device_checks, is_temporary, preload_checks, temporary_checks};
use privileged::privileged_files;
#[cfg(test)]
use privileged::{
    Closed, EXPECTED_CAPABILITIES, OTHER_CAPABILITIES, ROOT_CAPABILITIES, capabilities_below,
    capability_names, getcap_failure, is_clause, mounts, parse_getcap, privileged,
    unexpected_capabilities,
};
#[cfg(test)]
use process::of_root;
use process::{parse_status, processes};
use program::{module_of, normalize, scripts, started_in, subject, told};

/// Notes kept per item: one program can run as many processes.
const MAX_NOTES: usize = 3;

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

#[cfg(test)]
mod tests;
