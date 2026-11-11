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

mod capability;
mod files;
mod kernel;
mod modules;
mod mount_table;
mod net;
mod pinned;
mod preload;
mod privileged;
mod process;
mod program;

use std::collections::{BTreeMap, HashMap, HashSet};
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
use crate::json;
use crate::paths::file_name;
use crate::rules::RuleId;

use modules::{kernel, kernel_installed, kernel_release, module_name};
#[cfg(test)]
use preload::{Preload, preloaded, searched};
use preload::{device_checks, is_temporary, preload_checks, temporary_checks};
use privileged::privileged_files;
#[cfg(test)]
use privileged::{
    Closed, EXPECTED_CAPABILITIES, OTHER_CAPABILITIES, ROOT_CAPABILITIES, mounts, privileged,
    unexpected_capabilities,
};
#[cfg(test)]
use process::of_root;
use process::{parse_status, proc_text, processes, started_at, ticks_since_boot};
use program::{module_of, normalize, scripts, started_in, subject, told};

/// Notes kept per item: one program can run as many processes.
const MAX_NOTES: usize = 3;
/// The most bytes of one note as JSON writes it (a control character takes
/// six). A note names a path or two (each below 4 KiB, the kernel's limit)
/// and what was seen; past that the text is what an account wrote (a
/// library name in its environment, up to 128 KiB), and it may land on an
/// item of root's, which root's results keep whole.
const MAX_NOTE_BYTES: usize = 10 * 1024;

/// The most files the live checks read and hash in one sweep. Any process
/// names the files they look at (its program, the libraries it preloads),
/// any user can mark a file of their own set-id, and each may be a sparse
/// file of up to `MAX_HASHED_FILE_SIZE` that takes no disk space: at the
/// 512 MiB limit and about 180 MB/s for the hash (measured on a laptop in
/// 2026), 256 such files take some 13 minutes, which leaves the rest of the
/// root collector's 30 for its other bounds (`MAX_VOUCHED`,
/// `MAX_INSTALLED`) and its walk. A desktop's live checks read a few dozen
/// programs and set-id files. Past the limit an item is kept with its
/// alert, unread, and the sweep says files were left unread.
const MAX_LOOKED_AT: usize = 256;

/// What the live checks found.
#[derive(Debug, Default)]
pub(super) struct Live {
    pub(super) items: Vec<Item>,
    pub(super) notes: Vec<String>,
    /// What was not looked at, each as a sentence (see
    /// `Collection::truncated`).
    pub(super) unchecked: Vec<String>,
    /// The names of the items in `items` that only checks of what an
    /// account chose found (see `Chooser`): an account decides how many of
    /// those there are and what they are called.
    pub(super) of_accounts: HashSet<String>,
    /// The names of the items root's own checks or processes found, which
    /// are root's wherever they are: root decides how many there are.
    pub(super) of_root: HashSet<String>,
}

/// Who chose what a check looks at: root, or an account (its process, a
/// file it owns or could have put where it is). Any account can start a
/// process from any path it can write, listen on any free port and name a
/// program what it likes, so it decides how many items such checks find.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
enum Chooser {
    #[default]
    Root,
    Account,
}

impl Chooser {
    /// Who chose what a process is: root only for one that is root's in
    /// every respect (`Process::of_root`, `Status::of_root`).
    fn of(of_root: bool) -> Self {
        if of_root { Self::Root } else { Self::Account }
    }
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

/// A process whose program's path is not UTF-8 (see `not_utf8`).
struct Unnamed {
    pid: String,
    /// The path of its program, escaped.
    program: String,
    /// Root's own process (see `Process::of_root`).
    of_root: bool,
}

/// Every process the kernel lists, whoever it belongs to.
struct Listed {
    pid: u32,
    status: Status,
    /// The name it was started under (its first argument); none for a
    /// kernel thread, or a program that blanked its arguments.
    started_as: Option<Vec<u8>>,
    /// Whether the kernel marks it a kernel thread (`PF_KTHREAD` in its
    /// `stat`): a program cannot set that, and it can blank its arguments.
    kernel_thread: bool,
}

/// A running process, as far as it can be read.
#[derive(Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each is a separate fact read from /proc, not a state"
)]
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
    /// Its command line as the kernel keeps it, each argument ended by a
    /// null byte, cut at `process::MAX_START_BYTES` (see `arguments`).
    cmdline: Vec<u8>,
    /// What the checks use of its open files.
    open: Descriptors,
    /// The variables of its environment the checks read
    /// (`process::READ_VARIABLES`), each ended by a null byte.
    environment: Option<Vec<u8>>,
    /// More of its command line, or of those variables, was there than
    /// was kept (`process::MAX_START_BYTES`).
    read_in_part: bool,
    /// What of it that names a file is not UTF-8 (see `process::not_utf8`).
    not_utf8: Option<&'static str>,
    /// The mark of its working directory (see `program::started_in`).
    cwd_mark: Option<String>,
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

/// What the checks use of a process's open files (see
/// `process::descriptors`).
#[derive(Default)]
struct Descriptors {
    /// The sockets it holds, each once: the lowest descriptor that holds
    /// it, and its inode.
    sockets: Vec<(u32, u64)>,
    /// Its input (descriptor 0) is a terminal: somebody typed its command.
    on_terminal: bool,
    /// It has a keyboard open (see `preload::reads_keys`).
    keyboard: bool,
    /// The camera (`/dev/video…`) on the lowest descriptor that holds one.
    camera: Option<String>,
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

    /// Its arguments, its program's name first.
    fn arguments(&self) -> Vec<String> {
        process::arguments(&self.cmdline)
    }

    /// How it was started, shortened.
    fn started(&self) -> String {
        self.arguments()
            .iter()
            .take(4)
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Runs every live check against `scope` (its root holds `proc`).
pub(super) fn check(scope: &Scope<'_>) -> Live {
    let mut found = Found::default();
    let running = processes(scope.root);
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
    read_in_part(scope, &running, &mut found);
    not_utf8(scope, &running, &mut found);
    for process in &running.processes {
        found.through(Chooser::of(process.of_root), |found| {
            program_checks(scope, process, found);
        });
    }
    net::check(scope, &running, &mut found);
    kernel(scope, &mut found);
    kernel::check(scope, &running, &mut found);
    privileged_files(scope, &mut found);
    files::check(scope, &mut found);
    files::say_what_was_cut(scope, &mut found);
    // What root's checks found as well is root's, whoever else led to it.
    let of_root = found.of_root;
    let mut of_accounts = found.of_accounts;
    of_accounts.retain(|name| !of_root.contains(name));
    Live {
        items: found.items.into_values().collect(),
        notes: found.notes,
        unchecked: found.unchecked,
        of_accounts,
        of_root,
    }
}

/// Says which processes held more of what the checks read than was kept
/// (`process::MAX_START_BYTES`), or more environment than is read
/// (`process::MAX_ENVIRON_BYTES`). Root's own leave the root checks
/// incomplete. An account's is an item of the account's: it chose how
/// much its process holds, and must not be able to mark root's results
/// incomplete with it.
fn read_in_part(scope: &Scope<'_>, running: &Running, found: &mut Found) {
    let most = process::MAX_START_BYTES / 1024;
    let environ = process::MAX_ENVIRON_BYTES / 1024 / 1024;
    let (roots, accounts): (Vec<&Process>, Vec<&Process>) = running
        .processes
        .iter()
        .filter(|process| process.read_in_part)
        .partition(|process| process.of_root);
    if !roots.is_empty() {
        found.not_checked(
            scope,
            format!(
                "{} of root's running process(es) were looked at only in part: past {most} KiB \
                 of command line or of the library and Python search variables, or {environ} MiB \
                 of environment",
                roots.len()
            ),
        );
    }
    for process in accounts {
        let note = format!(
            "process {} ({}) was looked at only in part: past {most} KiB of command line or of \
             the library and Python search variables, or {environ} MiB of environment",
            process.pid,
            process.started()
        );
        found.through(Chooser::Account, |found| {
            found.add(scope, Category::Process, process.path(), note, None);
        });
    }
}

/// Says which processes name a file in a way that is not UTF-8, each as
/// one alert, an item `proc/<number>` of whoever owns the process: like
/// `read_in_part`, an account must not be able to mark root's results
/// incomplete with a name it chose, and no item is named after a file such
/// a name may stand for. A process whose program has such a name is not
/// checked at all; the others are, but for what those names point to.
/// Either may hide what it runs behind a name nothing can look up, so it
/// is always an alert (the owner's decision: no packaged program has such
/// a name, and a folder named so on a UTF-8 system is rare), and since
/// the next process may take its number, the item cannot be allowed (see
/// `state::not_allowable`).
fn not_utf8(scope: &Scope<'_>, running: &Running, found: &mut Found) {
    let unnamed = running.unnamed.iter().map(|unnamed| {
        let note = format!(
            "process {} ({}): the path of its program is not UTF-8, so it was not checked",
            unnamed.pid, unnamed.program
        );
        (&unnamed.pid, unnamed.of_root, note)
    });
    let named = running.processes.iter().filter_map(|process| {
        let part = process.not_utf8?;
        // As the kernel keeps it, escaped: read lossily, an argument would
        // name another file.
        let started = process
            .cmdline
            .split(|byte| *byte == 0)
            .filter(|argument| !argument.is_empty())
            .take(4)
            .map(|argument| argument.escape_ascii().to_string())
            .collect::<Vec<_>>()
            .join(" ");
        let note = format!(
            "process {} ({started}): {part} is not UTF-8, so what it names was not checked",
            process.pid
        );
        Some((&process.pid, process.of_root, note))
    });
    for (pid, of_root, note) in unnamed.chain(named) {
        found.through(Chooser::of(of_root), |found| {
            found.add_missing(
                scope,
                Category::Process,
                &format!("proc/{pid}"),
                "names what it runs in a way that is not UTF-8",
                note,
                RuleId::HiddenProgram,
            );
        });
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
    /// Who chose what the check under way looks at; set only by `through`.
    chooser: Chooser,
    /// The names of the items each side's checks added (see `Chooser`).
    /// Sets beside `items` rather than a field of `Item`: only the root
    /// collector asks, once, and `Item` is shared with the user's sweep
    /// and the results' format. A field would not remove `chooser` either:
    /// the forty-odd places that add an item would each need it as one
    /// more parameter (which takes `add_as` past clippy's limit on
    /// arguments), or read it from here as they do now.
    of_root: HashSet<String>,
    of_accounts: HashSet<String>,
    /// The files read for new items, set-id files and files with
    /// capabilities, up to `MAX_LOOKED_AT`, and whether the limit was said.
    looked_at: usize,
    said_limit: bool,
    /// What reading each file as each kind gave, so a program seen doing
    /// many things (listening on many ports) is read once.
    read: HashMap<(String, Category), Item>,
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
    /// Runs `check` on what `chooser` chose: the items it adds count as
    /// that side's.
    fn through(&mut self, chooser: Chooser, check: impl FnOnce(&mut Self)) {
        let outer = std::mem::replace(&mut self.chooser, chooser);
        check(self);
        self.chooser = outer;
    }

    /// Notes that `chooser` added to the item `name`.
    fn mark(&mut self, chooser: Chooser, name: &str) {
        let side = match chooser {
            Chooser::Root => &mut self.of_root,
            Chooser::Account => &mut self.of_accounts,
        };
        if !side.contains(name) {
            side.insert(name.to_string());
        }
    }

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

    /// Whether one more file may be read, within `MAX_LOOKED_AT`; the first
    /// time it may not, that is said as not checked, in a user's sweep too:
    /// root's checks have a limit of their own, and do not stand behind it.
    fn may_look(&mut self) -> bool {
        may_look(
            &mut self.looked_at,
            &mut self.said_limit,
            &mut self.unchecked,
        )
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
        let note = cut_note(note);
        // What an account's process runs or loads is the account's even
        // when the file is root's: it picks among every file root has (a
        // program under `/usr/bin` with `LD_LIBRARY_PATH` set, any path in a
        // mount namespace of its own, any file in `LD_PRELOAD`), far more
        // than root's results hold. Root's own checks rank such a file
        // root's where they find it themselves.
        self.mark(self.chooser, name);
        let Self {
            items,
            read,
            looked_at,
            said_limit,
            unchecked,
            ..
        } = self;
        let item = items.entry(name.to_string()).or_insert_with(|| {
            let key = (path.to_string(), category);
            let mut item = if let Some(seen) = read.get(&key) {
                seen.clone()
            } else if may_look(looked_at, said_limit, unchecked) {
                let item = collect::item_named(scope, category, path, path);
                read.insert(key, item.clone());
                item
            } else {
                unread_item(scope, category, path, NOT_READ_PAST_LIMIT)
            };
            if name != path {
                item.path = name.to_string();
                item.file = Some(path.to_string());
            }
            item
        });
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
        let note = cut_note(note);
        self.mark(self.chooser, path);
        let item = self
            .items
            .entry(path.to_string())
            .or_insert_with(|| unread_item(scope, category, path, reason));
        push_note(item, note.clone());
        if !item.alerts.iter().any(|(existing, _)| *existing == rule) {
            item.alerts.push((rule, note));
        }
    }
}

/// `note` cut to `MAX_NOTE_BYTES` as written in JSON.
fn cut_note(mut note: String) -> String {
    let mut written = 0;
    let end = note.char_indices().find_map(|(index, character)| {
        written += json::written_len(character);
        (written > MAX_NOTE_BYTES).then_some(index)
    });
    if let Some(end) = end {
        note.truncate(end);
        note.push('…');
    }
    note
}

/// Counts one more file read in `looked_at`, within `MAX_LOOKED_AT`; past
/// it says so once, in `unchecked`.
fn may_look(looked_at: &mut usize, said_limit: &mut bool, unchecked: &mut Vec<String>) -> bool {
    if *looked_at < MAX_LOOKED_AT {
        *looked_at += 1;
        return true;
    }
    if !*said_limit {
        *said_limit = true;
        unchecked.push(format!(
            "the live checks read at most {MAX_LOOKED_AT} files: the rest of the programs, libraries, modules, set-id files and files with capabilities they found are listed unread"
        ));
    }
    false
}

/// Why an item past `MAX_LOOKED_AT` was not read. The judge tells it from
/// a file only root can read by this text.
pub(in crate::sweep) const NOT_READ_PAST_LIMIT: &str =
    "not read: the live checks' limit of 256 files was reached";

const _: () = assert!(MAX_LOOKED_AT == 256, "NOT_READ_PAST_LIMIT names the limit");

/// An item for `path` that the live checks did not read, for `reason`.
fn unread_item(scope: &Scope<'_>, category: Category, path: &str, reason: &str) -> Item {
    Item {
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
    /// Processes not checked: the path of their program is not UTF-8.
    unnamed: Vec<Unnamed>,
    /// When the list was read, in ticks since boot (see `ticks_since_boot`):
    /// a process missing from it that started before then was hidden from
    /// it, whatever a later list shows.
    listed_at: Option<u64>,
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
