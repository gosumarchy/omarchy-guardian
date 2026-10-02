//! The sweep's live checks: what is running now, the way Objective-See's
//! process, network, keyboard, camera and kernel-extension viewers look at a
//! Mac.
//!
//! Only what does not add up is listed, so a clean system shows nothing:
//! a running program with no file on disk, or running from a temporary or
//! cache directory; a library no package installed preloaded into a
//! program; a program no repository package installed that listens on the
//! network, reads the keyboard or uses a camera; a loaded kernel module no
//! package installed; and setuid, setgid or capability files no package
//! vouches for. Everything is read from `/proc`, `modules.dep` and file
//! modes; nothing found is run. As a user only the user's own processes
//! can be inspected, so the root collector runs these checks too.

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use super::collect::{self, Body, Item, Origin, Scope};
use super::read::{self, View};
use super::tier::Tier;
use crate::autorun::Category;
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
/// Capabilities that amount to root.
const DANGEROUS_CAPABILITIES: &[&str] = &[
    "cap_setuid",
    "cap_setgid",
    "cap_sys_admin",
    "cap_sys_ptrace",
    "cap_sys_module",
    "cap_dac_override",
    "cap_chown",
    "cap_fowner",
];
/// Packaged programs that set such capabilities on themselves.
const EXPECTED_CAPABILITIES: &[(&str, &str)] = &[
    ("usr/bin/newuidmap", "cap_setuid"),
    ("usr/bin/newgidmap", "cap_setgid"),
    ("usr/bin/gsr-kms-server", "cap_sys_admin"),
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

/// A running process, as far as it can be read.
struct Process {
    pid: String,
    /// The `exe` link's text (`/usr/bin/x`, `/x (deleted)`, `/memfd:y`).
    exe: String,
    /// The device and inode of the file the process really runs.
    exe_id: Option<(u64, u64)>,
    arguments: Vec<String>,
    /// Where its open files lead.
    fds: Vec<String>,
    environment: Option<Vec<u8>>,
    /// Its working directory, relative to `/`: what a script given by a
    /// relative name is relative to.
    cwd: Option<String>,
    /// It runs in a user namespace of its own, where it can mount what it
    /// likes over any path: the name of its program vouches for nothing.
    own_namespace: bool,
    /// Root's own process: nobody else chose what it is called.
    of_root: bool,
}

/// Runs every live check against `scope` (its root holds `proc`).
pub fn check(scope: &Scope<'_>) -> Live {
    let mut found = Found::default();
    let (processes, hidden) = processes(&scope.root.join("proc"));
    if hidden > 0 {
        found.notes.push(format!(
            "{hidden} running process(es) of other users could not be looked at; the root checks cover them"
        ));
    }
    for process in &processes {
        program_checks(scope, process, &mut found);
    }
    listeners(scope, &processes, &mut found);
    kernel(scope, &mut found);
    privileged_files(scope, &mut found);
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
}

impl Found {
    /// Adds what was seen about the file at `path`; one item per path.
    fn add(
        &mut self,
        scope: &Scope<'_>,
        category: Category,
        path: &str,
        note: String,
        alert: Option<RuleId>,
    ) {
        let item = self
            .items
            .entry(path.to_string())
            .or_insert_with(|| collect::item(scope, category, path.to_string(), None));
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

/// Whether a repository package installed the file at `path`.
fn packaged(scope: &Scope<'_>, path: &str) -> bool {
    scope
        .index
        .owner(path)
        .is_some_and(|owned| !scope.index.is_foreign(scope.index.package(owned)))
}

/// Every process whose program can be read, and how many could not be.
fn processes(proc: &Path) -> (Vec<Process>, usize) {
    let Ok(listing) = fs::read_dir(proc) else {
        return (Vec::new(), 0);
    };
    let mut processes = Vec::new();
    let mut hidden = 0;
    let namespace = |directory: &Path| fs::read_link(directory.join("ns/user")).ok();
    let ours = namespace(&proc.join("self"));
    for entry in listing.filter_map(Result::ok) {
        let Some(pid) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !pid.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let directory = entry.path();
        // Asked before and after the rest is read: a process number may
        // pass to another process in between.
        let root_before = of_root(&directory);
        let exe = match fs::read_link(directory.join("exe")) {
            Ok(exe) => exe.to_string_lossy().into_owned(),
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                hidden += 1;
                continue;
            }
            // Kernel threads have no program; a process may have exited.
            Err(_) => continue,
        };
        let fds = fs::read_dir(directory.join("fd"))
            .map(|fds| {
                fds.filter_map(Result::ok)
                    .filter_map(|fd| fs::read_link(fd.path()).ok())
                    .map(|target| target.to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        let environment = fs::read(directory.join("environ")).ok();
        let exe_id = fs::metadata(directory.join("exe"))
            .ok()
            .map(|metadata| (metadata.dev(), metadata.ino()));
        let arguments = fs::read(directory.join("cmdline"))
            .map(|bytes| {
                bytes
                    .split(|byte| *byte == 0)
                    .filter(|argument| !argument.is_empty())
                    .map(|argument| String::from_utf8_lossy(argument).into_owned())
                    .collect()
            })
            .unwrap_or_default();
        // Unreadable for a process (an old kernel, a test tree) counts as
        // ours.
        let own_namespace =
            namespace(&directory).is_some_and(|theirs| ours.as_ref() != Some(&theirs));
        processes.push(Process {
            pid,
            exe,
            exe_id,
            arguments,
            fds,
            environment,
            cwd: fs::read_link(directory.join("cwd")).ok().and_then(|cwd| {
                cwd.to_str()
                    .map(|cwd| cwd.trim_start_matches('/').to_string())
            }),
            own_namespace,
            of_root: root_before && of_root(&directory),
        });
    }
    processes.sort_by(|left, right| left.pid.cmp(&right.pid));
    (processes, hidden)
}

/// Whether the process at `directory` is root's in every respect (the
/// real, effective, saved and filesystem user of its `status`). Who owns
/// its `/proc` directory does not say: that is root for any process that
/// made itself undumpable, where `/proc` hides other users' processes.
fn of_root(directory: &Path) -> bool {
    fs::read_to_string(directory.join("status")).is_ok_and(|status| {
        status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .is_some_and(|ids| {
                let mut ids = ids.split_whitespace().peekable();
                ids.peek().is_some() && ids.all(|id| id == "0")
            })
    })
}

/// Programs that run the script they are given: who they are says nothing
/// about what they run.
const INTERPRETERS: &[&str] = &[
    "python", "python3", "perl", "ruby", "node", "bun", "deno", "php", "lua", "luajit", "bash",
    "sh", "dash", "zsh", "fish", "java", "socat", "nc", "ncat", "awk", "gawk", "mawk", "busybox",
    "openssl", "tclsh", "wish", "expect", "Rscript", "pwsh", "erl", "julia", "dotnet", "mono",
    "guile",
];

/// The dynamic loader run as a program (`ld-linux-x86-64.so.2 ./program`):
/// it runs the program it is given, as an interpreter runs a script.
fn is_loader(name: &str) -> bool {
    name == "ld.so" || name.starts_with("ld-linux") || name.starts_with("ld-musl")
}

fn is_interpreter(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    is_loader(name)
        || INTERPRETERS.iter().any(|interpreter| {
            name == *interpreter
                || name
                    .strip_prefix(interpreter)
                    .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit() || c == '.'))
        })
}

/// Whether `process` runs a repository package's program and nothing else:
/// the file at its path is the very file it runs (a bind mount or rename
/// cannot borrow a packaged name) and it is not an interpreter.
fn trusted_program(scope: &Scope<'_>, process: &Process, exe: &str) -> bool {
    if !packaged(scope, exe) || is_interpreter(exe) || replaced_in_own_namespace(process) {
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
    process.own_namespace && process.exe.ends_with(" (deleted)")
}

/// Options that take the next argument as their value in some interpreter
/// or in the loader (`python3 -W ignore x.py`, `ld-linux --library-path d
/// prog`). In another they are plain flags (`python3 -I x.py`), so what
/// follows one may be the script or may be a value before it.
const VALUE_OPTIONS: &[&str] = &[
    "--library-path",
    "--preload",
    "--audit",
    "--argv0",
    "--glibc-hwcaps-prepend",
    "--glibc-hwcaps-mask",
    "-W",
    "-X",
    "-r",
    "--require",
    "--import",
    "--loader",
    "-I",
    "-cp",
    "-classpath",
    "--class-path",
    "--module-path",
    // `bash -o pipefail script`.
    "-o",
    "-O",
];

/// The arguments that may be the script (or, for the loader, the program)
/// of a process: the first that is no option, and, where that one follows
/// an option that may have taken it as its value, the next one too. Code
/// given on the command line (`python3 -c …`) comes out as one, and is
/// dropped where it names no file; `bash -e x.sh`, where `-e` is a plain
/// flag, keeps its script.
fn script_arguments(arguments: &[String]) -> Vec<&str> {
    let mut candidates = Vec::new();
    let mut may_be_value = false;
    for argument in arguments.iter().skip(1).map(String::as_str) {
        if argument.starts_with('-') {
            may_be_value = VALUE_OPTIONS.contains(&argument);
            continue;
        }
        candidates.push(argument);
        if !may_be_value {
            break;
        }
        may_be_value = false;
    }
    candidates
}

/// The files on disk an interpreter (or the loader) may be running as its
/// script, most likely first; none for a program that is not one, and for
/// a relay, which runs what it is told (`ncat -e /usr/bin/bash`), not a
/// script.
fn scripts(scope: &Scope<'_>, process: &Process, exe: &str) -> Vec<String> {
    let relay = matches!(exe.rsplit('/').next(), Some("nc" | "ncat" | "socat"));
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
    let started = process
        .arguments
        .iter()
        .take(4)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(" ");
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

/// The checks on one process: its program, what it preloads, and whether
/// it reads the keyboard or uses a camera.
fn program_checks(scope: &Scope<'_>, process: &Process, found: &mut Found) {
    let pid = &process.pid;
    let exe = process.exe.trim_start_matches('/');
    if let Some(name) = exe.strip_prefix("memfd:") {
        let name = name.trim_end_matches(" (deleted)");
        found.add_missing(
            scope,
            Category::Process,
            &format!("memfd:{name}"),
            "runs only in memory",
            format!("process {pid} runs a program that exists only in memory"),
            RuleId::HiddenProgram,
        );
        return;
    }
    if let Some(path) = exe.strip_suffix(" (deleted)") {
        // In a mount namespace of its own a process gives its program any
        // name, a root-only path included: whether a file is there is asked
        // as anyone could ask it, unless the process is root's.
        let there = if process.of_root {
            scope.root.join(path).is_file()
        } else {
            collect::is_file_there(scope, path, None)
        };
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
        if there {
            // Replaced while it runs: an update of a package (fine), or of
            // anything else (worth a look, not an alarm).
            if !packaged(scope, path) {
                found.add(
                    scope,
                    Category::Process,
                    path,
                    format!("process {pid} runs an older /{path}, replaced while it runs"),
                    None,
                );
            }
            return;
        }
        found.add_missing(
            scope,
            Category::Process,
            path,
            "deleted while it runs",
            format!("process {pid} runs /{path}, which was deleted"),
            RuleId::HiddenProgram,
        );
        return;
    }
    temporary_checks(scope, process, exe, found);
    preload_checks(scope, process, exe, found);
    if trusted_program(scope, process, exe) {
        return;
    }
    device_checks(scope, process, exe, found);
}

/// Whether an untrusted process reads the keyboard or uses a camera.
fn device_checks(scope: &Scope<'_>, process: &Process, exe: &str, found: &mut Found) {
    let pid = &process.pid;
    let (path, started) = subject(scope, process, exe);
    if process.fds.iter().any(|fd| reads_keys(scope, fd)) {
        found.add(
            scope,
            Category::Input,
            &path,
            format!("process {pid} ({started}) reads the keyboard device"),
            Some(RuleId::KeyboardReader),
        );
    }
    if let Some(camera) = process.fds.iter().find(|fd| fd.starts_with("/dev/video")) {
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
            Preload::Path(library) if !packaged(scope, &library) => {
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

/// TCP sockets listening on anything but the loopback interface, by the
/// program that holds them.
fn listeners(scope: &Scope<'_>, processes: &[Process], found: &mut Found) {
    // A socket is shared by every process that inherited it: each one can
    // accept on it, so each is looked at, not just one of them.
    let mut holders: HashMap<String, Vec<&Process>> = HashMap::new();
    for process in processes {
        for fd in &process.fds {
            if let Some(inode) = fd
                .strip_prefix("socket:[")
                .and_then(|rest| rest.strip_suffix(']'))
            {
                // Once per process, however many copies of the socket it
                // holds.
                let sharing = holders.entry(inode.to_string()).or_default();
                if sharing
                    .last()
                    .is_none_or(|last: &&Process| last.pid != process.pid)
                {
                    sharing.push(process);
                }
            }
        }
    }
    let mut unattributed = 0;
    for table in ["tcp", "tcp6"] {
        let Ok(text) = fs::read_to_string(scope.root.join("proc/net").join(table)) else {
            continue;
        };
        for (address, port, inode) in text.lines().skip(1).filter_map(listening) {
            if is_loopback(&address) {
                continue;
            }
            let Some(sharing) = holders.get(&inode) else {
                unattributed += 1;
                continue;
            };
            for process in sharing {
                listener(scope, process, port, found);
            }
        }
    }
    if unattributed > 0 {
        found.notes.push(format!(
            "{unattributed} listening socket(s) belong to processes of other users; the root checks cover them"
        ));
    }
}

/// What to say about `process`, which holds a socket listening on `port`.
fn listener(scope: &Scope<'_>, process: &Process, port: u16, found: &mut Found) {
    let exe = process.exe.trim_start_matches('/');
    // Programs with no file on disk are reported by the program checks
    // already, but for one that only borrows a name.
    let borrowed = replaced_in_own_namespace(process);
    if (exe.ends_with(" (deleted)") && !borrowed)
        || exe.starts_with("memfd:")
        || trusted_program(scope, process, exe)
    {
        return;
    }
    let exe = exe.trim_end_matches(" (deleted)");
    let (path, started) = subject(scope, process, exe);
    let pid = &process.pid;
    // An interpreter's listener is always shown: with no script on disk
    // (`python -c …`), or with a packaged "script" it was handed (`ncat -e
    // /usr/bin/bash`), it would otherwise pass as trusted. So is one under
    // a borrowed name, whose item is the packaged file of that name.
    let alert = (is_interpreter(exe) || borrowed).then_some(RuleId::NetworkListener);
    found.add(
        scope,
        Category::Listener,
        &path,
        format!("process {pid} ({started}) listens on TCP port {port} from the network"),
        alert,
    );
}

/// A listening TCP socket from a `/proc/net/tcp{,6}` line: its local
/// address (hex), port and inode.
fn listening(line: &str) -> Option<(String, u16, String)> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.get(3) != Some(&"0A") {
        return None;
    }
    let (address, port) = fields.get(1)?.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    Some((address.to_string(), port, (*fields.get(9)?).to_string()))
}

/// Whether a `/proc/net` address (hex, network order per 32-bit word) is
/// loopback: `127.x.x.x`, `::1` or `::ffff:127.x.x.x`.
fn is_loopback(address: &str) -> bool {
    match address.len() {
        8 => address.ends_with("7F"),
        32 => {
            address == "00000000000000000000000001000000"
                || (address.starts_with("0000000000000000FFFF0000") && address.ends_with("7F"))
        }
        _ => false,
    }
}

/// Loaded modules no package installed, and the taint flag.
fn kernel(scope: &Scope<'_>, found: &mut Found) {
    let Ok(release) = fs::read_to_string(scope.root.join("proc/sys/kernel/osrelease")) else {
        return;
    };
    let release = release.trim();
    let modules_root = format!("usr/lib/modules/{release}");
    // After a kernel update the running kernel's modules are gone, or put
    // back by a helper (kernel-modules-hook) outside any package, until the
    // next boot: then nothing here can be checked against a package.
    // `modules.dep` is generated by depmod; `pkgbase` comes with the kernel
    // package.
    let installed = format!("{modules_root}/pkgbase");
    if !scope.root.join(&installed).is_file() || !packaged(scope, &installed) {
        found.notes.push(format!(
            "kernel modules not checked: kernel {release} is no longer installed as a package (updated); they are checked again after a reboot"
        ));
    } else {
        loaded_modules(scope, &modules_root, found);
    }
    let taint = fs::read_to_string(scope.root.join("proc/sys/kernel/tainted"))
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
        .unwrap_or(0);
    if taint != 0 {
        found
            .notes
            .push(format!("the kernel is tainted ({})", taint_flags(taint)));
    }
}

fn loaded_modules(scope: &Scope<'_>, modules_root: &str, found: &mut Found) {
    let files: HashMap<String, String> =
        fs::read_to_string(scope.root.join(modules_root).join("modules.dep"))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.split(':').next())
            .map(|path| (module_name(path), path.to_string()))
            .collect();
    let dkms = scope.root.join("var/lib/dkms").is_dir();
    let loaded = fs::read_to_string(scope.root.join("proc/modules")).unwrap_or_default();
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
            // An in-tree module the kernel marks out-of-tree (`O`) is not
            // the file it was loaded under that name from.
            let taint = fs::read_to_string(scope.root.join("sys/module").join(name).join("taint"))
                .unwrap_or_default();
            if file.starts_with("kernel/") && taint.contains('O') {
                found.add(
                    scope,
                    Category::KernelModule,
                    &path,
                    format!("module {name} is loaded out-of-tree under an in-tree module's name"),
                    Some(RuleId::UnknownKernelModule),
                );
            }
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

/// A module's name from its `modules.dep` path: `kernel/x/snd-hda.ko.zst`
/// is `snd_hda`.
fn module_name(path: &str) -> String {
    let file = path.rsplit('/').next().unwrap_or(path);
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

/// Setuid and setgid files, and files with capabilities, that no package
/// vouches for.
fn privileged_files(scope: &Scope<'_>, found: &mut Found) {
    let mut looked_at = 0;
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
                    _ => continue,
                };
            let Ok(listing) = fs::read_dir(format!("/proc/self/fd/{}", opened.as_raw_fd())) else {
                continue;
            };
            for entry in listing.filter_map(Result::ok) {
                looked_at += 1;
                if looked_at > MAX_WALK {
                    found.unchecked.push(format!(
                        "more than {MAX_WALK} files: setuid programs were not looked for everywhere"
                    ));
                    break 'walk;
                }
                let Ok(metadata) = entry.metadata() else {
                    continue;
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
        }
    }
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
    // program given root-like ones (`setcap cap_setuid+ep python`) is
    // only trusted when it is known to set them on itself.
    let unexpected = capabilities.is_some_and(|capabilities| {
        DANGEROUS_CAPABILITIES.iter().any(|dangerous| {
            capabilities.contains(dangerous)
                && !EXPECTED_CAPABILITIES
                    .iter()
                    .any(|(known, capability)| *known == path && capability == dangerous)
        })
    });
    if !vouched || unexpected {
        let why = if vouched {
            "root-like rights a packaged program does not set itself"
        } else {
            "no package vouches for it"
        };
        found.items.entry(path.to_string()).or_insert(item);
        found.add(
            scope,
            Category::Setuid,
            path,
            format!("{what}; {why}"),
            Some(RuleId::UnknownPrivilegedFile),
        );
    }
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
    .filter(|captured| captured.status.code() != Some(124))
    .map(|captured| {
        parse_getcap(&String::from_utf8_lossy(&captured.stdout))
            .iter()
            .any(|(reported, _)| reported == path)
    })
}

/// Files with capabilities, from `getcap -r` (on the real system only).
fn capability_files(scope: &Scope<'_>) -> Result<Vec<(String, String)>, String> {
    if scope.root != Path::new("/") || !Path::new(GETCAP).is_file() {
        return Ok(Vec::new());
    }
    let mut args = vec![OsString::from("-r")];
    args.extend(
        PRIVILEGED_ROOTS
            .iter()
            .map(|root| OsString::from(format!("/{root}")))
            .filter(|root| Path::new(root).is_dir()),
    );
    let captured = tools::run(
        Path::new(GETCAP),
        &args,
        None,
        &[("LC_ALL", "C")],
        Limits {
            timeout_secs: 300,
            max_output: 4 * 1024 * 1024,
        },
    )
    .map_err(|error| error.to_string())?;
    if captured.status.code() == Some(124) {
        return Err("getcap timed out".into());
    }
    Ok(parse_getcap(&String::from_utf8_lossy(&captured.stdout)))
}

/// `getcap` lines: the path, then capability clauses (`cap_x,cap_y=ep`,
/// `=ep`, ` [rootid=N]`); a path may hold spaces.
fn parse_getcap(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let split = [" cap_", " =", " ["]
                .iter()
                .filter_map(|marker| line.find(marker))
                .min()?;
            let (path, capabilities) = line.split_at(split);
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
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::Path;

    use super::{Preload, check, is_loopback, listening, module_name, parse_getcap, preloaded};
    use crate::autorun::Category;
    use crate::rules::RuleId;
    use crate::sha256::Sha256;
    use crate::sweep::collect::{Origin, Scope};
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
        assert_eq!(
            listening(line),
            Some(("00000000".into(), 8080, "4242".into()))
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
        assert!(about("20").is_empty(), "{:?}", about("20"));
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
        assert!(alerts.contains(&RuleId::NetworkListener), "{alerts:?}");
        assert!(alerts.contains(&RuleId::KeyboardReader), "{alerts:?}");
        assert!(!named.is_trusted());
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
                ("home/u/.local/bin/tool", Category::Process, vec![]),
                ("home/u/server", Category::Listener, vec![]),
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
                ("tmp/gone", Category::Process, vec![RuleId::HiddenProgram]),
                (
                    "usr/bin/helper",
                    Category::Setuid,
                    vec![RuleId::UnknownPrivilegedFile]
                ),
                (
                    "usr/bin/python3",
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
            .find(|item| item.path == "home/u/server")
            .unwrap();
        assert!(server.notes[0].contains("TCP port 8080"));
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
        assert!(!notes.iter().any(|note| note.contains("process 31 ")));
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
            fds: Vec::new(),
            environment: Some(environment.replace(';', "\0").into_bytes()),
            own_namespace: false,
            of_root: false,
            cwd: cwd.map(str::to_string),
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
            fds: Vec::new(),
            environment: None,
            own_namespace: false,
            of_root: false,
            cwd: None,
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
}
