//! The live checks for what hides or pries: places where two of the
//! kernel's own accounts of the system should agree and do not, which is
//! what a rootkit that filters one of them leaves behind.
//!
//! - a taint a module set, with no loaded module that says it set it;
//! - a process that answers under its number but is missing from the list
//!   of processes;
//! - a program that wears a kernel thread's name;
//! - a process attached to another the way a debugger is;
//! - eBPF objects pinned in `/sys/fs/bpf` (root's to list).

use std::collections::HashSet;
use std::fs;

use super::{
    Found, Listed, Process, Running, Status, is_named, parse_status, plain, subject,
    trusted_program,
};
use crate::autorun::Category;
use crate::rules::RuleId;
use crate::sweep::collect::{Origin, Scope};

/// The taint bits a module sets, and the letter the module then carries
/// in `/sys/module/<name>/taint`.
const MODULE_TAINTS: &[(u32, char, &str)] = &[
    (0, 'P', "proprietary"),
    (1, 'F', "loaded by force"),
    (12, 'O', "out-of-tree"),
    (13, 'E', "unsigned"),
    (15, 'K', "a live patch"),
];

/// The highest process number up to which every number is tried in the
/// search for hidden processes: trying one takes about a microsecond, and
/// a system that has run for weeks has handed out millions.
const MAX_TRIED: u32 = 250_000;

/// The most control groups whose members are read.
const MAX_CONTROL_GROUPS: usize = 20_000;

/// Debuggers and tracers a repository package installs.
const DEBUGGERS: &[&str] = &[
    "gdb",
    "gdbserver",
    "lldb",
    "lldb-server",
    "lldb-dap",
    "strace",
    "ltrace",
    "rr",
    "perf",
    "valgrind",
];

/// Debug adapters and crash handlers that editors and browsers bring with
/// them, outside any package.
const DEBUG_ADAPTERS: &[&str] = &[
    "codelldb",
    "lldb-dap",
    "lldb-server",
    "lldb-vscode",
    "OpenDebugAD7",
    "vsdbg",
    "dlv",
    "crashpad_handler",
    "chrome_crashpad_handler",
];

/// Programs that hold secrets in memory: passwords typed, keys unlocked,
/// sessions. Anything attached to one can read them.
const SECRET_HOLDERS: &[&str] = &[
    "ssh",
    "sshd",
    "sshd-session",
    "ssh-agent",
    "sudo",
    "su",
    "doas",
    "run0",
    "login",
    "gpg",
    "gpg-agent",
    "gnome-keyring-daemon",
    "kwalletd5",
    "kwalletd6",
    "keepassxc",
    "bitwarden",
    "1password",
    "pass",
    "secret-tool",
    "polkit-gnome-authentication-agent-1",
    "hyprpolkitagent",
    "chromium",
    "chrome",
    "firefox",
    "brave",
    "vivaldi-bin",
];

/// Shells: what is typed into one passes through its memory.
const SHELLS: &[&str] = &["bash", "sh", "zsh", "fish", "dash", "ksh", "tcsh"];

/// eBPF pins the system's own tools make.
const KNOWN_PINS: &[&str] = &["systemd", "tc", "xdp", "ip", "snap"];

/// The kernel's taint flags.
pub(super) fn taint(scope: &Scope<'_>) -> u64 {
    fs::read_to_string(scope.root.join("proc/sys/kernel/tainted"))
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0)
}

/// Runs the checks.
pub(super) fn check(scope: &Scope<'_>, running: &Running, found: &mut Found) {
    hidden_module(scope, found);
    hidden_processes(scope, running, found);
    posing_as_kernel(scope, running, found);
    tracers(scope, running, found);
    pinned_bpf(scope, found);
}

/// A taint only a module sets, with no loaded module that carries it: the
/// kernel remembers a module that its list of modules does not show.
fn hidden_module(scope: &Scope<'_>, found: &mut Found) {
    let taint = taint(scope);
    let Ok(modules) = fs::read_dir(scope.root.join("sys/module")) else {
        return;
    };
    let carried: String = modules
        .filter_map(Result::ok)
        .filter_map(|module| fs::read_to_string(module.path().join("taint")).ok())
        .collect();
    let unexplained: Vec<&str> = MODULE_TAINTS
        .iter()
        .filter(|(bit, letter, _)| taint & (1 << bit) != 0 && !carried.contains(*letter))
        .map(|(_, _, what)| *what)
        .collect();
    if unexplained.is_empty() {
        return;
    }
    let what = unexplained.join(", ");
    // A module that was unloaded leaves its taint behind. Where one that
    // sets such a taint is installed and not loaded now, that is the
    // likely story.
    if out_of_tree_module_not_loaded(scope) {
        found.notes.push(format!(
            "the kernel says a module tainted it ({what}) and no loaded module accounts for it; a module installed outside the kernel's own tree is not loaded now and may have been"
        ));
        return;
    }
    found.add_missing(
        scope,
        Category::KernelModule,
        "sys/module",
        "not among the loaded modules",
        format!(
            "the kernel says a module tainted it ({what}), but no loaded module accounts for it: a hidden module, or one unloaded since"
        ),
        RuleId::RootkitSign,
    );
}

/// Whether a module from outside the kernel's own tree is installed for
/// the running kernel and not loaded.
fn out_of_tree_module_not_loaded(scope: &Scope<'_>) -> bool {
    let Some(release) = super::kernel_release(scope) else {
        return false;
    };
    let loaded: HashSet<String> = fs::read_to_string(scope.root.join("proc/modules"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_string)
        .collect();
    fs::read_to_string(
        scope
            .root
            .join("usr/lib/modules")
            .join(release)
            .join("modules.dep"),
    )
    .unwrap_or_default()
    .lines()
    .filter_map(|line| line.split(':').next())
    .any(|file| !file.starts_with("kernel/") && !loaded.contains(&super::module_name(file)))
}

/// The process numbers among `numbers` that are not in `listed` and still
/// answer as a process of their own. A thread answers under its number
/// without being listed, and says which process it belongs to: that is
/// not hiding.
pub(super) fn unlisted(
    listed: &HashSet<u32>,
    numbers: impl Iterator<Item = u32>,
    answers: &dyn Fn(u32) -> Option<Status>,
) -> Vec<(u32, String)> {
    numbers
        .filter(|pid| *pid != 0 && !listed.contains(pid))
        .filter_map(|pid| {
            answers(pid)
                .filter(|status| status.group == pid)
                .map(|status| (pid, status.name))
        })
        .collect()
}

/// The numbers `/proc` lists as processes.
fn listing(scope: &Scope<'_>) -> HashSet<u32> {
    fs::read_dir(scope.root.join("proc"))
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// The processes the control groups list as their members (every
/// `cgroup.procs` under `/sys/fs/cgroup`): the kernel's other account of
/// what runs, which whatever filters the list of processes rarely thinks
/// of. One outside the sweep's own process namespace is listed as 0.
pub(super) fn members_of_control_groups(scope: &Scope<'_>) -> Vec<u32> {
    let mut members = Vec::new();
    let mut pending = vec![scope.root.join("sys/fs/cgroup")];
    let mut looked_at = 0;
    while let Some(directory) = pending.pop() {
        looked_at += 1;
        if looked_at > MAX_CONTROL_GROUPS {
            break;
        }
        members.extend(
            fs::read_to_string(directory.join("cgroup.procs"))
                .unwrap_or_default()
                .lines()
                .filter_map(|line| line.trim().parse::<u32>().ok()),
        );
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        pending.extend(
            entries
                .filter_map(Result::ok)
                .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
                .map(|entry| entry.path()),
        );
    }
    members
}

/// Processes that exist (their `status` opens under their number) and are
/// missing from the list of processes. The numbers tried are those the
/// control groups name, and, while the system has not handed out more
/// numbers than can be tried in a moment, every number below the highest
/// one listed.
fn hidden_processes(scope: &Scope<'_>, running: &Running, found: &mut Found) {
    let listed: HashSet<u32> = running.listed.iter().map(|listed| listed.pid).collect();
    let Some(highest) = listed.iter().max().copied() else {
        return;
    };
    let proc = scope.root.join("proc");
    let answers = |pid: u32| {
        fs::read_to_string(proc.join(pid.to_string()).join("status"))
            .ok()
            .map(|text| parse_status(&text))
    };
    let every = if highest <= MAX_TRIED {
        1..highest
    } else {
        0..0
    };
    let numbers = members_of_control_groups(scope).into_iter().chain(every);
    let mut suspects = unlisted(&listed, numbers, &answers);
    if suspects.is_empty() {
        return;
    }
    suspects.sort();
    suspects.dedup();
    // One that started while the search ran is in the list by now.
    let now = listing(scope);
    for (pid, name) in suspects {
        let still = answers(pid).is_some_and(|status| status.group == pid);
        if now.contains(&pid) || !still {
            continue;
        }
        found.add_missing(
            scope,
            Category::Process,
            &format!("proc/{pid}"),
            "not in the list of processes",
            format!(
                "process {pid} ({}) exists, and the list of processes does not show it: something hides it",
                name.escape_debug()
            ),
            RuleId::RootkitSign,
        );
    }
}

/// Whether `name` is written the way process listings show a kernel
/// thread: in square brackets, with no blank in it.
fn bracketed(name: &str) -> bool {
    name.len() > 2
        && name.starts_with('[')
        && name.ends_with(']')
        && !name.contains(char::is_whitespace)
}

/// Programs that wear a kernel thread's name (`[kworker/0:1]`). A kernel
/// thread has no command line and no program; whatever has one and is
/// named like that means to be overlooked.
fn posing_as_kernel(scope: &Scope<'_>, running: &Running, found: &mut Found) {
    for listed in &running.listed {
        let posing =
            bracketed(&listed.status.name) || listed.started_as.as_deref().is_some_and(bracketed);
        // A kernel thread was started as nothing.
        if !posing || listed.started_as.is_none() {
            continue;
        }
        let shown = listed.started_as.as_deref().unwrap_or_default();
        let note = format!(
            "process {} is named like a kernel thread ({}), and is a program",
            listed.pid,
            shown.escape_debug()
        );
        match process_of(running, listed.pid) {
            Some(process) if !process.deleted && !process.path().starts_with("memfd:") => {
                found.add(
                    scope,
                    Category::Process,
                    process.path(),
                    note,
                    Some(RuleId::RootkitSign),
                );
            }
            Some(process) => found.add_missing(
                scope,
                Category::Process,
                process.path(),
                "no file on disk",
                note,
                RuleId::RootkitSign,
            ),
            // Another user's: the root checks name its program.
            None if scope.origin != Origin::Root => {}
            None => found.add_missing(
                scope,
                Category::Process,
                &format!("proc/{}", listed.pid),
                "its program could not be read",
                note,
                RuleId::RootkitSign,
            ),
        }
    }
}

/// The readable process with number `pid`.
fn process_of(running: &Running, pid: u32) -> Option<&Process> {
    running
        .processes
        .iter()
        .find(|process| process.number() == pid)
}

/// What a traced process is called: its program's file name where that can
/// be read, else the short name it gives itself.
fn name_of<'a>(running: &'a Running, listed: &'a Listed) -> &'a str {
    process_of(running, listed.pid).map_or(listed.status.name.as_str(), Process::name)
}

/// Whether a process called `name` holds secrets. The kernel's short name
/// is cut at 15 characters.
fn holds_secrets(name: &str) -> bool {
    SHELLS.iter().chain(SECRET_HOLDERS).any(|holder| {
        is_named(name, holder)
            || (name.len() == 15 && holder.len() > 15 && holder.starts_with(name))
    })
}

/// Whether process `pid` was started, however many steps down, by process
/// `ancestor`.
fn descends_from(running: &Running, pid: u32, ancestor: u32) -> bool {
    let mut current = pid;
    for _ in 0..64 {
        let Some(listed) = running.listed.iter().find(|listed| listed.pid == current) else {
            return false;
        };
        if listed.status.parent == ancestor {
            return true;
        }
        current = listed.status.parent;
    }
    false
}

/// Processes another process is attached to the way a debugger is. A
/// program started under its tracer is being debugged; a packaged
/// debugger attached to something is a developer at work. Anything
/// attached to a program that holds secrets is reported whatever it is
/// (`strace` wrapped around `ssh` or `sudo` is how passwords are logged),
/// but for the shells a debugger's own children start.
fn tracers(scope: &Scope<'_>, running: &Running, found: &mut Found) {
    for traced in running
        .listed
        .iter()
        .filter(|listed| listed.status.tracer != 0)
    {
        let target = name_of(running, traced);
        let tracer = process_of(running, traced.status.tracer);
        let started_under_it = descends_from(running, traced.pid, traced.status.tracer);
        let debugger = tracer.is_some_and(|tracer| is_debugger(scope, tracer, found));
        let shell = SHELLS.iter().any(|shell| is_named(target, shell));
        let rule = if holds_secrets(target) && !(shell && started_under_it && debugger) {
            RuleId::TracedSecrets
        } else if started_under_it || debugger {
            continue;
        } else {
            RuleId::TracedProcess
        };
        let note = format!(
            "process {} is attached to process {} ({}) and can read its memory",
            traced.status.tracer,
            traced.pid,
            target.escape_debug()
        );
        let name = format!("attached-to-{}", plain(target));
        match tracer {
            Some(tracer) if !tracer.deleted && !tracer.path().starts_with("memfd:") => {
                let (path, _) = subject(scope, tracer, tracer.path());
                found.add_as(
                    scope,
                    Category::Process,
                    &format!("{path}:{name}"),
                    &path,
                    note,
                    Some(rule),
                );
            }
            Some(tracer) => found.add_missing(
                scope,
                Category::Process,
                tracer.path(),
                "no file on disk",
                note,
                rule,
            ),
            // Another user's: the root checks name its program.
            None if scope.origin != Origin::Root => {}
            None => found.add_missing(
                scope,
                Category::Process,
                &format!("proc/{}:{name}", traced.status.tracer),
                "its program could not be read",
                note,
                rule,
            ),
        }
    }
}

/// Whether `tracer` is a debugger: a packaged one, or one of the debug
/// adapters editors bring along.
fn is_debugger(scope: &Scope<'_>, tracer: &Process, found: &mut Found) -> bool {
    let name = tracer.name();
    DEBUG_ADAPTERS.contains(&name)
        || (DEBUGGERS.iter().any(|debugger| is_named(name, debugger))
            && !tracer.deleted
            && trusted_program(scope, tracer, tracer.path(), found))
}

/// eBPF objects pinned under `/sys/fs/bpf`, which stay loaded in the
/// kernel with no process holding them. Only root can list them.
fn pinned_bpf(scope: &Scope<'_>, found: &mut Found) {
    let Ok(pins) = fs::read_dir(scope.root.join("sys/fs/bpf")) else {
        return;
    };
    let mut names: Vec<String> = pins
        .filter_map(Result::ok)
        .map(|pin| pin.file_name().to_string_lossy().into_owned())
        .filter(|name| !KNOWN_PINS.iter().any(|known| name.starts_with(known)))
        .collect();
    names.sort();
    for name in names {
        found.add_missing(
            scope,
            Category::KernelModule,
            &format!("sys/fs/bpf/{}", plain(&name)),
            "a pinned eBPF object",
            format!(
                "eBPF object {} is pinned in /sys/fs/bpf: it stays in the kernel with no process holding it",
                name.escape_debug()
            ),
            RuleId::KernelTap,
        );
    }
}
