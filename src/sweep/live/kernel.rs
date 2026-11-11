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
use std::ops::RangeInclusive;
use std::thread;

use super::{
    Chooser, Found, Listed, Process, Running, Status, parse_status, plain, proc_text, started_at,
    subject, ticks_since_boot, trusted_program,
};
use crate::autorun::Category;
use crate::rules::RuleId;
use crate::sweep::collect::{Origin, Scope};
use crate::sweep::programs::{is_named, is_shell};

/// The taint bits a module sets, and the letter the module then carries
/// in `/sys/module/<name>/taint`.
const MODULE_TAINTS: &[(u32, char, &str)] = &[
    (0, 'P', "proprietary"),
    (1, 'F', "loaded by force"),
    (12, 'O', "out-of-tree"),
    (13, 'E', "unsigned"),
    (15, 'K', "a live patch"),
];

/// The most process numbers tried in the search for hidden processes: as
/// many as a 64-bit kernel hands out at all (numbers below 4,194,304).
/// Trying one takes a few microseconds, so all of them take some seconds
/// of work, shared between a few threads. The search tries them in
/// ascending shares once: root that knows of it can move a hidden process
/// onto a number already passed, but root that knows of it can also hide
/// the lookups themselves.
#[cfg(not(test))]
const MAX_TRIED: u32 = 4_194_304;
/// In tests, every sweep of a fixture runs the search, and 4 million
/// failed opens in each took minutes in all; the logic is the same.
#[cfg(test)]
const MAX_TRIED: u32 = 65_536;

/// The most threads that try process numbers at once.
const MAX_SEARCHERS: u32 = 8;

/// Modules whose licence the kernel counts as proprietary, by the start of
/// their name: loading one sets that taint.
const PROPRIETARY_MODULES: &[&str] = &[
    "nvidia", "wl", "zfs", "zcommon", "znvpair", "zunicode", "zavl", "zlua", "zzstd", "icp", "spl",
    "fglrx", "vmmon", "vmnet",
];

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
    hidden_processes(scope, running, MAX_TRIED, found);
    posing_as_kernel(scope, running, found);
    tracers(scope, running, found);
    pinned_bpf(scope, found);
}

/// A taint only a module sets, with no loaded module that carries it: the
/// kernel remembers a module that its list of modules does not show.
fn hidden_module(scope: &Scope<'_>, found: &mut Found) {
    let taint = taint(scope);
    let read = fs::read_dir(scope.root.join("sys/module"));
    let Some(modules) = found.read(
        scope,
        "/sys/module",
        "a module the kernel's list does not show was not looked for",
        read,
    ) else {
        return;
    };
    let carried: String = modules
        .filter_map(Result::ok)
        .filter_map(|module| fs::read_to_string(module.path().join("taint")).ok())
        .collect();
    let unexplained: Vec<(char, &str)> = MODULE_TAINTS
        .iter()
        .filter(|(bit, letter, _)| taint & (1 << bit) != 0 && !carried.contains(*letter))
        .map(|(_, letter, what)| (*letter, *what))
        .collect();
    if unexplained.is_empty() {
        return;
    }
    let what = unexplained
        .iter()
        .map(|(_, what)| *what)
        .collect::<Vec<_>>()
        .join(", ");
    // A module that was unloaded leaves its taint behind. Where a module
    // that would have set this very taint is installed for the running
    // kernel and not loaded now, that is the likely story. A machine with
    // any DKMS module has such a module all the time, so it explains only
    // what it would set: a forced load or a live patch it does not, and a
    // proprietary taint only one with such a licence does.
    let would_set = unloaded_taints(scope);
    if unexplained
        .iter()
        .all(|(letter, _)| would_set.contains(*letter))
    {
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

/// The taint letters the modules would have set that are installed for the
/// running kernel from outside its own tree, are there as files (so they
/// could have been loaded since it started) and are not loaded now: `O`
/// for any of them, `E` since such builds are not signed with the kernel's
/// key, and `P` for one whose licence the kernel counts as proprietary.
fn unloaded_taints(scope: &Scope<'_>) -> String {
    let Some(release) = super::kernel_release(scope) else {
        return String::new();
    };
    let directory = scope.root.join("usr/lib/modules").join(release);
    let loaded: HashSet<String> = fs::read_to_string(scope.root.join("proc/modules"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_string)
        .collect();
    let mut letters = String::new();
    for file in fs::read_to_string(directory.join("modules.dep"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.split(':').next())
        .filter(|file| !file.starts_with("kernel/"))
    {
        let name = super::module_name(file);
        if loaded.contains(&name) || !directory.join(file).is_file() {
            continue;
        }
        for letter in ['O', 'E'] {
            if !letters.contains(letter) {
                letters.push(letter);
            }
        }
        if PROPRIETARY_MODULES
            .iter()
            .any(|known| name.starts_with(known))
            && !letters.contains('P')
        {
            letters.push('P');
        }
    }
    letters
}

/// The process numbers among `numbers` that are not in `listed` and still
/// answer as a process of their own. A thread answers under its number
/// without being listed, and says which process it belongs to: that is
/// not hiding.
pub(super) fn unlisted(
    listed: &HashSet<u32>,
    numbers: impl Iterator<Item = u32>,
    answers: &(dyn Fn(u32) -> Option<Status> + Sync),
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

/// The highest process number there may be: one below the most a 64-bit
/// kernel hands out at all (`PID_MAX_LIMIT` in `include/linux/threads.h`,
/// which bounds every write to `pid_max`), and never less than the highest
/// one listed. `pid_max` is not read: root can start a process above it
/// and lower it after, or mount another file over it, and a search that
/// stopped there would miss that process. The control groups were read
/// for such numbers too, and are not: past the cap on how many are read,
/// whoever hides the process makes it unread. The bound holds while the
/// kernel's own code does: a module can hand out any number, and hide its
/// lookups as well.
fn highest_number(listed: u32) -> u32 {
    (MAX_TRIED - 1).max(listed)
}

/// `unlisted` over every number of `range`, shared between a few threads;
/// and the parts of the range whose search did not come back (its thread
/// died): nothing was learned of those numbers, which is not the same as
/// nothing hiding among them.
pub(super) fn unlisted_among(
    listed: &HashSet<u32>,
    range: RangeInclusive<u32>,
    answers: &(dyn Fn(u32) -> Option<Status> + Sync),
) -> (Vec<(u32, String)>, Vec<RangeInclusive<u32>>) {
    let (first, last) = (*range.start(), *range.end());
    let searchers = thread::available_parallelism()
        .map_or(1, |cores| u32::try_from(cores.get()).unwrap_or(1))
        .min(MAX_SEARCHERS);
    let share = (last.saturating_sub(first) / searchers).saturating_add(1);
    thread::scope(|threads| {
        let searches: Vec<_> = (0..searchers)
            .map(|searcher| {
                let from = first.saturating_add(share.saturating_mul(searcher));
                let to = from.saturating_add(share - 1).min(last);
                (
                    from..=to,
                    threads.spawn(move || unlisted(listed, from..=to, answers)),
                )
            })
            .collect();
        let mut found = Vec::new();
        let mut not_searched = Vec::new();
        for (part, search) in searches {
            match search.join() {
                Ok(unlisted) => found.extend(unlisted),
                Err(_) => not_searched.push(part),
            }
        }
        (found, not_searched)
    })
}

/// Says which process numbers the search for hidden processes did not
/// get through: a note for a user's sweep, and for the root checks, which
/// nothing else covers, something left unchecked.
pub(super) fn say_not_searched(
    scope: &Scope<'_>,
    not_searched: &[RangeInclusive<u32>],
    found: &mut Found,
) {
    for part in not_searched {
        let sentence = format!(
            "process numbers {} to {} were not tried in the search for hidden processes: that part of the search failed",
            part.start(),
            part.end()
        );
        if scope.origin == Origin::Root {
            found.unchecked.push(sentence);
        } else {
            found.notes.push(sentence);
        }
    }
}

/// Processes that exist (their `status` opens under their number) and are
/// missing from the list of processes. The numbers tried are every number
/// a process may have (see `highest_number`). Where that is more than `most` numbers, the newest
/// `most` are tried and the sweep says the rest were not.
pub(super) fn hidden_processes(scope: &Scope<'_>, running: &Running, most: u32, found: &mut Found) {
    let listed: HashSet<u32> = running.listed.iter().map(|listed| listed.pid).collect();
    // An empty list is searched too: a filter that empties it for the
    // sweep alone would otherwise turn the search off with it.
    let highest = listed.iter().max().copied().unwrap_or(0);
    let proc = scope.root.join("proc");
    let answers = |pid: u32| {
        proc_text(&proc.join(pid.to_string()).join("status"))
            .ok()
            .map(|text| parse_status(&text))
    };
    let top = highest_number(highest);
    let first = top.saturating_sub(most.saturating_sub(1)).max(1);
    if first > 1 {
        let sentence = format!(
            "process numbers go up to {top}: only the newest {most} were tried in the search for hidden processes"
        );
        if scope.origin == Origin::Root {
            found.unchecked.push(sentence);
        } else {
            found.notes.push(sentence);
        }
    }
    let (mut suspects, not_searched) = unlisted_among(&listed, first..=top, &answers);
    say_not_searched(scope, &not_searched, found);
    if suspects.is_empty() {
        return;
    }
    suspects.sort();
    suspects.dedup();
    // One that started while the search ran is in the list by now. That
    // list alone proves nothing: what hides a process from one read can
    // show it to the next. So one in it counts as new only if it started
    // between the first read of the list and now (a start time ahead of
    // now is made up); where any time is unknown, it was hidden.
    let now = listing(scope);
    let checked_at = ticks_since_boot(&proc);
    let started_since_listed = |pid: u32| match (
        running.listed_at,
        checked_at,
        started_at(&proc.join(pid.to_string())),
    ) {
        (Some(listed_at), Some(checked_at), Some(started)) => {
            (listed_at..=checked_at).contains(&started)
        }
        _ => false,
    };
    let hidden: Vec<(u32, String)> = suspects
        .into_iter()
        .filter(|(pid, _)| {
            (!now.contains(pid) || !started_since_listed(*pid))
                && answers(*pid).is_some_and(|status| status.group == *pid)
        })
        .collect();
    // With nothing listed, every process answers: that is one finding, the
    // list itself, not one for each process. Its path is its own, so an
    // allow of another item at `proc` does not cover it.
    if listed.is_empty() && !hidden.is_empty() {
        let named: Vec<String> = hidden
            .iter()
            .take(5)
            .map(|(pid, name)| format!("{pid} ({})", name.escape_debug()))
            .collect();
        found.add_missing(
            scope,
            Category::Process,
            "proc#unlisted",
            "the list of processes shows none",
            format!(
                "the list of processes is empty or could not be read, and {} answer by their \
                 number ({}{}): something hides the list",
                match hidden.len() {
                    1 => "1 process".to_string(),
                    count => format!("{count} processes"),
                },
                named.join(", "),
                if hidden.len() > named.len() {
                    ", …"
                } else {
                    ""
                }
            ),
            RuleId::RootkitSign,
        );
        return;
    }
    for (pid, name) in hidden {
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
        // A program may blank its arguments, so what started it does not
        // tell a kernel thread; the kernel does.
        if listed.kernel_thread {
            continue;
        }
        let shown = String::from_utf8_lossy(listed.started_as.as_deref().unwrap_or_default());
        if !bracketed(&listed.status.name) && !bracketed(&shown) {
            continue;
        }
        let note = format!(
            "process {} is named like a kernel thread ({}), and is a program",
            listed.pid,
            shown.escape_debug()
        );
        // Any account names its processes what it likes.
        found.through(Chooser::of(listed.status.of_root), |found| {
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
        });
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
    // Shells: what is typed into one passes through its memory.
    is_shell(name)
        || SECRET_HOLDERS.iter().any(|holder| {
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
        let shell = is_shell(target);
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
        // Any account may attach to its own processes, as often as it likes,
        // and names the item through the target's name. A tracer is a thread
        // id, and a thread is not in the list of processes: its `status`
        // is read by its number. One that cannot be shown to be root's is
        // an account's.
        let tracer_of_root = match tracer {
            Some(tracer) => tracer.of_root,
            None => {
                status_of(scope, traced.status.tracer).is_some_and(|status| status.of_root)
                    && still_traced_by(scope, traced)
            }
        };
        let chooser = Chooser::of(tracer_of_root);
        found.through(chooser, |found| match tracer {
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
        });
    }
}

/// What the `status` of process or thread `pid` says now.
fn status_of(scope: &Scope<'_>, pid: u32) -> Option<Status> {
    let text = proc_text(&scope.root.join(format!("proc/{pid}/status"))).ok()?;
    Some(parse_status(&text))
}

/// Whether `traced` still has the tracer it was listed with. The tracer's
/// number may have gone to another thread, root's say, after the tracer
/// left. Asked after the tracer's own `status` was read: a tracer that
/// leaves lets go of its target, and no number is given again while its
/// thread lives, so the same tracer now means that `status` was its own,
/// short of the numbers going round twice between the two reads.
fn still_traced_by(scope: &Scope<'_>, traced: &Listed) -> bool {
    status_of(scope, traced.pid).is_some_and(|now| now.tracer == traced.status.tracer)
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
/// kernel with no process holding them. Only root can list them: a user's
/// sweep leaves them to the root checks, and root, which nothing stands
/// behind, says so when it cannot.
fn pinned_bpf(scope: &Scope<'_>, found: &mut Found) {
    let pins = match fs::read_dir(scope.root.join("sys/fs/bpf")) {
        Ok(pins) => pins,
        // No such filesystem: nothing is pinned.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => {
            if scope.origin == Origin::Root {
                found.unchecked.push(format!(
                    "/sys/fs/bpf: could not be listed ({error}); pinned eBPF objects were not checked"
                ));
            }
            return;
        }
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
