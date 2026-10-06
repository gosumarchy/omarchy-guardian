//! Reading the processes of a system from its `proc`: each one's program,
//! arguments, open files, control group and `status`.

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use super::{DELETED, Listed, Process, Running, Source, Status, source};

/// Every process under `proc`.
pub(super) fn processes(proc: &Path) -> Running {
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

pub(super) fn parse_status(text: &str) -> Status {
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
pub(super) fn of_root(directory: &Path) -> bool {
    status(directory).of_root
}
