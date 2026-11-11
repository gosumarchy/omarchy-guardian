//! Reading the processes of a system from its `proc`: each one's program,
//! arguments, open files, control group and `status`.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use super::preload::reads_keys;
use super::program::cwd_mark;
use super::{DELETED, Descriptors, Listed, Process, Running, Source, Status, Unnamed, source};

/// The most bytes kept of one process's command line, and of the variables
/// of its environment the checks read (`READ_VARIABLES`). A program may
/// start with up to 6 MiB of both together, and a forked process shares
/// its parent's at no cost to it, while the collector keeps a copy of each
/// process's at once. Twice the longest one argument or variable may be
/// (128 KiB), so one of any length that starts in the first half is kept
/// whole; arbitrary otherwise, since a desktop's are a few KiB.
pub(super) const MAX_START_BYTES: usize = 256 * 1024;

/// The most bytes of a process's `environ` read. `exec` places at most
/// 6 MiB of arguments and environment together (three quarters of the
/// kernel's 8 MiB `_STK_LIM`), but a process can point its `environ` at
/// any memory it maps (`prctl(PR_SET_MM_MAP)`, which needs no privilege),
/// which would otherwise be read to its end at about 7 s per GiB.
pub(super) const MAX_ENVIRON_BYTES: u64 = 6 * 1024 * 1024;

/// The variables of a process's environment that the live checks read
/// (the dynamic linker's, and Python's search path); the rest is not kept.
/// A check that reads another must add it here.
pub(super) const READ_VARIABLES: &[&[u8]] = &[
    b"LD_PRELOAD=",
    b"LD_AUDIT=",
    b"LD_LIBRARY_PATH=",
    b"PYTHONPATH=",
    b"PYTHONHOME=",
    b"VIRTUAL_ENV=",
];

/// Every process under the `proc` of the system at `root`.
///
/// Of each process the collector keeps, at most: its command line and the
/// variables it reads, `MAX_START_BYTES` each, and its first argument once
/// more (`Listed`); 16 bytes per distinct socket it holds, of which it may
/// hold as many as its descriptor limit (524,288 under systemd's default,
/// so 8 MiB); and a few paths of up to 4 KiB (its program, working
/// directory, control group and camera). Each socket kept takes at least
/// an 8-byte entry in the process's table of descriptors in the kernel,
/// which counts against the account's own memory (a socket no other
/// process shares takes hundreds of bytes more), so sockets cost an account
/// at least half as much as they cost the collector. What a process started
/// with costs a forked one nothing, so about 5,000 processes of an account,
/// each with 768 KiB of those, reach the unit's `MemoryMax=4G`; the
/// collector is then stopped and the bar says the results are old.
pub(super) fn processes(root: &Path) -> Running {
    let proc = root.join("proc");
    let listed_at = ticks_since_boot(&proc);
    let listing = match source(fs::read_dir(&proc)) {
        Source::Read(listing) => listing,
        Source::Absent => return Running::default(),
        Source::Unreadable(reason) => {
            return Running {
                unlistable: Some(reason),
                listed_at,
                ..Running::default()
            };
        }
    };
    let mut running = Running {
        listed_at,
        ..Running::default()
    };
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
        let mut whole = true;
        let cmdline = command_line(&directory.join("cmdline"), &mut whole).unwrap_or_default();
        // Kept as bytes: as text, each byte that is not UTF-8 would take
        // three.
        let started_as = cmdline
            .split(|byte| *byte == 0)
            .find(|argument| !argument.is_empty())
            .map(<[u8]>::to_vec);
        running.listed.push(Listed {
            pid: number,
            status: before.clone(),
            started_as,
            kernel_thread: kernel_thread(&directory),
        });
        let exe = match fs::read_link(directory.join("exe")) {
            Ok(exe) => exe,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                running.unreadable += 1;
                continue;
            }
            // Kernel threads have no program; a process may have exited.
            Err(_) => continue,
        };
        let running_file = fs::metadata(directory.join("exe")).ok();
        let open = descriptors(root, &directory);
        let environment = environment(&directory.join("environ"), &mut whole);
        let cwd = link(&directory.join("cwd"));
        let of_root = before.of_root && status(&directory).of_root;
        let odd_name = not_utf8(cwd.as_deref(), &cmdline, environment.as_deref());
        // Read lossily, such a name stands for another file (`\xff` for
        // one named U+FFFD), whose content an item would show and an allow
        // would vouch for.
        let Some(exe) = exe.to_str().map(str::to_string) else {
            let program = exe.as_os_str().as_bytes().escape_ascii().to_string();
            running.unnamed.push(Unnamed {
                pid,
                program,
                of_root,
            });
            continue;
        };
        // Unreadable for a process (an old kernel, a test tree) counts as
        // ours.
        let own_namespace =
            link(&directory.join("ns/user")).is_some_and(|theirs| ours.as_ref() != Some(&theirs));
        running.processes.push(Process {
            pid,
            deleted: is_deleted(&exe, running_file.as_ref()),
            exe,
            exe_id: running_file.map(|metadata| (metadata.dev(), metadata.ino())),
            cmdline,
            open,
            environment,
            read_in_part: !whole,
            not_utf8: odd_name,
            cwd_mark: cwd.as_deref().map(|cwd| {
                let bytes = cwd.as_os_str().as_bytes();
                cwd_mark(bytes.strip_prefix(b"/").unwrap_or(bytes))
            }),
            cwd: cwd.and_then(|cwd| {
                cwd.to_str()
                    .map(|cwd| cwd.trim_start_matches('/').to_string())
            }),
            own_namespace,
            of_root,
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

/// What of a running program that names a file is not UTF-8, if any: its
/// working directory, its command line (which names its script), or what
/// it has the loader load. The checks leave such names out (see
/// `program::scripts` and `preload::preloaded`): read lossily, each stands
/// for another file. A command line cut where the reading stopped may end
/// inside a character; that counts too, since its last argument is left
/// out the same way.
pub(super) fn not_utf8(
    cwd: Option<&Path>,
    cmdline: &[u8],
    environment: Option<&[u8]>,
) -> Option<&'static str> {
    let broken = |bytes: &[u8]| std::str::from_utf8(bytes).is_err();
    if cwd.is_some_and(|cwd| cwd.to_str().is_none()) {
        Some("its working directory")
    } else if broken(cmdline) {
        Some("its command line")
    } else if loader_not_utf8(environment) {
        Some("what it has the loader load")
    } else {
        None
    }
}

/// Whether a process has the loader load what is named in a way that is
/// not UTF-8: in its `LD_PRELOAD`, `LD_AUDIT` or `LD_LIBRARY_PATH`.
pub(super) fn loader_not_utf8(environment: Option<&[u8]>) -> bool {
    environment
        .unwrap_or_default()
        .split(|byte| *byte == 0)
        .filter(|entry| {
            [&b"LD_PRELOAD="[..], b"LD_AUDIT=", b"LD_LIBRARY_PATH="]
                .iter()
                .any(|name| entry.starts_with(name))
        })
        .any(|entry| std::str::from_utf8(entry).is_err())
}

/// The arguments of a command line as the kernel keeps it (`cmdline`),
/// without the empty ones.
pub(super) fn arguments(cmdline: &[u8]) -> Vec<String> {
    cmdline
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .map(|argument| String::from_utf8_lossy(argument).into_owned())
        .collect()
}

/// What the checks use of the open files of the process at `directory`,
/// on the system at `root`: each socket once, with the lowest descriptor
/// that holds it, whether its input is a terminal, whether it reads a
/// keyboard, and the camera on its lowest descriptor that holds one. Every
/// descriptor is read and nothing else is kept of them: four thousand of
/// `/dev/null` cannot then hide the keyboard after them.
fn descriptors(root: &Path, directory: &Path) -> Descriptors {
    let mut held = Descriptors::default();
    let Ok(listing) = fs::read_dir(directory.join("fd")) else {
        return held;
    };
    let mut camera: Option<(u32, String)> = None;
    // Each device is asked about once: a process may hold one that is no
    // keyboard on every descriptor it has, and each asking reads `/sys`.
    // Only input devices are kept here: any other path a process opens is
    // no keyboard, and keeping each of up to 524,288 paths of 4 KiB would
    // cost the collector 2 GiB for one process.
    let mut not_keyboards = HashSet::new();
    for fd in listing.filter_map(Result::ok) {
        let number = fd.file_name().to_str().and_then(|name| name.parse().ok());
        let (Some(number), Ok(target)) = (number, fs::read_link(fd.path())) else {
            continue;
        };
        let target = target.to_string_lossy();
        if number == 0 {
            held.on_terminal = target.starts_with("/dev/pts/") || target.starts_with("/dev/tty");
        }
        if let Some(inode) = socket_inode(&target) {
            held.sockets.push((number, inode));
        } else if target.starts_with("/dev/video") {
            if camera.as_ref().is_none_or(|(lowest, _)| number < *lowest) {
                camera = Some((number, target.into_owned()));
            }
        } else if !held.keyboard
            && target.starts_with("/dev/input/event")
            && !not_keyboards.contains(&*target)
        {
            held.keyboard = reads_keys(root, &target);
            not_keyboards.insert(target.into_owned());
        }
    }
    held.sockets
        .sort_unstable_by_key(|&(fd, inode)| (inode, fd));
    held.sockets.dedup_by_key(|(_, inode)| *inode);
    // What the collector keeps follows the sockets, not the descriptors.
    held.sockets.shrink_to_fit();
    held.camera = camera.map(|(_, camera)| camera);
    held
}

/// The inode of a descriptor that is a socket (`socket:[123]`).
fn socket_inode(target: &str) -> Option<u64> {
    target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// The `cmdline` at `path`: the arguments whose ending null byte is among
/// the first `MAX_START_BYTES` + 1 bytes, with `whole` cleared if there was
/// more. A first argument with no null byte there is kept as far as that,
/// cut: it is the name the process was started under.
fn command_line(path: &Path, whole: &mut bool) -> Option<Vec<u8>> {
    let mut text = Vec::new();
    File::open(path)
        .ok()?
        .take(MAX_START_BYTES as u64 + 1)
        .read_to_end(&mut text)
        .ok()?;
    if text.len() > MAX_START_BYTES {
        *whole = false;
        let end = text
            .iter()
            .rposition(|byte| *byte == 0)
            .map_or(MAX_START_BYTES, |end| end + 1);
        text.truncate(end);
    }
    Some(text)
}

/// The variables of the `environ` at `path` that the checks read
/// (`READ_VARIABLES`), each ended by a null byte. Where those come to more
/// than `MAX_START_BYTES`, `whole` is cleared and the one that would take
/// them past it is left out, with all after it. Past `MAX_ENVIRON_BYTES`
/// nothing more is read, and `whole` is cleared too.
fn environment(path: &Path, whole: &mut bool) -> Option<Vec<u8>> {
    let mut reader = BufReader::new(File::open(path).ok()?.take(MAX_ENVIRON_BYTES + 1));
    let mut kept = Vec::new();
    let mut entry = Vec::new();
    loop {
        entry.clear();
        // One entry may be as long as the whole environment: past the most
        // that is kept, the rest of it is passed over unread into memory.
        let limit = MAX_START_BYTES as u64 + 1;
        if (&mut reader).take(limit).read_until(0, &mut entry).ok()? == 0 {
            if reader.get_ref().limit() == 0 {
                *whole = false;
            }
            return Some(kept);
        }
        if entry.last() != Some(&0) {
            if entry.len() > MAX_START_BYTES {
                reader.skip_until(0).ok()?;
            }
            entry.push(0);
        }
        if !READ_VARIABLES.iter().any(|name| entry.starts_with(name)) {
            continue;
        }
        if kept.len() + entry.len() > MAX_START_BYTES {
            *whole = false;
            return Some(kept);
        }
        kept.extend_from_slice(&entry);
    }
}

/// The control group of the process at `directory`, from its `cgroup`
/// (`0::/system.slice/sshd.service`).
fn cgroup(directory: &Path) -> String {
    // A group's name is the account's to choose (a delegated subtree).
    proc_text(&directory.join("cgroup"))
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

/// A process's `status`, `stat` or `cgroup` as text, each a few KiB at
/// most. The kernel writes its name there with every byte from 0x80 up as
/// it is, and a process may name itself bytes that are not UTF-8
/// (`prctl(PR_SET_NAME)`), or its group: read strictly, such a process
/// would not answer at all, and so pass every search.
pub(super) fn proc_text(path: &Path) -> io::Result<String> {
    Ok(String::from_utf8_lossy(&fs::read(path)?).into_owned())
}

/// The time since boot in clock ticks, from `/proc/uptime`: the unit and
/// clock of a process's start time in its `stat` (`USER_HZ`, 100 a second
/// on every architecture Arch builds for; both count from boot, the time
/// suspended included).
pub(super) fn ticks_since_boot(proc: &Path) -> Option<u64> {
    let text = fs::read_to_string(proc.join("uptime")).ok()?;
    let (seconds, fraction) = text.split_whitespace().next()?.split_once('.')?;
    let hundredths: u64 = fraction.get(..2)?.parse().ok()?;
    seconds
        .parse::<u64>()
        .ok()?
        .checked_mul(100)?
        .checked_add(hundredths)
}

/// Whether the kernel marks the process at `directory` a kernel thread:
/// `PF_KTHREAD` (0x00200000, `include/linux/sched.h`) in the flags, the
/// 9th field of its `stat`. Unreadable, it is taken for a program.
fn kernel_thread(directory: &Path) -> bool {
    const PF_KTHREAD: u64 = 0x0020_0000;
    proc_text(&directory.join("stat")).is_ok_and(|text| {
        text.rfind(')')
            .and_then(|end| {
                text[end + 1..]
                    .split_whitespace()
                    .nth(6)?
                    .parse::<u64>()
                    .ok()
            })
            .is_some_and(|flags| flags & PF_KTHREAD != 0)
    })
}

/// When the process at `directory` started, in ticks since boot: the 22nd
/// field of its `stat`, counted after the name in parentheses, which may
/// hold blanks and `)`.
pub(super) fn started_at(directory: &Path) -> Option<u64> {
    let text = proc_text(&directory.join("stat")).ok()?;
    let after_name = &text[text.rfind(')')? + 1..];
    after_name.split_whitespace().nth(19)?.parse().ok()
}

/// What the `status` of the process at `directory` says.
fn status(directory: &Path) -> Status {
    parse_status(&proc_text(&directory.join("status")).unwrap_or_default())
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
