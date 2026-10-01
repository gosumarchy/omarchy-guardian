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
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use super::collect::{self, Body, Item, Scope};
use super::tier::Tier;
use crate::autorun::Category;
use crate::rules::RuleId;
use crate::tools::{self, Limits};

const GETCAP: &str = "/usr/bin/getcap";
/// Where setuid and capability files are looked for.
const PRIVILEGED_ROOTS: &[&str] = &["usr", "opt", "etc", "home"];
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
}

/// A running process, as far as it can be read.
struct Process {
    pid: String,
    /// The `exe` link's text (`/usr/bin/x`, `/x (deleted)`, `/memfd:y`).
    exe: String,
    /// Where its open files lead.
    fds: Vec<String>,
    environment: Option<Vec<u8>>,
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
    }
}

#[derive(Default)]
struct Found {
    items: BTreeMap<String, Item>,
    notes: Vec<String>,
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
    for entry in listing.filter_map(Result::ok) {
        let Some(pid) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !pid.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let directory = entry.path();
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
        processes.push(Process {
            pid,
            exe,
            fds,
            environment,
        });
    }
    processes.sort_by(|left, right| left.pid.cmp(&right.pid));
    (processes, hidden)
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
        // An update replaced the file while it ran: normal until a restart.
        if packaged(scope, path) && scope.root.join(path).is_file() {
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
    let cache = scope.home.map(|home| format!("{home}/.cache/"));
    if TEMPORARY.iter().any(|directory| exe.starts_with(directory))
        || cache
            .as_ref()
            .is_some_and(|cache| exe.starts_with(cache.as_str()))
    {
        found.add(
            scope,
            Category::Process,
            exe,
            format!("process {pid} runs from a temporary or cache directory"),
            Some(RuleId::RunningFromTemp),
        );
    }
    for library in preloaded(process.environment.as_deref()) {
        if !packaged(scope, &library) {
            found.add(
                scope,
                Category::Process,
                &library,
                format!("preloaded into /{exe} (process {pid})"),
                Some(RuleId::PreloadedLibrary),
            );
        }
    }
    if packaged(scope, exe) {
        return;
    }
    if process
        .fds
        .iter()
        .any(|fd| fd.starts_with("/dev/input/event"))
    {
        found.add(
            scope,
            Category::Input,
            exe,
            format!("process {pid} reads keyboard and mouse devices"),
            Some(RuleId::KeyboardReader),
        );
    }
    if let Some(camera) = process.fds.iter().find(|fd| fd.starts_with("/dev/video")) {
        found.add(
            scope,
            Category::Camera,
            exe,
            format!("process {pid} has {camera} open"),
            None,
        );
    }
}

/// The libraries in a process's `LD_PRELOAD`, relative to `/`.
fn preloaded(environment: Option<&[u8]>) -> Vec<String> {
    let Some(environment) = environment else {
        return Vec::new();
    };
    environment
        .split(|byte| *byte == 0)
        .filter_map(|entry| entry.strip_prefix(b"LD_PRELOAD="))
        .flat_map(|value| {
            String::from_utf8_lossy(value)
                .split([':', ' '])
                .filter_map(|library| library.strip_prefix('/'))
                .filter(|library| !library.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// TCP sockets listening on anything but the loopback interface, by the
/// program that holds them.
fn listeners(scope: &Scope<'_>, processes: &[Process], found: &mut Found) {
    let mut holders: HashMap<String, (&str, &str)> = HashMap::new();
    for process in processes {
        for fd in &process.fds {
            if let Some(inode) = fd
                .strip_prefix("socket:[")
                .and_then(|rest| rest.strip_suffix(']'))
            {
                holders.insert(
                    inode.to_string(),
                    (process.pid.as_str(), process.exe.as_str()),
                );
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
            let Some((pid, exe)) = holders.get(&inode) else {
                unattributed += 1;
                continue;
            };
            let exe = exe.trim_start_matches('/');
            if exe.ends_with(" (deleted)") || exe.starts_with("memfd:") || packaged(scope, exe) {
                continue;
            }
            found.add(
                scope,
                Category::Listener,
                exe,
                format!("process {pid} listens on TCP port {port} from the network"),
                None,
            );
        }
    }
    if unattributed > 0 {
        found.notes.push(format!(
            "{unattributed} listening socket(s) belong to processes of other users; the root checks cover them"
        ));
    }
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
    let files: HashMap<String, String> =
        fs::read_to_string(scope.root.join(&modules_root).join("modules.dep"))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.split(':').next())
            .map(|path| (module_name(path), path.to_string()))
            .collect();
    let loaded = fs::read_to_string(scope.root.join("proc/modules")).unwrap_or_default();
    for name in loaded
        .lines()
        .filter_map(|line| line.split_whitespace().next())
    {
        match files.get(name) {
            Some(path) => {
                let path = format!("{modules_root}/{path}");
                if packaged(scope, &path) {
                    continue;
                }
                if path.contains("/updates/dkms/") {
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
            None => found.add_missing(
                scope,
                Category::KernelModule,
                &format!("sys/module/{name}"),
                "not among the installed modules",
                format!("module {name} is loaded but is not among this kernel's installed modules"),
                RuleId::UnknownKernelModule,
            ),
        }
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
    for start in PRIVILEGED_ROOTS {
        let Ok(top) = fs::symlink_metadata(scope.root.join(start)) else {
            continue;
        };
        let mut pending = vec![(*start).to_string()];
        while let Some(directory) = pending.pop() {
            let Ok(listing) = fs::read_dir(scope.root.join(&directory)) else {
                continue;
            };
            for entry in listing.filter_map(Result::ok) {
                looked_at += 1;
                if looked_at > MAX_WALK {
                    found
                        .notes
                        .push("too many files to look for setuid programs everywhere".into());
                    return;
                }
                let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                    continue;
                };
                let Ok(metadata) = entry.metadata() else {
                    continue;
                };
                let path = format!("{directory}/{name}");
                // Not into other file systems (like `find -xdev`).
                if metadata.is_dir() && metadata.dev() == top.dev() {
                    pending.push(path);
                } else if metadata.is_file() && metadata.mode() & 0o6000 != 0 {
                    privileged(scope, found, &path, "setuid or setgid");
                }
            }
        }
    }
    for (path, capabilities) in capability_files(scope) {
        privileged(scope, found, &path, &format!("capabilities {capabilities}"));
    }
}

fn privileged(scope: &Scope<'_>, found: &mut Found, path: &str, what: &str) {
    let item = collect::item(scope, Category::Setuid, path.to_string(), None);
    // A package's set-id file only root can read cannot be hashed here; the
    // root checks hash it. Its owner and mode are what can be checked now.
    if matches!(item.body, Body::Unreadable(_)) && packaged(scope, path) {
        return;
    }
    // A copy of a packaged program with extra rights is the classic
    // backdoor (a setuid copy of a shell), so a copy is not trusted here.
    if !matches!(item.tier, Tier::Vendor | Tier::Inert | Tier::Allowed) {
        found.items.entry(path.to_string()).or_insert(item);
        found.add(
            scope,
            Category::Setuid,
            path,
            format!("{what}; no package vouches for it"),
            Some(RuleId::UnknownPrivilegedFile),
        );
    }
}

/// Files with capabilities, from `getcap -r` (on the real system only).
fn capability_files(scope: &Scope<'_>) -> Vec<(String, String)> {
    if scope.root != Path::new("/") || !Path::new(GETCAP).is_file() {
        return Vec::new();
    }
    let mut args = vec![OsString::from("-r")];
    args.extend(
        PRIVILEGED_ROOTS
            .iter()
            .map(|root| OsString::from(format!("/{root}")))
            .filter(|root| Path::new(root).is_dir()),
    );
    let Ok(captured) = tools::run(
        Path::new(GETCAP),
        &args,
        None,
        &[("LC_ALL", "C")],
        Limits {
            timeout_secs: 120,
            max_output: 4 * 1024 * 1024,
        },
    ) else {
        return Vec::new();
    };
    String::from_utf8_lossy(&captured.stdout)
        .lines()
        .filter_map(|line| {
            let (path, capabilities) = line.rsplit_once(' ')?;
            Some((
                path.strip_prefix('/')?.to_string(),
                capabilities.to_string(),
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

    use super::{check, is_loopback, listening, module_name, preloaded};
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
            preloaded(Some(b"A=1\0LD_PRELOAD=/usr/lib/x.so:/home/u/.y.so\0")),
            ["usr/lib/x.so", "home/u/.y.so"]
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
        write(root, "proc/sys/kernel/tainted", "4096\n");
        write(
            root,
            "proc/modules",
            "a 1 0 - Live 0x0\nrootkit 1 0 - Live 0x0\nghost 1 0 - Live 0x0\n",
        );
        write(
            root,
            "proc/net/tcp",
            "  sl  local_address rem_address   st\n   0: 0100007F:0277 00000000:0000 0A 0:0 0:0 0 1000 0 111 1\n   1: 00000000:1F90 00000000:0000 0A 0:0 0:0 0 1000 0 222 1\n",
        );
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
                "#mtree\n/set type=file mode=755\n./usr/bin/hyprland sha256digest={}\n./usr/bin/updated sha256digest={}\n./usr/lib/modules/6.1-test/kernel/a.ko.zst mode=644 sha256digest={}\n",
                digest("compositor"),
                digest("new version"),
                digest("module a")
            ),
            &[],
        );
        (dir, index)
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
                    "usr/lib/modules/6.1-test/extra/rootkit.ko",
                    Category::KernelModule,
                    vec![RuleId::UnknownKernelModule]
                ),
            ]
        );
        assert!(live.items[3].notes[0].contains("TCP port 8080"));
        assert!(live.notes.iter().any(|note| note.contains("out-of-tree")));
    }
}
