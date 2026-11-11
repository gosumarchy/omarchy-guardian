//! What is looked for in one untrusted program: libraries the dynamic linker
//! was told to load into it, a temporary directory it runs from, and a
//! keyboard or camera it has open.

use std::fs;
use std::path::Path;

use super::{Found, Process, files, normalize, packaged, scripts, subject};
use crate::autorun::Category;
use crate::rules::RuleId;
use crate::sweep::collect::Scope;

/// The longest path the kernel opens, its NUL included (`PATH_MAX` in
/// `linux/limits.h`): the dynamic linker cannot load a longer one.
const PATH_MAX: usize = 4096;

/// Directories downloads and droppers land in.
const TEMPORARY: &[&str] = &["tmp/", "var/tmp/", "dev/shm/", "run/user/"];

/// Whether an untrusted process reads the keyboard or uses a camera.
pub(super) fn device_checks(scope: &Scope<'_>, process: &Process, exe: &str, found: &mut Found) {
    let pid = &process.pid;
    let (path, started) = subject(scope, process, exe);
    if process.open.keyboard {
        found.add(
            scope,
            Category::Input,
            &path,
            format!("process {pid} ({started}) reads the keyboard device"),
            Some(RuleId::KeyboardReader),
        );
    }
    if let Some(camera) = &process.open.camera {
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
pub(super) fn is_temporary(scope: &Scope<'_>, path: &str) -> bool {
    TEMPORARY
        .iter()
        .any(|directory| path.starts_with(directory))
        || scope
            .home
            .is_some_and(|home| path.starts_with(&format!("{home}/.cache/")))
}

pub(super) fn temporary_checks(scope: &Scope<'_>, process: &Process, exe: &str, found: &mut Found) {
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

/// The most preloaded libraries looked at per process. A program preloads
/// one or two; any process can name thousands, each a file the checks
/// would read and an item that would crowd out others. Past this the
/// process itself has an alert that says so.
const MAX_PRELOADED: usize = 16;

pub(super) fn preload_checks(scope: &Scope<'_>, process: &Process, exe: &str, found: &mut Found) {
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
    let libraries = preloaded(process.environment.as_deref());
    if libraries.len() > MAX_PRELOADED {
        found.add(
            scope,
            Category::Process,
            exe,
            format!(
                "process {pid} preloads {} libraries: only the first {MAX_PRELOADED} were looked at",
                libraries.len()
            ),
            Some(RuleId::PreloadedLibrary),
        );
    }
    for library in libraries.into_iter().take(MAX_PRELOADED) {
        match library {
            // Up to 128 KiB of the environment would become an item's name.
            Preload::Path(library) if library.len() >= PATH_MAX => found.add(
                scope,
                Category::Process,
                exe,
                format!(
                    "process {pid} preloads a path of {} bytes, longer than any the kernel opens",
                    library.len()
                ),
                Some(RuleId::PreloadedLibrary),
            ),
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

/// Whether open file `fd`, on the system at `root`, is an input device
/// with letter keys (a keyboard, not a game controller). Unknown devices
/// count as keyboards.
pub(super) fn reads_keys(root: &Path, fd: &str) -> bool {
    let Some(event) = fd.strip_prefix("/dev/input/") else {
        return false;
    };
    if !event.starts_with("event") {
        return false;
    }
    let Ok(bitmap) = fs::read_to_string(
        root.join("sys/class/input")
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

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Preload {
    /// A library by path, relative to `/`.
    Path(String),
    /// A name the dynamic linker looks up (`LD_LIBRARY_PATH` decides).
    Searched(String),
}

/// The libraries a process has the dynamic linker load into it: its
/// `LD_PRELOAD` and `LD_AUDIT`.
pub(super) fn preloaded(environment: Option<&[u8]>) -> Vec<Preload> {
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
            readable(value, b": ")
                .filter(|library| !library.is_empty())
                .filter_map(|library| match library.strip_prefix('/') {
                    Some(path) => normalize(path).map(Preload::Path),
                    None => Some(Preload::Searched(library.to_string())),
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The entries of a loader variable's `value`, split at any of
/// `separators`, without those that are not UTF-8: read lossily, each
/// would name another file. The linker loads the rest all the same, so
/// they are still checked (see `process::loader_not_utf8`, which tells of
/// the rest).
fn readable<'a>(value: &'a [u8], separators: &'a [u8]) -> impl Iterator<Item = &'a str> {
    value
        .split(|byte| separators.contains(byte))
        .filter_map(|entry| std::str::from_utf8(entry).ok())
}

/// The directories of a process's `LD_LIBRARY_PATH`, relative to `/`;
/// `None` for one that is relative to wherever the process runs. An empty
/// entry is left out, though it means that too: `X:$LD_LIBRARY_PATH` with
/// nothing set before leaves one in every launcher's environment. So are
/// the linker's own `$ORIGIN`, `$LIB` and `$PLATFORM`.
pub(super) fn searched(environment: Option<&[u8]>) -> Vec<Option<String>> {
    let Some(environment) = environment else {
        return Vec::new();
    };
    environment
        .split(|byte| *byte == 0)
        .filter_map(|entry| entry.strip_prefix(b"LD_LIBRARY_PATH="))
        .flat_map(|value| {
            readable(value, b":;")
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
