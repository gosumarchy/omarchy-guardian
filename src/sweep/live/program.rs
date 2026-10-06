//! What a running process really runs: the script an interpreter was given,
//! the Python module it was told to run, and how to name it.

use std::fs;

use super::{Module, Process, packaged, plain};
use crate::paths::file_name;
use crate::sweep::collect::{self, Scope};
use crate::sweep::programs::{is_interpreter, is_netcat, script_arguments};

/// The files on disk an interpreter (or the loader) may be running as its
/// script, most likely first; none for a program that is not one, and for
/// a relay, which runs what it is told (`ncat -e /usr/bin/bash`), not a
/// script.
pub(super) fn scripts(scope: &Scope<'_>, process: &Process, exe: &str) -> Vec<String> {
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
pub(super) fn subject(scope: &Scope<'_>, process: &Process, exe: &str) -> (String, String) {
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
pub(super) fn told(process: &Process, exe: &str) -> Option<String> {
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
pub(super) fn module_of(scope: &Scope<'_>, process: &Process, exe: &str) -> Option<Module> {
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
pub(super) fn started_in(process: &Process) -> Option<String> {
    let cwd = process.cwd.as_deref()?;
    let digest = crate::sha256::Sha256::digest(cwd.as_bytes()).to_string();
    Some(format!("cwd-{}", &digest[..12]))
}

/// `path` without `.`, `..` or empty parts; `None` when it climbs above `/`.
pub(super) fn normalize(path: &str) -> Option<String> {
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
