//! Which directories a command name is looked up in, and what in them
//! takes a system command's name.
//!
//! A program in a directory that comes before `/usr/bin` on `PATH` runs
//! whenever its name is typed. The directories are not a fixed list: mise,
//! npm, Go, Bun and the like each add their own, so they are read from the
//! real `PATH`s: the one this sweep runs with, the systemd user manager's,
//! and the ones the shell start-up files set.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use super::collect::{self, Body, Item, Origin, Scope};
use super::commands;
use super::read::{self, Found, View};
use super::tier::Tier;
use crate::autorun::Category;
use crate::rules::RuleId;
use crate::tools::{self, Limits};

const SYSTEMCTL: &str = "/usr/bin/systemctl";

/// Commands nothing in a directory a user can write should ever take the
/// name of, whoever put it there.
const ALWAYS_WATCHED: &[&str] = &[
    "sudo",
    "su",
    "doas",
    "pkexec",
    "run0",
    "ssh",
    "scp",
    "git",
    "gpg",
    "pacman",
    "yay",
    "paru",
    "makepkg",
    "systemctl",
    "loginctl",
    "passwd",
    "curl",
    "wget",
    "bash",
    "sh",
    "zsh",
    "fish",
    // The dispatcher every `omarchy …` command goes through, which is
    // what Guardian's own wrapper stands in front of.
    "omarchy",
    "omarchy-guardian",
];

/// Commands a version manager does take the name of (mise ships `node` and
/// `python`): a finding unless a version manager put the program there.
const WATCHED_UNLESS_MANAGED: &[&str] = &["python", "python3", "node", "claude", "opencode"];

/// Where mise itself may be, relative to the root or (`~`) the home.
const MISE: &[&str] = &[
    "usr/bin/mise",
    "usr/local/bin/mise",
    "~/.local/bin/mise",
    "~/.local/share/mise/bin/mise",
];

/// Where version managers keep what they installed, relative to the home.
const MANAGED: &[&str] = &[
    ".local/share/mise/installs/",
    ".local/share/mise/shims/",
    ".cargo/bin/",
];

/// The files whose `PATH` lines are read, relative to the home and to the
/// root: what a login, a shell of any kind, the user manager, the session
/// and Hyprland read. A `*` stands for any run of characters in a name.
const HOME_FILES: &[&str] = &[
    ".profile",
    ".bash_profile",
    ".bash_login",
    ".bashrc",
    ".zshenv",
    ".zprofile",
    ".zshrc",
    ".zlogin",
    ".config/fish/config.fish",
    ".config/fish/conf.d/*.fish",
    ".config/fish/fish_variables",
    ".config/environment.d/*.conf",
    ".pam_environment",
    ".config/uwsm/env*",
    ".config/uwsm/env.d/*",
    ".config/hypr/*.conf",
    ".config/hypr/*.lua",
];
const SYSTEM_FILES: &[&str] = &[
    "etc/profile",
    "etc/profile.d/*",
    "etc/bash.bashrc",
    "etc/environment",
    "etc/environment.d/*.conf",
    "usr/lib/environment.d/*.conf",
    "etc/zsh/zshenv",
    "etc/zsh/zprofile",
    "etc/zsh/zshrc",
    "etc/fish/config.fish",
    "etc/fish/conf.d/*.fish",
    "usr/share/omarchy/default/hypr/*.lua",
    "usr/share/omarchy/default/hypr/*.conf",
];

/// The most files read for their `PATH` lines, those a start-up file
/// reads in (`source`) included, and how far such a chain is followed.
const MAX_FILES: usize = 256;
const MAX_SOURCED_DEPTH: usize = 3;

/// The directories of the system's own commands: what comes before the
/// first of them on a `PATH` is looked in first.
const SYSTEM_DIRECTORIES: &[&str] = &["usr/bin", "bin", "usr/sbin", "sbin"];

/// The most directories kept, and the most `PATH` text read from one source.
const MAX_DIRECTORIES: usize = 256;
const MAX_PATH_BYTES: usize = 64 * 1024;

/// Where command names are looked up.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Search {
    /// Every directory, relative to the root, those ahead of `/usr/bin`
    /// first: the order a shell would try them in.
    pub directories: Vec<String>,
    /// The directories ahead of `/usr/bin` that someone other than root
    /// can write.
    pub shadowing: Vec<String>,
}

/// One entry of a `PATH`: the directory, and whether it comes before the
/// system's own.
type Entry = (String, bool);

/// The entries of the `PATH` value `value`, written out for `home`. An
/// entry that is not a literal directory (another variable, a relative
/// path) is left out here; `unsafe_entries` says which of those are a
/// danger in themselves.
fn entries(home: &str, value: &str) -> Vec<Entry> {
    let mut ahead = true;
    let mut found = Vec::new();
    for entry in value.split(':') {
        let entry = entry.trim().trim_matches(['"', '\'']);
        if matches!(entry, "$PATH" | "${PATH}" | "$path") {
            // What was there before: the system's own are in it.
            ahead = false;
            continue;
        }
        let expanded = commands::expand(home, &format!("{}/", entry.trim_end_matches('/')));
        let Some(directory) = expanded.strip_prefix('/') else {
            continue;
        };
        let directory = directory.trim_end_matches('/');
        if directory.is_empty() || directory.contains(['$', '`', '*']) {
            continue;
        }
        if SYSTEM_DIRECTORIES.contains(&directory) {
            ahead = false;
        }
        found.push((directory.to_string(), ahead));
    }
    found
}

/// What one statement does to `PATH`.
#[derive(Debug, PartialEq, Eq)]
enum Set {
    /// A `:`-separated list, `$PATH` standing for what was there before.
    Value(String),
    /// Something only running it would tell (`PATH=$(…)`).
    Opaque,
}

/// The words of the statements on a line of shell: split at `;`, `&&`,
/// `||`, `|` and `&` outside quotes, and after `then`, `do`, `else`, `{`
/// and the pattern of a `case` branch (`*)`). Quotes are taken off; a
/// substitution (`$(…)`, backquotes) and a zsh list (`(…)`) stay whole,
/// spaces and all. A `#` that starts a word ends the line.
fn statements(line: &str) -> Vec<Vec<String>> {
    let mut found: Vec<Vec<String>> = vec![Vec::new()];
    let mut word = String::new();
    let mut quote: Option<char> = None;
    let mut depth = 0_usize;
    let mut started = false;
    let mut characters = line.chars().peekable();
    let end = |found: &mut Vec<Vec<String>>, word: &mut String, started: &mut bool| {
        if *started && let Some(last) = found.last_mut() {
            last.push(std::mem::take(word));
        }
        *started = false;
        let keyword = found
            .last()
            .and_then(|words| words.last())
            .is_some_and(|last| {
                matches!(
                    last.as_str(),
                    "then"
                        | "do"
                        | "else"
                        | "elif"
                        | "if"
                        | "while"
                        | "{"
                        | "!"
                        | "and"
                        | "or"
                        | "not"
                        | "begin"
                ) || (last.ends_with(')') && !last.contains(['(', '=']))
            });
        if keyword && let Some(last) = found.last_mut() {
            last.pop();
            if !last.is_empty() {
                found.push(Vec::new());
            }
        }
    };
    while let Some(character) = characters.next() {
        match (quote, character) {
            (Some(open), _) if character == open && open != '`' => quote = None,
            (Some('`'), '`') => {
                quote = None;
                word.push(character);
            }
            (Some(_), _) => word.push(character),
            (None, '(') => {
                depth += 1;
                started = true;
                word.push(character);
            }
            (None, ')') if depth > 0 => {
                depth -= 1;
                word.push(character);
            }
            (None, _) if depth > 0 => word.push(character),
            (None, '"' | '\'') => {
                quote = Some(character);
                started = true;
            }
            (None, '`') => {
                quote = Some(character);
                started = true;
                word.push(character);
            }
            (None, '#') if !started => break,
            (None, ';' | '|' | '&') => {
                end(&mut found, &mut word, &mut started);
                while characters
                    .next_if(|next| matches!(next, ';' | '|' | '&'))
                    .is_some()
                {}
                if found.last().is_some_and(|last| !last.is_empty()) {
                    found.push(Vec::new());
                }
            }
            (None, _) if character.is_whitespace() => end(&mut found, &mut word, &mut started),
            (None, _) => {
                started = true;
                word.push(character);
            }
        }
    }
    end(&mut found, &mut word, &mut started);
    found.retain(|words| !words.is_empty());
    found
}

/// A `PATH` value with the ways of writing "what was there before"
/// reduced to `$PATH`.
fn plain_value(value: &str) -> String {
    value
        .replace("${PATH:+$PATH:}", "$PATH:")
        .replace("${PATH:+:$PATH}", ":$PATH")
        .replace("${PATH:+:${PATH}}", ":$PATH")
        .replace("${PATH:+${PATH}:}", "$PATH:")
        .replace("@{PATH}", "$PATH")
        .replace("@{HOME}", "$HOME")
}

/// What an assignment word (`PATH=x`, `PATH+=x`, `path=(a b)`) does to
/// `PATH`, if it is one to it.
fn assigned(word: &str) -> Option<Set> {
    let (name, value) = word.split_once('=')?;
    let (name, append) = match name.strip_suffix('+') {
        Some(name) => (name, true),
        None => (name, false),
    };
    if !matches!(name, "PATH" | "path") {
        return None;
    }
    let list = value
        .strip_prefix('(')
        .map(|list| list.trim_end_matches(')'));
    if list.unwrap_or(value).contains(['(', '`']) {
        return Some(Set::Opaque);
    }
    Some(Set::Value(match (list, append) {
        (Some(list), false) => list.split_whitespace().collect::<Vec<_>>().join(":"),
        (Some(list), true) => format!(
            "$PATH:{}",
            list.split_whitespace().collect::<Vec<_>>().join(":")
        ),
        // bash appends the text as it is (`PATH+=:/x`).
        (None, true) => format!("$PATH{}", plain_value(value)),
        (None, false) if name == "PATH" => plain_value(value),
        (None, false) => return None,
    }))
}

/// What the statement `words` does to `PATH`: an assignment on its own or
/// after `export`, `declare`, `typeset`, `local` or `readonly` (among
/// others: `export A=1 PATH=…`), fish's `set PATH …` and `fish_add_path`,
/// csh's `setenv PATH …`, and a line of `~/.pam_environment`. An
/// assignment before a command (`PATH=x make`) is for that command alone.
fn path_set(words: &[String]) -> Option<Set> {
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    let (first, rest) = words.split_first()?;
    let values = |values: &[&str]| {
        if values.iter().any(|value| value.contains(['(', '`'])) {
            Set::Opaque
        } else {
            Set::Value(plain_value(&values.join(":")))
        }
    };
    match *first {
        "export" | "declare" | "typeset" | "local" | "readonly" => rest
            .iter()
            .filter(|word| !word.starts_with(['-', '+']))
            .find_map(|word| assigned(word)),
        "set" => {
            let at = rest.iter().position(|word| !word.starts_with('-'))?;
            matches!(rest[at], "PATH" | "fish_user_paths").then(|| values(&rest[at + 1..]))
        }
        "setenv" if rest.first() == Some(&"PATH") => Some(values(&rest[1..])),
        "fish_add_path" => {
            let append = rest.iter().any(|word| matches!(*word, "-a" | "--append"));
            let directories: Vec<&str> = rest
                .iter()
                .filter(|word| !word.starts_with('-'))
                .copied()
                .collect();
            let listed = directories.join(":");
            Some(match values(&directories) {
                Set::Opaque => Set::Opaque,
                Set::Value(_) if append => Set::Value(format!("$PATH:{listed}")),
                Set::Value(_) => Set::Value(format!("{listed}:$PATH")),
            })
        }
        "PATH" => rest
            .iter()
            .find_map(|word| {
                word.strip_prefix("DEFAULT=")
                    .or_else(|| word.strip_prefix("OVERRIDE="))
            })
            .map(|value| values(&[value])),
        _ if words.iter().all(|word| is_assignment(word)) => {
            words.iter().find_map(|word| assigned(word))
        }
        _ => None,
    }
}

/// Whether `word` assigns to a variable (`NAME=value`, `NAME+=value`).
fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        let name = name.strip_suffix('+').unwrap_or(name);
        name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// What a line of Hyprland's configuration does to `PATH`: `env =
/// PATH,value`, or in Lua `hl.env("PATH", "value")`, where a value that is
/// not written out is known only to Hyprland.
fn hyprland(line: &str) -> Option<Set> {
    if let Some(rest) = line.strip_prefix("env")
        && let Some(setting) = rest.trim_start().strip_prefix('=')
    {
        let (name, value) = setting.split_once(',')?;
        return (name.trim() == "PATH").then(|| Set::Value(plain_value(value.trim())));
    }
    let (_, call) = line.split_once(".env(")?;
    let mut arguments = call.splitn(2, ',');
    let name = arguments.next()?.trim().trim_matches(['"', '\'']);
    if name != "PATH" {
        return None;
    }
    let value = arguments.next()?.trim().trim_end_matches(')').trim();
    let literal = value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .filter(|literal| !literal.contains('"'));
    Some(literal.map_or(Set::Opaque, |literal| Set::Value(plain_value(literal))))
}

/// What each line of `text` does to `PATH`, with its number.
fn scan(text: &str) -> Vec<(usize, Set)> {
    let mut found = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with("--") || line.len() > MAX_PATH_BYTES {
            continue;
        }
        let number = index + 1;
        if let Some(saved) = line
            .strip_prefix("SETUVAR ")
            .and_then(|rest| rest.split_once("fish_user_paths:"))
            .map(|(_, saved)| saved)
        {
            // fish keeps the list with `\\x1e` between its entries.
            let value = format!("{}:$PATH", saved.replace("\\x1e", ":"));
            found.push((number, Set::Value(value)));
        } else if let Some(set) = hyprland(line) {
            found.push((number, set));
        } else {
            found.extend(
                statements(line)
                    .iter()
                    .filter_map(|words| path_set(words))
                    .map(|set| (number, set)),
            );
        }
    }
    found
}

/// The values a start-up file gives `PATH`, each as a `:`-separated list
/// with `$PATH` standing for what was there before, wherever on a line the
/// statement stands (`[ -d ~/.x ] && export PATH=~/.x:$PATH`): `PATH=…`
/// alone or after `export`, `declare -x`, `typeset -x` or `local`, zsh's
/// `path=(…)` and `path+=(…)`, fish's `set PATH …`, `fish_add_path …` and
/// its saved `fish_user_paths`, csh's `setenv`, an environment file's line
/// and Hyprland's `env`.
pub fn assignments(text: &str) -> Vec<(usize, String)> {
    scan(text)
        .into_iter()
        .filter_map(|(line, set)| match set {
            Set::Value(value) => Some((line, value)),
            Set::Opaque => None,
        })
        .collect()
}

/// The lines of `text` that set `PATH` to something only running them
/// would tell (`PATH=$(…)`): the directories they add are not known, so
/// what is in them is not watched.
pub fn opaque(text: &str) -> Vec<usize> {
    let mut lines: Vec<usize> = scan(text)
        .into_iter()
        .filter(|(_, set)| *set == Set::Opaque)
        .map(|(line, _)| line)
        .collect();
    lines.dedup();
    lines
}

/// Whether a start-up file's text turns mise on for its shell (`eval
/// "$(mise activate bash)"`, `mise activate fish | source`): mise then puts
/// the directories of what it installed ahead of the system's.
fn activates_mise(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim();
        !line.starts_with('#') && line.contains("mise activate")
    })
}

/// Directories nothing lasting belongs in, as they appear in a `PATH`.
const TEMPORARY: &[&str] = &["/tmp", "/var/tmp", "/dev/shm", "/run/user/", "/.cache"];

/// The entries of the `PATH`s `text` sets that anyone can fill: the
/// working directory (`.`, or an empty entry), a relative directory, and a
/// temporary or cache directory. Each with its line.
pub fn unsafe_entries(text: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    for (line, value) in assignments(text) {
        for entry in value.split(':') {
            let entry = entry.trim().trim_matches(['"', '\'']);
            let what = if entry.is_empty() || entry == "." {
                Some("the directory a command is typed in is on PATH".to_string())
            } else if TEMPORARY.iter().any(|temporary| {
                entry == *temporary
                    || entry.starts_with(&format!("{}/", temporary.trim_end_matches('/')))
                    || (temporary.starts_with("/.") && entry.contains(temporary))
            }) {
                Some(format!(
                    "a temporary or cache directory is on PATH: {entry}"
                ))
            } else {
                None
            };
            if let Some(what) = what
                && !found.contains(&(line, what.clone()))
            {
                found.push((line, what));
            }
        }
    }
    found
}

/// The `PATH` of the systemd user manager, which starts the desktop's
/// services and the timer's sweep; `None` when it cannot be asked.
fn manager_path() -> Option<String> {
    let captured = tools::run(
        Path::new(SYSTEMCTL),
        &[OsString::from("--user"), OsString::from("show-environment")],
        None,
        &[("LC_ALL", "C")],
        Limits {
            timeout_secs: 5,
            max_output: MAX_PATH_BYTES,
        },
    )
    .ok()?;
    let stdout = captured.into_success().ok()?;
    String::from_utf8_lossy(&stdout)
        .lines()
        .find_map(|line| line.strip_prefix("PATH="))
        .map(str::to_string)
}

/// Whether someone other than root can put a program into `directory`.
fn others_can_write(root: &Path, directory: &str) -> bool {
    fs::metadata(root.join(directory)).is_ok_and(|metadata| {
        metadata.is_dir() && (metadata.uid() != 0 || metadata.mode() & 0o022 != 0)
    })
}

/// The text of every file whose `PATH` lines count (`HOME_FILES`,
/// `SYSTEM_FILES`), and of the files those read in with `source` or `.`,
/// which run as part of them.
fn start_up_texts(scope: &Scope<'_>, home: &str) -> Vec<String> {
    let patterns = scope
        .home
        .into_iter()
        .flat_map(|home| HOME_FILES.iter().map(move |file| format!("{home}/{file}")))
        .chain(SYSTEM_FILES.iter().map(|file| (*file).to_string()));
    let mut pending: Vec<(String, Option<String>, usize)> = Vec::new();
    for pattern in patterns {
        if pattern.contains('*') {
            let matched = read::matching(scope.root, &pattern).files;
            pending.extend(matched.into_iter().map(|file| (file, None, 0)));
        } else {
            pending.push((pattern, None, 0));
        }
    }
    pending.reverse();
    let mut seen: Vec<String> = Vec::new();
    let mut texts = Vec::new();
    while let Some((file, by, depth)) = pending.pop() {
        if seen.contains(&file) || seen.len() >= MAX_FILES {
            continue;
        }
        seen.push(file.clone());
        // A file another one reads in is named by that file: root looks
        // at it as it looks at anything a file leads to.
        let Found::File { head, .. } = collect::look(scope, Category::Shell, &file, by.as_deref())
        else {
            continue;
        };
        let text = String::from_utf8_lossy(&head).into_owned();
        if depth < MAX_SOURCED_DEPTH {
            for sourced in commands::sourced_files(&text) {
                let expanded = commands::expand(home, &sourced);
                if let Some(path) = expanded.strip_prefix('/')
                    && !path.contains(['$', '`', '*'])
                {
                    pending.push((path.to_string(), Some(file.clone()), depth + 1));
                }
            }
        }
        texts.push(text);
    }
    texts
}

/// Whether mise is installed where it usually is.
fn is_installed(scope: &Scope<'_>, home: &str) -> bool {
    MISE.iter().any(|mise| {
        let path = commands::expand(home, mise);
        fs::symlink_metadata(scope.root.join(path.trim_start_matches('/'))).is_ok()
    })
}

/// The versions of a tool under `directory` that a shell gets. mise links
/// the ones in use under shorter names (`latest`, `22` for `22.1.0`):
/// where there are such links, the versions they lead to; without any,
/// every version, since any may be the one in use. An older version kept
/// beside the one in use is on no `PATH`.
fn versions_in_use(scope: &Scope<'_>, directory: &str) -> Vec<String> {
    let versions = names(scope, directory).unwrap_or_default();
    let mut linked: Vec<String> = versions
        .iter()
        .filter_map(|version| {
            let target = fs::read_link(scope.root.join(directory).join(version)).ok()?;
            let name = target.file_name()?.to_str()?.to_string();
            versions.contains(&name).then_some(name)
        })
        .collect();
    linked.sort();
    linked.dedup();
    if linked.is_empty() { versions } else { linked }
}

/// The directories mise puts ahead of the system's own in a shell it is
/// turned on for: its shims, and the `bin` of the versions in use of every
/// tool it installed (`~/.local/share/mise/installs/node/22.1.0/bin`, or
/// the version's own directory where there is no `bin`).
fn mise_directories(scope: &Scope<'_>, home: &str) -> Vec<Entry> {
    let mut found = vec![(format!("{home}/.local/share/mise/shims"), true)];
    if scope.home.is_none() {
        return found;
    }
    let installs = format!("{home}/.local/share/mise/installs");
    for tool in names(scope, &installs).unwrap_or_default() {
        let versions = format!("{installs}/{tool}");
        for version in versions_in_use(scope, &versions) {
            // A tool that is one program has it in the version's
            // directory, without a `bin`.
            let version = format!("{versions}/{version}");
            let bin = format!("{version}/bin");
            let directory = if scope.root.join(&bin).is_dir() {
                bin
            } else {
                version
            };
            if scope.root.join(&directory).is_dir() && found.len() < MAX_DIRECTORIES {
                found.push((directory, true));
            }
        }
    }
    found.sort();
    found
}

/// Where command names are looked up on `scope`'s system: the real
/// `PATH`s when the system swept is the running one, the ones its start-up
/// files set, and the usual directories.
pub fn search(scope: &Scope<'_>) -> Search {
    let home = scope.home.unwrap_or("root");
    let mut sources: Vec<Vec<Entry>> = Vec::new();
    // The running system's own: a fixture has no environment.
    if scope.root == Path::new("/") {
        if let Some(path) = env::var("PATH")
            .ok()
            .filter(|path| path.len() <= MAX_PATH_BYTES)
        {
            sources.push(entries(home, &path));
        }
        // Root has no user manager of its own to ask.
        if scope.origin != Origin::Root
            && let Some(path) = manager_path()
        {
            sources.push(entries(home, &path));
        }
    }
    let mut mise = false;
    for text in start_up_texts(scope, home) {
        mise = mise || activates_mise(&text);
        for (_, value) in assignments(&text) {
            sources.push(entries(home, &value));
        }
    }
    if mise || is_installed(scope, home) {
        sources.push(mise_directories(scope, home));
    }
    let mut ahead: Vec<String> = Vec::new();
    let mut behind: Vec<String> = Vec::new();
    for (directory, is_ahead) in sources.into_iter().flatten() {
        let list = if is_ahead { &mut ahead } else { &mut behind };
        if !list.contains(&directory) && list.len() < MAX_DIRECTORIES {
            list.push(directory);
        }
    }
    // The usual directories, for the `PATH`s that could not be read (a
    // cron job's, another shell's): the home's ahead of the system's, as
    // most start-up files put them, unless a `PATH` that was read puts one
    // behind.
    for directory in commands::default_search(home) {
        let known = ahead.contains(&directory) || behind.contains(&directory);
        if !known && directory.starts_with(&format!("{home}/")) {
            ahead.push(directory);
        } else if !known {
            behind.push(directory);
        }
    }
    let shadowing = ahead
        .iter()
        .filter(|directory| others_can_write(scope.root, directory))
        .cloned()
        .collect();
    behind.retain(|directory| !ahead.contains(directory));
    if !behind.iter().any(|directory| directory == "usr/bin") {
        behind.push("usr/bin".into());
    }
    ahead.extend(behind);
    Search {
        directories: ahead,
        shadowing,
    }
}

/// Whether a program called `name` takes a system command's name.
fn shadows(scope: &Scope<'_>, name: &str) -> bool {
    ["usr/bin", "usr/share/omarchy/bin"]
        .iter()
        .any(|directory| fs::symlink_metadata(scope.root.join(directory).join(name)).is_ok())
}

/// What listing a directory gave.
enum Listing {
    Names(Vec<String>),
    /// Nothing is there (any more).
    Gone,
    /// Something is there and `scope` could not list it: a directory closed
    /// to it, one it will not follow a link into, or no directory at all.
    Closed,
}

/// The names in `directory` (not looked into further), as `scope` may see
/// them; `None` when it cannot be listed.
fn names(scope: &Scope<'_>, directory: &str) -> Option<Vec<String>> {
    match listing(scope, directory) {
        Listing::Names(names) => Some(names),
        Listing::Gone | Listing::Closed => None,
    }
}

/// `names`, with why there are none.
fn listing(scope: &Scope<'_>, directory: &str) -> Listing {
    let listed = |entries: io::Result<fs::ReadDir>| match entries {
        Ok(entries) => Listing::Names(
            entries
                .flatten()
                .filter_map(|entry| entry.file_name().into_string().ok())
                .take(read::MAX_ENTRIES + 1)
                .collect(),
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Listing::Gone,
        Err(_) => Listing::Closed,
    };
    if scope.origin == Origin::Root {
        // Without following a link anybody but root could have put there.
        match read::seen(scope.root, directory, View::Pinned).map(|seen| seen.what) {
            Some(read::Public::Directory(handle)) => listed(fs::read_dir(format!(
                "/proc/self/fd/{}",
                handle.as_raw_fd()
            ))),
            Some(_) => Listing::Closed,
            // The pinned walk does not say why it shows nothing.
            None => match fs::symlink_metadata(scope.root.join(directory)) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => Listing::Gone,
                _ => Listing::Closed,
            },
        }
    } else {
        listed(fs::read_dir(scope.root.join(directory)))
    }
}

/// The programs in the directories of `search` that someone other than
/// root can write and that take a system command's name, as paths; and
/// what could not be listed, or not in full, as sentences.
pub fn shadowing_programs(scope: &Scope<'_>, search: &Search) -> (Vec<String>, Vec<String>) {
    let mut paths = Vec::new();
    let mut unchecked = Vec::new();
    for directory in &search.shadowing {
        let mut listed = match listing(scope, directory) {
            Listing::Names(listed) => listed,
            // Gone since the search saw it: nothing is ahead there now.
            Listing::Gone => continue,
            Listing::Closed => {
                unchecked.push(format!(
                    "/{directory}: could not be listed; programs ahead of /usr/bin there were not checked"
                ));
                continue;
            }
        };
        if listed.len() > read::MAX_ENTRIES {
            unchecked.push(format!("/{directory}: more entries than were looked at"));
            listed.truncate(read::MAX_ENTRIES);
        }
        listed.sort();
        paths.extend(
            listed
                .into_iter()
                .filter(|name| {
                    is_watched(name) || name.starts_with("omarchy-") || shadows(scope, name)
                })
                .map(|name| format!("{directory}/{name}")),
        );
    }
    (paths, unchecked)
}

fn is_watched(name: &str) -> bool {
    ALWAYS_WATCHED.contains(&name)
}

/// Whether `path` is where a version manager keeps what it installed.
fn is_managed(scope: &Scope<'_>, path: &str) -> bool {
    scope.home.is_some_and(|home| {
        MANAGED
            .iter()
            .any(|managed| path.starts_with(&format!("{home}/{managed}")))
    })
}

/// The tier of the mise binary the link `item` leads to, if it is a mise
/// shim: mise's shims are links to mise itself under each tool's name.
fn mise_shim(scope: &Scope<'_>, item: &Item) -> Option<Tier> {
    let Body::Link(target) = &item.body else {
        return None;
    };
    let home = scope.home.unwrap_or("root");
    let resolved = read::resolve_where(&item.path, target, &|hop| {
        if scope.origin == Origin::Root {
            read::public_hop(scope.root, hop)
        } else {
            read::plain_hop(scope.root, hop)
        }
    })?;
    let known = MISE
        .iter()
        .any(|mise| commands::expand(home, mise).trim_start_matches('/') == resolved);
    if !known {
        return None;
    }
    let mise = collect::item(scope, Category::LocalBin, resolved, Some(&item.path));
    Some(if mise.tier == Tier::Vendor {
        Tier::Vendor
    } else {
        Tier::UserBuilt
    })
}

/// Says of each program in a directory of `search` what it takes over: one
/// under the name of a command that asks for a password, fetches or
/// installs is an alert, unless a version manager put it there under a name
/// version managers do take. A mise shim is as trusted as the mise it
/// links to.
pub fn mark(scope: &Scope<'_>, search: &Search, items: &mut [Item]) {
    for item in items
        .iter_mut()
        .filter(|item| item.category == Category::LocalBin && item.run_by.is_none())
    {
        let Some((directory, name)) = item.path.rsplit_once('/') else {
            continue;
        };
        if !search
            .shadowing
            .iter()
            .any(|shadowing| shadowing == directory)
        {
            continue;
        }
        let shim = mise_shim(scope, item);
        let managed = shim.is_some() || is_managed(scope, &item.path);
        let always = ALWAYS_WATCHED.contains(&name);
        let watched = always
            || ((WATCHED_UNLESS_MANAGED.contains(&name) || name.starts_with("omarchy-"))
                && !managed);
        if watched && shadows(scope, name) && !super::judge::is_trusted(item.tier) {
            item.alerts.push((
                RuleId::PathHijack,
                format!(
                    "/{directory} comes before /usr/bin on PATH: this runs whenever {name} is typed"
                ),
            ));
        } else if let Some(tier) = shim {
            item.tier = tier;
            item.notes
                .push("a mise shim (a link to mise itself)".into());
        } else if managed && item.tier == Tier::Unknown {
            item.tier = Tier::UserBuilt;
            item.notes
                .push("installed by a version manager, not by a package".into());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::fs;
    use std::os::unix::fs::symlink;

    use super::{
        Search, assignments, entries, mark, opaque, search, shadowing_programs, unsafe_entries,
    };
    use crate::autorun::Category;
    use crate::rules::RuleId;
    use crate::sweep::collect::{self, Origin, Scope};
    use crate::sweep::index::PackageIndex;
    use crate::sweep::tier::Tier;
    use crate::test_support::TempDir;

    #[test]
    fn a_path_is_read_in_order_and_split_at_the_systems_own() {
        assert_eq!(
            entries(
                "home/u",
                "/home/u/.local/share/mise/shims:$HOME/go/bin:/usr/local/bin:/usr/bin:~/.local/bin:$X/bin::."
            ),
            [
                ("home/u/.local/share/mise/shims".to_string(), true),
                ("home/u/go/bin".to_string(), true),
                ("usr/local/bin".to_string(), true),
                ("usr/bin".to_string(), false),
                ("home/u/.local/bin".to_string(), false),
            ]
        );
        // What a start-up file puts before the old PATH is ahead; what it
        // puts after is not.
        assert_eq!(
            entries("home/u", "$HOME/.bun/bin:$PATH:/opt/x/bin"),
            [
                ("home/u/.bun/bin".to_string(), true),
                ("opt/x/bin".to_string(), false)
            ]
        );
    }

    #[test]
    fn path_lines_of_every_shell_are_read() {
        let text = "export PATH=\"$HOME/.bun/bin:$PATH\"\nPATH=/tmp/x:$PATH; export PATH\n# PATH=/no\npath=(~/bin $path)\npath+=(/opt/y)\nset -gx PATH $HOME/.deno/bin $PATH\nfish_add_path -g ~/.cargo/bin\nfish_add_path --append /opt/z\nSETUVAR fish_user_paths:/home/u/a\\x1e/tmp/b\necho PATH=$PATH\n";
        let values: Vec<String> = assignments(text)
            .into_iter()
            .map(|(_, value)| value)
            .collect();
        assert_eq!(
            values,
            [
                "$HOME/.bun/bin:$PATH",
                "/tmp/x:$PATH",
                "~/bin:$path",
                "$PATH:/opt/y",
                "$HOME/.deno/bin:$PATH",
                "~/.cargo/bin:$PATH",
                "$PATH:/opt/z",
                "/home/u/a:/tmp/b:$PATH",
            ]
        );
        let lines: Vec<usize> = unsafe_entries(text)
            .into_iter()
            .map(|(line, _)| line)
            .collect();
        assert_eq!(lines, [2, 9]);
        let odd = unsafe_entries(
            "PATH=.:$PATH\nPATH=$PATH:\nexport PATH=\"$HOME/.cache/x/bin:$PATH\"\nPATH=$HOME/bin:$PATH\n",
        );
        assert_eq!(odd.len(), 3, "{odd:?}");
        assert!(odd[0].1.contains("typed in") && odd[2].1.contains(".cache/x/bin"));
    }

    #[test]
    fn a_path_is_found_wherever_on_a_line_it_is_set() {
        let values = |text: &str| -> Vec<String> {
            assignments(text)
                .into_iter()
                .map(|(_, value)| value)
                .collect()
        };
        for (line, expected) in [
            ("[ -d ~/.x ] && export PATH=~/.x:$PATH", "~/.x:$PATH"),
            (
                "if [ -d /opt/a ]; then PATH=/opt/a:$PATH; fi",
                "/opt/a:$PATH",
            ),
            ("declare -x PATH=\"/opt/b:$PATH\"", "/opt/b:$PATH"),
            ("typeset -gx PATH=/opt/c:$PATH", "/opt/c:$PATH"),
            ("export A=1 PATH=/opt/d:$PATH B=2", "/opt/d:$PATH"),
            ("A=1 PATH=/opt/e:$PATH", "/opt/e:$PATH"),
            ("test -d x || { PATH=/opt/f:$PATH; }", "/opt/f:$PATH"),
            ("  *) PATH=\"/opt/g${PATH:+:$PATH}\" ;;", "/opt/g:$PATH"),
            ("PATH=\"${PATH:+$PATH:}/opt/h\"", "$PATH:/opt/h"),
            ("PATH+=:/opt/i", "$PATH:/opt/i"),
            (
                "export PATH=\"$HOME/my tools:$PATH\"",
                "$HOME/my tools:$PATH",
            ),
            ("[[ -d ~/z ]] && path=(~/z $path)", "~/z:$path"),
            ("true; path+=(/opt/j /opt/k)", "$PATH:/opt/j:/opt/k"),
            ("test -d ~/f; and set -gx PATH ~/f $PATH", "~/f:$PATH"),
            ("status is-login && fish_add_path ~/g", "~/g:$PATH"),
            ("setenv PATH ${PATH}:/opt/l", "${PATH}:/opt/l"),
            (
                "PATH DEFAULT=@{HOME}/bin:${PATH} OVERRIDE=",
                "$HOME/bin:${PATH}",
            ),
            ("env = PATH,$HOME/h:$PATH", "$HOME/h:$PATH"),
            ("hl.env(\"PATH\", \"/opt/m:/usr/bin\")", "/opt/m:/usr/bin"),
        ] {
            assert_eq!(values(line), [expected], "{line}");
            assert!(opaque(line).is_empty(), "{line}");
        }
        // Not a lasting change of PATH, or not one at all.
        for line in [
            "PATH=/opt/x:$PATH make install",
            "echo PATH=/opt/x",
            "export MANPATH=/opt/x",
            "# export PATH=/opt/x:$PATH",
            "true # PATH=/opt/x",
            "alias p='echo $PATH'",
            "hl.env(\"OMARCHY_PATH\", paths.omarchy_path)",
            "env = XCURSOR_SIZE,24",
        ] {
            assert!(values(line).is_empty(), "{line}: {:?}", values(line));
            assert!(opaque(line).is_empty(), "{line}");
        }
        // What only running it would tell is said, not passed over.
        for line in [
            "export PATH=$(getconf PATH):$PATH",
            "PATH=\"$(/usr/bin/tool path)\"",
            "PATH=`tool path`:$PATH",
            "set -gx PATH (tool path) $PATH",
            "hl.env(\"PATH\", table.concat(kept, \":\"))",
        ] {
            assert!(values(line).is_empty(), "{line}: {:?}", values(line));
            assert_eq!(opaque(line), [1], "{line}");
        }
        assert_eq!(
            unsafe_entries("[ -d /tmp/b ] && export PATH=/tmp/b:$PATH\n").len(),
            1
        );
    }

    #[test]
    fn every_file_a_shell_or_a_session_reads_counts_for_the_path() {
        let dir = TempDir::new("sweep-path-sources");
        let root = dir.path();
        if std::os::unix::fs::MetadataExt::uid(&fs::metadata(root).unwrap()) == 0 {
            return;
        }
        let write = |path: &str, text: &str| {
            fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
            fs::write(root.join(path), text).unwrap();
        };
        write(
            "home/u/.bashrc",
            "[ -r ~/.config/shell/extra ] && . ~/.config/shell/extra\nX=$HOME/opt\nsource $X/env.sh\neval \"$(mise activate bash)\"\n",
        );
        write(
            "home/u/.config/shell/extra",
            "export PATH=\"$HOME/a/bin:$PATH\"\n",
        );
        write(
            "home/u/opt/env.sh",
            "if true; then PATH=$HOME/b/bin:$PATH; fi\n",
        );
        write(
            "home/u/.config/fish/conf.d/x.fish",
            "fish_add_path ~/c/bin\n",
        );
        write(
            "home/u/.config/environment.d/10-x.conf",
            "PATH=$HOME/d/bin:$PATH\n",
        );
        write(
            "home/u/.pam_environment",
            "PATH DEFAULT=@{HOME}/e/bin:${PATH}\n",
        );
        write(
            "home/u/.config/uwsm/env-hyprland",
            "export PATH=$HOME/f/bin:$PATH\n",
        );
        write(
            "home/u/.config/hypr/envs.conf",
            "env = PATH,$HOME/g/bin:$PATH\n",
        );
        write("etc/profile.d/x.sh", "PATH=/opt/h/bin:$PATH\n");
        write("etc/environment.d/x.conf", "PATH=/opt/i/bin:${PATH}\n");
        write(
            "usr/share/omarchy/default/hypr/envs.lua",
            "hl.env(\"PATH\", \"/opt/j/bin:/usr/bin\")\n",
        );
        let installs = "home/u/.local/share/mise/installs";
        write(&format!("{installs}/node/22.1.0/bin/node"), "node");
        write(&format!("{installs}/node/22.1.0/bin/sudo"), "odd");
        write(&format!("{installs}/tool/latest/tool"), "tool");
        write("usr/bin/node", "system");
        write("usr/bin/sudo", "system");
        for directory in ["a", "b", "c", "d", "e", "f", "g"] {
            fs::create_dir_all(root.join(format!("home/u/{directory}/bin"))).unwrap();
        }
        let index = PackageIndex::with_foreign(HashSet::new());
        let scope = Scope {
            root,
            home: Some("home/u"),
            index: &index,
            origin: Origin::System,
        };
        let found = search(&scope);
        for directory in ["a", "b", "c", "d", "e", "f", "g"] {
            let directory = format!("home/u/{directory}/bin");
            assert!(found.shadowing.contains(&directory), "{directory}");
        }
        let at = |directory: &str| {
            found
                .directories
                .iter()
                .position(|known| known == directory)
        };
        let system = at("usr/bin").unwrap();
        for directory in ["opt/h/bin", "opt/i/bin", "opt/j/bin"] {
            assert!(at(directory).is_some_and(|at| at < system), "{directory}");
        }
        // What mise installed is ahead in a shell it is turned on for.
        let node = format!("{installs}/node/22.1.0/bin");
        assert!(found.shadowing.contains(&node), "{:?}", found.shadowing);
        let (paths, _) = shadowing_programs(&scope, &found);
        assert!(paths.contains(&format!("{node}/node")));
        assert!(found.shadowing.contains(&format!("{installs}/tool/latest")));
        let mut items: Vec<_> = paths
            .into_iter()
            .map(|path| collect::item(&scope, Category::LocalBin, path, None))
            .collect();
        mark(&scope, &found, &mut items);
        let alerts = |name: &str| {
            items
                .iter()
                .find(|item| item.path == format!("{node}/{name}"))
                .map(|item| item.alerts.len())
        };
        assert_eq!(alerts("node"), Some(0));
        assert_eq!(alerts("sudo"), Some(1));
    }

    #[test]
    fn only_the_versions_mise_has_in_use_are_ahead() {
        let dir = TempDir::new("sweep-path-mise");
        let root = dir.path();
        let installs = "home/u/.local/share/mise/installs";
        for version in ["2.1.1", "2.1.2"] {
            let directory = root.join(format!("{installs}/claude/{version}"));
            fs::create_dir_all(&directory).unwrap();
            fs::write(directory.join("claude"), version).unwrap();
        }
        fs::create_dir_all(root.join(format!("{installs}/node/22.1.0/bin"))).unwrap();
        // mise links the version in use under shorter names; the older
        // one kept beside it is on no `PATH`.
        for alias in ["latest", "2"] {
            symlink("./2.1.2", root.join(format!("{installs}/claude/{alias}"))).unwrap();
        }
        let index = PackageIndex::with_foreign(HashSet::new());
        let scope = Scope {
            root,
            home: Some("home/u"),
            index: &index,
            origin: Origin::System,
        };
        let directories: Vec<String> = super::mise_directories(&scope, "home/u")
            .into_iter()
            .map(|(directory, _)| directory)
            .collect();
        assert_eq!(
            directories,
            [
                format!("{installs}/claude/2.1.2"),
                // Without links, any version may be the one in use.
                format!("{installs}/node/22.1.0/bin"),
                "home/u/.local/share/mise/shims".to_string(),
            ]
        );
    }

    #[test]
    fn a_start_up_file_that_sets_the_path_from_a_command_says_so() {
        let dir = TempDir::new("sweep-path-opaque");
        let root = dir.path();
        fs::create_dir_all(root.join("home/u")).unwrap();
        fs::write(
            root.join("home/u/.zshrc"),
            "export PATH=$(tool path):$PATH\n",
        )
        .unwrap();
        let index = PackageIndex::with_foreign(HashSet::new());
        let scope = Scope {
            root,
            home: Some("home/u"),
            index: &index,
            origin: Origin::System,
        };
        let item = collect::item(&scope, Category::Shell, "home/u/.zshrc".into(), None);
        assert!(
            item.notes
                .iter()
                .any(|note| note.starts_with("line 1 sets PATH in a way Guardian cannot follow")),
            "{:?}",
            item.notes
        );
    }

    #[test]
    fn programs_ahead_of_the_systems_own_are_found_where_the_start_up_files_put_them() {
        let dir = TempDir::new("sweep-path");
        let root = dir.path();
        // Run as root (a container), every directory here is root's own:
        // there is nobody else who could write them.
        if std::os::unix::fs::MetadataExt::uid(&fs::metadata(root).unwrap()) == 0 {
            return;
        }
        let write = |path: &str, text: &str| {
            fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
            fs::write(root.join(path), text).unwrap();
        };
        for name in ["sudo", "node", "ls", "mise", "omarchy-menu", "omarchy"] {
            write(&format!("usr/bin/{name}"), "system");
        }
        write("home/u/.bashrc", "export PATH=\"$HOME/tools/bin:$PATH\"\n");
        write("home/u/tools/bin/sudo", "#!/bin/sh\n");
        write("home/u/tools/bin/omarchy", "#!/bin/sh\n");
        write("home/u/tools/bin/ls", "#!/bin/sh\n");
        write("home/u/tools/bin/mine", "#!/bin/sh\n");
        // A version manager's: shims that are links to mise, and what it
        // installed.
        fs::create_dir_all(root.join("home/u/.local/share/mise/shims")).unwrap();
        for name in ["node", "sudo"] {
            symlink(
                "/usr/bin/mise",
                root.join("home/u/.local/share/mise/shims").join(name),
            )
            .unwrap();
        }
        symlink(
            "/home/u/tools/bin/mine",
            root.join("home/u/.local/share/mise/shims/ls"),
        )
        .unwrap();
        let index = PackageIndex::with_foreign(HashSet::new());
        let scope = Scope {
            root,
            home: Some("home/u"),
            index: &index,
            origin: Origin::System,
        };
        let found = search(&scope);
        assert_eq!(found.directories[0], "home/u/tools/bin");
        assert!(found.shadowing.contains(&"home/u/tools/bin".to_string()));
        assert!(
            found
                .shadowing
                .contains(&"home/u/.local/share/mise/shims".to_string())
        );
        assert_eq!(
            found.directories.last().map(String::as_str),
            Some("usr/bin")
        );

        let (paths, unchecked) = shadowing_programs(&scope, &found);
        assert!(unchecked.is_empty());
        assert_eq!(
            paths,
            [
                "home/u/tools/bin/ls",
                "home/u/tools/bin/omarchy",
                "home/u/tools/bin/sudo",
                "home/u/.local/share/mise/shims/ls",
                "home/u/.local/share/mise/shims/node",
                "home/u/.local/share/mise/shims/sudo",
            ]
        );
        let mut items: Vec<_> = paths
            .into_iter()
            .map(|path| collect::item(&scope, Category::LocalBin, path, None))
            .collect();
        mark(&scope, &found, &mut items);
        let alerted = |path: &str| {
            items
                .iter()
                .find(|item| item.path == path)
                .is_some_and(|item| {
                    item.alerts
                        .iter()
                        .any(|(rule, _)| *rule == RuleId::PathHijack)
                })
        };
        // `sudo` is an alert wherever it is, a mise shim or not; `ls` is
        // listed; a shim for `node` is what mise is for.
        assert!(alerted("home/u/tools/bin/sudo"));
        // The bare dispatcher, not only the `omarchy-*` commands.
        assert!(alerted("home/u/tools/bin/omarchy"));
        assert!(alerted("home/u/.local/share/mise/shims/sudo"));
        assert!(!alerted("home/u/tools/bin/ls"));
        assert!(!alerted("home/u/.local/share/mise/shims/node"));
        let node = items
            .iter()
            .find(|item| item.path.ends_with("shims/node"))
            .unwrap();
        assert_eq!(node.tier, Tier::UserBuilt);
        assert!(node.notes.iter().any(|note| note.contains("mise shim")));
        // A link in the shims directory that is not to mise is no shim,
        // though it sits where a version manager keeps its own.
        let ls = items
            .iter()
            .find(|item| item.path.ends_with("shims/ls"))
            .unwrap();
        assert!(!ls.notes.iter().any(|note| note.contains("mise shim")));
    }

    #[test]
    fn a_directory_behind_the_systems_own_takes_no_commands_name() {
        let dir = TempDir::new("sweep-path-behind");
        let root = dir.path();
        if std::os::unix::fs::MetadataExt::uid(&fs::metadata(root).unwrap()) == 0 {
            return;
        }
        let write = |path: &str, text: &str| {
            fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
            fs::write(root.join(path), text).unwrap();
        };
        fs::create_dir_all(root.join("home/u/.local/share/mise/shims")).unwrap();
        let index = PackageIndex::with_foreign(HashSet::new());
        let scope = Scope {
            root,
            home: Some("home/u"),
            index: &index,
            origin: Origin::System,
        };
        // A directory a start-up file puts behind the system's own takes
        // no command's name there.
        write("home/u/.bashrc", "export PATH=\"$PATH:$HOME/.local/bin\"\n");
        write("home/u/.local/bin/sudo", "#!/bin/sh\n");
        let behind = search(&scope);
        assert!(!behind.shadowing.contains(&"home/u/.local/bin".to_string()));
        assert!(
            behind
                .directories
                .contains(&"home/u/.local/bin".to_string())
        );
        // The directories no `PATH` that was read speaks of stay ahead.
        assert!(
            behind
                .shadowing
                .contains(&"home/u/.local/share/mise/shims".to_string())
        );

        // Nothing but the usual directories without a home.
        let bare = search(&Scope {
            root,
            home: None,
            index: &index,
            origin: Origin::System,
        });
        assert_eq!(
            bare,
            Search {
                directories: crate::sweep::commands::default_search("root"),
                shadowing: Vec::new(),
            }
        );
    }

    #[test]
    fn a_directory_ahead_that_cannot_be_listed_is_said() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("sweep-path-closed");
        let root = dir.path();
        for file in ["usr/bin/sudo", "home/u/bin/sudo", "home/u/closed/sudo"] {
            let path = root.join(file);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, "x").unwrap();
        }
        fs::write(root.join("home/u/file"), "no directory").unwrap();
        symlink("bin", root.join("home/u/linked")).unwrap();
        let index = PackageIndex::with_foreign(HashSet::new());
        let scope = |origin| Scope {
            root,
            home: Some("home/u"),
            index: &index,
            origin,
        };
        let ahead = |directories: &[&str]| Search {
            directories: Vec::new(),
            shadowing: directories
                .iter()
                .map(|name| format!("home/u/{name}"))
                .collect(),
        };
        let closed = |name: &str| {
            format!(
                "/home/u/{name}: could not be listed; programs ahead of /usr/bin there were not checked"
            )
        };
        // What is there and is no directory to list is said, whoever
        // looks; what is gone since the search saw it is not.
        for origin in [Origin::System, Origin::Root] {
            let (paths, unchecked) =
                shadowing_programs(&scope(origin), &ahead(&["gone", "file", "bin"]));
            assert_eq!(paths, ["home/u/bin/sudo"], "{origin:?}");
            assert_eq!(unchecked, [closed("file")], "{origin:?}");
        }
        // Root follows no link into a directory, and says it did not look.
        let (paths, unchecked) = shadowing_programs(&scope(Origin::Root), &ahead(&["linked"]));
        assert!(paths.is_empty(), "{paths:?}");
        assert_eq!(unchecked, [closed("linked")]);
        let (paths, unchecked) = shadowing_programs(&scope(Origin::System), &ahead(&["linked"]));
        assert_eq!(paths, ["home/u/linked/sudo"]);
        assert!(unchecked.is_empty(), "{unchecked:?}");
        // A directory closed to the reader. Nothing is closed to root, who
        // then lists it like any other.
        let directory = root.join("home/u/closed");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o000)).unwrap();
        let is_closed = fs::read_dir(&directory).is_err();
        let found = shadowing_programs(&scope(Origin::System), &ahead(&["closed"]));
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
        if is_closed {
            assert_eq!(found, (vec![], vec![closed("closed")]));
        } else {
            assert_eq!(found, (vec!["home/u/closed/sudo".to_string()], vec![]));
        }
    }
}
