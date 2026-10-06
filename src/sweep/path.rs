//! Which directories a command name is looked up in, and what in them
//! takes a system command's name.
//!
//! A program in a directory that comes before `/usr/bin` on `PATH` runs
//! whenever its name is typed. The directories are not a fixed list: mise,
//! npm, Go, Bun and the like each add their own, so they are read from the
//! real `PATH`s: the one this sweep runs with, the systemd user manager's,
//! and the ones the shell start-up files set.

mod statement;

pub use statement::{assignments, opaque, unsafe_entries};

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

/// Whether a start-up file's text turns mise on for its shell (`eval
/// "$(mise activate bash)"`, `mise activate fish | source`): mise then puts
/// the directories of what it installed ahead of the system's.
fn activates_mise(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim();
        !line.starts_with('#') && line.contains("mise activate")
    })
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
mod tests;
