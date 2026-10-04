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

/// The start-up files whose `PATH` lines are read, relative to the home
/// and to the root.
const HOME_FILES: &[&str] = &[
    ".profile",
    ".bash_profile",
    ".bashrc",
    ".zshenv",
    ".zprofile",
    ".zshrc",
    ".config/fish/config.fish",
    ".config/fish/fish_variables",
    ".config/uwsm/env",
];
const SYSTEM_FILES: &[&str] = &["etc/profile", "etc/environment", "etc/zsh/zshenv"];

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

/// The values a start-up file gives `PATH`, each as a `:`-separated list
/// with `$PATH` standing for what was there before: `PATH=…`, `export
/// PATH=…`, zsh's `path=(…)` and `path+=(…)`, fish's `set PATH …`,
/// `fish_add_path …` and its saved `fish_user_paths`.
pub fn assignments(text: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.starts_with('#') || line.len() > MAX_PATH_BYTES {
            continue;
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        let value = if let Some(saved) = line
            .strip_prefix("SETUVAR ")
            .and_then(|rest| rest.split_once("fish_user_paths:"))
            .map(|(_, saved)| saved)
        {
            // fish keeps the list with `\x1e` between its entries.
            Some(format!("{}:$PATH", saved.replace("\\x1e", ":")))
        } else if words.first() == Some(&"fish_add_path") {
            let append = words.iter().any(|word| matches!(*word, "-a" | "--append"));
            let directories: Vec<&str> = words[1..]
                .iter()
                .filter(|word| !word.starts_with('-'))
                .copied()
                .collect();
            Some(if append {
                format!("$PATH:{}", directories.join(":"))
            } else {
                format!("{}:$PATH", directories.join(":"))
            })
        } else if words.first() == Some(&"set")
            && let Some(at) = words.iter().skip(1).position(|word| !word.starts_with('-'))
            && matches!(words[at + 1], "PATH" | "fish_user_paths")
        {
            Some(words[at + 2..].join(":"))
        } else {
            let line = line.strip_prefix("export ").unwrap_or(line);
            if let Some(value) = line.strip_prefix("PATH=") {
                Some(
                    value
                        .split([';', ' '])
                        .next()
                        .unwrap_or_default()
                        .trim_matches(['"', '\''])
                        .to_string(),
                )
            } else if let Some(list) = line
                .strip_prefix("path=(")
                .or_else(|| line.strip_prefix("path+=("))
            {
                let listed = list
                    .split(')')
                    .next()
                    .unwrap_or_default()
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(":");
                Some(if line.starts_with("path+=") {
                    format!("$PATH:{listed}")
                } else {
                    listed
                })
            } else {
                None
            }
        };
        if let Some(value) = value {
            found.push((index + 1, value));
        }
    }
    found
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
    let files = scope
        .home
        .into_iter()
        .flat_map(|home| HOME_FILES.iter().map(move |file| format!("{home}/{file}")))
        .chain(SYSTEM_FILES.iter().map(|file| (*file).to_string()));
    for file in files {
        if let Found::File { head, .. } = collect::look(scope, Category::Shell, &file, None) {
            for (_, value) in assignments(&String::from_utf8_lossy(&head)) {
                sources.push(entries(home, &value));
            }
        }
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

/// The names in `directory` (not looked into further), as `scope` may see
/// them; `None` when it cannot be listed.
fn names(scope: &Scope<'_>, directory: &str) -> Option<Vec<String>> {
    let listed = |entries: fs::ReadDir| -> Vec<String> {
        entries
            .flatten()
            .filter_map(|entry| entry.file_name().into_string().ok())
            .take(read::MAX_ENTRIES + 1)
            .collect()
    };
    if scope.origin == Origin::Root {
        // Without following a link anybody but root could have put there.
        match read::seen(scope.root, directory, View::Pinned)?.what {
            read::Public::Directory(handle) => {
                fs::read_dir(format!("/proc/self/fd/{}", handle.as_raw_fd()))
                    .ok()
                    .map(listed)
            }
            _ => None,
        }
    } else {
        fs::read_dir(scope.root.join(directory)).ok().map(listed)
    }
}

/// The programs in the directories of `search` that someone other than
/// root can write and that take a system command's name, as paths; and
/// what could not be listed in full, as sentences.
pub fn shadowing_programs(scope: &Scope<'_>, search: &Search) -> (Vec<String>, Vec<String>) {
    let mut paths = Vec::new();
    let mut unchecked = Vec::new();
    for directory in &search.shadowing {
        let Some(mut listed) = names(scope, directory) else {
            continue;
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

    use super::{Search, assignments, entries, mark, search, shadowing_programs, unsafe_entries};
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
        for name in ["sudo", "node", "ls", "mise", "omarchy-menu"] {
            write(&format!("usr/bin/{name}"), "system");
        }
        write("home/u/.bashrc", "export PATH=\"$HOME/tools/bin:$PATH\"\n");
        write("home/u/tools/bin/sudo", "#!/bin/sh\n");
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
}
