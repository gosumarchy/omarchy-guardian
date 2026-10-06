//! Following an item: the paths its link, its commands and the files it
//! reads in lead to, and which of them are followed.

use std::fs;
use std::path::Path;

use super::sight::{hop, look_past_link, names_a_file, view};
use super::{Body, Followed, Item, Scope, is_file_there, is_read_script, is_there, listed};
use crate::autorun::Category;
use crate::sweep::commands;
use crate::sweep::path::Search;
use crate::sweep::read::{self, Found, View};

/// Where the kernel keeps what is no program on disk: device nodes and its
/// own files. A command that names one (`--list-file /dev/stdout`) names
/// where its output goes, and `/dev/stdout` leads to whatever the sweep
/// itself writes to: nothing there is followed.
const NOT_FOLLOWED: &[&str] = &["dev/", "proc/", "sys/"];

/// Memory a user fills with files like any directory (`/dev/shm`), and
/// what lives until the next boot (`/run`, `/run/user/<uid>`): a program
/// run from there is followed like any other, but only a regular file is
/// one. The sockets and pipes services keep there are not.
const FILES_ONLY: &[&str] = &["dev/shm/", "run/"];

/// The longest command line split into its commands.
const MAX_SPLIT_LINE: usize = 64 * 1024;

/// Whether `command` is a pattern of files and nothing else
/// (`~/.config/hypr/conf.d/*.conf`), not a command line with a `*` in it.
fn is_pattern(command: &str) -> bool {
    let bare = command.trim();
    let bare = ["$HOME/", "${HOME}/"]
        .iter()
        .find_map(|home| bare.strip_prefix(home))
        .unwrap_or(bare);
    command.contains(['*', '?'])
        && !bare.contains(|c: char| c.is_whitespace() || ";|&$()<>`'\"\\".contains(c))
}

/// The paths `item` leads to that need judging too: a link's target, and
/// the programs and scripts its commands run. A bare command name is
/// looked up in `search`.
///
/// `configuration` says that `item` is itself configuration (a catalogued
/// file, or more of one): only then is what it reads in more of the same.
/// A script some command runs reads nothing in as configuration, whatever
/// its lines look like.
pub(super) fn follow(
    scope: &Scope<'_>,
    item: &Item,
    search: &Search,
    configuration: bool,
) -> Followed {
    let mut targets = Vec::new();
    let mut unfollowed: Vec<String> = Vec::new();
    let mut limit = |sentence: String| {
        if !unfollowed.contains(&sentence) {
            unfollowed.push(sentence);
        }
    };
    let by = Some(item.path.as_str());
    // What is read, not run: where a link leads (the same file under
    // another name), and what an SSH file reads in. Anything a command
    // names as well is run.
    let mut read_in: Vec<String> = Vec::new();
    let mut started: Vec<String> = Vec::new();
    // What a shell was handed as its script (`sh /x/run`).
    let mut handed: Vec<String> = Vec::new();
    if let Some(resolved) = link_target(scope, item) {
        read_in.push(resolved.clone());
        targets.push(resolved);
    }
    let included = included_by(item, configuration);
    let variables = variables_of(item);
    let mut environment: Vec<String> = Vec::new();
    // A file some other line runs under the very same words is run.
    let times = |list: &[String], command: &str| list.iter().filter(|one| *one == command).count();
    let mut record = |command: &str, target: &str| {
        let only = |list: &[String]| {
            let reads = times(list, command);
            reads > 0 && reads == times(&item.runs, command)
        };
        if only(&included) {
            read_in.push(target.to_string());
        } else if only(&variables) {
            environment.push(target.to_string());
        } else {
            started.push(target.to_string());
        }
    };
    let home: &str = &home_for(scope, item);
    let view = view(scope, by);
    let list = |directory: &str| listed(scope, view, directory);
    for command in &item.runs {
        // A pattern alone (a Hyprland `source`) names the files it
        // matches; anything else with a `*` in it (a command line, however
        // it is written) still runs its program.
        if is_pattern(command) {
            let (matched, more) = commands::glob_targets(home, command, &list);
            // A directory a pattern matches too (`/*`) is no more run
            // than one a command names.
            for target in matched
                .into_iter()
                .filter(|target| names_a_file(scope, target, by))
            {
                record(command, &target);
                targets.push(target);
            }
            if more {
                limit(format!(
                    "only the first {} files a pattern names",
                    commands::MAX_GLOB
                ));
            }
            continue;
        }
        // Each command of a line a shell runs (`a; b && c | d`) runs its
        // own program. Other lines (a unit's `ExecStart=`) are not shell:
        // there only ` ; ` separates commands, and a long line is taken
        // whole.
        let shell_line = matches!(
            item.category,
            Category::Cron | Category::Shell | Category::Hyprland
        ) || is_read_script(item);
        let lookup = commands::Lookup {
            home,
            search: &search.directories,
            exists: &|candidate| is_there(scope, candidate, by),
            capped: std::cell::Cell::new(false),
            shell_scripts: std::cell::RefCell::default(),
        };
        let (parts, long) = parts_of(command, shell_line);
        if long {
            limit(format!(
                "a command line longer than {MAX_SPLIT_LINE} bytes was taken as one command"
            ));
        }
        let (parts, more) = parts;
        if more {
            lookup.capped.set(true);
        }
        for part in parts {
            let reached = lookup.targets(&part);
            handed.extend(lookup.shell_scripts.take());
            for target in reached {
                record(command, &target);
                if !targets.contains(&target) {
                    targets.push(target);
                }
            }
        }
        if lookup.capped.get() {
            limit(format!(
                "only the first {} commands of a line",
                commands::MAX_INNER_COMMANDS
            ));
        }
    }
    let kinds = Kinds {
        read_in: &read_in,
        started: &started,
        handed: &handed,
        environment: &environment,
    };
    let mut followed = settle(scope, view, by, targets, &kinds);
    followed.unfollowed = unfollowed;
    followed
}

/// The regular file the link `item` leads to, if it is a link to one (a
/// masked unit's `/dev/null` is none).
fn link_target(scope: &Scope<'_>, item: &Item) -> Option<String> {
    let Body::Link(target) = &item.body else {
        return None;
    };
    read::resolve_where(&item.path, target, &|next| hop(scope, next))
        .filter(|resolved| matches!(look_past_link(scope, resolved), Found::File { .. }))
}

/// What the unit `item` reads as a list of variables and does not run
/// (`EnvironmentFile=`), by the words that name it.
fn variables_of(item: &Item) -> Vec<String> {
    match (&item.body, item.category) {
        (Body::Text(text), Category::Systemd) => commands::environment_files(&item.path, text),
        _ => Vec::new(),
    }
}

/// What `item` reads in as more configuration, by the words that name it
/// (an SSH `Include`): only where it is itself configuration.
fn included_by(item: &Item, configuration: bool) -> Vec<String> {
    match (&item.body, item.category) {
        (Body::Text(text), Category::Ssh) if configuration => commands::ssh_read_in(text),
        _ => Vec::new(),
    }
}

/// The home directory `~` stands for in `item`, relative to the root: in a
/// user's crontab that user's, not the sweep's.
fn home_for(scope: &Scope<'_>, item: &Item) -> String {
    item.path
        .strip_prefix("var/spool/cron/")
        .and_then(|user| user_home(scope.root, user))
        .or_else(|| scope.home.map(str::to_string))
        .unwrap_or_else(|| "root".to_string())
}

/// The commands of one command line, and whether it held more than are
/// looked up; and whether it was too long to split at all. Each command of
/// a line a shell runs (`a; b && c | d`) runs its own program; other lines
/// (a unit's `ExecStart=`) are not shell, and there only ` ; ` separates
/// commands.
fn parts_of(command: &str, shell_line: bool) -> ((Vec<String>, bool), bool) {
    if command.len() > MAX_SPLIT_LINE {
        ((vec![command.to_string()], false), true)
    } else if shell_line {
        (commands::split_commands(command), false)
    } else {
        (
            (command.split(" ; ").map(str::to_string).collect(), false),
            false,
        )
    }
}

/// How the targets of an item were reached, by the paths as written.
struct Kinds<'a> {
    /// Read as configuration (a link's target, an SSH `Include`).
    read_in: &'a [String],
    /// Named by a command.
    started: &'a [String],
    /// Handed to a shell as its script.
    handed: &'a [String],
    /// Read by a unit as a list of variables.
    environment: &'a [String],
}

/// The paths among `targets` that are followed, as the walk reaches them;
/// those among them that are read as configuration and not run; and those
/// a shell was handed as its script.
fn settle(
    scope: &Scope<'_>,
    view: Option<View>,
    by: Option<&str>,
    targets: Vec<String>,
    kinds: &Kinds<'_>,
) -> Followed {
    let mut shell_scripts = Vec::new();
    let mut environment = Vec::new();
    let under =
        |places: &[&str], target: &str| places.iter().any(|place| target.starts_with(place));
    let mut reached = Vec::new();
    let mut configuration = Vec::new();
    for target in targets {
        let followed = if under(FILES_ONLY, &target) {
            is_file_there(scope, &target, by)
        } else {
            !under(NOT_FOLLOWED, &target)
        };
        if !followed {
            continue;
        }
        let path = match view {
            // The path the pinned walk took, not one resolved again.
            Some(view) => read::seen(scope.root, &target, view).map(|seen| seen.path),
            None => read::canonical(scope.root, &target),
        };
        let Some(path) = path else {
            continue;
        };
        if kinds.read_in.contains(&target) && !kinds.started.contains(&target) {
            configuration.push(path.clone());
        }
        if kinds.handed.contains(&target) {
            shell_scripts.push(path.clone());
        }
        if kinds.environment.contains(&target) && !kinds.started.contains(&target) {
            environment.push(path.clone());
        }
        reached.push(path);
    }
    Followed {
        targets: reached,
        configuration,
        shell_scripts,
        environment,
        unfollowed: Vec::new(),
    }
}

/// The home directory of `user`, relative to the root, from `/etc/passwd`.
fn user_home(root: &Path, user: &str) -> Option<String> {
    fs::read_to_string(root.join("etc/passwd"))
        .ok()?
        .lines()
        .find_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            (fields.first() == Some(&user))
                .then(|| {
                    fields
                        .get(5)
                        .map(|home| home.trim_start_matches('/').to_string())
                })
                .flatten()
        })
        .filter(|home| !home.is_empty())
}
