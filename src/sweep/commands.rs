//! What an auto-run file starts: the command lines it holds, and the
//! programs and scripts those name. Used to list what each item runs and to
//! judge the files it runs too (a trusted interpreter is judged by the
//! script it is given).

mod shell;
mod targets;

use super::{lua, read};
use crate::autorun::Category;
use crate::paths::file_name;

pub use shell::{is_shell_script, sourced_files};
use shell::{path_variables, sourced, started, without_case_patterns, zdotdir};
use targets::split;
pub use targets::{
    Lookup, MAX_GLOB, MAX_INNER_COMMANDS, default_search, expand, glob_targets, split_commands,
};
#[cfg(test)]
pub use targets::{inner_commands, targets, targets_where};

/// Whether `path` (relative to the root) is the script the SSH server runs
/// at every login: `~/.ssh/rc` or `/etc/ssh/sshrc`. It is a shell script,
/// not configuration, whatever directory it sits in.
pub fn is_ssh_rc(path: &str) -> bool {
    path == "etc/ssh/sshrc" || path.ends_with("/.ssh/rc")
}

/// The command lines `text` (a file of `category` named `name`) runs.
pub fn commands(category: Category, path: &str, text: &str) -> Vec<String> {
    let name = file_name(path);
    // The login script of the SSH server is read as the shell script it is.
    let category = if is_ssh_rc(path) {
        Category::Shell
    } else {
        category
    };
    // logrotate's files are no crontabs: what their `postrotate` scripts
    // run is reviewed as the text it is.
    if path.starts_with("etc/logrotate") {
        return Vec::new();
    }
    if category == Category::Cron {
        return crontab(path, text);
    }
    if category == Category::Hyprland {
        return if read::has_extension(name, "lua") {
            lua::startup_commands(text)
        } else {
            hyprland_conf(text)
        };
    }
    if name == "mimeapps.list" {
        return handlers(text);
    }
    // An include line of sudoers may start with `#`, like a comment.
    if category == Category::Sudo {
        return sudoers(path, text);
    }
    let variables = if category == Category::Shell {
        path_variables(text)
    } else {
        Vec::new()
    };
    // systemd reads a line that ends in `\` on into the next one.
    let joined;
    let text = if category == Category::Systemd && text.contains("\\\n") {
        joined = text.replace("\\\n", " ");
        joined.as_str()
    } else {
        text
    };
    let mut found = Vec::new();
    let mut cases = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        // A line of `;;` alone ends a `case` branch: the next is a pattern.
        if line.starts_with(';') {
            if category == Category::Shell && line.len() <= MAX_STARTED_LINE {
                without_case_patterns(line, &mut cases);
            }
            continue;
        }
        // A `case` branch's pattern (`/*)`) is matched, not run.
        let branches;
        let line = if category == Category::Shell && line.len() <= MAX_STARTED_LINE {
            branches = without_case_patterns(line, &mut cases);
            branches.as_str()
        } else {
            line
        };
        let expanded = crate::rules::with_variables(line, &variables);
        // A line that grew past what is looked at is read as written.
        let line = if expanded.len() > MAX_STARTED_LINE {
            line
        } else {
            expanded.as_str()
        };
        let command = match category {
            Category::Udev => udev(line),
            Category::Kernel => modprobe(line),
            Category::Pam => pam(line),
            Category::Ssh => ssh(line).map(|(_, value)| value).into_iter().collect(),
            Category::Shell => {
                let mut runs = sourced(line);
                runs.extend(started(line));
                runs.extend(zdotdir(line));
                runs
            }
            Category::Terminal => terminal(name, line),
            Category::Toolchain => toolchain(name, line),
            Category::Browser => native_host(line),
            Category::Systemd => key_value(line)
                .into_iter()
                .map(|command| with_specifiers(path, &command))
                .collect(),
            _ => key_value(line),
        };
        found.extend(command);
    }
    found
}

/// What of a file of `category` was not looked through for what it runs,
/// as sentences: a limit was reached, and nobody should take the list of
/// what it runs for the whole of it.
pub fn unfollowed(category: Category, text: &str) -> Vec<String> {
    let long = text
        .lines()
        .filter(|line| line.len() > MAX_STARTED_LINE)
        .count();
    if category == Category::Shell && long > 0 {
        vec![format!(
            "{long} line(s) longer than {MAX_STARTED_LINE} bytes were not looked through for the programs they start"
        )]
    } else {
        Vec::new()
    }
}

/// What a sudoers file reads in (`@include file`, `@includedir directory`,
/// and the older `#include` and `#includedir`), and the programs and
/// plugins `sudo.conf` names. A directory is given as the pattern of its
/// files; a name relative to the including file is made whole.
fn sudoers(path: &str, text: &str) -> Vec<String> {
    let directory = path.rsplit_once('/').map_or("", |(directory, _)| directory);
    let whole = |file: &str| {
        let file = file.trim_matches('"');
        if file.starts_with('/') {
            file.to_string()
        } else {
            format!("/{directory}/{file}")
        }
    };
    let mut found = Vec::new();
    for line in text.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        let included = match words.as_slice() {
            // `%h` in a name stands for the host name, which is not known
            // here.
            [_, file, ..] if file.contains('%') => continue,
            ["@include" | "#include", file, ..] => whole(file),
            ["@includedir" | "#includedir", directory, ..] => {
                format!("{}/*", whole(directory).trim_end_matches('/'))
            }
            ["Path" | "Plugin", _, program, ..] if program.starts_with('/') => {
                (*program).to_string()
            }
            _ => continue,
        };
        if !found.contains(&included) {
            found.push(included);
        }
    }
    found
}

/// systemd's specifiers for the directories a unit's commands live in,
/// written out: for a user unit the home's own, for a system unit the
/// system's. `%t` in a user unit is `/run/user/<uid>`, which is not known
/// here and stays as written.
fn with_specifiers(path: &str, command: &str) -> String {
    if !command.contains('%') {
        return command.to_string();
    }
    let user = path.contains("/systemd/user") || path.contains("/containers/systemd/");
    let directories: &[(&str, &str)] = if user {
        &[
            ("%h", "~"),
            ("%E", "~/.config"),
            ("%S", "~/.local/state"),
            ("%C", "~/.cache"),
            ("%L", "~/.local/state/log"),
        ]
    } else {
        &[
            ("%h", "/root"),
            ("%E", "/etc"),
            ("%S", "/var/lib"),
            ("%C", "/var/cache"),
            ("%L", "/var/log"),
            ("%t", "/run"),
        ]
    };
    command
        .split(' ')
        .map(|word| {
            for (specifier, directory) in directories {
                if let Some(rest) = word.strip_prefix(specifier)
                    && (rest.is_empty() || rest.starts_with('/'))
                {
                    return format!("{directory}{rest}");
                }
            }
            word.to_string()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The first quoted strings of a TOML or JSON value, joined as the words
/// of one command: `"x"` and `["sh", "-c", "x"]` alike. A value without
/// quotes is taken as written.
fn quoted_words(value: &str) -> String {
    let value = value.trim();
    if !value.contains(['"', '\'']) {
        return value.trim_end_matches(',').to_string();
    }
    let mut words = Vec::new();
    let mut rest = value;
    while let Some(start) = rest.find(['"', '\'']) {
        let quote = rest[start..].chars().next().unwrap_or('"');
        let after = &rest[start + 1..];
        let Some(end) = after.find(quote) else {
            break;
        };
        words.push(&after[..end]);
        rest = &after[end + 1..];
        // An inline table's next key (`program = "x", args = [...]`) is
        // not part of the command.
        if rest.trim_start().starts_with('}') {
            break;
        }
    }
    words.join(" ")
}

/// What a terminal, a prompt or tmux is told to run each time it starts:
/// alacritty's `shell`/`program`, kitty's `shell`, `startup_session` and
/// `watcher`, ghostty's `command` and `initial-command`, foot's `shell`,
/// starship's `command` and `when` of a custom module, and tmux's
/// `run-shell`, `default-command`, `default-shell` and `source-file`.
fn terminal(name: &str, line: &str) -> Vec<String> {
    let mut found = Vec::new();
    if name.ends_with("tmux.conf") {
        let words = split(line);
        for (index, word) in words.iter().enumerate() {
            let value = match word.as_str() {
                "run-shell" | "run" | "if-shell" | "if" | "source-file" | "source" => words
                    [index + 1..]
                    .iter()
                    .find(|word| !word.starts_with('-')),
                "default-command" | "default-shell" => words.get(index + 1),
                _ => None,
            };
            if let Some(value) = value.filter(|value| !value.is_empty()) {
                found.push(value.clone());
            }
        }
        return found;
    }
    if name == "kitty.conf" {
        let (key, value) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
        let value = value.trim();
        if matches!(key, "shell" | "startup_session" | "watcher")
            && !value.is_empty()
            && !matches!(value, "." | "none")
        {
            found.push(value.to_string());
        }
        return found;
    }
    let Some((key, value)) = line.split_once('=') else {
        return found;
    };
    let key = key.trim();
    let runs = match name {
        "config" => matches!(key, "command" | "initial-command"),
        "foot.ini" => key == "shell",
        "starship.toml" => matches!(key, "command" | "when" | "shell"),
        // alacritty: `shell = "x"`, `program = "x"` or an inline table.
        _ => matches!(
            key,
            "shell" | "program" | "terminal.shell" | "shell.program"
        ),
    };
    if !runs {
        return found;
    }
    // An inline table (`{ program = "x", args = [...] }`): its program.
    let command = match value.find("program") {
        Some(at) if value.trim_start().starts_with('{') => value[at..]
            .split(['"', '\''])
            .nth(1)
            .unwrap_or_default()
            .to_string(),
        _ => quoted_words(value),
    };
    if !command.is_empty() && !matches!(command.as_str(), "true" | "false") {
        found.push(command);
    }
    found
}

/// The files a `node-options` value has Node.js load before anything
/// else (`--require /x.js`, `--import=/x.mjs`).
fn node_loaded(value: &str) -> Vec<String> {
    let words: Vec<&str> = value
        .split_whitespace()
        .map(|word| word.trim_matches(['"', '\'']))
        .collect();
    let mut found = Vec::new();
    for (index, word) in words.iter().enumerate() {
        let loaded = match word.split_once('=') {
            Some(("--require" | "--import" | "--loader" | "--experimental-loader", file)) => {
                Some(file)
            }
            None if matches!(*word, "--require" | "-r" | "--import" | "--loader") => {
                words.get(index + 1).copied()
            }
            _ => None,
        };
        found.extend(loaded.filter(|file| !file.is_empty()).map(str::to_string));
    }
    found
}

/// The script a yarn settings file has every yarn command run
/// (`yarnPath: x`, `yarn-path "x"`); a relative one is beside the file,
/// which is in the home.
fn yarn_path(line: &str) -> Vec<String> {
    let Some((key, value)) = line.split_once([':', ' ', '\t']) else {
        return Vec::new();
    };
    let value = value.trim().trim_matches(['"', '\'']);
    if !matches!(key.trim_matches('"'), "yarnPath" | "yarn-path") || value.is_empty() {
        return Vec::new();
    }
    if value.starts_with(['/', '~', '$']) {
        vec![value.to_string()]
    } else {
        vec![format!("~/{}", value.trim_start_matches("./"))]
    }
}

/// What a package manager's or mise's configuration makes it run:
/// npm's shells, `git` and loaded scripts, yarn's `yarnPath`, cargo's
/// wrappers, linker, runner and credential provider, Go's `-toolexec` and
/// compilers, and mise's sourced files, hooks and task commands.
fn toolchain(name: &str, line: &str) -> Vec<String> {
    if matches!(name, ".yarnrc" | ".yarnrc.yml") {
        return yarn_path(line);
    }
    let Some((key, value)) = line.split_once('=') else {
        return Vec::new();
    };
    let key = key.trim().trim_matches('"');
    let runs = match name {
        "npmrc" | ".npmrc" if key.eq_ignore_ascii_case("node-options") => {
            return node_loaded(value);
        }
        "npmrc" | ".npmrc" => matches!(
            key,
            "script-shell" | "shell" | "git" | "onload-script" | "init-module"
        ),
        "env" if matches!(key, "CC" | "CXX") => true,
        "env" => {
            return value
                .split_whitespace()
                .filter_map(|word| word.trim_matches(['"', '\'']).strip_prefix("-toolexec="))
                .map(str::to_string)
                .collect();
        }
        "config.toml" | "config" | ".mise.toml" => matches!(
            key,
            "rustc-wrapper"
                | "rustc-workspace-wrapper"
                | "rustc"
                | "rustdoc"
                | "linker"
                | "runner"
                | "credential-provider"
                | "_.source"
                | "_.file"
                | "run"
                | "enter"
                | "leave"
                | "cd"
                | "preinstall"
                | "postinstall"
        ),
        _ => false,
    };
    let command = quoted_words(value);
    if runs && !command.is_empty() {
        vec![command]
    } else {
        Vec::new()
    }
}

/// The program a native-messaging manifest lets a browser extension start
/// (`"path": "/usr/lib/x/host"`).
fn native_host(line: &str) -> Vec<String> {
    // The manifest may be written on one line or on many.
    let Some((_, rest)) = line.split_once("\"path\"") else {
        return Vec::new();
    };
    let program = rest
        .trim_start()
        .strip_prefix(':')
        .and_then(|value| value.split('"').nth(1))
        .unwrap_or_default();
    if program.starts_with('/') {
        vec![program.to_string()]
    } else {
        Vec::new()
    }
}

/// The launchers a `mimeapps.list` names (`x-scheme-handler/https=a.desktop;`),
/// as the files they would be in the home: one that is there opens the
/// link or file instead of the system's.
fn handlers(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in text.lines() {
        let Some((_, value)) = line.trim().split_once('=') else {
            continue;
        };
        for launcher in value.split(';').map(str::trim) {
            let file = format!("~/.local/share/applications/{launcher}");
            if read::has_extension(launcher, "desktop")
                && !launcher.contains('/')
                && !found.contains(&file)
            {
                found.push(file);
            }
        }
    }
    found
}

/// The longest line of a start-up file looked through for programs, and
/// the most substitutions on it.
const MAX_STARTED_LINE: usize = 64 * 1024;
const MAX_SUBSTITUTIONS: usize = 16;

/// The commands of a crontab: after five time fields (or `@reboot` and
/// friends), and the user field the system crontabs (`/etc/crontab`,
/// `/etc/cron.d/`) have. Environment lines run nothing; a script (in
/// `cron.daily/` and the like) is reviewed as the file it is.
fn crontab(path: &str, text: &str) -> Vec<String> {
    let system = path == "etc/crontab" || path.starts_with("etc/cron.d/");
    // A script in `cron.daily` and the like is no table of jobs. A table
    // is one whatever its first line: `#` starts a comment in it, `#!` too.
    let table = system || path == "etc/anacrontab" || path.starts_with("var/spool/cron/");
    if text.starts_with("#!") && !table {
        return Vec::new();
    }
    let mut found = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        let time_fields = if words[0].starts_with('@') {
            1
        } else if words.len() > 5 && words[..5].iter().all(|field| is_time_field(field)) {
            5
        } else {
            // `NAME=value` or something cron would reject.
            continue;
        };
        let skip = time_fields + usize::from(system);
        if words.len() > skip {
            found.push(words[skip..].join(" "));
        }
    }
    found
}

fn is_time_field(field: &str) -> bool {
    field
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "*/,-".contains(character))
}

/// `Exec=`, `ExecStart=` and friends in units, hooks, D-Bus services and
/// desktop entries; and the `…Command=` keys of the login screen's and
/// pacman's configuration (`SessionCommand`, `XferCommand`) and greetd's
/// `command`.
fn key_value(line: &str) -> Vec<String> {
    let Some((key, value)) = line.split_once('=') else {
        return Vec::new();
    };
    let key = key.trim();
    // A file of `NAME=value` lines a unit reads into its environment; a
    // leading `-` only says it may be missing.
    if key == "EnvironmentFile" {
        let file = value.trim().trim_start_matches('-');
        return if file.is_empty() {
            Vec::new()
        } else {
            vec![file.to_string()]
        };
    }
    let command = key == "command" || (key.len() > 7 && key.ends_with("Command"));
    let runs = key == "Exec"
        || command
        || (key.starts_with("Exec") && key[4..].chars().all(|c| c.is_ascii_alphabetic()));
    if !runs {
        return Vec::new();
    }
    let value = value.trim();
    let value = if command {
        value.trim_matches('"')
    } else {
        value.trim_start_matches(['-', '@', ':', '+', '!'])
    };
    // Desktop field codes (`%u`, `%F`…) are filled in at launch.
    let value: Vec<&str> = value
        .split_whitespace()
        .filter(|word| !(word.len() == 2 && word.starts_with('%')))
        .collect();
    if value.is_empty() {
        Vec::new()
    } else {
        vec![value.join(" ")]
    }
}

/// `RUN+="…"`, `RUN{program}+="…"`, `PROGRAM="…"` and `IMPORT{program}="…"`.
fn udev(line: &str) -> Vec<String> {
    let mut found = Vec::new();
    for part in line.split(',') {
        let part = part.trim();
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        let key = key.trim_end_matches(['+', ':']);
        if matches!(key, "RUN" | "RUN{program}" | "PROGRAM" | "IMPORT{program}") {
            let value = value.trim().trim_matches('"');
            if !value.is_empty() {
                found.push(value.to_string());
            }
        }
    }
    found
}

/// `install <module> <command>` and `remove <module> <command>`.
fn modprobe(line: &str) -> Vec<String> {
    let mut words = line.split_whitespace();
    match (words.next(), words.next()) {
        (Some("install" | "remove"), Some(_module)) => {
            let rest: Vec<&str> = words.collect();
            if rest.is_empty() {
                Vec::new()
            } else {
                vec![rest.join(" ")]
            }
        }
        _ => Vec::new(),
    }
}

/// A PAM line's module, and `pam_exec.so`'s program.
fn pam(line: &str) -> Vec<String> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let Some(module) = words
        .iter()
        .position(|word| read::has_extension(word, "so"))
    else {
        return Vec::new();
    };
    // A bare module name is looked up in the module directory.
    let path = if words[module].contains('/') {
        words[module].to_string()
    } else {
        format!("/usr/lib/security/{}", words[module])
    };
    let mut found = vec![path];
    if words[module].ends_with("pam_exec.so")
        && let Some(program) = words[module + 1..]
            .iter()
            .find(|word| word.starts_with('/'))
    {
        found.push((*program).to_string());
    }
    found
}

/// An SSH client or server line that runs a command or loads a library:
/// its key (lower case) and what it runs or loads. The key and its value
/// are separated by blanks or by `=`. `Match … exec "command"` runs its
/// command to decide whether the block applies.
pub fn ssh(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    let end = line.find(|c: char| c.is_whitespace() || c == '=')?;
    let key = line[..end].to_ascii_lowercase();
    let value = line[end..]
        .trim_start_matches(|c: char| c.is_whitespace() || c == '=')
        .trim();
    let unquoted = |text: &str| text.trim_matches('"').to_string();
    let runs = match key.as_str() {
        "proxycommand"
        | "localcommand"
        | "knownhostscommand"
        | "authorizedkeyscommand"
        | "authorizedprincipalscommand"
        | "forcecommand"
        | "pkcs11provider"
        | "securitykeyprovider" => unquoted(value),
        // The first file: it is read as more of this configuration.
        "include" => unquoted(value.split_whitespace().next().unwrap_or_default()),
        // Files of the server that decide who may log in: a certificate
        // authority whose signature opens every account, the names a
        // certificate may log in under. One named per account (`%u`, `%h`)
        // is that account's file, looked at with its keys.
        "trustedusercakeys" | "authorizedprincipalsfile" | "authorizedkeysfile" | "revokedkeys" => {
            let file = unquoted(value.split_whitespace().next().unwrap_or_default());
            if !file.starts_with('/') || file.contains('%') {
                return None;
            }
            file
        }
        // `Subsystem name command`.
        "subsystem" => value
            .split_once(char::is_whitespace)
            .map(|(_, command)| unquoted(command.trim()))?,
        "match" => {
            let lower = value.to_ascii_lowercase();
            let at = lower
                .split_whitespace()
                .position(|word| word == "exec" || word == "!exec")?;
            let rest: Vec<&str> = value.split_whitespace().skip(at + 1).collect();
            // The command is one word, quoted when it holds blanks.
            let command = rest.join(" ");
            match command.strip_prefix('"') {
                Some(quoted) => quoted.split('"').next().unwrap_or_default().to_string(),
                None => rest.first().copied().unwrap_or_default().to_string(),
            }
        }
        _ => return None,
    };
    // What the programs do themselves runs nothing.
    (!runs.is_empty() && !matches!(runs.as_str(), "none" | "internal" | "internal-sftp"))
        .then_some((key, runs))
}

/// The files a unit reads into its environment (`EnvironmentFile=`), as
/// `commands` gives them. systemd reads such a file as `NAME=value` lines
/// and nothing else: it sets variables, and can run nothing.
pub fn environment_files(path: &str, text: &str) -> Vec<String> {
    text.replace("\\\n", " ")
        .lines()
        .filter_map(|line| line.trim().split_once('='))
        .filter(|(key, _)| key.trim() == "EnvironmentFile")
        .map(|(_, value)| value.trim().trim_start_matches('-'))
        .filter(|file| !file.is_empty())
        .map(|file| with_specifiers(path, file))
        .collect()
}

/// The files an SSH client or server file reads as more configuration or
/// as lists of keys and names, as `ssh` gives them: an `Include`, and the
/// server's key and principal files. They are read, not run: what any
/// other line names (a `ProxyCommand`, a `Match … exec`) is a program.
pub fn ssh_read_in(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .filter_map(ssh)
        .filter(|(key, _)| {
            matches!(
                key.as_str(),
                "include"
                    | "trustedusercakeys"
                    | "authorizedprincipalsfile"
                    | "authorizedkeysfile"
                    | "revokedkeys"
            )
        })
        .map(|(_, value)| value)
        .collect()
}

/// What a Hyprland `.conf` runs or loads: `exec` and its variants, the
/// command of a `bind… = MODS, key, exec, command`, a `plugin` (a library
/// loaded into the compositor) and a `source`d file (one with `*` or `?`
/// in its last part is a pattern, which `collect::follow` writes out to
/// the files it matches); and the commands hypridle and its like run when
/// the session goes idle, locks or sleeps.
fn hyprland_conf(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let (key, value) = line.trim().split_once('=')?;
            let (key, value) = (key.trim(), value.trim());
            let runs = match key {
                "exec" | "exec-once" | "execr" | "execr-once" | "exec-shutdown" | "plugin"
                | "on-timeout" | "on-resume" | "lock_cmd" | "unlock_cmd" | "on_lock_cmd"
                | "on_unlock_cmd" | "before_sleep_cmd" | "after_sleep_cmd" => {
                    Some(value.to_string())
                }
                "source" => Some(value.to_string()),
                key if key.starts_with("bind") => {
                    // `bindd` and its like carry a description before the
                    // dispatcher.
                    let described = key["bind".len()..].contains('d');
                    let mut parts = value.splitn(4 + usize::from(described), ',').map(str::trim);
                    let (_mods, _key) = (parts.next()?, parts.next()?);
                    if described {
                        parts.next()?;
                    }
                    let (dispatcher, argument) = (parts.next()?, parts.next());
                    matches!(dispatcher, "exec" | "execr")
                        .then(|| argument.unwrap_or_default().to_string())
                }
                _ => None,
            };
            runs.filter(|value| !value.is_empty())
        })
        .collect()
}

#[cfg(test)]
mod tests;
