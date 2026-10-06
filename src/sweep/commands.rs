//! What an auto-run file starts: the command lines it holds, and the
//! programs and scripts those name. Used to list what each item runs and to
//! judge the files it runs too (a trusted interpreter is judged by the
//! script it is given).

#[cfg(test)]
use std::path::Path;

use super::programs::{self, Argument, SCRIPT_SHELLS, ScriptArguments, is_script_shell};
use super::{lua, read};
use crate::autorun::Category;
use crate::paths::file_name;

/// A wrapper that runs the command after it: its name, its options that
/// take the next word as their value, and how many words of its own come
/// before the command (`timeout 5 prog`, `flock file prog`).
struct Wrapper {
    name: &'static str,
    value_options: &'static [&'static str],
    own_words: usize,
}

const fn wrapper(
    name: &'static str,
    value_options: &'static [&'static str],
    own_words: usize,
) -> Wrapper {
    Wrapper {
        name,
        value_options,
        own_words,
    }
}

const WRAPPERS: &[Wrapper] = &[
    wrapper("env", &["-u", "--unset", "-C", "--chdir"], 0),
    wrapper("uwsm-app", &["-t", "-a", "-u", "-s", "-p"], 0),
    wrapper("uwsm", &["-t", "-a", "-u", "-s", "-p"], 0),
    wrapper(
        "systemd-run",
        &[
            "-p",
            "--property",
            "-u",
            "--unit",
            "--uid",
            "--gid",
            "-E",
            "--setenv",
            "--slice",
            "--working-directory",
            "-M",
            "--machine",
            "-H",
            "--host",
            "--description",
        ],
        0,
    ),
    wrapper("setsid", &[], 0),
    wrapper("nohup", &[], 0),
    wrapper("exec", &["-a"], 0),
    wrapper(
        "sudo",
        &[
            "-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "-r", "-t",
        ],
        0,
    ),
    wrapper("doas", &["-u", "-C"], 0),
    wrapper("timeout", &["-s", "--signal", "-k", "--kill-after"], 1),
    wrapper("nice", &["-n", "--adjustment"], 0),
    wrapper("ionice", &["-c", "-n", "-p"], 0),
    wrapper("flock", &["-w", "--timeout", "-E"], 1),
    wrapper("chrt", &[], 1),
    wrapper("taskset", &[], 1),
    wrapper("stdbuf", &["-i", "-o", "-e"], 0),
];

/// Subcommands of `uwsm` that run the command after them.
const UWSM_RUNS: &[&str] = &["app", "start"];

/// Where a bare command name is looked for when the real `PATH`s say
/// nothing more (see `path::search`), relative to the root; `~` stands for
/// the home directory. The directories version managers put ahead of
/// `/usr/bin` come first, as they do on a `PATH`.
pub const SEARCH: &[&str] = &[
    "~/.local/bin",
    "~/.cargo/bin",
    "~/bin",
    "~/.local/share/mise/shims",
    "~/go/bin",
    "~/.bun/bin",
    "~/.deno/bin",
    "~/.local/share/pnpm",
    "~/.npm-global/bin",
    "~/.nix-profile/bin",
    "usr/local/sbin",
    "usr/local/bin",
    "usr/bin",
];

/// `SEARCH` with the home directory written out.
pub fn default_search(home: &str) -> Vec<String> {
    SEARCH
        .iter()
        .map(|directory| expand(home, directory).trim_start_matches('/').to_string())
        .collect()
}

/// Whether `path` (relative to the root) is the script the SSH server runs
/// at every login: `~/.ssh/rc` or `/etc/ssh/sshrc`. It is a shell script,
/// not configuration, whatever directory it sits in.
pub fn is_ssh_rc(path: &str) -> bool {
    path == "etc/ssh/sshrc" || path.ends_with("/.ssh/rc")
}

/// The shell a `#!` line (without the `#!`) runs, if it runs one: the
/// program itself, the one `env` is told to start (past its options, the
/// variables it sets or unsets, and inside the one word `-S` takes), or
/// the shell `busybox` is asked to be.
fn shebang_shell(line: &str) -> Option<&str> {
    fn named(word: &str) -> &str {
        file_name(word)
    }
    let mut words = line.split_whitespace().peekable();
    let mut name = named(words.next()?);
    if name == "env" {
        loop {
            let word = words.next()?;
            if matches!(word, "-u" | "--unset" | "-C" | "--chdir") {
                words.next();
            } else if !(word.starts_with('-') || word.contains('=')) {
                name = named(word);
                break;
            }
        }
    }
    if name == "busybox" {
        name = named(words.next()?);
    }
    is_script_shell(name).then_some(name)
}

/// Whether the file at `path` with content `text` is a shell script: its
/// first line names one of `SCRIPT_SHELLS` (also through `env` or
/// `busybox`, and after a byte-order mark), or it has no such line and its
/// name ends in one of theirs (`x.sh`). A script of another interpreter
/// (Python, Perl, Node, fish) is not read as one.
pub fn is_shell_script(path: &str, text: &str) -> bool {
    let first = text
        .trim_start_matches('\u{feff}')
        .lines()
        .next()
        .unwrap_or_default();
    if let Some(line) = first.strip_prefix("#!") {
        return shebang_shell(line).is_some();
    }
    let name = file_name(path);
    SCRIPT_SHELLS
        .iter()
        .any(|shell| read::has_extension(name, shell))
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

/// The start-up files zsh reads from the directory a `ZDOTDIR=` line names
/// instead of the home.
fn zdotdir(line: &str) -> Vec<String> {
    let line = line.strip_prefix("export ").unwrap_or(line);
    let Some(value) = line.strip_prefix("ZDOTDIR=") else {
        return Vec::new();
    };
    let directory = value
        .split([';', ' ', '\t'])
        .next()
        .unwrap_or_default()
        .trim_matches(['"', '\''])
        .trim_end_matches('/');
    if directory.is_empty() || directory.contains(['`', '(']) {
        return Vec::new();
    }
    [".zshenv", ".zprofile", ".zshrc", ".zlogin", ".zlogout"]
        .iter()
        .map(|file| format!("{directory}/{file}"))
        .collect()
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

/// Variables a shell start-up file sets to a path (`TOOLS=~/opt/tools`,
/// `export BIN="$HOME/bin"`), so `$TOOLS/run` is looked at as that path.
fn path_variables(text: &str) -> Vec<(String, String)> {
    let mut found: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim_matches(['"', '\'']);
        let is_name = name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        let is_path = ["/", "~/", "$HOME/", "${HOME}/"]
            .iter()
            .any(|start| value.starts_with(start));
        // No other variable in it: written out once, a path never grows
        // into more paths.
        let rest = value
            .strip_prefix("$HOME")
            .or_else(|| value.strip_prefix("${HOME}"))
            .unwrap_or(value);
        if is_name
            && name != "HOME"
            && is_path
            && !value.contains(char::is_whitespace)
            && !rest.contains(['$', '`'])
        {
            found.retain(|(known, _)| known != name);
            found.push((name.to_string(), value.to_string()));
            if found.len() > MAX_PATH_VARIABLES {
                found.remove(0);
            }
        }
    }
    found
}

/// The most path variables one start-up file keeps.
const MAX_PATH_VARIABLES: usize = 32;

/// The files a pattern (`~/.config/hypr/conf.d/*.conf`) names: `*` and `?`
/// in its last part only, matched against what `list` says the directory
/// holds, at most `MAX_GLOB` of them; and whether there were more.
pub fn glob_targets(
    home: &str,
    pattern: &str,
    list: &dyn Fn(&str) -> Vec<String>,
) -> (Vec<String>, bool) {
    let expanded = expand(home, pattern.trim());
    let Some(absolute) = expanded.strip_prefix('/') else {
        return (Vec::new(), false);
    };
    let (directory, last) = absolute.rsplit_once('/').unwrap_or(("", absolute));
    if directory.contains(['*', '?'])
        || !last.contains(['*', '?'])
        || absolute.contains(char::is_whitespace)
    {
        return (Vec::new(), false);
    }
    let mut names: Vec<String> = list(directory)
        .into_iter()
        .filter(|name| glob_match(last, name))
        .collect();
    names.sort();
    let more = names.len() > MAX_GLOB;
    (
        names
            .into_iter()
            .take(MAX_GLOB)
            .map(|name| format!("{directory}/{name}"))
            .collect(),
        more,
    )
}

/// The most files one pattern stands for.
pub const MAX_GLOB: usize = 1024;

/// Whether `name` matches `pattern` (`*` any run, `?` one character). A
/// name starting with `.` matches only a pattern that does, as in a shell.
fn glob_match(pattern: &str, name: &str) -> bool {
    if name.starts_with('.') && !pattern.starts_with('.') {
        return false;
    }
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    let (mut p, mut n) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == name[n]) {
            p += 1;
            n += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some((p, n));
            p += 1;
        } else if let Some((star_at, matched)) = star {
            p = star_at + 1;
            n = matched + 1;
            star = Some((star_at, matched + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|character| *character == '*')
}

/// The files a shell start-up file reads in (see `sourced`), with the
/// variables it sets to a path written out (`$OMARCHY_PATH/default/x`).
pub fn sourced_files(text: &str) -> Vec<String> {
    let variables = path_variables(text);
    text.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#') && line.len() <= MAX_STARTED_LINE)
        .flat_map(|line| sourced(&crate::rules::with_variables(line, &variables)))
        .collect()
}

/// The files a line of a shell start-up file reads in: `source file` and
/// `. file`, also behind a test (`[ -r file ] && . file`). The file runs as
/// part of the one that names it.
fn sourced(line: &str) -> Vec<String> {
    let words: Vec<&str> = line.split_whitespace().collect();
    words
        .windows(2)
        .enumerate()
        .filter(|(index, pair)| {
            matches!(pair[0], "source" | ".")
                && (*index == 0
                    || matches!(
                        words[index - 1],
                        "&&" | "||" | "then" | "do" | "else" | "{" | "("
                    )
                    || words[index - 1].ends_with(';'))
        })
        .map(|(_, pair)| pair[1].trim_matches(['"', '\'', ';']).to_string())
        .filter(|file| !file.is_empty())
        .collect()
}

/// `line` of a shell file without the patterns of its `case` branches
/// (`pat)`, `a|b)`, `(pat)`), which are matched against a word and run
/// nothing: `/*)` is no program, and neither are the directories it would
/// name as a pattern of files. `cases` carries, from line to line and for
/// each `case` that is open, whether a pattern comes next.
///
/// Only a pattern where the shell reads one is taken out (after `in` and
/// after `;;` of a `case` that starts a statement), so a line that merely
/// looks like one (`( ~/bin/x )` on its own, a subshell) stays a command.
fn without_case_patterns(line: &str, cases: &mut Vec<bool>) -> String {
    let mut kept = String::new();
    for (index, piece) in line.split(";;").enumerate() {
        if index > 0 {
            kept.push_str(" ; ");
            if let Some(next) = cases.last_mut() {
                *next = true;
            }
        }
        let mut rest = piece;
        loop {
            if cases.last() == Some(&true) {
                let branch = rest
                    .trim_start()
                    .trim_start_matches(['&', ';'])
                    .trim_start();
                if is_word_at(branch, "esac") {
                    cases.pop();
                    rest = &branch["esac".len()..];
                    continue;
                }
                // A comment after `;;` is not the next pattern.
                if !branch.is_empty() && !branch.starts_with('#') {
                    if let Some(end) = case_pattern_end(branch) {
                        rest = &branch[end..];
                    }
                    if let Some(next) = cases.last_mut() {
                        *next = false;
                    }
                }
            }
            // A `case` among this branch's commands (or the first one),
            // and where one ends.
            let opened = case_opening(rest);
            let closed = word_position(rest, "esac").filter(|_| !cases.is_empty());
            match (opened, closed) {
                (Some(after), closed) if closed.is_none_or(|closed| after < closed) => {
                    // What follows the patterns is a statement of its own.
                    kept.push_str(&rest[..after]);
                    kept.push_str(" ; ");
                    rest = &rest[after..];
                    cases.push(true);
                }
                (_, Some(closed)) => {
                    kept.push_str(&rest[..closed]);
                    rest = &rest[closed + "esac".len()..];
                    cases.pop();
                }
                _ => break,
            }
        }
        kept.push_str(rest);
    }
    kept
}

/// Whether `text` starts with the shell word `word`.
fn is_word_at(text: &str, word: &str) -> bool {
    text.strip_prefix(word).is_some_and(|rest| {
        rest.chars()
            .next()
            .is_none_or(|next| next.is_whitespace() || ";&|)".contains(next))
    })
}

/// Where the shell word `word` starts in `text`, as a word of its own.
fn word_position(text: &str, word: &str) -> Option<usize> {
    text.match_indices(word).map(|(at, _)| at).find(|at| {
        is_word_at(&text[*at..], word)
            && text[..*at]
                .chars()
                .next_back()
                .is_none_or(|before| before.is_whitespace() || ";&|(".contains(before))
    })
}

/// Where the patterns begin after a `case WORD in` in `text`. The `case`
/// must start a statement: the word in an `echo` opens nothing, and so
/// cannot make the lines after it read as patterns.
fn case_opening(text: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(at) = word_position(&text[from..], "case").map(|at| at + from) {
        from = at + "case".len();
        let before = text[..at].trim_end();
        let starts = before.is_empty()
            || before.ends_with([';', '&', '|', '{', '(', ')'])
            || ["then", "do", "else"].iter().any(|keyword| {
                before.ends_with(keyword)
                    && word_position(before, keyword) == Some(before.len() - keyword.len())
            });
        if !starts {
            continue;
        }
        if let Some(after) = word_position(&text[from..], "in") {
            return Some(from + after + "in".len());
        }
    }
    None
}

/// Where a `case` pattern at the start of `branch` ends (past its `)`):
/// alternatives with no blank in them, and no substitution or statement
/// before the bracket.
fn case_pattern_end(branch: &str) -> Option<usize> {
    let open = usize::from(branch.starts_with('('));
    let close = branch[open..].find(')')? + open;
    let pattern = &branch[open..close];
    let plain = !pattern.trim().is_empty()
        && !pattern.contains(['(', ';', '&', '`'])
        && pattern
            .split('|')
            .all(|alternative| !alternative.trim().contains(char::is_whitespace));
    plain.then_some(close + 1)
}

/// The longest line of a start-up file looked through for programs, and
/// the most substitutions on it.
const MAX_STARTED_LINE: usize = 64 * 1024;
const MAX_SUBSTITUTIONS: usize = 16;

/// The programs a line of a shell start-up file names by a path, as the
/// command of a statement (`~/bin/agent &`, `cd x && exec /opt/x/run`) or
/// inside a substitution (`eval "$(~/bin/tool init)"`). A bare name is not
/// looked up: it is a shell builtin or an ordinary command far more often
/// than not. A very long line is left to the review of the file's text.
fn started(line: &str) -> Vec<String> {
    if line.len() > MAX_STARTED_LINE {
        return Vec::new();
    }
    let is_path = |word: &str| {
        ["/", "~/", "$HOME/", "${HOME}/"]
            .iter()
            .any(|start| word.starts_with(start))
    };
    let clean = |word: &str| {
        word.trim_matches(['"', '\'', ';', '&', ')', '(', '`'])
            .to_string()
    };
    let mut found = Vec::new();
    // `>&` and `&>` are redirections, not the end of a statement.
    let statements = line
        .replace("&&", ";")
        .replace("||", ";")
        .replace(">&", "> ")
        .replace("&>", " >");
    for statement in statements.split([';', '|', '&']) {
        // Past what comes before a command: keywords, wrappers that run
        // it, assignments, a `case` pattern.
        // The words inside a substitution (`X=$(find /etc/x)`) are not the
        // statement's command: the substitution is read below. What comes
        // after it (`X=$(date) ~/bin/y`) still is.
        let mut depth = 0_usize;
        let mut ticked = false;
        let words: Vec<String> = split(statement)
            .into_iter()
            .filter(|word| {
                let opens = word.contains("$(");
                let inside = depth > 0 || ticked || opens || word.contains('`');
                // Only a substitution's own brackets count: a subshell
                // `( ~/bin/y )` hides nothing.
                if depth > 0 || opens {
                    depth = (depth + word.matches('(').count())
                        .saturating_sub(word.matches(')').count());
                }
                ticked ^= word.matches('`').count() % 2 == 1;
                !inside
            })
            .collect();
        let first = words.into_iter().find(|word| {
            !(matches!(
                word.as_str(),
                "exec"
                    | "nohup"
                    | "command"
                    | "setsid"
                    | "env"
                    | "nice"
                    | "time"
                    | "sudo"
                    | "doas"
                    | "if"
                    | "elif"
                    | "while"
                    | "until"
                    | "then"
                    | "do"
                    | "else"
                    | "!"
                    | "{"
                    | "("
            ) || (word.contains('=') && !is_path(word))
                // A `case` pattern (`x)`), not a subshell's last program.
                || (word.ends_with(')') && !is_path(word.trim_end_matches(')')))
                || word.starts_with(['>', '<'])
                || word.starts_with('-'))
        });
        if let Some(word) = first.map(|word| clean(&word)).filter(|word| is_path(word))
            && !found.contains(&word)
        {
            found.push(word);
        }
    }
    for opener in ["$(", "`"] {
        for (at, _) in line.match_indices(opener).take(MAX_SUBSTITUTIONS) {
            let word = line[at + opener.len()..]
                .split_whitespace()
                .next()
                .map(clean)
                .unwrap_or_default();
            if is_path(&word) && !found.contains(&word) {
                found.push(word);
            }
        }
    }
    found
}

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

/// The files `command` runs, relative to the root: its program (a bare
/// name is looked up in `SEARCH`) and, for an interpreter, the script it is
/// given. `home` is the home directory relative to the root. Only paths
/// that exist under `root` are returned.
#[cfg(test)]
pub fn targets(root: &Path, home: &str, command: &str) -> Vec<String> {
    targets_where(home, command, &|candidate| {
        std::fs::symlink_metadata(root.join(candidate)).is_ok()
    })
}

/// `targets`, with the caller saying which candidate paths are there.
#[cfg(test)]
pub fn targets_where(home: &str, command: &str, exists: &dyn Fn(&str) -> bool) -> Vec<String> {
    Lookup {
        home,
        search: &default_search(home),
        exists,
        capped: std::cell::Cell::new(false),
        shell_scripts: std::cell::RefCell::default(),
    }
    .targets(command)
}

/// How the files a command runs are looked for.
pub struct Lookup<'a> {
    /// The home directory relative to the root.
    pub home: &'a str,
    /// Where a bare command name is looked for, in the order a shell
    /// would, relative to the root.
    pub search: &'a [String],
    /// Which candidate paths are there: as root, a path only root can read
    /// is not looked for at a user's word.
    pub exists: &'a dyn Fn(&str) -> bool,
    /// Set when a line held more commands than are looked up.
    pub capped: std::cell::Cell<bool>,
    /// The files a shell was handed as its script (`sh /x/run`): that a
    /// shell runs a file is what says it is a shell script, whatever its
    /// name and first line.
    pub shell_scripts: std::cell::RefCell<Vec<String>>,
}

impl Lookup<'_> {
    /// The files `command` runs (see `targets`).
    pub fn targets(&self, command: &str) -> Vec<String> {
        targets_of(self, command)
    }
}

/// Steps past what comes before a command in `words`: leading assignments
/// and wrappers, with the wrappers' own options and words. Returns where
/// the command starts. A wrapper found anywhere but in `/usr/bin` (a
/// `sudo` in `~/.local/bin`) is what runs first, and is added to `found`.
fn past_wrappers(lookup: &Lookup<'_>, words: &mut Vec<String>, found: &mut Vec<String>) -> usize {
    let mut at = 0;
    while let Some(word) = words.get(at).cloned() {
        let name = file_name(&word);
        let assignment = word.contains('=') && !word.starts_with('/') && !word.starts_with('-');
        if assignment || word == "--" || word.starts_with('-') {
            at += 1;
        } else if let Some(wrapper) = WRAPPERS.iter().find(|wrapper| wrapper.name == name) {
            found.extend(
                locate(lookup, &word)
                    .into_iter()
                    .filter(|path| !path.starts_with("usr/bin/")),
            );
            at += 1;
            while let Some(option) = words.get(at).filter(|word| word.starts_with('-')).cloned() {
                at += 1;
                if option == "--" {
                    break;
                }
                // `env -S "program arguments"`: the command is in one word.
                if name == "env" && matches!(option.as_str(), "-S" | "--split-string") {
                    if let Some(inner) = words.get(at).cloned() {
                        words.splice(at..=at, split(&inner));
                    }
                    break;
                }
                if wrapper.value_options.contains(&option.as_str()) {
                    at += 1;
                }
            }
            at += wrapper.own_words;
            if name == "uwsm"
                && words
                    .get(at)
                    .is_some_and(|word| UWSM_RUNS.contains(&word.as_str()))
            {
                at += 1;
                // The subcommand's own options.
                while let Some(option) = words.get(at).filter(|word| word.starts_with('-')) {
                    let takes_value = wrapper.value_options.contains(&option.as_str());
                    let end = option == "--";
                    at += 1 + usize::from(takes_value);
                    if end {
                        break;
                    }
                }
            }
        } else {
            break;
        }
    }
    at
}

fn targets_of(lookup: &Lookup<'_>, command: &str) -> Vec<String> {
    let mut words = split(command);
    let mut found = Vec::new();
    let at = past_wrappers(lookup, &mut words, &mut found);
    let mut words = words.iter().skip(at).map(String::as_str).peekable();
    let Some(program) = words.next() else {
        return found;
    };
    found.extend(locate(lookup, program));
    let mut name = file_name(program);
    // `busybox sh script`: the shell is the applet it is asked to be.
    if name == "busybox"
        && let Some(applet) = words.next_if(|applet| is_script_shell(applet))
    {
        name = applet;
    }
    if programs::runs_a_script(name) {
        let shell = is_script_shell(name);
        let mut arguments = ScriptArguments::of(name);
        let mut values = 0;
        while let Some(word) = words.next() {
            // `sh -c "command line"` (also `-lc`, `-ic`) runs that line:
            // each command in it is found the same way, wrappers and
            // all. What `/usr/bin` holds is not listed again.
            // (Not `java -verbose:gc`: an option with a value of its own.)
            if word.starts_with('-')
                && !word.starts_with("--")
                && word.ends_with('c')
                && !word.contains([':', '='])
            {
                if let Some(code) = words.next() {
                    let (commands, more) = split_commands(code);
                    if more {
                        lookup.capped.set(true);
                    }
                    for command in commands {
                        for path in targets_of(lookup, &command) {
                            if !path.starts_with("usr/bin/") && !found.contains(&path) {
                                found.push(path);
                            }
                        }
                    }
                }
                break;
            }
            // `perl -e code` is given no script. For a shell `-e` is a
            // plain flag (`bash -e script`).
            if programs::takes_code(name, word) {
                break;
            }
            // `bash -o pipefail …`: for a shell the option's name is not
            // the script. For Python `-O` is a plain flag.
            if shell && matches!(word, "-o" | "-O" | "+o" | "+O") {
                words.next();
                continue;
            }
            // `python3 -W ignore script`: the word after an option that
            // may take a value is looked at, and so is the next.
            let argument = arguments.read(word);
            if argument == Argument::Option {
                continue;
            }
            if word.contains('/') {
                let script = locate(lookup, word);
                if shell {
                    lookup
                        .shell_scripts
                        .borrow_mut()
                        .extend(script.iter().cloned());
                }
                found.extend(script);
            }
            // A shell's options that take a value are the ones above.
            if shell || argument == Argument::Script {
                break;
            }
            // Each word after an option that takes a value is looked at;
            // a line with no end of them is not followed to its end.
            values += 1;
            if values >= MAX_OPTION_VALUES {
                lookup.capped.set(true);
                break;
            }
        }
    }
    found
}

/// The most values of options that are looked at on the way to a script.
const MAX_OPTION_VALUES: usize = 8;

/// The most commands of one line a shell runs that are looked up.
pub const MAX_INNER_COMMANDS: usize = 1024;

/// The commands of a line a shell runs (a crontab's, or `sh -c`'s): split
/// at `;`, `|`, `&` and line ends outside quotes.
#[cfg(test)]
pub fn inner_commands(code: &str) -> Vec<String> {
    split_commands(code).0
}

/// `inner_commands`: the first `MAX_INNER_COMMANDS` that are not empty,
/// and whether the line held more.
pub fn split_commands(code: &str) -> (Vec<String>, bool) {
    let mut commands = Vec::new();
    let mut command = String::new();
    let mut quote: Option<char> = None;
    let mut previous = ' ';
    let mut characters = code.chars().peekable();
    while let Some(character) = characters.next() {
        // `>&`, `&>` and `<&` are redirections, not the end of a command.
        let redirection =
            character == '&' && (matches!(previous, '>' | '<') || characters.peek() == Some(&'>'));
        previous = character;
        match quote {
            Some(open) if character == open => quote = None,
            None if matches!(character, '"' | '\'') => quote = Some(character),
            None if matches!(character, ';' | '|' | '&' | '\n') && !redirection => {
                if !command.trim().is_empty() {
                    commands.push(std::mem::take(&mut command));
                    if commands.len() == MAX_INNER_COMMANDS {
                        let more = characters.any(|rest| !rest.is_whitespace());
                        return (commands, more);
                    }
                }
                command.clear();
                continue;
            }
            _ => {}
        }
        command.push(character);
    }
    if !command.trim().is_empty() {
        commands.push(command);
    }
    (commands, false)
}

/// The paths `word` may name, relative to the root, that exist there. A
/// bare name gives every place on the search list it is found in, first
/// the one a shell would take: the `PATH` of whatever runs the command
/// may still differ from the ones the list was made from.
fn locate(lookup: &Lookup<'_>, word: &str) -> Vec<String> {
    let expanded = expand(lookup.home, word);
    let candidates: Vec<String> = if let Some(absolute) = expanded.strip_prefix('/') {
        vec![absolute.to_string()]
    } else if expanded.contains('/') {
        return Vec::new();
    } else {
        lookup
            .search
            .iter()
            .map(|directory| format!("{directory}/{expanded}"))
            .collect()
    };
    candidates
        .into_iter()
        .filter(|candidate| (lookup.exists)(candidate))
        .collect()
}

/// `~`, `$HOME`, `${HOME}` and systemd's `%h` as the home directory, and
/// the XDG directories where they are by default.
pub fn expand(home: &str, word: &str) -> String {
    for prefix in ["~/", "$HOME/", "${HOME}/", "%h/"] {
        if let Some(rest) = word.strip_prefix(prefix) {
            return format!("/{home}/{rest}");
        }
    }
    for (prefixes, directory) in [
        (["$XDG_CONFIG_HOME/", "${XDG_CONFIG_HOME}/"], ".config"),
        (["$XDG_DATA_HOME/", "${XDG_DATA_HOME}/"], ".local/share"),
    ] {
        for prefix in prefixes {
            if let Some(rest) = word.strip_prefix(prefix) {
                return format!("/{home}/{directory}/{rest}");
            }
        }
    }
    word.to_string()
}

/// Words of a command line, quotes removed.
fn split(command: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote: Option<char> = None;
    for character in command.chars() {
        match (quote, character) {
            (Some(open), _) if character == open => quote = None,
            (None, '"' | '\'') => quote = Some(character),
            (None, ' ' | '\t') => {
                if !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                }
            }
            _ => word.push(character),
        }
    }
    if !word.is_empty() {
        words.push(word);
    }
    words
}

#[cfg(test)]
mod tests;
