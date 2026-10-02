//! What an auto-run file starts: the command lines it holds, and the
//! programs and scripts those name. Used to list what each item runs and to
//! judge the files it runs too (a trusted interpreter is judged by the
//! script it is given).

#[cfg(test)]
use std::path::Path;

use super::{lua, read};
use crate::autorun::Category;

/// Programs that run the file they are given.
const INTERPRETERS: &[&str] = &[
    "sh", "bash", "dash", "zsh", "fish", "ksh", "python", "python3", "perl", "ruby", "node", "bun",
    "deno", "lua", "luajit", "php", "tclsh", "wish", "expect", "Rscript", "pwsh", "julia", "guile",
    "awk", "gawk", "mawk",
];

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

/// Where a bare command name is looked for, relative to the root; `~`
/// stands for the home directory.
const SEARCH: &[&str] = &[
    "~/.local/bin",
    "~/.cargo/bin",
    "~/bin",
    "usr/local/sbin",
    "usr/local/bin",
    "usr/bin",
];

/// The command lines `text` (a file of `category` named `name`) runs.
pub fn commands(category: Category, path: &str, text: &str) -> Vec<String> {
    let name = path.rsplit('/').next().unwrap_or(path);
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
    let mut found = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let command = match category {
            Category::Udev => udev(line),
            Category::Kernel => modprobe(line),
            Category::Pam => pam(line),
            Category::Ssh => ssh(line).map(|(_, value)| value).into_iter().collect(),
            Category::Shell => {
                let mut runs = sourced(line);
                runs.extend(started(line));
                runs
            }
            _ => key_value(line),
        };
        found.extend(command);
    }
    found
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

/// The longest line of a start-up file looked through for programs, and
/// the most substitutions on it.
const MAX_STARTED_LINE: usize = 4096;
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
        let first = split(statement).into_iter().find(|word| {
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
                || word.ends_with(')')
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
    if text.starts_with("#!") {
        return Vec::new();
    }
    let system = path == "etc/crontab" || path.starts_with("etc/cron.d/");
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

/// What a Hyprland `.conf` runs or loads: `exec` and its variants, the
/// command of a `bind… = MODS, key, exec, command`, a `plugin` (a library
/// loaded into the compositor) and a `source`d file (one with `*` in its
/// name is not looked up).
fn hyprland_conf(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let (key, value) = line.trim().split_once('=')?;
            let (key, value) = (key.trim(), value.trim());
            let runs = match key {
                "exec" | "exec-once" | "execr" | "execr-once" | "exec-shutdown" | "plugin" => {
                    Some(value.to_string())
                }
                "source" => (!value.contains('*')).then(|| value.to_string()),
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

/// `targets`, with the caller saying which candidate paths are there: as
/// root, a path only root can read is not looked for at a user's word.
pub fn targets_where(home: &str, command: &str, exists: &dyn Fn(&str) -> bool) -> Vec<String> {
    let mut words = split(command);
    let mut found = Vec::new();
    // Leading assignments and wrappers, with the wrappers' own options and
    // words: what runs is the command after them. A wrapper found anywhere
    // but in `/usr/bin` (a `sudo` in `~/.local/bin`) is what runs first.
    let mut at = 0;
    while let Some(word) = words.get(at).cloned() {
        let name = word.rsplit('/').next().unwrap_or(&word);
        let assignment = word.contains('=') && !word.starts_with('/') && !word.starts_with('-');
        if assignment || word == "--" || word.starts_with('-') {
            at += 1;
        } else if let Some(wrapper) = WRAPPERS.iter().find(|wrapper| wrapper.name == name) {
            found.extend(
                locate(home, &word, exists)
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
    let mut words = words.iter().skip(at).map(String::as_str);
    let Some(program) = words.next() else {
        return found;
    };
    found.extend(locate(home, program, exists));
    let name = program.rsplit('/').next().unwrap_or(program);
    let interpreter = INTERPRETERS.iter().any(|interpreter| {
        name == *interpreter
            || name
                .strip_prefix(interpreter)
                .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit() || c == '.'))
    });
    if interpreter {
        while let Some(word) = words.next() {
            // `sh -c "command line"` (also `-lc`, `-ic`) runs that line:
            // each command in it is found the same way, wrappers and
            // all. What `/usr/bin` holds is not listed again.
            if word.starts_with('-') && !word.starts_with("--") && word.ends_with('c') {
                if let Some(code) = words.next() {
                    for command in inner_commands(code) {
                        for path in targets_where(home, &command, exists) {
                            if !path.starts_with("usr/bin/") && !found.contains(&path) {
                                found.push(path);
                            }
                        }
                    }
                }
                break;
            }
            if word == "-e" {
                break;
            }
            // `bash -o pipefail …`: for a shell the option's name is not
            // the script. For Python `-O` is a plain flag.
            let shell = matches!(name, "sh" | "bash" | "dash" | "zsh");
            if shell && matches!(word, "-o" | "-O" | "+o" | "+O") {
                words.next();
                continue;
            }
            if word.starts_with('-') {
                continue;
            }
            if word.contains('/') {
                found.extend(locate(home, word, exists));
            }
            break;
        }
    }
    found
}

/// The most commands of one `sh -c` line that are looked up.
const MAX_INNER_COMMANDS: usize = 32;

/// The commands of a `sh -c` line: split at `;`, `|`, `&` and line ends
/// outside quotes, the first `MAX_INNER_COMMANDS` that are not empty.
fn inner_commands(code: &str) -> Vec<String> {
    let mut commands = Vec::new();
    let mut command = String::new();
    let mut quote: Option<char> = None;
    for character in code.chars() {
        match quote {
            Some(open) if character == open => quote = None,
            None if matches!(character, '"' | '\'') => quote = Some(character),
            None if matches!(character, ';' | '|' | '&' | '\n') => {
                if !command.trim().is_empty() {
                    commands.push(std::mem::take(&mut command));
                    if commands.len() == MAX_INNER_COMMANDS {
                        return commands;
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
    commands
}

/// The paths `word` may name, relative to the root, that exist there. A
/// bare name gives every place it is found in: which of them a shell
/// would take depends on a `PATH` that is not known here.
fn locate(home: &str, word: &str, exists: &dyn Fn(&str) -> bool) -> Vec<String> {
    let expanded = expand(home, word);
    let candidates: Vec<String> = if let Some(absolute) = expanded.strip_prefix('/') {
        vec![absolute.to_string()]
    } else if expanded.contains('/') {
        return Vec::new();
    } else {
        SEARCH
            .iter()
            .map(|directory| {
                format!(
                    "{}/{expanded}",
                    expand(home, directory).trim_start_matches('/')
                )
            })
            .collect()
    };
    candidates
        .into_iter()
        .filter(|candidate| exists(candidate))
        .collect()
}

/// `~`, `$HOME`, `${HOME}` and systemd's `%h` as the home directory, and
/// the XDG directories where they are by default.
fn expand(home: &str, word: &str) -> String {
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
mod tests {
    use std::fs;

    use super::{commands, targets, targets_where};
    use crate::autorun::Category;
    use crate::test_support::TempDir;

    #[test]
    fn commands_are_found_per_kind_of_file() {
        assert_eq!(
            commands(
                Category::Systemd,
                "x.service",
                "[Service]\nExecStartPre=-/usr/bin/true\nExecStart=/home/u/.cache/run.sh --now\nEnvironment=A=1\n"
            ),
            ["/usr/bin/true", "/home/u/.cache/run.sh --now"]
        );
        assert_eq!(
            commands(
                Category::Autostart,
                "x.desktop",
                "[Desktop Entry]\nExec=foo %u\nTryExec=foo\n"
            ),
            ["foo"]
        );
        assert_eq!(
            commands(
                Category::Udev,
                "99.rules",
                "ACTION==\"add\", RUN+=\"/usr/local/bin/x $kernel\"\n"
            ),
            ["/usr/local/bin/x $kernel"]
        );
        assert_eq!(
            commands(
                Category::Kernel,
                "x.conf",
                "install usb-storage /bin/sh -c 'curl x|sh'\noptions x y=1\n"
            ),
            ["/bin/sh -c 'curl x|sh'"]
        );
        assert_eq!(
            commands(
                Category::Pam,
                "x",
                "auth optional pam_exec.so quiet /usr/local/bin/log\n"
            ),
            ["/usr/lib/security/pam_exec.so", "/usr/local/bin/log"]
        );
        assert_eq!(
            commands(Category::Ssh, "config", "Host x\n  ProxyCommand nc %h %p\n"),
            ["nc %h %p"]
        );
        assert_eq!(
            commands(Category::Hyprland, "a.conf", "exec-once = waybar\n$x = 1\n"),
            ["waybar"]
        );
        // Crontabs: time fields, the system crontabs' user field, no
        // `Key=value` reading.
        assert_eq!(
            commands(
                Category::Cron,
                "var/spool/cron/u",
                "MAILTO=u\nExecStart=/etc/shadow\n*/5 * * * * /home/u/x.sh --now\n@reboot ~/y\n"
            ),
            ["/home/u/x.sh --now", "~/y"]
        );
        assert_eq!(
            commands(
                Category::Cron,
                "etc/cron.d/x",
                "0 3 * * mon root /usr/bin/z\n"
            ),
            ["/usr/bin/z"]
        );
        assert!(commands(Category::Cron, "etc/cron.daily/x", "#!/bin/sh\ncurl x\n").is_empty());
    }

    #[test]
    fn what_a_start_up_file_or_a_command_line_names_is_found() {
        // A program a shell start-up file runs by its path.
        assert_eq!(
            commands(
                Category::Shell,
                "home/u/.bashrc",
                "export X=1\n~/bin/agent --daemon &\nexec /opt/x/run\neval \"$($HOME/bin/tool init)\"\nls -l\n[ -r ~/.x ] && . ~/.x\ncd /tmp && FOO=1 ~/bin/second\ntrue & A=\"b c\" nice ~/bin/third\nif ! ~/bin/fourth; then :; fi\nls >& /dev/null\nls &>/tmp/log\n",
            ),
            [
                "~/bin/agent",
                "/opt/x/run",
                "$HOME/bin/tool",
                "~/.x",
                "~/bin/second",
                "~/bin/third",
                "~/bin/fourth",
            ]
        );
        // A line of nothing but substitutions is read once, not once per
        // substitution.
        let many = "$(/x1 $(/x2 ".repeat(100);
        assert_eq!(commands(Category::Shell, "home/u/.bashrc", &many).len(), 2);
        let long = "$(/x ".repeat(400_000);
        let started = std::time::Instant::now();
        assert!(commands(Category::Shell, "home/u/.bashrc", &long).is_empty());
        assert!(started.elapsed().as_secs() < 10);
        let exists = |candidate: &str| {
            [
                "home/u/.cargo/bin/tool",
                "home/u/.config/app/run.sh",
                "home/u/.local/bin/first",
                "home/u/.local/bin/second",
                "usr/bin/sh",
            ]
            .contains(&candidate)
        };
        // A bare name where cargo installs, and the XDG directories.
        assert_eq!(
            targets_where("home/u", "tool --serve", &exists),
            ["home/u/.cargo/bin/tool"]
        );
        assert_eq!(
            targets_where("home/u", "$XDG_CONFIG_HOME/app/run.sh", &exists),
            ["home/u/.config/app/run.sh"]
        );
        // Every command of a `-c` line, not only its first.
        assert_eq!(
            targets_where("home/u", "sh -c 'first && second; third | first'", &exists),
            [
                "usr/bin/sh",
                "home/u/.local/bin/first",
                "home/u/.local/bin/second"
            ]
        );
        // A separator inside quotes separates nothing, and empty commands
        // do not use up the limit.
        assert_eq!(
            targets_where("home/u", "sh -c 'x=\";\" second'", &exists),
            ["usr/bin/sh", "home/u/.local/bin/second"]
        );
        let padded = format!("sh -c '{} second'", ";".repeat(100));
        assert_eq!(
            targets_where("home/u", &padded, &exists),
            ["usr/bin/sh", "home/u/.local/bin/second"]
        );
    }

    #[test]
    fn targets_resolve_programs_and_the_scripts_interpreters_run() {
        let dir = TempDir::new("sweep-targets");
        let root = dir.path();
        for path in [
            "usr/bin/bash",
            "usr/bin/waybar",
            "home/u/.local/bin/sudo",
            "home/u/.cache/x.sh",
        ] {
            fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
            fs::write(root.join(path), "").unwrap();
        }
        assert_eq!(targets(root, "home/u", "waybar"), ["usr/bin/waybar"]);
        assert_eq!(
            targets(root, "home/u", "uwsm-app -- waybar --log"),
            ["usr/bin/waybar"]
        );
        assert_eq!(
            targets(root, "home/u", "/usr/bin/bash -l ~/.cache/x.sh"),
            ["usr/bin/bash", "home/u/.cache/x.sh"]
        );
        assert_eq!(targets(root, "home/u", "bash -c 'x'"), ["usr/bin/bash"]);
        // A name in ~/.local/bin is found before /usr/bin.
        assert_eq!(
            targets(root, "home/u", "sudo x"),
            ["home/u/.local/bin/sudo"]
        );
        assert_eq!(
            targets(root, "home/u", "A=1 %h/.cache/x.sh"),
            ["home/u/.cache/x.sh"]
        );
        assert!(targets(root, "home/u", "missing").is_empty());
    }

    #[test]
    fn configuration_commands_are_found_and_logrotate_is_no_crontab() {
        assert_eq!(
            commands(
                Category::Autostart,
                "etc/sddm.conf.d/x.conf",
                "[X11]\nSessionCommand=/usr/share/sddm/scripts/Xsession\nSessionDir=/usr/share/xsessions\n"
            ),
            ["/usr/share/sddm/scripts/Xsession"]
        );
        assert_eq!(
            commands(
                Category::PacmanHook,
                "etc/pacman.conf",
                "#XferCommand = /usr/bin/curl -L -C - -f -o %o %u\nXferCommand = /usr/local/bin/fetch %u\nHookDir = /etc/pacman.d/hooks/\n"
            ),
            ["/usr/local/bin/fetch"]
        );
        assert_eq!(
            commands(
                Category::Autostart,
                "etc/greetd/config.toml",
                "[default_session]\ncommand = \"tuigreet --cmd Hyprland\"\n"
            ),
            ["tuigreet --cmd Hyprland"]
        );
        assert!(
            commands(
                Category::Cron,
                "etc/logrotate.d/x",
                "/var/log/x {\n  compress delaycompress missingok notifempty copytruncate sharedscripts\n}\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn what_runs_is_found_past_wrappers_and_in_files_that_are_read_in() {
        let dir = TempDir::new("sweep-wrappers");
        let root = dir.path();
        for path in [
            "usr/bin/bash",
            "usr/bin/sudo",
            "usr/bin/waybar",
            "home/u/.cache/x.sh",
            "home/u/.local/bin/timeout",
        ] {
            fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
            fs::write(root.join(path), "").unwrap();
        }
        let payload = ["home/u/.cache/x.sh"];
        for command in [
            "uwsm app -- ~/.cache/x.sh",
            "sudo -u nobody ~/.cache/x.sh --flag",
            "systemd-run --user --unit x -p Restart=no ~/.cache/x.sh",
            "env -u DISPLAY A=1 ~/.cache/x.sh",
            "env -S \"~/.cache/x.sh --flag\"",
            "nice -n 5 ionice -c 3 ~/.cache/x.sh",
            "flock /tmp/lock ~/.cache/x.sh",
            "setsid nohup ~/.cache/x.sh",
        ] {
            assert_eq!(targets(root, "home/u", command), payload, "{command}");
        }
        // A wrapper that is not the system's own is what runs first.
        assert_eq!(
            targets(root, "home/u", "timeout 5 ~/.cache/x.sh"),
            ["home/u/.local/bin/timeout", "home/u/.cache/x.sh"]
        );
        // The program a shell is handed as its command line.
        for command in [
            "bash -c '~/.cache/x.sh --now'",
            "bash -lc 'nohup ~/.cache/x.sh'",
            "bash -c 'A=1 sudo ~/.cache/x.sh'",
            "bash -o pipefail -c '~/.cache/x.sh'",
        ] {
            assert_eq!(
                targets(root, "home/u", command),
                ["usr/bin/bash", "home/u/.cache/x.sh"],
                "{command}"
            );
        }
        assert_eq!(
            targets(root, "home/u", "uwsm app -s b -- ~/.cache/x.sh"),
            payload
        );
        // `-O` is a plain flag there: the script is what follows.
        fs::write(root.join("usr/bin/python3"), "").unwrap();
        assert_eq!(
            targets(root, "home/u", "python3 -O ~/.cache/x.sh"),
            ["usr/bin/python3", "home/u/.cache/x.sh"]
        );
        assert_eq!(
            targets(root, "home/u", "bash -c 'echo hi'"),
            ["usr/bin/bash"]
        );

        // Files a shell start-up file reads in.
        assert_eq!(
            commands(
                Category::Shell,
                "home/u/.bashrc",
                "source ~/.cache/x.sh\n[ -r /etc/x ] && . /etc/x\n# source /no\necho source of truth\nexport A=1\ntrue; . /etc/y\necho . done\n"
            ),
            ["~/.cache/x.sh", "/etc/x", "/etc/y"]
        );
        // What a unit reads into its environment.
        assert_eq!(
            commands(
                Category::Systemd,
                "etc/systemd/system/x.service",
                "[Service]\nEnvironmentFile=-/etc/x.env\nExecStart=/usr/bin/waybar\n"
            ),
            ["/etc/x.env", "/usr/bin/waybar"]
        );
        // Hyprland: binds, plugins and files it is told to read.
        assert_eq!(
            commands(
                Category::Hyprland,
                "home/u/.config/hypr/hyprland.conf",
                "exec-once = waybar\nbind = SUPER, Return, exec, ~/.cache/x.sh\nbindl = , XF86AudioMute, exec, wpctl set-mute\nbind = SUPER, Q, killactive\nbindd = SUPER, T, Open a terminal, exec, uwsm-app -- foot\nplugin = /tmp/evil.so\nsource = ~/.config/hypr/extra.txt\nsource = ~/.config/hypr/conf.d/*\n"
            ),
            [
                "waybar",
                "~/.cache/x.sh",
                "wpctl set-mute",
                "uwsm-app -- foot",
                "/tmp/evil.so",
                "~/.config/hypr/extra.txt"
            ]
        );
        // SSH: `=` or blanks, commands and libraries.
        for (line, runs) in [
            ("ProxyCommand=/tmp/x %h", Some("/tmp/x %h")),
            ("proxycommand   /tmp/x", Some("/tmp/x")),
            ("ProxyCommand none", None),
            (
                "Subsystem sftp /usr/lib/ssh/sftp-server",
                Some("/usr/lib/ssh/sftp-server"),
            ),
            ("Match user git exec \"/tmp/y %h\"", Some("/tmp/y %h")),
            ("Match host x", None),
            ("SecurityKeyProvider /tmp/sk.so", Some("/tmp/sk.so")),
            ("ProxyJump bastion", None),
            ("Subsystem sftp internal-sftp", None),
            ("SecurityKeyProvider internal", None),
            (
                "Include ~/.orbstack/ssh/config",
                Some("~/.orbstack/ssh/config"),
            ),
        ] {
            assert_eq!(
                super::ssh(line).map(|(_, value)| value).as_deref(),
                runs,
                "{line}"
            );
        }
    }
}
