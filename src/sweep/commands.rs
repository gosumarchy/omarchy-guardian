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
    "sh", "bash", "dash", "zsh", "fish", "python", "python3", "perl", "ruby", "node", "lua",
    "luajit", "php",
];

/// Wrappers that run the command after them.
const WRAPPERS: &[&str] = &[
    "env",
    "uwsm-app",
    "uwsm",
    "systemd-run",
    "setsid",
    "nohup",
    "exec",
];

/// Where a bare command name is looked for, relative to the root; `~`
/// stands for the home directory.
const SEARCH: &[&str] = &["~/.local/bin", "usr/local/bin", "usr/bin"];

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
            Category::Ssh => ssh(line),
            _ => key_value(line),
        };
        found.extend(command);
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

/// SSH client and server keys that run a command.
fn ssh(line: &str) -> Vec<String> {
    let Some((key, value)) = line.split_once(char::is_whitespace) else {
        return Vec::new();
    };
    let key = key.trim_end_matches('=').to_ascii_lowercase();
    if matches!(
        key.as_str(),
        "proxycommand"
            | "localcommand"
            | "knownhostscommand"
            | "authorizedkeyscommand"
            | "forcecommand"
    ) {
        vec![value.trim().trim_start_matches('=').trim().to_string()]
    } else {
        Vec::new()
    }
}

/// `exec`, `exec-once`, `execr`, `execr-once` and `exec-shutdown` in a
/// Hyprland `.conf`.
fn hyprland_conf(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let (key, value) = line.trim().split_once('=')?;
            matches!(
                key.trim(),
                "exec" | "exec-once" | "execr" | "execr-once" | "exec-shutdown"
            )
            .then(|| value.trim().to_string())
            .filter(|value| !value.is_empty())
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
    let words = split(command);
    let mut words = words.iter().map(String::as_str).peekable();
    // Leading assignments and wrappers.
    while let Some(word) = words.peek() {
        let name = word.rsplit('/').next().unwrap_or(word);
        let assignment = word.contains('=') && !word.starts_with('/') && !word.starts_with('-');
        if assignment || WRAPPERS.contains(&name) || *word == "--" || word.starts_with('-') {
            words.next();
        } else {
            break;
        }
    }
    let Some(program) = words.next() else {
        return Vec::new();
    };
    let mut found = Vec::new();
    if let Some(path) = locate(home, program, exists) {
        found.push(path);
    }
    let name = program.rsplit('/').next().unwrap_or(program);
    let interpreter = INTERPRETERS.iter().any(|interpreter| {
        name == *interpreter
            || name
                .strip_prefix(interpreter)
                .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit() || c == '.'))
    });
    if interpreter {
        for word in words {
            if word == "-c" || word == "-e" {
                break;
            }
            if word.starts_with('-') {
                continue;
            }
            if let Some(path) = locate(home, word, exists).filter(|_| word.contains('/')) {
                found.push(path);
            }
            break;
        }
    }
    found
}

/// The path `word` names, relative to the root, if it exists there.
fn locate(home: &str, word: &str, exists: &dyn Fn(&str) -> bool) -> Option<String> {
    let expanded = expand(home, word);
    let candidates: Vec<String> = if let Some(absolute) = expanded.strip_prefix('/') {
        vec![absolute.to_string()]
    } else if expanded.contains('/') {
        return None;
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
    candidates.into_iter().find(|candidate| exists(candidate))
}

/// `~`, `$HOME`, `${HOME}` and systemd's `%h` as the home directory.
fn expand(home: &str, word: &str) -> String {
    for prefix in ["~/", "$HOME/", "${HOME}/", "%h/"] {
        if let Some(rest) = word.strip_prefix(prefix) {
            return format!("/{home}/{rest}");
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

    use super::{commands, targets};
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
}
