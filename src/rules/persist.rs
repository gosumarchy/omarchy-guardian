//! Persistence beyond the well-known paths: a directive that runs a
//! command on its own (a desktop entry, a unit, a bar module, a compositor
//! `exec`, a cron line, a udev rule) whose program lives where no installed
//! program does, a script that writes a file the session reads at every
//! start, and the commands that arrange for something to keep running.
//!
//! A directive that runs `/usr/bin/x`, `~/.local/bin/x` or a script beside
//! its own configuration is how every desktop is set up, and stays quiet.

use super::is_packaged_path;
use super::shell::{self, Command, program_name, unquoted_words};
use crate::paths::file_name;

/// Dot-files in the home that sessions have always run by name.
const SESSION_FILES: &[&str] = &[
    ".fehbg",
    ".xinitrc",
    ".xprofile",
    ".xsession",
    ".xsessionrc",
];

/// What `path` is below the home directory, when it is written as one of
/// the forms that name the home.
fn below_home(path: &str) -> Option<&str> {
    if let Some(rest) = ["~/", "$home/", "${home}/", "%h/", "/root/"]
        .iter()
        .find_map(|prefix| path.strip_prefix(prefix))
    {
        return Some(rest);
    }
    let rest = path.strip_prefix("/home/")?;
    rest.split_once('/').map(|(_, rest)| rest)
}

/// Whether `path` is somewhere a download or a dropped file lands and no
/// installed program lives: a temporary or cache directory, the runtime
/// directory, or a hidden file directly in the home.
pub fn is_drop_location(path: &str) -> bool {
    let path = path.trim_matches(['"', '\'']);
    if [
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
        "/run/user/",
        "$xdg_cache_home/",
        "${xdg_cache_home}/",
        "$xdg_runtime_dir/",
        "${xdg_runtime_dir}/",
        "%t/",
    ]
    .iter()
    .any(|prefix| path.starts_with(prefix))
    {
        return true;
    }
    below_home(path).is_some_and(|rest| {
        rest.starts_with(".cache/")
            || (rest.len() > 1
                && rest.starts_with('.')
                && !rest.contains('/')
                && !SESSION_FILES.contains(&rest))
    })
}

/// Interpreters whose first operand is the script that runs.
const INTERPRETERS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "fish", "python", "python3", "perl", "node", "ruby", "lua",
    "php",
];

/// Words before the program of a directive that only say how to start it.
const LAUNCHERS: &[&str] = &[
    "sudo",
    "doas",
    "env",
    "exec",
    "setsid",
    "nohup",
    "nice",
    "command",
    "uwsm",
    "app",
    "uwsm-app",
    "hyprctl",
    "dispatch",
    "systemd-run",
    "systemd-cat",
    "flock",
    "--",
];

/// The furthest an inline `sh -c '…'` is followed into another.
const MAX_INLINE: usize = 3;

/// Whether the command a directive runs is, or hands to an interpreter, a
/// file in a drop location. An inline `sh -c '…'` is read as its own
/// commands.
fn runs_from_drop(command: &str, depth: usize) -> bool {
    shell::split_top(command, &["&&", "||", ";", "|"])
        .iter()
        .any(|statement| {
            let words = unquoted_words(statement);
            let mut words = words.iter().map(String::as_str).peekable();
            // Hyprland's `[workspace 2 silent] cmd`.
            if words.peek().is_some_and(|word| word.starts_with('[')) {
                for word in words.by_ref() {
                    if word.ends_with(']') {
                        break;
                    }
                }
            }
            let Some(program) = words.find(|word| {
                !(LAUNCHERS.contains(word)
                    || word.starts_with('-')
                    || (word.contains('=') && !word.starts_with(['/', '.', '$', '~', '%'])))
            }) else {
                return false;
            };
            if is_drop_location(program) {
                return true;
            }
            if !INTERPRETERS.contains(&program_name(program)) {
                return false;
            }
            let mut inline = false;
            for word in words {
                if word.starts_with('-') {
                    inline = inline || (!word.starts_with("--") && word.ends_with('c'));
                } else if inline {
                    return depth < MAX_INLINE && runs_from_drop(word, depth + 1);
                } else {
                    return is_drop_location(word);
                }
            }
            false
        })
}

/// Keys that hold a command which runs on its own, in a desktop entry, a
/// unit, a Hyprland, hypridle or hyprlock configuration.
const COMMAND_KEYS: &[&str] = &[
    "exec",
    "tryexec",
    "execstart",
    "execstartpre",
    "execstartpost",
    "execstop",
    "execstoppost",
    "execreload",
    "execcondition",
    "exec-once",
    "execr",
    "execr-once",
    "exec-shutdown",
    "exec_once",
    "on-timeout",
    "on-resume",
    "lock_cmd",
    "unlock_cmd",
    "before_sleep_cmd",
    "after_sleep_cmd",
    "on_lock_cmd",
    "on_unlock_cmd",
    "onclick",
];

/// Keys of a bar module (waybar's JSON) that hold a command.
fn is_bar_key(key: &str) -> bool {
    matches!(key, "exec" | "exec-if" | "exec-on-event" | "on-update")
        || [
            "on-click",
            "on-scroll",
            "on-double-click",
            "on-triple-click",
        ]
        .iter()
        .any(|prefix| key.starts_with(prefix))
}

/// The quoted strings on a line, without their quotes.
fn strings(text: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find(['"', '\'']) {
        let quote = rest[open..].chars().next().unwrap_or('"');
        let inside = &rest[open + 1..];
        let Some(close) = inside.find(quote) else {
            break;
        };
        found.push(&inside[..close]);
        rest = &inside[close + 1..];
    }
    found
}

/// The five time fields of a cron line, or `@reboot` and its kin, and
/// after them the command.
fn cron_command(line: &str) -> Option<&str> {
    if let Some(rest) = line.strip_prefix('@') {
        let (when, command) = rest.split_once(char::is_whitespace)?;
        return matches!(
            when,
            "reboot"
                | "hourly"
                | "daily"
                | "weekly"
                | "monthly"
                | "yearly"
                | "annually"
                | "midnight"
        )
        .then_some(command);
    }
    let mut rest = line;
    for _ in 0..5 {
        let (field, after) = rest.split_once(char::is_whitespace)?;
        if field.is_empty()
            || !field
                .chars()
                .all(|c| c.is_ascii_digit() || matches!(c, '*' | '/' | ',' | '-'))
        {
            return None;
        }
        rest = after.trim_start();
    }
    Some(rest)
}

/// The commands a line sets up to run on their own, by any of the
/// directives named above.
fn directives(line: &str) -> Vec<String> {
    let line = line.trim();
    let mut found: Vec<String> = Vec::new();
    // udev: `…, RUN+="/tmp/x"`.
    if let Some(at) = line.find("run+=") {
        found.extend(strings(&line[at..]).first().map(ToString::to_string));
    }
    if let Some(command) = cron_command(line) {
        found.push(command.to_string());
        // `/etc/cron.d` names the user first.
        if let Some((_, after_user)) = command.split_once(char::is_whitespace) {
            found.push(after_user.to_string());
        }
    }
    // A bar module: `"on-click": "cmd"`.
    if let Some(rest) = line.strip_prefix('"')
        && let Some((key, value)) = rest.split_once('"')
        && let Some(value) = value.trim_start().strip_prefix(':')
        && is_bar_key(key)
    {
        let value = value.trim().trim_end_matches(',');
        found.push(
            value
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .unwrap_or(value)
                .replace("\\\"", "\""),
        );
    }
    // QML: `command: ["sh", "-c", "…"]`, `execDetached(["…"])`.
    for opener in ["command:", "execdetached("] {
        if let Some(at) = line.find(opener) {
            let parts = strings(&line[at + opener.len()..]);
            if !parts.is_empty() {
                found.push(
                    parts
                        .iter()
                        .map(|part| format!("'{part}'"))
                        .collect::<Vec<_>>()
                        .join(" "),
                );
            }
        }
    }
    // Hyprland's Lua: `exec_once("…")`, `exec_on_start = { "…", "…" }`.
    if ["exec_once", "exec_on_start", "exec_cmd("]
        .iter()
        .any(|name| line.contains(name))
    {
        found.extend(strings(line).iter().map(ToString::to_string));
    }
    let Some((key, value)) = line.split_once('=') else {
        return found;
    };
    let (key, value) = (key.trim(), value.trim());
    if COMMAND_KEYS.contains(&key) {
        // systemd's `-`, `@`, `+`, `!` and `:` before the program.
        found.push(
            value
                .trim_start_matches(['-', '@', '+', '!', ':'])
                .to_string(),
        );
    } else if key.starts_with("bind") && key.len() <= 8 {
        // `bind = SUPER, X, exec, cmd`: what follows the dispatcher.
        let mut fields = value.split(',');
        if fields.any(|field| field.trim() == "exec") {
            found.push(fields.collect::<Vec<_>>().join(","));
        }
    } else if key == "text"
        && let Some(rest) = value.strip_prefix("cmd[")
    {
        // hyprlock: `text = cmd[update:1000] command`.
        found.extend(rest.split_once(']').map(|(_, command)| command.to_string()));
    }
    found
}

/// Whether the line is a directive whose command lives in a drop location.
fn directive_runs_from_drop(line: &str) -> bool {
    if ![
        "/tmp/",
        "/shm/",
        ".cache/",
        "cache_home",
        "runtime_dir",
        "/run/user/",
        "%t/",
        "~/.",
        "home/.",
        "home}/.",
        "%h/.",
        "/root/.",
    ]
    .iter()
    .any(|mark| line.contains(mark))
    {
        return false;
    }
    directives(line)
        .iter()
        .any(|command| runs_from_drop(command, 0))
}

/// Commands whose name in `~/.local/bin` is run instead of the real one,
/// since that directory comes first on Omarchy's `PATH`.
const SHADOWED_COMMANDS: &[&str] = &[
    "sudo",
    "su",
    "doas",
    "ssh",
    "scp",
    "git",
    "gpg",
    "pacman",
    "yay",
    "paru",
    "makepkg",
    "systemctl",
    "curl",
    "wget",
];

/// Whether `path` is a file a session reads, or runs from, at every start
/// besides those `PERSISTENCE_PATHS` already names wherever they appear.
/// These are ordinary to mention, so they count only as what a command
/// writes.
fn is_startup_file(path: &str) -> bool {
    let name = file_name(path);
    let within = |directory: &str, extensions: &[&str]| {
        path.split_once(directory).is_some_and(|(_, rest)| {
            extensions.is_empty() || extensions.iter().any(|extension| rest.ends_with(extension))
        })
    };
    matches!(name, ".pam_environment" | ".zshenv")
        || path == "/etc/passwd"
        || within(".config/fish/conf.d/", &[])
        || within(".config/systemd/user.control/", &[])
        || within(".config/uwsm/env", &[])
        || within(".config/hypr/", &[".conf", ".lua"])
        // `~/.local/share/applications/*.desktop` is left out: it only
        // adds a menu entry, not an auto-run, and every ordinary app
        // installer writes one. Autostart (`~/.config/autostart`) is where
        // a desktop entry runs on its own, and is already a persistence
        // path.
        || (path
            .strip_suffix(name)
            .is_some_and(|directory| directory.ends_with(".local/bin/"))
            && SHADOWED_COMMANDS.contains(&name))
}

/// The files one command writes: what it redirects into, and what `tee`,
/// `install`, `cp`, `mv`, `ln` and `sed -i` are given to write.
fn written_files(part: &str) -> Vec<String> {
    let mut found = Vec::new();
    let words = unquoted_words(part);
    let mut rest = words.iter();
    while let Some(word) = rest.next() {
        if matches!(word.as_str(), ">" | ">>") {
            found.extend(rest.next().cloned());
        } else if let Some(name) = word.strip_prefix(">>").or_else(|| word.strip_prefix('>'))
            && !name.starts_with('&')
        {
            found.push(name.to_string());
        }
    }
    let Some(command) = shell::command(part) else {
        return found;
    };
    let operands: Vec<&str> = command
        .operands()
        .take_while(|word| !word.starts_with('>') && !word.starts_with("2>"))
        .collect();
    match command.program.as_str() {
        "tee" => found.extend(operands.iter().map(ToString::to_string)),
        "install" | "cp" | "mv" | "ln" => {
            if let Some((destination, sources)) = operands.split_last() {
                found.push((*destination).to_string());
                // Into a directory: under the name it had.
                if destination.ends_with('/') {
                    found.extend(
                        sources
                            .iter()
                            .map(|source| format!("{destination}{}", file_name(source))),
                    );
                }
            }
        }
        "sed"
            if command.has_short('i')
                || command.arguments.iter().any(|word| word == "--in-place") =>
        {
            found.extend(operands.iter().skip(1).map(ToString::to_string));
        }
        _ => {}
    }
    found
}

/// Whether the line writes a startup file. One a PKGBUILD puts into its
/// own package (`"$pkgdir"/…`) is a package file.
fn writes_startup_file(line: &str) -> bool {
    if ![
        ".pam_environment",
        ".zshenv",
        "fish/conf.d/",
        "user.control/",
        "uwsm/env",
        "/etc/passwd",
        ".config/hypr/",
        ".local/bin/",
    ]
    .iter()
    .any(|mark| line.contains(mark))
    {
        return false;
    }
    shell::statements(line).iter().any(|statement| {
        shell::pipeline(statement).iter().any(|part| {
            written_files(part)
                .iter()
                .any(|path| is_startup_file(path) && !is_packaged_path(path))
        })
    })
}

/// Settings of git that make it run a command, or fetch from another
/// address, in every repository of the user or the system.
fn is_git_takeover_key(key: &str) -> bool {
    matches!(
        key,
        "core.hookspath"
            | "core.fsmonitor"
            | "core.sshcommand"
            | "core.pager"
            | "credential.helper"
    ) || (key.starts_with("url.") && key.ends_with("insteadof"))
}

/// A command that arranges for something to keep running, or to run
/// later, outside any file the other rules name.
fn arranges_persistence(command: &Command) -> bool {
    let has = |word: &str| command.arguments.iter().any(|argument| argument == word);
    let starts = |prefix: &str| {
        command
            .arguments
            .iter()
            .any(|argument| argument.starts_with(prefix))
    };
    match command.program.as_str() {
        "loginctl" => has("enable-linger"),
        // `--on-active`/`--on-unit-active` are relative one-shots that do
        // not survive a reboot (reminders and delayed actions use them);
        // only the timers that fire on a calendar or at boot persist.
        "systemd-run" => {
            has("--user")
                && ["--on-calendar", "--on-boot", "--on-startup"]
                    .iter()
                    .any(|timer| starts(timer))
        }
        "at" => {
            has("-f")
                || command
                    .operands()
                    .next()
                    .is_some_and(|when| when.starts_with("now"))
        }
        "chattr" => command
            .arguments
            .iter()
            .any(|word| word.starts_with('+') && word.contains('i')),
        "git" => {
            let mut operands = command
                .operands()
                .skip_while(|word| *word != "config")
                .skip(1);
            (has("--global") || has("--system"))
                && ![
                    "--get",
                    "--get-all",
                    "--unset",
                    "--unset-all",
                    "--list",
                    "-l",
                ]
                .iter()
                .any(|read| has(read))
                && operands.next().is_some_and(is_git_takeover_key)
                && operands.next().is_some()
        }
        // A second account with the user id of root.
        "useradd" => {
            (has("-o") || has("--non-unique") || has("-ou"))
                && command.arguments.windows(2).any(|pair| {
                    matches!(pair[0].as_str(), "-u" | "--uid" | "-ou") && pair[1] == "0"
                })
        }
        _ => false,
    }
}

/// A shell start-up line that takes over a command or what every program
/// loads: an alias for `sudo` or `ssh`, an exported `LD_PRELOAD`, a `PATH`
/// that begins in a drop location.
fn takes_over_shell(line: &str) -> bool {
    let alias = ["sudo", "su", "doas", "ssh"].iter().any(|name| {
        line.split_once(&format!("alias {name}="))
            // `alias sudo='sudo '` only makes aliases expand after sudo.
            .is_some_and(|(_, value)| {
                let value = value.trim_start_matches(['\\', '"', '\'']);
                !value
                    .strip_prefix(name)
                    .is_some_and(|rest| rest.starts_with([' ', '\'', '"']) && rest.trim_matches([' ', '\'', '"', '\\', ';']).is_empty())
            })
    });
    let preload = line.contains("export ld_preload=");
    let path = line.split("export path=").skip(1).any(|value| {
        let first = value
            .trim_start_matches(['"', '\''])
            .split([':', '"', '\'', ' '])
            .next()
            .unwrap_or_default();
        // As a directory: `~/.bin` is a habit, `~/.cache/bin` is not.
        is_drop_location(&format!("{}/", first.trim_end_matches('/')))
    });
    alias || preload || path
}

/// Whether the line, lowercased and without what it only prints, sets up
/// persistence in one of the ways this module knows.
pub fn matches(line: &str) -> bool {
    if directive_runs_from_drop(line) || writes_startup_file(line) {
        return true;
    }
    if (line.contains("alias ") || line.contains("export ")) && takes_over_shell(line) {
        return true;
    }
    [
        "enable-linger",
        "systemd-run",
        "at ",
        "chattr",
        "git ",
        "useradd",
    ]
    .iter()
    .any(|word| line.contains(word))
        && shell::statements(line).iter().any(|statement| {
            shell::pipeline(statement).iter().any(|part| {
                shell::command(part).is_some_and(|command| arranges_persistence(&command))
            })
        })
}

#[cfg(test)]
mod tests {
    use super::{is_drop_location, matches};

    #[test]
    fn drop_locations_are_told_from_where_programs_live() {
        for path in [
            "/tmp/x",
            "/var/tmp/.x/run",
            "/dev/shm/x",
            "~/.cache/x/run.sh",
            "$home/.cache/x",
            "${xdg_cache_home}/x",
            "$xdg_runtime_dir/x",
            "/run/user/1000/x",
            "%t/x",
            "%h/.cache/x",
            "~/.x",
            "$home/.updater",
            "/home/someone/.cache/x",
            "/home/someone/.hidden",
        ] {
            assert!(is_drop_location(path), "{path}");
        }
        for path in [
            "/usr/bin/x",
            "/usr/lib/x/helper",
            "/opt/x/run",
            "~/.local/bin/x",
            "~/.config/waybar/scripts/x.sh",
            "$home/.local/share/omarchy/bin/omarchy-menu",
            "~/.cargo/bin/x",
            "./scripts/x.sh",
            "scripts/x.sh",
            "x",
            "~/bin/x",
            "~/.fehbg",
            "/home/someone/bin/x",
            "/tmpfiles/x",
        ] {
            assert!(!is_drop_location(path), "{path}");
        }
    }

    #[test]
    fn a_directive_running_from_a_drop_location_is_caught() {
        for line in [
            // Desktop entries and units.
            "exec=/tmp/x --daemon",
            "tryexec=/dev/shm/x",
            "exec=sh -c \"/tmp/.x/run\"",
            "exec=env foo=1 ~/.cache/x/run",
            "execstart=/var/tmp/x",
            "execstart=-/bin/bash %h/.cache/x/run.sh",
            "execstartpre=+/tmp/prepare",
            "execstoppost=%t/x",
            // Bar modules.
            "\"exec\": \"~/.cache/x/status.sh\",",
            "\"on-click\": \"bash /tmp/x.sh\",",
            "\"on-click-right\": \"sh -c '$xdg_runtime_dir/x'\"",
            "\"on-scroll-up\": \"$home/.x\",",
            "\"exec-if\": \"/tmp/x\",",
            // Hyprland, hypridle and hyprlock.
            "exec-once = ~/.cache/x",
            "exec = uwsm app -- /tmp/x",
            "exec-once = [workspace 2 silent] /dev/shm/x",
            "bind = super, x, exec, /tmp/x",
            "bindd = super, x, open thing, exec, uwsm-app -- ~/.cache/x/run",
            "on-timeout = /tmp/x",
            "lock_cmd = bash ~/.cache/lock.sh",
            "text = cmd[update:1000] /tmp/x",
            "hl.exec_once(\"/tmp/x --flag\")",
            // QML.
            "command: [\"sh\", \"-c\", \"/tmp/x\"]",
            "command: [\"/dev/shm/x\", \"--flag\"]",
            "quickshell.execdetached([\"bash\", \"/tmp/x.sh\"])",
            // cron and udev.
            "*/5 * * * * /tmp/x",
            "@reboot ~/.cache/x/run",
            "0 3 * * * root /var/tmp/x",
            "action==\"add\", subsystem==\"usb\", run+=\"/tmp/x\"",
        ] {
            assert!(matches(line), "{line}");
        }
        for line in [
            "exec=/usr/bin/x %u",
            "exec=x --flag",
            "tryexec=x",
            "exec=sh -c \"x --flag; y\"",
            "execstart=/usr/lib/x/daemon --foreground",
            "execstartpre=/usr/bin/mkdir -p /tmp/x",
            "execstartpre=-/usr/bin/rm -f /run/user/1000/x.sock",
            "execstart=/usr/bin/x --socket %t/x.sock",
            "environment=tmpdir=/tmp/x",
            "\"exec\": \"~/.config/waybar/scripts/weather.sh\",",
            "\"on-click\": \"omarchy-menu\",",
            "\"on-click\": \"$home/.local/share/omarchy/bin/omarchy-menu\",",
            "\"exec\": \"cat /tmp/x.status\",",
            "\"format\": \"/tmp/x\",",
            "exec-once = uwsm app -- waybar",
            "exec-once = ~/.local/bin/x",
            "exec-once = ~/.config/hypr/scripts/start.sh",
            "exec = hyprctl setcursor x 24",
            "bind = super, return, exec, uwsm app -- xdg-terminal-exec",
            "bind = super, s, exec, grim /tmp/shot.png",
            "bind = super, x, movetoworkspace, 2",
            "on-timeout = loginctl lock-session",
            "lock_cmd = pidof hyprlock || hyprlock",
            "command: [\"sh\", \"-c\", \"omarchy-menu\"]",
            "command: [\"cat\", \"/tmp/x.json\"]",
            "0 3 * * * /usr/bin/x --cron",
            "0 0 0 0 0 0",
            "run+=\"/usr/lib/udev/x %k\"",
            "path=/tmp/x",
            "cache = ~/.cache/x",
        ] {
            assert!(!matches(line), "{line}");
        }
    }

    #[test]
    fn writing_a_startup_file_is_caught_but_naming_one_is_not() {
        for line in [
            "echo 'export x=1' >> ~/.zshenv",
            "echo \"path default=/tmp/x\" > ~/.pam_environment",
            "cp x.fish ~/.config/fish/conf.d/",
            "tee ~/.config/uwsm/env >/dev/null",
            "echo 'exec-once = x' >> ~/.config/hypr/autostart.conf",
            "cat extra.conf >> \"$home/.config/hypr/hyprland.conf\"",
            "sed -i 's/a/b/' ~/.config/hypr/bindings.conf",
            "cp start.lua ~/.config/hypr/start.lua",
            "ln -sf \"$pwd/sudo\" ~/.local/bin/sudo",
            "install -m755 wrapper $home/.local/bin/git",
            "cp unit ~/.config/systemd/user.control/x.service",
            "echo 'x:x:0:0::/root:/bin/bash' >> /etc/passwd",
        ] {
            assert!(matches(line), "{line}");
        }
        for line in [
            "cat ~/.zshenv",
            "[ -f ~/.zshenv ] && source ~/.zshenv",
            "ls ~/.config/hypr/*.conf",
            "source = ~/.config/hypr/monitors.conf",
            "grep -q x ~/.config/hypr/hyprland.conf",
            "cp ~/.config/hypr/hyprland.conf backup/",
            // A menu entry is not an auto-run (see `is_startup_file`).
            "install -Dm644 x.desktop ~/.local/share/applications/x.desktop",
            "cp x.desktop ~/.local/share/applications/",
            "install -m755 tool ~/.local/bin/tool",
            "ln -s ~/.local/bin/git-helper /usr/local/bin/x",
            "install -Dm644 x.desktop \"$pkgdir\"/usr/share/applications/x.desktop",
            "install -Dm644 x.conf \"$pkgdir/etc/skel/.config/hypr/x.conf\"",
            "grep root /etc/passwd",
            "getent passwd \"$user\" > /dev/null",
        ] {
            assert!(!matches(line), "{line}");
        }
    }

    #[test]
    fn a_path_that_climbs_out_of_the_package_is_not_a_package_file() {
        for line in [
            "echo x >> \"$pkgdir/../../../.zshenv\"",
            "cp x \"$pkgdir/../../home/u/.config/hypr/a.conf\"",
            "install -m755 x \"${pkgdir}\"/../.local/bin/sudo",
            "cp x.fish $pkgdir/usr/../../../.config/fish/conf.d/",
            "echo x >> $pkgdir/.\\./.\\./.zshenv",
            "echo x >> \"$pkgdir\"/.\".\"/.\".\"/.zshenv",
        ] {
            assert!(matches(line), "{line}");
        }
        for line in [
            "echo x >> \"$pkgdir/etc/skel/.zshenv\"",
            "cp x.fish \"${pkgdir}\"/etc/skel/.config/fish/conf.d/",
        ] {
            assert!(!matches(line), "{line}");
        }
    }

    #[test]
    fn commands_that_arrange_to_keep_running_are_caught() {
        for line in [
            "loginctl enable-linger \"$user\"",
            "systemd-run --user --on-calendar=hourly /usr/bin/x",
            "systemd-run --user --on-boot=30 x",
            "echo x | at now + 1 minute",
            "at -f job.sh midnight",
            "sudo chattr +i /etc/x.conf",
            "git config --global core.hookspath /tmp/hooks",
            "git config --system core.sshcommand 'ssh -i /tmp/k'",
            "git config --global credential.helper store",
            "git config --global url.\"https://x.example/\".insteadof https://github.com/",
            "git config --global core.pager 'x | less'",
            "echo \"alias sudo='/tmp/x'\" >> \"$rc\"",
            "alias ssh='ssh -o proxycommand=x'",
            "export ld_preload=/usr/lib/x.so",
            "export path=/tmp/bin:$path",
            "export path=\"$home/.cache/bin:$path\"",
            "useradd -o -u 0 -g 0 backup",
        ] {
            assert!(matches(line), "{line}");
        }
        for line in [
            "loginctl show-user \"$user\"",
            "systemd-run --user --scope x",
            "systemd-run --on-active=30 x",
            "systemd-run --user --on-active=5m bash -c x",
            "systemd-run --user --collect --on-active=2s systemctl reboot",
            "look at now",
            "chattr -i /etc/x.conf",
            "git config --global user.name x",
            "git config --global init.defaultbranch main",
            "git config core.hookspath .githooks",
            "git config --global --get credential.helper",
            "git config --global --unset core.pager",
            "git -c core.pager=cat log",
            "alias sudo='sudo '",
            "alias ll='ls -l'",
            "alias sshfs-x='sshfs x:'",
            "export path=\"$home/.local/bin:$path\"",
            "export path=$path:/tmp/bin-is-last",
            "export ld_library_path=/opt/x/lib",
            "useradd -m -g wheel someone",
            "useradd -u 1001 someone",
        ] {
            assert!(!matches(line), "{line}");
        }
    }
}
