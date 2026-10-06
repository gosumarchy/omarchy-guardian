//! Local, line-oriented heuristics.
//!
//! Every rule is a `RuleId` variant with a `Matcher`, so adding a rule without
//! deciding how it matches is a compile error rather than a silent miss.

use crate::report::Severity;

pub mod addressed;
mod destructive;
pub mod encoded;
pub mod exfil;
pub mod fetch;
pub mod flow;
pub mod hidden;
pub mod hosts;
mod matchers;
mod net;
mod paths;
pub mod persist;
mod run;
pub mod shell;

use destructive::is_destructive_operation;
use matchers::{
    CREDENTIAL_FILES, disables_protection, disables_tls_verification, is_crypto_mining,
    is_download_piped_to_shell, is_encoded_command_execution, is_privilege_escalation,
    is_remote_shell, looks_like_credential_exfiltration, pipes_into_shell, references_credential,
    removes_traces,
};
pub use matchers::{continues, is_sandbox_helper};
pub use net::{
    Scheme, declares_lookalike_host, extract_network_destinations, host_concerns, is_ip_host,
    is_local_host,
};
pub use paths::{is_documentation, is_executable_or_runtime_config, is_sensitive_path};
use paths::{is_packaged_path, is_persistence};
use run::as_file;
pub use run::{
    command_variables, fetched_files, run_globs, run_targets, runs_file, with_variables,
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

fn contains_any(haystack: &str, patterns: &[&str]) -> bool {
    patterns
        .iter()
        .any(|pattern| contains_pattern(haystack, pattern))
}

/// Programs that fetch from the network.
const FETCHERS: &[&str] = &["curl", "wget", "aria2c"];

#[cfg(test)]
mod tests;
