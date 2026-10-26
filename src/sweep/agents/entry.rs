//! One entry of an agent's configuration and the item made of it: its text
//! is only what it starts, with secrets taken out, and its alerts are what
//! is seen in that alone.

use super::redact::redacted;
use super::{Found, MAX_ENTRIES};
use crate::autorun::Category;
use crate::rules::{RuleId, is_local_host};
use crate::sha256::Sha256;
use crate::sweep::collect::{self, Body, Item, NOT_ALL_FOLLOWED, Scope};
use crate::sweep::tier::Tier;
use crate::sweep::tools::LOADING_VARIABLES;

/// The API hosts of the providers an agent talks to: a base address
/// elsewhere sends what the agent works on to someone else. Exact hosts,
/// not the shared cloud domains, where anyone can run a server. Checked on
/// 2026-10-26 against the Claude Code docs for Amazon Bedrock, Google
/// Cloud's Agent Platform and Microsoft Foundry, and the hosts of the
/// Anthropic, `OpenAI` and Azure `OpenAI` APIs.
const PROVIDER_HOSTS: &[&str] = &[
    "api.anthropic.com",
    "api.openai.com",
    "aiplatform.googleapis.com",
    "aiplatform.eu.rep.googleapis.com",
    "aiplatform.us.rep.googleapis.com",
];

/// The provider hosts with one name of the user's choice in them (a region,
/// a resource), as the text before and after it.
const PROVIDER_PATTERNS: &[(&str, &str)] = &[
    ("bedrock-runtime.", ".amazonaws.com"),
    ("", "-aiplatform.googleapis.com"),
    ("", ".openai.azure.com"),
    ("", ".services.ai.azure.com"),
];

/// What one entry of an agent's configuration starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Launch {
    /// A command line, as a shell is given it.
    Command(String),
    /// A server or web hook reached over the network, by the scheme and
    /// host (with its port) of its address: the rest of an address may
    /// carry a token.
    Remote { scheme: String, host: String },
    /// A package the agent installs from npm and loads (`opencode-x@1.2`).
    Package(String),
    /// The variables an agent sets for itself and all it starts.
    Environment(Vec<Variable>),
}

/// One variable an agent sets. Its value is never read, but for an address
/// (`*_BASE_URL`, `*_PROXY`), of which the scheme and host are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Variable {
    pub(super) name: String,
    pub(super) address: Option<(String, String)>,
}

impl Variable {
    /// The variable `name` set to `value`. An address without a host
    /// (empty) gives none.
    pub(super) fn of(name: &str, value: &str) -> Self {
        let address = Self::is_address(name)
            .then(|| scheme_and_host(value))
            .filter(|(_, host)| !host.is_empty());
        Self {
            name: name.to_string(),
            address,
        }
    }

    /// The variable `name`, whose value is not read.
    pub(super) fn named(name: &str) -> Self {
        Self {
            name: name.to_string(),
            address: None,
        }
    }

    /// Whether the value of `name` is an address, of which the host is
    /// read.
    pub(super) fn is_address(name: &str) -> bool {
        let upper = name.to_ascii_uppercase();
        upper.ends_with("_BASE_URL") || upper.ends_with("_PROXY")
    }
}

/// One entry that starts something.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Entry {
    /// Where in its file it is (`hooks/PreToolUse/0/0`).
    pub(super) key: String,
    pub(super) launch: Launch,
    /// The names of the variables it is started with.
    pub(super) variables: Vec<String>,
}

impl Entry {
    pub(super) fn command(key: impl Into<String>, line: &str) -> Self {
        Self {
            key: key.into(),
            launch: Launch::Command(line.to_string()),
            variables: Vec::new(),
        }
    }
}

/// The entries of one file, and what in it is there and could not be read.
#[derive(Debug, Default)]
pub(super) struct Entries {
    pub(super) list: Vec<Entry>,
    /// Each as the rest of a sentence (`the command of mcpServers/x`).
    unread: Vec<String>,
}

impl Entries {
    pub(super) fn push(&mut self, entry: Entry) {
        self.list.push(entry);
    }

    /// Says that the `what` (a field, a table) of the entry at `key` is
    /// there and could not be read.
    pub(super) fn unread(&mut self, key: &str, what: &str) {
        self.unread.push(format!("the {what} of {key}"));
    }
}

/// Where the entries of one file were found, for their items.
pub(super) struct Source<'a> {
    /// The configuration file, relative to the root.
    pub(super) file: &'a str,
    /// What `${CLAUDE_PLUGIN_ROOT}` stands for in a plugin's entries,
    /// relative to the root.
    pub(super) plugin_root: Option<&'a str>,
    /// What is said of each item, here only (whose plugin or project it is).
    pub(super) note: Option<String>,
}

impl<'a> Source<'a> {
    pub(super) fn of(file: &'a str) -> Self {
        Self {
            file,
            plugin_root: None,
            note: None,
        }
    }
}

/// Makes items of `entries`, found in `source`, at most `MAX_ENTRIES`, and
/// says what could not be read.
pub(super) fn add(scope: &Scope<'_>, source: &Source<'_>, entries: Entries, found: &mut Found) {
    for unread in &entries.unread {
        found.unchecked(source.file, &format!("{unread} could not be read"));
    }
    if entries.list.len() > MAX_ENTRIES {
        found.unchecked(
            source.file,
            &format!("more than {MAX_ENTRIES} entries that start something"),
        );
    }
    for entry in entries.list.into_iter().take(MAX_ENTRIES) {
        found.items.push(item(scope, source, entry));
    }
}

/// The item of `entry`. Its text is what the entry starts:
///
/// - a command line with its secrets taken out (see `redact::redacted`);
/// - for a remote server, the scheme and host of its address;
/// - for an npm package, its name, without who it logs in as;
/// - for an agent's environment, the names of its variables, and the scheme
///   and host of those that are addresses;
///
/// and before it, on a comment line, the names of the variables it is
/// started with. What it runs, which is followed, is each reading of the
/// command line with a plugin's directory written in (see
/// `plugin_root_readings`); the text is the line as written, without its
/// secrets.
fn item(scope: &Scope<'_>, source: &Source<'_>, entry: Entry) -> Item {
    let Entry {
        key,
        launch,
        variables,
    } = entry;
    let path = format!("{}#{key}", source.file);
    let mut runs = Vec::new();
    let mut alerts = Vec::new();
    let mut notes: Vec<String> = source.note.iter().cloned().collect();
    let started = match launch {
        Launch::Command(line) => {
            // Followed with its secrets: a script passed as the value of a
            // secret-named flag is still found. The collector takes the
            // secrets out once it has been followed (see
            // `hide_secrets_in_runs`).
            runs.extend(plugin_root_readings(&line, source.plugin_root));
            if source.plugin_root.is_some() {
                notes.extend(plugin_root_not_followed(&line, &runs));
            }
            redacted(&line)
        }
        Launch::Remote { scheme, host } => {
            alerts.extend(remote_alert(&host));
            format!("{scheme}://{host}")
        }
        Launch::Package(package) => {
            let package = redacted(&package);
            if !is_pinned(&package) {
                alerts.push((
                    RuleId::RemoteCodeInstall,
                    format!(
                        "{package}: installed from npm and run with no version fixed, so whatever is published next runs"
                    ),
                ));
            }
            format!("npm package {package}")
        }
        Launch::Environment(set) => {
            alerts.extend(set.iter().flat_map(environment_alerts));
            environment_text(&set)
        }
    };
    let text = if variables.is_empty() {
        format!("{started}\n")
    } else {
        format!(
            "# started with these variables set (values not read): {}\n{started}\n",
            variables.join(" ")
        )
    };
    Item {
        file: None,
        origin: collect::origin(scope, &path),
        category: Category::Agent,
        tier: Tier::Unknown,
        sha256: Some(Sha256::digest(text.as_bytes())),
        body: Body::Text(text),
        runs,
        run_by: None,
        notes,
        alerts,
        path,
    }
}

/// The alert of a server or web hook at `host`, unless it is this machine.
fn remote_alert(host: &str) -> Option<(RuleId, String)> {
    (!is_local_host(without_port(host))).then(|| {
        (
            RuleId::RiskyConfiguration,
            format!(
                "talks to a remote server at {host}: the agent sends it what it works on, and acts on what it answers"
            ),
        )
    })
}

/// The text of an agent's environment: one variable a line.
fn environment_text(set: &[Variable]) -> String {
    let lines = set.iter().map(|variable| match &variable.address {
        Some((scheme, host)) => format!("{}={scheme}://{host}", variable.name),
        None => variable.name.clone(),
    });
    std::iter::once(
        "# variables the agent sets for itself and all it starts (values not read, but for the host of an address)"
            .to_string(),
    )
    .chain(lines)
    .collect::<Vec<_>>()
    .join("\n")
}

/// What a variable an agent sets for itself is worth an alert for: one that
/// changes what is loaded or run (the same list an editor's terminal is
/// held to), and a base address that is not its provider's.
fn environment_alerts(variable: &Variable) -> Vec<(RuleId, String)> {
    let mut alerts = Vec::new();
    let name = &variable.name;
    let upper = name.to_ascii_uppercase();
    // A proxy is honoured in either case (`https_proxy`); the loader's
    // variables only as written.
    let proxy = upper.ends_with("_PROXY") && LOADING_VARIABLES.contains(&upper.as_str());
    if LOADING_VARIABLES.contains(&name.as_str()) || proxy {
        alerts.push((
            RuleId::RiskyConfiguration,
            format!(
                "sets {name} for the agent and all it starts: it changes what they load, run or connect through"
            ),
        ));
    }
    if upper == "NODE_EXTRA_CA_CERTS" {
        alerts.push((
            RuleId::RiskyConfiguration,
            format!(
                "sets {name}: the agent trusts the certificates it names, so whoever holds one can read and change what it sends"
            ),
        ));
    }
    if let Some((_, host)) = &variable.address
        && upper.ends_with("_BASE_URL")
    {
        let bare = without_port(host);
        if !is_provider_host(bare) && !is_local_host(bare) {
            alerts.push((
                RuleId::RiskyConfiguration,
                format!(
                    "{name} sends what the agent works on to {host}, which is not its provider's"
                ),
            ));
        }
    }
    alerts
}

/// Whether `host` is one of `PROVIDER_HOSTS`, or of `PROVIDER_PATTERNS`
/// with one DNS name part (letters, digits, `-`) in the middle.
fn is_provider_host(host: &str) -> bool {
    let is_label = |name: &str| {
        !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    };
    PROVIDER_HOSTS.contains(&host)
        || PROVIDER_PATTERNS.iter().any(|(before, after)| {
            host.strip_prefix(before)
                .and_then(|rest| rest.strip_suffix(after))
                .is_some_and(is_label)
        })
}

/// `host` without a port (`localhost:3000`, `[::1]:8080`).
pub(super) fn without_port(host: &str) -> &str {
    host.rsplit_once(':')
        .filter(|(name, port)| {
            !port.is_empty()
                && port.chars().all(|c| c.is_ascii_digit())
                && (!name.contains(':') || name.ends_with(']'))
        })
        .map_or(host, |(name, _)| name)
}

/// Whether an npm package names the one version it installs
/// (`pkg@1.2.3`, `@scope/pkg@1.2.3-rc.1`): a whole `x.y.z`, not a tag or
/// a range (`@1`, `@1.x`, `@^1.2.0`).
pub(super) fn is_pinned(package: &str) -> bool {
    let Some((_, version)) = package.get(1..).and_then(|rest| rest.rsplit_once('@')) else {
        return false;
    };
    let (release, label) = version
        .split_once(['-', '+'])
        .map_or((version, ""), |(release, label)| (release, label));
    let numbers: Vec<&str> = release.split('.').collect();
    numbers.len() == 3
        && numbers
            .iter()
            .all(|number| !number.is_empty() && number.chars().all(|c| c.is_ascii_digit()))
        && label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
}

/// The address `url` as a server it reaches (see `scheme_and_host`).
pub(super) fn remote(url: &str) -> Launch {
    let (scheme, host) = scheme_and_host(url);
    Launch::Remote { scheme, host }
}

/// The scheme (a letter, then letters, digits, `+`, `.` or `-`) and host of
/// an address, in lower case; who it logs in as and the rest of it are left
/// out. A scheme that is no such word is left out too.
fn scheme_and_host(url: &str) -> (String, String) {
    let url = url.trim().to_ascii_lowercase();
    let (scheme, rest) = match url.split_once("://") {
        Some((scheme, rest)) if is_scheme(scheme) => (scheme, rest),
        Some((_, rest)) => ("", rest),
        None => ("", url.as_str()),
    };
    let authority = rest
        .split(|c: char| matches!(c, '/' | '?' | '#') || c.is_whitespace())
        .next()
        .unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or_default();
    (scheme.to_string(), host.to_string())
}

fn is_scheme(scheme: &str) -> bool {
    scheme.starts_with(|c: char| c.is_ascii_lowercase())
        && scheme
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '+' | '.' | '-'))
}

/// `program` and `args` as one shell line, each word quoted where a shell
/// would split it. Its secrets are taken out when it becomes an item's
/// text.
pub(super) fn command_line(program: &str, args: &[String]) -> String {
    std::iter::once(program)
        .chain(args.iter().map(String::as_str))
        .map(quoted)
        .collect::<Vec<_>>()
        .join(" ")
}

/// `word` as a shell reads it back as one word. `$` and braces stay as
/// they are: an agent fills in `${VAR}` in a server's arguments itself.
pub(super) fn quoted(word: &str) -> String {
    let plain = !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "@%+=:,./_~-${}".contains(c));
    if plain {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', r"'\''"))
    }
}

/// The variable a plugin's commands name its own directory by.
const PLUGIN_ROOT: &str = "CLAUDE_PLUGIN_ROOT";

/// The readings of `line` that are followed, with the plugin's directory
/// (`root`, relative to the root) written in for `${CLAUDE_PLUGIN_ROOT}`
/// and `$CLAUDE_PLUGIN_ROOT`: as Claude Code runs it, with the variable
/// set, and, when the line has a form with a default
/// (`${CLAUDE_PLUGIN_ROOT:-.}`, as trailofbits' modern-python writes its
/// hook), with each default taken. Only a default of path characters is
/// read either way; any other (`$(…)`, another variable, quotes) stays as
/// written in both, since its closing brace cannot be found without a
/// shell's parser. None of these is the text reviewed: the line itself may
/// unset or change the variable, so that text is the line as written.
pub(super) fn plugin_root_readings(line: &str, root: Option<&str>) -> Vec<String> {
    let Some(root) = root else {
        return vec![line.to_string()];
    };
    let directory = format!("/{root}");
    let set = with_plugin_root(line, &directory, Reading::Set);
    let unset = with_plugin_root(line, &directory, Reading::Unset);
    if unset == set {
        vec![set]
    } else {
        vec![set, unset]
    }
}

/// Why the readings of a plugin's command `line`, `runs`, may not reach
/// what it runs, as a note: the line changes the variable, so the
/// directory written in may not be its value (`CLAUDE_PLUGIN_ROOT=/x`,
/// `unset`, `export`, `env -u`); or a form was left as written and names
/// no file. Following the new value would take a shell's parser, and
/// `env -i` or an indirect `unset $v` changes it without naming it, so
/// the line is reviewed as written and the gap is said.
fn plugin_root_not_followed(line: &str, runs: &[String]) -> Option<String> {
    if changes_plugin_root(line) {
        Some(format!(
            "{NOT_ALL_FOLLOWED}a command that changes ${PLUGIN_ROOT}"
        ))
    } else if runs.iter().any(|run| names_braced_plugin_root(run)) {
        Some(format!(
            "{NOT_ALL_FOLLOWED}a form of ${{{PLUGIN_ROOT}}} that is neither plain nor a path default"
        ))
    } else {
        None
    }
}

/// Whether `line` names the plugin's variable other than to expand it, as
/// an assignment or an argument does: `CLAUDE_PLUGIN_ROOT` not after `$`
/// or `${`, and not part of a longer name.
fn changes_plugin_root(line: &str) -> bool {
    let is_name = |c: char| c.is_ascii_alphanumeric() || c == '_';
    line.match_indices(PLUGIN_ROOT).any(|(at, _)| {
        let before = &line[..at];
        let after = &line[at + PLUGIN_ROOT.len()..];
        !before.ends_with('$')
            && !before.ends_with("${")
            && !before.ends_with(is_name)
            && !after.starts_with(is_name)
    })
}

/// Whether `run` still holds `${CLAUDE_PLUGIN_ROOT…}`, which no reading
/// wrote in; `${CLAUDE_PLUGIN_ROOT_X}` is another variable.
fn names_braced_plugin_root(run: &str) -> bool {
    let open = format!("${{{PLUGIN_ROOT}");
    run.match_indices(&open).any(|(at, _)| {
        !run[at + open.len()..].starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// How a default form of the plugin's variable is read.
#[derive(Debug, Clone, Copy)]
enum Reading {
    /// Claude Code sets the variable for a plugin's commands.
    Set,
    /// The variable is unset, or empty for the `:` forms. The plain forms
    /// keep the directory: written in empty, they would add a reading of
    /// every plugin command, naming a script that is not there, and the
    /// text reviewed shows them as written anyway.
    Unset,
}

/// `line` with `directory` written in for `${CLAUDE_PLUGIN_ROOT}` and
/// `$CLAUDE_PLUGIN_ROOT`, and each default form read as `reading` says.
fn with_plugin_root(line: &str, directory: &str, reading: Reading) -> String {
    let line = with_braced_plugin_root(line, directory, reading);
    let bare = format!("${PLUGIN_ROOT}");
    let mut out = String::with_capacity(line.len());
    let mut rest = line.as_str();
    while let Some(at) = rest.find(&bare) {
        let after = &rest[at + bare.len()..];
        out.push_str(&rest[..at]);
        // `$CLAUDE_PLUGIN_ROOT_X` is another variable.
        if after.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_') {
            out.push_str(&bare);
        } else {
            out.push_str(directory);
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

/// `line` with `directory` written in for `${CLAUDE_PLUGIN_ROOT}`, and each
/// form whose default is a plain path (`:-`, `-`, `:=`, `=`) read as
/// `reading` says. `:+`, `:?` and any other default are left as written.
fn with_braced_plugin_root(line: &str, directory: &str, reading: Reading) -> String {
    let open = format!("${{{PLUGIN_ROOT}");
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(at) = rest.find(&open) {
        let after = &rest[at + open.len()..];
        out.push_str(&rest[..at]);
        // With the default held to path characters, the first `}` is the
        // one that closes the expansion: none can be quoted or escaped.
        let written = after.find('}').and_then(|end| {
            let word = &after[..end];
            let default = [":-", ":=", "-", "="]
                .iter()
                .find_map(|form| word.strip_prefix(form))
                .filter(|default| {
                    default
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "._/-".contains(c))
                });
            let written = match (word.is_empty(), default, reading) {
                (true, _, _) | (false, Some(_), Reading::Set) => directory,
                (false, Some(default), Reading::Unset) => default,
                (false, None, _) => return None,
            };
            Some((written, end))
        });
        if let Some((written, end)) = written {
            out.push_str(written);
            rest = &after[end + 1..];
        } else {
            out.push_str(&open);
            rest = after;
        }
    }
    out.push_str(rest);
    out
}
