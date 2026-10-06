//! What the reviewer CLI would load on this machine before it reads a
//! request: settings files, hooks and managed settings.

use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::json::Json;
use crate::tools::Reviewer;

use super::REMOVED_VARIABLES;

/// Variables that decide where the request goes, which configuration the
/// reviewer reads, or which certificates it trusts. People use them for
/// proxies, Bedrock and Vertex, so they are kept, and the report names the
/// ones that were set: a review sent somewhere else is then not silent.
pub(super) const NAMED_VARIABLES: &[&str] = &[
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_BEDROCK_BASE_URL",
    "ANTHROPIC_VERTEX_BASE_URL",
    "CLAUDE_CONFIG_DIR",
    "OPENCODE_CONFIG",
    "OPENCODE_CONFIG_DIR",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NODE_EXTRA_CA_CERTS",
    "SSL_CERT_FILE",
];

/// The largest system-wide settings file read to see what it sets, and the
/// most files read from a settings directory.
const MAX_SETTINGS_BYTES: u64 = 1024 * 1024;
const MAX_SETTINGS_FILES: usize = 64;

/// Top-level keys of Claude Code's managed settings that send the request
/// elsewhere or run a command during the review: a key helper, environment
/// for the CLI (a base URL, a proxy), hooks, credential helpers, and
/// plugins, which bring hooks of their own.
const CLAUDE_SETTINGS_KEYS: &[&str] = &[
    "apiKeyHelper",
    "env",
    "hooks",
    "awsAuthRefresh",
    "awsCredentialExport",
    "gcpAuthRefresh",
    "otelHeadersHelper",
    "enabledPlugins",
];

/// The same for OpenCode's managed config, which is merged over the config
/// Guardian passes: providers (a `baseURL`), plugins, MCP servers, and
/// anything that would give the review agent its tools back.
const OPENCODE_SETTINGS_KEYS: &[&str] = &[
    "provider",
    "plugin",
    "mcp",
    "permission",
    "tools",
    "agent",
    "mode",
    "instructions",
    "command",
    "experimental",
];

/// What a reviewer run is exposed to besides the request: lines for the
/// report, and for a root transaction a reason not to run it at all.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Exposure {
    pub(crate) notes: Vec<String>,
    /// Set only for the pacman classes: the review is then unavailable.
    pub(crate) refusal: Option<String>,
}

/// Looks at what `reviewer` will take from Guardian's environment and from
/// the system-wide settings no flag switches off (Claude Code's managed
/// settings still apply under `--setting-sources ""`, and OpenCode merges
/// `/etc/opencode` over the config it is given). The variables are named,
/// never shown. With `privileged` (the pacman classes), settings that set
/// an endpoint, a key helper, environment, hooks or plugins make the review
/// unavailable: Guardian cannot tell a company's policy file from one a
/// package left there, and a root transaction is not judged through either.
pub(crate) fn exposure(reviewer: Reviewer, privileged: bool) -> Exposure {
    exposure_in(
        reviewer,
        privileged,
        &|name| env::var_os(name).is_some_and(|value| !value.is_empty()),
        Path::new("/etc"),
    )
}

pub(super) fn exposure_in(
    reviewer: Reviewer,
    privileged: bool,
    is_set: &dyn Fn(&str) -> bool,
    etc: &Path,
) -> Exposure {
    let mut exposure = Exposure::default();
    let set = |names: &'static [&'static str]| -> Vec<&'static str> {
        names.iter().copied().filter(|name| is_set(name)).collect()
    };
    let kept = set(NAMED_VARIABLES);
    if !kept.is_empty() {
        exposure.notes.push(format!(
            "the reviewer ran with: {} (set in Guardian's environment; they decide where the review is sent and what the reviewer trusts)",
            kept.join(", ")
        ));
    }
    let removed = set(REMOVED_VARIABLES);
    if !removed.is_empty() {
        exposure.notes.push(format!(
            "removed from the reviewer's environment: {}",
            removed.join(", ")
        ));
    }

    let mut risky: Vec<String> = Vec::new();
    for path in managed_settings(reviewer, etc) {
        exposure.notes.push(format!(
            "the reviewer loads system-wide settings from {}",
            path.display()
        ));
        match read_settings(&path).map(|settings| risky_settings(reviewer, &settings)) {
            Some(keys) if keys.is_empty() => {}
            Some(keys) => risky.push(format!("{} sets {}", path.display(), keys.join(", "))),
            None => risky.push(format!(
                "{} cannot be read as JSON, so what it sets is not known",
                path.display()
            )),
        }
    }
    if privileged && !risky.is_empty() {
        exposure.refusal = Some(format!(
            "the reviewer's system-wide settings could send the review elsewhere or run commands during it ({}); a root transaction is not reviewed through them",
            risky.join("; ")
        ));
    }
    exposure
}

/// The system-wide settings files `reviewer` reads that exist under `etc`.
fn managed_settings(reviewer: Reviewer, etc: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    match reviewer {
        Reviewer::ClaudeCode => {
            let directory = etc.join("claude-code");
            files.push(directory.join("managed-settings.json"));
            let mut drop_ins: Vec<PathBuf> = fs::read_dir(directory.join("managed-settings.d"))
                .into_iter()
                .flatten()
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| {
                    path.extension()
                        .is_some_and(|extension| extension == "json")
                })
                .collect();
            drop_ins.sort();
            drop_ins.truncate(MAX_SETTINGS_FILES);
            files.extend(drop_ins);
        }
        Reviewer::OpenCode => {
            let directory = etc.join("opencode");
            files.extend(["opencode.json", "opencode.jsonc"].map(|name| directory.join(name)));
        }
    }
    files.retain(|path| fs::symlink_metadata(path).is_ok());
    files
}

/// A settings file as JSON; `None` when it cannot be read as such (too
/// large, not UTF-8, comments in it).
fn read_settings(path: &Path) -> Option<Json> {
    let mut text = String::new();
    File::open(path)
        .ok()?
        .take(MAX_SETTINGS_BYTES + 1)
        .read_to_string(&mut text)
        .ok()
        .filter(|read| *read as u64 <= MAX_SETTINGS_BYTES)?;
    Json::parse(&text).ok()
}

/// The keys in `settings` that could send the review elsewhere or run a
/// command during it: the listed top-level ones when they hold something,
/// and any key at any depth that names a base URL or an endpoint.
fn risky_settings(reviewer: Reviewer, settings: &Json) -> Vec<String> {
    let listed = match reviewer {
        Reviewer::ClaudeCode => CLAUDE_SETTINGS_KEYS,
        Reviewer::OpenCode => OPENCODE_SETTINGS_KEYS,
    };
    let mut keys: Vec<String> = settings
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(key, value)| listed.contains(&key.as_str()) && holds_something(value))
        .map(|(key, _)| key.clone())
        .collect();
    endpoint_keys(settings, 0, &mut keys);
    keys.sort();
    keys.dedup();
    keys
}

const fn holds_something(value: &Json) -> bool {
    match value {
        Json::Null | Json::Bool(false) => false,
        Json::String(text) => !text.is_empty(),
        Json::Array(items) => !items.is_empty(),
        Json::Object(members) => !members.is_empty(),
        Json::Bool(true) | Json::Number(_) => true,
    }
}

/// Collects keys spelled like a base URL or an endpoint (`baseURL`,
/// `ANTHROPIC_BASE_URL`, `api-endpoint`), wherever they are.
fn endpoint_keys(value: &Json, depth: usize, keys: &mut Vec<String>) {
    // The parser bounds nesting; this only keeps the walk shallow.
    if depth > 16 {
        return;
    }
    match value {
        Json::Object(members) => {
            for (key, member) in members {
                let plain: String = key
                    .chars()
                    .filter(|character| !matches!(character, '_' | '-'))
                    .collect::<String>()
                    .to_ascii_lowercase();
                if (plain.contains("baseurl") || plain.contains("endpoint"))
                    && holds_something(member)
                {
                    keys.push(key.clone());
                }
                endpoint_keys(member, depth + 1, keys);
            }
        }
        Json::Array(items) => {
            for item in items {
                endpoint_keys(item, depth + 1, keys);
            }
        }
        Json::Null | Json::Bool(_) | Json::Number(_) | Json::String(_) => {}
    }
}
