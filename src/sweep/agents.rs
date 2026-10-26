//! What AI coding agents start on their own: Claude Code's hooks, status
//! line, helpers, MCP servers and plugins, OpenCode's MCP servers and
//! plugins, and Codex's MCP servers and `notify` program. An agent runs
//! these on every tool call, at every start or on every refresh of its
//! status line, and a theme, a plugin or a program run once can add one.
//!
//! The files these live in hold far more than what runs: tokens, account
//! data, the paths of every project opened and its history. None of them
//! becomes an item, and nothing of them is sent anywhere. Each entry that
//! starts something becomes an item of its own instead, named by its file
//! and its key in it (`~/.claude/settings.json#hooks/PreToolUse/0/0`),
//! whose text is only what it starts: a command line, the names of the
//! variables it is started with (never their values), an npm package, or
//! for a remote server the scheme and host of its address. That text is
//! what the review sees, and its digest what tells a changed entry from an
//! unchanged one. The collector follows each command like any other, so a
//! script a hook names is read and reviewed as a program.
//!
//! What is there and cannot be read (a link, a file too large, text that is
//! not JSON or TOML) is said as not checked, never passed over.

mod claude;
mod codex;
mod opencode;

use std::env;
use std::fs;
use std::io;

use super::collect::{self, Body, Item, Scope};
use super::tier::Tier;
use crate::autorun::Category;
use crate::files::read_small_file;
use crate::json::Json;
use crate::rules::RuleId;
use crate::sha256::Sha256;

/// The largest configuration file read: `~/.claude.json` grows with every
/// project opened. Arbitrary, far above the sizes seen (under 1 MiB).
const MAX_CONFIG: u64 = 16 * 1024 * 1024;

/// The most entries of one file that become items. Arbitrary, far above
/// any real configuration; past it the rest is said as not checked.
const MAX_ENTRIES: usize = 500;

/// What stands where the value of a flag or variable named for a secret
/// was taken out of a server's arguments.
const VALUE_NOT_READ: &str = "<value-not-read>";

/// Words that mark a flag or variable as holding a secret
/// (`--api-key`, `GITHUB_TOKEN=`).
const SECRET_WORDS: &[&str] = &[
    "token",
    "secret",
    "password",
    "passwd",
    "pass",
    "key",
    "apikey",
    "auth",
    "credential",
    "credentials",
    "pat",
    "bearer",
];

/// What the agents' configuration gave.
#[derive(Debug, Default)]
pub(super) struct Found {
    pub(super) items: Vec<Item>,
    /// What could not be read, each as a sentence.
    pub(super) unchecked: Vec<String>,
}

impl Found {
    /// Says that the file at `file` (relative to the root) was not checked,
    /// and why.
    fn unchecked(&mut self, file: &str, reason: &str) {
        self.unchecked.push(format!(
            "/{}: {reason}; what it starts was not checked",
            file.escape_debug()
        ));
    }
}

/// What one entry of an agent's configuration starts.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Launch {
    /// A command line, as a shell is given it.
    Command(String),
    /// A server or web hook reached over the network, by the scheme and
    /// host (with its port) of its address: the rest of an address may
    /// carry a token.
    Remote { scheme: String, host: String },
    /// A package the agent installs from npm and loads (`opencode-x@1.2`).
    Package(String),
}

/// One entry that starts something.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    /// Where in its file it is (`hooks/PreToolUse/0/0`).
    key: String,
    launch: Launch,
    /// The names of the variables it is started with.
    variables: Vec<String>,
}

impl Entry {
    fn command(key: impl Into<String>, line: &str) -> Self {
        Self {
            key: key.into(),
            launch: Launch::Command(line.to_string()),
            variables: Vec::new(),
        }
    }
}

/// An MCP server as the agents describe one: a program with arguments and
/// variables, or an address.
#[derive(Debug, Default)]
struct Server {
    command: Option<String>,
    args: Vec<String>,
    url: Option<String>,
    variables: Vec<String>,
}

impl Server {
    /// A server of Claude Code (`command`, `args`, `env`, `url`) or OpenCode
    /// (`command` as an array, `environment`, `url`).
    fn from_json(server: &Json) -> Self {
        let mut words: Vec<String> = match server.get("command") {
            Some(Json::String(command)) => vec![command.clone()],
            Some(command) => strings(command),
            None => Vec::new(),
        };
        words.extend(server.get("args").map(strings).unwrap_or_default());
        let mut words = words.into_iter();
        Self {
            command: words.next(),
            args: words.collect(),
            url: server.get("url").and_then(Json::as_str).map(str::to_string),
            variables: ["env", "environment"]
                .iter()
                .filter_map(|key| server.get(key).and_then(Json::as_object))
                .flatten()
                .map(|(name, _)| name.clone())
                .collect(),
        }
    }

    /// The entry at `key`; `None` for a server with neither a program nor
    /// an address, which starts nothing.
    fn into_entry(self, key: String) -> Option<Entry> {
        let launch = match (self.command, self.url) {
            (Some(command), _) => Launch::Command(command_line(&command, &self.args)),
            (None, Some(url)) => remote(&url),
            (None, None) => return None,
        };
        Some(Entry {
            key,
            launch,
            variables: self.variables,
        })
    }
}

/// Where the entries of one file were found, for their items.
struct Source<'a> {
    /// The configuration file, relative to the root.
    file: &'a str,
    /// What `${CLAUDE_PLUGIN_ROOT}` stands for in a plugin's entries,
    /// relative to the root.
    plugin_root: Option<&'a str>,
    /// What is said of each item (whose plugin or project it is).
    note: Option<String>,
}

impl<'a> Source<'a> {
    fn of(file: &'a str) -> Self {
        Self {
            file,
            plugin_root: None,
            note: None,
        }
    }
}

/// Where each agent keeps its configuration, relative to the root.
#[derive(Debug, PartialEq, Eq)]
struct Dirs {
    claude: String,
    claude_json: String,
    opencode: String,
    /// The file `OPENCODE_CONFIG` names, read besides the usual one.
    opencode_config: Option<String>,
    codex: String,
}

impl Dirs {
    /// The directories of the home at `home`, where `variable` gives the
    /// value of an environment variable, relative to the root, that moves
    /// one: `CLAUDE_CONFIG_DIR` (which holds `.claude.json` too),
    /// `XDG_CONFIG_HOME`, `OPENCODE_CONFIG` and `CODEX_HOME`.
    fn new(home: &str, variable: &dyn Fn(&str) -> Option<String>) -> Self {
        let claude = variable("CLAUDE_CONFIG_DIR");
        Self {
            claude_json: claude.as_ref().map_or_else(
                || format!("{home}/.claude.json"),
                |claude| format!("{claude}/.claude.json"),
            ),
            claude: claude.unwrap_or_else(|| format!("{home}/.claude")),
            opencode: variable("XDG_CONFIG_HOME").map_or_else(
                || format!("{home}/.config/opencode"),
                |config| format!("{config}/opencode"),
            ),
            opencode_config: variable("OPENCODE_CONFIG"),
            codex: variable("CODEX_HOME").unwrap_or_else(|| format!("{home}/.codex")),
        }
    }

    /// The directories of `scope`'s home. The environment says where they
    /// are only when it is that home's own (its `HOME` is that home): the
    /// root collector, and a sweep of another tree, take the defaults.
    fn of(scope: &Scope<'_>) -> Option<Self> {
        let home = scope.home?;
        let own = env::var("HOME").is_ok_and(|value| value.trim_matches('/') == home);
        let variable = |name: &str| {
            env::var(name)
                .ok()
                .filter(|_| own)
                .and_then(|value| relative(&value))
        };
        Some(Self::new(home, &variable))
    }
}

/// An absolute path as a path relative to the root, if it is a plain one.
fn relative(path: &str) -> Option<String> {
    let rest = path.strip_prefix('/')?.trim_end_matches('/');
    let plain = !rest.is_empty() && rest.split('/').all(|part| !matches!(part, "" | "." | ".."));
    plain.then(|| rest.to_string())
}

/// What the AI coding agents in `scope` start on their own: the system's
/// managed Claude Code settings, and with a home, each agent's own.
pub(super) fn collect(scope: &Scope<'_>) -> Found {
    let mut found = Found::default();
    let dirs = Dirs::of(scope);
    claude::collect(scope, dirs.as_ref(), &mut found);
    if let Some(dirs) = &dirs {
        opencode::collect(scope, dirs, &mut found);
        codex::collect(scope, &dirs.codex, &mut found);
    }
    found
}

/// The text of the configuration file at `file`, if there is one; one that
/// is there and cannot be read is said in `found`. A link is not followed.
fn read(scope: &Scope<'_>, file: &str, found: &mut Found) -> Option<String> {
    let path = scope.root.join(file);
    let reason = match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return None,
        Err(error) => error.to_string(),
        Ok(metadata) if metadata.is_symlink() => "a link, which is not followed".into(),
        Ok(metadata) if !metadata.is_file() => "not a regular file".into(),
        Ok(metadata) if metadata.len() > MAX_CONFIG => "larger than 16 MiB".into(),
        Ok(_) => match read_small_file(&path, MAX_CONFIG) {
            Some(text) => return Some(text),
            None => "could not be read".into(),
        },
    };
    found.unchecked(file, &reason);
    None
}

/// The configuration file at `file` as JSON (comments and trailing commas
/// allowed, as OpenCode allows them), if there is one; one that is there
/// and cannot be read as JSON is said in `found`.
fn read_json(scope: &Scope<'_>, file: &str, found: &mut Found) -> Option<Json> {
    let text = read(scope, file, found)?;
    match Json::parse(&without_comments(&text)) {
        Ok(json) => Some(json),
        Err(error) => {
            found.unchecked(file, &format!("not JSON ({error})"));
            None
        }
    }
}

/// `text` with the comments and trailing commas of JSONC taken out, so the
/// strict reader takes it. What is inside a string stays as it is.
fn without_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut characters = text.chars().peekable();
    let mut quoted = false;
    while let Some(character) = characters.next() {
        if quoted {
            out.push(character);
            match character {
                '\\' => out.extend(characters.next()),
                '"' => quoted = false,
                _ => {}
            }
            continue;
        }
        match (character, characters.peek()) {
            ('"', _) => {
                quoted = true;
                out.push(character);
            }
            ('/', Some('/')) => while characters.next_if(|next| *next != '\n').is_some() {},
            ('/', Some('*')) => {
                characters.next();
                let mut previous = ' ';
                for next in characters.by_ref() {
                    if previous == '*' && next == '/' {
                        break;
                    }
                    previous = next;
                }
                out.push(' ');
            }
            (']' | '}', _) => {
                let kept = out.trim_end().len();
                if out[..kept].ends_with(',') {
                    out.truncate(kept - 1);
                }
                out.push(character);
            }
            _ => out.push(character),
        }
    }
    out
}

/// The entries of a table of MCP servers by name, at `prefix` and the name.
fn server_entries(servers: &Json, prefix: &str, entries: &mut Vec<Entry>) {
    for (name, server) in servers.as_object().unwrap_or_default() {
        let key = format!("{prefix}{}", key_part(name));
        entries.extend(Server::from_json(server).into_entry(key));
    }
}

/// The strings of a JSON array; anything else in it is left out.
fn strings(value: &Json) -> Vec<String> {
    value
        .as_array()
        .unwrap_or_default()
        .iter()
        .filter_map(Json::as_str)
        .map(str::to_string)
        .collect()
}

/// Makes items of `entries`, found in `source`, at most `MAX_ENTRIES`.
fn add(scope: &Scope<'_>, source: &Source<'_>, entries: Vec<Entry>, found: &mut Found) {
    if entries.len() > MAX_ENTRIES {
        found.unchecked(
            source.file,
            &format!("more than {MAX_ENTRIES} entries that start something"),
        );
    }
    for entry in entries.into_iter().take(MAX_ENTRIES) {
        found.items.push(item(scope, source, entry));
    }
}

/// The item of `entry`: its text is what it starts (see the module docs).
fn item(scope: &Scope<'_>, source: &Source<'_>, entry: Entry) -> Item {
    let Entry {
        key,
        launch,
        variables,
    } = entry;
    let path = format!("{}#{key}", source.file);
    let mut runs = Vec::new();
    let mut alerts = Vec::new();
    let started = match launch {
        Launch::Command(line) => {
            runs.push(with_plugin_root(&line, source.plugin_root));
            line
        }
        Launch::Remote { scheme, host } => {
            if !crate::rules::is_local_host(without_port(&host)) {
                alerts.push((
                    RuleId::RiskyConfiguration,
                    format!(
                        "talks to a remote server at {host}: the agent sends it what it works on, and acts on what it answers"
                    ),
                ));
            }
            format!("{scheme}://{host}")
        }
        Launch::Package(package) => {
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
        notes: source.note.iter().cloned().collect(),
        alerts,
        path,
    }
}

/// `host` without a port (`localhost:3000`, `[::1]:8080`).
fn without_port(host: &str) -> &str {
    host.rsplit_once(':')
        .filter(|(name, port)| {
            !port.is_empty()
                && port.chars().all(|c| c.is_ascii_digit())
                && (!name.contains(':') || name.ends_with(']'))
        })
        .map_or(host, |(name, _)| name)
}

/// Whether an npm package names the one version it installs
/// (`pkg@1.2.3`, `@scope/pkg@1.2.3-rc.1`), not a tag or a range.
fn is_pinned(package: &str) -> bool {
    package
        .get(1..)
        .and_then(|rest| rest.rsplit_once('@'))
        .is_some_and(|(_, version)| {
            version.starts_with(|c: char| c.is_ascii_digit())
                && version
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
        })
}

/// The address `url` as the scheme and host it reaches; who it logs in as
/// and the rest of the address are left out.
fn remote(url: &str) -> Launch {
    let url = url.trim();
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let authority = rest
        .split(|c: char| matches!(c, '/' | '?' | '#') || c.is_whitespace())
        .next()
        .unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or_default();
    Launch::Remote {
        scheme: scheme.to_ascii_lowercase(),
        host: host.to_ascii_lowercase(),
    }
}

/// `program` and `args` as one shell line, each word quoted where a shell
/// would split it. The value a flag or variable named for a secret takes,
/// and who an address logs in as, are taken out: a server's arguments are
/// where a token is written when it is not in a variable.
fn command_line(program: &str, args: &[String]) -> String {
    let mut words = vec![quoted(program)];
    let mut secret_next = false;
    for arg in args {
        let word = if secret_next {
            VALUE_NOT_READ.to_string()
        } else {
            without_secret(arg)
        };
        secret_next = arg.starts_with('-') && !arg.contains('=') && names_a_secret(arg);
        words.push(quoted(&word));
    }
    words.join(" ")
}

/// `arg` with a secret value taken out: of `--token=x`, of `API_KEY=x`,
/// and the login of `scheme://user:password@host`.
fn without_secret(arg: &str) -> String {
    if let Some((name, _)) = arg.split_once('=')
        && names_a_secret(name)
        && !name.contains("://")
    {
        return format!("{name}={VALUE_NOT_READ}");
    }
    match arg.split_once("://") {
        Some((scheme, rest)) => {
            let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
            match rest[..end].rsplit_once('@') {
                Some((_, host)) => format!("{scheme}://{host}{}", &rest[end..]),
                None => arg.to_string(),
            }
        }
        None => arg.to_string(),
    }
}

/// Whether a flag or variable name (`--api-key`, `GITHUB_TOKEN`) is named
/// for a secret.
fn names_a_secret(name: &str) -> bool {
    name.split(|c: char| !c.is_ascii_alphanumeric())
        .any(|word| SECRET_WORDS.contains(&word.to_ascii_lowercase().as_str()))
}

/// `word` as a shell reads it back as one word. `$` and braces stay as
/// they are: an agent fills in `${VAR}` in a server's arguments itself.
fn quoted(word: &str) -> String {
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

/// `line` with the plugin's directory (`root`, relative to the root)
/// written in for `${CLAUDE_PLUGIN_ROOT}` and `$CLAUDE_PLUGIN_ROOT`, so the
/// scripts it names are followed. The item's text keeps the line as
/// written.
fn with_plugin_root(line: &str, root: Option<&str>) -> String {
    let Some(root) = root else {
        return line.to_string();
    };
    let directory = format!("/{root}");
    let line = line.replace(&format!("${{{PLUGIN_ROOT}}}"), &directory);
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
            out.push_str(&directory);
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

/// `name` (a key the configuration chose: an event, a server, a plugin, a
/// project's path) as one part of an item's name: as it is where it is
/// plain, else as `~` and the start of its digest, so that no name reads as
/// more than one part and no two keys share one.
fn key_part(name: &str) -> String {
    let plain = !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.@:+".contains(c));
    if plain {
        name.to_string()
    } else {
        let digest = Sha256::digest(name.as_bytes()).to_string();
        format!("~{}", &digest[..12])
    }
}

#[cfg(test)]
mod tests;
