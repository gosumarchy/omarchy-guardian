//! What AI coding agents start on their own: Claude Code's hooks, status
//! line, helpers, environment, MCP servers and plugins, OpenCode's MCP
//! servers and plugins, and Codex's MCP servers and `notify` program. An
//! agent runs these on every tool call, at every start or on every refresh
//! of its status line, and a theme, a plugin or a program run once can add
//! one.
//!
//! The files these live in hold far more than what runs: tokens, account
//! data, the paths of every project opened and its history. None of them
//! becomes an item, and nothing of them is sent anywhere. Each entry that
//! starts something becomes an item of its own instead, named by its file
//! and its key in it (`~/.claude/settings.json#hooks/PreToolUse/0/0`),
//! whose text is only what it starts (see `entry::item`). That text is what
//! the review sees, and its digest what tells a changed entry from an
//! unchanged one. The collector follows each command like any other, so a
//! script a hook names is read and reviewed as a program.
//!
//! # Invariants
//!
//! - **Names are collision-free.** Every part of a key the configuration
//!   chose is one `key_part`, which never holds a `/`, and every kind of
//!   entry has its own fixed layout of parts, so two entries share a name
//!   only where one file is read twice. The collector still reports a name
//!   it already holds as not checked rather than drop it.
//! - **Nothing of a project's path reaches an item's text or name.** A
//!   project is named by a digest keyed with a secret kept in Guardian's
//!   private state, or by its position where there is no key.
//! - **Fail closed.** A file, field or variable that is there and cannot be
//!   read is said as not checked, never passed over. Only an entry with
//!   neither a program nor an address, which starts nothing, is silent.

mod claude;
mod codex;
mod entry;
mod opencode;
mod redact;

use std::env;
use std::fs;
use std::io::{self, Read as _};
use std::path::Path;

use super::collect::{Item, Scope};
use super::state;
use crate::engine::store::Store;
use crate::files::{self, AtomicWrite, read_small_file};
use crate::json::Json;
use crate::sha256::{self, Digest, Sha256};
use entry::{Entries, Entry, Launch, Source, add, command_line};

/// The largest configuration file read: `~/.claude.json` grows with every
/// project opened. Arbitrary, far above the sizes seen (under 1 MiB).
const MAX_CONFIG: u64 = 16 * 1024 * 1024;

/// The most entries of one file that become items. Arbitrary, far above
/// any real configuration; past it the rest is said as not checked.
const MAX_ENTRIES: usize = 500;

/// The file in the sweep's private state directory that holds the key a
/// project's path is named by.
const PROJECT_KEY: &str = "agent-project-key";

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

/// The key a project's path is named by: 32 random bytes kept in the
/// sweep's private state directory, so that the name of an item tells
/// nobody without the key which project it is, and stays the same from one
/// sweep to the next.
#[derive(Debug, PartialEq, Eq)]
struct ProjectKey(Digest);

impl ProjectKey {
    /// The name of the project at `path`: its keyed digest in hex.
    fn name(&self, path: &str) -> String {
        sha256::hmac(&self.0, path.as_bytes()).to_string()
    }

    /// The key in the sweep's state directory, made there if there is none.
    /// `None` where there is no such directory or it cannot be written: a
    /// project is then named by its position. Two sweeps that each make a
    /// key write their own and the last one stays; the names the other gave
    /// show as new once.
    fn kept() -> Option<Self> {
        let directory = state::directory(&Store::default_root()?).ok()?;
        let path = directory.join(PROJECT_KEY);
        if let Some(key) = read_small_file(&path, 128)
            .and_then(|text| Digest::from_hex(text.trim()))
            .map(Self)
        {
            return Some(key);
        }
        let random = Path::new("/dev/urandom");
        let mut bytes = [0_u8; 32];
        fs::File::open(random)
            .and_then(|mut file| file.read_exact(&mut bytes))
            .ok()?;
        // The digest of random bytes is as random, and has a hex form.
        let key = Sha256::digest(&bytes);
        let options = AtomicWrite {
            temporary: directory.join(format!(".{PROJECT_KEY}.new")),
            mode: 0o600,
            exact_mode: true,
            owner: None,
            sync: true,
        };
        files::write_atomic(&path, key.to_string().as_bytes(), &options).ok()?;
        Some(Self(key))
    }
}

/// Where each agent keeps its configuration, relative to the root.
#[derive(Debug, PartialEq, Eq)]
struct Dirs {
    claude: String,
    claude_json: String,
    opencode: String,
    /// The directory `OPENCODE_CONFIG_DIR` names, read besides the usual one.
    opencode_extra: Option<String>,
    /// The file `OPENCODE_CONFIG` names, read besides the usual ones.
    opencode_config: Option<String>,
    codex: String,
    project_key: Option<ProjectKey>,
}

/// The environment variables that move an agent's directory.
const DIRECTORY_VARIABLES: &[&str] = &[
    "CLAUDE_CONFIG_DIR",
    "XDG_CONFIG_HOME",
    "OPENCODE_CONFIG_DIR",
    "OPENCODE_CONFIG",
    "CODEX_HOME",
];

impl Dirs {
    /// The directories of the home at `home`, where `variable` gives the
    /// value, relative to the root, of one of `DIRECTORY_VARIABLES` that is
    /// set: `CLAUDE_CONFIG_DIR` holds `.claude.json` too.
    fn new(
        home: &str,
        variable: &dyn Fn(&str) -> Option<String>,
        project_key: Option<ProjectKey>,
    ) -> Self {
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
            opencode_extra: variable("OPENCODE_CONFIG_DIR"),
            opencode_config: variable("OPENCODE_CONFIG"),
            codex: variable("CODEX_HOME").unwrap_or_else(|| format!("{home}/.codex")),
            project_key,
        }
    }

    /// The directories of `scope`'s home. The environment, and the key a
    /// project is named by, belong to the home of the user running the
    /// sweep (its `HOME`); for any other home (a test tree, or a `HOME`
    /// that is not the one swept) the defaults stand and a project is named
    /// by its position. A variable set to what is no plain absolute path is
    /// said in `found`, and the default stands for it.
    fn of(scope: &Scope<'_>, found: &mut Found) -> Option<Self> {
        let home = scope.home?;
        let own = env::var("HOME").is_ok_and(|value| value.trim_matches('/') == home);
        if !own {
            return Some(Self::new(home, &|_| None, None));
        }
        let lookup = |name: &str| env::var_os(name).map(|value| value.into_string().ok());
        let variable = resolved(&lookup, found);
        Some(Self::new(home, &variable, ProjectKey::kept()))
    }
}

/// How each of `DIRECTORY_VARIABLES` that `lookup` finds set (`Some(None)`
/// for a value that is not UTF-8) reads as a path relative to the root; one
/// that is no plain absolute path is said in `found` and left out.
fn resolved(
    lookup: &dyn Fn(&str) -> Option<Option<String>>,
    found: &mut Found,
) -> impl Fn(&str) -> Option<String> + use<> {
    let mut values = Vec::new();
    for name in DIRECTORY_VARIABLES {
        match lookup(name).map(|value| value.as_deref().and_then(relative)) {
            None => {}
            Some(Some(path)) => values.push((*name, path)),
            Some(None) => found.unchecked.push(format!(
                "{name} is set to what is no plain absolute path: the default was read in its place, and what the agent reads there was not checked"
            )),
        }
    }
    move |name: &str| {
        values
            .iter()
            .find(|(set, _)| *set == name)
            .map(|(_, path)| path.clone())
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
    let dirs = Dirs::of(scope, &mut found);
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
        Ok(metadata) if metadata.len() > MAX_CONFIG => {
            format!("larger than {} MiB", MAX_CONFIG / 1024 / 1024)
        }
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

/// The strings of a JSON array; `None` for anything else, or an array that
/// holds anything but strings.
fn string_list(value: &Json) -> Option<Vec<String>> {
    value
        .as_array()?
        .iter()
        .map(|word| word.as_str().map(str::to_string))
        .collect()
}

/// An MCP server as the agents describe one: a program with arguments and
/// variables, or an address, and a program that makes its headers.
#[derive(Debug, Default)]
struct Server {
    command: Option<String>,
    args: Vec<String>,
    url: Option<String>,
    headers_helper: Option<String>,
    variables: Vec<String>,
    /// The fields that are there and could not be read (`command`).
    unread: Vec<&'static str>,
}

impl Server {
    /// A server of Claude Code (`command`, `args`, `env`, `url`,
    /// `headersHelper`) or OpenCode (`command` as an array, `environment`,
    /// `url`).
    fn from_json(server: &Json) -> Self {
        let mut this = Self::default();
        let mut words = match server.get("command") {
            None => Vec::new(),
            Some(Json::String(command)) => vec![command.clone()],
            Some(command) => this.list(command, "command"),
        };
        if let Some(args) = server.get("args") {
            words.extend(this.list(args, "args"));
        }
        let mut words = words.into_iter();
        this.command = words.next();
        this.args = words.collect();
        this.url = this.string(server.get("url"), "url");
        this.headers_helper = this.string(server.get("headersHelper"), "headersHelper");
        for field in ["env", "environment"] {
            match server.get(field).map(Json::as_object) {
                None => {}
                Some(Some(variables)) => this
                    .variables
                    .extend(variables.iter().map(|(name, _)| name.clone())),
                Some(None) => this.unread.push(field),
            }
        }
        this
    }

    fn list(&mut self, value: &Json, field: &'static str) -> Vec<String> {
        string_list(value).unwrap_or_else(|| {
            self.unread.push(field);
            Vec::new()
        })
    }

    fn string(&mut self, value: Option<&Json>, field: &'static str) -> Option<String> {
        match value {
            None => None,
            Some(Json::String(text)) => Some(text.clone()),
            Some(_) => {
                self.unread.push(field);
                None
            }
        }
    }

    /// Adds the entries of the server at `key` to `entries`: the server
    /// itself, and its `headersHelper` at `key/headersHelper`. A server
    /// with neither a program nor an address starts nothing; a field that
    /// could not be read is said as not checked.
    fn add_to(self, key: &str, entries: &mut Entries) {
        for field in &self.unread {
            entries.unread(key, field);
        }
        if let Some(helper) = &self.headers_helper {
            entries.push(Entry::command(format!("{key}/headersHelper"), helper));
        }
        let launch = match (self.command, self.url) {
            (Some(command), _) => Launch::Command(command_line(&command, &self.args)),
            (None, Some(url)) => entry::remote(&url),
            (None, None) => return,
        };
        entries.push(Entry {
            key: key.to_string(),
            launch,
            variables: self.variables,
        });
    }
}

/// The entries of a table of MCP servers by name, at `prefix` and the name.
fn server_entries(servers: &Json, prefix: &str, entries: &mut Entries) {
    let Some(servers) = servers.as_object() else {
        entries.unread(prefix.trim_end_matches('/'), "table of servers");
        return;
    };
    for (name, server) in servers {
        Server::from_json(server).add_to(&format!("{prefix}{}", key_part(name)), entries);
    }
}

/// `name` (a key the configuration chose: an event, a server, a plugin) as
/// one part of an item's name: as it is where it is plain, else as `~` and
/// its whole digest, so that no part holds a `/` and no two keys share one.
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
        format!("~{}", Sha256::digest(name.as_bytes()))
    }
}

#[cfg(test)]
mod tests;
