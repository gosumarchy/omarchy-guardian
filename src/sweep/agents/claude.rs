//! Claude Code: the hooks, status line, helpers and environment of its
//! settings, the MCP servers of `~/.claude.json` and of the system's managed
//! files, and the hooks and servers of every installed plugin.

use super::entry::Variable;
use super::{
    Dirs, Entries, Entry, Found, Launch, ProjectKey, Source, add, entry, key_part, read_json,
    relative, server_entries, string_list,
};
use crate::json::Json;
use crate::sweep::collect::Scope;

/// The settings and servers an administrator sets for every user.
const MANAGED: &[&str] = &[
    "etc/claude-code/managed-settings.json",
    "etc/claude-code/managed-mcp.json",
];

/// Settings whose value is a command Claude Code runs on its own: to get an
/// API key or cloud credentials, and the headers of its telemetry.
const HELPERS: &[&str] = &[
    "apiKeyHelper",
    "awsAuthRefresh",
    "awsCredentialExport",
    "otelHeadersHelper",
];

/// Where a plugin describes itself, relative to its directory.
const MANIFEST: &str = ".claude-plugin/plugin.json";

/// The files a plugin's hooks and servers are read from without its
/// manifest naming them, relative to its directory.
const PLUGIN_HOOKS: &str = "hooks/hooks.json";
const PLUGIN_SERVERS: &str = ".mcp.json";

/// The managed files of the system and, with `dirs`, the home's settings,
/// `.claude.json` and plugins.
pub(super) fn collect(scope: &Scope<'_>, dirs: Option<&Dirs>, found: &mut Found) {
    for file in MANAGED {
        config_file(scope, file, None, found);
    }
    let Some(dirs) = dirs else {
        return;
    };
    let key = dirs.project_key.as_ref();
    for name in ["settings.json", "settings.local.json"] {
        config_file(scope, &format!("{}/{name}", dirs.claude), key, found);
    }
    config_file(scope, &dirs.claude_json, key, found);
    plugins(scope, &dirs.claude, found);
}

/// The entries of one of Claude Code's own files. Every kind is looked for
/// in every file: one where Claude Code does not read it adds an item that
/// nothing runs, which is the cheaper mistake.
fn config_file(scope: &Scope<'_>, file: &str, key: Option<&ProjectKey>, found: &mut Found) {
    let Some(json) = read_json(scope, file, found) else {
        return;
    };
    let mut entries = Entries::default();
    if let Some(hooks) = json.get("hooks") {
        hook_entries(hooks, "hooks", &mut entries);
    }
    match json.get("statusLine") {
        None => {}
        Some(line @ Json::Object(_)) => {
            command_entry(line.get("command"), "statusLine", &mut entries);
        }
        Some(_) => entries.unread("statusLine", "table"),
    }
    for helper in HELPERS {
        command_entry(json.get(helper), helper, &mut entries);
    }
    if let Some(env) = json.get("env") {
        environment_entry(env, &mut entries);
    }
    if let Some(servers) = json.get("mcpServers") {
        server_entries(servers, "mcpServers/", &mut entries);
    }
    match json.get("projects") {
        None => {}
        Some(Json::Object(projects)) => {
            add(scope, &Source::of(file), entries, found);
            project_entries(scope, file, projects, key, found);
            return;
        }
        Some(_) => entries.unread("projects", "table"),
    }
    add(scope, &Source::of(file), entries, found);
}

/// The servers of each project of `.claude.json`. Nothing derived from a
/// project's path is in an item's name or text, which the review sees: a
/// project is named by its path's digest keyed with `key`, or without one
/// by its position. Only the user is told the path, in the item's note.
fn project_entries(
    scope: &Scope<'_>,
    file: &str,
    projects: &[(String, Json)],
    key: Option<&ProjectKey>,
    found: &mut Found,
) {
    for (index, (project, settings)) in projects.iter().enumerate() {
        let Some(servers) = settings.get("mcpServers") else {
            continue;
        };
        let name = key.map_or_else(|| index.to_string(), |key| key.name(project));
        let mut entries = Entries::default();
        server_entries(
            servers,
            &format!("projects/{name}/mcpServers/"),
            &mut entries,
        );
        let source = Source {
            file,
            plugin_root: None,
            note: Some(format!("an MCP server of the project {project}")),
        };
        add(scope, &source, entries, found);
    }
}

/// The command at `key` (`statusLine`, `apiKeyHelper`), if `value` is one.
fn command_entry(value: Option<&Json>, key: &str, entries: &mut Entries) {
    match value {
        None => {}
        Some(Json::String(command)) => entries.push(Entry::command(key, command)),
        Some(_) => entries.unread(key, "command"),
    }
}

/// The variables of `env`, which Claude Code sets for itself and for all it
/// starts, as one entry: their names, and the host of those that are
/// addresses. A value that is no string has no host to give.
fn environment_entry(env: &Json, entries: &mut Entries) {
    let Some(variables) = env.as_object() else {
        entries.unread("env", "table");
        return;
    };
    if variables.is_empty() {
        return;
    }
    let set = variables
        .iter()
        .map(|(name, value)| Variable::of(name, value.as_str().unwrap_or_default()))
        .collect();
    entries.push(Entry {
        key: "env".into(),
        launch: Launch::Environment(set),
        variables: Vec::new(),
    });
}

/// The commands and web hooks of a `hooks` table (each event to groups of
/// hooks), each at `prefix`, the event, the group and the hook.
fn hook_entries(hooks: &Json, prefix: &str, entries: &mut Entries) {
    let Some(events) = hooks.as_object() else {
        entries.unread(prefix, "table of hooks");
        return;
    };
    for (event, groups) in events {
        let at = format!("{prefix}/{}", key_part(event));
        let Some(groups) = groups.as_array() else {
            entries.unread(&at, "list of groups");
            continue;
        };
        for (group_index, group) in groups.iter().enumerate() {
            let at = format!("{at}/{group_index}");
            let Some(hooks) = group.get("hooks").and_then(Json::as_array) else {
                entries.unread(&at, "list of hooks");
                continue;
            };
            for (hook_index, hook) in hooks.iter().enumerate() {
                hook_entry(hook, &format!("{at}/{hook_index}"), entries);
            }
        }
    }
}

/// The command or web hook of one hook, at `key`.
fn hook_entry(hook: &Json, key: &str, entries: &mut Entries) {
    let launch = match hook.get("type").map(Json::as_str) {
        None | Some(Some("command")) => match hook.get("command") {
            Some(Json::String(command)) => Launch::Command(command.clone()),
            _ => return entries.unread(key, "command"),
        },
        Some(Some("http")) => match hook.get("url") {
            Some(Json::String(url)) => entry::remote(url),
            _ => return entries.unread(key, "url"),
        },
        // These ask a model, or call a tool of a server already started,
        // and start nothing of their own.
        Some(Some("prompt" | "agent" | "mcp_tool")) => return,
        Some(_) => return entries.unread(key, "type"),
    };
    entries.push(Entry {
        key: key.to_string(),
        launch,
        variables: Vec::new(),
    });
}

/// The hooks and servers of every plugin `installed_plugins.json` lists,
/// named by the plugin rather than by the directory of its version, so an
/// update shows as a change. Only a plugin in Claude Code's own plugin
/// directory is read.
fn plugins(scope: &Scope<'_>, claude: &str, found: &mut Found) {
    let file = format!("{claude}/plugins/installed_plugins.json");
    let Some(json) = read_json(scope, &file, found) else {
        return;
    };
    let Some(plugins) = json.get("plugins").and_then(Json::as_object) else {
        found.unchecked(&file, "its table of plugins could not be read");
        return;
    };
    let directory = format!("{claude}/plugins/");
    for (name, installs) in plugins {
        let Some(installs) = installs.as_array() else {
            let reason = format!("the installs of {} could not be read", name.escape_debug());
            found.unchecked(&file, &reason);
            continue;
        };
        for (index, install) in installs.iter().enumerate() {
            let path = install.get("installPath").and_then(Json::as_str);
            let Some(root) = path
                .and_then(relative)
                .filter(|root| root.starts_with(&directory))
            else {
                let reason = format!(
                    "the plugin {} is not installed in /{directory}",
                    name.escape_debug()
                );
                found.unchecked(&file, &reason);
                continue;
            };
            let version = install.get("version").and_then(Json::as_str);
            let source = Source {
                file: &file,
                plugin_root: Some(&root),
                note: Some(format!(
                    "of the Claude Code plugin {name} (version {})",
                    version.unwrap_or("unknown")
                )),
            };
            let key = format!("plugins/{}/{index}", key_part(name));
            let entries = plugin_entries(scope, &root, &key, found);
            add(scope, &source, entries, found);
        }
    }
}

/// The hooks and servers of the plugin in `root`, each at `key` and the
/// source it came from: `manifest-hooks` and `manifest-mcp` for those the
/// manifest holds, `hooks` and `mcp` for the files Claude Code reads
/// without being told, `hooks-file-{i}` and `mcp-file-{i}` for the files the
/// manifest names, by their position in its list.
fn plugin_entries(scope: &Scope<'_>, root: &str, key: &str, found: &mut Found) -> Entries {
    let mut entries = Entries::default();
    let mut hook_files = vec![("hooks".to_string(), PLUGIN_HOOKS.to_string())];
    let mut server_files = vec![("mcp".to_string(), PLUGIN_SERVERS.to_string())];
    let manifest_file = format!("{root}/{MANIFEST}");
    if let Some(manifest) = read_json(scope, &manifest_file, found) {
        match manifest.get("hooks") {
            Some(hooks @ Json::Object(_)) => {
                let hooks = hooks.get("hooks").unwrap_or(hooks);
                hook_entries(hooks, &format!("{key}/manifest-hooks"), &mut entries);
            }
            Some(named) => {
                let named = plugin_files(named, "hooks-file", &manifest_file, found);
                hook_files.extend(named.into_iter().filter(|(_, file)| file != PLUGIN_HOOKS));
            }
            None => {}
        }
        match manifest.get("mcpServers") {
            Some(servers @ Json::Object(_)) => {
                let servers = servers.get("mcpServers").unwrap_or(servers);
                server_entries(servers, &format!("{key}/manifest-mcp/"), &mut entries);
            }
            Some(named) => {
                let named = plugin_files(named, "mcp-file", &manifest_file, found);
                server_files.extend(named.into_iter().filter(|(_, file)| file != PLUGIN_SERVERS));
            }
            None => {}
        }
    }
    for (source, file) in &hook_files {
        if let Some(json) = read_json(scope, &format!("{root}/{file}"), found) {
            let hooks = json.get("hooks").unwrap_or(&json);
            hook_entries(hooks, &format!("{key}/{source}"), &mut entries);
        }
    }
    for (source, file) in &server_files {
        if let Some(json) = read_json(scope, &format!("{root}/{file}"), found) {
            let servers = json.get("mcpServers").unwrap_or(&json);
            server_entries(servers, &format!("{key}/{source}/"), &mut entries);
        }
    }
    entries
}

/// The files a manifest names (`"./hooks/more.json"`, or a list of them),
/// relative to the plugin's directory, each with its source: `kind` and
/// its position in the list. One that leads out of the directory is said
/// as not checked: a plugin's files are what was installed with it.
fn plugin_files(
    named: &Json,
    kind: &str,
    manifest: &str,
    found: &mut Found,
) -> Vec<(String, String)> {
    let named = match named {
        Json::String(file) => Some(vec![file.clone()]),
        other => string_list(other),
    };
    let Some(named) = named else {
        found.unchecked(manifest, &format!("its {kind} list could not be read"));
        return Vec::new();
    };
    let mut files = Vec::new();
    for (index, file) in named.iter().enumerate() {
        let file = file.strip_prefix("./").unwrap_or(file);
        let inside = !file.is_empty()
            && !file.starts_with('/')
            && file.split('/').all(|part| !matches!(part, "" | "." | ".."));
        if inside {
            files.push((format!("{kind}-{index}"), file.to_string()));
        } else {
            let reason = format!("names a file outside its plugin ({})", file.escape_debug());
            found.unchecked(manifest, &reason);
        }
    }
    files
}
