//! Claude Code: the hooks, status line and helpers of its settings, the
//! MCP servers of `~/.claude.json` and of the system's managed files, and
//! the hooks and servers of every installed plugin.

use super::{
    Dirs, Entry, Found, Launch, Source, add, key_part, read_json, relative, remote, server_entries,
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
        config_file(scope, file, found);
    }
    let Some(dirs) = dirs else {
        return;
    };
    for name in ["settings.json", "settings.local.json"] {
        config_file(scope, &format!("{}/{name}", dirs.claude), found);
    }
    config_file(scope, &dirs.claude_json, found);
    plugins(scope, &dirs.claude, found);
}

/// The entries of one of Claude Code's own files. Every kind is looked for
/// in every file: one where Claude Code does not read it adds an item that
/// nothing runs, which is the cheaper mistake.
fn config_file(scope: &Scope<'_>, file: &str, found: &mut Found) {
    let Some(json) = read_json(scope, file, found) else {
        return;
    };
    let mut entries = Vec::new();
    if let Some(hooks) = json.get("hooks") {
        hook_entries(hooks, "hooks/", &mut entries);
    }
    if let Some(command) = json
        .get("statusLine")
        .and_then(|line| line.get("command"))
        .and_then(Json::as_str)
    {
        entries.push(Entry::command("statusLine", command));
    }
    for helper in HELPERS {
        if let Some(command) = json.get(helper).and_then(Json::as_str) {
            entries.push(Entry::command(*helper, command));
        }
    }
    if let Some(servers) = json.get("mcpServers") {
        server_entries(servers, "mcpServers/", &mut entries);
    }
    add(scope, &Source::of(file), entries, found);

    // A project is named by a digest of its path in what goes to the
    // review, which names an item; only the user is told the path.
    let projects = json.get("projects").and_then(Json::as_object);
    for (project, settings) in projects.unwrap_or_default() {
        let mut entries = Vec::new();
        if let Some(servers) = settings.get("mcpServers") {
            let prefix = format!("projects/{}/mcpServers/", key_part(project));
            server_entries(servers, &prefix, &mut entries);
        }
        let source = Source {
            file,
            plugin_root: None,
            note: Some(format!("an MCP server of the project {project}")),
        };
        add(scope, &source, entries, found);
    }
}

/// The commands and web hooks of a `hooks` table (each event to groups of
/// hooks), each at `prefix`, the event, the group and the hook.
fn hook_entries(hooks: &Json, prefix: &str, entries: &mut Vec<Entry>) {
    for (event, groups) in hooks.as_object().unwrap_or_default() {
        let groups = groups.as_array().unwrap_or_default();
        for (group_index, group) in groups.iter().enumerate() {
            let hooks = group.get("hooks").and_then(Json::as_array);
            for (hook_index, hook) in hooks.unwrap_or_default().iter().enumerate() {
                let launch = match hook.get("type").and_then(Json::as_str) {
                    Some("http") => hook.get("url").and_then(Json::as_str).map(remote),
                    // These ask a model and start nothing.
                    Some("prompt" | "agent") => None,
                    _ => hook
                        .get("command")
                        .and_then(Json::as_str)
                        .map(|command| Launch::Command(command.to_string())),
                };
                entries.extend(launch.map(|launch| Entry {
                    key: format!("{prefix}{}/{group_index}/{hook_index}", key_part(event)),
                    launch,
                    variables: Vec::new(),
                }));
            }
        }
    }
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
    let directory = format!("{claude}/plugins/");
    let plugins = json.get("plugins").and_then(Json::as_object);
    for (name, installs) in plugins.unwrap_or_default() {
        let installs = installs.as_array().unwrap_or_default();
        for (index, install) in installs.iter().enumerate() {
            let key = match index {
                0 => key_part(name),
                _ => format!("{}/{index}", key_part(name)),
            };
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
            let entries = plugin_entries(scope, &root, &key, found);
            add(scope, &source, entries, found);
        }
    }
}

/// The hooks and servers of the plugin in `root`, each at `key`: those its
/// manifest holds or names, and those of the files Claude Code reads
/// without being told.
fn plugin_entries(scope: &Scope<'_>, root: &str, key: &str, found: &mut Found) -> Vec<Entry> {
    let mut entries = Vec::new();
    let mut hook_files = vec![PLUGIN_HOOKS.to_string()];
    let mut server_files = vec![PLUGIN_SERVERS.to_string()];
    let manifest_file = format!("{root}/{MANIFEST}");
    if let Some(manifest) = read_json(scope, &manifest_file, found) {
        let at = format!("{key}/{MANIFEST}/");
        match manifest.get("hooks") {
            Some(hooks @ Json::Object(_)) => {
                let hooks = hooks.get("hooks").unwrap_or(hooks);
                hook_entries(hooks, &format!("{at}hooks/"), &mut entries);
            }
            Some(named) => hook_files.extend(plugin_files(named, &manifest_file, found)),
            None => {}
        }
        match manifest.get("mcpServers") {
            Some(servers @ Json::Object(_)) => {
                let servers = servers.get("mcpServers").unwrap_or(servers);
                server_entries(servers, &format!("{at}mcpServers/"), &mut entries);
            }
            Some(named) => server_files.extend(plugin_files(named, &manifest_file, found)),
            None => {}
        }
    }
    for files in [&mut hook_files, &mut server_files] {
        files.sort();
        files.dedup();
    }
    for file in &hook_files {
        if let Some(json) = read_json(scope, &format!("{root}/{file}"), found) {
            let hooks = json.get("hooks").unwrap_or(&json);
            hook_entries(hooks, &format!("{key}/{file}/"), &mut entries);
        }
    }
    for file in &server_files {
        if let Some(json) = read_json(scope, &format!("{root}/{file}"), found) {
            let servers = json.get("mcpServers").unwrap_or(&json);
            server_entries(servers, &format!("{key}/{file}/"), &mut entries);
        }
    }
    entries
}

/// The files a manifest names (`"./hooks/more.json"`, or a list of them),
/// relative to the plugin's directory. One that leads out of it is said as
/// not checked: a plugin's files are what was installed with it.
fn plugin_files(named: &Json, manifest: &str, found: &mut Found) -> Vec<String> {
    let named = match named {
        Json::String(file) => vec![file.clone()],
        other => super::strings(other),
    };
    let mut files = Vec::new();
    for file in named {
        let file = file.strip_prefix("./").unwrap_or(&file);
        let inside = !file.is_empty()
            && !file.starts_with('/')
            && file.split('/').all(|part| !matches!(part, "" | "." | ".."));
        if inside {
            files.push(file.to_string());
        } else {
            let reason = format!("names a file outside its plugin ({})", file.escape_debug());
            found.unchecked(manifest, &reason);
        }
    }
    files
}
