//! OpenCode: the MCP servers and plugins its configuration names, and the
//! plugin files in its plugin directories.

use super::{Dirs, Entry, Found, Launch, Source, add, quoted, read_json, server_entries};
use crate::autorun::Category;
use crate::json::Json;
use crate::sweep::collect::{self, Scope};
use crate::sweep::read;

/// The configuration files of OpenCode's directory. It reads both.
const CONFIG_FILES: &[&str] = &["opencode.json", "opencode.jsonc"];

/// The files OpenCode loads as plugins at every start, relative to its
/// directory: the code itself, reviewed as the text it is.
const PLUGIN_FILES: &[&str] = &["plugin/*.js", "plugin/*.ts", "plugins/*.js", "plugins/*.ts"];

/// The configuration files and plugin files of `dirs`.
pub(super) fn collect(scope: &Scope<'_>, dirs: &Dirs, found: &mut Found) {
    let files = CONFIG_FILES
        .iter()
        .map(|name| format!("{}/{name}", dirs.opencode))
        .chain(dirs.opencode_config.clone());
    for file in files {
        config_file(scope, &file, found);
    }
    for pattern in PLUGIN_FILES {
        let pattern = format!("{}/{pattern}", dirs.opencode);
        let matches = read::matching(scope.root, &pattern);
        if matches.truncated {
            found.unchecked(&pattern, "more files than were looked at");
        }
        found
            .unchecked
            .extend(matches.unnamed.iter().map(|name| collect::not_utf8(name)));
        for directory in &matches.unreadable {
            found.unchecked(directory, "could not be listed");
        }
        for path in matches.files {
            found
                .items
                .push(collect::item(scope, Category::Agent, path, None));
        }
    }
}

/// The servers (`mcp`) and plugins (`plugin`) of one configuration file. A
/// plugin is a package OpenCode installs from npm, or a file it loads
/// (`file://`), which is followed and reviewed like a program.
fn config_file(scope: &Scope<'_>, file: &str, found: &mut Found) {
    let Some(json) = read_json(scope, file, found) else {
        return;
    };
    let mut entries = Vec::new();
    if let Some(servers) = json.get("mcp") {
        server_entries(servers, "mcp/", &mut entries);
    }
    let plugins = json.get("plugin").and_then(Json::as_array);
    for (index, plugin) in plugins.unwrap_or_default().iter().enumerate() {
        let Some(plugin) = plugin.as_str() else {
            continue;
        };
        let launch = match plugin.strip_prefix("file://") {
            Some(path) => Launch::Command(quoted(path)),
            None => Launch::Package(plugin.to_string()),
        };
        entries.push(Entry {
            key: format!("plugin/{index}"),
            launch,
            variables: Vec::new(),
        });
    }
    add(scope, &Source::of(file), entries, found);
}
