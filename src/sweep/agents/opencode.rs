//! OpenCode: the MCP servers and plugins its configuration names, and the
//! plugin files in its plugin directories.

use super::entry::quoted;
use super::{Dirs, Entries, Entry, Found, Launch, Source, add, read_json, server_entries};
use crate::autorun::Category;
use crate::json::Json;
use crate::sweep::collect::{self, Scope};
use crate::sweep::read;

/// The configuration files of OpenCode's directory. It reads both.
const CONFIG_FILES: &[&str] = &["opencode.json", "opencode.jsonc"];

/// The files OpenCode loads as plugins at every start, relative to its
/// directory: the code itself, reviewed as the text it is.
const PLUGIN_FILES: &[&str] = &["plugin/*.js", "plugin/*.ts", "plugins/*.js", "plugins/*.ts"];

/// The configuration files and plugin files of `dirs`: its directory, the
/// one `OPENCODE_CONFIG_DIR` names, and the file `OPENCODE_CONFIG` names.
pub(super) fn collect(scope: &Scope<'_>, dirs: &Dirs, found: &mut Found) {
    let mut directories = vec![dirs.opencode.as_str()];
    directories.extend(
        dirs.opencode_extra
            .as_deref()
            .filter(|extra| *extra != dirs.opencode),
    );
    let mut files: Vec<String> = directories
        .iter()
        .flat_map(|directory| {
            CONFIG_FILES
                .iter()
                .map(move |name| format!("{directory}/{name}"))
        })
        .collect();
    // Read once, where it names a file read anyway: two items of one name
    // would be said as not checked.
    if let Some(config) = &dirs.opencode_config
        && !files.contains(config)
    {
        files.push(config.clone());
    }
    for file in &files {
        config_file(scope, file, found);
    }
    for directory in directories {
        plugin_files(scope, directory, found);
    }
}

/// The plugin files in `directory`, each an item of its own.
fn plugin_files(scope: &Scope<'_>, directory: &str, found: &mut Found) {
    for pattern in PLUGIN_FILES {
        let pattern = format!("{directory}/{pattern}");
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
    let mut entries = Entries::default();
    if let Some(servers) = json.get("mcp") {
        server_entries(servers, "mcp/", &mut entries);
    }
    let plugins = match json.get("plugin") {
        None => &[][..],
        Some(Json::Array(plugins)) => plugins,
        Some(_) => {
            entries.unread("plugin", "list");
            &[][..]
        }
    };
    for (index, plugin) in plugins.iter().enumerate() {
        let key = format!("plugin/{index}");
        let Some(plugin) = plugin.as_str() else {
            entries.unread(&key, "name");
            continue;
        };
        let launch = match plugin.strip_prefix("file://") {
            Some(path) => Launch::Command(quoted(path)),
            None => Launch::Package(plugin.to_string()),
        };
        entries.push(Entry {
            key,
            launch,
            variables: Vec::new(),
        });
    }
    add(scope, &Source::of(file), entries, found);
}
