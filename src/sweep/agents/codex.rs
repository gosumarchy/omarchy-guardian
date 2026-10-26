//! Codex: the MCP servers of its `config.toml`, and the program it runs
//! when a turn ends (`notify`).

use std::collections::BTreeMap;

use super::{Entries, Entry, Found, Launch, Server, Source, add, command_line, key_part, read};
use crate::sweep::collect::Scope;
use crate::tomlish::{self, Value};

/// The deepest key path an inline table is opened to: past a server's
/// variables (`mcp_servers.x.env.NAME`) nothing is read. Arbitrary, and
/// keeps a file of tables in tables from going deeper than the stack.
const MAX_DEPTH: usize = 8;

/// The entries of `config.toml` in the directory `codex`.
pub(super) fn collect(scope: &Scope<'_>, codex: &str, found: &mut Found) {
    let file = format!("{codex}/config.toml");
    let Some(text) = read(scope, &file, found) else {
        return;
    };
    let parsed = match tomlish::entries(&text) {
        Ok(parsed) => parsed,
        Err(error) => {
            found.unchecked(&file, &format!("not TOML Guardian can read ({error})"));
            return;
        }
    };
    let mut flat = Vec::new();
    for entry in &parsed {
        let path: Vec<String> = entry.full_path().into_iter().map(str::to_string).collect();
        flatten(path, &entry.value, &mut flat);
    }
    let mut entries = Entries::default();
    let mut servers: BTreeMap<&str, Server> = BTreeMap::new();
    for (path, raw) in &flat {
        let path: Vec<&str> = path.iter().map(String::as_str).collect();
        match path.as_slice() {
            ["notify"] => notify_entry(raw, &mut entries),
            ["mcp_servers", name, "env", variable, ..] => {
                let server = servers.entry(name).or_default();
                server.variables.push((*variable).to_string());
            }
            ["mcp_servers", name, field] => {
                server_field(servers.entry(name).or_default(), field, raw);
            }
            ["mcp_servers"] => entries.unread("mcp_servers", "table of servers"),
            ["mcp_servers", name] => entries.unread(&key(name), "table"),
            _ => {}
        }
    }
    for (name, server) in servers {
        server.add_to(&key(name), &mut entries);
    }
    add(scope, &Source::of(&file), entries, found);
}

fn key(name: &str) -> String {
    format!("mcp_servers/{}", key_part(name))
}

/// Adds `path = raw` to `flat`, with an inline table under `mcp_servers`
/// opened to its entries (`x = { command = "y" }` is `x.command = "y"`), as
/// Codex reads both forms the same. A table that cannot be opened stays as
/// it is written, where it is a value no field takes and is said as not
/// checked.
fn flatten(path: Vec<String>, raw: &str, flat: &mut Vec<(Vec<String>, String)>) {
    let opened = (path.first().is_some_and(|first| first == "mcp_servers")
        && path.len() < MAX_DEPTH)
        .then(|| tomlish::inline_table_entries(raw))
        .flatten();
    let Some(inner) = opened else {
        flat.push((path, raw.to_string()));
        return;
    };
    for (key, value) in inner {
        let mut path = path.clone();
        path.extend(key);
        flatten(path, &value, flat);
    }
}

/// The program Codex runs when a turn ends, as a list of words.
fn notify_entry(raw: &str, entries: &mut Entries) {
    let Some(Value::StringArray(words)) = tomlish::typed_value(raw) else {
        return entries.unread("notify", "command");
    };
    if let Some((program, args)) = words.split_first() {
        entries.push(Entry {
            key: "notify".into(),
            launch: Launch::Command(command_line(program, args)),
            variables: Vec::new(),
        });
    }
}

/// Takes in one field of a server's table: its program, arguments or
/// address; one of these that is not what it should be is said as not
/// checked. Its other fields (timeouts, tools, the names of the variables
/// it passes on) start nothing.
fn server_field(server: &mut Server, field: &str, raw: &str) {
    match (field, tomlish::typed_value(raw)) {
        ("command", Some(Value::String(command))) => server.command = Some(command),
        ("args", Some(Value::StringArray(args))) => server.args = args,
        ("url", Some(Value::String(url))) => server.url = Some(url),
        ("command", _) => server.unread.push("command"),
        ("args", _) => server.unread.push("args"),
        ("url", _) => server.unread.push("url"),
        ("env", _) => server.unread.push("env"),
        _ => {}
    }
}
