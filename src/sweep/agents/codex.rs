//! Codex: the MCP servers of its `config.toml`, and the program it runs
//! when a turn ends (`notify`).

use std::collections::BTreeMap;

use super::{Entry, Found, Launch, Server, Source, add, command_line, key_part, read};
use crate::sweep::collect::Scope;
use crate::tomlish::{self, Value};

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
    let mut entries = Vec::new();
    let mut servers: BTreeMap<&str, Server> = BTreeMap::new();
    for entry in &parsed {
        match entry.full_path().as_slice() {
            ["notify"] => {
                if let Some(Value::StringArray(words)) = tomlish::typed_value(&entry.value)
                    && let Some((program, args)) = words.split_first()
                {
                    entries.push(Entry {
                        key: "notify".into(),
                        launch: Launch::Command(command_line(program, args)),
                        variables: Vec::new(),
                    });
                }
            }
            ["mcp_servers", name, field] => {
                let server = servers.entry(name).or_default();
                server_field(server, field, &entry.value);
            }
            ["mcp_servers", name, "env", variable] => {
                let server = servers.entry(name).or_default();
                server.variables.push((*variable).to_string());
            }
            _ => {}
        }
    }
    for (name, server) in servers {
        entries.extend(server.into_entry(format!("mcp_servers/{}", key_part(name))));
    }
    add(scope, &Source::of(&file), entries, found);
}

/// Takes in one field of a server's table: its program, arguments,
/// address, or the names of its variables (`env = { A = "x" }`).
fn server_field(server: &mut Server, field: &str, raw: &str) {
    match (field, tomlish::typed_value(raw)) {
        ("command", Some(Value::String(command))) => server.command = Some(command),
        ("args", Some(Value::StringArray(args))) => server.args = args,
        ("url", Some(Value::String(url))) => server.url = Some(url),
        ("env", _) => server
            .variables
            .extend(tomlish::inline_table_keys(raw).unwrap_or_default()),
        _ => {}
    }
}
