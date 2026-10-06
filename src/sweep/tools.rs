//! Local checks of the settings of developer tools: package managers,
//! `curl`, `wget` and an editor's `settings.json`. These files hold
//! registry tokens and proxy passwords, so they are never sent to the AI
//! (see `judge::is_local_only`); what in them makes a tool run a program,
//! load code, send its traffic through somebody else or stop checking
//! certificates is told here, by key. A value is never shown: only the key,
//! and the host of an address.

mod editor;

pub use editor::editor;

use super::config::{host, is_usual, key_value};
use crate::paths::file_name;
use crate::tomlish;

#[cfg(test)]
use editor::NOT_SETTINGS;

/// How what is seen ends when the value is a path in a temporary or cache
/// directory, where downloads land and anyone's program may write.
pub const FROM_TEMPORARY: &str = " (in a temporary or cache directory)";

/// How what is seen ends when an address is plain HTTP: whoever is on the
/// way can change what is fetched.
pub const CLEARTEXT: &str = " (over unencrypted HTTP)";

/// The most alerts kept for one file.
const MAX_ALERTS: usize = 20;

/// Environment variables that load code into, or change the programs of,
/// whatever is started with them.
const LOADING_VARIABLES: &[&str] = &[
    "LD_PRELOAD",
    "LD_AUDIT",
    "LD_LIBRARY_PATH",
    "PATH",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PERL5OPT",
    "PERL5LIB",
    "RUBYOPT",
    "RUBYLIB",
    "BASH_ENV",
    "ENV",
    "PROMPT_COMMAND",
    "ZDOTDIR",
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTDOC",
    "RUSTFLAGS",
    "CC",
    "CXX",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_ASKPASS",
    "GIT_EXEC_PATH",
    "SSH_ASKPASS",
    "SUDO_ASKPASS",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "EDITOR",
    "VISUAL",
    "PAGER",
];

/// The variables among them whose value is the program to run: a compiler
/// by its name, or one of the system's by its path, is how these are set
/// on any developer's machine.
const PROGRAM_VARIABLES: &[&str] = &[
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTDOC",
    "CC",
    "CXX",
    "GIT_SSH",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
    "SUDO_ASKPASS",
    "EDITOR",
    "VISUAL",
    "PAGER",
];

/// Where the distribution keeps the certificate authorities, in files only
/// root writes: naming one of them picks no authority of the file's own.
const SYSTEM_AUTHORITIES: &[&str] = &[
    "/etc/ssl/",
    "/etc/ca-certificates/",
    "/usr/share/ca-certificates/",
];

/// The hosts Go modules, which are named by where they live, mostly come
/// from: leaving one of them unchecked leaves most modules unchecked.
const MODULE_HOSTS: &[&str] = &[
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "golang.org",
    "google.golang.org",
    "gopkg.in",
    "k8s.io",
];

/// Whose settings a file holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tool {
    Npm,
    Yarn,
    Bun,
    Pip,
    Cargo,
    Go,
    Gem,
    Conda,
    Wget,
    Curl,
}

fn tool(path: &str) -> Option<Tool> {
    let name = file_name(path);
    Some(match name {
        "npmrc" | ".npmrc" => Tool::Npm,
        ".yarnrc" | ".yarnrc.yml" => Tool::Yarn,
        ".bunfig.toml" | "bunfig.toml" => Tool::Bun,
        "pip.conf" | ".pydistutils.cfg" => Tool::Pip,
        "config.toml" | "config" if path.contains(".cargo/") => Tool::Cargo,
        "env" if path.ends_with("go/env") => Tool::Go,
        ".gemrc" => Tool::Gem,
        ".condarc" => Tool::Conda,
        ".wgetrc" | "wgetrc" => Tool::Wget,
        ".curlrc" => Tool::Curl,
        _ => return None,
    })
}

/// A value without the quotes, brackets and commas its file wraps it in.
fn bare(value: &str) -> &str {
    value
        .trim()
        .trim_end_matches(',')
        .trim_matches(['"', '\'', '[', ']'])
        .trim()
}

/// Whether `value` names a path in a temporary or cache directory.
pub fn is_temporary(value: &str) -> bool {
    let from_root = |directory: &str| {
        value.match_indices(directory).any(|(at, _)| {
            !value[..at].ends_with(|c: char| {
                c.is_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '~' | '}')
            })
        })
    };
    value.contains("/.cache/")
        || ["/tmp/", "/var/tmp/", "/dev/shm/"]
            .into_iter()
            .any(from_root)
}

/// Whether `value` holds a plain HTTP address of another machine.
fn is_cleartext(value: &str) -> bool {
    value.match_indices("http://").any(|(at, _)| {
        let rest = &value[at + "http://".len()..];
        let authority = rest
            .split(['/', '"', '\'', ' ', ','])
            .next()
            .unwrap_or_default();
        let host = authority.rsplit('@').next().unwrap_or_default();
        !["localhost", "127.0.0.1", "[::1]"]
            .iter()
            .any(|local| host == *local || host.starts_with(&format!("{local}:")))
    })
}

/// `what`, with how serious the value makes it.
fn graded(what: String, value: &str) -> String {
    if is_temporary(value) {
        format!("{what}{FROM_TEMPORARY}")
    } else if is_cleartext(value) {
        format!("{what}{CLEARTEXT}")
    } else {
        what
    }
}

fn is_off(value: &str) -> bool {
    matches!(
        bare(value).to_ascii_lowercase().as_str(),
        "false" | "0" | "off" | "no" | "none"
    )
}

/// A program named by its path anywhere but the system's own directories:
/// a bare name is looked up like any command, and what a package installed
/// is that package's to vouch for.
fn is_own_program(value: &str) -> bool {
    let program = bare(value);
    let program = program.split_whitespace().next().unwrap_or_default();
    let system = ["/usr/", "/bin/", "/opt/"]
        .iter()
        .any(|system| program.starts_with(system));
    (program.contains('/') && !system) || is_temporary(value)
}

/// Whether setting the variable `name` to `value` changes what runs or is
/// loaded: any of `LOADING_VARIABLES`, except one that names a program and
/// names a system one.
fn sets_what_runs(name: &str, value: &str) -> bool {
    let name = name.to_ascii_uppercase();
    if PROGRAM_VARIABLES.contains(&name.as_str()) {
        return is_own_program(value);
    }
    LOADING_VARIABLES.contains(&name.as_str()) || name.starts_with("GIT_CONFIG")
}

fn runs(key: &str, value: &str) -> String {
    graded(
        format!("{key}: the tool runs a program of this file's choosing"),
        value,
    )
}

fn proxied(key: &str, value: &str) -> String {
    let through = host(bare(value)).map_or_else(String::new, |host| format!(" ({host})"));
    graded(
        format!("{key}: its traffic goes through a proxy{through}"),
        value,
    )
}

/// What naming the certificate authorities does; nothing when they are the
/// system's own.
fn authorities(key: &str, value: &str) -> Option<String> {
    if is_off(value) {
        return Some(unchecked(key));
    }
    let file = bare(value);
    if !file.contains("..")
        && SYSTEM_AUTHORITIES
            .iter()
            .any(|system| file.starts_with(system))
    {
        return None;
    }
    Some(graded(
        format!("{key}: certificates are checked against authorities of this file's choosing"),
        value,
    ))
}

fn unchecked(key: &str) -> String {
    format!("{key}: certificates are not checked")
}

/// The hosts of the addresses in `value` that are not a usual registry.
/// Only what is written as an address counts: a token beside it is never
/// taken for a host.
fn fetched(value: &str) -> Option<String> {
    fetched_where(value, &|host, entry| !is_usual(host) || is_cleartext(entry))
}

/// A Python package index is set to a company's own, or to a project's
/// (the wheels of `PyTorch`), on many machines, so a host is told only when the
/// address itself is odd: plain HTTP, a bare address, a name made to read
/// as another, or a place data is dropped off.
fn index(value: &str) -> Option<String> {
    fetched_where(value, &|host, entry| {
        is_cleartext(entry)
            || host == IPV6
            || crate::rules::is_ip_host(host)
            || host.split('.').any(|label| label.starts_with("xn--"))
            || !crate::rules::host_concerns(entry).is_empty()
    })
}

/// What stands for the host of an address in brackets (`https://[::1]/`).
const IPV6: &str = "an IPv6 address";

/// `fetched`, for the addresses `is_odd` (asked with the host and the
/// address) picks.
fn fetched_where(value: &str, is_odd: &dyn Fn(&str, &str) -> bool) -> Option<String> {
    let odd: Vec<String> = value
        .split([',', '|', ' ', '{', '}', '='])
        .map(|entry| entry.trim_matches(['"', '\'']))
        .filter(|entry| entry.contains("://"))
        .filter_map(|entry| {
            if entry.contains("://[") {
                return Some((IPV6.to_string(), entry));
            }
            let entry = entry.trim_matches(['[', ']']);
            host(entry).map(|host| (host, entry))
        })
        .filter(|(host, entry)| is_odd(host, entry))
        .map(|(host, _)| host)
        .collect();
    (!odd.is_empty()).then(|| {
        graded(
            format!("packages are fetched from {}", odd.join(", ")),
            value,
        )
    })
}

fn npm(key: &str, value: &str) -> Option<String> {
    // A registry's own credentials (`//host/:_authToken=`).
    if key.starts_with("//") {
        return None;
    }
    match key {
        "registry" => fetched(value),
        _ if key.ends_with(":registry") => fetched(value),
        "script-shell" | "shell" | "git" => Some(runs(key, value)),
        "node-options" | "node_options"
            if [
                "--require",
                "-r ",
                "--import",
                "--loader",
                "--experimental-loader",
                "--inspect",
            ]
            .iter()
            .any(|option| value.contains(option)) =>
        {
            Some(graded(
                format!(
                    "{key}: code of this file's choosing is loaded into every Node.js it starts"
                ),
                value,
            ))
        }
        "onload-script" | "init-module" => Some(graded(
            format!("{key}: a script of this file's choosing is loaded"),
            value,
        )),
        "proxy" | "https-proxy" | "http-proxy" => Some(proxied(key, value)),
        "cafile" | "ca" if !matches!(bare(value), "null" | "") => authorities(key, value),
        "strict-ssl" if is_off(value) => Some(unchecked(key)),
        "globalconfig" | "userconfig" => Some(graded(
            format!("{key}: its settings are read from another file"),
            value,
        )),
        "prefix" if is_temporary(value) => {
            Some(format!("{key}: programs are installed{FROM_TEMPORARY}"))
        }
        // `~/.cache/npm` is a tidy home; a world-writable directory is not.
        "cache" if is_temporary(&value.replace("/.cache/", "/")) => {
            Some(format!("{key}: packages are kept{FROM_TEMPORARY}"))
        }
        _ => None,
    }
}

fn yarn(key: &str, value: &str) -> Option<String> {
    let compact: String = key.chars().filter(|c| !matches!(c, '-' | '_')).collect();
    match compact.as_str() {
        "registry" | "npmregistryserver" => fetched(value),
        "yarnpath" => Some(graded(
            format!("{key}: every yarn command runs a script of this file's choosing"),
            value,
        )),
        "plugins" => Some(format!("{key}: plugins are loaded into every yarn command")),
        "httpproxy" | "httpsproxy" | "proxy" => Some(proxied(key, value)),
        "cafilepath" | "cafile" | "httpscafilepath" => authorities(key, value),
        "enablestrictssl" | "strictssl" if is_off(value) => Some(unchecked(key)),
        "unsafehttpwhitelist" => Some(format!(
            "{key}: packages may be fetched over unencrypted HTTP"
        )),
        _ => None,
    }
}

fn bun(section: &str, key: &str, value: &str) -> Option<String> {
    match (section, key) {
        (_, "preload") if !matches!(bare(value), "") => Some(graded(
            format!("{key}: scripts of this file's choosing are loaded into every bun run"),
            value,
        )),
        ("install", "registry") | ("install.scopes", _) => fetched(value),
        ("install", "cafile" | "ca") => authorities(key, value),
        // `shell` picks one of bun's two shells and `bun` is a switch;
        // anything else there is not theirs.
        ("run", "shell" | "bun") if !matches!(bare(value), "system" | "bun" | "true" | "false") => {
            Some(runs(key, value))
        }
        _ => None,
    }
}

fn pip(key: &str, value: &str) -> Option<String> {
    match key {
        "index-url" | "extra-index-url" | "index_url" => index(value),
        "find-links" | "find_links" => fetched(value).or_else(|| {
            (!value.contains("://")).then(|| {
                graded(
                    format!("{key}: packages are taken from a directory of this file's choosing"),
                    value,
                )
            })
        }),
        "trusted-host" => Some(format!("{key}: a host's certificate is not checked")),
        "proxy" => Some(proxied(key, value)),
        "cert" | "client-cert" => authorities(key, value),
        _ => None,
    }
}

/// Whether a `GOPRIVATE` or `GONOSUMDB` pattern leaves most modules
/// unchecked: everything, a whole top-level domain, or a host most modules
/// live on.
fn is_wide(pattern: &str) -> bool {
    let pattern = pattern.trim();
    let host = pattern.split('/').next().unwrap_or_default();
    let labels = host
        .trim_start_matches("*.")
        .split('.')
        .filter(|label| !label.is_empty() && *label != "*")
        .count();
    labels < 2 || (MODULE_HOSTS.contains(&host) && !pattern.contains('/'))
}

fn go(key: &str, value: &str) -> Option<String> {
    let said = |what: &str| Some(format!("{key}: {what}"));
    let plain = bare(value);
    match key {
        "goproxy" => fetched(value),
        "goflags" if value.contains("-toolexec") || value.contains("-overlay") => {
            said("every Go build runs through a program of its choosing")
        }
        "goinsecure" | "gonosumcheck" => said("Go modules are fetched without the usual checks"),
        "gosumdb" if plain != "sum.golang.org" => {
            said("Go modules are fetched without the usual checks")
        }
        "gonosumdb" | "goprivate" | "gonoproxy" if plain.split(',').any(is_wide) => {
            said("most Go modules are fetched without the usual checks")
        }
        "cc" | "cxx" | "ar" | "pkg_config"
            if !matches!(
                plain,
                "gcc" | "g++" | "cc" | "c++" | "clang" | "clang++" | "ar" | "pkg-config"
            ) =>
        {
            Some(runs(key, value))
        }
        // `netrc`, `git` and `off` are Go's own; anything else is a command.
        "goauth"
            if !plain.split(';').all(|way| {
                matches!(
                    way.split_whitespace().next(),
                    Some("netrc" | "git" | "off") | None
                )
            }) =>
        {
            Some(runs(key, value))
        }
        "gobin" if is_temporary(&format!("{plain}/")) => {
            Some(format!("{key}: Go installs programs{FROM_TEMPORARY}"))
        }
        _ => None,
    }
}

fn cargo(section: &str, key: &str, value: &str) -> Option<String> {
    let said = |what: &str| Some(format!("{key}: {what}"));
    match (section, key) {
        (_, "registry" | "index") => fetched(value),
        (_, "replace-with") => said("crates come from another source"),
        ("http", "proxy") => Some(proxied(key, value)),
        ("http", "cainfo") => authorities(key, value),
        ("http", "check-revoke") if is_off(value) => Some(unchecked(key)),
        // `[env.NAME]` with `value = "x"` is `NAME = "x"` under `[env]`.
        (_, "value")
            if section
                .strip_prefix("env.")
                .is_some_and(|name| sets_what_runs(name, value)) =>
        {
            let name = section.strip_prefix("env.").unwrap_or(section);
            Some(graded(
                format!("{name}: set for every program cargo runs"),
                value,
            ))
        }
        ("env", _) if sets_what_runs(key, &table_value(value)) => Some(graded(
            format!("{key}: set for every program cargo runs"),
            value,
        )),
        (
            _,
            "rustc" | "rustdoc" | "rustc-wrapper" | "rustc-workspace-wrapper" | "linker" | "runner",
        ) if is_own_program(value) => Some(graded(
            format!("{key}: every build runs a program outside the system's directories"),
            value,
        )),
        // The linker named in the flags is judged like the `linker` key.
        (_, "rustflags")
            if flag_values(value, "linker=").any(is_own_program)
                || value.contains("-Zpre-link")
                || value.contains("--sysroot") =>
        {
            Some(graded(
                format!("{key}: every build links through a program of this file's choosing"),
                value,
            ))
        }
        (_, "credential-provider" | "global-credential-providers")
            if value.split(['"', '\'']).any(|word| {
                !word.trim_matches(['[', ']', ',', ' ']).is_empty()
                    && !word.starts_with("cargo:")
                    && word.chars().any(char::is_alphanumeric)
            }) =>
        {
            Some(graded(
                format!("{key}: a program of this file's choosing is handed the registry token"),
                value,
            ))
        }
        ("alias", _) if value.contains("--config") => {
            said("an alias passes settings of its own to cargo")
        }
        (_, "paths") => Some(graded(
            format!("{key}: dependencies are replaced by local copies"),
            value,
        )),
        _ if section.starts_with("patch") => Some(graded(
            format!("{key}: this crate is replaced in every build"),
            value,
        )),
        _ => None,
    }
}

/// The value of a cargo `[env]` entry, which may be a table
/// (`{ value = "x", force = true }`).
fn table_value(value: &str) -> String {
    if !value.trim_start().starts_with('{') {
        return value.to_string();
    }
    inline_members(value.trim())
        .into_iter()
        .find(|(path, _)| path.len() == 1 && path[0] == "value")
        .map_or_else(|| value.to_string(), |(_, inner)| inner)
}

/// What follows each `flag` in a list of compiler flags, up to the end of
/// its word.
fn flag_values<'a>(value: &'a str, flag: &'a str) -> impl Iterator<Item = &'a str> {
    value.match_indices(flag).map(move |(at, _)| {
        let rest = &value[at + flag.len()..];
        let end = rest
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ']'))
            .unwrap_or(rest.len());
        &rest[..end]
    })
}

fn gem(line: &str, key: &str, value: &str) -> Option<String> {
    let key = key.trim_matches(':');
    match key {
        "http_proxy" | "https_proxy" | "http-proxy" => Some(proxied(key, value)),
        "ssl_verify_mode" if bare(value) == "0" => Some(unchecked(key)),
        "ssl_ca_cert" | "ssl_client_cert" => authorities(key, value),
        // A source is a list entry (`- https://…`) or an option of the
        // `gem:` line; either way it is an address on the line.
        _ if line.contains("--http-proxy") || line.contains(" -p ") => Some(proxied("gem", line)),
        _ => fetched(line),
    }
}

fn conda(line: &str, key: &str, value: &str) -> Option<String> {
    match key {
        "ssl_verify" | "verify_ssl" if is_off(value) => Some(unchecked(key)),
        "ssl_verify" | "client_ssl_cert" | "client_ssl_cert_key"
            if !matches!(
                bare(value).to_ascii_lowercase().as_str(),
                "true" | "yes" | "on" | "1" | "truststore"
            ) =>
        {
            authorities(key, value)
        }
        "proxy_servers" => Some(format!("{key}: its traffic goes through a proxy")),
        "http" | "https" if value.contains("://") => Some(proxied(key, value)),
        _ => fetched(line),
    }
}

fn wget(key: &str, value: &str) -> Option<String> {
    let key = key.replace('-', "_");
    match key.as_str() {
        "check_certificate" if is_off(value) => Some(unchecked(&key)),
        "http_proxy" | "https_proxy" | "ftp_proxy" => Some(proxied(&key, value)),
        "ca_certificate" | "ca_directory" | "certificate" => authorities(&key, value),
        "use_askpass" => Some(runs(&key, value)),
        "output_document" | "post_file" | "body_file" | "load_cookies" => Some(graded(
            format!("{key}: every wget reads or writes a file of this file's choosing"),
            value,
        )),
        _ => None,
    }
}

/// One line of a `.curlrc`: an option with or without its dashes, and a
/// value after a space, `=` or `:`.
fn curl(line: &str) -> Option<String> {
    let line = line.trim();
    let short = line.starts_with('-') && !line.starts_with("--");
    let option = line.trim_start_matches('-');
    let at = option.find([' ', '\t', '=', ':']).unwrap_or(option.len());
    let (key, value) = option.split_at(at);
    let value = value.trim_start_matches([' ', '\t', '=', ':']);
    let key = match (short, key) {
        (true, "k") => "insecure",
        (true, "x") => "proxy",
        (true, "o") => "output",
        (true, "K") => "config",
        (true, "E") => "cert",
        (true, _) => return None,
        (false, key) => key,
    };
    match key {
        "insecure" | "proxy-insecure" | "doh-insecure" | "ssl-no-revoke" => Some(unchecked(key)),
        "proxy" | "preproxy" | "socks4" | "socks4a" | "socks5" | "socks5-hostname" => {
            Some(proxied(key, value))
        }
        "cacert" | "capath" | "proxy-cacert" | "pinnedpubkey" | "cert" => authorities(key, value),
        "resolve" | "connect-to" | "doh-url" | "dns-servers" => {
            Some(format!("{key}: host names lead where this file says"))
        }
        "output" | "trace" | "trace-ascii" | "dump-header" | "cookie-jar" | "config"
        | "netrc-file" | "upload-file" | "data" => Some(graded(
            format!("{key}: every curl reads or writes a file of this file's choosing"),
            value,
        )),
        _ => None,
    }
}

/// The key and value of a line; a key that opens a list or a table
/// (`plugins:`) has an empty value.
fn pair(line: &str) -> Option<(String, &str)> {
    // A gem setting is a YAML symbol (`:http_proxy: x`).
    let line = line.strip_prefix(':').unwrap_or(line);
    if let Some(key) = line.strip_suffix(':') {
        let key = key.trim().trim_matches(['"', '\'']);
        return (!key.is_empty() && !key.contains(char::is_whitespace))
            .then(|| (key.to_ascii_lowercase(), ""));
    }
    let (key, value) = key_value(line)?;
    let key = key.to_ascii_lowercase();
    Some((key.trim_start_matches("--").to_string(), value))
}

/// What is said of a TOML file that cannot be read as one.
const NOT_TOML: &str =
    "the file cannot be read as TOML from here on: only keys that start a line were checked";

/// How deep inline tables are looked into.
const MAX_INLINE_DEPTH: usize = 8;

/// What the TOML entry at `path` (its tables, then its key) does, at
/// `line`. An inline table that says nothing as a whole is looked into:
/// `build = { rustc-wrapper = "/x" }` is `build.rustc-wrapper = "/x"`.
fn toml_entry(
    tool: Tool,
    path: &[String],
    value: &str,
    (line, depth): (usize, usize),
    found: &mut Vec<(usize, String)>,
) {
    let Some((key, tables)) = path.split_last() else {
        return;
    };
    let section = tables.join(".");
    let seen = if tool == Tool::Bun {
        bun(&section, key, value)
    } else {
        cargo(&section, key, value)
    };
    if let Some(seen) = seen {
        found.push((line, seen));
    } else if depth < MAX_INLINE_DEPTH && value.starts_with('{') {
        for (inner, value) in inline_members(value) {
            let path: Vec<String> = path.iter().cloned().chain(inner).collect();
            toml_entry(tool, &path, &value, (line, depth + 1), found);
        }
    }
}

/// The keys of an inline table (`{ a = 1, b.c = "x" }`), each as its path
/// in lower case, with its value.
fn inline_members(table: &str) -> Vec<(Vec<String>, String)> {
    let inner = table
        .strip_prefix('{')
        .and_then(|rest| rest.strip_suffix('}'))
        .unwrap_or_default();
    // Split at the commas that are in no string and no table or array of
    // the table's own.
    let mut members = Vec::new();
    let mut start = 0;
    let mut depth = 0_usize;
    let mut quote = None;
    let mut escaped = false;
    for (at, character) in inner.char_indices() {
        match (quote, character) {
            _ if escaped => escaped = false,
            (Some('"'), '\\') => escaped = true,
            (Some(open), _) if character == open => quote = None,
            (None, '"' | '\'') => quote = Some(character),
            (None, '{' | '[') => depth += 1,
            (None, '}' | ']') => depth = depth.saturating_sub(1),
            (None, ',') if depth == 0 => {
                members.push(&inner[start..at]);
                start = at + 1;
            }
            // Inside a string, or nothing that splits.
            _ => {}
        }
    }
    members.push(&inner[start..]);
    members
        .into_iter()
        .filter_map(|member| tomlish::entries(member).ok()?.into_iter().next())
        .map(|entry| {
            let path = entry.key.iter().map(|part| part.to_ascii_lowercase());
            (path.collect(), entry.value)
        })
        .collect()
}

/// What the settings of a developer tool at `path` do that is worth
/// seeing, each with its line; nothing for a file of no known tool.
pub fn alerts(path: &str, text: &str) -> Vec<(usize, String)> {
    let Some(tool) = tool(path) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    // TOML is read by key, wherever on a line and however it is written
    // (`build.rustc-wrapper = …`, `build = { rustc-wrapper = … }`).
    if matches!(tool, Tool::Cargo | Tool::Bun) {
        // A byte order mark is no part of the first key.
        match tomlish::entries(text.trim_start_matches('\u{feff}')) {
            Ok(entries) => {
                for entry in &entries {
                    let path: Vec<String> = entry
                        .full_path()
                        .iter()
                        .map(|part| part.to_ascii_lowercase())
                        .collect();
                    toml_entry(tool, &path, &entry.value, (entry.line, 0), &mut found);
                }
                found.truncate(MAX_ALERTS);
                return found;
            }
            // Read line by line then, as far as that goes, and said.
            Err(error) => found.push((error.line(), NOT_TOML.to_string())),
        }
    }
    let mut section = String::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            && !matches!(tool, Tool::Gem | Tool::Conda | Tool::Yarn)
        {
            section = name.trim_matches(['[', ']', ' ']).to_ascii_lowercase();
            continue;
        }
        let seen = if tool == Tool::Curl {
            curl(line)
        } else {
            let pair = pair(line);
            let (key, value) = pair
                .as_ref()
                .map_or(("", ""), |(key, value)| (key.as_str(), *value));
            match tool {
                Tool::Gem => gem(line, key, value),
                Tool::Conda => conda(line, key, value),
                _ if key.is_empty() => None,
                Tool::Npm => npm(key, value),
                Tool::Yarn => yarn(key, value),
                Tool::Bun => bun(&section, key, value),
                Tool::Pip => pip(key, value),
                Tool::Go => go(key, value),
                Tool::Cargo => cargo(&section, key, value),
                Tool::Wget => wget(key, value),
                Tool::Curl => None,
            }
        };
        if let Some(seen) = seen
            && found.len() < MAX_ALERTS
        {
            found.push((index + 1, seen));
        }
    }
    found
}

#[cfg(test)]
mod tests;
