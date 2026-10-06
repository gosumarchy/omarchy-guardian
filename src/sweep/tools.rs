//! Local checks of the settings of developer tools: package managers,
//! `curl`, `wget` and an editor's `settings.json`. These files hold
//! registry tokens and proxy passwords, so they are never sent to the AI
//! (see `judge::is_local_only`); what in them makes a tool run a program,
//! load code, send its traffic through somebody else or stop checking
//! certificates is told here, by key. A value is never shown: only the key,
//! and the host of an address.

use super::config::{host, is_usual, key_value};
use crate::tomlish;

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

/// Where tools keep the Python environments they make, below a home's
/// cache and data directories: an interpreter there is the ordinary one of
/// a project, not a download.
const VIRTUALENVS: &[&str] = &[
    "/.cache/pypoetry/virtualenvs/",
    "/.cache/uv/",
    "/.cache/pre-commit/",
    "/.local/share/virtualenvs/",
    "/.venv/",
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
    let name = path.rsplit('/').next().unwrap_or(path);
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

/// One key of an editor's settings, wherever on a line it stands.
struct Member {
    /// The key, with its escapes read.
    key: String,
    /// The line the key is on.
    line: usize,
    /// The value on one line, as the checks read it: strings in quotes
    /// with their escapes read, no comments, no blanks between the parts.
    value: String,
    /// The keys of the tables the value holds, at whatever depth of lists.
    inside: Vec<Member>,
}

/// How deep the tables and lists of an editor's settings may go.
const MAX_SETTINGS_DEPTH: usize = 64;

/// Reads an editor's settings the way editors do: JSON with `//` and
/// `/* */` comments and a comma allowed after the last entry. Unlike them
/// it does not read on past what it cannot make out: a file an editor
/// would load in part is not one whose keys were all seen.
struct Settings<'a> {
    bytes: &'a [u8],
    at: usize,
    line: usize,
}

impl Settings<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    /// Skips blanks and comments; `None` for a comment that never ends.
    fn blank(&mut self) -> Option<()> {
        loop {
            match (self.peek(), self.bytes.get(self.at + 1).copied()) {
                (Some(b'\n'), _) => {
                    self.line += 1;
                    self.at += 1;
                }
                (Some(b' ' | b'\t' | b'\r'), _) => self.at += 1,
                (Some(b'/'), Some(b'/')) => {
                    // An editor ends the comment at a lone `\r` too.
                    while self
                        .peek()
                        .is_some_and(|byte| !matches!(byte, b'\n' | b'\r'))
                    {
                        self.at += 1;
                    }
                }
                (Some(b'/'), Some(b'*')) => {
                    self.at += 2;
                    while !self.bytes[self.at.min(self.bytes.len())..].starts_with(b"*/") {
                        if self.peek()? == b'\n' {
                            self.line += 1;
                        }
                        self.at += 1;
                    }
                    self.at += 2;
                }
                _ => return Some(()),
            }
        }
    }

    /// A string, from its opening quote, with its escapes read.
    fn string(&mut self) -> Option<String> {
        let mut read = Vec::new();
        self.at += 1;
        loop {
            let byte = self.peek()?;
            self.at += 1;
            match byte {
                b'"' => return Some(String::from_utf8_lossy(&read).into_owned()),
                b'\n' | b'\r' => return None,
                b'\\' => {
                    let escape = self.peek()?;
                    self.at += 1;
                    let character = match escape {
                        b'"' | b'\\' | b'/' => char::from(escape),
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => self.escaped()?,
                        _ => return None,
                    };
                    read.extend(character.encode_utf8(&mut [0; 4]).as_bytes());
                }
                byte => read.push(byte),
            }
        }
    }

    /// The four hex digits after `\u`.
    fn unit(&mut self) -> Option<u32> {
        // Digits only: `from_str_radix` would also take a sign.
        let digits = self
            .bytes
            .get(self.at..self.at + 4)
            .filter(|digits| digits.iter().all(u8::is_ascii_hexdigit))?;
        let unit = u32::from_str_radix(std::str::from_utf8(digits).ok()?, 16).ok()?;
        self.at += 4;
        Some(unit)
    }

    /// The character of a `\u` escape, or of the two that make one; a
    /// half without its other half is the replacement character.
    fn escaped(&mut self) -> Option<char> {
        let first = self.unit()?;
        if (0xd800..0xdc00).contains(&first) && self.bytes[self.at..].starts_with(b"\\u") {
            let back = self.at;
            self.at += 2;
            let second = self.unit()?;
            if (0xdc00..0xe000).contains(&second) {
                let joined = 0x1_0000 + ((first - 0xd800) << 10) + (second - 0xdc00);
                return Some(char::from_u32(joined).unwrap_or(char::REPLACEMENT_CHARACTER));
            }
            self.at = back;
        }
        Some(char::from_u32(first).unwrap_or(char::REPLACEMENT_CHARACTER))
    }

    /// Reads one value: its text is added to `text`, and the keys of the
    /// tables in it to `inside`.
    fn value(&mut self, depth: usize, text: &mut String, inside: &mut Vec<Member>) -> Option<()> {
        if depth > MAX_SETTINGS_DEPTH {
            return None;
        }
        self.blank()?;
        match self.peek()? {
            open @ (b'{' | b'[') => {
                let close = if open == b'{' { b'}' } else { b']' };
                self.at += 1;
                text.push(char::from(open));
                loop {
                    self.blank()?;
                    if self.peek()? == close {
                        self.at += 1;
                        text.push(char::from(close));
                        return Some(());
                    }
                    if open == b'{' {
                        inside.push(self.member(depth)?);
                        text.push_str(&inside.last().map(Member::shown).unwrap_or_default());
                    } else {
                        self.value(depth + 1, text, inside)?;
                    }
                    self.blank()?;
                    // A comma, or the end; one may follow the last entry.
                    match self.peek()? {
                        b',' => {
                            self.at += 1;
                            text.push(',');
                        }
                        byte if byte == close => {}
                        _ => return None,
                    }
                }
            }
            b'"' => {
                let string = self.string()?;
                text.push('"');
                text.push_str(&string);
                text.push('"');
                Some(())
            }
            _ => {
                // A number or a word (`true`, `null`).
                let start = self.at;
                while self
                    .peek()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || b"+-.".contains(&byte))
                {
                    self.at += 1;
                }
                text.push_str(&String::from_utf8_lossy(&self.bytes[start..self.at]));
                (self.at > start).then_some(())
            }
        }
    }

    /// Reads one `"key": value` of a table.
    fn member(&mut self, depth: usize) -> Option<Member> {
        if self.peek()? != b'"' {
            return None;
        }
        let line = self.line;
        let key = self.string()?;
        self.blank()?;
        if self.peek()? != b':' {
            return None;
        }
        self.at += 1;
        let mut member = Member {
            key,
            line,
            value: String::new(),
            inside: Vec::new(),
        };
        self.value(depth + 1, &mut member.value, &mut member.inside)?;
        Some(member)
    }
}

impl Member {
    /// The member as part of the value that holds it.
    fn shown(&self) -> String {
        format!("\"{}\":{}", self.key, self.value)
    }
}

/// The keys of an editor's settings; the line they stop making sense at
/// where they cannot be read to the end. An empty file has none.
fn settings(text: &str) -> Result<Vec<Member>, usize> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut settings = Settings {
        bytes: text.as_bytes(),
        at: 0,
        line: 1,
    };
    let mut read = || {
        settings.blank()?;
        let mut inside = Vec::new();
        match settings.peek() {
            None => return Some(inside),
            Some(b'{') => settings.value(0, &mut String::new(), &mut inside)?,
            Some(_) => return None,
        }
        settings.blank()?;
        settings.peek().is_none().then_some(inside)
    };
    // The end of a file that ends its last line is not a line of its own.
    read().ok_or_else(|| settings.line.min(text.lines().count().max(1)))
}

/// What a key inside a terminal's environment or profile table of an
/// editor's settings does.
fn terminal_setting(key: &str, value: &str) -> Option<String> {
    match key {
        "path" if is_own_program(value) => Some(graded(
            "the editor's terminal starts a shell outside the system's directories".into(),
            value,
        )),
        "args"
            if value.contains("\"-c\"")
                || value.contains("\"--rcfile\"")
                || value.contains("\"--init-file\"") =>
        {
            Some(
                "the editor's terminal starts its shell with commands of this file's choosing"
                    .into(),
            )
        }
        _ => None,
    }
}

/// Whether an editor's setting says where a tool is (`python.pythonPath`,
/// `clangd.path`, `rust-analyzer.server.path`).
fn names_a_program(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.ends_with("path") || key.ends_with("executable")
}

/// Whether `key` says where a Python interpreter is and `value` is one in
/// a virtual environment a tool made (Poetry keeps them below `~/.cache`):
/// in the home's cache, but not in a directory anyone may write.
fn is_virtualenv_interpreter(key: &str, value: &str) -> bool {
    let key = key.to_ascii_lowercase();
    (key.contains("python") || key.contains("interpreter"))
        && VIRTUALENVS.iter().any(|kept| value.contains(kept))
        && !value.contains("..")
        && !is_temporary(&value.replace("/.cache/", "/"))
}

/// One key of an editor's settings, outside any table.
fn editor_setting(key: &str, value: &str) -> Option<String> {
    let plain = bare(value);
    match key {
        "security.workspace.trust.enabled" if plain == "false" => {
            Some("every folder opened is trusted to run its tasks and extensions".into())
        }
        "task.allowAutomaticTasks" if plain == "on" => {
            Some("a folder's tasks run as soon as it is opened".into())
        }
        "http.proxy" if !plain.is_empty() => Some(proxied(key, value)),
        "http.proxyStrictSSL" if plain == "false" => Some(unchecked(key)),
        "git.path" if is_own_program(value) => Some(graded(
            "git.path: the editor runs a git outside the system's directories".into(),
            value,
        )),
        _ if key.starts_with("terminal.integrated.shellArgs.")
            && (value.contains("\"-c\"") || value.contains("\"--rcfile\"")) =>
        {
            Some(
                "the editor's terminal starts its shell with commands of this file's choosing"
                    .into(),
            )
        }
        _ if key.starts_with("terminal.integrated.shell.") && is_own_program(value) => {
            Some(graded(
                "the editor's terminal starts a shell outside the system's directories".into(),
                value,
            ))
        }
        // Any tool the editor is told where to find (`python.pythonPath`,
        // `clangd.path`, `rust-analyzer.server.path`).
        _ if names_a_program(key)
            && value.starts_with('"')
            && is_temporary(value)
            && !is_virtualenv_interpreter(key, value) =>
        {
            Some(format!("{key}: the editor runs a program{FROM_TEMPORARY}"))
        }
        _ => None,
    }
}

/// What an editor's `settings.json` does that is worth seeing, each with
/// its line: the environment and shell of its terminal, its proxy, the
/// programs it is told to run from odd places, and the switches that let a
/// folder run its tasks unasked.
///
/// The file is kept from the AI, so nothing else looks at it: one that
/// cannot be read to the end as an editor's settings is said to be, at the
/// line where it stops making sense, instead of passing with no key seen.
pub fn editor(text: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    match settings(text) {
        Ok(settings) => told_of(&settings, None, &mut found),
        Err(line) => found.push((line, NOT_SETTINGS.to_string())),
    }
    found
}

/// What is said of an editor's settings that cannot be read to the end.
const NOT_SETTINGS: &str =
    "the file cannot be read as JSON with comments from here on: none of its settings were checked";

/// What `members` do, each at its line. `table` is the terminal table
/// they are in (its environment, or its profiles), at whatever depth.
fn told_of(members: &[Member], table: Option<&str>, found: &mut Vec<(usize, String)>) {
    for member in members {
        let (key, value) = (member.key.as_str(), member.value.as_str());
        let terminal = table.is_none()
            && ["env.", "profiles.", "automationProfile."]
                .iter()
                .any(|kind| key.starts_with(&format!("terminal.integrated.{kind}")));
        let seen = match table {
            Some(name) if name.contains(".env.") => loading_variable(key, value),
            Some(_) => terminal_setting(key, value),
            // What a terminal table does is in its keys.
            None if terminal => None,
            None => editor_setting(key, value),
        };
        if let Some(seen) = seen
            && found.len() < MAX_ALERTS
        {
            found.push((member.line, seen));
        }
        told_of(&member.inside, table.or(terminal.then_some(key)), found);
    }
}

/// A variable of the editor's terminal that changes what runs or is loaded
/// there. Which editor or pager the terminal's programs open is a
/// preference, like any other variable an app reads.
fn loading_variable(name: &str, value: &str) -> Option<String> {
    (!matches!(
        name.to_ascii_uppercase().as_str(),
        "EDITOR" | "VISUAL" | "PAGER"
    ) && sets_what_runs(name, value))
    .then(|| format!("the editor's terminal starts every program with {name} set by this file"))
}

#[cfg(test)]
mod tests {
    use super::{CLEARTEXT, FROM_TEMPORARY, NOT_SETTINGS, NOT_TOML, alerts, editor, is_temporary};

    /// What is seen in `text` at `path`, without the line numbers.
    fn seen(path: &str, text: &str) -> Vec<String> {
        alerts(path, text)
            .into_iter()
            .map(|(_, seen)| seen)
            .collect()
    }

    /// Every line of `must` is told, by a sentence that starts with its
    /// key, and none of `must_not` is.
    fn told(path: &str, must: &[&str], must_not: &[&str]) {
        for line in must {
            let found = seen(path, &format!("{line}\n"));
            assert_eq!(found.len(), 1, "{path}: {line}: {found:?}");
        }
        let quiet = seen(path, &format!("{}\n", must_not.join("\n")));
        assert!(quiet.is_empty(), "{path}: {quiet:?}");
    }

    #[test]
    fn temporary_and_cache_directories_are_told_from_others() {
        for path in [
            "/tmp/x",
            "\"/var/tmp/x\"",
            "--require /dev/shm/a.js",
            "~/.cache/x",
            "$HOME/.cache/a/b",
        ] {
            assert!(is_temporary(path), "{path}");
        }
        for path in [
            "/home/u/tmp/x",
            "~/tmp/x",
            "/usr/lib/tmpfiles.d/x",
            "~/.cachet/x",
        ] {
            assert!(!is_temporary(path), "{path}");
        }
    }

    #[test]
    fn npm_and_yarn_settings_that_run_load_or_redirect_are_told() {
        told(
            "home/u/.npmrc",
            &[
                "node-options=--require /home/u/x.js",
                "NODE_OPTIONS=--import=/home/u/x.mjs",
                "git=/home/u/bin/git",
                "shell=/home/u/sh",
                "script-shell=/usr/bin/zsh",
                "onload-script=/home/u/x.js",
                "init-module=/home/u/.init.js",
                "https-proxy=http://10.0.0.1:3128",
                "proxy=http://proxy.corp.example:8080",
                "cafile=/home/u/ca.pem",
                "cafile=/tmp/ca.pem",
                "cafile=/etc/ssl/../../home/u/ca.pem",
                "ca=\"-----BEGIN CERTIFICATE-----\"",
                "strict-ssl=false",
                "prefix=/tmp/npm",
                "cache=/dev/shm/npm",
                "globalconfig=/home/u/other",
                "userconfig=/tmp/npmrc",
                "registry=http://registry.npmjs.org/",
                "@corp:registry=https://npm.corp.example/",
            ],
            &[
                "registry=https://registry.npmjs.org/",
                "//registry.npmjs.org/:_authToken=npm_SECRET.SECRET",
                "node-options=--max-old-space-size=4096",
                "prefix=/home/u/.npm-global",
                "prefix=~/.npm-global",
                "@corp:registry=https://npm.pkg.github.com",
                "cafile=/etc/ssl/certs/ca-certificates.crt",
                "cafile=/etc/ca-certificates/extracted/tls-ca-bundle.pem",
                "cafile=/usr/share/ca-certificates/trust-source/x.crt",
                "cache=/home/u/.cache/npm",
                "save-exact=true",
                "ca=null",
                "strict-ssl=true",
                "email=u@corp.example",
            ],
        );
        let graded = seen(
            "home/u/.npmrc",
            "node-options=--require /tmp/x.js\nregistry=http://npm.corp.example/\nproxy=http://u:hunter2@proxy.corp.example:8080\n",
        );
        assert!(graded[0].ends_with(FROM_TEMPORARY), "{graded:?}");
        assert!(graded[1].ends_with(CLEARTEXT), "{graded:?}");
        // A value is never shown, only the host of an address.
        assert!(
            graded[2].contains("(proxy.corp.example)") && !graded.join(" ").contains("hunter2")
        );
        told(
            "home/u/.yarnrc.yml",
            &[
                "yarnPath: .yarn/releases/evil.cjs",
                "plugins:",
                "httpProxy: \"http://10.0.0.1:3128\"",
                "httpsProxy: \"http://10.0.0.1:3128\"",
                "caFilePath: /home/u/ca.pem",
                "enableStrictSsl: false",
                "unsafeHttpWhitelist:",
                "npmRegistryServer: \"https://npm.corp.example\"",
            ],
            &[
                "npmRegistryServer: \"https://registry.yarnpkg.com\"",
                "enableStrictSsl: true",
                "nodeLinker: node-modules",
                "enableTelemetry: false",
                "npmAuthToken: \"abc.def.SECRET\"",
            ],
        );
        told(
            "home/u/.yarnrc",
            &[
                "yarn-path \"/home/u/yarn.js\"",
                "registry \"https://npm.corp.example\"",
                "strict-ssl false",
                "https-proxy \"http://10.0.0.1:3128\"",
                "cafile \"/home/u/ca.pem\"",
            ],
            &[
                "registry \"https://registry.yarnpkg.com\"",
                "lastUpdateCheck 1700000000",
            ],
        );
    }

    #[test]
    fn bun_and_pip_settings_that_run_load_or_redirect_are_told() {
        told(
            "home/u/.bunfig.toml",
            &[
                "preload = [\"/home/u/x.ts\"]",
                "[install]\nregistry = \"https://npm.corp.example\"",
                "[install]\nregistry = { url = \"https://npm.corp.example\", token = \"abc.SECRET\" }",
                "[install.scopes]\n\"@corp\" = \"https://npm.corp.example\"",
                "[install]\ncafile = \"/home/u/ca.pem\"",
                "[run]\nshell = \"/home/u/sh\"",
            ],
            &[
                "telemetry = false",
                "[install]\nregistry = \"https://registry.npmjs.org\"",
                "[install]\nregistry = { url = \"https://registry.npmjs.org\", token = \"abc.SECRET\" }",
                "[run]\nshell = \"system\"\nbun = true",
                "[test]\ncoverage = true",
            ],
        );
        assert!(!seen(
            "home/u/.bunfig.toml",
            "[install]\nregistry = { url = \"https://npm.corp.example\", token = \"abc.SECRET\" }\n"
        )
        .join(" ")
        .contains("SECRET"));
        for path in [
            "home/u/.config/pip/pip.conf",
            "home/u/.pip/pip.conf",
            "home/u/.pydistutils.cfg",
        ] {
            told(
                path,
                &[
                    "index-url = http://pypi.corp.example/simple",
                    "extra-index-url = http://pypi.org/simple",
                    "index-url = https://10.0.0.9/simple",
                    "index-url = https://[fd00::9]:8443/simple",
                    "extra-index-url = https://xn--pyp-qma.org/simple",
                    "extra-index-url = https://github.com.evil.example/simple",
                    "index-url = https://webhook.site/simple",
                    "find-links = /tmp/wheels",
                    "find-links = https://wheels.corp.example/",
                    "trusted-host = pypi.corp.example",
                    "proxy = http://10.0.0.1:3128",
                    "cert = /home/u/ca.pem",
                    "client-cert = /home/u/me.pem",
                ],
                &[
                    "[global]",
                    "index-url = https://pypi.org/simple",
                    // A project's or a company's own index, over HTTPS.
                    "extra-index-url = https://download.pytorch.org/whl/cpu",
                    "index-url = https://files.pythonhosted.org/simple",
                    "index-url = https://user:hunter2@pypi.corp.example/simple",
                    "index-url = http://localhost:3141/root/pypi",
                    "cert = /etc/ssl/certs/ca-certificates.crt",
                    "timeout = 60",
                    "no-index = true",
                    "user-agent = x",
                    "require-virtualenv = true",
                ],
            );
        }
        let wheels = seen("home/u/.pip/pip.conf", "find-links = /tmp/wheels\n");
        assert!(wheels[0].ends_with(FROM_TEMPORARY), "{wheels:?}");
    }

    #[test]
    fn go_and_cargo_settings_that_run_load_or_redirect_are_told() {
        told(
            "home/u/.config/go/env",
            &[
                "GOPROXY=https://goproxy.corp.example,direct",
                "GOFLAGS=-toolexec=/home/u/x",
                "GOINSECURE=*.corp.example",
                "GONOSUMCHECK=1",
                "GOSUMDB=off",
                "GONOSUMDB=*",
                "GOPRIVATE=github.com",
                "GOPRIVATE=*.com",
                "CC=/home/u/cc",
                "CXX=evil++",
                "GOAUTH=/home/u/auth https://x",
                "GOBIN=/tmp/bin",
            ],
            &[
                "GOPROXY=https://proxy.golang.org,direct",
                "GOPATH=/home/u/go",
                "GOSUMDB=sum.golang.org",
                "GOPRIVATE=github.com/corp/*,*.corp.example",
                "GOPRIVATE=github.com/mycorp/*",
                "GONOSUMDB=git.corp.example",
                "CC=clang",
                "GOAUTH=netrc",
                "GOBIN=/home/u/go/bin",
                "GOFLAGS=-mod=mod",
                "GOTOOLCHAIN=local",
            ],
        );
        told(
            "home/u/.cargo/config.toml",
            &[
                "[http]\nproxy = \"http://10.0.0.1:3128\"",
                "[http]\ncainfo = \"/home/u/ca.pem\"",
                "[http]\ncheck-revoke = false",
                "[env]\nRUSTC_WRAPPER = \"/home/u/w\"",
                "[env]\nCC = \"/tmp/cc\"",
                "[env]\nCC = { value = \"bin/cc\", relative = true }",
                "[env]\nPATH = \"/home/u/bin\"",
                "[build]\nrustflags = [\"-C\", \"linker=/tmp/ld\"]",
                "[env]\nLD_PRELOAD = { value = \"/home/u/x.so\", force = true }",
                "[target.x86_64-unknown-linux-gnu]\nlinker = \"/home/u/ld\"",
                "[target.x86_64-unknown-linux-gnu]\nrunner = \"/tmp/run\"",
                "[target.x86_64-unknown-linux-gnu]\nrustflags = [\"-C\", \"linker=/home/u/ld\"]",
                "[build]\nrustflags = [\"-Clinker=/home/u/ld\"]",
                "[build]\nrustc = \"/home/u/rustc\"",
                "[build]\nrustdoc = \"/home/u/rustdoc\"",
                "[build]\nrustc-wrapper = \"/home/u/.cache/w\"",
                "[build]\nrustc-workspace-wrapper = \"./w\"",
                "[registries.corp]\nindex = \"sparse+https://crates.corp.example/index/\"",
                "[source.crates-io]\nreplace-with = \"mirror\"",
                "[source.mirror]\nregistry = \"http://crates.corp.example/index\"",
                "[registry]\nglobal-credential-providers = [\"/home/u/provider\"]",
                "[registries.corp]\ncredential-provider = [\"/home/u/provider\", \"--x\"]",
                "[alias]\nb = \"build --config /home/u/c.toml\"",
                "paths = [\"/home/u/crate\"]",
                "[patch.crates-io]\nserde = { path = \"/tmp/serde\" }",
            ],
            &[
                "[http]\ntimeout = 30\ncheck-revoke = true",
                "[net]\ngit-fetch-with-cli = true",
                "[env]\nCARGO_TERM_COLOR = \"always\"",
                // A system compiler by its name or path, as the direct
                // keys take it.
                "[env]\nCC = \"clang\"\nCXX = { value = \"/usr/bin/clang++\", force = true }",
                "[build]\nrustflags = [\"-C\", \"linker=clang\"]",
                "[target.x86_64-unknown-linux-gnu]\nrustflags = [\"-Clinker=/usr/bin/clang\", \"-C\", \"link-arg=-fuse-ld=mold\"]",
                "[build]\nrustc-wrapper = \"sccache\"",
                "[build]\nrustc-wrapper = \"/usr/bin/sccache\"\njobs = 8",
                "[target.x86_64-unknown-linux-gnu]\nlinker = \"clang\"\nrustflags = [\"-C\", \"link-arg=-fuse-ld=mold\"]",
                "[registries.ok]\nindex = \"https://github.com/rust-lang/crates.io-index\"",
                "[registry]\nglobal-credential-providers = [\"cargo:token\", \"cargo:libsecret\"]",
                "[alias]\nb = \"build --release\"",
                "[term]\ncolor = \"always\"",
            ],
        );
        // Mise shares the file name and is reviewed as text.
        assert!(
            seen(
                "home/u/.config/mise/config.toml",
                "[env]\nPATH = \"/tmp\"\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn gem_conda_wget_and_curl_settings_that_redirect_are_told() {
        told(
            "home/u/.gemrc",
            &[
                "- https://gems.corp.example/",
                "gem: --source https://gems.corp.example",
                "gem: --http-proxy http://10.0.0.1:3128",
                ":http_proxy: http://10.0.0.1:3128",
                ":ssl_verify_mode: 0",
                ":ssl_ca_cert: /home/u/ca.pem",
            ],
            &[
                "---",
                ":sources:",
                "- https://rubygems.org/",
                "gem: --no-document",
                ":ssl_verify_mode: 1",
            ],
        );
        told(
            "home/u/.condarc",
            &[
                "  - https://conda.corp.example/pkgs",
                "channel_alias: https://conda.corp.example",
                "ssl_verify: false",
                "ssl_verify: /home/u/ca.pem",
                "proxy_servers:",
                "  http: http://10.0.0.1:3128",
            ],
            &[
                "channels:",
                "  - conda-forge",
                "  - defaults",
                "ssl_verify: true",
                "auto_activate_base: false",
            ],
        );
        told(
            "home/u/.wgetrc",
            &[
                "check_certificate = off",
                "check-certificate=off",
                "http_proxy = http://10.0.0.1:3128/",
                "https_proxy = http://10.0.0.1:3128/",
                "ca_certificate = /home/u/ca.pem",
                "use_askpass = /home/u/ask",
                "output_document = /home/u/.bashrc",
            ],
            &[
                "check_certificate = on",
                "use_proxy = on",
                "tries = 3",
                "timestamping = on",
            ],
        );
        told(
            "home/u/.curlrc",
            &[
                "insecure",
                "-k",
                "--insecure",
                "proxy = http://10.0.0.1:3128",
                "-x socks5://10.0.0.1:1080",
                "--proxy=\"http://10.0.0.1:3128\"",
                "cacert = /home/u/ca.pem",
                "capath = /tmp/certs",
                "resolve = pypi.org:443:10.0.0.9",
                "output = /home/u/.bashrc",
                "-K /home/u/other",
                "trace-ascii = /tmp/t",
            ],
            &[
                "silent",
                "-s",
                "--location",
                "-L",
                "--silent",
                "cacert = /etc/ssl/certs/ca-certificates.crt",
                "user-agent = \"x\"",
                "connect-timeout = 10",
                "# insecure",
            ],
        );
    }

    #[test]
    fn editor_settings_that_run_load_or_redirect_are_told() {
        let lines =
            |text: &str| -> Vec<usize> { editor(text).into_iter().map(|(line, _)| line).collect() };
        let settings = r#"{
  // "git.path": "/tmp/commented",
  "editor.fontSize": 12,
  "security.workspace.trust.enabled": false,
  "task.allowAutomaticTasks": "on",
  "terminal.integrated.env.linux": {
    "EDITOR_THEME": "dark",
    "LD_PRELOAD": "/home/u/x.so"
  },
  "terminal.integrated.profiles.linux": {
    "bash": { "path": "bash", "icon": "terminal-bash" },
    "odd": {
      "path": "/home/u/.local/sh",
      "args": ["-c", "curl x | sh"]
    }
  },
  "terminal.integrated.defaultProfile.linux": "odd",
  "terminal.integrated.automationProfile.linux": { "path": "/tmp/sh" },
  "terminal.integrated.shellArgs.linux": ["-c", "x"],
  "git.path": "/home/u/bin/git",
  "http.proxy": "http://u:hunter2@10.0.0.1:3128",
  "http.proxyStrictSSL": false,
  "python.defaultInterpreterPath": "/tmp/venv/bin/python",
  "clangd.path": "/home/u/.cache/clangd/clangd",
  "extensions.autoUpdate": true
}
"#;
        assert_eq!(
            lines(settings),
            [4, 5, 8, 13, 14, 18, 19, 20, 21, 22, 23, 24]
        );
        let found = editor(settings);
        assert!(!found.iter().any(|(_, seen)| seen.contains("hunter2")));
        assert!(found[5].1.ends_with(FROM_TEMPORARY), "{found:?}");
        let quiet = r#"{
  "terminal.integrated.env.linux": { "FOO": "bar", "EDITOR": "nvim", "CC": "clang" },
  "terminal.integrated.env.osx": {
    "VISUAL": "/home/u/bin/edit",
    "PAGER": "less",
    "LANG": "en_US.UTF-8",
    "TERM": "xterm-256color",
    "RUSTC_WRAPPER": "/usr/bin/sccache"
  },
  "terminal.integrated.defaultProfile.linux": "zsh",
  "python.defaultInterpreterPath": "/home/u/.cache/pypoetry/virtualenvs/app-x-py3.12/bin/python",
  "python.pythonPath": "~/.local/share/virtualenvs/app-x/bin/python",
  "mypy.interpreter.path": "/home/u/.cache/uv/environments-v2/x/bin/python",
  "terminal.integrated.profiles.linux": { "zsh": { "path": "/usr/bin/zsh", "args": ["-l"] } },
  "git.path": "/usr/bin/git",
  "http.proxyStrictSSL": true,
  "python.defaultInterpreterPath": "/home/u/.venv/bin/python",
  "rust-analyzer.server.path": "~/.cargo/bin/rust-analyzer",
  "security.workspace.trust.enabled": true,
  "files.exclude": { "**/.git": true }
}
"#;
        assert!(editor(quiet).is_empty(), "{:?}", editor(quiet));
        // The variables that change what the terminal's programs run or
        // load, and a compiler from the home.
        let loading = "{\n\"terminal.integrated.env.linux\": {\n\"PATH\": \"/home/u/bin:${env:PATH}\",\n\"GIT_CONFIG_GLOBAL\": \"/home/u/x\",\n\"https_proxy\": \"http://10.0.0.1:3128\",\n\"CC\": \"/home/u/bin/cc\",\n\"GIT_SSH_COMMAND\": \"ssh -i x\",\n\"MY_APP_MODE\": \"dev\"\n}\n}\n";
        assert_eq!(lines(loading), [3, 4, 5, 6, 7]);
        assert_eq!(
            lines(
                "{\n\"terminal.integrated.env.linux\": { \"A\": \"1\", \"NODE_OPTIONS\": \"--require /x.js\" }\n}\n"
            ),
            [2]
        );
    }

    #[test]
    fn an_editors_settings_are_read_by_key_wherever_on_a_line_it_stands() {
        let lines =
            |text: &str| -> Vec<usize> { editor(text).into_iter().map(|(line, _)| line).collect() };
        // On one line, on the line of the brace, after another key.
        assert_eq!(lines(r#"{"git.path":"/tmp/x"}"#), [1]);
        // A comment ends at a lone carriage return, as it does for the
        // editor, and a `\u` escape is four hex digits and no sign.
        assert_eq!(lines("{ // x\r\"git.path\": \"/tmp/x\",\n\"a\": 1 }"), [1]);
        assert_eq!(lines("{\"git.p\\u+061th\": \"/tmp/x\"}").len(), 1);
        assert!(
            editor("{\"git.p\\u+061th\": \"/tmp/x\"}")[0]
                .1
                .contains("cannot be read")
        );
        assert_eq!(
            lines(r#"{ "security.workspace.trust.enabled": false }"#),
            [1]
        );
        assert_eq!(
            lines("{ \"git.path\": \"/home/u/bin/git\",\n  \"editor.fontSize\": 12 }\n"),
            [1]
        );
        assert_eq!(
            lines(
                "{\n  \"editor.fontSize\": 12, \"http.proxyStrictSSL\": false,\n\n  \"task.allowAutomaticTasks\": \"on\" }"
            ),
            [2, 4]
        );
        // A value that goes over several lines, at the line of its key.
        assert_eq!(
            lines(
                "{\n  \"terminal.integrated.shellArgs.linux\": [\n    \"-c\",\n    \"x\"\n  ]\n}\n"
            ),
            [2]
        );
        assert_eq!(lines("{\n  \"git.path\":\n\n    \"/tmp/x\"\n}\n"), [2]);
        // A terminal table on one line with the rest, and its keys below.
        assert_eq!(
            lines("{\"a\": 1, \"terminal.integrated.env.linux\": {\"LD_PRELOAD\": \"/x.so\"}}"),
            [1]
        );
        assert_eq!(
            lines(
                "{\"terminal.integrated.profiles.linux\": {\"odd\": {\n\"path\": \"/tmp/sh\", \"args\": [\n\"-c\", \"x\"]}}}"
            ),
            [2, 2]
        );
        // A key in a table of another key's (a language's own settings).
        assert_eq!(
            lines("{\"[python]\": {\"python.defaultInterpreterPath\": \"/tmp/v/python\"}}"),
            [1]
        );
        // Comments and a comma after the last entry, as editors allow; a
        // key after a comment on its line; nothing inside a comment or a
        // string.
        let commented = "// \"git.path\": \"/tmp/a\"\n{\n  /* \"git.path\": \"/tmp/b\",\n     \"http.proxyStrictSSL\": false */\n  /* own */ \"git.path\": \"/tmp/c\", // \"git.path\": \"/tmp/d\"\n  \"x.note\": \"\\\"git.path\\\": \\\"/tmp/e\\\" // */ /*\",\n  \"x.list\": [1, 2,],\n}\n";
        assert_eq!(lines(commented), [5]);
        // Escapes are read before a key or a value is looked at.
        assert_eq!(lines(r#"{"git.p\u0061th": "\/tmp\/x"}"#), [1]);
        assert_eq!(
            lines(r#"{"terminal.integrated.shellArgs.linux": ["\u002dc", "x \ud83d\ude00"]}"#),
            [1]
        );
        // Nothing to read is nothing to say.
        for empty in ["", "\n", "// none\n", "/* none */", "{}", "\u{feff}{ }\n"] {
            assert_eq!(lines(empty), [0; 0], "{empty:?}");
        }
    }

    #[test]
    fn an_editors_settings_that_cannot_be_read_to_the_end_are_said_to_be() {
        let unread = |text: &str| -> Option<usize> {
            let found = editor(text);
            assert!(found.len() <= 1 || found.iter().all(|(_, seen)| seen != NOT_SETTINGS));
            found
                .into_iter()
                .find(|(_, seen)| seen == NOT_SETTINGS)
                .map(|(line, _)| line)
        };
        for (text, line) in [
            // Cut short, in a table, a string or a comment.
            ("{\"git.path\": \"/tmp/x\"", 1),
            ("{\n\"git.path\": \"/tmp/x", 2),
            ("{\n\"a\": 1 /* \"git.path\": \"/tmp/x\"\n}\n", 3),
            // What an editor reads on past: a missing comma, a missing
            // value, a key without quotes, a string over two lines.
            ("{\n\"a\": 1\n\"git.path\": \"/tmp/x\"\n}\n", 3),
            ("{\n\"a\":\n}\n", 3),
            ("{\ngit.path: \"/tmp/x\"\n}\n", 2),
            ("{\"a\": \"x\ny\", \"git.path\": \"/tmp/x\"}", 1),
            ("{\"a\": \"\\x\"}", 1),
            ("{\"a\": 'x'}", 1),
            // No table of settings, or more after it.
            ("[]", 1),
            ("\"git.path\"", 1),
            ("{}\n{\"git.path\": \"/tmp/x\"}\n", 2),
            ("{}}", 1),
        ] {
            assert_eq!(unread(text), Some(line), "{text:?}");
        }
        // Deeper than any settings go.
        let deep = format!("{{\"a\": {}1{}}}", "[".repeat(100), "]".repeat(100));
        assert_eq!(unread(&deep), Some(1));
        let fine = format!("{{\"a\": {}1{}}}", "[".repeat(20), "]".repeat(20));
        assert_eq!(unread(&fine), None);
        // It is a finding of the file, at its line.
        let told = crate::sweep::config::alerts(
            crate::autorun::Category::Editor,
            "home/u/.config/Code/User/settings.json",
            "{\n  \"git.path\": \"/tmp/x\"\n",
            &|_| false,
        );
        assert_eq!(
            told,
            [(
                crate::rules::RuleId::RiskyConfiguration,
                format!("line 2: {NOT_SETTINGS}")
            )]
        );
    }

    #[test]
    fn an_editors_settings_are_read_whatever_they_hold() {
        use crate::test_support::Rng;
        const PIECES: &[&str] = &[
            "{",
            "}",
            "[",
            "]",
            ":",
            ",",
            "\"",
            "\\",
            "\\u",
            "d83d",
            "//",
            "/*",
            "*/",
            "\n",
            " ",
            "\"git.path\"",
            "\"/tmp/x\"",
            "\"terminal.integrated.env.linux\"",
            "true",
            "1",
            "é",
        ];
        let settings = "{\n  // one\n  \"git.path\": \"/tmp/x\", /* two */\n  \"terminal.integrated.env.linux\": { \"LD_PRELOAD\": \"/x.so\" },\n  \"x\": [1, {\"path\": \"\\u00e9\"}],\n}\n";
        assert_eq!(editor(settings).len(), 2);
        let check = |text: &str| {
            let lines = text.lines().count().max(1);
            for (line, seen) in editor(text) {
                assert!((1..=lines).contains(&line), "{text:?}: {line}");
                assert!(!seen.is_empty());
            }
        };
        let mut rng = Rng::new(7);
        for _ in 0..10_000 {
            check(&rng.text(PIECES, 16));
            check(&rng.mutated(settings, PIECES));
        }
    }

    #[test]
    fn toml_settings_are_read_by_key_however_they_are_written() {
        let cargo = "home/u/.cargo/config.toml";
        let lines = |path: &str, text: &str| -> Vec<usize> {
            alerts(path, text)
                .into_iter()
                .map(|(line, _)| line)
                .collect()
        };
        // A dotted key, a key in quotes, an inline table, and one in
        // another; a value over several lines, at the line of its key.
        for (text, line) in [
            ("build.rustc-wrapper = \"/tmp/w\"\n", 1),
            ("\"build\".\"rustc-wrapper\" = \"/tmp/w\"\n", 1),
            ("build = { rustc-wrapper = \"/tmp/w\" }\n", 1),
            ("build = { jobs = 8, rustc-wrapper = \"/tmp/w\" }\n", 1),
            (
                "http = { timeout = 30, proxy = \"http://10.0.0.1:3128\" }\n",
                1,
            ),
            ("env.LD_PRELOAD = \"/home/u/x.so\"\n", 1),
            // A variable as a table of its own, in each way to write one,
            // and a file that begins with a byte order mark.
            ("[env.LD_PRELOAD]\nvalue = \"/home/u/x.so\"\n", 2),
            ("env.LD_PRELOAD.value = \"/home/u/x.so\"\n", 1),
            ("[env]\nLD_PRELOAD.value = \"/home/u/x.so\"\n", 2),
            ("[env]\nCC = { \"value\" = \"/home/u/cc\" }\n", 2),
            ("\u{feff}build.rustc-wrapper = \"/tmp/w\"\n", 1),
            (
                "env = { A = \"x, y\", LD_PRELOAD = { value = \"/home/u/x.so\", force = true } }\n",
                1,
            ),
            (
                "target = { x86_64-unknown-linux-gnu = { linker = \"/home/u/ld\" } }\n",
                1,
            ),
            (
                "[target]\nx86_64-unknown-linux-gnu.runner = \"/tmp/run\"\n",
                2,
            ),
            (
                "registries.corp = { index = \"sparse+https://crates.corp.example/index/\" }\n",
                1,
            ),
            (
                "[build]\nrustflags = [\n  \"-C\",\n  \"linker=/tmp/ld\",\n]\n",
                2,
            ),
        ] {
            assert_eq!(lines(cargo, text), [line], "{text}");
        }
        assert_eq!(
            lines(
                cargo,
                "[build]\njobs = 8\nrustflags = [\n  \"-Clinker=/tmp/ld\",\n]\n"
            ),
            [3]
        );
        assert_eq!(
            lines(
                "home/u/.bunfig.toml",
                "install.registry = \"https://npm.corp.example\"\nrun = { shell = \"/home/u/sh\" }\n"
            ),
            [1, 2]
        );
        // The same written of what is fine says nothing.
        for text in [
            "build.rustc-wrapper = \"sccache\"\nbuild = { jobs = 8 }\n",
            "env = { CC = \"clang\", NOTE = \"LD_PRELOAD = /x.so, rustc = /tmp/x\" }\n",
            "registries.ok = { index = \"https://github.com/rust-lang/crates.io-index\" }\n",
            "[profile.release]\nlto = true\ndebug = { level = 1 }\n",
        ] {
            assert_eq!(lines(cargo, text), [0; 0], "{text}");
        }
        // A file that is no TOML is read line by line, and said to be.
        let broken = "[build]\nrustc-wrapper = \"/tmp/w\"\nnot toml at all\n";
        let found = alerts(cargo, broken);
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found[0], (3, NOT_TOML.to_string()));
        assert_eq!(found[1].0, 2);
    }
}
