//! Local checks of the settings of developer tools: package managers,
//! `curl`, `wget` and an editor's `settings.json`. These files hold
//! registry tokens and proxy passwords, so they are never sent to the AI
//! (see `judge::is_local_only`); what in them makes a tool run a program,
//! load code, send its traffic through somebody else or stop checking
//! certificates is told here, by key. A value is never shown: only the key,
//! and the host of an address.

use super::config::{host, is_usual, key_value};

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
        ("env", _) if sets_what_runs(key, table_value(value)) => Some(graded(
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
fn table_value(value: &str) -> &str {
    if !value.trim_start().starts_with('{') {
        return value;
    }
    value
        .split_once("value")
        .and_then(|(_, rest)| rest.split(['"', '\'']).nth(1))
        .unwrap_or(value)
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

/// What the settings of a developer tool at `path` do that is worth
/// seeing, each with its line; nothing for a file of no known tool.
pub fn alerts(path: &str, text: &str) -> Vec<(usize, String)> {
    let Some(tool) = tool(path) else {
        return Vec::new();
    };
    let mut found = Vec::new();
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

/// The key of a `"key": value` line of a JSON settings file, and the rest.
fn json_pair(line: &str) -> Option<(&str, &str)> {
    let rest = line.trim().strip_prefix('"')?;
    let (key, rest) = rest.split_once('"')?;
    Some((key, rest.trim_start().strip_prefix(':')?.trim()))
}

/// How deep a line leaves the braces and brackets it opens, relative to
/// where it started.
fn depth(line: &str) -> i32 {
    let mut depth = 0;
    let mut quoted = false;
    let mut escaped = false;
    for character in line.chars() {
        match character {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '"' => quoted = !quoted,
            '{' | '[' if !quoted => depth += 1,
            '}' | ']' if !quoted => depth -= 1,
            _ => {}
        }
    }
    depth
}

/// What a line inside a terminal's environment or profile table of an
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
pub fn editor(text: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    // The terminal table the lines are in, and how deep.
    let mut table: Option<(String, i32)> = None;
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        let pair = json_pair(line);
        let mut seen = None;
        if let Some((name, level)) = &mut table {
            if let Some((key, value)) = pair {
                seen = if name.contains(".env.") {
                    loading_variable(key, value)
                } else {
                    terminal_setting(key, value).or_else(|| inline(name, value))
                };
            }
            *level += depth(line);
            if *level <= 0 {
                table = None;
            }
        } else if let Some((key, value)) = pair {
            let terminal = ["env.", "profiles.", "automationProfile."]
                .iter()
                .any(|kind| key.starts_with(&format!("terminal.integrated.{kind}")));
            if terminal {
                // A table written on one line holds its keys on this one.
                seen = inline(key, value);
                let level = depth(value);
                if level > 0 {
                    table = Some((key.to_string(), level));
                }
            } else {
                seen = editor_setting(key, value);
            }
        }
        if let Some(seen) = seen
            && found.len() < MAX_ALERTS
        {
            found.push((index + 1, seen));
        }
    }
    found
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

/// What a terminal table written on one line (`{"LD_PRELOAD": "/x.so"}`)
/// does.
fn inline(table: &str, value: &str) -> Option<String> {
    value
        .split(['{', ','])
        .filter_map(json_pair)
        .find_map(|(key, value)| {
            if table.contains(".env.") {
                loading_variable(key, value)
            } else {
                terminal_setting(key, value)
            }
        })
}

#[cfg(test)]
mod tests {
    use super::{CLEARTEXT, FROM_TEMPORARY, alerts, editor, is_temporary};

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
}
