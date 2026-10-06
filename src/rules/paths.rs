//! File classification that is not a rule: documentation, files that run or
//! configure what runs, sensitive paths, and the naming of persistence paths.

use std::path::Path;

use crate::paths::file_name;

use super::{pattern_starts, persist};

const PERSISTENCE_PATHS: &[&str] = &[
    ".config/autostart/",
    ".config/systemd/user/",
    ".config/environment.d/",
    "/etc/systemd/system/",
    "/etc/cron.",
    "/etc/rc.local",
    "/etc/ld.so.preload",
    "/etc/profile.d/",
    "crontab -",
    ".ssh/authorized_keys",
    ".bashrc",
    ".zshrc",
    "~/.profile",
    "$home/.profile",
    "${home}/.profile",
    ".bash_profile",
    ".zprofile",
    ".config/fish/config.fish",
    ".config/omarchy/hooks/",
    "/etc/xdg/autostart/",
    "/etc/udev/rules.d/",
    "exec-once",
    "/library/launchagents/",
    "currentversion\\run",
];

/// A persistence path (see `names_persistence_path`), or one of the other
/// ways of persisting that `persist` reads.
pub(super) fn is_persistence(line: &str) -> bool {
    names_persistence_path(line) || persist::matches(line)
}

/// A persistence path, unless it is a file a PKGBUILD puts in the package
/// (`"$pkgdir"/etc/profile.d/x.sh`): pacman installs it as a listed package
/// file, just like a unit under `/usr/lib/systemd/system`.
fn names_persistence_path(line: &str) -> bool {
    PERSISTENCE_PATHS.iter().any(|pattern| {
        pattern_starts(line, pattern).any(|start| {
            let before = &line[..start];
            // The last word; `rsplit` cuts after the whole whitespace
            // character, which may be longer than one byte.
            let word = before
                .rsplit(char::is_whitespace)
                .next()
                .unwrap_or(before)
                .trim_start_matches(['>', '<', '"', '\'', '(']);
            let rest = line[start..]
                .split(char::is_whitespace)
                .next()
                .unwrap_or_default();
            !is_packaged_path(word) || rest.contains("..")
        })
    })
}

/// Whether `word` is a path, or the start of one, inside the package a
/// PKGBUILD assembles: it begins with `$pkgdir` and never climbs out of it
/// with `..`.
pub(super) fn is_packaged_path(word: &str) -> bool {
    // `."."` and `.\.` are `..` to the shell.
    let plain: String = word
        .chars()
        .filter(|character| !matches!(character, '"' | '\'' | '\\'))
        .collect();
    is_pkgdir_prefix(word) && !plain.contains("..")
}

/// `$pkgdir` or `${pkgdir}` as a whole word, possibly quoted: `$pkgdirz`
/// is another (empty) variable, so it does not count.
fn is_pkgdir_prefix(word: &str) -> bool {
    let rest = word
        .strip_prefix("${pkgdir}")
        .or_else(|| word.strip_prefix("$pkgdir"));
    rest.is_some_and(|rest| {
        rest.chars()
            .next()
            .is_none_or(|next| !(next.is_ascii_alphanumeric() || next == '_'))
    })
}

/// Names of prose files, matched as a prefix followed by the end of the name
/// or `.`, `-` or `_`: `LICENSE`, `LICENSE.txt`, `COPYING.LESSER`,
/// `eula_text.html`.
const PROSE_NAMES: &[&str] = &[
    "readme",
    "license",
    "licence",
    "copying",
    "changelog",
    "authors",
    "notice",
    "eula",
    "terms",
];

/// Prose files are sent to the AI review but not matched by the local
/// command rules, where install instructions (`sudo pacman -S ...`) and
/// examples would otherwise block every project with a README.
pub(crate) fn is_documentation(rel: &str) -> bool {
    let path = Path::new(rel);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if matches!(
        extension.as_str(),
        "md" | "markdown" | "rst" | "adoc" | "asciidoc" | "org" | "changelog"
    ) {
        return true;
    }

    // License texts: by name, or anywhere under a REUSE-style `LICENSES/`.
    let prose_name = PROSE_NAMES.iter().any(|prose| {
        name.strip_prefix(prose)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(['.', '-', '_']))
    });
    let in_licenses = path.parent().is_some_and(|parent| {
        parent.components().any(|component| {
            component.as_os_str().to_str().is_some_and(|name| {
                matches!(name.to_ascii_lowercase().as_str(), "licenses" | "licences")
            })
        })
    });
    // A script or config named like a license still runs.
    let prose_extension =
        matches!(extension.as_str(), "html" | "htm") || !is_executable_or_runtime_config(rel);
    (prose_name || in_licenses) && prose_extension
}

/// Files whose URLs are likely to be requested when the software runs.
pub(crate) fn is_executable_or_runtime_config(rel: &str) -> bool {
    let path = Path::new(rel);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    matches!(
        extension.as_str(),
        "bash"
            | "bat"
            | "c"
            | "cc"
            | "cmd"
            | "cpp"
            | "cs"
            | "cjs"
            | "conf"
            | "css"
            | "desktop"
            | "ex"
            | "exs"
            | "fish"
            | "go"
            | "h"
            | "html"
            | "hpp"
            | "ini"
            | "java"
            | "json"
            | "js"
            | "jsx"
            | "kt"
            | "lua"
            | "mjs"
            | "php"
            | "pl"
            | "ps1"
            | "py"
            | "pyw"
            | "rb"
            | "rs"
            | "scala"
            | "sc"
            | "service"
            | "sh"
            | "svg"
            | "swift"
            | "toml"
            | "ts"
            | "tsx"
            | "xml"
            | "yaml"
            | "yml"
    ) || matches!(
        name.as_str(),
        "dockerfile"
            | "makefile"
            | "pkgbuild"
            | ".install"
            | ".bashrc"
            | ".zshrc"
            | ".profile"
            | ".bash_profile"
            | ".zprofile"
            | ".xprofile"
            | "package.json"
    )
}

/// Whether a relative path looks like it holds credentials. The check uses
/// the path inside the reviewed tree, so where the tree itself lives (for
/// example under `~/secrets/`) does not matter.
pub(crate) fn is_sensitive_path(rel: &str) -> bool {
    let lower = rel.to_lowercase();
    let name = file_name(&lower);

    lower.split('/').any(|component| {
        matches!(
            component,
            ".ssh" | ".aws" | ".gnupg" | "credentials" | "secrets"
        )
    }) || name.starts_with(".env.")
        || name.starts_with(".env_")
        || ["secret", "credential"]
            .iter()
            .any(|word| name.contains(word))
        || name
            .split(|character: char| !character.is_ascii_alphanumeric())
            .any(|word| word == "token" || word == "tokens")
        || [
            ".pem",
            ".key",
            ".p12",
            ".pfx",
            ".keystore",
            ".jks",
            ".kdbx",
            ".tfstate",
            ".tfvars",
            ".tfvars.json",
            // `.env` itself and `prod.env`.
            ".env",
        ]
        .iter()
        .any(|extension| name.ends_with(extension))
        // Files that hold a login by their purpose. `.npmrc` and `.envrc`
        // are not among them: projects ship those as plain settings, and
        // withholding one makes a review incomplete.
        || matches!(
            name,
            ".pypirc" | ".netrc" | "id_rsa" | "id_ed25519" | "id_ecdsa" | "id_dsa"
        )
        || lower.ends_with(".kube/config")
        || lower.ends_with(".docker/config.json")
}
