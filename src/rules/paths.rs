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
        // The matches come in order, so those in one word share its
        // reading.
        let mut word: Option<Word> = None;
        // Most lines hold none, and `contains` is the cheaper search.
        line.contains(pattern)
            && pattern_starts(line, pattern).any(|start| {
                if word.as_ref().is_none_or(|known| start >= known.end) {
                    word = Some(Word::around(line, start));
                }
                word.as_ref().is_some_and(|word| {
                    !word.is_packaged_before(line, start) || word.climbs_from(start)
                })
            })
    })
}

/// The word of a line that a persistence path was found in, read once for
/// every match in it.
struct Word {
    /// Where it begins, past what may stand before a path: a redirection,
    /// a quote, a parenthesis.
    path: usize,
    /// Where it ends: at whitespace, or with the line.
    end: usize,
    /// The first index a `..` has been written by, as the shell reads it:
    /// `."."` and `.\.` are `..` (see `is_packaged_path`).
    climbed: Option<usize>,
    /// Where the last `..` written out begins.
    last_climb: Option<usize>,
}

impl Word {
    /// The word around `at`, which is not whitespace.
    fn around(line: &str, at: usize) -> Self {
        // `rsplit` cuts after the whole whitespace character, which may be
        // longer than one byte.
        let before = &line[..at];
        let start = at
            - before
                .rsplit(char::is_whitespace)
                .next()
                .unwrap_or(before)
                .len();
        let end = line[at..]
            .find(char::is_whitespace)
            .map_or(line.len(), |length| at + length);
        let word = &line[start..end];
        let opening = word.len() - word.trim_start_matches(['>', '<', '"', '\'', '(']).len();
        // No match begins with one of those, so it is never among them.
        let path = (start + opening).min(at);
        let mut climbed = None;
        let mut dot = false;
        for (index, character) in line[path..end].char_indices() {
            if matches!(character, '"' | '\'' | '\\') {
                continue;
            }
            if dot && character == '.' {
                climbed = Some(path + index + 1);
                break;
            }
            dot = character == '.';
        }
        Self {
            path,
            end,
            climbed,
            last_climb: line[at..end].rfind("..").map(|index| at + index),
        }
    }

    /// Whether what the word holds before `at` is a path inside the
    /// package (see `is_packaged_path`).
    fn is_packaged_before(&self, line: &str, at: usize) -> bool {
        is_pkgdir_prefix(&line[self.path..at]) && self.climbed.is_none_or(|end| end > at)
    }

    /// Whether the word has a `..` from `at` on.
    fn climbs_from(&self, at: usize) -> bool {
        self.last_climb.is_some_and(|climb| climb >= at)
    }
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
