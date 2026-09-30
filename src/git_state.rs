//! Checks a `.git/config` found in a reviewed tree for keys that make git
//! run a command.
//!
//! `git clone` never carries a repository's config or hooks, but a tree that
//! arrives as an archive or a copied checkout does, and a later `git status`
//! or `git describe` in it (a build often runs one) runs whatever
//! `core.fsmonitor` or a filter names. The config is checked here and never
//! sent to the AI, since remote URLs can carry tokens.

/// Keys that name a command git runs, as `section.key`, `section.*.key` for
/// any subsection, or `section.*` for every key in the section.
const EXECUTING_KEYS: &[&str] = &[
    "core.fsmonitor",
    "core.hookspath",
    "core.sshcommand",
    "core.pager",
    "core.editor",
    "core.askpass",
    "core.gitproxy",
    "sequence.editor",
    "credential.helper",
    "credential.*.helper",
    "gpg.program",
    "gpg.*.program",
    "filter.*.clean",
    "filter.*.smudge",
    "filter.*.process",
    "diff.*.textconv",
    "diff.*.command",
    "diff.external",
    "merge.*.driver",
    "include.path",
    "includeif.*.path",
    "uploadpack.packobjectshook",
    "protocol.ext.allow",
    "pager.*",
];

/// Whether `rel` is a git config file the walk reviews: a `.git/config`, or a
/// submodule's under `.git/modules/`.
pub fn is_git_config(rel: &str) -> bool {
    let mut components = rel.split('/').rev();
    components.next() == Some("config") && rel.split('/').any(|component| component == ".git")
}

/// The lines of `text` that set a key running a command, as (line number,
/// `key = value` with any URL credentials masked).
pub fn executing_keys(text: &str) -> Vec<(usize, String)> {
    let mut section = String::new();
    let mut subsection: Option<String> = None;
    let mut hits = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if let Some(header) = line.strip_prefix('[') {
            let header = header.split(']').next().unwrap_or_default().trim();
            if let Some((name, sub)) = header.split_once(char::is_whitespace) {
                section = name.to_lowercase();
                subsection = Some(sub.trim().trim_matches('"').to_string());
            } else if let Some((name, sub)) = header.split_once('.') {
                section = name.to_lowercase();
                subsection = Some(sub.to_string());
            } else {
                section = header.to_lowercase();
                subsection = None;
            }
            continue;
        }
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .map_or((line, "true"), |(key, value)| (key.trim(), value.trim()));
        let key = key.to_lowercase();
        if !runs_command(&section, subsection.is_some(), &key, value) {
            continue;
        }
        let full = subsection.as_ref().map_or_else(
            || format!("{section}.{key}"),
            |sub| format!("{section}.{sub}.{key}"),
        );
        hits.push((index + 1, format!("{full} = {}", mask_credentials(value))));
    }
    hits
}

fn runs_command(section: &str, has_subsection: bool, key: &str, value: &str) -> bool {
    let value = value.trim_matches('"');
    if section == "alias" {
        return value.starts_with('!');
    }
    // `core.fsmonitor = true/false` switches the built-in daemon.
    if section == "core" && key == "fsmonitor" {
        return !matches!(
            value.to_lowercase().as_str(),
            "true" | "false" | "yes" | "no" | "on" | "off" | "1" | "0" | ""
        );
    }
    // Hooks in a directory of the tree (husky's `.husky/_`) are files the
    // walk reviews anyway.
    if section == "core" && key == "hookspath" && is_in_tree(value) {
        return false;
    }
    EXECUTING_KEYS.iter().any(|pattern| {
        let mut parts = pattern.split('.');
        let (Some(name), Some(second)) = (parts.next(), parts.next()) else {
            return false;
        };
        if name != section {
            return false;
        }
        match (second, parts.next()) {
            ("*", None) => true,
            ("*", Some(last)) => has_subsection && last == key,
            (only, None) => !has_subsection && only == key,
            _ => false,
        }
    })
}

/// A relative path that stays inside the working tree.
fn is_in_tree(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with(['/', '~'])
        && !path.contains('$')
        && path.split('/').all(|component| component != "..")
}

/// `scheme://user:secret@host` becomes `scheme://***@host`.
fn mask_credentials(value: &str) -> String {
    let Some((scheme, rest)) = value.split_once("://") else {
        return value.to_string();
    };
    match rest.split_once('@') {
        Some((credentials, host)) if !credentials.contains('/') => {
            format!("{scheme}://***@{host}")
        }
        _ => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{executing_keys, is_git_config};

    fn keys(text: &str) -> Vec<String> {
        executing_keys(text)
            .into_iter()
            .map(|(_, hit)| hit)
            .collect()
    }

    #[test]
    fn commands_are_flagged_and_switches_are_not() {
        assert_eq!(
            keys("[core]\n\tfsmonitor = \"touch /tmp/p\"\n\tbare = false\n"),
            ["core.fsmonitor = \"touch /tmp/p\""]
        );
        assert!(keys("[core]\n\tfsmonitor = true\n").is_empty());
        assert_eq!(
            keys("[alias]\n\tx = !sh -c id\n\ty = log\n"),
            ["alias.x = !sh -c id"]
        );
        assert_eq!(keys("[include]\n\tpath = ../x\n"), ["include.path = ../x"]);
        assert_eq!(
            keys("[filter \"lfs\"]\n\tsmudge = git-lfs smudge -- %f\n"),
            ["filter.lfs.smudge = git-lfs smudge -- %f"]
        );
        assert!(keys("[remote \"origin\"]\n\turl = https://h/r.git\n").is_empty());
        assert!(keys("[core]\n\thooksPath = .husky/_\n").is_empty());
        assert_eq!(
            keys("[core]\n\thooksPath = ../../x\n"),
            ["core.hookspath = ../../x"]
        );
    }

    #[test]
    fn credentials_in_a_flagged_value_are_masked() {
        assert_eq!(
            keys("[core]\n\tsshCommand = ssh https://me:tok@h/x\n"),
            ["core.sshcommand = ssh https://***@h/x"]
        );
    }

    #[test]
    fn git_config_paths_are_recognised() {
        assert!(is_git_config(".git/config"));
        assert!(is_git_config("sub/.git/modules/lib/config"));
        assert!(!is_git_config("config"));
        assert!(!is_git_config(".git/hooks/pre-commit"));
    }
}
