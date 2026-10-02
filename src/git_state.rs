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
    "core.alternaterefscommand",
    "submodule.*.update",
    "remote.*.uploadpack",
    "remote.*.receivepack",
    "remote.*.vcs",
    "difftool.*.cmd",
    "mergetool.*.cmd",
    "trailer.*.command",
    "trailer.*.cmd",
    "gpg.*.defaultkeycommand",
    // Hooks defined in the configuration itself.
    "hook.*.command",
];

/// Whether `rel` is a git config file the walk reviews: a `.git/config`, or a
/// submodule's under `.git/modules/`.
pub fn is_git_config(rel: &str) -> bool {
    let mut components = rel.split('/').rev();
    matches!(components.next(), Some("config" | "config.worktree"))
        && rel.split('/').any(|component| component == ".git")
}

/// The lines of `text` that set a key running a command, as (line number,
/// `key = value` with any URL credentials masked).
pub fn executing_keys(text: &str) -> Vec<(usize, String)> {
    // The sections a key may belong to. Usually one; after a header that
    // may itself be the tail of a continued value, also the ones before.
    let mut sections: Vec<(String, Option<String>)> = vec![(String::new(), None)];
    let mut hits: Vec<(usize, String)> = Vec::new();
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let lines: Vec<&str> = text.lines().collect();
    for (index, raw) in lines.iter().enumerate() {
        // Where git continues a line onto the next depends on quotes,
        // comments and how many backslashes end it. Rather than repeat
        // those rules, a line ending in a backslash is read both ways, on
        // its own and joined with what follows, and what comes after it is
        // read both as a line of its own and as more of that value: a key
        // that runs a command in any reading is reported.
        let continued = index > 0 && lines[index - 1].ends_with('\\');
        let mut readings = vec![(*raw).to_string()];
        if raw.ends_with('\\') {
            let mut joined = (*raw).to_string();
            let mut next = index + 1;
            while joined.ends_with('\\') {
                joined.pop();
                match lines.get(next) {
                    Some(line) => joined.push_str(line),
                    None => break,
                }
                next += 1;
            }
            readings.push(joined);
        }
        for (reading_index, reading) in readings.into_iter().enumerate() {
            let mut line = reading.trim();
            if let Some(header) = line.strip_prefix('[') {
                let (header, rest) = split_header(header);
                let header = header.trim();
                let found = if let Some((name, sub)) = header.split_once(char::is_whitespace) {
                    (
                        name.to_lowercase(),
                        Some(sub.trim().trim_matches('"').to_string()),
                    )
                } else if let Some((name, sub)) = header.split_once('.') {
                    (name.to_lowercase(), Some(sub.to_string()))
                } else {
                    (header.to_lowercase(), None)
                };
                // Only the line as it stands opens a section; if it may be
                // the rest of a value, the sections before stay too.
                if reading_index == 0 {
                    if !continued {
                        sections.clear();
                    }
                    if !sections.contains(&found) {
                        sections.push(found);
                    }
                }
                // A key may follow its section on the same line.
                line = rest.trim();
            }
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .map_or((line, "true"), |(key, value)| (key.trim(), value.trim()));
            let key = key.to_lowercase();
            for (section, subsection) in &sections {
                if !runs_command(section, subsection.is_some(), &key, value) {
                    continue;
                }
                let full = subsection.as_ref().map_or_else(
                    || format!("{section}.{key}"),
                    |sub| format!("{section}.{sub}.{key}"),
                );
                let hit = (index + 1, format!("{full} = {}", mask_credentials(value)));
                if !hits.contains(&hit) {
                    hits.push(hit);
                }
            }
        }
    }
    hits
}

/// A section header (without its `[`) and what follows its closing `]`,
/// which a quoted subsection may itself contain (`[remote "a]b"]`).
fn split_header(header: &str) -> (&str, &str) {
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in header.char_indices() {
        match character {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ']' if !quoted => return (&header[..index], &header[index + 1..]),
            _ => {}
        }
    }
    (header, "")
}

fn runs_command(section: &str, has_subsection: bool, key: &str, value: &str) -> bool {
    // As git takes a value: quotes group and are dropped (`"" !x` is
    // `!x`), and blanks around it do not count.
    let value = value.replace('"', "");
    let value = value.trim();
    // An empty value clears a list (`credential.helper =`); it runs nothing.
    if value.is_empty() {
        return false;
    }
    if section == "alias" {
        return value.starts_with('!');
    }
    // `submodule.<name>.update` is a mode (`checkout`, `rebase`, `none`),
    // or a command behind `!`.
    if section == "submodule" && key == "update" {
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

/// A relative path that stays inside the working tree, and outside the
/// git directory, whose files the walk reads only in part.
fn is_in_tree(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with(['/', '~'])
        && !path.contains('$')
        && path
            .split('/')
            .all(|component| component != ".." && component != ".git")
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
        assert!(keys("[credential]\n\thelper =\n").is_empty());
        assert_eq!(
            keys("[core]\n\thooksPath = ../../x\n"),
            ["core.hookspath = ../../x"]
        );
    }

    #[test]
    fn the_config_is_read_the_way_git_reads_it() {
        let keys = |text: &str| -> Vec<String> {
            executing_keys(text)
                .into_iter()
                .map(|(line, excerpt)| format!("{line}:{excerpt}"))
                .collect()
        };
        // A key on its section's line, a byte-order mark, a continued line.
        assert_eq!(
            keys("[core] fsmonitor = sh x\n"),
            ["1:core.fsmonitor = sh x"]
        );
        assert_eq!(
            keys("\u{feff}[core]\n\tfsmonitor = sh x\n"),
            ["2:core.fsmonitor = sh x"]
        );
        assert_eq!(
            keys("[core]\n\tfsmoni\\\ntor = sh x\n\tbare = false\n"),
            ["2:core.fsmonitor = sh x"]
        );
        // A value ending in an escaped backslash, or in a comment that
        // ends in one, does not swallow the next line either; and a `]`
        // inside a quoted subsection does not end the header.
        assert_eq!(
            keys("[core]\n\tbare = x\\\\\n\tfsmonitor = sh x\n"),
            ["3:core.fsmonitor = sh x"]
        );
        assert_eq!(
            keys("[core]\n\tbare = x # c \\\n\tfsmonitor = sh x\n"),
            ["3:core.fsmonitor = sh x"]
        );
        assert_eq!(
            keys("[remote \"a]b\"] uploadpack = sh x\n"),
            ["1:remote.a]b.uploadpack = sh x"]
        );
        // A header that may be the rest of a continued value does not
        // take the keys after it out of the section before.
        assert_eq!(
            keys("[core]\n\tx = a\\\n[alias]\n\tfsmonitor = sh x\n"),
            ["4:core.fsmonitor = sh x"]
        );
        // Quotes around nothing do not hide what a value starts with.
        assert_eq!(
            keys("[alias]\n\tx = \"\" !sh x\n\ty = \"\" \"!sh y\"\n\tz = status\n").len(),
            2
        );
        // A comment ending in a backslash does not swallow the next line.
        assert_eq!(
            keys("[core]\n# note \\\n\tfsmonitor = sh x\n"),
            ["3:core.fsmonitor = sh x"]
        );
        assert!(keys("[submodule \"a\"]\n\tupdate = rebase\n").is_empty());
        // Hooks kept inside the git directory are not files the walk reads.
        assert_eq!(
            keys("[core]\n\thooksPath = .git/x\n\thooksPath = .husky/_\n"),
            ["2:core.hookspath = .git/x"]
        );
        // More keys that name a command.
        let text = "[submodule \"a\"]\n\tupdate = !sh x\n[remote \"origin\"]\n\tuploadpack = sh x\n\turl = https://x.example/r\n[difftool \"d\"]\n\tcmd = sh x\n[gpg \"ssh\"]\n\tdefaultKeyCommand = sh x\n";
        assert_eq!(keys(text).len(), 4, "{:?}", keys(text));
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
