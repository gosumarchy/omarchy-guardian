//! An editor's `settings.json`: reading JSON with comments, and what its
//! keys make the editor or its terminal run, load or send elsewhere.

use super::{
    FROM_TEMPORARY, MAX_ALERTS, bare, graded, is_own_program, is_temporary, proxied,
    sets_what_runs, unchecked,
};

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
            // The two Unicode line separators end a line for an editor.
            let rest = &self.bytes[self.at.min(self.bytes.len())..];
            if rest.starts_with("\u{2028}".as_bytes()) || rest.starts_with("\u{2029}".as_bytes()) {
                self.line += 1;
                self.at += 3;
                continue;
            }
            match (self.peek(), self.bytes.get(self.at + 1).copied()) {
                (Some(b'\n'), _) => {
                    self.line += 1;
                    self.at += 1;
                }
                // A carriage return alone ends a line as well.
                (Some(b'\r'), next) => {
                    self.line += usize::from(next != Some(b'\n'));
                    self.at += 1;
                }
                (Some(b' ' | b'\t'), _) => self.at += 1,
                (Some(b'/'), Some(b'/')) => {
                    // An editor ends the comment at a lone `\r` too, and
                    // at the two Unicode line separators.
                    while self
                        .peek()
                        .is_some_and(|byte| !matches!(byte, b'\n' | b'\r'))
                        && !self.bytes[self.at..].starts_with("\u{2028}".as_bytes())
                        && !self.bytes[self.at..].starts_with("\u{2029}".as_bytes())
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
pub(super) const NOT_SETTINGS: &str =
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
