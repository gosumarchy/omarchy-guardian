//! Reading the statements that set `PATH`: what a line of a shell start-up
//! file, an environment file or a Hyprland configuration gives it, which
//! lines only running them would tell, and which entries anyone can fill.

use super::MAX_PATH_BYTES;

/// What one statement does to `PATH`.
#[derive(Debug, PartialEq, Eq)]
enum Set {
    /// A `:`-separated list, `$PATH` standing for what was there before.
    Value(String),
    /// Something only running it would tell (`PATH=$(…)`).
    Opaque,
}

/// The words of the statements on a line of shell: split at `;`, `&&`,
/// `||`, `|` and `&` outside quotes, and after `then`, `do`, `else`, `{`
/// and the pattern of a `case` branch (`*)`). Quotes are taken off; a
/// substitution (`$(…)`, backquotes) and a zsh list (`(…)`) stay whole,
/// spaces and all. A `#` that starts a word ends the line.
fn statements(line: &str) -> Vec<Vec<String>> {
    let mut found: Vec<Vec<String>> = vec![Vec::new()];
    let mut word = String::new();
    let mut quote: Option<char> = None;
    let mut depth = 0_usize;
    let mut started = false;
    let mut characters = line.chars().peekable();
    let end = |found: &mut Vec<Vec<String>>, word: &mut String, started: &mut bool| {
        if *started && let Some(last) = found.last_mut() {
            last.push(std::mem::take(word));
        }
        *started = false;
        let keyword = found
            .last()
            .and_then(|words| words.last())
            .is_some_and(|last| {
                matches!(
                    last.as_str(),
                    "then"
                        | "do"
                        | "else"
                        | "elif"
                        | "if"
                        | "while"
                        | "{"
                        | "!"
                        | "and"
                        | "or"
                        | "not"
                        | "begin"
                ) || (last.ends_with(')') && !last.contains(['(', '=']))
            });
        if keyword && let Some(last) = found.last_mut() {
            last.pop();
            if !last.is_empty() {
                found.push(Vec::new());
            }
        }
    };
    while let Some(character) = characters.next() {
        match (quote, character) {
            (Some(open), _) if character == open && open != '`' => quote = None,
            (Some('`'), '`') => {
                quote = None;
                word.push(character);
            }
            (Some(_), _) => word.push(character),
            (None, '(') => {
                depth += 1;
                started = true;
                word.push(character);
            }
            (None, ')') if depth > 0 => {
                depth -= 1;
                word.push(character);
            }
            (None, _) if depth > 0 => word.push(character),
            (None, '"' | '\'') => {
                quote = Some(character);
                started = true;
            }
            (None, '`') => {
                quote = Some(character);
                started = true;
                word.push(character);
            }
            (None, '#') if !started => break,
            (None, ';' | '|' | '&') => {
                end(&mut found, &mut word, &mut started);
                while characters
                    .next_if(|next| matches!(next, ';' | '|' | '&'))
                    .is_some()
                {}
                if found.last().is_some_and(|last| !last.is_empty()) {
                    found.push(Vec::new());
                }
            }
            (None, _) if character.is_whitespace() => end(&mut found, &mut word, &mut started),
            (None, _) => {
                started = true;
                word.push(character);
            }
        }
    }
    end(&mut found, &mut word, &mut started);
    found.retain(|words| !words.is_empty());
    found
}

/// A `PATH` value with the ways of writing "what was there before"
/// reduced to `$PATH`.
fn plain_value(value: &str) -> String {
    value
        .replace("${PATH:+$PATH:}", "$PATH:")
        .replace("${PATH:+:$PATH}", ":$PATH")
        .replace("${PATH:+:${PATH}}", ":$PATH")
        .replace("${PATH:+${PATH}:}", "$PATH:")
        .replace("@{PATH}", "$PATH")
        .replace("@{HOME}", "$HOME")
}

/// What an assignment word (`PATH=x`, `PATH+=x`, `path=(a b)`) does to
/// `PATH`, if it is one to it.
fn assigned(word: &str) -> Option<Set> {
    let (name, value) = word.split_once('=')?;
    let (name, append) = match name.strip_suffix('+') {
        Some(name) => (name, true),
        None => (name, false),
    };
    if !matches!(name, "PATH" | "path") {
        return None;
    }
    let list = value
        .strip_prefix('(')
        .map(|list| list.trim_end_matches(')'));
    if list.unwrap_or(value).contains(['(', '`']) {
        return Some(Set::Opaque);
    }
    Some(Set::Value(match (list, append) {
        (Some(list), false) => list.split_whitespace().collect::<Vec<_>>().join(":"),
        (Some(list), true) => format!(
            "$PATH:{}",
            list.split_whitespace().collect::<Vec<_>>().join(":")
        ),
        // bash appends the text as it is (`PATH+=:/x`).
        (None, true) => format!("$PATH{}", plain_value(value)),
        (None, false) if name == "PATH" => plain_value(value),
        (None, false) => return None,
    }))
}

/// What the statement `words` does to `PATH`: an assignment on its own or
/// after `export`, `declare`, `typeset`, `local` or `readonly` (among
/// others: `export A=1 PATH=…`), fish's `set PATH …` and `fish_add_path`,
/// csh's `setenv PATH …`, and a line of `~/.pam_environment`. An
/// assignment before a command (`PATH=x make`) is for that command alone.
fn path_set(words: &[String]) -> Option<Set> {
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    let (first, rest) = words.split_first()?;
    let values = |values: &[&str]| {
        if values.iter().any(|value| value.contains(['(', '`'])) {
            Set::Opaque
        } else {
            Set::Value(plain_value(&values.join(":")))
        }
    };
    match *first {
        "export" | "declare" | "typeset" | "local" | "readonly" => rest
            .iter()
            .filter(|word| !word.starts_with(['-', '+']))
            .find_map(|word| assigned(word)),
        "set" => {
            let at = rest.iter().position(|word| !word.starts_with('-'))?;
            matches!(rest[at], "PATH" | "fish_user_paths").then(|| values(&rest[at + 1..]))
        }
        "setenv" if rest.first() == Some(&"PATH") => Some(values(&rest[1..])),
        "fish_add_path" => {
            let append = rest.iter().any(|word| matches!(*word, "-a" | "--append"));
            let directories: Vec<&str> = rest
                .iter()
                .filter(|word| !word.starts_with('-'))
                .copied()
                .collect();
            let listed = directories.join(":");
            Some(match values(&directories) {
                Set::Opaque => Set::Opaque,
                Set::Value(_) if append => Set::Value(format!("$PATH:{listed}")),
                Set::Value(_) => Set::Value(format!("{listed}:$PATH")),
            })
        }
        "PATH" => rest
            .iter()
            .find_map(|word| {
                word.strip_prefix("DEFAULT=")
                    .or_else(|| word.strip_prefix("OVERRIDE="))
            })
            .map(|value| values(&[value])),
        _ if words.iter().all(|word| is_assignment(word)) => {
            words.iter().find_map(|word| assigned(word))
        }
        _ => None,
    }
}

/// Whether `word` assigns to a variable (`NAME=value`, `NAME+=value`).
fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        let name = name.strip_suffix('+').unwrap_or(name);
        name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// What a line of Hyprland's configuration does to `PATH`: `env =
/// PATH,value`, or in Lua `hl.env("PATH", "value")`, where a value that is
/// not written out is known only to Hyprland.
fn hyprland(line: &str) -> Option<Set> {
    if let Some(rest) = line.strip_prefix("env")
        && let Some(setting) = rest.trim_start().strip_prefix('=')
    {
        let (name, value) = setting.split_once(',')?;
        return (name.trim() == "PATH").then(|| Set::Value(plain_value(value.trim())));
    }
    let (_, call) = line.split_once(".env(")?;
    let mut arguments = call.splitn(2, ',');
    let name = arguments.next()?.trim().trim_matches(['"', '\'']);
    if name != "PATH" {
        return None;
    }
    let value = arguments.next()?.trim().trim_end_matches(')').trim();
    let literal = value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .filter(|literal| !literal.contains('"'));
    Some(literal.map_or(Set::Opaque, |literal| Set::Value(plain_value(literal))))
}

/// What each line of `text` does to `PATH`, with its number.
fn scan(text: &str) -> Vec<(usize, Set)> {
    let mut found = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with("--") || line.len() > MAX_PATH_BYTES {
            continue;
        }
        let number = index + 1;
        if let Some(saved) = line
            .strip_prefix("SETUVAR ")
            .and_then(|rest| rest.split_once("fish_user_paths:"))
            .map(|(_, saved)| saved)
        {
            // fish keeps the list with `\\x1e` between its entries.
            let value = format!("{}:$PATH", saved.replace("\\x1e", ":"));
            found.push((number, Set::Value(value)));
        } else if let Some(set) = hyprland(line) {
            found.push((number, set));
        } else {
            found.extend(
                statements(line)
                    .iter()
                    .filter_map(|words| path_set(words))
                    .map(|set| (number, set)),
            );
        }
    }
    found
}

/// The values a start-up file gives `PATH`, each as a `:`-separated list
/// with `$PATH` standing for what was there before, wherever on a line the
/// statement stands (`[ -d ~/.x ] && export PATH=~/.x:$PATH`): `PATH=…`
/// alone or after `export`, `declare -x`, `typeset -x` or `local`, zsh's
/// `path=(…)` and `path+=(…)`, fish's `set PATH …`, `fish_add_path …` and
/// its saved `fish_user_paths`, csh's `setenv`, an environment file's line
/// and Hyprland's `env`.
pub fn assignments(text: &str) -> Vec<(usize, String)> {
    scan(text)
        .into_iter()
        .filter_map(|(line, set)| match set {
            Set::Value(value) => Some((line, value)),
            Set::Opaque => None,
        })
        .collect()
}

/// The lines of `text` that set `PATH` to something only running them
/// would tell (`PATH=$(…)`): the directories they add are not known, so
/// what is in them is not watched.
pub fn opaque(text: &str) -> Vec<usize> {
    let mut lines: Vec<usize> = scan(text)
        .into_iter()
        .filter(|(_, set)| *set == Set::Opaque)
        .map(|(line, _)| line)
        .collect();
    lines.dedup();
    lines
}

/// Directories nothing lasting belongs in, as they appear in a `PATH`.
const TEMPORARY: &[&str] = &["/tmp", "/var/tmp", "/dev/shm", "/run/user/", "/.cache"];

/// The entries of the `PATH`s `text` sets that anyone can fill: the
/// working directory (`.`, or an empty entry), a relative directory, and a
/// temporary or cache directory. Each with its line.
pub fn unsafe_entries(text: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    for (line, value) in assignments(text) {
        for entry in value.split(':') {
            let entry = entry.trim().trim_matches(['"', '\'']);
            let what = if entry.is_empty() || entry == "." {
                Some("the directory a command is typed in is on PATH".to_string())
            } else if TEMPORARY.iter().any(|temporary| {
                entry == *temporary
                    || entry.starts_with(&format!("{}/", temporary.trim_end_matches('/')))
                    || (temporary.starts_with("/.") && entry.contains(temporary))
            }) {
                Some(format!(
                    "a temporary or cache directory is on PATH: {entry}"
                ))
            } else {
                None
            };
            if let Some(what) = what
                && !found.contains(&(line, what.clone()))
            {
                found.push((line, what));
            }
        }
    }
    found
}
