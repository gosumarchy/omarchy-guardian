//! What a shell start-up file starts: whether a file is a shell script, the
//! files it sources, the programs its lines name, and the variables and
//! `case` patterns on the way to them.

use super::{MAX_STARTED_LINE, MAX_SUBSTITUTIONS, split};
use crate::paths::file_name;
use crate::sweep::programs::{SCRIPT_SHELLS, is_script_shell};
use crate::sweep::read;

/// The shell a `#!` line (without the `#!`) runs, if it runs one: the
/// program itself, the one `env` is told to start (past its options, the
/// variables it sets or unsets, and inside the one word `-S` takes), or
/// the shell `busybox` is asked to be.
fn shebang_shell(line: &str) -> Option<&str> {
    fn named(word: &str) -> &str {
        file_name(word)
    }
    let mut words = line.split_whitespace().peekable();
    let mut name = named(words.next()?);
    if name == "env" {
        loop {
            let word = words.next()?;
            if matches!(word, "-u" | "--unset" | "-C" | "--chdir") {
                words.next();
            } else if !(word.starts_with('-') || word.contains('=')) {
                name = named(word);
                break;
            }
        }
    }
    if name == "busybox" {
        name = named(words.next()?);
    }
    is_script_shell(name).then_some(name)
}

/// Whether the file at `path` with content `text` is a shell script: its
/// first line names one of `SCRIPT_SHELLS` (also through `env` or
/// `busybox`, and after a byte-order mark), or it has no such line and its
/// name ends in one of theirs (`x.sh`). A script of another interpreter
/// (Python, Perl, Node, fish) is not read as one.
pub fn is_shell_script(path: &str, text: &str) -> bool {
    let first = text
        .trim_start_matches('\u{feff}')
        .lines()
        .next()
        .unwrap_or_default();
    if let Some(line) = first.strip_prefix("#!") {
        return shebang_shell(line).is_some();
    }
    let name = file_name(path);
    SCRIPT_SHELLS
        .iter()
        .any(|shell| read::has_extension(name, shell))
}

/// The start-up files zsh reads from the directory a `ZDOTDIR=` line names
/// instead of the home.
pub(super) fn zdotdir(line: &str) -> Vec<String> {
    let line = line.strip_prefix("export ").unwrap_or(line);
    let Some(value) = line.strip_prefix("ZDOTDIR=") else {
        return Vec::new();
    };
    let directory = value
        .split([';', ' ', '\t'])
        .next()
        .unwrap_or_default()
        .trim_matches(['"', '\''])
        .trim_end_matches('/');
    if directory.is_empty() || directory.contains(['`', '(']) {
        return Vec::new();
    }
    [".zshenv", ".zprofile", ".zshrc", ".zlogin", ".zlogout"]
        .iter()
        .map(|file| format!("{directory}/{file}"))
        .collect()
}

/// Variables a shell start-up file sets to a path (`TOOLS=~/opt/tools`,
/// `export BIN="$HOME/bin"`), so `$TOOLS/run` is looked at as that path.
pub(super) fn path_variables(text: &str) -> Vec<(String, String)> {
    let mut found: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim_matches(['"', '\'']);
        let is_name = name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        let is_path = ["/", "~/", "$HOME/", "${HOME}/"]
            .iter()
            .any(|start| value.starts_with(start));
        // No other variable in it: written out once, a path never grows
        // into more paths.
        let rest = value
            .strip_prefix("$HOME")
            .or_else(|| value.strip_prefix("${HOME}"))
            .unwrap_or(value);
        if is_name
            && name != "HOME"
            && is_path
            && !value.contains(char::is_whitespace)
            && !rest.contains(['$', '`'])
        {
            found.retain(|(known, _)| known != name);
            found.push((name.to_string(), value.to_string()));
            if found.len() > MAX_PATH_VARIABLES {
                found.remove(0);
            }
        }
    }
    found
}

/// The most path variables one start-up file keeps.
const MAX_PATH_VARIABLES: usize = 32;

/// The files a shell start-up file reads in (see `sourced`), with the
/// variables it sets to a path written out (`$OMARCHY_PATH/default/x`).
pub fn sourced_files(text: &str) -> Vec<String> {
    let variables = path_variables(text);
    text.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#') && line.len() <= MAX_STARTED_LINE)
        .flat_map(|line| sourced(&crate::rules::with_variables(line, &variables)))
        .collect()
}

/// The files a line of a shell start-up file reads in: `source file` and
/// `. file`, also behind a test (`[ -r file ] && . file`). The file runs as
/// part of the one that names it.
pub(super) fn sourced(line: &str) -> Vec<String> {
    let words: Vec<&str> = line.split_whitespace().collect();
    words
        .windows(2)
        .enumerate()
        .filter(|(index, pair)| {
            matches!(pair[0], "source" | ".")
                && (*index == 0
                    || matches!(
                        words[index - 1],
                        "&&" | "||" | "then" | "do" | "else" | "{" | "("
                    )
                    || words[index - 1].ends_with(';'))
        })
        .map(|(_, pair)| pair[1].trim_matches(['"', '\'', ';']).to_string())
        .filter(|file| !file.is_empty())
        .collect()
}

/// `line` of a shell file without the patterns of its `case` branches
/// (`pat)`, `a|b)`, `(pat)`), which are matched against a word and run
/// nothing: `/*)` is no program, and neither are the directories it would
/// name as a pattern of files. `cases` carries, from line to line and for
/// each `case` that is open, whether a pattern comes next.
///
/// Only a pattern where the shell reads one is taken out (after `in` and
/// after `;;` of a `case` that starts a statement), so a line that merely
/// looks like one (`( ~/bin/x )` on its own, a subshell) stays a command.
pub(super) fn without_case_patterns(line: &str, cases: &mut Vec<bool>) -> String {
    let mut kept = String::new();
    for (index, piece) in line.split(";;").enumerate() {
        if index > 0 {
            kept.push_str(" ; ");
            if let Some(next) = cases.last_mut() {
                *next = true;
            }
        }
        let mut rest = piece;
        loop {
            if cases.last() == Some(&true) {
                let branch = rest
                    .trim_start()
                    .trim_start_matches(['&', ';'])
                    .trim_start();
                if is_word_at(branch, "esac") {
                    cases.pop();
                    rest = &branch["esac".len()..];
                    continue;
                }
                // A comment after `;;` is not the next pattern.
                if !branch.is_empty() && !branch.starts_with('#') {
                    if let Some(end) = case_pattern_end(branch) {
                        rest = &branch[end..];
                    }
                    if let Some(next) = cases.last_mut() {
                        *next = false;
                    }
                }
            }
            // A `case` among this branch's commands (or the first one),
            // and where one ends.
            let opened = case_opening(rest);
            let closed = word_position(rest, "esac").filter(|_| !cases.is_empty());
            match (opened, closed) {
                (Some(after), closed) if closed.is_none_or(|closed| after < closed) => {
                    // What follows the patterns is a statement of its own.
                    kept.push_str(&rest[..after]);
                    kept.push_str(" ; ");
                    rest = &rest[after..];
                    cases.push(true);
                }
                (_, Some(closed)) => {
                    kept.push_str(&rest[..closed]);
                    rest = &rest[closed + "esac".len()..];
                    cases.pop();
                }
                _ => break,
            }
        }
        kept.push_str(rest);
    }
    kept
}

/// Whether `text` starts with the shell word `word`.
fn is_word_at(text: &str, word: &str) -> bool {
    text.strip_prefix(word).is_some_and(|rest| {
        rest.chars()
            .next()
            .is_none_or(|next| next.is_whitespace() || ";&|)".contains(next))
    })
}

/// Where the shell word `word` starts in `text`, as a word of its own.
fn word_position(text: &str, word: &str) -> Option<usize> {
    text.match_indices(word).map(|(at, _)| at).find(|at| {
        is_word_at(&text[*at..], word)
            && text[..*at]
                .chars()
                .next_back()
                .is_none_or(|before| before.is_whitespace() || ";&|(".contains(before))
    })
}

/// Where the patterns begin after a `case WORD in` in `text`. The `case`
/// must start a statement: the word in an `echo` opens nothing, and so
/// cannot make the lines after it read as patterns.
fn case_opening(text: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(at) = word_position(&text[from..], "case").map(|at| at + from) {
        from = at + "case".len();
        let before = text[..at].trim_end();
        let starts = before.is_empty()
            || before.ends_with([';', '&', '|', '{', '(', ')'])
            || ["then", "do", "else"].iter().any(|keyword| {
                before.ends_with(keyword)
                    && word_position(before, keyword) == Some(before.len() - keyword.len())
            });
        if !starts {
            continue;
        }
        if let Some(after) = word_position(&text[from..], "in") {
            return Some(from + after + "in".len());
        }
    }
    None
}

/// Where a `case` pattern at the start of `branch` ends (past its `)`):
/// alternatives with no blank in them, and no substitution or statement
/// before the bracket.
fn case_pattern_end(branch: &str) -> Option<usize> {
    let open = usize::from(branch.starts_with('('));
    let close = branch[open..].find(')')? + open;
    let pattern = &branch[open..close];
    let plain = !pattern.trim().is_empty()
        && !pattern.contains(['(', ';', '&', '`'])
        && pattern
            .split('|')
            .all(|alternative| !alternative.trim().contains(char::is_whitespace));
    plain.then_some(close + 1)
}

/// The programs a line of a shell start-up file names by a path, as the
/// command of a statement (`~/bin/agent &`, `cd x && exec /opt/x/run`) or
/// inside a substitution (`eval "$(~/bin/tool init)"`). A bare name is not
/// looked up: it is a shell builtin or an ordinary command far more often
/// than not. A very long line is left to the review of the file's text.
pub(super) fn started(line: &str) -> Vec<String> {
    if line.len() > MAX_STARTED_LINE {
        return Vec::new();
    }
    let is_path = |word: &str| {
        ["/", "~/", "$HOME/", "${HOME}/"]
            .iter()
            .any(|start| word.starts_with(start))
    };
    let clean = |word: &str| {
        word.trim_matches(['"', '\'', ';', '&', ')', '(', '`'])
            .to_string()
    };
    let mut found = Vec::new();
    // `>&` and `&>` are redirections, not the end of a statement.
    let statements = line
        .replace("&&", ";")
        .replace("||", ";")
        .replace(">&", "> ")
        .replace("&>", " >");
    for statement in statements.split([';', '|', '&']) {
        // Past what comes before a command: keywords, wrappers that run
        // it, assignments, a `case` pattern.
        // The words inside a substitution (`X=$(find /etc/x)`) are not the
        // statement's command: the substitution is read below. What comes
        // after it (`X=$(date) ~/bin/y`) still is.
        let mut depth = 0_usize;
        let mut ticked = false;
        let words: Vec<String> = split(statement)
            .into_iter()
            .filter(|word| {
                let opens = word.contains("$(");
                let inside = depth > 0 || ticked || opens || word.contains('`');
                // Only a substitution's own brackets count: a subshell
                // `( ~/bin/y )` hides nothing.
                if depth > 0 || opens {
                    depth = (depth + word.matches('(').count())
                        .saturating_sub(word.matches(')').count());
                }
                ticked ^= word.matches('`').count() % 2 == 1;
                !inside
            })
            .collect();
        let first = words.into_iter().find(|word| {
            !(matches!(
                word.as_str(),
                "exec"
                    | "nohup"
                    | "command"
                    | "setsid"
                    | "env"
                    | "nice"
                    | "time"
                    | "sudo"
                    | "doas"
                    | "if"
                    | "elif"
                    | "while"
                    | "until"
                    | "then"
                    | "do"
                    | "else"
                    | "!"
                    | "{"
                    | "("
            ) || (word.contains('=') && !is_path(word))
                // A `case` pattern (`x)`), not a subshell's last program.
                || (word.ends_with(')') && !is_path(word.trim_end_matches(')')))
                || word.starts_with(['>', '<'])
                || word.starts_with('-'))
        });
        if let Some(word) = first.map(|word| clean(&word)).filter(|word| is_path(word))
            && !found.contains(&word)
        {
            found.push(word);
        }
    }
    for opener in ["$(", "`"] {
        for (at, _) in line.match_indices(opener).take(MAX_SUBSTITUTIONS) {
            let word = line[at + opener.len()..]
                .split_whitespace()
                .next()
                .map(clean)
                .unwrap_or_default();
            if is_path(&word) && !found.contains(&word) {
                found.push(word);
            }
        }
    }
    found
}
