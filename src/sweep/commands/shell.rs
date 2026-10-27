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
pub(crate) fn is_shell_script(path: &str, text: &str) -> bool {
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

/// `text` of a shell script someone runs, started as `started` (relative
/// to the root), with the script's own directory written in where it names
/// it, as scripts find the helpers that lie beside them:
/// `$(dirname "$0")`, `${0%/*}`, under bash also `$(dirname
/// "${BASH_SOURCE[0]}")` and `${BASH_SOURCE%/*}`, the real `file` for
/// `$(readlink -f "$0")` and `$(realpath "$0")` (and its directory for
/// `dirname` of that), and `$(cd "…" && pwd)` around such a directory.
/// `SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"` then sets a path variable
/// like any other.
///
/// `$0` is the path the script was started by, so `started` is the link
/// that led to `file` where one did; in a file a shell sources it is the shell,
/// which is why a start-up file never comes here. `$BASH_SOURCE` is only
/// set under bash, so only a script whose first line names bash has it
/// written in; one handed to `sh` despite that line is read as if bash ran
/// it. A line that is long, or that would grow long, is left as written:
/// its `$(dirname` then names no file, and following says so.
pub(crate) fn with_script_directory(text: &str, started: &str, file: &str) -> String {
    let bash = text
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("#!"))
        .and_then(shebang_shell)
        == Some("bash");
    let directory = |path: &str| {
        path.rsplit_once('/')
            .map_or_else(|| "/".to_string(), |(directory, _)| format!("/{directory}"))
    };
    let own = OwnPath {
        started: format!("/{started}"),
        directory: directory(started),
        file: format!("/{file}"),
        file_directory: directory(file),
        bash,
    };
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let written = (line.len() <= MAX_STARTED_LINE)
            .then(|| own.written_in(line))
            .filter(|written| written.len() <= MAX_STARTED_LINE);
        out.push_str(written.as_deref().unwrap_or(line));
    }
    out
}

/// What a script someone runs names itself by: `$0` and its directory,
/// the real file a link to it resolves to and that file's directory, and
/// whether `$BASH_SOURCE` is set (it runs under bash).
struct OwnPath {
    started: String,
    directory: String,
    file: String,
    file_directory: String,
    bash: bool,
}

impl OwnPath {
    /// `line` with the script's own file and directory written in (see
    /// `with_script_directory`).
    fn written_in(&self, line: &str) -> String {
        if !line.contains("dirname")
            && !line.contains("${0%")
            && !line.contains("BASH_SOURCE")
            && !line.contains("readlink")
            && !line.contains("realpath")
        {
            return line.to_string();
        }
        let mut line = line.replace("${0%/*}", &self.directory);
        if self.bash {
            for trimmed in ["${BASH_SOURCE%/*}", "${BASH_SOURCE[0]%/*}"] {
                line = line.replace(trimmed, &self.directory);
            }
        }
        // Inner substitutions first: each pass writes in those that hold
        // no other, so `$(cd "$(dirname "$0")" && pwd)` takes two.
        for _ in 0..MAX_NESTED_SUBSTITUTIONS {
            let (written, changed) = self.substitutions_written(&line);
            line = written;
            if !changed {
                break;
            }
        }
        line
    }

    /// `line` with each `$(…)` that holds no other and that `call` knows
    /// written in, and whether any was. Linear in the line: where a `$(`
    /// holds another, the scan goes on from the last one inside it, so no
    /// stretch of the line is searched for its `)` twice.
    fn substitutions_written(&self, line: &str) -> (String, bool) {
        let mut out = String::with_capacity(line.len());
        let mut changed = false;
        let mut rest = line;
        while let Some(at) = rest.find("$(") {
            out.push_str(&rest[..at]);
            let inner = &rest[at + 2..];
            let Some(end) = inner.find(')') else {
                rest = &rest[at..];
                break;
            };
            if let Some(nested) = inner[..end].rfind("$(") {
                out.push_str("$(");
                out.push_str(&inner[..nested]);
                rest = &inner[nested..];
            } else if let Some(written) = self.call(&inner[..end]) {
                out.push_str(written);
                changed = true;
                rest = &inner[end + 1..];
            } else {
                out.push_str("$(");
                rest = inner;
            }
        }
        out.push_str(rest);
        (out, changed)
    }

    /// What the command `call` inside `$(…)` prints when it asks for the
    /// script's own file or directory: the real file for `readlink -f` or
    /// `realpath` of the script, the directory for `dirname` of either, and
    /// for `cd` into such a directory and `pwd`. A word is bare or wrapped
    /// in one pair of double quotes, nothing else: `'$0'` is the text `$0`,
    /// and a quote left open (`"$0)/x"`) means the `)` was not the end.
    fn call(&self, call: &str) -> Option<&str> {
        let words: Vec<&str> = call
            .split_whitespace()
            .map(unquoted)
            .filter(|word| *word != Some("--"))
            .collect::<Option<_>>()?;
        let is_script = |word: &str| {
            word == self.started
                || matches!(word, "$0" | "${0}")
                || (self.bash
                    && matches!(
                        word,
                        "$BASH_SOURCE" | "${BASH_SOURCE}" | "${BASH_SOURCE[0]}"
                    ))
        };
        match words.as_slice() {
            ["readlink", "-f", script] | ["realpath", script] if is_script(script) => {
                Some(&self.file)
            }
            ["dirname", script] if is_script(script) => Some(&self.directory),
            ["dirname", file] if *file == self.file => Some(&self.file_directory),
            ["cd", "-P" | "-L", there, rest @ ..] | ["cd", there, rest @ ..] if is_pwd(rest) => {
                [&self.directory, &self.file_directory]
                    .into_iter()
                    .find(|directory| *there == directory.as_str())
                    .map(String::as_str)
            }
            _ => None,
        }
    }
}

/// `word` without the one pair of double quotes around it, if it has
/// them; `None` for any other quote in it.
fn unquoted(word: &str) -> Option<&str> {
    match word
        .strip_prefix('"')
        .and_then(|word| word.strip_suffix('"'))
    {
        Some(inner) if !inner.contains('"') => Some(inner),
        Some(_) => None,
        None => (!word.contains(['"', '\''])).then_some(word),
    }
}

/// Whether `rest`, the words after `cd DIR`, only print where that left
/// the shell: `cd`'s output sent nowhere, then `&& pwd` or `; pwd`, with
/// `-P` or `-L` and nothing after it.
fn is_pwd(rest: &[&str]) -> bool {
    let Some(at) = rest.iter().position(|word| matches!(*word, "&&" | ";")) else {
        return false;
    };
    let quiet = rest[..at].iter().all(|word| {
        matches!(
            *word,
            "&>" | ">" | "/dev/null" | ">/dev/null" | "&>/dev/null" | "2>&1" | "2>/dev/null"
        )
    });
    quiet && matches!(rest[at + 1..], ["pwd"] | ["pwd", "-P" | "-L"])
}

/// How deep `$(…)` inside `$(…)` is written in; three covers
/// `$(cd "$(dirname "$(readlink -f "$0")")" && pwd)`.
const MAX_NESTED_SUBSTITUTIONS: usize = 3;

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
pub(crate) fn sourced_files(text: &str) -> Vec<String> {
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
    // A word of slashes alone is no program: `//` is jq's operator in a
    // quoted filter (`jq '.a | .b // ""'`), cut out where the line is split
    // at the `|` inside it.
    let is_path = |word: &str| {
        ["/", "~/", "$HOME/", "${HOME}/"]
            .iter()
            .any(|start| word.starts_with(start))
            && !word.chars().all(|c| c == '/')
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
        let is_command = |word: &String| {
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
        };
        let words = split(statement);
        // A command that is itself a substitution (`"$(dirname "$1")/x"`)
        // names a program no one can tell: kept as written, following says
        // so.
        if let Some(word) = words.iter().find(|word| is_command(word))
            && (word.contains("$(") || word.contains('`'))
        {
            let word = clean(word);
            if !found.contains(&word) {
                found.push(word);
            }
            continue;
        }
        // The words inside a substitution (`X=$(find /etc/x)`) are not the
        // statement's command: the substitution is read below. What comes
        // after it (`X=$(date) ~/bin/y`) still is.
        let mut depth = 0_usize;
        let mut ticked = false;
        let words: Vec<String> = words
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
        let first = words.into_iter().find(|word| is_command(word));
        // A command under a variable's directory (`"$TOOLS/x"`) is kept
        // too: where it leads is not known, and following says so.
        let under_variable = |word: &str| {
            word.contains('/')
                && word.strip_prefix('$').is_some_and(|name| {
                    name.starts_with(|c: char| c == '{' || c == '_' || c.is_ascii_alphanumeric())
                })
        };
        if let Some(word) = first
            .map(|word| clean(&word))
            .filter(|word| is_path(word) || under_variable(word))
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
