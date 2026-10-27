//! What a shell start-up file starts: whether a file is a shell script, the
//! files it sources, the programs its lines name, and the variables and
//! `case` patterns on the way to them.

use super::{MAX_STARTED_LINE, MAX_SUBSTITUTIONS, split};
use crate::paths::file_name;
use crate::sweep::programs::{SCRIPT_SHELLS, is_script_shell, runs_a_script};
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
///
/// Nothing is written in for a path a shell would read as more than a
/// word: whoever plants a script picks its directory, and one holding a
/// quote, a space, `;` or `$(` would split the line around it into other
/// statements, hiding a program that follows.
pub(crate) fn with_script_directory(text: &str, started: &str, file: &str) -> String {
    let plain = |path: &str| {
        path.chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-+@%,:".contains(c))
    };
    if !plain(started) || !plain(file) {
        return text.to_string();
    }
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
/// the shell: `cd`'s output sent nowhere, then `&& pwd`, or `; pwd` with
/// the `;` a word of its own, with `-P` or `-L` and nothing after it. A
/// `/dev/null` not after a redirection is a second argument, which makes
/// `cd` fail.
fn is_pwd(rest: &[&str]) -> bool {
    let Some(at) = rest.iter().position(|word| matches!(*word, "&&" | ";")) else {
        return false;
    };
    let mut words = rest[..at].iter();
    while let Some(word) = words.next() {
        let quiet = match *word {
            ">/dev/null" | "&>/dev/null" | "2>/dev/null" | "2>&1" => true,
            ">" | "&>" | "2>" => words.next() == Some(&"/dev/null"),
            _ => false,
        };
        if !quiet {
            return false;
        }
    }
    matches!(rest[at + 1..], ["pwd"] | ["pwd", "-P" | "-L"])
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

/// Whether `word` names a program by a path.
///
/// A word of slashes alone is no program: `//` is jq's operator in a
/// quoted filter (`jq '.a | .b // ""'`), cut out where the line is split
/// at the `|` inside it.
fn is_path(word: &str) -> bool {
    ["/", "~/", "$HOME/", "${HOME}/"]
        .iter()
        .any(|start| word.starts_with(start))
        && !word.chars().all(|c| c == '/')
}

/// Whether `word` is a statement's command, not what comes before it:
/// keywords, wrappers that run it, assignments, a `case` pattern.
fn is_command(word: &str) -> bool {
    !(matches!(
        word,
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
}

/// The command line of a statement whose command, `words[0]`, is an
/// interpreter (or `env`) handed a path (`bash "$DIR/x.sh"`,
/// `/usr/bin/env python3 /opt/x/check.py`), for following to find its
/// script as on any command line, or to say it is unknown. awk is left
/// out: its first operand is its program (`'{print $1}'`), and the paths
/// after that are what it reads. A word no quote can hold ends the line
/// past the first path; before it, the statement is left as it was.
fn handed_script(words: &[String]) -> Option<String> {
    let (interpreter, arguments) = words.split_first()?;
    let name = file_name(interpreter);
    let handed = (runs_a_script(name) || name == "env") && !matches!(name, "awk" | "gawk" | "mawk");
    let first_path = arguments.iter().position(|word| word.contains('/'))? + 1;
    if !handed {
        return None;
    }
    let mut line = Vec::new();
    for (at, word) in words.iter().enumerate() {
        match quoted(word) {
            Some(word) => line.push(word),
            None if at > first_path => break,
            None => return None,
        }
    }
    Some(line.join(" "))
}

/// `word` as one word of a command line `split` reads back: as it is, or
/// in the quotes it does not hold.
fn quoted(word: &str) -> Option<String> {
    if !word.contains([' ', '\t', '\'', '"']) {
        Some(word.to_string())
    } else if !word.contains('\'') {
        Some(format!("'{word}'"))
    } else {
        (!word.contains('"')).then(|| format!("\"{word}\""))
    }
}

/// Whether `word` names a command under a variable's directory
/// (`"$TOOLS/x"`, `$1/x`): where it leads is not known, and following says
/// so.
fn is_under_variable(word: &str) -> bool {
    word.contains('/')
        && word.strip_prefix('$').is_some_and(|name| {
            name.starts_with(|c: char| c == '{' || c == '_' || c.is_ascii_alphanumeric())
        })
}

/// Whether a line of a shell script starts statements, or goes on with
/// something begun before it: the arguments of a command whose line ended
/// in `\`, or the text of a here-document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LineStart {
    Command,
    Argument,
}

/// Where a shell script's lines stand: inside a command whose line ended
/// with `\`, or inside a here-document until the word that ends it.
#[derive(Debug, Default)]
pub(super) struct LineStarts {
    continued: bool,
    here_document: Option<String>,
}

impl LineStarts {
    /// How `raw` starts, given the lines before it. Untrimmed: `echo \ `
    /// ends in an escaped blank, not in a `\` that goes on.
    pub(super) fn next(&mut self, raw: &str) -> LineStart {
        let start = if self.continued || self.here_document.is_some() {
            LineStart::Argument
        } else {
            LineStart::Command
        };
        let line = raw.trim();
        let comment = line.starts_with('#');
        self.continued = !comment && continues(raw);
        match &self.here_document {
            Some(end) if line == end => self.here_document = None,
            None if !comment => self.here_document = here_document_end(line),
            Some(_) | None => {}
        }
        start
    }
}

/// Whether `line` goes on into the next one: it ends in an odd number of
/// backslashes (an even number is that many escaped backslashes).
fn continues(line: &str) -> bool {
    let trailing = line.len() - line.trim_end_matches('\\').len();
    trailing % 2 == 1
}

/// The word that ends a here-document `line` opens (`cat <<EOF`,
/// `<<-'END'`), if it opens one. A here-string (`<<<`) names no word, as
/// the word stops at a `<`. A shift (`$((x << 2))`) is taken for one too:
/// the lines after it are then read as arguments, which only leaves out
/// what `LineStart::Command` adds.
fn here_document_end(line: &str) -> Option<String> {
    let at = line.find("<<")?;
    let rest = line[at + 2..].trim_start_matches('-').trim_start();
    let word: String = rest
        .chars()
        .take_while(|c| !c.is_whitespace() && !matches!(c, ';' | '&' | '|' | '<' | '>' | ')'))
        .filter(|c| !matches!(c, '\'' | '"' | '\\'))
        .collect();
    (!word.is_empty()).then_some(word)
}

/// The programs a line of a shell start-up file names by a path, as the
/// command of a statement (`~/bin/agent &`, `cd x && exec /opt/x/run`) or
/// inside a substitution (`eval "$(~/bin/tool init)"`). A bare name is not
/// looked up: it is a shell builtin or an ordinary command far more often
/// than not. A very long line is left to the review of the file's text.
///
/// A statement or substitution whose command is an interpreter handed a
/// path (`bash "$D/x.sh"`) is returned whole (see `handed_script`), so
/// following finds its script or says it is unknown.
///
/// A command named through a variable (`"$TOOLS/x"`) or a substitution
/// (`"$(dirname "$1")/x"`) is kept for following to say it is unknown,
/// but only on a line that starts statements (`LineStart::Command`) and
/// not in a `[[ … ]]` test or `(( … ))` arithmetic: elsewhere such a word
/// is far more often an argument than a command. Anything else is read
/// the same on every line.
///
/// So a script can turn that note off: for the rest of the file with a
/// `<<` whose word never comes again, and for the next line with a line
/// ending in `\` before the command. That only takes it back to how a
/// script was read before the note existed; telling every such line apart
/// needs quotes followed across lines.
pub(super) fn started(line: &str, start: LineStart) -> Vec<String> {
    if line.len() > MAX_STARTED_LINE {
        return Vec::new();
    }
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
        let words = split(statement);
        let handed = words
            .iter()
            .position(|word| is_command(word))
            .and_then(|at| handed_script(&words[at..]));
        // A command that is itself a substitution (`"$(dirname "$1")/x"`)
        // names a program no one can tell: kept as written, following says
        // so. The statement is still read below, since an empty
        // substitution leaves the next word as the command
        // (`$(true) /opt/x`).
        let unknown_kept =
            start == LineStart::Command && words.last().is_none_or(|word| word != "]]");
        if unknown_kept
            && let Some(word) = words.iter().find(|word| is_command(word))
            && (word.contains("$(") || word.contains('`'))
            && !word.starts_with("((")
        {
            let word = clean(word);
            if !found.contains(&word) {
                found.push(word);
            }
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
        if unknown_kept
            && let Some(command) = handed
            && !found.contains(&command)
        {
            found.push(command);
        }
        let first = words.into_iter().find(|word| is_command(word));
        if let Some(word) = first
            .map(|word| clean(&word))
            .filter(|word| is_path(word) || (unknown_kept && is_under_variable(word)))
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
            // `$(perl "$DIR/check.pl")`: an interpreter is handed its script
            // inside one too, and a substitution runs on any line. Each is
            // read up to its first `)` or backtick, at most
            // `MAX_SUBSTITUTIONS` times a line, so one inside it ends it
            // early (`$(python3 "$(pwd)/x.py")` names no path); the
            // script's own directory is written in before this.
            let inner = &line[at + opener.len()..];
            let inner = &inner[..inner.find([')', '`']).unwrap_or(inner.len())];
            if let Some(command) = handed_script(&split(inner))
                && !found.contains(&command)
            {
                found.push(command);
            }
        }
    }
    found
}
