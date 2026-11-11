//! Reads shell start-up files line by line, to tell whether the line that
//! loads Guardian's Bash interceptor can take effect, and whether an alias
//! or function stands in front of an AUR helper.
//!
//! This is a line scanner, not a shell: it follows blocks, here-documents,
//! quoted text over several lines and continued lines by their usual spelling.
//! It errs towards "not effective". What another file sourced from here does is
//! not seen, nor code written to hide what it runs (a command named by a
//! variable, `\x` escapes in `$'…'`, a quoted or escaped `exec` such as `"exec"
//! bash`): whoever writes the file can do anything. Nor is a function or alias
//! defined before the line and run after it (or named by a hook, or one that
//! runs `exec` when it is called), `set -r`, or a syntax error that stops bash
//! reading the file. A loop that unsets functions by a name it does not spell
//! out (`unset -f "$f"`) is told as taking the interceptor away: it may. A
//! command or block that runs in a subshell, in a pipeline or put in the
//! background (`exec bash &`, `{ exec bash; } &`), is read as the file's own:
//! it errs towards an alarm.

use std::collections::VecDeque;

/// What the interceptor defines. Unset, redefined or aliased after it is
/// loaded, the command goes straight to Omarchy again.
const INTERCEPTED: [&str; 6] = [
    "omarchy",
    "omarchy-theme-install",
    "omarchy-theme-update",
    "omarchy-plugin-add",
    "omarchy-plugin-update",
    "_omarchy_guardian_help_requested",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Loads {
    /// Nothing in the file names the interceptor.
    Missing,
    Effective,
    /// The file names it, and it does not take effect: why.
    Ineffective(String),
}

/// The words of a line of code: split at blanks and `;`.
fn words(code: &str) -> Vec<&str> {
    code.split(|character: char| character.is_whitespace() || character == ';')
        .filter(|word| !word.is_empty())
        .collect()
}

/// The first word of each command on a line: after `;`, `&&`, `||`, `|`,
/// and past the words that only lead into a command (`do if`, `else if`,
/// `! if`, `time if`).
fn command_words(code: &str) -> Vec<&str> {
    code.split([';', '&', '|'])
        .filter_map(|command| {
            command
                .split_whitespace()
                .find(|word| !matches!(*word, "do" | "then" | "else" | "!" | "time" | "{"))
        })
        .collect()
}

/// How many blocks a line opens, and how many it closes.
fn nesting(code: &str) -> (usize, usize) {
    let commands = command_words(code);
    let opened = commands
        .iter()
        .filter(|word| matches!(**word, "if" | "while" | "until" | "for" | "case" | "select"))
        .count()
        + words(code)
            .iter()
            .filter(|word| **word == "{" || word.ends_with("(){"))
            .count();
    // A `}` ends a block only where a command starts (`echo }` is a word).
    let closed = commands
        .iter()
        .filter(|word| matches!(**word, "fi" | "done" | "esac" | "}"))
        .count();
    (opened, closed)
}

/// How many `(` a line opens and `)` it closes: a subshell, a substitution
/// or a list left open runs what follows in another shell, or not at all.
fn parentheses(code: &str) -> (usize, usize) {
    let count = |wanted| {
        code.chars()
            .filter(|character| *character == wanted)
            .count()
    };
    (count('('), count(')'))
}

/// Whether a line ends in `&&`, `||` or `|`, which join the next line to it.
fn goes_on(code: &str) -> bool {
    let code = code.trim_end();
    code.ends_with("&&") || code.ends_with('|')
}

/// Whether `command` replaces the shell (`exec bash`, `x=1 exec bash`,
/// `exec 2>/dev/null bash`); `exec` with only redirections
/// (`exec 2>/dev/null`, `exec 3>&1`) does not.
fn replaces_shell(command: &str) -> bool {
    // A `case` runs its arms, past `in` (`case $(tty) in x) exec y`).
    let command = match command.trim_start().strip_prefix("case ") {
        Some(rest) => rest.split_once(" in ").map_or("", |(_, arms)| arms),
        None => command,
    };
    // A pattern's `)` may stand apart from it, by any blanks (`*i* ) exec
    // y`, `( *i* ) exec y`).
    let command = command
        .split(')')
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join(")");
    // Not `command_start`, which steps past `exec` to the command it runs.
    let mut words = command.split_whitespace();
    if command_word(&mut words) != Some("exec") {
        return false;
    }
    while let Some(word) = words.next() {
        match redirection(word) {
            // `> file`: the next word is where it goes, which may be a
            // process substitution of several words (`2> >(tee f >&2)`).
            Some(Redirection::TakesNext) => {
                let mut open = Unclosed::default();
                for target in words.by_ref() {
                    if !open.read(target) {
                        break;
                    }
                }
            }
            Some(Redirection::Whole) => {}
            // `-a name` (or `-la name`) names the program; `-c` and `-l`
            // take nothing.
            None if word.starts_with('-') && word.contains('a') => {
                words.next();
            }
            None if word.starts_with('-') => {}
            None => return true,
        }
    }
    false
}

/// The words in front of the one a simple command runs: reserved words,
/// the builtins that run another (`command`, `builtin`, `eval`), and the
/// options `command -p` and `time -p` take. One list for `command_word` and
/// `command_start`, so that both find the same word.
const RUNS_NEXT: [&str; 13] = [
    "if", "then", "else", "elif", "while", "until", "do", "time", "builtin", "command", "-p", "--",
    "eval",
];

/// The word of a simple command that names what it runs, taken from
/// `words`: past reserved words, the builtins that run another
/// (`command`, `builtin`, `eval`), assignments, whose value may run over
/// several words (`x=$(a b)`, ``x=`a b` ``, `x=( a b )`), and a `case`
/// pattern (`*i*)`, `(x)`), which may be glued to it (`x)exec`).
fn command_word<'a>(words: &mut impl Iterator<Item = &'a str>) -> Option<&'a str> {
    let mut value = Unclosed::default();
    loop {
        let word = words.next()?;
        if value.is_open() {
            value.read(word);
            continue;
        }
        if matches!(word, "!" | "{") || RUNS_NEXT.contains(&word) {
            continue;
        }
        // A group in parentheses before the command word, read to its
        // close: a pattern's spaced `(` (`( *i*) exec`), or a subshell as a
        // condition (`if ( :) then exec`), whose own words run elsewhere.
        if word.contains('=') && !word.starts_with('=') || word == "(" {
            value.read(word);
            continue;
        }
        match word.rsplit_once(')') {
            Some((pattern, rest)) if !pattern.trim_start_matches('(').contains('(') => {
                if !rest.is_empty() {
                    return Some(rest);
                }
            }
            _ => return Some(word),
        }
    }
}

/// What a value read word by word leaves open: parentheses (`$(`, `(`,
/// `>(`) and a backtick.
#[derive(Debug, Default)]
struct Unclosed {
    parentheses: usize,
    backtick: bool,
}

impl Unclosed {
    /// Reads `word`, and returns whether something is still open after it.
    fn read(&mut self, word: &str) -> bool {
        self.parentheses = (self.parentheses + word.matches('(').count())
            .saturating_sub(word.matches(')').count());
        self.backtick ^= word.matches('`').count() % 2 == 1;
        self.is_open()
    }

    fn is_open(&self) -> bool {
        self.parentheses > 0 || self.backtick
    }
}

/// Where in `code` each command that starts a function's definition
/// begins (`f() {`, `function f`), in any of its commands
/// (`if :; then f() {`).
fn definitions(code: &str) -> impl Iterator<Item = usize> {
    simple_commands(code)
        .filter(|command| defined_name(&words(command_start(command))).is_some())
        .map(move |command| offset_in(code, command))
}

/// The name of the function whose definition `words` start, in each way
/// bash takes one: `function f`, `f()`, `f ()`, `f ( )`, `f( )`.
fn defined_name<'a>(words: &[&'a str]) -> Option<&'a str> {
    let parentheses_next = |rest: &[&str]| match rest {
        [first, ..] if first.starts_with("()") => true,
        ["(", next, ..] => next.starts_with(')'),
        _ => false,
    };
    let name = match words {
        ["function", word, ..] => word.split('(').next().unwrap_or_default(),
        [word, rest @ ..] if !word.contains('=') => match word.split_once('(') {
            Some((name, after))
                if after.starts_with(')')
                    || (after.is_empty()
                        && rest.first().is_some_and(|next| next.starts_with(')'))) =>
            {
                name
            }
            None if parentheses_next(rest) => word,
            Some(_) | None => return None,
        },
        _ => return None,
    };
    // bash takes no name with a substitution or redirection in it: `$( )`
    // and `<( )` define nothing.
    let named = !name.is_empty() && !name.contains(['$', '<', '>', '`', '\'', '"', '\\']);
    named.then_some(name)
}

/// Where `part`, a slice of `code` (as `simple_commands` returns), starts
/// in it.
fn offset_in(code: &str, part: &str) -> usize {
    let at = (part.as_ptr() as usize).wrapping_sub(code.as_ptr() as usize);
    assert!(at <= code.len(), "a part of the line it came from");
    at
}

/// Whether the definition `code` stops at the function's name, so that its
/// body opens on a later line (`f()`, `function f`), unlike `f() ( : )`.
fn names_only(code: &str) -> bool {
    let words = words(command_start(code));
    let Some(name) = defined_name(&words) else {
        return false;
    };
    // Past the name, with blanks taken out, only its own `()` may stand:
    // `f()(ls)` and `f() {` carry their body.
    let joined = words.concat();
    let joined = match words.as_slice() {
        ["function", ..] => &joined["function".len()..],
        _ => &joined,
    };
    matches!(joined.strip_prefix(name), Some("" | "()"))
}

/// The commands of `code`, split at `;`, `&` and `|` where these are no
/// part of a redirection (`2>&1`, `&>log`, `>|file`). A command that runs
/// in a subshell (`a | exec b`, `exec b &`) is still one of them: a `|`
/// may also stand inside `$(…)` or between a `case` pattern's choices,
/// and each side is read so that neither hides an `exec`.
fn simple_commands(code: &str) -> impl Iterator<Item = &str> {
    let bytes = code.as_bytes();
    let mut from = 0;
    let mut commands = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let byte = bytes[at];
        let redirected = at
            .checked_sub(1)
            .is_some_and(|before| matches!(bytes[before], b'<' | b'>'))
            || (byte == b'&' && bytes.get(at + 1) == Some(&b'>'));
        if matches!(byte, b';' | b'&' | b'|') && !redirected {
            commands.push(&code[from..at]);
            at += 1;
            from = at;
            continue;
        }
        at += 1;
    }
    commands.push(&code[from..]);
    commands.into_iter()
}

/// A word that redirects (`2>/dev/null`, `>&2`, `&>log`, `{fd}>file`,
/// `<<<x`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Redirection {
    /// It holds where it goes (`2>/dev/null`).
    Whole,
    /// Where it goes is the next word (`>`).
    TakesNext,
}

/// How `word` redirects, if it does.
fn redirection(word: &str) -> Option<Redirection> {
    let rest = word.trim_start_matches(|character: char| character.is_ascii_digit());
    let rest = match rest.strip_prefix('{') {
        Some(named) => named.split_once('}').map_or(rest, |(_, after)| after),
        None => rest,
    };
    let rest = rest
        .strip_prefix('&')
        .filter(|after| after.starts_with('>'))
        .unwrap_or(rest);
    rest.starts_with(['<', '>']).then(|| {
        if rest.trim_start_matches(['<', '>', '&', '|']).is_empty() {
            Redirection::TakesNext
        } else {
            Redirection::Whole
        }
    })
}

/// What a line leaves open for the next to go on inside: a quote, or a
/// substitution inside one. Inside double quotes, `$(…)` and a backtick
/// start quoting afresh (`"$(echo '"')"` is one word), so what is open is
/// a stack, the innermost last.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Frame {
    /// `'…'`: nothing inside is special.
    Single,
    /// `"…"`: a backslash keeps the next character.
    Double,
    /// `$'…'`: a backslash keeps the next character (`$'don\'t'`).
    Ansi,
    /// `$(…)` inside quotes, with how many `(` are open in it.
    Substitution(usize),
    /// `` `…` `` inside quotes.
    Backtick,
    /// `${…}` inside quotes.
    Parameter,
}

/// Reads `characters` from `from` inside `frames`, up to where the last
/// of them closes: the index after it, or `None` where the line ends first
/// (or a comment inside a substitution ends it) and leaves the rest open
/// for the next line.
fn skip_text(characters: &[char], from: usize, frames: &mut Vec<Frame>) -> Option<usize> {
    let mut index = from;
    // Whether the character before is a `$` that is not escaped.
    let mut dollar = false;
    while let Some(&frame) = frames.last() {
        let character = *characters.get(index)?;
        let next = characters.get(index + 1).copied();
        let code = matches!(frame, Frame::Substitution(_) | Frame::Backtick);
        let was_dollar = std::mem::replace(&mut dollar, false);
        match (frame, character) {
            (Frame::Single | Frame::Ansi, '\'')
            | (Frame::Double, '"')
            | (Frame::Backtick, '`')
            | (Frame::Parameter, '}')
            | (Frame::Substitution(0), ')') => {
                frames.pop();
            }
            (Frame::Single, _) => {}
            (_, '\\') => index += 1,
            (Frame::Ansi, _) => {}
            (_, '$') if next == Some('(') => {
                frames.push(Frame::Substitution(0));
                index += 1;
            }
            (_, '$') if next == Some('{') => {
                frames.push(Frame::Parameter);
                index += 1;
            }
            (_, '$') => dollar = true,
            (_, '`') => frames.push(Frame::Backtick),
            (Frame::Double, _) => {}
            (_, '"') => frames.push(Frame::Double),
            (_, '\'') => frames.push(if was_dollar {
                Frame::Ansi
            } else {
                Frame::Single
            }),
            (Frame::Substitution(depth), '(') => {
                frames.pop();
                frames.push(Frame::Substitution(depth + 1));
            }
            (Frame::Substitution(depth), ')') => {
                frames.pop();
                frames.push(Frame::Substitution(depth - 1));
            }
            // A comment inside a substitution runs to the end of the line.
            (_, '#') if code && word_starts(characters, index) => return None,
            _ => {}
        }
        index += 1;
    }
    Some(index)
}

/// Whether a word starts at `characters[index]`: at the line's start, or
/// after a blank, `;`, `&`, `|` or `(`.
fn word_starts(characters: &[char], index: usize) -> bool {
    index
        .checked_sub(1)
        .and_then(|at| characters.get(at))
        .is_none_or(|before| before.is_whitespace() || matches!(before, ';' | '&' | '|' | '('))
}

/// A line of code as the scanner reads it.
struct Scanned {
    /// The line without its comment and without what is inside quotes: a
    /// word in a string or after `#` is not a command.
    bare: String,
    /// How many characters of the line are code: up to its comment.
    code_end: usize,
    /// Whether the line ends in a backslash that joins the next to it (not
    /// one in a comment).
    continues: bool,
}

/// What a `(` opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Group {
    /// A subshell, or a group of a `[[ =~ ]]` pattern: an operator.
    Subshell,
    /// `$(`, `<(` or `>(`: part of a word (`$(echo a)#` is one).
    Word,
    /// `@(`, `!(`, `+(`, `*(` or `?(`: a pattern, where `#` and `|` are
    /// letters (`@(#*|y)`).
    Extglob,
}

/// What a line has open at the point the scan has reached.
#[derive(Debug, Default)]
struct Open {
    /// Each `((` open, `true` where it is `$((`, part of a word.
    arithmetic: Vec<bool>,
    /// How deep in `${…}` the scan is: `;#` there is text (`${x//;#/_}`).
    parameter: usize,
    /// What each `(` open opens.
    groups: Vec<Group>,
    /// Whether the last `)` closed a group that is part of a word.
    closed_word: bool,
    /// Whether the scan is inside `[[ … ]]`, where `|` and `)` belong to a
    /// pattern.
    test: bool,
}

impl Open {
    /// Whether the `#` at `characters[index]` starts a comment: it does
    /// where a word starts (after a blank or an operator, not after an
    /// escaped character), outside `${…}`, `[[ … ]]` and extglob patterns.
    /// After `)` that closes a `$(…)` it is part of the word
    /// (`$(echo a)#`).
    fn comment_at(&self, characters: &[char], index: usize, escaped: bool) -> bool {
        let Some(&before) = index.checked_sub(1).and_then(|at| characters.get(at)) else {
            return true;
        };
        if self.parameter > 0 || escaped {
            return false;
        }
        match before {
            ';' | '&' => true,
            '(' => self.groups.last() != Some(&Group::Extglob) && !self.test,
            '|' => !self.groups.contains(&Group::Extglob) && !self.test,
            ')' => !self.closed_word && !self.test,
            _ => before.is_whitespace(),
        }
    }
    /// Reads the character at `index`, which is no quote, escape or
    /// comment, into `scanned`, and returns the index of the last
    /// character it took.
    fn step(
        &mut self,
        characters: &[char],
        index: usize,
        scanned: &mut Scanned,
        documents: &mut VecDeque<Document>,
    ) -> usize {
        let character = characters[index];
        let next = characters.get(index + 1).copied();
        let after = |at: usize| characters.get(at).is_none_or(|c| c.is_whitespace());
        match character {
            // `$${` is `$$` and a `{`.
            '$' if next == Some('{')
                && characters[..=index]
                    .iter()
                    .rev()
                    .take_while(|c| **c == '$')
                    .count()
                    % 2
                    == 1 =>
            {
                self.parameter += 1;
                scanned.bare.push_str("${");
                return index + 1;
            }
            '}' if self.parameter > 0 => {
                self.parameter -= 1;
                scanned.bare.push('}');
            }
            // A blank inside `${…}` is part of its word: `${1:- }` leaves no
            // `}` alone, to be read as a block's end, and `${x:- return }`
            // runs no `return`.
            _ if self.parameter > 0 && character.is_whitespace() => scanned.bare.push('_'),
            '(' if next == Some('(') => {
                self.arithmetic
                    .push(index.checked_sub(1).map(|at| characters[at]) == Some('$'));
                scanned.bare.push_str("((");
                return index + 1;
            }
            ')' if next == Some(')') && !self.arithmetic.is_empty() => {
                // `$((1))#` is one word, as `$(…)#` is; after a plain
                // `((1))` a `#` starts a comment.
                self.closed_word = self.arithmetic.pop() == Some(true);
                scanned.bare.push_str("))");
                return index + 1;
            }
            '(' => {
                let group = match index.checked_sub(1).map(|at| characters[at]) {
                    Some('$' | '<' | '>') => Group::Word,
                    Some('@' | '!' | '+' | '*' | '?') => Group::Extglob,
                    _ => Group::Subshell,
                };
                self.groups.push(group);
                scanned.bare.push('(');
            }
            ')' => {
                self.closed_word = self
                    .groups
                    .pop()
                    .is_some_and(|group| group != Group::Subshell);
                scanned.bare.push(')');
            }
            '[' if next == Some('[') && (index == 0 || after(index - 1)) && after(index + 2) => {
                self.test = true;
                scanned.bare.push_str("[[");
                return index + 1;
            }
            ']' if next == Some(']') && self.test => {
                self.test = false;
                scanned.bare.push_str("]]");
                return index + 1;
            }
            '<' if next == Some('<') && self.arithmetic.is_empty() => {
                scanned.bare.push(' ');
                if characters.get(index + 2) == Some(&'<') {
                    return index + 2;
                }
                let tabs = characters.get(index + 2) == Some(&'-');
                if let Some(end) = end_word(&characters[index + 2..]) {
                    documents.push_back(Document { end, tabs });
                }
                return index + 1;
            }
            _ => scanned.bare.push(character),
        }
        index
    }
}

/// Reads a file's lines in order, carrying what one leaves open to the
/// next: a here-document, and the quotes and substitutions bash is inside
/// (`Frame`).
#[derive(Debug, Default)]
struct Reader {
    /// The here-documents the lines are in, in the order they end.
    documents: VecDeque<Document>,
    frames: Vec<Frame>,
}

/// A here-document: the word that ends it, alone on its line, and whether
/// tabs before that word are dropped (`<<-`).
#[derive(Debug)]
struct Document {
    end: String,
    tabs: bool,
}

impl Reader {
    /// Whether `line`, the next line as written, is in a here-document: a
    /// line of it, or the one that ends it.
    fn in_document(&mut self, line: &str) -> bool {
        let Some(document) = self.documents.front() else {
            return false;
        };
        let line = if document.tabs {
            line.trim_start_matches('\t')
        } else {
            line
        };
        if line == document.end {
            self.documents.pop_front();
        }
        true
    }

    /// Whether the next line starts inside quoted text.
    fn in_quotes(&self) -> bool {
        !self.frames.is_empty()
    }

    /// Reads `code`, the next line (not one `in_document`): drops quoted
    /// text and the comment, and finds a here-document's end word. `<<`
    /// inside `(( ))` or `$(( ))` is a shift, and `<<<` a here-string:
    /// neither starts a document.
    fn scan(&mut self, code: &str) -> Scanned {
        let characters: Vec<char> = code.chars().collect();
        let mut scanned = Scanned {
            bare: String::new(),
            code_end: characters.len(),
            continues: false,
        };
        let mut index = 0;
        if self.in_quotes() {
            let Some(end) = skip_text(&characters, 0, &mut self.frames) else {
                return scanned;
            };
            scanned.bare.push('_');
            index = end;
        }
        let mut open = Open::default();
        // Whether the character before `index` was escaped.
        let mut escaped = false;
        while index < characters.len() {
            let character = characters[index];
            if character == '#' && open.comment_at(&characters, index, escaped) {
                scanned.code_end = index;
                return scanned;
            }
            escaped = false;
            match character {
                // The escaped character is text: part of the word inside
                // `${…}` (`${x//\}/y}`), a blank outside it.
                '\\' => {
                    scanned
                        .bare
                        .push(if open.parameter > 0 { '_' } else { ' ' });
                    scanned.continues = index + 1 == characters.len();
                    escaped = true;
                    index += 2;
                    continue;
                }
                // Quoted text is one word (`${1:-"d"}`). One that goes on
                // past the line is left open for the next. An escaped `$`
                // opens no `$'…'`.
                '\'' | '"' => {
                    let dollar = index > 0 && characters[index - 1] == '$';
                    self.frames.push(match character {
                        '"' => Frame::Double,
                        _ if dollar && !after_escape(&characters, index - 1) => Frame::Ansi,
                        _ => Frame::Single,
                    });
                    scanned.bare.push('_');
                    let Some(end) = skip_text(&characters, index + 1, &mut self.frames) else {
                        return scanned;
                    };
                    index = end;
                    continue;
                }
                _ => index = open.step(&characters, index, &mut scanned, &mut self.documents),
            }
            index += 1;
        }
        scanned
    }
}

/// Whether `characters[index]` is escaped: an odd number of backslashes
/// stands before it.
fn after_escape(characters: &[char], index: usize) -> bool {
    characters[..index]
        .iter()
        .rev()
        .take_while(|character| **character == '\\')
        .count()
        % 2
        == 1
}

/// The end word of a here-document, from what follows its `<<`.
fn end_word(rest: &[char]) -> Option<String> {
    let word: String = rest
        .iter()
        .skip_while(|character| **character == '-')
        .skip_while(|character| character.is_whitespace())
        .take_while(|character| {
            !character.is_whitespace()
                && !matches!(character, ';' | '<' | '>' | '|' | '&' | '(' | ')')
        })
        .filter(|character| !matches!(character, '\'' | '"' | '\\'))
        .collect();
    (!word.is_empty()).then_some(word)
}

/// Whether a line is the usual "stop here unless this shell is
/// interactive" guard, the one place a `return` before Guardian's line is
/// fine (the interceptor is for interactive shells): a test of `$-` for
/// `i`, or of `$PS1` for being empty, that returns when the shell is not
/// interactive, or a one-line `case $- in`.
fn interactive_guard(code: &str) -> bool {
    let plain: String = code
        .chars()
        .filter(|character| !matches!(character, '"' | '\''))
        .collect();
    let words: Vec<&str> = plain.split_whitespace().collect();
    if words.starts_with(&["case", "$-", "in"]) {
        return plain.contains("*i*") && words.last() == Some(&"esac");
    }
    let Some(at) = words.iter().position(|word| matches!(*word, "&&" | "||")) else {
        return false;
    };
    let action: Vec<&str> = words[at + 1..]
        .iter()
        .map(|word| word.trim_end_matches(';'))
        .filter(|word| !word.is_empty())
        .collect();
    let returns = match action.as_slice() {
        ["return"] => true,
        ["return", code] => code.parse::<u8>().is_ok(),
        _ => false,
    };
    let (["[", inner @ .., "]"] | ["[[", inner @ .., "]]"] | ["test", inner @ ..]) = &words[..at]
    else {
        return false;
    };
    let prompt = |word: &str| matches!(word, "$PS1" | "${PS1}" | "${PS1-}" | "${PS1:-}");
    // What the test is true for: a shell that is not interactive, or one
    // that is.
    let (not_interactive, interactive) = match inner {
        ["-z", word] => (prompt(word), false),
        ["-n", word] | [word] => (false, prompt(word)),
        ["$-" | "${-}", "!=", "*i*"] | ["!", "$-" | "${-}", "=~", "i"] => (true, false),
        ["$-" | "${-}", "==" | "=", "*i*"] | ["$-" | "${-}", "=~", "i"] => (false, true),
        _ => (false, false),
    };
    returns && ((not_interactive && words[at] == "&&") || (interactive && words[at] == "||"))
}

/// Whether a line defines a function called `name`.
fn defines_function(code: &str, name: &str) -> bool {
    defined_name(&words(code)) == Some(name)
}

/// Whether a line makes an alias called `name` (Bash, zsh or fish).
fn defines_alias(code: &str, name: &str) -> bool {
    let words = words(code);
    if words.first() != Some(&"alias") {
        return false;
    }
    let mut named = words[1..].iter().filter(|word| !word.starts_with('-'));
    // fish spells it `alias name value`.
    named.clone().next().is_some_and(|word| names(word, name))
        || named.any(|word| {
            word.split_once('=')
                .is_some_and(|(alias, _)| names(alias, name))
        })
}

/// The lines of `text` that are code: not blank, not comments.
fn code_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
}

/// Where the line Guardian writes stands in a start-up file.
#[derive(Debug)]
struct Found {
    /// The index of the line.
    index: usize,
    /// What is wrong with where it stands, if anything.
    problem: Option<&'static str>,
}

/// Where the last line of `text` that is `source_line` stands.
fn standing(text: &str, source_line: &str) -> Option<Found> {
    let (mut depth, mut parentheses_open) = (0_usize, 0_usize);
    let mut reader = Reader::default();
    // Whether the next line goes on from this one: past a backslash, or
    // past `&&` or `|`, which a blank or comment line does not end.
    let (mut continued, mut joined) = (false, false);
    let mut returned = false;
    let mut found = None;
    let mut functions = Functions::default();
    let mut carried = Carried::default();
    for (index, line) in text.lines().enumerate() {
        let code = line.trim();
        if reader.in_document(line) {
            if code == source_line {
                found = Some(Found {
                    index,
                    problem: Some("it is inside a here-document"),
                });
            }
            continue;
        }
        if !reader.in_quotes() && (code.is_empty() || code.starts_with('#')) {
            // It ends a line continued past a backslash.
            continued = joined;
            carried.end();
            continue;
        }
        // Inside quoted text the line is text, and its own quotes are read
        // as such below.
        if code == source_line && reader.in_quotes() {
            found = Some(Found {
                index,
                problem: Some("it is inside quoted text"),
            });
        } else if code == source_line {
            let problem = if continued {
                Some("it continues the line before it")
            } else if depth > 0 {
                Some("it is inside a function or block")
            } else if parentheses_open > 0 {
                Some("it is inside parentheses: a subshell, a substitution or a list")
            } else if returned {
                Some("a `return`, `exit` or `exec` comes before it")
            } else {
                None
            };
            found = Some(Found { index, problem });
            (continued, joined) = (false, false);
            continue;
        }
        let scanned = reader.scan(code);
        let (opened, closed) = nesting(&scanned.bare);
        // Not inside a block, and not in one written on this line (a
        // one-line function). What is quoted or in a comment is no
        // command, and the "stop here unless interactive" line is the one
        // `return` before it that is fine.
        let leaves = words(&scanned.bare)
            .iter()
            .any(|word| matches!(*word, "return" | "exit"))
            && !interactive_guard(code);
        let outside = functions.outside(&scanned, depth, (opened, closed));
        let command = carried.join(&outside, scanned.continues);
        let replaces = simple_commands(&command).any(replaces_shell);
        if depth == 0 && opened == 0 && (leaves || replaces) {
            returned = true;
        }
        // After the line, a shell replaced takes the functions away, in a
        // block too (`if …; then exec tmux; fi`); one in parentheses runs
        // in a subshell.
        if let Some(Found {
            problem: problem @ None,
            ..
        }) = &mut found
            && replaces
            && parentheses_open == 0
        {
            *problem = Some("a later `exec` replaces the shell");
        }
        depth = (depth + opened).saturating_sub(closed);
        let (left_open, closing) = parentheses(&scanned.bare);
        parentheses_open = (parentheses_open + left_open).saturating_sub(closing);
        joined = goes_on(&scanned.bare);
        continued = scanned.continues || joined;
    }
    found
}

/// What `standing` keeps of functions' bodies, to tell an `exec` the shell
/// runs from one in a body, which runs only when the function is called.
#[derive(Debug, Default)]
struct Functions {
    /// The block depth at which a function's body opened, while inside it.
    inside: Option<usize>,
    /// A function's name was read on a line that opened nothing: its body
    /// opens on the next line of code (`f()` and then `{`).
    named: bool,
}

/// The last command of a line continued past a backslash, at most
/// `MAX_CARRIED` bytes of it: read with the next (`exec \`).
#[derive(Debug, Default)]
struct Carried(String);

/// How much of a command continued over several lines is kept. A command
/// a start-up file continues names its program within its first words;
/// without a bound, each line would read all the lines before it.
/// Arbitrary.
const MAX_CARRIED: usize = 1024;

impl Carried {
    /// The command `outside` goes on, with what the line before carried;
    /// when the line `continues`, its last command is carried to the next.
    fn join(&mut self, outside: &str, continues: bool) -> String {
        let command = std::mem::take(&mut self.0) + outside;
        if continues {
            let last = simple_commands(&command).last().unwrap_or_default();
            self.0 = if last.len() <= MAX_CARRIED {
                last.to_owned()
            } else {
                // A blank after the cut: the next line must not be glued to
                // a cut word (`X=12` and then `exec x`).
                let mut end = MAX_CARRIED;
                while !last.is_char_boundary(end) {
                    end -= 1;
                }
                format!("{} ", &last[..end])
            };
        }
        command
    }

    /// A blank or comment line ends a line continued past a backslash.
    fn end(&mut self) {
        self.0.clear();
    }
}

impl Functions {
    /// What of the line `scanned`, at block depth `depth` and opening and
    /// closing `blocks`, runs outside a function's body.
    fn outside(&mut self, scanned: &Scanned, depth: usize, blocks: (usize, usize)) -> String {
        let (opened, closed) = blocks;
        let bare = scanned.bare.as_str();
        let mut found = definitions(bare);
        let definition = found.next();
        let another = found.next().is_some();
        let defines = definition.is_some() || (self.named && opened > 0);
        self.named = definition.is_some_and(|at| names_only(&bare[at..])) && opened == 0;
        let after = (depth + opened).saturating_sub(closed);
        // What of the line runs outside a body: all of it; what comes before
        // a definition on it (`exec x; f() {`); past the `}` that closes a
        // body on it (`f() { :; }; exec x`, `}; exec x`).
        let before = definition.map_or("", |at| &bare[..at]);
        // The `}` that closes is a command word, not one of `${HOME}` or
        // `{a,b}`. The first is taken: past a nested block's `}` the rest
        // of the body is read too, which errs towards an alarm.
        // With no such `}`, what follows the definition's own command
        // (`f() ( : ); exec x`), which errs towards an alarm where the body
        // holds a `;`.
        let past = |command: &str| &bare[offset_in(bare, command) + command.len()..];
        let closing = simple_commands(bare)
            .find(|command| command.split_whitespace().next() == Some("}"))
            .or_else(|| definition.and_then(|at| simple_commands(&bare[at..]).next()))
            .map_or("", past);
        let outside = match self.inside {
            // Code may stand between two definitions on one line (`f() {
            // :; }; exec x; g() {`): the whole line is read, which errs
            // towards an alarm.
            _ if another => bare.to_owned(),
            // Inside a body, a line that defines a function (`g() { :; }`
            // nested, or `}; g() {`): which part runs outside is not told
            // apart, so the whole line is read, which errs towards an alarm.
            Some(_) if definition.is_some() => bare.to_owned(),
            Some(at) if after <= at => closing.to_owned(),
            Some(_) => String::new(),
            None if defines && opened > closed => before.to_owned(),
            None if defines => format!("{before} {closing}"),
            None => bare.to_owned(),
        };
        if self.inside.is_none() && defines && opened > closed {
            self.inside = Some(depth);
        } else if self.inside.is_some_and(|at| after <= at) {
            self.inside = None;
        }
        outside
    }
}

/// Whether `source_line`, the exact line Guardian writes, is in `text` (a
/// `~/.bashrc`) where it runs, with nothing after it that takes the
/// interceptor's functions away again. `path` is the interceptor's own.
pub(super) fn interceptor(text: &str, source_line: &str, path: &str) -> Loads {
    let Some(Found { index, problem }) = standing(text, source_line) else {
        return if code_lines(text).any(|line| line.contains(path)) {
            Loads::Ineffective(
                "a line names the interceptor, but it is not the line Guardian writes".into(),
            )
        } else {
            Loads::Missing
        };
    };
    if let Some(problem) = problem {
        return Loads::Ineffective(problem.into());
    }
    // An alias is tried before a function, and one made earlier even
    // renames the function as it is defined: anywhere in the file counts.
    // Guardian's line starts with `[[`, which an alias can replace too.
    let commands = bash_commands(text.lines());
    for name in INTERCEPTED.iter().chain(&["source", "[["]) {
        if commands
            .iter()
            .any(|command| defines_alias(command_start(command), name))
        {
            return Loads::Ineffective(format!("an alias named `{name}` stands in front of it"));
        }
    }
    // A name reference may be given its name by a later command.
    let referenced = commands.iter().any(|command| declares_reference(command))
        && commands
            .iter()
            .any(|command| command.contains("BASH_ALIASES"));
    if referenced || commands.iter().any(|command| sets_guarded_alias(command)) {
        return Loads::Ineffective("a line makes an alias through `BASH_ALIASES`".into());
    }
    // A function made read-only before the line cannot be defined by it;
    // one locked after it keeps the interceptor's.
    if bash_commands(text.lines().take(index))
        .iter()
        .any(|command| locks_function(command))
    {
        return Loads::Ineffective("a function it defines is made read-only".into());
    }
    // A function called `source` runs instead of the builtin that loads
    // it, and `enable -n source` turns the builtin off, however `enable`
    // is reached (`builtin enable`, `\enable`, `'enable'`).
    if commands.iter().any(|command| {
        defines_function(command_start(command), "source") || disables_source(command)
    }) {
        return Loads::Ineffective(
            "the builtin `source` that loads it is turned off, or a function stands in front of \
             it"
            .into(),
        );
    }
    if let Some(problem) = taken_away_after(text, index) {
        return Loads::Ineffective(problem);
    }
    Loads::Effective
}

/// What takes the interceptor's functions away, given `index`, the line of
/// `text` that sources it: a command after that line, or a hook set
/// anywhere.
fn taken_away_after(text: &str, index: usize) -> Option<String> {
    for command in bash_commands(text.lines().skip(index + 1)) {
        if let Some(problem) = takes_away(&command) {
            return Some(problem);
        }
    }
    // A hook runs later, at a prompt or on a signal, wherever it is set.
    // Its quotes are dropped before its line is split, so each command of
    // a line that sets one counts as the hook's (`PROMPT_COMMAND='a; b'`).
    // Whether a prompt runs in the shell is read from the whole line: it is
    // split at `|`, which `${| …; }` holds.
    let hooked = bash_lines(text.lines()).into_iter().any(|line| {
        let commands = split_commands(&line);
        let in_shell = runs_in_shell(&line);
        commands.iter().any(|command| match hook_set(command) {
            Some(Hook::Commands) => true,
            Some(Hook::Prompt) => in_shell,
            None => false,
        }) && commands.iter().any(|command| {
            let body = hook_body(command);
            takes_away(command).is_some()
                || takes_away(body).is_some()
                || INTERCEPTED
                    .iter()
                    .any(|name| defines_alias(command_start(body), name))
        })
    });
    hooked.then(|| {
        "a hook (`trap`, `PROMPT_COMMAND`, a prompt, `bind -x`) takes its functions away".into()
    })
}

/// What the hook `command` sets runs: past `trap`, or the value given to
/// `PROMPT_COMMAND` (`PROMPT_COMMAND+=(…)`); the command itself otherwise.
fn hook_body(command: &str) -> &str {
    let start = command_start(command);
    if let Some(body) = start.strip_prefix("trap ") {
        return body;
    }
    command
        .split_once('=')
        .map_or(command, |(_, value)| value.trim_start_matches(['(', ' ']))
}

/// The lines of `lines` as bash reads them, read loosely: a line goes on
/// into the next past a backslash at its end or quoted text left open, and
/// comments and here-documents are left out. A line that ends in `&&` goes
/// on too, but what follows is no part of a hook its first part sets.
fn bash_lines<'a>(lines: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut read = Vec::new();
    let mut joined = String::new();
    let mut reader = Reader::default();
    for line in lines {
        if reader.in_document(line) {
            continue;
        }
        let line = line.trim();
        let scanned = reader.scan(line);
        let code: String = line.chars().take(scanned.code_end).collect();
        match code.strip_suffix('\\') {
            Some(start) if scanned.continues => joined.push_str(start),
            _ => {
                joined.push_str(&code);
                if reader.in_quotes() {
                    joined.push('\n');
                } else {
                    read.push(std::mem::take(&mut joined));
                }
            }
        }
    }
    if !joined.is_empty() {
        read.push(joined);
    }
    read
}

/// The commands of `lines` as bash would split them (`bash_lines`, then
/// `split_commands`).
fn bash_commands<'a>(lines: impl Iterator<Item = &'a str>) -> Vec<String> {
    bash_lines(lines)
        .iter()
        .flat_map(|line| split_commands(line))
        .collect()
}

/// The commands of one line, read loosely and on the side of finding too
/// much: quotes and backslashes are dropped (`un\set`, `$'unset'`, and a
/// quoted command such as `PROMPT_COMMAND='unset -f omarchy'` reads as
/// one), a backtick is a blank (what it runs feeds the command around it),
/// and a command ends at a line break, `;`, `&` and `|`.
fn split_commands(line: &str) -> Vec<String> {
    // `$'…'` and `$"…"` are quotes too.
    let bare: String = line
        .replace("$'", "'")
        .replace("$\"", "\"")
        .replace('`', " ")
        .chars()
        .filter(|c| !matches!(c, '\\' | '\'' | '"'))
        .collect();
    bare.split(['\n', ';', '&', '|'])
        .map(str::trim)
        .filter(|command| !command.is_empty())
        .map(str::to_string)
        .collect()
}

/// `command` from the word that runs: past the reserved words and the
/// prefixes in front of it (`if`, `then`, `{`, `!`, `time`, `builtin`,
/// `command -p`, `eval`, `x=1`, a `case` pattern's `a)`).
fn command_start(command: &str) -> &str {
    let mut rest = command.trim_start();
    loop {
        let rest_trimmed = rest.trim_start_matches(['(', '{', '!']).trim_start();
        let (word, after) = rest_trimmed
            .split_once(char::is_whitespace)
            .unwrap_or((rest_trimmed, ""));
        let skipped = RUNS_NEXT.contains(&word)
            || word == "exec"
            || (word.contains('=') && !word.starts_with('='))
            || (word.ends_with(')') && !word.contains('('));
        if !skipped || after.is_empty() {
            return rest_trimmed;
        }
        rest = after;
    }
}

/// The words of one of `bash_commands`: a redirect or an assignment ends
/// a word too (`omarchy>/dev/null`, `PROMPT_COMMAND=unset`).
fn command_parts(command: &str) -> Vec<&str> {
    command
        .split(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '=' | '(' | ')'))
        .filter(|word| !word.is_empty())
        .collect()
}

/// Whether `command` declares a name reference (`declare -n`).
fn declares_reference(command: &str) -> bool {
    let parts = command_parts(command_start(command));
    matches!(parts.first(), Some(&("declare" | "typeset" | "local")))
        && parts
            .iter()
            .any(|word| word.starts_with('-') && word.contains('n'))
}

/// Whether `command` writes `BASH_ALIASES` (`BASH_ALIASES[x]=`, `+=`,
/// `${BASH_ALIASES[x]:=…}`, `declare -A BASH_ALIASES=(…)`, `printf -v` or
/// `read` into a key) for a name the interceptor needs, or one it does not
/// spell out (`$k`, or a backtick's blank). Reading it
/// (`${BASH_ALIASES[x]}`, `[[ -v BASH_ALIASES[x] ]]`, `unset`) writes
/// nothing.
fn sets_guarded_alias(command: &str) -> bool {
    let assigned = |after: &str| after.starts_with('=') || after.starts_with("+=");
    let guarded = |key: &str| {
        key.contains(['$', ' ']) || INTERCEPTED.contains(&key) || matches!(key, "source" | "[[")
    };
    let verb = command_parts(command_start(command)).first().copied();
    // A name reference to it writes it by another name.
    if declares_reference(command) && command.contains("BASH_ALIASES") {
        return true;
    }
    command.match_indices("BASH_ALIASES").any(|(at, name)| {
        let rest = &command[at + name.len()..];
        // The keys of a whole list (`=([x]=…)`).
        if rest.starts_with("=(") || rest.starts_with("+=(") {
            return rest
                .split('[')
                .skip(1)
                .filter_map(|key| key.split_once(']'))
                .any(|(key, after)| assigned(after) && guarded(key));
        }
        // One key, up to the `]` before what writes it (`[[[]=x` is `[[`).
        let Some(inside) = rest.strip_prefix('[') else {
            return false;
        };
        let handed = match verb {
            Some("printf") => command[..at].trim_end().ends_with("-v"),
            Some("read") => true,
            _ => false,
        };
        let key = if handed {
            inside.split_once(']').map(|(key, _)| key)
        } else {
            ["]=", "]+=", "]:="]
                .iter()
                .filter_map(|op| inside.find(op))
                .min()
                .map(|end| &inside[..end])
                .filter(|key| !key.contains(']'))
        };
        key.is_some_and(guarded)
    })
}

/// Whether `command` makes a function the interceptor defines read-only
/// (`readonly -f omarchy`, `declare -rf omarchy`).
fn locks_function(command: &str) -> bool {
    let words = command_parts(command_start(command));
    let Some((&verb, after)) = words.split_first() else {
        return false;
    };
    let options: String = after
        .iter()
        .filter(|word| word.starts_with('-'))
        .copied()
        .collect();
    let locks = match verb {
        "readonly" => options.contains('f'),
        // `-F` locks the function too.
        "declare" | "typeset" => options.contains(['f', 'F']) && options.contains('r'),
        _ => false,
    };
    locks
        && after
            .iter()
            .any(|word| INTERCEPTED.iter().any(|name| names(word, name)))
}

/// Whether `command` turns the builtin `source` off (`enable -n source`),
/// or may: the name it turns off is not spelled out (`enable -n $x`).
fn disables_source(command: &str) -> bool {
    let words = command_parts(command_start(command));
    // `enable` must be what runs: `echo enable -n source` turns nothing off.
    let Some((&"enable", after)) = words.split_first() else {
        return false;
    };
    let Some(option) = after
        .iter()
        .position(|word| word.starts_with('-') && word.contains('n'))
    else {
        return false;
    };
    after[option + 1..]
        .iter()
        .any(|word| *word == "source" || word.contains('$'))
}

/// A hook bash runs later, which `command` sets (`hook_set`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hook {
    /// A `trap`, the prompt's commands (`PROMPT_COMMAND`), or a key's
    /// (`bind -x`): run in the shell itself.
    Commands,
    /// A prompt (`PS0` to `PS4`): only its `${ …; }` runs in the shell
    /// itself; its `$(…)` runs in a subshell, which takes nothing away.
    Prompt,
}

/// The hook `command` sets, if any. An element or an append
/// (`PROMPT_COMMAND[1]=`, `PROMPT_COMMAND+=`) sets one too.
fn hook_set(command: &str) -> Option<Hook> {
    let words = command_parts(command_start(command));
    match words.first() {
        Some(&"trap") => Some(Hook::Commands),
        Some(&"bind") => words
            .iter()
            .any(|word| word.starts_with('-') && word.contains('x'))
            .then_some(Hook::Commands),
        // An assignment, which `command_start` steps past.
        _ => command_parts(command).iter().find_map(|word| {
            match word.split('[').next().unwrap_or(word).trim_end_matches('+') {
                "PROMPT_COMMAND" => Some(Hook::Commands),
                "PS0" | "PS1" | "PS2" | "PS3" | "PS4" => Some(Hook::Prompt),
                _ => None,
            }
        }),
    }
}

/// Whether `line` holds a `${ …; }` or `${| …; }`, which runs in the shell
/// itself: `${` and then a blank (a newline or tab too) or `|`.
fn runs_in_shell(line: &str) -> bool {
    line.match_indices("${").any(|(at, _)| {
        line[at + 2..].starts_with(|character: char| character.is_whitespace() || character == '|')
    })
}

/// Whether `word` names `name`, or may once bash expands its braces
/// (`{omarchy,x}`, `s{ource,}`, `{x,{omarchy,y}}`). A word that expands to
/// more than `MAX_EXPANDED` words, or holds a range (`omarch{x..z}`), is
/// taken to name it, rather than expanded into every word it may be.
fn names(word: &str, name: &str) -> bool {
    let mut left = MAX_EXPANDED;
    expands_to(word, name, &mut left)
}

/// How many words `names` tries for one word. The count of words is the
/// product of each group's choices, so it is bounded, not the groups; a
/// start-up file's names expand to a few. Arbitrary.
const MAX_EXPANDED: usize = 256;

/// `names`, with `left` words still to try.
fn expands_to(word: &str, name: &str, left: &mut usize) -> bool {
    if word == name {
        return true;
    }
    let Some((before, group, after)) = brace_group(word) else {
        return false;
    };
    let Some(choices) = group else {
        return true;
    };
    for choice in choices {
        if *left == 0 {
            return true;
        }
        *left -= 1;
        if expands_to(&format!("{before}{choice}{after}"), name, left) {
            return true;
        }
    }
    false
}

/// The first group of `word` that bash expands: what comes before it, its
/// choices (split at the commas outside nested braces), and what comes
/// after. A range (`{a..z}`) has `None` for its choices. A group without a
/// comma or range is text, and so is a `{` that is not closed: `None`.
fn brace_group(word: &str) -> Option<(&str, Option<Vec<&str>>, &str)> {
    let open = word.find('{')?;
    let mut depth = 0_usize;
    let mut commas = Vec::new();
    for (at, character) in word.char_indices().skip_while(|(at, _)| *at <= open) {
        match character {
            '{' => depth += 1,
            '}' if depth == 0 => {
                let inside = &word[open + 1..at];
                let (before, after) = (&word[..open], &word[at + 1..]);
                if commas.is_empty() {
                    return inside.contains("..").then_some((before, None, after));
                }
                let mut choices = Vec::new();
                let mut from = open + 1;
                for comma in commas {
                    choices.push(&word[from..comma]);
                    from = comma + 1;
                }
                choices.push(&word[from..at]);
                return Some((before, Some(choices), after));
            }
            '}' => depth -= 1,
            ',' if depth == 0 => commas.push(at),
            _ => {}
        }
    }
    None
}

/// What `command`, after Guardian's line, does to the interceptor's
/// functions: unsets one, or a name it does not spell out, or defines one
/// again.
fn takes_away(command: &str) -> Option<String> {
    let words = command_parts(command);
    // `builtin unset` is `unset` all the same; a name may be in braces
    // (`unset -f {omarchy,x}`). `unset -v` unsets variables only, and a
    // function that unsets itself (`unset -f "$FUNCNAME"`, the usual lazy
    // loader) unsets no other.
    if let Some(unset) = words.iter().position(|word| *word == "unset") {
        let after = &words[unset + 1..];
        let variables = after
            .iter()
            .any(|word| word.starts_with('-') && word.contains('v') && !word.contains('f'));
        let names: Vec<&str> = after
            .iter()
            .copied()
            .filter(|word| !word.starts_with('-') && !word.contains("FUNCNAME"))
            .collect();
        for name in INTERCEPTED {
            if !variables
                && names
                    .iter()
                    .any(|word| word.split(['{', '}', ',']).any(|part| part == name))
            {
                return Some(format!("a later line unsets `{name}`"));
            }
        }
        // Only `-f` is sure to reach a function: a plain `unset` takes a
        // variable of that name first, and `${!prefix*}` names variables.
        let functions = after
            .iter()
            .any(|word| word.starts_with('-') && word.contains('f'));
        if !variables && functions && names.iter().any(|word| word.contains(['$', '{'])) {
            return Some("a later line unsets a name it does not spell out".into());
        }
    }
    let defined = command_start(command);
    INTERCEPTED
        .iter()
        .find(|name| defines_function(defined, name))
        .map(|name| format!("a later line redefines `{name}`"))
}

/// Whether `text` (a shell start-up file) has an alias or function called
/// `helper` that itself passes `--makepkg` with something other than `gate`
/// (Guardian's own shim): the helper then builds with whatever that names,
/// whatever its saved configuration says. `--makepkg` on another command
/// of the file is not an override of this helper.
pub(super) fn overrides_makepkg(text: &str, helper: &str, gate: &str) -> bool {
    // Untrimmed: an indented word that ends a here-document ends none
    // (`  EOF` after `<<EOF`).
    let lines: Vec<&str> = text.lines().collect();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index].trim();
        if defines_alias(line, helper) && passes_other_makepkg(line, gate) {
            return true;
        }
        if !defines_function(line, helper) {
            index += 1;
            continue;
        }
        let body = function_body(&lines[index..]);
        if body
            .iter()
            .filter(|line| !line.trim_start().starts_with('#'))
            .any(|line| passes_other_makepkg(line, gate))
        {
            return true;
        }
        // Past the body: a definition inside it was read with it, and
        // starting again at each would read an unclosed body to the end of
        // the file once per line.
        index += body.len();
    }
    false
}

/// How a function's body is written: in braces, in parentheses (a
/// subshell), or (fish) up to its `end`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Body {
    Braces,
    Parentheses,
    Fish,
}

/// Whether `line` holds code: it is neither blank nor a comment.
fn is_code(line: &str) -> bool {
    let line = line.trim();
    !line.is_empty() && !line.starts_with('#')
}

/// How the body of the function that starts on the first of `lines` is
/// written, from what opens it: what follows the name, or else the next
/// line of code (`yay()` and then `{`).
fn body_kind(lines: &[&str]) -> Body {
    let mut head = lines
        .iter()
        .map(|line| line.trim())
        .filter(|line| is_code(line));
    let name = head.next().unwrap_or_default();
    // The name's `()` may hold blanks (`yay ( ) {`).
    let after_parentheses = name
        .split_once('(')
        .and_then(|(_, rest)| rest.trim_start().strip_prefix(')'));
    let after_name = match after_parentheses {
        Some(rest) => rest.trim_start(),
        None => name.strip_prefix("function").map_or("", |rest| {
            let rest = rest.trim_start();
            rest.split_once(char::is_whitespace)
                .map_or("", |(_, after)| after.trim_start())
        }),
    };
    // A comment or a lone `\` after the name leaves the body to a later
    // line.
    let opener = if after_name.is_empty() || after_name.starts_with('#') || after_name == "\\" {
        head.next().unwrap_or_default()
    } else {
        after_name
    };
    match opener.chars().next() {
        Some('{') => Body::Braces,
        Some('(') => Body::Parentheses,
        _ => Body::Fish,
    }
}

/// How many blocks a fish line opens and closes.
fn fish_counts(line: &str) -> (usize, usize) {
    let first = line.split_whitespace().next().unwrap_or_default();
    (
        usize::from(matches!(
            first,
            "function" | "if" | "for" | "while" | "switch" | "begin"
        )),
        usize::from(first == "end"),
    )
}

/// How many parentheses the line `code` of a body in parentheses opens and
/// closes. On the name's line (`first`), the name's own `()`, which may hold
/// blanks, opens nothing; inside a `case` (`cases` open), a pattern's `)`
/// closes nothing.
fn parenthesised_counts(code: &str, first: bool, cases: &mut usize) -> (usize, usize) {
    let code = match code.split_once('(') {
        Some((name, rest)) if first => rest
            .trim_start()
            .strip_prefix(')')
            .map_or_else(|| code.to_owned(), |rest| format!("{name} {rest}")),
        _ => code.to_owned(),
    };
    let (open, close) = parentheses(&code);
    let (case_opened, case_closed) = case_blocks(&code);
    let close = if *cases > 0 || case_opened > 0 {
        close.min(open)
    } else {
        close
    };
    *cases = (*cases + case_opened).saturating_sub(case_closed);
    (open, close)
}

/// The lines of the function that starts on the first of `lines`: to the
/// `}` or `)` that closes it, or (fish) to its `end`. Blank and comment
/// lines may stand between its name and its body.
fn function_body<'a>(lines: &'a [&'a str]) -> &'a [&'a str] {
    let body = body_kind(lines);
    let mut cases = 0_usize;
    let (mut depth, mut started, mut code_seen) = (0_usize, false, 0_usize);
    let mut reader = Reader::default();
    // A line continued past a backslash is read with the next, so a `}`
    // there is an argument (`echo \` and `}`), not a command.
    let mut pending = String::new();
    for (index, line) in lines.iter().enumerate() {
        // A `}` in a here-document ends nothing.
        if reader.in_document(line) {
            continue;
        }
        if !reader.in_quotes() && !is_code(line) {
            continue;
        }
        code_seen += 1;
        let line = line.trim();
        let (opened, closed) = if body == Body::Fish {
            fish_counts(line)
        } else {
            let scanned = reader.scan(line);
            pending.push_str(&scanned.bare);
            pending.push(' ');
            if scanned.continues {
                continue;
            }
            let counted = if body == Body::Braces {
                nesting(&pending)
            } else {
                parenthesised_counts(&pending, index == 0, &mut cases)
            };
            pending.clear();
            counted
        };
        depth = (depth + opened).saturating_sub(closed);
        started = started || opened > 0;
        // A body not opened by the second line of code is none.
        if (started && depth == 0) || (!started && code_seen >= 2) {
            return &lines[..=index];
        }
    }
    lines
}

/// How many `case` blocks the line `code` opens and closes.
fn case_blocks(code: &str) -> (usize, usize) {
    let commands = command_words(code);
    let count = |wanted| commands.iter().filter(|word| **word == wanted).count();
    (count("case"), count("esac"))
}

/// Whether a line passes `--makepkg` with a value that is not `gate`.
fn passes_other_makepkg(line: &str, gate: &str) -> bool {
    let plain: String = line
        .chars()
        .map(|character| {
            if matches!(character, '"' | '\'' | ';' | '=') {
                ' '
            } else {
                character
            }
        })
        .collect();
    let words: Vec<&str> = plain.split_whitespace().collect();
    words
        .iter()
        .enumerate()
        .any(|(index, word)| *word == "--makepkg" && words.get(index + 1) != Some(&gate))
}

#[cfg(test)]
mod tests {
    use super::{Loads, interceptor, overrides_makepkg};

    const PATH: &str = "/usr/lib/omarchy-guardian/omarchy-bash-interceptor.sh";
    const LINE: &str = "[[ -r /usr/lib/omarchy-guardian/omarchy-bash-interceptor.sh ]] && source /usr/lib/omarchy-guardian/omarchy-bash-interceptor.sh";

    fn loads(text: &str) -> Loads {
        interceptor(text, LINE, PATH)
    }

    fn why(text: &str) -> String {
        match loads(text) {
            Loads::Ineffective(why) => why,
            other => panic!("{other:?} for {text}"),
        }
    }

    #[test]
    fn only_guardians_own_line_where_it_runs_loads_the_interceptor() {
        let usual = format!(
            "[[ $- != *i* ]] && return\nsource \"$OMARCHY_PATH/default/bash/rc\"\nalias p='python'\n\n# Omarchy Guardian theme command interception\n{LINE}\n\nalias cc='claude'\nf() {{\n  echo x\n}}\n"
        );
        assert_eq!(loads(&usual), Loads::Effective);
        assert_eq!(loads(&format!("  {LINE}  \n")), Loads::Effective);
        assert_eq!(loads("alias ll='ls -l'\n"), Loads::Missing);
        assert_eq!(loads(&format!("# {LINE}\n")), Loads::Missing);

        // Looks like it, and loads nothing.
        assert!(why(&format!(": source {PATH}\n")).contains("not the line Guardian writes"));
        assert!(why(&format!("{LINE} && unset -f omarchy\n")).contains("not the line"));
        assert!(why(&format!("true || {LINE}\n")).contains("not the line"));
    }

    #[test]
    fn a_line_that_never_runs_is_not_effective() {
        assert!(why(&format!("never() {{\n{LINE}\n}}\n")).contains("function or block"));
        assert!(why(&format!("if false; then\n  {LINE}\nfi\n")).contains("function or block"));
        assert!(why(&format!("cat <<'EOF' >/dev/null\n{LINE}\nEOF\n")).contains("here-document"));
        assert!(why(&format!("echo \\\n{LINE}\n")).contains("continues"));
        assert!(why(&format!("return\n{LINE}\n")).contains("`return`, `exit` or `exec`"));
        assert!(why(&format!("true && exit 0\n{LINE}\n")).contains("`return`, `exit` or `exec`"));
        // A block that closed before it, and a return inside one, are fine.
        assert_eq!(
            loads(&format!(
                "if x; then\n  return\nfi\ng() {{ return; }}\ncat <<EOF\nreturn\nEOF\n{LINE}\n"
            )),
            Loads::Effective
        );
        assert_eq!(
            loads(&format!("case $- in *i*) ;; *) return;; esac\n{LINE}\n")),
            Loads::Effective
        );
    }

    #[test]
    fn what_takes_the_functions_away_again_is_not_effective() {
        assert!(why(&format!("{LINE}\nunset -f omarchy\n")).contains("unsets `omarchy`"));
        assert!(
            why(&format!("{LINE}\nunset -f x omarchy-plugin-add\n")).contains("omarchy-plugin-add")
        );
        assert!(
            why(&format!(
                "{LINE}\nomarchy() {{ command omarchy \"$@\"; }}\n"
            ))
            .contains("redefines")
        );
        assert!(
            why(&format!(
                "{LINE}\nfunction omarchy-theme-install {{\n:\n}}\n"
            ))
            .contains("redefines")
        );
        assert!(
            why(&format!(
                "{LINE}\nalias omarchy=/usr/share/omarchy/bin/omarchy\n"
            ))
            .contains("alias")
        );
        assert!(why(&format!("alias omarchy='x'\n{LINE}\n")).contains("alias"));
        assert!(why(&format!("{LINE}\n\\unset -f omarchy\n")).contains("unsets `omarchy`"));
        assert!(why(&format!("{LINE}\nbuiltin unset -f omarchy\n")).contains("unsets `omarchy`"));
        assert!(why(&format!("source() {{ :; }}\n{LINE}\n")).contains("builtin `source`"));
        assert!(why(&format!("enable -n source\n{LINE}\n")).contains("builtin `source`"));
        assert!(why(&format!("{LINE}\n'unset' -f omarchy\n")).contains("unsets `omarchy`"));
        // However the verb or the name is quoted or escaped, and in braces.
        for later in [
            "unset -f 'omarchy'",
            "unset -f \"omarchy\"",
            "un\\set -f omarchy",
            "un'set' -f omarchy",
            "unset -f {omarchy,omarchy-theme-install}",
        ] {
            assert!(
                why(&format!("{LINE}\n{later}\n")).contains("unsets `omarchy`"),
                "{later}"
            );
        }
        for disable in [
            "builtin enable -n source",
            "\\enable -n source",
            "'enable' -n source",
        ] {
            assert!(
                why(&format!("{disable}\n{LINE}\n")).contains("builtin `source`"),
                "{disable}"
            );
        }
        // `enable source` turns the builtin on.
        assert_eq!(loads(&format!("enable source\n{LINE}\n")), Loads::Effective);
        // Before it, a function of that name is replaced by the
        // interceptor's; other names are nobody's business.
        assert_eq!(
            loads(&format!(
                "omarchy() {{ :; }}\n{LINE}\nunset -f other\nalias omarchyx=1\nomarchy-theme-list() {{ :; }}\n"
            )),
            Loads::Effective
        );
    }

    #[test]
    fn each_command_is_read_as_bash_splits_it() {
        // Commands joined without blanks, redirected, continued on the next
        // line, run later or through `eval`.
        for later in [
            "true&&unset -f omarchy",
            "unset -f omarchy>/dev/null",
            "unset -f omarchy&>/dev/null",
            "unset -f $'omarchy'",
            "unset -f omar\\\nchy",
            "PROMPT_COMMAND='unset -f omarchy'",
            "eval \"$(printf 'unset -f %s' omarchy)\"",
        ] {
            assert!(
                why(&format!("{LINE}\n{later}\n")).contains("unsets `omarchy`"),
                "{later}"
            );
        }
        for later in ["unset -f omarch{y,}", "n=omarchy; unset -f \"$n\""] {
            assert!(
                why(&format!("{LINE}\n{later}\n")).contains("does not spell out"),
                "{later}"
            );
        }
        for later in ["true&&omarchy() { :; }", "eval 'omarchy() { :; }'"] {
            assert!(
                why(&format!("{LINE}\n{later}\n")).contains("redefines `omarchy`"),
                "{later}"
            );
        }
        for disable in [
            "true&&enable -n source",
            "enable -n source>/dev/null",
            "enable -n $'source'",
            "x=source; enable -n $x",
            "enable -n so\\\nurce",
        ] {
            assert!(
                why(&format!("{disable}\n{LINE}\n")).contains("builtin `source`"),
                "{disable}"
            );
        }
        // The words of one command count, not those of the line.
        for before in [
            "echo enable -n source",
            "[[ -n $x ]] && echo enable source",
            "enable -n echo; source ~/.x",
        ] {
            assert_eq!(
                loads(&format!("{before}\n{LINE}\n")),
                Loads::Effective,
                "{before}"
            );
        }
        assert_eq!(
            loads(&format!("{LINE}\nunset HISTFILE; omarchy theme list\n")),
            Loads::Effective
        );
    }

    #[test]
    fn a_command_is_read_from_the_word_that_runs() {
        for before in [
            "if true; then enable -n source; fi",
            "{ enable -n source; }",
            "! enable -n source",
            "time enable -n source",
            "command -p enable -n source",
            "x=1 enable -n source",
            "enable -n `echo source`",
            "enable -n so$x",
            "x=1 # note \\\nenable -n source",
            "echo x\\\\\nenable -n source",
        ] {
            assert!(
                why(&format!("{before}\n{LINE}\n")).contains("builtin `source`"),
                "{before}"
            );
        }
        for later in [
            "if true; then omarchy() { :; }; fi",
            "{ omarchy() { :; }; }",
            "a) omarchy() { :; } ;;",
            "omarchy ( ) { :; }",
            "x=1 # note \\\nomarchy() { :; }",
        ] {
            assert!(
                why(&format!("{LINE}\n{later}\n")).contains("redefines `omarchy`"),
                "{later}"
            );
        }
        assert!(why(&format!("{LINE}\nunset -f `echo omarchy`\n")).contains("unsets `omarchy`"));
        for later in ["unset -f omarch$y", "unset -f omarch$(echo y)"] {
            assert!(
                why(&format!("{LINE}\n{later}\n")).contains("does not spell out"),
                "{later}"
            );
        }
        for alias in [
            "true && alias omarchy='echo gone'",
            "builtin alias omarchy=x",
            "alias '[[=false'",
            "true && alias source=:",
        ] {
            assert!(
                why(&format!("{alias}\n{LINE}\n")).contains("an alias named"),
                "{alias}"
            );
        }
        assert!(why(&format!("BASH_ALIASES[omarchy]=x\n{LINE}\n")).contains("BASH_ALIASES"));
        // A backslash in a comment joins no line, here-documents and
        // comments run nothing, and these unset no function of Guardian's.
        assert_eq!(loads(&format!("x=1 # note \\\n{LINE}\n")), Loads::Effective);
        for later in [
            "_lazy() { unset -f \"$FUNCNAME\"; }",
            "_lazy() { unset -f \"${FUNCNAME[0]}\"; }",
            "clear_vars() { unset -v \"$1\"; }",
            "cat <<EOF\nTo undo: unset $HOME\nEOF",
            "ls # remember: unset $X",
        ] {
            assert_eq!(
                loads(&format!("{LINE}\n{later}\n")),
                Loads::Effective,
                "{later}"
            );
        }
    }

    #[test]
    fn what_bash_reads_as_one_word_or_a_comment_is_read_so() {
        // A here-document's end word ends at a redirect or a pipe.
        for opening in ["cat <<EOF>/dev/null", "cat <<EOF|cat >/dev/null"] {
            assert!(
                why(&format!("{LINE}\n{opening}\nx\nEOF\nunset -f omarchy\n"))
                    .contains("unsets `omarchy`"),
                "{opening}"
            );
            assert_eq!(
                loads(&format!("{opening}\nx\nEOF\n{LINE}\n")),
                Loads::Effective,
                "{opening}"
            );
        }
        // Quoted text inside `${…}` closes no block, and `;#` starts a
        // comment.
        assert_eq!(
            loads(&format!(
                "f() {{\n  local x=${{1:-\"default\"}}\n  [ -z \"$x\" ] && return 1\n}}\n{LINE}\n"
            )),
            Loads::Effective
        );
        assert_eq!(
            loads(&format!("echo hi;# return\n{LINE}\n")),
            Loads::Effective
        );
        // A plain unset of a name it does not spell out takes variables.
        for later in [
            "for v in FOO BAR; do unset $v; done",
            "unset ${!LESS_TERMCAP_*}",
            "case $1 in unset) echo \"$2\";; esac",
            "BASH_ALIASES[ll]=\"ls -l\"",
        ] {
            assert_eq!(
                loads(&format!("{LINE}\n{later}\n")),
                Loads::Effective,
                "{later}"
            );
        }
        for alias in [
            "BASH_ALIASES+=([omarchy]=echo)",
            "BASH_ALIASES[omarchy]+=echo",
            "declare -A BASH_ALIASES=([omarchy]=echo)",
            "BASH_ALIASES[$n]=echo",
        ] {
            assert!(
                why(&format!("{alias}\n{LINE}\n")).contains("BASH_ALIASES"),
                "{alias}"
            );
        }
        for lock in [
            "readonly -f omarchy",
            "declare -rf omarchy",
            "typeset -f -r omarchy",
        ] {
            assert!(
                why(&format!("omarchy() {{ :; }}; {lock}\n{LINE}\n")).contains("read-only"),
                "{lock}"
            );
        }
    }

    #[test]
    fn what_bash_reads_as_a_pattern_or_a_parameter_is_no_comment_or_alias() {
        // A quote over several lines, closed after a `}`, closes no block;
        // `#` after `(` or `|` is a pattern, and BASH_ALIASES read writes no
        // alias.
        for before in [
            "pids() {\n  ps | awk '\n    NR > 1 {\n      print $1\n    }'\n}",
            "if [[ $l =~ ^(#|$) ]]; then :; fi",
            "case x in @(#*|y)) : ;; esac",
            "echo \"${BASH_ALIASES[omarchy]}\"",
            "[[ -v BASH_ALIASES[omarchy] ]]",
            "unset 'BASH_ALIASES[omarchy]'",
        ] {
            assert_eq!(
                loads(&format!("{before}\n{LINE}\n")),
                Loads::Effective,
                "{before}"
            );
        }
        // `#` inside `${…}` or right after `$(…)` is part of the word.
        for later in [
            "y=${x//;#/_}; unset -f omarchy",
            "echo $(echo a)#; unset -f omarchy",
        ] {
            assert!(
                why(&format!("{LINE}\n{later}\n")).contains("unsets `omarchy`"),
                "{later}"
            );
        }
        assert!(
            why(&format!("BASH_ALIASES[`echo omarchy`]=echo\n{LINE}\n")).contains("BASH_ALIASES")
        );
        assert!(
            why(&format!(
                "omarchy() {{ :; }}; declare -rF omarchy\n{LINE}\n"
            ))
            .contains("read-only")
        );
        // Locked after the line, the function is the interceptor's.
        assert_eq!(
            loads(&format!("{LINE}\nreadonly -f omarchy\n")),
            Loads::Effective
        );
    }

    #[test]
    fn quoted_text_over_several_lines_and_parameters_hold_no_code() {
        // The `{` inside a quote opens nothing, so the `}'` that closes it
        // closes nothing either; a `#` after `|` or a pattern's `)` starts
        // a comment; a blank inside `${…}` leaves no `}` alone.
        for function in [
            "  awk '{\n    print $1\n  }' file",
            "  local c='{\n    \"a\": 1\n  }'",
            "  jq \"{\n    a: .b\n  }\"",
            "  sed -n '/x/{\n    p\n  }'",
            "  echo $'don\\'t'",
            "  echo hi |# note }",
            "  case $x in\n    a)# }\n    ;;\n  esac",
            "  local y=${1:- }",
            "  m=${m% }",
            "  REPLY=${REPLY//+(\\/)/\\/}",
            "  nths=( ${FZF_NTH//,/ } )",
        ] {
            assert_eq!(
                loads(&format!("f() {{\n{function}\n  return 0\n}}\n{LINE}\n")),
                Loads::Effective,
                "{function}"
            );
        }
        assert!(
            why(&format!(
                "f() {{\n  awk '{{\n    print\n  }}'\n  {LINE}\n}}\n"
            ))
            .contains("inside a function")
        );
        assert!(why(&format!("x='\n{LINE}\n'\n")).contains("inside quoted text"));
        assert!(why(&format!("x='\n'\nreturn\n{LINE}\n")).contains("`return`"));
        assert_eq!(
            loads(&format!("echo ${{x:- return }}\n{LINE}\n")),
            Loads::Effective
        );
        // A `#` inside `${…}` is text; after `$$` a `{` is no parameter.
        // Inside `[[ … ]]` a `#` after `)` or `|` is part of the pattern.
        for later in [
            "echo ${x:-a #}; unset -f omarchy",
            "[[ $x =~ (a)#b ]]; unset -f omarchy",
            "[[ $x =~ ^a|#x ]]; unset -f omarchy",
        ] {
            assert!(
                why(&format!("{LINE}\n{later}\n")).contains("unsets `omarchy`"),
                "{later}"
            );
        }
        assert_eq!(
            loads(&format!("{LINE}\necho $${{;# unset -f omarchy\n")),
            Loads::Effective
        );
        assert!(
            why(&format!("{LINE}\nPROMPT_COMMAND='\nunset -f omarchy\n'\n"))
                .contains("unsets `omarchy`")
        );
        // A `<<` inside quoted text starts no here-document.
        assert!(
            why(&format!("{LINE}\nmsg='\nsee <<EOF\n'\nunset -f omarchy\n"))
                .contains("unsets `omarchy`")
        );
        for alias in [
            ": ${BASH_ALIASES[omarchy]:=echo}",
            "printf -v 'BASH_ALIASES[omarchy]' %s echo",
            "read -r 'BASH_ALIASES[omarchy]' <<< echo",
            "BASH_ALIASES['[[']=echo",
        ] {
            assert!(
                why(&format!("{alias}\n{LINE}\n")).contains("BASH_ALIASES"),
                "{alias}"
            );
        }
        for read in [
            "echo ${BASH_ALIASES[omarchy]:-none} x[1]=2",
            "printf '%s\\n' \"${BASH_ALIASES[omarchy]}\"",
        ] {
            assert_eq!(
                loads(&format!("{read}\n{LINE}\n")),
                Loads::Effective,
                "{read}"
            );
        }
    }

    #[test]
    fn quotes_inside_a_substitution_inside_quotes_are_read_afresh() {
        // Bash 5.3 loads it after each first line, and returns, or unsets
        // after it, in the others.
        for effective in [
            "v=\"$(grep v f | sed 's/\"//g')\"",
            "a=\"$(echo x | cut -d'\"' -f2)\"",
            "trap 'echo hi' EXIT",
            "PROMPT_COMMAND='history -a'",
            "shopt -s extglob\ncase x in @(#*|y)) : ;; esac",
        ] {
            assert_eq!(
                loads(&format!("{effective}\n{LINE}\n")),
                Loads::Effective,
                "{effective}"
            );
        }
        for (before, after) in [
            ("x=\"$(echo '\"')\"\nreturn\n: # '", ""),
            (
                "",
                "x=\"$(echo '\"')\"\ny=' <<EOF'\nunset -f omarchy-plugin-add",
            ),
            ("arr=(# don't\n)\nreturn\n: # '", ""),
            ("x=$(ls |# don't\n)\nreturn\n: # '", ""),
            ("echo \\$'a\\'\nreturn\n: # '", ""),
            ("x=\"`echo \"a'b\"`\"\nreturn\n: # '", ""),
            ("x='\n#'\nreturn", ""),
            ("", "diff <(echo)#; unset -f omarchy"),
        ] {
            let text = format!("{before}\n{LINE}\n{after}\n");
            assert!(matches!(loads(&text), Loads::Ineffective(_)), "{text}");
        }
    }

    #[test]
    fn a_hash_after_an_escaped_character_starts_no_comment() {
        for escaped in ["\\)", "\\;", "\\&", "\\ ", "\\|"] {
            let text = format!("{LINE}\necho a{escaped}#; unset -f omarchy-plugin-add\n");
            assert_eq!(
                why(&text),
                "a later line unsets `omarchy-plugin-add`",
                "{text}"
            );
        }
    }

    #[test]
    fn where_quoted_text_ends_is_read_as_bash_reads_it() {
        // Each was run through bash 5.3 (`bash -O extglob`) with the line
        // replaced by an `echo`, which ran as a command.
        for before in [
            "x='\n# '\n",
            ": @(a|b|#x) '\n'\n",
            ": !(a|#x) '\n'\n",
            ": +(a|#x) '\n'\n",
            ": *(a|#x) '\n'\n",
            ": ?(a|#x) '\n'\n",
            "x=\"$(echo $'\\'')\"\n",
            "x=\"$( (echo) ; echo ' )\"' )\"\n",
            "x=\"$(echo a # it's\n)\"\n",
            "x=\"${y:-'}'}\"\n",
        ] {
            let text = format!("{before}{LINE}\n");
            assert!(matches!(loads(&text), Loads::Effective), "{text}");
        }
        // Inside `${…}` in double quotes a `'` still opens quoted text,
        // which bash then reads to the end of the file.
        assert_eq!(
            why(&format!("x=\"${{y:-'}}\"\n{LINE}\n")),
            "it is inside quoted text"
        );
    }

    #[test]
    fn a_hook_set_before_it_that_takes_it_away_is_not_effective() {
        for hook in [
            "trap 'unset -f omarchy' DEBUG",
            "PROMPT_COMMAND='unset -f omarchy'",
            "PS1='${ unset -f omarchy; }> '",
            "bind -x '\"\\C-x\": unset -f omarchy'",
            // A hook of several commands, an element and an append.
            "PROMPT_COMMAND='history -a; unset -f omarchy'",
            "trap ':; unset -f omarchy' DEBUG",
            "trap ': && unset -f omarchy' DEBUG",
            "PROMPT_COMMAND='history -a\nunset -f omarchy'",
            "PROMPT_COMMAND+=('unset -f omarchy')",
            "PROMPT_COMMAND[1]='unset -f omarchy'",
            // One that defines a function or alias again.
            "trap 'omarchy() { :; }' DEBUG",
            "trap 'alias omarchy=:' DEBUG",
            "PROMPT_COMMAND='alias omarchy=:'",
        ] {
            assert!(
                why(&format!("{hook}\n{LINE}\n")).starts_with("a hook ("),
                "{hook}"
            );
        }
        // A hook that leaves them, and a prompt's `$(…)`, which runs in a
        // subshell.
        for hook in [
            "PROMPT_COMMAND='history -a'",
            "PROMPT_COMMAND+=('history -a')",
            "PS1='$(unset -f omarchy)> '",
        ] {
            assert_eq!(
                loads(&format!("{hook}\n{LINE}\n")),
                Loads::Effective,
                "{hook}"
            );
        }
    }

    #[test]
    fn where_bash_never_runs_the_line_in_its_own_shell_is_told() {
        // Each was run in bash 5.3 with a stub interceptor.
        for before in [
            "(",
            "x=$(",
            "f() (",
            "false &&",
            "f() {\nfor i in 1; do if true; then :; fi; done",
            "f() {\necho }",
            "x=$((1))#'",
            "[[ $- == *i* ]] && exec bash --norc",
            "cat <<EOF\n  EOF",
            "cat <<A <<B\na\nA",
        ] {
            let text = format!("{before}\n{LINE}\n)\n}}\n'\nEOF\nB\n");
            assert!(matches!(loads(&text), Loads::Ineffective(_)), "{text}");
        }
        assert_eq!(
            why(&format!("{LINE}\nexec bash --norc\n")),
            "a later `exec` replaces the shell"
        );
        for before in [
            "a=(\n x\n)",
            "true ||\n  :",
            "f() { echo }; }",
            "exec 2>/dev/null",
            "cat <<-EOF\n\tx\n\tEOF",
            "cat <<A <<B\na\nA\nb\nB",
            "case $- in *i*) ;; *) return;; esac",
        ] {
            let text = format!("{before}\n{LINE}\nexec >/dev/null 2>&1\n");
            assert_eq!(loads(&text), Loads::Effective, "{text}");
        }
    }

    #[test]
    fn a_name_bash_reaches_by_braces_or_a_reference_is_read() {
        for text in [
            format!("{LINE}\nalias {{omarchy,zz}}=echo\n"),
            format!("{LINE}\nalias s{{ource,}}=:\n"),
            format!("{LINE}\nalias sou{{rce,x}}=:\n"),
            format!("{LINE}\ndeclare -n a; a=BASH_ALIASES; a[source]=:\n"),
            format!("{LINE}\ndeclare -n a=BASH_ALIASES; a[omarchy]=echo\n"),
            format!("{LINE}\ndeclare -n a='BASH_ALIASES[omarchy]'; a=echo\n"),
            format!("omarchy() {{ :; }}\nreadonly -f {{omarchy,zz}}\n{LINE}\n"),
            // Nested groups, and a range, which is taken to name it.
            format!("{LINE}\nalias {{x,{{omarchy,y}}}}=:\n"),
            format!("{LINE}\nalias omarch{{x..z}}=:\n"),
        ] {
            assert!(matches!(loads(&text), Loads::Ineffective(_)), "{text}");
        }
        // Text in braces, and one name of many choices that is not it.
        for text in [
            format!("{LINE}\nalias {{x}}=:\n"),
            format!("{LINE}\nalias {{a,b}}{{c,d}}=:\n"),
        ] {
            assert_eq!(loads(&text), Loads::Effective, "{text}");
        }
    }

    #[test]
    fn a_name_that_expands_to_very_many_words_is_read_in_bounded_time() {
        // 30 choices in each of 8 groups is 30^8 words; past the bound the
        // word is taken to name it.
        let group = format!("{{{}}}", vec!["a"; 30].join(","));
        let text = format!("{LINE}\nalias {}=x\n", group.repeat(8));
        let started = std::time::Instant::now();
        assert!(matches!(loads(&text), Loads::Ineffective(_)));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        // A long line of many words is read in time linear in it.
        let long = format!("{LINE}\nPS1=x{}\n", " y".repeat(50_000));
        let started = std::time::Instant::now();
        assert_eq!(loads(&long), Loads::Effective);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn a_command_continued_past_the_carried_bound_ends_at_a_blank() {
        // Past the bound the carried text ends with a blank, so the next
        // line starts a word of its own (`X=12` and then `exec true`).
        let text = format!("{LINE}\n{}\\\nexec true\n", "X=12 ".repeat(400));
        assert_eq!(
            loads(&text),
            Loads::Ineffective("a later `exec` replaces the shell".into())
        );
    }

    #[test]
    fn no_text_makes_the_reader_panic() {
        // Lines of shell-significant pieces from a fixed xorshift sequence:
        // quotes, substitutions, here-documents, continued lines, bodies
        // that open and never close, multi-byte characters.
        let pieces = [
            LINE, "'", "\"", "`", "$(", ")", "${", "}", "{", "(", "f()", "yay()", "<<E", "E", "\\",
            "#", ";", "&", "|", "&&", "exec", "x", " ", "\n", "é", "case", "in", "esac",
            "function", "end", "$'", "=", ">", "2>",
        ];
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..5_000 {
            let text: String = (0..next() % 24)
                .map(|_| pieces[usize::try_from(next() % pieces.len() as u64).unwrap()])
                .collect();
            let _ = loads(&text);
            let _ = overrides_makepkg(&text, "yay", GATE);
        }
    }

    #[test]
    fn a_long_run_of_continued_lines_is_read_in_linear_time() {
        // A debug build reads these in well under a second; a scan that
        // went back over the lines before each one would take minutes. The
        // 5 s bound leaves room for a loaded machine.
        for run in ["a \\\n", "; \\\n"] {
            let text = format!("{LINE}\n{}", run.repeat(10_000));
            let started = std::time::Instant::now();
            assert_eq!(loads(&text), Loads::Effective);
            assert!(started.elapsed() < std::time::Duration::from_secs(5));
        }
    }

    #[test]
    fn many_bodies_that_never_close_are_read_in_linear_time() {
        // The bound is the one of the test above, for the same reason.
        let text = "yay() {\n".repeat(20_000);
        let started = std::time::Instant::now();
        assert!(!overrides_makepkg(&text, "yay", GATE));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn a_prompt_runs_in_the_shell_only_through_its_own_substitution() {
        for prompt in [
            "PS1='${ unset -f omarchy; }'",
            "PS1='${\tunset -f omarchy; }'",
            "PS1='${\nunset -f omarchy; }'",
            "PS1='${| unset -f omarchy; }'",
        ] {
            let text = format!("{prompt}\n{LINE}\n");
            assert!(matches!(loads(&text), Loads::Ineffective(_)), "{text}");
        }
        let text = format!("PS1='$(unset -f omarchy)'\n{LINE}\n");
        assert_eq!(loads(&text), Loads::Effective);
    }

    #[test]
    fn only_an_exec_that_runs_in_the_shell_after_the_line_takes_it_away() {
        // Each was run in bash 5.3 with a stub interceptor.
        for after in [
            "reload() {\n  exec bash\n}",
            "echo \"a; exec true\"",
            "exec 2>/dev/null",
            "exec 3>&1",
            "exec {fd}>/tmp/x",
            "exec 2> /dev/null",
            "exec -a name",
            "exec -l",
            "f() { exec true; }",
            "( exec true )",
            "g ( ) { exec true; }",
            "g( ) {\n  exec true\n}",
            "g ( )\n{\n  exec true\n}",
            "f() ( : ); g() ( exec true )",
            // A `}` inside a word of the body closes nothing.
            "f() { echo ${x}; exec true; }",
            "f() { echo {a,b}; exec true; }",
            "f () {\n  exec true\n}",
            "exec -la name",
            "function f {\n  if :; then\n    exec true\n  fi\n}",
            "(\nexec true\n)",
            "((1))# ; unset -f omarchy",
            "exec 2> >(tee /dev/null >&2)",
            "exec 2> >(logger -t bash)",
            "exec 2>&1 > >(tee /dev/null)",
            "x=$( exec true )",
            "return",
            "f()\n{\n  exec true\n}",
            "f ()\n{\n  exec true\n}",
            "function f ()\n{\n  exec true\n}",
            "function f\n{\n  exec true\n}",
            "if :; then f() {\n  exec true\n}; fi",
            "exec \\\n\ntrue",
            "exec \\\n# c\ntrue",
        ] {
            let text = format!("{LINE}\n{after}\n");
            assert_eq!(loads(&text), Loads::Effective, "{text}");
        }
    }

    #[test]
    fn an_exec_that_runs_in_the_shell_after_the_line_takes_it_away() {
        // Each was run in bash 5.3 with a stub interceptor.
        for after in [
            "exec 2>/dev/null true",
            "exec 3>&1 true",
            "exec > /dev/null true",
            "x=1 exec true",
            "command exec true",
            "builtin exec true",
            "exec -a name true",
            "exec -la name true",
            "exec &>/dev/null true",
            "exec \\\n  true",
            // In a block, as an rc file starts tmux: the shell is replaced
            // wherever the condition holds.
            "if [ -z \"$TMUX\" ]; then\n  exec true\nfi",
            "if [ -z \"$TMUX\" ]; then exec true; fi",
            "[ -z \"$TMUX\" ] && { exec true; }",
            "while :; do\n  exec true\ndone",
            "case $- in *i*) exec true;; esac",
            "case $- in x|*i*) exec true;; esac",
            "f() {\n  :\n}\nif :; then exec true; fi",
            "f() { :; }; exec true",
            "f() {\n  :\n}; exec true",
            "f() {\n  :\n} && exec true",
            "case $(echo x) in x) exec true;; esac",
            "case x in\n  x)exec true;;\nesac",
            "case x in\n  (x) exec true;;\nesac",
            "X=$(echo a) exec true",
            "a=1 b=$(echo $(echo c)) exec true",
            "x=`echo a` exec true",
            "x=( a b ) exec true",
            "until exec true; do :; done",
            "exec 2> >(cat) true",
            "arr=(); exec true",
            "if false; then :; elif exec true; then :; fi",
            "while exec true; do :; done",
            "case x in esac; exec true",
            "case x in\n  *) exec true;;\nesac",
            // A command in a pipeline or put in the background runs in a
            // subshell; it is read as the file's own all the same, since a
            // `|` may also stand inside `$(…)` or a `case` pattern.
            "exec true &",
            "exec true | cat",
            "[[ -z $TMUX ]] && exec tmux new -A -s $(hostname | cut -d. -f1)",
            "exec true $(echo a | cat)",
            "X=$(echo a | cat) exec true",
            "case $TERM in xterm* | dumb) exec true;; esac",
            "case $- in\n  *i* | *x*) exec true ;;\nesac",
            "case x in (x|y) exec true;; esac",
            // A one-line function opens no body on the next line, and an
            // exec before a definition runs.
            "serve() ( cd /tmp && ls )\nif [[ -z $TMUX ]]; then exec true; fi",
            "f() ( : )\n{ exec true; }",
            "f() ( : )\nwhile :; do exec true; done",
            "exec true; f() { :; }",
            "exec true; f() {\n  :\n}",
            "f() { :; }; exec true; g() { :; }",
            "f() { :; }; exec true; g() {\n  :\n}",
            "f() { :; } && exec true; g() {\n  :\n}",
            "f() ( : ); exec true; g() {\n  :\n}",
            "f() {\n  :\n}; exec true; g() {\n  :\n}",
            "case $- in *i* ) exec true;; esac",
            "case $- in\n  *i* ) exec true ;;\nesac",
            "case $- in *i* | x ) exec true;; esac",
            // The `}` that closes a body is a command word, not one of
            // `${HOME}` or `{a,b}` later on the line.
            "f() { :; }; exec true -f ${HOME}/.tmux.conf",
            "f() { :; }; exec true new -s {a,b}",
            "f() { { :; }; }; exec true",
            "f() {\n  :\n}; exec true ${HOME}",
            "command -p exec true",
            "time -p exec true",
            "if exec true; then :; fi",
            // A second definition is told in each spelling bash takes.
            "f() { :; }; exec true; g ( ) { :; }",
            "f() { :; }; exec true; g( ) { :; }",
            "f() { :; }; exec true; g ( ) {\n:\n}",
            "f() {\n:\n}; exec true; g( ) {\n:\n}",
            "f() {\n:\n}; exec true; g() { :; }",
            // A body glued to the name is no name alone, so the next
            // line's block is no body.
            "l()(ls)\nif :; then exec true; fi",
            "f()(:)\n[[ $- == *i* ]] && { exec true; }",
            "c()((x++))\n{\nexec true\n}",
            // A substitution defines nothing.
            "$( ) ; { exec true; }",
            "<( ) && { exec true; }",
            "exec $( ) x",
            "$( )\nif :; then exec true; fi",
            // An assignment of an empty array defines nothing.
            "arr=() && { exec true; }",
            // A pattern's parentheses may stand apart by any blanks.
            "case $- in *i*  ) exec true;; esac",
            "case $- in *i*\t) exec true;; esac",
            "case $- in\n  *i*  ) exec true ;;\nesac",
            "case $- in ( *i* ) exec true;; esac",
            "case $- in ( *i*) exec true;; esac",
            "case $- in\n  ( *i* ) exec true ;;\nesac",
            // A subshell as a condition runs the `exec` after it in the
            // shell itself.
            "if ( : ) then exec true; fi",
            "while ( : ) do exec true; done",
            // Past a body in parentheses, or past a block after a body.
            "f() ( : ); exec true",
            "f() ( : ) && exec true",
            "f() {\n:\n}; { exec true; }",
        ] {
            let text = format!("{LINE}\n{after}\n");
            assert_eq!(why(&text), "a later `exec` replaces the shell", "{text}");
        }
    }

    #[test]
    fn a_comment_after_arithmetic_and_a_join_over_a_blank_line_are_read_as_bash_reads_them() {
        // `#` after a plain `((…))` starts a comment, whose apostrophe
        // opens nothing.
        let text = format!("x=1; ((x++))# don't\nreturn\n# it's\n{LINE}\n");
        assert!(matches!(loads(&text), Loads::Ineffective(_)), "{text}");
        // `&&` joins the next line of code, past blank and comment lines.
        for between in ["", "# c"] {
            let text = format!("false &&\n{between}\n{LINE}\n");
            assert_eq!(why(&text), "it continues the line before it", "{text}");
        }
        let text = format!("true \\\n\n{LINE}\n");
        assert_eq!(loads(&text), Loads::Effective, "{text}");
    }

    #[test]
    fn the_usual_bashrc_lines_before_it_do_not_make_it_ineffective() {
        // Each of these once read "a `return` or `exit` comes before it",
        // which turning the gate on again could not repair.
        for before in [
            "[ -z \"$PS1\" ] && return",
            "[[ -z $PS1 ]] && return",
            "[ -n \"${PS1-}\" ] || return 0",
            "[[ $- != *i* ]] && return",
            "[[ \"$-\" == *i* ]] || return;",
            "[[ $- =~ i ]] || return",
            "case $- in *i*) ;; *) return;; esac",
            "echo \"type exit to leave\"",
            "echo 'return here'",
            "export FOO=bar # exit code of last",
            "# exit",
            "alias e='exit'",
            // A shift and a here-string start no here-document, which
            // would swallow the rest of the file.
            "x=$(( 1 << 3 ))",
            "(( y = 1 << 2 ))",
            "read -r first <<< \"$line\"",
        ] {
            assert_eq!(
                loads(&format!("{before}\n{LINE}\n")),
                Loads::Effective,
                "{before}"
            );
        }
    }

    #[test]
    fn what_really_keeps_it_from_running_still_reads_ineffective() {
        for before in [
            "return",
            "exit 0",
            "true && exit",
            "[ -f ~/.x ] && return",
            // Returns when the shell *is* interactive.
            "[[ $- == *i* ]] && return",
            "[ -n \"$PS1\" ] && return",
            "[ -z \"$PS1\" ] && return; return",
            "echo \"a\" ; exit",
        ] {
            assert!(
                why(&format!("{before}\n{LINE}\n")).contains("`return`, `exit` or `exec`"),
                "{before}"
            );
        }
        assert!(why(&format!("if false; then\n  {LINE}\nfi\n")).contains("function or block"));
        assert!(why(&format!("cat <<EOF\n{LINE}\nEOF\n")).contains("here-document"));
        assert!(why(&format!("cat << 'END' # note\n{LINE}\nEND\n")).contains("here-document"));
        assert!(why(&format!("{LINE}\nunset -f omarchy\n")).contains("unsets `omarchy`"));
    }

    const GATE: &str = "/usr/lib/omarchy-guardian/guardian-makepkg";

    #[test]
    fn an_alias_or_function_in_front_of_a_helper_that_passes_makepkg_is_found() {
        assert!(overrides_makepkg(
            "alias yay='yay --makepkg /usr/bin/makepkg'\n",
            "yay",
            GATE
        ));
        assert!(overrides_makepkg(
            "yay() {\n  command yay --makepkg makepkg \"$@\"\n}\n",
            "yay",
            GATE
        ));
        assert!(overrides_makepkg(
            "yay() { command yay --makepkg=/tmp/x \"$@\"; }\n",
            "yay",
            GATE
        ));
        // Nor does one in a here-document.
        assert!(overrides_makepkg(
            "yay() {\n  cat <<EOF\n}\nEOF\n  command yay --makepkg /evil \"$@\"\n}\n",
            "yay",
            GATE
        ));
        // Nor one an indented word does not end (bash ends `<<EOF` only at
        // `EOF` alone), nor one continued from the line before.
        assert!(overrides_makepkg(
            "yay() {\n cat <<EOF\n  EOF\n}\nEOF\n command yay --makepkg /evil\n}\n",
            "yay",
            GATE
        ));
        assert!(overrides_makepkg(
            "yay() {\n  echo \\\n}\n  command yay --makepkg /evil \"$@\"\n}\n",
            "yay",
            GATE
        ));
        // Blank and comment lines before the body, and a body in
        // parentheses (a subshell).
        for text in [
            "yay()\n\n{\n  command yay --makepkg /evil \"$@\"\n}\n",
            "yay()\n# c\n{\n  command yay --makepkg /evil \"$@\"\n}\n",
            "yay() (\n\n  command yay --makepkg /evil \"$@\"\n)\n",
            "yay() (\n  # note\n  local x\n  command yay --makepkg /evil \"$@\"\n)\n",
            "yay() (\n  local d=${HOME}\n  command yay --makepkg /evil \"$@\"\n)\n",
            "yay() (\n  [ -n \"$x\" ] && { :; }\n  command yay --makepkg /evil \"$@\"\n)\n",
            "yay() (\n  case $x in a) :;; esac\n  command yay --makepkg /evil \"$@\"\n)\n",
            "yay()\n(\n  command yay --makepkg /evil \"$@\"\n)\n",
            "yay()\n# {\n(\n  command yay --makepkg /evil \"$@\"\n)\n",
            "function yay\n{\n  command yay --makepkg /evil \"$@\"\n}\n",
            "yay() # wrapper\n{\n  local x\n  command yay --makepkg /evil \"$@\"\n}\n",
            "yay ( ) {\n  local x\n  command yay --makepkg /evil \"$@\"\n}\n",
            "yay ( )\n(\n  local x\n  command yay --makepkg /evil \"$@\"\n)\n",
            "function yay ( )\n(\n  local x\n  command yay --makepkg /evil \"$@\"\n)\n",
            "yay ( ) # c\n(\n  local x\n  command yay --makepkg /evil \"$@\"\n)\n",
            "yay( )\n(\n  local x\n  command yay --makepkg /evil \"$@\"\n)\n",
            "yay() (\n  case $1 in\n    a) :;;\n  esac\n  command yay --makepkg /evil \"$@\"\n)\n",
            "yay() \\\n{\n  local x\n  command yay --makepkg /evil \"$@\"\n}\n",
            "yay (){\n  command yay --makepkg /evil \"$@\"\n}\n",
            "yay(){\n  command yay --makepkg /evil \"$@\"\n}\n",
            "function yay() {\n  command yay --makepkg /evil \"$@\"\n}\n",
        ] {
            assert!(overrides_makepkg(text, "yay", GATE), "{text}");
        }
        // A commented line in the body passes nothing.
        assert!(!overrides_makepkg(
            "yay() {\n  # command yay --makepkg /evil\n  command yay \"$@\"\n}\n",
            "yay",
            GATE
        ));
        // A `}` inside text over several lines ends no body.
        assert!(overrides_makepkg(
            "yay() {\n  echo '\n}\n'\n  command yay --makepkg /evil \"$@\"\n}\n",
            "yay",
            GATE
        ));
        // fish has no here-documents: a `<<` there hides nothing.
        assert!(overrides_makepkg(
            "function yay\n  echo a <<b\n  command yay --makepkg /evil $argv\nend\n",
            "yay",
            GATE
        ));
        // The `end` of a `begin` block closes no function.
        assert!(overrides_makepkg(
            "function yay\n  begin\n    true\n  end\n  command yay --makepkg /evil $argv\nend\n",
            "yay",
            GATE
        ));
        assert!(overrides_makepkg(
            "function paru\n  if true\n    command paru --makepkg makepkg $argv\n  end\nend\n",
            "paru",
            GATE
        ));
        assert!(!overrides_makepkg(
            "alias yay='yay --noconfirm'\n",
            "yay",
            GATE
        ));
        assert!(!overrides_makepkg(
            "# alias yay='yay --makepkg makepkg'\n",
            "yay",
            GATE
        ));
        assert!(!overrides_makepkg(
            "alias y='yay --makepkg makepkg'\n",
            "paru",
            GATE
        ));
    }

    #[test]
    fn makepkg_on_another_line_or_guardians_own_shim_is_no_override() {
        // An alias of the helper's name, and `--makepkg` on some other
        // command of the file.
        assert!(!overrides_makepkg(
            "alias yay='yay --noconfirm'\nalias p='paru --makepkg /usr/bin/makepkg'\n",
            "yay",
            GATE
        ));
        assert!(!overrides_makepkg(
            "yay() {\n  command yay \"$@\"\n}\nbuild() {\n  paru --makepkg makepkg\n}\n",
            "yay",
            GATE
        ));
        assert!(!overrides_makepkg(
            "function yay\n  command yay $argv\nend\nfunction b\n  paru --makepkg makepkg\nend\n",
            "yay",
            GATE
        ));
        // A name not followed by a body by its second line of code defines
        // none, so the line after that is not read as its body.
        assert!(!overrides_makepkg(
            "yay()\nalias x=y\nparu --makepkg makepkg\n",
            "yay",
            GATE
        ));
        // A `<<` in fish starts no here-document that would hide its `end`.
        assert!(!overrides_makepkg(
            "function yay\n  echo a <<b\n  command yay $argv\nend\nfunction b\n  paru --makepkg makepkg\nend\n",
            "yay",
            GATE
        ));
        // Passing Guardian's own shim keeps the build in the gate.
        assert!(!overrides_makepkg(
            &format!("alias yay='yay --makepkg {GATE}'\n"),
            "yay",
            GATE
        ));
        assert!(!overrides_makepkg(
            &format!("yay() {{\n  command yay --makepkg=\"{GATE}\" \"$@\"\n}}\n"),
            "yay",
            GATE
        ));
    }
}
