//! Reading a shell command line: its words, and a little closer than word
//! by word, its statements and pipelines outside quotes, the command
//! substitutions in it, and the program a part of it runs. The rules read
//! these here, but for the recursive `rm` rule, which has its own reader
//! in `removal.rs`.
//!
//! None of this is a shell parser. It reads the shapes the rules name.
//! `as_shell_reads` rebuilds a whole line as bash reads its words, and
//! every line rule, the recursive `rm` rule included, reads that as well as
//! the line as written. The two readers are separate, so a bypass fixed in
//! one must be checked in the other.

// TODO(gosumarchy): merge with the reader in `removal.rs` into one that
// yields words with their place and quoting, after the advisory is
// published.

/// Shells that read commands from standard input.
pub(super) const PIPE_SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "ash", "fish"];

/// Splits a command line into words at whitespace outside quotes. Quote
/// characters are kept in the words.
pub(super) fn shell_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote: Option<char> = None;
    for character in line.chars() {
        if quote.is_none() && character.is_whitespace() {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
            continue;
        }
        match quote {
            Some(open) if character == open => quote = None,
            None if character == '"' || character == '\'' => quote = Some(character),
            Some(_) | None => {}
        }
        word.push(character);
    }
    if !word.is_empty() {
        words.push(word);
    }
    words
}

pub(super) fn unquoted(word: &str) -> String {
    word.chars()
        .filter(|character| !matches!(character, '"' | '\''))
        .collect()
}

/// The words of a command line (see `shell_words`), without their quotes.
pub(super) fn unquoted_words(line: &str) -> Vec<String> {
    shell_words(line)
        .iter()
        .map(|word| unquoted(word))
        .collect()
}

/// `line` as a shell reads the words in it, where it is spelled to keep a
/// word from matching what it says: quotes that join the parts of a word or
/// stand around a command, a flag or what some commands act on (`c"u"rl`,
/// `r"m"`, `cu''rl`, `'rm'`, `ufw 'disable'`; see `without_word_quotes`), a
/// backslash before a letter, a digit, `-`, `/` or `.` (`c\url`, `\rm`,
/// `\-rf`), `$@` and `$*` touching a word (empty in a script run without
/// arguments), and `$IFS`, `${IFS}` or `${IFS:…}` (a blank, or nothing for
/// a part past its end). Empty where nothing is spelled so; two readings
/// where the line leaves a `${` open (see `without_word_quotes`).
///
/// The rules read both this and the line as written: a backslash or a quote
/// is also what some rules look for (`\x41` escapes, `sh -c "…"`).
///
/// Left to the AI review: positional parameters (`rm$IFS$9-rf`, which in a
/// function are often a real argument, `rm -rf $1/`), `$'\x72m'`, brace
/// expansion (`{c,}url`) and globs (`c?rl`).
pub(crate) fn as_shell_reads(line: &str) -> Vec<String> {
    let readings: Vec<String> = without_word_quotes(line)
        .iter()
        .map(|unquoted| spelled_out(unquoted))
        .collect();
    if readings.iter().all(|reading| reading == line) {
        Vec::new()
    } else {
        readings
    }
}

/// `unquoted` with `$IFS`, `$@`, `$*` and a backslash before a word
/// letter read as `as_shell_reads` says.
fn spelled_out(unquoted: &str) -> String {
    let is_word = |character: Option<char>| {
        character.is_some_and(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '/' | '.'))
    };
    let mut out = String::with_capacity(unquoted.len());
    let mut rest = unquoted;
    while let Some(character) = rest.chars().next() {
        let after = &rest[character.len_utf8()..];
        let next = after.chars().next();
        let skip = match character {
            '$' => {
                if let Some((name, blank)) = ifs_name(after) {
                    out.push_str(blank);
                    1 + name
                } else if let Some(empty) = ["@", "*", "{@}", "{*}"]
                    .into_iter()
                    .find(|name| after.starts_with(name))
                    .filter(|name| {
                        is_word(out.chars().next_back())
                            || is_word(after[name.len()..].chars().next())
                    })
                {
                    1 + empty.len()
                } else {
                    0
                }
            }
            '\\' if next
                .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '/' | '.')) =>
            {
                1
            }
            _ => 0,
        };
        if skip == 0 {
            out.push(character);
            rest = after;
        } else {
            rest = &rest[skip..];
        }
    }
    out
}

/// Whether `${IFS:<offset>[:<length>]}` holds a character, as bash takes a
/// substring of IFS's default three (a negative offset or length counts
/// from the end; one that goes past either end leaves nothing). `None` for
/// a part that is not two numbers.
fn ifs_part_is_blank(part: &str) -> Option<bool> {
    const LENGTH: i64 = 3;
    let mut numbers = part.splitn(2, ':').map(str::trim);
    let offset: i64 = numbers.next()?.parse().ok()?;
    let start = if offset < 0 { LENGTH + offset } else { offset };
    let end = match numbers.next() {
        None => LENGTH,
        Some(count) => {
            let count: i64 = count.parse().ok()?;
            if count < 0 {
                LENGTH + count
            } else {
                start.saturating_add(count)
            }
        }
    };
    Some((0..LENGTH).contains(&start) && end.min(LENGTH) > start)
}

/// The length of the name after a `$` that names `IFS`, and what a shell
/// reads it as: `IFS` up to where its name ends, `{IFS}`, or `{IFS:…}` up
/// to its brace, a blank, or nothing for a part of it that is empty
/// (`${IFS:3}`, `${IFS:0:0}`; `IFS` holds three characters by default).
fn ifs_name(after: &str) -> Option<(usize, &'static str)> {
    let starts = |name: &str| {
        after
            .get(..name.len())
            .is_some_and(|start| start.eq_ignore_ascii_case(name))
    };
    if starts("{ifs}") {
        Some(("{ifs}".len(), " "))
    } else if starts("{ifs:") {
        // Only what an offset and a length can hold, so a line of
        // `${IFS:` without a brace is read once, not once for each.
        let part = &after["{ifs:".len()..];
        let length = part
            .bytes()
            .take_while(|byte| byte.is_ascii_digit() || matches!(byte, b':' | b'-' | b' '))
            .count();
        if part.as_bytes().get(length) != Some(&b'}') {
            return None;
        }
        let blank = if part.starts_with('-') {
            // `${IFS:-…}` is the default-value form: IFS is set, so it is IFS.
            true
        } else {
            ifs_part_is_blank(&part[..length])?
        };
        Some((
            "{ifs:".len() + length + "}".len(),
            if blank { " " } else { "" },
        ))
    } else if starts("ifs")
        && !after["ifs".len()..]
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        Some(("ifs".len(), " "))
    } else {
        None
    }
}

/// `line` with the quotes of each word taken out where they join the parts
/// of one word and nothing quoted in it is blank: `r"m"`, `"r"m`, `cu''rl`
/// and `"c"'u'"rl"` are the words `rm` and `curl` a shell runs, and `r$''m`
/// is `rm` too. A word that is one quoted string is taken out of its
/// quotes where it is a command, a flag, or what a command that acts on its
/// arguments acts on (`'rm' -rf /`, `rm "-rf"`, `ufw 'disable'`; see
/// `Place`). A word with a quoted blank
/// (`"rm -rf /"`) is one argument and stays as written, as does a word
/// whose quote is left open. A quote of the other kind inside one, and a
/// quote after a backslash outside single quotes, is a letter.
fn without_word_quotes(line: &str) -> Vec<String> {
    match read_words(line, Braces::Read) {
        Ok(read) => vec![read],
        // A `${` left open reads the rest of the line as its letters, and
        // could hide a command bash runs once the line goes on (a `case`
        // that never ends keeps a `}` from closing it). The line is read a
        // second time with `${` as letters, and both readings are kept:
        // neither alone sees every command, and together they can only add
        // matches. Reading again with only the open `${`
        // as letters was weighed: marking one moves the depths after it,
        // so it can take rounds and still miss.
        Err(OpenBrace(read)) => {
            let letters = match read_words(line, Braces::Letters) {
                Ok(letters) | Err(OpenBrace(letters)) => letters,
            };
            if letters == read {
                vec![read]
            } else {
                vec![read, letters]
            }
        }
    }
}

/// How `read_words` reads `${…}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Braces {
    /// As bash does: what is inside is one word's, but for substitutions.
    Read,
    /// As letters, for a line that leaves a `${` open.
    Letters,
}

/// The line left a `${` open; how it was read.
#[derive(Debug)]
struct OpenBrace(String);

/// `without_word_quotes`, reading `${…}` as `braces` says.
fn read_words(line: &str, braces: Braces) -> Result<String, OpenBrace> {
    let mut reader = WordReader {
        out: String::with_capacity(line.len()),
        word: Word::default(),
        place: Place::Start,
        nesting: Nesting::default(),
        braces,
    };
    let mut characters = line.chars();
    while let Some(character) = characters.next() {
        reader.read(character, &mut characters);
    }
    let WordReader {
        mut out,
        mut word,
        place,
        mut nesting,
        ..
    } = reader;
    end_word(&mut word, &mut out, place, &mut nesting);
    if nesting.braces.is_empty() {
        Ok(out)
    } else {
        Err(OpenBrace(out))
    }
}

/// What `read_words` holds while it reads a line.
#[derive(Debug)]
struct WordReader {
    /// The line read so far, the words before `word` ended.
    out: String,
    word: Word,
    /// Where `word` stands.
    place: Place,
    nesting: Nesting,
    braces: Braces,
}

impl WordReader {
    fn read(&mut self, character: char, characters: &mut std::str::Chars<'_>) {
        if quoted_in_backtick(character, characters, &mut self.word, &self.nesting) {
            return;
        }
        // Outside single quotes a backslash keeps the next character, and
        // in `$'…'` too (`$'\''`).
        let escapes = self.word.open != Some('\'') || self.word.ansi;
        match self.word.open {
            Some(_) if character == '\\' && escapes => self.backslash(character, characters),
            Some(open) if character == open => self.word.close_quote(character),
            Some(_) => self.word.push(character),
            None => self.read_unquoted(character, characters),
        }
    }

    fn read_unquoted(&mut self, character: char, characters: &mut std::str::Chars<'_>) {
        let word = &mut self.word;
        match character {
            // Inside `${…}` a blank, `;`, `|`, `&` and a bare `(` or `)`
            // are letters (`${v// /}`, `${v//(/}`); `$(`, `<(`, `>(` and a
            // backtick there still open a substitution, and quotes are
            // quotes.
            letter if self.nesting.in_brace() && is_brace_letter(letter, &word.written) => {
                word.push(letter);
            }
            blank if blank.is_whitespace() => self.blank(blank),
            '}' if self.nesting.in_brace() => {
                self.nesting.close_brace();
                word.push(character);
            }
            // `&` after `>` or `<` (`2>&1`) is part of a redirection.
            ';' | '|' | '&' | '(' | '`'
                if !(character == '&' && word.written.ends_with(['>', '<'])) =>
            {
                self.separator(character);
            }
            '\\' => self.backslash(character, characters),
            '$' if characters.clone().next() == Some('{') => self.dollar_brace(characters),
            // The `}` that ends `${ …; }` is a keyword, where a command may
            // stand; one that ends a `{ …; }` inside it is a word.
            '}' if word.written.is_empty()
                && self.place == Place::Start
                && self.nesting.in_command_brace() =>
            {
                word.push(character);
                if !self.nesting.close_group() {
                    word.closes_to = Some(self.nesting.close_command_brace());
                }
            }
            // `\)` never gets here: the arm above reads it.
            ')' => {
                self.nesting.word(word.since_close());
                word.push(character);
                word.closes_to = Some(self.nesting.close());
            }
            '"' | '\'' => word.open_quote(character),
            letter => word.push(letter),
        }
    }

    fn blank(&mut self, blank: char) {
        if self.word.written.is_empty() {
            // Nothing after a closing backtick joins this word.
            self.word.closes_to = None;
        } else {
            self.place = end_word(&mut self.word, &mut self.out, self.place, &mut self.nesting);
        }
        self.out.push(blank);
    }

    /// A statement starts after `;`, `|`, `&`, `(` and a backtick
    /// (`true;'rm'`, `$('rm' …)`), and an array after `=(`.
    fn separator(&mut self, character: char) {
        let array = character == '(' && self.word.written.ends_with('=');
        // Where the word this touches stands (`$(a)$(b)`: after the first
        // substitution).
        let at = self.word.closes_to.unwrap_or(self.place);
        let outside = outside_of(character, &self.word.written, at);
        if !self.word.written.is_empty() {
            end_word(&mut self.word, &mut self.out, self.place, &mut self.nesting);
        }
        self.out.push(character);
        let closing = character == '`' && self.nesting.in_backtick();
        self.place = match character {
            '(' => self.nesting.open(outside),
            '`' => self.nesting.backtick(outside),
            _ => Place::Start,
        };
        if array {
            self.place = Place::Array;
        }
        // What touches a closing backtick is of one word with the
        // substitution, which stands where it goes back to
        // (`` x=`:`a 'rm' ``), as after a `)`. Where an empty word before
        // it went is spent: a separator after a closing backtick
        // (`` `:`;x=1 'rm' ``) leads to a command.
        self.word.closes_to = closing.then_some(self.place);
    }

    fn backslash(&mut self, character: char, characters: &mut std::str::Chars<'_>) {
        self.word.push(character);
        if let Some(escaped) = characters.next() {
            self.word.push(escaped);
        }
    }

    /// `$` before `{`. `$${` is `$$` and a `{`. Bash 5.3 runs the commands
    /// in `${ …; }` and `${| …; }`, as in `$(…)`.
    fn dollar_brace(&mut self, characters: &mut std::str::Chars<'_>) {
        self.word.push('$');
        if !lone_dollar(&self.word.written) {
            return;
        }
        if characters.clone().nth(1).is_some_and(starts_commands) {
            let at = self.word.closes_to.unwrap_or(self.place);
            let outside = outside_of('(', "$", at);
            end_word(&mut self.word, &mut self.out, self.place, &mut self.nesting);
            self.out.push(characters.next().unwrap_or_default());
            self.place = self.nesting.open_command_brace(outside);
        } else if self.braces == Braces::Read {
            self.word.push(characters.next().unwrap_or_default());
            self.nesting.open_brace();
        }
    }
}

/// Bash ends a backtick substitution at the next backtick, inside either
/// quote too (`` `echo '`; 'rm' … ``, `` `echo "`; … ``), after it reads
/// `` \` `` and `\\` there as one letter each, single quotes or not
/// (`` `echo '\`'`; 'rm' … ``). Whether `character` was taken so; a
/// backtick there closes the quote open in `word`, and is read on.
fn quoted_in_backtick(
    character: char,
    characters: &mut std::str::Chars<'_>,
    word: &mut Word,
    nesting: &Nesting,
) -> bool {
    if !nesting.in_backtick() || word.open.is_none() {
        return false;
    }
    if character == '\\' && matches!(characters.clone().next(), Some('`' | '\\')) {
        word.push(character);
        word.push(characters.next().unwrap_or_default());
        return true;
    }
    if character == '`' {
        word.open = None;
    }
    false
}

/// Whether `letter`, after `written` inside `${…}`, is a letter of the
/// word: a blank, `;`, `|`, `&`, `)`, and a `(` that opens no substitution.
fn is_brace_letter(letter: char, written: &str) -> bool {
    letter.is_whitespace()
        || matches!(letter, ';' | '|' | '&' | ')')
        || (letter == '(' && !opens_substitution(written))
}

/// Whether `${` followed by `after` holds commands (`${ …; }`, `${| …; }`).
fn starts_commands(after: char) -> bool {
    after.is_whitespace() || after == '|'
}

/// Whether a `(` after `written` opens a substitution: `$(`, `<(` or `>(`,
/// the mark not escaped.
fn opens_substitution(written: &str) -> bool {
    lone_dollar(written)
        || ['<', '>'].iter().any(|mark| {
            written
                .strip_suffix(*mark)
                .is_some_and(|before| (before.len() - before.trim_end_matches('\\').len()) % 2 == 0)
        })
}

/// Ends `word` (see `Word::end`); a word with a `)` in it goes where its
/// last `)` leads (see `Nesting::close`).
fn end_word(word: &mut Word, out: &mut String, place: Place, nesting: &mut Nesting) -> Place {
    let closes_to = word.closes_to;
    nesting.word(word.since_close());
    if place == Place::Start && word.written == "{" {
        nesting.open_group();
    }
    let closes = word.written == "}";
    let after = word.end(out, place);
    // A `}` where a command may stand is followed by one when it ends a
    // group or `${ …; }`; when it is only a word (`x=${ a=1 }; }`, or the
    // end of a `{` that was an argument, `${ command {; }`) a command follows
    // too, later. Reading one there can only add matches.
    if closes && place == Place::Start {
        return Place::Start;
    }
    closes_to.unwrap_or(after)
}

/// Whether the `$` that ends `text` starts an expansion: it is not the
/// second of `$$` (the shell's process number), nor escaped by an odd run
/// of backslashes (`\\$` is a backslash and a `$`).
fn lone_dollar(text: &str) -> bool {
    let before = text.trim_end_matches('$');
    let dollars = text.len() - before.len();
    if dollars == 0 {
        return false;
    }
    let backslashes = before.len() - before.trim_end_matches('\\').len();
    (dollars - backslashes % 2) % 2 == 1
}

/// The place a `(` or a backtick touching `written`, which stands `at`,
/// goes back to when it closes. `$(`, `<(` and `>(` among a command's
/// arguments are an argument, and so are an extended glob (`@(a|b)`,
/// `!(x)`) and a backtick there. A `(` after any other word that cannot
/// name a function (`%s(`) is not one bash would take, so the quotes
/// around it were misread (`"$(gettext "Run %s()")" "sudo"`): the place
/// stays. Any other (a subshell, `f()`, a `case` pattern, an array, a
/// substitution as the command) closes where a command may follow.
fn outside_of(opening: char, written: &str, at: Place) -> Place {
    const MARKS: [char; 8] = ['$', '<', '>', '@', '!', '?', '*', '+'];
    let among_arguments = !matches!(at, Place::Start | Place::FlagValue);
    let marked = opening == '`' || written.ends_with(MARKS);
    let misread = opening == '('
        && !written.is_empty()
        && !written.ends_with(MARKS)
        && !written.ends_with('=')
        && !written
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | ':' | '/'));
    if (marked && among_arguments) || misread {
        at
    } else {
        Place::Start
    }
}

/// The parentheses, backticks, `${…}` and `case` statements open at a
/// point of a line.
#[derive(Debug, Default)]
struct Nesting {
    /// The place outside each `(` still open, so its `)` goes back to it:
    /// `$(basename x) 'ufw'` is an argument, `a=() 'ufw'` a command.
    outside: Vec<Place>,
    /// The place outside a backtick still open. Backticks do not nest
    /// without a backslash, which this reader takes as a letter.
    backtick: Option<Place>,
    /// For each `case` seen, how many `(` were open around it.
    cases: Vec<usize>,
    /// For each `${` still open, how many `(` were open around it and
    /// whether a backtick was: it is the innermost while both still hold.
    braces: Vec<(usize, bool)>,
    /// For each `${ …; }` still open, how many `(` (its own among them)
    /// are open around its commands, and how many `{ …; }` groups.
    command_braces: Vec<(usize, usize)>,
}

impl Nesting {
    /// After a `(` that goes back to `outside` when it closes.
    fn open(&mut self, outside: Place) -> Place {
        self.outside.push(outside);
        Place::Start
    }

    /// After a backtick: one that opens goes back to `outside` when it
    /// closes, and ends any `${` left open inside it.
    fn backtick(&mut self, outside: Place) -> Place {
        if let Some(place) = self.backtick.take() {
            self.braces.retain(|(_, in_backtick)| !in_backtick);
            place
        } else {
            self.backtick = Some(outside);
            Place::Start
        }
    }

    /// Where a `)` leads. One that may end a `case` pattern (`y)`, `*(x))`,
    /// `$(case y in y) …`) has no `(` of its own, and a command may follow
    /// it; any other goes back to the place outside the `(` it closes, even
    /// with more of the word after it (`$(echo y)/bin 'rm'`).
    fn close(&mut self) -> Place {
        if self.cases.last() == Some(&self.outside.len()) {
            return Place::Start;
        }
        // Bash never ends `${ …; }` at a `)`: one at its own depth closes
        // the `(` around it, so the `${` was left open by a misread (a `{`
        // that was only a word, counted as a group) and is dropped.
        if self
            .command_braces
            .last()
            .is_some_and(|(around, _)| *around == self.outside.len())
        {
            self.command_braces.pop();
            self.outside.pop();
        }
        // A `case` this line did not open (its pattern on a line of its
        // own) leaves no `(` to close either. No `${` is open inside the
        // `(`: a `)` there is a letter.
        self.outside.pop().unwrap_or(Place::Start)
    }

    /// After `${ ` or `${|`, which goes back to `outside` when it closes.
    fn open_command_brace(&mut self, outside: Place) -> Place {
        self.outside.push(outside);
        self.command_braces.push((self.outside.len(), 0));
        Place::Start
    }

    /// Whether a `${ …; }` is open with nothing open inside it but
    /// parentheses a `case` leaves (see `close`).
    fn in_command_brace(&self) -> bool {
        self.command_braces
            .last()
            .is_some_and(|(around, _)| *around <= self.outside.len())
    }

    /// After a `{` that opens a group, inside a `${ …; }`.
    fn open_group(&mut self) {
        if let Some((_, groups)) = self.command_braces.last_mut() {
            *groups += 1;
        }
    }

    /// At a `}` where a command may stand inside a `${ …; }`: whether it
    /// ends a group of its own.
    fn close_group(&mut self) -> bool {
        match self.command_braces.last_mut() {
            Some((_, groups)) if *groups > 0 => {
                *groups -= 1;
                true
            }
            _ => false,
        }
    }

    /// Where the `}` of the innermost `${ …; }` leads, with what a `case`
    /// left open inside it closed.
    fn close_command_brace(&mut self) -> Place {
        let around = self.command_braces.pop().map_or(0, |(around, _)| around);
        self.outside.truncate(around);
        self.outside.pop().unwrap_or(Place::Start)
    }

    /// After `${`.
    fn open_brace(&mut self) {
        self.braces
            .push((self.outside.len(), self.backtick.is_some()));
    }

    /// Whether a `${` is the innermost of what is open.
    fn in_brace(&self) -> bool {
        self.braces.last() == Some(&(self.outside.len(), self.backtick.is_some()))
    }

    /// After the `}` of the innermost `${`.
    fn close_brace(&mut self) {
        self.braces.pop();
    }

    /// Notes a word as written, before any `)` in it. A bare `case`
    /// anywhere counts, and its `esac` is never looked for. Bash reads
    /// either keyword only where its grammar allows one, and reading an
    /// `esac` where it has none (`'esac'`, `` `esac` ``, `[[ a || esac ]]`)
    /// lets a pattern's `)` close the `(` around the `case` and hide the
    /// command after it, as does missing a `case` (`f() case …`). A `case`
    /// that is not one, or one that has ended, only makes a later `)` read
    /// as a place where a command may stand, which can add matches but not
    /// hide one.
    fn word(&mut self, written: &str) {
        if written == "case" {
            self.cases.push(self.outside.len());
        }
    }

    fn in_backtick(&self) -> bool {
        self.backtick.is_some()
    }
}

/// Where a word of a line stands, for whether one quoted string in it is
/// read without its quotes. The rules match text, and a quote is often all
/// that tells data from a command (`warning "…%s" "sudo"`, `x=("ufw"
/// "disable")`), so only a command, a flag, or what one of
/// `ACTING_COMMANDS` acts on is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Place {
    /// Where a statement's command is still to come: the first word, after
    /// `;`, `|`, `&`, `(` or a backtick (`without_word_quotes`), after an
    /// assignment, a number (`timeout 5`), and after a word in
    /// `STATEMENT_STARTS` or its flags.
    Start,
    /// After a flag where a command is still to come: the flag's value
    /// (`sudo -u root`) or the command (`sudo -E rm`).
    FlagValue,
    /// The arguments of a command in `ACTING_COMMANDS`.
    Acting,
    /// The arguments of any other command.
    Arguments,
    /// Inside `x=( … )`, until the statement ends: no command follows an
    /// array's `)` before then.
    Array,
}

/// Words after which a statement's command is still to come: keywords, and
/// programs that run the command after them.
const STATEMENT_STARTS: &[&str] = &[
    "sudo",
    "doas",
    "pkexec",
    "run0",
    "su",
    "runuser",
    "setpriv",
    "nsenter",
    "unshare",
    "systemd-run",
    "busybox",
    "strace",
    "fakeroot",
    "chrt",
    "watch",
    "firejail",
    "valgrind",
    "ltrace",
    "exec",
    "env",
    "command",
    "builtin",
    "eval",
    "coproc",
    "nohup",
    "time",
    "xargs",
    "nice",
    "ionice",
    "timeout",
    "stdbuf",
    "setsid",
    "then",
    "do",
    "else",
    "if",
    "elif",
    "while",
    "until",
    "{",
    "!",
];

/// Words whose one value comes before the command: `chroot` names a
/// directory, `function` the function's name, `flock` a lock file and
/// `taskset` a CPU mask, `sg` a group.
const STARTS_AFTER_A_VALUE: &[&str] = &["chroot", "function", "flock", "taskset", "sg"];

/// Commands whose arguments the rules read as what they do (`ufw disable`,
/// `nft flush ruleset`, `setenforce 0`), so a quoted one is no data.
const ACTING_COMMANDS: &[&str] = &[
    "ufw",
    "nft",
    "setenforce",
    "iptables",
    "ip6tables",
    "sysctl",
];

impl Place {
    /// The place of the word after `written` (`bare`: without its quotes),
    /// which stands at `self`.
    fn after(self, written: &str, bare: &str) -> Self {
        // The end of a test, after which only an operator or a reserved
        // word may stand (`if [[ -e / ]] then 'rm'`), wherever the reading
        // stands: no command is named `]]`.
        if written == "]]" {
            return Self::Start;
        }
        match self {
            // A flag's value, or another flag (`sudo -E -u root`).
            Self::FlagValue if bare.starts_with('-') => Self::FlagValue,
            Self::FlagValue => Self::Start,
            Self::Start => {
                let name = program_name(bare);
                // A redirection on its own (`>`, `2>`) takes its file next.
                // `{fd}>` names the descriptor it opens.
                let operator = match bare.strip_prefix('{').and_then(|rest| rest.split_once('}')) {
                    Some((name, rest)) if is_name(name) => rest,
                    _ => bare,
                };
                let redirection = operator.ends_with(['<', '>'])
                    && operator
                        .chars()
                        .all(|c| c.is_ascii_digit() || matches!(c, '<' | '>' | '&'));
                if bare.starts_with('-') || redirection || STARTS_AFTER_A_VALUE.contains(&name) {
                    Self::FlagValue
                } else if is_assignment(bare)
                    || operator.starts_with(|c: char| c.is_ascii_digit() || matches!(c, '<' | '>'))
                    || STATEMENT_STARTS.contains(&name)
                {
                    Self::Start
                } else if ACTING_COMMANDS.contains(&name) {
                    Self::Acting
                } else {
                    Self::Arguments
                }
            }
            // A block (`coproc name {`): a command may follow. A word with
            // a `)` goes where `without_word_quotes` says instead.
            Self::Acting | Self::Arguments if written == "{" => Self::Start,
            Self::Acting | Self::Arguments | Self::Array => self,
        }
    }

    /// Whether one quoted string here is read without its quotes, as `bare`.
    fn reads_bare(self, bare: &str) -> bool {
        match self {
            Self::Start | Self::FlagValue | Self::Acting => true,
            Self::Arguments => bare.starts_with('-'),
            Self::Array => false,
        }
    }
}

/// Whether `word` sets a variable (`NAME=value`, `NAME+=value`).
fn is_assignment(word: &str) -> bool {
    let Some(end) = word.find(['[', '=', '+']) else {
        return false;
    };
    let (name, rest) = word.split_at(end);
    // `NAME[i]=value` sets one element. The index may hold `=`, brackets
    // and quoted or escaped `]` of its own (`a[x=y]=1`, `a[']']=1`), which
    // `word` no longer shows, so any `]=` counts: a word read as an
    // assignment that is none only reads what follows as a command.
    if rest.starts_with('[') {
        return (rest.contains("]=") || rest.contains("]+=")) && is_name(name);
    }
    let rest = rest.strip_prefix('+').unwrap_or(rest);
    rest.starts_with('=') && is_name(name)
}

/// One word of a line being read by `without_word_quotes`.
#[derive(Debug, Default)]
struct Word {
    /// The word as written.
    written: String,
    /// The word without its quotes.
    bare: String,
    /// The quote open at this point.
    open: Option<char>,
    /// Whether a blank is inside its quotes.
    quoted_blank: bool,
    /// Whether a quote in it joins two parts of a word: it touches a
    /// letter outside it, or another quote.
    joined: bool,
    /// What came last outside quotes.
    last: Last,
    /// Where the word's last `)` leads (`Nesting::close`), if it has one.
    closes_to: Option<Place>,
    /// Whether the single quote open is a `$'…'`, where a backslash keeps
    /// the next character.
    ansi: bool,
}

/// What came last in a word being read, outside its quotes.
#[derive(Debug, Default, PartialEq, Eq)]
enum Last {
    /// Nothing yet, or a character that is not a word's letter.
    #[default]
    Other,
    /// A word's letter.
    Letter,
    /// A closing quote.
    Close,
}

impl Word {
    fn push(&mut self, character: char) {
        if self.open.is_some() {
            self.quoted_blank |= character.is_whitespace();
        } else {
            let letter = is_word_letter(character);
            self.joined |= self.last == Last::Close && letter;
            self.last = if letter { Last::Letter } else { Last::Other };
        }
        self.written.push(character);
        self.bare.push(character);
    }

    fn open_quote(&mut self, quote: char) {
        // `$'…'` and `$"…"` are quotes too: the `$` is no letter of the
        // word (`r$''m` is `rm`).
        let dollar = self.last == Last::Letter && lone_dollar(&self.bare);
        if dollar {
            self.bare.pop();
        }
        self.ansi = dollar && quote == '\'';
        // A quote touching what a substitution or `${…}` ends with joins
        // the word too (`$(:)'rm'`, `${v}'rm'`): an empty one reads as
        // nothing there.
        let substituted = self.last == Last::Other && self.written.ends_with([')', '}', '`']);
        self.joined |= self.last != Last::Other || substituted;
        self.written.push(quote);
        self.open = Some(quote);
    }

    fn close_quote(&mut self, quote: char) {
        self.written.push(quote);
        self.open = None;
        self.last = Last::Close;
    }

    /// The word as written after its last `)`, which may name a keyword
    /// (`f()case`): the whole word where it has none.
    fn since_close(&self) -> &str {
        match self.closes_to {
            Some(_) => self.written.rsplit(')').next().unwrap_or_default(),
            None => &self.written,
        }
    }

    /// Ends the word, which stands at `place`, into `out`, starts the next,
    /// and says where that one stands.
    fn end(&mut self, out: &mut String, place: Place) -> Place {
        let word = std::mem::take(self);
        let one_string = word.written.chars().next().is_some_and(|quote| {
            matches!(quote, '"' | '\'')
                && word.written.len() >= 2
                && word.written[1..].find(quote) == Some(word.written.len() - 2)
        });
        // Only quotes are left out of `bare`.
        let quoted = word.written.len() != word.bare.len();
        let unquote = quoted
            && !word.quoted_blank
            && word.open.is_none()
            && (word.joined || (one_string && place.reads_bare(&word.bare)));
        out.push_str(if unquote { &word.bare } else { &word.written });
        place.after(&word.written, &word.bare)
    }
}

/// A letter of a word, as the quotes that split one touch it.
fn is_word_letter(character: char) -> bool {
    character.is_alphanumeric() || matches!(character, '_' | '-' | '/' | '.' | '$')
}

/// A program's name without its directory.
pub(super) fn program_name(word: &str) -> &str {
    crate::paths::file_name(word)
}

/// A program's name without the version written after it: `python3.12` is
/// `python`.
pub(super) fn unversioned(program: &str) -> &str {
    program.trim_end_matches(|character: char| character.is_ascii_digit() || character == '.')
}

/// Whether `word` is a cluster of short options holding `flag`: `-c`,
/// `-lc`, but not `--c`.
pub(super) fn short_flag(word: &str, flag: char) -> bool {
    word.len() > 1
        && word.starts_with('-')
        && !word.starts_with("--")
        && word[1..].chars().all(|c| c.is_ascii_alphabetic())
        && word[1..].contains(flag)
}

/// The most substitutions of one line looked at.
const MAX_SUBSTITUTIONS: usize = 64;

/// A `$(…)`, `<(…)` or backtick substitution.
pub(super) struct Substitution<'a> {
    /// `$(`, `<(` or a backtick.
    open: &'static str,
    /// Where it opens in the line.
    pub(super) start: usize,
    pub(super) body: &'a str,
}

/// The index just past the `)` that closes a parenthesis opened before
/// `text`, or the end of `text` when nothing closes it. Parentheses inside
/// quotes do not count, except those of a substitution (`"$(…)"`).
fn closing_paren(text: &str) -> usize {
    let bytes = text.as_bytes();
    let mut depth = 1_usize;
    let mut quote: Option<u8> = None;
    // The depth the open quote began at: a `)` that closes a substitution
    // opened inside a double quote still counts.
    let mut quoted_at = 0_usize;
    for (index, byte) in text.bytes().enumerate() {
        match byte {
            b'\'' | b'"' if quote == Some(byte) && (byte == b'\'' || depth == quoted_at) => {
                quote = None;
            }
            b'\'' | b'"' if quote.is_none() => {
                quote = Some(byte);
                quoted_at = depth;
            }
            b'(' if quote.is_none()
                || (quote == Some(b'"') && index > 0 && bytes[index - 1] == b'$') =>
            {
                depth += 1;
            }
            b')' if quote.is_none() || (quote == Some(b'"') && depth > quoted_at) => {
                depth -= 1;
                if depth == 0 {
                    return index + 1;
                }
            }
            _ => {}
        }
    }
    text.len()
}

/// What stands between a parenthesis opened before `text` and the one
/// that closes it.
pub(super) fn argument(text: &str) -> &str {
    let end = closing_paren(text);
    text[..end].strip_suffix(')').unwrap_or(&text[..end])
}

/// Every substitution in `text`, the nested ones after the one around them.
pub(super) fn substitutions(text: &str) -> Vec<Substitution<'_>> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut index = 0;
    while index < bytes.len() && found.len() < MAX_SUBSTITUTIONS {
        let open = match (bytes[index], bytes.get(index + 1)) {
            // `$((` is arithmetic.
            (b'$', Some(b'(')) if bytes.get(index + 2) != Some(&b'(') => "$(",
            (b'<', Some(b'(')) => "<(",
            (b'`', _) => "`",
            _ => {
                index += 1;
                continue;
            }
        };
        let inside = index + open.len();
        if open == "`" {
            let length = text[inside..].find('`').unwrap_or(text.len() - inside);
            found.push(Substitution {
                open,
                start: index,
                body: &text[inside..inside + length],
            });
            // What `$(…)` it holds is read as well. A backtick inside it
            // is written with a backslash and opens nothing here.
            for nested in substitutions(&text[inside..inside + length]) {
                if found.len() < MAX_SUBSTITUTIONS {
                    found.push(Substitution {
                        start: inside + nested.start,
                        ..nested
                    });
                }
            }
            // Past the closing backtick: it does not open another.
            index = inside + length + 1;
        } else {
            found.push(Substitution {
                open,
                start: index,
                body: argument(&text[inside..]),
            });
            // On into the body, for the substitutions nested in it.
            index = inside;
        }
    }
    found
}

/// How much of a line's substitutions may be read beyond twice the line's
/// own length.
const MAX_NESTED: usize = 64 * 1024;

/// How much of the substitutions of one line is still read. A substitution
/// inside another holds the same text again, so sixty-four of them, each
/// reaching to the end of a long line, are sixty-four times the line: they
/// are read up to twice the line's length and `MAX_NESTED` more. A line of
/// a kibibyte never holds more, and neither does one whose substitutions
/// are not inside one another.
pub(super) struct Reading {
    left: usize,
}

impl Reading {
    pub(super) const fn of(line: &str) -> Self {
        Self {
            left: line.len().saturating_mul(2).saturating_add(MAX_NESTED),
        }
    }

    /// Whether `body` is still read. A rule that asks whether a body holds
    /// something must answer for one that is not read as for a line too
    /// long to read: by taking it to hold what is looked for. Only the
    /// naming of files a line reads in (`run::reads_in_file`) leaves an
    /// unread body out, having nothing to name; the rules that read the
    /// same line report it.
    pub(super) fn takes(&mut self, body: &str) -> bool {
        match self.left.checked_sub(body.len()) {
            Some(left) => {
                self.left = left;
                true
            }
            None => false,
        }
    }
}

/// Splits `text` at each of `separators` that stands outside quotes and
/// substitutions. A two-character separator is tried before a single one.
pub(super) fn split_top<'a>(text: &'a str, separators: &[&str]) -> Vec<&'a str> {
    let bytes = text.as_bytes();
    let mut parts = Vec::new();
    let mut quote: Option<u8> = None;
    let mut depth = 0_usize;
    let mut backtick = false;
    let mut start = 0;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        match quote {
            Some(b'\'') => {
                if byte == b'\'' {
                    quote = None;
                }
                index += 1;
                continue;
            }
            Some(_) if byte == b'"' => quote = None,
            None if byte == b'"' || byte == b'\'' => quote = Some(byte),
            _ => {}
        }
        match byte {
            b'`' => backtick = !backtick,
            b'(' if quote.is_none()
                || depth > 0
                || matches!(
                    index.checked_sub(1).map(|at| bytes[at]),
                    Some(b'$' | b'<' | b'>')
                ) =>
            {
                depth += 1;
            }
            b')' if depth > 0 => depth -= 1,
            _ => {}
        }
        // Separators are ASCII, so a continuation byte cannot begin one;
        // slicing there would also split a character.
        if quote.is_none() && depth == 0 && !backtick && text.is_char_boundary(index) {
            let rest = &text[index..];
            if let Some(separator) = separators
                .iter()
                .find(|separator| rest.starts_with(**separator))
            {
                parts.push(&text[start..index]);
                index += separator.len();
                start = index;
                continue;
            }
        }
        index += 1;
    }
    parts.push(&text[start..]);
    parts
}

/// The statements of a line: what `;`, `&&`, `||` and a line break divide.
pub(super) fn statements(line: &str) -> Vec<&str> {
    split_top(line, &["&&", "||", ";", "\n"])
}

/// The parts of one statement that a pipe joins.
pub(super) fn pipeline(statement: &str) -> Vec<&str> {
    // `||` first, so it is not read as two pipes.
    split_top(statement, &["||", "|"])
}

/// A program and what it is given, without quotes.
pub(super) struct Command {
    /// The program as written, with its directory.
    pub(super) path: String,
    /// The program's name without its directory.
    pub(super) program: String,
    pub(super) arguments: Vec<String>,
}

impl Command {
    /// Whether one of the command's own options is `flag` (`-c`), or a
    /// cluster of short options holding its letter (`-lc`).
    pub(super) fn has_short(&self, flag: char) -> bool {
        self.arguments
            .iter()
            .take_while(|word| word.starts_with('-'))
            .any(|word| short_flag(word, flag))
    }

    /// The arguments that are not options.
    pub(super) fn operands(&self) -> impl Iterator<Item = &str> {
        self.arguments
            .iter()
            .map(String::as_str)
            .filter(|word| !word.starts_with('-'))
    }

    pub(super) fn is_shell(&self) -> bool {
        PIPE_SHELLS.contains(&self.program.as_str())
    }
}

/// Words that run the command after them, or only open a block.
const WRAPPERS: &[&str] = &[
    "sudo", "doas", "run0", "env", "command", "exec", "nice", "nohup", "setsid", "stdbuf",
    "ionice", "chrt", "time", "then", "do", "else", "if", "while", "until", "!", "{", "(",
];

/// The program among `words`, which are left at what it is given: past
/// wrappers (`sudo -u x`, `env X=1`, `timeout 5`), assignments and what
/// opens a group or a block. Every rule that asks what a command runs
/// reads it here, so they agree on what a wrapper is.
pub(super) fn program_word<'a>(
    words: &mut (impl Iterator<Item = &'a str> + Clone),
) -> Option<&'a str> {
    program_past(words, &mut Passed::Unnoted)
}

/// What `program_past` does at a substitution an assignment opens, with a
/// program after it.
enum Passed<'a> {
    /// Looks past it to that program, and does not keep what it held.
    Unnoted,
    /// Looks past it, and keeps the words of each one it passed.
    Noted(Vec<Vec<&'a str>>),
    /// Reads what it holds, not what follows: for those words themselves.
    Never,
}

/// `program_word`, which may keep the words of a substitution it looked
/// past: the command there runs too.
fn program_past<'a>(
    words: &mut (impl Iterator<Item = &'a str> + Clone),
    passed: &mut Passed<'a>,
) -> Option<&'a str> {
    let mut elevated = false;
    // The command of a substitution an assignment was given (`x=$(date)`):
    // the program, unless one follows the assignment.
    let mut held: Option<&'a str> = None;
    // What stands after the opening of a substitution that is read on
    // (`x=$(sudo sh f)`): read next, as the word it is.
    let mut inner: Option<&'a str> = None;
    loop {
        let read_on = inner.is_some();
        let Some(word) = inner.take().or_else(|| words.next()) else {
            return held;
        };
        let bare = word.trim_start_matches(['(', '{', '`']);
        let bare = bare.strip_prefix("$(").unwrap_or(bare);
        // `sudo -u build cmd`: the user is not the program.
        if elevated && matches!(bare, "-u" | "-g" | "--user" | "--group") {
            if words.next().is_none() {
                return held;
            }
            continue;
        }
        elevated = elevated || matches!(bare, "sudo" | "doas" | "run0");
        if bare.is_empty() || WRAPPERS.contains(&bare) || bare.starts_with('-') {
            continue;
        }
        if bare == "timeout" {
            // `timeout 5s cmd`, `timeout --signal=9 10 cmd`.
            loop {
                match words.next() {
                    Some(next) if next.starts_with('-') => {}
                    Some(_) => break,
                    None => return held,
                }
            }
            continue;
        }
        // `VAR=x cmd`: an assignment before the program.
        if bare.contains('=') && !bare.starts_with(['/', '.', '$', '=']) {
            // An assignment inside a substitution that is read on is read
            // past as a value, not opened again.
            match (!read_on).then(|| substituted(bare)).flatten() {
                // `x=$(date) sh f`: the program follows; the command in
                // the substitution is it only when none does.
                Some(Substituted::Whole(command)) => {
                    held = held.or(command);
                    if let (Passed::Noted(noted), Some(command)) = (&mut *passed, command) {
                        noted.push(vec![command]);
                    }
                }
                Some(Substituted::Open(rest, backtick)) => {
                    let after = (!matches!(passed, Passed::Never))
                        .then(|| past_substitution(words, rest, backtick))
                        .flatten();
                    if let Some((within, after)) = after {
                        // `x=$(mktemp -d) sh f`: as above, with the
                        // substitution over several words.
                        held = held.or_else(|| command_of(rest));
                        if let Passed::Noted(noted) = passed {
                            let mut held: Vec<&str> = std::iter::once(rest)
                                .chain(words.clone().take(within))
                                .collect();
                            close(&mut held, backtick);
                            noted.push(held);
                        }
                        *words = after;
                    } else if rest.trim_start().starts_with('<') {
                        // `x=$(< f)` reads a file: with nothing after it,
                        // nothing is run.
                        return held;
                    } else {
                        // `x=$(sha256sum f`: the value is the command, and
                        // what follows is given to it.
                        inner = command_of(rest);
                    }
                }
                None => {}
            }
            continue;
        }
        return Some(bare);
    }
}

/// The most words a substitution is looked through for where it closes.
const MAX_SUBSTITUTED_WORDS: usize = 64;

/// How many words the substitution opened before `words` takes up to the
/// one that closes it, and `words` past that one, where a command follows;
/// `rest` is what stood after the opening. `None` where it does not close
/// within `MAX_SUBSTITUTED_WORDS`, or nothing but a redirection, a closing
/// or a comment follows: then what it holds is all there is to read.
fn past_substitution<'a, I>(words: &I, rest: &str, backtick: bool) -> Option<(usize, I)>
where
    I: Iterator<Item = &'a str> + Clone,
{
    let mut ahead = words.clone();
    let mut depth = 1 + depth_change(rest);
    for within in 1..=MAX_SUBSTITUTED_WORDS {
        let word = ahead.next()?;
        let closes = if backtick {
            word.contains('`')
        } else {
            depth += depth_change(word);
            depth <= 0
        };
        if closes {
            let next = ahead.clone().next()?;
            let no_command = next == "\\"
                || next.starts_with(['>', '<', '#', ')', '}', ';', '|', '&'])
                || next
                    .trim_start_matches(|character: char| character.is_ascii_digit())
                    .starts_with(['>', '<']);
            return (!no_command).then_some((within, ahead));
        }
    }
    None
}

/// Cuts the last of `held`, the words of a substitution from after its
/// opening, at what closes it: `f)` is `f`.
fn close(held: &mut Vec<&str>, backtick: bool) {
    let Some(last) = held.pop() else {
        return;
    };
    let end = if backtick {
        last.find('`')
    } else {
        let mut depth = 1 + held.iter().map(|word| depth_change(word)).sum::<isize>();
        last.bytes().position(|byte| {
            depth += match byte {
                b'(' => 1,
                b')' => -1,
                _ => 0,
            };
            depth <= 0
        })
    };
    let last = &last[..end.unwrap_or(last.len())];
    if !last.is_empty() {
        held.push(last);
    }
}

/// How many more `(` than `)` a word holds.
fn depth_change(word: &str) -> isize {
    word.bytes().fold(0, |depth, byte| match byte {
        b'(' => depth + 1,
        b')' => depth - 1,
        _ => depth,
    })
}

/// The command a substitution begins with: its first word, up to what
/// ends a word (`x=$(./f;)`, `x=$(./f|cat)`). `$(<file)` reads a file and
/// runs nothing.
fn command_of(inner: &str) -> Option<&str> {
    let inner = inner.trim_start();
    if inner.starts_with('<') {
        return None;
    }
    inner
        .split(|character: char| character.is_whitespace() || ";|&<>)`".contains(character))
        .next()
        .filter(|command| !command.is_empty())
}

/// The command an assignment's value runs.
enum Substituted<'a> {
    /// The substitution closes within the word (`x=$(date)`,
    /// `PATH=$(pwd)/bin`): its command, if it names one.
    Whole(Option<&'a str>),
    /// It goes on in the words after (`x=$(cmd`): what stands after its
    /// opening, and whether a backtick opened it.
    Open(&'a str, bool),
}

/// Reads the substitution an assignment's value begins with (`x=$(cmd`, or
/// with a backtick). `$((` is arithmetic, which runs nothing.
fn substituted(assignment: &str) -> Option<Substituted<'_>> {
    let (_, value) = assignment.split_once('=')?;
    let (inner, backtick) = match value.strip_prefix("$(") {
        Some(inner) => (inner, false),
        None => (value.strip_prefix('`')?, true),
    };
    if !backtick && inner.starts_with('(') {
        return None;
    }
    let end = if backtick {
        inner.find('`')
    } else {
        let mut depth = 1_usize;
        inner.char_indices().find_map(|(at, character)| {
            match character {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {}
            }
            (depth == 0).then_some(at)
        })
    };
    Some(match end {
        Some(end) => Substituted::Whole(command_of(&inner[..end])),
        None => Substituted::Open(inner, backtick),
    })
}

/// The command a statement, or one part of a pipeline, runs: past wrappers
/// (`sudo`, `env X=1`, `timeout 5`) and what opens a group.
pub(super) fn command(part: &str) -> Option<Command> {
    let words = unquoted_words(part);
    let mut words = words.iter().map(String::as_str);
    let path = program_word(&mut words)?.to_string();
    let arguments = words
        .map(|word| word.trim_end_matches(';').to_string())
        .filter(|word| !word.is_empty())
        .collect();
    Some(Command {
        program: program_name(&path).to_string(),
        path,
        arguments,
    })
}

/// `program_word`, with the program and what it is given inside each
/// substitution that was looked past for the program after it
/// (`x=$(sudo sh f) :`): those run as well.
pub(super) fn programs<'a>(
    words: &mut (impl Iterator<Item = &'a str> + Clone),
) -> (Option<&'a str>, Vec<Within<'a>>) {
    let mut passed = Passed::Noted(Vec::new());
    let program = program_past(words, &mut passed);
    let Passed::Noted(noted) = passed else {
        return (program, Vec::new());
    };
    let within = noted
        .into_iter()
        .filter_map(|words| {
            let mut words = words.into_iter();
            let program = program_past(&mut words, &mut Passed::Never)?;
            Some((program, words))
        })
        .collect();
    (program, within)
}

/// A program inside a substitution, and the words after it there.
pub(super) type Within<'a> = (&'a str, std::vec::IntoIter<&'a str>);

/// The commands inside the substitutions that `command` looked past.
pub(super) fn inner_commands(part: &str) -> Vec<Command> {
    let words = unquoted_words(part);
    let (_, within) = programs(&mut words.iter().map(String::as_str));
    within
        .into_iter()
        .map(|(path, rest)| Command {
            program: program_name(path).to_string(),
            path: path.to_string(),
            arguments: rest
                .map(|word| word.trim_end_matches(';').to_string())
                .filter(|word| !word.is_empty())
                .collect(),
        })
        .collect()
}

/// The last statement of a pipeline part cut at pipes alone, which is the
/// one whose output the pipe carries on: `a; b` gives `b`.
pub(super) fn piped_statement(part: &str) -> &str {
    let last = part.rsplit(';').next().unwrap_or(part);
    last.rsplit("&&").next().unwrap_or(last)
}

/// Whether the command whose output a pipe carries on from `part` is one
/// `accepts`. A part cut at a pipe may open a quote it does not close
/// (`sh -c "a; b | c"`), so it is read both with its quotes and without.
pub(super) fn pipes_from(part: &str, accepts: &dyn Fn(&Command) -> bool) -> bool {
    let quoted = statements(part).last().copied().unwrap_or(part);
    [quoted, piped_statement(part)]
        .iter()
        .any(|statement| command(statement).is_some_and(|command| accepts(&command)))
}

/// The file one command writes its output to: by a redirection, as `tee`,
/// or through `-out`.
pub(super) fn written_file(part: &str) -> Option<String> {
    let words = unquoted_words(part);
    let tee = words
        .first()
        .is_some_and(|word| program_name(word) == "tee");
    let mut rest = words.iter().skip(usize::from(tee));
    while let Some(word) = rest.next() {
        let name = match word.as_str() {
            ">" | ">>" | "-out" => rest.next().map(String::as_str),
            _ if tee && !word.starts_with('-') => Some(word.as_str()),
            _ => [">>", ">"]
                .iter()
                .find_map(|redirect| word.strip_prefix(redirect)),
        };
        if let Some(name) = name
            && !name.is_empty()
            && !name.starts_with('&')
            && !name.starts_with("/dev/")
        {
            return super::as_file(name);
        }
    }
    None
}

/// Whether the output of the substitution `found` in `line` is run: `eval
/// "$(…)"`, `sh -c "$(…)"`, `bash <<< "$(…)"`, `source <(…)`, `bash <(…)`.
/// A substitution that is only an argument or a value is not.
pub(super) fn is_run(line: &str, found: &Substitution<'_>) -> bool {
    let before = &line[..found.start];
    let statement = before
        .rsplit([';', '|', '\n'])
        .next()
        .unwrap_or(before)
        .rsplit("&&")
        .next()
        .unwrap_or(before);
    let Some(command) = command(statement) else {
        return false;
    };
    if found.open == "<(" {
        return command.is_shell() || matches!(command.program.as_str(), "source" | ".");
    }
    command.program == "eval"
        || (command.is_shell()
            && (command.has_short('c')
                || before.trim_end_matches(['"', '\'', ' ']).ends_with("<<<")))
}

/// Whether `line` runs the output of a substitution whose body `source`
/// accepts.
pub(super) fn runs_substitution(line: &str, source: &dyn Fn(&str) -> bool) -> bool {
    if !(line.contains("$(") || line.contains("<(") || line.contains('`')) {
        return false;
    }
    // Whether it is run is asked first: that reads the command before it,
    // and its body is read only then.
    let mut reading = Reading::of(line);
    substitutions(line)
        .iter()
        .any(|found| is_run(line, found) && (!reading.takes(found.body) || source(found.body)))
}

/// The names `word` is a reference to, quoted or not: `x` for `$x` and for
/// `${x}`. What follows the `$` is one, and so is what stands in braces
/// after it.
pub(super) fn referenced(word: &str) -> [Option<&str>; 2] {
    let rest = word.trim().trim_matches(['"', '\'']).strip_prefix('$');
    let braced = rest
        .and_then(|rest| rest.strip_prefix('{'))
        .and_then(|rest| rest.strip_suffix('}'));
    [rest, braced]
}

/// A variable name as a shell accepts it.
pub(super) fn is_name(word: &str) -> bool {
    word.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && word.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The assignments a statement makes, as (name, value as written):
/// `x=1`, `export x=$(…)`, `local a=1 b=2`.
pub(super) fn assignments(statement: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let words = shell_words(statement);
    let mut declaring = false;
    for (index, word) in words.iter().enumerate() {
        if matches!(
            word.as_str(),
            "export" | "local" | "declare" | "typeset" | "readonly"
        ) && index == 0
        {
            declaring = true;
            continue;
        }
        if declaring && word.starts_with('-') {
            continue;
        }
        let Some((name, value)) = word.split_once('=') else {
            break;
        };
        let name = name.strip_suffix('+').unwrap_or(name);
        if !is_name(name) {
            break;
        }
        // An unquoted substitution holds spaces: its words are the rest.
        let value = if value.starts_with("$(") || value.starts_with('`') {
            let at = statement.find(word.as_str()).unwrap_or(0) + name.len() + 1;
            statement.get(at..).unwrap_or(value).trim().to_string()
        } else {
            value.to_string()
        };
        let whole = value.starts_with("$(") || value.starts_with('`');
        found.push((name.to_string(), value));
        if whole || !declaring {
            // `x=1 cmd` runs cmd; only a declaration lists several.
            break;
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::{
        argument, assignments, command, pipeline, referenced, runs_substitution, statements,
        substitutions,
    };

    #[test]
    fn substitutions_are_found_with_the_ones_nested_in_them() {
        let found = substitutions("eval \"$(echo \"$(cat x)\" | tr a b)\" `id` $((1 + 2))");
        let bodies: Vec<&str> = found.iter().map(|found| found.body).collect();
        assert_eq!(bodies, ["echo \"$(cat x)\" | tr a b", "cat x", "id"]);
        assert_eq!(argument("a(b)c) d"), "a(b)c");
        assert_eq!(argument("never closed"), "never closed");
    }

    #[test]
    fn a_line_is_divided_outside_quotes_and_substitutions() {
        assert_eq!(
            statements("a \"b; c\" && d $(e; f) || g; h"),
            ["a \"b; c\" ", " d $(e; f) ", " g", " h"]
        );
        assert_eq!(
            pipeline("a 'x | y' | b \"$(c | d)\" || e"),
            ["a 'x | y' ", " b \"$(c | d)\" ", " e"]
        );
    }

    #[test]
    fn the_program_is_read_past_wrappers() {
        for (part, program, arguments) in [
            (
                "sudo -E env X=1 bash -lc 'x y'",
                "bash",
                &["-lc", "x y"][..],
            ),
            ("timeout --signal=9 10 /usr/bin/sh -s", "sh", &["-s"]),
            ("( X=1 eval \"$x\";", "eval", &["$x"]),
            ("if ! rev", "rev", &[]),
        ] {
            let found = command(part).unwrap_or_else(|| panic!("{part}"));
            assert_eq!(found.program, program, "{part}");
            assert_eq!(found.arguments, arguments, "{part}");
        }
        assert!(command("X=1").is_none());
        assert!(command("sudo").is_none());
    }

    #[test]
    fn words_names_and_option_clusters_are_read_one_way() {
        use super::{program_name, program_word, short_flag, unquoted_words, unversioned};
        assert_eq!(
            unquoted_words("a \"b c\" 'd'e  \"f"),
            ["a", "b c", "de", "f"]
        );
        assert_eq!(program_name("/usr/bin/python3.12"), "python3.12");
        for (program, plain) in [
            ("python3.12", "python"),
            ("pip3", "pip"),
            ("sh", "sh"),
            ("7", ""),
        ] {
            assert_eq!(unversioned(program), plain, "{program}");
        }
        for (word, held) in [
            ("-k", true),
            ("-fsSLk", true),
            ("-s", false),
            ("--k", false),
            ("--insecure-k", false),
            ("-k=1", false),
            ("-", false),
            ("k", false),
        ] {
            assert_eq!(short_flag(word, 'k'), held, "{word}");
        }
        // The words after the program are left for the caller.
        let mut words = "sudo -u build timeout 5 X=1 (sh -c x".split(' ');
        assert_eq!(program_word(&mut words), Some("sh"));
        assert_eq!(words.collect::<Vec<_>>(), ["-c", "x"]);
        assert_eq!(program_word(&mut "nohup env".split(' ')), None);
    }

    #[test]
    fn only_a_substitution_that_is_run_counts() {
        let any = |_: &str| true;
        for line in [
            "eval \"$(x)\"",
            "sudo bash -c \"$(x)\"",
            "sh -ec \"$(x)\"",
            "bash <<< \"$(x)\"",
            "source <(x)",
            ". <(x)",
            "a; bash <(x)",
            "eval `x`",
        ] {
            assert!(runs_substitution(line, &any), "{line}");
        }
        for line in [
            "v=$(x)",
            "echo \"$(x)\"",
            "diff <(x) y",
            "bash script.sh \"$(x)\"",
            "cat <<< \"$(x)\"",
            "eval \"$y\"",
        ] {
            assert!(!runs_substitution(line, &any), "{line}");
        }
    }

    #[test]
    fn assignments_and_references_are_read() {
        let pairs = |statement: &str| assignments(statement);
        assert_eq!(pairs("x=1"), [("x".to_string(), "1".to_string())]);
        assert_eq!(
            pairs("export x=\"$(curl -s https://x.example/a)\""),
            [(
                "x".to_string(),
                "\"$(curl -s https://x.example/a)\"".to_string()
            )]
        );
        assert_eq!(
            pairs("x=$(mktemp -d)"),
            [("x".to_string(), "$(mktemp -d)".to_string())]
        );
        assert_eq!(
            pairs("local -r a=1 b=2"),
            [
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "2".to_string())
            ]
        );
        assert!(pairs("make CC=gcc").is_empty());
        assert!(pairs("[ $a = 1 ]").is_empty());
        let is_reference = |word: &str, name: &str| referenced(word).contains(&Some(name));
        assert!(is_reference("\"${x}\"", "x"));
        assert!(is_reference("$x", "x"));
        assert!(!is_reference("$xy", "x"));
        assert!(!is_reference("\"$x/y\"", "x"));
        assert_eq!(referenced("x"), [None, None]);
    }

    #[test]
    fn substitutions_inside_one_another_are_read_up_to_a_measure() {
        use super::{MAX_NESTED, Reading};
        let none = |_: &str| false;
        let any = |_: &str| true;
        // A few inside one another are each read.
        assert!(!runs_substitution("eval $(a $(b $(c $(d))))", &none));
        assert!(runs_substitution("eval $(a $(b $(c $(d))))", &|body| body == "d"));
        // Sixty-four that each reach the end of a long line are more than is
        // read: a line that runs them is taken to run what is looked for.
        let nested = "$(x ".repeat(50_000);
        assert!(runs_substitution(&format!("eval {nested}"), &none));
        // One that is not run is not read at all.
        assert!(!runs_substitution(&nested, &any));
        assert!(!runs_substitution(&format!("echo {nested}"), &any));
        // As many side by side are no more than the line.
        let beside = "$(x) ".repeat(50_000);
        assert!(!runs_substitution(&format!("eval {beside}"), &none));
        let mut reading = Reading::of("abcd");
        assert!(reading.takes(&"x".repeat(8 + MAX_NESTED)));
        assert!(!reading.takes("x"));
        assert!(reading.takes(""));
    }
}
