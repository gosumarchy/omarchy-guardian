//! Recursive `rm` of `/`, `/*`, `~` or `$HOME` itself, read word by word
//! as bash splits a line into commands.
//!
//! One pass over the line keeps a stack of contexts: the line, and each
//! `$(…)`, `<(…)`, `${ …; }`, `${…}` and glued `(…)` opened inside it. A
//! backtick substitution is read as bash reads it, up to the next backtick
//! no backslash escapes whatever quotes stand before it, and what is
//! between is read as a line of its own. Each context that runs commands
//! has its own quote and its own command being read, so a separator inside
//! quotes, inside `${…}`, or inside a substitution ends nothing outside it,
//! and the substitution's words are a command of their own. A `case` or `{` group open in a context keeps its
//! `)` or `}` from ending that context.
//!
//! What a substitution prints, and a variable in the command word, are
//! taken to be nothing, so `$(:)rm` and `rm$u` are `rm`, as bash runs them
//! when they are empty. A variable in a target is not: `"$HOME/$pkg"` is
//! the ordinary removal of a path below home, which a package installs.
//!
//! Any `rm` word counts, not only the first of a command (`x rm -r ~`),
//! and the flags and target are those after it in the same command. That
//! leans toward finding too much, and keeps the reading linear: a line of
//! many `rm` words shares one pass over its arguments, and each letter is
//! added to its word in constant time however deep the `${…}` it stands in.
//! A backtick nested in another is escaped once more for each level, so the
//! text read again for it shrinks.
//!
//! This is one of two readers of shell lines. Every line rule, this one
//! included, reads a line as written and as `shell::as_shell_reads`
//! rebuilds it; this reader is used by the recursive `rm` rule alone. A
//! bypass fixed in one reader must be checked in the other.
//!
//! Left to the AI review: `$'…'` escapes that spell letters (`$'\x72m'`),
//! `$!` and other special parameters glued to the command (`$!rm`), a
//! word bash builds from brace expansion or a glob other than a trailing
//! `*` (`/{,}`, `{/,x}`, `/?*`, `/[a-z]*`), a command word a default value
//! holds (`${x:-rm} -rf ~`), and a substitution inside a default value
//! (`${x:-<(rm -rf /)}`).

// TODO(gosumarchy): merge with the reader in `shell.rs` into one that
// yields words with their place and quoting, after the advisory is
// published.

/// Recursive `rm` of `/`, `/*`, `~` or `$HOME` itself, in a line lowercased
/// as `rules::line_rules` reads it. Removing paths below them
/// (`rm -rf /tmp/build`, `rm -rf "$pkgdir"`) is ordinary build hygiene.
pub(super) fn removes_root_or_home(line: &str) -> bool {
    let mut reader = Reader {
        contexts: vec![Context::new(Closer::Line)],
        found: false,
    };
    let mut characters = line.chars().peekable();
    while let Some(character) = characters.next() {
        reader.read(character, &mut characters);
        if reader.found {
            return true;
        }
    }
    // What is left open ends with the line: the next line may close it
    // (`rm -rf /$(echo` and then `)`).
    while reader.contexts.len() > 1 {
        reader.close();
    }
    reader.end_word();
    reader.found
}

type Characters<'a> = std::iter::Peekable<std::str::Chars<'a>>;

/// Stands in a word for a `*` or `~` that bash reads as itself: quoted or
/// escaped (`"/*"` names a file called `*`), or a `~` that is not at the
/// start of a word or is followed by a quote or substitution (`''~`,
/// `~$(:)`), which bash does not expand.
const LITERAL: char = '\0';

/// What ends a context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Closer {
    /// The line itself, which runs commands.
    Line,
    /// `)`, of `$(…)` or `<(…)`, which run commands.
    Paren,
    /// The `}` that starts a command in `${ …; }` or `${| …; }`, which run
    /// commands.
    Brace,
    /// `end`, of `${…}` or of an array's or extglob's `(…)` (`a=(…)`,
    /// `@(…)`), whose letters are the word of the context at `owner`. A
    /// `(…)` counts the parentheses open inside it in `depth`.
    Word { owner: usize, end: char },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Quote {
    Single,
    Double,
    /// `$'…'`, where a backslash keeps the character after it.
    AnsiC,
}

/// What one command read so far holds.
#[derive(Debug, Default)]
struct Command {
    /// An `rm` word was read.
    removes: bool,
    /// A recursive flag was read after it.
    recursive: bool,
    /// `/`, `~` or `$HOME` was read after it.
    target: bool,
    /// How many words the command has, past the reserved words a command
    /// may follow (`then`), to tell a reserved word.
    words: usize,
}

#[derive(Debug)]
struct Context {
    closer: Closer,
    quote: Option<Quote>,
    /// The parentheses open inside a `Paren` or `(…)` `Word` context, so
    /// `$((1))`, `$( (x) )` and `@(a@(b))` close at their own `)`.
    depth: usize,
    /// The `case`s and `{` groups open here, whose `)` and `}` end no
    /// `$(…)` or `${ …; }`.
    compounds: usize,
    command: Command,
    /// The word being read, without its quotes and escapes.
    word: String,
    /// A quote, an escape or a substitution was read in the word, so a `#`
    /// after it is a letter even when the word is still empty (`""#`), and
    /// the word is no reserved word (`\case`).
    started: bool,
    /// The word being read is what a redirection writes to or reads from.
    redirected: bool,
}

impl Context {
    fn new(closer: Closer) -> Self {
        Self {
            closer,
            quote: None,
            depth: 0,
            compounds: 0,
            command: Command::default(),
            word: String::new(),
            started: false,
            redirected: false,
        }
    }
}

#[derive(Debug)]
struct Reader {
    /// The line at index 0, which is never popped, and the contexts opened
    /// inside it, the innermost last.
    contexts: Vec<Context>,
    found: bool,
}

impl Reader {
    fn top(&mut self) -> &mut Context {
        let at = self.contexts.len() - 1;
        &mut self.contexts[at]
    }

    /// Ends the context on top unless it is the line, so `contexts` is
    /// never empty.
    fn pop(&mut self) {
        if self.contexts.len() > 1 {
            self.contexts.pop();
        }
    }

    /// Where the context is whose word a letter is part of: a `Word`
    /// context adds its letters to the word of its owner.
    fn owner_at(&self) -> usize {
        match self.contexts.last().map(|context| context.closer) {
            Some(Closer::Word { owner, .. }) => owner,
            _ => self.contexts.len() - 1,
        }
    }

    fn owner(&mut self) -> &mut Context {
        let at = self.owner_at();
        &mut self.contexts[at]
    }

    fn push_letter(&mut self, letter: char) {
        self.owner().word.push(letter);
    }

    /// A letter bash reads as itself, not as a glob or a tilde.
    fn push_quoted(&mut self, letter: char) {
        self.push_letter(if matches!(letter, '*' | '~') {
            LITERAL
        } else {
            letter
        });
    }

    /// A quote, an escape or a substitution starts in the word.
    fn start(&mut self) {
        let owner = self.owner();
        owner.started = true;
        if owner.word == "~" {
            // A tilde followed by a quote or substitution before any `/`
            // is not expanded.
            owner.word = LITERAL.to_string();
        }
    }

    fn open_quote(&mut self, quote: Quote) {
        self.start();
        self.top().quote = Some(quote);
    }

    fn read(&mut self, character: char, rest: &mut Characters<'_>) {
        match self.top().quote {
            Some(Quote::Single | Quote::AnsiC) if character == '\'' => self.top().quote = None,
            Some(Quote::AnsiC) if character == '\\' => {
                if let Some(next) = rest.next() {
                    self.push_quoted(next);
                }
            }
            Some(Quote::Single | Quote::AnsiC) => self.push_quoted(character),
            Some(Quote::Double) => self.read_in_double(character, rest),
            None => self.read_unquoted(character, rest),
        }
    }

    fn read_in_double(&mut self, character: char, rest: &mut Characters<'_>) {
        match character {
            '"' => self.top().quote = None,
            '\\' => {
                if let Some(next) = rest.next() {
                    self.push_quoted(next);
                }
            }
            '$' => self.dollar(rest),
            '`' => self.backtick(rest),
            _ => self.push_quoted(character),
        }
    }

    fn read_unquoted(&mut self, character: char, rest: &mut Characters<'_>) {
        match character {
            '\'' => self.open_quote(Quote::Single),
            '"' => self.open_quote(Quote::Double),
            '$' if rest.next_if_eq(&'\'').is_some() => self.open_quote(Quote::AnsiC),
            // `$"…"` is translated text, a double quote when no
            // translation is installed.
            '$' if rest.next_if_eq(&'"').is_some() => self.open_quote(Quote::Double),
            // A backslash and a line break join two lines.
            '\\' => match rest.next() {
                Some('\n') | None => {}
                Some(next) => {
                    self.start();
                    self.push_quoted(next);
                }
            },
            '$' => self.dollar(rest),
            '`' => self.backtick(rest),
            _ => match self.top().closer {
                Closer::Word { end, .. } => self.read_in_word(character, end, rest),
                _ => self.read_in_command(character, rest),
            },
        }
    }

    /// An unquoted character in a `Word` context that `end` closes.
    fn read_in_word(&mut self, character: char, end: char, rest: &mut Characters<'_>) {
        let top = self.top();
        let closes = match character {
            // `<(…)` and `>(…)` in an array run commands (`a=(<(…))`).
            // The word is not empty here, so nothing is started.
            '<' | '>' if end == ')' && rest.next_if_eq(&'(').is_some() => {
                self.contexts.push(Context::new(Closer::Paren));
                return;
            }
            '(' if end == ')' => {
                top.depth += 1;
                false
            }
            ')' if end == ')' && top.depth > 0 => {
                top.depth -= 1;
                false
            }
            _ => character == end,
        };
        self.push_letter(character);
        if closes {
            self.pop();
        }
    }

    /// An unquoted character in a context that runs commands.
    fn read_in_command(&mut self, character: char, rest: &mut Characters<'_>) {
        let top = self.top();
        let word_start = top.word.is_empty() && !top.started;
        match character {
            ' ' | '\t' => self.end_word(),
            '&' if rest.peek() == Some(&'>') => self.redirect(rest),
            '\n' | ';' | '|' | '&' => self.end_command(),
            '>' | '<' => self.redirect_after(character, rest),
            // An array (`a=(…)`) or an extglob (`@(…)`) is one word with
            // its parentheses. makepkg turns extglob on, so `!(` is one too,
            // but where a command starts, where it is `!` and a subshell.
            '(' if top.word.ends_with(['=', '@', '?', '*', '+', '!'])
                && !(top.word == "!" && top.command.words == 0) =>
            {
                let owner = self.owner_at();
                self.push_letter(character);
                self.contexts
                    .push(Context::new(Closer::Word { owner, end: ')' }));
            }
            '(' => {
                if top.closer == Closer::Paren {
                    top.depth += 1;
                }
                self.end_command();
            }
            ')' => self.close_paren(),
            // A comment, up to the line break that ends it.
            '#' if word_start => while rest.next_if(|next| *next != '\n').is_some() {},
            '}' if top.closer == Closer::Brace
                && word_start
                && top.command.words == 0
                && top.compounds == 0 =>
            {
                self.close();
            }
            '~' if !word_start => self.push_letter(LITERAL),
            _ => self.push_letter(character),
        }
    }

    /// `)`, which ends a `$(…)` unless a parenthesis or a `case` is open
    /// inside it.
    fn close_paren(&mut self) {
        let top = self.top();
        if top.word == "esac" && !top.started && top.command.words == 0 {
            // `esac)` ends the `case` before the `)` is read.
            self.end_word();
        }
        let top = self.top();
        if top.closer == Closer::Paren && top.depth == 0 && top.compounds == 0 {
            self.close();
        } else {
            top.depth = top.depth.saturating_sub(1);
            // The word before it is a `case` pattern (`case)`), which is
            // no reserved word.
            top.started = true;
            self.end_command();
        }
    }

    /// An unquoted or double-quoted `$`: a substitution, a parameter, or a
    /// letter.
    fn dollar(&mut self, rest: &mut Characters<'_>) {
        match rest.peek() {
            Some('(') => {
                rest.next();
                self.start();
                self.contexts.push(Context::new(Closer::Paren));
            }
            Some('{') => {
                rest.next();
                self.start();
                if rest
                    .next_if(|next| matches!(next, ' ' | '\t' | '\n' | '|'))
                    .is_some()
                {
                    self.contexts.push(Context::new(Closer::Brace));
                } else {
                    let owner = self.owner_at();
                    self.contexts[owner].word.push_str("${");
                    self.contexts
                        .push(Context::new(Closer::Word { owner, end: '}' }));
                }
            }
            // A positional parameter is one digit (`$1rm` is `$1` and
            // `rm`), and `$@` and `$*` are empty without arguments.
            Some(&name) if name.is_ascii_digit() || matches!(name, '@' | '*') => {
                rest.next();
                self.push_parameter(&name.to_string());
            }
            // A bare name ends at the first letter no name holds, a quote
            // or backslash included (`$v\rm` is `$v` and `rm`), so it is
            // written in braces.
            Some(next) if next.is_ascii_alphabetic() || *next == '_' => {
                let mut name = String::new();
                while let Some(letter) =
                    rest.next_if(|next| next.is_ascii_alphanumeric() || *next == '_')
                {
                    name.push(letter);
                }
                self.push_parameter(&name);
            }
            _ => self.push_letter('$'),
        }
    }

    fn push_parameter(&mut self, name: &str) {
        let word = &mut self.owner().word;
        word.push_str("${");
        word.push_str(name);
        word.push('}');
    }

    /// A backtick substitution, which bash reads up to the next backtick no
    /// backslash escapes, inside quotes, after a `#` or a `$(` too, and runs
    /// as a line of its own once `` \` ``, `\\` and `\$` are one letter each.
    /// What it prints is taken to be nothing, as for `$(…)`.
    fn backtick(&mut self, rest: &mut Characters<'_>) {
        let mut inner = String::new();
        while let Some(character) = rest.next() {
            match character {
                '`' => break,
                '\\' => match rest.next() {
                    Some(escaped @ ('`' | '\\' | '$')) => inner.push(escaped),
                    Some(next) => {
                        inner.push('\\');
                        inner.push(next);
                    }
                    None => inner.push('\\'),
                },
                _ => inner.push(character),
            }
        }
        self.start();
        self.found = self.found || removes_root_or_home(&inner);
    }

    /// `>` or `<`, which ends the word before it (`/*>/dev/null`). A
    /// descriptor before it (`2>&1`) is read as an argument, which is never
    /// `rm`, a flag or a target.
    fn redirect_after(&mut self, character: char, rest: &mut Characters<'_>) {
        if rest.peek() == Some(&'(') {
            // `<(…)` and `>(…)` run commands, like `$(…)`.
            rest.next();
            self.start();
            self.contexts.push(Context::new(Closer::Paren));
            return;
        }
        self.end_word();
        // `>>`, `>&`, `>|`, `<<`, `<>`, `<&`.
        rest.next_if(|next| *next == character || matches!(next, '&' | '|' | '>'));
        self.top().redirected = true;
    }

    /// `&>` or `&>>`.
    fn redirect(&mut self, rest: &mut Characters<'_>) {
        self.end_word();
        rest.next();
        rest.next_if_eq(&'>');
        self.top().redirected = true;
    }

    /// Ends the context on top, with the word and command it was reading.
    fn close(&mut self) {
        self.end_word();
        self.pop();
    }

    fn end_command(&mut self) {
        self.end_word();
        self.top().command = Command::default();
    }

    fn end_word(&mut self) {
        let top = self.top();
        let quoted = std::mem::take(&mut top.started);
        // An empty word leaves a redirection waiting for its target
        // (`> /`).
        if top.word.is_empty() {
            return;
        }
        let word = std::mem::take(&mut top.word);
        if std::mem::take(&mut top.redirected) {
            return;
        }
        let command = &mut top.command;
        // A quoted word is never a reserved word (`\case`).
        let reserved = !quoted && command.words == 0;
        if reserved {
            match word.as_str() {
                "case" | "{" => top.compounds += 1,
                "esac" | "}" => top.compounds = top.compounds.saturating_sub(1),
                _ => {}
            }
        }
        // After these a command may start (`then case …`).
        let leads_in = matches!(
            word.as_str(),
            "if" | "then" | "else" | "elif" | "while" | "until" | "do" | "!" | "time" | "{"
        );
        if !(reserved && leads_in) {
            command.words += 1;
        }
        if is_rm(&word) {
            command.removes = true;
        } else if command.removes {
            command.recursive = command.recursive || is_recursive_flag(&word);
            command.target = command.target || is_root_or_home(&word);
        }
        if command.removes && command.recursive && command.target {
            self.found = true;
        }
    }
}

/// Whether `word` runs `rm`, with every `${…}` in it taken to be empty
/// (`rm$u`, `r${u}m`).
fn is_rm(word: &str) -> bool {
    let mut program = String::new();
    let mut depth = 0_usize;
    let mut letters = word.chars().peekable();
    while let Some(letter) = letters.next() {
        if letter == '$' && letters.next_if_eq(&'{').is_some() {
            depth += 1;
        } else if letter == '}' && depth > 0 {
            depth -= 1;
        } else if depth == 0 {
            program.push(letter);
        }
    }
    program == "rm" || program.ends_with("/rm")
}

/// `-r` (`-R`, lowercased), letters with it (`-rf`), or `--recursive` or any
/// prefix of it longer than `--`, which GNU `rm` takes for it (`--recu`).
fn is_recursive_flag(word: &str) -> bool {
    match word.strip_prefix("--") {
        Some(long) => !long.is_empty() && "recursive".starts_with(long),
        None => word
            .strip_prefix('-')
            .is_some_and(|flags| flags.contains('r')),
    }
}

/// Whether `target`, without its quotes, is `/`, `~` or `$HOME` itself or
/// everything in it (`/*`, `~/`, `/./*`), with `$HOME` in any spelling
/// that is `$HOME` when it is set (`${home:?}`, `${home:-x}`, `${home%/}`).
fn is_root_or_home(target: &str) -> bool {
    // The first part ends at the `}` that closes its parameter, whose
    // operation may hold a `/` or another parameter (`${home%/}`,
    // `${home:-${x}}`), and otherwise at the first `/`.
    let end = if target.starts_with("${") {
        parameter_end(target)
    } else {
        target.find('/')
    };
    let (first, rest) = target.split_at(end.unwrap_or(target.len()));
    let whole = rest
        .split('/')
        .all(|part| matches!(part, "." | "..") || part.bytes().all(|byte| byte == b'*'));
    // `rm` refuses a path that ends in `.` or `..` (`rm -rf /.`).
    let refused = rest.trim_end_matches('/').ends_with('.');
    whole && !refused && (target.starts_with('/') || first == "~" || is_home_parameter(first))
}

/// Where the `}` that closes the `${` `target` starts with ends, past the
/// `${…}` inside it.
fn parameter_end(target: &str) -> Option<usize> {
    let mut depth = 0_usize;
    let mut previous = None;
    for (at, character) in target.char_indices() {
        match character {
            '{' if previous == Some('$') => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(at + 1);
                }
            }
            _ => {}
        }
        previous = Some(character);
    }
    None
}

/// `${home}`, or `${home` and any operation on it but `+` and `:+`, which
/// give their word when it is set (`${home:+x}` is `x`). Every other one
/// leaves a path in or above home, or home itself, when it is set
/// (`${home#x}`, `${home:-x}`, `${home,,}`); `${home#/}`, a path relative
/// to the working directory, is found too, which is accepted.
fn is_home_parameter(word: &str) -> bool {
    let Some(operation) = word
        .strip_prefix("${home")
        .and_then(|rest| rest.strip_suffix('}'))
    else {
        return false;
    };
    let name_goes_on =
        operation.starts_with(|letter: char| letter.is_ascii_alphanumeric() || letter == '_');
    !name_goes_on && !operation.starts_with('+') && !operation.starts_with(":+")
}
