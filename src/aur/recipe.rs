//! Reads a PKGBUILD's top-level code far enough to say how it arrives at
//! what makepkg fetches: written out plainly, worked out in a way that gives
//! the same result wherever the recipe is loaded, or set where Guardian
//! cannot follow.
//!
//! Guardian lists a recipe's sources in a jail before the build loads the
//! recipe again outside it. A recipe can tell the two apart, so the listing
//! alone proves nothing about the build: the text has to show that the
//! recipe has no way to give the two different answers. This is not a
//! shell. It reads statements and words as bash splits them, knows the
//! plain forms, and counts everything else as not followed.

use std::collections::HashMap;

/// What a recipe may not set where Guardian cannot follow: what is fetched,
/// how it is verified, and where makepkg works.
const WATCHED: &[&str] = &[
    "source",
    "noextract",
    "validpgpkeys",
    "BUILDDIR",
    "SRCDEST",
    "SRCPKGDEST",
    "PKGDEST",
    "BUILDFILE",
    "DLAGENTS",
    "VCSCLIENTS",
];

/// The functions makepkg calls itself, after the sources are fetched.
const STANDARD_FUNCTIONS: &[&str] = &["prepare", "build", "check", "package", "pkgver", "verify"];

/// Variables makepkg's configuration sets before the recipe is loaded: the
/// same in the listing and in the build.
const CONFIGURED: &[&str] = &["CARCH", "CHOST", "srcdir", "pkgdir", "startdir"];

/// Commands that change how the rest of the recipe is read.
const CONTROL: &[&str] = &[
    "eval", "source", ".", "trap", "alias", "exec", "enable", "coproc",
];

/// Commands that declare the variables they are given.
const DECLARING: &[&str] = &["declare", "typeset", "local", "export", "readonly"];

/// The most reasons kept; a recipe needs one to be asked about.
const MAX_REASONS: usize = 8;

/// Whether `name` is a variable Guardian watches: one of `WATCHED`, a
/// checksum array, or any of them for one architecture (`source_x86_64`).
fn is_watched(name: &str) -> bool {
    let base = name.split_once('_').map_or(name, |(base, _)| base);
    WATCHED.contains(&name)
        || matches!(base, "source" | "noextract")
        || super::CHECKSUMS.contains(&base)
}

fn is_name(text: &str) -> bool {
    text.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn is_standard(function: &str) -> bool {
    STANDARD_FUNCTIONS.contains(&function) || function.starts_with("package_")
}

/// How one statement follows the one before it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Separator {
    /// A new line, `;`, `|` or `&`.
    Plain,
    /// `&&` or `||`: runs depending on the statement before.
    Chained,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Statement {
    line: usize,
    /// Words as written, quotes included. An array assignment is one
    /// statement: `name=(` first, then its elements.
    words: Vec<String>,
    separator: Separator,
}

/// What the lexer is inside of.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Inside {
    Single,
    /// `$'...'`, where a backslash keeps the next character.
    Ansi,
    Double,
    Backtick,
    /// `${ ... }`, which may hold blanks and `&` (`${x/-g }`, `${x/a/&b}`).
    Brace,
    /// `$( ... )`, `<( ... )` or `(( ... ))`, with its open parentheses.
    Substitution(usize),
}

struct Lexer<'a> {
    characters: std::iter::Peekable<std::str::Chars<'a>>,
    line: usize,
    stack: Vec<Inside>,
    word: String,
    words: Vec<String>,
    started: usize,
    in_array: bool,
    /// Between `[[` and `]]`, where `&&` and `||` end no statement.
    in_test: bool,
    separator: Separator,
    /// The end marker of a here-document that starts after this line.
    here_document: Option<String>,
    /// Lines Guardian may split otherwise than bash does.
    unsure: Vec<usize>,
    statements: Vec<Statement>,
}

impl Lexer<'_> {
    fn end_word(&mut self) {
        if self.word.is_empty() {
            return;
        }
        if self.words.is_empty() {
            self.started = self.line;
        }
        match self.word.as_str() {
            "[[" => self.in_test = true,
            "]]" => self.in_test = false,
            _ => {}
        }
        self.words.push(std::mem::take(&mut self.word));
    }

    fn end_statement(&mut self, next: Separator) {
        self.end_word();
        if !self.words.is_empty() {
            self.statements.push(Statement {
                line: self.started,
                words: std::mem::take(&mut self.words),
                separator: self.separator,
            });
        }
        self.separator = next;
        self.in_array = false;
        self.in_test = false;
    }

    /// Skips the lines of a here-document: text, not code.
    fn skip_here_document(&mut self, marker: &str) {
        let mut current = String::new();
        for character in self.characters.by_ref() {
            if character != '\n' {
                current.push(character);
                continue;
            }
            self.line += 1;
            if current.trim_start_matches('\t') == marker {
                return;
            }
            current.clear();
        }
    }

    /// One character inside quotes or a substitution: kept in the word.
    fn quoted(&mut self, inside: Inside, character: char) {
        let substitution = matches!(inside, Inside::Substitution(_));
        // A comment in a substitution: its quotes open nothing.
        if substitution
            && character == '#'
            && self
                .word
                .ends_with(|last: char| last.is_whitespace() || last == '(')
        {
            while self.characters.next_if(|next| *next != '\n').is_some() {}
            return;
        }
        // Where a here-document inside a substitution ends, and so which
        // of its quotes count, is not followed.
        if substitution && character == '<' && self.word.ends_with('<') {
            self.unsure.push(self.line);
        }
        self.word.push(character);
        if character == '\n' {
            self.line += 1;
        }
        match (inside, character) {
            (Inside::Single | Inside::Ansi, '\'')
            | (Inside::Double, '"')
            | (Inside::Backtick, '`')
            | (Inside::Brace, '}') => {
                self.stack.pop();
            }
            (Inside::Single, _) => {}
            (_, '\\') => {
                if let Some(next) = self.characters.next() {
                    self.word.push(next);
                }
            }
            (Inside::Double | Inside::Substitution(_) | Inside::Brace, '$')
                if matches!(self.characters.peek(), Some('(' | '{')) =>
            {
                let opened = self.characters.next();
                self.word.extend(opened);
                self.stack.push(if opened == Some('{') {
                    Inside::Brace
                } else {
                    Inside::Substitution(1)
                });
            }
            (Inside::Double | Inside::Substitution(_) | Inside::Brace, '`') => {
                self.stack.push(Inside::Backtick);
            }
            // Inside double quotes a single quote is a character.
            (Inside::Substitution(_) | Inside::Brace, '\'')
                if !self.stack.contains(&Inside::Double) =>
            {
                self.stack.push(Inside::Single);
            }
            (Inside::Substitution(_) | Inside::Brace, '"') => self.stack.push(Inside::Double),
            (Inside::Substitution(depth), '(') => {
                self.stack.pop();
                self.stack.push(Inside::Substitution(depth + 1));
            }
            (Inside::Substitution(depth), ')') => {
                self.stack.pop();
                if depth > 1 {
                    self.stack.push(Inside::Substitution(depth - 1));
                }
            }
            _ => {}
        }
    }

    /// `<<` after the word so far: notes the end marker of the
    /// here-document (not for `<<<`, which takes a word).
    fn here_marker(&mut self) {
        self.word.push_str("<<");
        if self.characters.peek() == Some(&'<') {
            return;
        }
        let mut marker = String::new();
        while let Some(&next) = self.characters.peek() {
            if next == '\n' || (next.is_whitespace() && !marker.is_empty()) {
                break;
            }
            self.characters.next();
            if !(next.is_whitespace() || "-'\"\\".contains(next)) {
                marker.push(next);
            }
        }
        self.end_word();
        self.here_document = Some(marker).filter(|marker| !marker.is_empty());
    }

    fn open(&mut self, inside: Inside, character: char) {
        self.word.push(character);
        self.stack.push(inside);
    }

    /// `&&`, `||`, `|`, `&`, or the `&` of a redirection (`2>&1`, `&>x`).
    fn operator(&mut self, character: char, next: Option<char>) {
        if next == Some(character) {
            self.characters.next();
            self.end_statement(Separator::Chained);
        } else if character == '&' && (self.word.ends_with('>') || next == Some('>')) {
            self.word.push(character);
        } else {
            self.end_statement(Separator::Plain);
        }
    }

    fn new_line(&mut self) {
        if self.in_array {
            self.end_word();
            self.line += 1;
            return;
        }
        self.end_statement(Separator::Plain);
        self.line += 1;
        if let Some(marker) = self.here_document.take() {
            self.skip_here_document(&marker);
        }
    }

    /// One character outside any quote.
    fn plain(&mut self, character: char) {
        let next = self.characters.peek().copied();
        let splits = !(self.in_array || self.in_test);
        match character {
            '\\' => match self.characters.next() {
                Some('\n') => self.line += 1,
                Some(escaped) => {
                    self.word.push('\\');
                    self.word.push(escaped);
                }
                None => {}
            },
            '\'' if self.word.ends_with('$') => self.open(Inside::Ansi, character),
            '\'' => self.open(Inside::Single, character),
            '"' => self.open(Inside::Double, character),
            '`' => self.open(Inside::Backtick, character),
            '#' if self.word.is_empty() => {
                while self.characters.next_if(|next| *next != '\n').is_some() {}
            }
            '$' | '<' | '>' if next == Some('(') => {
                self.characters.next();
                self.word.push(character);
                self.open(Inside::Substitution(1), '(');
            }
            '$' if next == Some('{') => {
                self.characters.next();
                self.word.push(character);
                self.open(Inside::Brace, '{');
            }
            '<' if next == Some('<') => {
                self.characters.next();
                self.here_marker();
            }
            // `(( ... ))`: arithmetic, where `&&` ends no statement.
            '(' if self.word.is_empty() && next == Some('(') => {
                self.characters.next();
                self.word.push('(');
                self.open(Inside::Substitution(2), '(');
            }
            '(' if self.word.ends_with('=') && !self.in_array => {
                self.word.push('(');
                self.end_word();
                self.in_array = true;
            }
            ')' if self.in_array => {
                self.end_word();
                self.in_array = false;
            }
            '\n' => self.new_line(),
            _ if character.is_whitespace() => self.end_word(),
            ';' if splits => self.end_statement(Separator::Plain),
            '&' | '|' if splits => self.operator(character, next),
            _ => self.word.push(character),
        }
    }
}

/// The statements of `recipe`, split the way bash splits them, and the
/// lines where Guardian is not sure it reads them as bash does.
fn statements(recipe: &str) -> (Vec<Statement>, Vec<usize>) {
    let mut lexer = Lexer {
        characters: recipe.chars().peekable(),
        line: 1,
        stack: Vec::new(),
        word: String::new(),
        words: Vec::new(),
        started: 1,
        in_array: false,
        in_test: false,
        separator: Separator::Plain,
        here_document: None,
        unsure: Vec::new(),
        statements: Vec::new(),
    };
    while let Some(character) = lexer.characters.next() {
        match lexer.stack.last().copied() {
            Some(inside) => lexer.quoted(inside, character),
            None => lexer.plain(character),
        }
    }
    // A quote or substitution still open at the end was read too far.
    if !lexer.stack.is_empty() || lexer.in_array {
        lexer.unsure.push(lexer.line);
    }
    lexer.end_statement(Separator::Plain);
    (lexer.statements, lexer.unsure)
}

/// What Guardian knows of a variable's value.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Value {
    /// Written out: this text, wherever the recipe is loaded.
    Literal(String),
    /// Worked out from written-out values in a way Guardian does not
    /// repeat (`${pkgver%.*}`), with the same result wherever it is loaded.
    Derived,
    /// Depends on something Guardian cannot follow, named here.
    Unknown(String),
}

impl Value {
    fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unknown(why), _) | (_, Self::Unknown(why)) => Self::Unknown(why),
            (Self::Literal(left), Self::Literal(right)) => Self::Literal(left + &right),
            _ => Self::Derived,
        }
    }
}

type Variables = HashMap<String, Value>;

/// The value of the variable `name` where it is expanded.
fn lookup(name: &str, variables: &Variables) -> Value {
    match variables.get(name) {
        Some(value) => value.clone(),
        // makepkg takes the package base from the first package name.
        None if name == "pkgbase" && variables.contains_key("pkgname") => {
            lookup("pkgname", variables)
        }
        None if CONFIGURED.contains(&name) => Value::Derived,
        None => Value::Unknown(format!("${name}, which the recipe does not set")),
    }
}

/// `word` as bash expands it, as far as Guardian follows: quotes removed
/// and plain variables put in.
fn expand(word: &str, variables: &Variables) -> Value {
    let mut value = Value::Literal(String::new());
    let mut push = |part: Value| value = std::mem::replace(&mut value, Value::Derived).join(part);
    let mut characters = word.chars().peekable();
    let mut double = false;
    while let Some(character) = characters.next() {
        match character {
            '\'' if !double => {
                let text: String = characters
                    .by_ref()
                    .take_while(|next| *next != '\'')
                    .collect();
                push(Value::Literal(text));
            }
            '"' => double = !double,
            '\\' => push(Value::Literal(characters.next().into_iter().collect())),
            '`' => push(Value::Unknown("a command's output".into())),
            '$' => match characters.peek().copied() {
                Some('(') => push(Value::Unknown("a command's output".into())),
                Some('{') => {
                    characters.next();
                    let inner: String = characters
                        .by_ref()
                        .take_while(|next| *next != '}')
                        .collect();
                    push(braced(&inner, variables));
                }
                Some(first) if first.is_ascii_alphabetic() || first == '_' => {
                    let mut name = String::new();
                    while let Some(next) =
                        characters.next_if(|next| next.is_ascii_alphanumeric() || *next == '_')
                    {
                        name.push(next);
                    }
                    push(lookup(&name, variables));
                }
                _ => push(Value::Unknown("a shell parameter".into())),
            },
            // A pattern, a list in braces or the home directory: bash
            // makes other words of these.
            '*' | '?' | '[' | '{' | '~' | '<' | '>' if !double => push(Value::Derived),
            _ => push(Value::Literal(character.to_string())),
        }
    }
    value
}

/// The value of `${inner}`.
fn braced(inner: &str, variables: &Variables) -> Value {
    if is_name(inner) {
        return lookup(inner, variables);
    }
    // `${!name}` reads a variable whose name is itself a value.
    if inner.starts_with('!') || inner.contains('`') || inner.contains("$(") {
        return Value::Unknown("an indirect expansion or a command's output".into());
    }
    let named = |text: &str| -> String {
        text.chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect()
    };
    // The variable it expands, and every other one it reads on the way
    // (`${list[@]/#/$url/}`).
    let mut names = vec![named(inner.trim_start_matches('#'))];
    names.extend(
        inner
            .match_indices('$')
            .map(|(at, _)| named(inner[at + 1..].trim_start_matches('{')))
            .filter(|name| !name.is_empty()),
    );
    names
        .iter()
        .find_map(|name| match lookup(name, variables) {
            Value::Unknown(why) => Some(Value::Unknown(why)),
            _ => None,
        })
        .unwrap_or(Value::Derived)
}

/// Whether a watched array is one a listing shows (sources, checksums and
/// the like). The others (`DLAGENTS`, makepkg's directories) change how or
/// where makepkg fetches, which no listing shows.
fn is_listed(name: &str) -> bool {
    let base = name.split_once('_').map_or(name, |(base, _)| base);
    matches!(base, "source" | "noextract" | "validpgpkeys") || super::CHECKSUMS.contains(&base)
}

/// Bash's own commands, which a function of the same name replaces.
const BUILTINS: &[&str] = &[
    "alias",
    "bind",
    "break",
    "builtin",
    "caller",
    "cd",
    "command",
    "compgen",
    "complete",
    "continue",
    "declare",
    "dirs",
    "disown",
    "echo",
    "enable",
    "eval",
    "exec",
    "exit",
    "export",
    "false",
    "getopts",
    "hash",
    "help",
    "kill",
    "let",
    "local",
    "mapfile",
    "popd",
    "printf",
    "pushd",
    "pwd",
    "read",
    "readarray",
    "readonly",
    "return",
    "set",
    "shift",
    "shopt",
    "source",
    "test",
    "times",
    "trap",
    "true",
    "type",
    "typeset",
    "ulimit",
    "umask",
    "unalias",
    "unset",
    "wait",
];

/// The functions makepkg defines for itself, read from its own files as
/// text. `None` when they cannot be read.
fn makepkg_functions() -> Option<Vec<String>> {
    let mut files = vec![std::path::PathBuf::from("/usr/bin/makepkg")];
    let mut pending = vec![std::path::PathBuf::from("/usr/share/makepkg")];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).ok()?.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "sh") {
                files.push(path);
            }
        }
    }
    let mut names = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(file).ok()?;
        names.extend(
            text.lines()
                .filter_map(|line| line.split_once("()"))
                .map(|(name, _)| name.trim_start_matches("function ").to_string())
                .filter(|name| is_name(name)),
        );
    }
    Some(names)
}

/// Whether a function named `name` stands in for something makepkg runs
/// between loading the recipe and fetching its sources: one of bash's
/// commands, one of makepkg's own functions, or a program. Where makepkg's
/// functions (`makepkg`) could not be read, any name may be one.
fn shadows_command(name: &str, makepkg: Option<&[String]>) -> bool {
    BUILTINS.contains(&name)
        || std::path::Path::new("/usr/bin").join(name).exists()
        || makepkg.is_none_or(|known| known.iter().any(|known| known == name))
}

/// How a statement depends on what ran before it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Condition {
    Always,
    /// On the machine's architecture only, which is the same in the
    /// listing and the build, or once for each of a written-out list.
    Fixed,
    /// On anything else: the listing and the build may differ.
    Open,
}

impl Condition {
    fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::Open, _) | (_, Self::Open) => Self::Open,
            (Self::Fixed, _) | (_, Self::Fixed) => Self::Fixed,
            _ => Self::Always,
        }
    }

    fn fixed_if(fixed: bool) -> Self {
        if fixed { Self::Fixed } else { Self::Open }
    }
}

/// Whether `word` reads the architecture and nothing else.
fn is_arch(word: &str) -> bool {
    matches!(word.trim_matches('"'), "$CARCH" | "${CARCH}")
}

/// Whether `words` are a test of the architecture against written-out
/// names: `[[ $CARCH == x86_64 ]]`. A test of anything else (a file, the
/// environment) can come out differently in the listing and the build.
fn is_arch_test(words: &[String]) -> bool {
    let Some((first, rest)) = words.split_first() else {
        return false;
    };
    matches!(first.as_str(), "[[" | "[" | "test")
        && rest.iter().any(|word| is_arch(word))
        && rest.iter().all(|word| {
            is_arch(word)
                || matches!(
                    word.as_str(),
                    "]]" | "]" | "==" | "=" | "!=" | "!" | "||" | "&&"
                )
                || word
                    .trim_matches(['"', '\''])
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_*?".contains(c))
        })
}

/// One statement with where it stands in the recipe.
#[derive(Clone, Debug)]
struct Placed {
    statement: Statement,
    /// The function it is in, if any.
    function: Option<String>,
    condition: Condition,
}

/// The name a statement's first words define as a function, how many words
/// that takes, and whether they open its body too: `name()`, `name ()`,
/// `function name`, `name(){`.
fn function_definition(words: &[String]) -> Option<(String, usize, bool)> {
    let first = words.first()?;
    let (first, opens) = match first.strip_suffix('{') {
        Some(rest) if rest.ends_with("()") => (rest, true),
        _ => (first.as_str(), false),
    };
    let (name, mut used) = if first == "function" {
        (words.get(1)?.trim_end_matches("()").to_string(), 2)
    } else if let Some(name) = first.strip_suffix("()") {
        (name.to_string(), 1)
    } else if words.get(1).map(String::as_str) == Some("()") {
        (first.to_string(), 2)
    } else {
        return None;
    };
    if !opens && words.get(used).map(String::as_str) == Some("()") {
        used += 1;
    }
    (!name.is_empty() && !name.contains(['=', '$', '"', '\''])).then_some((name, used, opens))
}

/// Places every statement: in which function, and under which condition.
#[derive(Default)]
struct Placer {
    /// The open `{` blocks: a function's name, or `None` for a group.
    blocks: Vec<Option<String>>,
    /// The open `if`, `case` and loops, and whether each is a `case`.
    conditions: Vec<(Condition, bool)>,
    /// A function named on a line that has not opened its body yet.
    pending: Option<String>,
    /// What an `a && b` chain's tests so far make of what follows.
    chain: Option<Condition>,
    placed: Vec<Placed>,
    functions: Vec<String>,
    /// A `}` that closed nothing: the braces are not read as bash does.
    unbalanced: bool,
}

impl Placer {
    fn of(recipe: &str) -> (Self, Vec<usize>) {
        let (statements, unsure) = statements(recipe);
        let mut placer = Self::default();
        for statement in &statements {
            placer.place(statement);
        }
        (placer, unsure)
    }

    fn condition(&self) -> Condition {
        self.conditions
            .iter()
            .fold(Condition::Always, |all, (condition, _)| all.and(*condition))
    }

    /// Takes the keywords and braces that open and close blocks off the
    /// front of `words`, and returns what is left: a command.
    fn structure<'a>(&mut self, mut words: &'a [String]) -> &'a [String] {
        loop {
            if let Some((name, used, opens)) = function_definition(words) {
                self.functions.push(name.clone());
                if opens {
                    self.blocks.push(Some(name));
                } else {
                    self.pending = Some(name);
                }
                words = &words[used..];
                continue;
            }
            let Some(first) = words.first().map(String::as_str) else {
                return words;
            };
            let in_case = self.conditions.last().is_some_and(|(_, case)| *case);
            match first {
                "{" => {
                    let name = self.pending.take();
                    self.blocks.push(name);
                }
                "then" | "do" | "else" | "!" | "time" => {}
                "fi" | "esac" | "done" => {
                    self.conditions.pop();
                }
                "if" | "elif" => {
                    if first == "elif" {
                        self.conditions.pop();
                    }
                    let fixed = Condition::fixed_if(is_arch_test(&words[1..]));
                    self.conditions.push((fixed, false));
                }
                "case" => {
                    let fixed = Condition::fixed_if(words.get(1).is_some_and(|word| is_arch(word)));
                    self.conditions.push((fixed, true));
                    let after = words.iter().position(|word| word == "in");
                    words = &words[after.map_or(words.len(), |at| at + 1)..];
                    continue;
                }
                "for" | "select" => {
                    // What it runs over is looked at where it is read.
                    self.conditions.push((Condition::Fixed, false));
                    return words;
                }
                "while" | "until" => self.conditions.push((Condition::Open, false)),
                // A pattern of a `case` comes before its commands.
                _ if in_case && first.ends_with(')') && !first.contains('(') => {}
                _ => return words,
            }
            words = &words[1..];
        }
    }

    fn place(&mut self, statement: &Statement) {
        let chained = match statement.separator {
            Separator::Chained => self.chain.unwrap_or(Condition::Open),
            Separator::Plain => Condition::Always,
        };
        let words = self.structure(&statement.words).to_vec();
        // What follows a test in a chain runs only when the test holds.
        self.chain = Some(chained.and(Condition::fixed_if(is_arch_test(&words))));
        // A `}` closes a block wherever bash takes it as one (`(x) }`);
        // taking one too many only shows more of the recipe as top level.
        let closes = words.iter().filter(|word| *word == "}").count();
        let function = self.blocks.iter().rev().find_map(Clone::clone);
        let condition = self.condition().and(chained);
        for _ in 0..closes {
            self.unbalanced |= self.blocks.pop().is_none();
        }
        let words: Vec<String> = words.into_iter().filter(|word| word != "}").collect();
        if !words.is_empty() {
            self.placed.push(Placed {
                function,
                condition,
                statement: Statement {
                    words,
                    line: statement.line,
                    separator: statement.separator,
                },
            });
        }
    }
}

/// How a recipe arrives at what makepkg fetches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sources {
    /// Written out: each watched array once, in plain words. The arrays as
    /// written, by name, which a listing must give back exactly.
    Written(Vec<(String, Vec<String>)>),
    /// Worked out from written-out values, the same wherever the recipe is
    /// loaded.
    Derived,
    /// Set where Guardian cannot follow, as `line N: why`.
    NotFollowed(Vec<String>),
}

struct Reader {
    variables: Variables,
    /// The watched arrays written in plain words.
    arrays: Vec<(String, Vec<String>)>,
    derived: bool,
    reasons: Vec<String>,
    functions: Vec<String>,
    bodies: Vec<Placed>,
}

impl Reader {
    fn not_followed(&mut self, line: usize, why: &str) {
        if self.reasons.len() < MAX_REASONS {
            self.reasons.push(format!("line {line}: {why}"));
        }
    }

    /// An array assignment: `name=(` or `name+=(`, then its elements.
    fn array(&mut self, placed: &Placed, name: &str, append: bool, in_call: bool) {
        let line = placed.statement.line;
        let open = placed.condition == Condition::Open || in_call;
        let elements: Vec<Value> = placed.statement.words[1..]
            .iter()
            .map(|word| expand(word, &self.variables))
            .collect();
        let unknown = elements.iter().find_map(|value| match value {
            Value::Unknown(why) => Some(why.clone()),
            _ => None,
        });
        if !is_watched(name) {
            let value = match (unknown, elements.first()) {
                (Some(why), _) => Value::Unknown(why),
                (None, _) if open => Value::Unknown(format!("${name}, set under a condition")),
                // `$name` is the array's first element.
                (None, Some(Value::Literal(first)))
                    if !append && placed.condition == Condition::Always =>
                {
                    Value::Literal(first.clone())
                }
                _ => Value::Derived,
            };
            self.variables.insert(name.to_string(), value);
            return;
        }
        // Later words may read it (`noextract=("${source[@]##*/}")`).
        self.variables.insert(
            name.to_string(),
            unknown.clone().map_or(Value::Derived, Value::Unknown),
        );
        if !is_listed(name) {
            return self.not_followed(
                line,
                &format!("{name} is set, which changes how or where makepkg fetches"),
            );
        }
        if let Some(why) = unknown {
            return self.not_followed(line, &format!("{name} is built from {why}"));
        }
        if open {
            return self.not_followed(
                line,
                &format!("{name} is set under a condition or inside a function"),
            );
        }
        let literal: Option<Vec<String>> = elements
            .into_iter()
            .map(|value| match value {
                Value::Literal(text) => Some(text),
                _ => None,
            })
            .collect();
        let again = self.arrays.iter().any(|(known, _)| known == name);
        match literal {
            Some(words) if !append && !again && placed.condition == Condition::Always => {
                self.arrays.push((name.to_string(), words));
            }
            _ => self.derived = true,
        }
    }

    /// A plain assignment, `name=value`: true when the word was one.
    fn scalar(&mut self, placed: &Placed, word: &str, in_call: bool) -> bool {
        let Some((target, value)) = word.split_once('=') else {
            return false;
        };
        let append = target.ends_with('+');
        let target = target.strip_suffix('+').unwrap_or(target);
        let name = target.split('[').next().unwrap_or(target);
        if !is_name(name) {
            return false;
        }
        if is_watched(name) {
            // One element set by its number, always and to a value that is
            // the same everywhere (`sha256sums[2]=SKIP`), is worked out
            // like any other; nothing else is followed.
            let index = target.strip_prefix(name).unwrap_or_default();
            let numbered = index.len() > 2
                && index.starts_with('[')
                && index.ends_with(']')
                && index[1..index.len() - 1]
                    .chars()
                    .all(|c| c.is_ascii_digit());
            let fixed = numbered
                && is_listed(name)
                && !append
                && !in_call
                && placed.condition != Condition::Open
                && !matches!(expand(value, &self.variables), Value::Unknown(_));
            if fixed {
                self.derived = true;
            } else {
                self.not_followed(
                    placed.statement.line,
                    &format!("{name} is set in a form other than a plain array"),
                );
            }
            return true;
        }
        let value = match expand(value, &self.variables) {
            Value::Unknown(why) => Value::Unknown(why),
            _ if placed.condition == Condition::Open || in_call => {
                Value::Unknown(format!("${name}, set under a condition"))
            }
            Value::Literal(text)
                if placed.condition == Condition::Always && target == name && !append =>
            {
                Value::Literal(text)
            }
            _ => Value::Derived,
        };
        self.variables.insert(name.to_string(), value);
        true
    }

    /// A command that assigns to the variables it is given by name.
    fn assigner(&mut self, placed: &Placed, command: &str, operands: &[String]) {
        let line = placed.statement.line;
        let declares = DECLARING.contains(&command);
        let flags = operands.iter().filter(|word| word.starts_with('-'));
        if declares && flags.clone().any(|flag| flag.contains('n')) {
            return self.not_followed(line, "a variable is made a reference to another");
        }
        let targets: Vec<&str> = match command {
            // Only the word after `-v` is assigned.
            "printf" => operands
                .iter()
                .enumerate()
                .find_map(|(at, word)| match word.strip_prefix("-v") {
                    Some("") => operands.get(at + 1).map(String::as_str),
                    Some(name) => Some(name),
                    None => None,
                })
                .into_iter()
                .collect(),
            _ => operands
                .iter()
                .take_while(|word| !word.starts_with(['<', '>']))
                .filter(|word| !word.starts_with('-'))
                .map(String::as_str)
                .collect(),
        };
        for target in targets {
            let bare = target.trim_matches(['"', '\'']);
            let name = bare.split(['=', '+', '[']).next().unwrap_or(bare);
            if name.contains(['$', '`']) {
                self.not_followed(
                    line,
                    &format!("{command} assigns to a variable named by another"),
                );
            } else if is_watched(name) {
                self.not_followed(line, &format!("{command} sets {name}"));
            } else if is_name(name) {
                let given = bare
                    .split_once('=')
                    .map(|(_, value)| expand(value, &self.variables));
                let value = match given {
                    Some(Value::Unknown(why)) => Value::Unknown(why),
                    _ if !declares || placed.condition == Condition::Open => {
                        Value::Unknown(format!("${name}, set by {command}"))
                    }
                    Some(_) => Value::Derived,
                    // Declared without a value: it keeps the one it has.
                    None => continue,
                };
                self.variables.insert(name.to_string(), value);
            }
        }
    }

    /// A call of a function the recipe defines: its body is read as part
    /// of the top level.
    fn call(&mut self, line: usize, name: &str, depth: usize) {
        if depth >= 4 {
            return self.not_followed(line, "functions call each other too deep to follow");
        }
        if is_standard(name) {
            return self.not_followed(
                line,
                &format!("{name}() is called while the recipe is loaded"),
            );
        }
        let body: Vec<Placed> = self
            .bodies
            .iter()
            .filter(|placed| placed.function.as_deref() == Some(name))
            .cloned()
            .collect();
        for statement in &body {
            self.read(statement, true, depth + 1);
        }
    }

    /// A `for` loop's variable takes each of the words it runs over.
    fn for_loop(&mut self, line: usize, operands: &[String]) {
        let Some((name, list)) = operands.split_first() else {
            return;
        };
        let unknown = list
            .iter()
            .skip_while(|word| *word != "in")
            .skip(1)
            .find_map(|word| match expand(word, &self.variables) {
                Value::Unknown(why) => Some(why),
                _ => None,
            });
        if let Some(why) = &unknown {
            self.not_followed(line, &format!("a loop runs over {why}"));
        }
        if is_name(name) {
            self.variables.insert(name.clone(), Value::Derived);
        }
    }

    /// One statement at the top level, or (`in_call`) in a function the
    /// top level calls.
    fn read(&mut self, placed: &Placed, in_call: bool, depth: usize) {
        let words = &placed.statement.words;
        let line = placed.statement.line;
        if let Some(name) = words.first().and_then(|first| first.strip_suffix("=(")) {
            let (name, append) = match name.strip_suffix('+') {
                Some(name) => (name, true),
                None => (name, false),
            };
            if is_name(name) {
                return self.array(placed, name, append, in_call);
            }
        }
        // `${name:=value}` assigns where it is expanded.
        for word in words {
            for (at, _) in word.match_indices("${") {
                let inner = &word[at + 2..];
                let name: String = inner
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                let after = &inner[name.len()..];
                if (after.starts_with(":=") || after.starts_with('=')) && is_watched(&name) {
                    self.not_followed(line, &format!("{name} is set inside an expansion"));
                }
            }
        }
        let mut rest = words.as_slice();
        while let Some(word) = rest.first() {
            if !(matches!(word.as_str(), "builtin" | "command")
                || self.scalar(placed, word, in_call))
            {
                break;
            }
            rest = &rest[1..];
        }
        let Some((command, operands)) = rest.split_first() else {
            return;
        };
        let command = command.as_str();
        // A watched name given to a command as `name=` may be set by it.
        for word in operands {
            let name = word.split(['=', '+', '[']).next().unwrap_or_default();
            if word.contains('=') && is_watched(name) && !DECLARING.contains(&command) {
                self.not_followed(
                    line,
                    &format!("{name} is set in a form other than a plain array"),
                );
            }
        }
        let assigns = |word: &String| word.starts_with("-v");
        match command {
            _ if CONTROL.contains(&command) => self.not_followed(
                line,
                &format!("`{command}` runs or reads in code Guardian does not follow"),
            ),
            "exit" | "return" if !in_call => self.not_followed(
                line,
                &format!("`{command}` stops the recipe before its end"),
            ),
            "printf" if !operands.iter().any(assigns) => {}
            "printf" | "read" | "mapfile" | "readarray" | "unset" | "let" => {
                self.assigner(placed, command, operands);
            }
            _ if DECLARING.contains(&command) => self.assigner(placed, command, operands),
            "for" | "select" => self.for_loop(line, operands),
            _ if self.functions.iter().any(|function| function == command) => {
                self.call(line, command, depth);
            }
            _ => {}
        }
    }
}

/// Classifies how `recipe` arrives at its sources (see `Sources`).
pub fn sources(recipe: &str) -> Sources {
    let (placer, unsure) = Placer::of(recipe);
    let (top, bodies): (Vec<Placed>, Vec<Placed>) = placer
        .placed
        .into_iter()
        .partition(|placed| placed.function.is_none());
    let mut reader = Reader {
        variables: Variables::new(),
        arrays: Vec::new(),
        derived: false,
        reasons: Vec::new(),
        functions: placer.functions,
        bodies,
    };
    for line in unsure {
        reader.not_followed(
            line,
            "quoting Guardian may read otherwise than the shell does",
        );
    }
    if placer.unbalanced || !placer.blocks.is_empty() {
        reader.reasons.push(
            "the recipe's braces do not pair up as Guardian reads them, so where its functions end is not sure"
                .into(),
        );
    }
    // A function under another name can stand in for a command makepkg
    // itself runs between loading the recipe and fetching the sources.
    let helpers: Vec<String> = reader
        .functions
        .iter()
        .filter(|name| !is_standard(name))
        .cloned()
        .collect();
    if !helpers.is_empty() {
        let makepkg = makepkg_functions();
        for name in helpers {
            if shadows_command(&name, makepkg.as_deref()) {
                reader.reasons.push(format!(
                    "the recipe defines {name}(), which stands in for a command makepkg runs"
                ));
            }
        }
    }
    for placed in &top {
        reader.read(placed, false, 0);
    }
    if !reader.reasons.is_empty() {
        reader.reasons.truncate(MAX_REASONS);
        Sources::NotFollowed(reader.reasons)
    } else if reader.derived {
        Sources::Derived
    } else {
        Sources::Written(reader.arrays)
    }
}

/// The variables a recipe sets to plain text at its top level, longest name
/// first, for reading its functions' commands as they will run
/// (`./$_binary`).
pub fn written_variables(recipe: &str) -> Vec<(String, String)> {
    let (placer, _) = Placer::of(recipe);
    let mut variables = Variables::new();
    let top = placer
        .placed
        .iter()
        .filter(|placed| placed.function.is_none());
    for placed in top {
        let words = &placed.statement.words;
        let Some((name, value)) = words.first().and_then(|word| word.split_once('=')) else {
            continue;
        };
        if !is_name(name) {
            continue;
        }
        let value = if placed.condition != Condition::Always {
            Value::Derived
        } else if value == "(" {
            words
                .get(1)
                .map_or(Value::Derived, |first| expand(first, &variables))
        } else {
            expand(value, &variables)
        };
        variables.insert(name.to_string(), value);
    }
    let mut written: Vec<(String, String)> = variables
        .into_iter()
        .filter_map(|(name, value)| match value {
            Value::Literal(text) => Some((name, text)),
            _ => None,
        })
        .collect();
    // So that `$pkgname` is not read as `$pkg` followed by `name`.
    written.sort_by(|left, right| right.0.len().cmp(&left.0.len()).then(left.0.cmp(&right.0)));
    written
}

#[cfg(test)]
mod tests {
    use super::{Sources, sources, statements, written_variables};

    fn written(recipe: &str) -> Vec<(String, Vec<String>)> {
        match sources(recipe) {
            Sources::Written(arrays) => arrays,
            other => panic!("{recipe:?}: {other:?}"),
        }
    }

    fn words(recipe: &str) -> Vec<Vec<String>> {
        statements(recipe)
            .0
            .into_iter()
            .map(|statement| statement.words)
            .collect()
    }

    fn list(words: &[&str]) -> Vec<String> {
        words.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn statements_are_split_as_bash_splits_them() {
        assert_eq!(
            words("a=1; b=\"x ; y\" # c=3\nsource=(one\n  'two three' # note\n  four)\n"),
            [
                list(&["a=1"]),
                list(&["b=\"x ; y\""]),
                list(&["source=(", "one", "'two three'", "four"]),
            ]
        );
        // A substitution, a redirection and a here-document are no
        // statement ends; `${#x}` and `$#` are no comments.
        assert_eq!(
            words("x=$(a; b | c) y=${#z} 2>&1\ncat <<EOF\nsource=(evil)\nEOF\nz=1\n"),
            [
                list(&["x=$(a; b | c)", "y=${#z}", "2>&1"]),
                list(&["cat", "<<"]),
                list(&["z=1"]),
            ]
        );
        assert_eq!(
            words("[[ a == b && c == d ]] && x=1\n(( a && b )); y=$'it\\'s'; z=2\n"),
            [
                list(&["[[", "a", "==", "b", "&&", "c", "==", "d", "]]"]),
                list(&["x=1"]),
                list(&["(( a && b ))"]),
                list(&["y=$'it\\'s'"]),
                list(&["z=2"]),
            ]
        );
        assert_eq!(statements("a\n\nb && c\n").0[2].line, 3);
    }

    #[test]
    fn plain_arrays_are_written_with_their_plain_variables_put_in() {
        let recipe = "pkgname=demo\npkgver=1.2\n_commit=abc123 # pinned\nurl=\"https://example.org/$pkgname\"\n\
source=(\"$pkgname-$pkgver.tar.gz::$url/archive/v${pkgver}.tar.gz\"\n        'fix.patch'\n        \"git+$url.git#commit=$_commit\")\n\
sha256sums=('abc'\n            SKIP 'SKIP')\nbuild() {\n  local source=x\n  eval make\n  BUILDDIR=b make\n}\n";
        assert_eq!(
            written(recipe),
            [
                (
                    "source".to_string(),
                    list(&[
                        "demo-1.2.tar.gz::https://example.org/demo/archive/v1.2.tar.gz",
                        "fix.patch",
                        "git+https://example.org/demo.git#commit=abc123",
                    ])
                ),
                ("sha256sums".to_string(), list(&["abc", "SKIP", "SKIP"])),
            ]
        );
        // The package base is the first package name.
        assert_eq!(
            written("pkgname=(one two)\nsource=($pkgbase.tar)\n")[0].1,
            ["one.tar"]
        );
    }

    #[test]
    fn sources_worked_out_from_written_values_are_derived() {
        for recipe in [
            "pkgver=1.2.3\nsource=(\"https://example.org/${pkgver%.*}/x.tar.gz\")\n",
            "source=(a)\nsource+=(b)\n",
            "source=(a)\nsource_x86_64=(\"x-$CARCH.tar\")\n",
            "case \"$CARCH\" in\n  x86_64) _a=amd64 ;;\n  aarch64|armv7h) _a=arm64 ;;\nesac\nsource=(\"x_$_a.deb\")\n",
            "[[ $CARCH == x86_64 ]] && source+=(a)\n",
            "[[ $CARCH == x86_64 || $CARCH == i686 ]] && source+=(a)\n",
            "if [ \"$CARCH\" = aarch64 ]; then\n  source=(b)\nelse\n  source=(c)\nfi\n",
            "_langs=(de fr)\nsource=()\nfor _l in \"${_langs[@]}\"; do\n  source+=(\"$_l.xpi\")\ndone\n",
            "source=({a,b}.tar)\n",
            "export _x=1\nsource=(\"$_x.tar\")\n",
            // An element set by its number, always (pacman-contrib#119).
            "source=(a b)\nsha256sums=(x y)\nsha256sums[1]='SKIP'\n",
            "source=(a/b.tar c)\nnoextract=(\"${source[@]##*/}\")\n",
            "_names=(a b)\n_url=https://example.org\nsource=(\"${_names[@]/#/$_url/}\")\n",
            "create_links() { :; }\nsource=(a)\nsource+=(b)\n",
        ] {
            assert_eq!(sources(recipe), Sources::Derived, "{recipe}");
        }
    }

    #[test]
    fn sources_set_where_guardian_cannot_follow_are_named() {
        for recipe in [
            "[[ -w . ]] && source=(evil)\n",
            "[[ -w . ]] || source=(evil)\n",
            "source[$i]=evil\n",
            "[[ -w . ]] && source[0]=evil\n",
            "source[0]=$(curl x)\n",
            "source=evil\n",
            "declare -a source=(evil)\n",
            "typeset -a source=(evil)\n",
            "declare -n ref=source\n",
            "local -n ref=sha256sums\n",
            "readonly noextract=(x)\n",
            "eval 'source=(evil)'\n",
            "builtin eval 'source=(evil)'\n",
            "printf -v source %s evil\n",
            "v=source; printf -v \"$v\" %s evil\n",
            "read -r -a source <<<\"evil\"\n",
            "mapfile -t source < list\n",
            "readarray -t sha256sums < list\n",
            "if [ -e /.dockerenv ]; then source=(a); fi\n",
            "case $HOME in /home/*) source=(a) ;; esac\n",
            "while true; do source+=(a); break; done\n",
            "for x in $(ls); do source+=(a); done\n",
            "_f() { source=(evil); }\n_f\n",
            "_f() { eval \"$1\"; }\n_f x\n",
            "source=($(curl -s https://example.org/list))\n",
            "source=(`cat list`)\n",
            "_v=$(uname -r)\nsource=(\"x-$_v.tar\")\n",
            "source=(\"$HOME/x.tar\")\n",
            "[[ -n $DISPLAY ]] && _v=a\nsource=(\"x-$_v.tar\")\n",
            "source=(a)\n. ./more.sh\n",
            "source other\nsource=(a)\n",
            "trap 'source=(evil)' DEBUG\n",
            "source=(a)\nexit 0\n",
            "curl() { /usr/bin/curl evil; }\nsource=(a)\n",
            "prepare() { :; }\nprepare\n",
            ": \"${source:=evil}\"\n",
            "BUILDDIR=/x\n",
            "printf -v PKGDEST %s /x\n",
            "unset source\n",
            "source_x86_64[x]=evil\n",
            "source+=evil\n",
            "x=1 source=evil true\n",
            "DLAGENTS=(\"https::/usr/bin/evil $HOME\")\n",
            "_x=${!y}\nsource=($_x)\n",
            // Text that could hide code from a reader that pairs quotes
            // or braces otherwise than bash.
            "_x=$(cat <<E\n'\nE\n)\nsource=(evil) # '\n",
            "_f() { (true) }\nsource=(a)\n_g() { :; }\n}\n",
            "_f() {\n  :\nsource=(a)\n",
            "x=\"unclosed\nsource=(a)\n",
        ] {
            assert!(
                matches!(sources(recipe), Sources::NotFollowed(ref why) if !why.is_empty()),
                "{recipe}: {:?}",
                sources(recipe)
            );
        }
    }

    #[test]
    fn quoting_that_bash_reads_as_one_word_hides_nothing() {
        // `$'\''` is one quote character; what follows is code.
        assert!(matches!(
            sources("x=$'\\''; eval evil #'\n"),
            Sources::NotFollowed(_)
        ));
        // A comment inside a substitution opens no quote.
        assert!(matches!(
            sources("_x=$(echo a # it's\n)\neval evil # '\n"),
            Sources::NotFollowed(_)
        ));
        // A `}` given to a command closes nothing in bash; reading it as a
        // close shows more as top level, never less.
        assert!(matches!(
            sources("_f() { echo }; eval evil; }\n"),
            Sources::NotFollowed(_)
        ));
        // `${ ... }` holds blanks and `&` without ending a statement, so
        // the function's closing brace is the one bash takes.
        assert_eq!(
            sources("build() {\n  x=${CFLAGS/-g }\n  y=${v/a/&b}\n  eval z\n}\nsource=(a)\n"),
            Sources::Written(vec![("source".into(), vec!["a".into()])])
        );
    }

    #[test]
    fn what_a_recipe_does_elsewhere_is_no_reason_to_ask() {
        for recipe in [
            "pkgname=demo\nsource=(a)\nbuild() {\n  eval \"$(x)\"\n  printf -v v %s y\n  export BUILDDIR=b\n  read -r source < f\n}\n",
            "_helper() { local x=$1; echo \"$x\"; }\npackage() { _helper a; }\nsource=(a)\n",
            "shopt -s extglob\nsource=(a)\nprintf '%s\\n' hello\n",
            "# source=(evil)\nsource=(a) # eval\n",
            "pkgdesc=\"eval; source=(x) && exit\"\nsource=(a)\n",
            "package_demo() {\n  depends=(x)\n  source=(evil)\n}\nsource=(a)\n",
            "build() {\n  if true; then\n    make\n  fi\n  for x in a; do :; done\n}\nsource=(a)\n",
            "package(){\n  install -Dm755 x \"${pkgdir}/usr/bin/x\"\n}\nsource=(a)\n",
            "function _f {\n  :\n}\nsource=(a)\n",
        ] {
            assert_eq!(written(recipe)[0].1, ["a"], "{recipe}");
        }
    }

    #[test]
    fn written_variables_are_the_plain_top_level_ones() {
        assert_eq!(
            written_variables(
                "pkgname=demo-bin\n_name=${pkgname%-bin}\n_bin=tool\npkgver=1\n[[ -n $X ]] && _c=1\nbuild() { _in=1; }\n"
            ),
            [
                ("pkgname".to_string(), "demo-bin".to_string()),
                ("pkgver".into(), "1".into()),
                ("_bin".into(), "tool".into()),
            ]
        );
    }

    /// Run with `GUARDIAN_RECIPE_SAMPLES=<dir of package dirs> cargo test
    /// measures_real_recipes -- --ignored --nocapture` to see how real
    /// recipes are classified.
    #[test]
    #[ignore = "needs a directory of real PKGBUILDs"]
    fn measures_real_recipes() {
        let Some(root) = std::env::var_os("GUARDIAN_RECIPE_SAMPLES") else {
            return;
        };
        let (mut total, mut plain, mut derived, mut asked, mut differs) = (0, 0, 0, 0, 0);
        for entry in std::fs::read_dir(root).unwrap().flatten() {
            let Ok(recipe) = std::fs::read_to_string(entry.path().join("PKGBUILD")) else {
                continue;
            };
            total += 1;
            match sources(&recipe) {
                Sources::Written(arrays) => {
                    plain += 1;
                    if let Ok(listing) = std::fs::read_to_string(entry.path().join(".SRCINFO"))
                        && let Some(what) = crate::aur::written_mismatch(&arrays, &listing)
                    {
                        differs += 1;
                        outln!("DIFFERS {}: {what}", entry.path().display());
                    }
                }
                Sources::Derived => derived += 1,
                Sources::NotFollowed(why) => {
                    asked += 1;
                    outln!("ASKED {}: {why:?}", entry.path().display());
                }
            }
        }
        outln!(
            "{total} recipes: {plain} written ({differs} differ from their .SRCINFO), {derived} derived, {asked} not followed"
        );
    }
}
