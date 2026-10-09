//! Comments in the languages that write them `//` and `/* */`.
//!
//! A `/*` opens a comment only where code is read, so strings are followed:
//! one that runs over lines (a template string, a raw string) may hold a
//! line that starts with `/*`, and the code after the string would be passed
//! over with it. Following them needs no full parser as long as it gives up
//! in time: where what is being read cannot be told for certain (a regular
//! expression or markup that may hold a quote, a raw string, a spliced line,
//! text the compiler skips) the reader is unsure from there to the end of the
//! file, and takes no block comment and no `//` line that may hold code as a
//! comment again. Giving up only ever shows more.

use super::{blank, is_a_path};

/// What a file's language writes differently from the others.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Dialect {
    /// JavaScript and TypeScript; `markup` where JSX may be written.
    Script {
        markup: bool,
    },
    Go,
    Rust,
    /// C and C++, where a `\` at the end of a line joins the next one to it.
    C,
    CSharp,
    Java,
    /// Swift, Kotlin, Scala and Dart: block comments nest.
    Nesting,
    Other,
}

impl Dialect {
    pub(super) fn of(extension: &str) -> Self {
        match extension {
            "js" | "jsx" | "mjs" | "cjs" | "tsx" => Self::Script { markup: true },
            "ts" => Self::Script { markup: false },
            "go" => Self::Go,
            "rs" => Self::Rust,
            "c" | "h" | "cc" | "cpp" | "cxx" | "hpp" | "hh" => Self::C,
            "cs" => Self::CSharp,
            "java" => Self::Java,
            "swift" | "kt" | "kts" | "scala" | "dart" => Self::Nesting,
            _ => Self::Other,
        }
    }

    /// The letters that may stand directly before a quote without making
    /// the string a raw one.
    fn prefixes(self) -> &'static [&'static str] {
        match self {
            Self::Rust => &["b", "c"],
            Self::C => &["L", "u", "U", "u8"],
            Self::Script { .. }
            | Self::Go
            | Self::CSharp
            | Self::Java
            | Self::Nesting
            | Self::Other => &[],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Code,
    /// In a block comment; `hidden` when it opened at the start of a line.
    Comment {
        depth: usize,
        hidden: bool,
    },
    /// In a string that this character closes.
    Quoted(char),
    /// In the text of a template string.
    Template,
}

/// After these a `/` or a `<` begins a value: a regular expression, markup.
const BEFORE_A_VALUE: [&str; 14] = [
    "return",
    "typeof",
    "instanceof",
    "in",
    "of",
    "new",
    "delete",
    "void",
    "throw",
    "case",
    "do",
    "else",
    "yield",
    "await",
];

/// One line, and what is known of it before it is read.
struct Text<'a> {
    line: &'a str,
    chars: Vec<char>,
    /// Where the line's first word starts.
    indent: usize,
    /// The last quote or comment marker, and the last brace: what a regular
    /// expression before them could hold.
    last_mark: Option<usize>,
    last_brace: Option<usize>,
}

impl<'a> Text<'a> {
    fn new(line: &'a str) -> Self {
        let chars: Vec<char> = line.chars().collect();
        let pair = |at: usize| {
            chars[at] == '/' && matches!(chars.get(at + 1), Some('/' | '*'))
                || matches!(chars[at], '"' | '\'' | '`')
        };
        Self {
            line,
            indent: chars
                .iter()
                .take_while(|character| character.is_whitespace())
                .count(),
            last_mark: (0..chars.len()).rev().find(|at| pair(*at)),
            last_brace: chars
                .iter()
                .rposition(|character| matches!(character, '{' | '}')),
            chars,
        }
    }

    fn starts(&self, at: usize, text: &str) -> bool {
        text.chars()
            .enumerate()
            .all(|(offset, character)| self.chars.get(at + offset) == Some(&character))
    }
}

/// Reads a file line by line and blanks its comments.
pub(super) struct Reader {
    dialect: Dialect,
    mode: Mode,
    /// The `${` expressions open in template strings, each with the count
    /// of braces open inside it.
    expressions: Vec<usize>,
    unsure: bool,
    first: bool,
}

impl Reader {
    pub(super) fn new(dialect: Dialect) -> Self {
        Self {
            dialect,
            mode: Mode::Code,
            expressions: Vec::new(),
            unsure: false,
            first: true,
        }
    }

    /// `line` with its comments blanked.
    pub(super) fn line(&mut self, line: &str) -> String {
        if std::mem::take(&mut self.first) && line.starts_with("#!") {
            return line.to_string();
        }
        if !self.unsure {
            if !self.suspect(line)
                && let Some(code) = self.read(line)
            {
                return code;
            }
            self.unsure = true;
        }
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") && !is_a_path(trimmed) && !self.may_hold_code(line) {
            blank(line)
        } else {
            line.to_string()
        }
    }

    /// Whether a `//` line could run all the same, when it is not known to
    /// be read as code: inside a template string an expansion does, and a
    /// line break `str::lines` does not split at ends the comment.
    fn may_hold_code(&self, line: &str) -> bool {
        line.contains("${")
            || line.contains(['\r', '\u{2028}', '\u{2029}'])
            || self.dialect == Dialect::Java && line.contains("\\u")
    }

    /// Whether `line` holds something this reader does not follow, wherever
    /// on the line it stands.
    fn suspect(&self, line: &str) -> bool {
        // A line break the language sees and `str::lines` does not, and
        // strings in three quotes, each language's own.
        line.contains(['\r', '\u{2028}', '\u{2029}'])
            || line.contains("\"\"\"")
            || line.contains("'''")
            || match self.dialect {
                // Comments of their own in a script a page loads.
                Dialect::Script { .. } => line.contains("<!--") || line.contains("-->"),
                // Trigraphs: `??/` is a `\`.
                Dialect::C => line.contains("??/") || line.contains("??'"),
                // What a false condition leaves out is not read at all, a
                // `/*` in it included.
                Dialect::CSharp => line
                    .trim_start()
                    .strip_prefix('#')
                    .map(str::trim_start)
                    .is_some_and(|directive| {
                        directive.starts_with("if") || directive.starts_with("el")
                    }),
                // `\u000a` is a line break and `"` a quote, before
                // anything else is read.
                Dialect::Java => line.contains("\\u"),
                Dialect::Go | Dialect::Rust | Dialect::Nesting | Dialect::Other => false,
            }
    }

    /// The line with its comments blanked, or `None` once what is being
    /// read cannot be told.
    fn read(&mut self, line: &str) -> Option<String> {
        let text = Text::new(line);
        let spliced = self.spliced(line);
        if self.mode == Mode::Code && text.starts(text.indent, "//") && !is_a_path(line) {
            // Spliced, the comment runs on over the next line.
            return spliced.is_none().then(|| blank(line));
        }

        let mut at = 0;
        // How much of the line, from its start, is a comment that opened
        // at the start of a line.
        let mut hidden = 0;
        let in_hidden = |mode: Mode| matches!(mode, Mode::Comment { hidden: true, .. });
        while at < text.chars.len() {
            let was_hidden = in_hidden(self.mode);
            at = match self.mode {
                Mode::Code => self.code(&text, at)?,
                Mode::Comment { .. } => self.comment(&text, at),
                Mode::Quoted(quote) => self.quoted(&text, at, quote),
                Mode::Template => self.template(&text, at),
            };
            if was_hidden || in_hidden(self.mode) {
                hidden = at.min(text.chars.len());
            }
        }

        match self.mode {
            // A string still open: one that runs over lines, or one a
            // closing `\` (`at` went past the end) carries on.
            Mode::Quoted(quote) => {
                let escaped = at > text.chars.len();
                let carried = match self.dialect {
                    Dialect::Go => quote == '`',
                    Dialect::Rust => quote == '"',
                    Dialect::Script { .. } | Dialect::C => escaped,
                    Dialect::CSharp | Dialect::Java | Dialect::Nesting | Dialect::Other => false,
                };
                if !carried {
                    return None;
                }
            }
            // `*\` and a `/` on the next line close the comment.
            Mode::Comment { .. } if spliced.is_some() => return None,
            // A splice may join two halves of a `/*`, or an `R` to its `"`.
            Mode::Code
                if spliced.is_some_and(|before| {
                    before
                        .chars()
                        .last()
                        .is_none_or(|last| is_word(last) || last == '/')
                }) =>
            {
                return None;
            }
            Mode::Code | Mode::Comment { .. } | Mode::Template => {}
        }

        // Inside a template string, `/* ${code} */` is text with code in
        // it: belt and braces, a comment line that holds an expansion stays
        // visible.
        if hidden == 0 || line.contains("${") {
            return Some(line.to_string());
        }
        let shown: String = text.chars[hidden..].iter().collect();
        Some(" ".repeat(hidden) + &shown)
    }

    /// What stands before the `\` that joins this line to the next, in C.
    fn spliced<'a>(&self, line: &'a str) -> Option<&'a str> {
        (self.dialect == Dialect::C)
            // GCC splices with blanks after the `\` too.
            .then(|| line.trim_end().strip_suffix('\\'))
            .flatten()
    }

    /// Reads the character at `at` as code and says where to read on.
    fn code(&mut self, text: &Text<'_>, at: usize) -> Option<usize> {
        let script = matches!(self.dialect, Dialect::Script { .. });
        match text.chars[at] {
            '/' if text.starts(at, "//") => {
                // The rest is a comment, unless a splice carries it on.
                return self
                    .spliced(text.line)
                    .is_none()
                    .then_some(text.chars.len());
            }
            '/' if text.starts(at, "/*") => {
                self.mode = Mode::Comment {
                    depth: 1,
                    hidden: at == text.indent,
                };
                return Some(at + 2);
            }
            // A regular expression is not followed: one that could hold a
            // quote, a comment marker or a brace that counts is given up on.
            '/' if script && may_begin_a_value(&text.chars[..at]) => {
                let after = |mark: Option<usize>| mark.is_some_and(|mark| mark > at);
                if after(text.last_mark) || !self.expressions.is_empty() && after(text.last_brace) {
                    return None;
                }
            }
            // Nor is markup, whose text is not code.
            '<' if self.dialect == (Dialect::Script { markup: true })
                && text
                    .chars
                    .get(at + 1)
                    .is_some_and(|next| next.is_ascii_alphabetic() || *next == '>')
                && may_begin_a_value(&text.chars[..at]) =>
            {
                return None;
            }
            '"' | '\'' => return self.quote(text, at),
            '`' if script => self.mode = Mode::Template,
            '`' if self.dialect == Dialect::Go => self.mode = Mode::Quoted('`'),
            '{' => {
                if let Some(open) = self.expressions.last_mut() {
                    *open += 1;
                }
            }
            '}' => match self.expressions.last_mut() {
                Some(0) => {
                    self.expressions.pop();
                    self.mode = Mode::Template;
                }
                Some(open) => *open -= 1,
                None => {}
            },
            _ => {}
        }
        Some(at + 1)
    }

    /// Opens the string whose quote is at `at`.
    fn quote(&mut self, text: &Text<'_>, at: usize) -> Option<usize> {
        let before = &text.chars[..at];
        // `r"…"`, `R"(…)"`, `@"…"`, `#"…"#`, `1'000`: a string that ends
        // somewhere else than the rules here say, or no string at all.
        let marks = before
            .iter()
            .rposition(|character| *character != '$')
            .map(|last| before[last]);
        let word_start = before
            .iter()
            .rposition(|character| !is_word(*character))
            .map_or(0, |last| last + 1);
        let word: String = before[word_start..].iter().collect();
        if matches!(marks, Some('#' | '@'))
            || !word.is_empty() && !self.dialect.prefixes().contains(&word.as_str())
        {
            return None;
        }

        if self.dialect == Dialect::Rust && text.chars[at] == '\'' {
            let after = |offset: usize| text.chars.get(at + offset).copied();
            return match (after(1), after(2)) {
                (Some('\''), _) => None,
                // `'\n'`: a character, read as a string is.
                (Some('\\'), _) => {
                    self.mode = Mode::Quoted('\'');
                    Some(at + 1)
                }
                (Some(_), Some('\'')) => Some(at + 3),
                // A lifetime.
                _ => Some(at + 1),
            };
        }
        self.mode = Mode::Quoted(text.chars[at]);
        Some(at + 1)
    }

    /// Reads on inside a string, to past its end or the end of the line; a
    /// `\` that ends the line takes the result one past it.
    fn quoted(&mut self, text: &Text<'_>, mut at: usize, quote: char) -> usize {
        // A raw string in Go: a `\` in it is one.
        let escapes = !(self.dialect == Dialect::Go && quote == '`');
        while let Some(character) = text.chars.get(at) {
            if escapes && *character == '\\' {
                at += 2;
                continue;
            }
            at += 1;
            if *character == quote {
                self.mode = Mode::Code;
                break;
            }
        }
        at
    }

    /// Reads on in the text of a template string, to past its end, into an
    /// expression in it, or to the end of the line.
    fn template(&mut self, text: &Text<'_>, mut at: usize) -> usize {
        while let Some(character) = text.chars.get(at) {
            match character {
                '\\' => at += 2,
                '`' => {
                    self.mode = Mode::Code;
                    return at + 1;
                }
                '$' if text.starts(at, "${") => {
                    self.expressions.push(0);
                    self.mode = Mode::Code;
                    return at + 2;
                }
                _ => at += 1,
            }
        }
        at
    }

    /// Reads on inside a block comment, to past its end or the end of the
    /// line.
    fn comment(&mut self, text: &Text<'_>, mut at: usize) -> usize {
        let Mode::Comment { mut depth, hidden } = self.mode else {
            return at;
        };
        let nests = matches!(self.dialect, Dialect::Rust | Dialect::Nesting);
        while at < text.chars.len() {
            if text.starts(at, "*/") {
                at += 2;
                depth -= 1;
                if depth == 0 {
                    self.mode = Mode::Code;
                    return at;
                }
            } else if nests && text.starts(at, "/*") {
                at += 2;
                depth += 1;
            } else {
                at += 1;
            }
        }
        self.mode = Mode::Comment { depth, hidden };
        at
    }
}

fn is_word(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

/// Whether a value may begin after `before`, where a `/` opens a regular
/// expression and a `<` markup: not after a name, a number or a `]`, where
/// they divide and compare.
fn may_begin_a_value(before: &[char]) -> bool {
    let end = before
        .iter()
        .rposition(|character| !character.is_whitespace())
        .map_or(0, |last| last + 1);
    let before = &before[..end];
    let Some(last) = before.last() else {
        return true;
    };
    if *last == ']' {
        return false;
    }
    if !is_word(*last) {
        return true;
    }
    let start = before
        .iter()
        .rposition(|character| !is_word(*character))
        .map_or(0, |last| last + 1);
    let word: String = before[start..].iter().collect();
    BEFORE_A_VALUE.contains(&word.as_str())
}
