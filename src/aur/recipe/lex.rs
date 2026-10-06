//! Splits a recipe into words and operators the way bash does, as far as
//! Guardian follows it. Where it may split otherwise than bash, it says so
//! (`unsure`), and the recipe counts as not followed: a reader that pairs a
//! quote differently sees code as text.

/// A word as written, quotes included.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Word {
    pub text: String,
    pub line: usize,
    /// For an array assignment (`text` is `name=(` or `name+=(`): its
    /// elements.
    pub elements: Option<Vec<Word>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Token {
    Word(Word),
    /// `;`, a new line, `&&`, `||`, `|`, `|&`, `&`, `(`, `)`, `;;`, `;&`
    /// or `;;&`.
    Operator(&'static str, usize),
    /// A redirection with the word it reads or writes. `expands`: a
    /// here-document whose text bash expands, and which holds a `$` or a
    /// backtick.
    Redirect {
        target: Word,
        expands: bool,
    },
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
    /// `$( ... )`, `<( ... )`, `(( ... ))` or a pattern list such as
    /// `!( ... )`, with its open parentheses.
    Substitution(usize, Kind),
}

/// What a pair of parentheses holds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Commands, where a `#` starts a comment.
    Code,
    /// `$(( ... ))` or `(( ... ))`: a `#` there is no comment, unless bash
    /// reads the whole as commands after all.
    Arithmetic,
    /// `!( ... )`: a `#` is a character.
    Pattern,
}

/// Where the next word stands in its command.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Position {
    /// It starts one, so `[[` and `((` are bash's own.
    Start,
    /// After `for`, where `((` opens the loop's arithmetic.
    AfterFor,
    Inside,
}

/// A here-document whose text starts after the line it is named on.
struct Here {
    marker: String,
    strip_tabs: bool,
    expands: bool,
    /// Where its redirection is among the tokens.
    token: usize,
}

/// Words after which a command still starts: `if [[ ... ]]`.
const BEFORE_COMMAND: &[&str] = &[
    "if", "then", "else", "elif", "do", "while", "until", "!", "time", "{",
];

/// Whether bash splits words at `character`: a space, a tab or a new line,
/// and no other character that only looks like one.
fn is_blank(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\n')
}

/// Whether `text` is the left side of an assignment up to and including
/// its `=`: `name=`, `name+=`, `name[3]=`.
fn is_assignment_start(text: &str) -> bool {
    let Some(target) = text.strip_suffix('=') else {
        return false;
    };
    let target = target.strip_suffix('+').unwrap_or(target);
    let name = target.split('[').next().unwrap_or(target);
    super::is_name(name)
        && (target.len() == name.len()
            || (target.ends_with(']') && !target.contains(['"', '\'', '\\'])))
}

struct Lexer<'a> {
    characters: std::iter::Peekable<std::str::Chars<'a>>,
    line: usize,
    stack: Vec<Inside>,
    word: String,
    started: usize,
    tokens: Vec<Token>,
    /// The array assignment being read.
    array: Option<Word>,
    /// Between `[[` and `]]`, where `&&`, `(` and `<` are part of the test.
    in_test: bool,
    /// The next word starts a command, so `[[` and `((` are bash's own.
    position: Position,
    /// The next word is what a redirection reads or writes.
    redirect: bool,
    here: Vec<Here>,
    /// A `<<` inside the substitution being read: a here-document there
    /// ends where Guardian does not follow.
    here_in_substitution: bool,
    /// How long the word was just after a character escaped with a
    /// backslash: that character is no blank and no operator to bash.
    escaped_at: Option<usize>,
    unsure: Vec<usize>,
}

impl Lexer<'_> {
    fn unsure(&mut self) {
        if self.unsure.last() != Some(&self.line) {
            self.unsure.push(self.line);
        }
    }

    /// Whether a backslash and a new line come next: bash joins the lines
    /// there, and reads what is before and after them as one.
    fn joins_ahead(&self) -> bool {
        let mut ahead = self.characters.clone();
        ahead.next() == Some('\\') && ahead.next() == Some('\n')
    }

    fn push(&mut self, character: char) {
        if self.word.is_empty() {
            self.started = self.line;
        }
        self.word.push(character);
    }

    fn end_word(&mut self) {
        self.here_in_substitution = false;
        if self.word.is_empty() {
            return;
        }
        let word = Word {
            text: std::mem::take(&mut self.word),
            line: self.started,
            elements: None,
        };
        if self.redirect {
            self.redirect = false;
            self.tokens.push(Token::Redirect {
                target: word,
                expands: false,
            });
        } else if let Some(array) = &mut self.array {
            array.elements.get_or_insert_with(Vec::new).push(word);
        } else {
            self.emit(word);
        }
    }

    fn emit(&mut self, word: Word) {
        let text = word.text.as_str();
        if self.in_test {
            self.in_test = text != "]]";
        } else if self.position == Position::Start && text == "[[" {
            self.in_test = true;
        }
        self.position = match self.position {
            Position::Start if text == "for" => Position::AfterFor,
            Position::Start if BEFORE_COMMAND.contains(&text) => Position::Start,
            _ => Position::Inside,
        };
        self.tokens.push(Token::Word(word));
    }

    fn operator(&mut self, operator: &'static str) {
        self.end_word();
        // A redirection with nothing after it.
        if std::mem::take(&mut self.redirect) {
            self.unsure();
        }
        self.tokens.push(Token::Operator(operator, self.line));
        self.position = Position::Start;
    }

    /// Whether a single quote opens a quotation where the lexer stands:
    /// always, except straight inside double quotes, where `${ ... }` has
    /// rules of its own (`quote_in_quoted_braces`). Inside a substitution
    /// within them it opens one again.
    fn single_quotes(&self) -> bool {
        !self
            .stack
            .iter()
            .rev()
            .take_while(|inside| !matches!(inside, Inside::Substitution(..) | Inside::Backtick))
            .any(|inside| *inside == Inside::Double)
    }

    /// The character after a backslash just kept in the word, inside
    /// quotes or a substitution: kept with it.
    fn escaped(&mut self, inside: Inside) {
        // `<` and a joined line, or `\<`: whether a here-document follows
        // is told by the `<` Guardian counts.
        let before_less = self.word[..self.word.len() - 1].ends_with('<');
        if let Some(next) = self.characters.next() {
            if matches!(inside, Inside::Substitution(..))
                && (next == '<' || (next == '\n' && before_less))
            {
                self.unsure();
            }
            self.word.push(next);
            self.line += usize::from(next == '\n');
            self.escaped_at = Some(self.word.len());
        }
    }

    /// One character inside quotes or a substitution: kept in the word.
    fn quoted(&mut self, inside: Inside, character: char) {
        let boundary = |last: char| is_blank(last) || "(;|&".contains(last);
        if let Inside::Substitution(_, kind @ (Kind::Code | Kind::Arithmetic)) = inside {
            // A comment: its quotes open nothing.
            if character == '#' && self.word.ends_with(boundary) {
                // After an escaped blank or operator, or a joined line,
                // it is part of a word.
                if kind == Kind::Arithmetic || self.escaped_at == Some(self.word.len()) {
                    self.unsure();
                }
                while self.characters.next_if(|next| *next != '\n').is_some() {}
                return;
            }
            // A here-document (not `<<<`, and not a shift on one line).
            if character == '<'
                && self.word.ends_with('<')
                && !self.word.ends_with("<<")
                && self.characters.peek() != Some(&'<')
            {
                self.here_in_substitution = true;
            }
            if character == '\n' && self.here_in_substitution {
                self.unsure();
            }
            // A `case` has patterns that close with `)`.
            if is_blank(character)
                && self
                    .word
                    .strip_suffix("case")
                    .is_some_and(|before| before.ends_with(boundary))
            {
                self.unsure();
            }
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
            (_, '\\') => self.escaped(inside),
            // Bash joins two lines before it reads what follows a `$`.
            (Inside::Double | Inside::Substitution(..) | Inside::Brace, '$')
                if self.joins_ahead() =>
            {
                self.unsure();
            }
            (Inside::Double | Inside::Substitution(..) | Inside::Brace, '$')
                if matches!(self.characters.peek(), Some('(' | '{')) =>
            {
                let opened = self.characters.next();
                self.word.extend(opened);
                let inside = if opened == Some('{') {
                    Inside::Brace
                } else {
                    Inside::Substitution(1, self.kind_ahead())
                };
                self.stack.push(inside);
            }
            (Inside::Substitution(..) | Inside::Brace, '$')
                if self.characters.peek() == Some(&'\'') && self.single_quotes() =>
            {
                self.word.push('\'');
                self.characters.next();
                self.stack.push(Inside::Ansi);
            }
            // `$$` is one parameter. Whether a `'`, a `(` or a `{` after
            // it opens what it opens after one `$` depends on what the
            // parentheses or braces hold.
            (Inside::Substitution(..) | Inside::Brace, '$')
                if self.characters.peek() == Some(&'$') =>
            {
                self.word.push('$');
                self.characters.next();
                if matches!(self.characters.peek(), Some('\'' | '(' | '{')) {
                    self.unsure();
                }
            }
            (Inside::Double | Inside::Substitution(..) | Inside::Brace, '`') => {
                self.stack.push(Inside::Backtick);
            }
            (Inside::Substitution(..) | Inside::Brace, '\'') if self.single_quotes() => {
                self.stack.push(Inside::Single);
            }
            (Inside::Brace, '\'') => self.quote_in_quoted_braces(),
            (Inside::Substitution(..) | Inside::Brace, '"') => self.stack.push(Inside::Double),
            (Inside::Substitution(depth, kind), '(') => {
                self.stack.pop();
                self.stack.push(Inside::Substitution(depth + 1, kind));
            }
            (Inside::Substitution(depth, kind), ')') => {
                self.stack.pop();
                if depth > 1 {
                    self.stack.push(Inside::Substitution(depth - 1, kind));
                }
            }
            _ => {}
        }
    }

    /// A `'` just read straight inside `"${ ... }"`. Bash looks for the one
    /// that pairs with it (`"${x#'}'}"`), though after some operators both
    /// stay characters of the value (`"${x:-'a'}"`). Read as a pair or as
    /// two characters, the braces end at the same place where nothing
    /// between the two closes or opens anything; anywhere else Guardian
    /// does not say which it is.
    fn quote_in_quoted_braces(&mut self) {
        let mut ahead = self.characters.clone();
        let same = loop {
            match ahead.next() {
                Some('\'') => break true,
                Some('}' | '"' | '\\' | '$' | '`') | None => break false,
                Some(_) => {}
            }
        };
        if !same {
            return self.unsure();
        }
        for character in self.characters.by_ref() {
            self.word.push(character);
            self.line += usize::from(character == '\n');
            if character == '\'' {
                break;
            }
        }
    }

    /// What a `$(` just read holds, by the character after it.
    fn kind_ahead(&mut self) -> Kind {
        if self.characters.peek() == Some(&'(') {
            Kind::Arithmetic
        } else {
            Kind::Code
        }
    }

    fn open(&mut self, inside: Inside, character: char) {
        self.push(character);
        self.stack.push(inside);
    }

    /// The file descriptor written before a redirection (`2>`) belongs to
    /// it; `{name}>` would set a variable.
    fn before_redirect(&mut self) {
        if !self.word.is_empty() && self.word.chars().all(|c| c.is_ascii_digit()) {
            self.word.clear();
        } else if self.word.starts_with('{') && self.word.ends_with('}') {
            self.unsure();
            self.word.clear();
        }
        self.end_word();
        if self.redirect || self.array.is_some() {
            self.unsure();
        }
    }

    /// `<` or `>` and what belongs to it (`>>`, `>&`, `<>`, `>|`).
    fn redirection(&mut self, character: char) {
        self.before_redirect();
        let more: &[char] = if character == '>' {
            &['>', '|', '&']
        } else {
            &['>', '&']
        };
        self.characters.next_if(|next| more.contains(next));
        self.redirect = true;
    }

    /// The end marker written after `<<`, as bash reads it, and whether any
    /// of it is quoted.
    fn here_marker(&mut self) -> (String, bool) {
        let (mut marker, mut quoted) = (String::new(), false);
        let mut quote = None;
        while let Some(&next) = self.characters.peek() {
            match quote {
                Some(open) if next == open => quote = None,
                Some(_) if next == '\n' => break,
                None if is_blank(next) || ";&|<>()".contains(next) => break,
                None if next == '\'' || next == '"' => {
                    quote = Some(next);
                    quoted = true;
                }
                // `$'X'`, `$"X"` and a marker in backticks are not read
                // here as bash reads them, nor is a backslash inside `"`.
                None if next == '$' || next == '`' => {
                    self.unsure();
                    marker.push(next);
                }
                Some('"') if next == '\\' => {
                    self.unsure();
                    marker.push(next);
                }
                None if next == '\\' => {
                    self.characters.next();
                    // Before a new line it joins the lines and quotes
                    // nothing.
                    if self.characters.peek() == Some(&'\n') {
                        self.line += 1;
                    } else {
                        quoted = true;
                        marker.extend(self.characters.peek());
                    }
                }
                _ => marker.push(next),
            }
            self.characters.next();
        }
        if quote.is_some() {
            self.unsure();
        }
        (marker, quoted)
    }

    /// `<<` after the word so far: a here-document, or (`<<<`) a word.
    fn here(&mut self) {
        self.before_redirect();
        if self.characters.next_if_eq(&'<').is_some() {
            self.redirect = true;
            return;
        }
        // A joined line before the `-` or the marker: what comes after
        // it belongs to the `<<`.
        let joined = self.joins_ahead();
        let strip_tabs = self.characters.next_if_eq(&'-').is_some();
        while self
            .characters
            .next_if(|next| *next == ' ' || *next == '\t')
            .is_some()
        {}
        if joined || self.joins_ahead() {
            self.unsure();
        }
        let (marker, quoted) = self.here_marker();
        if marker.is_empty() {
            self.unsure();
        }
        self.here.push(Here {
            marker,
            strip_tabs,
            expands: !quoted,
            token: self.tokens.len(),
        });
        self.tokens.push(Token::Redirect {
            target: Word {
                line: self.line,
                ..Word::default()
            },
            expands: false,
        });
    }

    /// Skips the lines of the here-documents named on the line that just
    /// ended: text, not code.
    fn skip_here_documents(&mut self) {
        for here in std::mem::take(&mut self.here) {
            let (mut current, mut expands, mut found) = (String::new(), false, false);
            while let Some(character) = self.characters.next() {
                // Under a marker written without quotes, bash joins a line
                // that ends in a backslash with the next one before it
                // looks for the marker; a backslash keeps another.
                if character == '\\' && here.expands {
                    match self.characters.next() {
                        Some('\n') => self.line += 1,
                        kept => {
                            current.push(character);
                            current.extend(kept);
                        }
                    }
                    continue;
                }
                if character != '\n' {
                    current.push(character);
                    continue;
                }
                self.line += 1;
                let text = if here.strip_tabs {
                    current.trim_start_matches('\t')
                } else {
                    current.as_str()
                };
                if text == here.marker {
                    found = true;
                    break;
                }
                expands |= current.contains(['$', '`']);
                current.clear();
            }
            // Bash also ends one at the end of the file; anything else
            // that never ends was read too far.
            if !found && current != here.marker {
                self.unsure();
            }
            if let Some(Token::Redirect { expands: noted, .. }) = self.tokens.get_mut(here.token) {
                *noted = here.expands && expands;
            }
        }
    }

    fn new_line(&mut self) {
        if self.array.is_some() || self.in_test {
            self.end_word();
            if !self.here.is_empty() {
                self.unsure();
            }
            self.line += 1;
            return;
        }
        self.operator("\n");
        self.line += 1;
        self.skip_here_documents();
    }

    /// `(` outside any quote.
    fn parenthesis(&mut self, next: Option<char>) {
        if self.array.is_none() && is_assignment_start(&self.word) {
            self.push('(');
            let line = self.started;
            self.array = Some(Word {
                text: std::mem::take(&mut self.word),
                line,
                elements: Some(Vec::new()),
            });
        } else if self.word.ends_with(['?', '*', '+', '@', '!']) {
            // A pattern list: `!(a|b)`.
            self.open(Inside::Substitution(1, Kind::Pattern), '(');
        } else if self.array.is_some() {
            self.unsure();
            self.push('(');
        } else if self.word.is_empty()
            && next == Some('(')
            && self.position != Position::Inside
            && !self.redirect
        {
            // `(( ... ))`: arithmetic, where `&&` ends no statement.
            self.characters.next();
            self.push('(');
            self.open(Inside::Substitution(2, Kind::Arithmetic), '(');
        } else {
            self.operator("(");
        }
    }

    fn close_parenthesis(&mut self) {
        self.end_word();
        match self.array.take() {
            Some(array) => {
                // What stands straight after the `)` goes on the word:
                // `x=(a)#b` has no comment.
                let ends = self
                    .characters
                    .peek()
                    .is_none_or(|next| is_blank(*next) || ";&|)".contains(*next));
                if !ends {
                    self.unsure();
                }
                self.emit(array);
            }
            None => self.operator(")"),
        }
    }

    /// `;`, `&` or `|` where it ends a command.
    fn separator(&mut self, character: char, next: Option<char>) {
        if self.array.is_some() {
            self.unsure();
            return self.push(character);
        }
        let take = |lexer: &mut Self, operator| {
            lexer.characters.next();
            lexer.operator(operator);
        };
        match (character, next) {
            (';', Some(';')) => {
                self.characters.next();
                if self.characters.next_if_eq(&'&').is_some() {
                    self.operator(";;&");
                } else {
                    self.operator(";;");
                }
            }
            (';', Some('&')) => take(self, ";&"),
            (';', _) => self.operator(";"),
            ('&', Some('&')) => take(self, "&&"),
            // `&>file`, `&>>file`.
            ('&', Some('>')) => {
                self.before_redirect();
                self.characters.next();
                self.characters.next_if_eq(&'>');
                self.redirect = true;
            }
            ('&', _) => self.operator("&"),
            ('|', Some('|')) => take(self, "||"),
            ('|', Some('&')) => take(self, "|&"),
            _ => self.operator("|"),
        }
    }

    /// One character between `[[` and `]]`, outside any quote: `(` and `)`
    /// are words of their own, the other operators part of one.
    fn test(&mut self, character: char) {
        match character {
            '(' | ')' => {
                self.end_word();
                self.push(character);
                self.end_word();
            }
            _ => self.push(character),
        }
    }

    /// One character outside any quote.
    fn plain(&mut self, character: char) {
        let next = self.characters.peek().copied();
        match character {
            '\\' => match self.characters.next() {
                Some('\n') => {
                    // `<` and `<` on two joined lines are one `<<`.
                    if self.redirect && self.word.is_empty() {
                        self.unsure();
                    }
                    self.line += 1;
                }
                Some(escaped) => {
                    self.push('\\');
                    self.push(escaped);
                }
                None => {}
            },
            '\'' => self.open(Inside::Single, character),
            '"' => self.open(Inside::Double, character),
            '`' => self.open(Inside::Backtick, character),
            '#' if self.word.is_empty() => {
                while self.characters.next_if(|next| *next != '\n').is_some() {}
            }
            '$' | '<' | '>' if next == Some('(') => {
                self.characters.next();
                self.push(character);
                let kind = if character == '$' {
                    self.kind_ahead()
                } else {
                    Kind::Code
                };
                self.open(Inside::Substitution(1, kind), '(');
            }
            '$' if next == Some('{') => {
                self.characters.next();
                self.push(character);
                self.open(Inside::Brace, '{');
            }
            // `$'...'`: after a `$` that stands alone, with no backslash
            // before it.
            '$' if next == Some('\'') => {
                self.characters.next();
                self.push(character);
                self.open(Inside::Ansi, '\'');
            }
            // `$$` is one parameter: a `'` after it is a plain quote.
            '$' if next == Some('$') => {
                self.characters.next();
                self.push(character);
                self.push(character);
            }
            // Bash joins two lines before it reads what follows a `$`.
            '$' if next == Some('\\') => {
                if self.characters.clone().nth(1) == Some('\n') {
                    self.unsure();
                }
                self.push(character);
            }
            '\n' => self.new_line(),
            ' ' | '\t' => self.end_word(),
            // `]];` ends the test: the `;` is no part of it.
            '(' | ')' | ';' | '&' | '|' | '<' | '>' if self.in_test && self.word != "]]" => {
                self.test(character);
            }
            '<' if next == Some('<') => {
                self.characters.next();
                self.here();
            }
            '<' | '>' => self.redirection(character),
            '(' => self.parenthesis(next),
            ')' => self.close_parenthesis(),
            ';' | '&' | '|' => self.separator(character, next),
            _ => self.push(character),
        }
    }
}

/// The words and operators of `recipe`, and the lines where Guardian is not
/// sure it reads them as bash does.
pub fn tokens(recipe: &str) -> (Vec<Token>, Vec<usize>) {
    let mut lexer = Lexer {
        characters: recipe.chars().peekable(),
        line: 1,
        stack: Vec::new(),
        word: String::new(),
        started: 1,
        tokens: Vec::new(),
        array: None,
        in_test: false,
        position: Position::Start,
        redirect: false,
        here: Vec::new(),
        here_in_substitution: false,
        escaped_at: None,
        unsure: Vec::new(),
    };
    // Bash drops a NUL as it reads the file, so the characters around one
    // stand together for it.
    if recipe.contains('\0') {
        lexer.unsure();
    }
    while let Some(character) = lexer.characters.next() {
        match lexer.stack.last().copied() {
            Some(inside) => lexer.quoted(inside, character),
            None => lexer.plain(character),
        }
    }
    // A quote, an array, a test or a here-document still open at the end
    // was read too far.
    if !lexer.stack.is_empty() || lexer.array.is_some() || lexer.in_test || !lexer.here.is_empty() {
        lexer.unsure();
    }
    lexer.operator("\n");
    (lexer.tokens, lexer.unsure)
}
