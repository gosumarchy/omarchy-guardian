//! Builds the commands of a recipe from its words: which run one after
//! another, which depend on another's result, and which lie inside an `if`,
//! a loop, a group or a function. What it does not know is an error, and
//! the recipe counts as not followed.

use super::lex::{Token, Word};

/// How a command follows the one before it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Join {
    /// After it, whatever it gave: a new line or `;`.
    Sequence,
    /// `&&` or `||`: depending on its result.
    Chained,
    /// `|`: both run on their own, beside the shell that reads the recipe.
    Pipe,
}

#[derive(Clone, Debug)]
pub struct Item {
    pub join: Join,
    /// Ended with `&`.
    pub background: bool,
    pub command: Command,
    /// What its redirections read or write, and whether one is a
    /// here-document that bash expands.
    pub redirects: Vec<(Word, bool)>,
}

#[derive(Clone, Debug)]
pub enum Command {
    Simple(Vec<Word>),
    /// `[[ ... ]]`, without the brackets.
    Test(Vec<Word>),
    /// `(( ... ))`, with them.
    Arithmetic(Word),
    Group(Vec<Item>),
    Subshell(Vec<Item>),
    /// Each `if` or `elif` with its commands, then the `else`.
    If(Vec<(Vec<Item>, Vec<Item>)>, Vec<Item>),
    /// `while` or `until`.
    While(Vec<Item>, Vec<Item>),
    For {
        name: Word,
        /// The words after `in`; none runs over the arguments.
        list: Option<Vec<Word>>,
        body: Vec<Item>,
    },
    Case(Word, Vec<(Vec<Word>, Vec<Item>)>),
    Function {
        name: String,
        body: Vec<Item>,
        /// The last line of its body.
        end: usize,
    },
    /// A form Guardian reads past without following it: `select`,
    /// `coproc`, `for (( ... ))`.
    Other(&'static str, Vec<Item>),
}

impl Item {
    /// The line it starts on, as far as it has words of its own.
    pub fn line(&self) -> usize {
        match &self.command {
            Command::Simple(words) | Command::Test(words) => {
                words.first().map_or(0, |word| word.line)
            }
            Command::Arithmetic(word) | Command::Case(word, _) => word.line,
            Command::For { name, .. } => name.line,
            Command::Group(items)
            | Command::Subshell(items)
            | Command::While(items, _)
            | Command::Function { body: items, .. }
            | Command::Other(_, items) => items.first().map_or(0, Self::line),
            Command::If(clauses, _) => clauses
                .first()
                .and_then(|(condition, _)| condition.first())
                .map_or(0, Self::line),
        }
    }
}

/// The line the parser could not read on from.
pub type Parsed<T> = Result<T, usize>;

struct Parser {
    tokens: Vec<Token>,
    at: usize,
    line: usize,
}

/// Words that end a list of commands rather than start one.
const CLOSING: &[&str] = &["then", "else", "elif", "fi", "do", "done", "esac", "}"];

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.at).cloned();
        self.at += 1;
        match &token {
            Some(Token::Word(word) | Token::Redirect { target: word, .. }) => self.line = word.line,
            Some(Token::Operator(_, line)) => self.line = *line,
            None => {}
        }
        token
    }

    fn fail<T>(&self) -> Parsed<T> {
        Err(self.line)
    }

    fn peek_operator(&self) -> Option<&'static str> {
        match self.peek() {
            Some(Token::Operator(operator, _)) => Some(operator),
            _ => None,
        }
    }

    /// The next token as a plain word: no array assignment.
    fn peek_word(&self) -> Option<&str> {
        match self.peek() {
            Some(Token::Word(word)) if word.elements.is_none() => Some(&word.text),
            _ => None,
        }
    }

    fn take_operator(&mut self, operator: &str) -> bool {
        let found = self.peek_operator() == Some(operator);
        if found {
            self.next();
        }
        found
    }

    fn take_word(&mut self, text: &str) -> bool {
        let found = self.peek_word() == Some(text);
        if found {
            self.next();
        }
        found
    }

    fn expect_word(&mut self, text: &str) -> Parsed<()> {
        if self.take_word(text) {
            Ok(())
        } else {
            self.next();
            self.fail()
        }
    }

    fn word(&mut self) -> Parsed<Word> {
        match self.next() {
            Some(Token::Word(word)) => Ok(word),
            _ => self.fail(),
        }
    }

    fn skip_new_lines(&mut self) {
        while self.take_operator("\n") {}
    }

    fn skip_separators(&mut self) {
        while self.take_operator("\n") || self.take_operator(";") {}
    }

    /// Commands up to one of `until`: a closing word, or an operator such
    /// as `)` or `;;`.
    fn list(&mut self, until: &[&str]) -> Parsed<Vec<Item>> {
        let mut items = Vec::new();
        loop {
            self.skip_separators();
            let stops = match self.peek() {
                None => true,
                Some(Token::Operator(operator, _)) => until.contains(operator),
                Some(Token::Word(_)) => self.peek_word().is_some_and(|word| until.contains(&word)),
                Some(Token::Redirect { .. }) => false,
            };
            if stops {
                return Ok(items);
            }
            let first = items.len();
            self.and_or(&mut items)?;
            if self.take_operator("&") {
                for item in &mut items[first..] {
                    item.background = true;
                }
            }
        }
    }

    /// Pipelines joined by `&&` and `||`.
    fn and_or(&mut self, items: &mut Vec<Item>) -> Parsed<()> {
        let mut join = Join::Sequence;
        loop {
            while self.take_word("!") || self.take_word("time") {}
            items.push(self.item(join)?);
            while self.take_operator("|") || self.take_operator("|&") {
                self.skip_new_lines();
                items.push(self.item(Join::Pipe)?);
            }
            if !(self.take_operator("&&") || self.take_operator("||")) {
                return Ok(());
            }
            self.skip_new_lines();
            join = Join::Chained;
        }
    }

    fn item(&mut self, join: Join) -> Parsed<Item> {
        let mut redirects = Vec::new();
        let command = self.command(&mut redirects)?;
        while let Some(Token::Redirect { target, expands }) = self.peek() {
            redirects.push((target.clone(), *expands));
            self.next();
        }
        Ok(Item {
            join,
            background: false,
            command,
            redirects,
        })
    }

    fn command(&mut self, redirects: &mut Vec<(Word, bool)>) -> Parsed<Command> {
        if self.take_operator("(") {
            let body = self.list(&[")"])?;
            return if self.take_operator(")") {
                Ok(Command::Subshell(body))
            } else {
                self.fail()
            };
        }
        let Some(first) = self.peek_word().map(str::to_string) else {
            return self.simple(redirects);
        };
        match first.as_str() {
            "{" => {
                self.next();
                let body = self.list(&["}"])?;
                self.expect_word("}")?;
                Ok(Command::Group(body))
            }
            "if" => self.conditional(),
            "while" | "until" => {
                self.next();
                let condition = self.list(&["do"])?;
                Ok(Command::While(condition, self.loop_body()?))
            }
            "for" | "select" => self.for_loop(first == "select"),
            "case" => self.case(),
            "function" => {
                self.next();
                let name = self.word()?.text;
                if self.take_operator("(") && !self.take_operator(")") {
                    return self.fail();
                }
                self.function(name)
            }
            "[[" => {
                self.next();
                let mut words = Vec::new();
                while !self.take_word("]]") {
                    words.push(self.word()?);
                }
                Ok(Command::Test(words))
            }
            "coproc" => {
                self.next();
                let mut body = vec![self.item(Join::Sequence)?];
                // `coproc NAME { ...; }`.
                if self.peek_word() == Some("{") || self.peek_operator() == Some("(") {
                    body.push(self.item(Join::Sequence)?);
                }
                Ok(Command::Other("coproc", body))
            }
            _ if first.starts_with("((") => Ok(Command::Arithmetic(self.word()?)),
            _ if CLOSING.contains(&first.as_str()) => {
                self.next();
                self.fail()
            }
            _ => self.simple(redirects),
        }
    }

    /// A plain command, or `name()` with a function's body after it.
    fn simple(&mut self, redirects: &mut Vec<(Word, bool)>) -> Parsed<Command> {
        let mut words = Vec::new();
        loop {
            match self.peek() {
                Some(Token::Word(word)) => words.push(word.clone()),
                Some(Token::Redirect { target, expands }) => {
                    redirects.push((target.clone(), *expands));
                }
                Some(Token::Operator("(", _)) if words.len() == 1 && redirects.is_empty() => {
                    self.next();
                    if !self.take_operator(")") {
                        return self.fail();
                    }
                    return self.function(words.remove(0).text);
                }
                _ => break,
            }
            self.next();
        }
        if words.is_empty() && redirects.is_empty() {
            self.next();
            return self.fail();
        }
        Ok(Command::Simple(words))
    }

    fn function(&mut self, name: String) -> Parsed<Command> {
        self.skip_new_lines();
        let body = self.item(Join::Sequence)?;
        let body = match body {
            Item {
                command: Command::Group(items),
                ref redirects,
                ..
            } if redirects.is_empty() => items,
            other => vec![other],
        };
        Ok(Command::Function {
            name,
            body,
            end: self.line,
        })
    }

    fn conditional(&mut self) -> Parsed<Command> {
        self.next();
        let mut clauses = Vec::new();
        loop {
            let condition = self.list(&["then"])?;
            self.expect_word("then")?;
            clauses.push((condition, self.list(&["elif", "else", "fi"])?));
            if self.take_word("elif") {
                continue;
            }
            let otherwise = if self.take_word("else") {
                self.list(&["fi"])?
            } else {
                Vec::new()
            };
            self.expect_word("fi")?;
            return Ok(Command::If(clauses, otherwise));
        }
    }

    /// `do ... done`, or the braces bash also takes after a `for`.
    fn loop_body(&mut self) -> Parsed<Vec<Item>> {
        self.skip_separators();
        let close = if self.take_word("{") { "}" } else { "done" };
        if close == "done" {
            self.expect_word("do")?;
        }
        let body = self.list(&[close])?;
        self.expect_word(close)?;
        Ok(body)
    }

    fn for_loop(&mut self, select: bool) -> Parsed<Command> {
        self.next();
        let name = self.word()?;
        if name.text.starts_with("((") {
            return Ok(Command::Other("for ((", self.loop_body()?));
        }
        self.skip_new_lines();
        let list = if self.take_word("in") {
            let mut words = Vec::new();
            while let Some(Token::Word(word)) = self.peek() {
                words.push(word.clone());
                self.next();
            }
            Some(words)
        } else {
            None
        };
        let body = self.loop_body()?;
        if select {
            return Ok(Command::Other("select", body));
        }
        Ok(Command::For { name, list, body })
    }

    fn case(&mut self) -> Parsed<Command> {
        self.next();
        let word = self.word()?;
        self.skip_new_lines();
        self.expect_word("in")?;
        let mut arms = Vec::new();
        loop {
            self.skip_new_lines();
            if self.take_word("esac") {
                return Ok(Command::Case(word, arms));
            }
            self.take_operator("(");
            let mut patterns = vec![self.word()?];
            while self.take_operator("|") {
                patterns.push(self.word()?);
            }
            if !self.take_operator(")") {
                return self.fail();
            }
            let body = self.list(&[";;", ";&", ";;&", "esac"])?;
            arms.push((patterns, body));
            let _ =
                self.take_operator(";;") || self.take_operator(";&") || self.take_operator(";;&");
        }
    }
}

/// The commands of a recipe, from its tokens.
pub fn commands(tokens: Vec<Token>) -> Parsed<Vec<Item>> {
    let mut parser = Parser {
        tokens,
        at: 0,
        line: 1,
    };
    let items = parser.list(&[])?;
    if parser.peek().is_some() {
        parser.next();
        return parser.fail();
    }
    Ok(items)
}
