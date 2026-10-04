//! Reads a PKGBUILD's top-level code far enough to say how it arrives at
//! what makepkg fetches: written out plainly, worked out in a way that gives
//! the same result wherever the recipe is loaded, or set where Guardian
//! cannot follow.
//!
//! Guardian lists a recipe's sources in a jail before the build loads the
//! recipe again outside it. A recipe can tell the two apart, so the listing
//! alone proves nothing about the build: the text has to show that the
//! recipe has no way to give the two different answers. This is not a
//! shell. It reads the commands bash runs while it loads the recipe, knows
//! the plain forms, and counts everything else as not followed: a value
//! that can differ from one run to the next (a file that is there, the
//! environment, a command's output) may reach nothing Guardian watches.

mod lex;
mod parse;

use lex::Word;
use parse::{Command, Item, Join};
use std::collections::{BTreeMap, HashMap, HashSet};

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

/// Variables bash itself fills in, with what differs from run to run,
/// whatever the recipe sets them to.
const DYNAMIC: &[&str] = &[
    "RANDOM",
    "SRANDOM",
    "SECONDS",
    "LINENO",
    "PPID",
    "UID",
    "EUID",
    "GROUPS",
    "HOSTNAME",
    "PWD",
    "OLDPWD",
    "SHLVL",
    "REPLY",
    "MAPFILE",
    "COPROC",
    "OPTARG",
    "OPTIND",
    "FUNCNAME",
    "PIPESTATUS",
    "DIRSTACK",
];

/// Commands that run or read in code, or change how the rest of the recipe
/// is read.
const CONTROL: &[&str] = &[
    "eval", "source", ".", "trap", "alias", "enable", "coproc", "bind", "complete", "compgen",
    "compopt", "caller", "fc", "history", "jobs", "bg", "fg", "suspend", "logout",
];

/// Commands that declare the variables they are given.
const DECLARING: &[&str] = &["declare", "typeset", "local", "export", "readonly"];

/// The `shopt` options that change how patterns match and nothing else.
const PATTERN_OPTIONS: &[&str] = &[
    "-s",
    "-u",
    "-q",
    "extglob",
    "nullglob",
    "globstar",
    "dotglob",
    "nocasematch",
    "nocaseglob",
    "failglob",
];

/// What `set` may be given: how bash treats failures and what it prints.
const SET_OPTIONS: &[&str] = &[
    "-e", "+e", "-u", "+u", "-x", "+x", "-o", "+o", "-eu", "-euo", "-ex", "errexit", "nounset",
    "xtrace", "pipefail",
];

/// makepkg's functions that print a message and do nothing else.
const MESSAGES: &[&str] = &["msg", "msg2", "warning", "error", "plain"];

/// The variables makepkg reads out of `package()` functions by running
/// the lines that set them (`extract_function_variable`), beside the
/// checksum arrays.
const ATTRIBUTES: &[&str] = &[
    "arch",
    "backup",
    "checkdepends",
    "conflicts",
    "depends",
    "groups",
    "license",
    "makedepends",
    "noextract",
    "optdepends",
    "options",
    "provides",
    "replaces",
    "source",
    "validpgpkeys",
    "xdata",
    "changelog",
    "epoch",
    "install",
    "pkgbase",
    "pkgdesc",
    "pkgrel",
    "pkgver",
    "url",
];

/// Why a word with `*`, `?` or `[` in it is not the same everywhere.
const PATTERN: &str = "a pattern for file names, which depends on the files there";

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

/// Whether makepkg runs the lines of `function` that set a package's
/// attributes while it loads the recipe.
fn is_package(function: &str) -> bool {
    function == "package" || function.starts_with("package_")
}

fn is_attribute(name: &str) -> bool {
    let base = name.split_once('_').map_or(name, |(base, _)| base);
    ATTRIBUTES.contains(&name) || ATTRIBUTES.contains(&base) || super::CHECKSUMS.contains(&base)
}

/// Whether `text` is a whole number as written.
fn is_number(text: &str) -> bool {
    let digits = text.strip_prefix('-').unwrap_or(text);
    !digits.is_empty() && digits.len() < 18 && digits.chars().all(|c| c.is_ascii_digit())
}

/// Whether a word is written with no quoting and no expansion: a name bash
/// takes as it stands.
fn is_plain(text: &str) -> bool {
    text == "["
        || (!text.is_empty()
            && text
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "_-./+:@%,^=".contains(c)))
}

fn after(text: &str, at: usize) -> Option<char> {
    text.get(at..).and_then(|rest| rest.chars().next())
}

/// Where the backtick that ends a command substitution is in `text`.
fn backtick_end(text: &str) -> Option<usize> {
    escaped_end(text, '`')
}

/// Where the first `close` that no backslash keeps is in `text`.
fn escaped_end(text: &str, close: char) -> Option<usize> {
    let mut at = 0;
    while let Some(character) = after(text, at) {
        match character {
            _ if character == close => return Some(at),
            '\\' => at += 1 + after(text, at + 1).map_or(0, char::len_utf8),
            _ => at += character.len_utf8(),
        }
    }
    None
}

/// Where the double quote that ends a quotation is in `text`.
fn quote_end(text: &str) -> Option<usize> {
    let mut at = 0;
    while let Some(character) = after(text, at) {
        let rest = text.get(at + 1..)?;
        match character {
            '"' => return Some(at),
            '\\' => at += 1 + after(rest, 0).map_or(0, char::len_utf8),
            '`' => at += backtick_end(rest)? + 2,
            '$' if rest.starts_with('(') => at += closing(rest.get(1..)?, ')', false)? + 3,
            '$' if rest.starts_with('{') => at += closing(rest.get(1..)?, '}', true)? + 3,
            _ => at += character.len_utf8(),
        }
    }
    None
}

/// Where the `close` is that ends what was opened just before `text`
/// (`$(`, `${`, `[`), past the quotes and substitutions inside it.
/// `in_double`: within double quotes, where a single quote in `${...}` is
/// a character.
fn closing(text: &str, close: char, in_double: bool) -> Option<usize> {
    let open = match close {
        ')' => '(',
        ']' => '[',
        _ => '\0',
    };
    let mut depth = 0_usize;
    let mut at = 0;
    while let Some(character) = after(text, at) {
        let rest = text.get(at + 1..)?;
        match character {
            '\\' => at += 1 + after(rest, 0).map_or(0, char::len_utf8),
            '\'' if !(in_double && close == '}') => at += rest.find('\'')? + 2,
            '"' => at += quote_end(rest)? + 2,
            '`' => at += backtick_end(rest)? + 2,
            '$' if rest.starts_with('(') => at += closing(rest.get(1..)?, ')', false)? + 3,
            '$' if rest.starts_with('{') => at += closing(rest.get(1..)?, '}', in_double)? + 3,
            _ if character == close && depth == 0 => return Some(at),
            _ => {
                if character == open {
                    depth += 1;
                } else if character == close {
                    depth -= 1;
                }
                at += character.len_utf8();
            }
        }
    }
    None
}

/// `word` with its quotes taken off, when it holds nothing bash expands:
/// what a command given this word as a name gets.
fn literal(word: &str) -> Option<String> {
    let mut text = String::new();
    let mut characters = word.chars();
    let mut double = false;
    while let Some(character) = characters.next() {
        match character {
            '\'' if !double => text.extend(characters.by_ref().take_while(|next| *next != '\'')),
            '"' => double = !double,
            '\\' => text.extend(characters.next()),
            '$' | '`' => return None,
            '*' | '?' | '[' | '{' | '~' | '<' | '>' | '(' if !double => {
                // A subscript is part of a name; anything else is a pattern.
                if character != '[' || text.is_empty() {
                    return None;
                }
                text.push(character);
            }
            _ => text.push(character),
        }
    }
    Some(text)
}

/// `word` without its quotes and backslashes, whatever else it holds.
fn unquoted(word: &str) -> String {
    let mut text = String::new();
    let mut characters = word.chars();
    while let Some(character) = characters.next() {
        match character {
            '\'' | '"' => {}
            '\\' => text.extend(characters.next()),
            _ => text.push(character),
        }
    }
    text
}

/// A word that assigns: `name=value`, `name+=value`, `name[3]=value`.
struct Assignment<'a> {
    name: &'a str,
    subscript: Option<&'a str>,
    append: bool,
    value: &'a str,
}

impl<'a> Assignment<'a> {
    /// `text` as an assignment, the way bash sees one: the name and the
    /// `=` written without quotes.
    fn of(text: &'a str) -> Option<Self> {
        let length = text
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .count();
        let name = text.get(..length).filter(|name| is_name(name))?;
        let mut rest = text.get(length..)?;
        let mut subscript = None;
        if let Some(inner) = rest.strip_prefix('[') {
            let end = closing(inner, ']', false)?;
            subscript = inner.get(..end);
            rest = inner.get(end + 1..)?;
        }
        let append = rest.starts_with('+');
        let value = rest.get(usize::from(append)..)?.strip_prefix('=')?;
        Some(Self {
            name,
            subscript,
            append,
            value,
        })
    }
}

/// What Guardian knows of a variable's value.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Value {
    /// Written out: this text, wherever the recipe is loaded.
    Literal(String),
    /// Worked out from written-out values in a way Guardian does not
    /// repeat (`${pkgver%.*}`), with the same result wherever it is loaded.
    Derived,
    /// Depends on something that can differ between two runs, named here.
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

    /// The value of something worked out from this one and `other`.
    fn mixed(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unknown(why), _) | (_, Self::Unknown(why)) => Self::Unknown(why),
            _ => Self::Derived,
        }
    }

    fn unknown(&self) -> Option<&str> {
        match self {
            Self::Unknown(why) => Some(why),
            _ => None,
        }
    }

    fn empty() -> Self {
        Self::Literal(String::new())
    }
}

type Variables = HashMap<String, Value>;

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

/// How a command depends on what ran before it, and what its own result
/// depends on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Condition {
    Always,
    /// On values that are the same in the listing and the build (the
    /// machine's architecture, what the recipe wrote out), or once for
    /// each of a written-out list.
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

    /// The result of a command that read `value`.
    fn of(value: &Value) -> Self {
        match value {
            Value::Unknown(_) => Self::Open,
            _ => Self::Fixed,
        }
    }
}

/// Which of bash's expansions a word goes through where it stands.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// A command's word or an array's element: patterns match file names.
    Words,
    /// The value of a plain assignment: `~` is the home directory.
    Value,
    /// Text compared or cut (`[[ ... ]]`, `case`, `${x#...}`): neither.
    Text,
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

/// A function the recipe defines: its name, its body, and the lines the
/// body spans.
type Defined<'a> = (&'a str, &'a [Item], usize, usize);

/// Every function the recipe defines anywhere.
fn functions<'a>(items: &'a [Item], found: &mut Vec<Defined<'a>>) {
    for item in items {
        match &item.command {
            Command::Function { name, body, end } => {
                found.push((name, body, item.line(), *end));
                functions(body, found);
            }
            Command::Group(body)
            | Command::Subshell(body)
            | Command::For { body, .. }
            | Command::Other(_, body) => functions(body, found),
            Command::While(condition, body) => {
                functions(condition, found);
                functions(body, found);
            }
            Command::If(clauses, otherwise) => {
                for (condition, body) in clauses {
                    functions(condition, found);
                    functions(body, found);
                }
                functions(otherwise, found);
            }
            Command::Case(_, arms) => arms.iter().for_each(|(_, body)| functions(body, found)),
            Command::Simple(_) | Command::Test(_) | Command::Arithmetic(_) => {}
        }
    }
}

struct Reader<'a> {
    variables: Variables,
    /// Variables that hold a whole number, whatever it is: arithmetic on
    /// anything else can run what the value says.
    numbers: HashSet<String>,
    /// Arrays declared with names for keys, which are text, not arithmetic.
    keyed: HashSet<String>,
    /// The watched arrays written in plain words.
    arrays: Vec<(String, Vec<String>)>,
    derived: bool,
    reasons: Vec<String>,
    functions: HashMap<&'a str, Vec<&'a [Item]>>,
    /// makepkg's own functions, read when a command's name is first looked
    /// up.
    makepkg: std::cell::OnceCell<Option<Vec<String>>>,
    /// What the command being read depends on.
    condition: Condition,
    /// In a function the top level calls, or on a line of `package()` that
    /// makepkg runs after the recipe is loaded.
    late: bool,
    depth: usize,
    /// For each function being called, what its local variables held.
    locals: Vec<Vec<(String, Option<Value>)>>,
    /// Whether the recipe runs a program while it is loaded, which can
    /// make files.
    runs: bool,
    /// The first line with a pattern that reads as an address.
    address_pattern: Option<usize>,
}

impl<'a> Reader<'a> {
    fn new(items: &'a [Item]) -> (Self, Vec<Defined<'a>>) {
        let mut found = Vec::new();
        functions(items, &mut found);
        let mut defined: HashMap<&str, Vec<&[Item]>> = HashMap::new();
        for (name, body, ..) in &found {
            defined.entry(name).or_default().push(body);
        }
        let reader = Self {
            variables: Variables::new(),
            numbers: HashSet::new(),
            keyed: HashSet::new(),
            arrays: Vec::new(),
            derived: false,
            reasons: Vec::new(),
            functions: defined,
            makepkg: std::cell::OnceCell::new(),
            condition: Condition::Always,
            late: false,
            depth: 0,
            locals: Vec::new(),
            runs: false,
            address_pattern: None,
        };
        (reader, found)
    }

    fn not_followed(&mut self, line: usize, why: &str) {
        let reason = format!("line {line}: {why}");
        if self.reasons.len() < MAX_REASONS && !self.reasons.contains(&reason) {
            self.reasons.push(reason);
        }
    }

    fn set(&mut self, name: &str, value: Value) {
        self.numbers.remove(name);
        self.variables.insert(name.to_string(), value);
    }

    /// The value of the variable `name` where it is expanded.
    fn lookup(&self, name: &str) -> Value {
        if DYNAMIC.contains(&name) || name.starts_with("BASH") || name.starts_with("EPOCH") {
            return Value::Unknown(format!("${name}, which differs from one run to the next"));
        }
        match self.variables.get(name) {
            Some(value) => value.clone(),
            // makepkg takes the package base from the first package name.
            None if name == "pkgbase" && self.variables.contains_key("pkgname") => {
                self.lookup("pkgname")
            }
            None if CONFIGURED.contains(&name) => Value::Derived,
            None => Value::Unknown(format!("${name}, which the recipe does not set")),
        }
    }

    fn holds_number(&self, name: &str) -> bool {
        self.numbers.contains(name)
            || matches!(self.variables.get(name), Some(Value::Literal(text)) if is_number(text))
    }

    /// `word` as bash expands it, as far as Guardian follows: quotes
    /// removed and plain variables put in. What it sets or runs on the way
    /// is noted.
    fn expand(&mut self, line: usize, word: &str, mode: Mode) -> Value {
        let mut value = Value::empty();
        let mut double = false;
        // Whether the word is a pattern, and one that reads as an address.
        let mut pattern = None;
        let mut at = 0;
        while let Some(character) = after(word, at) {
            let start = at;
            at += character.len_utf8();
            let rest = word.get(at..).unwrap_or_default();
            let part = match character {
                '\'' if !double => {
                    let end = rest.find('\'').unwrap_or(rest.len());
                    at += end + 1;
                    Value::Literal(rest.get(..end).unwrap_or_default().to_string())
                }
                '"' => {
                    double = !double;
                    continue;
                }
                '\\' => {
                    let Some(next) = after(rest, 0) else { break };
                    at += next.len_utf8();
                    match next {
                        '\n' => continue,
                        _ if double && !"$`\"\\".contains(next) => {
                            Value::Literal(format!("\\{next}"))
                        }
                        _ => Value::Literal(next.to_string()),
                    }
                }
                '`' => {
                    at += backtick_end(rest).map_or(rest.len(), |end| end + 1);
                    self.runs = true;
                    Value::Unknown("a command's output".into())
                }
                '$' => {
                    let (part, used) = self.dollar(line, rest, double);
                    at += used;
                    part
                }
                '<' | '>' if !double && rest.starts_with('(') => {
                    self.not_followed(
                        line,
                        "a process substitution runs a command while the recipe is read",
                    );
                    at += closing(rest.get(1..).unwrap_or_default(), ')', false)
                        .map_or(rest.len(), |end| end + 2);
                    Value::Unknown("a command's output".into())
                }
                '*' | '?' | '[' if !double && mode == Mode::Words => {
                    let address = matches!(&value, Value::Literal(text) if text.contains("://"));
                    pattern = Some(pattern.unwrap_or(true) && address);
                    Value::Literal(character.to_string())
                }
                '~' if !double
                    && mode != Mode::Text
                    && (start == 0
                        || word.get(..start).is_some_and(|b| b.ends_with([':', '=']))) =>
                {
                    Value::Unknown("the home directory".into())
                }
                // A list in braces makes several words of one, always the
                // same ones.
                '{' if !double && mode == Mode::Words && rest.contains('}') => Value::Derived,
                _ => Value::Literal(character.to_string()),
            };
            value = value.join(part);
        }
        match pattern {
            // `git+https://host/repo?signed` matches a file only under a
            // directory named `git+https:`, which is there for the listing
            // as for the build unless the recipe makes it while it loads.
            Some(true) => {
                self.address_pattern.get_or_insert(line);
                value
            }
            Some(false) if value.unknown().is_none() => Value::Unknown(PATTERN.into()),
            _ => value,
        }
    }

    /// What follows a `$`: the value, and how much of `rest` it took.
    fn dollar(&mut self, line: usize, rest: &str, double: bool) -> (Value, usize) {
        let lost = || {
            (
                Value::Unknown("quoting Guardian does not follow".into()),
                rest.len(),
            )
        };
        let inner = rest.get(1..).unwrap_or_default();
        match after(rest, 0) {
            Some('(') => {
                let Some(end) = closing(inner, ')', false) else {
                    return lost();
                };
                let inside = inner.get(..end).unwrap_or_default();
                let arithmetic = inside
                    .strip_prefix('(')
                    .and_then(|text| text.strip_suffix(')'));
                let value = if let Some(arithmetic) = arithmetic {
                    self.arithmetic(line, arithmetic)
                } else {
                    self.runs = true;
                    Value::Unknown("a command's output".into())
                };
                (value, end + 2)
            }
            Some('{') => {
                let Some(end) = closing(inner, '}', double) else {
                    return lost();
                };
                let value = self.braced(line, inner.get(..end).unwrap_or_default());
                (value, end + 2)
            }
            Some('\'') if !double => {
                let end = escaped_end(inner, '\'').unwrap_or(inner.len());
                let text = inner.get(..end).unwrap_or_default();
                let value = if text.contains('\\') {
                    Value::Derived
                } else {
                    Value::Literal(text.to_string())
                };
                (value, (end + 2).min(rest.len()))
            }
            Some('"') if !double => (Value::Unknown("a translated text".into()), 0),
            Some('[') => {
                self.not_followed(line, "arithmetic in a form Guardian does not follow");
                let end = inner.find(']').map_or(rest.len(), |end| end + 2);
                (
                    Value::Unknown("arithmetic Guardian does not follow".into()),
                    end,
                )
            }
            Some(first) if first.is_ascii_alphabetic() || first == '_' => {
                let length = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .count();
                (self.lookup(rest.get(..length).unwrap_or_default()), length)
            }
            Some(first) if first.is_ascii_digit() || "@*#?$!-".contains(first) => {
                (Value::Unknown("a shell parameter".into()), 1)
            }
            _ => (Value::Literal("$".into()), 0),
        }
    }

    /// The value of `${inner}`.
    fn braced(&mut self, line: usize, inner: &str) -> Value {
        if is_name(inner) {
            return self.lookup(inner);
        }
        let indirect = inner.starts_with('!');
        let length = inner.starts_with('#') && inner.len() > 1;
        let body = inner
            .get(usize::from(indirect || length)..)
            .unwrap_or_default();
        let named = body
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .count();
        let name = body.get(..named).unwrap_or_default();
        let mut rest = body.get(named..).unwrap_or_default();
        let mut value = if is_name(name) {
            self.lookup(name)
        } else {
            Value::Unknown("a shell parameter".into())
        };
        let mut all = false;
        if let Some(inside) = rest.strip_prefix('[') {
            let Some(end) = closing(inside, ']', false) else {
                return Value::Unknown("quoting Guardian does not follow".into());
            };
            let subscript = inside.get(..end).unwrap_or_default();
            all = matches!(subscript, "@" | "*");
            value = value.mixed(self.subscript(line, name, subscript));
            rest = inside.get(end + 1..).unwrap_or_default();
        }
        if indirect {
            // `${!list[@]}` gives a list's positions; `${!name}` reads a
            // variable whose name is itself a value.
            return if all && rest.is_empty() {
                value
            } else {
                Value::Unknown("an indirect expansion".into())
            };
        }
        if length || rest.is_empty() {
            return value;
        }
        self.operation(line, name, rest, value)
    }

    /// `${name<rest>}` where `rest` cuts, replaces or supplies a value.
    fn operation(&mut self, line: usize, name: &str, rest: &str, value: Value) -> Value {
        let sets = rest.strip_prefix(":=").or_else(|| rest.strip_prefix('='));
        if let Some(given) = sets {
            let given = self.expand(line, given, Mode::Text);
            if is_watched(name) {
                self.not_followed(line, &format!("{name} is set inside an expansion"));
            }
            if matches!(&value, Value::Literal(text) if !text.is_empty()) || !is_name(name) {
                return value;
            }
            let mixed = value.mixed(given);
            self.set(name, mixed.clone());
            return mixed;
        }
        let supplies = [":-", "-", ":+", "+", ":?", "?"]
            .iter()
            .find_map(|operator| rest.strip_prefix(operator));
        if let Some(given) = supplies {
            return value.mixed(self.expand(line, given, Mode::Text));
        }
        match after(rest, 0) {
            Some('#' | '%' | '/' | '^' | ',') => {
                value.mixed(self.expand(line, rest.get(1..).unwrap_or_default(), Mode::Text))
            }
            Some(':') => {
                let mut value = value.mixed(Value::Derived);
                for part in rest.split(':').filter(|part| !part.trim().is_empty()) {
                    value = value.mixed(self.arithmetic(line, part));
                }
                value
            }
            Some('@') if matches!(rest, "@Q" | "@E" | "@U" | "@u" | "@L" | "@K" | "@k") => {
                value.mixed(Value::Derived)
            }
            _ => {
                self.not_followed(line, "an expansion in a form Guardian does not follow");
                Value::Unknown("an expansion Guardian does not follow".into())
            }
        }
    }

    /// What reading `name[subscript]` depends on.
    fn subscript(&mut self, line: usize, name: &str, subscript: &str) -> Value {
        if matches!(subscript, "@" | "*") {
            Value::empty()
        } else if self.keyed.contains(name) {
            self.expand(line, subscript, Mode::Text)
        } else {
            self.arithmetic(line, subscript)
        }
    }

    /// The names an arithmetic expression reads or sets, and whether it
    /// sets any. `None` where it holds a form Guardian does not follow.
    fn arithmetic_names(text: &str) -> Option<(Vec<&str>, bool)> {
        let mut names = Vec::new();
        let mut assigns = false;
        let mut at = 0;
        let mut previous = ' ';
        while let Some(character) = after(text, at) {
            let rest = text.get(at..)?;
            let mut length = character.len_utf8();
            match character {
                '`' | '\\' | '[' | ']' | '@' | '#' | '{' | '}' | '\'' => return None,
                '$' => {
                    let name = rest.get(1..)?;
                    if !name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
                        return None;
                    }
                }
                '=' => {
                    let compares = "=!<>".contains(previous)
                        && !text.get(..at)?.ends_with("<<")
                        && !text.get(..at)?.ends_with(">>");
                    if rest.starts_with("==") {
                        length = 2;
                    } else if !compares {
                        assigns = true;
                    }
                }
                '+' | '-' if rest.get(1..)?.starts_with(character) => {
                    assigns = true;
                    length = 2;
                }
                _ if character.is_ascii_alphabetic() || character == '_' => {
                    length = rest
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .count();
                    if !previous.is_ascii_digit() {
                        names.push(rest.get(..length)?);
                    }
                }
                _ => {}
            }
            previous = character;
            at += length;
        }
        Some((names, assigns))
    }

    /// What an arithmetic expression gives. It may hold whole numbers and
    /// variables that hold one: bash evaluates any other value as an
    /// expression of its own, which can set a variable or run a command.
    fn arithmetic(&mut self, line: usize, text: &str) -> Value {
        let text = text.trim().trim_matches('"');
        if text.contains("$(") || text.contains('`') {
            self.runs = true;
            self.not_followed(
                line,
                "arithmetic on a command's output, which bash evaluates",
            );
            return Value::Unknown("a command's output".into());
        }
        // `${#list[@]}` is a count, and `${name}` is `$name`.
        let mut value = Value::Derived;
        let mut plain = String::new();
        let mut rest = text;
        while let Some((before, more)) = rest.split_once("${") {
            let (inner, more) = more.split_once('}').unwrap_or((more, ""));
            plain.push_str(before);
            let counted = inner
                .strip_prefix('#')
                .map(|name| name.trim_end_matches("[@]").trim_end_matches("[*]"));
            match counted {
                Some(name) if is_name(name) => {
                    plain.push('0');
                    value = value.mixed(self.lookup(name));
                }
                None if is_name(inner) => {
                    plain.push('$');
                    plain.push_str(inner);
                }
                _ => plain.push('{'),
            }
            rest = more;
        }
        plain.push_str(rest);
        let Some((names, assigns)) = Self::arithmetic_names(&plain) else {
            self.not_followed(line, "arithmetic in a form Guardian does not follow");
            return Value::Unknown("arithmetic Guardian does not follow".into());
        };
        for name in &names {
            if is_watched(name) {
                self.not_followed(line, &format!("{name} is used in arithmetic"));
            } else if self.holds_number(name) {
                value = value.mixed(self.lookup(name));
            } else {
                self.not_followed(
                    line,
                    &format!("arithmetic on ${name}, which is not a plain number"),
                );
                value = Value::Unknown(format!("arithmetic on ${name}"));
            }
        }
        if assigns {
            for name in names {
                let set = if self.condition == Condition::Open {
                    Value::Unknown(format!("${name}, set under a condition"))
                } else {
                    value.clone()
                };
                self.set(name, set);
                self.numbers.insert(name.to_string());
            }
        }
        value
    }

    /// `[[ ... ]]`, `[ ... ]` or `test`: what its result depends on. A
    /// comparison of written-out values is the same everywhere; a look at
    /// a file is not.
    fn test(&mut self, line: usize, words: &[Word], mode: Mode) -> Condition {
        let mut status = Condition::Fixed;
        for (index, word) in words.iter().enumerate() {
            let text = word.text.as_str();
            let operator = text.len() <= 3
                && text.starts_with('-')
                && text.len() > 1
                && text.chars().skip(1).all(|c| c.is_ascii_alphabetic());
            match text {
                // `[[` evaluates what it compares as numbers; `[` only
                // reads them.
                "-eq" | "-ne" | "-lt" | "-le" | "-gt" | "-ge" if mode == Mode::Text => {
                    let before = index.checked_sub(1).and_then(|at| words.get(at));
                    for operand in before.into_iter().chain(words.get(index + 1)) {
                        let value = self.arithmetic(line, &operand.text);
                        status = status.and(Condition::of(&value));
                    }
                }
                "]" | "==" | "=" | "!=" | "!" | "&&" | "||" | "(" | ")" | "<" | ">" | "=~"
                | "-z" | "-n" | "-eq" | "-ne" | "-lt" | "-le" | "-gt" | "-ge" => {}
                _ if operator => status = Condition::Open,
                _ => {
                    let value = self.expand(line, text, mode);
                    status = status.and(Condition::of(&value));
                }
            }
        }
        status
    }

    /// An array assignment: `name=(` or `name+=(`, then its elements.
    fn array(&mut self, word: &Word) -> Condition {
        let line = word.line;
        let target = word.text.strip_suffix("=(").unwrap_or(&word.text);
        let (target, append) = match target.strip_suffix('+') {
            Some(target) => (target, true),
            None => (target, false),
        };
        let name = target.split('[').next().unwrap_or(target);
        let open = self.condition == Condition::Open || self.late;
        let elements: Vec<Value> = word
            .elements
            .iter()
            .flatten()
            .map(|element| self.expand(element.line, &element.text, Mode::Words))
            .collect();
        let unknown = elements
            .iter()
            .find_map(|value| value.unknown().map(str::to_string));
        let status = if unknown.is_some() {
            Condition::Open
        } else {
            Condition::Fixed
        };
        // What is added to a value that can differ can differ too.
        let before = self.variables.get(name).filter(|_| append).cloned();
        if !is_watched(name) {
            let value = match (unknown, before, elements.first()) {
                (Some(why), ..) | (None, Some(Value::Unknown(why)), _) => Value::Unknown(why),
                (None, ..) if open => Value::Unknown(format!("${name}, set under a condition")),
                // `$name` is the array's first element.
                (None, None, Some(Value::Literal(first)))
                    if !append && target == name && self.condition == Condition::Always =>
                {
                    Value::Literal(first.clone())
                }
                _ => Value::Derived,
            };
            self.set(name, value);
            return status;
        }
        // Later words may read it (`noextract=("${source[@]##*/}")`).
        let unknown =
            unknown.or_else(|| before.and_then(|value| value.unknown().map(str::to_string)));
        self.set(name, unknown.clone().map_or(Value::Derived, Value::Unknown));
        if !is_listed(name) {
            self.not_followed(
                line,
                &format!("{name} is set, which changes how or where makepkg fetches"),
            );
        } else if let Some(why) = unknown {
            self.not_followed(line, &format!("{name} is built from {why}"));
        } else if open {
            self.not_followed(
                line,
                &format!("{name} is set under a condition or inside a function"),
            );
        } else {
            let written: Option<Vec<String>> = elements
                .into_iter()
                .map(|value| match value {
                    Value::Literal(text) => Some(text),
                    _ => None,
                })
                .collect();
            let again = self.arrays.iter().any(|(known, _)| known == name);
            match written {
                Some(words) if !append && !again && self.condition == Condition::Always => {
                    self.arrays.push((name.to_string(), words));
                }
                _ => self.derived = true,
            }
        }
        status
    }

    /// A plain assignment, `name=value`.
    fn scalar(&mut self, line: usize, assignment: &Assignment<'_>) -> Condition {
        let name = assignment.name;
        let given = self.expand(line, assignment.value, Mode::Value);
        let status = Condition::of(&given);
        if is_watched(name) {
            // One element set by its number, always and to a value that is
            // the same everywhere (`sha256sums[2]=SKIP`), is worked out
            // like any other; nothing else is followed.
            let numbered = assignment
                .subscript
                .is_some_and(|subscript| !subscript.is_empty() && is_number(subscript));
            let fixed = numbered
                && is_listed(name)
                && !assignment.append
                && !self.late
                && self.condition != Condition::Open
                && given.unknown().is_none();
            if fixed {
                self.derived = true;
            } else {
                self.not_followed(
                    line,
                    &format!("{name} is set in a form other than a plain array"),
                );
            }
            return status;
        }
        let mut value = given;
        if let Some(subscript) = assignment.subscript {
            value = value.mixed(self.subscript(line, name, subscript));
        }
        if assignment.append {
            value = value.mixed(self.lookup(name));
        }
        let plain = self.condition == Condition::Always && !self.late;
        let value = match value {
            Value::Unknown(why) => Value::Unknown(why),
            _ if self.condition == Condition::Open || self.late => {
                Value::Unknown(format!("${name}, set under a condition"))
            }
            Value::Literal(text) if plain => Value::Literal(text),
            _ => Value::Derived,
        };
        self.set(name, value);
        // A count or a sum is a number, whatever it comes to.
        let text = assignment.value.trim_matches('"');
        let whole = |open: &str, close: char| {
            text.strip_prefix(open)
                .is_some_and(|rest| closing(rest, close, false) == Some(rest.len() - 1))
        };
        let summed = text.starts_with("$((") && text.ends_with("))") && whole("$(", ')');
        if (whole("${#", '}') || summed) && !text[1..].contains("$(") {
            self.numbers.insert(name.to_string());
        }
        status
    }

    /// A plain command: the assignments before it, then the command with
    /// its words.
    fn simple(&mut self, words: &[Word]) -> Condition {
        let mut status = Condition::Fixed;
        let mut set = Vec::new();
        let mut rest = words;
        while let Some((word, more)) = rest.split_first() {
            if word.elements.is_some() {
                status = status.and(self.array(word));
                set.push(word.text.split(['=', '+', '[']).next().unwrap_or_default());
            } else if let Some(assignment) = Assignment::of(&word.text) {
                status = status.and(self.scalar(word.line, &assignment));
                set.push(assignment.name);
            } else {
                break;
            }
            rest = more;
        }
        let Some((command, operands)) = rest.split_first() else {
            return status;
        };
        // Set before a command, they last as long as it runs.
        for name in set {
            if is_watched(name) {
                self.not_followed(command.line, &format!("{name} is set for one command only"));
            } else {
                self.set(
                    name,
                    Value::Unknown(format!("${name}, set for one command only")),
                );
            }
        }
        self.run(command, operands, true)
    }

    fn expand_all(&mut self, words: &[Word]) {
        for word in words {
            match &word.elements {
                Some(_) => {
                    self.array(word);
                }
                None => {
                    self.expand(word.line, &word.text, Mode::Words);
                }
            }
        }
    }

    /// The command `command` with its `operands`: what its result depends
    /// on. `functions`: whether a function of the recipe may answer to the
    /// name (not after `command` or `builtin`).
    fn run(&mut self, command: &Word, operands: &[Word], functions: bool) -> Condition {
        let line = command.line;
        let name = command.text.as_str();
        if !is_plain(name) || name.contains('=') {
            self.not_followed(
                line,
                "a command is named by a variable or in quotes, which Guardian does not follow",
            );
            return Condition::Open;
        }
        if functions && self.functions.contains_key(name) {
            self.call(line, name);
            return Condition::Open;
        }
        match name {
            ":" | "true" | "false" => {
                self.expand_all(operands);
                return Condition::Fixed;
            }
            "[" | "test" => return self.test(line, operands, Mode::Words),
            "shopt" | "set" => {
                let known = if name == "set" {
                    SET_OPTIONS
                } else {
                    PATTERN_OPTIONS
                };
                if operands
                    .iter()
                    .any(|word| !known.contains(&word.text.as_str()))
                {
                    self.not_followed(line, &format!("`{name}` changes how bash reads the recipe"));
                }
                return Condition::Fixed;
            }
            "command" | "builtin" => return self.prefixed(name, operands),
            "unset" => self.unset(line, operands),
            "let" => {
                for word in operands {
                    self.arithmetic(line, &unquoted(&word.text));
                }
            }
            "printf" | "wait" | "read" | "mapfile" | "readarray" | "getopts" => {
                self.assigner(line, name, operands);
            }
            "exit" | "return" | "break" | "continue" => self.leaves(line, name),
            "exec" if operands.is_empty() => {}
            _ if DECLARING.contains(&name) => self.declare(line, name, operands),
            _ if CONTROL.contains(&name) || name == "exec" => self.not_followed(
                line,
                &format!("`{name}` runs or reads in code Guardian does not follow"),
            ),
            _ => {
                self.runs = true;
                self.expand_all(operands);
                if !(BUILTINS.contains(&name) || MESSAGES.contains(&name) || name.contains('/'))
                    && self.is_makepkg_function(name)
                {
                    self.not_followed(
                        line,
                        &format!("{name}() is one of makepkg's own functions, which Guardian does not follow"),
                    );
                }
            }
        }
        Condition::Open
    }

    fn is_makepkg_function(&self, name: &str) -> bool {
        self.makepkg
            .get_or_init(makepkg_functions)
            .as_ref()
            .is_none_or(|known| known.iter().any(|known| known == name))
    }

    /// `command name ...` or `builtin name ...`: the command itself, past
    /// any function of that name.
    fn prefixed(&mut self, prefix: &str, operands: &[Word]) -> Condition {
        let mut rest = operands;
        while let Some((first, more)) = rest.split_first() {
            match first.text.as_str() {
                // Asks whether a command is there.
                "-v" | "-V" if prefix == "command" => {
                    self.expand_all(more);
                    return Condition::Open;
                }
                "-p" | "--" => rest = more,
                _ => return self.run(first, more, false),
            }
        }
        Condition::Open
    }

    /// `exit`, `return`, `break` or `continue`: what follows it does not
    /// run.
    fn leaves(&mut self, line: usize, name: &str) {
        let stops = matches!(name, "exit" | "return");
        if stops && !self.late {
            self.not_followed(line, &format!("`{name}` stops the recipe before its end"));
        } else if self.condition == Condition::Open {
            self.not_followed(
                line,
                &format!("`{name}` under a condition leaves out what follows it"),
            );
        }
    }

    /// `unset`: the variables it is given are gone.
    fn unset(&mut self, line: usize, operands: &[Word]) {
        for word in operands {
            if matches!(word.text.as_str(), "-v" | "-f" | "-n") {
                continue;
            }
            let Some(plain) = literal(&word.text) else {
                self.not_followed(line, "unset is given a name Guardian cannot read");
                continue;
            };
            let name = plain.split('[').next().unwrap_or_default();
            if is_watched(name) {
                self.not_followed(line, &format!("unset sets {name}"));
            } else if self.functions.contains_key(name) {
                self.not_followed(line, &format!("unset removes the function {name}()"));
            } else if is_name(name) {
                let value = match self.condition {
                    Condition::Always if name == plain => Value::empty(),
                    Condition::Open => Value::Unknown(format!("${name}, set under a condition")),
                    _ => Value::Derived,
                };
                self.set(name, value);
            }
        }
    }

    /// `declare`, `local`, `export` and the like: each word after the
    /// options is a name, or an assignment.
    fn declare(&mut self, line: usize, command: &str, operands: &[Word]) {
        let local = matches!(command, "local" | "declare" | "typeset");
        let (mut global, mut keyed, mut functions) = (false, false, false);
        for word in operands {
            let text = word.text.as_str();
            if text.starts_with(['-', '+']) && word.elements.is_none() {
                if !is_plain(text) {
                    self.not_followed(
                        line,
                        &format!("{command} is given options Guardian cannot read"),
                    );
                } else if local && text.contains('n') {
                    self.not_followed(line, "a variable is made a reference to another");
                } else if local && text.contains('i') {
                    self.not_followed(line, "a variable is made to evaluate what it is given");
                }
                global |= text.contains('g');
                keyed |= text.contains('A');
                functions |= text.contains(['f', 'F']);
                continue;
            }
            let assignment = Assignment::of(text);
            let name = match (&word.elements, &assignment) {
                (Some(_), _) => text.split(['=', '+', '[']).next().unwrap_or_default(),
                (None, Some(assignment)) => assignment.name,
                (None, None) => text,
            };
            if functions {
                continue;
            }
            if !is_name(name) {
                self.not_followed(
                    line,
                    &format!("{command} assigns to a variable named by another"),
                );
                continue;
            }
            if local
                && !global
                && let Some(frame) = self.locals.last_mut()
            {
                frame.push((name.to_string(), self.variables.get(name).cloned()));
            }
            if keyed {
                self.keyed.insert(name.to_string());
            }
            match (&word.elements, assignment) {
                // Declared without a value, it keeps the one it has.
                (Some(_), _) | (None, None) if is_watched(name) => {
                    self.not_followed(line, &format!("{command} sets {name}"));
                }
                (Some(_), _) => {
                    self.array(word);
                }
                (None, Some(assignment)) => {
                    self.scalar(line, &assignment);
                }
                (None, None) => {}
            }
        }
    }

    /// A command that assigns to the variables it is given by name
    /// (`read`, `printf -v`, `mapfile`, `getopts`, `wait -p`).
    fn assigner(&mut self, line: usize, command: &str, operands: &[Word]) {
        // The options that take a value, the one whose value is a variable
        // to set, and whether the words after the options are variables.
        let (valued, naming, named) = match command {
            "read" => ("adinNptu", Some('a'), true),
            "mapfile" | "readarray" => ("dnOsuCc", None, true),
            "printf" => ("v", Some('v'), false),
            "wait" => ("p", Some('p'), false),
            _ => ("", None, false),
        };
        let mut targets: Vec<&Word> = Vec::new();
        let mut glued: Vec<String> = Vec::new();
        let mut others: Vec<&Word> = Vec::new();
        let mut words = operands.iter();
        let mut options = true;
        while let Some(word) = words.next() {
            let text = word.text.as_str();
            if !(options && text.len() > 1 && text.starts_with('-')) {
                options = false;
                if named {
                    targets.push(word);
                } else {
                    others.push(word);
                }
                continue;
            }
            if !is_plain(text) {
                return self.not_followed(
                    line,
                    &format!("{command} is given options Guardian cannot read"),
                );
            }
            if text == "--" {
                options = false;
                continue;
            }
            if matches!(command, "mapfile" | "readarray") && text.contains('C') {
                return self
                    .not_followed(line, &format!("{command} runs a command for what it reads"));
            }
            // An option that takes a value takes the rest of its word, or
            // the next word.
            let Some(at) = text.find(|c: char| valued.contains(c)) else {
                continue;
            };
            let names = text.get(at..).and_then(|rest| rest.chars().next()) == naming;
            match (text.get(at + 1..).filter(|rest| !rest.is_empty()), names) {
                (Some(rest), true) => glued.push(rest.to_string()),
                (Some(_), false) => {}
                (None, true) => targets.extend(words.next()),
                (None, false) => others.extend(words.next()),
            }
        }
        if command == "getopts" {
            targets.extend(others.get(1).copied());
        }
        for word in others {
            self.expand(word.line, &word.text, Mode::Words);
        }
        let targets = targets
            .into_iter()
            .map(|word| word.text.clone())
            .chain(glued);
        for target in targets.collect::<Vec<_>>() {
            let plain = literal(&target).unwrap_or_default();
            let name = plain.split('[').next().unwrap_or_default();
            if is_watched(name) {
                self.not_followed(line, &format!("{command} sets {name}"));
            } else if is_name(name) {
                self.set(name, Value::Unknown(format!("${name}, set by {command}")));
            } else {
                self.not_followed(
                    line,
                    &format!("{command} assigns to a variable named by another"),
                );
            }
        }
    }

    /// A call of a function the recipe defines: its body is read as part
    /// of the top level.
    fn call(&mut self, line: usize, name: &str) {
        if self.depth >= 4 {
            return self.not_followed(line, "functions call each other too deep to follow");
        }
        if is_standard(name) {
            return self.not_followed(
                line,
                &format!("{name}() is called while the recipe is loaded"),
            );
        }
        let bodies = self.functions.get(name).cloned().unwrap_or_default();
        let [body] = bodies.as_slice() else {
            return self.not_followed(line, &format!("{name}() is defined more than once"));
        };
        let late = std::mem::replace(&mut self.late, true);
        self.depth += 1;
        self.locals.push(Vec::new());
        self.list(body, self.condition);
        // What it declared for itself is gone when it returns.
        for (local, before) in self.locals.pop().unwrap_or_default().into_iter().rev() {
            match before {
                Some(value) => self.set(&local, value),
                None => {
                    self.variables.remove(&local);
                }
            }
        }
        self.depth -= 1;
        self.late = late;
    }

    /// What every variable is known as, to see whether a loop's next round
    /// reads other values than the one before.
    fn known(&self) -> BTreeMap<String, u8> {
        self.variables
            .iter()
            .map(|(name, value)| {
                let kind = match value {
                    Value::Literal(_) => 0,
                    Value::Derived => 1,
                    Value::Unknown(_) => 2,
                };
                (name.clone(), kind)
            })
            .collect()
    }

    /// Reads a loop's commands until another round changes nothing: what
    /// one round sets, the next one reads.
    fn rounds(&mut self, line: usize, mut round: impl FnMut(&mut Self)) {
        for _ in 0..6 {
            let before = self.known();
            round(self);
            if self.known() == before {
                return;
            }
        }
        self.not_followed(line, "a loop Guardian does not follow to its end");
    }

    /// A `for` loop: its variable takes each of the words it runs over.
    fn for_loop(&mut self, name: &Word, list: Option<&[Word]>, body: &[Item]) {
        let line = name.line;
        let mut under = self.condition.and(Condition::Fixed);
        // Without a list it runs over the arguments.
        let mut value = match list {
            Some(_) => Value::Derived,
            None => Value::Unknown("a shell parameter".into()),
        };
        for word in list.into_iter().flatten() {
            value = value.mixed(self.expand(word.line, &word.text, Mode::Words));
        }
        under = under.and(Condition::of(&value));
        if is_watched(&name.text) {
            self.not_followed(line, &format!("a loop sets {}", name.text));
        } else if !is_name(&name.text) {
            self.not_followed(line, "a loop sets a variable named by another");
        }
        let numbers = list.is_some_and(|list| {
            list.iter().all(|word| {
                let text = word.text.trim_matches('"');
                let positions = text
                    .strip_prefix("${!")
                    .and_then(|rest| rest.strip_suffix("[@]}"))
                    .is_some_and(|array| is_name(array) && !self.keyed.contains(array));
                is_number(text) || positions
            })
        });
        self.rounds(line, |reader| {
            reader.set(&name.text, value.clone());
            if numbers {
                reader.numbers.insert(name.text.clone());
            }
            reader.list(body, under);
        });
    }

    fn command(&mut self, command: &Command, line: usize) -> Condition {
        match command {
            Command::Simple(words) => return self.simple(words),
            Command::Test(words) => return self.test(line, words, Mode::Text),
            Command::Arithmetic(word) => {
                let inner = word
                    .text
                    .strip_prefix("((")
                    .and_then(|text| text.strip_suffix("))"));
                let Some(inner) = inner else {
                    self.not_followed(line, "arithmetic in a form Guardian does not follow");
                    return Condition::Open;
                };
                return Condition::of(&self.arithmetic(line, inner));
            }
            Command::Group(items) => {
                self.list(items, self.condition);
            }
            // What a subshell sets is gone when it ends.
            Command::Subshell(items) => {
                self.list(items, Condition::Open);
            }
            Command::If(clauses, otherwise) => {
                let mut under = self.condition;
                for (condition, body) in clauses {
                    let result = self.list(condition, under);
                    under = under.and(Condition::Fixed).and(result);
                    self.list(body, under);
                }
                self.list(otherwise, under);
            }
            Command::While(condition, body) => {
                let under = self.condition;
                self.rounds(line, |reader| {
                    let result = reader.list(condition, under);
                    reader.list(body, under.and(Condition::Fixed).and(result));
                });
            }
            Command::For { name, list, body } => self.for_loop(name, list.as_deref(), body),
            Command::Case(word, arms) => {
                let value = self.expand(word.line, &word.text, Mode::Text);
                let mut under = self.condition.and(Condition::of(&value));
                for (patterns, body) in arms {
                    for pattern in patterns {
                        let value = self.expand(pattern.line, &pattern.text, Mode::Text);
                        under = under.and(Condition::of(&value));
                    }
                    self.list(body, under);
                }
            }
            Command::Function { .. } => return Condition::Fixed,
            Command::Other(what, _) => {
                self.not_followed(
                    line,
                    &format!("`{what}` is a form Guardian does not follow"),
                );
            }
        }
        Condition::Open
    }

    /// Reads `items` under `condition`. What comes back is what their
    /// results depend on, taken together.
    fn list(&mut self, items: &[Item], condition: Condition) -> Condition {
        let mut all = Condition::Fixed;
        let mut chain = Condition::Fixed;
        for (index, item) in items.iter().enumerate() {
            let piped = item.join == Join::Pipe
                || items
                    .get(index + 1)
                    .is_some_and(|next| next.join == Join::Pipe);
            let mut under = if item.join == Join::Sequence {
                chain = Condition::Fixed;
                condition
            } else {
                condition.and(chain)
            };
            // Beside the shell that reads the recipe: what it sets is gone.
            if piped || item.background {
                under = Condition::Open;
            }
            let saved = std::mem::replace(&mut self.condition, under);
            for (target, expands) in &item.redirects {
                if *expands {
                    self.not_followed(target.line, "a here-document holds what bash expands");
                }
                self.expand(target.line, &target.text, Mode::Words);
            }
            let status = self.command(&item.command, item.line());
            self.condition = saved;
            chain = chain.and(status);
            all = all.and(status);
        }
        all
    }

    /// The lines of a `package()` function that makepkg runs while it
    /// loads the recipe: those that start by setting one of a package's
    /// attributes. It runs each whole line, so what else stands on it is
    /// read as top-level code. `started` gets the lines read this way.
    fn attribute_lines(&mut self, items: &[Item], started: &mut HashSet<usize>) {
        let mut index = 0;
        while let Some(item) = items.get(index) {
            let end = items
                .iter()
                .skip(index + 1)
                .position(|next| next.join == Join::Sequence)
                .map_or(items.len(), |more| index + 1 + more);
            if let Command::Simple(words) = &item.command
                && let Some((first, rest)) = words.split_first()
                && is_attribute(first.text.split(['=', '+', '[']).next().unwrap_or_default())
                && (first.elements.is_some() || Assignment::of(&first.text).is_some())
            {
                started.insert(first.line);
                let late = std::mem::replace(&mut self.late, true);
                let saved = std::mem::replace(&mut self.condition, Condition::Fixed);
                // makepkg puts the attribute itself in a variable of its
                // own; the rest of the line runs as written.
                match (&first.elements, Assignment::of(&first.text)) {
                    (Some(elements), _) => self.expand_all(elements),
                    (None, Some(assignment)) => {
                        self.expand(first.line, assignment.value, Mode::Value);
                    }
                    (None, None) => {}
                }
                self.simple(rest);
                for (target, _) in &item.redirects {
                    self.expand(target.line, &target.text, Mode::Words);
                }
                self.list(
                    items.get(index + 1..end).unwrap_or_default(),
                    Condition::Open,
                );
                self.condition = saved;
                self.late = late;
            }
            index = end;
        }
        for item in items {
            match &item.command {
                Command::Group(body)
                | Command::Subshell(body)
                | Command::For { body, .. }
                | Command::Function { body, .. }
                | Command::Other(_, body) => self.attribute_lines(body, started),
                Command::While(condition, body) => {
                    self.attribute_lines(condition, started);
                    self.attribute_lines(body, started);
                }
                Command::If(clauses, otherwise) => {
                    for (condition, body) in clauses {
                        self.attribute_lines(condition, started);
                        self.attribute_lines(body, started);
                    }
                    self.attribute_lines(otherwise, started);
                }
                Command::Case(_, arms) => {
                    for (_, body) in arms {
                        self.attribute_lines(body, started);
                    }
                }
                Command::Simple(_) | Command::Test(_) | Command::Arithmetic(_) => {}
            }
        }
    }

    /// The lines of text inside `package()` that makepkg takes for an
    /// attribute though no command starts there: a line of a
    /// here-document or of a text over several lines. It finds them in
    /// the function as bash prints it, where such text stands as written.
    fn attribute_text(&mut self, recipe: &str, from: usize, to: usize, started: &HashSet<usize>) {
        let lines = recipe
            .lines()
            .enumerate()
            .skip(from)
            .take(to.saturating_sub(from));
        for (index, text) in lines {
            let line = index + 1;
            let trimmed = text.trim_start();
            let name = trimmed.split(['=', '+']).next().unwrap_or_default();
            let sets = trimmed
                .get(name.len()..)
                .is_some_and(|rest| rest.starts_with('=') || rest.starts_with("+="));
            if started.contains(&line)
                || trimmed.len() == text.len()
                || !is_attribute(name)
                || !sets
            {
                continue;
            }
            let (tokens, unsure) = lex::tokens(text);
            match parse::commands(tokens) {
                Ok(items) if unsure.is_empty() => {
                    let before = self.reasons.len();
                    self.attribute_lines(&items, &mut HashSet::new());
                    // The line numbers inside the piece count from one.
                    for reason in self.reasons.iter_mut().skip(before) {
                        let why = reason.split_once(": ").map_or("", |(_, why)| why);
                        *reason = format!("line {line}: {why}");
                    }
                }
                _ => self.not_followed(
                    line,
                    "a line inside package() that makepkg runs while it loads the recipe",
                ),
            }
        }
    }
}

/// A recipe read as commands, or the reason it is not followed.
fn commands(recipe: &str) -> Result<(Vec<Item>, Vec<usize>), String> {
    let (tokens, unsure) = lex::tokens(recipe);
    match parse::commands(tokens) {
        Ok(items) => Ok((items, unsure)),
        Err(line) => Err(format!(
            "line {line}: Guardian does not read the recipe's shell as bash does from here"
        )),
    }
}

/// Classifies how `recipe` arrives at its sources (see `Sources`).
pub fn sources(recipe: &str) -> Sources {
    let (items, unsure) = match commands(recipe) {
        Ok(read) => read,
        Err(why) => return Sources::NotFollowed(vec![why]),
    };
    let (mut reader, defined) = Reader::new(&items);
    for line in unsure {
        reader.not_followed(
            line,
            "quoting Guardian may read otherwise than the shell does",
        );
    }
    // A function under another name can stand in for a command makepkg
    // itself runs between loading the recipe and fetching the sources.
    for (name, ..) in &defined {
        // One of bash's commands, a program, or one of makepkg's own
        // functions; where those cannot be read, any name may be one.
        let shadows = BUILTINS.contains(name)
            || std::path::Path::new("/usr/bin").join(name).exists()
            || reader.is_makepkg_function(name);
        if !is_standard(name) && shadows {
            let reason =
                format!("the recipe defines {name}(), which stands in for a command makepkg runs");
            if !reader.reasons.contains(&reason) {
                reader.reasons.push(reason);
            }
        }
    }
    reader.list(&items, Condition::Always);
    for (name, body, from, to) in defined {
        if is_package(name) {
            let mut started = HashSet::new();
            reader.attribute_lines(body, &mut started);
            reader.attribute_text(recipe, from, to, &started);
        }
    }
    if let Some(line) = reader.address_pattern.filter(|_| reader.runs) {
        reader.not_followed(
            line,
            &format!("a source is {PATTERN}, and the recipe runs commands"),
        );
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
    let Ok((items, _)) = commands(recipe) else {
        return Vec::new();
    };
    let (mut reader, _) = Reader::new(&items);
    reader.list(&items, Condition::Always);
    let mut written: Vec<(String, String)> = reader
        .variables
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

/// Whether `text` holds `name` as a whole word that is not being expanded
/// (`$NAME`, `${NAME...}`).
fn names_bare(text: &str, name: &str) -> bool {
    let word = |character: char| character.is_ascii_alphanumeric() || character == '_';
    text.match_indices(name).any(|(index, _)| {
        let before = text[..index].chars().next_back();
        let after = text[index + name.len()..].chars().next();
        !before.is_some_and(|character| word(character) || character == '$' || character == '{')
            && !after.is_some_and(word)
    })
}

/// The names `top_level_naming` looks for.
pub struct Naming<'a> {
    /// Variables that may not be assigned.
    pub set: &'a [&'a str],
    /// Variables that may not be given by name to one of `assigners`.
    pub given: &'a [&'a str],
    pub assigners: &'a [&'a str],
}

/// The lines outside any function where `items` name what `names` holds.
fn naming_lines(items: &[Item], names: &Naming<'_>, found: &mut Vec<usize>) {
    for item in items {
        match &item.command {
            Command::Simple(words) => {
                let texts: Vec<String> = words.iter().map(|word| unquoted(&word.text)).collect();
                let assigned = texts.iter().any(|text| {
                    let name = text.split(['=', '+', '[']).next().unwrap_or_default();
                    text.contains('=') && names.set.contains(&name)
                });
                // A name given to a command that assigns (`printf -v`,
                // `read`), or to one named by a variable.
                let mut command = texts
                    .iter()
                    .skip_while(|text| Assignment::of(text).is_some() || text.ends_with("=("))
                    .skip_while(|text| {
                        matches!(text.as_str(), "command" | "builtin" | "-p" | "--")
                    });
                let assigns = command.next().is_some_and(|text| {
                    names.assigners.contains(&text.as_str()) || text.contains(['$', '`'])
                });
                let given = assigns
                    && command.any(|text| names.given.iter().any(|name| names_bare(text, name)));
                if assigned || given {
                    found.extend(words.first().map(|word| word.line));
                }
            }
            Command::For { name, body, .. } => {
                if names.set.contains(&unquoted(&name.text).as_str()) {
                    found.push(name.line);
                }
                naming_lines(body, names, found);
            }
            Command::Group(body) | Command::Subshell(body) | Command::Other(_, body) => {
                naming_lines(body, names, found);
            }
            Command::While(condition, body) => {
                naming_lines(condition, names, found);
                naming_lines(body, names, found);
            }
            Command::If(clauses, otherwise) => {
                for (condition, body) in clauses {
                    naming_lines(condition, names, found);
                    naming_lines(body, names, found);
                }
                naming_lines(otherwise, names, found);
            }
            Command::Case(_, arms) => {
                for (_, body) in arms {
                    naming_lines(body, names, found);
                }
            }
            Command::Function { .. } | Command::Test(_) | Command::Arithmetic(_) => {}
        }
    }
}

/// The lines of `recipe`, outside its functions, that set one of the
/// variables in `names` or give one to a command that assigns, however the
/// name is quoted (`declare BUILD''DIR=x`, `printf -v "SRCDEST"`). `None`
/// where the recipe is not read as commands.
pub fn top_level_naming(recipe: &str, names: &Naming<'_>) -> Option<Vec<usize>> {
    let (items, _) = commands(recipe).ok()?;
    let mut found = Vec::new();
    naming_lines(&items, names, &mut found);
    found.sort_unstable();
    found.dedup();
    Some(found)
}

#[cfg(test)]
mod tests {
    use super::lex::{Token, tokens};
    use super::{Naming, Sources, sources, top_level_naming, written_variables};

    fn written(recipe: &str) -> Vec<(String, Vec<String>)> {
        match sources(recipe) {
            Sources::Written(arrays) => arrays,
            other => panic!("{recipe:?}: {other:?}"),
        }
    }

    /// The words of each command, an array's elements after its name.
    fn words(recipe: &str) -> Vec<Vec<String>> {
        let mut commands = vec![Vec::new()];
        for token in tokens(recipe).0 {
            match token {
                Token::Word(word) => {
                    let elements = word.elements.unwrap_or_default();
                    let last = commands.last_mut().unwrap();
                    last.push(word.text);
                    last.extend(elements.into_iter().map(|element| element.text));
                }
                Token::Operator(..) => commands.push(Vec::new()),
                Token::Redirect { target, .. } => {
                    let last = commands.last_mut().unwrap();
                    last.push(format!("> {}", target.text));
                }
            }
        }
        commands.retain(|command| !command.is_empty());
        commands
    }

    fn list(words: &[&str]) -> Vec<String> {
        words.iter().map(ToString::to_string).collect()
    }

    fn not_followed(recipe: &str) -> bool {
        matches!(sources(recipe), Sources::NotFollowed(ref why) if !why.is_empty())
    }

    #[test]
    fn words_are_split_as_bash_splits_them() {
        assert_eq!(
            words("a=1; b=\"x ; y\" # c=3\nsource=(one\n  'two three' # note\n  four)\n"),
            [
                list(&["a=1"]),
                list(&["b=\"x ; y\""]),
                list(&["source=(", "one", "'two three'", "four"]),
            ]
        );
        // A substitution, a redirection and a here-document are no
        // command ends; `${#x}` and `$#` are no comments.
        assert_eq!(
            words("x=$(a; b | c) y=${#z} 2>&1\ncat <<EOF\nsource=(evil)\nEOF\nz=1\n"),
            [
                list(&["x=$(a; b | c)", "y=${#z}", "> 1"]),
                list(&["cat", "> "]),
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
        // Two arrays set by one command are two arrays.
        assert_eq!(
            words("depends=(a) source=(b c)\n"),
            [list(&["depends=(", "a", "source=(", "b", "c"])]
        );
    }

    #[test]
    fn a_here_document_ends_at_its_marker_however_it_is_written() {
        for recipe in [
            "cat <<X>/dev/null\ntext\nX\nsource=(a)\n",
            "cat <<X;:\ntext\nX\nsource=(a)\n",
            "cat <<'X'|cat\n$(text)\nX\nsource=(a)\n",
            "cat <<-X\n\ttext\n\tX\nsource=(a)\n",
            "cat << \"X Y\"\ntext\nX Y\nsource=(a)\n",
            "cat <<\\X\n`text`\nX\nsource=(a)\n",
            "cat <<A <<B\none\nA\ntwo\nB\nsource=(a)\n",
        ] {
            assert_eq!(written(recipe)[0].1, ["a"], "{recipe}");
        }
        // One that never ends, or whose text bash expands, hides code.
        assert!(not_followed("source=(a)\ncat <<X\ntext\n"));
        assert!(not_followed("source=(a)\ncat <<X\n${source:=evil}\nX\n"));
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
        // A signed checkout's `?` matches no file: no directory is named
        // like an address, unless the recipe makes one while it loads.
        let signed = "url=https://example.org/x\nsource=(git+$url.git?signed#tag=v1)\n";
        assert_eq!(
            written(signed)[0].1,
            ["git+https://example.org/x.git?signed#tag=v1"]
        );
        assert!(not_followed(&format!(
            "mkdir -p git+https:/example.org\n{signed}"
        )));
        assert!(not_followed(&format!(
            "_x=$(mkdir -p git+https:)\n{signed}"
        )));
        assert!(not_followed("source=(x?signed::https://example.org/x)\n"));
        // The package base is the first package name.
        assert_eq!(
            written("pkgname=(one two)\nsource=($pkgbase.tar)\n")[0].1,
            ["one.tar"]
        );
        assert_eq!(
            written("export _x=1\nsource=(\"$_x.tar\")\n")[0].1,
            ["1.tar"]
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
            // Both ways set a written-out value.
            "if [[ $CARCH == x86_64 ]]; then _a=amd64; else _a=arm64; fi\nsource=(\"x-$_a.tar\")\n",
            "[[ $CARCH == x86_64 ]] && _a=amd64 || _a=arm64\nsource=(\"x-$_a.tar\")\n",
            "pkgver=1.2rc1\nif [[ $pkgver == *rc* ]]; then _d=testing; else _d=stable; fi\nsource=(\"$_d/x.tar\")\n",
            "_langs=(de fr)\nsource=()\nfor _l in \"${_langs[@]}\"; do\n  source+=(\"$_l.xpi\")\ndone\n",
            "source=({a,b}.tar)\n",
            // An element set by its number, always (pacman-contrib#119).
            "source=(a b)\nsha256sums=(x y)\nsha256sums[1]='SKIP'\n",
            "source=(a/b.tar c)\nnoextract=(\"${source[@]##*/}\")\n",
            "_names=(a b)\n_url=https://example.org\nsource=(\"${_names[@]/#/$_url/}\")\n",
            "create_links() { :; }\nsource=(a)\nsource+=(b)\n",
            "_n=$(nproc)\nif test \"$_n\" -ge 4; then _j=4; fi\nsource=(a)\nsource+=(b)\n",
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
            "while read -r _l; do source+=(a); done < list\n",
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
            assert!(not_followed(recipe), "{recipe}: {:?}", sources(recipe));
        }
    }

    /// Each of these gave another answer in the listing than in the build
    /// while reading as plain: the guard looks at something the listing's
    /// jail changes.
    #[test]
    fn a_guard_bash_applies_is_one_guardian_sees() {
        let guard = "[[ -w PKGBUILD ]]";
        for body in [
            // A new line after `&&` ends no chain.
            "G &&\nsource=(evil)\n",
            "G ||\n\n  source=(evil)\n",
            // A group, a subshell or a compound command under a chain.
            "G && {\n  :\n  source=(evil)\n}\n",
            "G && { :; source+=(evil); }\n",
            "G || if true; then source=(evil); fi\n",
            "G && for _x in a; do source=(evil); done\n",
            "G && case a in a) source=(evil) ;; esac\n",
            "if G; then :; else source=(evil); fi\n",
            "if true; then G || source=(evil); fi\n",
            "G && _v=evil\nsource=(\"$_v\")\n",
            "G && { _v=evil; }\nsource=(\"good$_v\")\n",
            "! G || source=(evil)\n",
            "G; (( $? )) && source=(evil)\n",
            "G && x=(a) source=(evil)\n",
            "G && return\nsource+=(evil)\n",
            "_f() { G && return; source=(evil); }\n_f\n",
            "for _x in a b; do G && break; source=(evil); done\n",
        ] {
            let recipe = format!("source=(good)\n{}", body.replace('G', guard));
            assert!(not_followed(&recipe), "{recipe}: {:?}", sources(&recipe));
        }
    }

    #[test]
    fn a_command_named_in_quotes_or_by_a_variable_is_not_followed() {
        for recipe in [
            "_f() { source=(evil); }\n\"_f\"\n",
            "_f() { source=(evil); }\n_f''\n",
            "_f() { source=(evil); }\n_g=_f\n$_g\n",
            "\\eval 'source=(evil)'\n",
            "'eval' 'source=(evil)'\n",
            "_e=eval\n$_e 'source=(evil)'\n",
            "\\. ./more.sh\n",
            "\"source\" ./more.sh\n",
            "command eval 'source=(evil)'\n",
            "builtin source ./more.sh\n",
            "command -p builtin eval x\n",
            "e\"\"val x\n",
            "${_x:-eval} x\n",
            // A function makepkg itself defines.
            "array_build source _x\n",
            "source_safe ./more.sh\n",
            "_f() { :; }\n_f() { source=(evil); }\n_f\n",
            "_f() { :; }\nunset -f _f\n_f\n",
        ] {
            assert!(not_followed(recipe), "{recipe}: {:?}", sources(recipe));
        }
    }

    #[test]
    fn a_watched_name_given_to_a_command_in_any_quoting_is_seen() {
        for recipe in [
            "printf -v s''ource %s evil\n",
            "printf -vsource %s evil\n",
            "read sou\\rce\n",
            "read -r \"source\" < f\n",
            "read -rasource < f\n",
            "declare s\"ource\"=x\n",
            "declare 'source=x'\n",
            "local sou\\rce=x\n",
            "typeset \"$_n\"=x\n",
            "export \"source\"\n",
            "readonly 's'ource\n",
            "mapfile -t 'source' < f\n",
            "readarray \"source\" < f\n",
            "mapfile -C 'source=(evil);:' -c 1 _x < f\n",
            "getopts a source\n",
            "getopts a \"sou\"rce\n",
            "let source=1\n",
            "let 'BUILDDIR = 5'\n",
            "(( source = 1 ))\n",
            "(( BUILDDIR++ ))\n",
            "_e='source=1'\n(( _e ))\n",
            "_e='source[0]=1'\n_v=$(( _e ))\n",
            "_e='x[$(id)]'\n[[ $_e -eq 1 ]] && :\n",
            "[[ $(cat f) -eq 1 ]] && :\n",
            "_v=$(cat f)\n[[ $_v -ge 0 ]] && :\n",
            "_e='x[$(id)]'\n_a=(1 2)\n_v=${_a[$_e]}\n",
            ": ${source:=x}\n",
            ": \"${source=x}\"\n",
            "_v=${noextract:=x}\n",
            "echo ${_a:-${source:=x}}\n",
            "coproc source { :; }\n",
            "declare -n _r=source\n_r=(evil)\n",
            "declare -n _r\n",
            "declare -i _i\n_i='source=1'\n",
            "for source in evil; do :; done\n",
            "for sha256sums in a; do :; done\n",
            "select source in evil; do :; done\n",
            "while read source; do :; done < f\n",
            "while read -r _x source; do :; done < f\n",
            "wait -p source\n",
            "exec {source}>f\n",
            "unset 'source'\n",
            "unset sou\\rce\n",
            "_x=1 source=(evil) true\n",
        ] {
            assert!(not_followed(recipe), "{recipe}: {:?}", sources(recipe));
        }
    }

    #[test]
    fn what_can_differ_between_two_runs_reaches_no_source() {
        for value in [
            "/home/*/.bash_history",
            "*.patch",
            "x?.tar",
            "[ab].tar",
            "~/x.tar",
            "~user/x",
            "$HOME/x",
            "$USER",
            "$PWD",
            "$RANDOM",
            "$SECONDS",
            "$EPOCHSECONDS",
            "$$",
            "$PPID",
            "$HOSTNAME",
            "$UID",
            "$EUID",
            "$BASHPID",
            "${BASH_VERSION}",
            "$SHLVL",
            "$TERM",
            "$DISPLAY",
            "$WAYLAND_DISPLAY",
            "$XDG_RUNTIME_DIR",
            "$PATH",
            "$1",
            "$@",
            "$?",
            "$(id -u)",
            "`id -u`",
            "$((RANDOM % 2))",
            "$(( $(id -u) + 1 ))",
            "${_unset:-x}",
            "${HOME:+x}",
            "${HOME##*/}",
            "${#HOME}",
            "<(echo x)",
            ">(cat)",
            "$\"text\"",
            "$[1+1]",
        ] {
            // In a source, in a variable a source reads, and in what a
            // condition or a loop depends on.
            for recipe in [
                format!("source=(good {value})\n"),
                format!("_x=({value})\nsource=(good ${{_x[0]:+evil}})\n"),
                format!("_x=({value})\nsource=(good)\n[[ -n $_x ]] && source+=(evil)\n"),
                format!("source=(good)\nfor _f in {value}; do source+=(evil); done\n"),
                format!(
                    "_x=({value})\nsource=(good)\ncase ${{_x[0]}} in ?*) source+=(evil) ;; esac\n"
                ),
                format!("_x=({value})\n_y=a\n_y+=$_x\nsource=(\"$_y\")\n"),
            ] {
                assert!(not_followed(&recipe), "{recipe}: {:?}", sources(&recipe));
            }
        }
        // Looking at a file, or asking whether a command is there.
        for test in [
            "[[ -e /x ]]",
            "[[ -f x ]]",
            "[[ -d x ]]",
            "[[ -w . ]]",
            "[[ -r x ]]",
            "[[ -x x ]]",
            "[[ -s x ]]",
            "[[ -t 1 ]]",
            "[[ (-e x) ]]",
            "[[ a == a && -e x ]]",
            "[ -e x ]",
            "test -e x",
            "[ x = * ]",
            "type git",
            "command -v git",
            "hash git",
            "git --version",
            "cd /x",
            "{ true; }",
            "(true)",
            "ls | grep -q x",
            "[[ a < $HOME ]]",
        ] {
            for recipe in [
                format!("source=(good)\n{test} && source+=(evil)\n"),
                format!("source=(good)\nif {test}; then source+=(evil); fi\n"),
                format!("source=(good)\nwhile {test}; do source+=(evil); done\n"),
                format!("_v=good\n{test} || _v=evil\nsource=($_v)\n"),
            ] {
                assert!(not_followed(&recipe), "{recipe}: {:?}", sources(&recipe));
            }
        }
        // What one round of a loop sets, the next one reads.
        assert!(not_followed(
            "_c=a\nfor _i in 1 2 3; do source+=($_c); _c=$_b; _b=$_a; _a=$(id); done\n"
        ));
        // A variable set beside the shell, or for a function only, keeps
        // what the environment gave it.
        for recipe in [
            "(_v=good)\nsource=($_v)\n",
            "_v=good | true\nsource=($_v)\n",
            "_v=good &\nsource=($_v)\n",
            "_v=good true\nsource=($_v)\n",
            "_f() { local HOME=good; }\n_f\nsource=($HOME)\n",
        ] {
            assert!(not_followed(recipe), "{recipe}: {:?}", sources(recipe));
        }
    }

    #[test]
    fn lines_of_package_that_makepkg_runs_are_read_as_top_level() {
        for recipe in [
            "source=(a)\npackage() {\n  depends=(foo) source=($([[ -w PKGBUILD ]] && echo evil || echo good))\n}\n",
            "source=(a)\npackage() { depends=(foo) source=(evil); }\n",
            "source=(a)\npackage_demo() {\n  pkgdesc=x source=(evil)\n}\n",
            "source=(a)\npackage() {\n  if true; then\n    depends+=(foo) && source=(evil)\n  fi\n}\n",
            "source=(a)\npackage() {\n  depends=(foo) BUILDDIR=/x\n}\n",
            "source=(a)\npackage() {\n  depends=(${source:=evil})\n}\n",
            "source=(a)\npackage() {\n  depends=(foo) && eval x\n}\n",
            "source=(a)\npackage() {\n  depends=(>(printf x))\n}\n",
            "source=(a)\npackage() {\n  options=(a) sha256sums=(evil)\n}\n",
            // Text that bash prints back as a line of its own.
            "source=(a)\npackage() {\n  cat <<E\n depends=(h) source=(evil)\nE\n}\n",
            "source=(a)\npackage() {\n  echo \"x\n depends=(s) source=(evil)\"\n}\n",
        ] {
            assert!(not_followed(recipe), "{recipe}: {:?}", sources(recipe));
        }
        // An attribute alone on its line sets nothing else.
        for recipe in [
            "source=(a)\npackage() {\n  depends=(foo\n    bar)\n  pkgdesc=\"x $pkgname\"\n  provides=(\"x=$pkgver\")\n  source=(evil)\n}\n",
            "source=(a)\npackage() {\n  depends=($(echo x))\n  install -Dm644 a b\n  cat <<E\n url=https://example.org\nE\n}\n",
            "source=(a)\nbuild() {\n  depends=(foo) source=(evil)\n}\n",
        ] {
            assert_eq!(written(recipe)[0].1, ["a"], "{recipe}");
        }
    }

    #[test]
    fn quoting_that_bash_reads_as_one_word_hides_nothing() {
        // `$'\''` is one quote character; what follows is code.
        assert!(not_followed("x=$'\\''; eval evil #'\n"));
        // A comment inside a substitution opens no quote.
        assert!(not_followed("_x=$(echo a # it's\n)\neval evil # '\n"));
        // A `}` given to a command closes nothing.
        assert_eq!(
            written("_g() { echo }; }\nbuild() { _g; }\nsource=(a)\n")[0].1,
            ["a"]
        );
        // `${ ... }` holds blanks and `&` without ending a statement, so
        // the function's closing brace is the one bash takes.
        assert_eq!(
            sources("build() {\n  x=${CFLAGS/-g }\n  y=${v/a/&b}\n  eval z\n}\nsource=(a)\n"),
            Sources::Written(vec![("source".into(), vec!["a".into()])])
        );
        // `[[` is bash's own only where a command starts; `#` is no
        // comment in a pattern list or in arithmetic; a quote inside a
        // substitution inside quotes is a quote.
        for recipe in [
            "echo [[ ; source=(evil); : ]]\n",
            "echo @(a|#b) ; source=(evil)\n: )\n",
            ": $(( 1 #) )); source=(evil)\n: ) )\n",
            "_x=\"$(echo ')' ; echo \" )\"; source=(evil) #\"\n",
        ] {
            assert!(
                !matches!(sources(recipe), Sources::Written(ref arrays) if arrays.is_empty()),
                "{recipe}: {:?}",
                sources(recipe)
            );
        }
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
            // Shell that only a function runs is read past, whatever it is.
            "source=(a)\nbuild() {\n  case $x in\n    a|b) make ;;\n    (c) : ;&\n    *) rm !(keep) ;;\n  esac\n  while read -r l; do :; done < <(ls)\n  for ((i=0; i<3; i++)); do :; done\n  [[ $x =~ ^(a|b)$ ]] && (cd x && make) |& tee log &>/dev/null\n  cat > f <<-EOF\n\t$x )\n\tEOF\n  x=$(( 1 << 2 ))\n  y=$(sed s/a/b/ <<< \"$x\")\n}\n",
            // Programs and what they are given depend on the run; they set
            // nothing in the shell that reads the recipe.
            "source=(a)\necho \"$HOME\" *.c > /dev/null\n[[ -e x ]] && msg hello\n",
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

    #[test]
    fn a_path_variable_is_found_however_its_name_is_quoted() {
        let names = Naming {
            set: &["BUILDDIR", "srcdir"],
            given: &["BUILDDIR"],
            assigners: &["printf", "read", "declare"],
        };
        let lines = |recipe: &str| top_level_naming(recipe, &names).unwrap();
        assert_eq!(lines("pkgname=x\ndeclare BUILD''DIR=/x\n"), [2]);
        assert_eq!(lines("export \"BUILDDIR\"=/x\n"), [1]);
        assert_eq!(lines("printf -v BUILD\\DIR %s /x\n"), [1]);
        assert_eq!(lines("command printf -v 'BUILDDIR' %s /x\n"), [1]);
        assert_eq!(lines("true &&\n  srcdir=/x\n"), [2]);
        assert_eq!(lines("for BUILDDIR in /x; do :; done\n"), [1]);
        assert_eq!(lines("$_c BUILDDIR\n"), [1]);
        assert!(lines("build() { BUILDDIR=/x; }\necho \"$BUILDDIR\" BUILDDIR\n").is_empty());
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
