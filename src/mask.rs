//! Which parts of a source line can act.
//!
//! Comments never run, and text a shell script only prints (`echo` and
//! `printf` arguments, `cat <<EOF` bodies) is shown to the user rather than
//! executed. The local rules read lines with comments blanked, and the
//! context rules (see `RuleId::ignores_messages`) also with printed text
//! blanked, so install notes such as `echo "run: sudo systemctl enable x"`
//! are not reported as behaviour. The AI review still sees every file whole.
//!
//! Masking only ever blanks characters, never line breaks, so masked lines
//! stay aligned with `str::lines` of the original text.

use std::path::Path;

use crate::paths::file_name;

mod shell;
mod slash;

use shell::shell;
use slash::Dialect;

/// One line as the local rules see it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Line {
    /// The line with comments blanked.
    pub(crate) code: String,
    /// `code` with printed-only text also blanked.
    pub(crate) quiet: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Language {
    Shell {
        pkgbuild: bool,
    },
    /// `#` starts a full-line comment.
    Hash,
    /// `//` full-line and `/* */` block comments (see `slash`).
    Slash(Dialect),
    Lua,
    /// Unified diff (see `patch`).
    Patch,
    Other,
}

/// The lines of `text`, aligned with `text.lines()`.
pub(crate) fn lines(rel: &str, text: &str) -> Vec<Line> {
    let per_line = |mask: &mut dyn FnMut(&str) -> String| {
        text.lines()
            .map(|line| {
                let code = mask(line);
                Line {
                    quiet: code.clone(),
                    code,
                }
            })
            .collect()
    };

    match language(rel, text) {
        Language::Shell { pkgbuild } => shell(text, pkgbuild),
        Language::Hash => per_line(&mut |line| {
            if line.trim_start().starts_with('#') {
                blank(line)
            } else {
                line.to_string()
            }
        }),
        Language::Slash(dialect) => {
            let mut reader = slash::Reader::new(dialect);
            per_line(&mut |line| reader.line(line))
        }
        Language::Lua => {
            let mut closing: Option<String> = None;
            per_line(&mut |line| lua_comments(line, &mut closing))
        }
        Language::Patch => patch(text),
        Language::Other => per_line(&mut str::to_string),
    }
}

fn language(rel: &str, text: &str) -> Language {
    let path = Path::new(rel);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if name == "pkgbuild" {
        return Language::Shell { pkgbuild: true };
    }
    if name == ".install" {
        return Language::Shell { pkgbuild: false };
    }
    if let Some(language) = shebang(text) {
        return language;
    }
    match extension.as_str() {
        "sh" | "bash" | "zsh" | "ksh" | "install" => Language::Shell { pkgbuild: false },
        "py" | "pyw" | "rb" | "pl" | "pm" | "toml" | "yaml" | "yml" | "conf" | "cfg" | "ini"
        | "service" | "timer" | "socket" | "desktop" | "fish" | "cmake" => Language::Hash,
        "c" | "h" | "cc" | "cpp" | "cxx" | "hpp" | "hh" | "cs" | "java" | "js" | "jsx" | "mjs"
        | "cjs" | "ts" | "tsx" | "go" | "rs" | "swift" | "kt" | "kts" | "scala" | "dart"
        | "zig" | "css" | "scss" | "less" | "jsonc" => Language::Slash(Dialect::of(&extension)),
        "lua" => Language::Lua,
        "patch" | "diff" => Language::Patch,
        _ if matches!(
            name.as_str(),
            "makefile" | "gnumakefile" | "dockerfile" | "containerfile" | "cmakelists.txt"
        ) =>
        {
            Language::Hash
        }
        _ => Language::Other,
    }
}

/// The comment style of a script's interpreter, from its `#!` line.
fn shebang(text: &str) -> Option<Language> {
    let line = text.lines().next()?.strip_prefix("#!")?;
    let mut words = line.split_whitespace();
    let basename = |word: &str| file_name(word).to_string();
    let mut program = basename(words.next()?);
    if program == "env" {
        program = basename(words.find(|word| !word.starts_with('-'))?);
    }
    let program =
        program.trim_end_matches(|character: char| character.is_ascii_digit() || character == '.');
    match program {
        "sh" | "bash" | "zsh" | "dash" | "ksh" | "mksh" => {
            Some(Language::Shell { pkgbuild: false })
        }
        "python" | "perl" | "ruby" => Some(Language::Hash),
        _ => None,
    }
}

/// A unified diff. Removed lines do not exist once the patch applies, so the
/// context rules skip them; the rules for directly dangerous commands still
/// see them, since `patch -R` applies a diff in reverse. Added and context
/// lines that are full-line comments in the patched file's language are
/// comments.
fn patch(text: &str) -> Vec<Line> {
    let mut target = Language::Other;
    text.lines()
        .map(|line| {
            if let Some(path) = line.strip_prefix("+++ ") {
                let path = path.split('\t').next().unwrap_or_default().trim();
                target = language(path, "");
            }
            let removed = line.starts_with('-') && !line.starts_with("---");
            let comment = (line.starts_with('+') && !line.starts_with("+++")
                || line.starts_with(' '))
                && is_full_line_comment(target, &line[1..]);
            let code = if comment {
                blank(line)
            } else {
                line.to_string()
            };
            let quiet = if removed { blank(line) } else { code.clone() };
            Line { code, quiet }
        })
        .collect()
}

fn is_full_line_comment(language: Language, line: &str) -> bool {
    let line = line.trim_start();
    match language {
        Language::Shell { .. } | Language::Hash => line.starts_with('#'),
        Language::Slash(_) => line.starts_with("//") && !is_a_path(line),
        Language::Lua => line.starts_with("--"),
        Language::Patch | Language::Other => false,
    }
}

/// Whether a line that starts with `//` reads as a path (`//usr/bin/curl
/// …`): a shell handed the file runs it as a command, whatever the file is
/// called, so it is not passed over as a comment.
fn is_a_path(line: &str) -> bool {
    line.trim_start()
        .strip_prefix("//")
        // Directly after the slashes: `// see src/x.rs` is a comment, and
        // so is an address.
        .filter(|rest| {
            rest.starts_with(|character: char| {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '$' | '~')
            })
        })
        .and_then(|rest| rest.split_whitespace().next())
        .is_some_and(|word| word.contains('/') && !word.contains("://"))
}

fn blank(line: &str) -> String {
    " ".repeat(line.chars().count())
}

/// `--` comments and `--[[ ]]` / `--[==[ ]==]` block comments opening at
/// the start of a line.
fn lua_comments(line: &str, closing: &mut Option<String>) -> String {
    if let Some(close) = closing.as_deref() {
        return match line.find(close) {
            Some(end) => {
                let code_start = end + close.len();
                *closing = None;
                blank(&line[..code_start]) + &line[code_start..]
            }
            None => blank(line),
        };
    }

    let trimmed = line.trim_start();
    let Some(comment) = trimmed.strip_prefix("--") else {
        return line.to_string();
    };
    if let Some(level) = comment.strip_prefix('[') {
        let equals = level.len() - level.trim_start_matches('=').len();
        if level[equals..].starts_with('[') {
            let close = format!("]{}]", "=".repeat(equals));
            let body_start = line.len() - trimmed.len() + 2 + 1 + equals + 1;
            if let Some(end) = line[body_start..].find(&close) {
                let code_start = body_start + end + close.len();
                return blank(&line[..code_start]) + &line[code_start..];
            }
            *closing = Some(close);
        }
    }
    blank(line)
}

#[cfg(test)]
mod tests;
