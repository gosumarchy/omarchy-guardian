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

/// One line as the local rules see it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    /// The line with comments blanked.
    pub code: String,
    /// `code` with printed-only text also blanked.
    pub quiet: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Language {
    Shell {
        pkgbuild: bool,
    },
    /// `#` starts a full-line comment.
    Hash,
    /// `//` full-line and `/* */` block comments.
    Slash,
    Lua,
    /// Unified diff: removed lines do not exist once the patch applies.
    Patch,
    Other,
}

/// The lines of `text`, aligned with `text.lines()`.
pub fn lines(rel: &str, text: &str) -> Vec<Line> {
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
        Language::Slash => {
            let mut in_block = false;
            per_line(&mut |line| block_comments(line, &mut in_block, "//", "/*", "*/"))
        }
        Language::Lua => {
            let mut closing: Option<String> = None;
            per_line(&mut |line| lua_comments(line, &mut closing))
        }
        Language::Patch => per_line(&mut |line| {
            if line.starts_with('-') {
                blank(line)
            } else {
                line.to_string()
            }
        }),
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
        | "zig" | "css" | "scss" | "less" | "jsonc" => Language::Slash,
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
    let basename = |word: &str| word.rsplit('/').next().unwrap_or_default().to_string();
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

fn blank(line: &str) -> String {
    " ".repeat(line.chars().count())
}

/// Full-line comments and block comments that open at the start of a line.
/// Comment markers after code are left alone: telling them apart from the
/// same characters inside a string needs a real parser.
fn block_comments(
    line: &str,
    in_block: &mut bool,
    single: &str,
    open: &str,
    close: &str,
) -> String {
    let (skipped, rest) = if *in_block {
        (0, line)
    } else {
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        if trimmed.starts_with(single) {
            return blank(line);
        }
        let Some(after_open) = trimmed.strip_prefix(open) else {
            return line.to_string();
        };
        *in_block = true;
        (indent + open.len(), after_open)
    };

    match rest.find(close) {
        Some(end) => {
            *in_block = false;
            let code_start = skipped + end + close.len();
            blank(&line[..code_start]) + &line[code_start..]
        }
        None => blank(line),
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Context {
    Single,
    /// `$'...'`, where backslash escapes apply.
    AnsiC,
    Double,
    /// `$(...)` or `(...)`: ordinary shell syntax, nested.
    Paren,
    /// `$((...))` or `((...))`, where `<<` is a shift and `#` a base.
    Arithmetic,
    Backtick,
}

struct Heredoc {
    delimiter: String,
    strip_tabs: bool,
    quoted: bool,
    /// Index just past the delimiter word, to check the rest of its line.
    after: usize,
    /// `cat <<EOF` alone as a statement: the body is printed.
    shown: bool,
}

/// One simple command at the top level of a script.
struct Statement {
    start: usize,
    /// It pipes, redirects, or substitutes a command, so what it "prints"
    /// may be consumed or executed rather than shown.
    consumed: bool,
}

impl Statement {
    const fn at(start: usize) -> Self {
        Self {
            start,
            consumed: false,
        }
    }
}

struct Shell<'a> {
    chars: &'a [char],
    code: Vec<char>,
    quiet: Vec<char>,
    pkgbuild: bool,
}

/// A small shell lexer: quotes, `$(...)`, backticks, comments, heredocs and
/// statement boundaries. It is not a full parser; wherever it is unsure it
/// blanks nothing, so a lexing mistake can only leave extra text visible to
/// the rules.
fn shell(text: &str, pkgbuild: bool) -> Vec<Line> {
    let chars: Vec<char> = text.chars().collect();
    let mut shell = Shell {
        chars: &chars,
        code: chars.clone(),
        quiet: chars.clone(),
        pkgbuild,
    };
    shell.lex();

    let code: String = shell.code.into_iter().collect();
    let quiet: String = shell.quiet.into_iter().collect();
    code.lines()
        .zip(quiet.lines())
        .map(|(code, quiet)| Line {
            code: code.to_string(),
            quiet: quiet.to_string(),
        })
        .collect()
}

impl Shell<'_> {
    fn at(&self, index: usize) -> char {
        self.chars.get(index).copied().unwrap_or('\0')
    }

    fn blank_both(&mut self, from: usize, to: usize) {
        for index in from..to.min(self.chars.len()) {
            if self.chars[index] != '\n' {
                self.code[index] = ' ';
                self.quiet[index] = ' ';
            }
        }
    }

    fn blank_quiet(&mut self, from: usize, to: usize) {
        for index in from..to.min(self.chars.len()) {
            if self.chars[index] != '\n' {
                self.quiet[index] = ' ';
            }
        }
    }

    fn line_end(&self, from: usize) -> usize {
        self.chars[from.min(self.chars.len())..]
            .iter()
            .position(|character| *character == '\n')
            .map_or(self.chars.len(), |offset| from + offset)
    }

    fn is_word_start(&self, index: usize) -> bool {
        index == 0
            || matches!(
                self.at(index - 1),
                ' ' | '\t' | '\n' | ';' | '&' | '|' | '(' | ')'
            )
    }

    fn is_word_end(&self, index: usize) -> bool {
        matches!(self.at(index), ' ' | '\t' | '\n' | ';' | '\0')
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one state machine reads best in one place"
    )]
    fn lex(&mut self) {
        let mut stack: Vec<Context> = Vec::new();
        let mut statement = Statement::at(0);
        let mut heredocs: Vec<Heredoc> = Vec::new();
        let mut index = 0;

        while index < self.chars.len() {
            let character = self.chars[index];
            let next = self.at(index + 1);
            let top = stack.last().copied();

            match top {
                Some(Context::Single) => {
                    if character == '\'' {
                        stack.pop();
                    }
                    index += 1;
                    continue;
                }
                Some(Context::AnsiC) => {
                    match character {
                        '\\' => index += 1,
                        '\'' => {
                            stack.pop();
                        }
                        _ => {}
                    }
                    index += 1;
                    continue;
                }
                Some(Context::Double) => {
                    match character {
                        '\\' => index += 1,
                        '"' => {
                            stack.pop();
                        }
                        '`' => {
                            statement.consumed = true;
                            stack.push(Context::Backtick);
                        }
                        '$' if next == '(' => {
                            statement.consumed = true;
                            stack.push(Context::Paren);
                            index += 1;
                        }
                        _ => {}
                    }
                    index += 1;
                    continue;
                }
                None | Some(Context::Paren | Context::Arithmetic | Context::Backtick) => {}
            }

            let arithmetic = top == Some(Context::Arithmetic);
            match character {
                '\\' => index += 1,
                '\'' => stack.push(Context::Single),
                '"' => stack.push(Context::Double),
                '$' if next == '\'' => {
                    stack.push(Context::AnsiC);
                    index += 1;
                }
                '$' | '(' if (character == '(' || next == '(') => {
                    statement.consumed = true;
                    let opener = if character == '$' { index + 1 } else { index };
                    if self.at(opener + 1) == '(' {
                        stack.extend([Context::Arithmetic, Context::Arithmetic]);
                        index = opener + 1;
                    } else if arithmetic {
                        stack.push(Context::Arithmetic);
                        index = opener;
                    } else {
                        stack.push(Context::Paren);
                        index = opener;
                    }
                }
                ')' => {
                    if matches!(top, Some(Context::Paren | Context::Arithmetic)) {
                        stack.pop();
                    }
                }
                '`' => {
                    statement.consumed = true;
                    if top == Some(Context::Backtick) {
                        stack.pop();
                    } else {
                        stack.push(Context::Backtick);
                    }
                }
                '#' if !arithmetic && self.is_word_start(index) => {
                    let end = self.line_end(index);
                    self.blank_both(index, end);
                    index = end;
                    continue;
                }
                '<' if !arithmetic && next == '<' => {
                    statement.consumed = true;
                    if self.at(index + 2) == '<' {
                        index += 3;
                        continue;
                    }
                    let shown = stack.is_empty()
                        && self.command_word(statement.start, index).0 == "cat"
                        && self.words(statement.start, index).len() == 1;
                    match self.heredoc(index + 2, shown) {
                        Some(heredoc) => {
                            index = heredoc.after;
                            heredocs.push(heredoc);
                        }
                        None => index += 2,
                    }
                    continue;
                }
                '>' if stack.is_empty() => {
                    // A message sent to the terminal's stderr is still only shown.
                    match self.terminal_redirect(index + 1) {
                        Some(end) => {
                            index = end;
                            continue;
                        }
                        None => statement.consumed = true,
                    }
                }
                '|' | '&' | ';' if stack.is_empty() => {
                    let doubled = next == character;
                    if character == '|' && !doubled {
                        statement.consumed = true;
                    }
                    self.finish(&statement, index);
                    index += if doubled { 2 } else { 1 };
                    statement = Statement::at(index);
                    continue;
                }
                '<' | '>' | '|' => statement.consumed = true,
                '{' | '}'
                    if stack.is_empty()
                        && self.is_word_start(index)
                        && self.is_word_end(index + 1) =>
                {
                    self.finish(&statement, index);
                    statement = Statement::at(index + 1);
                }
                '\n' => {
                    if stack.is_empty() {
                        self.finish(&statement, index);
                    }
                    if !heredocs.is_empty() {
                        let only_one = heredocs.len() == 1;
                        let mut after_bodies = index + 1;
                        for mut heredoc in heredocs.drain(..) {
                            let rest: String = self.chars[heredoc.after..index].iter().collect();
                            let rest = rest.trim();
                            heredoc.shown &= only_one && (rest.is_empty() || rest.starts_with('#'));
                            after_bodies = self.heredoc_body(&heredoc, after_bodies);
                        }
                        index = after_bodies;
                        if stack.is_empty() {
                            statement = Statement::at(index);
                        }
                        continue;
                    }
                    if stack.is_empty() {
                        statement = Statement::at(index + 1);
                    }
                }
                _ => {}
            }
            index += 1;
        }

        if stack.is_empty() {
            self.finish(&statement, self.chars.len());
        }
    }

    /// The end of `&2` or `/dev/stderr` after a `>`, when that is the whole
    /// redirection target.
    fn terminal_redirect(&self, from: usize) -> Option<usize> {
        ["&2", "/dev/stderr"].into_iter().find_map(|target| {
            let end = from + target.chars().count();
            let matches = target
                .chars()
                .enumerate()
                .all(|(offset, character)| self.at(from + offset) == character);
            (matches && (self.is_word_end(end) || matches!(self.at(end), '&' | '|'))).then_some(end)
        })
    }

    /// Reads the delimiter after `<<`. `from` is just past the operator.
    fn heredoc(&self, from: usize, shown: bool) -> Option<Heredoc> {
        let mut index = from;
        let strip_tabs = self.at(index) == '-';
        if strip_tabs {
            index += 1;
        }
        while matches!(self.at(index), ' ' | '\t') {
            index += 1;
        }

        let mut delimiter = String::new();
        let mut quoted = false;
        loop {
            match self.at(index) {
                '\0' | ' ' | '\t' | '\n' | ';' | '&' | '|' | '<' | '>' | '(' | ')' => break,
                quote @ ('\'' | '"') => {
                    quoted = true;
                    index += 1;
                    while !matches!(self.at(index), '\0' | '\n') && self.at(index) != quote {
                        delimiter.push(self.at(index));
                        index += 1;
                    }
                    index += 1;
                }
                '\\' => {
                    quoted = true;
                    delimiter.push(self.at(index + 1));
                    index += 2;
                }
                character => {
                    delimiter.push(character);
                    index += 1;
                }
            }
        }

        (!delimiter.is_empty()).then_some(Heredoc {
            delimiter,
            strip_tabs,
            quoted,
            after: index,
            shown,
        })
    }

    /// Consumes a heredoc body starting at `from` and returns the index just
    /// past its delimiter line. A printed body is blanked in `quiet` unless
    /// the shell expands a command substitution in it.
    fn heredoc_body(&mut self, heredoc: &Heredoc, from: usize) -> usize {
        let mut start = from;
        while start < self.chars.len() {
            let end = self.line_end(start);
            let line: String = self.chars[start..end].iter().collect();
            let candidate = if heredoc.strip_tabs {
                line.trim_start_matches('\t')
            } else {
                line.as_str()
            };
            if candidate.trim_end_matches('\r') == heredoc.delimiter {
                return end + 1;
            }
            let expands = !heredoc.quoted && (line.contains("$(") || line.contains('`'));
            if heredoc.shown && !expands {
                self.blank_quiet(start, end);
            }
            start = end + 1;
        }
        self.chars.len()
    }

    /// Whitespace-separated words of `from..to`, as `(start, end)` indices.
    fn words(&self, from: usize, to: usize) -> Vec<(usize, usize)> {
        let mut words = Vec::new();
        let mut index = from;
        while index < to {
            while index < to && self.at(index).is_whitespace() {
                index += 1;
            }
            let start = index;
            while index < to && !self.at(index).is_whitespace() {
                index += 1;
            }
            if start < index {
                words.push((start, index));
            }
        }
        words
    }

    /// The statement's command word, after leading keywords such as `then`,
    /// and the index of the word after it.
    fn command_word(&self, from: usize, to: usize) -> (String, Option<usize>) {
        let words = self.words(from, to);
        let mut words = words.iter().map(|(start, end)| {
            (
                self.chars[*start..*end].iter().collect::<String>(),
                *start,
                *end,
            )
        });
        for (word, _, end) in words.by_ref() {
            if !matches!(word.as_str(), "then" | "do" | "else" | "!") {
                let following = self.words(end, to).first().map(|(start, _)| *start);
                return (word, following.or(Some(end)));
            }
        }
        (String::new(), None)
    }

    /// Blanks what a finished statement only prints.
    fn finish(&mut self, statement: &Statement, end: usize) {
        if statement.consumed {
            return;
        }
        let (word, arguments) = self.command_word(statement.start, end);
        let Some(arguments) = arguments else {
            return;
        };
        match word.as_str() {
            "echo" => self.blank_quiet(arguments, end),
            "printf" => {
                let first: String = self.chars[arguments..end.max(arguments)]
                    .iter()
                    .take_while(|character| !character.is_whitespace())
                    .collect();
                if first != "-v" {
                    self.blank_quiet(arguments, end);
                }
            }
            // The PKGBUILD's project homepage, which makepkg never fetches.
            _ if self.pkgbuild && word.starts_with("url=") => {
                let start = self
                    .words(statement.start, end)
                    .first()
                    .map_or(statement.start, |(start, _)| *start);
                self.blank_quiet(start, end);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::lines;

    fn code(rel: &str, text: &str) -> Vec<String> {
        lines(rel, text)
            .into_iter()
            .map(|line| line.code.trim_end().to_string())
            .collect()
    }

    fn quiet(rel: &str, text: &str) -> Vec<String> {
        lines(rel, text)
            .into_iter()
            .map(|line| line.quiet.trim_end().to_string())
            .collect()
    }

    #[test]
    fn lines_stay_aligned_with_the_original() {
        let text = "a\n# b\r\n\necho 'c\nd'\n";
        assert_eq!(lines("x.sh", text).len(), text.lines().count());
        assert_eq!(lines("x.py", text).len(), text.lines().count());
        assert_eq!(lines("x.c", text).len(), text.lines().count());
    }

    #[test]
    fn shell_comments_are_blanked_but_not_hashes_in_words_or_strings() {
        assert_eq!(
            code(
                "PKGBUILD",
                "# see http://a.test\nx=1 # sudo y\necho \"#no\" ${#arr} a#b\n"
            ),
            ["", "x=1", "echo \"#no\" ${#arr} a#b"]
        );
    }

    #[test]
    fn printed_messages_are_quiet_but_still_code() {
        let text = "post_install() {\n  echo 'sudo rm -rf /var/log/x/'\n  printf '%s\\n' \\\n    \"  sudo /usr/lib/x.sh\"\n}\n";
        assert_eq!(
            quiet(".INSTALL", text),
            ["post_install() {", "  echo", "  printf", "", "}"]
        );
        assert!(code(".INSTALL", text)[1].contains("sudo"));
        assert_eq!(quiet("x.sh", "echo 'sudo a' >&2\n"), ["echo"]);
        assert_eq!(
            quiet("x.sh", "echo 'sudo a' >&2x\n")[0],
            "echo 'sudo a' >&2x"
        );
    }

    #[test]
    fn multi_line_echo_strings_are_quiet() {
        let text =
            "echo \"\nadd this to ~/.bashrc:\n  echo 'source x' >> ~/.bashrc\n\"\nsudo true\n";
        assert_eq!(quiet("x.install", text), ["echo", "", "", "", "sudo true"]);
    }

    #[test]
    fn printed_text_that_is_consumed_or_expanded_stays_visible() {
        for text in [
            "echo 'sudo x' | sh\n",
            "echo 'source x' >> ~/.bashrc\n",
            "echo \"$(sudo id)\"\n",
            "echo `sudo id`\n",
            "eval \"$(echo sudo x)\"\n",
            "printf -v cmd 'sudo %s' x\n",
            "x=$(echo 'sudo y')\n",
        ] {
            assert_eq!(quiet("x.sh", text)[0], text.trim_end(), "{text:?}");
        }
    }

    #[test]
    fn statements_after_a_message_are_not_quiet() {
        assert_eq!(
            quiet("x.sh", "echo hi && sudo a; echo b || sudo c\n"),
            ["echo    && sudo a; echo   || sudo c"]
        );
        assert_eq!(
            quiet("x.sh", "if x; then echo 'sudo a'; fi\n"),
            ["if x; then echo         ; fi"]
        );
    }

    #[test]
    fn printed_heredocs_are_quiet_and_others_are_not() {
        let printed = "cat <<EOF\n  sudo systemctl enable x\nEOF\nsudo y\n";
        assert_eq!(quiet("x.sh", printed), ["cat <<EOF", "", "EOF", "sudo y"]);

        for text in [
            "cat > /etc/x <<EOF\nsudo a\nEOF\n",
            "sh <<'EOF'\nsudo a\nEOF\n",
            "cat <<EOF | sh\nsudo a\nEOF\n",
            "cat <<EOF\n$(sudo a)\nEOF\n",
        ] {
            assert!(quiet("x.sh", text)[1].contains("sudo"), "{text:?}");
        }
        // A quoted delimiter prints `$(...)` literally.
        assert_eq!(quiet("x.sh", "cat <<'EOF'\n$(sudo a)\nEOF\n")[1], "");
    }

    #[test]
    fn heredoc_bodies_are_not_lexed_as_shell() {
        // The apostrophe in the body must not open a quote.
        let text = "cat > f <<EOF\ndon't\nEOF\n# comment\n";
        assert_eq!(code("x.sh", text), ["cat > f <<EOF", "don't", "EOF", ""]);
        // Arithmetic shifts are not heredocs.
        assert_eq!(code("x.sh", "x=$((1<<2))\n# c\n"), ["x=$((1<<2))", ""]);
    }

    #[test]
    fn pkgbuild_homepage_is_quiet() {
        assert_eq!(
            quiet(
                "PKGBUILD",
                "url=\"http://a.test\"\nsource=(\"http://b.test/x\")\n"
            ),
            ["", "source=(\"http://b.test/x\")"]
        );
        assert_eq!(
            quiet("other.sh", "url=\"http://a.test\"\n")[0],
            "url=\"http://a.test\""
        );
    }

    #[test]
    fn full_line_comments_in_other_languages() {
        assert_eq!(
            code("a.py", "# http://x\nos.system(x)  # c\n"),
            ["", "os.system(x)  # c"]
        );
        assert_eq!(
            code(
                "a.c",
                "/*\n * http://www.apache.org/licenses/LICENSE-2.0\n */ int x;\n// eval(\nf(\"//\");\n"
            ),
            ["", "", "    int x;", "", "f(\"//\");"]
        );
        assert_eq!(
            code(
                "a.lua",
                "-- os.execute(x)\n--[[\nos.execute(y)\n]] f()\nos.execute(z)\n"
            ),
            ["", "", "", "   f()", "os.execute(z)"]
        );
        assert_eq!(
            code("fix.patch", "--- a/x\n+++ b/x\n-sudo a\n+sudo b\n"),
            ["", "+++ b/x", "", "+sudo b"]
        );
        // `#` is not a comment in C.
        assert_eq!(code("a.c", "#define X 1\n"), ["#define X 1"]);
    }

    #[test]
    fn scripts_are_recognised_by_their_interpreter() {
        assert_eq!(code("run", "#!/usr/bin/env bash\n# x\n"), ["", ""]);
        assert_eq!(code("run", "#!/usr/bin/python3\n# x\n"), ["", ""]);
        assert_eq!(
            code("run", "#!/usr/bin/node\n# x\n"),
            ["#!/usr/bin/node", "# x"]
        );
    }
}
