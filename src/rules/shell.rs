//! Reading a shell command line: its words, and a little closer than word
//! by word, its statements and pipelines outside quotes, the command
//! substitutions in it, and the program a part of it runs. Every rule
//! reads these here, so that they agree.
//!
//! None of this is a shell parser. It reads the shapes the rules name and
//! gives up (finds nothing) on anything else.

/// Shells that read commands from standard input.
pub(super) const PIPE_SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "ash", "fish"];

/// Splits a command line into words at whitespace outside quotes. Quote
/// characters are kept in the words.
pub(super) fn shell_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote: Option<char> = None;
    for character in line.chars() {
        if quote.is_none() && character.is_whitespace() {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
            continue;
        }
        match quote {
            Some(open) if character == open => quote = None,
            None if character == '"' || character == '\'' => quote = Some(character),
            Some(_) | None => {}
        }
        word.push(character);
    }
    if !word.is_empty() {
        words.push(word);
    }
    words
}

pub(super) fn unquoted(word: &str) -> String {
    word.chars()
        .filter(|character| !matches!(character, '"' | '\''))
        .collect()
}

/// The words of a command line (see `shell_words`), without their quotes.
pub(super) fn unquoted_words(line: &str) -> Vec<String> {
    shell_words(line)
        .iter()
        .map(|word| unquoted(word))
        .collect()
}

/// A program's name without its directory.
pub(super) fn program_name(word: &str) -> &str {
    crate::paths::file_name(word)
}

/// A program's name without the version written after it: `python3.12` is
/// `python`.
pub(super) fn unversioned(program: &str) -> &str {
    program.trim_end_matches(|character: char| character.is_ascii_digit() || character == '.')
}

/// Whether `word` is a cluster of short options holding `flag`: `-c`,
/// `-lc`, but not `--c`.
pub(super) fn short_flag(word: &str, flag: char) -> bool {
    word.len() > 1
        && word.starts_with('-')
        && !word.starts_with("--")
        && word[1..].chars().all(|c| c.is_ascii_alphabetic())
        && word[1..].contains(flag)
}

/// The most substitutions of one line looked at.
const MAX_SUBSTITUTIONS: usize = 64;

/// A `$(…)`, `<(…)` or backtick substitution.
pub(super) struct Substitution<'a> {
    /// `$(`, `<(` or a backtick.
    open: &'static str,
    /// Where it opens in the line.
    start: usize,
    pub(super) body: &'a str,
}

/// The index just past the `)` that closes a parenthesis opened before
/// `text`, or the end of `text` when nothing closes it. Parentheses inside
/// quotes do not count, except those of a substitution (`"$(…)"`).
fn closing_paren(text: &str) -> usize {
    let bytes = text.as_bytes();
    let mut depth = 1_usize;
    let mut quote: Option<u8> = None;
    // The depth the open quote began at: a `)` that closes a substitution
    // opened inside a double quote still counts.
    let mut quoted_at = 0_usize;
    for (index, byte) in text.bytes().enumerate() {
        match byte {
            b'\'' | b'"' if quote == Some(byte) && (byte == b'\'' || depth == quoted_at) => {
                quote = None;
            }
            b'\'' | b'"' if quote.is_none() => {
                quote = Some(byte);
                quoted_at = depth;
            }
            b'(' if quote.is_none()
                || (quote == Some(b'"') && index > 0 && bytes[index - 1] == b'$') =>
            {
                depth += 1;
            }
            b')' if quote.is_none() || (quote == Some(b'"') && depth > quoted_at) => {
                depth -= 1;
                if depth == 0 {
                    return index + 1;
                }
            }
            _ => {}
        }
    }
    text.len()
}

/// What stands between a parenthesis opened before `text` and the one
/// that closes it.
pub(super) fn argument(text: &str) -> &str {
    let end = closing_paren(text);
    text[..end].strip_suffix(')').unwrap_or(&text[..end])
}

/// Every substitution in `text`, the nested ones after the one around them.
pub(super) fn substitutions(text: &str) -> Vec<Substitution<'_>> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut index = 0;
    while index < bytes.len() && found.len() < MAX_SUBSTITUTIONS {
        let open = match (bytes[index], bytes.get(index + 1)) {
            // `$((` is arithmetic.
            (b'$', Some(b'(')) if bytes.get(index + 2) != Some(&b'(') => "$(",
            (b'<', Some(b'(')) => "<(",
            (b'`', _) => "`",
            _ => {
                index += 1;
                continue;
            }
        };
        let inside = index + open.len();
        if open == "`" {
            let length = text[inside..].find('`').unwrap_or(text.len() - inside);
            found.push(Substitution {
                open,
                start: index,
                body: &text[inside..inside + length],
            });
            // Past the closing backtick: it does not open another.
            index = inside + length + 1;
        } else {
            found.push(Substitution {
                open,
                start: index,
                body: argument(&text[inside..]),
            });
            // On into the body, for the substitutions nested in it.
            index = inside;
        }
    }
    found
}

/// How much of a line's substitutions may be read beyond twice the line's
/// own length.
const MAX_NESTED: usize = 64 * 1024;

/// How much of the substitutions of one line is still read. A substitution
/// inside another holds the same text again, so sixty-four of them, each
/// reaching to the end of a long line, are sixty-four times the line: they
/// are read up to twice the line's length and `MAX_NESTED` more. A line of
/// a kibibyte never holds more, and neither does one whose substitutions
/// are not inside one another.
pub(super) struct Reading {
    left: usize,
}

impl Reading {
    pub(super) const fn of(line: &str) -> Self {
        Self {
            left: line.len().saturating_mul(2).saturating_add(MAX_NESTED),
        }
    }

    /// Whether `body` is still read. A rule that asks whether a body holds
    /// something must answer for one that is not read as for a line too
    /// long to read: by taking it to hold what is looked for. Only the
    /// naming of files a line reads in (`run::reads_in_file`) leaves an
    /// unread body out, having nothing to name; the rules that read the
    /// same line report it.
    pub(super) fn takes(&mut self, body: &str) -> bool {
        match self.left.checked_sub(body.len()) {
            Some(left) => {
                self.left = left;
                true
            }
            None => false,
        }
    }
}

/// Splits `text` at each of `separators` that stands outside quotes and
/// substitutions. A two-character separator is tried before a single one.
pub(super) fn split_top<'a>(text: &'a str, separators: &[&str]) -> Vec<&'a str> {
    let bytes = text.as_bytes();
    let mut parts = Vec::new();
    let mut quote: Option<u8> = None;
    let mut depth = 0_usize;
    let mut backtick = false;
    let mut start = 0;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        match quote {
            Some(b'\'') => {
                if byte == b'\'' {
                    quote = None;
                }
                index += 1;
                continue;
            }
            Some(_) if byte == b'"' => quote = None,
            None if byte == b'"' || byte == b'\'' => quote = Some(byte),
            _ => {}
        }
        match byte {
            b'`' => backtick = !backtick,
            b'(' if quote.is_none()
                || depth > 0
                || matches!(
                    index.checked_sub(1).map(|at| bytes[at]),
                    Some(b'$' | b'<' | b'>')
                ) =>
            {
                depth += 1;
            }
            b')' if depth > 0 => depth -= 1,
            _ => {}
        }
        // Separators are ASCII, so a continuation byte cannot begin one;
        // slicing there would also split a character.
        if quote.is_none() && depth == 0 && !backtick && text.is_char_boundary(index) {
            let rest = &text[index..];
            if let Some(separator) = separators
                .iter()
                .find(|separator| rest.starts_with(**separator))
            {
                parts.push(&text[start..index]);
                index += separator.len();
                start = index;
                continue;
            }
        }
        index += 1;
    }
    parts.push(&text[start..]);
    parts
}

/// The statements of a line: what `;`, `&&`, `||` and a line break divide.
pub(super) fn statements(line: &str) -> Vec<&str> {
    split_top(line, &["&&", "||", ";", "\n"])
}

/// The parts of one statement that a pipe joins.
pub(super) fn pipeline(statement: &str) -> Vec<&str> {
    // `||` first, so it is not read as two pipes.
    split_top(statement, &["||", "|"])
}

/// A program and what it is given, without quotes.
pub(super) struct Command {
    /// The program as written, with its directory.
    pub(super) path: String,
    /// The program's name without its directory.
    pub(super) program: String,
    pub(super) arguments: Vec<String>,
}

impl Command {
    /// Whether one of the command's own options is `flag` (`-c`), or a
    /// cluster of short options holding its letter (`-lc`).
    pub(super) fn has_short(&self, flag: char) -> bool {
        self.arguments
            .iter()
            .take_while(|word| word.starts_with('-'))
            .any(|word| short_flag(word, flag))
    }

    /// The arguments that are not options.
    pub(super) fn operands(&self) -> impl Iterator<Item = &str> {
        self.arguments
            .iter()
            .map(String::as_str)
            .filter(|word| !word.starts_with('-'))
    }

    pub(super) fn is_shell(&self) -> bool {
        PIPE_SHELLS.contains(&self.program.as_str())
    }
}

/// Words that run the command after them, or only open a block.
const WRAPPERS: &[&str] = &[
    "sudo", "doas", "run0", "env", "command", "exec", "nice", "nohup", "setsid", "stdbuf",
    "ionice", "chrt", "time", "then", "do", "else", "if", "while", "until", "!", "{", "(",
];

/// The program among `words`, which are left at what it is given: past
/// wrappers (`sudo -u x`, `env X=1`, `timeout 5`), assignments and what
/// opens a group or a block. Every rule that asks what a command runs
/// reads it here, so they agree on what a wrapper is.
pub(super) fn program_word<'a>(words: &mut impl Iterator<Item = &'a str>) -> Option<&'a str> {
    let mut elevated = false;
    // The command of a substitution that an assignment holds whole
    // (`x=$(date)`): the program, unless one follows the assignment.
    let mut held: Option<&'a str> = None;
    // What stands after the opening of one that goes on (`x=$(sudo`), read
    // next as the word it is.
    let mut opened: Option<&'a str> = None;
    loop {
        let Some(word) = opened.take().or_else(|| words.next()) else {
            return held;
        };
        let bare = word.trim_start_matches(['(', '{', '`']);
        let bare = bare.strip_prefix("$(").unwrap_or(bare);
        // `sudo -u build cmd`: the user is not the program.
        if elevated && matches!(bare, "-u" | "-g" | "--user" | "--group") {
            if words.next().is_none() {
                return held;
            }
            continue;
        }
        elevated = elevated || matches!(bare, "sudo" | "doas" | "run0");
        if bare.is_empty() || WRAPPERS.contains(&bare) || bare.starts_with('-') {
            continue;
        }
        if bare == "timeout" {
            // `timeout 5s cmd`, `timeout --signal=9 10 cmd`.
            loop {
                match words.next() {
                    Some(next) if next.starts_with('-') => {}
                    Some(_) => break,
                    None => return held,
                }
            }
            continue;
        }
        // `VAR=x cmd`: an assignment before the program.
        if bare.contains('=') && !bare.starts_with(['/', '.', '$', '=']) {
            match substituted(bare) {
                // `x=$(date) sh f`: the program follows; the command in
                // the substitution is it only when none does.
                Some(Substituted::Whole(command)) => held = held.or(command),
                // `x=$(sha256sum f`: the value is a command that goes on,
                // and what follows is given to it.
                Some(Substituted::Open(rest)) => opened = (!rest.is_empty()).then_some(rest),
                None => {}
            }
            continue;
        }
        return Some(bare);
    }
}

/// The command an assignment's value runs.
enum Substituted<'a> {
    /// The substitution closes within the word (`x=$(date)`,
    /// `PATH=$(pwd)/bin`): its command, if it names one.
    Whole(Option<&'a str>),
    /// It goes on in the words after (`x=$(cmd`): what stands after its
    /// opening, which is empty when the command is the next word.
    Open(&'a str),
}

/// Reads the substitution an assignment's value begins with (`x=$(cmd`, or
/// with a backtick). `$((` is arithmetic, which runs nothing.
fn substituted(assignment: &str) -> Option<Substituted<'_>> {
    let (_, value) = assignment.split_once('=')?;
    let (inner, backtick) = match value.strip_prefix("$(") {
        Some(inner) => (inner, false),
        None => (value.strip_prefix('`')?, true),
    };
    if !backtick && inner.starts_with('(') {
        return None;
    }
    let end = if backtick {
        inner.find('`')
    } else {
        let mut depth = 1_usize;
        inner.char_indices().find_map(|(at, character)| {
            match character {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {}
            }
            (depth == 0).then_some(at)
        })
    };
    Some(match end {
        Some(end) => Substituted::Whole(inner[..end].split_whitespace().next()),
        None => Substituted::Open(inner),
    })
}

/// The command a statement, or one part of a pipeline, runs: past wrappers
/// (`sudo`, `env X=1`, `timeout 5`) and what opens a group.
pub(super) fn command(part: &str) -> Option<Command> {
    let words = unquoted_words(part);
    let mut words = words.iter().map(String::as_str);
    let path = program_word(&mut words)?.to_string();
    let arguments = words
        .map(|word| word.trim_end_matches(';').to_string())
        .filter(|word| !word.is_empty())
        .collect();
    Some(Command {
        program: program_name(&path).to_string(),
        path,
        arguments,
    })
}

/// The last statement of a pipeline part cut at pipes alone, which is the
/// one whose output the pipe carries on: `a; b` gives `b`.
pub(super) fn piped_statement(part: &str) -> &str {
    let last = part.rsplit(';').next().unwrap_or(part);
    last.rsplit("&&").next().unwrap_or(last)
}

/// Whether the command whose output a pipe carries on from `part` is one
/// `accepts`. A part cut at a pipe may open a quote it does not close
/// (`sh -c "a; b | c"`), so it is read both with its quotes and without.
pub(super) fn pipes_from(part: &str, accepts: &dyn Fn(&Command) -> bool) -> bool {
    let quoted = statements(part).last().copied().unwrap_or(part);
    [quoted, piped_statement(part)]
        .iter()
        .any(|statement| command(statement).is_some_and(|command| accepts(&command)))
}

/// The file one command writes its output to: by a redirection, as `tee`,
/// or through `-out`.
pub(super) fn written_file(part: &str) -> Option<String> {
    let words = unquoted_words(part);
    let tee = words
        .first()
        .is_some_and(|word| program_name(word) == "tee");
    let mut rest = words.iter().skip(usize::from(tee));
    while let Some(word) = rest.next() {
        let name = match word.as_str() {
            ">" | ">>" | "-out" => rest.next().map(String::as_str),
            _ if tee && !word.starts_with('-') => Some(word.as_str()),
            _ => [">>", ">"]
                .iter()
                .find_map(|redirect| word.strip_prefix(redirect)),
        };
        if let Some(name) = name
            && !name.is_empty()
            && !name.starts_with('&')
            && !name.starts_with("/dev/")
        {
            return super::as_file(name);
        }
    }
    None
}

/// Whether the output of the substitution `found` in `line` is run: `eval
/// "$(…)"`, `sh -c "$(…)"`, `bash <<< "$(…)"`, `source <(…)`, `bash <(…)`.
/// A substitution that is only an argument or a value is not.
pub(super) fn is_run(line: &str, found: &Substitution<'_>) -> bool {
    let before = &line[..found.start];
    let statement = before
        .rsplit([';', '|', '\n'])
        .next()
        .unwrap_or(before)
        .rsplit("&&")
        .next()
        .unwrap_or(before);
    let Some(command) = command(statement) else {
        return false;
    };
    if found.open == "<(" {
        return command.is_shell() || matches!(command.program.as_str(), "source" | ".");
    }
    command.program == "eval"
        || (command.is_shell()
            && (command.has_short('c')
                || before.trim_end_matches(['"', '\'', ' ']).ends_with("<<<")))
}

/// Whether `line` runs the output of a substitution whose body `source`
/// accepts.
pub(super) fn runs_substitution(line: &str, source: &dyn Fn(&str) -> bool) -> bool {
    if !(line.contains("$(") || line.contains("<(") || line.contains('`')) {
        return false;
    }
    // Whether it is run is asked first: that reads the command before it,
    // and its body is read only then.
    let mut reading = Reading::of(line);
    substitutions(line)
        .iter()
        .any(|found| is_run(line, found) && (!reading.takes(found.body) || source(found.body)))
}

/// The names `word` is a reference to, quoted or not: `x` for `$x` and for
/// `${x}`. What follows the `$` is one, and so is what stands in braces
/// after it.
pub(super) fn referenced(word: &str) -> [Option<&str>; 2] {
    let rest = word.trim().trim_matches(['"', '\'']).strip_prefix('$');
    let braced = rest
        .and_then(|rest| rest.strip_prefix('{'))
        .and_then(|rest| rest.strip_suffix('}'));
    [rest, braced]
}

/// A variable name as a shell accepts it.
pub(super) fn is_name(word: &str) -> bool {
    word.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && word.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The assignments a statement makes, as (name, value as written):
/// `x=1`, `export x=$(…)`, `local a=1 b=2`.
pub(super) fn assignments(statement: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let words = shell_words(statement);
    let mut declaring = false;
    for (index, word) in words.iter().enumerate() {
        if matches!(
            word.as_str(),
            "export" | "local" | "declare" | "typeset" | "readonly"
        ) && index == 0
        {
            declaring = true;
            continue;
        }
        if declaring && word.starts_with('-') {
            continue;
        }
        let Some((name, value)) = word.split_once('=') else {
            break;
        };
        let name = name.strip_suffix('+').unwrap_or(name);
        if !is_name(name) {
            break;
        }
        // An unquoted substitution holds spaces: its words are the rest.
        let value = if value.starts_with("$(") || value.starts_with('`') {
            let at = statement.find(word.as_str()).unwrap_or(0) + name.len() + 1;
            statement.get(at..).unwrap_or(value).trim().to_string()
        } else {
            value.to_string()
        };
        let whole = value.starts_with("$(") || value.starts_with('`');
        found.push((name.to_string(), value));
        if whole || !declaring {
            // `x=1 cmd` runs cmd; only a declaration lists several.
            break;
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::{
        argument, assignments, command, pipeline, referenced, runs_substitution, statements,
        substitutions,
    };

    #[test]
    fn substitutions_are_found_with_the_ones_nested_in_them() {
        let found = substitutions("eval \"$(echo \"$(cat x)\" | tr a b)\" `id` $((1 + 2))");
        let bodies: Vec<&str> = found.iter().map(|found| found.body).collect();
        assert_eq!(bodies, ["echo \"$(cat x)\" | tr a b", "cat x", "id"]);
        assert_eq!(argument("a(b)c) d"), "a(b)c");
        assert_eq!(argument("never closed"), "never closed");
    }

    #[test]
    fn a_line_is_divided_outside_quotes_and_substitutions() {
        assert_eq!(
            statements("a \"b; c\" && d $(e; f) || g; h"),
            ["a \"b; c\" ", " d $(e; f) ", " g", " h"]
        );
        assert_eq!(
            pipeline("a 'x | y' | b \"$(c | d)\" || e"),
            ["a 'x | y' ", " b \"$(c | d)\" ", " e"]
        );
    }

    #[test]
    fn the_program_is_read_past_wrappers() {
        for (part, program, arguments) in [
            (
                "sudo -E env X=1 bash -lc 'x y'",
                "bash",
                &["-lc", "x y"][..],
            ),
            ("timeout --signal=9 10 /usr/bin/sh -s", "sh", &["-s"]),
            ("( X=1 eval \"$x\";", "eval", &["$x"]),
            ("if ! rev", "rev", &[]),
        ] {
            let found = command(part).unwrap_or_else(|| panic!("{part}"));
            assert_eq!(found.program, program, "{part}");
            assert_eq!(found.arguments, arguments, "{part}");
        }
        assert!(command("X=1").is_none());
        assert!(command("sudo").is_none());
    }

    #[test]
    fn words_names_and_option_clusters_are_read_one_way() {
        use super::{program_name, program_word, short_flag, unquoted_words, unversioned};
        assert_eq!(
            unquoted_words("a \"b c\" 'd'e  \"f"),
            ["a", "b c", "de", "f"]
        );
        assert_eq!(program_name("/usr/bin/python3.12"), "python3.12");
        for (program, plain) in [
            ("python3.12", "python"),
            ("pip3", "pip"),
            ("sh", "sh"),
            ("7", ""),
        ] {
            assert_eq!(unversioned(program), plain, "{program}");
        }
        for (word, held) in [
            ("-k", true),
            ("-fsSLk", true),
            ("-s", false),
            ("--k", false),
            ("--insecure-k", false),
            ("-k=1", false),
            ("-", false),
            ("k", false),
        ] {
            assert_eq!(short_flag(word, 'k'), held, "{word}");
        }
        // The words after the program are left for the caller.
        let mut words = "sudo -u build timeout 5 X=1 (sh -c x".split(' ');
        assert_eq!(program_word(&mut words), Some("sh"));
        assert_eq!(words.collect::<Vec<_>>(), ["-c", "x"]);
        assert_eq!(program_word(&mut "nohup env".split(' ')), None);
    }

    #[test]
    fn only_a_substitution_that_is_run_counts() {
        let any = |_: &str| true;
        for line in [
            "eval \"$(x)\"",
            "sudo bash -c \"$(x)\"",
            "sh -ec \"$(x)\"",
            "bash <<< \"$(x)\"",
            "source <(x)",
            ". <(x)",
            "a; bash <(x)",
            "eval `x`",
        ] {
            assert!(runs_substitution(line, &any), "{line}");
        }
        for line in [
            "v=$(x)",
            "echo \"$(x)\"",
            "diff <(x) y",
            "bash script.sh \"$(x)\"",
            "cat <<< \"$(x)\"",
            "eval \"$y\"",
        ] {
            assert!(!runs_substitution(line, &any), "{line}");
        }
    }

    #[test]
    fn assignments_and_references_are_read() {
        let pairs = |statement: &str| assignments(statement);
        assert_eq!(pairs("x=1"), [("x".to_string(), "1".to_string())]);
        assert_eq!(
            pairs("export x=\"$(curl -s https://x.example/a)\""),
            [(
                "x".to_string(),
                "\"$(curl -s https://x.example/a)\"".to_string()
            )]
        );
        assert_eq!(
            pairs("x=$(mktemp -d)"),
            [("x".to_string(), "$(mktemp -d)".to_string())]
        );
        assert_eq!(
            pairs("local -r a=1 b=2"),
            [
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "2".to_string())
            ]
        );
        assert!(pairs("make CC=gcc").is_empty());
        assert!(pairs("[ $a = 1 ]").is_empty());
        let is_reference = |word: &str, name: &str| referenced(word).contains(&Some(name));
        assert!(is_reference("\"${x}\"", "x"));
        assert!(is_reference("$x", "x"));
        assert!(!is_reference("$xy", "x"));
        assert!(!is_reference("\"$x/y\"", "x"));
        assert_eq!(referenced("x"), [None, None]);
    }

    #[test]
    fn substitutions_inside_one_another_are_read_up_to_a_measure() {
        use super::{MAX_NESTED, Reading};
        let none = |_: &str| false;
        let any = |_: &str| true;
        // A few inside one another are each read.
        assert!(!runs_substitution("eval $(a $(b $(c $(d))))", &none));
        assert!(runs_substitution("eval $(a $(b $(c $(d))))", &|body| body == "d"));
        // Sixty-four that each reach the end of a long line are more than is
        // read: a line that runs them is taken to run what is looked for.
        let nested = "$(x ".repeat(50_000);
        assert!(runs_substitution(&format!("eval {nested}"), &none));
        // One that is not run is not read at all.
        assert!(!runs_substitution(&nested, &any));
        assert!(!runs_substitution(&format!("echo {nested}"), &any));
        // As many side by side are no more than the line.
        let beside = "$(x) ".repeat(50_000);
        assert!(!runs_substitution(&format!("eval {beside}"), &none));
        let mut reading = Reading::of("abcd");
        assert!(reading.takes(&"x".repeat(8 + MAX_NESTED)));
        assert!(!reading.takes("x"));
        assert!(reading.takes(""));
    }
}
