//! Reads shell start-up files line by line, to tell whether the line that
//! loads Guardian's Bash interceptor can take effect, and whether an alias
//! or function stands in front of an AUR helper.
//!
//! This is a line scanner, not a shell: it follows blocks, here-documents
//! and continued lines by their usual spelling. It errs towards "not
//! effective". What another file sourced from here does is not seen.

/// What the interceptor defines. Unset, redefined or aliased after it is
/// loaded, the command goes straight to Omarchy again.
pub const INTERCEPTED: [&str; 6] = [
    "omarchy",
    "omarchy-theme-install",
    "omarchy-theme-update",
    "omarchy-plugin-add",
    "omarchy-plugin-update",
    "_omarchy_guardian_help_requested",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Loads {
    /// Nothing in the file names the interceptor.
    Missing,
    Effective,
    /// The file names it, and it does not take effect: why.
    Ineffective(String),
}

/// The words of a line of code: split at blanks and `;`.
fn words(code: &str) -> Vec<&str> {
    code.split(|character: char| character.is_whitespace() || character == ';')
        .filter(|word| !word.is_empty())
        .collect()
}

/// The first word of each command on a line: after `;`, `&&`, `||`, `|`.
fn command_words(code: &str) -> Vec<&str> {
    code.split([';', '&', '|'])
        .filter_map(|command| command.split_whitespace().next())
        .collect()
}

/// How many blocks a line opens, less how many it closes.
fn nesting(code: &str) -> (usize, usize) {
    let commands = command_words(code);
    let opened = commands
        .iter()
        .filter(|word| matches!(**word, "if" | "while" | "until" | "for" | "case" | "select"))
        .count()
        + words(code)
            .iter()
            .filter(|word| **word == "{" || word.ends_with("(){"))
            .count();
    let closed = commands
        .iter()
        .filter(|word| matches!(**word, "fi" | "done" | "esac"))
        .count()
        + words(code).iter().filter(|word| **word == "}").count();
    (opened, closed)
}

/// A line of code as the scanner reads it.
struct Scanned {
    /// The line without its comment and without what is inside quotes: a
    /// word in a string or after `#` is not a command.
    bare: String,
    /// The word that ends a here-document started on this line, if one is.
    document: Option<String>,
}

/// Reads one line: drops quoted text and the comment, and finds a
/// here-document's end word. `<<` inside `(( ))` or `$(( ))` is a shift,
/// and `<<<` a here-string: neither starts a document.
fn scan(code: &str) -> Scanned {
    let characters: Vec<char> = code.chars().collect();
    let mut bare = String::new();
    let mut document = None;
    let mut arithmetic = 0_usize;
    let mut index = 0;
    while index < characters.len() {
        let character = characters[index];
        let next = characters.get(index + 1).copied();
        match character {
            // The escaped character is text.
            '\\' => {
                bare.push(' ');
                index += 1;
            }
            '\'' | '"' => {
                index = closing_quote(&characters, index);
                bare.push(' ');
            }
            '#' if index == 0 || characters[index - 1].is_whitespace() => break,
            '(' if next == Some('(') => {
                arithmetic += 1;
                bare.push_str("((");
                index += 1;
            }
            ')' if next == Some(')') && arithmetic > 0 => {
                arithmetic -= 1;
                bare.push_str("))");
                index += 1;
            }
            '<' if next == Some('<') && arithmetic == 0 => {
                if characters.get(index + 2) == Some(&'<') {
                    index += 2;
                } else {
                    if document.is_none() {
                        document = end_word(&characters[index + 2..]);
                    }
                    index += 1;
                }
                bare.push(' ');
            }
            _ => bare.push(character),
        }
        index += 1;
    }
    Scanned { bare, document }
}

/// The index of the quote that closes the one at `open` (the last
/// character when it is never closed). Inside double quotes a backslash
/// keeps the next character.
fn closing_quote(characters: &[char], open: usize) -> usize {
    let quote = characters[open];
    let mut index = open + 1;
    while index < characters.len() {
        if characters[index] == '\\' && quote == '"' {
            index += 2;
            continue;
        }
        if characters[index] == quote {
            return index;
        }
        index += 1;
    }
    characters.len().saturating_sub(1)
}

/// The end word of a here-document, from what follows its `<<`.
fn end_word(rest: &[char]) -> Option<String> {
    let word: String = rest
        .iter()
        .skip_while(|character| **character == '-')
        .skip_while(|character| character.is_whitespace())
        .take_while(|character| !character.is_whitespace() && **character != ';')
        .filter(|character| !matches!(character, '\'' | '"' | '\\'))
        .collect();
    (!word.is_empty()).then_some(word)
}

/// Whether a line is the usual "stop here unless this shell is
/// interactive" guard, the one place a `return` before Guardian's line is
/// fine (the interceptor is for interactive shells): a test of `$-` for
/// `i`, or of `$PS1` for being empty, that returns when the shell is not
/// interactive, or a one-line `case $- in`.
fn interactive_guard(code: &str) -> bool {
    let plain: String = code
        .chars()
        .filter(|character| !matches!(character, '"' | '\''))
        .collect();
    let words: Vec<&str> = plain.split_whitespace().collect();
    if words.starts_with(&["case", "$-", "in"]) {
        return plain.contains("*i*") && words.last() == Some(&"esac");
    }
    let Some(at) = words.iter().position(|word| matches!(*word, "&&" | "||")) else {
        return false;
    };
    let action: Vec<&str> = words[at + 1..]
        .iter()
        .map(|word| word.trim_end_matches(';'))
        .filter(|word| !word.is_empty())
        .collect();
    let returns = match action.as_slice() {
        ["return"] => true,
        ["return", code] => code.parse::<u8>().is_ok(),
        _ => false,
    };
    let (["[", inner @ .., "]"] | ["[[", inner @ .., "]]"] | ["test", inner @ ..]) = &words[..at]
    else {
        return false;
    };
    let prompt = |word: &str| matches!(word, "$PS1" | "${PS1}" | "${PS1-}" | "${PS1:-}");
    // What the test is true for: a shell that is not interactive, or one
    // that is.
    let (not_interactive, interactive) = match inner {
        ["-z", word] => (prompt(word), false),
        ["-n", word] | [word] => (false, prompt(word)),
        ["$-" | "${-}", "!=", "*i*"] | ["!", "$-" | "${-}", "=~", "i"] => (true, false),
        ["$-" | "${-}", "==" | "=", "*i*"] | ["$-" | "${-}", "=~", "i"] => (false, true),
        _ => (false, false),
    };
    returns && ((not_interactive && words[at] == "&&") || (interactive && words[at] == "||"))
}

/// Whether a line defines a function called `name`.
fn defines_function(code: &str, name: &str) -> bool {
    let words = words(code);
    let bare = |word: &str| word.split('(').next().unwrap_or_default() == name;
    match words.as_slice() {
        ["function", word, ..] => bare(word),
        [word, rest @ ..] => {
            (word.starts_with(name) && bare(word) && word.contains("()"))
                || (*word == name && rest.first().is_some_and(|next| next.starts_with("()")))
        }
        [] => false,
    }
}

/// Whether a line makes an alias called `name` (Bash, zsh or fish).
fn defines_alias(code: &str, name: &str) -> bool {
    let words = words(code);
    if words.first() != Some(&"alias") {
        return false;
    }
    let mut named = words[1..].iter().filter(|word| !word.starts_with('-'));
    // fish spells it `alias name value`.
    named.clone().next() == Some(&name)
        || named.any(|word| {
            word.strip_prefix(name)
                .is_some_and(|rest| rest.starts_with('='))
        })
}

/// The lines of `text` that are code: not blank, not comments.
fn code_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
}

/// Whether `source_line`, the exact line Guardian writes, is in `text` (a
/// `~/.bashrc`) where it runs, with nothing after it that takes the
/// interceptor's functions away again. `path` is the interceptor's own.
pub fn interceptor(text: &str, source_line: &str, path: &str) -> Loads {
    let mut depth = 0_usize;
    let mut document: Option<String> = None;
    let mut continued = false;
    let mut returned = false;
    // The last such line and what is wrong with where it stands.
    let mut found: Option<(usize, Option<&str>)> = None;
    for (index, line) in text.lines().enumerate() {
        let code = line.trim();
        if let Some(end) = &document {
            if code == end {
                document = None;
            } else if code == source_line {
                found = Some((index, Some("it is inside a here-document")));
            }
            continue;
        }
        if code.is_empty() || code.starts_with('#') {
            continued = false;
            continue;
        }
        if code == source_line {
            let problem = if continued {
                Some("it continues the line before it")
            } else if depth > 0 {
                Some("it is inside a function or block")
            } else if returned {
                Some("a `return` or `exit` comes before it")
            } else {
                None
            };
            found = Some((index, problem));
            continued = false;
            continue;
        }
        let scanned = scan(code);
        let (opened, closed) = nesting(&scanned.bare);
        // Not inside a block, and not in one written on this line (a
        // one-line function). What is quoted or in a comment is no
        // command, and the "stop here unless interactive" line is the one
        // `return` before it that is fine.
        if depth == 0
            && opened == 0
            && !interactive_guard(code)
            && words(&scanned.bare)
                .iter()
                .any(|word| matches!(*word, "return" | "exit"))
        {
            returned = true;
        }
        depth = (depth + opened).saturating_sub(closed);
        document = scanned.document;
        continued = code.ends_with('\\') && !code.ends_with("\\\\");
    }

    let Some((index, problem)) = found else {
        return if code_lines(text).any(|line| line.contains(path)) {
            Loads::Ineffective(
                "a line names the interceptor, but it is not the line Guardian writes".into(),
            )
        } else {
            Loads::Missing
        };
    };
    if let Some(problem) = problem {
        return Loads::Ineffective(problem.into());
    }
    // An alias is tried before a function, and one made earlier even
    // renames the function as it is defined: anywhere in the file counts.
    for name in INTERCEPTED.iter().chain(&["source"]) {
        if code_lines(text).any(|line| defines_alias(line, name)) {
            return Loads::Ineffective(format!("an alias named `{name}` stands in front of it"));
        }
    }
    for line in text.lines().skip(index + 1).map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        for name in INTERCEPTED {
            let words = words(line);
            if words.contains(&"unset") && words.contains(&name) {
                return Loads::Ineffective(format!("a later line unsets `{name}`"));
            }
            if defines_function(line, name) {
                return Loads::Ineffective(format!("a later line redefines `{name}`"));
            }
        }
    }
    Loads::Effective
}

/// Whether `text` (a shell start-up file) has an alias or function called
/// `helper` that itself passes `--makepkg` with something other than `gate`
/// (Guardian's own shim): the helper then builds with whatever that names,
/// whatever its saved configuration says. `--makepkg` on another command
/// of the file is not an override of this helper.
pub fn overrides_makepkg(text: &str, helper: &str, gate: &str) -> bool {
    let lines: Vec<&str> = code_lines(text).collect();
    lines.iter().enumerate().any(|(index, line)| {
        if defines_alias(line, helper) {
            passes_other_makepkg(line, gate)
        } else if defines_function(line, helper) {
            function_body(&lines[index..])
                .iter()
                .any(|line| passes_other_makepkg(line, gate))
        } else {
            false
        }
    })
}

/// The lines of the function that starts on the first of `lines`: to the
/// `}` that closes it, or (fish, which has no braces) to its `end`.
fn function_body<'a>(lines: &'a [&'a str]) -> &'a [&'a str] {
    let braces = lines.iter().take(2).any(|line| line.contains('{'));
    let mut depth = 0_usize;
    for (index, line) in lines.iter().enumerate() {
        let (opened, closed) = if braces {
            nesting(&scan(line).bare)
        } else {
            let first = line.split_whitespace().next().unwrap_or_default();
            (
                usize::from(matches!(
                    first,
                    "function" | "if" | "for" | "while" | "switch" | "begin"
                )),
                usize::from(first == "end"),
            )
        };
        depth = (depth + opened).saturating_sub(closed);
        if depth == 0 && (index > 0 || opened > 0) {
            return &lines[..=index];
        }
    }
    lines
}

/// Whether a line passes `--makepkg` with a value that is not `gate`.
fn passes_other_makepkg(line: &str, gate: &str) -> bool {
    let plain: String = line
        .chars()
        .map(|character| {
            if matches!(character, '"' | '\'' | ';' | '=') {
                ' '
            } else {
                character
            }
        })
        .collect();
    let words: Vec<&str> = plain.split_whitespace().collect();
    words
        .iter()
        .enumerate()
        .any(|(index, word)| *word == "--makepkg" && words.get(index + 1) != Some(&gate))
}

#[cfg(test)]
mod tests {
    use super::{Loads, interceptor, overrides_makepkg};

    const PATH: &str = "/usr/lib/omarchy-guardian/omarchy-bash-interceptor.sh";
    const LINE: &str = "[[ -r /usr/lib/omarchy-guardian/omarchy-bash-interceptor.sh ]] && source /usr/lib/omarchy-guardian/omarchy-bash-interceptor.sh";

    fn loads(text: &str) -> Loads {
        interceptor(text, LINE, PATH)
    }

    fn why(text: &str) -> String {
        match loads(text) {
            Loads::Ineffective(why) => why,
            other => panic!("{other:?} for {text}"),
        }
    }

    #[test]
    fn only_guardians_own_line_where_it_runs_loads_the_interceptor() {
        let usual = format!(
            "[[ $- != *i* ]] && return\nsource \"$OMARCHY_PATH/default/bash/rc\"\nalias p='python'\n\n# Omarchy Guardian theme command interception\n{LINE}\n\nalias cc='claude'\nf() {{\n  echo x\n}}\n"
        );
        assert_eq!(loads(&usual), Loads::Effective);
        assert_eq!(loads(&format!("  {LINE}  \n")), Loads::Effective);
        assert_eq!(loads("alias ll='ls -l'\n"), Loads::Missing);
        assert_eq!(loads(&format!("# {LINE}\n")), Loads::Missing);

        // Looks like it, and loads nothing.
        assert!(why(&format!(": source {PATH}\n")).contains("not the line Guardian writes"));
        assert!(why(&format!("{LINE} && unset -f omarchy\n")).contains("not the line"));
        assert!(why(&format!("true || {LINE}\n")).contains("not the line"));
    }

    #[test]
    fn a_line_that_never_runs_is_not_effective() {
        assert!(why(&format!("never() {{\n{LINE}\n}}\n")).contains("function or block"));
        assert!(why(&format!("if false; then\n  {LINE}\nfi\n")).contains("function or block"));
        assert!(why(&format!("cat <<'EOF' >/dev/null\n{LINE}\nEOF\n")).contains("here-document"));
        assert!(why(&format!("echo \\\n{LINE}\n")).contains("continues"));
        assert!(why(&format!("return\n{LINE}\n")).contains("`return` or `exit`"));
        assert!(why(&format!("true && exit 0\n{LINE}\n")).contains("`return` or `exit`"));
        // A block that closed before it, and a return inside one, are fine.
        assert_eq!(
            loads(&format!(
                "if x; then\n  return\nfi\ng() {{ return; }}\ncat <<EOF\nreturn\nEOF\n{LINE}\n"
            )),
            Loads::Effective
        );
        assert_eq!(
            loads(&format!("case $- in *i*) ;; *) return;; esac\n{LINE}\n")),
            Loads::Effective
        );
    }

    #[test]
    fn what_takes_the_functions_away_again_is_not_effective() {
        assert!(why(&format!("{LINE}\nunset -f omarchy\n")).contains("unsets `omarchy`"));
        assert!(
            why(&format!("{LINE}\nunset -f x omarchy-plugin-add\n")).contains("omarchy-plugin-add")
        );
        assert!(
            why(&format!(
                "{LINE}\nomarchy() {{ command omarchy \"$@\"; }}\n"
            ))
            .contains("redefines")
        );
        assert!(
            why(&format!(
                "{LINE}\nfunction omarchy-theme-install {{\n:\n}}\n"
            ))
            .contains("redefines")
        );
        assert!(
            why(&format!(
                "{LINE}\nalias omarchy=/usr/share/omarchy/bin/omarchy\n"
            ))
            .contains("alias")
        );
        assert!(why(&format!("alias omarchy='x'\n{LINE}\n")).contains("alias"));
        // Before it, a function of that name is replaced by the
        // interceptor's; other names are nobody's business.
        assert_eq!(
            loads(&format!(
                "omarchy() {{ :; }}\n{LINE}\nunset -f other\nalias omarchyx=1\nomarchy-theme-list() {{ :; }}\n"
            )),
            Loads::Effective
        );
    }

    #[test]
    fn the_usual_bashrc_lines_before_it_do_not_make_it_ineffective() {
        // Each of these once read "a `return` or `exit` comes before it",
        // which turning the gate on again could not repair.
        for before in [
            "[ -z \"$PS1\" ] && return",
            "[[ -z $PS1 ]] && return",
            "[ -n \"${PS1-}\" ] || return 0",
            "[[ $- != *i* ]] && return",
            "[[ \"$-\" == *i* ]] || return;",
            "[[ $- =~ i ]] || return",
            "case $- in *i*) ;; *) return;; esac",
            "echo \"type exit to leave\"",
            "echo 'return here'",
            "export FOO=bar # exit code of last",
            "# exit",
            "alias e='exit'",
            // A shift and a here-string start no here-document, which
            // would swallow the rest of the file.
            "x=$(( 1 << 3 ))",
            "(( y = 1 << 2 ))",
            "read -r first <<< \"$line\"",
        ] {
            assert_eq!(
                loads(&format!("{before}\n{LINE}\n")),
                Loads::Effective,
                "{before}"
            );
        }
    }

    #[test]
    fn what_really_keeps_it_from_running_still_reads_ineffective() {
        for before in [
            "return",
            "exit 0",
            "true && exit",
            "[ -f ~/.x ] && return",
            // Returns when the shell *is* interactive.
            "[[ $- == *i* ]] && return",
            "[ -n \"$PS1\" ] && return",
            "[ -z \"$PS1\" ] && return; return",
            "echo \"a\" ; exit",
        ] {
            assert!(
                why(&format!("{before}\n{LINE}\n")).contains("`return` or `exit`"),
                "{before}"
            );
        }
        assert!(why(&format!("if false; then\n  {LINE}\nfi\n")).contains("function or block"));
        assert!(why(&format!("cat <<EOF\n{LINE}\nEOF\n")).contains("here-document"));
        assert!(why(&format!("cat << 'END' # note\n{LINE}\nEND\n")).contains("here-document"));
        assert!(why(&format!("{LINE}\nunset -f omarchy\n")).contains("unsets `omarchy`"));
    }

    const GATE: &str = "/usr/lib/omarchy-guardian/guardian-makepkg";

    #[test]
    fn an_alias_or_function_in_front_of_a_helper_that_passes_makepkg_is_found() {
        assert!(overrides_makepkg(
            "alias yay='yay --makepkg /usr/bin/makepkg'\n",
            "yay",
            GATE
        ));
        assert!(overrides_makepkg(
            "yay() {\n  command yay --makepkg makepkg \"$@\"\n}\n",
            "yay",
            GATE
        ));
        assert!(overrides_makepkg(
            "yay() { command yay --makepkg=/tmp/x \"$@\"; }\n",
            "yay",
            GATE
        ));
        assert!(overrides_makepkg(
            "function paru\n  if true\n    command paru --makepkg makepkg $argv\n  end\nend\n",
            "paru",
            GATE
        ));
        assert!(!overrides_makepkg(
            "alias yay='yay --noconfirm'\n",
            "yay",
            GATE
        ));
        assert!(!overrides_makepkg(
            "# alias yay='yay --makepkg makepkg'\n",
            "yay",
            GATE
        ));
        assert!(!overrides_makepkg(
            "alias y='yay --makepkg makepkg'\n",
            "paru",
            GATE
        ));
    }

    #[test]
    fn makepkg_on_another_line_or_guardians_own_shim_is_no_override() {
        // An alias of the helper's name, and `--makepkg` on some other
        // command of the file.
        assert!(!overrides_makepkg(
            "alias yay='yay --noconfirm'\nalias p='paru --makepkg /usr/bin/makepkg'\n",
            "yay",
            GATE
        ));
        assert!(!overrides_makepkg(
            "yay() {\n  command yay \"$@\"\n}\nbuild() {\n  paru --makepkg makepkg\n}\n",
            "yay",
            GATE
        ));
        assert!(!overrides_makepkg(
            "function yay\n  command yay $argv\nend\nfunction b\n  paru --makepkg makepkg\nend\n",
            "yay",
            GATE
        ));
        // Passing Guardian's own shim keeps the build in the gate.
        assert!(!overrides_makepkg(
            &format!("alias yay='yay --makepkg {GATE}'\n"),
            "yay",
            GATE
        ));
        assert!(!overrides_makepkg(
            &format!("yay() {{\n  command yay --makepkg=\"{GATE}\" \"$@\"\n}}\n"),
            "yay",
            GATE
        ));
    }
}
