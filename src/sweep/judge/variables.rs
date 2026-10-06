//! Telling a file that only sets variables, and runs nothing, from one that
//! does more.

use super::secrets::is_secret_name;

/// Variables that decide what runs or is loaded: setting one, even to a
/// literal, is more than keeping a value.
const LOADING_NAMES: &[&str] = &[
    "PATH",
    "IFS",
    "ENV",
    "BASH_ENV",
    "PROMPT_COMMAND",
    "ZDOTDIR",
    "SHELLOPTS",
    "BASHOPTS",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONHOME",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PERL5OPT",
    "PERL5LIB",
    "RUBYOPT",
    "RUBYLIB",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_ASKPASS",
    "GIT_EXEC_PATH",
    "SSH_ASKPASS",
    "SUDO_ASKPASS",
    "EDITOR",
    "VISUAL",
    "PAGER",
    "BROWSER",
    "FISH_USER_PATHS",
];

/// Settings that are commonly exported beside secrets and that change
/// neither what runs nor what is trusted, by name and by how a name ends.
///
/// This list, like the names that say secret, is a judgement about noise,
/// not a proof: it decides only whether a file kept from the AI raises
/// `kept-from-review`. A name that is missing here costs a finding the
/// user answers once with `sweep allow`; a name wrongly here would let a
/// setting pass unsaid, so only names that hold an identifier, a region
/// or the like are on it. Listing every variable that loads or redirects
/// something cannot be done, which is why the rule allows by shape and
/// does not deny by name; `LOADING_NAMES` stays as a backstop.
const INERT_NAMES: &[&str] = &[
    "LANG",
    "TZ",
    "TERM",
    "COLORTERM",
    "USER",
    "LOGNAME",
    "HOSTNAME",
    "EMAIL",
];
const INERT_ENDINGS: &[&str] = &[
    "_ID",
    "_REGION",
    "_PROFILE",
    "_ACCOUNT",
    "_USER",
    "_USERNAME",
    "_NAME",
    "_ORG",
    "_PROJECT",
    "_ENV",
    "_STAGE",
    "_TENANT",
    "_DATABASE",
    "_DB",
    "_PORT",
    "_MODEL",
];

/// Whether setting the variable `name` to `value` only keeps a value:
/// the name is one that says secret or is a plainly inert setting, and
/// the value is an opaque word, not a place or a command (no `/`, no
/// leading `~` or `.`, no `://`, no blank). A path, an address or any
/// other variable is more than that, whatever it is called: most of what
/// redirects a program is a variable set to a path.
fn keeps_a_value(name: &str, value: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    let written = name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    let loads = LOADING_NAMES.contains(&upper.as_str())
        || ["LD_", "DYLD_", "GIT_CONFIG"]
            .iter()
            .any(|start| upper.starts_with(start))
        || upper.ends_with("_PROXY");
    // `PWD` says password as a part of a name; alone it is the shell's.
    let secret = upper != "PWD" && is_secret_name(name);
    let inert = INERT_NAMES.contains(&upper.as_str())
        || upper.starts_with("LC_")
        || INERT_ENDINGS.iter().any(|ending| upper.ends_with(ending));
    let opaque = !value.contains(['/', ' ', '\t'])
        && !value.starts_with(['~', '.'])
        && !value.contains("://");
    written && !loads && (secret || inert) && opaque
}

/// The words of `line`, each with where it starts, quotes taken off; `None`
/// for a line that holds anything a shell would expand, run, chain or
/// redirect: `$`, a backtick or a backslash anywhere, any of `;&|<>(){}`
/// outside quotes, or a quote that does not close on the line.
fn literal_words(line: &str) -> Option<Vec<(usize, String)>> {
    let mut words = Vec::new();
    let mut word: Option<(usize, String)> = None;
    let mut quote: Option<char> = None;
    for (at, character) in line.char_indices() {
        if matches!(character, '$' | '`' | '\\') {
            return None;
        }
        match quote {
            Some(open) if character == open => quote = None,
            None if matches!(character, '"' | '\'') => {
                quote = Some(character);
                word.get_or_insert((at, String::new()));
            }
            None if character.is_whitespace() => words.extend(word.take()),
            None if ";&|<>(){}".contains(character) => return None,
            // Inside quotes, or a plain character outside them.
            _ => word.get_or_insert((at, String::new())).1.push(character),
        }
    }
    if quote.is_some() {
        return None;
    }
    words.extend(word);
    Some(words)
}

/// Whether the word `word` of `line`, which starts at `at`, is written as
/// `NAME=value` with the name outside quotes, and only keeps a value.
fn assigns(line: &str, (at, word): &(usize, String)) -> bool {
    let named = line[*at..].split_once('=').map(|(name, _)| name);
    word.split_once('=')
        .is_some_and(|(name, value)| named == Some(name) && keeps_a_value(name, value))
}

/// Whether `line` does nothing but keep a value in a variable (see
/// `keeps_a_value`), in the forms a shell, fish, Hyprland or an
/// environment file writes that: `NAME=value` (several on a line, after
/// `export` too), `set -gx NAME value`, `env = NAME,value` and `$name =
/// value`. A blank line and a comment do nothing at all.
pub(super) fn sets_a_variable(line: &str) -> bool {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return true;
    }
    // Hyprland's own variable: the one place a `$` is no expansion.
    if let Some(named) = line.strip_prefix('$') {
        return named.split_once('=').is_some_and(|(name, value)| {
            literal_words(value).is_some_and(|words| match words.as_slice() {
                [] => keeps_a_value(name.trim(), ""),
                [(_, value)] => keeps_a_value(name.trim(), value),
                _ => false,
            })
        });
    }
    let Some(words) = literal_words(line) else {
        return false;
    };
    let hyprland = |setting: &str| {
        setting
            .split_once(',')
            .is_some_and(|(name, value)| keeps_a_value(name.trim(), value.trim()))
    };
    let word = |index: usize| words.get(index).map(|(_, word)| word.as_str());
    match word(0) {
        // Hyprland: `env = NAME,value`.
        Some("env")
            if word(1) == Some("=") || word(1).is_some_and(|next| next.starts_with('=')) =>
        {
            line.split_once('=')
                .is_some_and(|(_, setting)| hyprland(setting))
        }
        Some(joined) if joined.starts_with("env=") => hyprland(&joined["env=".len()..]),
        // fish: `set [-flags] NAME value`.
        Some("set") => {
            let rest: Vec<&str> = words
                .iter()
                .skip(1)
                .map(|(_, word)| word.as_str())
                .skip_while(|word| word.starts_with('-'))
                .collect();
            match rest.as_slice() {
                [name] => keeps_a_value(name, ""),
                [name, value] => keeps_a_value(name, value),
                _ => false,
            }
        }
        Some("export") => words.len() > 1 && words[1..].iter().all(|word| assigns(line, word)),
        Some(_) => words.iter().all(|word| assigns(line, word)),
        None => true,
    }
}

/// Whether every line of `text` only keeps a value in a secret-named or
/// plainly inert variable (see `sets_a_variable`): a file a shell reads in
/// can hold any command and redirect any program, and the ordinary one
/// under a secret-looking path holds only such lines. Any other line, any
/// other variable and any value that is a place makes it more than that.
pub(super) fn sets_only_variables(text: &str) -> bool {
    text.lines().all(sets_a_variable)
}
