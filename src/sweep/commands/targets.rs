//! The files a command line runs: past its wrappers to the program, the
//! script an interpreter is given, and where each is looked for.

#[cfg(test)]
use std::path::Path;

use crate::paths::file_name;
use crate::sweep::programs::{self, Argument, SCRIPT_EXTENSIONS, ScriptArguments, is_script_shell};
use crate::sweep::read::has_extension;

/// A wrapper that runs the command after it: its name, its options that
/// take the next word as their value, and how many words of its own come
/// before the command (`timeout 5 prog`, `flock file prog`).
struct Wrapper {
    name: &'static str,
    value_options: &'static [&'static str],
    own_words: usize,
}

const fn wrapper(
    name: &'static str,
    value_options: &'static [&'static str],
    own_words: usize,
) -> Wrapper {
    Wrapper {
        name,
        value_options,
        own_words,
    }
}

const WRAPPERS: &[Wrapper] = &[
    wrapper("env", &["-u", "--unset", "-C", "--chdir"], 0),
    wrapper("uwsm-app", &["-t", "-a", "-u", "-s", "-p"], 0),
    wrapper("uwsm", &["-t", "-a", "-u", "-s", "-p"], 0),
    wrapper(
        "systemd-run",
        &[
            "-p",
            "--property",
            "-u",
            "--unit",
            "--uid",
            "--gid",
            "-E",
            "--setenv",
            "--slice",
            "--working-directory",
            "-M",
            "--machine",
            "-H",
            "--host",
            "--description",
        ],
        0,
    ),
    wrapper("setsid", &[], 0),
    wrapper("nohup", &[], 0),
    wrapper("exec", &["-a"], 0),
    wrapper(
        "sudo",
        &[
            "-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "-r", "-t",
        ],
        0,
    ),
    wrapper("doas", &["-u", "-C"], 0),
    wrapper("timeout", &["-s", "--signal", "-k", "--kill-after"], 1),
    wrapper("nice", &["-n", "--adjustment"], 0),
    wrapper("ionice", &["-c", "-n", "-p"], 0),
    wrapper("flock", &["-w", "--timeout", "-E"], 1),
    wrapper("chrt", &[], 1),
    wrapper("taskset", &[], 1),
    wrapper("stdbuf", &["-i", "-o", "-e"], 0),
];

/// Subcommands of `uwsm` that run the command after them.
const UWSM_RUNS: &[&str] = &["app", "start"];

/// Where a bare command name is looked for when the real `PATH`s say
/// nothing more (see `path::search`), relative to the root; `~` stands for
/// the home directory. The directories version managers put ahead of
/// `/usr/bin` come first, as they do on a `PATH`.
const SEARCH: &[&str] = &[
    "~/.local/bin",
    "~/.cargo/bin",
    "~/bin",
    "~/.local/share/mise/shims",
    "~/go/bin",
    "~/.bun/bin",
    "~/.deno/bin",
    "~/.local/share/pnpm",
    "~/.npm-global/bin",
    "~/.nix-profile/bin",
    "usr/local/sbin",
    "usr/local/bin",
    "usr/bin",
];

/// `SEARCH` with the home directory written out.
pub(crate) fn default_search(home: &str) -> Vec<String> {
    SEARCH
        .iter()
        .map(|directory| expand(home, directory).trim_start_matches('/').to_string())
        .collect()
}

/// The files a pattern (`~/.config/hypr/conf.d/*.conf`) names: `*` and `?`
/// in its last part only, matched against what `list` says the directory
/// holds, at most `MAX_GLOB` of them; and whether there were more.
pub(crate) fn glob_targets(
    home: &str,
    pattern: &str,
    list: &dyn Fn(&str) -> Vec<String>,
) -> (Vec<String>, bool) {
    let expanded = expand(home, pattern.trim());
    let Some(absolute) = expanded.strip_prefix('/') else {
        return (Vec::new(), false);
    };
    let (directory, last) = absolute.rsplit_once('/').unwrap_or(("", absolute));
    if directory.contains(['*', '?'])
        || !last.contains(['*', '?'])
        || absolute.contains(char::is_whitespace)
    {
        return (Vec::new(), false);
    }
    let mut names: Vec<String> = list(directory)
        .into_iter()
        .filter(|name| glob_match(last, name))
        .collect();
    names.sort();
    let more = names.len() > MAX_GLOB;
    (
        names
            .into_iter()
            .take(MAX_GLOB)
            .map(|name| format!("{directory}/{name}"))
            .collect(),
        more,
    )
}

/// The most files one pattern stands for.
pub(crate) const MAX_GLOB: usize = 1024;

/// Whether `name` matches `pattern` (`*` any run, `?` one character). A
/// name starting with `.` matches only a pattern that does, as in a shell.
fn glob_match(pattern: &str, name: &str) -> bool {
    if name.starts_with('.') && !pattern.starts_with('.') {
        return false;
    }
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    let (mut p, mut n) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == name[n]) {
            p += 1;
            n += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some((p, n));
            p += 1;
        } else if let Some((star_at, matched)) = star {
            p = star_at + 1;
            n = matched + 1;
            star = Some((star_at, matched + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|character| *character == '*')
}

/// The files `command` runs, relative to the root: its program (a bare
/// name is looked up in `SEARCH`) and, for an interpreter, the script it is
/// given. `home` is the home directory relative to the root. Only paths
/// that exist under `root` are returned.
#[cfg(test)]
pub(super) fn targets(root: &Path, home: &str, command: &str) -> Vec<String> {
    targets_where(home, command, &|candidate| {
        std::fs::symlink_metadata(root.join(candidate)).is_ok()
    })
}

/// `targets`, with the caller saying which candidate paths are there.
#[cfg(test)]
pub(super) fn targets_where(
    home: &str,
    command: &str,
    exists: &dyn Fn(&str) -> bool,
) -> Vec<String> {
    Lookup {
        home,
        search: &default_search(home),
        exists,
        capped: std::cell::Cell::new(false),
        unwritten: std::cell::Cell::new(false),
        shell_scripts: std::cell::RefCell::default(),
    }
    .targets(command)
}

/// How the files a command runs are looked for.
pub(crate) struct Lookup<'a> {
    /// The home directory relative to the root.
    pub(crate) home: &'a str,
    /// Where a bare command name is looked for, in the order a shell
    /// would, relative to the root.
    pub(crate) search: &'a [String],
    /// Which candidate paths are there: as root, a path only root can read
    /// is not looked for at a user's word.
    pub(crate) exists: &'a dyn Fn(&str) -> bool,
    /// Set when a line held more commands than are looked up.
    pub(crate) capped: std::cell::Cell<bool>,
    /// Set when a command names its program or script through a variable
    /// or a substitution that is not written in (see `is_unwritten`).
    pub(crate) unwritten: std::cell::Cell<bool>,
    /// The files a shell was handed as its script (`sh /x/run`): that a
    /// shell runs a file is what says it is a shell script, whatever its
    /// name and first line.
    pub(crate) shell_scripts: std::cell::RefCell<Vec<String>>,
}

impl Lookup<'_> {
    /// The files `command` runs (see `targets`).
    pub(crate) fn targets(&self, command: &str) -> Vec<String> {
        targets_of(self, command)
    }
}

/// Steps past what comes before a command in `words`: leading assignments
/// and wrappers, with the wrappers' own options and words. Returns where
/// the command starts. A wrapper found anywhere but in `/usr/bin` (a
/// `sudo` in `~/.local/bin`) is what runs first, and is added to `found`.
fn past_wrappers(lookup: &Lookup<'_>, words: &mut Vec<String>, found: &mut Vec<String>) -> usize {
    let mut at = 0;
    while let Some(word) = words.get(at).cloned() {
        let name = file_name(&word);
        let assignment = word.contains('=') && !word.starts_with('/') && !word.starts_with('-');
        if assignment || word == "--" || word.starts_with('-') {
            at += 1;
        } else if let Some(wrapper) = WRAPPERS.iter().find(|wrapper| wrapper.name == name) {
            found.extend(
                locate(lookup, &word)
                    .into_iter()
                    .filter(|path| !path.starts_with("usr/bin/")),
            );
            at += 1;
            while let Some(option) = words.get(at).filter(|word| word.starts_with('-')).cloned() {
                at += 1;
                if option == "--" {
                    break;
                }
                // `env -S "program arguments"`: the command is in one word.
                if name == "env" && matches!(option.as_str(), "-S" | "--split-string") {
                    if let Some(inner) = words.get(at).cloned() {
                        words.splice(at..=at, split(&inner));
                    }
                    break;
                }
                if wrapper.value_options.contains(&option.as_str()) {
                    at += 1;
                }
            }
            at += wrapper.own_words;
            if name == "uwsm"
                && words
                    .get(at)
                    .is_some_and(|word| UWSM_RUNS.contains(&word.as_str()))
            {
                at += 1;
                // The subcommand's own options.
                while let Some(option) = words.get(at).filter(|word| word.starts_with('-')) {
                    let takes_value = wrapper.value_options.contains(&option.as_str());
                    let end = option == "--";
                    at += 1 + usize::from(takes_value);
                    if end {
                        break;
                    }
                }
            }
        } else {
            break;
        }
    }
    at
}

fn targets_of(lookup: &Lookup<'_>, command: &str) -> Vec<String> {
    let mut words = split(command);
    let mut found = Vec::new();
    let at = past_wrappers(lookup, &mut words, &mut found);
    let mut words = words.iter().skip(at).map(String::as_str).peekable();
    let Some(program) = words.next() else {
        return found;
    };
    if is_unwritten(lookup.home, program) {
        lookup.unwritten.set(true);
    }
    found.extend(locate(lookup, program));
    let mut name = file_name(program);
    // `busybox sh script`: the shell is the applet it is asked to be.
    if name == "busybox"
        && let Some(applet) = words.next_if(|applet| is_script_shell(applet))
    {
        name = applet;
    }
    if programs::runs_a_script(name) {
        let shell = is_script_shell(name);
        let mut arguments = ScriptArguments::of(name);
        let mut values = 0;
        while let Some(word) = words.next() {
            // `bash 2>/dev/null script`: a redirection is no argument, and
            // one whose file is the next word (`2> /dev/null`) takes it.
            if let Some(file) = redirected_to(word) {
                if file.is_empty() {
                    words.next();
                }
                continue;
            }
            // `sh -c "command line"` (also `-lc`, `-ic`) runs that line:
            // each command in it is found the same way, wrappers and
            // all. What `/usr/bin` holds is not listed again.
            // (Not `java -verbose:gc`: an option with a value of its own.)
            if word.starts_with('-')
                && !word.starts_with("--")
                && word.ends_with('c')
                && !word.contains([':', '='])
            {
                if let Some(code) = words.next() {
                    let (commands, more) = split_commands(code);
                    if more {
                        lookup.capped.set(true);
                    }
                    for command in commands {
                        for path in targets_of(lookup, &command) {
                            if !path.starts_with("usr/bin/") && !found.contains(&path) {
                                found.push(path);
                            }
                        }
                    }
                }
                break;
            }
            // `perl -e code` is given no script. For a shell `-e` is a
            // plain flag (`bash -e script`).
            if programs::takes_code(name, word) {
                break;
            }
            // `bash -o pipefail …`: for a shell the option's name is not
            // the script. For Python `-O` is a plain flag.
            if shell && matches!(word, "-o" | "-O" | "+o" | "+O") {
                words.next();
                continue;
            }
            // `python3 -W ignore script`: the word after an option that
            // may take a value is looked at, and so is the next.
            let argument = arguments.read(word);
            if argument == Argument::Option {
                continue;
            }
            if is_unwritten(lookup.home, word) {
                lookup.unwritten.set(true);
            }
            if word.contains('/') {
                let script = locate(lookup, word);
                if shell {
                    lookup
                        .shell_scripts
                        .borrow_mut()
                        .extend(script.iter().cloned());
                }
                found.extend(script);
            }
            // A shell's options that take a value are the ones above.
            if shell || argument == Argument::Script {
                found.extend(scripts_beside(lookup, word, words));
                break;
            }
            // Each word after an option that takes a value is looked at;
            // a line with no end of them is not followed to its end.
            values += 1;
            if values >= MAX_OPTION_VALUES {
                lookup.capped.set(true);
                break;
            }
        }
    }
    found
}

/// The file `word` redirects to, if it is a redirection (`2>/dev/null`,
/// `>&2`, `&>log`, `<in`): empty where the file is the next word (`2>`).
fn redirected_to(word: &str) -> Option<&str> {
    let operator = word.trim_start_matches(|c: char| c.is_ascii_digit());
    let operator = operator.strip_prefix('&').unwrap_or(operator);
    operator
        .starts_with(['>', '<'])
        .then(|| operator.trim_start_matches(['>', '<', '&']))
}

/// The scripts among `arguments` that lie in the directory of `script`,
/// the one an interpreter was handed: a wrapper often runs the script it
/// is given beside it (`bash ~/p/hooks/wrap.sh ~/p/hooks/hook.py`). Only
/// a file with a script's extension in that same directory: any other
/// argument may be a key, a log or a document, which the review has no
/// business reading.
fn scripts_beside<'a>(
    lookup: &Lookup<'_>,
    script: &str,
    arguments: impl Iterator<Item = &'a str>,
) -> Vec<String> {
    let Some((directory, _)) = script.rsplit_once('/') else {
        return Vec::new();
    };
    let mut found = Vec::new();
    let mut beside = arguments.filter(|argument| {
        argument.rsplit_once('/').is_some_and(|(folder, name)| {
            folder == directory
                && SCRIPT_EXTENSIONS
                    .iter()
                    .any(|extension| has_extension(name, extension))
        })
    });
    for argument in beside.by_ref().take(MAX_SCRIPTS_BESIDE) {
        found.extend(locate(lookup, argument));
    }
    if beside.next().is_some() {
        lookup.capped.set(true);
    }
    found
}

/// The most scripts handed beside a script that are followed
/// (`scripts_beside`); arbitrary, as `MAX_OPTION_VALUES`.
pub(crate) const MAX_SCRIPTS_BESIDE: usize = 8;

/// Whether `word`, a program or a script, is named through a variable or
/// a substitution that nothing wrote in (`$SCRIPT_DIR/x`, `/opt/$V/run`,
/// `$(dirname`, `` `pwd`/x ``), so the file that runs is not known here.
/// What `expand` writes in (`~`, `$HOME`, the XDG directories at their
/// default places) is known; `$HOMEBREW_PREFIX` is not.
fn is_unwritten(home: &str, word: &str) -> bool {
    has_expansion(&expand(home, word))
}

/// Whether `word`, quotes removed, holds something a shell writes in:
/// a `$` that may start an expansion (see `starts_expansion`), a
/// substitution in backticks, or a `~` that names another user's home
/// (`~alice/x`), which `expand` does not write in.
pub(super) fn has_expansion(word: &str) -> bool {
    word.contains('`')
        || (word.starts_with('~') && !word.starts_with("~/"))
        || word
            .match_indices('$')
            .any(|(at, _)| starts_expansion(&word[at + 1..]))
}

/// Whether a `$` followed by `after` may start an expansion. A `$` at the
/// end of a word, or before `/`, `)`, `|`, `]`, `.` or a quote, is text
/// every shell leaves as it is: a regex's end anchor (`'s|/x$||'`,
/// `'\.toml)$'`). Anything else counts, even where it is no expansion
/// (`'a$\|b'`), so that the forms not listed here, bash's `$'\x2f'` (which
/// arrives as `$\x2f`) and `$[…]` or zsh's `$=x`, are never passed over.
/// Quotes are gone by the time a word gets here, so a `$X` that was in
/// single quotes counts too.
fn starts_expansion(after: &str) -> bool {
    !(after.is_empty() || after.starts_with(['/', ')', '|', ']', '.', '\'', '"']))
}

/// The most values of options that are looked at on the way to a script.
pub(crate) const MAX_OPTION_VALUES: usize = 8;

/// The most commands of one line a shell runs that are looked up.
pub(crate) const MAX_INNER_COMMANDS: usize = 1024;

/// The commands of a line a shell runs (a crontab's, or `sh -c`'s): split
/// at `;`, `|`, `&` and line ends outside quotes.
#[cfg(test)]
pub(super) fn inner_commands(code: &str) -> Vec<String> {
    split_commands(code).0
}

/// `inner_commands`: the first `MAX_INNER_COMMANDS` that are not empty,
/// and whether the line held more.
pub(crate) fn split_commands(code: &str) -> (Vec<String>, bool) {
    let mut commands = Vec::new();
    let mut command = String::new();
    let mut quote: Option<char> = None;
    let mut previous = ' ';
    let mut characters = code.chars().peekable();
    while let Some(character) = characters.next() {
        // `>&`, `&>` and `<&` are redirections, not the end of a command.
        let redirection =
            character == '&' && (matches!(previous, '>' | '<') || characters.peek() == Some(&'>'));
        previous = character;
        match quote {
            Some(open) if character == open => quote = None,
            None if matches!(character, '"' | '\'') => quote = Some(character),
            None if matches!(character, ';' | '|' | '&' | '\n') && !redirection => {
                if !command.trim().is_empty() {
                    commands.push(std::mem::take(&mut command));
                    if commands.len() == MAX_INNER_COMMANDS {
                        let more = characters.any(|rest| !rest.is_whitespace());
                        return (commands, more);
                    }
                }
                command.clear();
                continue;
            }
            _ => {}
        }
        command.push(character);
    }
    if !command.trim().is_empty() {
        commands.push(command);
    }
    (commands, false)
}

/// The paths `word` may name, relative to the root, that exist there. A
/// bare name gives every place on the search list it is found in, first
/// the one a shell would take: the `PATH` of whatever runs the command
/// may still differ from the ones the list was made from.
fn locate(lookup: &Lookup<'_>, word: &str) -> Vec<String> {
    let expanded = expand(lookup.home, word);
    let candidates: Vec<String> = if let Some(absolute) = expanded.strip_prefix('/') {
        vec![absolute.to_string()]
    } else if expanded.contains('/') {
        return Vec::new();
    } else {
        lookup
            .search
            .iter()
            .map(|directory| format!("{directory}/{expanded}"))
            .collect()
    };
    candidates
        .into_iter()
        .filter(|candidate| (lookup.exists)(candidate))
        .collect()
}

/// `~`, `$HOME`, `${HOME}` and systemd's `%h` as the home directory, and
/// the XDG directories where they are by default.
pub(crate) fn expand(home: &str, word: &str) -> String {
    for prefix in ["~/", "$HOME/", "${HOME}/", "%h/"] {
        if let Some(rest) = word.strip_prefix(prefix) {
            return format!("/{home}/{rest}");
        }
    }
    for (prefixes, directory) in [
        (["$XDG_CONFIG_HOME/", "${XDG_CONFIG_HOME}/"], ".config"),
        (["$XDG_DATA_HOME/", "${XDG_DATA_HOME}/"], ".local/share"),
    ] {
        for prefix in prefixes {
            if let Some(rest) = word.strip_prefix(prefix) {
                return format!("/{home}/{directory}/{rest}");
            }
        }
    }
    word.to_string()
}

/// Words of a command line, quotes removed.
pub(super) fn split(command: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote: Option<char> = None;
    for character in command.chars() {
        match (quote, character) {
            (Some(open), _) if character == open => quote = None,
            (None, '"' | '\'') => quote = Some(character),
            (None, ' ' | '\t') => {
                if !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                }
            }
            _ => word.push(character),
        }
    }
    if !word.is_empty() {
        words.push(word);
    }
    words
}
