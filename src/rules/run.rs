//! What a line runs: the files it fetches, the files and programs it starts,
//! and the variables its commands are built from.

use std::collections::HashSet;

use super::matchers::pipes_into_shell;
use super::shell::{PIPE_SHELLS, program_name, shell_words, unquoted, unquoted_words, unversioned};
use super::{FETCHERS, encoded, fetch, shell};

/// What runs a file given to it.
const RUNNERS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "ash", "fish", "source", ".", "python", "perl", "node",
    "ruby", "php", "lua",
];

/// A file name as written, without a leading `./` and without the
/// backtick that closes a substitution it stands last in.
pub(super) fn as_file(word: &str) -> Option<String> {
    let name = word.trim_end_matches([';', '`']).trim_start_matches("./");
    (!name.is_empty()).then(|| name.to_string())
}

/// The program a word names where it may open a substitution or a group:
/// `x=$(curl`, `(curl`.
fn fetcher_name(word: &str) -> &str {
    let word = word.rsplit("$(").next().unwrap_or(word);
    let word = word.rsplit('`').next().unwrap_or(word);
    // `(curl …)`, `{ curl …; }`: a group opens before it.
    program_name(word.trim_start_matches(['(', '{']))
}

/// The file a fetch on `line` is saved as: `curl -o x`, `wget -O x`,
/// `curl … > x`, or the name in the address for `wget` and `curl -O`.
pub(super) fn fetched_file(line: &str) -> Option<String> {
    let words = unquoted_words(line);
    let at = words
        .iter()
        .position(|word| FETCHERS.contains(&fetcher_name(word)))?;
    let name = saved_as(&words, at)?;
    // Last in a substitution or a group, the name is written with what
    // closes it.
    if words[..=at].iter().any(|word| word.contains('(')) {
        return as_file(without_group_close(&name));
    }
    Some(name)
}

/// `fetched_file`, for the fetcher at `at` among `words`.
fn saved_as(words: &[String], at: usize) -> Option<String> {
    let fetcher = fetcher_name(&words[at]);
    let mut by_address = fetcher == "wget";
    let mut address = None;
    let mut rest = words[at + 1..].iter();
    while let Some(word) = rest.next() {
        match word.as_str() {
            ";" | "&&" | "||" | "|" => break,
            "-O" | "--remote-name" if fetcher == "curl" => by_address = true,
            // wget's `-o` names its log.
            "-o" if fetcher == "wget" => {
                rest.next();
            }
            ">" | ">>" => return rest.next().and_then(|name| as_file(name)),
            "-o" | "-O" | "--output" | "--output-document" | "--out" => {
                match rest.next().map(String::as_str) {
                    // Standard output: only a redirection saves it.
                    Some("-") => by_address = false,
                    name => return name.and_then(as_file),
                }
            }
            _ if fetcher == "wget"
                && word.starts_with('-')
                && !word.starts_with("--")
                && word.ends_with("O-") =>
            {
                by_address = false;
            }
            // Short options given together: `-fsSLo x`, `-qO x`.
            _ if word.len() > 2
                && word.starts_with('-')
                && !word.starts_with("--")
                && word.ends_with(['o', 'O'])
                && !(fetcher == "wget" && word.ends_with('o')) =>
            {
                if word.ends_with('O') && fetcher == "curl" {
                    by_address = true;
                } else {
                    match rest.next().map(String::as_str) {
                        Some("-") => by_address = false,
                        name => return name.and_then(as_file),
                    }
                }
            }
            _ => {
                if let Some(name) = [">>", ">"]
                    .iter()
                    .find_map(|option| word.strip_prefix(option))
                {
                    return as_file(name);
                }
                match ["--output=", "--output-document=", "--out="]
                    .iter()
                    .find_map(|option| word.strip_prefix(option))
                {
                    Some("-") => by_address = false,
                    Some(name) => return as_file(name),
                    None => {}
                }
                if word.contains("://") {
                    address = Some(word);
                }
            }
        }
    }
    let address = address.filter(|_| by_address)?;
    let path = address.split(['?', '#']).next().unwrap_or_default();
    as_file(program_name(path.trim_end_matches(';')))
}

/// Every file a fetch on `line` is saved as: what `fetched_file` names,
/// and what `fetch::saved_files` adds (through `tee`, into a directory, by
/// another fetcher).
pub(crate) fn fetched_files(line: &str) -> Vec<String> {
    let mut found = Vec::new();
    // A substitution runs what it holds (`x=$(sudo curl -o f …)`,
    // `$(curl … | tee f)`), so each is read as a line of its own.
    for text in std::iter::once(line).chain(substituted_lines(line)) {
        for file in fetched_file(text)
            .into_iter()
            .chain(fetch::saved_files(text))
        {
            if !found.contains(&file) {
                found.push(file);
            }
        }
    }
    found
}

/// A word without the `)` that closes the group it stands last in:
/// `(sh x)`. A word with a parenthesis of its own is left as it is, and
/// so is one that is nothing else.
fn without_group_close(word: &str) -> &str {
    let bare = word.trim_end_matches(')');
    if word.contains('(') || bare.is_empty() {
        word
    } else {
        bare
    }
}

/// The command one statement, or one part of a pipeline, runs, for
/// `runs_file` and `run_targets`. What stands before the program is read
/// by `shell::command`: wrappers (`sudo -u x`, `nohup`, `timeout 5`),
/// assignments (`X=1`) and what opens a group or a block. A command as a
/// configuration's value (`exec = sh x`) is read from after the key.
fn run_command(part: &str) -> Option<shell::Command> {
    let words = shell_words(part);
    if words.get(1).is_some_and(|word| word == "=") {
        return shell::command(&words[2..].join(" "));
    }
    shell::command(part)
}

/// The command `part` runs when it is a setting whose value begins with a
/// path: `ExecStart=/bin/sh x`. To a shell the same words run `x` with a
/// variable set, so this is a second reading, not the first.
fn value_command(part: &str) -> Option<shell::Command> {
    let words = shell_words(part);
    let (key, value) = words.first()?.split_once('=')?;
    // A unit file writes marks before the program: `ExecStart=-/bin/sh x`.
    let value = value.trim_start_matches(['-', '@', '+', '!', ':', '|']);
    if key.is_empty() || key.contains(['/', '"', '\'', '$']) || !unquoted(value).starts_with('/') {
        return None;
    }
    let rest = [&[value.to_string()], &words[1..]].concat().join(" ");
    shell::command(&rest)
}

/// Whether `line` runs the file named `file`: given to a shell or an
/// interpreter, sourced, or run by its path (see `run_command`).
pub(crate) fn runs_file(line: &str, file: &str) -> bool {
    // Inside a group a word is written with the group's `)`: the file as
    // it was saved, and the word that names it.
    let is_named = |word: &str| {
        as_file(word.trim_start_matches('<')).is_some_and(|name| {
            name == file || without_group_close(&name) == without_group_close(file)
        })
    };
    let names_it = |statement: &str| unquoted_words(statement).iter().any(|word| is_named(word));
    // `cat x | sh`.
    if pipes_into_shell(line, names_it) {
        return true;
    }
    let line = line.replace("&&", ";").replace("||", ";");
    line.split([';', '|']).any(|statement| {
        [run_command(statement), value_command(statement)]
            .into_iter()
            .flatten()
            .chain(shell::inner_commands(statement))
            .any(|command| runs_named(&command, &is_named))
    })
}

/// Whether `command` runs a file `is_named` knows: by its path, or as what
/// a shell or an interpreter is given.
fn runs_named(command: &shell::Command, is_named: &dyn Fn(&str) -> bool) -> bool {
    let program = command.path.as_str();
    if (program.contains('/') || program.starts_with('$')) && is_named(program) {
        return true;
    }
    let name = command.program.as_str();
    let unversioned = unversioned(name);
    // Only parsed or compiled: `sh -n`, `node --check`, `python -m`.
    let only_checks = command
        .arguments
        .iter()
        .take_while(|word| word.starts_with('-'))
        .any(|word| match word.as_str() {
            "-n" => PIPE_SHELLS.contains(&unversioned),
            "-m" => unversioned == "python",
            "--check" => unversioned == "node",
            _ => false,
        });
    (RUNNERS.contains(&name) || (!unversioned.is_empty() && RUNNERS.contains(&unversioned)))
        && !only_checks
        && command.arguments.iter().any(|word| is_named(word))
}

/// The files `line` runs or reads in as code, as written: what it gives a
/// shell or an interpreter (`sh x`, `. ./x`, `python3 x.py`, `sh <x`),
/// what it runs by its path (`./x`, `/opt/x`), and what it pipes into a
/// shell (`cat x | sh`). The program is found as in `runs_file`.
pub(crate) fn run_targets(line: &str) -> Vec<String> {
    let mut found = targets_of(line);
    // A substitution runs what it holds (`x=$(cat f | sh) make`), so each
    // is read as a line of its own.
    for body in substituted_lines(line) {
        // `$(<f)` reads a file and runs nothing.
        if body.trim_start().starts_with('<') {
            continue;
        }
        for target in targets_of(body) {
            if !found.contains(&target) {
                found.push(target);
            }
        }
    }
    found
}

/// What each substitution of `line` holds, where the shell runs it. One
/// past what `Reading` reads is left out: it names no file. So is one in
/// single quotes or behind a backslash, which is text (`echo 'run `x`'`),
/// unless the line hands text to a shell.
fn substituted_lines(line: &str) -> Vec<&str> {
    let quoted = Quoted::read(line);
    let handed_on = hands_text_on(line, &quoted.words);
    let mut reading = shell::Reading::of(line);
    shell::substitutions(line)
        .into_iter()
        .filter(|substitution| handed_on || !quoted.text.contains(&substitution.start))
        .map(|substitution| substitution.body)
        .filter(|body| reading.takes(body))
        .collect()
}

/// Programs that run text given to them as `-c`, besides the shells in
/// `PIPE_SHELLS`.
const TEXT_RUNNERS: &[&str] = &[
    "csh", "tcsh", "mksh", "su", "runuser", "sg", "script", "watch", "python",
];

/// Whether `line` gives text to a shell to run: to `eval` or `trap`, down
/// a pipe into one, or to one it names as `-c` (`bash -lc '…'`,
/// `$SHELL -c '…'`) or through a here-string. Without a shell on the line
/// those are another program's (`wc -c`, `cat <<< '…'`).
fn hands_text_on(line: &str, quoted: &HashSet<usize>) -> bool {
    let mut names_runner = false;
    let mut is_given = line.contains("<<<");
    // Whether the word before was a variable, which may hold a shell.
    let mut after_variable = false;
    for word in line.split_whitespace() {
        // In a quote the word is part of a message: `echo 'a trap …'`.
        let start = word.as_ptr() as usize - line.as_ptr() as usize;
        if !quoted.contains(&start)
            && word
                .split([';', '&', '|', '!', '\\', '(', '{', '`'])
                .any(|part| matches!(part, "eval" | "trap"))
        {
            return true;
        }
        let bare = word.trim_matches(['(', '{', '"', '\'', ';', ')']);
        let program = unversioned(program_name(bare));
        let option = bare.starts_with('-') && !bare.starts_with("--") && bare.ends_with('c');
        names_runner = names_runner
            || PIPE_SHELLS.contains(&program)
            || PIPE_SHELLS.contains(&program_name(bare))
            || TEXT_RUNNERS.contains(&program)
            || (option && after_variable);
        is_given = is_given || option;
        after_variable = bare.starts_with('$');
    }
    (names_runner && is_given) || pipes_into_shell(line, |_| true)
}

/// What the quotes of a line make of its parts.
struct Quoted {
    /// Where a `$` or a backtick stands that is text to the shell: inside
    /// single quotes, or after a backslash.
    text: HashSet<usize>,
    /// Where a word begins inside a quote.
    words: HashSet<usize>,
}

impl Quoted {
    /// Reads the quotes of `line`. Quotes inside a substitution are its
    /// own (`"$(echo "it's")"`), and in `$'…'` a backslash keeps a quote
    /// from closing it.
    fn read(line: &str) -> Self {
        // The substitutions open around what is being read.
        let mut around: Vec<Around> = Vec::new();
        let mut quote: Option<u8> = None;
        let mut found = HashSet::new();
        let mut words = HashSet::new();
        let bytes = line.as_bytes();
        let mut at = 0;
        while at < bytes.len() {
            let byte = bytes[at];
            if quote.is_some() && at > 0 && bytes[at - 1].is_ascii_whitespace() {
                words.insert(at);
            }
            // `$'…'` is kept as `$`.
            let single = matches!(quote, Some(b'\'' | b'$'));
            let room = around.len() < MAX_SEGMENTS;
            match byte {
                b'\\' if quote != Some(b'\'') => {
                    if matches!(bytes.get(at + 1), Some(b'$' | b'`')) {
                        found.insert(at + 1);
                    }
                    at += 1;
                }
                b'$' | b'`' if single => {
                    found.insert(at);
                }
                b'\'' if single => quote = None,
                b'"' if quote == Some(b'"') => quote = None,
                b'\'' | b'"' if quote.is_none() => quote = Some(byte),
                b'$' if quote.is_none() && bytes.get(at + 1) == Some(&b'\'') => {
                    quote = Some(b'$');
                    at += 1;
                }
                b'$' if room && bytes.get(at + 1) == Some(&b'(') => {
                    around.push(Around::new(quote.take(), false));
                    at += 1;
                }
                b'`' if quote.is_none() && around.last().is_some_and(|open| open.backtick) => {
                    quote = around.pop().and_then(|open| open.quote);
                }
                b'`' if room => around.push(Around::new(quote.take(), true)),
                b'(' if quote.is_none() => {
                    if let Some(open) = around.last_mut() {
                        open.groups += 1;
                    }
                }
                b')' if quote.is_none() => match around.last_mut() {
                    Some(open) if open.groups > 0 => open.groups -= 1,
                    Some(open) if !open.backtick => {
                        quote = around.pop().and_then(|open| open.quote);
                    }
                    _ => {}
                },
                _ => {}
            }
            at += 1;
        }
        Self { text: found, words }
    }
}

/// A substitution that is open in `Quoted::read`.
struct Around {
    /// The quote it stands in, open again when it closes.
    quote: Option<u8>,
    /// A backtick opened it, not `$(`.
    backtick: bool,
    /// The `(` inside it that are not closed yet.
    groups: usize,
}

impl Around {
    const fn new(quote: Option<u8>, backtick: bool) -> Self {
        Self {
            quote,
            backtick,
            groups: 0,
        }
    }
}

/// `run_targets`, for the line itself.
fn targets_of(line: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    // The names found so far, so that a line of many is not read through
    // for each.
    let mut known: HashSet<String> = HashSet::new();
    // A word that ends in `)` is a file in a group that closes there, or
    // a file of that name: both are named, and a name no file has is
    // nobody's.
    let mut add = |word: &str| {
        let word = word.trim_start_matches('<');
        // `./x>/dev/null`: a redirection written onto the word ends it.
        let word = word.split(['<', '>']).next().unwrap_or(word);
        for word in [without_group_close(word), word] {
            if let Some(name) = as_file(word)
                && !name.starts_with('-')
                && known.insert(name.clone())
            {
                found.push(name);
            }
        }
    };
    let flat = line.replace("&&", ";").replace("||", ";");
    for (index, statement) in flat.split(';').enumerate() {
        if index >= MAX_STATEMENTS {
            break;
        }
        // Each segment's command, read once.
        let commands: Vec<Option<shell::Command>> = statement
            .split('|')
            .take(MAX_SEGMENTS)
            .map(run_command)
            .collect();
        // Whether a shell reads what comes after each segment, worked out
        // once from the end.
        let mut shell_after = vec![false; commands.len() + 1];
        for at in (0..commands.len()).rev() {
            let is_shell = commands[at].as_ref().is_some_and(shell::Command::is_shell);
            shell_after[at] = shell_after[at + 1] || is_shell;
        }
        // A substitution that was looked past for the program after it
        // runs a command too, at the same place in the pipeline.
        // Its output is the variable's, so no shell after it reads it.
        let within: Vec<shell::Command> = statement
            .split('|')
            .take(MAX_SEGMENTS)
            .flat_map(shell::inner_commands)
            .collect();
        let each = commands
            .iter()
            .enumerate()
            .filter_map(|(at, command)| Some((shell_after[at + 1], command.as_ref()?)))
            .chain(within.iter().map(|command| (false, command)));
        for (piped_into_shell, command) in each {
            if command.path.contains('/') {
                add(&command.path);
            }
            let arguments: Vec<&str> = command.arguments.iter().map(String::as_str).collect();
            // `cat x | sh`: what is read into a shell after it.
            let name = command.program.as_str();
            if name == "cat" && piped_into_shell {
                for argument in &arguments {
                    if !argument.starts_with('-') {
                        add(argument);
                    }
                }
                continue;
            }
            let unversioned = unversioned(name);
            if !(RUNNERS.contains(&name)
                || (!unversioned.is_empty() && RUNNERS.contains(&unversioned)))
            {
                continue;
            }
            // Code given on the command line, or only checked: no file.
            let options: Vec<&&str> = arguments
                .iter()
                .take_while(|word| word.starts_with('-'))
                .collect();
            let shell = PIPE_SHELLS.contains(&unversioned);
            if options.iter().any(|option| {
                matches!(**option, "-c" | "-n" | "-m" | "--check")
                    || (**option == "-e" && !shell)
                    || (shell
                        && option.len() > 2
                        && !option.starts_with("--")
                        && option.ends_with('c'))
            }) {
                continue;
            }
            if let Some(first) = arguments.iter().find(|word| !word.starts_with('-')) {
                add(first);
            }
        }
    }
    for name in extra_run_targets(line) {
        add(&name);
    }
    found
}

/// The directories and globs `line` names where what is in them is run or
/// read in as code, as written: the words of a loop (`for h in hooks.d/*`),
/// a glob given to a shell, an interpreter or `source`, a glob read into a
/// pipe (`cat dir/* | sh`), and the directory of `run-parts` and of a
/// `find` that runs or passes on what it finds. `run_targets` names single
/// files; which files these reach is known only where they run. What a
/// loop does with its words is on later lines, so every loop over paths
/// counts.
pub(crate) fn run_globs(line: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    if !(line.contains(['*', '?'])
        || ["for ", "run-parts", "find "]
            .iter()
            .any(|sign| line.contains(sign)))
    {
        return found;
    }
    let is_glob = |word: &str| word.contains(['*', '?', '[']);
    let piped = line.contains('|');
    let flat = line.replace("&&", ";").replace("||", ";");
    for statement in flat.split([';', '|']).take(MAX_STATEMENTS) {
        // A command as a configuration's value (`exec = run-parts d`) is
        // read from after the key when the line does not start with one.
        let after_key = statement.split_once('=').map(|(_, value)| value);
        for statement in std::iter::once(statement).chain(after_key) {
            let named = globs_run_by(statement, piped, &is_glob);
            let known = !named.is_empty();
            for word in named {
                let word = word.trim_end_matches(')').to_string();
                if !word.is_empty() && !found.contains(&word) {
                    found.push(word);
                }
            }
            if known {
                break;
            }
        }
    }
    found
}

/// `run_globs` for one statement; `piped` says its line has a pipe.
fn globs_run_by(statement: &str, piped: bool, is_glob: &dyn Fn(&str) -> bool) -> Vec<String> {
    let Some(command) = shell::command(statement) else {
        return Vec::new();
    };
    let name = command.program.as_str();
    let unversioned = unversioned(name);
    // Also the value alone, as it is read from after the `=`.
    let value = statement.trim_start();
    let assigned = statement.contains("=$(")
        || statement.contains("=`")
        || value.starts_with("$(")
        || value.starts_with('`');
    let arguments: Vec<&str> = command.arguments.iter().map(String::as_str).collect();
    let operands = arguments
        .iter()
        .copied()
        .filter(|word| !word.starts_with('-'));
    let named: Vec<&str> = match name {
        "for" | "select" => operands
            .skip_while(|word| *word != "in")
            .skip(1)
            .take_while(|word| *word != "do")
            .filter(|word| word.contains('/') || is_glob(word))
            .collect(),
        "run-parts" => operands.collect(),
        // The places searched come before the first test.
        // What a variable is given (`x=$(find … | head -n 1)`) is a name
        // found, not a file run.
        "find"
            if !assigned && (piped || statement.contains("-exec") || statement.contains("-ok")) =>
        {
            arguments
                .iter()
                .copied()
                .take_while(|word| !word.starts_with(['-', '(', '!', '\\']))
                .collect()
        }
        "cat" if !piped => Vec::new(),
        _ if name == "cat"
            || RUNNERS.contains(&name)
            || (!unversioned.is_empty() && RUNNERS.contains(&unversioned)) =>
        {
            operands.filter(|word| is_glob(word)).collect()
        }
        _ => Vec::new(),
    };
    named.into_iter().map(ToString::to_string).collect()
}

/// Files a line runs or reads in that `run_targets`' shell reading does not
/// reach: make's includes, an interpreter given a file to read in on its
/// command line, a script sourced next to the running one, an archive read
/// in, and the commands in a `package.json`. Each name is returned as
/// written, for `run_targets` to clean.
fn extra_run_targets(line: &str) -> Vec<String> {
    let mut found = Vec::new();
    make_includes(line, &mut found);
    reads_in_file(line, &mut found);
    sourced_sibling(line, &mut found);
    unpacked_file(line, &mut found);
    package_json_runs(line, &mut found);
    found
}

/// make's `include x`, `-include x`, `sinclude x`, and `$(shell cat x)`.
fn make_includes(line: &str, found: &mut Vec<String>) {
    let mut words = line.split_whitespace();
    if let Some(first) = words.next()
        && matches!(first.trim_start_matches('-'), "include" | "sinclude")
    {
        found.extend(words.map(ToString::to_string));
    }
    if let Some(at) = line.find("$(shell cat ") {
        let rest = &line[at + "$(shell cat ".len()..];
        found.extend(
            rest.split(')')
                .next()
                .and_then(|inside| inside.split_whitespace().next())
                .map(ToString::to_string),
        );
    }
}

/// An interpreter told on its command line to read a file in: `sh -c
/// "$(cat x)"`, `python -c "exec(open('x').read())"`, `node -e
/// "require('./x')"`.
fn reads_in_file(line: &str, found: &mut Vec<String>) {
    // `$(cat x)` / `` `cat x` `` whose output a shell runs (`sh -c
    // "$(cat x)"`, `eval "$(cat x)"`), not one only captured in a value.
    // A body past what `Reading` reads names no file here: unlike a rule,
    // this has no answer that stands for "it may". The line is not let
    // through for that: a rule that asks whether it runs such a
    // substitution takes the unread body to hold what it looks for, and
    // reports the line.
    let mut reading = shell::Reading::of(line);
    for substitution in shell::substitutions(line) {
        if shell::is_run(line, &substitution)
            && reading.takes(substitution.body)
            && let Some(command) = shell::command(substitution.body)
            && command.program == "cat"
        {
            found.extend(command.operands().next().map(ToString::to_string));
        }
    }
    // `open('x')` inside an `exec`/`eval` argument: the first of each kind
    // in what a call is given.
    let given = encoded::run_arguments(line);
    for argument in &given.arguments {
        for opener in OPENERS {
            found.extend(opened(argument, opener).next());
        }
    }
    // Calls left unread are given something on the line, so every file
    // opened anywhere on it is named: more than they open, never less.
    // Each opener is looked for once over the line, not once for each call.
    if let Some(line) = given.unread {
        for opener in OPENERS {
            found.extend(opened(line, opener));
        }
    }
}

/// How code given to a run call opens a file to read it in.
const OPENERS: &[&str] = &["open('", "open(\"", "read_text('", "read_text(\""];

/// The file each `opener` in `text` names: what stands up to the next quote.
fn opened<'a>(text: &'a str, opener: &'a str) -> impl Iterator<Item = String> + 'a {
    text.match_indices(opener).filter_map(move |(at, _)| {
        text[at + opener.len()..]
            .split(['\'', '"'])
            .next()
            .map(ToString::to_string)
    })
}

/// A script read in beside the running one: `. "$(dirname "$0")/x"`,
/// `source "${BASH_SOURCE%/*}/x"`.
fn sourced_sibling(line: &str, found: &mut Vec<String>) {
    let statement = line.trim_start();
    let Some(rest) = statement
        .strip_prefix(". ")
        .or_else(|| statement.strip_prefix("source "))
    else {
        return;
    };
    let argument = rest.trim().trim_matches(['"', '\'']);
    if argument.contains("dirname ") || argument.contains("bash_source") || argument.contains("${0")
    {
        found.extend(as_file(program_name(argument)));
    }
}

/// Archives read in: `tar xf x`, `tar -xf x`, `bsdtar -xf x`, `unzip x`,
/// `7z x x`. Reported like a run, since an extract step feeds a build.
fn unpacked_file(line: &str, found: &mut Vec<String>) {
    for statement in shell::statements(line) {
        let Some(command) = shell::command(statement) else {
            continue;
        };
        let operands: Vec<String> = command.operands().map(ToString::to_string).collect();
        // The archive is the value of `-f`, or the first operand that is
        // not the mode word (`x`, `xf`, the 7z verb).
        let file_option = command
            .arguments
            .iter()
            .position(|word| word == "-f" || word == "--file")
            .and_then(|at| command.arguments.get(at + 1))
            .or_else(|| {
                command
                    .arguments
                    .iter()
                    .find_map(|word| word.strip_prefix("--file=").map(|_| word))
            });
        let archive = match command.program.as_str() {
            "tar" | "bsdtar"
                if command.has_short('x')
                    || operands.first().is_some_and(|word| word.contains('x')) =>
            {
                file_option
                    .map(|word| word.trim_start_matches("--file=").to_string())
                    .or_else(|| {
                        operands
                            .iter()
                            .find(|word| !word.chars().all(|c| "xfvzjJ-".contains(c)))
                            .cloned()
                    })
            }
            "unzip" => operands.into_iter().next(),
            "7z" | "7za" | "7zr"
                if operands
                    .first()
                    .is_some_and(|word| matches!(word.as_str(), "x" | "e")) =>
            {
                operands.into_iter().nth(1)
            }
            _ => None,
        };
        found.extend(archive.as_deref().and_then(as_file));
    }
}

/// The commands a `package.json` script line runs: `"postinstall": "node
/// scripts/x.js"`, and any `"scripts"` entry.
fn package_json_runs(line: &str, found: &mut Vec<String>) {
    let trimmed = line.trim_start();
    if !trimmed.starts_with('"') {
        return;
    }
    let Some((key, value)) = trimmed[1..].split_once("\":") else {
        return;
    };
    // A key naming a lifecycle script or any entry of the scripts map.
    let script_key = key.ends_with("install")
        || key.ends_with("prepare")
        || key.ends_with("prepublish")
        || matches!(
            key,
            "start" | "build" | "postinstall" | "preinstall" | "prestart"
        );
    if !script_key && !trimmed.contains("script") {
        // Only recognised script keys, to stay off ordinary JSON strings.
        return;
    }
    let value = value.trim().trim_end_matches(',');
    if let Some(command) = value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
    {
        found.extend(run_targets(&command.replace("\\\"", "\"")));
    }
}

/// Variables a file sets to a fetcher or a shell (`F=curl`, `S="bash"`),
/// lowercased, so `$F … | $S` is judged as what it runs.
pub(crate) fn command_variables(text: &str) -> Vec<(String, String)> {
    let mut found: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        let line = line.trim().strip_prefix("export ").unwrap_or(line.trim());
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim_matches(['"', '\'']);
        let is_name = !name.is_empty()
            && name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        let program = program_name(value);
        if is_name
            && !value.contains(char::is_whitespace)
            && (FETCHERS.contains(&program) || PIPE_SHELLS.contains(&program))
        {
            let name = name.to_ascii_lowercase();
            found.retain(|(known, _)| *known != name);
            found.push((name, program.to_string()));
            if found.len() > MAX_COMMAND_VARIABLES {
                found.remove(0);
            }
        }
    }
    found
}

/// The most such variables one file keeps.
const MAX_COMMAND_VARIABLES: usize = 32;

/// `code` with `$name` and `${name}` of `variables` written out. Names are
/// matched as given: a caller that wants it case-blind lowercases both.
pub(crate) fn with_variables(code: &str, variables: &[(String, String)]) -> String {
    if variables.is_empty() || !code.contains('$') {
        return code.to_string();
    }
    // Names written as a shell writes them are looked up among the names
    // the line holds after a `$`, which are read in one pass; any other
    // name is looked for by itself.
    let plain = variables.iter().all(|(name, _)| shell::is_name(name));
    let mut out = code.to_string();
    let mut next = 0;
    while next < variables.len() {
        // The first variable from `next` on that the line names. Most
        // lines name none, and are not written anew for any.
        let at = if plain {
            let named = names_after_dollar(&out);
            variables[next..]
                .iter()
                .position(|(name, _)| named.contains(name.as_str()))
        } else {
            variables[next..].iter().position(|(name, _)| {
                out.match_indices('$').any(|(at, _)| {
                    let rest = &out[at + 1..];
                    rest.starts_with(name.as_str())
                        || rest
                            .strip_prefix('{')
                            .is_some_and(|rest| rest.starts_with(name.as_str()))
                })
            })
        };
        let Some(at) = at else {
            break;
        };
        let (name, value) = &variables[next + at];
        out = written_out(&out, name, value);
        // What was written may have made another name: the line is read
        // again for the variables after this one.
        next += at + 1;
    }
    out
}

/// The names `text` holds after a `$` or a `${`: each run of the
/// characters a name is made of.
fn names_after_dollar(text: &str) -> HashSet<&str> {
    text.match_indices('$')
        .filter_map(|(at, _)| {
            let rest = &text[at + 1..];
            let rest = rest.strip_prefix('{').unwrap_or(rest);
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            (end > 0).then(|| &rest[..end])
        })
        .collect()
}

/// `text` with `${name}`, and `$name` where the name ends there, replaced
/// by `value`.
fn written_out(text: &str, name: &str, value: &str) -> String {
    let out = text.replace(&format!("${{{name}}}"), value);
    let pattern = format!("${name}");
    let mut result = String::with_capacity(out.len());
    let mut rest = out.as_str();
    while let Some(at) = rest.find(&pattern) {
        let after = &rest[at + pattern.len()..];
        result.push_str(&rest[..at]);
        if after.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_') {
            result.push_str(&pattern);
        } else {
            result.push_str(value);
        }
        rest = after;
    }
    result.push_str(rest);
    result
}

/// The most pipeline parts of one statement looked at.
const MAX_SEGMENTS: usize = 64;

/// The most statements of one line looked at for what they run.
const MAX_STATEMENTS: usize = 64;
