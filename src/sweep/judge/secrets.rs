//! Keeping secrets out of what is sent to the review: the values of
//! variables that hold a credential, and the passwords in URLs.

/// Names that hold a secret: an assignment to one has its value taken out
/// before the file is reviewed.
const SECRET_NAMES: &[&str] = &[
    "KEY",
    "APIKEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "PASSPHRASE",
    "CREDENTIAL",
    "CREDENTIALS",
    "AUTH",
    "AUTHTOKEN",
    "PAT",
    "PASS",
    "PWD",
    "PSK",
];

/// What stands where a value was taken out.
pub(super) const REDACTED: &str = "<redacted-by-guardian>";

/// `text` with the values of assignments that look like secrets
/// (`export API_KEY=…`, `Environment=TOKEN=…`, fish's `set -gx TOKEN …`)
/// taken out. Shell start-up files, `environment.d` and units are where
/// exported keys live, and the sweep sends what it reviews to the AI
/// provider on a timer. Only a plain literal is taken out: a value that is
/// computed (`$(…)`, a variable, a path) is code or configuration to
/// review, and holds no secret itself.
pub(super) fn without_secrets(text: &str) -> String {
    text.split_inclusive('\n')
        .map(|line| {
            let line = redact_line(line).unwrap_or_else(|| line.to_string());
            without_url_passwords(&line)
        })
        .collect()
}

/// A password written out as it is: nothing a shell would expand or run
/// in its place, which is code to review and no secret.
fn is_plain_password(password: &str) -> bool {
    !password.is_empty()
        && password
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-.+=%,!*~^:@".contains(c))
}

/// `line` with the password of each `scheme://user:password@host` taken
/// out. The user and the host stay: where something goes is what a review
/// needs to see. A password that is an expansion is no secret itself.
fn without_url_passwords(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(at) = rest.find("://") {
        let (before, after) = rest.split_at(at + 3);
        out.push_str(before);
        let end = after
            .find(|c: char| c.is_whitespace() || matches!(c, '/' | '"' | '\'' | '?' | '#'))
            .unwrap_or(after.len());
        let authority = &after[..end];
        match authority
            .rsplit_once('@')
            .and_then(|(userinfo, host)| Some((userinfo.split_once(':')?, host)))
        {
            Some(((user, password), host)) if is_plain_password(password) => {
                out.push_str(user);
                out.push(':');
                out.push_str(REDACTED);
                out.push('@');
                out.push_str(host);
            }
            _ => out.push_str(authority),
        }
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

fn redact_line(line: &str) -> Option<String> {
    // fish: `set [-flags] NAME value`.
    let words: Vec<&str> = line.split_whitespace().collect();
    if words.first() == Some(&"set")
        && let Some(name_at) = words.iter().skip(1).position(|word| !word.starts_with('-'))
        && let (Some(name), Some(value)) = (words.get(name_at + 1), words.get(name_at + 2))
        && is_secret_name(name)
        && is_literal_secret(value.trim_matches(['"', '\'']))
        && words.len() == name_at + 3
    {
        return Some(line.replacen(value, REDACTED, 1));
    }
    let mut out = String::new();
    let mut rest = line;
    let mut changed = false;
    while let Some(at) = rest.find('=') {
        let (before, after) = rest.split_at(at);
        // Blanks around the `=` (`password = "…"` in a configuration
        // file) are kept as they are.
        let blanks = after[1..].len() - after[1..].trim_start_matches([' ', '\t']).len();
        let (padding, after) = after[1..].split_at(blanks);
        // The name is the run of name characters before the `=` (all one
        // byte each, so the cut is on a character boundary).
        let named = before.trim_end_matches([' ', '\t']);
        let name_start = named.len()
            - named
                .bytes()
                .rev()
                .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                .count();
        let name = &named[name_start..];
        let (value, quote) = match after.chars().next() {
            Some(quote @ ('"' | '\'')) => (
                after[1..].split(quote).next().unwrap_or_default(),
                Some(quote),
            ),
            // An unquoted value may end the quotes of what it sits in
            // (`Environment="TOKEN=value"`).
            _ => (
                after
                    .split(|c: char| c.is_whitespace() || c == ';')
                    .next()
                    .unwrap_or_default()
                    .trim_end_matches(['"', '\'']),
                None,
            ),
        };
        out.push_str(before);
        out.push('=');
        out.push_str(padding);
        let closed = quote.is_none_or(|quote| after[1..].contains(quote));
        // Quoted or not, only a value of plain characters goes: no blank,
        // no `;`, `|` or `&`. This reads one line at a time and cannot tell
        // a quote that opens a value from one that closes an earlier
        // string, so a value that could hold a command is never taken out.
        if is_secret_name(name) && is_literal_secret(value) && closed {
            changed = true;
            if let Some(quote) = quote {
                out.push(quote);
                out.push_str(REDACTED);
                out.push(quote);
                rest = &after[value.len() + 2..];
            } else {
                out.push_str(REDACTED);
                rest = &after[value.len()..];
            }
        } else {
            rest = after;
        }
    }
    out.push_str(rest);
    changed.then_some(out)
}

/// Whether a part of `name` (between `_`) is one of `SECRET_NAMES`:
/// `OPENAI_API_KEY` and `DB_PASSWORD` are, `AuthorizedKeysCommand` and
/// `KEYMAP` are not.
///
/// A name written as one word counts where it ends in one of
/// `SECRET_ENDINGS` (`PGPASSWORD`, `MYSQLPASSWORD`).
pub(super) fn is_secret_name(name: &str) -> bool {
    let name = name.to_ascii_uppercase();
    name.split('_').any(|part| SECRET_NAMES.contains(&part))
        || (!name.contains('_') && SECRET_ENDINGS.iter().any(|ending| name.ends_with(ending)))
}

/// How a secret's name ends where it is written as one word.
const SECRET_ENDINGS: &[&str] = &["PASSWORD", "PASSWD", "SECRET", "TOKEN", "APIKEY"];

/// Whether `value` is a literal long enough to be a secret: no expansion,
/// no command, and nothing that says where something is (a path, a URL,
/// a relative file): those are what a review needs to see.
fn is_literal_secret(value: &str) -> bool {
    value.len() >= 8
        && !value.starts_with(['/', '~', '$', '-', '.'])
        && !value.contains("://")
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-./+=:@%,".contains(c))
}
