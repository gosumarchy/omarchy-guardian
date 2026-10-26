//! Keeping secrets out of what is sent to the review: the values of
//! variables that hold a credential, the passwords in URLs, and GRUB's
//! password hashes.

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
            // The hash first: a user name with `KEY=` in it would
            // otherwise take the line, and leave the hash in it.
            let line = without_grub_hash(line)
                .or_else(|| redact_line(line))
                .unwrap_or_else(|| line.to_string());
            without_url_passwords(&line)
        })
        .collect()
}

/// `line` with the hash taken out, where it is exactly GRUB's
/// `password_pbkdf2 <user> grub.pbkdf2.sha512.<rounds>.<salt>.<hash>` and
/// nothing else. A hash in that shape is digits and hexadecimal only and
/// can carry no code, so taking it out hides nothing a review needs (see
/// the masking rule in this module's callers); a line of any other shape
/// is left as it is.
fn without_grub_hash(line: &str) -> Option<String> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let [command, _user, hash] = words[..] else {
        return None;
    };
    let fields: Vec<&str> = hash
        .strip_prefix("grub.pbkdf2.sha512.")?
        .split('.')
        .collect();
    let is_hex = |field: &str| !field.is_empty() && field.bytes().all(|b| b.is_ascii_hexdigit());
    let shaped = command == "password_pbkdf2"
        && matches!(fields[..], [rounds, salt, digest]
            if !rounds.is_empty()
                && rounds.bytes().all(|b| b.is_ascii_digit())
                && is_hex(salt)
                && is_hex(digest));
    // The hash is cut out where it stands: a `replacen` would take the
    // first equal text, which may be the user's name.
    let at = hash.as_ptr().addr() - line.as_ptr().addr();
    shaped.then(|| format!("{}{REDACTED}{}", &line[..at], &line[at + hash.len()..]))
}

/// Whether `text`, boot configuration, holds a secret `without_secrets`
/// does not take out. On any line but the exact `password_pbkdf2` one
/// that is masked, that is:
///
/// - a word that starts with `password`, in any case: GRUB's plain
///   `password <user> <password>`, `password_pbkdf2` and `password_argon2`
///   in any other shape (quoted, followed by a comment or a `;`, inside a
///   `menuentry { }` or after `then`), an option such as `--password`,
///   and a comment that names one (`# Password: …`);
/// - a password hash, `grub.pbkdf2.` or `grub.argon2.`, wherever it is;
/// - `GRUB_USERS`, which `/etc/default/grub` sets to
///   `name;access;plain|pbkdf2|argon2;secret` entries;
/// - a word between blanks with a `:` before an `@`: the user and
///   password of an address, with a scheme (`cifs://alice:p;ss@nas`) or
///   without (dracut's `netroot=iscsi:user:password@server…`), which
///   masking cannot take out whole (`without_url_passwords` needs `://`
///   and plain characters); and a word with an `@` and an odd number of
///   one kind of quote, as a quoted password may hold a blank
///   (`"netroot=cifs://u:p ss@h"`), but where the `@` follows `=` or `=/`
///   (`"quiet rootflags=subvol=@"`);
/// - an assignment to a name that says secret (`GRUB_PASSWORD=…`, see
///   `is_secret_name`, on the last part of a dotted name), whatever the
///   value, quoted or not, but the kernel parameters in
///   `KEY_FILE_PARAMETERS`, and to one of `SECRET_PARAMETERS`; and
///   `set [-flags] NAME value` with such a name (the UEFI shell's form in
///   `startup.nsh`, in any case and after an `@`, and GRUB's);
/// - in a file that runs `cryptomount` anywhere, a word that starts with
///   `-p` or `--password` on any line, as its options may go on after a
///   `\` on the next.
///
/// The text is read as written, split at blanks and `;{}()"'`, not as
/// GRUB or the shell parses it: a word joined from quoted parts
/// (`pass"word"`) or split by a `\` at the end of a line is not seen.
/// Such a file is read by the local rules only, as the secret wins over
/// the review; this fails closed, so a comment that names a password
/// keeps the file from the review too.
pub(super) fn has_boot_secret(text: &str) -> bool {
    let cryptomount = text.contains("cryptomount");
    text.lines().any(|line| {
        if without_grub_hash(line).is_some() {
            return false;
        }
        let words: Vec<&str> = line
            .split(|c: char| c.is_whitespace() || ";{}()\"'".contains(c))
            .filter(|word| !word.is_empty())
            .collect();
        let passphrase = cryptomount
            && words
                .iter()
                .any(|word| word.starts_with("-p") || word.starts_with("--password"));
        let hash = ["grub.pbkdf2.", "grub.argon2.", "GRUB_USERS"]
            .iter()
            .any(|marker| line.contains(marker));
        let password = words.iter().any(|word| {
            word.trim_start_matches('-')
                .to_ascii_lowercase()
                .starts_with("password")
        });
        // Split at blanks only: a password may hold any other character.
        // `rootflags=subvol=@` and `getty@tty1` have no `:` before the `@`.
        let userinfo = line.split_whitespace().any(|word| {
            let odd = |quote: char| word.matches(quote).count() % 2 == 1;
            // An `@` right after `=` is a value of its own, such as Btrfs's
            // `rootflags=subvol=@` inside a quoted command line.
            word.split_once('@').is_some_and(|(before, _)| {
                before.contains(':')
                    || (!before.trim_end_matches('/').ends_with('=') && (odd('"') || odd('\'')))
            })
        });
        hash || password || userinfo || passphrase || assigns_secret(line) || sets_secret(&words)
    })
}

/// Whether `words`, one line, are `set [-flags] NAME value` with a name
/// that says secret (`set -v PASSWORD hunter2`, `set TOKEN abc`).
fn sets_secret(words: &[&str]) -> bool {
    if !words.first().is_some_and(|command| is_set(command)) {
        return false;
    }
    words[1..]
        .iter()
        .find(|word| !word.starts_with('-'))
        .is_some_and(|name| is_secret_name(name.split('=').next().unwrap_or_default()))
}

/// Whether `command` is `set`. The UEFI shell reads its commands in any
/// case, and a leading `@` only stops it from echoing the line.
fn is_set(command: &str) -> bool {
    command.trim_start_matches('@').eq_ignore_ascii_case("set")
}

/// Kernel parameters whose value is a secret but whose name does not say so
/// to `is_secret_name`: dracut's CIFS password, as dracut.cmdline(7)
/// documents it (`cifsuser=`, `cifspass=`). Matched on the whole name.
/// `PASS` is not one of `SECRET_ENDINGS`, as `BYPASS` and `COMPASS` end so.
const SECRET_PARAMETERS: &[&str] = &["cifspass"];

/// Kernel parameters whose name says key but whose value is where a key
/// file is (`<path>[:<device>]`), never the key: systemd-cryptsetup's, as
/// systemd-cryptsetup-generator(8) documents them. Only these are passed
/// over; any other dotted name that says secret (`cifs.password=`, a
/// hook's `*.passphrase=`) can hold one, and sending it to the AI provider
/// is a leak whoever else on the machine can read `/proc/cmdline`.
const KEY_FILE_PARAMETERS: &[&str] = &["rd.luks.key", "luks.key"];

/// Whether `line` assigns to a name that says secret, but one of
/// `KEY_FILE_PARAMETERS`, or to one of `SECRET_PARAMETERS` (see
/// `has_boot_secret`). What may stand between the name and the `=` is
/// passed over first: a `+` (`NAME+=`), a subscript (`NAME[0]=`) and the
/// brace of `${NAME}`.
fn assigns_secret(line: &str) -> bool {
    line.match_indices('=').any(|(at, _)| {
        let named = line[..at].trim_end_matches([' ', '\t', '+']);
        let named = match named.strip_suffix(']') {
            Some(subscripted) => subscripted.rsplit_once('[').map_or(named, |(name, _)| name),
            None => named,
        };
        let named = named.trim_end_matches('}');
        let length = |dots: bool| {
            named
                .bytes()
                .rev()
                .take_while(|byte| {
                    byte.is_ascii_alphanumeric() || *byte == b'_' || (dots && *byte == b'.')
                })
                .count()
        };
        let last = &named[named.len() - length(false)..];
        let whole = &named[named.len() - length(true)..];
        SECRET_PARAMETERS.contains(&whole)
            || (!last.is_empty() && !KEY_FILE_PARAMETERS.contains(&whole) && is_secret_name(last))
    })
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
pub(super) fn without_url_passwords(line: &str) -> String {
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
    // fish, and the UEFI shell: `set [-flags] NAME value`.
    let words: Vec<&str> = line.split_whitespace().collect();
    if words.first().is_some_and(|command| is_set(command))
        && let Some(name_at) = words.iter().skip(1).position(|word| !word.starts_with('-'))
        && let (Some(name), Some(value)) = (words.get(name_at + 1), words.get(name_at + 2))
        && is_secret_name(name)
        && is_literal_secret(value.trim_matches(['"', '\'']))
        && words.len() == name_at + 3
    {
        // Cut where the value stands: a `replacen` would take the first
        // equal text, which may be part of the name.
        let at = value.as_ptr().addr() - line.as_ptr().addr();
        return Some(format!(
            "{}{REDACTED}{}",
            &line[..at],
            &line[at + value.len()..]
        ));
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
