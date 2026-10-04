//! Who may log in and administer: accounts, the members of the groups that
//! amount to root, and the SSH keys that open an account.
//!
//! None of it is a file that runs, so each fact is an item of its own: an
//! account that can log in, a member of `wheel`, one authorised key. A new
//! one then shows as new in `sweep --diff` and in the timer's notification,
//! and one that was looked at can be allowed like any other item. Nothing
//! here is sent to the AI, and no key is shown: a key is named by its type
//! and SHA-256 fingerprint, as `ssh-keygen -l` prints it.

use std::fs;

use super::collect::{self, Body, Item, Origin, Scope};
use super::read::{self, Found, View};
use super::tier::Tier;
use crate::autorun::Category;
use crate::rules::RuleId;
use crate::sha256::Sha256;

/// Groups whose members can become root, or read what only root should:
/// `wheel` and `sudo` through sudo, `docker`, `lxd`, `incus-admin` and
/// `libvirt` through a container or machine they may start as root, `disk`
/// and `shadow` by reading the disks and the password hashes.
const ROOT_GROUPS: &[&str] = &[
    "root",
    "wheel",
    "sudo",
    "docker",
    "lxd",
    "incus-admin",
    "libvirt",
    "disk",
    "shadow",
];

/// Shells nobody logs in with.
const NO_LOGIN: &[&str] = &["nologin", "false", "git-shell", "sync", "halt", "shutdown"];

/// The first user id of an ordinary account.
const FIRST_USER_ID: u32 = 1000;

/// The most accounts, members and keys that become items.
const MAX_FACTS: usize = 500;
/// The largest key file read.
const MAX_KEY_FILE: usize = 1024 * 1024;

/// One line of `/etc/passwd`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    /// The password field: `x` (kept in `/etc/shadow`), empty (none
    /// needed), `!`/`*` (locked) or a hash.
    password: String,
    pub uid: u32,
    gid: u32,
    /// Relative to the root.
    pub home: String,
    shell: String,
}

/// The accounts of a `passwd` text; a line that does not parse is left out.
pub fn accounts(passwd: &str) -> Vec<Account> {
    passwd
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            // A name is part of an item's path: nothing that reads as a
            // directory.
            let name = *fields.first()?;
            if name.is_empty() || name.contains(['/', '#']) || name.starts_with('.') {
                return None;
            }
            Some(Account {
                name: name.to_string(),
                password: (*fields.get(1)?).to_string(),
                uid: fields.get(2)?.parse().ok()?,
                gid: fields.get(3)?.parse().ok()?,
                home: fields.get(5)?.trim_matches('/').to_string(),
                shell: (*fields.get(6)?).to_string(),
            })
        })
        .collect()
}

impl Account {
    fn can_log_in(&self) -> bool {
        let shell = self.shell.rsplit('/').next().unwrap_or_default();
        !NO_LOGIN.contains(&shell)
    }
}

/// Whether a password field (of `passwd` or `shadow`) lets someone in:
/// `None` when it only says the password is kept in `/etc/shadow`.
fn has_usable_password(field: &str) -> Option<bool> {
    match field {
        "x" => None,
        // An empty field is a login without any password.
        "" => Some(true),
        locked if locked.starts_with(['!', '*']) => Some(false),
        _ => Some(true),
    }
}

/// An item for a fact that is no file: `text` is what is remembered and
/// compared, `path` names it (`etc/group#wheel:u`).
fn fact(origin: Origin, path: String, text: String, note: String) -> Item {
    Item {
        origin,
        category: Category::Account,
        path,
        tier: Tier::Unknown,
        sha256: Some(Sha256::digest(text.as_bytes())),
        body: Body::Text(text),
        runs: Vec::new(),
        run_by: None,
        notes: vec![note],
        alerts: Vec::new(),
    }
}

/// The accounts that can log in, each an item; with an alert for a second
/// account with user id 0 and for a system account someone can log in to.
/// `shadow` is `/etc/shadow` where the reader may read it (the root
/// collector): only whether an account has a usable password is taken from
/// it, never the hash.
fn account_items(origin: Origin, passwd: &[Account], shadow: Option<&str>) -> Vec<Item> {
    let shadowed = |name: &str| -> Option<bool> {
        shadow?.lines().find_map(|line| {
            let mut fields = line.split(':');
            (fields.next()? == name).then(|| has_usable_password(fields.next()?))?
        })
    };
    let mut items = Vec::new();
    for account in passwd.iter().filter(|account| account.can_log_in()) {
        let password = has_usable_password(&account.password).or_else(|| shadowed(&account.name));
        let mut item = fact(
            origin,
            format!("etc/passwd#{}", account.name),
            format!(
                "account {} uid {} shell {}",
                account.name, account.uid, account.shell
            ),
            format!("an account with a login shell (user id {})", account.uid),
        );
        if account.uid == 0 && account.name != "root" {
            item.alerts.push((
                RuleId::PrivilegedAccount,
                format!(
                    "{} has user id 0: it is root under another name",
                    account.name
                ),
            ));
        } else if account.uid != 0 && account.uid < FIRST_USER_ID && password == Some(true) {
            item.alerts.push((
                RuleId::PrivilegedAccount,
                format!(
                    "the system account {} has a login shell and a password that works",
                    account.name
                ),
            ));
        }
        items.push(item);
    }
    items
}

/// The members of the groups that amount to root, each an item: the ones
/// `/etc/group` lists and the accounts whose own group it is.
fn member_items(origin: Origin, passwd: &[Account], group: &str) -> Vec<Item> {
    let mut items = Vec::new();
    for line in group.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        let (Some(name), Some(gid)) = (
            fields.first().copied(),
            fields.get(2).and_then(|gid| gid.parse::<u32>().ok()),
        ) else {
            continue;
        };
        if !ROOT_GROUPS.contains(&name) {
            continue;
        }
        let mut members: Vec<&str> = fields
            .get(3)
            .into_iter()
            .flat_map(|members| members.split(','))
            .map(str::trim)
            .filter(|member| !member.is_empty() && !member.contains(['/', '#']))
            .chain(
                passwd
                    .iter()
                    .filter(|account| account.gid == gid)
                    .map(|account| account.name.as_str()),
            )
            // Root is root with or without a group.
            .filter(|member| *member != "root")
            .collect();
        members.sort_unstable();
        members.dedup();
        for member in members {
            items.push(fact(
                origin,
                format!("etc/group#{name}:{member}"),
                format!("member {member} of group {name}"),
                format!("{member} is in {name}, whose members can become root"),
            ));
        }
    }
    items
}

/// Standard base64 decoded, or `None`.
fn base64(encoded: &str) -> Option<Vec<u8>> {
    let mut bits = 0_u32;
    let mut count = 0;
    let mut bytes = Vec::with_capacity(encoded.len() * 3 / 4);
    for character in encoded.trim_end_matches('=').bytes() {
        let value = match character {
            b'A'..=b'Z' => character - b'A',
            b'a'..=b'z' => character - b'a' + 26,
            b'0'..=b'9' => character - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(value);
        count += 6;
        if count >= 8 {
            count -= 8;
            bytes.push(u8::try_from((bits >> count) & 0xff).ok()?);
        }
    }
    Some(bytes)
}

/// Standard base64 without padding, as SSH writes a fingerprint.
fn to_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let group = chunk
            .iter()
            .fold(0_u32, |group, byte| (group << 8) | u32::from(*byte))
            << (8 * (3 - chunk.len()));
        for index in 0..=chunk.len() {
            let sextet = (group >> (18 - 6 * index)) & 0x3f;
            if let Some(letter) = usize::try_from(sextet).ok().and_then(|at| ALPHABET.get(at)) {
                out.push(char::from(*letter));
            }
        }
    }
    out
}

/// One authorised key: its type, the SHA-256 fingerprint of the key, its
/// comment, and the names of its options (a `command=` and its value are
/// what the key runs; the value stays in the file).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    kind: String,
    /// The digest in hex, for a name that is a plain path component.
    hex: String,
    fingerprint: String,
    comment: String,
    options: Vec<String>,
}

/// The names of a key's options (`from="a, b",command="x"` gives
/// `command` and `from`): split at the commas outside quotes, the values
/// left behind.
fn option_names(options: &str) -> Vec<String> {
    let mut names = Vec::new();
    let (mut quoted, mut start) = (false, 0);
    let mut name = |option: &str| {
        let name = option
            .split('=')
            .next()
            .unwrap_or_default()
            .trim()
            .to_lowercase();
        if !name.is_empty() && name.len() < 40 {
            names.push(name);
        }
    };
    for (index, character) in options.char_indices() {
        match character {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                name(&options[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    name(&options[start..]);
    names.sort();
    names.dedup();
    names
}

fn is_key_type(word: &str) -> bool {
    word.starts_with("ssh-") || word.starts_with("ecdsa-") || word.starts_with("sk-")
}

/// The keys of an `authorized_keys` text. A line that is not a key is
/// counted, not guessed at.
pub fn keys(text: &str) -> (Vec<Key>, usize) {
    let mut found = Vec::new();
    let mut odd = 0;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Options come first and may hold blanks inside quotes.
        let mut words: Vec<&str> = Vec::new();
        let (mut quoted, mut start) = (false, 0);
        for (index, character) in line.char_indices() {
            match character {
                '"' => quoted = !quoted,
                ' ' | '\t' if !quoted => {
                    if index > start {
                        words.push(&line[start..index]);
                    }
                    start = index + 1;
                }
                _ => {}
            }
        }
        if start < line.len() {
            words.push(&line[start..]);
        }
        let Some(at) = words.iter().position(|word| is_key_type(word)) else {
            odd += 1;
            continue;
        };
        let Some(blob) = words.get(at + 1).and_then(|blob| base64(blob)) else {
            odd += 1;
            continue;
        };
        let digest = Sha256::digest(&blob).to_string();
        let raw: Vec<u8> = (0..digest.len() / 2)
            .filter_map(|index| u8::from_str_radix(digest.get(index * 2..index * 2 + 2)?, 16).ok())
            .collect();
        let options = option_names(&words[..at].join(" "));
        found.push(Key {
            kind: words[at].to_string(),
            fingerprint: format!("SHA256:{}", to_base64(&raw)),
            hex: digest,
            comment: words[at + 2..]
                .join(" ")
                .chars()
                .filter(|character| !character.is_control())
                .take(80)
                .collect(),
            options,
        });
    }
    (found, odd)
}

/// The key files of an account, relative to its home: SSH's defaults and
/// what `AuthorizedKeysFile` in the server's configuration names (`%h` and
/// a relative path are the home, `%u` the account).
fn key_files(config: &[String], account: &str) -> Vec<String> {
    let mut files = vec![
        ".ssh/authorized_keys".to_string(),
        ".ssh/authorized_keys2".to_string(),
    ];
    for text in config {
        for line in text.lines() {
            let mut words = line.split_whitespace();
            if !words
                .next()
                .is_some_and(|key| key.eq_ignore_ascii_case("authorizedkeysfile"))
            {
                continue;
            }
            for file in words {
                let file = file.replace("%u", account);
                // A file outside the home is an item of the SSH
                // configuration that names it, not this account's.
                let relative = match file.strip_prefix("%h/") {
                    Some(relative) => relative.to_string(),
                    None if file.starts_with('/') || file == "none" => continue,
                    None => file,
                };
                let plain = relative
                    .split('/')
                    .all(|part| !matches!(part, "" | "." | ".."));
                if plain && !relative.contains('%') && !files.contains(&relative) {
                    files.push(relative);
                }
            }
        }
    }
    files
}

/// The server's configuration: the main file and its drop-ins, as far as
/// everyone may read them.
fn sshd_configuration(scope: &Scope<'_>) -> Vec<String> {
    let mut paths = vec!["etc/ssh/sshd_config".to_string()];
    paths.extend(
        read::entries(scope.root, "etc/ssh/sshd_config.d")
            .files
            .into_iter()
            .filter(|file| read::has_extension(file, "conf")),
    );
    paths
        .iter()
        .filter_map(
            |path| match collect::look(scope, Category::Ssh, path, None) {
                Found::File { head, .. } => Some(String::from_utf8_lossy(&head).into_owned()),
                _ => None,
            },
        )
        .collect()
}

/// How the key files of an account are looked at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Detail {
    /// One item for each key: the account is the reader's own, or root.
    Keys,
    /// One item for the account: how many keys, and a hash of the list, so
    /// that a change shows. Whose keys they are is the other account's
    /// business.
    Count,
}

/// The keys that may log in as `account`, read with `look` (which says
/// what is at a path relative to the root, as far as the reader may see).
fn key_items(
    origin: Origin,
    account: &Account,
    files: &[String],
    detail: Detail,
    look: &dyn Fn(&str) -> Option<Found>,
) -> Vec<Item> {
    let mut items = Vec::new();
    let mut all: Vec<String> = Vec::new();
    for file in files {
        let path = format!("{}/{file}", account.home);
        let Some(Found::File { head, size, .. }) = look(&path) else {
            continue;
        };
        if usize::try_from(size).unwrap_or(usize::MAX) > MAX_KEY_FILE {
            continue;
        }
        let (found, odd) = keys(&String::from_utf8_lossy(&head));
        for key in found {
            all.push(key.hex.clone());
            if detail == Detail::Count {
                continue;
            }
            let options = if key.options.is_empty() {
                String::new()
            } else {
                format!(" options {}", key.options.join(","))
            };
            let mut item = fact(
                origin,
                format!("{path}#{}", &key.hex[..16]),
                format!("{} {} {}{options}", key.kind, key.fingerprint, key.comment),
                format!(
                    "a key that may log in as {}: {} {} {}",
                    account.name, key.kind, key.fingerprint, key.comment
                ),
            );
            if key
                .options
                .iter()
                .any(|option| matches!(option.as_str(), "command" | "environment"))
            {
                item.alerts
                    .push((RuleId::SshCommand, "command= or environment= option".into()));
            }
            items.push(item);
        }
        if odd > 0 && detail == Detail::Keys {
            items.push(fact(
                origin,
                format!("{path}#unread"),
                format!("{odd} line(s) that are no key"),
                format!("{odd} line(s) of the key file could not be read as a key"),
            ));
        }
    }
    if detail == Detail::Count && !all.is_empty() {
        all.sort();
        items.push(fact(
            origin,
            format!("{}/.ssh/authorized_keys#keys", account.home),
            format!(
                "{} key(s): {}",
                all.len(),
                Sha256::digest(all.join("\n").as_bytes())
            ),
            format!(
                "{} key(s) may log in as {}; whose they are is that account's to see",
                all.len(),
                account.name
            ),
        ));
    }
    items
}

/// What `scope` sees of accounts, groups and its own home's keys.
pub fn items(scope: &Scope<'_>) -> Vec<Item> {
    let read = |path: &str| fs::read_to_string(scope.root.join(path)).unwrap_or_default();
    let passwd = accounts(&read("etc/passwd"));
    // Only root reads `/etc/shadow`, by its fixed path and never following
    // a link, for a yes or no on each account.
    let shadow = (scope.origin == Origin::Root)
        .then(|| read::look_as(scope.root, "etc/shadow", View::Pinned))
        .flatten()
        .and_then(|found| match found {
            Found::File { head, .. } => Some(String::from_utf8_lossy(&head).into_owned()),
            _ => None,
        });
    let mut items = account_items(scope.origin, &passwd, shadow.as_deref());
    items.extend(member_items(scope.origin, &passwd, &read("etc/group")));
    if let Some(home) = scope.home {
        let name = passwd
            .iter()
            .find(|account| account.home == home)
            .map_or_else(
                || home.rsplit('/').next().unwrap_or(home).to_string(),
                |account| account.name.clone(),
            );
        let own = Account {
            name,
            password: String::new(),
            uid: 0,
            gid: 0,
            home: home.to_string(),
            shell: String::new(),
        };
        let files = key_files(&sshd_configuration(scope), &own.name);
        // A user's sweep reads its own home; the root collector's home is
        // root's.
        let origin = if scope.origin == Origin::System {
            Origin::User
        } else {
            scope.origin
        };
        items.extend(key_items(origin, &own, &files, Detail::Keys, &|path| {
            Some(collect::look(scope, Category::Ssh, path, None))
        }));
    }
    items.truncate(MAX_FACTS);
    items
}

/// The keys of `account`, as the root collector may report them: read as
/// that account could read them itself, no link followed (a key file that
/// is a link to a file of root's shows nothing).
pub fn keys_of(scope: &Scope<'_>, account: &Account, detail: Detail) -> Vec<Item> {
    let files = key_files(&sshd_configuration(scope), &account.name);
    key_items(Origin::Root, account, &files, detail, &|path| {
        read::look_as(scope.root, path, View::Owner(account.uid))
    })
}

#[cfg(test)]
mod tests {
    use super::{
        Account, Detail, account_items, accounts, key_files, key_items, keys, member_items,
    };
    use crate::rules::RuleId;
    use crate::sha256::Sha256;
    use crate::sweep::collect::Origin;
    use crate::sweep::read::Found;

    const PASSWD: &str = "root:x:0:0::/root:/usr/bin/bash\nbin:x:1:1::/:/usr/bin/nologin\ngit:x:969:969::/srv/git:/usr/bin/git-shell\ndaemon:x:2:2::/:/bin/sh\ntoor:x:0:0::/root:/bin/bash\nu:x:1000:1000::/home/u:/bin/zsh\nold:$6$hash:7:7::/:/bin/sh\nsvc::8:8::/:/bin/bash\nbad/name:x:1:1::/:/bin/sh\n";

    #[test]
    fn accounts_that_can_log_in_are_items_and_the_odd_ones_alerts() {
        let passwd = accounts(PASSWD);
        assert_eq!(passwd.len(), 8);
        let shadow = "root:$6$secret:1::::::\ndaemon:$6$alsosecret:1::::::\nu:!:1::::::\n";
        let items = account_items(Origin::Root, &passwd, Some(shadow));
        let found: Vec<(&str, bool)> = items
            .iter()
            .map(|item| (item.path.as_str(), !item.alerts.is_empty()))
            .collect();
        assert_eq!(
            found,
            [
                ("etc/passwd#root", false),
                // A system account with a shell and a password in shadow.
                ("etc/passwd#daemon", true),
                // Root under another name.
                ("etc/passwd#toor", true),
                ("etc/passwd#u", false),
                // A hash in passwd itself, and no password at all.
                ("etc/passwd#old", true),
                ("etc/passwd#svc", true),
            ]
        );
        assert!(items.iter().all(|item| {
            item.alerts
                .iter()
                .all(|(rule, _)| *rule == RuleId::PrivilegedAccount)
        }));
        // Nothing of a hash is kept, in the item or what it is compared by.
        let all = format!("{items:?}");
        assert!(!all.contains("secret") && !all.contains("$6$"), "{all}");
        // Without shadow, `x` says nothing: no alert on a guess.
        let unread = account_items(Origin::System, &passwd, None);
        assert!(unread[1].alerts.is_empty());
        assert!(!unread[4].alerts.is_empty());
    }

    #[test]
    fn members_of_the_groups_that_amount_to_root_are_items() {
        let passwd = accounts(PASSWD);
        let group = "root:x:0:root\nwheel:x:998:u,v\ndocker:x:966:\nusers:x:100:u\ndisk:x:7:\n";
        let paths: Vec<String> = member_items(Origin::System, &passwd, group)
            .into_iter()
            .map(|item| item.path)
            .collect();
        // `toor` by its own group 0, `old` by its own group 7 (disk).
        assert_eq!(
            paths,
            [
                "etc/group#root:toor",
                "etc/group#wheel:u",
                "etc/group#wheel:v",
                "etc/group#disk:old"
            ]
        );
    }

    #[test]
    fn keys_are_named_by_type_and_fingerprint_never_by_the_key() {
        // `ssh-keygen -lf` prints SHA256:<base64 of the digest of the blob>.
        let blob = "AAAAC3NzaC1lZDI1NTE5AAAAIGuardianTestKeyMaterial0123456789abcdefghi";
        let text = format!(
            "# mine\nssh-ed25519 {blob} me@laptop\nfrom=\"10.0.0.1, 10.0.0.2\",command=\"/tmp/x --y\" ssh-ed25519 {blob} deploy key\nnot a key line\nssh-rsa !!! broken\n"
        );
        let (found, odd) = keys(&text);
        assert_eq!(odd, 2);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].kind, "ssh-ed25519");
        assert_eq!(found[0].comment, "me@laptop");
        assert!(found[0].fingerprint.starts_with("SHA256:"));
        assert_eq!(found[0].fingerprint.len(), "SHA256:".len() + 43);
        assert_eq!(found[1].options, ["command", "from"]);
        assert_eq!(found[1].comment, "deploy key");
        assert_eq!(
            super::to_base64(b"any carnal pleas"),
            "YW55IGNhcm5hbCBwbGVhcw"
        );
        assert_eq!(
            super::base64("YW55IGNhcm5hbCBwbGVhcw==").unwrap(),
            b"any carnal pleas"
        );

        let account = Account {
            name: "u".into(),
            password: "x".into(),
            uid: 1000,
            gid: 1000,
            home: "home/u".into(),
            shell: "/bin/zsh".into(),
        };
        let look = |path: &str| {
            (path == "home/u/.ssh/authorized_keys").then(|| Found::File {
                sha256: Sha256::digest(text.as_bytes()),
                mode: 0o600,
                size: text.len() as u64,
                head: text.clone().into_bytes(),
            })
        };
        let files = key_files(&[], "u");
        let items = key_items(Origin::System, &account, &files, Detail::Keys, &look);
        assert_eq!(items.len(), 3);
        assert!(items[0].path.starts_with("home/u/.ssh/authorized_keys#"));
        assert_eq!(
            items[0].path.len(),
            "home/u/.ssh/authorized_keys#".len() + 16
        );
        assert!(items[0].notes[0].contains("may log in as u"));
        assert!(items[0].alerts.is_empty());
        assert_eq!(items[1].alerts[0].0, RuleId::SshCommand);
        assert_eq!(items[2].path, "home/u/.ssh/authorized_keys#unread");
        let all = format!("{items:?}");
        assert!(!all.contains(blob) && !all.contains("/tmp/x"), "{all}");

        // Another account's keys: how many, and a hash that moves when
        // the list does.
        let counted = key_items(Origin::Root, &account, &files, Detail::Count, &look);
        assert_eq!(counted.len(), 1);
        assert_eq!(counted[0].path, "home/u/.ssh/authorized_keys#keys");
        assert!(counted[0].notes[0].starts_with("2 key(s) may log in as u"));
        assert!(!format!("{counted:?}").contains("me@laptop"));
    }

    #[test]
    fn the_servers_configuration_names_more_key_files() {
        let config = vec![
            "# AuthorizedKeysFile no\nAuthorizedKeysFile .ssh/authorized_keys %h/.ssh/extra /etc/ssh/keys/%u ../../etc/shadow none\n"
                .to_string(),
        ];
        assert_eq!(
            key_files(&config, "u"),
            [
                ".ssh/authorized_keys",
                ".ssh/authorized_keys2",
                ".ssh/extra"
            ]
        );
    }
}
