//! The root part of the sweep. Some auto-run files only root can read (the
//! sudoers file and drop-ins, root's crontab, shell files and keys, some
//! programs services run), so `sweep --root` runs `sweep-collect` through
//! sudo. That command only collects: it reads, never runs anything it
//! finds, makes no AI call and writes nothing. It prints the items no
//! package vouches for as JSON on stdout, and the user's own sweep judges
//! them with the user's settings.
//!
//! It also looks, for the accounts its results go to, at what would make
//! their own sweep lie (an override of Guardian's user units) and at the
//! keys that may log in as them, as those accounts could look themselves;
//! of other accounts' keys it says only how many there are.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write as _};
use std::os::unix::fs::{self as unix_fs, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::time::UNIX_EPOCH;

use super::access::{self, Account, Detail};
use super::collect::{self, Body, Collection, Item, Origin, Scope};
use super::index::{self, LOCAL_DB, PackageIndex};
use super::state::{self, Remembered};
use super::tier::Tier;
use super::{live, own};
use crate::autorun::Category;
use crate::engine::store;
use crate::json::Json;
use crate::rules::RuleId;
use crate::sha256::Digest;

const SUDO: &str = "/usr/bin/sudo";
const INSTALLED: &str = "/usr/bin/omarchy-guardian";
/// Root's home, relative to `/`.
const ROOT_HOME: &str = "root";
/// The most output and items taken from the root collector.
const MAX_OUTPUT: u64 = 64 * 1024 * 1024;
const MAX_ITEMS: usize = 5000;
/// The version of the results. 2: the collector compares packaged programs
/// only root can read, reports what it could not check in the kernel's own
/// accounts, and keeps track of new accounts, members and keys itself.
const VERSION: u64 = 2;
/// The oldest version still read. Its results are kept, and count as those
/// of a collector that does not run every check (see `RootPart::outdated`).
const OLDEST_VERSION: u64 = 1;
/// The most of one note that is kept.
const MAX_NOTE_CHARS: usize = 400;

/// What the root collector found.
#[derive(Debug, Default)]
pub struct RootPart {
    pub items: Vec<Item>,
    pub truncated: Vec<String>,
    /// What the live checks say of the system as a whole (a tainted
    /// kernel, modules no package installed).
    pub notes: Vec<String>,
    /// Written by an older collector, which did not run every check this
    /// one does: what the user's own sweep leaves to the root checks is not
    /// covered by these results.
    pub outdated: bool,
    /// The paths of the accounts, members, keys and trust anchors that are
    /// new to the collector, when it kept track (see `news`).
    pub news: Option<Vec<String>>,
}

/// Where the collector remembers the accounts, group members, keys and
/// trust anchors it reported, beside its results: root's alone to write,
/// so nothing running as a user can make a new one look known.
const TRUST_SEEN: &str = "/var/lib/omarchy-guardian/sweep/trust-seen.json";

/// How long one of those counts as new after the collector first saw it:
/// longer than results are used for, so that a sweep which missed a day
/// still hears of it.
const NEW_FOR_SECS: u64 = 48 * 60 * 60;

/// The most the collector remembers.
const MAX_TRUST_SEEN: usize = 20_000;

/// What the collector remembers of one of them: its content, and when it
/// first had that content (0 for what was there when tracking started,
/// which is news to nobody).
type TrustSeen = std::collections::BTreeMap<String, (String, u64)>;

fn read_trust_seen(path: &Path) -> Option<TrustSeen> {
    if !state::owned_alone(path, 0, Path::new(state::ROOT_STATE_ANCHOR), MAX_OUTPUT) {
        return None;
    }
    let json = Json::parse(&fs::read_to_string(path).ok()?).ok()?;
    Some(
        json.as_object()?
            .iter()
            .filter_map(|(label, entry)| {
                Some((
                    label.clone(),
                    (
                        entry.get("content")?.as_str()?.to_string(),
                        entry.get("first")?.as_u64()?,
                    ),
                ))
            })
            .collect(),
    )
}

fn trust_seen_json(seen: &TrustSeen) -> String {
    Json::object(seen.iter().map(|(label, (content, first))| {
        (
            label.as_str(),
            Json::object([
                ("content", Json::from(content.as_str())),
                ("first", Json::from(*first)),
            ]),
        )
    }))
    .to_string()
}

/// Whether `item` is one an account keeps under `/home`, or was reached
/// from one: that account decides how many of those there are.
fn of_an_account(item: &Item) -> bool {
    let at_home = |path: &str| path.starts_with("home/");
    at_home(&item.path) || item.run_by.as_deref().is_some_and(at_home)
}

/// The items no package vouches for, in the order they are kept where
/// there is room for only so many: root's own and the system's first, and
/// what the accounts keep under `/home` after them. An account that fills
/// its home with thousands of lines then crowds out its own, and never
/// root's keys or a unit in `/etc`.
fn in_keeping_order(items: &[Item]) -> impl Iterator<Item = &Item> {
    let untrusted = |of_account: bool| {
        items
            .iter()
            .filter(move |item| !item.is_trusted() && of_an_account(item) == of_account)
    };
    untrusted(false).chain(untrusted(true))
}

/// The paths among `items` of the accounts, group members, keys and trust
/// anchors that are new to the collector at `now`: not in `seen`, or there
/// with other content, for `NEW_FOR_SECS` from when that was first so.
/// `seen` is brought up to date. With none yet, everything is remembered
/// and the collector has nothing to say of what is new (`None`): the sweep
/// that reads the results then goes by what it remembers itself, rather
/// than hearing "nothing new" from a collector that could not know. What
/// is gone is forgotten, so that one put back is new again.
fn news(items: &[Item], seen: Option<TrustSeen>, now: u64) -> (Option<Vec<String>>, TrustSeen) {
    let first_look = seen.is_none();
    let before = seen.unwrap_or_default();
    let mut after = TrustSeen::new();
    let mut new = Vec::new();
    for item in in_keeping_order(items)
        .filter(|item| super::is_trust(item))
        .take(MAX_TRUST_SEEN)
    {
        let fingerprint = state::fingerprint(item);
        let content = state::content_of(&fingerprint).to_string();
        let first = match before.get(&item.path) {
            Some((known, first)) if *known == content => *first,
            _ if first_look => 0,
            _ => now.max(1),
        };
        if first != 0 && now.saturating_sub(first) < NEW_FOR_SECS {
            new.push(item.path.clone());
        }
        after.insert(item.path.clone(), (content, first));
    }
    ((!first_look).then_some(new), after)
}

/// Where the scheduled root collector leaves what it found.
pub const RESULTS: &str = "/var/lib/omarchy-guardian/sweep/root.json";
/// Older results are not used: the daily timer should have replaced them.
const MAX_AGE_SECS: u64 = 36 * 60 * 60;

/// `omarchy-guardian sweep-collect [--out]`: run as root, by `sweep --root`
/// through sudo (printing to stdout), or by the daily system timer with
/// `--out` (writing `RESULTS`, only when the system configuration allows
/// it, readable by the configured group).
pub fn collect_command(out: bool, settings: &crate::config::Settings) -> ExitCode {
    if !store::effective_uid().is_ok_and(|uid| uid == 0) {
        errln!(
            "omarchy-guardian sweep-collect: only `sweep --root` and its timer run this, as root"
        );
        return ExitCode::from(2);
    }
    // The list of allowed items an older Guardian kept beside the results
    // moves to where every user can read it. Not being able to is no reason
    // to collect nothing: the next allow says why.
    drop(state::move_legacy_allowed(
        Path::new(state::SYSTEM_ALLOWED),
        Path::new(state::LEGACY_SYSTEM_ALLOWED),
    ));
    let (consent, group) = settings.sweep_root();
    let group = if out {
        if consent != Some(crate::config::model::RootConsent::Allowed) {
            outln!("Root checks are not allowed in the system configuration; nothing collected.");
            return ExitCode::SUCCESS;
        }
        let Some(gid) = group.as_deref().and_then(group_id) else {
            errln!(
                "omarchy-guardian sweep-collect: no valid [sweep] group in the system configuration"
            );
            return ExitCode::from(2);
        };
        Some(gid)
    } else {
        None
    };
    let index = match index::foreign_packages()
        .and_then(|foreign| PackageIndex::load(Path::new(LOCAL_DB), foreign))
    {
        Ok(index) => index,
        Err(error) => {
            errln!("omarchy-guardian sweep-collect: cannot read the package database: {error}");
            return ExitCode::from(2);
        }
    };
    let scope = Scope {
        root: Path::new("/"),
        home: Some(ROOT_HOME),
        index: &index,
        origin: Origin::Root,
    };
    let mut collection = collect::collect(&scope);
    let live = live::check(&scope);
    collect::merge(&mut collection, live.items);
    collection.truncated.extend(live.unchecked);
    // Who reads these results: the group the system configuration names,
    // or the user who ran `sweep --root`. Other accounts' crontabs and
    // `at` jobs are theirs: only how many were left out is noted.
    let passwd = fs::read_to_string("/etc/passwd").unwrap_or_default();
    let readers = match group {
        Some(gid) => accounts_in_group(
            gid,
            &passwd,
            &fs::read_to_string("/etc/group").unwrap_or_default(),
        ),
        None => std::env::var("SUDO_USER").into_iter().collect(),
    };
    let accounts = access::accounts(&passwd);
    collect::merge(&mut collection, of_accounts(&scope, &accounts, &readers));
    collection.truncated.extend(accounts_left_out(&accounts));
    let withheld = withhold_others_jobs(&mut collection.items, &readers, &|job| {
        let uid = fs::symlink_metadata(Path::new("/").join(job)).ok()?.uid();
        accounts
            .iter()
            .find(|account| account.uid == uid)
            .map(|account| account.name.clone())
    });
    let mut notes = live.notes;
    notes.append(&mut collection.notes);
    if withheld > 0 {
        notes.push(format!(
            "{withheld} crontab(s) or at job(s) of other accounts were left out: they are theirs to see"
        ));
    }
    // What is new among the accounts, members, keys and trust anchors is
    // told from the collector's own record. Only the timer's run keeps
    // one; a run through sudo reads it where there is one and writes
    // nothing, as it writes nothing else. Without a record yet (the
    // timer's first run too) the results carry no list.
    let now = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let seen = read_trust_seen(Path::new(TRUST_SEEN));
    let (new, seen) = news(&collection.items, seen, now);
    let json = to_json(&collection, &notes, new.as_deref()).to_string();
    match group {
        // Written as it is, for the sweep that asked to parse: a path
        // with a hidden character must stay the path it is.
        None => match writeln!(std::io::stdout(), "{json}") {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(2),
        },
        Some(gid) => match write_results(Path::new(RESULTS), &json, gid).and_then(|()| {
            state::write_text_mode(Path::new(TRUST_SEEN), &trust_seen_json(&seen), 0o600)
        }) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                errln!("omarchy-guardian sweep-collect: {error}");
                ExitCode::from(2)
            }
        },
    }
}

/// The name of this process's primary group, from `/proc/self/status` and
/// `/etc/group`.
pub fn primary_group() -> Option<String> {
    let gid: u32 = fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("Gid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    private_group(
        gid,
        &fs::read_to_string("/etc/group").ok()?,
        &fs::read_to_string("/etc/passwd").ok()?,
    )
}

/// The name of group `gid` when it is one person's alone: no listed
/// members, and the primary group of one account only. Root's results are
/// readable by that group, so a shared one (`users`) would show them to
/// everyone in it.
fn private_group(gid: u32, group: &str, passwd: &str) -> Option<String> {
    let (name, members) = group.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        (fields.get(2)?.parse::<u32>().ok()? == gid)
            .then(|| (fields[0].to_string(), fields.get(3).copied().unwrap_or("")))
    })?;
    let primary_of = passwd
        .lines()
        .filter(|line| {
            line.split(':')
                .nth(3)
                .and_then(|field| field.parse::<u32>().ok())
                == Some(gid)
        })
        .count();
    (members.trim().is_empty() && primary_of == 1 && crate::config::file::is_group_name(&name))
        .then_some(name)
}

/// The accounts whose primary group is `gid`, or that `/etc/group` lists
/// as its members.
fn accounts_in_group(gid: u32, passwd: &str, group: &str) -> Vec<String> {
    let mut accounts: Vec<String> = passwd
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            (fields.get(3)?.parse::<u32>().ok()? == gid).then(|| fields[0].to_string())
        })
        .collect();
    for line in group.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.get(2).and_then(|id| id.parse::<u32>().ok()) == Some(gid) {
            accounts.extend(
                fields
                    .get(3)
                    .into_iter()
                    .flat_map(|members| members.split(','))
                    .filter(|member| !member.is_empty())
                    .map(str::to_string),
            );
        }
    }
    accounts.sort();
    accounts.dedup();
    accounts
}

/// The most accounts with a home under `/home` whose keys are looked at.
const MAX_ACCOUNTS: usize = 200;

/// The accounts `of_accounts` looks at: not root, with a home under
/// `/home`.
fn with_a_home(accounts: &[Account]) -> impl Iterator<Item = &Account> {
    accounts
        .iter()
        .filter(|account| account.uid != 0 && account.home.starts_with("home/"))
}

/// What is said when there are more such accounts than are looked at:
/// the keys and unit overrides of the rest were not checked.
fn accounts_left_out(accounts: &[Account]) -> Option<String> {
    let more = with_a_home(accounts).count().saturating_sub(MAX_ACCOUNTS);
    (more > 0).then(|| {
        format!(
            "more than {MAX_ACCOUNTS} accounts with a home under /home: the keys of {more} were not looked at"
        )
    })
}

/// What root reports about the accounts with a home under `/home`, each
/// looked at as that account could look itself (no link followed, nothing
/// read that it could not read): for the accounts the results go to
/// (`readers`), what overrides Guardian's user units in their home and
/// each key that may log in as them; for every other account only how many
/// keys there are, and a hash of the list so that a change shows. Whose
/// keys those are is that account's business, like its crontab.
fn of_accounts(scope: &Scope<'_>, accounts: &[Account], readers: &[String]) -> Vec<Item> {
    let mut items = Vec::new();
    for account in with_a_home(accounts).take(MAX_ACCOUNTS) {
        let reader = readers.contains(&account.name);
        if reader {
            items.extend(own::of_account(scope, &account.home, account.uid));
        }
        let detail = if reader { Detail::Keys } else { Detail::Count };
        items.extend(access::keys_of(scope, account, detail));
    }
    items
}

/// Leaves the crontabs and `at` jobs of root and of `readers` in `items`,
/// and takes out those of other accounts: they are theirs. A crontab is
/// named after its account; `owner` says whose an `at` job is (one nobody
/// can tell is somebody else's). Returns how many were taken out.
fn withhold_others_jobs(
    items: &mut Vec<Item>,
    readers: &[String],
    owner: &dyn Fn(&str) -> Option<String>,
) -> usize {
    let others = |path: &str| {
        let account = match path.strip_prefix("var/spool/cron/") {
            _ if collect::is_at_job(path) => owner(path).unwrap_or_default(),
            Some(account) => account.to_string(),
            None => return false,
        };
        account != "root" && !readers.contains(&account)
    };
    let withheld = items.iter().filter(|item| others(&item.path)).count();
    // And what was found by following them: their scripts are theirs too.
    items.retain(|item| !others(&item.path) && !item.run_by.as_deref().is_some_and(others));
    withheld
}

/// The id of group `name`, from `/etc/group`.
fn group_id(name: &str) -> Option<u32> {
    fs::read_to_string("/etc/group")
        .ok()?
        .lines()
        .find_map(|line| {
            let mut fields = line.split(':');
            (fields.next()? == name)
                .then(|| fields.nth(1)?.parse().ok())
                .flatten()
        })
}

/// Writes `json` to `path` (and its directory) owned by root and group
/// `gid`: the directory 0750, the file 0640, replaced atomically.
fn write_results(path: &Path, json: &str, gid: u32) -> Result<(), String> {
    let describe = |path: &Path, error: std::io::Error| format!("{}: {error}", path.display());
    let directory = path.parent().ok_or("no directory")?;
    fs::create_dir_all(directory).map_err(|error| describe(directory, error))?;
    unix_fs::chown(directory, Some(0), Some(gid)).map_err(|error| describe(directory, error))?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o750))
        .map_err(|error| describe(directory, error))?;
    let temporary = path.with_extension("json.tmp");
    drop(fs::remove_file(&temporary));
    let result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .and_then(|mut file| file.write_all(json.as_bytes()))
        .and_then(|()| unix_fs::chown(&temporary, Some(0), Some(gid)))
        .and_then(|()| fs::set_permissions(&temporary, fs::Permissions::from_mode(0o640)))
        .and_then(|()| fs::rename(&temporary, path));
    if result.is_err() {
        drop(fs::remove_file(&temporary));
    }
    result.map_err(|error| describe(path, error))
}

/// What the scheduled root collector found, if it is trustworthy and
/// recent: owned by root and writable by no one else, file and directory,
/// and at most `MAX_AGE_SECS` old.
pub fn from_results(path: &Path, now: u64) -> Result<RootPart, String> {
    if let Some(problem) = results_problem(path, now) {
        return Err(problem);
    }
    let text = fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    from_json(&text)
}

/// Why the results at `path` are not used, as far as that shows without
/// reading them (the bar asks this too).
pub fn results_problem(path: &Path, now: u64) -> Option<String> {
    let directory = path.parent()?;
    for checked in [directory, path] {
        let metadata = match fs::symlink_metadata(checked) {
            Ok(metadata) => metadata,
            Err(error) => return Some(format!("{}: {error}", checked.display())),
        };
        if metadata.file_type().is_symlink() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0
        {
            return Some(format!(
                "{} is not root's alone; ignoring it",
                checked.display()
            ));
        }
    }
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => return Some(error.to_string()),
    };
    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |elapsed| elapsed.as_secs());
    if now.saturating_sub(modified) > MAX_AGE_SECS {
        return Some("the daily root check has not run for more than 36 hours".into());
    }
    (metadata.len() > MAX_OUTPUT).then(|| "the root check's results are too large".into())
}

fn to_json(collection: &Collection, notes: &[String], news: Option<&[String]>) -> Json {
    let untrusted = || in_keeping_order(&collection.items);
    let mut truncated = collection.truncated.clone();
    let left_out = untrusted().count().saturating_sub(MAX_ITEMS);
    if left_out > 0 {
        truncated.push(format!(
            "the root checks found more than {MAX_ITEMS} items: {left_out} were left out"
        ));
    }
    let mut members = vec![
        ("version", Json::from(VERSION)),
        (
            "items",
            Json::Array(untrusted().take(MAX_ITEMS).map(item_json).collect()),
        ),
    ];
    // Only where the collector kept track: without the list, the sweep
    // that reads this tells what is new from what it remembers itself.
    if let Some(news) = news {
        members.push((
            "new_trust",
            Json::Array(news.iter().map(|path| Json::from(path.as_str())).collect()),
        ));
    }
    members.extend([
        (
            "truncated",
            Json::Array(
                collect::bounded(truncated)
                    .into_iter()
                    .map(Json::from)
                    .collect(),
            ),
        ),
        (
            "notes",
            Json::Array(
                collect::bounded(notes.to_vec())
                    .into_iter()
                    .map(Json::from)
                    .collect(),
            ),
        ),
    ]);
    Json::object(members)
}

fn item_json(item: &Item) -> Json {
    let body = match &item.body {
        Body::Text(text) => Json::object([
            ("kind", Json::from("text")),
            ("text", Json::from(text.as_str())),
        ]),
        Body::Binary(format) => Json::object([
            ("kind", Json::from("binary")),
            ("format", Json::from(*format)),
        ]),
        Body::Undecodable => Json::object([("kind", Json::from("undecodable"))]),
        Body::Oversized => Json::object([("kind", Json::from("oversized"))]),
        Body::Link(target) => Json::object([
            ("kind", Json::from("link")),
            ("target", Json::from(target.as_str())),
        ]),
        Body::Unreadable(reason) => Json::object([
            ("kind", Json::from("unreadable")),
            ("reason", Json::from(reason.as_str())),
        ]),
    };
    let strings = |values: &[String]| {
        Json::Array(
            values
                .iter()
                .map(|value| Json::from(value.as_str()))
                .collect(),
        )
    };
    let mut members = vec![
        ("path", Json::from(item.path.as_str())),
        ("category", Json::from(item.category.name())),
        ("tier", Json::from(item.tier.name())),
        ("body", body),
        ("runs", strings(&item.runs)),
        ("notes", strings(&item.notes)),
        (
            "alerts",
            Json::Array(
                item.alerts
                    .iter()
                    .map(|(rule, seen)| {
                        Json::object([
                            ("rule", Json::from(rule.name())),
                            ("seen", Json::from(seen.as_str())),
                        ])
                    })
                    .collect(),
            ),
        ),
    ];
    if let Some(digest) = &item.sha256 {
        members.push(("sha256", Json::from(digest.to_string())));
    }
    if let Some(by) = &item.run_by {
        members.push(("run_by", Json::from(by.as_str())));
    }
    Json::object(members)
}

/// An item from the root collector's JSON; `None` for anything malformed.
fn item_from_json(json: &Json) -> Option<Item> {
    let text = |key: &str| json.get(key).and_then(Json::as_str);
    let strings = |key: &str| -> Option<Vec<String>> {
        json.get(key)?
            .as_array()?
            .iter()
            .map(|value| value.as_str().map(str::to_string))
            .collect()
    };
    let path = text("path")?;
    // Paths are relative and plain: no `..`, no empty components.
    if path.starts_with('/') || path.split('/').any(|part| matches!(part, "" | "." | "..")) {
        return None;
    }
    let body_json = json.get("body")?;
    let body_text = |key: &str| {
        body_json
            .get(key)
            .and_then(Json::as_str)
            .map(str::to_string)
    };
    let body = match body_json.get("kind")?.as_str()? {
        "text" => Body::Text(body_text("text")?),
        // Binary formats are a short fixed list; a label from the JSON is
        // kept for the life of the run.
        "binary" => {
            let label = body_text("format")?;
            Body::Binary(if label == collect::WITHHELD {
                collect::WITHHELD
            } else {
                crate::content::Format::label_named(&label)
            })
        }
        "undecodable" => Body::Undecodable,
        "oversized" => Body::Oversized,
        "link" => Body::Link(body_text("target")?),
        "unreadable" => Body::Unreadable(body_text("reason")?),
        _ => return None,
    };
    Some(Item {
        origin: Origin::Root,
        category: Category::from_name(text("category")?)?,
        path: path.to_string(),
        tier: Tier::from_name(text("tier")?)?,
        sha256: match text("sha256") {
            Some(hex) => Some(Digest::from_hex(hex)?),
            None => None,
        },
        body,
        runs: strings("runs")?,
        run_by: text("run_by").map(str::to_string),
        notes: strings("notes")?,
        // Results from before alerts existed have none.
        alerts: json
            .get("alerts")
            .and_then(Json::as_array)
            .unwrap_or_default()
            .iter()
            .map(|alert| {
                Some((
                    RuleId::from_name(alert.get("rule")?.as_str()?)?,
                    alert.get("seen")?.as_str()?.to_string(),
                ))
            })
            .collect::<Option<Vec<_>>>()?,
    })
}

fn from_json(text: &str) -> Result<RootPart, String> {
    let json = Json::parse(text.trim()).map_err(|error| format!("unreadable output: {error}"))?;
    let version = json.get("version").and_then(Json::as_u64);
    if !version.is_some_and(|version| (OLDEST_VERSION..=VERSION).contains(&version)) {
        return Err("the root collector is a different version; reinstall Guardian".into());
    }
    let listed = json
        .get("items")
        .and_then(Json::as_array)
        .ok_or("no item list")?;
    let items: Vec<Item> = listed
        .iter()
        .take(MAX_ITEMS)
        // One odd item (a process with a strange `LD_PRELOAD`, say) must not
        // throw away everything else root found.
        .filter_map(item_from_json)
        .collect();
    // But it is said: what root found and this sweep could not read is
    // something that was not checked.
    let unread = listed.len() - items.len();
    let sentences = |key: &str| -> Vec<String> {
        json.get(key)
            .and_then(Json::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(|entry| entry.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut truncated = sentences("truncated");
    if unread > 0 {
        truncated.push(format!(
            "{unread} item(s) of the root checks could not be read and were left out"
        ));
    }
    Ok(RootPart {
        items,
        truncated,
        notes: collect::bounded(sentences("notes"))
            .into_iter()
            .map(|note| note.chars().take(MAX_NOTE_CHARS).collect())
            .collect(),
        outdated: version != Some(VERSION),
        news: json.get("new_trust").and_then(Json::as_array).map(|list| {
            list.iter()
                .filter_map(|path| path.as_str().map(str::to_string))
                .take(MAX_ITEMS)
                .collect()
        }),
    })
}

/// The installed Guardian, when it is root's alone: the only program run
/// as root on the user's behalf.
fn installed() -> Result<&'static Path, String> {
    let program = Path::new(INSTALLED);
    let metadata = fs::metadata(program).map_err(|error| {
        format!("{INSTALLED}: {error}; root's part needs the installed Guardian (./install.sh)")
    })?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(format!(
            "{INSTALLED} is not root's alone; root's part needs the installed Guardian (./install.sh)"
        ));
    }
    Ok(program)
}

/// Runs the installed Guardian's `command` with `arguments` as root,
/// through sudo, which asks for the password on the terminal, to do
/// `what` ("changing ..."), which is said first. What only root may write
/// is written this way: by the installed, root-owned program, never by the
/// one that is running.
pub fn as_root(command: &str, arguments: &[&str], what: &str) -> Result<(), String> {
    let program = installed()?;
    errln!("Guardian needs root for {what}; it asks for your password.");
    let status = Command::new(SUDO)
        .arg(program)
        .arg(command)
        .args(arguments)
        .stdin(Stdio::inherit())
        .status()
        .map_err(|error| format!("cannot start sudo: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "{what} failed ({status}); nothing was changed. If the installed Guardian is older than this one, run ./install.sh"
        ))
    }
}

/// Changes the system's list of allowed items through sudo (see
/// `system_allow_command`).
pub fn system_allow(arguments: &[&str]) -> Result<(), String> {
    as_root(
        "sweep-allow-system",
        arguments,
        "changing the system's allowed items",
    )
}

/// The longest label and fingerprint the system's list takes.
const MAX_LABEL: usize = 4096;
const MAX_FINGERPRINT: usize = 8192;

const ALLOW_USAGE: &str = "usage: omarchy-guardian sweep-allow-system (--add LABEL FINGERPRINT | --remove LABEL | --clear)...";

/// Applies the changes `arguments` ask for to the system's list. A label
/// in a home (`~/…`) is kept for `invoker`, the user who ran sudo, and for
/// nobody else: root, who has no such user, cannot add one. `--clear`
/// drops the system's items and that user's, and leaves other users' home
/// items alone.
fn change_allowed(
    allowed: &mut Remembered,
    arguments: &[String],
    invoker: Option<u32>,
) -> Result<(), String> {
    let key = |label: &str| -> Result<String, String> {
        let plain = label.len() <= MAX_LABEL && !label.chars().any(char::is_control);
        if state::is_home_label(label) && plain {
            invoker.map(|uid| state::system_key(label, uid)).ok_or_else(|| {
                "an item in a home is allowed for the user who asks: run `sweep allow` as that user".to_string()
            })
        } else if label.starts_with('/') && plain {
            Ok(label.to_string())
        } else {
            Err(format!("{label:?} is not a label the sweep shows"))
        }
    };
    if arguments.is_empty() {
        return Err(ALLOW_USAGE.into());
    }
    let mut rest = arguments;
    while let Some((flag, tail)) = rest.split_first() {
        rest = match (flag.as_str(), tail) {
            ("--add", [label, fingerprint, tail @ ..]) => {
                if fingerprint.is_empty()
                    || fingerprint.len() > MAX_FINGERPRINT
                    || fingerprint.chars().any(char::is_control)
                {
                    return Err(format!("{label}: not a fingerprint"));
                }
                allowed.insert(key(label)?, fingerprint.clone());
                tail
            }
            ("--remove", [label, tail @ ..]) => {
                allowed.remove(&key(label)?);
                tail
            }
            ("--clear", tail) => {
                allowed.retain(|key, _| {
                    key.split_once(':').is_some_and(|(owner, label)| {
                        state::is_home_label(label)
                            && owner.parse::<u32>().is_ok_and(|uid| Some(uid) != invoker)
                    })
                });
                tail
            }
            _ => return Err(ALLOW_USAGE.into()),
        };
    }
    Ok(())
}

/// The changes `arguments` ask for as the audit trail keeps them: the
/// labels, without their fingerprints.
fn changes_asked(arguments: &[String]) -> String {
    let mut asked = Vec::new();
    let mut rest = arguments;
    while let Some((flag, tail)) = rest.split_first() {
        rest = match (flag.as_str(), tail) {
            ("--add", [label, _, tail @ ..]) => {
                asked.push(format!("allow {label}"));
                tail
            }
            ("--remove", [label, tail @ ..]) => {
                asked.push(format!("forget {label}"));
                tail
            }
            (_, tail) => {
                asked.push("forget everything".to_string());
                tail
            }
        };
    }
    asked.join("; ")
}

/// `omarchy-guardian sweep-allow-system (--add LABEL FINGERPRINT | --remove
/// LABEL | --clear)...`, run as root through sudo by `sweep allow` and
/// `sweep forget`: the list of allowed items, which only root writes. The
/// user it acts for is the one sudo says ran it (`SUDO_UID`).
pub fn system_allow_command(arguments: &[String]) -> ExitCode {
    if !store::effective_uid().is_ok_and(|uid| uid == 0) {
        errln!("omarchy-guardian sweep-allow-system: only `sweep allow` runs this, as root");
        return ExitCode::from(2);
    }
    let invoker = std::env::var("SUDO_UID")
        .ok()
        .and_then(|uid| uid.parse::<u32>().ok())
        .filter(|uid| *uid != 0);
    let path = Path::new(state::SYSTEM_ALLOWED);
    if let Err(error) = state::move_legacy_allowed(path, Path::new(state::LEGACY_SYSTEM_ALLOWED)) {
        errln!("omarchy-guardian sweep-allow-system: {error}");
        return ExitCode::from(2);
    }
    let mut allowed = state::system_allowed(path);
    if let Err(reason) = change_allowed(&mut allowed, arguments, invoker) {
        errln!("omarchy-guardian sweep-allow-system: {reason}");
        return ExitCode::from(2);
    }
    match state::save_system_allowed(path, &allowed) {
        Ok(()) => {
            crate::audit::allow_list_changed(&changes_asked(arguments), invoker);
            ExitCode::SUCCESS
        }
        Err(error) => {
            errln!("omarchy-guardian sweep-allow-system: {error}");
            ExitCode::from(2)
        }
    }
}

/// Runs the root collector through sudo, which asks for the password on
/// the terminal, and reads what it found.
pub fn from_root() -> Result<RootPart, String> {
    // Always the installed, root-owned Guardian: running the current
    // executable would let a user-writable build run as root.
    let program = installed()?;
    errln!(
        "Guardian needs root to check what your user can't read (sudoers, root's crontab, shell files and keys). It only reads them."
    );
    let mut child = Command::new(SUDO)
        .arg(program)
        .arg("sweep-collect")
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot start sudo: {error}"))?;
    let mut output = String::new();
    let read = child
        .stdout
        .take()
        .ok_or("no output")?
        .take(MAX_OUTPUT)
        .read_to_string(&mut output);
    let status = child.wait().map_err(|error| error.to_string())?;
    read.map_err(|error| error.to_string())?;
    if !status.success() {
        return Err(format!("the root collector exited with {status}"));
    }
    from_json(&output)
}

/// Replaces what the user's sweep could not judge on the system side with
/// what root found: the user's home items and trusted system items stay.
pub fn merge(collection: &mut Collection, part: RootPart) {
    // Root's view only fills in what the user could not read: root's
    // results may be a day old, and what the user read now is newer.
    collection.items.retain(|item| {
        item.origin == Origin::User
            || !item.alerts.is_empty()
            || !matches!(item.body, Body::Unreadable(_))
    });
    collect::merge(collection, part.items);
    collection.truncated.extend(part.truncated);
    collection.root_news = part.news;
}

#[cfg(test)]
mod tests {
    #[test]
    fn more_accounts_than_are_looked_at_is_said() {
        use super::{MAX_ACCOUNTS, accounts_left_out};
        let passwd = |count: usize| {
            let mut lines = vec![
                "root:x:0:0::/root:/bin/bash".to_string(),
                "svc:x:900:900::/srv/svc:/bin/sh".to_string(),
            ];
            lines.extend((0..count).map(|number| {
                let uid = 1000 + number;
                format!("u{number}:x:{uid}:{uid}::/home/u{number}:/bin/bash")
            }));
            let text = lines.join("\n");
            crate::sweep::access::accounts(&text)
        };
        // Root and an account whose home is elsewhere are not counted.
        assert_eq!(accounts_left_out(&passwd(MAX_ACCOUNTS)), None);
        assert_eq!(
            accounts_left_out(&passwd(MAX_ACCOUNTS + 2)).as_deref(),
            Some(
                "more than 200 accounts with a home under /home: the keys of 2 were not looked at"
            )
        );
    }

    #[test]
    fn other_accounts_crontabs_are_withheld() {
        use super::{accounts_in_group, withhold_others_jobs};
        let passwd = "root:x:0:0::/root:/bin/bash\nu:x:1000:1000::/home/u:/bin/bash\nv:x:1001:1001::/home/v:/bin/bash\n";
        let group = "wheel:x:998:u\nu:x:1000:\nshared:x:2000:v,u\n";
        assert_eq!(accounts_in_group(1000, passwd, group), ["u"]);
        assert_eq!(accounts_in_group(2000, passwd, group), ["u", "v"]);
        let crontab = |account: &str| {
            let mut item = item(
                &format!("var/spool/cron/{account}"),
                Origin::Root,
                Tier::Unknown,
                Body::Text("* * * * * /x\n".into()),
            );
            item.runs = vec!["/x".into()];
            item
        };
        let mut items = vec![crontab("root"), crontab("u"), crontab("v")];
        let mut followed = item(
            "home/v/bin/job",
            Origin::Root,
            Tier::Unknown,
            Body::Text("#!/bin/sh\n".into()),
        );
        followed.run_by = Some("var/spool/cron/v".into());
        items.push(followed);
        // `at` jobs are told apart by who owns the file.
        let jobs = [
            "var/spool/atd/a0001",
            "var/spool/atd/a0002",
            "var/spool/atd/a0003",
            "var/spool/atd/a0004",
            // The other spools `at` is built with.
            "var/spool/at/a0002",
            "var/spool/at/a0003",
            "var/spool/cron/atjobs/a0002",
            "var/spool/cron/atjobs/a0003",
        ];
        for job in jobs {
            items.push(item(
                job,
                Origin::Root,
                Tier::Unknown,
                Body::Binary(crate::sweep::collect::WITHHELD),
            ));
        }
        let owner = |job: &str| match job.rsplit('/').next() {
            Some("a0001") => Some("root".to_string()),
            Some("a0002") => Some("u".to_string()),
            Some("a0003") => Some("v".to_string()),
            _ => None,
        };
        assert_eq!(
            withhold_others_jobs(&mut items, &["u".to_string()], &owner),
            5
        );
        let paths: Vec<&str> = items.iter().map(|item| item.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "var/spool/cron/root",
                "var/spool/cron/u",
                "var/spool/atd/a0001",
                "var/spool/atd/a0002",
                "var/spool/at/a0002",
                "var/spool/cron/atjobs/a0002"
            ]
        );
    }

    #[test]
    fn the_list_of_allowed_items_keeps_a_home_for_the_user_who_asked() {
        use super::change_allowed;
        let arguments = |words: &[&str]| -> Vec<String> {
            words.iter().map(|word| (*word).to_string()).collect()
        };
        let mut allowed = crate::sweep::state::Remembered::new();
        change_allowed(
            &mut allowed,
            &arguments(&["--add", "/etc/x", "a", "--add", "~/.bashrc", "b"]),
            Some(1000),
        )
        .unwrap();
        change_allowed(
            &mut allowed,
            &arguments(&["--add", "~/.bashrc", "c"]),
            Some(1001),
        )
        .unwrap();
        assert_eq!(
            allowed.keys().collect::<Vec<_>>(),
            ["/etc/x", "1000:~/.bashrc", "1001:~/.bashrc"]
        );
        // Root has no home of a user to speak for, and nothing else is a
        // label.
        for (words, invoker) in [
            (&["--add", "~/.bashrc", "b"][..], None),
            (&["--add", "1000:~/.bashrc", "b"][..], Some(1000)),
            (&["--add", "relative", "b"][..], Some(1000)),
            (&["--add", "/etc/x\n/etc/y", "b"][..], Some(1000)),
            (&["--add", "/etc/x", ""][..], Some(1000)),
            (&["--add", "/etc/x"][..], Some(1000)),
            (&["--allow-everything"][..], Some(1000)),
            (&[][..], Some(1000)),
        ] {
            let mut copy = allowed.clone();
            assert!(
                change_allowed(&mut copy, &arguments(words), invoker).is_err(),
                "{words:?}"
            );
        }
        // One user's forget leaves the other's home alone.
        change_allowed(
            &mut allowed,
            &arguments(&["--remove", "~/.bashrc"]),
            Some(1001),
        )
        .unwrap();
        assert_eq!(
            allowed.keys().collect::<Vec<_>>(),
            ["/etc/x", "1000:~/.bashrc"]
        );
        change_allowed(&mut allowed, &arguments(&["--clear"]), Some(1001)).unwrap();
        assert_eq!(allowed.keys().collect::<Vec<_>>(), ["1000:~/.bashrc"]);
    }

    /// Gives `path` and everything below it to `nobody`, where root can.
    fn give_tree(path: &std::path::Path) {
        if path.is_dir() && !path.is_symlink() {
            for entry in std::fs::read_dir(path).unwrap().flatten() {
                give_tree(&entry.path());
            }
        }
        crate::test_support::give(path, crate::test_support::NOBODY);
    }

    #[test]
    fn root_reports_on_each_home_as_its_account_could_look_itself() {
        use std::os::unix::fs::MetadataExt;
        let dir = crate::test_support::TempDir::new("root-accounts");
        let root = dir.path();
        let uid = std::fs::metadata(root).unwrap().uid();
        let write = |path: &str, text: &str| {
            std::fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
            std::fs::write(root.join(path), text).unwrap();
        };
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGuardianTestKeyMaterial0123456789abcdefghi";
        write("home/u/.ssh/authorized_keys", &format!("{key} u@laptop\n"));
        write(
            "home/v/.ssh/authorized_keys",
            &format!("{key} v@laptop\n{key} v@other\n"),
        );
        write(
            "home/u/.config/systemd/user/omarchy-guardian-sweep.service.d/x.conf",
            "[Service]\nEnvironment=HOME=/tmp/x\n",
        );
        write(
            "home/v/.config/systemd/user/omarchy-guardian-sweep.service.d/x.conf",
            "[Service]\nEnvironment=HOME=/tmp/x\n",
        );
        // A key file that is a link to a file the account may read (kept
        // in a dotfiles directory) is its key file all the same; one that
        // leads to a file it could not read (a file of root's, say) shows
        // nothing.
        write("home/w/.ssh/real", &format!("{key} w\n"));
        std::os::unix::fs::symlink("real", root.join("home/w/.ssh/authorized_keys")).unwrap();
        write("home/x/.ssh/closed", &format!("{key} x\n"));
        std::os::unix::fs::symlink("closed", root.join("home/x/.ssh/authorized_keys")).unwrap();
        std::fs::set_permissions(
            root.join("home/x/.ssh/closed"),
            std::os::unix::fs::PermissionsExt::from_mode(0o000),
        )
        .unwrap();
        // Run as root, the homes are root's, and an account with user id 0
        // is root, whose home is not looked at this way: the accounts are
        // `nobody`'s then, and so are their homes where root can give them
        // away (else they are read by what their modes show everyone).
        let uid = if uid == 0 {
            for home in ["home/u", "home/v", "home/w", "home/x"] {
                give_tree(&root.join(home));
            }
            crate::test_support::NOBODY
        } else {
            uid
        };
        let passwd = format!(
            "root:x:0:0::/root:/bin/bash\nu:x:{uid}:{uid}::/home/u:/bin/bash\nv:x:{uid}:{uid}::/home/v:/bin/bash\nw:x:{uid}:{uid}::/home/w:/bin/bash\nx:x:{uid}:{uid}::/home/x:/bin/bash\nsvc:x:{uid}:{uid}::/srv/svc:/bin/bash\n"
        );
        let index =
            crate::sweep::index::PackageIndex::with_foreign(std::collections::HashSet::new());
        let scope = crate::sweep::collect::Scope {
            root,
            home: Some("root"),
            index: &index,
            origin: Origin::Root,
        };
        let items = super::of_accounts(
            &scope,
            &crate::sweep::access::accounts(&passwd),
            &["u".to_string()],
        );
        let paths: Vec<&str> = items.iter().map(|item| item.path.as_str()).collect();
        assert_eq!(paths.len(), 4, "{paths:?}");
        // The reader's own: the override of Guardian's unit, and each key.
        assert_eq!(
            paths[0],
            "home/u/.config/systemd/user/omarchy-guardian-sweep.service.d/x.conf"
        );
        assert_eq!(items[0].alerts[0].0, crate::rules::RuleId::GuardianOverride);
        assert!(paths[1].starts_with("home/u/.ssh/authorized_keys#"));
        // Another account's: how many keys, and nothing of its units.
        assert_eq!(paths[2], "home/v/.ssh/authorized_keys#keys");
        assert!(items[2].notes[0].starts_with("2 key(s) may log in as v"));
        assert!(!format!("{items:?}").contains("v@laptop"));
        assert_eq!(paths[3], "home/w/.ssh/authorized_keys#keys");
        assert!(items[3].notes[0].starts_with("1 key(s) may log in as w"));
    }

    use super::{from_json, merge, to_json};
    use crate::autorun::Category;
    use crate::sha256::Sha256;
    use crate::sweep::collect::{Body, Collection, Item, Origin};
    use crate::sweep::tier::Tier;

    fn item(path: &str, origin: Origin, tier: Tier, body: Body) -> Item {
        Item {
            origin,
            category: Category::Sudo,
            path: path.into(),
            tier,
            sha256: Some(Sha256::digest(path.as_bytes())),
            body,
            runs: vec!["/usr/bin/x".into()],
            run_by: Some("etc/y".into()),
            notes: vec!["a note".into()],
            alerts: Vec::new(),
        }
    }

    #[test]
    fn items_round_trip_and_trusted_ones_stay_behind() {
        let collection = Collection {
            items: vec![
                item(
                    "etc/sudoers.d/evil",
                    Origin::Root,
                    Tier::Unknown,
                    Body::Text("ALL ALL=(ALL) NOPASSWD: ALL\n".into()),
                ),
                item(
                    "usr/bin/x",
                    Origin::Root,
                    Tier::Modified,
                    Body::Binary("ELF executable"),
                ),
                item(
                    "etc/sudoers",
                    Origin::Root,
                    Tier::Vendor,
                    Body::Text("trusted".into()),
                ),
            ],
            truncated: vec!["/etc/x".into()],
            notes: Vec::new(),
            root_news: None,
        };
        let mut collection = collection;
        // The drop-in is in the catalog itself: its content travels.
        collection.items[0].run_by = None;
        collection.items[1]
            .alerts
            .push((crate::rules::RuleId::HiddenProgram, "seen".into()));
        let noted = vec!["the kernel is tainted (flags 4096)".to_string()];
        let part = from_json(&to_json(&collection, &noted, None).to_string()).unwrap();
        assert_eq!(part.notes, noted);
        assert_eq!(part.items, collection.items[..2]);
        assert_eq!(part.truncated, ["/etc/x"]);
    }

    #[test]
    fn facts_that_are_no_files_travel_like_any_item() {
        // An account, a member, a key: named with a `#`, kept as text.
        let mut fact = item(
            "etc/passwd#toor",
            Origin::Root,
            Tier::Unknown,
            Body::Text("account toor uid 0 shell /bin/bash".into()),
        );
        fact.category = Category::Account;
        fact.run_by = None;
        fact.alerts.push((
            crate::rules::RuleId::PrivilegedAccount,
            "toor has user id 0".into(),
        ));
        let collection = Collection {
            items: vec![fact],
            ..Collection::default()
        };
        let part = from_json(&to_json(&collection, &[], None).to_string()).unwrap();
        assert_eq!(part.items, collection.items);
    }

    #[test]
    fn only_a_private_group_may_read_roots_results() {
        let passwd = "root:x:0:0::/root:/bin/bash\nu:x:1000:1000::/home/u:/bin/bash\nv:x:1001:100::/home/v:/bin/bash\nw:x:1002:100::/home/w:/bin/bash\n";
        let group = "root:x:0:\nu:x:1000:\nusers:x:100:\nwheel:x:998:u\n";
        assert_eq!(
            super::private_group(1000, group, passwd).as_deref(),
            Some("u")
        );
        assert_eq!(super::private_group(100, group, passwd), None);
        assert_eq!(super::private_group(998, group, passwd), None);
    }

    #[test]
    fn malformed_or_foreign_output_is_refused() {
        assert!(from_json("not json").is_err());
        assert!(from_json(r#"{"version":3,"items":[]}"#).is_err());
        assert!(from_json(r#"{"items":[]}"#).is_err());
        // An older collector's results are read, and known as that.
        assert!(from_json(r#"{"version":1,"items":[]}"#).unwrap().outdated);
        let current =
            from_json(r#"{"version":2,"items":[],"new_trust":["etc/passwd#x"]}"#).unwrap();
        assert!(!current.outdated);
        assert_eq!(current.news, Some(vec!["etc/passwd#x".to_string()]));
        assert_eq!(from_json(r#"{"version":2,"items":[]}"#).unwrap().news, None);
        let escaping = r#"{"version":1,"items":[{"path":"../etc/x","category":"sudo","tier":"unknown","body":{"kind":"undecodable"},"runs":[],"notes":[],"alerts":[]}]}"#;
        // A bad item is left out; the rest of root's results still count.
        assert!(from_json(escaping).unwrap().items.is_empty());
    }

    #[test]
    fn what_root_reached_by_following_keeps_only_its_hash() {
        use crate::sweep::collect::{WITHHELD, item as collect_item};
        let dir = crate::test_support::TempDir::new("root-withheld");
        let root = dir.path();
        std::fs::create_dir_all(root.join("var/spool/cron")).unwrap();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/shadow"), "root:$6$hash:\n").unwrap();
        std::fs::write(root.join("var/spool/cron/u"), "* * * * * /etc/shadow\n").unwrap();
        let index =
            crate::sweep::index::PackageIndex::with_foreign(std::collections::HashSet::new());
        let scope = crate::sweep::collect::Scope {
            root,
            home: Some("root"),
            index: &index,
            origin: Origin::Root,
        };
        // A crontab line names it: followed, so its content stays home,
        // whoever may read it, and nothing is followed from it.
        let followed = collect_item(
            &scope,
            Category::Cron,
            "etc/shadow".into(),
            Some("var/spool/cron/u"),
        );
        assert_eq!(followed.body, Body::Binary(WITHHELD));
        assert!(followed.runs.is_empty());
        // The crontab itself is an auto-run file: its content travels.
        let direct = collect_item(&scope, Category::Cron, "var/spool/cron/u".into(), None);
        assert!(matches!(direct.body, Body::Text(_)));
        assert_eq!(direct.runs, ["/etc/shadow"]);
    }

    #[test]
    fn root_findings_replace_what_the_user_could_not_judge() {
        let mut collection = Collection {
            items: vec![
                item(
                    "etc/sudoers",
                    Origin::System,
                    Tier::Unknown,
                    Body::Unreadable("denied".into()),
                ),
                item(
                    "etc/pam.d/x",
                    Origin::System,
                    Tier::Vendor,
                    Body::Text(String::new()),
                ),
                item(
                    "home/u/.bashrc",
                    Origin::User,
                    Tier::Unknown,
                    Body::Text(String::new()),
                ),
            ],
            ..Collection::default()
        };
        // The user's own live alert (a program in memory) stays.
        let mut memory = item(
            "memfd:payload",
            Origin::System,
            Tier::Unknown,
            Body::Unreadable("runs only in memory".into()),
        );
        memory
            .alerts
            .push((crate::rules::RuleId::HiddenProgram, "seen".into()));
        collection.items.push(memory);
        let root = item(
            "etc/sudoers.d/evil",
            Origin::Root,
            Tier::Unknown,
            Body::Text(String::new()),
        );
        merge(
            &mut collection,
            super::RootPart {
                items: vec![root],
                ..super::RootPart::default()
            },
        );
        let paths: Vec<&str> = collection
            .items
            .iter()
            .map(|item| item.path.as_str())
            .collect();
        assert_eq!(
            paths,
            [
                "etc/pam.d/x",
                "etc/sudoers.d/evil",
                "home/u/.bashrc",
                "memfd:payload"
            ]
        );
    }

    #[test]
    fn an_accounts_flood_of_items_leaves_roots_and_the_systems_in() {
        // More lines in a home than the results hold: sorted by path they
        // would come before `root/`, `usr/` and `var/`.
        let mut items: Vec<Item> = (0..super::MAX_ITEMS + 10)
            .map(|index| {
                let mut key = item(
                    &format!("home/u/.ssh/authorized_keys#{index:06}"),
                    Origin::Root,
                    Tier::Unknown,
                    Body::Text("junk".into()),
                );
                key.category = Category::Account;
                key.run_by = None;
                key
            })
            .collect();
        let mut followed = item(
            "opt/x/run",
            Origin::Root,
            Tier::Unknown,
            Body::Text("x".into()),
        );
        followed.run_by = Some("home/u/.bashrc".into());
        items.push(followed);
        for path in ["root/.ssh/authorized_keys#aa", "var/spool/cron/root"] {
            let mut own = item(path, Origin::Root, Tier::Unknown, Body::Text("x".into()));
            own.category = Category::Account;
            own.run_by = None;
            items.push(own);
        }
        let collection = Collection {
            items,
            ..Collection::default()
        };
        let part = from_json(&to_json(&collection, &[], None).to_string()).unwrap();
        assert_eq!(part.items.len(), super::MAX_ITEMS);
        assert_eq!(part.items[0].path, "root/.ssh/authorized_keys#aa");
        assert_eq!(part.items[1].path, "var/spool/cron/root");
        assert!(
            part.items[2..]
                .iter()
                .all(|item| item.path.starts_with("home/u/"))
        );
        assert!(
            part.truncated[0].ends_with("13 were left out"),
            "{:?}",
            part.truncated
        );
        // The collector's record keeps the same order.
        let (_, seen) = super::news(&collection.items, None, 1);
        assert!(seen.contains_key("root/.ssh/authorized_keys#aa"));
    }

    #[test]
    fn the_collector_tells_what_is_new_from_its_own_record() {
        use crate::autorun::Category;
        let key = |name: &str, text: &str| {
            let mut key = item(
                &format!("root/.ssh/authorized_keys#{name}"),
                Origin::Root,
                Tier::Unknown,
                Body::Text(text.into()),
            );
            key.category = Category::Account;
            key.sha256 = Some(Sha256::digest(text.as_bytes()));
            key
        };
        let unit = item(
            "etc/systemd/system/x.service",
            Origin::Root,
            Tier::Unknown,
            Body::Text("[Service]".into()),
        );
        let hour = 60 * 60;
        // The first look remembers everything and has no list of what is
        // new: the sweep that reads the results goes by its own memory.
        let (new, seen) = super::news(&[key("a", "one"), unit.clone()], None, 1000);
        assert_eq!(new, None);
        assert_eq!(
            seen.keys().collect::<Vec<_>>(),
            ["root/.ssh/authorized_keys#a"]
        );
        // A key that was not there, and one that changed, are new, and stay
        // so for two days, whatever the sweeps that read the results
        // remember.
        let items = [key("a", "other"), key("b", "two"), unit];
        let news = |items: &[Item], seen, now| {
            let (new, seen) = super::news(items, Some(seen), now);
            (new.unwrap(), seen)
        };
        let (new, seen) = news(&items, seen, 2000);
        assert_eq!(
            new,
            ["root/.ssh/authorized_keys#a", "root/.ssh/authorized_keys#b"]
        );
        let (new, seen) = news(&items, seen, 2000 + 47 * hour);
        assert_eq!(new.len(), 2);
        let (new, seen) = news(&items, seen, 2000 + 49 * hour);
        assert!(new.is_empty());
        // One that went and came back is new again.
        let (_, seen) = news(&items[..1], seen, 2000 + 50 * hour);
        let (new, seen) = news(&items, seen, 2000 + 51 * hour);
        assert_eq!(new, ["root/.ssh/authorized_keys#b"]);
        // The record is written and read back as it is; the results carry
        // the list only where a record was kept.
        let text = super::trust_seen_json(&seen);
        assert!(text.contains("\"first\":"));
        let collection = Collection {
            items: items.to_vec(),
            ..Collection::default()
        };
        let part = from_json(&to_json(&collection, &[], Some(&new)).to_string()).unwrap();
        assert_eq!(part.news, Some(new));
        // Without a record the results carry none, and the reader's own
        // memory stands in.
        let untracked = from_json(&to_json(&collection, &[], None).to_string()).unwrap();
        assert_eq!(untracked.news, None);
        let mut merged = Collection::default();
        merge(&mut merged, part);
        assert_eq!(
            merged.root_news,
            Some(vec!["root/.ssh/authorized_keys#b".to_string()])
        );
    }
}
