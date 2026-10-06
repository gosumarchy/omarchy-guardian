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

mod allow;
mod results;

pub use allow::{as_root, system_allow, system_allow_command};
pub use results::{from_results, results_problem};

use std::fs;
use std::io::{Read, Write as _};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

use super::access::{self, Account, Detail};
use super::collect::{self, Body, Collection, Item, Origin, Scope};
use super::index::{self, LOCAL_DB, PackageIndex};
use super::state;
use super::{live, own};
use crate::json::Json;
use crate::user;
use results::{from_json, to_json, write_results};

#[cfg(test)]
use allow::change_allowed;

const SUDO: &str = "/usr/bin/sudo";
const INSTALLED: &str = "/usr/bin/omarchy-guardian";
/// Root's home, relative to `/`.
const ROOT_HOME: &str = "root";
/// The most output and items taken from the root collector.
const MAX_OUTPUT: u64 = 64 * 1024 * 1024;
const MAX_ITEMS: usize = 5000;

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

/// `omarchy-guardian sweep-collect [--out]`: run as root, by `sweep --root`
/// through sudo (printing to stdout), or by the daily system timer with
/// `--out` (writing `RESULTS`, only when the system configuration allows
/// it, readable by the configured group).
pub fn collect_command(out: bool, settings: &crate::config::Settings) -> ExitCode {
    if !user::effective_uid().is_ok_and(|uid| uid == 0) {
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
    let now = crate::time::now();
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
mod tests;
