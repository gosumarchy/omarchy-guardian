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

pub(super) use allow::system_allow;
pub(crate) use allow::{as_root, system_allow_command};
pub(crate) use results::{from_results, results_problem};

use std::collections::{BTreeMap, HashMap, HashSet};
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
use crate::autorun::Category;
use crate::error::{Error, IoContext};
use crate::json::Json;
use crate::report::FAILED;
use crate::rules::RuleId;
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
pub(crate) struct RootPart {
    pub(crate) items: Vec<Item>,
    pub(crate) truncated: Vec<String>,
    /// What the live checks say of the system as a whole (a tainted
    /// kernel, modules no package installed).
    pub(crate) notes: Vec<String>,
    /// The directories the collector listed for the auto-run patterns
    /// (see `Collection::listed`).
    pub(crate) listed: Vec<String>,
    /// Written by an older collector, which did not run every check this
    /// one does: what the user's own sweep leaves to the root checks is not
    /// covered by these results.
    pub(crate) outdated: bool,
    /// The paths of the accounts, members, keys and trust anchors that are
    /// new to the collector, when it kept track (see `news`).
    pub(crate) news: Option<Vec<String>>,
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
type TrustSeen = BTreeMap<String, (String, u64)>;

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

/// Root's own crontab, the one entry of a spool that only root writes.
/// It is told by its name: accounts write `/var/spool/cron` only through
/// `crontab`, which names each file after the account that runs it, so no
/// account can put a file called `root` there.
const ROOT_CRONTAB: &str = "var/spool/cron/root";

/// Whether `path` is where an account keeps what it likes: its home, its
/// runtime directory, or a spool it hands its jobs to (a crontab named
/// after it). Whose an `at` job is its file's owner says, not its name
/// (see `made_by_accounts`).
fn in_an_accounts_place(path: &str) -> bool {
    account_of(path).is_some()
        || (path.starts_with("var/spool/") && !collect::is_at_job(path) && path != ROOT_CRONTAB)
}

/// Whether `item` is one an account keeps under `/home` or in its runtime
/// directory `/run/user/<uid>`, or was reached from one: that account
/// decides how many of those there are. `/run/user/0` is root's own.
fn of_an_account(item: &Item) -> bool {
    let kept = |path: &str| {
        path.starts_with("home/")
            || path
                .strip_prefix("run/user/")
                .is_some_and(|rest| !rest.starts_with("0/"))
    };
    kept(&item.path) || item.run_by.as_deref().is_some_and(kept)
}

/// The paths of items an account made, beyond what their place shows (see
/// `in_an_accounts_place`): what the live checks found only
/// through what an account chose (`live`) and the collection does not hold
/// by itself, and the `at` jobs whose file `uid_of` says is not root's.
/// What the collection holds as well is root's finding, so it keeps its
/// alert and its rank.
fn made_by_accounts(
    collection: &Collection,
    live: HashSet<String>,
    uid_of: &dyn Fn(&str) -> Option<u32>,
) -> HashSet<String> {
    let collected: HashSet<&str> = collection
        .items
        .iter()
        .map(|item| item.path.as_str())
        .collect();
    let mut made: HashSet<String> = live
        .into_iter()
        .filter(|name| !collected.contains(name.as_str()))
        .collect();
    made.extend(
        collection
            .items
            .iter()
            .filter(|item| collect::is_at_job(&item.path) && uid_of(&item.path) != Some(0))
            .map(|item| item.path.clone()),
    );
    made
}

/// The paths of the items in `collection` that are root's: those root
/// found by itself, those the live checks found through root's own
/// (`live_roots`, even in an account's place: root runs it there), and
/// those such an item leads to, through any of the
/// ways that lead there (`run_by` and `Collection::runners`). An item an
/// account made (in its place, or in `made`) is not one root found by
/// itself, and leads nowhere that is root's: from its crontab or its
/// `~/.bashrc` an account names as many files as it likes, wherever they
/// are. Reached from root's, it is root's none the less: root runs it.
fn roots_own<'a>(
    collection: &'a Collection,
    made: &HashSet<String>,
    live_roots: &HashSet<String>,
) -> HashSet<&'a str> {
    let by_an_account = |item: &Item| {
        in_an_accounts_place(&item.path)
            || item.file.as_deref().is_some_and(in_an_accounts_place)
            || made.contains(&item.path)
    };
    let mut leads_to: HashMap<&str, Vec<&Item>> = HashMap::new();
    for item in &collection.items {
        let runners = collection.runners.get(&item.path).into_iter().flatten();
        for lead in item.run_by.iter().chain(runners) {
            leads_to.entry(lead.as_str()).or_default().push(item);
        }
    }
    let mut pending: Vec<&Item> = collection
        .items
        .iter()
        .filter(|item| {
            live_roots.contains(&item.path) || (item.run_by.is_none() && !by_an_account(item))
        })
        .collect();
    let mut roots: HashSet<&str> = pending.iter().map(|item| item.path.as_str()).collect();
    while let Some(item) = pending.pop() {
        if by_an_account(item) {
            continue;
        }
        for &target in leads_to.get(item.path.as_str()).into_iter().flatten() {
            if roots.insert(&target.path) {
                pending.push(target);
            }
        }
    }
    roots
}

/// The most items standing in for the sweep's own units that are kept
/// first for one home or one runtime directory (so twice that for an
/// account with both). The bar needs one to say the sweep is turned off;
/// an account can make hundreds (64 drop-ins in each of a dozen
/// directories), which ahead of root's own would crowd those out.
const MAX_OVERRIDES_OF_AN_ACCOUNT: usize = 16;

/// The home or runtime directory `path` is in (`home/alice`,
/// `run/user/1000`), if any.
fn account_of(path: &str) -> Option<&str> {
    // Only root can write `/run/user/0`, so it is root's, not an account's.
    if path.starts_with("run/user/0/") {
        return None;
    }
    ["home/", "run/user/"].into_iter().find_map(|place| {
        let rest = path.strip_prefix(place)?;
        let end = place.len() + rest.find('/').unwrap_or(rest.len());
        Some(&path[..end])
    })
}

/// The items of `collection` no package vouches for, in the order they
/// are kept where there is room for only so many: those that stand in for
/// one of the sweep's own units first (the bar reads them from these
/// results; at most `MAX_OVERRIDES_OF_AN_ACCOUNT` of one home or runtime
/// directory), then root's (`roots_own`), and what the accounts made after
/// them (see `made_by_accounts` for `made`, `roots_own` for
/// `live_roots`). Each account
/// decides how many of its own there are: thousands of them crowd out the
/// accounts' items, and never root's keys, a unit in `/etc` or a root
/// process.
fn in_keeping_order<'a>(
    collection: &'a Collection,
    made: &HashSet<String>,
    live_roots: &HashSet<String>,
) -> Kept<'a> {
    let roots = roots_own(collection, made, live_roots);
    let mut overrides_of: HashMap<&str, usize> = HashMap::new();
    let mut kept: Vec<(u8, &Item)> = collection
        .items
        .iter()
        .filter(|item| !item.is_trusted())
        .map(|item| {
            let overrides = item
                .alerts
                .iter()
                .any(|(rule, _)| *rule == RuleId::GuardianOverride)
                && account_of(&item.path).is_none_or(|account| {
                    let count = overrides_of.entry(account).or_default();
                    *count += 1;
                    *count <= MAX_OVERRIDES_OF_AN_ACCOUNT
                });
            let rank = match (overrides, roots.contains(item.path.as_str())) {
                (true, _) => 0,
                (false, true) => 1,
                (false, false) => 2,
            };
            (rank, item)
        })
        .collect();
    // Stable, so each group keeps the collection's order.
    kept.sort_by_key(|(rank, _)| *rank);
    Kept {
        items: kept.into_iter().map(|(_, item)| item).collect(),
        roots,
    }
}

/// The untrusted items in the order they are kept (`in_keeping_order`),
/// and the paths of those that are root's (`roots_own`).
#[derive(Debug)]
struct Kept<'a> {
    items: Vec<&'a Item>,
    roots: HashSet<&'a str>,
}

/// The most items of one kind (processes, listeners, set-id files, …) that
/// accounts made which the live checks hand to root's results. Any account
/// chooses how many of those there are and what they are named (a process
/// per path in `/dev/shm`, a listener per port, a deleted or memfd program
/// under any name, a set-id file of its own). Those rank after root's
/// anyway; the cap keeps one kind an account floods from crowding out the
/// accounts' other kinds and their homes' items. Arbitrary, and well above
/// a desktop's few dozen of a kind. Root's own are all kept.
const MAX_LIVE_OF_A_KIND: usize = 200;

/// `items` from the live checks, with at most `MAX_LIVE_OF_A_KIND` of each
/// kind among those in `made` (the first by name; one account's may then
/// crowd out another's), and a sentence in `truncated` for each
/// kind that had more.
fn within_kind_limit(
    items: Vec<Item>,
    made: &HashSet<String>,
    truncated: &mut Vec<String>,
) -> Vec<Item> {
    let mut counts: BTreeMap<Category, usize> = BTreeMap::new();
    let mut kept = Vec::with_capacity(items.len());
    for item in items {
        if made.contains(&item.path) {
            let count = counts.entry(item.category).or_default();
            *count += 1;
            if *count > MAX_LIVE_OF_A_KIND {
                continue;
            }
        }
        kept.push(item);
    }
    for (category, count) in counts {
        if count > MAX_LIVE_OF_A_KIND {
            truncated.push(format!(
                "the live checks found {count} items in {} that accounts made: \
                 only the first {MAX_LIVE_OF_A_KIND} are in the results",
                category.label()
            ));
        }
    }
    kept
}

/// The paths among `kept` (the items in `in_keeping_order`) of the
/// accounts, group members, keys and trust anchors that are new to the
/// collector at `now`: not in `seen`, or there with other content, for
/// `NEW_FOR_SECS` from when that was first so.
/// `seen` is brought up to date. With none yet, everything is remembered
/// and the collector has nothing to say of what is new (`None`): the sweep
/// that reads the results then goes by what it remembers itself, rather
/// than hearing "nothing new" from a collector that could not know. What
/// is gone is forgotten, so that one put back is new again.
fn news(kept: &[&Item], seen: Option<TrustSeen>, now: u64) -> (Option<Vec<String>>, TrustSeen) {
    let first_look = seen.is_none();
    let before = seen.unwrap_or_default();
    let mut after = TrustSeen::new();
    let mut new = Vec::new();
    for item in kept
        .iter()
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
pub(crate) const RESULTS: &str = "/var/lib/omarchy-guardian/sweep/root.json";

/// Where `sweep-collect` puts what it found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CollectTo {
    /// For `sweep --root`, which runs it through sudo.
    Stdout,
    /// `RESULTS`, for the daily system timer (`--out`).
    Results,
}

/// `omarchy-guardian sweep-collect [--out]`: run as root, by `sweep --root`
/// through sudo (printing to stdout), or by the daily system timer with
/// `--out` (writing `RESULTS`, only when the system configuration allows
/// it, readable by the configured group).
pub(crate) fn collect_command(to: CollectTo, settings: &crate::config::Settings) -> ExitCode {
    let out = to == CollectTo::Results;
    if !user::effective_uid().is_ok_and(|uid| uid == 0) {
        errln!(
            "omarchy-guardian sweep-collect: only `sweep --root` and its timer run this, as root"
        );
        return ExitCode::from(FAILED);
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
            return ExitCode::from(FAILED);
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
            return ExitCode::from(FAILED);
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
    let made = made_by_accounts(&collection, live.of_accounts, &owner_of);
    let items = within_kind_limit(live.items, &made, &mut collection.truncated);
    collect::merge(&mut collection, items);
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
    add_accounts_items(&mut collection, of_accounts(&scope, &accounts, &readers));
    collection.truncated.extend(accounts_left_out(&accounts));
    let withheld = withhold_others_jobs(&mut collection.items, &readers, &|job| {
        let uid = owner_of(job)?;
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
    let kept = in_keeping_order(&collection, &made, &live.of_root);
    let (new, seen) = news(&kept.items, seen, now);
    let json = to_json(&collection, &kept, &notes, new.as_deref()).to_string();
    match group {
        // Written as it is, for the sweep that asked to parse: a path
        // with a hidden character must stay the path it is.
        None => match writeln!(std::io::stdout(), "{json}") {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(FAILED),
        },
        Some(gid) => match write_results(Path::new(RESULTS), &json, gid).and_then(|()| {
            state::write_text_mode(Path::new(TRUST_SEEN), &trust_seen_json(&seen), 0o600)
        }) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                errln!("omarchy-guardian sweep-collect: {error}");
                ExitCode::from(FAILED)
            }
        },
    }
}

/// The name of this process's primary group, from `/proc/self/status` and
/// `/etc/group`.
pub(crate) fn primary_group() -> Option<String> {
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
/// looked at as that account could look itself (links followed only as far
/// as it may see, nothing read that it could not read): for the accounts the results go to
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

/// Adds `items` to `collection`: the overrides of Guardian's units that
/// `own::of_account` found as `add_overrides` adds them, and every other
/// item merged by path.
fn add_accounts_items(collection: &mut Collection, items: Vec<Item>) {
    let (overrides, others): (Vec<Item>, Vec<Item>) =
        items.into_iter().partition(is_accounts_override);
    add_overrides(collection, overrides);
    collect::merge(collection, others);
}

/// Whether `item` is an override of Guardian's units that root found in an
/// account's home or runtime directory (`own::of_account`). A file a unit
/// runs is `Systemd` too, but it was reached from its runner, so it has a
/// `run_by`; it merges by path, as the user's newer reading replaces it.
fn is_accounts_override(item: &Item) -> bool {
    item.category == Category::Systemd && item.run_by.is_none() && of_an_account(item)
}

/// Adds `overrides`, of Guardian's units in accounts' homes and runtime
/// directories (`/run/user/<uid>`, not root's), as `own::of_account` finds
/// them, to `collection`. Each folds into an item there with the same path and the
/// same reading (hash and body), which says the same, and is added beside
/// any other item at its path. Merging by path alone would lose one: two
/// overrides can share a path (a drop-in whose name is not UTF-8, written
/// `\xNN`, beside one whose UTF-8 name reads the same), and the one not
/// read would fold into the other, so a decoy's hash would stand for both.
/// `own::of_account` gives no two overrides of one account the same path
/// and reading, so none is lost; what folds is the same file reported
/// twice (by the user's sweep and root's, or for two accounts that share
/// a home). The items are left unsorted: `add_accounts_items` merges after
/// this, which sorts.
fn add_overrides(collection: &mut Collection, overrides: Vec<Item>) {
    for item in overrides {
        let same = collection.items.iter_mut().find(|existing| {
            existing.path == item.path
                && existing.sha256 == item.sha256
                && existing.body == item.body
        });
        match same {
            Some(existing) => collect::fold(existing, item),
            None => collection.items.push(item),
        }
    }
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

/// Who owns the file at `path` (relative to `/`), not following a link.
fn owner_of(path: &str) -> Option<u32> {
    fs::symlink_metadata(Path::new("/").join(path))
        .ok()
        .map(|metadata| metadata.uid())
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
fn installed() -> Result<&'static Path, Error> {
    let program = Path::new(INSTALLED);
    let metadata = fs::metadata(program).map_err(|error| {
        Error::Message(format!(
            "{INSTALLED}: {error}; root's part needs the installed Guardian (./install.sh)"
        ))
    })?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(Error::Message(format!(
            "{INSTALLED} is not root's alone; root's part needs the installed Guardian (./install.sh)"
        )));
    }
    Ok(program)
}

/// Runs the root collector through sudo, which asks for the password on
/// the terminal, and reads what it found.
pub(super) fn from_root() -> Result<RootPart, Error> {
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
        .spawning("sudo")?;
    let mut output = String::new();
    let read = child
        .stdout
        .take()
        .ok_or_else(|| Error::Message("no output".into()))?
        .take(MAX_OUTPUT)
        .read_to_string(&mut output);
    let status = child.wait().spawning("sudo")?;
    read.map_err(|error| Error::ToolFailed {
        tool: "the root collector".into(),
        detail: format!("its output could not be read: {error}"),
    })?;
    if !status.success() {
        return Err(Error::Message(format!(
            "the root collector exited with {status}"
        )));
    }
    from_json(&output)
}

/// Replaces what the user's sweep could not judge on the system side with
/// what root found: the user's home items and trusted system items stay.
pub(super) fn merge(collection: &mut Collection, part: RootPart) {
    // Root's view only fills in what the user could not read: root's
    // results may be a day old, and what the user read now is newer. What
    // the user's live checks left unread for their limit is kept unless
    // root has it, alerts or not: root may never have seen it, and where
    // it has, root's read stands for the file.
    let from_root: HashSet<&str> = part.items.iter().map(|item| item.path.as_str()).collect();
    collection.items.retain(|item| match &item.body {
        Body::Unreadable(reason) if reason == live::NOT_READ_PAST_LIMIT => {
            !from_root.contains(item.path.as_str())
        }
        body => {
            item.origin == Origin::User
                || !item.alerts.is_empty()
                || !matches!(body, Body::Unreadable(_))
        }
    });
    // Root's walk is not carried over, only the first launcher each of its
    // items keeps: an extra edge only refuses more owner settings.
    for item in &part.items {
        if let Some(by) = &item.run_by {
            collection
                .runners
                .entry(item.path.clone())
                .or_default()
                .push(by.clone());
        }
    }
    add_accounts_items(collection, part.items);
    // A directory the user could not list is looked at when root listed
    // it: root looked there for every pattern match, and its results hold
    // each one no package vouches for. Root having run is not enough; it
    // may not have been able to list it either. The results name the
    // directory, not the pattern it was listed for: the collector runs the
    // same catalogue as this sweep, and only results written before an
    // update that added a pattern through a directory the user cannot list
    // could stand for a pattern root did not run. That lasts only until the
    // collector runs again (results are used for 36 hours at most), so the
    // pattern is not named as well.
    collection
        .unlisted
        .retain(|directory| !part.listed.contains(directory));
    collection.truncated.extend(part.truncated);
    collection.root_news = part.news;
}

#[cfg(test)]
mod tests;
