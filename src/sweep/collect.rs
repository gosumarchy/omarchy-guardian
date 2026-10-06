//! Collecting what runs on its own: every file in the auto-run catalog (the
//! system's, and the user's under their home), what links there point at,
//! and the programs and scripts the collected files run, each with its
//! trust tier and content.

mod follow;
mod item;
mod sight;

pub use item::{item, item_of};
pub use sight::{holds, is_file_there, is_there, look, packaged_item, packaged_out_of_sight};

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io;
use std::os::fd::AsRawFd as _;
use std::path::Path;

use super::index::PackageIndex;
use super::read::{self, View};
use super::tier::Tier;
use super::{access, boot, commands, own, path};
use crate::autorun::{Category, Kind, Location, SYSTEM, SYSTEM_SWEEP, USER};
use crate::paths::file_name;
use crate::rules::RuleId;
use crate::sha256::Digest;
use follow::follow;
use item::settings_alerts;

#[cfg(test)]
use sight::user_steered;

/// Command names a program in the home directory should never take over.
const WATCHED_NAMES: &[&str] = &[
    "sudo",
    "su",
    "doas",
    "run0",
    "pacman",
    "yay",
    "paru",
    "makepkg",
    "ssh",
    "scp",
    "git",
    "gpg",
    "passwd",
    "bash",
    "sh",
    "zsh",
    "systemctl",
    "omarchy-guardian",
];

/// Where Omarchy's installer lives; paths it mentions are noted as "likely
/// Omarchy" when no package owns them.
const OMARCHY_INSTALL: &[&str] = &["usr/share/omarchy/install", "usr/share/omarchy/migrations"];

/// Why root did not look at a path a user could have chosen.
pub const NOT_LOOKED_AT: &str =
    "only root can read it, and a user's file or process names it: not looked at";

/// The variables a locale file sets.
const LOCALE_VARIABLES: &[&str] = &["LANG", "LANGUAGE"];

/// The format label of a file root hashed but did not hand back.
pub const WITHHELD: &str = "root-only file (hashed, content withheld)";

/// The format label of a packaged file only root can read that a process
/// led the root collector to: compared with its package, and no more told.
pub const COMPARED: &str = "root-only packaged file (compared with its package, hash withheld)";

/// What is said of a packaged file that its package installs readable by
/// everyone and that no longer is.
pub const CLOSED: &str = "its package installs it readable by everyone, and it no longer is";

/// How a note starts that says a limit was reached while looking for what
/// an item runs. Such an item cannot be allowed (an allow would vouch for
/// commands nobody followed), and where its text is not reviewed either,
/// the sweep counts as incomplete.
pub const NOT_ALL_FOLLOWED: &str = "not all of what it runs was followed: ";

/// How the note starts on an item that is read as more of a catalogued
/// file's configuration and that nothing runs: where a link in an auto-run
/// location leads, and a file an SSH `Include` names, however many such
/// steps away. The catalogued file's path follows. A program one of those
/// files runs (a `ProxyCommand` script) does not carry it, and is reviewed
/// like any other program (see `judge::is_local_only`). An item keeps the
/// note only while every way the sweep reached it was as configuration:
/// `merge` takes it away from one that another check found running.
const CONFIGURATION_OF: &str = "read as configuration, not run, of /";

/// How the note starts on such an item that a link leads to: the link's
/// path follows, which is the name the file is read under (`~/.npmrc` for
/// the `~/dotfiles/npmrc` it points at).
const STANDS_FOR: &str = "stands for the link /";

/// The catalogued file `item` is read as more configuration of, relative
/// to the root, if it is (see `CONFIGURATION_OF`).
pub fn configuration_of(item: &Item) -> Option<&str> {
    item.notes
        .iter()
        .find_map(|note| note.strip_prefix(CONFIGURATION_OF))
}

/// The path whose name says what kind of file `item` is: its own, or for
/// configuration a link leads to, the link's.
pub fn stands_for(item: &Item) -> &str {
    configuration_of(item)
        .and_then(|_| {
            item.notes
                .iter()
                .find_map(|note| note.strip_prefix(STANDS_FOR))
        })
        .unwrap_or(&item.path)
}

/// Whether `item` is of a kind whose text is kept from the review for
/// what it is (see `judge::is_local_only`): configuration that holds
/// tokens, hosts and names.
fn is_kept_by_kind(item: &Item) -> bool {
    matches!(
        item.category,
        Category::Ssh | Category::Git | Category::Trust | Category::Toolchain | Category::Editor
    ) || (item.category == Category::Shell && item.path.ends_with("/fish_variables"))
}

/// The path the content of `item` was read from, relative to the root:
/// what a path says of a file (that it holds secrets, that it is a script)
/// is asked of this path, never of the name an item is listed under.
pub fn file_of(item: &Item) -> &str {
    item.file.as_deref().unwrap_or(&item.path)
}

/// The item of the file at `path`, listed under `name`: the path with
/// what a live check saw the file doing (`/usr/bin/node:tcp-3000`).
pub fn item_named(scope: &Scope<'_>, category: Category, name: &str, path: &str) -> Item {
    let mut item = item(scope, category, path.to_string(), None);
    if name != path {
        item.path = name.to_string();
        item.file = Some(path.to_string());
    }
    item
}

/// The note on an item that was reached only as a unit's
/// `EnvironmentFile=`: a list of variables systemd reads, which nothing
/// runs.
const ENVIRONMENT_ONLY: &str =
    "read by a unit as a list of variables (EnvironmentFile=), run by nothing";

/// Whether `item` was reached only as a unit's `EnvironmentFile=`.
pub fn is_environment_file(item: &Item) -> bool {
    item.notes.iter().any(|note| note == ENVIRONMENT_ONLY)
}

/// Whether `note` says how an item was reached: such a note holds only
/// while every way the sweep reached the item was that way.
fn is_configuration_note(note: &str) -> bool {
    note.starts_with(CONFIGURATION_OF) || note.starts_with(STANDS_FOR) || note == ENVIRONMENT_ONLY
}

/// Where `at` keeps its jobs: Arch's spool, the one other builds use, and
/// Debian's beside the crontabs.
const AT_SPOOLS: &[&str] = &["var/spool/atd/", "var/spool/at/", "var/spool/cron/atjobs/"];

/// Whether `path` is a queued `at` job. One starts with the whole
/// environment of whoever queued it, tokens and all, and is told apart by
/// who owns the file, not by its name.
pub fn is_at_job(path: &str) -> bool {
    AT_SPOOLS.iter().any(|spool| path.starts_with(spool))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Origin {
    /// The system, read as the user.
    System,
    /// The user's home directory.
    User,
    /// The system and root's home, read by the root collector.
    Root,
}

/// What an item holds, as far as the review is concerned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    Text(String),
    /// A recognised binary format: hashed, never read.
    Binary(&'static str),
    /// Binary data where text belongs; cannot be reviewed.
    Undecodable,
    /// Text larger than the review limit.
    Oversized,
    /// A link; its target is its own item when it needs judging.
    Link(String),
    /// Could not be read as this user.
    Unreadable(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub origin: Origin,
    pub category: Category,
    /// Relative to the root (`etc/udev/rules.d/x.rules`, `home/u/.bashrc`).
    pub path: String,
    pub tier: Tier,
    pub sha256: Option<Digest>,
    pub body: Body,
    /// The command lines it runs.
    pub runs: Vec<String>,
    /// The item that runs or links to this one.
    pub run_by: Option<String>,
    /// The path the content was read from, where `path` is not that: a
    /// live check lists a file under its path and what it saw it doing.
    pub file: Option<String>,
    pub notes: Vec<String>,
    /// What the live checks established about it (a rule and what was seen).
    pub alerts: Vec<(RuleId, String)>,
}

impl Item {
    /// Trusted items are only counted. An item the live checks raised an
    /// alert about is not trusted by its tier (a setuid copy of a packaged
    /// program is still a copy), only by the user allowing it.
    pub fn is_trusted(&self) -> bool {
        self.tier == Tier::Allowed
            || (super::judge::is_trusted(self.tier) && self.alerts.is_empty())
    }
}

#[derive(Debug, Default)]
pub struct Collection {
    pub items: Vec<Item>,
    /// What was not looked at, each as a sentence: a location with more
    /// entries than the limit, a name that cannot be read.
    pub truncated: Vec<String>,
    /// What is said of the system as a whole (Secure Boot is off).
    pub notes: Vec<String>,
    /// The paths of root's accounts, members, keys and trust anchors that
    /// the root collector says are new, when it kept track itself (see
    /// `root::news`); `None` when it did not.
    pub root_news: Option<Vec<String>>,
}

/// What a collection runs against.
pub struct Scope<'a> {
    pub root: &'a Path,
    /// The home directory relative to the root (`home/u`), if any.
    pub home: Option<&'a str>,
    pub index: &'a PackageIndex,
    pub origin: Origin,
}

/// Collects the system catalog and, with a home, the user catalog.
pub fn collect(scope: &Scope<'_>) -> Collection {
    let mut paths: BTreeMap<String, Category> = BTreeMap::new();
    let mut collection = Collection::default();
    for location in SYSTEM.iter().chain(SYSTEM_SWEEP) {
        add_location(scope, location, "", &mut paths, &mut collection.truncated);
    }
    if let Some(home) = scope.home {
        for location in USER {
            add_location(
                scope,
                location,
                &format!("{home}/"),
                &mut paths,
                &mut collection.truncated,
            );
        }
    }

    // Programs that take a system command's name, wherever a `PATH` puts
    // a directory someone can write ahead of `/usr/bin`.
    let search = path::search(scope);
    let (shadowing, unlisted) = path::shadowing_programs(scope, &search);
    for path in shadowing {
        paths.entry(path).or_insert(Category::LocalBin);
    }
    collection.truncated.extend(unlisted);
    // What stands in for Guardian's own units, in the unit directories the
    // catalog does not walk.
    for path in own::paths(scope) {
        paths.entry(path).or_insert(Category::Systemd);
    }

    let mut walk = Walk {
        seen: paths.keys().cloned().collect(),
        pending: paths
            .into_iter()
            .map(|(path, category)| (0, item(scope, category, path, None)))
            .collect(),
        ..Walk::default()
    };
    let omarchy = omarchy_paths(scope.root);
    while let Some((reading, mut item)) = walk.pending.pop() {
        // A script that was read again since this reading of it was
        // queued: the newer one stands.
        if walk.readings.get(&item.path).copied().unwrap_or(0) != reading {
            continue;
        }
        // Configuration itself: a catalogued file, or one reached as more
        // of one and run by nothing so far.
        let root = if item.run_by.is_none() {
            Some(item.path.clone())
        } else if walk.run.contains(&item.path) {
            None
        } else {
            walk.roots.get(&item.path).cloned()
        };
        let followed = follow(scope, &item, &search, root.is_some());
        for target in &followed.targets {
            walk.reach(scope, &item, &followed, root.as_deref(), target);
        }
        item.notes.extend(
            followed
                .unfollowed
                .into_iter()
                .map(|limit| format!("{NOT_ALL_FOLLOWED}{limit}")),
        );
        if item.tier == Tier::Unknown && omarchy.contains(&format!("/{}", item.path)) {
            item.notes.push("a path Omarchy's installer writes".into());
        }
        if item.tier == Tier::Unknown && sets_only_the_locale(&item) {
            item.tier = Tier::Inert;
            item.notes.push("sets the locale and nothing else".into());
        }
        walk.placed
            .insert(item.path.clone(), collection.items.len());
        collection.items.push(item);
    }
    // The readings a shorter way to a script took the place of.
    let mut index = 0;
    collection.items.retain(|_| {
        index += 1;
        !walk.replaced.contains(&(index - 1))
    });
    path::mark(scope, &search, &mut collection.items);
    mark_reach(&mut collection.items, &walk);
    for item in &mut collection.items {
        // The package's own directory, and the one for shared data, may
        // hold a drop-in a repository package ships for every unit;
        // nothing else there is spared.
        let shipped = item.tier == Tier::Vendor
            && ["usr/lib/systemd/", "usr/share/systemd/"]
                .iter()
                .any(|packaged| item.path.starts_with(packaged));
        if own::is_override(scope.home, &item.path) && !shipped {
            own::mark(item);
        }
    }
    collection
        .items
        .sort_by(|left, right| left.path.cmp(&right.path));
    add_facts(scope, &mut collection);
    collection
}

/// What following the collected items has reached so far.
#[derive(Default)]
struct Walk {
    /// Every path that is an item already.
    seen: HashSet<String>,
    /// The items whose own targets are still to be followed, each with
    /// which reading of its path it is (see `readings`).
    pending: Vec<(usize, Item)>,
    /// How often a path was read again from a shorter way to it: only its
    /// latest reading counts, wherever an older one still waits.
    readings: HashMap<String, usize>,
    /// Where in the collection the item of a path was put.
    placed: HashMap<String, usize>,
    /// The places of items a later reading of their path replaced.
    replaced: HashSet<usize>,
    /// What was reached as more configuration, with the catalogued file it
    /// belongs to.
    roots: HashMap<String, String>,
    /// What a link led to, with the link.
    linked: HashMap<String, String>,
    /// What some command runs: a file that is both configuration and run
    /// is a program.
    run: HashSet<String>,
    /// How many scripts deep each script that is looked through lies.
    depths: HashMap<String, usize>,
    /// What a unit reads as a list of variables, and what was reached in
    /// any other way.
    environment: HashSet<String>,
    otherwise: HashSet<String>,
}

impl Walk {
    /// Takes in `target`, which following `item` led to (`followed`);
    /// `root` is the catalogued file `item` is configuration of, if it is.
    fn reach(
        &mut self,
        scope: &Scope<'_>,
        item: &Item,
        followed: &Followed,
        root: Option<&str>,
        target: &String,
    ) {
        match root {
            Some(root) if followed.configuration.contains(target) => {
                self.roots
                    .entry(target.clone())
                    .or_insert_with(|| root.to_string());
            }
            _ => {
                self.run.insert(target.clone());
            }
        }
        if followed.environment.contains(target) {
            self.environment.insert(target.clone());
        } else {
            self.otherwise.insert(target.clone());
        }
        // A script lies one deeper than the script that starts it. One
        // already read from further down a chain is read again from here:
        // a long way to it must not stand for the short one.
        let depth = self.depths.get(&item.path).map_or(1, |depth| depth + 1);
        let fresh = self.seen.insert(target.clone());
        let shallower = !fresh && self.depths.get(target).is_some_and(|known| depth < *known);
        // An older reading is not searched for: one that still waits is
        // passed over when its turn comes, and one already collected is
        // taken out at the end. Each costs the same however many there are.
        if shallower {
            *self.readings.entry(target.clone()).or_insert(0) += 1;
            if let Some(place) = self.placed.remove(target) {
                self.replaced.insert(place);
            }
        }
        if !(fresh || shallower) {
            return;
        }
        let mut reached = self::item(scope, item.category, target.clone(), Some(&item.path));
        if matches!(item.body, Body::Link(_)) {
            read_as(scope, &mut reached, &item.path);
            self.linked.insert(target.clone(), item.path.clone());
        }
        let handed = followed.shell_scripts.contains(target);
        if (handed && read_as_script(&mut reached)) || is_read_script(&reached) {
            bound_scripts(depth, &mut reached, &mut self.depths);
        }
        let reading = self.readings.get(target).copied().unwrap_or(0);
        self.pending.push((reading, reached));
    }
}

/// Adds what is no file of an auto-run location: who may log in and
/// administer, and how the machine was started.
fn add_facts(scope: &Scope<'_>, collection: &mut Collection) {
    let (facts, left_out) = access::items(scope);
    merge(collection, facts);
    // Root has nothing behind it to cover what it left out; a user's
    // sweep says so in a note.
    if let Some(sentence) = left_out {
        if scope.origin == Origin::Root {
            collection.truncated.push(sentence);
        } else {
            collection.notes.push(sentence);
        }
    }
    let boot = boot::check(scope);
    merge(collection, boot.items);
    collection.truncated.extend(boot.unchecked);
    collection.notes.extend(boot.notes);
}

/// Puts on each item the notes that say how it was reached: as
/// configuration all the way from a catalogued file (see
/// `CONFIGURATION_OF`), through a link, or only as a unit's list of
/// variables.
fn mark_reach(items: &mut [Item], walk: &Walk) {
    let reached_by: HashMap<String, Option<String>> = items
        .iter()
        .map(|item| (item.path.clone(), item.run_by.clone()))
        .collect();
    for item in items {
        if item.run_by.is_some()
            && is_only_configuration(&item.path, &reached_by, &walk.roots, &walk.run)
            && let Some(root) = walk.roots.get(&item.path)
        {
            item.notes.push(format!("{CONFIGURATION_OF}{root}"));
            if let Some(link) = walk.linked.get(&item.path) {
                item.notes.push(format!("{STANDS_FOR}{link}"));
            }
        }
        if walk.environment.contains(&item.path) && !walk.otherwise.contains(&item.path) {
            item.notes.push(ENVIRONMENT_ONLY.to_string());
        }
    }
}

/// Keeps chains of scripts within `MAX_SCRIPT_DEPTH`: `reached`, a script
/// that lies `depth` scripts deep, is not looked through for what it starts
/// when that is deeper, and says so. The depth is remembered, so that the
/// script is read again should a shorter way lead to it.
fn bound_scripts(depth: usize, reached: &mut Item, depths: &mut HashMap<String, usize>) {
    depths.insert(reached.path.clone(), depth);
    if depth > MAX_SCRIPT_DEPTH && !reached.runs.is_empty() {
        reached.runs.clear();
        reached.notes.push(format!(
            "{NOT_ALL_FOLLOWED}a chain of more than {MAX_SCRIPT_DEPTH} scripts"
        ));
    }
}

/// Whether the item at `path` was reached as configuration all the way
/// from a catalogued file: nothing runs it, and the same holds for the item
/// that led to it, up to one the catalogue names.
fn is_only_configuration(
    path: &str,
    reached_by: &HashMap<String, Option<String>>,
    roots: &HashMap<String, String>,
    run: &HashSet<String>,
) -> bool {
    let mut current = path;
    // Chains are short; one that is not ends as not configuration.
    for _ in 0..32 {
        match reached_by.get(current) {
            Some(None) => return true,
            Some(Some(by)) if roots.contains_key(current) && !run.contains(current) => {
                current = by;
            }
            _ => return false,
        }
    }
    false
}

/// How many scripts deep a chain of scripts is looked through (a unit's
/// wrapper, what it starts, and what that starts): past it the next
/// script is reviewed as text, and says that what it runs was not followed.
const MAX_SCRIPT_DEPTH: usize = 3;

/// Whether the text file at `path` is a shell script that is looked
/// through for the programs it starts and the files it sources, the way a
/// shell start-up file is (those are of `Category::Shell`, and always
/// are): a shell script no repository package vouches for as it is, in a
/// location whose files run (a unit's wrapper, a cron script, an Omarchy
/// hook) or reached by following a command. A packaged script that is
/// intact is not: thousands of them start packaged programs, which tells
/// nothing. A file of a kind kept as configuration (a tool's settings, an
/// SSH file) is one only where something led to it, or where it is the
/// SSH server's login script, which is always read.
fn is_script_to_read(
    category: Category,
    path: &str,
    run_by: Option<&str>,
    tier: Tier,
    text: &str,
) -> bool {
    if commands::is_ssh_rc(path) {
        return true;
    }
    let configuration = matches!(
        category,
        Category::Ssh | Category::Git | Category::Trust | Category::Toolchain | Category::Editor
    );
    category != Category::Shell
        && matches!(
            tier,
            Tier::Unknown | Tier::UserBuilt | Tier::Edited | Tier::Modified
        )
        && (run_by.is_some() || !configuration)
        && commands::is_shell_script(path, text)
}

/// What the file at `path` is read as for the commands it runs: its own
/// category, or for a shell script no package vouches for a start-up
/// file's, whatever kind of location named it.
fn reader(
    category: Category,
    path: &str,
    run_by: Option<&str>,
    tier: Tier,
    body: &Body,
) -> Category {
    match body {
        Body::Text(text) if is_script_to_read(category, path, run_by, tier, text) => {
            Category::Shell
        }
        _ => category,
    }
}

/// The command lines the text file at `path` runs: what its own kind of
/// file runs, always, and where it is also read as a shell script
/// (`reader`), what a script of that text starts and sources as well. A
/// first line of `#!/bin/sh` is a comment to systemd, udev, cron and SSH:
/// it never takes the place of how the file is really read.
fn runs_of(category: Category, reader: Category, path: &str, text: &str) -> Vec<String> {
    let mut runs = commands::commands(category, path, text);
    if reader != category {
        for run in commands::commands(reader, path, text) {
            if !runs.contains(&run) {
                runs.push(run);
            }
        }
    }
    runs
}

/// Reads `item` as a shell script as well as what it is: a shell was
/// handed it as its script, which says so whatever its name and first
/// line. Only a file no package vouches for, as for any script. Returns
/// whether it is read that way.
fn read_as_script(item: &mut Item) -> bool {
    let unvouched = matches!(
        item.tier,
        Tier::Unknown | Tier::UserBuilt | Tier::Edited | Tier::Modified
    );
    let Body::Text(text) = &item.body else {
        return false;
    };
    if !unvouched || item.category == Category::Shell {
        return false;
    }
    item.runs = runs_of(item.category, Category::Shell, &item.path, text);
    true
}

/// `is_script_to_read` of an item.
fn is_read_script(item: &Item) -> bool {
    matches!(&item.body, Body::Text(text)
        if is_script_to_read(item.category, &item.path, item.run_by.as_deref(), item.tier, text))
}

/// Reads `item`, which the link at `link` leads to, as the file that link
/// stands for: what a file runs and what its settings say is told by its
/// name (`.npmrc`, `settings.json`), and a dotfile manager keeps the real
/// file under another one (`~/dotfiles/npmrc`).
fn read_as(scope: &Scope<'_>, item: &mut Item, link: &str) {
    let Body::Text(text) = &item.body else {
        return;
    };
    let reader = reader(item.category, link, None, item.tier, &item.body);
    item.runs = runs_of(item.category, reader, link, text);
    for alert in settings_alerts(scope, item.category, link, item.tier, &item.body) {
        if !item.alerts.contains(&alert) {
            item.alerts.push(alert);
        }
    }
}

/// Whether `item` is the system's or a home's `locale.conf`, which the
/// profile script of every login shell reads in, and holds nothing but the
/// locale: `LANG=`, `LANGUAGE=` and `LC_…=` with plain values. No package
/// owns the file (the installer writes it), and one that only says which
/// language to speak runs nothing. Any other line, or a value a shell
/// would expand, leaves it an item to look at.
fn sets_only_the_locale(item: &Item) -> bool {
    let named = item.path == "etc/locale.conf" || item.path.ends_with("/.config/locale.conf");
    let Body::Text(text) = &item.body else {
        return false;
    };
    named
        && text.lines().map(str::trim).all(|line| {
            line.is_empty()
                || line.starts_with('#')
                || line.split_once('=').is_some_and(|(name, value)| {
                    (LOCALE_VARIABLES.contains(&name) || name.starts_with("LC_"))
                        && value.chars().all(|c| {
                            c.is_ascii_alphanumeric()
                                || matches!(c, '_' | '-' | '.' | '@' | ':' | '"')
                        })
                })
        })
}

/// Whether nobody looked for everything `item` runs (see
/// `NOT_ALL_FOLLOWED`).
pub fn is_capped(item: &Item) -> bool {
    item.notes
        .iter()
        .any(|note| note.starts_with(NOT_ALL_FOLLOWED))
}

/// Adds `items` to `collection`; an item already there by path gains the
/// new one's notes and alerts instead of appearing twice.
///
/// An item that was reached as configuration only stays that only while
/// the new one was too: one another check found by itself (running, or as
/// what a command names) is a program, so the notes that keep it from the
/// review go. And where a live check found a file whose kind keeps it from
/// the review (a tool's settings, an SSH file), it is listed as what that
/// check saw: a file something runs is read as a program.
pub fn merge(collection: &mut Collection, items: Vec<Item>) {
    for item in items {
        if let Some(existing) = collection
            .items
            .iter_mut()
            .find(|existing| existing.path == item.path)
        {
            if configuration_of(&item).is_none() {
                let kept = configuration_of(existing).is_some() || is_kept_by_kind(existing);
                existing.notes.retain(|note| !is_configuration_note(note));
                if kept && item.category.is_live() {
                    existing.category = item.category;
                }
            }
            for note in item.notes {
                if !existing.notes.contains(&note) {
                    existing.notes.push(note);
                }
            }
            for alert in item.alerts {
                if !existing.alerts.contains(&alert) {
                    existing.alerts.push(alert);
                }
            }
        } else {
            collection.items.push(item);
        }
    }
    collection
        .items
        .sort_by(|left, right| left.path.cmp(&right.path));
}

/// Adds the files of `location` (under `prefix`, the home for user
/// locations) that run on their own.
fn add_location(
    scope: &Scope<'_>,
    location: &Location,
    prefix: &str,
    paths: &mut BTreeMap<String, Category>,
    truncated: &mut Vec<String>,
) {
    let base = format!("{prefix}{}", location.path);
    let candidates = if location.kind == Kind::Glob {
        let matches = read::matching(scope.root, &base);
        if matches.truncated {
            truncated.push(format!("/{base}: more matches than were looked at"));
        }
        truncated.extend(matches.unnamed.iter().map(|name| not_utf8(name)));
        truncated.extend(
            matches
                .unreadable
                .iter()
                .map(|directory| format!("/{directory}: could not be listed")),
        );
        matches.files
    } else if location.kind == Kind::File {
        // A file behind a directory only root can list is still looked at,
        // and reported as unreadable.
        match fs::symlink_metadata(scope.root.join(&base)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return,
            Ok(_) | Err(_) => vec![base],
        }
    } else {
        let listing = read::entries(scope.root, &base);
        if listing.truncated {
            truncated.push(format!("/{base}: more entries than were looked at"));
        }
        truncated.extend(listing.unnamed.iter().map(|name| not_utf8(name)));
        // A directory only root can list is one unreadable item.
        for directory in listing.unreadable {
            paths.entry(directory).or_insert(location.category);
        }
        listing.files
    };
    for path in candidates {
        let relative = path.strip_prefix(prefix).unwrap_or(&path);
        if location.contains(relative) && wanted(scope, location.category, relative) {
            paths.entry(path).or_insert(location.category);
        }
    }
}

/// The sentence for an entry whose name the sweep cannot read.
pub fn not_utf8(shown: &str) -> String {
    // A name may hold a newline, which would start a line of its own.
    format!("/{}{NOT_UTF8}", shown.escape_debug())
}

const NOT_UTF8: &str = ": a name that is not UTF-8 was not checked";

/// The most sentences of what was not looked at that are kept.
const MAX_UNCHECKED: usize = 20;

/// `unchecked` without repeats and within a bound, the rest counted.
pub fn bounded(mut unchecked: Vec<String>) -> Vec<String> {
    // Names last: anyone can make many, and they must not crowd out a
    // limit that was reached.
    unchecked.sort_by_key(|sentence| (sentence.ends_with(NOT_UTF8), sentence.clone()));
    unchecked.dedup();
    let more = unchecked.len().saturating_sub(MAX_UNCHECKED);
    unchecked.truncate(MAX_UNCHECKED);
    if more > 0 {
        unchecked.push(format!("and {more} more that were not checked"));
    }
    unchecked
}

/// Whether a file in a user location is one that runs on its own.
fn wanted(scope: &Scope<'_>, category: Category, relative: &str) -> bool {
    let name = file_name(relative);
    match category {
        // A backup Omarchy left (`hyprland.conf.bak.1700000000`) ends in
        // neither; a file Hyprland is told to `source` is followed from
        // the one that names it, whatever it is called.
        Category::Hyprland => read::has_extension(name, "lua") || read::has_extension(name, "conf"),
        // Omarchy runs every hook but `*.sample`.
        Category::OmarchyHook => !name.ends_with(".sample"),
        // Old password hashes (`pam_pwhistory`): never read, never handed on.
        Category::Pam => name != "opasswd",
        Category::Autostart if relative.starts_with(".config/autostart/") => {
            name.ends_with(".desktop")
        }
        // Only launchers that replace a system app's; one `mimeapps.list`
        // names is followed from there.
        Category::Desktop if relative.starts_with(".local/share/applications/") => {
            name == "mimeapps.list"
                || (name.ends_with(".desktop")
                    && scope
                        .root
                        .join("usr/share/applications")
                        .join(name)
                        .exists())
        }
        Category::Browser if relative.contains("essaging") => read::has_extension(name, "json"),
        // Only programs named like a system command.
        Category::LocalBin => {
            WATCHED_NAMES.contains(&name)
                || name.starts_with("omarchy-")
                || scope.root.join("usr/bin").join(name).exists()
        }
        _ => true,
    }
}

/// What a directory holds, as the walk may see it.
fn listed(scope: &Scope<'_>, view: Option<View>, directory: &str) -> Vec<String> {
    let names = |entries: fs::ReadDir| {
        entries
            .flatten()
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect()
    };
    match view {
        Some(view) => match read::seen(scope.root, directory, view).map(|seen| seen.what) {
            Some(read::Public::Directory(handle)) => {
                fs::read_dir(format!("/proc/self/fd/{}", handle.as_raw_fd()))
                    .map(names)
                    .unwrap_or_default()
            }
            _ => Vec::new(),
        },
        None => fs::read_dir(scope.root.join(directory))
            .map(names)
            .unwrap_or_default(),
    }
}

/// What following an item gave.
#[derive(Debug, Default, PartialEq, Eq)]
struct Followed {
    /// The paths it leads to.
    targets: Vec<String>,
    /// Those among them that the item reads as more configuration and
    /// does not run (see `CONFIGURATION_OF`).
    configuration: Vec<String>,
    /// Those among them that a shell was handed as its script.
    shell_scripts: Vec<String>,
    /// Those among them that a unit reads as a list of variables
    /// (`EnvironmentFile=`) and that it does not run.
    environment: Vec<String>,
    /// The limits that were reached, each as the rest of a sentence.
    unfollowed: Vec<String>,
}

/// Absolute paths mentioned in Omarchy's installer scripts.
fn omarchy_paths(root: &Path) -> HashSet<String> {
    let mut paths = HashSet::new();
    for directory in OMARCHY_INSTALL {
        for file in read::entries(root, directory).files {
            let Ok(text) = fs::read_to_string(root.join(&file)) else {
                continue;
            };
            for word in text.split(|c: char| {
                c.is_whitespace() || matches!(c, '"' | '\'' | '>' | '<' | '(' | ')' | ';')
            }) {
                if word.starts_with('/') && word.len() > 1 {
                    paths.insert(word.trim_end_matches([',', '|']).to_string());
                }
            }
        }
    }
    paths
}

#[cfg(test)]
mod tests;
