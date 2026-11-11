//! Guardian's own sweep units, and what stands in for them.
//!
//! The daily sweep is a systemd user unit, and the root checks a system
//! unit. systemd lets a file in another unit directory replace a unit, and a
//! drop-in change any line of it: a `HOME=`, an `XDG_STATE_HOME=` or an
//! `ExecStart=` in `omarchy-guardian-sweep.service.d/` makes the sweep look
//! at another home, write its results elsewhere or not run at all, while the
//! bar still shows a sweep that ran. Anything of that kind is an alert of
//! its own, which allowing the file does not quiet.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use super::collect::{Body, Item, Origin, Scope, WITHHELD};
use super::read::{self, Found, View};
use super::tier::Tier;
use crate::autorun::Category;
use crate::rules::RuleId;
use crate::sha256::Digest;

/// The units of the user's sweep and of the root checks.
const USER_UNITS: &[&str] = &[
    "omarchy-guardian-sweep.service",
    "omarchy-guardian-sweep.timer",
];
const SYSTEM_UNITS: &[&str] = &[
    "omarchy-guardian-sweep-collect.service",
    "omarchy-guardian-sweep-collect.timer",
];

/// Why an override root found has no hash.
const NOT_READ: &str =
    "there, and not read: not a regular file, closed to its account, or changed as it was read";
/// Why one has none because root's bounds for the account were reached
/// (`MAX_ACCOUNT_PARTS`, `MAX_ACCOUNT_BYTES`): told apart from `NOT_READ`,
/// so an account that spent them is not taken for a permission problem.
/// One file over the bound for a file is `TOO_BIG`.
const PAST_BOUND: &str = "there, and not read: past root's bound for this account";
/// Why a drop-in whose name is not UTF-8 has none.
const UNNAMED: &str = "there, and not read: its name is not UTF-8";
/// Why a drop-in directory with more names than `MAX_DROP_INS` is reported
/// as one item: which of its names it would keep would be up to readdir
/// order, so an override could hide behind the others.
const CROWDED: &str = "there, and not read: more than 64 names";
/// Why a file larger than `MAX_UNIT_BYTES` was not read.
const TOO_BIG: &str = "there, and not read: larger than the 1 MiB root reads of one file";

/// Where systemd reads user units from besides the package's own
/// directory, relative to the home: every directory of its search path
/// (`systemd-analyze --user unit-paths`), all of which but the late
/// generators' outrank the package's, and the data directory Flatpak adds
/// to the user manager's `XDG_DATA_DIRS`.
const HOME_DIRECTORIES: &[&str] = &[
    ".config/systemd/user",
    ".config/systemd/user.control",
    ".config/systemd/user.attached",
    ".local/share/systemd/user",
    ".local/share/flatpak/exports/share/systemd/user",
];
/// The same below `/run/user/<uid>`.
const RUNTIME_DIRECTORIES: &[&str] = &[
    "systemd/user",
    "systemd/user.control",
    "systemd/user.attached",
    "systemd/transient",
    "systemd/generator",
    "systemd/generator.early",
    "systemd/generator.late",
];
/// The same for every user, relative to the root. The two under `share`
/// are the system's `XDG_DATA_DIRS`: systemd looks there before
/// `/usr/lib/systemd/user`, so a unit of the same name there replaces the
/// package's.
const SHARED_USER_DIRECTORIES: &[&str] = &[
    "etc/systemd/user",
    "etc/xdg/systemd/user",
    "run/systemd/user",
    "usr/local/share/systemd/user",
    "usr/share/systemd/user",
    "var/lib/flatpak/exports/share/systemd/user",
    "usr/local/lib/systemd/user",
];
/// Where systemd reads system units from besides the package's own
/// (`systemd-analyze --system unit-paths`).
const SYSTEM_DIRECTORIES: &[&str] = &[
    "etc/systemd/system",
    "etc/systemd/system.control",
    "etc/systemd/system.attached",
    "run/systemd/system",
    "run/systemd/system.control",
    "run/systemd/system.attached",
    "run/systemd/transient",
    "run/systemd/generator",
    "run/systemd/generator.early",
    "run/systemd/generator.late",
    "usr/local/lib/systemd/system",
];
/// The package's own directories: its units are there, so only a drop-in
/// beside them is an override.
const PACKAGE_USER: &str = "usr/lib/systemd/user";
const PACKAGE_SYSTEM: &str = "usr/lib/systemd/system";

/// The most drop-ins looked at in one directory. `CROWDED` gives the
/// number in words, and a test holds the two together.
const MAX_DROP_INS: usize = 64;

/// What was seen, for the alert.
const SEEN: &str = "stands in for, or changes, a unit of Guardian's own sweep";

/// The drop-in directories whose files apply to `unit`: its own, the ones
/// for every unit whose name starts like it (`omarchy-.service.d`), and
/// the one for every unit of its type (`service.d`).
fn drop_in_directories(unit: &str) -> Vec<String> {
    let (name, kind) = unit.rsplit_once('.').unwrap_or((unit, ""));
    let mut directories = vec![format!("{unit}.d"), format!("{kind}.d")];
    for (at, _) in name.match_indices('-') {
        directories.push(format!("{}-.{kind}.d", &name[..at]));
    }
    directories
}

/// Whether the file at `relative` (to a unit directory) overrides one of
/// `units`.
fn overrides(units: &[&str], relative: &str, with_units: bool) -> bool {
    units.iter().any(|unit| {
        (with_units && relative == *unit)
            || relative.split_once('/').is_some_and(|(directory, file)| {
                !file.contains('/') && drop_in_directories(unit).iter().any(|own| own == directory)
            })
    })
}

/// Whether `path` (relative to the root) overrides one of Guardian's units,
/// for a sweep whose home is `home`.
pub(super) fn is_override(home: Option<&str>, path: &str) -> bool {
    let under = |directory: &str, units: &[&str], with_units: bool| {
        path.strip_prefix(directory)
            .and_then(|rest| rest.strip_prefix('/'))
            .is_some_and(|relative| overrides(units, relative, with_units))
    };
    let in_home = home.is_some_and(|home| {
        HOME_DIRECTORIES
            .iter()
            .any(|directory| under(&format!("{home}/{directory}"), USER_UNITS, true))
    });
    let in_runtime = path.strip_prefix("run/user/").is_some_and(|rest| {
        rest.split_once('/').is_some_and(|(_, below)| {
            RUNTIME_DIRECTORIES.iter().any(|directory| {
                below
                    .strip_prefix(directory)
                    .and_then(|rest| rest.strip_prefix('/'))
                    .is_some_and(|relative| overrides(USER_UNITS, relative, true))
            })
        })
    });
    in_home
        || in_runtime
        || SHARED_USER_DIRECTORIES
            .iter()
            .any(|directory| under(directory, USER_UNITS, true))
        || SYSTEM_DIRECTORIES
            .iter()
            .any(|directory| under(directory, SYSTEM_UNITS, true))
        || under(PACKAGE_USER, USER_UNITS, false)
        || under(PACKAGE_SYSTEM, SYSTEM_UNITS, false)
}

/// What may override a unit, found by listing unit directories.
#[derive(Debug, Default)]
struct Candidates {
    /// The paths to look at, sorted, so the order does not depend on the
    /// order a directory lists its names in.
    paths: BTreeSet<String>,
    /// Drop-ins whose names are not UTF-8, the name written as
    /// `read::link_text` writes it: systemd reads them, and the sweep
    /// cannot name them to look, so each is an override not read. No two
    /// such names share that text, but a UTF-8 name can (the byte `\xff`
    /// and the four characters `\xff`): then both are reported, the
    /// UTF-8 one looked at and this one not read, so neither a decoy
    /// beside it nor deleting one hides the other. A suffix on this path
    /// would only move the collision, since a UTF-8 name can hold any
    /// text.
    unnamed: BTreeSet<String>,
    /// Drop-in directories with more names than `MAX_DROP_INS`: each is
    /// one override not read (`CROWDED`).
    crowded: Vec<String>,
}

impl Candidates {
    /// The paths under unit directory `directory` that may override one of
    /// `units`: the unit files themselves, and what `list` says their
    /// drop-in directories hold.
    fn add(
        &mut self,
        directory: &str,
        units: &[&str],
        with_units: bool,
        list: &dyn Fn(&str) -> Listed,
    ) {
        for unit in units {
            if with_units {
                self.paths.insert(format!("{directory}/{unit}"));
            }
            for drop_ins in drop_in_directories(unit) {
                let holder = format!("{directory}/{drop_ins}");
                let Names { names, unnamed } = match list(&holder) {
                    Listed::Names(names) => names,
                    Listed::Crowded => {
                        self.crowded.push(holder);
                        continue;
                    }
                };
                self.paths
                    .extend(names.iter().map(|name| format!("{holder}/{name}")));
                self.unnamed
                    .extend(unnamed.iter().map(|name| format!("{holder}/{name}")));
            }
        }
    }
}

/// What a drop-in directory holds.
#[derive(Debug)]
enum Listed {
    /// Its names, `MAX_DROP_INS` at most.
    Names(Names),
    /// More names than `MAX_DROP_INS`.
    Crowded,
}

impl Listed {
    const NONE: Self = Self::Names(Names {
        names: Vec::new(),
        unnamed: Vec::new(),
    });
}

/// The names in a drop-in directory: those that are UTF-8, and the others
/// written as `read::link_text` writes them.
#[derive(Debug, Default)]
struct Names {
    names: Vec<String>,
    unnamed: Vec<String>,
}

fn names_in(entries: fs::ReadDir) -> Listed {
    let mut listed = Names::default();
    for (at, entry) in entries.flatten().enumerate() {
        if at == MAX_DROP_INS {
            return Listed::Crowded;
        }
        match entry.file_name().into_string() {
            Ok(name) => listed.names.push(name),
            Err(name) => listed.unnamed.push(read::link_text(Path::new(&name))),
        }
    }
    Listed::Names(listed)
}

/// The id of the user whose directory `home` is.
fn owner(root: &Path, home: &str) -> Option<u32> {
    fs::symlink_metadata(root.join(home))
        .ok()
        .map(|metadata| metadata.uid())
}

/// The paths under `root` of what may override Guardian's units outside
/// the package's own directories: in the system's other unit directories
/// and, with a home (relative to the root), in that home's and its runtime
/// directory's. With `packaged`, the drop-ins beside the package's own
/// units as well. Only paths where something is are kept.
fn candidates_under(root: &Path, home: Option<&str>, packaged: bool) -> Candidates {
    let list = |directory: &str| -> Listed {
        fs::read_dir(root.join(directory)).map_or(Listed::NONE, names_in)
    };
    let mut found = Candidates::default();
    for directory in SHARED_USER_DIRECTORIES {
        found.add(directory, USER_UNITS, true, &list);
    }
    for directory in SYSTEM_DIRECTORIES {
        found.add(directory, SYSTEM_UNITS, true, &list);
    }
    if packaged {
        found.add(PACKAGE_USER, USER_UNITS, false, &list);
        found.add(PACKAGE_SYSTEM, SYSTEM_UNITS, false, &list);
    }
    if let Some(home) = home {
        for directory in HOME_DIRECTORIES {
            found.add(&format!("{home}/{directory}"), USER_UNITS, true, &list);
        }
        if let Some(uid) = owner(root, home) {
            for directory in RUNTIME_DIRECTORIES {
                let directory = format!("run/user/{uid}/{directory}");
                found.add(&directory, USER_UNITS, true, &list);
            }
        }
    }
    found
        .paths
        .retain(|path| fs::symlink_metadata(root.join(path)).is_ok());
    found
}

/// What may override Guardian's units and `scope` can look at as itself:
/// in the system's unit directories and, with a home, in that home's and
/// its runtime directory's. The paths, to be read as items, and the
/// overrides not read: drop-ins whose names are not UTF-8, and drop-in
/// directories with too many names. The root collector looks at root's own
/// home here; the homes of the accounts its results go to are looked at as
/// those accounts (`of_account`).
pub(super) fn paths(scope: &Scope<'_>) -> (Vec<String>, Vec<Item>) {
    let found = candidates_under(scope.root, scope.home, true);
    let unnamed = found.unnamed.into_iter().map(|path| (path, UNNAMED));
    let crowded = found.crowded.into_iter().map(|path| (path, CROWDED));
    let not_read = unnamed
        .chain(crowded)
        .map(|(path, why)| not_read(scope.origin, path, why))
        .collect();
    (found.paths.into_iter().collect(), not_read)
}

/// An override at `path` that was not read, for `why`, with the alert.
/// The collector marks every path `is_override` accepts again, but a
/// crowded drop-in directory is not one of them, so the mark is put here.
fn not_read(origin: Origin, path: String, why: &str) -> Item {
    let mut item = Item {
        file: None,
        origin,
        category: Category::Systemd,
        path,
        tier: Tier::Unknown,
        sha256: None,
        body: Body::Unreadable(why.into()),
        runs: Vec::new(),
        run_by: None,
        notes: Vec::new(),
        alerts: Vec::new(),
    };
    mark(&mut item);
    item
}

/// What stands in for Guardian's units right now, for the bar: the same
/// files the sweep alerts on (`is_override`), found without the package
/// index, which is too much to load every half minute. Drop-ins in the
/// package's own directories are therefore left to the sweep: only it
/// can tell the one a repository package ships for every unit from one
/// put there by hand. A drop-in directory with too many names is listed
/// itself. Sorted, and each path once: a name that is not UTF-8 can read
/// as one that is, and the bar shows only paths.
pub(crate) fn standing(root: &Path, home: Option<&str>) -> Vec<String> {
    let found = candidates_under(root, home, false);
    let standing: BTreeSet<String> = found
        .paths
        .into_iter()
        .chain(found.unnamed)
        .filter(|path| is_override(home, path))
        .chain(found.crowded)
        .collect();
    standing.into_iter().collect()
}

/// Puts the alert on `item`, which overrides one of Guardian's units. An
/// alert takes away whatever trust its tier gave it: a mask is no longer
/// inert.
pub(super) fn mark(item: &mut Item) {
    if !item
        .alerts
        .iter()
        .any(|(rule, _)| *rule == RuleId::GuardianOverride)
    {
        item.alerts.push((RuleId::GuardianOverride, SEEN.into()));
    }
}

/// Whether there is anything at `path`, as account `view` could tell
/// itself: it may enter the directory the name is in.
fn is_there(scope: &Scope<'_>, path: &str, view: View) -> bool {
    let Some((directory, name)) = path.rsplit_once('/') else {
        return false;
    };
    match read::seen(scope.root, directory, view).map(|seen| seen.what) {
        Some(read::Public::Directory(handle)) => {
            fs::symlink_metadata(format!("/proc/self/fd/{}/{name}", handle.as_raw_fd())).is_ok()
        }
        _ => false,
    }
}

/// The overrides of the user sweep's units in the home of account `uid`
/// (`home`, relative to the root) and its runtime directory, as the root
/// collector may report them: looked at as that account could itself, its
/// links on the way followed as it may follow them, and with the content
/// left where it is. So the finding does not rest on that account's own
/// sweep being honest.
///
/// What is there and cannot be hashed (a drop-in padded past the read
/// limit, a file closed to its own account, something that is no file) is
/// reported all the same, without a hash: root's report is for the case
/// where the account's own sweep was turned away, and dropping what could
/// not be read would be the way to turn root away too. That something is
/// there tells the account nothing it cannot see: the path is one Guardian
/// chose below the account's own home or runtime directory, not one a user
/// named, the links on the way lead only where the account may follow
/// them, a directory is listed only where the account may list it, and it
/// is looked for only as the account may look.
pub(super) fn of_account(scope: &Scope<'_>, home: &str, uid: u32) -> Vec<Item> {
    let looks = Looks::new(scope, View::Owner(uid));
    let found = looks.candidates(home, uid);
    looks.report(found)
}

/// How many parts of paths root may open for one account in `of_account`,
/// in all. Each look walks its path from the root, one open a part, so
/// links that lead deep (`~/.config` to `d/d/…/d/back`, 230 parts) would
/// otherwise cost some 33,000 opens a resolve, a few hundred resolves an
/// account, and keep the collector past its 30-minute timeout. An honest
/// account's unit directories take some 110 resolves of a few parts each
/// and a few hundred looks (about 5,000 parts); 65,536 is arbitrary above
/// that, about 0.4 s at the measured 200 ms for 33,000 parts. A look is
/// charged once and walks its path at most three times (`found_at`: the
/// look, then whether anything is there), so the bound holds within that
/// factor. Once spent, each directory left is one item not read.
const MAX_ACCOUNT_PARTS: usize = 65_536;

/// The most bytes of one unit file or drop-in root hashes for an account:
/// real ones are a few hundred bytes. Arbitrary, well above that.
const MAX_UNIT_BYTES: u64 = 1024 * 1024;

/// The most bytes of an account's unit files and drop-ins root hashes in
/// all. Each drop-in directory holds up to `MAX_DROP_INS` names, which can
/// all be hard links to one large file (hashed at some 80 MiB/s,
/// measured), and there are some 100 such directories an account.
/// Arbitrary: 16 files at `MAX_UNIT_BYTES`, about 0.2 s. Past it, each
/// file is reported as not read, with the alert.
const MAX_ACCOUNT_BYTES: u64 = 16 * MAX_UNIT_BYTES;

/// What `of_account` looks at as one account, with what it may still
/// look at.
struct Looks<'a> {
    scope: &'a Scope<'a>,
    view: View,
    /// Parts of paths it may still open (see `MAX_ACCOUNT_PARTS`).
    parts_left: Cell<usize>,
    /// Bytes it may still hash (see `MAX_ACCOUNT_BYTES`).
    bytes_left: Cell<u64>,
    /// Where each directory a path named led (see `real`), so each is
    /// resolved once.
    resolved: RefCell<HashMap<String, Result<Option<String>, &'static str>>>,
    /// Directories not listed as the account, with why: not followed to
    /// their end, or there and closed to it. One item not read each: every
    /// name looked for below it would be one too, and it is not empty to
    /// the account.
    not_listed: RefCell<Vec<(String, &'static str)>>,
}

impl<'a> Looks<'a> {
    /// Looks at what `view` may see below `scope`'s root, with the whole
    /// budget left.
    fn new(scope: &'a Scope<'a>, view: View) -> Self {
        Self {
            scope,
            view,
            parts_left: Cell::new(MAX_ACCOUNT_PARTS),
            bytes_left: Cell::new(MAX_ACCOUNT_BYTES),
            resolved: RefCell::new(HashMap::new()),
            not_listed: RefCell::new(Vec::new()),
        }
    }

    /// What may override the user sweep's units in `home` and in the
    /// runtime directory of `uid`, listed as the account may list it. A
    /// directory not followed is noted in `not_listed`.
    fn candidates(&self, home: &str, uid: u32) -> Candidates {
        let not_followed = |path: &str, why| self.not_listed.borrow_mut().push((path.into(), why));
        let list = |directory: &str| self.list(directory);
        let mut found = Candidates::default();
        let runtime = format!("run/user/{uid}");
        for (top, directories) in [(home, HOME_DIRECTORIES), (&runtime, RUNTIME_DIRECTORIES)] {
            if let Err(why) = self.real(top) {
                not_followed(top, why);
                continue;
            }
            for directory in directories {
                let base = format!("{top}/{directory}");
                if let Err(why) = self.real(&base) {
                    not_followed(&base, why);
                    continue;
                }
                found.add(&base, USER_UNITS, true, &list);
            }
        }
        found
    }

    /// Each of `found` as an item of root's, with the alert: what is there
    /// looked at now (see `found_at`), and the rest not read. Nothing is
    /// dropped for a path reported twice: a name that is not UTF-8 can read
    /// as one that is (see `Candidates::unnamed`).
    fn report(&self, found: Candidates) -> Vec<Item> {
        let unnamed = found.unnamed.into_iter().map(|path| (path, UNNAMED));
        let crowded = found.crowded.into_iter().map(|path| (path, CROWDED));
        let not_read = self
            .not_listed
            .take()
            .into_iter()
            .chain(crowded)
            .chain(unnamed)
            .map(|(path, why)| (path, (None, Body::Unreadable(why.into()))));
        let looked = found
            .paths
            .into_iter()
            .filter_map(|path| Some((path.clone(), self.found_at(&path)?)));
        let item = |(path, (sha256, body))| {
            let mut item = Item {
                file: None,
                origin: Origin::Root,
                category: Category::Systemd,
                path,
                tier: Tier::Unknown,
                sha256,
                body,
                runs: Vec::new(),
                run_by: None,
                notes: vec!["seen by the root checks".into()],
                alerts: Vec::new(),
            };
            mark(&mut item);
            item
        };
        looked.chain(not_read).map(item).collect()
    }

    /// Takes the parts of `path` from what is left: `false` once spent.
    fn take_parts(&self, path: &str) -> bool {
        let parts = path.split('/').count();
        match self.parts_left.get().checked_sub(parts) {
            Some(left) => {
                self.parts_left.set(left);
                true
            }
            None => false,
        }
    }

    /// Where systemd finds the directory `path` names: the links on the
    /// way followed as the account may follow them (`~/.config/systemd`
    /// linked into a dotfiles directory, as GNU stow does), as `keys_of`
    /// follows `~/.ssh`. An error, with why, where the way was not followed
    /// to its end: a directory root's walk was kept out of (a FUSE mount of
    /// the account's, a home on NFS with `root_squash`) or a chain of links
    /// too long (`NOT_READ`), or the account's budget spent (`PAST_BOUND`).
    fn real(&self, path: &str) -> Result<Option<String>, &'static str> {
        if let Some(resolved) = self.resolved.borrow().get(path) {
            return resolved.clone();
        }
        // The walk stops at the first hop refused, so the budget is why
        // when `take_parts` turned a hop away.
        let spent = Cell::new(false);
        let hop = |part: &str| {
            if self.take_parts(part) {
                read::hop_below(self.scope.root, part, self.view)
            } else {
                spent.set(true);
                read::Hop::Refused
            }
        };
        let resolved = read::resolve_path(path, &hop)
            .map_err(|()| if spent.get() { PAST_BOUND } else { NOT_READ });
        self.resolved
            .borrow_mut()
            .insert(path.to_string(), resolved.clone());
        resolved
    }

    /// What the directory `path` names holds, where the account may list
    /// it. One not followed to its end (see `real`), one that is there and
    /// may not be listed, and one swapped since it was resolved are noted
    /// as not listed.
    fn list(&self, path: &str) -> Listed {
        let not_listed = |why| {
            self.not_listed.borrow_mut().push((path.to_string(), why));
            Listed::NONE
        };
        let directory = match self.real(path) {
            Ok(Some(directory)) => directory,
            Ok(None) => return Listed::NONE,
            Err(why) => return not_listed(why),
        };
        if !self.take_parts(&directory) {
            return not_listed(PAST_BOUND);
        }
        match read::seen_or_why(self.scope.root, &directory, self.view).map(|seen| seen.what) {
            Ok(read::Public::Directory(handle)) => {
                let listed = handle
                    .metadata()
                    .is_ok_and(|metadata| self.view.may_list(&metadata));
                if !listed {
                    return not_listed(NOT_READ);
                }
                fs::read_dir(format!("/proc/self/fd/{}", handle.as_raw_fd()))
                    .map_or(Listed::NONE, names_in)
            }
            Err(read::Unseen::Nothing) => Listed::NONE,
            // Not a directory the account may list now: something else
            // since it was resolved, or a part root's walk is refused at.
            Ok(_) | Err(read::Unseen::Through) => not_listed(NOT_READ),
        }
    }

    /// What the account finds at `path`: its hash and body, or `None` where
    /// nothing is there. The directory it is in is resolved (see `real`);
    /// the name itself is looked at, so a link there is a link.
    fn found_at(&self, path: &str) -> Option<(Option<Digest>, Body)> {
        let not_read = |why: &str| Some((None, Body::Unreadable(why.into())));
        let (directory, name) = path.rsplit_once('/')?;
        let directory = match self.real(directory) {
            Ok(directory) => directory?,
            Err(why) => return not_read(why),
        };
        let looked = format!("{directory}/{name}");
        if !self.take_parts(&looked) {
            return not_read(PAST_BOUND);
        }
        let (root, view) = (self.scope.root, self.view);
        let Some(seen) = read::seen(root, &looked, view) else {
            // Nothing the account may see: nothing there, a file closed to
            // it, or a part of the way swapped for a link since the
            // directory was resolved. Only where nothing is there is
            // nothing reported.
            let there = is_there(self.scope, &looked, view)
                || read::seen_or_why(root, &looked, view).err() == Some(read::Unseen::Through);
            return if there { not_read(NOT_READ) } else { None };
        };
        let most = MAX_UNIT_BYTES.min(self.bytes_left.get());
        // A file larger than one file may take, or than what is left, is
        // turned away by its size, and costs nothing: hard links to one
        // sparse file of a terabyte would otherwise spend the budget
        // unread.
        let size = match &seen.what {
            read::Public::File(file) => Some(file.metadata().map_or(0, |metadata| metadata.len())),
            _ => None,
        };
        match size {
            Some(size) if size > MAX_UNIT_BYTES => return not_read(TOO_BIG),
            Some(size) if size > most => return not_read(PAST_BOUND),
            _ => {}
        }
        let found = read::look_pinned_within(seen, most);
        self.bytes_left.set(
            self.bytes_left
                .get()
                .saturating_sub(charged(&found, size, most)),
        );
        match found {
            Found::File { sha256, .. } => Some((Some(sha256), Body::Binary(WITHHELD))),
            Found::Link(target) => Some((None, Body::Link(target))),
            Found::Other | Found::Unreadable(_) => not_read(NOT_READ),
        }
    }
}

/// What looking at a file costs the account's byte budget: what was
/// hashed; `most` for a regular file that was not hashed after all, which
/// grew past `most` as it was read or failed partway; nothing for what is
/// not a regular file (`size` is `None`).
fn charged(found: &Found, size: Option<u64>, most: u64) -> u64 {
    match (found, size) {
        (Found::File { size, .. }, _) => *size,
        (_, Some(_)) => most,
        (_, None) => 0,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    use super::{
        CROWDED, Listed, Looks, MAX_ACCOUNT_BYTES, MAX_DROP_INS, MAX_UNIT_BYTES, NOT_READ,
        PAST_BOUND, TOO_BIG, UNNAMED, USER_UNITS, View, charged, drop_in_directories, is_override,
        of_account, standing,
    };
    use crate::rules::RuleId;
    use crate::sweep::collect::{Body, Origin, Scope, WITHHELD, collect};
    use crate::sweep::index::PackageIndex;
    use crate::sweep::read::Found;
    use crate::test_support::TempDir;

    #[test]
    fn what_overrides_guardians_units_is_told_from_what_enables_them() {
        let home = Some("home/u");
        for path in [
            "home/u/.config/systemd/user/omarchy-guardian-sweep.service",
            "home/u/.config/systemd/user/omarchy-guardian-sweep.timer",
            "home/u/.config/systemd/user/omarchy-guardian-sweep.service.d/x.conf",
            "home/u/.config/systemd/user/omarchy-guardian-.service.d/x.conf",
            "home/u/.config/systemd/user/omarchy-.service.d/x.conf",
            "home/u/.config/systemd/user/service.d/x.conf",
            "home/u/.config/systemd/user.control/omarchy-guardian-sweep.timer.d/50-x.conf",
            "home/u/.local/share/systemd/user/omarchy-guardian-sweep.service",
            "run/user/1000/systemd/transient/omarchy-guardian-sweep.service",
            "etc/systemd/user/omarchy-guardian-sweep.timer",
            // Ahead of the package's own directory on systemd's path.
            "usr/share/systemd/user/omarchy-guardian-sweep.service",
            "usr/local/share/systemd/user/omarchy-guardian-sweep.timer",
            "usr/share/systemd/user/service.d/x.conf",
            "var/lib/flatpak/exports/share/systemd/user/omarchy-guardian-sweep.service",
            "home/u/.local/share/flatpak/exports/share/systemd/user/omarchy-guardian-sweep.service",
            "home/u/.config/systemd/user.attached/omarchy-guardian-sweep.service",
            "run/user/1000/systemd/user.attached/omarchy-guardian-sweep.service.d/x.conf",
            "run/systemd/system.attached/omarchy-guardian-sweep-collect.service",
            "etc/systemd/system/omarchy-guardian-sweep-collect.service.d/x.conf",
            "etc/systemd/system/omarchy-guardian-sweep-collect.timer",
            "usr/lib/systemd/user/omarchy-guardian-sweep.service.d/x.conf",
        ] {
            assert!(is_override(home, path), "{path}");
        }
        for path in [
            // The package's own units, and the links that enable them.
            "usr/lib/systemd/user/omarchy-guardian-sweep.service",
            "usr/lib/systemd/system/omarchy-guardian-sweep-collect.timer",
            "home/u/.config/systemd/user/timers.target.wants/omarchy-guardian-sweep.timer",
            "etc/systemd/system/timers.target.wants/omarchy-guardian-sweep-collect.timer",
            // Other units, and another home.
            "home/u/.config/systemd/user/other.service.d/x.conf",
            "home/u/.config/systemd/user/omarchy-guardian-sweep.service.d/sub/x.conf",
            "home/v/.config/systemd/user/omarchy-guardian-sweep.service",
            "etc/systemd/system/omarchy-guardian-sweep.service",
            "usr/share/systemd/user/other.service",
        ] {
            assert!(!is_override(home, path), "{path}");
        }
    }

    #[test]
    fn overrides_are_found_by_the_user_and_by_root_looking_as_that_user() {
        let dir = TempDir::new("sweep-own");
        let root = dir.path();
        let uid = fs::metadata(root).unwrap().uid();
        let units = root.join("home/u/.config/systemd/user");
        fs::create_dir_all(units.join("omarchy-guardian-sweep.service.d")).unwrap();
        fs::write(
            units.join("omarchy-guardian-sweep.service.d/home.conf"),
            "[Service]\nEnvironment=HOME=/tmp/fake\n",
        )
        .unwrap();
        symlink("/dev/null", units.join("omarchy-guardian-sweep.timer")).unwrap();
        fs::write(units.join("other.service"), "[Service]\nExecStart=/x\n").unwrap();
        let index = PackageIndex::with_foreign(HashSet::new());
        let scope = Scope {
            root,
            home: Some("home/u"),
            index: &index,
            origin: Origin::System,
        };
        let collection = collect(&scope);
        let found: Vec<_> = collection
            .items
            .iter()
            .filter(|item| !item.alerts.is_empty())
            .collect();
        let paths: Vec<&str> = found.iter().map(|item| item.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "home/u/.config/systemd/user/omarchy-guardian-sweep.service.d/home.conf",
                "home/u/.config/systemd/user/omarchy-guardian-sweep.timer",
            ]
        );
        assert!(found.iter().all(|item| {
            item.alerts
                .iter()
                .any(|(rule, _)| *rule == RuleId::GuardianOverride)
                && !item.is_trusted()
        }));
        // Another unit beside them is an ordinary item.
        assert!(
            collection
                .items
                .iter()
                .any(|item| { item.path.ends_with("other.service") && item.alerts.is_empty() })
        );

        // The bar finds the same two without a package index. A drop-in
        // beside the package's own units is left to the sweep, which can
        // tell whether a repository package ships it.
        let beside = root.join("usr/lib/systemd/user/omarchy-guardian-sweep.service.d");
        fs::create_dir_all(&beside).unwrap();
        fs::write(beside.join("x.conf"), "[Service]\n").unwrap();
        assert_eq!(standing(root, Some("home/u")), paths);
        assert!(standing(root, None).is_empty());
        assert_eq!(super::paths(&scope).0.len(), 3);

        // Root, for the account the results go to: the same files, by
        // hash, without their content.
        let as_root = Scope {
            root,
            home: Some("root"),
            index: &index,
            origin: Origin::Root,
        };
        let reported = of_account(&as_root, "home/u", uid);
        assert_eq!(reported.len(), 2);
        assert_eq!(reported[0].body, Body::Binary(WITHHELD));
        assert!(reported[0].sha256.is_some());
        assert_eq!(reported[1].body, Body::Link("/dev/null".into()));
        // Another account sees the same two while it may enter the home,
        // and nothing once it may not.
        if uid != 0 {
            assert_eq!(of_account(&as_root, "home/u", uid + 1).len(), 2);
            fs::set_permissions(root.join("home/u"), fs::Permissions::from_mode(0o700)).unwrap();
            assert!(of_account(&as_root, "home/u", uid + 1).is_empty());
        }
    }

    /// Whether `item` is an override not read for `why`, with the alert.
    fn is_unread(item: &crate::sweep::collect::Item, why: &str) -> bool {
        item.sha256.is_none()
            && item.body == Body::Unreadable(why.into())
            && item
                .alerts
                .iter()
                .any(|(rule, _)| *rule == RuleId::GuardianOverride)
    }

    #[test]
    fn a_drop_in_whose_name_is_not_utf8_is_an_override_not_read() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let dir = TempDir::new("sweep-own-unnamed");
        let root = dir.path();
        let uid = fs::metadata(root).unwrap().uid();
        let holder = "home/u/.config/systemd/user/omarchy-guardian-sweep.service.d";
        fs::create_dir_all(root.join(holder)).unwrap();
        // systemd reads it: a drop-in is any name ending in `.conf`.
        let name = OsStr::from_bytes(b"\xff.conf");
        fs::write(root.join(holder).join(name), "[Service]\nExecStart=\n").unwrap();
        let shown = format!("{holder}/\\xff.conf");
        let is_unread_alert =
            |item: &crate::sweep::collect::Item| item.path == shown && is_unread(item, UNNAMED);
        let index = PackageIndex::with_foreign(HashSet::new());
        let scope = Scope {
            root,
            home: Some("home/u"),
            index: &index,
            origin: Origin::System,
        };
        assert!(collect(&scope).items.iter().any(is_unread_alert));
        assert_eq!(standing(root, Some("home/u")), std::slice::from_ref(&shown));
        let as_root = Scope {
            root,
            home: Some("root"),
            index: &index,
            origin: Origin::Root,
        };
        let reported = of_account(&as_root, "home/u", uid);
        assert!(reported.iter().any(is_unread_alert), "{reported:?}");
    }

    #[test]
    fn a_name_that_is_not_utf8_hides_no_other_override() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let dir = TempDir::new("sweep-own-collide");
        let root = dir.path();
        let uid = fs::metadata(root).unwrap().uid();
        let holder = "home/u/.config/systemd/user/omarchy-guardian-sweep.service.d";
        fs::create_dir_all(root.join(holder)).unwrap();
        // Two names that are not UTF-8, the character a lossy reading
        // would show for either, and the four characters `\xff`.
        for name in [&b"\xff.conf"[..], b"\xfe.conf", "\u{fffd}.conf".as_bytes()] {
            fs::write(root.join(holder).join(OsStr::from_bytes(name)), "").unwrap();
        }
        fs::write(
            root.join(format!("{holder}/\\xff.conf")),
            "ExecStart=/evil\n",
        )
        .unwrap();
        let index = PackageIndex::with_foreign(HashSet::new());
        let as_root = Scope {
            root,
            home: Some("root"),
            index: &index,
            origin: Origin::Root,
        };
        let reported = of_account(&as_root, "home/u", uid);
        let mut seen: Vec<(&str, bool)> = reported
            .iter()
            .map(|item| (item.path.rsplit('/').next().unwrap(), item.sha256.is_some()))
            .collect();
        seen.sort_unstable();
        // `\xff.conf` stands for two overrides: the one that could be read,
        // by its hash, and the one that could not.
        assert_eq!(
            seen,
            [
                ("\\xfe.conf", false),
                ("\\xff.conf", false),
                ("\\xff.conf", true),
                ("\u{fffd}.conf", true)
            ]
        );
    }

    /// A drop-in directory below `root` holding a file named by the byte
    /// `\xff` and a decoy named by the four characters `\xff`, which
    /// `read::link_text` writes the same: the decoy's path, which is the
    /// path both are reported by.
    fn with_decoy(root: &std::path::Path) -> String {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let holder = "home/u/.config/systemd/user/omarchy-guardian-sweep.service.d";
        fs::create_dir_all(root.join(holder)).unwrap();
        let unnamed = root.join(holder).join(OsStr::from_bytes(b"\xff.conf"));
        fs::write(unnamed, "[Service]\nExecStart=/evil\n").unwrap();
        let decoy = format!("{holder}/\\xff.conf");
        fs::write(root.join(&decoy), "").unwrap();
        decoy
    }

    #[test]
    fn a_name_that_reads_as_another_is_reported_beside_it() {
        let dir = TempDir::new("sweep-own-collide-both");
        let root = dir.path();
        let uid = fs::metadata(root).unwrap().uid();
        let path = with_decoy(root);
        // The bar shows paths only, so the one path once.
        let standing = standing(root, Some("home/u"));
        assert_eq!(standing, std::slice::from_ref(&path));
        let index = PackageIndex::with_foreign(HashSet::new());
        let scope = Scope {
            root,
            home: Some("home/u"),
            index: &index,
            origin: Origin::User,
        };
        let (paths, not_read) = super::paths(&scope);
        assert_eq!(paths, std::slice::from_ref(&path));
        assert!(
            not_read.len() == 1 && not_read[0].path == path && is_unread(&not_read[0], UNNAMED),
            "{not_read:?}"
        );
        let as_root = Scope {
            root,
            home: Some("root"),
            index: &index,
            origin: Origin::Root,
        };
        let reported = of_account(&as_root, "home/u", uid);
        assert_eq!(reported.len(), 2, "{reported:?}");
        assert!(reported.iter().all(|item| item.path == path));
        assert!(reported.iter().any(|item| item.sha256.is_some()));
        assert!(reported.iter().any(|item| is_unread(item, UNNAMED)));
    }

    #[test]
    fn deleting_the_decoy_after_listing_hides_no_override_from_root() {
        let dir = TempDir::new("sweep-own-decoy-gone");
        let root = dir.path();
        let uid = fs::metadata(root).unwrap().uid();
        let path = with_decoy(root);
        let index = PackageIndex::with_foreign(HashSet::new());
        let as_root = Scope {
            root,
            home: Some("root"),
            index: &index,
            origin: Origin::Root,
        };
        let looks = Looks::new(&as_root, View::Owner(uid));
        let found = looks.candidates("home/u", uid);
        // As the account would, watching its own directory for root's
        // listing: the decoy is gone before root looks at it.
        fs::remove_file(root.join(&path)).unwrap();
        let reported = looks.report(found);
        assert!(
            reported.len() == 1 && reported[0].path == path && is_unread(&reported[0], UNNAMED),
            "{reported:?}"
        );
    }

    #[test]
    fn root_hashes_only_so_many_bytes_of_an_accounts_drop_ins() {
        let dir = TempDir::new("sweep-own-bytes");
        let root = dir.path();
        let uid = fs::metadata(root).unwrap().uid();
        let holder = root.join("home/u/.config/systemd/user/omarchy-guardian-sweep.service.d");
        fs::create_dir_all(&holder).unwrap();
        // One file at the limit for each, named many times: the first
        // names are hashed until the account's bytes run out.
        let large = holder.join("a00.conf");
        fs::write(&large, vec![b'#'; usize::try_from(MAX_UNIT_BYTES).unwrap()]).unwrap();
        let names = MAX_ACCOUNT_BYTES / MAX_UNIT_BYTES + 4;
        for at in 1..names {
            fs::hard_link(&large, holder.join(format!("a{at:02}.conf"))).unwrap();
        }
        // Files past the limit for one file are turned away by their size,
        // and cost nothing: they come first, and every byte of the
        // account's budget is still hashed.
        let padded = fs::File::create(holder.join("0.conf")).unwrap();
        padded.set_len(MAX_UNIT_BYTES + 1).unwrap();
        for at in 1..=names {
            fs::hard_link(holder.join("0.conf"), holder.join(format!("{at:02}.conf"))).unwrap();
        }
        // Neither does what is no file.
        for at in 0..names {
            symlink("/dev/null", holder.join(format!("+{at:02}.conf"))).unwrap();
        }
        let index = PackageIndex::with_foreign(HashSet::new());
        let as_root = Scope {
            root,
            home: Some("root"),
            index: &index,
            origin: Origin::Root,
        };
        let reported = of_account(&as_root, "home/u", uid);
        let hashed = |item: &&crate::sweep::collect::Item| item.sha256.is_some();
        assert_eq!(
            reported.iter().filter(hashed).count(),
            usize::try_from(MAX_ACCOUNT_BYTES / MAX_UNIT_BYTES).unwrap()
        );
        assert_eq!(reported.len(), usize::try_from(3 * names + 1).unwrap());
        let name =
            |item: &crate::sweep::collect::Item| item.path.rsplit('/').next().unwrap().to_owned();
        for item in reported
            .iter()
            .filter(|item| !hashed(item) && !matches!(item.body, Body::Link(_)))
        {
            // The padded files are told by their own size, the rest by the
            // account's spent budget.
            let why = if name(item).starts_with('a') {
                PAST_BOUND
            } else {
                TOO_BIG
            };
            assert!(is_unread(item, why), "{item:?}");
        }
        // `TOO_BIG` gives the bound in words.
        assert!(TOO_BIG.contains("1 MiB") && MAX_UNIT_BYTES == 1 << 20);
    }

    #[test]
    fn small_drop_ins_cost_only_their_own_bytes() {
        let dir = TempDir::new("sweep-own-small");
        let root = dir.path();
        let uid = fs::metadata(root).unwrap().uid();
        let holder = root.join("home/u/.config/systemd/user/omarchy-guardian-sweep.service.d");
        fs::create_dir_all(&holder).unwrap();
        // More small files than the budget holds files at the limit: were
        // each charged the limit, the last would go unhashed.
        let count = MAX_ACCOUNT_BYTES / MAX_UNIT_BYTES + 8;
        for at in 0..count {
            fs::write(holder.join(format!("{at:02}.conf")), format!("# {at}\n")).unwrap();
        }
        let index = PackageIndex::with_foreign(HashSet::new());
        let as_root = Scope {
            root,
            home: Some("root"),
            index: &index,
            origin: Origin::Root,
        };
        let reported = of_account(&as_root, "home/u", uid);
        assert_eq!(reported.len(), usize::try_from(count).unwrap());
        assert!(
            reported.iter().all(|item| item.sha256.is_some()),
            "{reported:?}"
        );
    }

    #[test]
    fn a_look_is_charged_what_it_hashed_or_its_bound() {
        let hashed = Found::File {
            sha256: crate::sha256::Sha256::digest(b""),
            mode: 0o644,
            size: 7,
            head: Vec::new(),
        };
        assert_eq!(charged(&hashed, Some(7), 100), 7);
        // A regular file not hashed after all grew or failed as it was read.
        assert_eq!(
            charged(&Found::Unreadable(NOT_READ.into()), Some(7), 100),
            100
        );
        assert_eq!(charged(&Found::Other, None, 100), 0);
    }

    #[test]
    fn a_drop_in_directory_is_read_to_a_bound() {
        let dir = TempDir::new("sweep-own-many");
        let root = dir.path();
        let holder = "etc/systemd/system/omarchy-guardian-sweep-collect.service.d";
        fs::create_dir_all(root.join(holder)).unwrap();
        for at in 1..=MAX_DROP_INS {
            fs::write(root.join(holder).join(format!("{at}.conf")), "").unwrap();
        }
        assert_eq!(standing(root, None).len(), MAX_DROP_INS);
        // One more, and which names would be kept is up to the order the
        // directory lists them in: the directory is the override.
        fs::write(root.join(holder).join("0.conf"), "").unwrap();
        assert_eq!(standing(root, None), [holder]);
        assert!(CROWDED.contains(&MAX_DROP_INS.to_string()));
    }

    #[test]
    fn a_drop_in_directory_with_too_many_names_is_one_override_not_read() {
        let dir = TempDir::new("sweep-own-crowded");
        let root = dir.path();
        let uid = fs::metadata(root).unwrap().uid();
        let holder = "home/u/.config/systemd/user/omarchy-guardian-sweep.service.d";
        fs::create_dir_all(root.join(holder)).unwrap();
        fs::write(root.join(holder).join("evil.conf"), "ExecStart=/evil\n").unwrap();
        for at in 0..MAX_DROP_INS {
            fs::write(root.join(holder).join(format!("junk{at:03}")), "").unwrap();
        }
        let is_crowded =
            |item: &crate::sweep::collect::Item| item.path == holder && is_unread(item, CROWDED);
        let index = PackageIndex::with_foreign(HashSet::new());
        let as_root = Scope {
            root,
            home: Some("root"),
            index: &index,
            origin: Origin::Root,
        };
        let reported = of_account(&as_root, "home/u", uid);
        assert!(
            reported.len() == 1 && is_crowded(&reported[0]),
            "{reported:?}"
        );
        let scope = Scope {
            root,
            home: Some("home/u"),
            index: &index,
            origin: Origin::System,
        };
        assert!(collect(&scope).items.iter().any(is_crowded));
        assert_eq!(standing(root, Some("home/u")), [holder]);
    }

    #[test]
    fn a_unit_where_systemd_looks_before_the_packages_directory_is_an_override() {
        let dir = TempDir::new("sweep-own-ahead");
        let root = dir.path();
        let index = PackageIndex::with_foreign(HashSet::new());
        let scope = Scope {
            root,
            home: Some("home/u"),
            index: &index,
            origin: Origin::System,
        };
        let ahead = "usr/share/systemd/user/omarchy-guardian-sweep.service";
        fs::create_dir_all(root.join(ahead).parent().unwrap()).unwrap();
        fs::write(root.join(ahead), "[Service]\nExecStart=/usr/bin/true\n").unwrap();
        assert_eq!(standing(root, None), [ahead]);
        let replaced = collect(&scope);
        assert!(replaced.items.iter().any(|item| {
            item.path == ahead
                && item
                    .alerts
                    .iter()
                    .any(|(rule, _)| *rule == RuleId::GuardianOverride)
        }));
    }

    #[test]
    fn root_reports_an_override_it_cannot_hash_by_its_path() {
        let dir = TempDir::new("sweep-own-unread");
        let root = dir.path();
        let uid = fs::metadata(root).unwrap().uid();
        let drop_ins = root.join("home/u/.config/systemd/user/omarchy-guardian-sweep.service.d");
        fs::create_dir_all(&drop_ins).unwrap();
        fs::write(drop_ins.join("read.conf"), "[Service]\n").unwrap();
        let index = PackageIndex::with_foreign(HashSet::new());
        let as_root = Scope {
            root,
            home: Some("root"),
            index: &index,
            origin: Origin::Root,
        };
        // What is there and cannot be hashed is reported too, without a
        // hash: a drop-in closed to its own account, one that is no file,
        // and one padded past the read limit.
        fs::write(drop_ins.join("closed.conf"), "[Service]\nExecStart=\n").unwrap();
        fs::set_permissions(
            drop_ins.join("closed.conf"),
            fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        fs::create_dir(drop_ins.join("odd.conf")).unwrap();
        let padded = fs::File::create(drop_ins.join("padded.conf")).unwrap();
        padded
            .set_len(crate::scan::MAX_HASHED_FILE_SIZE + 1)
            .unwrap();
        let reported = of_account(&as_root, "home/u", uid);
        let unread: Vec<&str> = reported
            .iter()
            .filter(|item| matches!(item.body, Body::Unreadable(_)))
            .map(|item| {
                assert_eq!(item.sha256, None);
                assert!(
                    item.alerts
                        .iter()
                        .any(|(rule, _)| *rule == RuleId::GuardianOverride)
                );
                item.path.rsplit('/').next().unwrap()
            })
            .collect();
        // Closed is what the file's mode says to its account, not what the
        // reader can open: root, which opens everything, reports the same.
        assert_eq!(unread, ["closed.conf", "odd.conf", "padded.conf"]);
        assert_eq!(reported.len(), 4);
        // An account that may not enter the directory is told nothing.
        fs::set_permissions(root.join("home/u"), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(of_account(&as_root, "home/u", uid + 1).is_empty());
    }

    #[test]
    fn a_unit_directory_that_is_a_link_is_followed_as_its_account_follows_it() {
        let dir = TempDir::new("own-linked");
        let root = dir.path();
        let uid = fs::metadata(root).unwrap().uid();
        let dotfiles = root.join("home/u/dotfiles/user");
        fs::create_dir_all(dotfiles.join("omarchy-guardian-sweep.service.d")).unwrap();
        fs::write(
            dotfiles.join("omarchy-guardian-sweep.service.d/evil.conf"),
            "[Service]\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("home/u/.config/systemd")).unwrap();
        // As GNU stow links it, and systemd follows it: the override is
        // reported and hashed by the path systemd reads it at, so the
        // account's own sweep can clear it, and the drop-in directories
        // behind the link that are not there are not reported.
        symlink(
            "../../dotfiles/user",
            root.join("home/u/.config/systemd/user"),
        )
        .unwrap();
        // The link is the account's, not the root owner's alone, so root's
        // walk does not follow it by itself.
        fs::set_permissions(
            root.join("home/u/.config/systemd"),
            fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        let index = PackageIndex::with_foreign(HashSet::new());
        let as_root = Scope {
            root,
            home: Some("root"),
            index: &index,
            origin: Origin::Root,
        };
        let reported = of_account(&as_root, "home/u", uid + 1);
        let paths: Vec<&str> = reported.iter().map(|item| item.path.as_str()).collect();
        assert_eq!(
            paths,
            ["home/u/.config/systemd/user/omarchy-guardian-sweep.service.d/evil.conf"]
        );
        assert!(reported[0].sha256.is_some());
        // A link not followed to its end (a loop) is one item, not read.
        fs::remove_file(root.join("home/u/.config/systemd/user")).unwrap();
        symlink("user", root.join("home/u/.config/systemd/user")).unwrap();
        let reported = of_account(&as_root, "home/u", uid + 1);
        assert!(
            reported
                .iter()
                .any(|item| item.path == "home/u/.config/systemd/user"
                    && matches!(item.body, Body::Unreadable(_))),
            "{:?}",
            reported.iter().map(|item| &item.path).collect::<Vec<_>>()
        );
    }

    /// A root as `a_unit_directory_that_is_a_link_is_followed_as_its_account_follows_it`
    /// sets it up: `home/u/.config/systemd/user` a link of the account's to
    /// `home/u/dotfiles/user`.
    fn stowed(dir: &TempDir) -> std::path::PathBuf {
        let root = dir.path();
        fs::create_dir_all(root.join("home/u/dotfiles/user")).unwrap();
        fs::create_dir_all(root.join("home/u/.config/systemd")).unwrap();
        symlink(
            "../../dotfiles/user",
            root.join("home/u/.config/systemd/user"),
        )
        .unwrap();
        fs::set_permissions(
            root.join("home/u/.config/systemd"),
            fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        root.join("home/u/dotfiles/user")
    }

    #[test]
    fn a_directory_the_account_may_enter_but_not_list_is_not_listed() {
        let dir = TempDir::new("own-unlisted");
        let root = dir.path();
        let uid = fs::metadata(root).unwrap().uid();
        let holder = stowed(&dir).join("omarchy-guardian-sweep.service.d");
        fs::create_dir_all(&holder).unwrap();
        fs::write(holder.join("secret-name.conf"), "[Service]\n").unwrap();
        // Another account's directory, which others may enter and not list.
        fs::set_permissions(&holder, fs::Permissions::from_mode(0o711)).unwrap();
        let index = PackageIndex::with_foreign(HashSet::new());
        let as_root = Scope {
            root,
            home: Some("root"),
            index: &index,
            origin: Origin::Root,
        };
        let reported = of_account(&as_root, "home/u", uid + 1);
        fs::set_permissions(&holder, fs::Permissions::from_mode(0o755)).unwrap();
        let paths: Vec<&str> = reported.iter().map(|item| item.path.as_str()).collect();
        assert_eq!(
            paths,
            ["home/u/.config/systemd/user/omarchy-guardian-sweep.service.d"]
        );
        assert!(matches!(reported[0].body, Body::Unreadable(_)));
    }

    #[test]
    fn a_way_swapped_for_a_link_after_it_was_resolved_is_not_read() {
        let dir = TempDir::new("own-swapped");
        let root = dir.path();
        let uid = fs::metadata(root).unwrap().uid();
        fs::create_dir_all(root.join("home/u/elsewhere")).unwrap();
        fs::write(root.join("home/u/elsewhere/evil.conf"), "[Service]\n").unwrap();
        // Where the way was resolved to is now a link of the account's.
        symlink("elsewhere", root.join("home/u/swapped")).unwrap();
        fs::set_permissions(root.join("home/u"), fs::Permissions::from_mode(0o777)).unwrap();
        let index = PackageIndex::with_foreign(HashSet::new());
        let as_root = Scope {
            root,
            home: Some("root"),
            index: &index,
            origin: Origin::Root,
        };
        let holder = "home/u/.config/systemd/user/omarchy-guardian-sweep.service.d";
        let looks = Looks::new(&as_root, View::Owner(uid + 1));
        looks
            .resolved
            .borrow_mut()
            .insert(holder.into(), Ok(Some("home/u/swapped".into())));
        let Listed::Names(listed) = looks.list(holder) else {
            panic!("a swapped directory is not crowded");
        };
        assert!(listed.names.is_empty() && listed.unnamed.is_empty());
        assert_eq!(looks.not_listed.take(), [(holder.to_string(), NOT_READ)]);
        assert!(matches!(
            looks.found_at(&format!("{holder}/evil.conf")),
            Some((None, Body::Unreadable(_)))
        ));
    }

    #[test]
    fn what_is_left_past_the_parts_budget_is_told_from_what_is_closed() {
        let dir = TempDir::new("own-spent");
        let root = dir.path();
        let uid = fs::metadata(root).unwrap().uid();
        let holder = "home/u/.config/systemd/user/omarchy-guardian-sweep.service.d";
        fs::create_dir_all(root.join(holder)).unwrap();
        fs::write(root.join(holder).join("evil.conf"), "[Service]\n").unwrap();
        symlink("loop", root.join("home/u/loop")).unwrap();
        let index = PackageIndex::with_foreign(HashSet::new());
        let as_root = Scope {
            root,
            home: Some("root"),
            index: &index,
            origin: Origin::Root,
        };
        let looks = Looks::new(&as_root, View::Owner(uid));
        looks
            .resolved
            .borrow_mut()
            .insert(holder.into(), Ok(Some(holder.into())));
        assert_eq!(looks.real("home/u/loop/x"), Err(NOT_READ));
        looks.parts_left.set(0);
        assert_eq!(looks.real("home/u/.config"), Err(PAST_BOUND));
        assert!(matches!(looks.list(holder), Listed::Names(_)));
        assert_eq!(looks.not_listed.take(), [(holder.to_string(), PAST_BOUND)]);
        assert_eq!(
            looks.found_at(&format!("{holder}/evil.conf")),
            Some((None, Body::Unreadable(PAST_BOUND.into())))
        );
    }

    #[test]
    fn the_looks_at_one_account_are_bounded_and_an_honest_one_fits() {
        let dir = TempDir::new("own-budget");
        let root = dir.path();
        let uid = fs::metadata(root).unwrap().uid();
        let user = stowed(&dir);
        for unit in USER_UNITS {
            for holder in drop_in_directories(unit) {
                fs::create_dir_all(user.join(&holder)).unwrap();
                for at in 0..MAX_DROP_INS {
                    fs::write(user.join(&holder).join(format!("{at}.conf")), "").unwrap();
                }
            }
        }
        let holders: usize = USER_UNITS
            .iter()
            .map(|unit| drop_in_directories(unit).len())
            .sum();
        let index = PackageIndex::with_foreign(HashSet::new());
        let as_root = Scope {
            root,
            home: Some("root"),
            index: &index,
            origin: Origin::Root,
        };
        // Every drop-in an honest account may have is read.
        let reported = of_account(&as_root, "home/u", uid + 1);
        assert_eq!(reported.len(), holders * MAX_DROP_INS);
        assert!(reported.iter().all(|item| item.sha256.is_some()));
        // `~/.config` behind 230 directories and a link back: each look
        // walks those parts, and past the budget what is left is not read.
        let deep = vec!["d"; 230].join("/");
        fs::create_dir_all(root.join("home/u").join(&deep)).unwrap();
        symlink(
            root.join("home/u/real")
                .strip_prefix(root)
                .map(|path| std::path::Path::new("/").join(path))
                .unwrap(),
            root.join("home/u").join(&deep).join("back"),
        )
        .unwrap();
        fs::rename(root.join("home/u/.config"), root.join("home/u/real")).unwrap();
        symlink(format!("{deep}/back"), root.join("home/u/.config")).unwrap();
        fs::set_permissions(root.join("home/u"), fs::Permissions::from_mode(0o777)).unwrap();
        let reported = of_account(&as_root, "home/u", uid + 1);
        assert!(
            reported.len() <= holders * MAX_DROP_INS + 16,
            "{} items",
            reported.len()
        );
        assert!(
            reported
                .iter()
                .any(|item| item.path.starts_with("home/u/.config") && is_unread(item, PAST_BOUND)),
            "{:?}",
            reported.iter().map(|item| &item.path).collect::<Vec<_>>()
        );
    }

    #[test]
    fn overrides_below_a_home_that_is_a_link_of_roots_are_each_reported() {
        let dir = TempDir::new("own-home-link");
        let root = dir.path();
        let uid = fs::metadata(root).unwrap().uid();
        let drop_ins = root.join("data/u/.config/systemd/user/omarchy-guardian-sweep.service.d");
        fs::create_dir_all(&drop_ins).unwrap();
        fs::write(drop_ins.join("evil.conf"), "[Service]\n").unwrap();
        fs::create_dir_all(root.join("home")).unwrap();
        symlink("../data/u", root.join("home/u")).unwrap();
        let index = PackageIndex::with_foreign(HashSet::new());
        let as_root = Scope {
            root,
            home: Some("root"),
            index: &index,
            origin: Origin::Root,
        };
        let reported = of_account(&as_root, "home/u", uid + 1);
        let paths: Vec<&str> = reported.iter().map(|item| item.path.as_str()).collect();
        assert_eq!(
            paths,
            ["home/u/.config/systemd/user/omarchy-guardian-sweep.service.d/evil.conf"]
        );
        assert!(reported[0].sha256.is_some());
    }

    #[test]
    fn a_unit_directory_root_cannot_look_into_is_reported() {
        let dir = TempDir::new("own-refused");
        let root = dir.path();
        let uid = fs::metadata(root).unwrap().uid();
        fs::create_dir_all(root.join("home/u/.config/systemd/user")).unwrap();
        let index = PackageIndex::with_foreign(HashSet::new());
        let as_root = Scope {
            root,
            home: Some("root"),
            index: &index,
            origin: Origin::Root,
        };
        // Another account may enter it, by the mode; the reader, its owner
        // here, may not look inside (as root on an account's FUSE mount).
        let systemd = root.join("home/u/.config/systemd");
        fs::set_permissions(&systemd, fs::Permissions::from_mode(0o445)).unwrap();
        let blocked = fs::symlink_metadata(systemd.join("user")).is_err();
        let reported = of_account(&as_root, "home/u", uid + 1);
        fs::set_permissions(&systemd, fs::Permissions::from_mode(0o755)).unwrap();
        if !blocked {
            // Root reads past the mode.
            return;
        }
        // One item for each directory below the one it was kept out of.
        let paths: Vec<&str> = reported.iter().map(|item| item.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "home/u/.config/systemd/user",
                "home/u/.config/systemd/user.control",
                "home/u/.config/systemd/user.attached"
            ]
        );
        assert!(reported.iter().all(|item| {
            matches!(item.body, Body::Unreadable(_))
                && item
                    .alerts
                    .iter()
                    .any(|(rule, _)| *rule == RuleId::GuardianOverride)
        }));
        // A home root cannot look into at all is one item.
        fs::set_permissions(root.join("home"), fs::Permissions::from_mode(0o445)).unwrap();
        let reported = of_account(&as_root, "home/u", uid + 1);
        fs::set_permissions(root.join("home"), fs::Permissions::from_mode(0o755)).unwrap();
        let paths: Vec<&str> = reported.iter().map(|item| item.path.as_str()).collect();
        assert_eq!(paths, ["home/u"]);
        // So is a drop-in directory root cannot look into.
        let holder = root
            .join("home/u/.config/systemd/user")
            .join(&drop_in_directories(USER_UNITS[0])[0]);
        fs::create_dir(&holder).unwrap();
        fs::write(holder.join("evil.conf"), "[Service]\n").unwrap();
        fs::set_permissions(&holder, fs::Permissions::from_mode(0o055)).unwrap();
        let reported = of_account(&as_root, "home/u", uid + 1);
        fs::set_permissions(&holder, fs::Permissions::from_mode(0o755)).unwrap();
        let shown = holder.strip_prefix(root).unwrap().to_str().unwrap();
        assert!(
            reported.iter().any(|item| item.path == shown
                && matches!(item.body, Body::Unreadable(_))
                && item
                    .alerts
                    .iter()
                    .any(|(rule, _)| *rule == RuleId::GuardianOverride)),
            "{:?}",
            reported.iter().map(|item| &item.path).collect::<Vec<_>>()
        );
    }
}
