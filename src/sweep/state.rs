//! What the sweep remembers between runs, in a private `sweep` directory of
//! the review store: the last sweep's untrusted items (so `--diff` and the
//! schedule report only what is new or changed). The items the user allowed
//! (`sweep allow`), each by its label and content hash so that a changed
//! file is looked at again, are kept in a list only root writes: a program
//! running as the user could otherwise allow its own autostart entry.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::collect::Item;
use super::tier::Tier;
use crate::engine::store;
use crate::json::Json;

const BASELINE: &str = "baseline.json";
const ALLOWED: &str = "allowed.json";
const TOLD: &str = "told.json";
const LAST_RUN: &str = "last-run.json";
const STARTED: &str = "started";
/// The most reasons an unfinished sweep keeps.
const MAX_REASONS: usize = 5;
/// The longest reason, and the largest record, read back.
const MAX_REASON_CHARS: usize = 300;
const MAX_RECORD_BYTES: u64 = 64 * 1024;

/// The sweep's directory in the review store.
pub fn directory(store_root: &Path) -> Result<PathBuf, String> {
    let uid = store::effective_uid()?;
    store::private_dir(store_root, uid)?;
    let directory = store_root.join("sweep");
    store::private_dir(&directory, uid)?;
    Ok(directory)
}

/// An item's content hash as remembered: the file's SHA-256, or for a link
/// its target, or `-` when it could not be read.
pub fn fingerprint(item: &Item) -> String {
    let content = match (&item.sha256, &item.body) {
        (Some(digest), _) => digest.to_string(),
        (None, super::collect::Body::Link(target)) => format!("link:{target}"),
        (None, _) => UNREAD.into(),
    };
    // What the live checks saw is part of it: allowing a program that
    // autostarts does not allow it to start reading the keyboard.
    let mut alerts: Vec<&str> = item.alerts.iter().map(|(rule, _)| rule.name()).collect();
    alerts.sort_unstable();
    alerts.dedup();
    if alerts.is_empty() {
        content
    } else {
        format!("{content}+{}", alerts.join(","))
    }
}

/// The mark on the remembered fingerprint of an item with a finding.
pub const FLAGGED: &str = "+finding";

/// The fingerprint of an item that could not be read (and raised no
/// alert): only this one carries over a previous fingerprint.
pub const UNREAD: &str = "-";

/// Label to fingerprint.
pub type Remembered = BTreeMap<String, String>;

fn read(path: &Path) -> Remembered {
    let Some(json) = fs::read_to_string(path)
        .ok()
        .and_then(|text| Json::parse(&text).ok())
    else {
        return Remembered::new();
    };
    json.as_object()
        .unwrap_or_default()
        .iter()
        .filter_map(|(label, value)| Some((label.clone(), value.as_str()?.to_string())))
        .collect()
}

fn write(path: &Path, remembered: &Remembered) -> Result<(), String> {
    let json = Json::object(
        remembered
            .iter()
            .map(|(label, value)| (label.as_str(), Json::from(value.as_str()))),
    );
    write_text(path, &json.to_string())
}

fn write_text(path: &Path, text: &str) -> Result<(), String> {
    write_text_mode(path, text, 0o600)
}

/// Writes `text` to `path` through a new file and a rename, so a reader
/// never sees half of it. The file has exactly `mode`, whatever the umask
/// of the process: the root collector runs with one that would close a
/// list everyone is meant to read.
pub fn write_text_mode(path: &Path, text: &str, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;
    let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
    drop(fs::remove_file(&temporary));
    let result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temporary)
        .and_then(|mut file| {
            file.set_permissions(fs::Permissions::from_mode(mode))?;
            file.write_all(text.as_bytes())
        })
        .and_then(|()| fs::rename(&temporary, path));
    if result.is_err() {
        drop(fs::remove_file(&temporary));
    }
    result.map_err(|error| format!("{}: {error}", path.display()))
}

/// The list an older Guardian kept in the user's own state directory. It
/// counts for nothing now: whatever runs as the user can write it.
pub fn old_allowed(directory: &Path) -> Remembered {
    read(&directory.join(ALLOWED))
}

/// Where allowed items are kept: a list only root writes (through sudo),
/// so a program running as the user cannot add to it. A home's items are
/// kept under the user id they were allowed for, and every user reads it:
/// it sits where everyone may, not beside root's results, whose directory
/// only one group may enter.
pub const SYSTEM_ALLOWED: &str = "/var/lib/omarchy-guardian/allowed.json";

/// Where Guardian up to 0.7.18 kept that list: in the directory of root's
/// results. A user outside that directory's group could add to the list
/// through sudo and never read it back, so nothing they allowed counted.
/// Root moves it on its next write (`move_legacy_allowed`); until then a
/// sweep that can still reach it reads it there.
pub const LEGACY_SYSTEM_ALLOWED: &str = "/var/lib/omarchy-guardian/sweep/allowed.json";

/// The most the system list may hold; one that grew past it would read as
/// empty.
const MAX_SYSTEM_LIST_BYTES: u64 = MAX_RECORD_BYTES * 16;

/// How `label` is kept in the system list for user `uid`: a home's label
/// (`~/.bashrc`) with the user id before it (`1000:~/.bashrc`), so that
/// what one user allowed in their home says nothing about another's.
pub fn system_key(label: &str, uid: u32) -> String {
    if is_home_label(label) {
        format!("{uid}:{label}")
    } else {
        label.to_string()
    }
}

/// What of the system list `system` counts for user `uid`, by the labels
/// the sweep shows: the system's items, and that user's own home items.
pub fn allowed_for(system: &Remembered, uid: u32) -> Remembered {
    system
        .iter()
        .filter_map(|(key, fingerprint)| {
            let label = if key.starts_with('/') {
                key.as_str()
            } else {
                let (owner, label) = key.split_once(':')?;
                (owner.parse::<u32>().ok()? == uid && is_home_label(label)).then_some(label)?
            };
            Some((label.to_string(), fingerprint.clone()))
        })
        .collect()
}

/// Why `item` cannot be allowed as it is, if it cannot.
pub fn not_allowable(item: &Item) -> Option<&'static str> {
    if item
        .alerts
        .iter()
        .any(|(rule, _)| *rule == crate::rules::RuleId::GuardianOverride)
    {
        // Allowing it would let whatever wrote it quiet the sweep it
        // redirects.
        return Some("it changes Guardian's own sweep, which an allow does not cover; remove it");
    }
    if super::collect::is_capped(item) {
        // An allow vouches for what the item runs, and nobody looked for
        // all of that.
        return Some(
            "not all of what it runs was followed, so it cannot be vouched for as a whole",
        );
    }
    None
}

/// Whether a label names something in the user's own home.
pub fn is_home_label(label: &str) -> bool {
    label.starts_with("~/")
}

/// The directory above everything Guardian's root halves write.
pub const ROOT_STATE_ANCHOR: &str = "/var/lib";

/// Whether the file at `path` is `owner`'s alone to write: a regular file
/// of at most `max_bytes`, which, like every directory above it up to
/// `anchor`, is owned by `owner` and not writable by a group or by
/// everyone. For root's state, `owner` is 0 and `anchor` is `/var/lib`.
pub fn owned_alone(path: &Path, owner: u32, anchor: &Path, max_bytes: u64) -> bool {
    let alone = |path: &Path| {
        fs::symlink_metadata(path)
            .is_ok_and(|metadata| metadata.uid() == owner && metadata.mode() & 0o022 == 0)
    };
    let mut directory = path.parent();
    while let Some(current) = directory {
        if !alone(current) {
            return false;
        }
        if current == anchor {
            break;
        }
        directory = current.parent();
    }
    let regular = fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.len() <= max_bytes);
    regular && alone(path)
}

/// The system list at `path`, while it and the directories above it up to
/// `/var/lib` are root's and nobody else may write them; empty otherwise.
pub fn system_allowed(path: &Path) -> Remembered {
    roots().list(path)
}

/// Whose a list of allowed items must be to count, and below which
/// directory: root's, below `/var/lib`. A test plays root with its own
/// user and directory.
#[derive(Clone, Copy)]
struct Keeper<'a> {
    owner: u32,
    anchor: &'a Path,
}

fn roots() -> Keeper<'static> {
    Keeper {
        owner: 0,
        anchor: Path::new(ROOT_STATE_ANCHOR),
    }
}

impl Keeper<'_> {
    /// The list at `path` while it is the keeper's alone; empty otherwise.
    fn list(self, path: &Path) -> Remembered {
        if !owned_alone(path, self.owner, self.anchor, MAX_SYSTEM_LIST_BYTES) {
            return Remembered::new();
        }
        read(path)
    }

    /// The list at `system`, or where there is none yet, the one an older
    /// Guardian left at `legacy`.
    fn current(self, system: &Path, legacy: &Path) -> Remembered {
        if fs::symlink_metadata(system).is_ok() {
            self.list(system)
        } else {
            self.list(legacy)
        }
    }

    /// See `move_legacy_allowed`.
    fn move_legacy(self, path: &Path, legacy: &Path) -> Result<(), String> {
        if fs::symlink_metadata(legacy).is_err() {
            return Ok(());
        }
        if fs::symlink_metadata(path).is_err() {
            let old = self.list(legacy);
            if !old.is_empty() {
                save_system_allowed(path, &old)?;
            }
        }
        fs::remove_file(legacy).map_err(|error| format!("{}: {error}", legacy.display()))
    }
}

/// What counts as allowed for user `uid`: only what the system list at
/// `system` holds, which only root writes. Where root has not written that
/// one yet, the list an older Guardian left at `legacy` stands in.
pub fn all_allowed(system: &Path, legacy: &Path, uid: u32) -> Remembered {
    allowed_for(&roots().current(system, legacy), uid)
}

/// `all_allowed` of this system's list.
pub fn allowed_here(uid: u32) -> Remembered {
    all_allowed(
        Path::new(SYSTEM_ALLOWED),
        Path::new(LEGACY_SYSTEM_ALLOWED),
        uid,
    )
}

/// Moves the list an older Guardian kept at `legacy` to `path`, as root:
/// taken over as it is where there is no list at `path` yet and the old one
/// is root's alone, and removed either way, so that one list counts.
pub fn move_legacy_allowed(path: &Path, legacy: &Path) -> Result<(), String> {
    roots().move_legacy(path, legacy)
}

/// Writes the system list, as root: readable by everyone, written only by
/// root, in a directory everyone may enter.
pub fn save_system_allowed(path: &Path, allowed: &Remembered) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;
    if let Some(directory) = path.parent() {
        fs::create_dir_all(directory)
            .map_err(|error| format!("{}: {error}", directory.display()))?;
        // Whatever umask root's shell had: a list its users cannot reach
        // allows nothing. Exactly this mode, on this one directory, and
        // nothing below it is touched: root's other state lives here too.
        // `sweep/` (the collector's results, closed to all but the
        // configured group) and `permits/` (written by the permit root
        // half: root's alone to write, readable by everyone) keep the
        // modes their writers gave them, and both want what this sets on
        // their parent: everyone may enter, only root may write.
        fs::set_permissions(directory, fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("{}: {error}", directory.display()))?;
    }
    let json = Json::object(
        allowed
            .iter()
            .map(|(label, value)| (label.as_str(), Json::from(value.as_str()))),
    )
    .to_string();
    if json.len() as u64 > MAX_SYSTEM_LIST_BYTES {
        return Err("the list of allowed items is full; forget some first".into());
    }
    write_text_mode(path, &json, 0o644)
}

/// Rewrites the list an older Guardian kept (see `old_allowed`); an empty
/// one is removed.
pub fn save_old_allowed(directory: &Path, allowed: &Remembered) -> Result<(), String> {
    let path = directory.join(ALLOWED);
    if allowed.is_empty() {
        return match fs::remove_file(&path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                Err(format!("{}: {error}", path.display()))
            }
            _ => Ok(()),
        };
    }
    write(&path, allowed)
}

/// Whether a sweep has remembered anything yet.
pub fn has_baseline(directory: &Path) -> bool {
    directory.join(BASELINE).is_file()
}

pub fn baseline(directory: &Path) -> Remembered {
    read(&directory.join(BASELINE))
}

/// What the scheduled sweeps have told about so far: what the next one's
/// notification is measured against. A sweep run by hand does not write it,
/// so running one says nothing on the timer's behalf (what it finds would
/// otherwise never be notified). Installs from before it existed fall back
/// to what the last sweep remembered.
pub fn told(directory: &Path) -> Remembered {
    if directory.join(TOLD).is_file() {
        read(&directory.join(TOLD))
    } else {
        baseline(directory)
    }
}

pub fn has_told(directory: &Path) -> bool {
    directory.join(TOLD).is_file() || has_baseline(directory)
}

pub fn save_told(directory: &Path, current: &Remembered) -> Result<(), String> {
    write(&directory.join(TOLD), current)
}

/// Remembers the untrusted items of this sweep for the next `--diff`.
pub fn save_baseline(directory: &Path, current: &Remembered) -> Result<(), String> {
    write(&directory.join(BASELINE), current)
}

/// Marks items the user allowed, while they are unchanged and can be
/// allowed at all (see `not_allowable`).
pub fn apply_allowed(items: &mut [Item], allowed: &Remembered, label: impl Fn(&Item) -> String) {
    for item in items {
        if item.is_trusted() || not_allowable(item).is_some() {
            continue;
        }
        if allowed
            .get(&label(item))
            .is_some_and(|remembered| *remembered == fingerprint(item))
        {
            item.tier = Tier::Allowed;
        }
    }
}

/// How the last sweep ended, as the bar tells it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// It saw everything it looks at (and may have found something).
    Complete,
    /// It could not see or review everything.
    Incomplete,
    /// It could not run at all.
    Failed,
}

impl Outcome {
    const fn name(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Incomplete => "incomplete",
            Self::Failed => "failed",
        }
    }
}

/// The last sweep: when it ran, how it ended and, unless it was complete,
/// why. Written by every sweep, so that one which stops running, or keeps
/// ending unfinished, shows in the bar instead of going quiet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LastRun {
    /// Seconds since the epoch.
    pub at: u64,
    pub outcome: Outcome,
    pub reasons: Vec<String>,
}

impl LastRun {
    pub fn new(at: u64, outcome: Outcome, mut reasons: Vec<String>) -> Self {
        let more = reasons.len().saturating_sub(MAX_REASONS);
        reasons.truncate(MAX_REASONS);
        if more > 0 {
            reasons.push(format!("and {more} more"));
        }
        Self {
            at,
            outcome,
            reasons,
        }
    }
}

/// The last sweep's record in the store at `store_root`, without creating
/// anything (the bar only reads). A sweep from before there was a record
/// left what it remembered: that counts as a complete run of that time.
pub fn last_run_in(store_root: &Path) -> Option<LastRun> {
    let directory = store_root.join("sweep");
    // Only where there is no record at all: one that cannot be read is
    // not vouched for by what a sweep run by hand remembered.
    if fs::symlink_metadata(directory.join(LAST_RUN)).is_ok() {
        return last_run(&directory);
    }
    let at = fs::metadata(directory.join(BASELINE))
        .ok()?
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some(LastRun::new(at, Outcome::Complete, Vec::new()))
}

/// Notes that a scheduled sweep started at `now`; `save_last_run` takes the
/// note away. One that stays is a sweep that was killed, crashed or hangs.
pub fn mark_started(directory: &Path, now: u64) -> Result<(), String> {
    write_text(&directory.join(STARTED), &now.to_string())
}

/// When the scheduled sweep that has not ended yet started, if there is
/// one, in the store at `store_root`.
pub fn started_in(store_root: &Path) -> Option<u64> {
    let path = store_root.join("sweep").join(STARTED);
    if fs::metadata(&path).ok()?.len() > 32 {
        return None;
    }
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// The record is a file anyone running as the user can write: it is read
/// within bounds, and its text is shown as one plain line.
pub fn last_run(directory: &Path) -> Option<LastRun> {
    let path = directory.join(LAST_RUN);
    if fs::metadata(&path).ok()?.len() > MAX_RECORD_BYTES {
        return None;
    }
    let json = Json::parse(&fs::read_to_string(path).ok()?).ok()?;
    let outcome = match json.get("outcome")?.as_str()? {
        "complete" => Outcome::Complete,
        "incomplete" => Outcome::Incomplete,
        "failed" => Outcome::Failed,
        _ => return None,
    };
    Some(LastRun {
        at: json.get("at")?.as_u64()?,
        outcome,
        reasons: json
            .get("reasons")
            .and_then(Json::as_array)
            .unwrap_or_default()
            .iter()
            .filter_map(Json::as_str)
            .take(MAX_REASONS + 1)
            .map(|reason| {
                crate::text::shown(reason)
                    .chars()
                    .filter(|character| !matches!(character, '<' | '>'))
                    .take(MAX_REASON_CHARS)
                    .collect()
            })
            .collect(),
    })
}

pub fn save_last_run(directory: &Path, run: &LastRun) -> Result<(), String> {
    let json = Json::object([
        ("at", Json::from(run.at)),
        ("outcome", Json::from(run.outcome.name())),
        (
            "reasons",
            Json::Array(
                run.reasons
                    .iter()
                    .map(|reason| Json::from(reason.as_str()))
                    .collect(),
            ),
        ),
    ]);
    // The sweep ended, whether or not that can be written down.
    let unmarked = match fs::remove_file(directory.join(STARTED)) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            Err(format!("{}: {error}", directory.join(STARTED).display()))
        }
        _ => Ok(()),
    };
    write_text(&directory.join(LAST_RUN), &json.to_string()).and(unmarked)
}

/// How an item changed since the last sweep.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Change {
    New,
    Changed,
    Removed,
}

impl Change {
    /// How the change is shown, and its colour.
    pub const fn shown(self) -> (&'static str, &'static str) {
        match self {
            Self::New => ("+ new", "33;1"),
            Self::Changed => ("~ changed", "33;1"),
            Self::Removed => ("- removed", "2"),
        }
    }
}

/// How the notes the sweep keeps for itself among the remembered items
/// start; no item's label does (those start with `/` or `~/`).
pub const OWN_NOTE: &str = "guardian:";

/// Remembered once accounts, groups, keys and trust anchors were looked at
/// (and, for the second, once root's part of them was): before that,
/// finding them says nothing about their being new.
pub const TRUST_SEEN: &str = "guardian:trust-seen";
pub const ROOT_TRUST_SEEN: &str = "guardian:root-trust-seen";

/// The content part of a fingerprint: without the alerts and the finding
/// mark, which come and go with the checks that could run.
pub fn content_of(fingerprint: &str) -> &str {
    fingerprint.split('+').next().unwrap_or(fingerprint)
}

/// What changed between `previous` and `current` (both label to
/// fingerprint of the untrusted items).
pub fn diff(previous: &Remembered, current: &Remembered) -> Vec<(Change, String)> {
    let mut changes = Vec::new();
    let own_note = |label: &&String| !label.starts_with(OWN_NOTE);
    let (previous, current): (Remembered, Remembered) = (
        previous
            .iter()
            .filter(|(label, _)| own_note(label))
            .map(|(label, value)| (label.clone(), value.clone()))
            .collect(),
        current
            .iter()
            .filter(|(label, _)| own_note(label))
            .map(|(label, value)| (label.clone(), value.clone()))
            .collect(),
    );
    let (previous, current) = (&previous, &current);
    for (label, fingerprint) in current {
        match previous.get(label) {
            None => changes.push((Change::New, label.clone())),
            // What could not be read before is no change once it can be,
            // unless it now raises an alert. A finding that is gone from
            // a file that did not change is none either: the AI was not
            // reached this time, or judged it differently.
            Some(old)
                if old != fingerprint
                    && (old != UNREAD || fingerprint.contains('+'))
                    && old.strip_suffix(FLAGGED) != Some(fingerprint.as_str()) =>
            {
                changes.push((Change::Changed, label.clone()));
            }
            Some(_) => {}
        }
    }
    for label in previous
        .keys()
        .filter(|label| !current.contains_key(*label))
    {
        changes.push((Change::Removed, label.clone()));
    }
    changes.sort_by(|left, right| left.1.cmp(&right.1));
    changes
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{Change, Remembered, apply_allowed, baseline, diff, save_baseline};
    use crate::autorun::Category;
    use crate::sha256::Sha256;
    use crate::sweep::collect::{Body, Item, Origin};
    use crate::sweep::tier::Tier;
    use crate::test_support::TempDir;

    fn item(path: &str, text: &str) -> Item {
        Item {
            origin: Origin::User,
            category: Category::Shell,
            path: path.into(),
            tier: Tier::Unknown,
            sha256: Some(Sha256::digest(text.as_bytes())),
            body: Body::Text(text.into()),
            runs: Vec::new(),
            run_by: None,
            notes: Vec::new(),
            alerts: Vec::new(),
        }
    }

    #[test]
    fn items_count_as_allowed_only_from_roots_list_and_a_home_only_for_its_user() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = TempDir::new("sweep-allowed-system");
        let mut own = Remembered::new();
        own.insert("~/.bashrc".into(), "a".into());
        own.insert("/etc/profile.d/x.sh".into(), "b".into());
        // The list an older Guardian kept in the user's own directory is
        // only read to say what is in it.
        super::save_old_allowed(dir.path(), &own).unwrap();
        assert_eq!(super::old_allowed(dir.path()), own);
        // A list in a directory that is not root's counts for nothing.
        let system = dir.path().join("system.json");
        super::save_system_allowed(&system, &own).unwrap();
        assert!(super::system_allowed(&system).is_empty());
        if std::os::unix::fs::MetadataExt::uid(&fs::metadata(dir.path()).unwrap()) != 0 {
            assert!(super::all_allowed(&system, &system, 1000).is_empty());
        }
        assert!(super::is_home_label("~/x") && !super::is_home_label("/root/x"));
        // Saving sets the mode of the list's directory and of nothing in
        // it: what else root keeps there stays as closed as it was made.
        let kept = dir.path().join("kept");
        for (name, mode) in [("sweep", 0o750), ("permits", 0o700)] {
            fs::create_dir_all(kept.join(name)).unwrap();
            fs::set_permissions(kept.join(name), fs::Permissions::from_mode(mode)).unwrap();
        }
        fs::set_permissions(&kept, fs::Permissions::from_mode(0o700)).unwrap();
        super::save_system_allowed(&kept.join("allowed.json"), &own).unwrap();
        let mode =
            |path: &std::path::Path| fs::metadata(path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(&kept), 0o755);
        assert_eq!(mode(&kept.join("sweep")), 0o750);
        assert_eq!(mode(&kept.join("permits")), 0o700);

        // Root's list is one every user can reach: beside the results it
        // sat in a directory only one group may enter. The old one is read
        // until root moves it, then the new one alone counts.
        let keeper = super::Keeper {
            owner: std::os::unix::fs::MetadataExt::uid(&fs::metadata(dir.path()).unwrap()),
            anchor: dir.path(),
        };
        let state = dir.path().join("guardian");
        let (list, legacy) = (state.join("allowed.json"), state.join("sweep/allowed.json"));
        fs::create_dir_all(state.join("sweep")).unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(state.join("sweep"), fs::Permissions::from_mode(0o750)).unwrap();
        super::save_system_allowed(&legacy, &own).unwrap();
        assert_eq!(keeper.current(&list, &legacy), own);
        keeper.move_legacy(&list, &legacy).unwrap();
        assert!(!legacy.exists());
        assert_eq!(keeper.list(&list), own);
        assert_eq!(keeper.current(&list, &legacy), own);
        let mode =
            |path: &std::path::Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!((mode(&state), mode(&list)), (0o755, 0o644));
        // A list written again where the new one stands does not take its
        // place.
        let mut other = own.clone();
        other.insert("/etc/stale".into(), "c".into());
        super::save_system_allowed(&legacy, &other).unwrap();
        assert_eq!(keeper.current(&list, &legacy), own);
        keeper.move_legacy(&list, &legacy).unwrap();
        assert!(!legacy.exists());
        assert_eq!(keeper.list(&list), own);

        // In root's list a home's label is bound to a user id.
        assert_eq!(super::system_key("~/.bashrc", 1000), "1000:~/.bashrc");
        assert_eq!(super::system_key("/etc/x", 1000), "/etc/x");
        let list: Remembered = [
            ("/etc/x", "s"),
            ("1000:~/.bashrc", "mine"),
            ("1001:~/.bashrc", "theirs"),
            // Written by hand, or by an older version: bound to nobody.
            ("~/.profile", "nobody's"),
            ("x:~/.profile", "nobody's"),
            ("1000:/etc/y", "not a home label"),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect();
        let mine = super::allowed_for(&list, 1000);
        assert_eq!(
            mine.iter().collect::<Vec<_>>(),
            [
                (&"/etc/x".to_string(), &"s".to_string()),
                (&"~/.bashrc".to_string(), &"mine".to_string())
            ]
        );
        assert_eq!(super::allowed_for(&list, 1001)["~/.bashrc"], "theirs");
        assert_eq!(super::allowed_for(&list, 0).len(), 1);
        // An emptied old list is removed.
        super::save_old_allowed(dir.path(), &Remembered::new()).unwrap();
        assert!(!dir.path().join("allowed.json").exists());
    }

    #[test]
    fn an_override_of_guardians_sweep_or_a_half_followed_item_is_never_allowed() {
        let mut items = vec![item("a", "one"), item("b", "two"), item("c", "three")];
        items[0].alerts.push((
            crate::rules::RuleId::GuardianOverride,
            "changes the sweep".into(),
        ));
        items[1].notes.push(format!(
            "{}only the first 1024 commands of a line",
            crate::sweep::collect::NOT_ALL_FOLLOWED
        ));
        let list: Remembered = items
            .iter()
            .map(|item| (item.path.clone(), super::fingerprint(item)))
            .collect();
        apply_allowed(&mut items, &list, |item| item.path.clone());
        let tiers: Vec<Tier> = items.iter().map(|item| item.tier).collect();
        assert_eq!(tiers, [Tier::Unknown, Tier::Unknown, Tier::Allowed]);
        assert!(super::not_allowable(&items[0]).is_some());
        assert!(super::not_allowable(&items[2]).is_none());
        // What the sweep notes for itself is no change to tell.
        let before = Remembered::new();
        let after: Remembered = [(super::TRUST_SEEN.to_string(), "1".to_string())]
            .into_iter()
            .collect();
        assert!(diff(&before, &after).is_empty() && diff(&after, &before).is_empty());
        assert_eq!(super::content_of("abc+path-hijack+finding"), "abc");
    }
    #[test]
    fn changes_are_new_changed_or_removed() {
        let previous = Remembered::from([
            ("a".into(), "1".into()),
            ("b".into(), "2".into()),
            ("c".into(), "3".into()),
            ("e".into(), "-".into()),
            ("f".into(), "-".into()),
        ]);
        let current = Remembered::from([
            ("a".into(), "1".into()),
            ("b".into(), "9".into()),
            ("d".into(), "4".into()),
            // Unreadable before, read now (root's results arrived): no change.
            ("e".into(), "5".into()),
            // ... unless it now raises an alert.
            ("f".into(), "6+keyboard-reader".into()),
        ]);
        assert_eq!(
            diff(&previous, &current),
            [
                (Change::Changed, "b".to_string()),
                (Change::Removed, "c".to_string()),
                (Change::New, "d".to_string()),
                (Change::Changed, "f".to_string())
            ]
        );
    }

    #[test]
    fn what_the_timer_told_about_is_kept_apart_from_what_was_last_seen() {
        use super::{has_told, save_told, told};
        let dir = TempDir::new("sweep-told");
        assert!(!has_told(dir.path()));
        // An install from before: the last sweep stands in.
        let seen: Remembered = [("/etc/a".to_string(), "1".to_string())]
            .into_iter()
            .collect();
        save_baseline(dir.path(), &seen).unwrap();
        assert!(has_told(dir.path()));
        assert_eq!(told(dir.path()), seen);
        // Once the timer has told, a sweep by hand no longer moves it.
        save_told(dir.path(), &seen).unwrap();
        let more: Remembered = [
            ("/etc/a".to_string(), "1".to_string()),
            ("/etc/new".to_string(), "2".to_string()),
        ]
        .into_iter()
        .collect();
        save_baseline(dir.path(), &more).unwrap();
        assert_eq!(told(dir.path()), seen);
        assert_eq!(baseline(dir.path()), more);
        // A finding that appears is a change; one that goes is not.
        let plain: Remembered = [("/etc/a".to_string(), "1".to_string())]
            .into_iter()
            .collect();
        let flagged: Remembered = [("/etc/a".to_string(), "1+finding".to_string())]
            .into_iter()
            .collect();
        assert_eq!(
            diff(&plain, &flagged),
            [(Change::Changed, "/etc/a".to_string())]
        );
        assert!(diff(&flagged, &plain).is_empty());
        assert_eq!(
            diff(&told(dir.path()), &more),
            [(Change::New, "/etc/new".to_string())]
        );
    }

    #[test]
    fn an_allowed_item_counts_as_trusted_until_it_changes() {
        let dir = TempDir::new("sweep-state");
        let mut items = vec![item("x", "one"), item("y", "two")];
        let mut list = Remembered::new();
        list.insert("/x".into(), super::fingerprint(&items[0]));
        list.insert("/y".into(), "an older hash".into());
        apply_allowed(&mut items, &list, |item| format!("/{}", item.path));
        assert_eq!(items[0].tier, Tier::Allowed);
        assert_eq!(items[1].tier, Tier::Unknown);

        save_baseline(dir.path(), &list).unwrap();
        assert_eq!(baseline(dir.path()), list);
        assert!(
            fs::read_dir(dir.path()).unwrap().count() == 1,
            "no temporary files left"
        );
    }

    #[test]
    fn the_last_run_is_remembered_with_why_it_did_not_finish() {
        use super::{
            LastRun, Outcome, last_run, last_run_in, mark_started, save_last_run, started_in,
        };
        let dir = TempDir::new("sweep-last-run");
        let sweep = dir.path().join("sweep");
        fs::create_dir_all(&sweep).unwrap();
        assert_eq!(last_run_in(dir.path()), None);

        // What an older sweep left counts as a run.
        fs::write(sweep.join("baseline.json"), "{}").unwrap();
        let from_baseline = last_run_in(dir.path()).unwrap();
        assert_eq!(from_baseline.outcome, Outcome::Complete);
        assert!(from_baseline.at > 0);

        let reasons: Vec<String> = (0..8).map(|index| format!("reason {index}")).collect();
        let run = LastRun::new(42, Outcome::Incomplete, reasons);
        assert_eq!(run.reasons.len(), 6);
        assert_eq!(run.reasons[5], "and 3 more");
        // A sweep that started is known as such until it records its end.
        assert_eq!(started_in(dir.path()), None);
        mark_started(&sweep, 40).unwrap();
        assert_eq!(started_in(dir.path()), Some(40));
        save_last_run(&sweep, &run).unwrap();
        assert_eq!(started_in(dir.path()), None);
        assert_eq!(last_run(&sweep), Some(run.clone()));
        assert_eq!(last_run_in(dir.path()), Some(run));

        // What is read back is bounded and plain.
        fs::write(
            sweep.join("last-run.json"),
            format!(
                "{{\"at\":1,\"outcome\":\"failed\",\"reasons\":[\"<b>x\\ny\",\"{}\"]}}",
                "z".repeat(1000)
            ),
        )
        .unwrap();
        let read = last_run(&sweep).unwrap();
        assert_eq!(read.reasons[0], "bx\\ny");
        assert_eq!(read.reasons[1].len(), 300);
        fs::write(sweep.join("last-run.json"), " ".repeat(70 * 1024)).unwrap();
        assert_eq!(last_run(&sweep), None);

        // A record that does not parse is no record.
        fs::write(
            sweep.join("last-run.json"),
            "{\"at\":1,\"outcome\":\"fine\"}",
        )
        .unwrap();
        assert_eq!(last_run(&sweep), None);
        // Nor does what a sweep by hand remembered stand in for it.
        assert_eq!(last_run_in(dir.path()), None);
    }
}
