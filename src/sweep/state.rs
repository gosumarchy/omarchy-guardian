//! What the sweep remembers between runs, in a private `sweep` directory of
//! the review store: the last sweep's untrusted items (so `--diff` and the
//! schedule report only what is new or changed) and the items the user
//! allowed (`sweep allow`), each by its label and content hash, so a changed
//! file is looked at again.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use super::collect::Item;
use super::tier::Tier;
use crate::engine::store;
use crate::json::Json;

const BASELINE: &str = "baseline.json";
const ALLOWED: &str = "allowed.json";
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
    let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
    let result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .and_then(|mut file| file.write_all(text.as_bytes()))
        .and_then(|()| fs::rename(&temporary, path));
    if result.is_err() {
        drop(fs::remove_file(&temporary));
    }
    result.map_err(|error| format!("{}: {error}", path.display()))
}

pub fn allowed(directory: &Path) -> Remembered {
    read(&directory.join(ALLOWED))
}

pub fn save_allowed(directory: &Path, allowed: &Remembered) -> Result<(), String> {
    write(&directory.join(ALLOWED), allowed)
}

/// Whether a sweep has remembered anything yet.
pub fn has_baseline(directory: &Path) -> bool {
    directory.join(BASELINE).is_file()
}

pub fn baseline(directory: &Path) -> Remembered {
    read(&directory.join(BASELINE))
}

/// Remembers the untrusted items of this sweep for the next `--diff`.
pub fn save_baseline(directory: &Path, current: &Remembered) -> Result<(), String> {
    write(&directory.join(BASELINE), current)
}

/// Marks items the user allowed, while they are unchanged.
pub fn apply_allowed(items: &mut [Item], allowed: &Remembered, label: impl Fn(&Item) -> String) {
    for item in items {
        if item.is_trusted() {
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

/// What changed between `previous` and `current` (both label to
/// fingerprint of the untrusted items).
pub fn diff(previous: &Remembered, current: &Remembered) -> Vec<(Change, String)> {
    let mut changes = Vec::new();
    for (label, fingerprint) in current {
        match previous.get(label) {
            None => changes.push((Change::New, label.clone())),
            // What could not be read before is no change once it can be,
            // unless it now raises an alert.
            Some(old) if old != fingerprint && (old != UNREAD || fingerprint.contains('+')) => {
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

    use super::{
        Change, Remembered, allowed, apply_allowed, baseline, diff, save_allowed, save_baseline,
    };
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
    fn an_allowed_item_counts_as_trusted_until_it_changes() {
        let dir = TempDir::new("sweep-state");
        let mut items = vec![item("x", "one"), item("y", "two")];
        let mut list = Remembered::new();
        list.insert("/x".into(), super::fingerprint(&items[0]));
        list.insert("/y".into(), "an older hash".into());
        save_allowed(dir.path(), &list).unwrap();
        apply_allowed(&mut items, &allowed(dir.path()), |item| {
            format!("/{}", item.path)
        });
        assert_eq!(items[0].tier, Tier::Allowed);
        assert_eq!(items[1].tier, Tier::Unknown);

        save_baseline(dir.path(), &list).unwrap();
        assert_eq!(baseline(dir.path()), list);
        assert!(
            fs::read_dir(dir.path()).unwrap().count() == 2,
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
