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
    let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
    let result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .and_then(|mut file| file.write_all(json.to_string().as_bytes()))
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

/// How an item changed since the last sweep.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Change {
    New,
    Changed,
    Removed,
}

impl Change {
    pub const fn mark(self) -> char {
        match self {
            Self::New => '+',
            Self::Changed => '~',
            Self::Removed => '-',
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
            Some(old) if old != fingerprint => changes.push((Change::Changed, label.clone())),
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
        ]);
        let current = Remembered::from([
            ("a".into(), "1".into()),
            ("b".into(), "9".into()),
            ("d".into(), "4".into()),
        ]);
        assert_eq!(
            diff(&previous, &current),
            [
                (Change::Changed, "b".to_string()),
                (Change::Removed, "c".to_string()),
                (Change::New, "d".to_string())
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
}
