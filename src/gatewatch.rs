//! Tells the desktop when protection goes away by itself: a gate that was
//! on and no longer is, or a setting that became weaker than its level.
//!
//! Each `status` run (the bar asks every half minute) and each scheduled
//! sweep reads every gate's state and compares it with the last record. A
//! drop raises one notification and stays among the bar's problems until
//! the gate is back on or `status --dismiss`. What the user turns off
//! through Guardian itself is recorded without a notification.
//!
//! Watched the same way, beside the gates: the wrappers on the session's
//! PATH, the pacman gate's root-owned reviewer, the settings files, a
//! system-wide settings file of the reviewer's appearing in `/etc`, and a
//! file standing in for one of the sweep's own units.
//!
//! The record is a file in the user's own state directory. It catches
//! things breaking and crude tampering (a line removed from `~/.bashrc`);
//! a program that also rewrites the record is not caught.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::agent::Exposure;
use crate::config::Settings;
use crate::engine::store::{self, Store};
use crate::json::Json;
use crate::notify;

const RECORD: &str = "gatewatch.json";
const LOCK: &str = "gatewatch.lock";
/// A lock older than this was left by a run that died.
const STALE_LOCK: Duration = Duration::from_secs(60);

/// How much of its job a gate does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Off,
    Partial,
    On,
}

impl Level {
    const fn name(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Partial => "partial",
            Self::On => "on",
        }
    }

    fn parse(name: &str) -> Option<Self> {
        [Self::Off, Self::Partial, Self::On]
            .into_iter()
            .find(|level| level.name() == name)
    }
}

/// One gate as it is now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gate {
    /// Its name in the record, which stays the same between versions.
    pub key: String,
    pub level: Level,
    /// What a notification says when it dropped: "the AUR gate is off".
    pub now: String,
}

/// Everything watched, as it is now.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub gates: Vec<Gate>,
    /// The gates (by key) whose state could not be read the way every
    /// caller reads it: the state of one that depends on the session's
    /// PATH, seen from a shell with no session to ask. Their record is
    /// left as it is, so two callers with different PATHs cannot take
    /// turns raising and clearing the same alert.
    pub unknown: Vec<String>,
    /// Settings weaker than their level and not accepted: the system
    /// file's key for each, and the line that says it.
    pub weak: Vec<(String, String)>,
}

/// The record's name for the reviewer's system-wide settings.
pub const REVIEWER_SETTINGS: &str = "reviewer settings";
/// The record's name for what the root checks saw standing in for the
/// sweep's own units.
pub const SWEEP_UNITS: &str = "sweep units";

/// How `agent::exposure` words a system-wide settings file the reviewer
/// loads; the file's path follows.
const LOADS_SETTINGS: &str = "the reviewer loads system-wide settings from ";

/// The reviewer's system-wide settings as something to watch: a file in
/// `/etc/claude-code` or `/etc/opencode` applies to every review whatever
/// Guardian passes the reviewer, and one that appears was put there by root
/// or by a package. On with none, partly on with one that sets nothing
/// that could redirect a review, off with one the pacman gate refuses to
/// review through. `exposures` holds what `agent::exposure` says of each
/// reviewer in use, asked as for a root transaction.
pub fn reviewer_settings(exposures: &[Exposure]) -> Gate {
    let mut files: Vec<&str> = exposures
        .iter()
        .flat_map(|exposure| &exposure.notes)
        .filter_map(|note| note.strip_prefix(LOADS_SETTINGS))
        .collect();
    files.sort_unstable();
    files.dedup();
    let refused = exposures.iter().any(|exposure| exposure.refusal.is_some());
    let (level, now) = match (files.is_empty(), refused) {
        (true, false) => (
            Level::On,
            "the reviewer loads no system-wide settings".to_string(),
        ),
        (_, true) => (
            Level::Off,
            format!(
                "the reviewer's system-wide settings ({}) could send a review elsewhere or run commands during it; the pacman gate does not review through them",
                files.join(", ")
            ),
        ),
        (false, false) => (
            Level::Partial,
            format!(
                "the reviewer now loads system-wide settings ({}), which apply to every review",
                files.join(", ")
            ),
        ),
    };
    Gate {
        key: REVIEWER_SETTINGS.into(),
        level,
        now,
    }
}

/// What the root checks saw standing in for one of the sweep's own units
/// (`paths`, absolute), as something to watch: on with none.
pub fn sweep_units(paths: &[String]) -> Gate {
    Gate {
        key: SWEEP_UNITS.into(),
        level: if paths.is_empty() {
            Level::On
        } else {
            Level::Off
        },
        now: match paths {
            [] => "nothing stands in for the sweep's own units".into(),
            [first, rest @ ..] => format!(
                "the root checks found {first}{} standing in for one of the sweep's own units",
                if rest.is_empty() {
                    String::new()
                } else {
                    format!(" and {} more", rest.len())
                }
            ),
        },
    }
}

/// Who is looking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observer {
    /// The bar or the scheduled sweep: a drop is news.
    Watching,
    /// The user just changed something through Guardian: recorded, and
    /// not news.
    Chosen,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Record {
    gates: Vec<(String, Level)>,
    weak: Vec<String>,
    /// Drops not yet dismissed or repaired: the gate or setting, and the
    /// line the bar shows.
    alerts: Vec<(String, String)>,
}

impl Record {
    fn parse(text: &str) -> Option<Self> {
        let json = Json::parse(text).ok()?;
        let gates = json
            .get("gates")?
            .as_object()?
            .iter()
            .map(|(key, level)| Some((key.clone(), Level::parse(level.as_str()?)?)))
            .collect::<Option<_>>()?;
        let weak = json
            .get("weak")?
            .as_array()?
            .iter()
            .map(|key| key.as_str().map(str::to_string))
            .collect::<Option<_>>()?;
        let alerts = json
            .get("alerts")?
            .as_array()?
            .iter()
            .map(|alert| {
                Some((
                    alert.get("key")?.as_str()?.to_string(),
                    alert.get("text")?.as_str()?.to_string(),
                ))
            })
            .collect::<Option<_>>()?;
        Some(Self {
            gates,
            weak,
            alerts,
        })
    }

    fn render(&self) -> String {
        let gates = Json::Object(
            self.gates
                .iter()
                .map(|(key, level)| (key.clone(), Json::from(level.name())))
                .collect(),
        );
        let weak = Json::Array(
            self.weak
                .iter()
                .map(|key| Json::from(key.as_str()))
                .collect(),
        );
        let alerts = Json::Array(
            self.alerts
                .iter()
                .map(|(key, text)| {
                    Json::object([
                        ("key", Json::from(key.as_str())),
                        ("text", Json::from(text.as_str())),
                    ])
                })
                .collect(),
        );
        Json::object([("gates", gates), ("weak", weak), ("alerts", alerts)]).to_string()
    }
}

/// What the bar says of a drop until it is repaired or dismissed.
const SINCE: &str =
    "it was on when Guardian last looked; `omarchy-guardian status --dismiss` marks this seen";

/// The record after seeing `snapshot`, and what is news in it: the lines
/// of the drops since `previous`. Without a previous record nothing is
/// news: there is nothing to have dropped from.
fn compare(
    previous: Option<&Record>,
    snapshot: &Snapshot,
    observer: Observer,
) -> (Record, Vec<String>) {
    let level_now = |key: &str| {
        snapshot
            .gates
            .iter()
            .find(|gate| gate.key == key)
            .map(|gate| gate.level)
    };
    let known = |key: &str| !snapshot.unknown.iter().any(|unknown| unknown == key);
    // What was raised stays until it is repaired: the gate back on. What
    // could not be read this time stays as it was.
    let mut alerts: Vec<(String, String)> = previous
        .map(|previous| previous.alerts.clone())
        .unwrap_or_default()
        .into_iter()
        .filter(|(key, _)| !known(key) || level_now(key).is_some_and(|level| level != Level::On))
        .collect();
    let mut news = Vec::new();
    if let (Some(previous), Observer::Watching) = (previous, observer) {
        for gate in snapshot.gates.iter().filter(|gate| known(&gate.key)) {
            let before = previous
                .gates
                .iter()
                .find(|(key, _)| *key == gate.key)
                .map(|(_, level)| *level);
            if before.is_some_and(|before| gate.level < before) {
                alerts.retain(|(key, _)| *key != gate.key);
                alerts.push((gate.key.clone(), format!("{} ({SINCE})", gate.now)));
                news.push(gate.now.clone());
            }
        }
        // A weaker setting is a problem of the bar's for as long as it
        // lasts (see `status`), so it is only news here.
        news.extend(
            snapshot
                .weak
                .iter()
                .filter(|(key, _)| !previous.weak.contains(key))
                .map(|(_, line)| line.clone()),
        );
    }
    let recorded = |key: &str| {
        previous?
            .gates
            .iter()
            .find(|(recorded, _)| recorded == key)
            .map(|(_, level)| *level)
    };
    let record = Record {
        gates: snapshot
            .gates
            .iter()
            .filter_map(|gate| {
                let level = if known(&gate.key) {
                    Some(gate.level)
                } else {
                    recorded(&gate.key)
                };
                Some((gate.key.clone(), level?))
            })
            .collect(),
        weak: snapshot.weak.iter().map(|(key, _)| key.clone()).collect(),
        alerts,
    };
    (record, news)
}

/// One notification's text for every drop found at once.
fn headline(news: &[String]) -> Option<String> {
    let (first, rest) = news.split_first()?;
    Some(if rest.is_empty() {
        first.clone()
    } else {
        format!("{first}, and {} more change(s)", rest.len())
    })
}

/// Compares `snapshot` with the record in `directory`, saves it, and
/// returns the drops still standing (the gate and the bar's line for it)
/// and the notification to show, if any. Two runs at once (the bar and the sweep) must not both
/// call the same drop news: only the one holding the lock compares, the
/// other reports what is on record.
fn observe_in(
    directory: &Path,
    snapshot: &Snapshot,
    observer: Observer,
) -> (Vec<(String, String)>, Option<String>) {
    let path = directory.join(RECORD);
    let text = fs::read_to_string(&path).ok();
    let previous = text.as_deref().and_then(Record::parse);
    let standing = |record: &Record| record.alerts.clone();
    let Some(_lock) = Lock::take(directory.join(LOCK)) else {
        return (previous.as_ref().map(standing).unwrap_or_default(), None);
    };
    let (record, news) = compare(previous.as_ref(), snapshot, observer);
    let rendered = record.render();
    // The bar asks every half minute: the file is only written when
    // something changed. A record that cannot be saved raises nothing, or
    // the same drop would be news on every run.
    if text.as_deref() != Some(rendered.as_str()) && write(&path, &rendered).is_err() {
        return (standing(&record), None);
    }
    (standing(&record), headline(&news))
}

/// Saves `text` as `path`, private to the user, all of it or none.
pub fn write(path: &Path, text: &str) -> std::io::Result<()> {
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    drop(fs::remove_file(&temporary));
    let written = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .and_then(|mut file| file.write_all(text.as_bytes()))
        .and_then(|()| fs::rename(&temporary, path));
    if written.is_err() {
        drop(fs::remove_file(&temporary));
    }
    written
}

/// A lock file, removed when dropped.
struct Lock(PathBuf);

impl Lock {
    fn take(path: PathBuf) -> Option<Self> {
        let stale = fs::symlink_metadata(&path)
            .and_then(|metadata| metadata.modified())
            .is_ok_and(|modified| {
                SystemTime::now()
                    .duration_since(modified)
                    .is_ok_and(|age| age > STALE_LOCK)
            });
        if stale {
            drop(fs::remove_file(&path));
        }
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .ok()
            .map(|_| Self(path))
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        drop(fs::remove_file(&self.0));
    }
}

/// The user's private state directory, made if missing. Root keeps no
/// record: under `sudo -E` the directory is the user's.
pub fn directory() -> Option<PathBuf> {
    let uid = store::effective_uid().ok().filter(|uid| *uid != 0)?;
    let root = Store::default_root()?;
    store::private_dir(&root, uid).ok()?;
    Some(root)
}

/// Records `snapshot`, notifies about what dropped since the last record
/// (unless the user chose it), and returns the drops still standing (the
/// gate's key and the line that says it), for the bar's list of problems.
pub fn observe(snapshot: &Snapshot, observer: Observer) -> Vec<(String, String)> {
    let Some(directory) = directory() else {
        return Vec::new();
    };
    let (standing, news) = observe_in(&directory, snapshot, observer);
    if let Some(news) = news {
        notify::changed(&news);
    }
    standing
}

/// `status --dismiss`: the drops on record are seen.
pub fn dismiss() {
    let Some(path) = directory().map(|directory| directory.join(RECORD)) else {
        return;
    };
    let Some(mut record) = fs::read_to_string(&path)
        .ok()
        .as_deref()
        .and_then(Record::parse)
    else {
        return;
    };
    if !record.alerts.is_empty() {
        record.alerts.clear();
        drop(write(&path, &record.render()));
    }
}

/// Run at the end of a scheduled sweep, so a gate that went off is told
/// within a day even where no bar asks for the status.
pub fn after_sweep(scheduled: bool, settings: &Settings) {
    if scheduled {
        observe(&crate::status::snapshot(settings), Observer::Watching);
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{Gate, Level, Observer, RECORD, Record, Snapshot, compare, headline, observe_in};
    use crate::test_support::TempDir;

    fn gate(key: &str, level: Level) -> Gate {
        Gate {
            key: key.into(),
            level,
            now: format!("the {key} gate is {}", level.name()),
        }
    }

    fn snapshot(gates: &[(&str, Level)], weak: &[&str]) -> Snapshot {
        Snapshot {
            gates: gates.iter().map(|(key, level)| gate(key, *level)).collect(),
            unknown: Vec::new(),
            weak: weak
                .iter()
                .map(|key| ((*key).to_string(), format!("{key} is weaker")))
                .collect(),
        }
    }

    fn lines(standing: &[(String, String)]) -> Vec<&str> {
        standing.iter().map(|(key, _)| key.as_str()).collect()
    }

    #[test]
    fn a_state_only_one_caller_can_read_is_not_put_on_record() {
        let dir = TempDir::new("gatewatch-unknown");
        // The bar, in the session: both on.
        let session = snapshot(&[("aur", Level::On), ("path", Level::On)], &[]);
        observe_in(dir.path(), &session, Observer::Watching);
        // `status` from a shell with another PATH and no session to ask:
        // it reads both as dropped, and knows it cannot tell.
        let mut remote = snapshot(&[("aur", Level::Partial), ("path", Level::Off)], &[]);
        remote.unknown = vec!["aur".into(), "path".into()];
        for _ in 0..2 {
            assert_eq!(
                observe_in(dir.path(), &remote, Observer::Watching),
                (Vec::new(), None)
            );
            // The bar's next poll finds its record as it left it.
            assert_eq!(
                observe_in(dir.path(), &session, Observer::Watching),
                (Vec::new(), None)
            );
        }
        // Without that mark the same two callers take turns: a pop-up for
        // each such `status`, cleared by the bar's next poll.
        remote.unknown.clear();
        let (standing, news) = observe_in(dir.path(), &remote, Observer::Watching);
        assert_eq!(lines(&standing), ["aur", "path"]);
        assert!(news.is_some());

        // A drop the session itself saw stays on record, alert and all,
        // through a look that could not read it; and comes off when the
        // session sees the gate back on.
        let dropped = snapshot(&[("aur", Level::On), ("path", Level::Off)], &[]);
        observe_in(dir.path(), &session, Observer::Watching);
        let (standing, _) = observe_in(dir.path(), &dropped, Observer::Watching);
        assert_eq!(lines(&standing), ["path"]);
        let mut blind = session.clone();
        blind.unknown = vec!["path".into()];
        let (standing, news) = observe_in(dir.path(), &blind, Observer::Watching);
        assert_eq!((lines(&standing), news), (vec!["path"], None));
        let record = Record::parse(&fs::read_to_string(dir.path().join(RECORD)).unwrap()).unwrap();
        assert!(record.gates.contains(&("path".to_string(), Level::Off)));
        let (standing, _) = observe_in(dir.path(), &session, Observer::Watching);
        assert!(standing.is_empty());
    }

    #[test]
    fn a_gate_that_was_on_and_is_not_is_news_once_and_stays_until_it_is_back() {
        let dir = TempDir::new("gatewatch");
        let on = snapshot(&[("aur", Level::On), ("theme", Level::Off)], &[]);
        // The first record has nothing to compare with.
        assert_eq!(
            observe_in(dir.path(), &on, Observer::Watching),
            (Vec::new(), None)
        );

        let off = snapshot(&[("aur", Level::Off), ("theme", Level::Off)], &[]);
        let (standing, news) = observe_in(dir.path(), &off, Observer::Watching);
        assert_eq!(lines(&standing), ["aur"]);
        assert!(standing[0].1.starts_with("the aur gate is off (it was on"));
        assert_eq!(news.as_deref(), Some("the aur gate is off"));
        // Not news again, and still a problem.
        let (standing, news) = observe_in(dir.path(), &off, Observer::Watching);
        assert_eq!(lines(&standing), ["aur"]);
        assert_eq!(news, None);

        // Back on: gone.
        assert_eq!(
            observe_in(dir.path(), &on, Observer::Watching),
            (Vec::new(), None)
        );
        // On to partly on is a drop too.
        let partial = snapshot(&[("aur", Level::Partial), ("theme", Level::Off)], &[]);
        let (standing, news) = observe_in(dir.path(), &partial, Observer::Watching);
        assert_eq!(lines(&standing), ["aur"]);
        assert!(news.is_some());
        // A gate that came on, or was never on, is not.
        let more = snapshot(&[("aur", Level::Partial), ("theme", Level::On)], &[]);
        assert_eq!(observe_in(dir.path(), &more, Observer::Watching).1, None);
    }

    #[test]
    fn a_reviewer_settings_file_appearing_is_a_drop() {
        use super::{REVIEWER_SETTINGS, SWEEP_UNITS, reviewer_settings, sweep_units};
        use crate::agent::Exposure;

        let exposed = |notes: &[&str], refusal: Option<&str>| Exposure {
            notes: notes.iter().map(ToString::to_string).collect(),
            refusal: refusal.map(str::to_string),
        };
        // The variables a reviewer ran with are not this gate's.
        let none = reviewer_settings(&[
            exposed(&["removed from the reviewer's environment: X"], None),
            Exposure::default(),
        ]);
        assert_eq!(
            (none.key.as_str(), none.level),
            (REVIEWER_SETTINGS, Level::On)
        );

        let file =
            "the reviewer loads system-wide settings from /etc/claude-code/managed-settings.json";
        let loaded = reviewer_settings(&[exposed(&[file], None), exposed(&[file], None)]);
        assert_eq!(loaded.level, Level::Partial);
        assert_eq!(
            loaded
                .now
                .matches("/etc/claude-code/managed-settings.json")
                .count(),
            1,
            "{}",
            loaded.now
        );
        let refused = reviewer_settings(&[exposed(&[file], Some("sets hooks"))]);
        assert_eq!(refused.level, Level::Off);
        assert!(refused.now.contains("pacman gate"), "{}", refused.now);

        // Appearing is news once, and stays until it is gone or dismissed.
        let dir = TempDir::new("gatewatch-reviewer");
        let with = |gate: Gate| Snapshot {
            gates: vec![gate],
            ..Snapshot::default()
        };
        observe_in(dir.path(), &with(none.clone()), Observer::Watching);
        let (standing, news) = observe_in(dir.path(), &with(loaded.clone()), Observer::Watching);
        assert_eq!(lines(&standing), [REVIEWER_SETTINGS]);
        assert_eq!(news, Some(loaded.now));
        assert_eq!(
            observe_in(dir.path(), &with(none), Observer::Watching),
            (Vec::new(), None)
        );

        let clear = sweep_units(&[]);
        assert_eq!((clear.key.as_str(), clear.level), (SWEEP_UNITS, Level::On));
        let found = sweep_units(&["/etc/systemd/user/a.timer".into(), "/b".into()]);
        assert_eq!(found.level, Level::Off);
        assert!(
            found.now.contains("/etc/systemd/user/a.timer and 1 more"),
            "{}",
            found.now
        );
    }

    #[test]
    fn what_the_user_turned_off_is_recorded_without_a_notification() {
        let dir = TempDir::new("gatewatch-chosen");
        let on = snapshot(&[("aur", Level::On)], &[]);
        let off = snapshot(&[("aur", Level::Off)], &[]);
        observe_in(dir.path(), &on, Observer::Watching);
        assert_eq!(
            observe_in(dir.path(), &off, Observer::Chosen),
            (Vec::new(), None)
        );
        // The bar's next look finds it as recorded.
        assert_eq!(
            observe_in(dir.path(), &off, Observer::Watching),
            (Vec::new(), None)
        );
    }

    #[test]
    fn a_setting_that_became_weaker_is_news_once() {
        let dir = TempDir::new("gatewatch-weak");
        observe_in(dir.path(), &snapshot(&[], &[]), Observer::Watching);
        let weak = snapshot(&[], &["aur.ai=off"]);
        let (standing, news) = observe_in(dir.path(), &weak, Observer::Watching);
        // The bar lists it itself for as long as it lasts.
        assert!(standing.is_empty());
        assert_eq!(news.as_deref(), Some("aur.ai=off is weaker"));
        assert_eq!(observe_in(dir.path(), &weak, Observer::Watching).1, None);
        // Set back and weakened again: news again. Through the settings
        // app: not.
        observe_in(dir.path(), &snapshot(&[], &[]), Observer::Watching);
        assert!(
            observe_in(dir.path(), &weak, Observer::Watching)
                .1
                .is_some()
        );
        observe_in(dir.path(), &snapshot(&[], &[]), Observer::Watching);
        assert_eq!(observe_in(dir.path(), &weak, Observer::Chosen).1, None);
        assert_eq!(observe_in(dir.path(), &weak, Observer::Watching).1, None);
    }

    #[test]
    fn several_drops_make_one_notification_and_a_broken_record_starts_over() {
        assert_eq!(headline(&[]), None);
        assert_eq!(
            headline(&["a is off".into(), "b is off".into(), "c".into()]).as_deref(),
            Some("a is off, and 2 more change(s)")
        );
        let previous = Record {
            gates: vec![("a".into(), Level::On), ("b".into(), Level::On)],
            ..Record::default()
        };
        let now = snapshot(&[("a", Level::Off), ("b", Level::Off)], &[]);
        let (record, news) = compare(Some(&previous), &now, Observer::Watching);
        assert_eq!(news.len(), 2);
        assert_eq!(Record::parse(&record.render()), Some(record));

        // A record that is not one is replaced, and raises nothing.
        let dir = TempDir::new("gatewatch-broken");
        fs::write(dir.path().join(RECORD), "{\"gates\": 7}").unwrap();
        assert_eq!(
            observe_in(dir.path(), &now, Observer::Watching),
            (Vec::new(), None)
        );
        let saved = fs::read_to_string(dir.path().join(RECORD)).unwrap();
        assert!(Record::parse(&saved).is_some(), "{saved}");
        // The lock is gone after each run.
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
