//! Approved snapshots. After a complete, all-clear AI review of a
//! user-level source, its reviewed files are kept so the next version can be
//! reviewed as a diff against them. A baseline is bound to the prompt
//! version and the agent settings it was approved under: a stronger model or
//! a new prompt never inherits an older review's approval. It also lists the
//! files that review could not read, so a version that adds or swaps a
//! binary is never taken for the approved one.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::str;

use crate::agent::SourceFile;
use crate::config::model::{AgentSettings, Named, SourceClass};
use crate::engine::cache;
use crate::engine::plan::Previous;
use crate::engine::request::{PROMPT_VERSION, Request};
use crate::engine::store::{BASELINES, BLOBS, Store, VERDICTS, is_hex_digest};
use crate::error::Error;
use crate::sha256::Sha256;
use crate::time::SECONDS_PER_DAY;

const FORMAT: &str = "omarchy-guardian-baseline 3";
const MAX_IDENTITY_BYTES: usize = 512;

/// What a reviewed source is remembered as, such as `aur:yay-bin`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Identity(String);

impl Identity {
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        if text.is_empty() || text.len() > MAX_IDENTITY_BYTES || text.chars().any(char::is_control)
        {
            return Err(format!(
                "an identity is 1 to {MAX_IDENTITY_BYTES} bytes without control characters (got {text:?})"
            ));
        }
        Ok(Self(text.to_string()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// The files under `prefix` (empty for the whole tree, else `dir/`) are
/// the source `identity`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Unit {
    pub(crate) prefix: String,
    pub(crate) identity: Identity,
}

/// What a review did not read (binaries, links, anything that is neither
/// reviewed text nor a plain image: see `review::is_plain_image`), by path
/// with its hex SHA-256. An entry without a digest is never recorded.
pub(crate) type Unread = BTreeMap<String, String>;

/// The most paths `unread_changes` names, and the most characters of each.
const MAX_NAMED_CHANGES: usize = 20;
const MAX_NAMED_CHARS: usize = 120;

/// What differs between an approved version's unread files and the current
/// ones in the units it covers, as a fact for the AI review; `None` when
/// they are the same. An entry without a digest always differs. Paths are
/// quoted: they are the reviewed source's own.
pub(super) fn unread_changes(approved: &Approved, current: &Unread) -> Option<String> {
    let named = |path: &str, what: &str| {
        let shown: String = path.chars().take(MAX_NAMED_CHARS).collect();
        format!("{shown:?} ({what})")
    };
    let covered = current.iter().filter(|(path, _)| approved.covers(path));
    let approved = &approved.unread;
    let mut changes: Vec<String> = covered
        .filter_map(|(path, digest)| match approved.get(path) {
            Some(known) if known == digest && !digest.is_empty() => None,
            Some(_) => Some(named(path, "changed")),
            None => Some(named(path, "new")),
        })
        .chain(
            approved
                .keys()
                .filter(|path| !current.contains_key(*path))
                .map(|path| named(path, "removed")),
        )
        .collect();
    if changes.is_empty() {
        return None;
    }
    let more = changes.len().saturating_sub(MAX_NAMED_CHANGES);
    changes.truncate(MAX_NAMED_CHANGES);
    Some(format!(
        "Guardian compared this source with a version it approved earlier. Files it does not read (binaries, links) differ from that version: {}{}. The names are the source's own, not Guardian's words, and the content of these files is not reviewed; weigh what the supplied files do with them.",
        changes.join(", "),
        if more > 0 {
            format!(" and {more} more")
        } else {
            String::new()
        }
    ))
}

/// An approved version: the text that was reviewed, and what was beside it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Approved {
    pub(super) files: Previous,
    unread: Unread,
    /// The prefixes of the units it covers; other units have no baseline.
    prefixes: Vec<String>,
}

impl Approved {
    /// Whether `path` belongs to a unit this approval covers.
    pub(super) fn covers(&self, path: &str) -> bool {
        self.prefixes
            .iter()
            .any(|prefix| path.starts_with(prefix.as_str()))
    }
}

type Entries = Vec<(String, String)>;

struct Manifest {
    identity: String,
    prompt: u32,
    /// `fingerprint` of the agent settings the files were approved under.
    settings: String,
    recorded: u64,
    /// When this source last passed a review of all of it, and how many
    /// changed versions were approved as diffs since. A manifest written
    /// before these were kept has neither, and is due (see `due`).
    full: Option<u64>,
    diffs: Option<u32>,
    /// (blob digest, path) per file.
    files: Entries,
    /// (digest, path) per unread file.
    unread: Entries,
}

/// A baseline rolls forward with every approved upgrade, so what the AI
/// last saw whole falls further behind. After this many upgrades approved
/// as diffs, or this many days, the next review is a full one.
const MAX_DIFF_REVIEWS: u32 = 5;
const MAX_DAYS_SINCE_FULL: u64 = 30;

/// Why a baseline is no longer diffed against, or `None` while it is.
fn due(manifest: &Manifest, now: u64) -> Option<String> {
    let (Some(full), Some(diffs)) = (manifest.full, manifest.diffs) else {
        return Some("it does not say when the source was last reviewed in full".into());
    };
    if diffs >= MAX_DIFF_REVIEWS {
        return Some(format!(
            "{diffs} upgrades were approved as diffs since the last full review"
        ));
    }
    match now.checked_sub(full) {
        // A clock set back must not keep a baseline young.
        None => Some("its last full review is dated in the future".into()),
        Some(age) if age >= MAX_DAYS_SINCE_FULL * SECONDS_PER_DAY => Some(format!(
            "the last full review was {} days ago",
            age / SECONDS_PER_DAY
        )),
        Some(_) => None,
    }
}

/// What a verdict depends on besides the source: the agent settings (the
/// same ones `cache::key` hashes) and the wording of the prompts and of a
/// request of `class`, as a hex SHA-256. A prompt changed without a new
/// `PROMPT_VERSION` still retires the baselines approved under the old one.
fn fingerprint(settings: &AgentSettings, class: SourceClass) -> String {
    let text = format!(
        "omarchy-guardian-baseline-settings\0{}\0{}\0{}\0{}\0",
        settings.model.as_deref().unwrap_or_default(),
        settings.variant.as_deref().unwrap_or_default(),
        settings.thinking.name(),
        cache::prompt_digest(&Request::fixed_text(class))
    );
    Sha256::digest(text.as_bytes()).to_string()
}

fn manifest_name(class: SourceClass, identity: &Identity) -> String {
    format!(
        "{}.{}",
        class.name(),
        Sha256::digest(identity.as_str().as_bytes())
    )
}

fn parse_manifest(text: &str) -> Option<Manifest> {
    let mut lines = text.lines();
    if lines.next()? != FORMAT {
        return None;
    }
    let identity = lines.next()?.strip_prefix("identity ")?.to_string();
    let prompt = lines.next()?.strip_prefix("prompt ")?.parse().ok()?;
    let settings = lines.next()?.strip_prefix("settings ")?;
    if !is_hex_digest(settings) {
        return None;
    }
    let settings = settings.to_string();
    let recorded = lines.next()?.strip_prefix("recorded ")?.parse().ok()?;
    let mut full = None;
    let mut diffs = None;
    let mut files = Vec::new();
    let mut unread = Vec::new();
    for line in lines {
        // Optional, so a manifest from before they existed still parses
        // (and is then due for a full review).
        if let Some(when) = line.strip_prefix("full ") {
            full = Some(when.parse().ok()?);
            continue;
        }
        if let Some(count) = line.strip_prefix("diffs ") {
            diffs = Some(count.parse().ok()?);
            continue;
        }
        let (list, digest, path) = if let Some(entry) = line.strip_prefix("unread ") {
            let (digest, path) = entry.split_once(' ')?;
            (&mut unread, digest, path)
        } else {
            let mut fields = line.strip_prefix("file ")?.splitn(3, ' ');
            let digest = fields.next()?;
            if fields.next()?.parse::<usize>().is_err() {
                return None;
            }
            (&mut files, digest, fields.next()?)
        };
        if !is_hex_digest(digest) || path.is_empty() {
            return None;
        }
        list.push((digest.to_string(), path.to_string()));
    }
    Some(Manifest {
        identity,
        prompt,
        settings,
        recorded,
        full,
        diffs,
        files,
        unread,
    })
}

fn read_manifest(store: &Store, name: &str) -> Result<Option<Manifest>, Error> {
    Ok(store
        .read(BASELINES, name)?
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|text| parse_manifest(&text)))
}

/// The approved version of every unit that has a baseline, keyed by path
/// in the reviewed tree; `None` when no unit has one. A baseline that
/// does not parse (including an older format), names another identity, was
/// approved under another prompt version or other agent `settings`, or has
/// a missing or corrupt blob is deleted. This one does not ask how old the
/// baseline is; a review uses `load_fresh`.
#[cfg(test)]
pub(crate) fn load(
    store: &Store,
    class: SourceClass,
    units: &[Unit],
    settings: &AgentSettings,
) -> Result<Option<Approved>, Error> {
    load_with(store, class, units, settings, None).map(|loaded| loaded.approved)
}

/// What `load_fresh` found.
#[derive(Debug, Default)]
pub(super) struct Loaded {
    pub(super) approved: Option<Approved>,
    /// Why a unit's baseline was retired as due for a full review, as a
    /// line for the report.
    pub(super) due: Vec<String>,
}

/// `load` for a review at time `now`: a baseline that is due for a full
/// review (see `MAX_DIFF_REVIEWS`, `MAX_DAYS_SINCE_FULL`) is deleted like
/// any other that no longer counts, so that review is a full one and the
/// baseline it records starts again.
pub(super) fn load_fresh(
    store: &Store,
    class: SourceClass,
    units: &[Unit],
    settings: &AgentSettings,
    now: u64,
) -> Result<Loaded, Error> {
    load_with(store, class, units, settings, Some(now))
}

fn load_with(
    store: &Store,
    class: SourceClass,
    units: &[Unit],
    settings: &AgentSettings,
    now: Option<u64>,
) -> Result<Loaded, Error> {
    let expected = fingerprint(settings, class);
    let mut approved = Approved::default();
    let mut loaded = Loaded::default();
    let mut found = false;
    for unit in units {
        let name = manifest_name(class, &unit.identity);
        if store.read(BASELINES, &name)?.is_none() {
            continue;
        }
        match load_unit(store, &name, unit, &expected, now)? {
            UnitBaseline::Approved(files, unread) => {
                found = true;
                approved.prefixes.push(unit.prefix.clone());
                approved.files.extend(files);
                approved.unread.extend(unread);
            }
            UnitBaseline::Stale => store.remove(BASELINES, &name)?,
            UnitBaseline::Due(reason) => {
                loaded.due.push(format!(
                    "the approved version of {} is due for a full review: {reason}",
                    unit.identity.as_str()
                ));
                store.remove(BASELINES, &name)?;
            }
        }
    }
    loaded.approved = found.then_some(approved);
    Ok(loaded)
}

/// What one unit's stored baseline is worth to a review.
enum UnitBaseline {
    /// Its files and unread files, by path in the reviewed tree.
    Approved(Entries, Entries),
    /// Unreadable, another identity's, or approved under another prompt or
    /// other settings.
    Stale,
    /// Good, but due for a full review, with the reason.
    Due(String),
}

fn load_unit(
    store: &Store,
    name: &str,
    unit: &Unit,
    fingerprint: &str,
    now: Option<u64>,
) -> Result<UnitBaseline, Error> {
    let Some(manifest) = read_manifest(store, name)? else {
        return Ok(UnitBaseline::Stale);
    };
    if manifest.identity != unit.identity.as_str()
        || manifest.prompt != PROMPT_VERSION
        || manifest.settings != fingerprint
    {
        return Ok(UnitBaseline::Stale);
    }
    if let Some(reason) = now.and_then(|now| due(&manifest, now)) {
        return Ok(UnitBaseline::Due(reason));
    }
    let mut files = Vec::with_capacity(manifest.files.len());
    for (digest, path) in manifest.files {
        let Some(content) = store
            .get_blob(&digest)?
            .and_then(|bytes| String::from_utf8(bytes).ok())
        else {
            return Ok(UnitBaseline::Stale);
        };
        files.push((format!("{}{path}", unit.prefix), content));
    }
    let unread = manifest
        .unread
        .into_iter()
        .map(|(digest, path)| (format!("{}{path}", unit.prefix), digest))
        .collect();
    Ok(UnitBaseline::Approved(files, unread))
}

/// Deletes the baselines of `units`: the engine does so when a review that
/// had one is done in full instead, so what that review approves starts
/// again from a full review.
pub(super) fn retire(store: &Store, class: SourceClass, units: &[Unit]) -> Result<(), Error> {
    for unit in units {
        store.remove(BASELINES, &manifest_name(class, &unit.identity))?;
    }
    Ok(())
}

/// Records each unit's reviewed files, and the `unread` ones beside them,
/// as its approved version under the current prompt version and the agent
/// `settings` they were reviewed with. Paths that contain a newline or a
/// carriage return cannot be listed in a manifest and are left out, so they
/// are reviewed whole next time (`str::lines` strips a trailing '\r' too,
/// so such a path would otherwise round-trip under the wrong key). While an
/// unread file is left out (such a path, one outside every unit, one
/// without a digest), every review is a full one.
///
/// A unit that still has a baseline was reviewed against it (the engine
/// deletes the baseline of a review it does in full): when the files
/// differ, that was one more upgrade approved as a diff since the last
/// full review, and when they are the same, nothing new was approved.
/// Without one, this review was a full one.
pub(crate) fn record(
    store: &Store,
    class: SourceClass,
    units: &[Unit],
    files: &[SourceFile],
    unread: &Unread,
    settings: &AgentSettings,
    now: u64,
) -> Result<(), Error> {
    let approved_under = fingerprint(settings, class);
    for unit in units {
        let mut kept_files: Entries = Vec::new();
        let mut entries = String::new();
        for file in files {
            let Some(path) = file.path.strip_prefix(unit.prefix.as_str()) else {
                continue;
            };
            if path.is_empty() || path.contains('\n') || path.contains('\r') {
                continue;
            }
            let digest = store.put_blob(file.content.as_bytes())?;
            let _ = writeln!(entries, "file {digest} {} {path}", file.content.len());
            kept_files.push((digest, path.to_string()));
        }
        let mut kept_unread: Entries = Vec::new();
        for (path, digest) in unread {
            let Some(path) = path.strip_prefix(unit.prefix.as_str()) else {
                continue;
            };
            if path.is_empty()
                || path.contains('\n')
                || path.contains('\r')
                || !is_hex_digest(digest)
            {
                continue;
            }
            let _ = writeln!(entries, "unread {digest} {path}");
            kept_unread.push((digest.clone(), path.to_string()));
        }

        let name = manifest_name(class, &unit.identity);
        let reviewed_against = read_manifest(store, &name)?.filter(|manifest| {
            manifest.identity == unit.identity.as_str()
                && manifest.prompt == PROMPT_VERSION
                && manifest.settings == approved_under
        });
        let (full, diffs) = match reviewed_against {
            Some(Manifest {
                full: Some(full),
                diffs: Some(diffs),
                files,
                unread,
                ..
            }) => {
                let same = files == kept_files && unread == kept_unread;
                (full, diffs.saturating_add(u32::from(!same)))
            }
            Some(_) | None => (now, 0),
        };
        let text = format!(
            "{FORMAT}\nidentity {}\nprompt {PROMPT_VERSION}\nsettings {approved_under}\nrecorded {now}\nfull {full}\ndiffs {diffs}\n{entries}",
            unit.identity.as_str()
        );
        store.write(BASELINES, &name, text.as_bytes())?;
    }
    Ok(())
}

/// Deletes every class's baseline for `identity`; returns how many existed.
pub(crate) fn forget(store: &Store, identity: &Identity) -> Result<usize, Error> {
    let mut removed = 0;
    for &class in SourceClass::ALL {
        let name = manifest_name(class, identity);
        if store.read(BASELINES, &name)?.is_some() {
            store.remove(BASELINES, &name)?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// Deletes every baseline, blob and cached verdict; returns how many
/// baselines existed.
pub(crate) fn forget_all(store: &Store) -> Result<usize, Error> {
    let baselines = store.list(BASELINES)?.len();
    for dir in [BASELINES, VERDICTS, BLOBS] {
        for name in store.list(dir)? {
            store.remove(dir, &name)?;
        }
    }
    Ok(baselines)
}

/// Deletes stale leftover temp files, blobs no baseline references, then the
/// oldest baselines until the store fits in `max_bytes`. Unreadable
/// baselines are deleted.
pub(super) fn collect_garbage(store: &Store, max_bytes: u64, now: u64) -> Result<(), Error> {
    store.sweep_stale_temp_files(now)?;
    let mut manifests: Vec<(u64, String, Vec<String>)> = Vec::new();
    for name in store.list(BASELINES)? {
        if let Some(manifest) = read_manifest(store, &name)? {
            let digests = manifest
                .files
                .into_iter()
                .map(|(digest, _)| digest)
                .collect();
            manifests.push((manifest.recorded, name, digests));
        } else {
            store.remove(BASELINES, &name)?;
        }
    }
    // Oldest first.
    manifests.sort();

    loop {
        let referenced: BTreeSet<&str> = manifests
            .iter()
            .flat_map(|(_, _, digests)| digests.iter().map(String::as_str))
            .collect();
        for name in store.list(BLOBS)? {
            if !referenced.contains(name.as_str()) {
                store.remove(BLOBS, &name)?;
            }
        }
        if manifests.is_empty() || store.size()? <= max_bytes {
            return Ok(());
        }
        let (_, name, _) = manifests.remove(0);
        store.remove(BASELINES, &name)?;
    }
}

#[cfg(test)]
mod tests {
    use super::{Identity, Unit, Unread, collect_garbage, fingerprint, forget, forget_all};
    use crate::agent::SourceFile;
    use crate::config::model::{AgentSettings, SourceClass, Thinking};
    use crate::engine::plan::Previous;
    use crate::engine::request::PROMPT_VERSION;
    use crate::engine::store::{BASELINES, BLOBS, Store, VERDICTS};
    use crate::error::Error;
    use crate::test_support::TempDir;

    /// The approved text alone, as most tests here need it.
    fn load(
        store: &Store,
        class: SourceClass,
        units: &[Unit],
        settings: &AgentSettings,
    ) -> Result<Option<Previous>, Error> {
        Ok(super::load(store, class, units, settings)?.map(|approved| approved.files))
    }

    /// Records a version with nothing unread beside it.
    fn record(
        store: &Store,
        class: SourceClass,
        units: &[Unit],
        files: &[SourceFile],
        settings: &AgentSettings,
        now: u64,
    ) -> Result<(), Error> {
        super::record(store, class, units, files, &Unread::new(), settings, now)
    }

    fn file(path: &str, content: &str) -> SourceFile {
        SourceFile {
            path: path.into(),
            content: content.into(),
        }
    }

    fn unit(prefix: &str, identity: &str) -> Unit {
        Unit {
            prefix: prefix.into(),
            identity: Identity::parse(identity).unwrap(),
        }
    }

    fn settings() -> AgentSettings {
        AgentSettings::default()
    }

    fn store(dir: &TempDir) -> Store {
        Store::open(dir.path().join("store")).unwrap()
    }

    #[test]
    fn identities_are_bounded_and_printable() {
        assert!(Identity::parse("aur:yay-bin").is_ok());
        assert!(Identity::parse("").is_err());
        assert!(Identity::parse("a\nb").is_err());
        assert!(Identity::parse(&"x".repeat(513)).is_err());
    }

    #[test]
    fn a_recorded_baseline_loads_back() {
        let dir = TempDir::new("baseline-roundtrip");
        let store = store(&dir);
        let units = [unit("", "aur:demo")];
        assert_eq!(
            load(&store, SourceClass::Aur, &units, &settings()).unwrap(),
            None
        );

        record(
            &store,
            SourceClass::Aur,
            &units,
            &[file("PKGBUILD", "p\n"), file("src/a.c", "a\n")],
            &settings(),
            5,
        )
        .unwrap();

        let previous = load(&store, SourceClass::Aur, &units, &settings())
            .unwrap()
            .unwrap();
        assert_eq!(previous.get("PKGBUILD").map(String::as_str), Some("p\n"));
        assert_eq!(previous.get("src/a.c").map(String::as_str), Some("a\n"));
        assert_eq!(
            load(&store, SourceClass::Theme, &units, &settings()).unwrap(),
            None
        );
    }

    #[test]
    fn unread_changes_are_named_for_the_review() {
        let digest = |fill: &str| fill.repeat(64);
        let whole_tree = |unread: Unread| super::Approved {
            unread,
            prefixes: vec![String::new()],
            ..super::Approved::default()
        };
        let approved = whole_tree(Unread::from([
            ("lib/a.so".to_string(), digest("a")),
            ("lib/b.so".to_string(), digest("b")),
            ("node_modules/".to_string(), String::new()),
        ]));
        let same = Unread::from([("lib/a.so".to_string(), digest("a"))]);
        assert_eq!(
            super::unread_changes(&whole_tree(same.clone()), &same),
            None
        );
        // Another unit's files are not this approval's to compare.
        let one_unit = super::Approved {
            prefixes: vec!["lib/".to_string()],
            ..whole_tree(same)
        };
        let beside = Unread::from([
            ("lib/a.so".to_string(), digest("a")),
            ("other/x.so".to_string(), digest("x")),
        ]);
        assert_eq!(super::unread_changes(&one_unit, &beside), None);
        let current = Unread::from([
            ("lib/a.so".to_string(), digest("c")),
            ("lib/n\"ew.so".to_string(), digest("d")),
            ("node_modules/".to_string(), String::new()),
        ]);
        let fact = super::unread_changes(&approved, &current).unwrap();
        assert!(fact.contains(
            r#""lib/a.so" (changed), "lib/n\"ew.so" (new), "node_modules/" (changed), "lib/b.so" (removed)."#
        ), "{fact}");

        let many: Unread = (0..25).map(|n| (format!("f{n:02}"), digest("a"))).collect();
        let fact = super::unread_changes(&whole_tree(Unread::new()), &many).unwrap();
        assert!(fact.contains(r#""f19" (new) and 5 more."#), "{fact}");
        assert!(!fact.contains("f20"));
        let long = Unread::from([("x".repeat(500), digest("a"))]);
        let fact = super::unread_changes(&whole_tree(Unread::new()), &long).unwrap();
        assert!(
            fact.contains(&format!("\"{}\" (new)", "x".repeat(120))),
            "{fact}"
        );
    }

    #[test]
    fn unread_files_are_kept_per_unit() {
        let dir = TempDir::new("baseline-unread");
        let store = store(&dir);
        let good = [unit("good/", "theme:good")];
        let digest = "a".repeat(64);
        let unread = Unread::from([
            ("good/lib/helper.so".to_string(), digest.clone()),
            ("bad/x.so".to_string(), digest.clone()),
            ("good/odd\nname".to_string(), digest.clone()),
            ("good/node_modules/".to_string(), String::new()),
        ]);
        super::record(
            &store,
            SourceClass::Theme,
            &good,
            &[file("good/init.lua", "i\n")],
            &unread,
            &settings(),
            1,
        )
        .unwrap();

        let approved = super::load(&store, SourceClass::Theme, &good, &settings())
            .unwrap()
            .unwrap();
        assert_eq!(
            approved.unread,
            Unread::from([("good/lib/helper.so".to_string(), digest)])
        );
        assert_eq!(approved.files.len(), 1);
    }

    #[test]
    fn units_keep_their_own_files() {
        let dir = TempDir::new("baseline-units");
        let store = store(&dir);
        let good = [unit("good/", "theme:good")];
        record(
            &store,
            SourceClass::Theme,
            &good,
            &[file("good/colors.toml", "c\n"), file("bad/x.lua", "x\n")],
            &settings(),
            1,
        )
        .unwrap();

        let previous = load(&store, SourceClass::Theme, &good, &settings())
            .unwrap()
            .unwrap();
        let paths: Vec<&str> = previous.keys().map(String::as_str).collect();
        assert_eq!(paths, ["good/colors.toml"]);
    }

    #[test]
    fn paths_with_spaces_round_trip_and_newlines_are_skipped() {
        let dir = TempDir::new("baseline-paths");
        let store = store(&dir);
        let units = [unit("", "source:/tmp/x")];
        record(
            &store,
            SourceClass::Source,
            &units,
            &[
                file("my file.c", "a\n"),
                file("bad\nname.c", "b\n"),
                file("bad\rname.c", "c\n"),
            ],
            &settings(),
            1,
        )
        .unwrap();

        let previous = load(&store, SourceClass::Source, &units, &settings())
            .unwrap()
            .unwrap();
        let paths: Vec<&str> = previous.keys().map(String::as_str).collect();
        assert_eq!(paths, ["my file.c"]);
    }

    #[test]
    fn a_baseline_with_a_corrupt_blob_or_another_identity_is_deleted() {
        let dir = TempDir::new("baseline-corrupt");
        let store = store(&dir);
        let units = [unit("", "aur:demo")];
        record(
            &store,
            SourceClass::Aur,
            &units,
            &[file("PKGBUILD", "p\n")],
            &settings(),
            1,
        )
        .unwrap();
        for blob in store.list(BLOBS).unwrap() {
            store.write(BLOBS, &blob, b"tampered").unwrap();
        }
        assert_eq!(
            load(&store, SourceClass::Aur, &units, &settings()).unwrap(),
            None
        );
        assert!(store.list(BASELINES).unwrap().is_empty());

        // A manifest copied under another identity's name is not trusted.
        record(
            &store,
            SourceClass::Aur,
            &units,
            &[file("PKGBUILD", "p\n")],
            &settings(),
            1,
        )
        .unwrap();
        let name = store.list(BASELINES).unwrap().remove(0);
        let bytes = store.read(BASELINES, &name).unwrap().unwrap();
        let other = [unit("", "aur:other")];
        record(&store, SourceClass::Aur, &other, &[], &settings(), 1).unwrap();
        let other_name = store
            .list(BASELINES)
            .unwrap()
            .into_iter()
            .find(|candidate| *candidate != name)
            .unwrap();
        store.write(BASELINES, &other_name, &bytes).unwrap();
        assert_eq!(
            load(&store, SourceClass::Aur, &other, &settings()).unwrap(),
            None
        );
    }

    #[test]
    fn a_baseline_approved_under_other_settings_or_prompt_is_deleted() {
        let dir = TempDir::new("baseline-settings");
        let store = store(&dir);
        let units = [unit("", "aur:demo")];
        let files = [file("PKGBUILD", "p\n")];
        let others = [
            AgentSettings {
                thinking: Thinking::Max,
                ..AgentSettings::default()
            },
            AgentSettings {
                model: Some("a/b".into()),
                ..AgentSettings::default()
            },
            AgentSettings {
                variant: Some("deep".into()),
                ..AgentSettings::default()
            },
        ];
        for other in &others {
            record(&store, SourceClass::Aur, &units, &files, &settings(), 1).unwrap();
            assert!(
                load(&store, SourceClass::Aur, &units, &settings())
                    .unwrap()
                    .is_some()
            );
            assert_eq!(load(&store, SourceClass::Aur, &units, other).unwrap(), None);
            assert!(store.list(BASELINES).unwrap().is_empty(), "{other:?}");
        }

        // A manifest approved under another prompt version is not trusted.
        record(&store, SourceClass::Aur, &units, &files, &settings(), 1).unwrap();
        let name = store.list(BASELINES).unwrap().remove(0);
        let text = String::from_utf8(store.read(BASELINES, &name).unwrap().unwrap()).unwrap();
        let older_prompt = text.replace(
            &format!("\nprompt {PROMPT_VERSION}\n"),
            &format!("\nprompt {}\n", PROMPT_VERSION - 1),
        );
        assert_ne!(older_prompt, text);
        store
            .write(BASELINES, &name, older_prompt.as_bytes())
            .unwrap();
        assert_eq!(
            load(&store, SourceClass::Aur, &units, &settings()).unwrap(),
            None
        );
        assert!(store.list(BASELINES).unwrap().is_empty());

        // Nor does the format before unread files were listed.
        let format_two = text.replace(
            "omarchy-guardian-baseline 3\n",
            "omarchy-guardian-baseline 2\n",
        );
        assert!(format_two.starts_with("omarchy-guardian-baseline 2\nidentity aur:demo\n"));
        store
            .write(BASELINES, &name, format_two.as_bytes())
            .unwrap();
        assert_eq!(
            load(&store, SourceClass::Aur, &units, &settings()).unwrap(),
            None
        );

        // A format-1 manifest (no prompt or settings) is no baseline.
        let format_one = text
            .replace(
                "omarchy-guardian-baseline 3\n",
                "omarchy-guardian-baseline 1\n",
            )
            .replace(
                &format!(
                    "prompt {PROMPT_VERSION}\nsettings {}\n",
                    fingerprint(&settings(), SourceClass::Aur)
                ),
                "",
            )
            .replace("full 1\ndiffs 0\n", "");
        assert!(
            format_one
                .starts_with("omarchy-guardian-baseline 1\nidentity aur:demo\nrecorded 1\nfile ")
        );
        store
            .write(BASELINES, &name, format_one.as_bytes())
            .unwrap();
        assert_eq!(
            load(&store, SourceClass::Aur, &units, &settings()).unwrap(),
            None
        );
        assert!(store.list(BASELINES).unwrap().is_empty());
    }

    #[test]
    fn a_baseline_is_bound_to_the_wording_of_the_prompts() {
        // The same settings under another class's request wording, or
        // under other prompt text, are another fingerprint: a wording
        // change without a new prompt version still retires a baseline.
        let aur = fingerprint(&settings(), SourceClass::Aur);
        assert_eq!(aur, fingerprint(&settings(), SourceClass::Aur));
        assert_ne!(aur, fingerprint(&settings(), SourceClass::System));
        assert_ne!(
            crate::engine::cache::prompt_digest("one wording"),
            crate::engine::cache::prompt_digest("another wording")
        );
        // A manifest whose fingerprint was made under other wording.
        let dir = TempDir::new("baseline-wording");
        let store = store(&dir);
        let units = [unit("", "aur:demo")];
        record(
            &store,
            SourceClass::Aur,
            &units,
            &[file("PKGBUILD", "p\n")],
            &settings(),
            1,
        )
        .unwrap();
        let name = store.list(BASELINES).unwrap().remove(0);
        let text = String::from_utf8(store.read(BASELINES, &name).unwrap().unwrap()).unwrap();
        let reworded = text.replace(&aur, &fingerprint(&settings(), SourceClass::Theme));
        assert_ne!(reworded, text);
        store.write(BASELINES, &name, reworded.as_bytes()).unwrap();
        assert_eq!(
            load(&store, SourceClass::Aur, &units, &settings()).unwrap(),
            None
        );
    }

    const DAY: u64 = 86_400;

    /// What `load_fresh` gives at `now`: whether there is a baseline, and
    /// why not when it was due.
    fn fresh(store: &Store, units: &[Unit], now: u64) -> (bool, Vec<String>) {
        let loaded = super::load_fresh(store, SourceClass::Aur, units, &settings(), now).unwrap();
        (loaded.approved.is_some(), loaded.due)
    }

    #[test]
    fn a_baseline_is_due_for_a_full_review_after_five_upgrades() {
        let dir = TempDir::new("baseline-generations");
        let store = store(&dir);
        let units = [unit("", "aur:demo")];
        let version = |number: u32| {
            [
                file("PKGBUILD", &format!("pkgver={number}\n")),
                file("a", "a\n"),
            ]
        };
        let approve = |number: u32, now: u64| {
            record(
                &store,
                SourceClass::Aur,
                &units,
                &version(number),
                &settings(),
                now,
            )
            .unwrap();
        };
        // A full review, then five upgrades approved as diffs against it.
        approve(0, 100);
        for upgrade in 1..=5 {
            assert_eq!(fresh(&store, &units, 100), (true, Vec::new()), "{upgrade}");
            approve(upgrade, 100 + u64::from(upgrade));
        }
        let name = store.list(BASELINES).unwrap().remove(0);
        let text = String::from_utf8(store.read(BASELINES, &name).unwrap().unwrap()).unwrap();
        assert!(
            text.contains("\nrecorded 105\nfull 100\ndiffs 5\n"),
            "{text}"
        );

        // The sixth review is a full one: the baseline is retired.
        let (found, due) = fresh(&store, &units, 200);
        assert!(!found);
        assert!(
            matches!(due.as_slice(), [reason] if reason.contains("aur:demo") && reason.contains("5 upgrades")),
            "{due:?}"
        );
        assert!(store.list(BASELINES).unwrap().is_empty());
        // What it approves starts again.
        approve(6, 300);
        let text = String::from_utf8(store.read(BASELINES, &name).unwrap().unwrap()).unwrap();
        assert!(
            text.contains("\nrecorded 300\nfull 300\ndiffs 0\n"),
            "{text}"
        );
    }

    #[test]
    fn the_same_version_approved_again_is_no_upgrade() {
        let dir = TempDir::new("baseline-same");
        let store = store(&dir);
        let units = [unit("", "aur:demo")];
        let files = [file("PKGBUILD", "p\n")];
        // yay's second pass, a reinstall: nothing new was approved.
        for now in [100, 200, 300, 400, 500, 600, 700] {
            record(&store, SourceClass::Aur, &units, &files, &settings(), now).unwrap();
        }
        let name = store.list(BASELINES).unwrap().remove(0);
        let text = String::from_utf8(store.read(BASELINES, &name).unwrap().unwrap()).unwrap();
        assert!(
            text.contains("\nrecorded 700\nfull 100\ndiffs 0\n"),
            "{text}"
        );
        assert_eq!(fresh(&store, &units, 700), (true, Vec::new()));
        // A file Guardian does not read that changed is a new version.
        let unread = Unread::from([("lib.so".to_string(), "a".repeat(64))]);
        super::record(
            &store,
            SourceClass::Aur,
            &units,
            &files,
            &unread,
            &settings(),
            800,
        )
        .unwrap();
        let text = String::from_utf8(store.read(BASELINES, &name).unwrap().unwrap()).unwrap();
        assert!(text.contains("\nfull 100\ndiffs 1\n"), "{text}");
    }

    #[test]
    fn a_baseline_is_due_for_a_full_review_after_thirty_days() {
        let dir = TempDir::new("baseline-age");
        let store = store(&dir);
        let units = [unit("", "aur:demo")];
        let files = [file("PKGBUILD", "p\n")];
        let approve =
            || record(&store, SourceClass::Aur, &units, &files, &settings(), 1000).unwrap();

        approve();
        assert_eq!(
            fresh(&store, &units, 1000 + 30 * DAY - 1),
            (true, Vec::new())
        );
        let (found, due) = fresh(&store, &units, 1000 + 30 * DAY);
        assert!(!found);
        assert!(due[0].contains("30 days ago"), "{due:?}");
        assert!(store.list(BASELINES).unwrap().is_empty());

        // A clock set back does not keep a baseline young.
        approve();
        let (found, due) = fresh(&store, &units, 999);
        assert!(!found && due[0].contains("in the future"), "{due:?}");

        // A manifest written before the age was kept says nothing about
        // it: it parses, and is due.
        approve();
        let name = store.list(BASELINES).unwrap().remove(0);
        let text = String::from_utf8(store.read(BASELINES, &name).unwrap().unwrap()).unwrap();
        let older = text.replace("full 1000\ndiffs 0\n", "");
        assert_ne!(older, text);
        store.write(BASELINES, &name, older.as_bytes()).unwrap();
        assert!(
            load(&store, SourceClass::Aur, &units, &settings())
                .unwrap()
                .is_some()
        );
        let (found, due) = fresh(&store, &units, 1000);
        assert!(!found && due[0].contains("does not say"), "{due:?}");
        // And a version approved on top of one is not counted as a diff.
        store.write(BASELINES, &name, older.as_bytes()).unwrap();
        record(
            &store,
            SourceClass::Aur,
            &units,
            &[file("PKGBUILD", "q\n")],
            &settings(),
            2000,
        )
        .unwrap();
        let text = String::from_utf8(store.read(BASELINES, &name).unwrap().unwrap()).unwrap();
        assert!(text.contains("\nfull 2000\ndiffs 0\n"), "{text}");

        // Retiring deletes the units' baselines and nothing else.
        record(
            &store,
            SourceClass::Aur,
            &[unit("", "aur:other")],
            &files,
            &settings(),
            1,
        )
        .unwrap();
        super::retire(&store, SourceClass::Aur, &units).unwrap();
        assert_eq!(store.list(BASELINES).unwrap().len(), 1);
        super::retire(&store, SourceClass::Aur, &units).unwrap();
    }

    #[test]
    fn forget_removes_one_identity_or_everything() {
        let dir = TempDir::new("baseline-forget");
        let store = store(&dir);
        let units = [unit("", "aur:demo")];
        record(
            &store,
            SourceClass::Aur,
            &units,
            &[file("PKGBUILD", "p\n")],
            &settings(),
            1,
        )
        .unwrap();
        store.write(VERDICTS, "v", b"{}").unwrap();

        assert_eq!(forget(&store, &units[0].identity).unwrap(), 1);
        assert_eq!(forget(&store, &units[0].identity).unwrap(), 0);

        record(
            &store,
            SourceClass::Aur,
            &units,
            &[file("PKGBUILD", "p\n")],
            &settings(),
            1,
        )
        .unwrap();
        assert_eq!(forget_all(&store).unwrap(), 1);
        for dir_name in [BASELINES, BLOBS, VERDICTS] {
            assert!(store.list(dir_name).unwrap().is_empty(), "{dir_name}");
        }
    }

    #[test]
    fn garbage_collection_drops_orphans_then_the_oldest_baselines() {
        let dir = TempDir::new("baseline-gc");
        let store = store(&dir);
        record(
            &store,
            SourceClass::Aur,
            &[unit("", "aur:old")],
            &[file("a", "old\n")],
            &settings(),
            1,
        )
        .unwrap();
        record(
            &store,
            SourceClass::Aur,
            &[unit("", "aur:new")],
            &[file("a", "new\n")],
            &settings(),
            2,
        )
        .unwrap();
        store.put_blob(b"orphan").unwrap();

        collect_garbage(&store, u64::MAX, 1).unwrap();
        assert_eq!(store.list(BLOBS).unwrap().len(), 2);
        assert_eq!(store.list(BASELINES).unwrap().len(), 2);

        let size_of_newest = {
            let names = store.list(BASELINES).unwrap();
            let newest_manifest = names
                .iter()
                .map(|name| store.read(BASELINES, name).unwrap().unwrap())
                .find(|bytes| String::from_utf8_lossy(bytes).contains("aur:new"))
                .unwrap();
            u64::try_from(newest_manifest.len() + "new\n".len()).unwrap()
        };
        collect_garbage(&store, size_of_newest, 1).unwrap();
        assert!(
            load(
                &store,
                SourceClass::Aur,
                &[unit("", "aur:old")],
                &settings()
            )
            .unwrap()
            .is_none()
        );
        assert!(
            load(
                &store,
                SourceClass::Aur,
                &[unit("", "aur:new")],
                &settings()
            )
            .unwrap()
            .is_some()
        );

        collect_garbage(&store, 0, 1).unwrap();
        assert!(store.list(BASELINES).unwrap().is_empty());
        assert!(store.list(BLOBS).unwrap().is_empty());
    }
}
