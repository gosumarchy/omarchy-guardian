//! Approved snapshots. After a complete, all-clear AI review of a
//! user-level source, its reviewed files are kept so the next version can be
//! reviewed as a diff against them. A baseline is bound to the prompt
//! version and the agent settings it was approved under: a stronger model or
//! a new prompt never inherits an older review's approval.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::str;

use crate::agent::SourceFile;
use crate::config::model::{AgentSettings, Named, SourceClass};
use crate::engine::plan::Previous;
use crate::engine::request::PROMPT_VERSION;
use crate::engine::store::{BASELINES, BLOBS, Store, VERDICTS, is_hex_digest};
use crate::error::Error;
use crate::sha256::Sha256;

const FORMAT: &str = "omarchy-guardian-baseline 2";
const MAX_IDENTITY_BYTES: usize = 512;

/// What a reviewed source is remembered as, such as `aur:yay-bin`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity(String);

impl Identity {
    pub fn parse(text: &str) -> Result<Self, String> {
        if text.is_empty() || text.len() > MAX_IDENTITY_BYTES || text.chars().any(char::is_control)
        {
            return Err(format!(
                "an identity is 1 to {MAX_IDENTITY_BYTES} bytes without control characters (got {text:?})"
            ));
        }
        Ok(Self(text.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The files under `prefix` (empty for the whole tree, else `dir/`) are
/// the source `identity`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unit {
    pub prefix: String,
    pub identity: Identity,
}

struct Manifest {
    identity: String,
    prompt: u32,
    /// `fingerprint` of the agent settings the files were approved under.
    settings: String,
    recorded: u64,
    /// (blob digest, path) per file.
    files: Vec<(String, String)>,
}

/// The agent settings a verdict depends on (the same ones `cache::key`
/// hashes besides the class and request), as a hex SHA-256.
pub fn fingerprint(settings: &AgentSettings) -> String {
    let text = format!(
        "omarchy-guardian-baseline-settings\0{}\0{}\0{}\0",
        settings.model.as_deref().unwrap_or_default(),
        settings.variant.as_deref().unwrap_or_default(),
        settings.thinking.name()
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
    let mut files = Vec::new();
    for line in lines {
        let mut fields = line.strip_prefix("file ")?.splitn(3, ' ');
        let digest = fields.next()?;
        if fields.next()?.parse::<usize>().is_err() {
            return None;
        }
        let path = fields.next()?;
        if !is_hex_digest(digest) || path.is_empty() {
            return None;
        }
        files.push((digest.to_string(), path.to_string()));
    }
    Some(Manifest {
        identity,
        prompt,
        settings,
        recorded,
        files,
    })
}

fn read_manifest(store: &Store, name: &str) -> Result<Option<Manifest>, Error> {
    Ok(store
        .read(BASELINES, name)?
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|text| parse_manifest(&text)))
}

/// The approved files of every unit that has a baseline, keyed by their
/// path in the reviewed tree; `None` when no unit has one. A baseline that
/// does not parse (including an older format), names another identity, was
/// approved under another prompt version or other agent `settings`, or has
/// a missing or corrupt blob is deleted.
pub fn load(
    store: &Store,
    class: SourceClass,
    units: &[Unit],
    settings: &AgentSettings,
) -> Result<Option<Previous>, Error> {
    let expected = fingerprint(settings);
    let mut previous = Previous::new();
    let mut found = false;
    for unit in units {
        let name = manifest_name(class, &unit.identity);
        if store.read(BASELINES, &name)?.is_none() {
            continue;
        }
        if let Some(files) = load_unit(store, &name, unit, &expected)? {
            found = true;
            previous.extend(files);
        } else {
            store.remove(BASELINES, &name)?;
        }
    }
    Ok(found.then_some(previous))
}

fn load_unit(
    store: &Store,
    name: &str,
    unit: &Unit,
    fingerprint: &str,
) -> Result<Option<Vec<(String, String)>>, Error> {
    let Some(manifest) = read_manifest(store, name)? else {
        return Ok(None);
    };
    if manifest.identity != unit.identity.as_str()
        || manifest.prompt != PROMPT_VERSION
        || manifest.settings != fingerprint
    {
        return Ok(None);
    }
    let mut files = Vec::with_capacity(manifest.files.len());
    for (digest, path) in manifest.files {
        let Some(content) = store
            .get_blob(&digest)?
            .and_then(|bytes| String::from_utf8(bytes).ok())
        else {
            return Ok(None);
        };
        files.push((format!("{}{path}", unit.prefix), content));
    }
    Ok(Some(files))
}

/// Records each unit's reviewed files as its approved version under the
/// current prompt version and the agent `settings` they were reviewed with.
/// Paths that
/// contain a newline or a carriage return cannot be listed in a manifest
/// and are left out, so they are reviewed whole next time (`str::lines`
/// strips a trailing '\r' too, so such a path would otherwise round-trip
/// under the wrong key).
pub fn record(
    store: &Store,
    class: SourceClass,
    units: &[Unit],
    files: &[SourceFile],
    settings: &AgentSettings,
    now: u64,
) -> Result<(), Error> {
    let approved_under = fingerprint(settings);
    for unit in units {
        let mut text = format!(
            "{FORMAT}\nidentity {}\nprompt {PROMPT_VERSION}\nsettings {approved_under}\nrecorded {now}\n",
            unit.identity.as_str()
        );
        for file in files {
            let Some(path) = file.path.strip_prefix(unit.prefix.as_str()) else {
                continue;
            };
            if path.is_empty() || path.contains('\n') || path.contains('\r') {
                continue;
            }
            let digest = store.put_blob(file.content.as_bytes())?;
            let _ = writeln!(text, "file {digest} {} {path}", file.content.len());
        }
        store.write(
            BASELINES,
            &manifest_name(class, &unit.identity),
            text.as_bytes(),
        )?;
    }
    Ok(())
}

/// Deletes every class's baseline for `identity`; returns how many existed.
pub fn forget(store: &Store, identity: &Identity) -> Result<usize, Error> {
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
pub fn forget_all(store: &Store) -> Result<usize, Error> {
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
pub fn collect_garbage(store: &Store, max_bytes: u64, now: u64) -> Result<(), Error> {
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
    use super::{Identity, Unit, collect_garbage, fingerprint, forget, forget_all, load, record};
    use crate::agent::SourceFile;
    use crate::config::model::{AgentSettings, SourceClass, Thinking};
    use crate::engine::request::PROMPT_VERSION;
    use crate::engine::store::{BASELINES, BLOBS, Store, VERDICTS};
    use crate::test_support::TempDir;

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

        // A format-1 manifest (no prompt or settings) is no baseline.
        let format_one = text
            .replace(
                "omarchy-guardian-baseline 2\n",
                "omarchy-guardian-baseline 1\n",
            )
            .replace(
                &format!(
                    "prompt {PROMPT_VERSION}\nsettings {}\n",
                    fingerprint(&settings())
                ),
                "",
            );
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
