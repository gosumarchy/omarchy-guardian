//! Tests for what the makepkg gate remembers between runs.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;

use super::{Drift, Extraction, Kept, State, binary_changes, identity};
use crate::test_support::TempDir;

fn map(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|(path, digest)| ((*path).to_string(), (*digest).to_string()))
        .collect()
}

#[test]
fn confirmations_are_kept_per_package_and_only_in_a_private_directory() {
    let dir = TempDir::new("gate-state");
    let root = dir.path().join("state");
    let state = State::open(Some(&root), "demo");
    assert!(!state.is_confirmed("prebuilt abc"));
    state.remember_confirmed("prebuilt abc");
    assert!(state.is_confirmed("prebuilt abc"));
    assert!(!state.is_confirmed("prebuilt abd"));
    assert!(!State::open(Some(&root), "other").is_confirmed("prebuilt abc"));
    // A new Guardian, as on yay's next makepkg call, still knows.
    assert!(State::open(Some(&root), "demo").is_confirmed("prebuilt abc"));
    let kept = root.join("aur-gate");
    assert_eq!(
        fs::metadata(&kept).unwrap().permissions().mode() & 0o777,
        0o700
    );
    // Only so many are kept.
    for index in 0..40 {
        state.remember_confirmed(&format!("sources {index}"));
    }
    assert!(!state.is_confirmed("prebuilt abc"));
    assert!(state.is_confirmed("sources 39"));

    // Without a directory, or with one open to others, nothing is
    // remembered: the question is asked again.
    let nowhere = State::open(None, "demo");
    nowhere.remember_confirmed("x");
    assert!(!nowhere.is_confirmed("x"));
    let open = dir.path().join("open");
    fs::create_dir(&open).unwrap();
    fs::set_permissions(&open, fs::Permissions::from_mode(0o755)).unwrap();
    let state = State::open(Some(&open), "demo");
    state.remember_confirmed("x");
    assert!(!state.is_confirmed("x"));
}

#[test]
fn binaries_and_extractions_round_trip() {
    let dir = TempDir::new("gate-state-files");
    let state = State::open(Some(&dir.path().join("state")), "demo");
    assert_eq!(state.binaries(), None);
    let binaries = map(&[
        ("src/a b/tool", "11"),
        ("src/odd\nname", ""),
        ("src/x", "22"),
    ]);
    state.record_binaries(&binaries);
    let known = state.binaries().unwrap();
    assert_eq!(known.len(), 3);
    assert_eq!(binary_changes(&known, &binaries).1, Vec::<String>::new());
    // A file without a hash always counts as changed.
    assert_eq!(binary_changes(&known, &binaries).0, ["src/odd\\nname"]);
    let now = map(&[("src/a b/tool", "99"), ("src/new", "33")]);
    let (changed, gone) = binary_changes(&known, &now);
    assert_eq!(changed, ["src/a b/tool", "src/new"]);
    assert_eq!(gone, ["src/odd\\nname", "src/x"]);

    let extraction = Extraction {
        srcdir: "/build/demo/src".into(),
        identity: Some("1:2:3".into()),
        cleanbuild: true,
        downloads: map(&[("demo.tar.gz", &"a".repeat(64))]),
        files: map(&[("src/demo/a.c", &"b".repeat(64)), ("src/x y", "")]),
        unlisted: false,
    };
    assert_eq!(state.extraction(), Kept::Absent);
    assert!(state.record_extraction(&extraction));
    let Kept::Usable(read) = state.extraction() else {
        panic!("a record");
    };
    assert_eq!(read.srcdir, extraction.srcdir);
    assert_eq!(read.identity, extraction.identity);
    assert!(read.cleanbuild);
    assert_eq!(read.downloads["demo.tar.gz"], "a".repeat(32));
    assert_eq!(read.files["src/x y"], "");
}

#[test]
fn a_later_call_sees_what_changed_since_guardian_extracted() {
    let downloads = map(&[("demo.tar.gz", &"a".repeat(64))]);
    let files = map(&[
        ("src/demo/a.c", &"b".repeat(64)),
        ("src/demo/b.c", &"c".repeat(64)),
    ]);
    let dir = TempDir::new("gate-drift");
    let state = State::open(Some(&dir.path().join("state")), "demo");
    state.record_extraction(&Extraction {
        srcdir: "/x".into(),
        identity: Some("1:2:3".into()),
        cleanbuild: true,
        downloads: downloads.clone(),
        files: files.clone(),
        unlisted: false,
    });
    let Kept::Usable(extraction) = state.extraction() else {
        panic!("a record");
    };
    // The build made the directory anew and left the files alone.
    assert_eq!(
        extraction.drift(Some("1:9:9"), &downloads, &files),
        Drift::Files(HashSet::new())
    );
    // Still the directory Guardian made: the build worked elsewhere.
    assert_eq!(
        extraction.drift(Some("1:2:3"), &downloads, &files),
        Drift::Elsewhere
    );
    // A download that changed, and one the listing did not show.
    let mut other = downloads.clone();
    other.insert("demo.tar.gz".into(), "f".repeat(64));
    other.insert("extra.bin".into(), "e".repeat(64));
    assert_eq!(
        extraction.drift(Some("1:9:9"), &other, &files),
        Drift::Downloads(vec!["demo.tar.gz".into(), "extra.bin".into()])
    );
    // What prepare() patched or added.
    let mut patched = files.clone();
    patched.insert("src/demo/a.c".into(), "d".repeat(64));
    patched.insert("src/demo/new.sh".into(), "e".repeat(64));
    patched.remove("src/demo/b.c");
    let Drift::Files(changed) = extraction.drift(None, &downloads, &patched) else {
        panic!("files");
    };
    let mut changed: Vec<String> = changed.into_iter().collect();
    changed.sort();
    assert_eq!(changed, ["src/demo/a.c", "src/demo/new.sh"]);
    // Without `--cleanbuild` the directory is the same one either way.
    let kept = Extraction {
        cleanbuild: false,
        ..extraction
    };
    assert_eq!(
        kept.drift(Some("1:2:3"), &downloads, &files),
        Drift::Files(HashSet::new())
    );
}

#[test]
fn a_directory_made_again_under_the_same_name_is_another_one() {
    let dir = TempDir::new("gate-identity");
    let src = dir.path().join("src");
    fs::create_dir(&src).unwrap();
    let Some(first) = identity(&src) else {
        // A filesystem that does not record when a directory was made.
        return;
    };
    assert_eq!(identity(&src).as_deref(), Some(first.as_str()));
    fs::remove_dir(&src).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    fs::create_dir(&src).unwrap();
    assert_ne!(identity(&src), Some(first));
    assert_eq!(identity(&dir.path().join("missing")), None);
}
