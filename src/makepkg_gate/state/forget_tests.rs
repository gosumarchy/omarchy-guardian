//! Tests for forgetting what the makepkg gate remembers.

use std::collections::BTreeMap;
use std::fs;

use super::{State, forget, forget_all};
use crate::test_support::TempDir;

#[test]
fn forgetting_a_package_takes_its_records_and_leaves_the_others() {
    let dir = TempDir::new("gate-forget");
    let root = dir.path().join("state");
    let binaries: BTreeMap<String, String> = [("src/demo/tool".to_string(), "a".repeat(64))].into();
    for key in ["demo", "other"] {
        let state = State::open(Some(&root), key);
        state.remember_confirmed("sources abc");
        state.record_binaries(&binaries);
    }
    assert_eq!(forget(&root, "demo"), Ok(2));
    let demo = State::open(Some(&root), "demo");
    assert!(!demo.is_confirmed("sources abc"));
    assert_eq!(demo.binaries(), None);
    assert!(State::open(Some(&root), "other").is_confirmed("sources abc"));
    assert_eq!(forget(&root, "demo"), Ok(0));

    assert_eq!(forget_all(&root), Ok(2));
    assert!(!State::open(Some(&root), "other").is_confirmed("sources abc"));
    // The directory stays, for the next build.
    assert!(root.join("aur-gate").is_dir());
    assert_eq!(forget_all(&dir.path().join("none")), Ok(0));
    // A link in the directory's place is not followed.
    let elsewhere = dir.path().join("elsewhere");
    fs::create_dir_all(elsewhere.join("aur-gate")).unwrap();
    fs::write(elsewhere.join("aur-gate/kept"), "x").unwrap();
    let linked = dir.path().join("linked");
    fs::create_dir(&linked).unwrap();
    std::os::unix::fs::symlink(elsewhere.join("aur-gate"), linked.join("aur-gate")).unwrap();
    assert!(forget_all(&linked).is_err());
    assert!(elsewhere.join("aur-gate/kept").exists());
}
