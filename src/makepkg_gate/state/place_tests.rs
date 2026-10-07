//! Tests for a build whose records have no directory: one that is refused
//! or cannot be made stops it, and none at all is as it always was.
//!
//! Each directory is made unusable the same way for root as for a user:
//! by its mode, which is read and not tried, or by a file where a
//! directory should be.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use super::super::confirm::{binary_changes, confirm_not_followed, remember_binaries};
use super::super::{NOWHERE_NOTICE, NotHeld, hold_against_extraction, record_extraction};
use super::record_tests::{Tree, usable, with_step};
use super::{Kept, Missing, NotKept, State};
use crate::cli::Confirm;

const REFUSED: &str = "the directory of Guardian's records of builds is not the user's alone";
const NOT_MADE: &str = "the directory of Guardian's records of builds could not be made";

/// Says yes, and counts how often it was asked.
struct Yes(usize);

impl Confirm for Yes {
    fn confirm(&mut self, _question: &str) -> bool {
        self.0 += 1;
        true
    }
}

/// A build whose records would be kept under `root`.
fn tree_under(label: &str, root: impl FnOnce(&Path) -> std::path::PathBuf) -> Tree {
    let mut tree = Tree::new(label, "build".into(), "demo.tar.gz");
    let root = root(tree.dir.path());
    tree.state = State::open(Some(&root), "demo");
    tree
}

/// Both calls of the build must be stopped, for `why`, each message
/// holding `parts`; and what only saves a question or informs goes on.
fn stops_both_calls(tree: &Tree, why: &str, parts: &[&str]) {
    let src = tree.src();
    let check = |refused: &NotHeld, own: &str| {
        assert_eq!(refused.why, why);
        for part in parts.iter().chain(&[own, "Nothing was built."]) {
            assert!(
                refused.message.contains(part),
                "{part}: {}",
                refused.message
            );
        }
    };
    assert!(!tree.state.is_nowhere());
    assert!(matches!(tree.state.extraction(), Kept::Missing(_)));
    with_step(tree, &[], |step| {
        check(
            &record_extraction(step, &src, &tree.collected()).unwrap_err(),
            "no record of the sources it extracted for this build could be kept, and a later call of this build could not be held to them",
        );
        check(
            &hold_against_extraction(step, &src, &mut tree.collected()).unwrap_err(),
            "whether it has a record of the sources it extracted for this build cannot be known, and the sources cannot be held against one",
        );
        // An answer is not remembered and the binaries are not recorded:
        // both say so and neither stops anything.
        assert!(step.state.remember_confirmed("x").is_err());
        let mut yes = Yes(0);
        for asked in [1, 2] {
            assert!(confirm_not_followed(step, &["why".into()], &[], &mut yes));
            assert_eq!(yes.0, asked);
        }
        let upstream = tree.collected().select(1 << 20);
        remember_binaries(step, &upstream);
        assert_eq!(step.state.binaries(), None);
        assert_eq!(binary_changes(step, &upstream), None);
    });
}

#[test]
fn a_state_directory_open_to_others_stops_both_calls_of_a_build() {
    // The directory above the gate's own, open to the group.
    let mut tree = tree_under("gate-place-root", |dir| {
        let root = dir.join("open");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).unwrap();
        root
    });
    let root = tree.dir.path().join("open");
    let named = root.display().to_string();
    stops_both_calls(
        &tree,
        REFUSED,
        &[
            "Guardian does not use the directory it keeps its records of builds in (",
            &format!("{named} is accessible to group or others"),
            &format!("Make {named} a directory of yours alone (`chmod 700 {named}`)"),
            "or remove what is in its place; then run the build again from the start.",
        ],
    );
    assert!(!root.join("aur-gate").exists());

    // The gate's own directory, open to the group.
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let kept = root.join("aur-gate");
    fs::create_dir(&kept).unwrap();
    fs::set_permissions(&kept, fs::Permissions::from_mode(0o770)).unwrap();
    tree.state = State::open(Some(&root), "demo");
    let named = kept.display().to_string();
    assert_eq!(
        tree.state.extraction(),
        Kept::Missing(Missing::Refused {
            directory: kept.clone(),
            reason: format!("{named} is accessible to group or others"),
        })
    );
    stops_both_calls(
        &tree,
        REFUSED,
        &[
            &format!("{named} is accessible to group or others"),
            &format!("(`chmod 700 {named}`)"),
        ],
    );

    // Made the user's alone, it is used.
    fs::set_permissions(&kept, fs::Permissions::from_mode(0o700)).unwrap();
    tree.state = State::open(Some(&root), "demo");
    let src = tree.src();
    with_step(&tree, &[], |step| {
        assert_eq!(record_extraction(step, &src, &tree.collected()), Ok(()));
        assert!(usable(step.state).is_of(&src));
        assert_eq!(
            hold_against_extraction(step, &src, &mut tree.collected()),
            Ok(Vec::new())
        );
    });
}

#[test]
fn a_file_where_the_state_directory_goes_stops_both_calls_of_a_build() {
    let tree = tree_under("gate-place-file", |dir| {
        let root = dir.join("mine");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root.join("aur-gate"), "x").unwrap();
        root
    });
    let kept = tree.dir.path().join("mine/aur-gate");
    let named = kept.display().to_string();
    stops_both_calls(
        &tree,
        REFUSED,
        &[
            &format!("{named} is not a directory"),
            &format!("(`chmod 700 {named}`), or remove what is in its place"),
        ],
    );
    assert_eq!(fs::read_to_string(&kept).unwrap(), "x");
}

#[test]
fn a_state_directory_that_cannot_be_made_stops_both_calls_of_a_build() {
    // A file where a directory above it should be: no one can make it.
    let tree = tree_under("gate-place-unmade", |dir| {
        fs::write(dir.join("file"), "x").unwrap();
        dir.join("file/state")
    });
    let root = tree.dir.path().join("file/state");
    let named = root.display().to_string();
    match tree.state.extraction() {
        Kept::Missing(Missing::NotMade { directory, reason }) => {
            assert_eq!(directory, root);
            assert!(reason.starts_with(&format!("{named}: ")), "{reason}");
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        tree.state.record_extraction(&super::Extraction::default()),
        Err(NotKept::Missing(Missing::NotMade { .. }))
    ));
    stops_both_calls(
        &tree,
        NOT_MADE,
        &[
            "Guardian could not make the directory it keeps its records of builds in (",
            &format!("{named}: "),
            &format!("put right what the error names, so that {named} can be made"),
            "then run the build again from the start.",
        ],
    );
}

#[test]
fn with_nowhere_to_keep_anything_a_build_is_reviewed_as_it_is_found() {
    let mut tree = Tree::new("gate-place-nowhere", "build".into(), "demo.tar.gz");
    tree.state = State::open(None, "demo");
    let src = tree.src();
    assert!(tree.state.is_nowhere());
    assert!(NOWHERE_NOTICE.starts_with("Guardian has nowhere to keep a record"));
    with_step(&tree, &[], |step| {
        // Nothing is recorded, which is said (on standard error) and is
        // no reason to stop; the later call finds no record.
        assert_eq!(record_extraction(step, &src, &tree.collected()), Ok(()));
        assert_eq!(step.state.extraction(), Kept::Absent);
        let facts = hold_against_extraction(step, &src, &mut tree.collected()).unwrap();
        assert!(facts[0].contains("did not extract these sources itself"));
        // Nor is anything else kept, or an error.
        step.state.remember_confirmed("x").unwrap();
        assert!(!step.state.is_confirmed("x"));
        let upstream = tree.collected().select(1 << 20);
        step.state
            .record_binaries(&std::collections::BTreeMap::default())
            .unwrap();
        remember_binaries(step, &upstream);
        assert_eq!(step.state.binaries(), None);
    });
}
