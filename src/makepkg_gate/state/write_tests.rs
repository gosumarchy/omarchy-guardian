//! Tests for a record that cannot be written, and for a directory where
//! a record goes.
//!
//! The writes are made to fail the same way for root as for a user: by a
//! directory that is not empty under the name the new file is written to,
//! or by taking the state directory away. Permissions alone stop no write
//! of root's, so the one test that uses them asks first whether they do.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use super::super::confirm::{
    Prebuilt, all_binaries, binary_changes, confirm_not_followed, confirm_prebuilt,
    remember_binaries,
};
use super::super::{NotHeld, hold_against_extraction, record_extraction};
use super::record_tests::{Tree, usable, with_step};
use super::{Kept, NotKept, State, forget};
use crate::cli::Confirm;
use crate::error::Error;

const NOT_WRITTEN: &str = "the record of what Guardian extracted could not be written";
const IN_THE_WAY: &str = "a directory is in the place of the record of what Guardian extracted";

/// Keeps `state` from writing its record `what`: a directory that is not
/// empty takes the name its new file is written under. Returns it.
fn block_writes(state: &State, what: &str) -> PathBuf {
    let path = state.path(what).unwrap();
    let temporary = path.with_extension(format!("{what}.{}.tmp", std::process::id()));
    fs::create_dir(&temporary).unwrap();
    fs::write(temporary.join("kept"), "x").unwrap();
    temporary
}

/// Says yes, and counts how often it was asked.
struct Yes(usize);

impl Confirm for Yes {
    fn confirm(&mut self, _question: &str) -> bool {
        self.0 += 1;
        true
    }
}

/// The refusal must be the one for a record that was not written, naming
/// `named` and the state directory, and saying what to do.
fn assert_not_written(tree: &Tree, refused: &NotHeld, named: &str) {
    assert_eq!(refused.why, NOT_WRITTEN);
    let directory = tree.state.directory().unwrap().display().to_string();
    for part in [
        "Guardian could not write its record of the sources it extracted for this build (",
        named,
        "so a later call of this build could not be held to them. Nothing was built.",
        &format!("Free space on that disk, or fix the permissions of {directory}"),
        "then run the build again.",
    ] {
        assert!(
            refused.message.contains(part),
            "{part}: {}",
            refused.message
        );
    }
}

#[test]
fn a_record_that_cannot_be_written_stops_the_build_that_extracts() {
    let tree = Tree::new("gate-write-fails", "build".into(), "demo.tar.gz");
    let src = tree.src();
    let record = tree.state.path("extraction").unwrap();
    let temporary = block_writes(&tree.state, "extraction");
    with_step(&tree, &[], |step| {
        // The write fails and the state says so: it is not "all kept".
        match step.state.record_extraction(&usable_text(&tree)) {
            Err(NotKept::Write(Error::Io { path, .. })) => assert_eq!(path, temporary),
            other => panic!("{other:?}"),
        }
        // The call that extracts is stopped there, so no later call of
        // this build comes to find no record and go on unheld.
        let refused = record_extraction(step, &src, &tree.collected()).unwrap_err();
        assert_not_written(&tree, &refused, &temporary.display().to_string());
        assert_eq!(step.state.extraction(), Kept::Absent);
        assert!(!record.exists());
        // What was in the way is not Guardian's and is left.
        assert!(temporary.join("kept").exists());

        // Once it can be written, the build is recorded and held.
        fs::remove_dir_all(&temporary).unwrap();
        assert_eq!(record_extraction(step, &src, &tree.collected()), Ok(()));
        assert_eq!(
            hold_against_extraction(step, &src, &mut tree.collected()),
            Ok(Vec::new())
        );
    });

    // The state directory gone since it was opened: the error names the
    // record itself.
    fs::remove_dir_all(tree.state.directory().unwrap()).unwrap();
    with_step(&tree, &[], |step| {
        let refused = record_extraction(step, &src, &tree.collected()).unwrap_err();
        assert_not_written(&tree, &refused, &record.display().to_string());
    });
}

/// Any record of the tree's sources: what is written does not matter to a
/// write that fails.
fn usable_text(tree: &Tree) -> super::Extraction {
    super::Extraction {
        srcdir: tree.src().to_string_lossy().into_owned(),
        ..super::Extraction::default()
    }
}

#[test]
fn a_state_directory_that_cannot_be_written_stops_the_build_that_extracts() {
    let tree = Tree::new("gate-write-readonly", "build".into(), "demo.tar.gz");
    let src = tree.src();
    let directory = tree.state.directory().unwrap().to_path_buf();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).unwrap();
    // Root writes there all the same; a user does not.
    let probe = directory.join("probe");
    let writable = fs::write(&probe, "x").is_ok();
    drop(fs::remove_file(&probe));
    with_step(&tree, &[], |step| {
        let recorded = record_extraction(step, &src, &tree.collected());
        if writable {
            assert_eq!(recorded, Ok(()));
            assert!(usable(step.state).is_of(&src));
        } else {
            let record = step.state.path("extraction").unwrap();
            let refused = recorded.unwrap_err();
            assert_not_written(&tree, &refused, &record.display().to_string());
            assert!(
                refused.message.contains("Permission denied"),
                "{}",
                refused.message
            );
            assert_eq!(step.state.extraction(), Kept::Absent);
        }
    });
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    with_step(&tree, &[], |step| {
        assert_eq!(record_extraction(step, &src, &tree.collected()), Ok(()));
        assert_eq!(
            hold_against_extraction(step, &src, &mut tree.collected()),
            Ok(Vec::new())
        );
    });
}

#[test]
fn a_failed_write_leaves_the_earlier_record_and_the_build_is_held_to_it() {
    let tree = Tree::new("gate-write-stale", "build".into(), "demo.tar.gz");
    let src = tree.src();
    let record = tree.state.path("extraction").unwrap();
    with_step(&tree, &[], |step| {
        assert_eq!(record_extraction(step, &src, &tree.collected()), Ok(()));
        let earlier = fs::read(&record).unwrap();

        // The sources are extracted again and are others now: a file
        // changed and a file added. This time the record is not written.
        fs::write(src.join("demo/main.c"), "int main(void) { return 1; }\n").unwrap();
        fs::write(src.join("demo/added.sh"), "#!/bin/sh\n").unwrap();
        let temporary = block_writes(step.state, "extraction");
        let refused = record_extraction(step, &src, &tree.collected()).unwrap_err();
        assert_not_written(&tree, &refused, &temporary.display().to_string());

        // The earlier record is whole and still there. A later call is
        // held to it: what was extracted since counts as changed and is
        // reviewed first, and the checks that stop a build still run.
        assert_eq!(fs::read(&record).unwrap(), earlier);
        let mut collected = tree.collected();
        let facts = hold_against_extraction(step, &src, &mut collected).unwrap();
        assert!(
            facts[0].contains("2 file(s) in them are new or changed"),
            "{facts:?}"
        );
        fs::write(tree.build.join("demo.tar.gz"), b"\x1f\x8b\x08\0another").unwrap();
        let refused = hold_against_extraction(step, &src, &mut tree.collected()).unwrap_err();
        assert!(
            refused
                .message
                .contains("not the ones Guardian fetched and reviewed"),
            "{}",
            refused.message
        );
    });
}

#[test]
fn a_directory_where_the_record_goes_is_named_and_never_emptied() {
    let tree = Tree::new("gate-write-directory", "build".into(), "demo.tar.gz");
    let src = tree.src();
    let root = tree.dir.path().join("state");
    let record = tree.state.path("extraction").unwrap();
    let in_the_way = |refused: &NotHeld| {
        assert_eq!(refused.why, IN_THE_WAY);
        for part in [
            "a directory is where Guardian keeps its record of the sources it extracted",
            &record.display().to_string(),
            "Nothing was built.",
            "remove that directory yourself, then run the build again from the start.",
        ] {
            assert!(
                refused.message.contains(part),
                "{part}: {}",
                refused.message
            );
        }
    };
    with_step(&tree, &[], |step| {
        // One that is not empty: neither call goes on, neither removes it.
        fs::create_dir(&record).unwrap();
        fs::write(record.join("kept"), "x").unwrap();
        assert_eq!(step.state.extraction(), Kept::InTheWay(record.clone()));
        in_the_way(&hold_against_extraction(step, &src, &mut tree.collected()).unwrap_err());
        in_the_way(&record_extraction(step, &src, &tree.collected()).unwrap_err());
        // `forget` removes what it can, then names every directory it
        // left and says how to go on.
        step.state.remember_confirmed("x").unwrap();
        let binaries = step.state.path("binaries").unwrap();
        fs::create_dir(&binaries).unwrap();
        fs::write(binaries.join("kept"), "x").unwrap();
        let refused = forget(&root, "demo").unwrap_err().to_string();
        for part in [
            "1 record(s) of the AUR gate were forgotten, and 2 directory(ies)",
            &format!("{} (", binaries.display()),
            &format!("{} (", record.display()),
            "remove them yourself, then run this again.",
        ] {
            assert!(refused.contains(part), "{part}: {refused}");
        }
        assert!(!step.state.is_confirmed("x"));
        assert_eq!(fs::read_to_string(record.join("kept")).unwrap(), "x");
        assert_eq!(fs::read_to_string(binaries.join("kept")).unwrap(), "x");
        fs::remove_dir_all(&binaries).unwrap();

        // An empty one stops the call that does not extract, and goes
        // with `forget` or with the next extraction.
        fs::remove_file(record.join("kept")).unwrap();
        in_the_way(&hold_against_extraction(step, &src, &mut tree.collected()).unwrap_err());
        assert_eq!(forget(&root, "demo").unwrap(), 1);
        assert_eq!(step.state.extraction(), Kept::Absent);
        fs::create_dir(&record).unwrap();
        assert_eq!(record_extraction(step, &src, &tree.collected()), Ok(()));
        assert!(usable(step.state).is_of(&src));
    });
}

#[test]
fn an_answer_that_cannot_be_remembered_is_asked_for_again() {
    let tree = Tree::new("gate-write-answer", "build".into(), "demo.tar.gz");
    let temporary = block_writes(&tree.state, "confirmed");
    match tree.state.remember_confirmed("x") {
        Err(Error::Io { path, .. }) => assert_eq!(path, temporary),
        other => panic!("{other:?}"),
    }
    assert!(!tree.state.is_confirmed("x"));

    let reasons = ["line 2: source is set under a condition".to_string()];
    let mut prebuilt = Prebuilt::default();
    prebuilt.programs.insert("src/tool".into(), "a".repeat(64));
    let mut yes = Yes(0);
    with_step(&tree, &[], |step| {
        // The yes stands for this build, and is asked for at the next.
        for asked in [1, 2] {
            assert!(confirm_not_followed(step, &reasons, &[], &mut yes));
            assert_eq!(yes.0, asked);
        }
        for asked in [3, 4] {
            assert!(confirm_prebuilt(step, &prebuilt, &mut yes));
            assert_eq!(yes.0, asked);
        }
        // Once it can be written it is remembered.
        fs::remove_dir_all(&temporary).unwrap();
        assert!(confirm_not_followed(step, &reasons, &[], &mut yes));
        assert!(confirm_prebuilt(step, &prebuilt, &mut yes));
        assert_eq!(yes.0, 6);
        assert!(confirm_not_followed(step, &reasons, &[], &mut yes));
        assert!(confirm_prebuilt(step, &prebuilt, &mut yes));
        assert_eq!(yes.0, 6);
    });
}

#[test]
fn binaries_that_cannot_be_recorded_leave_the_earlier_record() {
    let tree = Tree::new("gate-write-binaries", "build".into(), "demo.tar.gz");
    let src = tree.src();
    fs::write(src.join("demo/tool"), b"\x7fELF\x02\x01\x01\0\0\0one").unwrap();
    let upstream = |tree: &Tree| tree.collected().select(1 << 20);
    with_step(&tree, &[], |step| {
        let first = upstream(&tree);
        let known: BTreeMap<String, String> = all_binaries(&first);
        assert!(!known.is_empty());

        // No earlier record: there is none after, as at a first build.
        let temporary = block_writes(step.state, "binaries");
        match step.state.record_binaries(&known) {
            Err(Error::Io { path, .. }) => assert_eq!(path, temporary),
            other => panic!("{other:?}"),
        }
        remember_binaries(step, &first);
        assert_eq!(step.state.binaries(), None);
        assert_eq!(binary_changes(step, &first), None);

        fs::remove_dir_all(&temporary).unwrap();
        remember_binaries(step, &first);
        assert!(step.state.binaries().is_some());
        assert_eq!(binary_changes(step, &first), None);

        // An earlier record: it stays, and the next build is compared
        // with it, so what changed since is still named.
        fs::write(src.join("demo/tool"), b"\x7fELF\x02\x01\x01\0\0\0two").unwrap();
        let second = upstream(&tree);
        let temporary = block_writes(step.state, "binaries");
        let kept = step.state.binaries();
        remember_binaries(step, &second);
        assert_eq!(step.state.binaries(), kept);
        let fact = binary_changes(step, &second).unwrap();
        assert!(fact.contains("1 are new or changed"), "{fact}");
        fs::remove_dir_all(&temporary).unwrap();
        remember_binaries(step, &second);
        assert_eq!(binary_changes(step, &second), None);
    });
}
