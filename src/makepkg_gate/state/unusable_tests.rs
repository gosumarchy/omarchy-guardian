//! Tests for a record of an extraction that is there and cannot be used,
//! and for sources too many to record.

use std::fs::{self, File};
use std::path::Path;
use std::process::Command;

use super::super::{NotHeld, hold_against_extraction, record_extraction};
use super::record_tests::{Tree, usable, with_step};
use super::{Extraction, Kept, MAX_BYTES, forget};

const UNUSABLE: &str = "the record of what Guardian extracted cannot be used";

/// What a build whose sources are too many to record is told.
fn too_many() -> NotHeld {
    NotHeld {
        message: "the sources have more files, or files with longer names, than Guardian can keep a record of, so a build cannot be held to what Guardian extracted and reviewed. Nothing was built, and running the build again ends the same way: no setting changes this. The one way on gives that check up for this build: after `omarchy-guardian forget aur:demo` (it also drops what else Guardian remembers of this package), a call that does not extract again (`makepkg --noextract`) finds no record, and the sources are reviewed as they are found, not held to what Guardian extracted.".into(),
        why: "the sources are too many to hold the build to",
    }
}

/// Removes whatever is under the record's name.
fn clear(path: &Path) {
    if fs::symlink_metadata(path).is_ok_and(|found| found.is_dir()) {
        fs::remove_dir_all(path).unwrap();
    } else {
        drop(fs::remove_file(path));
    }
}

/// Holds the build of `tree` against its record, which must stop it for
/// a record that cannot be used, saying `reason`. Then extracts again,
/// which must put a record that can be used in its place.
fn stops_and_recovers(tree: &Tree, reason: &str) {
    let src = tree.src();
    match tree.state.extraction() {
        Kept::Unusable(why) => assert!(why.contains(reason), "{why}"),
        other => panic!("{reason}: {other:?}"),
    }
    with_step(tree, &[], |step| {
        let refused = hold_against_extraction(step, &src, &mut tree.collected()).unwrap_err();
        assert_eq!(refused.why, UNUSABLE, "{reason}");
        for part in [
            "Guardian's record of the sources it extracted for this build cannot be used (",
            reason,
            "Nothing was built.",
            "Run the build again from the start",
            "`omarchy-guardian forget aur:demo`",
        ] {
            assert!(
                refused.message.contains(part),
                "{part}: {}",
                refused.message
            );
        }
        // The call that extracts does not read the record: it writes it.
        assert_eq!(
            record_extraction(step, &src, &tree.collected()),
            Ok(()),
            "{reason}"
        );
        assert!(usable(step.state).is_of(&src), "{reason}");
        assert_eq!(
            hold_against_extraction(step, &src, &mut tree.collected()),
            Ok(Vec::new()),
            "{reason}"
        );
    });
}

#[test]
fn a_record_that_cannot_be_used_stops_the_build_until_it_is_written_again() {
    let tree = Tree::new("gate-record-unusable", "build".into(), "demo.tar.gz");
    let src = tree.src();
    let path = tree.state.path("extraction").unwrap();
    let whole = with_step(&tree, &[], |step| {
        // No record: the sources are reviewed as they are, as before.
        assert_eq!(step.state.extraction(), Kept::Absent);
        let facts = hold_against_extraction(step, &src, &mut tree.collected()).unwrap();
        assert!(facts[0].contains("did not extract these sources itself"));
        assert_eq!(record_extraction(step, &src, &tree.collected()), Ok(()));
        fs::read(&path).unwrap()
    });

    // Larger than a record may be, without reading it.
    clear(&path);
    File::create(&path).unwrap().set_len(MAX_BYTES + 1).unwrap();
    stops_and_recovers(&tree, "it is larger than the 64 MiB a record may be");

    let not_written = "it is not written the way Guardian writes one";
    for bytes in [
        &b""[..],
        b"garbage\n",
        b"srcdir /x\nidentity -\ncleanbuild 0\nD aa caf\\u{E9}\n",
        b"srcdir /x\nidentity -\ncleanbuild 0\nD aa \xff\n",
        // The record itself, ending within its last line.
        &whole[..whole.len() - 1],
    ] {
        clear(&path);
        fs::write(&path, bytes).unwrap();
        stops_and_recovers(&tree, not_written);
    }

    // Not a regular file: a link (even to a record that could be read),
    // and a pipe, which is not opened and so not waited on. (A directory
    // is told apart: see `write_tests`.)
    let elsewhere = tree.dir.path().join("record");
    fs::write(&elsewhere, &whole).unwrap();
    clear(&path);
    std::os::unix::fs::symlink(&elsewhere, &path).unwrap();
    stops_and_recovers(&tree, "it is not a regular file");
    assert_eq!(fs::read(&elsewhere).unwrap(), whole);
    clear(&path);
    // Without `mkfifo` there is no pipe to make; the rest stands.
    if Command::new("mkfifo")
        .arg(&path)
        .status()
        .is_ok_and(|status| status.success())
    {
        stops_and_recovers(&tree, "it is not a regular file");
    }

    // `forget` removes it too: then there is no record.
    clear(&path);
    fs::write(&path, b"garbage\n").unwrap();
    assert!(matches!(tree.state.extraction(), Kept::Unusable(_)));
    assert_eq!(forget(&tree.dir.path().join("state"), "demo").unwrap(), 1);
    assert_eq!(tree.state.extraction(), Kept::Absent);
    with_step(&tree, &[], |step| {
        let facts = hold_against_extraction(step, &src, &mut tree.collected()).unwrap();
        assert!(facts[0].contains("did not extract these sources itself"));
    });
}

#[test]
fn a_record_of_another_directory_is_none_for_this_one() {
    let tree = Tree::new("gate-record-other", "build".into(), "demo.tar.gz");
    let src = tree.src();
    let other = tree.build.join("other");
    with_step(&tree, &[], |step| {
        assert_eq!(record_extraction(step, &other, &tree.collected()), Ok(()));
        let facts = hold_against_extraction(step, &src, &mut tree.collected()).unwrap();
        assert!(facts[0].contains("did not extract these sources itself"));
    });
}

#[test]
fn sources_too_many_to_record_are_recorded_as_that_and_stop_the_build() {
    let mut tree = Tree::new("gate-record-many", "build".into(), "demo.tar.gz");
    let src = tree.src();
    for index in 0..40 {
        fs::write(src.join(format!("demo/file-{index}.c")), "int x;\n").unwrap();
    }
    let path = tree.state.path("extraction").unwrap();
    let whole = with_step(&tree, &[], |step| {
        assert_eq!(record_extraction(step, &src, &tree.collected()), Ok(()));
        fs::read(&path).unwrap()
    });
    let header = usable(&tree.state).unlisted().to_text();
    assert!(header.len() + 1000 < whole.len());

    // A record may be exactly as large as the most, and no larger.
    tree.state.most = u64::try_from(whole.len()).unwrap();
    with_step(&tree, &[], |step| {
        assert_eq!(record_extraction(step, &src, &tree.collected()), Ok(()));
    });
    assert_eq!(fs::read(&path).unwrap(), whole);
    assert!(!usable(&tree.state).unlisted);

    tree.state.most -= 1;
    // The record on disk is now one byte too large to be read.
    assert!(matches!(tree.state.extraction(), Kept::Unusable(_)));
    with_step(&tree, &[], |step| {
        // Not written whole, not cut, and not left out: it says so.
        let refused = record_extraction(step, &src, &tree.collected()).unwrap_err();
        assert_eq!(refused, too_many());
        assert_eq!(fs::read_to_string(&path).unwrap(), header);
        assert!(header.ends_with("\ncleanbuild 0\nunlisted\n"), "{header}");
        let record = usable(step.state);
        assert!(record.unlisted && record.is_of(&src));
        assert!(record.downloads.is_empty() && record.files.is_empty());

        let refused = hold_against_extraction(step, &src, &mut tree.collected()).unwrap_err();
        assert_eq!(refused, too_many());
        // `forget` is the way on the message names: no record is left,
        // and the sources are then reviewed as they are found.
        assert_eq!(forget(&tree.dir.path().join("state"), "demo").unwrap(), 1);
        let facts = hold_against_extraction(step, &src, &mut tree.collected()).unwrap();
        assert!(facts[0].contains("did not extract these sources itself"));
        assert_eq!(
            record_extraction(step, &src, &tree.collected()).unwrap_err(),
            too_many()
        );
    });

    // With room for it again, the next extraction records it whole.
    tree.state.most = MAX_BYTES;
    with_step(&tree, &[], |step| {
        assert_eq!(record_extraction(step, &src, &tree.collected()), Ok(()));
        assert_eq!(
            hold_against_extraction(step, &src, &mut tree.collected()),
            Ok(Vec::new())
        );
    });
}

#[test]
fn a_record_that_lists_nothing_is_read_only_as_that() {
    let unlisted = Extraction {
        srcdir: "/build/d\u{e9}mo/src".into(),
        identity: Some("1:2:3".into()),
        cleanbuild: true,
        unlisted: true,
        ..Extraction::default()
    };
    let text = unlisted.to_text();
    assert_eq!(
        text,
        "srcdir /build/d\\u{e9}mo/src\nidentity 1:2:3\ncleanbuild 1\nunlisted\n"
    );
    assert_eq!(Extraction::parse(&text), Some(unlisted));
    for bad in [
        "srcdir /x\nidentity -\ncleanbuild 0\nunlisted\nunlisted\n",
        "srcdir /x\nidentity -\ncleanbuild 0\nunlisted\nD aa a\n",
        "srcdir /x\nidentity -\ncleanbuild 0\nD aa a\nunlisted\n",
        "srcdir /x\nidentity -\ncleanbuild 0\nunlisted \n",
        "srcdir /x\nidentity -\nunlisted\ncleanbuild 0\n",
    ] {
        assert_eq!(Extraction::parse(bad), None, "{bad:?}");
    }
}
