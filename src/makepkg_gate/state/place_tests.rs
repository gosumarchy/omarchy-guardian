//! Tests for a build whose records have no directory: whatever the reason,
//! it is stopped, and told the repair that fits the reason.
//!
//! Each directory is made unusable the same way for root as for a user:
//! by its mode, which is read and not tried, by a file or a link where a
//! directory should be, or by opening the state as another user than the
//! one the directories belong to.

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use super::super::confirm::{binary_changes, confirm_not_followed, remember_binaries};
use super::super::{NotHeld, hold_against_extraction, record_extraction, without_records};
use super::record_tests::{Tree, usable, with_step};
use super::{Kept, Missing, NotKept, State};
use crate::aur;
use crate::cli::Confirm;
use crate::error::Error;

const OPEN: &str = "the directory of Guardian's records of builds is open to others";
const NOT_MADE: &str = "the directory of Guardian's records of builds could not be made";
const FORGET: &str =
    "then `omarchy-guardian forget --all`, which drops all of Guardian's review memory";
const ELSEWHERE: &str = "point XDG_STATE_HOME at a directory on a filesystem that can.";

const EXTRACTS: &str = "no record of the sources it extracted for this build could be kept, and a later call of this build could not be held to them";
const HELD: &str = "whether it has a record of the sources it extracted for this build cannot be known, and the sources cannot be held against one";

/// Says yes, and counts how often it was asked.
struct Yes(usize);

impl Confirm for Yes {
    fn confirm(&mut self, _question: &str) -> bool {
        self.0 += 1;
        true
    }
}

fn mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// The user the test's directories belong to.
fn owner(tree: &Tree) -> u32 {
    fs::metadata(tree.dir.path()).unwrap().uid()
}

fn invocation(arguments: &[&str]) -> aur::Invocation {
    let arguments: Vec<OsString> = arguments.iter().map(Into::into).collect();
    aur::classify(&arguments)
}

/// A build with no directory for its records must be stopped at both
/// calls, and before either gets anywhere, for `why`. Each message holds
/// `parts` and none of `never`. What only saves a question or informs
/// goes on. Returns the message of the call that extracts.
fn stops_both_calls(tree: &Tree, why: &str, parts: &[&str], never: &[&str]) -> String {
    let src = tree.src();
    let check = |refused: &NotHeld, own: &str| {
        assert_eq!(refused.why, why);
        let ends = [
            "Nothing was built.",
            "Then run the build again from the start.",
        ];
        for part in parts.iter().chain(&[own]).chain(&ends) {
            assert!(
                refused.message.contains(part),
                "{part}: {}",
                refused.message
            );
        }
        for part in never {
            assert!(
                !refused.message.contains(part),
                "{part}: {}",
                refused.message
            );
        }
    };
    assert!(matches!(tree.state.extraction(), Kept::Missing(_)));
    assert!(matches!(
        tree.state.record_extraction(&super::Extraction::default()),
        Err(NotKept::Missing(_))
    ));
    // Before anything is reviewed, fetched or asked: a call that extracts
    // and one that builds from what was extracted.
    for arguments in [&["--noconfirm"][..], &["-s", "-C"], &[]] {
        check(
            &without_records(&tree.state, invocation(arguments)).unwrap(),
            EXTRACTS,
        );
    }
    for arguments in [&["--noconfirm", "--noextract"][..], &["-e"]] {
        check(
            &without_records(&tree.state, invocation(arguments)).unwrap(),
            HELD,
        );
    }
    // A call that only prints, or only downloads, keeps no record and is
    // not stopped for one.
    for arguments in [
        &["--packagelist"][..],
        &["--printsrcinfo"],
        &["--version"],
        &["-g"],
        &["--verifysource"],
    ] {
        assert_eq!(
            without_records(&tree.state, invocation(arguments)),
            None,
            "{arguments:?}"
        );
    }
    with_step(tree, &[], |step| {
        // The same at the steps themselves, should a call come that far.
        let refused = record_extraction(step, &src, &tree.collected()).unwrap_err();
        check(&refused, EXTRACTS);
        check(
            &hold_against_extraction(step, &src, &mut tree.collected()).unwrap_err(),
            HELD,
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
        refused.message
    })
}

#[test]
fn a_state_directory_open_to_others_is_closed_and_emptied_or_removed() {
    let mut tree = Tree::new("gate-place-open", "build".into(), "demo.tar.gz");
    let root = tree.dir.path().join("open");
    let kept = root.join("aur-gate");
    fs::create_dir(&root).unwrap();
    mode(&root, 0o750);
    let (above, below) = (root.display().to_string(), kept.display().to_string());
    let trust = "Closing it is not enough: while it was open, someone else may have put records in it, and Guardian would take them for its own.";

    // The directory above the gate's own, open to the group.
    tree.state = State::open(Some(&root), "demo");
    let message = stops_both_calls(
        &tree,
        OPEN,
        &[
            &format!(
                "Guardian does not use the directory it keeps its records of builds in ({above} is accessible to group or others)"
            ),
            trust,
            &format!("Close it and drop what it holds (`chmod 700 {above}`, {FORGET})"),
            &format!("or remove it (`rm -r {above}`; Guardian makes it anew)."),
            &format!("Where the filesystem cannot keep such a mode, {ELSEWHERE}"),
        ],
        &["sudo", &below],
    );
    assert!(message.ends_with("Then run the build again from the start."));
    assert!(!kept.exists());

    // Both open: both are named at once.
    fs::create_dir(&kept).unwrap();
    mode(&kept, 0o755);
    tree.state = State::open(Some(&root), "demo");
    assert_eq!(
        tree.state.missing(),
        Some(&Missing::Open {
            directories: vec![root.clone(), kept.clone()]
        })
    );
    stops_both_calls(
        &tree,
        OPEN,
        &[
            &format!("({above} and {below} are accessible to group or others)"),
            &format!("(`chmod 700 {above} {below}`, {FORGET})"),
            &format!("(`rm -r {above}`; Guardian makes it anew)"),
        ],
        &["sudo"],
    );

    // The gate's own directory alone.
    mode(&root, 0o700);
    tree.state = State::open(Some(&root), "demo");
    assert_eq!(
        tree.state.missing(),
        Some(&Missing::Open {
            directories: vec![kept.clone()]
        })
    );
    stops_both_calls(
        &tree,
        OPEN,
        &[
            &format!("({below} is accessible to group or others)"),
            trust,
            &format!("(`chmod 700 {below}`, {FORGET})"),
            &format!("(`rm -r {below}`; Guardian makes it anew)"),
        ],
        &["sudo"],
    );

    // Closed, it is used.
    mode(&kept, 0o700);
    tree.state = State::open(Some(&root), "demo");
    let src = tree.src();
    assert_eq!(tree.state.missing(), None);
    assert_eq!(without_records(&tree.state, invocation(&[])), None);
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
fn a_file_or_a_link_where_the_state_directory_goes_is_to_be_removed() {
    let why = "something that is not a directory is in the place of Guardian's records of builds";
    let mut tree = Tree::new("gate-place-file", "build".into(), "demo.tar.gz");
    let root = tree.dir.path().join("mine");
    let kept = root.join("aur-gate");
    fs::create_dir(&root).unwrap();
    mode(&root, 0o700);
    let parts = |path: &Path| {
        [
            format!(
                "({} is not a directory: a link, a file or something else is in its place)",
                path.display()
            ),
            format!(
                "Remove what is in its place (`rm {}`, which removes a link and not what it points to); Guardian makes the directory anew.",
                path.display()
            ),
        ]
    };
    // No mode and no owner puts these right.
    let never = ["chmod", "chown", "forget"];

    // A file where the gate's own directory goes.
    fs::write(&kept, "x").unwrap();
    tree.state = State::open(Some(&root), "demo");
    let [wrong, repair] = parts(&kept);
    stops_both_calls(&tree, why, &[&wrong, &repair], &never);
    assert_eq!(fs::read_to_string(&kept).unwrap(), "x");

    // A link to a directory of the user's own where the one above goes:
    // closing what it points to would change nothing.
    let elsewhere = tree.dir.path().join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    mode(&elsewhere, 0o700);
    let linked = tree.dir.path().join("linked");
    symlink(&elsewhere, &linked).unwrap();
    tree.state = State::open(Some(&linked), "demo");
    assert_eq!(
        tree.state.missing(),
        Some(&Missing::NotDirectory {
            path: linked.clone()
        })
    );
    let [wrong, repair] = parts(&linked);
    stops_both_calls(&tree, why, &[&wrong, &repair], &never);
    assert!(!elsewhere.join("aur-gate").exists());
}

#[test]
fn a_state_directory_of_another_user_is_to_be_made_ones_own() {
    let mut tree = Tree::new("gate-place-owner", "build".into(), "demo.tar.gz");
    let theirs = owner(&tree);
    let mine = theirs + 1;

    // The directory itself: it is there, closed, and another's.
    let root = tree.dir.path().join("theirs");
    fs::create_dir(&root).unwrap();
    mode(&root, 0o700);
    let named = root.display().to_string();
    tree.state = State::open_as(Some(&root), "demo", Ok(mine));
    assert_eq!(
        tree.state.missing(),
        Some(&Missing::Owner {
            directory: root.clone(),
            path: root.clone(),
            owner: theirs,
            uid: mine,
            above: false,
        })
    );
    stops_both_calls(
        &tree,
        "the directory of Guardian's records of builds belongs to another user",
        &[
            &format!(
                "Guardian does not use the directory it keeps its records of builds in ({named} is owned by uid {theirs}, not by you, uid {mine})"
            ),
            "Whoever owns it may have put records in it, and Guardian would take them for its own.",
            &format!("Remove it (`sudo rm -r {named}`; Guardian makes it anew)"),
            &format!(
                "or make it yours and drop what it holds (`sudo chown -R {mine} {named}`, {FORGET})"
            ),
            &format!("Where the filesystem cannot keep an owner, {ELSEWHERE}"),
        ],
        &["chmod"],
    );

    // A directory above it, where it is not there yet: nothing is made
    // under another's directory, and the path to put right is that one.
    let unmade = tree.dir.path().join("none/state");
    let above = tree.dir.path().display().to_string();
    tree.state = State::open_as(Some(&unmade), "demo", Ok(mine));
    assert_eq!(
        tree.state.missing(),
        Some(&Missing::Owner {
            directory: unmade.clone(),
            path: tree.dir.path().to_path_buf(),
            owner: theirs,
            uid: mine,
            above: true,
        })
    );
    stops_both_calls(
        &tree,
        "a directory above Guardian's records of builds belongs to another user",
        &[
            &format!(
                "Guardian does not make the directory it keeps its records of builds in ({}): {above}, the nearest directory above it that exists, is owned by uid {theirs}, not by you, uid {mine}",
                unmade.display()
            ),
            &format!(
                "Make that directory yours (`sudo chown {mine} {above}`), or point XDG_STATE_HOME at a directory of yours."
            ),
        ],
        &[
            "chmod",
            "forget",
            &format!("chown {mine} {}", unmade.display()),
        ],
    );
    assert!(!tree.dir.path().join("none").exists());
}

#[test]
fn a_user_that_cannot_be_told_is_said_to_be_that() {
    let mut tree = Tree::new("gate-place-user", "build".into(), "demo.tar.gz");
    let root = tree.dir.path().join("state");
    let unknown = || Err(Error::Refused("cannot read the effective user id".into()));
    tree.state = State::open_as(Some(&root), "demo", unknown());
    let kept = root.join("aur-gate").display().to_string();
    stops_both_calls(
        &tree,
        "Guardian cannot tell which user it runs as",
        &[
            &format!(
                "Guardian cannot tell which user it runs as (cannot read the effective user id), and so not whether the directory it keeps its records of builds in ({kept}) is that user's alone"
            ),
            "It reads that from /proc/self/status: run the build where /proc is mounted and can be read.",
        ],
        &["chmod", "chown", "forget", "rm "],
    );
}

#[test]
fn a_state_directory_that_cannot_be_made_stops_both_calls_of_a_build() {
    // A file where a directory above it should be: no one can make it.
    let mut tree = Tree::new("gate-place-unmade", "build".into(), "demo.tar.gz");
    fs::write(tree.dir.path().join("file"), "x").unwrap();
    let root: PathBuf = tree.dir.path().join("file/state");
    tree.state = State::open(Some(&root), "demo");
    let named = root.display().to_string();
    match tree.state.missing() {
        Some(Missing::NotMade { directory, reason }) => {
            assert_eq!(directory, &root);
            assert!(reason.starts_with(&format!("{named}: ")), "{reason}");
        }
        other => panic!("{other:?}"),
    }
    stops_both_calls(
        &tree,
        NOT_MADE,
        &[
            "Guardian could not make the directory it keeps its records of builds in (",
            &format!("{named}: "),
            &format!(
                "Free space on that disk, or put right what the error names, so that {named} can be made."
            ),
        ],
        &["chmod", "chown", "forget"],
    );
}

#[test]
fn with_nowhere_to_keep_its_records_a_build_is_stopped() {
    let mut tree = Tree::new("gate-place-nowhere", "build".into(), "demo.tar.gz");
    tree.state = State::open(None, "demo");
    assert_eq!(tree.state.missing(), Some(&Missing::Nowhere));
    stops_both_calls(
        &tree,
        "Guardian has nowhere to keep its records of builds",
        &[
            "Guardian has nowhere to keep its records of builds (neither XDG_STATE_HOME nor HOME names a place)",
            "Set HOME, or XDG_STATE_HOME, to a directory of yours.",
        ],
        &["chmod", "chown", "forget"],
    );
}
