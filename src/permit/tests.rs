//! Tests for `permit`.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use super::{
    Command, Content, LIFETIME_SECS, Pending, Place, Standing, Typed, add, enabled, find, grant,
    parse, pending_blocks, remove_where, standing_at, standing_permits,
};
use crate::audit::Gate;
use crate::config::Settings;
use crate::config::file::PartialConfig;
use crate::config::model::{Profile, SourceClass};
use crate::error::Error;
use crate::report::{Blocked, Decision, Gap, Report};
use crate::test_support::{NOBODY, TempDir, give};
use crate::user::real_uid as current_uid;

const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn settings(profile: Profile, allowed: Option<bool>) -> Settings {
    Settings::from_parts(
        PartialConfig {
            profile: Some(profile),
            permit_strict: allowed,
            ..PartialConfig::default()
        },
        PartialConfig::default(),
    )
}

fn theme(digest: &str) -> Content {
    Content::tree(Gate::Theme, SourceClass::Theme, "theme:demo", digest).unwrap()
}

/// A place whose permits are this test user's, as root's are root's.
fn place(directory: &Path) -> Place<'_> {
    Place {
        directory,
        owner: current_uid().unwrap(),
        anchor: directory,
    }
}

/// A private directory, as the root half and the user's state are.
fn private(label: &str) -> TempDir {
    let dir = TempDir::new(label);
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

struct Types(Option<&'static str>);

impl Typed for Types {
    fn typed(&mut self, _: &str) -> Option<String> {
        self.0.map(str::to_string)
    }
}

#[test]
fn the_id_is_bound_to_gate_class_and_every_digest() {
    let content = theme(A);
    // Long enough that no other content with the same ID is found.
    assert_eq!(content.id().len(), 32);
    assert_eq!(content.key().len(), 64);
    assert!(content.key().starts_with(&content.id()));
    assert_eq!(content.key(), theme(A).key());
    // A block is offered under the ID, with the whole SHA-256 for the
    // gate to print beside it.
    let offer = content.offer();
    assert_eq!(offer.to_string(), content.id());
    assert_eq!(offer.key, content.key());
    assert_eq!(
        Standing::Offered(offer).offered(),
        Some(content.id().as_str())
    );
    // Another digest, gate or class is another permit.
    assert_ne!(content.key(), theme(B).key());
    let as_plugin = Content::tree(Gate::Plugin, SourceClass::Plugin, "theme:demo", A).unwrap();
    assert_ne!(content.key(), as_plugin.key());
    let as_source = Content::tree(Gate::Theme, SourceClass::Source, "x", A).unwrap();
    assert_ne!(content.key(), as_source.key());
    // What it is called is not part of it; the order of digests is not
    // either.
    let named = Content::tree(Gate::Theme, SourceClass::Theme, "another name", A).unwrap();
    assert_eq!(content.key(), named.key());
    let parts = |first: &str, second: &str| {
        Content::new(
            Gate::Pacman,
            "local-package+official",
            "x",
            vec![
                format!("official:{first}"),
                format!("local-package:{second}"),
            ],
        )
        .unwrap()
        .key()
    };
    assert_eq!(
        Content::new(
            Gate::Pacman,
            "local-package+official",
            "x",
            vec![format!("local-package:{B}"), format!("official:{A}")]
        )
        .unwrap()
        .key(),
        parts(A, B)
    );
    assert_ne!(parts(A, B), parts(B, A));
}

#[test]
fn content_without_a_real_digest_cannot_be_named() {
    let new = |gate, class: &str, parts: Vec<String>| Content::new(gate, class, "x", parts);
    assert!(new(Gate::Aur, "aur", vec![format!("recipe:{A}")]).is_some());
    assert!(new(Gate::Aur, "aur", Vec::new()).is_none());
    assert!(new(Gate::Aur, "aur", vec!["recipe:size-1-2-3".into()]).is_none());
    assert!(
        new(
            Gate::Aur,
            "aur",
            vec![format!("recipe:{}", A.to_uppercase())]
        )
        .is_none()
    );
    assert!(new(Gate::Aur, "aur", vec![format!("Re cipe:{A}")]).is_none());
    assert!(new(Gate::Aur, "aur", vec![A.into()]).is_none());
    // The sweep and plain scans have no permits; `system` is no class
    // of an install.
    assert!(new(Gate::Scan, "source", vec![format!("tree:{A}")]).is_none());
    assert!(new(Gate::Sweep, "system", vec![format!("tree:{A}")]).is_none());
    assert!(new(Gate::Guard, "system", vec![format!("tree:{A}")]).is_none());
    assert!(new(Gate::Guard, "nonsense", vec![format!("tree:{A}")]).is_none());
}

#[test]
fn a_permit_stands_for_its_user_content_and_time_only() {
    let dir = private("permit-find");
    let place = place(dir.path());
    let uid = place.owner;
    let content = theme(A);
    let now = 1_000_000;
    assert!(find(&place, uid, &content, now).is_none());

    let permit = add(dir.path(), uid, "theme", "theme", &content.key(), now).unwrap();
    assert_eq!(permit.expires, now + LIFETIME_SECS);
    assert!(find(&place, uid, &content, now).is_some());
    assert!(find(&place, uid, &content, now + LIFETIME_SECS - 1).is_some());
    // Ended; another user; other bytes; a clock set back.
    assert!(find(&place, uid, &content, now + LIFETIME_SECS).is_none());
    assert!(find(&place, uid + 1, &content, now).is_none());
    assert!(find(&place, uid, &theme(B), now).is_none());
    assert!(find(&place, uid, &content, now - 10).is_none());
    // The same bytes at another gate.
    let guard = Content::tree(Gate::Guard, SourceClass::Theme, "x", A).unwrap();
    assert!(find(&place, uid, &guard, now).is_none());
    assert_eq!(standing_permits(&place, uid, now).len(), 1);
    assert!(standing_permits(&place, uid + 1, now).is_empty());
}

#[test]
fn a_permit_someone_else_could_write_counts_for_nothing() {
    let dir = private("permit-owner");
    let content = theme(A);
    let uid = current_uid().unwrap();
    let now = 1_000_000;
    add(dir.path(), uid, "theme", "theme", &content.key(), now).unwrap();
    let name = format!("{uid}-theme-{}", content.key());

    // Not root's: the production place asks for owner 0.
    let roots = Place {
        directory: dir.path(),
        owner: 0,
        anchor: dir.path(),
    };
    let path = dir.path().join(&name);
    if uid == 0 {
        // Run as root, the file is root's: it counts for root's place
        // until it, or its directory, is somebody else's. (Root of a
        // user namespace with no other user in it cannot give a file
        // away; the place of another owner below covers that.)
        assert!(find(&roots, uid, &content, now).is_some());
        if give(&path, NOBODY) {
            assert!(find(&roots, uid, &content, now).is_none());
            assert!(give(&path, 0));
            assert!(give(dir.path(), NOBODY));
            assert!(find(&roots, uid, &content, now).is_none());
            assert!(give(dir.path(), 0));
            assert!(find(&roots, uid, &content, now).is_some());
        }
        let others = Place {
            owner: NOBODY,
            ..roots
        };
        assert!(find(&others, uid, &content, now).is_none());
    } else {
        assert!(find(&roots, uid, &content, now).is_none());
    }

    let own = place(dir.path());
    assert!(find(&own, uid, &content, now).is_some());
    // Writable by a group, the file or its directory.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o664)).unwrap();
    assert!(find(&own, uid, &content, now).is_none());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(find(&own, uid, &content, now).is_none());
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(find(&own, uid, &content, now).is_some());

    // A file whose text says something else than its name.
    let other = theme(B);
    fs::copy(
        &path,
        dir.path().join(format!("{uid}-theme-{}", other.key())),
    )
    .unwrap();
    assert!(find(&own, uid, &other, now).is_none());
    // A link in its place.
    fs::remove_file(&path).unwrap();
    let elsewhere = dir.path().join("elsewhere");
    fs::write(&elsewhere, "{}").unwrap();
    std::os::unix::fs::symlink(&elsewhere, &path).unwrap();
    assert!(find(&own, uid, &content, now).is_none());
}

#[test]
fn the_root_half_takes_only_well_formed_arguments() {
    let dir = private("permit-add");
    let key = theme(A).key();
    let add = |gate: &str, class: &str, key: &str| add(dir.path(), 1000, gate, class, key, 5);
    for (gate, class, key) in [
        ("scan", "source", key.as_str()),
        ("sweep", "system", key.as_str()),
        ("../x", "theme", key.as_str()),
        ("theme", "theme/../..", key.as_str()),
        ("theme", "system", key.as_str()),
        ("theme", "theme", "abc"),
        ("theme", "theme", &key.to_uppercase()),
        ("theme", "theme", &format!("{}/", &key[..63])),
    ] {
        assert!(add(gate, class, key).is_err(), "{gate} {class} {key}");
    }
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    assert!(add("pacman", "local-package+official", &key).is_ok());
    let names: Vec<String> = fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, [format!("1000-pacman-{key}")]);
    let mode = fs::metadata(dir.path().join(&names[0]))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o644);
}

#[test]
fn ended_permits_are_cleared_and_a_user_holds_only_so_many() {
    let dir = private("permit-prune");
    let key = |index: usize| format!("{index:064x}");
    for index in 0..super::MAX_PERMITS {
        add(dir.path(), 1000, "aur", "aur", &key(index), 100).unwrap();
    }
    assert!(add(dir.path(), 1000, "aur", "aur", &key(999), 100).is_err());
    // Another user is not held up by them.
    assert!(add(dir.path(), 1001, "aur", "aur", &key(999), 100).is_ok());
    // Once they ended, the next one clears them away.
    let later = 100 + LIFETIME_SECS;
    add(dir.path(), 1000, "aur", "aur", &key(999), later).unwrap();
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    // What the pacman hook's root half does with a used permit.
    add(dir.path(), 1000, "pacman", "official", &key(1), later).unwrap();
    assert_eq!(
        remove_where(dir.path(), &|name| name.starts_with("1000-pacman-")),
        1
    );
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

fn blocked_report() -> Report {
    let mut report = Report::new("theme:demo");
    report.gaps.push(Gap::Undecodable("install.sh".into()));
    report
}

#[test]
fn a_block_is_offered_a_permit_and_a_permit_lets_it_through() {
    let permits = private("permit-standing");
    let state = private("permit-state");
    let place = place(permits.path());
    let content = theme(A);
    let report = blocked_report();
    let blocked = Decision::Blocked(Blocked::Incomplete);
    let settings = settings(Profile::Standard, None);
    let now = 2_000_000;
    let ask = |content: &[Content], report: &Report, decision, settings: &Settings| {
        standing_at(
            &place,
            content,
            report,
            decision,
            settings,
            Some(state.path()),
            now,
        )
    };

    assert_eq!(
        ask(std::slice::from_ref(&content), &report, blocked, &settings),
        Standing::Offered(content.offer())
    );
    let kept = pending_blocks(state.path(), now);
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].decision, "INCOMPLETE");
    assert!(kept[0].summary[0].contains("install.sh"));

    add(
        permits.path(),
        place.owner,
        "theme",
        "theme",
        &content.key(),
        now,
    )
    .unwrap();
    assert_eq!(
        ask(std::slice::from_ref(&content), &report, blocked, &settings),
        Standing::Permitted(content.id())
    );
    // Other bytes are offered their own permit, not let through.
    let other = theme(B);
    assert_eq!(
        ask(std::slice::from_ref(&other), &report, blocked, &settings),
        Standing::Offered(other.offer())
    );
    // What was reviewed may go by several names (a recipe before and
    // after makepkg downloaded into its directory): a permit for any
    // lets it through, and the first is the one offered.
    assert_eq!(
        ask(
            &[other.clone(), content.clone()],
            &report,
            blocked,
            &settings
        ),
        Standing::Permitted(content.id())
    );
    let third = theme(&"c".repeat(64));
    assert_eq!(
        ask(&[third.clone(), other.clone()], &report, blocked, &settings),
        Standing::Offered(third.offer())
    );
    // A review that passed has nothing to do with permits.
    assert_eq!(
        ask(
            std::slice::from_ref(&content),
            &Report::new("x"),
            Decision::Clear,
            &settings
        ),
        Standing::None
    );
}

#[test]
fn what_has_no_digest_or_was_refused_is_never_permitted() {
    let permits = private("permit-never");
    let state = private("permit-never-state");
    let place = place(permits.path());
    let content = theme(A);
    let now = 2_000_000;
    add(
        permits.path(),
        place.owner,
        "theme",
        "theme",
        &content.key(),
        now,
    )
    .unwrap();
    let standard = settings(Profile::Standard, None);
    let ask = |content: &[Content], report: &Report, settings: &Settings| {
        standing_at(
            &place,
            content,
            report,
            Decision::Blocked(Blocked::Incomplete),
            settings,
            Some(state.path()),
            now,
        )
    };
    // The permit is there and would be found.
    assert_eq!(
        ask(std::slice::from_ref(&content), &blocked_report(), &standard),
        Standing::Permitted(content.id())
    );
    // A refused package, a file that could not be read, a link that
    // leads elsewhere: the permit is ignored and none is offered.
    for gap in [
        Gap::Package(Error::Refused(
            "demo ships /usr/bin/omarchy-guardian".into(),
        )),
        Gap::Io(Error::Refused("x: permission denied".into())),
        Gap::Symlink("x".into()),
        Gap::HashLimit("x".into()),
        Gap::TreeTooLarge { files: 1, bytes: 1 },
    ] {
        let mut report = blocked_report();
        report.gaps.push(gap);
        assert_eq!(
            ask(std::slice::from_ref(&content), &report, &standard),
            Standing::None
        );
    }
    // No digest was established.
    assert_eq!(ask(&[], &blocked_report(), &standard), Standing::None);
    // The strict level, unless the system file allows permits there.
    for (profile, allowed, expected) in [
        (Profile::Strict, None, false),
        (Profile::Strict, Some(false), false),
        (Profile::Strict, Some(true), true),
        (Profile::LocalOnly, None, true),
    ] {
        let settings = settings(profile, allowed);
        assert_eq!(enabled(&settings, "theme"), expected);
        assert_eq!(
            ask(std::slice::from_ref(&content), &blocked_report(), &settings) != Standing::None,
            expected
        );
    }
    assert!(pending_blocks(state.path(), now).is_empty());
}

#[test]
fn a_strict_run_of_one_class_has_no_permits_either() {
    let strict_once = settings(Profile::Standard, None).with_profile(Profile::Strict);
    assert!(!enabled(&strict_once, "theme"));
    // The pacman classes follow the system file alone.
    assert!(enabled(&strict_once, "local-package+official"));
    assert!(!enabled(&settings(Profile::Strict, None), "official"));
    assert!(!enabled(&settings(Profile::Standard, None), "nonsense"));
}

#[test]
fn a_record_that_does_not_hash_to_its_id_is_not_a_block() {
    let state = private("permit-forged");
    let directory = state.path().join("permits");
    fs::create_dir(&directory).unwrap();
    let block = Pending {
        content: theme(A),
        decision: "INCOMPLETE".into(),
        summary: vec!["not reviewed: x".into()],
        at: 500,
    };
    let id = block.content.id();
    let honest = block.to_json();
    fs::write(directory.join(format!("{id}.json")), &honest).unwrap();
    assert_eq!(
        pending_blocks(state.path(), 600),
        std::slice::from_ref(&block)
    );
    // Too old, or from the future.
    assert!(pending_blocks(state.path(), 500 + 25 * 60 * 60).is_empty());
    assert!(pending_blocks(state.path(), 100).is_empty());

    // The digests of other content under the honest ID and key.
    let forged = honest.replace(A, B);
    assert_ne!(forged, honest);
    fs::write(directory.join(format!("{id}.json")), &forged).unwrap();
    assert!(pending_blocks(state.path(), 600).is_empty());
    // Another gate under the same ID.
    fs::write(
        directory.join(format!("{id}.json")),
        honest.replace("\"gate\":\"theme\"", "\"gate\":\"pacman\""),
    )
    .unwrap();
    assert!(pending_blocks(state.path(), 600).is_empty());
    // An honest record under another ID's name.
    fs::write(
        directory.join("0123456789abcdef0123456789abcdef.json"),
        &honest,
    )
    .unwrap();
    assert!(pending_blocks(state.path(), 600).is_empty());
    assert!(Pending::parse("{}").is_none());
    assert!(Pending::parse("not json").is_none());
}

#[test]
fn only_the_newest_blocks_are_kept() {
    let state = private("permit-kept");
    for index in 0..super::MAX_PENDING + 5 {
        let block = Pending {
            content: theme(&format!("{index:064x}")),
            decision: "INCOMPLETE".into(),
            summary: Vec::new(),
            at: 1000 + index as u64,
        };
        super::keep_pending(state.path(), &block).unwrap();
    }
    let kept = pending_blocks(state.path(), 2000);
    assert_eq!(kept.len(), super::MAX_PENDING);
    assert_eq!(kept[0].at, 1000 + super::MAX_PENDING as u64 + 4);
    let mode = fs::metadata(state.path().join("permits"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700);
}

#[test]
fn a_permit_takes_the_typed_word_and_a_terminal() {
    let state = private("permit-grant");
    let content = theme(A);
    let block = Pending {
        content: content.clone(),
        decision: "REVIEW REQUIRED".into(),
        summary: vec!["MEDIUM install.sh:3 shell-command-execution".into()],
        at: super::now(),
    };
    super::keep_pending(state.path(), &block).unwrap();
    let id = content.id();
    let standard = settings(Profile::Standard, None);
    let asked = std::cell::RefCell::new(Vec::new());
    let as_root = |arguments: &[&str]| {
        asked.borrow_mut().push(
            arguments
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        );
        Ok(())
    };
    let attempt = |id: &str, settings: &Settings, typed: Option<&'static str>| {
        grant(id, settings, state.path(), &mut Types(typed), &as_root)
    };

    // No terminal, a yes that is not the word, an unknown ID, the
    // strict level: root is never asked.
    assert!(attempt(&id, &standard, None).is_err());
    assert!(attempt(&id, &standard, Some("y")).is_err());
    assert!(attempt(&id, &standard, Some("")).is_err());
    assert!(
        attempt(
            "0123456789abcdef0123456789abcdef",
            &standard,
            Some("permit")
        )
        .is_err()
    );
    assert!(attempt(&id, &settings(Profile::Strict, None), Some("permit")).is_err());
    assert!(asked.borrow().is_empty());
    assert_eq!(pending_blocks(state.path(), super::now()).len(), 1);

    // Root gives itself none: the root half records the user sudo
    // names, and there is none. Nothing is asked and the block is kept.
    if current_uid() == Some(0) {
        let refused = attempt(&id, &standard, Some("permit")).unwrap_err();
        assert!(refused.contains("not by root"), "{refused}");
        assert!(asked.borrow().is_empty());
        assert_eq!(pending_blocks(state.path(), super::now()).len(), 1);
        return;
    }

    // Root is given the gate, the class and the SHA-256, and no more.
    assert!(attempt(&id, &standard, Some("permit")).is_ok());
    assert_eq!(
        *asked.borrow(),
        [vec![
            "--add".to_string(),
            "theme".to_string(),
            "theme".to_string(),
            content.key()
        ]]
    );
    assert!(pending_blocks(state.path(), super::now()).is_empty());
}

#[test]
fn the_command_takes_an_id_as_a_gate_prints_it() {
    let args = |words: &[&str]| -> Vec<std::ffi::OsString> {
        words.iter().map(std::ffi::OsString::from).collect()
    };
    assert_eq!(parse(&args(&[])), Ok(Command::List));
    assert_eq!(
        parse(&args(&["0123456789abcdef0123456789abcdef"])),
        Ok(Command::Grant("0123456789abcdef0123456789abcdef".into()))
    );
    assert_eq!(
        parse(&args(&["--revoke", "0123456789abcdef0123456789abcdef"])),
        Ok(Command::Revoke("0123456789abcdef0123456789abcdef".into()))
    );
    for bad in [
        &["--yes"][..],
        &["0123456789abcdef0123456789abcdef", "--yes"],
        &["--yes", "0123456789abcdef0123456789abcdef"],
        &["0123"],
        // The short ID of earlier versions, and one in capitals.
        &["0123456789abcdef"],
        &["0123456789ABCDEF0123456789ABCDEF"],
        &["../../../etc/pwd"],
        &["--revoke"],
    ] {
        assert!(parse(&args(bad)).is_err(), "{bad:?}");
    }
}
