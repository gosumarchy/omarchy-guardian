//! Tests of what the sweep remembers between runs.

use std::fs;

use super::{Change, Remembered, apply_allowed, baseline, diff, save_baseline};
use crate::autorun::Category;
use crate::sha256::Sha256;
use crate::sweep::collect::{Body, Item, Origin};
use crate::sweep::tier::Tier;
use crate::test_support::TempDir;

fn item(path: &str, text: &str) -> Item {
    Item {
        file: None,
        origin: Origin::User,
        category: Category::Shell,
        path: path.into(),
        tier: Tier::Unknown,
        sha256: Some(Sha256::digest(text.as_bytes())),
        body: Body::Text(text.into()),
        runs: Vec::new(),
        run_by: None,
        notes: Vec::new(),
        alerts: Vec::new(),
    }
}

#[test]
fn items_count_as_allowed_only_from_roots_list_and_a_home_only_for_its_user() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = TempDir::new("sweep-allowed-system");
    let mut own = Remembered::new();
    own.insert("~/.bashrc".into(), "a".into());
    own.insert("/etc/profile.d/x.sh".into(), "b".into());
    // The list an older Guardian kept in the user's own directory is
    // only read to say what is in it.
    super::save_old_allowed(dir.path(), &own).unwrap();
    assert_eq!(super::old_allowed(dir.path()), own);
    // A list in a directory that is not root's counts for nothing.
    let system = dir.path().join("system.json");
    super::save_system_allowed(&system, &own).unwrap();
    assert!(super::system_allowed(&system).is_empty());
    if std::os::unix::fs::MetadataExt::uid(&fs::metadata(dir.path()).unwrap()) != 0 {
        assert!(super::all_allowed(&system, &system, 1000).is_empty());
    }
    assert!(super::is_home_label("~/x") && !super::is_home_label("/root/x"));
    // Saving sets the mode of the list's directory and of nothing in
    // it: what else root keeps there stays as closed as it was made.
    let kept = dir.path().join("kept");
    for (name, mode) in [("sweep", 0o750), ("permits", 0o700)] {
        fs::create_dir_all(kept.join(name)).unwrap();
        fs::set_permissions(kept.join(name), fs::Permissions::from_mode(mode)).unwrap();
    }
    fs::set_permissions(&kept, fs::Permissions::from_mode(0o700)).unwrap();
    super::save_system_allowed(&kept.join("allowed.json"), &own).unwrap();
    let mode = |path: &std::path::Path| fs::metadata(path).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode(&kept), 0o755);
    assert_eq!(mode(&kept.join("sweep")), 0o750);
    assert_eq!(mode(&kept.join("permits")), 0o700);

    // Root's list is one every user can reach: beside the results it
    // sat in a directory only one group may enter. The old one is read
    // until root moves it, then the new one alone counts.
    let keeper = super::Keeper {
        owner: std::os::unix::fs::MetadataExt::uid(&fs::metadata(dir.path()).unwrap()),
        anchor: dir.path(),
    };
    let state = dir.path().join("guardian");
    let (list, legacy) = (state.join("allowed.json"), state.join("sweep/allowed.json"));
    fs::create_dir_all(state.join("sweep")).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(state.join("sweep"), fs::Permissions::from_mode(0o750)).unwrap();
    super::save_system_allowed(&legacy, &own).unwrap();
    assert_eq!(keeper.current(&list, &legacy), own);
    keeper.move_legacy(&list, &legacy).unwrap();
    assert!(!legacy.exists());
    assert_eq!(keeper.list(&list), own);
    assert_eq!(keeper.current(&list, &legacy), own);
    let mode = |path: &std::path::Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!((mode(&state), mode(&list)), (0o755, 0o644));
    // A list written again where the new one stands does not take its
    // place.
    let mut other = own.clone();
    other.insert("/etc/stale".into(), "c".into());
    super::save_system_allowed(&legacy, &other).unwrap();
    assert_eq!(keeper.current(&list, &legacy), own);
    keeper.move_legacy(&list, &legacy).unwrap();
    assert!(!legacy.exists());
    assert_eq!(keeper.list(&list), own);

    // In root's list a home's label is bound to a user id.
    assert_eq!(super::system_key("~/.bashrc", 1000), "1000:~/.bashrc");
    assert_eq!(super::system_key("/etc/x", 1000), "/etc/x");
    let list: Remembered = [
        ("/etc/x", "s"),
        ("1000:~/.bashrc", "mine"),
        ("1001:~/.bashrc", "theirs"),
        // Written by hand, or by an older version: bound to nobody.
        ("~/.profile", "nobody's"),
        ("x:~/.profile", "nobody's"),
        ("1000:/etc/y", "not a home label"),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_string(), value.to_string()))
    .collect();
    let mine = super::allowed_for(&list, 1000);
    assert_eq!(
        mine.iter().collect::<Vec<_>>(),
        [
            (&"/etc/x".to_string(), &"s".to_string()),
            (&"~/.bashrc".to_string(), &"mine".to_string())
        ]
    );
    assert_eq!(super::allowed_for(&list, 1001)["~/.bashrc"], "theirs");
    assert_eq!(super::allowed_for(&list, 0).len(), 1);
    // An emptied old list is removed.
    super::save_old_allowed(dir.path(), &Remembered::new()).unwrap();
    assert!(!dir.path().join("allowed.json").exists());
}

#[test]
fn an_override_of_guardians_sweep_or_a_half_followed_item_is_never_allowed() {
    let mut items = vec![item("a", "one"), item("b", "two"), item("c", "three")];
    items[0].alerts.push((
        crate::rules::RuleId::GuardianOverride,
        "changes the sweep".into(),
    ));
    items[1].notes.push(format!(
        "{}only the first 1024 commands of a line",
        crate::sweep::collect::NOT_ALL_FOLLOWED
    ));
    let list: Remembered = items
        .iter()
        .map(|item| (item.path.clone(), super::fingerprint(item)))
        .collect();
    apply_allowed(&mut items, &list, |item| item.path.clone());
    let tiers: Vec<Tier> = items.iter().map(|item| item.tier).collect();
    assert_eq!(tiers, [Tier::Unknown, Tier::Unknown, Tier::Allowed]);
    assert!(super::not_allowable(&items[0]).is_some());
    assert!(super::not_allowable(&items[2]).is_none());
    // What the sweep notes for itself is no change to tell.
    let before = Remembered::new();
    let after: Remembered = [(super::TRUST_SEEN.to_string(), "1".to_string())]
        .into_iter()
        .collect();
    assert!(diff(&before, &after).is_empty() && diff(&after, &before).is_empty());
    assert_eq!(super::content_of("abc+path-hijack+finding"), "abc");
}
#[test]
fn changes_are_new_changed_or_removed() {
    let previous = Remembered::from([
        ("a".into(), "1".into()),
        ("b".into(), "2".into()),
        ("c".into(), "3".into()),
        ("e".into(), "-".into()),
        ("f".into(), "-".into()),
    ]);
    let current = Remembered::from([
        ("a".into(), "1".into()),
        ("b".into(), "9".into()),
        ("d".into(), "4".into()),
        // Unreadable before, read now (root's results arrived): no change.
        ("e".into(), "5".into()),
        // ... unless it now raises an alert.
        ("f".into(), "6+keyboard-reader".into()),
    ]);
    assert_eq!(
        diff(&previous, &current),
        [
            (Change::Changed, "b".to_string()),
            (Change::Removed, "c".to_string()),
            (Change::New, "d".to_string()),
            (Change::Changed, "f".to_string())
        ]
    );
}

#[test]
fn what_the_timer_told_about_is_kept_apart_from_what_was_last_seen() {
    use super::{has_told, save_told, told};
    let dir = TempDir::new("sweep-told");
    assert!(!has_told(dir.path()));
    // An install from before: the last sweep stands in.
    let seen: Remembered = [("/etc/a".to_string(), "1".to_string())]
        .into_iter()
        .collect();
    save_baseline(dir.path(), &seen).unwrap();
    assert!(has_told(dir.path()));
    assert_eq!(told(dir.path()), seen);
    // Once the timer has told, a sweep by hand no longer moves it.
    save_told(dir.path(), &seen).unwrap();
    let more: Remembered = [
        ("/etc/a".to_string(), "1".to_string()),
        ("/etc/new".to_string(), "2".to_string()),
    ]
    .into_iter()
    .collect();
    save_baseline(dir.path(), &more).unwrap();
    assert_eq!(told(dir.path()), seen);
    assert_eq!(baseline(dir.path()), more);
    // A finding that appears is a change; one that goes is not.
    let plain: Remembered = [("/etc/a".to_string(), "1".to_string())]
        .into_iter()
        .collect();
    let flagged: Remembered = [("/etc/a".to_string(), "1+finding".to_string())]
        .into_iter()
        .collect();
    assert_eq!(
        diff(&plain, &flagged),
        [(Change::Changed, "/etc/a".to_string())]
    );
    assert!(diff(&flagged, &plain).is_empty());
    assert_eq!(
        diff(&told(dir.path()), &more),
        [(Change::New, "/etc/new".to_string())]
    );
}

#[test]
fn an_allowed_item_counts_as_trusted_until_it_changes() {
    let dir = TempDir::new("sweep-state");
    let mut items = vec![item("x", "one"), item("y", "two")];
    let mut list = Remembered::new();
    list.insert("/x".into(), super::fingerprint(&items[0]));
    list.insert("/y".into(), "an older hash".into());
    apply_allowed(&mut items, &list, |item| format!("/{}", item.path));
    assert_eq!(items[0].tier, Tier::Allowed);
    assert_eq!(items[1].tier, Tier::Unknown);

    save_baseline(dir.path(), &list).unwrap();
    assert_eq!(baseline(dir.path()), list);
    assert!(
        fs::read_dir(dir.path()).unwrap().count() == 1,
        "no temporary files left"
    );
}

#[test]
fn the_last_run_is_remembered_with_why_it_did_not_finish() {
    use super::{LastRun, Outcome, last_run, last_run_in, mark_started, save_last_run, started_in};
    let dir = TempDir::new("sweep-last-run");
    let sweep = dir.path().join("sweep");
    fs::create_dir_all(&sweep).unwrap();
    assert_eq!(last_run_in(dir.path()), None);

    // What an older sweep left counts as a run.
    fs::write(sweep.join("baseline.json"), "{}").unwrap();
    let from_baseline = last_run_in(dir.path()).unwrap();
    assert_eq!(from_baseline.outcome, Outcome::Complete);
    assert!(from_baseline.at > 0);

    let reasons: Vec<String> = (0..8).map(|index| format!("reason {index}")).collect();
    let run = LastRun::new(42, Outcome::Incomplete, reasons);
    assert_eq!(run.reasons.len(), 6);
    assert_eq!(run.reasons[5], "and 3 more");
    // A sweep that started is known as such until it records its end.
    assert_eq!(started_in(dir.path()), None);
    mark_started(&sweep, 40).unwrap();
    assert_eq!(started_in(dir.path()), Some(40));
    save_last_run(&sweep, &run).unwrap();
    assert_eq!(started_in(dir.path()), None);
    assert_eq!(last_run(&sweep), Some(run.clone()));
    assert_eq!(last_run_in(dir.path()), Some(run));

    // What is read back is bounded and plain.
    fs::write(
        sweep.join("last-run.json"),
        format!(
            "{{\"at\":1,\"outcome\":\"failed\",\"reasons\":[\"<b>x\\ny\",\"{}\"]}}",
            "z".repeat(1000)
        ),
    )
    .unwrap();
    let read = last_run(&sweep).unwrap();
    assert_eq!(read.reasons[0], "bx\\ny");
    assert_eq!(read.reasons[1].len(), 300);
    fs::write(sweep.join("last-run.json"), " ".repeat(70 * 1024)).unwrap();
    assert_eq!(last_run(&sweep), None);

    // A record that does not parse is no record.
    fs::write(
        sweep.join("last-run.json"),
        "{\"at\":1,\"outcome\":\"fine\"}",
    )
    .unwrap();
    assert_eq!(last_run(&sweep), None);
    // Nor does what a sweep by hand remembered stand in for it.
    assert_eq!(last_run_in(dir.path()), None);
}
