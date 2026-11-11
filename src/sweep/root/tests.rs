//! Tests of the root part of the sweep.

use std::collections::HashSet;

#[test]
fn more_accounts_than_are_looked_at_is_said() {
    use super::{MAX_ACCOUNTS, accounts_left_out};
    let passwd = |count: usize| {
        let mut lines = vec![
            "root:x:0:0::/root:/bin/bash".to_string(),
            "svc:x:900:900::/srv/svc:/bin/sh".to_string(),
        ];
        lines.extend((0..count).map(|number| {
            let uid = 1000 + number;
            format!("u{number}:x:{uid}:{uid}::/home/u{number}:/bin/bash")
        }));
        let text = lines.join("\n");
        crate::sweep::access::accounts(&text)
    };
    // Root and an account whose home is elsewhere are not counted.
    assert_eq!(accounts_left_out(&passwd(MAX_ACCOUNTS)), None);
    assert_eq!(
        accounts_left_out(&passwd(MAX_ACCOUNTS + 2)).as_deref(),
        Some("more than 200 accounts with a home under /home: the keys of 2 were not looked at")
    );
}

#[test]
fn other_accounts_crontabs_are_withheld() {
    use super::{accounts_in_group, withhold_others_jobs};
    let passwd = "root:x:0:0::/root:/bin/bash\nu:x:1000:1000::/home/u:/bin/bash\nv:x:1001:1001::/home/v:/bin/bash\n";
    let group = "wheel:x:998:u\nu:x:1000:\nshared:x:2000:v,u\n";
    assert_eq!(accounts_in_group(1000, passwd, group), ["u"]);
    assert_eq!(accounts_in_group(2000, passwd, group), ["u", "v"]);
    let crontab = |account: &str| {
        let mut item = item(
            &format!("var/spool/cron/{account}"),
            Origin::Root,
            Tier::Unknown,
            Body::Text("* * * * * /x\n".into()),
        );
        item.runs = vec!["/x".into()];
        item
    };
    let mut items = vec![crontab("root"), crontab("u"), crontab("v")];
    let mut followed = item(
        "home/v/bin/job",
        Origin::Root,
        Tier::Unknown,
        Body::Text("#!/bin/sh\n".into()),
    );
    followed.run_by = Some("var/spool/cron/v".into());
    items.push(followed);
    // `at` jobs are told apart by who owns the file.
    let jobs = [
        "var/spool/atd/a0001",
        "var/spool/atd/a0002",
        "var/spool/atd/a0003",
        "var/spool/atd/a0004",
        // The other spools `at` is built with.
        "var/spool/at/a0002",
        "var/spool/at/a0003",
        "var/spool/cron/atjobs/a0002",
        "var/spool/cron/atjobs/a0003",
    ];
    for job in jobs {
        items.push(item(
            job,
            Origin::Root,
            Tier::Unknown,
            Body::Binary(crate::sweep::collect::WITHHELD),
        ));
    }
    let owner = |job: &str| match job.rsplit('/').next() {
        Some("a0001") => Some("root".to_string()),
        Some("a0002") => Some("u".to_string()),
        Some("a0003") => Some("v".to_string()),
        _ => None,
    };
    assert_eq!(
        withhold_others_jobs(&mut items, &["u".to_string()], &owner),
        5
    );
    let paths: Vec<&str> = items.iter().map(|item| item.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "var/spool/cron/root",
            "var/spool/cron/u",
            "var/spool/atd/a0001",
            "var/spool/atd/a0002",
            "var/spool/at/a0002",
            "var/spool/cron/atjobs/a0002"
        ]
    );
}

#[test]
fn the_list_of_allowed_items_keeps_a_home_for_the_user_who_asked() {
    use super::change_allowed;
    let arguments =
        |words: &[&str]| -> Vec<String> { words.iter().map(|word| (*word).to_string()).collect() };
    let mut allowed = crate::sweep::state::Remembered::new();
    change_allowed(
        &mut allowed,
        &arguments(&["--add", "/etc/x", "a", "--add", "~/.bashrc", "b"]),
        Some(1000),
    )
    .unwrap();
    change_allowed(
        &mut allowed,
        &arguments(&["--add", "~/.bashrc", "c"]),
        Some(1001),
    )
    .unwrap();
    assert_eq!(
        allowed.keys().collect::<Vec<_>>(),
        ["/etc/x", "1000:~/.bashrc", "1001:~/.bashrc"]
    );
    // Root has no home of a user to speak for, and nothing else is a
    // label.
    for (words, invoker) in [
        (&["--add", "~/.bashrc", "b"][..], None),
        (&["--add", "1000:~/.bashrc", "b"][..], Some(1000)),
        (&["--add", "relative", "b"][..], Some(1000)),
        (&["--add", "/etc/x\n/etc/y", "b"][..], Some(1000)),
        (&["--add", "/etc/x", ""][..], Some(1000)),
        (&["--add", "/etc/x"][..], Some(1000)),
        (&["--allow-everything"][..], Some(1000)),
        (&[][..], Some(1000)),
    ] {
        let mut copy = allowed.clone();
        assert!(
            change_allowed(&mut copy, &arguments(words), invoker).is_err(),
            "{words:?}"
        );
    }
    // One user's forget leaves the other's home alone.
    change_allowed(
        &mut allowed,
        &arguments(&["--remove", "~/.bashrc"]),
        Some(1001),
    )
    .unwrap();
    assert_eq!(
        allowed.keys().collect::<Vec<_>>(),
        ["/etc/x", "1000:~/.bashrc"]
    );
    change_allowed(&mut allowed, &arguments(&["--clear"]), Some(1001)).unwrap();
    assert_eq!(allowed.keys().collect::<Vec<_>>(), ["1000:~/.bashrc"]);
}

#[test]
fn root_reports_on_each_home_as_its_account_could_look_itself() {
    use std::os::unix::fs::MetadataExt;
    let dir = crate::test_support::TempDir::new("root-accounts");
    let root = dir.path();
    let uid = std::fs::metadata(root).unwrap().uid();
    let write = |path: &str, text: &str| {
        std::fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
        std::fs::write(root.join(path), text).unwrap();
    };
    let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGuardianTestKeyMaterial0123456789abcdefghi";
    write("home/u/.ssh/authorized_keys", &format!("{key} u@laptop\n"));
    write(
        "home/v/.ssh/authorized_keys",
        &format!("{key} v@laptop\n{key} v@other\n"),
    );
    write(
        "home/u/.config/systemd/user/omarchy-guardian-sweep.service.d/x.conf",
        "[Service]\nEnvironment=HOME=/tmp/x\n",
    );
    write(
        "home/v/.config/systemd/user/omarchy-guardian-sweep.service.d/x.conf",
        "[Service]\nEnvironment=HOME=/tmp/x\n",
    );
    // A key file that is a link to a file the account may read (kept
    // in a dotfiles directory) is its key file all the same; one that
    // leads to a file it could not read (a file of root's, say) shows
    // nothing.
    write("home/w/.ssh/real", &format!("{key} w\n"));
    std::os::unix::fs::symlink("real", root.join("home/w/.ssh/authorized_keys")).unwrap();
    write("home/x/.ssh/closed", &format!("{key} x\n"));
    std::os::unix::fs::symlink("closed", root.join("home/x/.ssh/authorized_keys")).unwrap();
    std::fs::set_permissions(
        root.join("home/x/.ssh/closed"),
        std::os::unix::fs::PermissionsExt::from_mode(0o000),
    )
    .unwrap();
    // Run as root, the homes are root's, and an account with user id 0
    // is root, whose home is not looked at this way: the accounts are
    // `nobody`'s then, and so are their homes where root can give them
    // away (else they are read by what their modes show everyone).
    let uid = if uid == 0 {
        for home in ["home/u", "home/v", "home/w", "home/x"] {
            crate::test_support::give_tree(&root.join(home), crate::test_support::NOBODY);
        }
        crate::test_support::NOBODY
    } else {
        uid
    };
    let passwd = format!(
        "root:x:0:0::/root:/bin/bash\nu:x:{uid}:{uid}::/home/u:/bin/bash\nv:x:{uid}:{uid}::/home/v:/bin/bash\nw:x:{uid}:{uid}::/home/w:/bin/bash\nx:x:{uid}:{uid}::/home/x:/bin/bash\nsvc:x:{uid}:{uid}::/srv/svc:/bin/bash\n"
    );
    let index = crate::sweep::index::PackageIndex::with_foreign(HashSet::new());
    let scope = crate::sweep::collect::Scope {
        root,
        home: Some("root"),
        index: &index,
        origin: Origin::Root,
    };
    let items = super::of_accounts(
        &scope,
        &crate::sweep::access::accounts(&passwd),
        &["u".to_string()],
    );
    let paths: Vec<&str> = items.iter().map(|item| item.path.as_str()).collect();
    assert_eq!(paths.len(), 4, "{paths:?}");
    // The reader's own: the override of Guardian's unit, and each key.
    assert_eq!(
        paths[0],
        "home/u/.config/systemd/user/omarchy-guardian-sweep.service.d/x.conf"
    );
    assert_eq!(items[0].alerts[0].0, RuleId::GuardianOverride);
    assert!(paths[1].starts_with("home/u/.ssh/authorized_keys#"));
    // Another account's: how many keys, and nothing of its units.
    assert_eq!(paths[2], "home/v/.ssh/authorized_keys#keys");
    assert!(items[2].notes[0].starts_with("2 key(s) may log in as v"));
    assert!(!format!("{items:?}").contains("v@laptop"));
    assert_eq!(paths[3], "home/w/.ssh/authorized_keys#keys");
    assert!(items[3].notes[0].starts_with("1 key(s) may log in as w"));
}

use super::{from_json, merge, to_json};
use crate::autorun::Category;
use crate::rules::RuleId;
use crate::sha256::Sha256;
use crate::sweep::collect::{Body, Collection, Item, Origin};
use crate::sweep::tier::Tier;

fn item(path: &str, origin: Origin, tier: Tier, body: Body) -> Item {
    Item {
        file: None,
        origin,
        category: Category::Sudo,
        path: path.into(),
        tier,
        sha256: Some(Sha256::digest(path.as_bytes())),
        body,
        runs: vec!["/usr/bin/x".into()],
        run_by: Some("etc/y".into()),
        notes: vec!["a note".into()],
        alerts: Vec::new(),
    }
}

#[test]
fn items_round_trip_and_trusted_ones_stay_behind() {
    let collection = Collection {
        items: vec![
            item(
                "etc/sudoers.d/evil",
                Origin::Root,
                Tier::Unknown,
                Body::Text("ALL ALL=(ALL) NOPASSWD: ALL\n".into()),
            ),
            item(
                "usr/bin/x",
                Origin::Root,
                Tier::Modified,
                Body::Binary("ELF executable"),
            ),
            item(
                "etc/sudoers",
                Origin::Root,
                Tier::Vendor,
                Body::Text("trusted".into()),
            ),
        ],
        truncated: vec!["/etc/x".into()],
        // What root could not list is a gap of root's own; what it listed
        // travels, each once.
        unlisted: vec!["root/.local/lib".into()],
        listed: vec!["boot/EFI".into(), "usr/lib".into(), "boot/EFI".into()],
        ..Collection::default()
    };
    let mut collection = collection;
    // The drop-in is in the catalog itself: its content travels.
    collection.items[0].run_by = None;
    collection.items[1]
        .alerts
        .push((RuleId::HiddenProgram, "seen".into()));
    let noted = vec!["the kernel is tainted (flags 4096)".to_string()];
    let part = from_json(
        &to_json(
            &collection,
            &super::in_keeping_order(&collection, &HashSet::new(), &HashSet::new()),
            &noted,
            None,
        )
        .to_string(),
    )
    .unwrap();
    assert_eq!(part.notes, noted);
    assert_eq!(part.items, collection.items[..2]);
    assert_eq!(
        part.truncated,
        ["/etc/x", "/root/.local/lib: could not be listed"]
    );
    assert_eq!(part.listed, ["boot/EFI", "usr/lib"]);
}

#[test]
fn facts_that_are_no_files_travel_like_any_item() {
    // An account, a member, a key: named with a `#`, kept as text.
    let mut fact = item(
        "etc/passwd#toor",
        Origin::Root,
        Tier::Unknown,
        Body::Text("account toor uid 0 shell /bin/bash".into()),
    );
    fact.category = Category::Account;
    fact.run_by = None;
    fact.alerts
        .push((RuleId::PrivilegedAccount, "toor has user id 0".into()));
    let collection = Collection {
        items: vec![fact],
        ..Collection::default()
    };
    let part = from_json(
        &to_json(
            &collection,
            &super::in_keeping_order(&collection, &HashSet::new(), &HashSet::new()),
            &[],
            None,
        )
        .to_string(),
    )
    .unwrap();
    assert_eq!(part.items, collection.items);
}

#[test]
fn only_a_private_group_may_read_roots_results() {
    let passwd = "root:x:0:0::/root:/bin/bash\nu:x:1000:1000::/home/u:/bin/bash\nv:x:1001:100::/home/v:/bin/bash\nw:x:1002:100::/home/w:/bin/bash\n";
    let group = "root:x:0:\nu:x:1000:\nusers:x:100:\nwheel:x:998:u\n";
    assert_eq!(
        super::private_group(1000, group, passwd).as_deref(),
        Some("u")
    );
    assert_eq!(super::private_group(100, group, passwd), None);
    assert_eq!(super::private_group(998, group, passwd), None);
}

#[test]
fn malformed_or_foreign_output_is_refused() {
    assert!(from_json("not json").is_err());
    assert!(from_json(r#"{"version":4,"items":[]}"#).is_err());
    assert!(from_json(r#"{"items":[]}"#).is_err());
    // An older collector's results are read, and known as that.
    assert!(from_json(r#"{"version":1,"items":[]}"#).unwrap().outdated);
    assert!(from_json(r#"{"version":2,"items":[]}"#).unwrap().outdated);
    let current = from_json(r#"{"version":3,"items":[],"new_trust":["etc/passwd#x"]}"#).unwrap();
    assert!(!current.outdated);
    assert_eq!(current.news, Some(vec!["etc/passwd#x".to_string()]));
    assert_eq!(from_json(r#"{"version":3,"items":[]}"#).unwrap().news, None);
    let escaping = r#"{"version":1,"items":[{"path":"../etc/x","category":"sudo","tier":"unknown","body":{"kind":"undecodable"},"runs":[],"notes":[],"alerts":[]}]}"#;
    // A bad item is left out; the rest of root's results still count.
    assert!(from_json(escaping).unwrap().items.is_empty());
}

#[test]
fn what_root_reached_by_following_keeps_only_its_hash() {
    use crate::sweep::collect::{WITHHELD, item as collect_item};
    let dir = crate::test_support::TempDir::new("root-withheld");
    let root = dir.path();
    std::fs::create_dir_all(root.join("var/spool/cron")).unwrap();
    std::fs::create_dir_all(root.join("etc")).unwrap();
    std::fs::write(root.join("etc/shadow"), "root:$6$hash:\n").unwrap();
    std::fs::write(root.join("var/spool/cron/u"), "* * * * * /etc/shadow\n").unwrap();
    let index = crate::sweep::index::PackageIndex::with_foreign(HashSet::new());
    let scope = crate::sweep::collect::Scope {
        root,
        home: Some("root"),
        index: &index,
        origin: Origin::Root,
    };
    // A crontab line names it: followed, so its content stays home,
    // whoever may read it, and nothing is followed from it.
    let followed = collect_item(
        &scope,
        Category::Cron,
        "etc/shadow".into(),
        Some("var/spool/cron/u"),
    );
    assert_eq!(followed.body, Body::Binary(WITHHELD));
    assert!(followed.runs.is_empty());
    // The crontab itself is an auto-run file: its content travels.
    let direct = collect_item(&scope, Category::Cron, "var/spool/cron/u".into(), None);
    assert!(matches!(direct.body, Body::Text(_)));
    assert_eq!(direct.runs, ["/etc/shadow"]);
}

#[test]
fn root_findings_replace_what_the_user_could_not_judge() {
    let mut collection = Collection {
        items: vec![
            item(
                "etc/sudoers",
                Origin::System,
                Tier::Unknown,
                Body::Unreadable("denied".into()),
            ),
            item(
                "etc/pam.d/x",
                Origin::System,
                Tier::Vendor,
                Body::Text(String::new()),
            ),
            item(
                "home/u/.bashrc",
                Origin::User,
                Tier::Unknown,
                Body::Text(String::new()),
            ),
        ],
        ..Collection::default()
    };
    // The user's own live alert (a program in memory) stays.
    let mut memory = item(
        "memfd:payload",
        Origin::System,
        Tier::Unknown,
        Body::Unreadable("runs only in memory".into()),
    );
    memory.alerts.push((RuleId::HiddenProgram, "seen".into()));
    collection.items.push(memory);
    let root = item(
        "etc/sudoers.d/evil",
        Origin::Root,
        Tier::Unknown,
        Body::Text(String::new()),
    );
    merge(
        &mut collection,
        super::RootPart {
            items: vec![root],
            ..super::RootPart::default()
        },
    );
    let paths: Vec<&str> = collection
        .items
        .iter()
        .map(|item| item.path.as_str())
        .collect();
    assert_eq!(
        paths,
        [
            "etc/pam.d/x",
            "etc/sudoers.d/evil",
            "home/u/.bashrc",
            "memfd:payload"
        ]
    );
}

#[test]
fn an_accounts_units_that_turn_the_sweep_off_come_first_but_crowd_out_nothing() {
    // More drop-ins standing in for the sweep's unit than the results
    // hold, in one home; root's unit after them.
    let override_item = |path: String| {
        let mut unit = item(
            &path,
            Origin::Root,
            Tier::Unknown,
            Body::Text("[Service]".into()),
        );
        unit.run_by = None;
        unit.alerts
            .push((RuleId::GuardianOverride, "stands in for the sweep".into()));
        unit
    };
    let mut items: Vec<Item> = (0..super::MAX_ITEMS + 10)
        .map(|index| {
            override_item(format!(
                "home/u/.config/systemd/user/omarchy-guardian-sweep.service.d/{index:05}.conf"
            ))
        })
        .collect();
    // Another home, and a runtime directory, with more than are kept
    // first of each.
    let drop_ins = |directory: &str| -> Vec<Item> {
        (0..super::MAX_OVERRIDES_OF_AN_ACCOUNT + 4)
            .map(|index| {
                override_item(format!(
                    "{directory}/omarchy-guardian-sweep.service.d/{index:02}.conf"
                ))
            })
            .collect()
    };
    items.extend(drop_ins("home/v/.config/systemd/user"));
    items.extend(drop_ins("run/user/1000/systemd/user"));
    let mut own = item(
        "etc/systemd/system/x.service",
        Origin::Root,
        Tier::Unknown,
        Body::Text("x".into()),
    );
    own.run_by = None;
    items.push(own);
    let collection = Collection {
        items,
        ..Collection::default()
    };
    let part = from_json(
        &to_json(
            &collection,
            &super::in_keeping_order(&collection, &HashSet::new(), &HashSet::new()),
            &[],
            None,
        )
        .to_string(),
    )
    .unwrap();
    let first = super::MAX_OVERRIDES_OF_AN_ACCOUNT;
    // The first of each home's and of the runtime directory's, then
    // root's, then the rest.
    let places = |items: &[Item]| {
        items
            .iter()
            .map(|item| item.path.split('/').take(3).collect::<Vec<_>>().join("/"))
            .collect::<Vec<_>>()
    };
    let mut expected = vec!["home/u/.config".to_string(); first];
    expected.extend(vec!["home/v/.config".to_string(); first]);
    expected.extend(vec!["run/user/1000".to_string(); first]);
    assert_eq!(places(&part.items[..3 * first]), expected);
    assert_eq!(part.items[3 * first].path, "etc/systemd/system/x.service");
    assert!(
        part.items[3 * first + 1..]
            .iter()
            .all(|item| item.path.starts_with("home/u/"))
    );
}

/// An item a live check found, of `category`.
fn live(path: &str, category: Category) -> Item {
    let mut found = item(path, Origin::Root, Tier::Unknown, Body::Text("x".into()));
    found.category = category;
    found.run_by = None;
    found
}

#[test]
fn the_live_checks_hand_root_at_most_so_many_items_of_a_kind_that_accounts_made() {
    let limit = super::MAX_LIVE_OF_A_KIND;
    let made_by = |count: usize| -> (Vec<Item>, HashSet<String>) {
        let items: Vec<Item> = (0..count)
            .map(|index| live(&format!("dev/shm/a{index:03}"), Category::Process))
            .collect();
        let made = items.iter().map(|item| item.path.clone()).collect();
        (items, made)
    };
    // Exactly as many as are kept: nothing left out, nothing said.
    let (items, made) = made_by(limit);
    let mut truncated = Vec::new();
    assert_eq!(
        super::within_kind_limit(items, &made, &mut truncated).len(),
        limit
    );
    assert_eq!(truncated, Vec::<String>::new());
    // One more, and root's own of the same kind on top: all of root's stay.
    let (mut items, made) = made_by(limit + 1);
    items.extend((0..limit + 5).map(|pid| live(&format!("proc/{pid}"), Category::Process)));
    items.push(live("usr/bin/x:tcp-4444", Category::Listener));
    let kept = super::within_kind_limit(items, &made, &mut truncated);
    assert_eq!(kept.len(), limit + limit + 5 + 1);
    assert!(
        kept.iter()
            .all(|item| item.path != format!("dev/shm/a{limit:03}"))
    );
    assert_eq!(truncated.len(), 1, "{truncated:?}");
    assert!(
        truncated[0].starts_with(&format!("the live checks found {} items in", limit + 1)),
        "{truncated:?}"
    );
}

#[test]
fn what_accounts_make_at_will_does_not_crowd_out_roots_live_items() {
    // Programs run from `/dev/shm` sort before `proc/`, `memfd:` and
    // `usr/`, and each set-id file in a home before `usr/local/bin`; more
    // of them than the results hold, made by one account.
    let mut collection = Collection {
        items: vec![live("etc/systemd/system/x.service", Category::Systemd)],
        ..Collection::default()
    };
    let mut items: Vec<Item> = (0..super::MAX_ITEMS + 10)
        .map(|index| live(&format!("dev/shm/a{index:05}"), Category::Process))
        .collect();
    items.extend((0..300).map(|index| live(&format!("home/u/f{index:03}"), Category::Setuid)));
    let made: HashSet<String> = items
        .iter()
        .filter(|item| item.category != Category::Systemd)
        .map(|item| item.path.clone())
        .collect();
    let roots = [
        ("proc/1", Category::Process),
        ("proc", Category::Process),
        ("memfd:payload", Category::Process),
        ("usr/bin/x:tcp-4444", Category::Listener),
        ("usr/local/bin/planted", Category::Setuid),
    ];
    items.extend(roots.iter().map(|(path, category)| live(path, *category)));
    let mut truncated = Vec::new();
    let items = super::within_kind_limit(items, &made, &mut truncated);
    crate::sweep::collect::merge(&mut collection, items);
    let part = from_json(
        &to_json(
            &collection,
            &super::in_keeping_order(&collection, &made, &HashSet::new()),
            &[],
            None,
        )
        .to_string(),
    )
    .unwrap();
    let paths: Vec<&str> = part.items.iter().map(|item| item.path.as_str()).collect();
    assert_eq!(
        paths[..6],
        [
            "etc/systemd/system/x.service",
            "memfd:payload",
            "proc",
            "proc/1",
            "usr/bin/x:tcp-4444",
            "usr/local/bin/planted",
        ]
    );
    // Of what the account made, at most so many of a kind.
    for place in ["dev/shm/", "home/u/"] {
        let kept = paths.iter().filter(|path| path.starts_with(place)).count();
        assert_eq!(kept, super::MAX_LIVE_OF_A_KIND, "{place}");
    }
}

#[test]
fn a_flood_from_an_accounts_crontab_or_at_jobs_leaves_roots_in() {
    // A crontab and an `at` job of an account each name more files in
    // `/dev/shm` than the results hold, ahead of `etc/` by path; one of
    // those files names more. Root's crontab and `at` job name one each.
    let found = |path: &str, by: Option<&str>| {
        let mut found = item(path, Origin::Root, Tier::Unknown, Body::Text("x".into()));
        found.category = Category::Cron;
        found.run_by = by.map(str::to_string);
        found
    };
    let mut items = vec![
        found("var/spool/cron/u", None),
        found("var/spool/atd/a0001", None),
        found("var/spool/cron/root", None),
        found("var/spool/atd/a0002", None),
        found("etc/cron.d/x", None),
        found("dev/shm/by-root", Some("var/spool/cron/root")),
        found("dev/shm/by-roots-job", Some("var/spool/atd/a0002")),
        // The account names it first; root's crontab too.
        found("dev/shm/both", Some("var/spool/cron/u")),
        found("dev/shm/deeper", Some("dev/shm/f00000")),
        // Root's crontab runs a script in the account's home, which names
        // what it likes.
        found("home/u/script", Some("var/spool/cron/root")),
        found("dev/shm/from-home", Some("home/u/script")),
    ];
    for index in 0..super::MAX_ITEMS + 10 {
        items.push(found(
            &format!("dev/shm/f{index:05}"),
            Some("var/spool/cron/u"),
        ));
        items.push(found(
            &format!("dev/shm/j{index:05}"),
            Some("var/spool/atd/a0001"),
        ));
    }
    items.sort_by(|left, right| left.path.cmp(&right.path));
    let mut collection = Collection {
        items,
        ..Collection::default()
    };
    collection.runners.insert(
        "dev/shm/both".into(),
        vec!["var/spool/cron/u".into(), "var/spool/cron/root".into()],
    );
    let made = super::made_by_accounts(&collection, HashSet::new(), &|job| {
        Some(if job == "var/spool/atd/a0002" {
            0
        } else {
            1000
        })
    });
    assert_eq!(made, HashSet::from(["var/spool/atd/a0001".to_string()]));
    let kept = super::in_keeping_order(&collection, &made, &HashSet::new());
    let mut roots: Vec<&str> = kept.roots.iter().copied().collect();
    roots.sort_unstable();
    // Root's crontab leads to `dev/shm/both` only through the runners: its
    // `run_by` is the account's crontab, which reached it first.
    assert_eq!(
        roots,
        [
            "dev/shm/both",
            "dev/shm/by-root",
            "dev/shm/by-roots-job",
            "etc/cron.d/x",
            "home/u/script",
            "var/spool/atd/a0002",
            "var/spool/cron/root",
        ]
    );
    let part = from_json(&to_json(&collection, &kept, &[], None).to_string()).unwrap();
    let mut first: Vec<&str> = part.items[..7]
        .iter()
        .map(|item| item.path.as_str())
        .collect();
    first.sort_unstable();
    assert_eq!(
        first,
        [
            "dev/shm/both",
            "dev/shm/by-root",
            "dev/shm/by-roots-job",
            "etc/cron.d/x",
            "home/u/script",
            "var/spool/atd/a0002",
            "var/spool/cron/root",
        ]
    );
}

#[test]
fn what_the_live_checks_found_only_through_an_account_is_the_accounts_unless_collected() {
    let collection = Collection {
        items: vec![live("usr/local/bin/tool", Category::LocalBin)],
        ..Collection::default()
    };
    let live = HashSet::from([
        "usr/local/bin/tool".to_string(),
        "usr/bin/python3:tcp-8000".to_string(),
    ]);
    let made = super::made_by_accounts(&collection, live, &|_| Some(0));
    assert_eq!(
        made,
        HashSet::from(["usr/bin/python3:tcp-8000".to_string()])
    );
}

#[test]
fn an_accounts_runtime_directory_and_what_names_a_file_at_home_are_the_accounts() {
    let mut served = live("opt/served:tcp-8000", Category::Listener);
    served.file = Some("home/u/served".into());
    let collection = Collection {
        items: vec![
            served,
            live("run/user/1000/x", Category::Process),
            live("zz/root", Category::Process),
        ],
        ..Collection::default()
    };
    let order: Vec<&str> = super::in_keeping_order(&collection, &HashSet::new(), &HashSet::new())
        .items
        .iter()
        .map(|item| item.path.as_str())
        .collect();
    assert_eq!(order, ["zz/root", "opt/served:tcp-8000", "run/user/1000/x"]);
}

#[test]
fn an_accounts_flood_of_items_leaves_roots_and_the_systems_in() {
    // More lines in a home than the results hold: sorted by path they
    // would come before `root/`, `usr/` and `var/`.
    let mut items: Vec<Item> = (0..super::MAX_ITEMS + 10)
        .map(|index| {
            let mut key = item(
                &format!("home/u/.ssh/authorized_keys#{index:06}"),
                Origin::Root,
                Tier::Unknown,
                Body::Text("junk".into()),
            );
            key.category = Category::Account;
            key.run_by = None;
            key
        })
        .collect();
    let mut followed = item(
        "opt/x/run",
        Origin::Root,
        Tier::Unknown,
        Body::Text("x".into()),
    );
    followed.run_by = Some("home/u/.bashrc".into());
    items.push(followed);
    for path in ["root/.ssh/authorized_keys#aa", "var/spool/cron/root"] {
        let mut own = item(path, Origin::Root, Tier::Unknown, Body::Text("x".into()));
        own.category = Category::Account;
        own.run_by = None;
        items.push(own);
    }
    let collection = Collection {
        items,
        ..Collection::default()
    };
    let part = from_json(
        &to_json(
            &collection,
            &super::in_keeping_order(&collection, &HashSet::new(), &HashSet::new()),
            &[],
            None,
        )
        .to_string(),
    )
    .unwrap();
    assert_eq!(part.items.len(), super::MAX_ITEMS);
    assert_eq!(part.items[0].path, "root/.ssh/authorized_keys#aa");
    assert_eq!(part.items[1].path, "var/spool/cron/root");
    assert!(
        part.items[2..]
            .iter()
            .all(|item| item.path.starts_with("home/u/"))
    );
    assert!(
        part.truncated[0].ends_with("13 were left out"),
        "{:?}",
        part.truncated
    );
    // The collector's record keeps the same order.
    let (_, seen) = super::news(
        &super::in_keeping_order(&collection, &HashSet::new(), &HashSet::new()).items,
        None,
        1,
    );
    assert!(seen.contains_key("root/.ssh/authorized_keys#aa"));
}

#[test]
fn the_collector_tells_what_is_new_from_its_own_record() {
    use crate::autorun::Category;
    let key = |name: &str, text: &str| {
        let mut key = item(
            &format!("root/.ssh/authorized_keys#{name}"),
            Origin::Root,
            Tier::Unknown,
            Body::Text(text.into()),
        );
        key.category = Category::Account;
        key.sha256 = Some(Sha256::digest(text.as_bytes()));
        key
    };
    let unit = item(
        "etc/systemd/system/x.service",
        Origin::Root,
        Tier::Unknown,
        Body::Text("[Service]".into()),
    );
    let hour = 60 * 60;
    // The first look remembers everything and has no list of what is
    // new: the sweep that reads the results goes by its own memory.
    let (new, seen) = super::news(&[&key("a", "one"), &unit], None, 1000);
    assert_eq!(new, None);
    assert_eq!(
        seen.keys().collect::<Vec<_>>(),
        ["root/.ssh/authorized_keys#a"]
    );
    // A key that was not there, and one that changed, are new, and stay
    // so for two days, whatever the sweeps that read the results
    // remember.
    let items = [key("a", "other"), key("b", "two"), unit];
    let news = |items: &[Item], seen, now| {
        let kept: Vec<&Item> = items.iter().collect();
        let (new, seen) = super::news(&kept, Some(seen), now);
        (new.unwrap(), seen)
    };
    let (new, seen) = news(&items, seen, 2000);
    assert_eq!(
        new,
        ["root/.ssh/authorized_keys#a", "root/.ssh/authorized_keys#b"]
    );
    let (new, seen) = news(&items, seen, 2000 + 47 * hour);
    assert_eq!(new.len(), 2);
    let (new, seen) = news(&items, seen, 2000 + 49 * hour);
    assert!(new.is_empty());
    // One that went and came back is new again.
    let (_, seen) = news(&items[..1], seen, 2000 + 50 * hour);
    let (new, seen) = news(&items, seen, 2000 + 51 * hour);
    assert_eq!(new, ["root/.ssh/authorized_keys#b"]);
    // The record is written and read back as it is; the results carry
    // the list only where a record was kept.
    let text = super::trust_seen_json(&seen);
    assert!(text.contains("\"first\":"));
    let collection = Collection {
        items: items.to_vec(),
        ..Collection::default()
    };
    let part = from_json(
        &to_json(
            &collection,
            &super::in_keeping_order(&collection, &HashSet::new(), &HashSet::new()),
            &[],
            Some(&new),
        )
        .to_string(),
    )
    .unwrap();
    assert_eq!(part.news, Some(new));
    // Without a record the results carry none, and the reader's own
    // memory stands in.
    let untracked = from_json(
        &to_json(
            &collection,
            &super::in_keeping_order(&collection, &HashSet::new(), &HashSet::new()),
            &[],
            None,
        )
        .to_string(),
    )
    .unwrap();
    assert_eq!(untracked.news, None);
    let mut merged = Collection::default();
    merge(&mut merged, part);
    assert_eq!(
        merged.root_news,
        Some(vec!["root/.ssh/authorized_keys#b".to_string()])
    );
}

#[test]
fn a_directory_the_user_could_not_list_is_covered_only_where_root_listed_it() {
    let gap = "/boot/EFI: could not be listed";
    let unlisted = || Collection {
        unlisted: vec!["boot/EFI".into()],
        ..Collection::default()
    };
    let merged = |part: super::RootPart| {
        let mut collection = unlisted();
        merge(&mut collection, part);
        collection.not_looked_at()
    };
    // No results from root to merge (missing, stale or unreadable): the
    // directory was not looked at.
    assert_eq!(unlisted().not_looked_at(), [gap]);
    // Root listed it.
    assert!(
        merged(super::RootPart {
            listed: vec!["boot".into(), "boot/EFI".into()],
            ..super::RootPart::default()
        })
        .is_empty()
    );
    // Root ran, but listed only what is around it.
    assert_eq!(
        merged(super::RootPart {
            listed: vec!["boot".into(), "boot/EFI/limine".into()],
            ..super::RootPart::default()
        }),
        [gap]
    );
    // A collector that does not say what it listed covers nothing.
    let older = from_json(r#"{"version":3,"items":[],"truncated":[]}"#).unwrap();
    assert!(older.listed.is_empty());
    assert_eq!(merged(older), [gap]);
}

#[test]
fn missing_or_stale_results_are_not_used() {
    use std::os::unix::fs::MetadataExt;
    let dir = crate::test_support::TempDir::new("root-results-age");
    let path = dir.path().join("sweep/root.json");
    assert!(super::from_results(&path, 0).is_err());

    let collection = Collection {
        listed: vec!["boot/EFI".into()],
        ..Collection::default()
    };
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        to_json(
            &collection,
            &super::in_keeping_order(&collection, &HashSet::new(), &HashSet::new()),
            &[],
            None,
        )
        .to_string(),
    )
    .unwrap();
    let metadata = std::fs::metadata(&path).unwrap();
    let written = u64::try_from(metadata.mtime()).unwrap();
    let two_days_later = written + 48 * 60 * 60;
    let stale = super::from_results(&path, two_days_later);
    // Only results root owns are used at all; a test run by root (as in
    // CI) gets past that check and is refused for their age.
    if metadata.uid() == 0 {
        assert_eq!(
            super::from_results(&path, written).unwrap().listed,
            ["boot/EFI"]
        );
        assert_eq!(
            stale.unwrap_err().to_string(),
            "the daily root check has not run for more than 36 hours"
        );
    } else {
        assert!(stale.is_err());
    }
}

#[test]
fn what_runs_each_of_roots_items_is_kept_as_its_runner() {
    let tool = Item {
        run_by: Some("home/u/.bashrc".into()),
        ..item(
            "home/u/bin/tool",
            Origin::Root,
            Tier::Unknown,
            Body::Text("true\n".into()),
        )
    };
    let part = super::RootPart {
        items: vec![tool],
        ..super::RootPart::default()
    };
    // What the user's own walk found stays beside it.
    let mut collection = Collection::default();
    collection.runners.insert(
        "home/u/bin/tool".into(),
        vec!["etc/systemd/system/a.service".into()],
    );
    merge(&mut collection, part);
    assert_eq!(
        collection.runners["home/u/bin/tool"],
        ["etc/systemd/system/a.service", "home/u/.bashrc"]
    );
}

#[test]
fn the_accounts_items_carry_only_so_much_and_roots_all_of_theirs() {
    let file = |path: &str, size: usize| {
        let mut file = live(path, Category::Autostart);
        // Half in what an alert saw, which counts as much as the text.
        file.body = Body::Text("x".repeat(size / 2));
        file.alerts = vec![(RuleId::GuardianOverride, "x".repeat(size / 2))];
        file
    };
    let kib = 1024;
    let autostart = "home/u/.config/autostart";
    // Names as long as a path can be, of characters the JSON writes as six
    // bytes each.
    let long = |index: usize| format!("{autostart}/{}{index}", "\u{1}".repeat(4000));
    let mut items = vec![
        file("etc/cron.d/big", 1536 * kib),
        file(&format!("{autostart}/a1"), 600 * kib),
        file(&format!("{autostart}/a2"), 600 * kib),
        file(&format!("{autostart}/a3"), 10),
    ];
    items.extend((0..100).map(|index| file(&long(index), 10)));
    items.push(file(&format!("etc/{}", "\u{1}".repeat(4000)), 10));
    let collection = Collection {
        items,
        ..Collection::default()
    };
    let kept = super::in_keeping_order(&collection, &HashSet::new(), &HashSet::new());
    let json = to_json(&collection, &kept, &[], None).to_string();
    let part = from_json(&json).unwrap();
    let find = |path: &str| part.items.iter().find(|item| item.path == path);
    // Root's whole; the accounts' whole while they fit, then cut down to
    // their name and alerts while those fit, then left out and counted.
    for whole in [
        "etc/cron.d/big".to_string(),
        format!("{autostart}/a1"),
        format!("{autostart}/a3"),
    ] {
        let item = find(&whole).unwrap();
        assert!(matches!(item.body, Body::Text(_)), "{whole}");
        assert_eq!(item.runs.len(), 1, "{whole}");
    }
    // In keeping order, so the long names go whole, then cut, then not at
    // all.
    let shapes: Vec<&str> = std::iter::once(format!("{autostart}/a2"))
        .chain((0..100).map(long))
        .map(|path| match find(&path).map(|item| &item.body) {
            Some(Body::Text(_)) => "whole",
            Some(_) => {
                let item = find(&path).unwrap();
                assert_eq!(item.body, Body::Oversized);
                assert!(item.runs.is_empty());
                assert_eq!(item.notes.len(), 1);
                assert!(item.notes[0].starts_with("its content and notes were left out"));
                assert_eq!(item.alerts.len(), 1);
                assert_eq!(item.alerts[0].0, RuleId::GuardianOverride);
                assert_eq!(item.alerts[0].1, item.notes[0]);
                "cut"
            }
            None => "left out",
        })
        .collect();
    assert_eq!(shapes[0], "cut");
    let mut runs = shapes[1..].to_vec();
    runs.dedup();
    assert_eq!(runs, ["whole", "cut", "left out"]);
    let left_out = shapes.iter().filter(|shape| **shape == "left out").count();
    assert!(
        part.truncated.contains(&format!(
            "{left_out} item(s) accounts made were left out: root's results carry at most \
             2 MiB of those"
        )),
        "{:?}",
        part.truncated
    );
    assert!(find(&format!("etc/{}", "\u{1}".repeat(4000))).is_some());
    // What the accounts' items take stays within the bound: root's two
    // items are about 1.5 MiB and 24 KiB.
    assert!(json.len() < 4 * 1024 * 1024, "{}", json.len());
}

#[test]
fn a_program_root_runs_from_an_accounts_home_is_roots_whatever_the_account_floods() {
    let autostart = |index: usize| {
        // Names long enough that cut down they still pass the bound.
        let name = format!("home/u/.config/autostart/{}{index:03}", "a".repeat(4000));
        let mut file = live(&name, Category::Autostart);
        file.body = Body::Text("x".repeat(10 * 1024));
        file
    };
    let mut items: Vec<Item> = (0..600).map(autostart).collect();
    items.push(live("home/u/evil", Category::Process));
    let collection = Collection {
        items,
        ..Collection::default()
    };
    let live_roots = HashSet::from(["home/u/evil".to_string()]);
    let kept = super::in_keeping_order(&collection, &HashSet::new(), &live_roots);
    let part = from_json(&to_json(&collection, &kept, &[], None).to_string()).unwrap();
    assert_eq!(part.items[0].path, "home/u/evil");
    assert_eq!(part.items[0].body, Body::Text("x".into()));
    // The account's own were too many to carry.
    assert!(
        part.truncated
            .iter()
            .any(|sentence| sentence.contains("item(s) accounts made were left out")),
        "{:?}",
        part.truncated
    );
}

#[test]
fn what_the_users_live_checks_left_unread_for_their_limit_stays_unless_root_has_it() {
    let limit = || {
        let mut unread = item(
            "tmp/listener",
            Origin::System,
            Tier::Unknown,
            Body::Unreadable(crate::sweep::live::NOT_READ_PAST_LIMIT.into()),
        );
        unread.sha256 = None;
        unread
    };
    let root_only = item(
        "etc/x",
        Origin::System,
        Tier::Unknown,
        Body::Unreadable("permission denied".into()),
    );
    let merged = |part: super::RootPart| {
        let mut collection = Collection {
            items: vec![limit(), root_only.clone()],
            ..Collection::default()
        };
        merge(&mut collection, part);
        collection
            .items
            .iter()
            .map(|item| (item.path.clone(), matches!(item.body, Body::Unreadable(_))))
            .collect::<Vec<_>>()
    };
    // Root never saw it: it stays, unread; what only root can read goes.
    assert_eq!(
        merged(super::RootPart::default()),
        [("tmp/listener".to_string(), true)]
    );
    // Root has it: root's stands, whatever alerts the user's has.
    let read = item(
        "tmp/listener",
        Origin::Root,
        Tier::Unknown,
        Body::Text("x".into()),
    );
    for alerted in [false, true] {
        let mut collection = Collection {
            items: vec![limit()],
            ..Collection::default()
        };
        if alerted {
            collection.items[0]
                .alerts
                .push((RuleId::UnknownPrivilegedFile, "not read".into()));
        }
        merge(
            &mut collection,
            super::RootPart {
                items: vec![read.clone()],
                ..super::RootPart::default()
            },
        );
        let bodies: Vec<bool> = collection
            .items
            .iter()
            .map(|item| matches!(item.body, Body::Unreadable(_)))
            .collect();
        assert_eq!(bodies, [false], "alerted: {alerted}");
    }
}

#[test]
fn an_accounts_overrides_that_share_a_path_are_both_kept() {
    let path = "home/u/.config/systemd/user/omarchy-guardian-sweep.service.d/\\xff.conf";
    let override_of = |body| Item {
        category: Category::Systemd,
        run_by: None,
        ..item(path, Origin::Root, Tier::Unknown, body)
    };
    let read = override_of(Body::Text("ExecStart=\n".into()));
    let not_read = override_of(Body::Unreadable("its name is not UTF-8".into()));
    let key = "home/u/.ssh/authorized_keys#keys";
    let mut collection = Collection {
        items: vec![item(
            key,
            Origin::User,
            Tier::Unknown,
            Body::Text("k".into()),
        )],
        ..Collection::default()
    };
    super::add_accounts_items(
        &mut collection,
        vec![
            read,
            not_read,
            item(key, Origin::Root, Tier::Unknown, Body::Text("k".into())),
        ],
    );
    let at_path: Vec<&Body> = collection
        .items
        .iter()
        .filter(|item| item.path == path)
        .map(|item| &item.body)
        .collect();
    assert_eq!(at_path.len(), 2, "{:?}", collection.items);
    assert!(matches!(at_path[1], Body::Unreadable(_)));
    // A key file is merged into the one already there.
    assert_eq!(
        collection
            .items
            .iter()
            .filter(|item| item.path == key)
            .count(),
        1
    );
}

#[test]
fn an_accounts_overrides_that_share_a_path_both_reach_the_users_sweep() {
    let path = "home/u/.config/systemd/user/omarchy-guardian-sweep.service.d/\\xff.conf";
    let override_of = |body| Item {
        category: Category::Systemd,
        run_by: None,
        ..item(path, Origin::Root, Tier::Unknown, body)
    };
    let read = override_of(Body::Text("ExecStart=\n".into()));
    let not_read = Item {
        sha256: None,
        ..override_of(Body::Unreadable("its name is not UTF-8".into()))
    };
    let mut collection = Collection::default();
    super::add_accounts_items(&mut collection, vec![read.clone(), not_read]);
    let at_path = |collection: &Collection| -> Vec<Body> {
        collection
            .items
            .iter()
            .filter(|item| item.path == path)
            .map(|item| item.body.clone())
            .collect()
    };
    let results = to_json(
        &collection,
        &super::in_keeping_order(&collection, &HashSet::new(), &HashSet::new()),
        &[],
        None,
    )
    .to_string();
    let expected = [
        Body::Text("ExecStart=\n".into()),
        Body::Unreadable("its name is not UTF-8".into()),
    ];
    // A sweep that did not see them itself gets both.
    let mut users = Collection::default();
    merge(&mut users, from_json(&results).unwrap());
    assert_eq!(at_path(&users), expected, "{:?}", users.items);
    // One that read the same file itself keeps its own, which says the
    // same as root's and gains its notes, and the one it did not see.
    let mut users = Collection {
        items: vec![Item {
            origin: Origin::User,
            notes: Vec::new(),
            ..read.clone()
        }],
        ..Collection::default()
    };
    merge(&mut users, from_json(&results).unwrap());
    assert_eq!(at_path(&users), expected, "{:?}", users.items);
    assert_eq!(users.items[0].origin, Origin::User);
    assert_eq!(users.items[0].notes, read.notes);
    // One that read other content there keeps both readings.
    let mut users = Collection {
        items: vec![Item {
            origin: Origin::User,
            sha256: Some(Sha256::digest(b"other")),
            ..override_of(Body::Text("other\n".into()))
        }],
        ..Collection::default()
    };
    merge(&mut users, from_json(&results).unwrap());
    assert_eq!(at_path(&users).len(), 3, "{:?}", users.items);
}

#[test]
fn only_an_accounts_overrides_are_kept_beside_another_reading() {
    let reading = |path: &str, category, origin, text: &str| Item {
        category,
        run_by: None,
        sha256: Some(Sha256::digest(text.as_bytes())),
        ..item(path, origin, Tier::Unknown, Body::Text(text.into()))
    };
    let system = "etc/systemd/user/omarchy-guardian-sweep.service";
    let key = "home/u/.ssh/authorized_keys#keys";
    let unit = "home/u/.config/systemd/user/omarchy-guardian-sweep.service";
    // A file in a home that a system unit runs is no override.
    let reached = "home/u/bin/tool";
    let run = |item: Item| Item {
        run_by: Some("etc/systemd/system/x.service".into()),
        ..item
    };
    let mut users = Collection {
        items: vec![
            reading(system, Category::Systemd, Origin::User, "a"),
            reading(key, Category::Account, Origin::User, "a"),
            reading(unit, Category::Systemd, Origin::User, "a"),
            run(reading(reached, Category::Systemd, Origin::User, "a")),
        ],
        ..Collection::default()
    };
    let roots = Collection {
        items: vec![
            reading(system, Category::Systemd, Origin::Root, "b"),
            reading(key, Category::Account, Origin::Root, "b"),
            reading(unit, Category::Systemd, Origin::Root, "b"),
            run(reading(reached, Category::Systemd, Origin::Root, "b")),
        ],
        ..Collection::default()
    };
    merge(
        &mut users,
        from_json(
            &to_json(
                &roots,
                &super::in_keeping_order(&roots, &HashSet::new(), &HashSet::new()),
                &[],
                None,
            )
            .to_string(),
        )
        .unwrap(),
    );
    let count = |path: &str| users.items.iter().filter(|item| item.path == path).count();
    // Root's view of the system, of an account's keys and of a file a unit
    // runs folds into the user's, which is newer; an override in a home is
    // kept beside it.
    assert_eq!(
        [count(system), count(key), count(unit), count(reached)],
        [1, 1, 2, 1],
        "{:?}",
        users.items
    );
    // The hash tells two readings apart where the body does not, and the
    // same reading at another path is another item.
    let oversized = |text: &str| Item {
        body: Body::Oversized,
        ..reading(unit, Category::Systemd, Origin::Root, text)
    };
    let elsewhere = Item {
        path: "home/u/.config/systemd/user/omarchy-guardian-sweep.timer".into(),
        ..oversized("c")
    };
    let mut collection = Collection {
        items: vec![oversized("a"), elsewhere],
        ..Collection::default()
    };
    super::add_overrides(
        &mut collection,
        vec![oversized("b"), oversized("a"), oversized("c")],
    );
    assert_eq!(collection.items.len(), 4, "{:?}", collection.items);
    // The body tells two readings apart where no hash does (neither read).
    let not_read = |why: &str| Item {
        sha256: None,
        body: Body::Unreadable(why.into()),
        ..reading(unit, Category::Systemd, Origin::Root, "")
    };
    let mut collection = Collection {
        items: vec![not_read("a")],
        ..Collection::default()
    };
    super::add_overrides(&mut collection, vec![not_read("b"), not_read("a")]);
    assert_eq!(collection.items.len(), 2, "{:?}", collection.items);
}

#[test]
fn what_an_account_keeps_in_its_runtime_directory_leaves_roots_in() {
    let drop_in = |index: usize| {
        format!("run/user/1000/systemd/user/omarchy-guardian-sweep.service.d/{index:06}.conf")
    };
    let mut items: Vec<Item> = (0..super::MAX_ITEMS + 10)
        .map(|index| Item {
            category: Category::Systemd,
            run_by: None,
            ..item(
                &drop_in(index),
                Origin::Root,
                Tier::Unknown,
                Body::Text("x".into()),
            )
        })
        .collect();
    // Root's own runtime directory is root's, and sorts after the
    // account's.
    let roots_runtime = "run/user/0/systemd/user/omarchy-guardian-sweep.service";
    for path in [roots_runtime, "var/spool/cron/root"] {
        items.push(Item {
            run_by: None,
            ..item(path, Origin::Root, Tier::Unknown, Body::Text("x".into()))
        });
    }
    let collection = Collection {
        items,
        ..Collection::default()
    };
    let part = from_json(
        &to_json(
            &collection,
            &super::in_keeping_order(&collection, &HashSet::new(), &HashSet::new()),
            &[],
            None,
        )
        .to_string(),
    )
    .unwrap();
    assert_eq!(part.items.len(), super::MAX_ITEMS);
    let kept: Vec<&str> = part.items.iter().map(|item| item.path.as_str()).collect();
    assert_eq!(kept[..2], [roots_runtime, "var/spool/cron/root"]);
    assert!(
        kept[2..]
            .iter()
            .all(|path| path.starts_with("run/user/1000/"))
    );
}
