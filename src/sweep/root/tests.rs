//! Tests of the root part of the sweep.

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
    let index = crate::sweep::index::PackageIndex::with_foreign(std::collections::HashSet::new());
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
    assert_eq!(items[0].alerts[0].0, crate::rules::RuleId::GuardianOverride);
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
        notes: Vec::new(),
        root_news: None,
    };
    let mut collection = collection;
    // The drop-in is in the catalog itself: its content travels.
    collection.items[0].run_by = None;
    collection.items[1]
        .alerts
        .push((crate::rules::RuleId::HiddenProgram, "seen".into()));
    let noted = vec!["the kernel is tainted (flags 4096)".to_string()];
    let part = from_json(&to_json(&collection, &noted, None).to_string()).unwrap();
    assert_eq!(part.notes, noted);
    assert_eq!(part.items, collection.items[..2]);
    assert_eq!(part.truncated, ["/etc/x"]);
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
    fact.alerts.push((
        crate::rules::RuleId::PrivilegedAccount,
        "toor has user id 0".into(),
    ));
    let collection = Collection {
        items: vec![fact],
        ..Collection::default()
    };
    let part = from_json(&to_json(&collection, &[], None).to_string()).unwrap();
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
    assert!(from_json(r#"{"version":3,"items":[]}"#).is_err());
    assert!(from_json(r#"{"items":[]}"#).is_err());
    // An older collector's results are read, and known as that.
    assert!(from_json(r#"{"version":1,"items":[]}"#).unwrap().outdated);
    let current = from_json(r#"{"version":2,"items":[],"new_trust":["etc/passwd#x"]}"#).unwrap();
    assert!(!current.outdated);
    assert_eq!(current.news, Some(vec!["etc/passwd#x".to_string()]));
    assert_eq!(from_json(r#"{"version":2,"items":[]}"#).unwrap().news, None);
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
    let index = crate::sweep::index::PackageIndex::with_foreign(std::collections::HashSet::new());
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
    memory
        .alerts
        .push((crate::rules::RuleId::HiddenProgram, "seen".into()));
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
    let part = from_json(&to_json(&collection, &[], None).to_string()).unwrap();
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
    let (_, seen) = super::news(&collection.items, None, 1);
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
    let (new, seen) = super::news(&[key("a", "one"), unit.clone()], None, 1000);
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
        let (new, seen) = super::news(items, Some(seen), now);
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
    let part = from_json(&to_json(&collection, &[], Some(&new)).to_string()).unwrap();
    assert_eq!(part.news, Some(new));
    // Without a record the results carry none, and the reader's own
    // memory stands in.
    let untracked = from_json(&to_json(&collection, &[], None).to_string()).unwrap();
    assert_eq!(untracked.news, None);
    let mut merged = Collection::default();
    merge(&mut merged, part);
    assert_eq!(
        merged.root_news,
        Some(vec!["root/.ssh/authorized_keys#b".to_string()])
    );
}
