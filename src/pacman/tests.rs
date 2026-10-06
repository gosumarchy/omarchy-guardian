//! Tests for the pacman gate.

use std::fs;
use std::path::Path;
use std::process::Command;

use super::{
    Archives, Operation, is_valid_package_name, local_archives, missing_targets, parse_sync_info,
    parse_transaction, read_targets, scan_package, split_cmdline,
};
use crate::agent::{AgentReview, Status};
use crate::config::Settings;
use crate::config::file::PartialConfig;
use crate::config::model::SourceClass;
use crate::report::{AgentOutcome, AgentRun, Blocked, Decision, Report};
use crate::review::analyze_text;
use crate::rules::RuleId;
use crate::test_support::{TempDir, tool_available};

fn argv(line: &str) -> Vec<String> {
    line.split_whitespace().map(str::to_string).collect()
}

#[test]
fn only_sync_and_upgrade_operations_are_accepted() {
    for (line, expected) in [
        ("/usr/bin/pacman -Syu", Operation::Sync),
        ("pacman -yuS foo", Operation::Sync),
        ("pacman --sync foo", Operation::Sync),
        ("pacman -U /tmp/a.pkg.tar.zst", Operation::LocalUpgrade),
        ("pacman --upgrade a.pkg.tar.zst", Operation::LocalUpgrade),
        (
            "/bin/sh /e2e/bin/pacman -U a.pkg.tar.zst",
            Operation::LocalUpgrade,
        ),
    ] {
        assert_eq!(
            parse_transaction(&argv(line)).unwrap().operation,
            expected,
            "{line}"
        );
    }
    for line in ["pacman -Rns foo", "pacman -Qs foo", "pacman -- -S"] {
        assert!(parse_transaction(&argv(line)).is_err(), "{line}");
    }
}

#[test]
fn every_operand_of_an_upgrade_is_an_archive() {
    let operands = |line: &str| parse_transaction(&argv(line)).unwrap().operands;
    // Even one named like the program.
    assert_eq!(
        operands("pacman ./pacman -U good.pkg.tar.zst"),
        ["./pacman", "good.pkg.tar.zst"]
    );
    // Whatever it is named, and wherever it stands.
    assert_eq!(
        operands("pacman -U good-1-1-any.pkg.tar.zst evil.pkg.tar.lz4 thing.bin"),
        ["good-1-1-any.pkg.tar.zst", "evil.pkg.tar.lz4", "thing.bin"]
    );
    assert_eq!(
        operands("pacman first.bin -U --noconfirm last"),
        ["first.bin", "last"]
    );
    assert_eq!(
        operands("/bin/sh /e2e/bin/pacman -U a.pkg.tar.zst"),
        ["a.pkg.tar.zst"]
    );
    assert_eq!(
        operands("pacman -U -- -odd.pkg.tar.zst --needed"),
        ["-odd.pkg.tar.zst", "--needed"]
    );
    // An option's value is not an operand.
    assert_eq!(
        operands("pacman -U --overwrite /usr/* --ignore foo --color=never a.pkg.tar.zst --print x"),
        ["a.pkg.tar.zst", "x"]
    );
    assert_eq!(operands("pacman -U --ign foo --assume bar=1 a"), ["a"]);
}

#[test]
fn a_transaction_against_another_system_is_refused() {
    for line in [
        "pacman -U --root /mnt a.pkg.tar.zst",
        "pacman -U --root=/mnt a.pkg.tar.zst",
        "pacman -S --dbpath /tmp/db foo",
        "pacman -S --config /tmp/pacman.conf foo",
        "pacman -S --conf=/tmp/pacman.conf foo",
        "pacman -S --cachedir /tmp/cache foo",
        "pacman -S --sysroot /mnt foo",
        "pacman -S --hookdir /tmp/hooks foo",
        "pacman -S --gpgdir /tmp/gpg foo",
        "pacman -Sr /mnt foo",
        "pacman -r/mnt -U a.pkg.tar.zst",
        "pacman -Ub /tmp/db a.pkg.tar.zst",
    ] {
        let error = parse_transaction(&argv(line)).unwrap_err().to_string();
        assert!(error.contains("another system"), "{line}: {error}");
    }
    // After `--` they are operands, not options.
    assert!(parse_transaction(&argv("pacman -S -- --root")).is_ok());
    // yay names the default configuration on every call.
    for line in [
        "pacman -S -y -u --config /etc/pacman.conf --",
        "pacman -U --config=/etc/pacman.conf -- /tmp/a.pkg.tar.zst",
        "pacman -U --conf /etc/pacman.conf a.pkg.tar.zst",
    ] {
        assert!(parse_transaction(&argv(line)).is_ok(), "{line}");
    }
    assert_eq!(
        parse_transaction(&argv("pacman -U --config /etc/pacman.conf -- a b"))
            .unwrap()
            .operands,
        ["a", "b"]
    );
    assert!(parse_transaction(&argv("pacman -S --config")).is_err());
}

#[test]
fn upgrade_dependencies_are_the_targets_without_a_local_archive() {
    let mut archives = Archives::new();
    archives.insert("built".into(), Ok(vec!["built-1-1-any.pkg.tar".into()]));
    let targets = ["built".to_string(), "repo-dependency".to_string()];
    assert_eq!(missing_targets(&targets, &archives), ["repo-dependency"]);
}

#[test]
fn preflight_needs_a_system_opencode_only_when_a_class_requires_ai() {
    use super::{classes_requiring_ai, preflight};
    use crate::config::model::Profile;

    let standard = Settings::from_parts(PartialConfig::default(), PartialConfig::default());
    assert_eq!(
        classes_requiring_ai(&standard),
        [SourceClass::ThirdPartyRepo, SourceClass::LocalPackage]
    );
    let error = preflight(&standard, false).unwrap_err();
    assert!(error.contains("third-party-repo, local-package"), "{error}");
    assert!(error.contains("sudo pacman -S extra/opencode"), "{error}");
    assert_eq!(preflight(&standard, true), Ok(()));

    let private = Settings::from_parts(
        PartialConfig {
            profile: Some(Profile::LocalOnly),
            ..PartialConfig::default()
        },
        PartialConfig::default(),
    );
    assert_eq!(preflight(&private, false), Ok(()));
}

#[test]
fn cmdline_keeps_arguments_with_spaces() {
    assert_eq!(
        split_cmdline(b"pacman\0-U\0/tmp/with space.pkg.tar.zst\0").unwrap(),
        ["pacman", "-U", "/tmp/with space.pkg.tar.zst"]
    );
    assert!(split_cmdline(b"pacman\0\xff\0").is_err());
}

#[test]
fn targets_must_be_package_names() {
    assert_eq!(
        read_targets(&b"linux\n\nlib32-glibc\n"[..]).unwrap(),
        ["linux", "lib32-glibc"]
    );
    assert!(read_targets(&b"\n"[..]).is_err());
    assert!(read_targets(&b"../etc\n"[..]).is_err());
    assert!(is_valid_package_name("gtk2+extra"));
    assert!(is_valid_package_name("@scope"));
    assert!(!is_valid_package_name("-rf"));
    assert!(!is_valid_package_name(".hidden"));
}

#[test]
fn parses_sync_database_versions() {
    let output = "Repository      : core\nName            : linux\nVersion         : 6.10.1.arch1-1\nDescription     : The Linux kernel: and modules\nArchitecture    : x86_64\n\nRepository      : chaotic-aur\nName            : ttf-font\nVersion         : 2:1.0-3\nArchitecture    : any\n";
    let versions = parse_sync_info(output);
    assert_eq!(versions["linux"][0].version, "6.10.1.arch1-1");
    assert_eq!(versions["linux"][0].version_arch, "6.10.1.arch1-1-x86_64");
    assert_eq!(versions["linux"][0].repo, "core");
    assert_eq!(versions["ttf-font"][0].version_arch, "2:1.0-3-any");
    assert_eq!(versions["ttf-font"][0].repo, "chaotic-aur");
}

#[test]
fn the_archive_is_the_one_pacman_names() {
    let output = "core\u{1f}foo\u{1f}1-2\u{1f}foo-1-2-any.pkg.tar.zst\nextra\u{1f}bar\u{1f}2:1.0-3\u{1f}odd name\u{1f}x.pkg\nevil\u{1f}a\u{1f}1-1\u{1f}../../etc/x\nevil\u{1f}b\u{1f}1-1\u{1f}.hidden\nevil\u{1f}c\u{1f}1-1\u{1f}\nshort\u{1f}line\n";
    let filenames = super::parse_filenames(output);
    let key = |repo: &str, name: &str, version: &str| {
        (repo.to_string(), name.to_string(), version.to_string())
    };
    assert_eq!(filenames.len(), 2);
    assert_eq!(
        filenames[&key("core", "foo", "1-2")],
        "foo-1-2-any.pkg.tar.zst"
    );
    assert_eq!(
        filenames[&key("extra", "bar", "2:1.0-3")],
        "odd name\u{1f}x.pkg"
    );

    // Against this system's own databases, when there are any.
    let Ok(candidates) = super::sync_versions(&["pacman".to_string()]) else {
        return;
    };
    let Some(candidate) = candidates.get("pacman").and_then(|found| found.first()) else {
        return;
    };
    let filenames = super::sync_filenames(&candidates).unwrap();
    let name = &filenames[&key(&candidate.repo, "pacman", &candidate.version)];
    assert!(
        name.starts_with(&format!("pacman-{}", candidate.version_arch)),
        "{name}"
    );
}

fn clear_run(files: &[&str]) -> AgentRun {
    AgentRun {
        files: files.iter().map(ToString::to_string).collect(),
        label: "m · low".into(),
        chunk: None,
        cached: None,
        outcome: AgentOutcome::Reviewed(AgentReview {
            status: Status::Clear,
            summary: "ok".into(),
            findings: Vec::new(),
        }),
    }
}

#[test]
fn mixed_transaction_uses_each_targets_policy() {
    let settings = Settings::from_parts(PartialConfig::default(), PartialConfig::default());
    let policy = |class| settings.policy(class);

    let mut report = Report::new("pacman transaction");
    report.class = SourceClass::ThirdPartyRepo;
    report
        .file_classes
        .insert("core-pkg/a/.INSTALL".into(), SourceClass::Official);
    report
        .file_classes
        .insert("chaotic-pkg/b/.INSTALL".into(), SourceClass::ThirdPartyRepo);
    analyze_text(
        &mut report,
        "core-pkg/a/.INSTALL",
        "post_install() { setcap cap_net_raw+ep /usr/bin/x; }\n",
        false,
    );
    analyze_text(
        &mut report,
        "chaotic-pkg/b/.INSTALL",
        "post_install() { true; }\n",
        false,
    );
    report.agent_runs.push(clear_run(&[
        "core-pkg/a/.INSTALL",
        "chaotic-pkg/b/.INSTALL",
    ]));
    assert_eq!(report.decide(&policy), Decision::Warned);

    let mut flagged = Report::new("pacman transaction");
    flagged.class = SourceClass::ThirdPartyRepo;
    flagged
        .file_classes
        .insert("core-pkg/a/.INSTALL".into(), SourceClass::Official);
    flagged
        .file_classes
        .insert("chaotic-pkg/b/.INSTALL".into(), SourceClass::ThirdPartyRepo);
    analyze_text(
        &mut flagged,
        "core-pkg/a/.INSTALL",
        "post_install() { true; }\n",
        false,
    );
    analyze_text(
        &mut flagged,
        "chaotic-pkg/b/.INSTALL",
        "post_install() { setcap cap_net_raw+ep /usr/bin/x; }\n",
        false,
    );
    flagged.agent_runs.push(clear_run(&[
        "core-pkg/a/.INSTALL",
        "chaotic-pkg/b/.INSTALL",
    ]));
    assert_eq!(
        flagged.decide(&policy),
        Decision::Blocked(Blocked::Findings)
    );
}

#[test]
fn remote_and_missing_archives_are_refused() {
    let dir = TempDir::new("pacman-missing");
    let refused = |operands: &str| local_archives(&argv(operands), dir.path()).is_err();
    assert!(refused("https://x.test/a-1-1-any.pkg.tar.zst"));
    // Whatever follows the name: pacman downloads it all the same.
    assert!(refused("https://x.test/a-1-1-any.pkg.tar.zst?x=1"));
    assert!(refused("missing-1-1-any.pkg.tar.zst"));
    assert!(refused(""));
}

fn build_package(dir: &Path, install: Option<&str>) -> std::path::PathBuf {
    fs::write(
        dir.join(".PKGINFO"),
        "pkgname = sample\npkgbase = sample\npkgver = 1.0-1\narch = any\n",
    )
    .unwrap();
    let mut members = vec![".PKGINFO"];
    if let Some(script) = install {
        fs::write(dir.join(".INSTALL"), script).unwrap();
        members.push(".INSTALL");
    }
    let archive = dir.join("sample-1.0-1-any.pkg.tar");
    let status = Command::new("/usr/bin/bsdtar")
        .arg("-cf")
        .arg(&archive)
        .args(&members)
        .current_dir(dir)
        .status()
        .unwrap();
    assert!(status.success());
    archive
}

#[test]
fn relative_upgrade_archives_resolve_against_pacmans_directory() {
    if !tool_available("/usr/bin/bsdtar") || !tool_available("/usr/bin/pacman") {
        return;
    }
    let dir = TempDir::new("pacman-relative");
    let archive = build_package(dir.path(), None);

    let archives = local_archives(&argv("sample-1.0-1-any.pkg.tar"), dir.path()).unwrap();
    assert_eq!(archives["sample"], Ok(vec![archive.clone()]));

    // A package is what the file holds, not what it is called: an
    // archive under another name is found, never skipped.
    let renamed = dir.path().join("thing.bin");
    fs::rename(&archive, &renamed).unwrap();
    let archives = local_archives(&argv("thing.bin"), dir.path()).unwrap();
    assert_eq!(archives["sample"], Ok(vec![renamed]));
    fs::write(dir.path().join("notes.txt"), "not a package\n").unwrap();
    assert!(local_archives(&argv("thing.bin notes.txt"), dir.path()).is_err());
}

#[test]
fn archives_others_can_swap_are_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new("pacman-private");
    let shared = dir.path().join("shared");
    fs::create_dir(&shared).unwrap();
    fs::write(shared.join("x.pkg.tar.zst"), "x").unwrap();
    let uid = std::os::unix::fs::MetadataExt::uid(&fs::metadata(dir.path()).unwrap());
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(super::check_private(&shared.join("x.pkg.tar.zst"), Some(uid)).is_ok());
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(super::check_private(&shared.join("x.pkg.tar.zst"), Some(uid)).is_err());
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777)).unwrap();
    assert!(super::check_private(&shared.join("x.pkg.tar.zst"), Some(uid)).is_ok());
    // Owned by someone else (root's files are trusted, so not as root).
    if uid != 0 {
        assert!(super::check_private(&shared.join("x.pkg.tar.zst"), Some(uid + 1)).is_err());
    }
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn a_file_installed_setuid_root_is_a_finding() {
    use std::os::unix::fs::PermissionsExt;
    if !tool_available("/usr/bin/bsdtar") {
        return;
    }
    let dir = TempDir::new("pacman-setuid");
    let root = dir.path().join("root");
    fs::create_dir_all(root.join("usr/bin")).unwrap();
    fs::create_dir_all(root.join("opt/app")).unwrap();
    fs::create_dir_all(root.join("opt/fake")).unwrap();
    // What a Chromium-based program keeps beside its helper.
    fs::write(root.join("opt/app/icudtl.dat"), "x").unwrap();
    fs::write(root.join("opt/app/resources.pak"), "x").unwrap();
    fs::write(root.join(".PKGINFO"), "pkgname = sample\n").unwrap();
    // A new setuid program, one that is already installed that way,
    // and the helper Chromium-based programs need.
    for path in [
        "usr/bin/guardian-test-shell",
        "usr/bin/chrome-sandbox",
        "opt/fake/chrome-sandbox",
        "usr/bin/su",
        "opt/app/chrome-sandbox",
    ] {
        fs::write(root.join(path), b"\x7fELF\x02\x01\x01\0").unwrap();
        fs::set_permissions(root.join(path), fs::Permissions::from_mode(0o4755)).unwrap();
    }
    let archive = dir.path().join("sample-1-1-any.pkg.tar");
    let status = Command::new("/usr/bin/bsdtar")
        .args(["--uid", "0", "--gid", "0", "-cf"])
        .arg(&archive)
        .args([".PKGINFO", "usr", "opt"])
        .current_dir(&root)
        .status()
        .unwrap();
    assert!(status.success());

    let mut report = Report::new("test");
    scan_package(
        &archive,
        "sample",
        SourceClass::LocalPackage,
        &[],
        &|_| crate::payload::InArchive::Absent,
        &super::InstalledLinks::new(),
        &mut report,
    )
    .unwrap();
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.rule == RuleId::PrivilegeEscalation)
    );
    let mut found: Vec<&str> = report
        .findings
        .iter()
        .filter_map(|finding| finding.excerpt.split(' ').next())
        .collect();
    found.sort_unstable();
    // The helper beside its program's runtime is the only one let
    // through; `su` counts as installed where this system has it setuid.
    let su_installed = fs::metadata("/usr/bin/su")
        .is_ok_and(|metadata| metadata.permissions().mode() & 0o4000 != 0);
    let mut expected = vec![
        "/opt/fake/chrome-sandbox",
        "/usr/bin/chrome-sandbox",
        "/usr/bin/guardian-test-shell",
    ];
    if !su_installed {
        expected.push("/usr/bin/su");
    }
    assert_eq!(found, expected);
    assert!(
        report.findings[0]
            .excerpt
            .ends_with("is installed setuid root: it runs as root for whoever starts it")
    );
    assert_eq!(
        report.class_of("sample/sample-1-1-any.pkg.tar/usr/bin/guardian-test-shell"),
        SourceClass::LocalPackage
    );
}

#[test]
fn a_link_to_a_file_the_package_does_not_ship_is_reviewed_as_that_file() {
    if !tool_available("/usr/bin/bsdtar") {
        return;
    }
    let dir = TempDir::new("pacman-outside-link");
    let root = dir.path().join("root");
    fs::create_dir_all(root.join("etc/sudoers.d")).unwrap();
    fs::write(root.join(".PKGINFO"), "pkgname = sample\n").unwrap();
    // One to a file another package of the transaction ships, one to a
    // file root keeps on every system, one to nothing at all.
    for (name, target) in [
        ("shipped", "/usr/lib/other/rule"),
        ("system", "/etc/passwd"),
        ("missing", "/usr/lib/guardian-test-nowhere/rule"),
        ("masked", "/dev/null"),
        ("shared", "/dev/shm/guardian-test"),
    ] {
        std::os::unix::fs::symlink(target, root.join("etc/sudoers.d").join(name)).unwrap();
    }
    let archive = dir.path().join("sample-1-1-any.pkg.tar");
    let status = Command::new("/usr/bin/bsdtar")
        .args(["--uid", "0", "--gid", "0", "-cf"])
        .arg(&archive)
        .args([".PKGINFO", "etc"])
        .current_dir(&root)
        .status()
        .unwrap();
    assert!(status.success());

    let others = |path: &str| {
        if path == "usr/lib/other/rule" {
            crate::payload::InArchive::File(b"ALL ALL=(ALL) NOPASSWD: ALL\n".to_vec())
        } else {
            crate::payload::InArchive::Absent
        }
    };
    let mut report = Report::new("test");
    scan_package(
        &archive,
        "sample",
        SourceClass::LocalPackage,
        &[],
        &others,
        &super::InstalledLinks::new(),
        &mut report,
    )
    .unwrap();
    let sent = |name: &str| {
        report
            .agent_input
            .iter()
            .find(|file| file.path.ends_with(&format!("etc/sudoers.d/{name}")))
            .map(|file| file.content.clone())
    };
    assert!(
        sent("shipped").is_some_and(|text| text.contains("NOPASSWD")
            && text.contains("another package of this transaction")),
        "{:?}",
        sent("shipped")
    );
    if fs::metadata("/etc/passwd")
        .is_ok_and(|metadata| std::os::unix::fs::MetadataExt::uid(&metadata) == 0)
    {
        assert!(
            sent("system").is_some_and(|text| text.contains("on this system now")),
            "{:?}",
            sent("system")
        );
    }
    assert!(sent("missing").is_none());
    // A link to /dev/null masks; it is said, not a gap.
    assert!(sent("masked").is_some_and(|text| text.contains("does not ship")));
    // What anyone may write under /dev is no device: a gap.
    assert!(sent("shared").is_none());
    assert_eq!(report.gaps.len(), 2, "{:?}", report.gaps);
    assert!(
        report.gaps.iter().any(|gap| gap
            .to_string()
            .contains("/etc/sudoers.d/missing links to /usr/lib/guardian-test-nowhere/rule")),
        "{:?}",
        report.gaps
    );
}

#[test]
fn a_file_another_archive_ships_is_found_whichever_archive_comes_first() {
    if !tool_available("/usr/bin/bsdtar") {
        return;
    }
    let dir = TempDir::new("pacman-shipped");
    let pack = |name: &str, files: &[(&str, &str)]| {
        let root = dir.path().join(name);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(".PKGINFO"), format!("pkgname = {name}\n")).unwrap();
        let mut members = vec![".PKGINFO".to_string()];
        for (path, text) in files {
            fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
            fs::write(root.join(path), text).unwrap();
            members.push((*path).to_string());
        }
        let archive = dir.path().join(format!("{name}-1-1-any.pkg.tar"));
        let status = Command::new("/usr/bin/bsdtar")
            .args(["--uid", "0", "--gid", "0", "-cf"])
            .arg(&archive)
            .args(&members)
            .current_dir(&root)
            .status()
            .unwrap();
        assert!(status.success());
        archive
    };
    let asking = pack("a", &[("etc/a.conf", "x\n")]);
    let other = pack("b", &[("usr/lib/b/data", "y\n")]);
    let shipping = pack("c", &[("usr/lib/other/rule", "ALL ALL=(ALL) ALL\n")]);
    let archives = [asking.clone(), other, shipping];
    let shipped = super::Shipped {
        archives: &archives,
        index: std::cell::RefCell::new(None),
    };
    assert_eq!(
        shipped.lookup(&asking, "usr/lib/other/rule"),
        crate::payload::InArchive::File(b"ALL ALL=(ALL) ALL\n".to_vec())
    );
    assert_eq!(
        shipped.lookup(&asking, "usr/lib/nowhere"),
        crate::payload::InArchive::Absent
    );
    // An archive asks no question of itself.
    assert_eq!(
        shipped.lookup(&asking, "etc/a.conf"),
        crate::payload::InArchive::Absent
    );
    // One that cannot be read may be the one that ships it.
    let broken = [asking.clone(), dir.path().join("missing-1-1-any.pkg.tar")];
    let shipped = super::Shipped {
        archives: &broken,
        index: std::cell::RefCell::new(None),
    };
    assert_eq!(
        shipped.lookup(&asking, "usr/lib/other/rule"),
        crate::payload::InArchive::Other
    );
}

#[test]
fn a_link_chain_ends_at_what_the_transaction_puts_there() {
    use crate::payload::InArchive;
    // `/etc/localtime` is root's link into the zone database: when the
    // transaction replaces that file, its new content is what the
    // chain leads to.
    let Ok(target) = fs::read_link("/etc/localtime") else {
        return;
    };
    let Some(target) = target.to_str().and_then(|target| target.strip_prefix('/')) else {
        return;
    };
    let target = target.to_string();
    let others = |path: &str| {
        if path == target {
            InArchive::File(b"TZif-new".to_vec())
        } else {
            InArchive::Absent
        }
    };
    assert_eq!(
        super::linked_file(Path::new("/"), "/etc/localtime", &others),
        Ok(Some((
            "another package of this transaction ships it",
            b"TZif-new".to_vec()
        )))
    );
    // An unchanged link to it counts as changed, and one to a file the
    // transaction leaves alone does not.
    assert!(super::replaced_by_transaction(
        &format!("/{target}"),
        &others
    ));
    assert!(!super::replaced_by_transaction("/etc/hostname", &others));
}

#[test]
fn install_scripts_are_reviewed_through_the_archive_model() {
    if !tool_available("/usr/bin/bsdtar") {
        return;
    }
    let dir = TempDir::new("pacman-install");
    let archive = build_package(dir.path(), Some("post_install() { rm -rf /; }\n"));

    let mut report = Report::new("test");
    let (scriptlet, _, _) = scan_package(
        &archive,
        "sample",
        SourceClass::LocalPackage,
        &[],
        &|_| crate::payload::InArchive::Absent,
        &super::InstalledLinks::new(),
        &mut report,
    )
    .unwrap();
    assert!(scriptlet);
    assert_eq!(
        report.class_of("sample/sample-1.0-1-any.pkg.tar/.INSTALL"),
        SourceClass::LocalPackage
    );
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].rule, RuleId::DestructiveSystemOperation);
    assert_eq!(
        report.agent_input[0].content,
        "post_install() { rm -rf /; }\n"
    );
    assert!(!dir.path().join("sample").exists());

    // A Latin-1 byte no longer refuses a scriptlet: it is reviewed.
    let latin = TempDir::new("pacman-latin1");
    fs::write(
        latin.path().join(".INSTALL"),
        b"# caf\xe9\npost_install() { true; }\n",
    )
    .unwrap();
    let archive = build_package(latin.path(), None);
    let status = Command::new("/usr/bin/bsdtar")
        .arg("-rf")
        .arg(&archive)
        .arg(".INSTALL")
        .current_dir(latin.path())
        .status()
        .unwrap();
    assert!(status.success());
    let mut report = Report::new("test");
    assert!(
        scan_package(
            &archive,
            "sample",
            SourceClass::LocalPackage,
            &[],
            &|_| crate::payload::InArchive::Absent,
            &super::InstalledLinks::new(),
            &mut report
        )
        .unwrap()
        .0
    );

    let plain_dir = TempDir::new("pacman-plain");
    let plain = build_package(plain_dir.path(), None);
    assert!(
        !scan_package(
            &plain,
            "sample",
            SourceClass::LocalPackage,
            &[],
            &|_| crate::payload::InArchive::Absent,
            &super::InstalledLinks::new(),
            &mut Report::default()
        )
        .unwrap()
        .0
    );
}

/// A package archive `name`, owned by root, holding `files`.
fn pack(dir: &Path, name: &str, files: &[(&str, &[u8])]) -> std::path::PathBuf {
    let root = dir.join(format!("{name}-root"));
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join(".PKGINFO"), format!("pkgname = {name}\n")).unwrap();
    let mut members = vec![".PKGINFO".to_string()];
    for (path, bytes) in files {
        fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
        fs::write(root.join(path), bytes).unwrap();
        let top = path.split('/').next().unwrap().to_string();
        if !members.contains(&top) {
            members.push(top);
        }
    }
    let archive = dir.join(format!("{name}-1-1-any.pkg.tar"));
    let status = Command::new("/usr/bin/bsdtar")
        .args(["--uid", "0", "--gid", "0", "-cf"])
        .arg(&archive)
        .args(&members)
        .current_dir(&root)
        .status()
        .unwrap();
    assert!(status.success());
    archive
}

const ELF: &[u8] = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0\x03\0\x3e\0";

#[test]
fn links_in_auto_run_locations_are_found_by_where_they_lead() {
    use std::os::unix::fs::symlink;
    let dir = TempDir::new("pacman-links");
    let root = dir.path().join("root");
    for directory in [
        "etc/cron.d",
        "usr/share/b",
        "usr/lib/systemd/system/multi-user.target.wants",
        "etc/systemd/system",
    ] {
        fs::create_dir_all(root.join(directory)).unwrap();
    }
    fs::write(root.join("usr/share/b/rule"), "x\n").unwrap();
    fs::write(root.join("usr/lib/systemd/system/x.service"), "[Service]\n").unwrap();
    fs::write(root.join("etc/cron.d/plain"), "x\n").unwrap();
    // To a file that is there, by an absolute and a relative text; to
    // one that is not there yet, also through `/lib`; a unit a package
    // enables and one the administrator did.
    symlink("/usr/share/b/rule", root.join("etc/cron.d/a")).unwrap();
    symlink("../../usr/share/b/rule", root.join("etc/cron.d/again")).unwrap();
    symlink("../../usr/share/b/new", root.join("etc/cron.d/new")).unwrap();
    symlink("/lib/pkg/job", root.join("etc/cron.d/lib")).unwrap();
    symlink(
        "../x.service",
        root.join("usr/lib/systemd/system/multi-user.target.wants/x.service"),
    )
    .unwrap();
    symlink(
        "/usr/lib/systemd/system/x.service",
        root.join("etc/systemd/system/x.service"),
    )
    .unwrap();
    // Outside every auto-run location: not looked at.
    symlink("/usr/share/b/rule", root.join("usr/share/b/alias")).unwrap();

    let super::Installed {
        links,
        unseen,
        unknown,
    } = super::installed_links(&root, &dir.path().join("no-database"), 20_000);
    assert!(unseen.is_empty(), "{unseen:?}");
    assert!(unknown.is_empty(), "{unknown:?}");
    assert_eq!(
        links["usr/share/b/rule"],
        ["etc/cron.d/a", "etc/cron.d/again"]
    );
    assert_eq!(links["usr/share/b/new"], ["etc/cron.d/new"]);
    assert_eq!(links["usr/lib/pkg/job"], ["etc/cron.d/lib"]);
    let mut unit = links["usr/lib/systemd/system/x.service"].clone();
    unit.sort();
    assert_eq!(
        unit,
        [
            "etc/systemd/system/x.service",
            "usr/lib/systemd/system/multi-user.target.wants/x.service"
        ]
    );
    assert_eq!(links.len(), 4, "{links:?}");
}

#[test]
fn links_in_a_directory_only_root_lists_come_from_pacmans_record() {
    let entries = super::mtree_entries(
        "#mtree\n/set type=file uid=0 gid=0 mode=644\n./.PKGINFO time=1.0 size=10\n./etc time=1.0 mode=755 type=dir\n./etc/sudoers.d/a time=1.0 mode=777 type=link link=/usr/share/b/rule\n./etc/sudoers.d/with\\040space time=1.0 type=link link=../x\\040y\n./etc/sudoers.d/plain time=1.0 size=3\n./etc/sudoers.d/bad\\x time=1.0 size=3\n./etc/sudoers.d/nowhere time=1.0 type=link\n./etc/sudoers.d/odd time=1.0 type=link link=x\\q\n",
    );
    let link = |path: &str| entries.get(path).cloned();
    assert_eq!(
        link("etc/sudoers.d/a"),
        Some(Some("/usr/share/b/rule".to_string()))
    );
    assert_eq!(
        link("etc/sudoers.d/with space"),
        Some(Some("../x y".to_string()))
    );
    assert_eq!(link("etc/sudoers.d/plain"), Some(None));
    assert_eq!(link("etc"), Some(None));
    // A name or a link text that cannot be read describes nothing.
    assert_eq!(entries.len(), 5, "{entries:?}");
    assert_eq!(link("etc/sudoers.d/nowhere"), None);
    assert_eq!(link("etc/sudoers.d/odd"), None);

    if !tool_available("/usr/bin/gzip") {
        return;
    }
    let dir = TempDir::new("pacman-packaged-links");
    let db = dir.path().join("local");
    let record = |package: &str, files: &str, mtree: &str| {
        let directory = db.join(package);
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("files"), files).unwrap();
        fs::write(directory.join("mtree"), mtree).unwrap();
        assert!(
            Command::new("/usr/bin/gzip")
                .arg(directory.join("mtree"))
                .status()
                .unwrap()
                .success()
        );
        fs::rename(directory.join("mtree.gz"), directory.join("mtree")).unwrap();
    };
    record(
        "a-1-1",
        "%FILES%\netc/\netc/sudoers.d/\netc/sudoers.d/a\nusr/share/a/link\n",
        "#mtree\n./etc/sudoers.d/a time=1.0 mode=777 type=link link=/usr/share/b/rule\n./usr/share/a/link time=1.0 type=link link=/etc/passwd\n",
    );
    // Ships nothing there: its record is not even unpacked.
    let other = db.join("b-1-1");
    fs::create_dir_all(&other).unwrap();
    fs::write(
        other.join("files"),
        "%FILES%\netc/\netc/sudoers.d/\nusr/share/b/rule\n",
    )
    .unwrap();
    fs::write(other.join("mtree"), "not gzip").unwrap();
    fs::write(db.join("ALPM_DB_VERSION"), "9\n").unwrap();

    let hidden = ["etc/sudoers.d".to_string()];
    let found = super::packaged_links(&db, &hidden).unwrap();
    assert_eq!(
        found.links,
        [(
            "etc/sudoers.d/a".to_string(),
            "/usr/share/b/rule".to_string()
        )]
    );
    assert!(found.unknown.is_empty(), "{:?}", found.unknown);

    // What the file list has and the mtree does not describe (no
    // line, a link without its text) is said with its package; a
    // plain file and a backup entry are not.
    record(
        "c-2-1",
        "%FILES%\netc/sudoers.d/\netc/sudoers.d/plain\netc/sudoers.d/missing\netc/sudoers.d/nowhere\n\n%BACKUP%\netc/sudoers.d/plain\td41d8cd98f00b204e9800998ecf8427e\n",
        "#mtree\n/set type=file uid=0 gid=0 mode=644\n./etc/sudoers.d/plain time=1.0 size=3\n./etc/sudoers.d/nowhere time=1.0 type=link\n",
    );
    let found = super::packaged_links(&db, &hidden).unwrap();
    assert_eq!(found.links.len(), 1);
    let unknown = |path: &str| ("c-2-1".to_string(), path.to_string());
    assert_eq!(
        found.unknown,
        [
            unknown("etc/sudoers.d/missing"),
            unknown("etc/sudoers.d/nowhere")
        ]
    );
    // One sentence for the package, and none for what the transaction
    // puts something else in the place of.
    let said = super::unknown_entries(&found.unknown, &|_| false);
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(
        said[0].contains("the installed package c-2-1")
            && said[0].contains("/etc/sudoers.d/missing and 1 more"),
        "{said:?}"
    );
    let said = super::unknown_entries(&found.unknown, &|path| path.ends_with("missing"));
    assert!(
        said.len() == 1 && said[0].contains("whether /etc/sudoers.d/nowhere is"),
        "{said:?}"
    );
    assert!(super::unknown_entries(&found.unknown, &|_| true).is_empty());
    fs::remove_dir_all(db.join("c-2-1")).unwrap();
    // A record that cannot be read is said, not passed over.
    fs::write(other.join("files"), "%FILES%\netc/sudoers.d/b\n").unwrap();
    assert!(super::packaged_links(&db, &hidden).is_err());
    assert!(super::packaged_links(&dir.path().join("missing"), &hidden).is_err());
}

#[test]
fn what_a_link_on_the_system_leads_to_is_reviewed_when_a_package_replaces_it() {
    if !tool_available("/usr/bin/bsdtar") {
        return;
    }
    let dir = TempDir::new("pacman-stale-link");
    let mut program = ELF.to_vec();
    program.resize(3 * 1024 * 1024, 0);
    let archive = pack(
        dir.path(),
        "b",
        &[
            (
                "usr/share/guardian-test-b/rule",
                b"ALL ALL=(ALL) NOPASSWD: ALL\n",
            ),
            ("usr/share/guardian-test-b/tool", &program),
            ("usr/share/guardian-test-b/complete", b"complete -F _b b\n"),
            ("usr/share/guardian-test-b/untouched", b"x\n"),
        ],
    );
    let mut links = super::InstalledLinks::new();
    let mut lead = |to: &str, from: &str| {
        links
            .entry(format!("usr/share/guardian-test-b/{to}"))
            .or_default()
            .push(from.to_string());
    };
    lead("rule", "etc/sudoers.d/a");
    lead("tool", "usr/local/bin/tool");
    lead("complete", "usr/share/bash-completion/completions/b");
    let scan = |class| {
        let mut report = Report::new("test");
        let (_, summary, _) = scan_package(
            &archive,
            "b",
            class,
            &[],
            &|_| crate::payload::InArchive::Absent,
            &links,
            &mut report,
        )
        .unwrap();
        (report, summary)
    };

    let (report, summary) = scan(SourceClass::LocalPackage);
    assert!(report.gaps.is_empty(), "{:?}", report.gaps);
    let sent: Vec<&str> = report
        .agent_input
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    assert_eq!(
        sent,
        [
            "b/b-1-1-any.pkg.tar/usr/share/guardian-test-b/complete",
            "b/b-1-1-any.pkg.tar/usr/share/guardian-test-b/rule"
        ]
    );
    let rule = &report.agent_input[1].content;
    assert!(
        rule.contains("NOPASSWD")
            && rule.contains("/etc/sudoers.d/a, a symbolic link on this system"),
        "{rule}"
    );
    // A program a link in /usr/local/bin leads to is named, not read.
    assert_eq!(
        summary.not_reviewed,
        ["/usr/share/guardian-test-b/tool (ELF executable)"]
    );
    assert_eq!(report.hash_only.len(), 1);
    assert_eq!(
        report.class_of("b/b-1-1-any.pkg.tar/usr/share/guardian-test-b/rule"),
        SourceClass::LocalPackage
    );

    // A completion file is not reviewed for an official package,
    // whichever way it is reached.
    let (report, _) = scan(SourceClass::Official);
    assert_eq!(report.agent_input.len(), 1);

    // Without such links nothing of this package is looked at.
    let mut report = Report::new("test");
    scan_package(
        &archive,
        "b",
        SourceClass::LocalPackage,
        &[],
        &|_| crate::payload::InArchive::Absent,
        &super::InstalledLinks::new(),
        &mut report,
    )
    .unwrap();
    assert!(report.agent_input.is_empty());

    // The file as it is installed now adds nothing.
    assert!(super::same_as_installed(
        &dir.path().join("b-root"),
        "usr/share/guardian-test-b/rule",
        b"ALL ALL=(ALL) NOPASSWD: ALL\n"
    ));
    assert!(!super::same_as_installed(
        &dir.path().join("b-root"),
        "usr/share/guardian-test-b/rule",
        b"ALL ALL=(ALL) ALL\n"
    ));
}

#[test]
fn named_files_misplaced_files_and_a_changed_archive_reach_the_report() {
    use std::io::{Seek, SeekFrom, Write};
    if !tool_available("/usr/bin/bsdtar") {
        return;
    }
    let dir = TempDir::new("pacman-named");
    let mut big = b"#!/bin/sh\n".to_vec();
    big.resize(2 * 1024 * 1024 + 1, b'#');
    let archive = pack(
        dir.path(),
        "sample",
        &[
            (
                "usr/share/libalpm/hooks/guardian-test.hook",
                b"[Action]\nExec = /usr/bin/sh /usr/share/guardian-test/run.sh\n",
            ),
            (
                "usr/share/guardian-test/run.sh",
                b"/usr/lib/guardian-test/helper; . /usr/share/guardian-test/big.sh\n",
            ),
            ("usr/lib/guardian-test/helper", ELF),
            ("usr/share/guardian-test/big.sh", &big),
            ("usr/lib/security/pam_guardian_test.so", ELF),
        ],
    );
    let scan = |class| {
        let mut report = Report::new("test");
        let scanned = scan_package(
            &archive,
            "sample",
            class,
            &[],
            &|_| crate::payload::InArchive::Absent,
            &super::InstalledLinks::new(),
            &mut report,
        )
        .unwrap();
        (report, scanned)
    };
    let (report, (_, summary, fingerprint)) = scan(SourceClass::LocalPackage);
    let sent: Vec<&str> = report
        .agent_input
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    assert_eq!(
        sent,
        [
            "sample/sample-1-1-any.pkg.tar/usr/share/guardian-test/run.sh",
            "sample/sample-1-1-any.pkg.tar/usr/share/libalpm/hooks/guardian-test.hook",
        ]
    );
    // The program the script runs is said to be unread, to the user
    // and to the AI.
    assert_eq!(
        summary.not_reviewed,
        ["/usr/lib/guardian-test/helper (ELF executable)"]
    );
    assert_eq!(
        report.hash_only[0].path,
        "sample/sample-1-1-any.pkg.tar/usr/lib/guardian-test/helper"
    );
    // Text too large to read is a gap.
    assert_eq!(report.gaps.len(), 1, "{:?}", report.gaps);
    assert!(
        report.gaps[0]
            .to_string()
            .contains("/usr/share/guardian-test/big.sh, which /usr/share/guardian-test/run.sh names, is text over the 2 MiB review limit"),
        "{:?}",
        report.gaps
    );
    // A PAM module from anything but an official package is a finding.
    assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
    assert_eq!(report.findings[0].rule, RuleId::PrivilegeEscalation);
    assert!(
        report.findings[0]
            .excerpt
            .starts_with("/usr/lib/security/pam_guardian_test.so runs when someone logs in"),
        "{}",
        report.findings[0].excerpt
    );
    let (official, _) = scan(SourceClass::Official);
    assert!(official.findings.is_empty());

    // Once the review is over the archive must be what it was.
    fingerprint.verify().unwrap();
    let mut file = fs::OpenOptions::new().write(true).open(&archive).unwrap();
    file.seek(SeekFrom::Start(600)).unwrap();
    file.write_all(b"swapped").unwrap();
    drop(file);
    assert!(fingerprint.verify().is_err());
}

#[test]
fn a_deep_directory_is_looked_through_and_an_over_large_one_is_named() {
    use std::os::unix::fs::symlink;
    let dir = TempDir::new("pacman-deep-links");
    let root = dir.path().join("root");
    // Deeper than any catalogued shape: no reason to stop, and a link
    // down there is still found.
    let deep = "etc/systemd/system/a/b/c/d/e/f/g";
    fs::create_dir_all(root.join(deep)).unwrap();
    fs::create_dir_all(root.join("usr/share/b")).unwrap();
    symlink("/usr/share/b/unit", root.join(deep).join("x.service")).unwrap();
    let db = dir.path().join("no-database");
    let found = super::installed_links(&root, &db, 20_000);
    assert!(found.unseen.is_empty(), "{:?}", found.unseen);
    assert_eq!(
        found.links["usr/share/b/unit"],
        [format!("{deep}/x.service")]
    );

    // More entries than are looked through: said once, with the
    // directory that holds them and how many.
    fs::create_dir_all(root.join("etc/cron.d/many")).unwrap();
    for index in 0..40 {
        fs::write(root.join(format!("etc/cron.d/many/{index}")), "x\n").unwrap();
    }
    let found = super::installed_links(&root, &db, 30);
    assert_eq!(found.unseen.len(), 1, "{:?}", found.unseen);
    assert!(
        found.unseen[0]
            .starts_with("/etc/cron.d/ holds more than 30 entries (/etc/cron.d/many alone has 40)"),
        "{:?}",
        found.unseen
    );
    // The deep directory alone never was the reason.
    assert!(found.links.contains_key("usr/share/b/unit"));
}

#[test]
fn only_a_line_about_guardians_own_is_let_off() {
    for own in [
        "systemctl disable --now omarchy-guardian-sweep-collect.timer >/dev/null 2>&1 || true",
        "    systemctl stop omarchy-guardian-sweep.timer omarchy-guardian-sweep.service",
        "/usr/bin/systemctl --quiet disable 'omarchy-guardian-sweep.timer' 2> /dev/null; true",
        "rm -f /etc/pacman.d/hooks/omarchy-guardian.hook",
    ] {
        assert!(super::only_guardians_own(own), "{own}");
    }
    for other in [
        "systemctl disable ufw # omarchy-guardian",
        "systemctl stop apparmor omarchy-guardian-sweep.timer",
        "systemctl disable omarchy-guardian-sweep.timer; ufw disable",
        "systemctl disable omarchy-guardian-sweep.timer && setenforce 0",
        "systemctl disable omarchy-guardian-sweep.timer; sysctl kernel.yama.ptrace_scope=0",
        "systemctl disable omarchy-guardian-sweep.timer; nft flush ruleset",
        "systemctl disable omarchy-guardian-sweep.timer \"$other\"",
        "systemctl disable omarchy-guardian-sweep.timer sshd.service",
        "systemctl mask ufw.service",
    ] {
        assert!(!super::only_guardians_own(other), "{other}");
    }

    let script = "pre_remove() {\n  systemctl disable --now omarchy-guardian-sweep.timer\n  systemctl disable ufw # omarchy-guardian\n  systemctl stop apparmor omarchy-guardian-sweep.timer\n  systemctl disable \\\n    omarchy-guardian-sweep.timer ufw\n}\n";
    let findings = |target: &str| {
        let mut report = Report::new("test");
        analyze_text(&mut report, "x/.INSTALL", script, false);
        super::own_removal_is_no_attack(&mut report, target, "x/.INSTALL", script);
        let mut lines: Vec<usize> = report
            .findings
            .iter()
            .filter(|finding| finding.rule == RuleId::ProtectionDisabled)
            .map(|finding| finding.line)
            .collect();
        lines.sort_unstable();
        lines.dedup();
        lines
    };
    // Any other package keeps every finding; Guardian's own loses
    // only the line about its own timer.
    let all = findings("sample");
    assert!(
        all.contains(&2) && all.contains(&3) && all.contains(&4),
        "{all:?}"
    );
    let kept = findings("omarchy-guardian");
    assert!(!kept.contains(&2), "{kept:?}");
    let rest: Vec<usize> = all.iter().copied().filter(|line| *line != 2).collect();
    assert_eq!(kept, rest);
}

#[test]
fn what_was_not_read_inside_a_fingerprinted_archive_can_be_permitted() {
    use crate::report::Gap;
    if !tool_available("/usr/bin/bsdtar") {
        return;
    }
    let dir = TempDir::new("pacman-unread");
    let mut big = b"#!/bin/sh\n".to_vec();
    big.resize(2 * 1024 * 1024 + 1, b'#');
    let scan = |archive: &Path, name: &str| {
        let mut report = Report::new("test");
        let scanned = scan_package(
            archive,
            name,
            SourceClass::LocalPackage,
            &[],
            &|_| crate::payload::InArchive::Absent,
            &super::InstalledLinks::new(),
            &mut report,
        );
        (report, scanned)
    };
    let unread = |report: &Report, text: &str| {
        assert!(
            report
                .gaps
                .iter()
                .any(|gap| matches!(gap, Gap::PackageUnread(said) if said.contains(text))),
            "{text}: {:?}",
            report.gaps
        );
        assert!(report.content_hashed(), "{:?}", report.gaps);
    };

    // A compiled program in an auto-run directory, a named text file
    // and an auto-run file over the size limit: the archive is read
    // and fingerprinted, and each is a gap a permit can stand for.
    let archive = pack(
        dir.path(),
        "sample",
        &[
            ("usr/lib/systemd/system-generators/guardian-test", ELF),
            (
                "usr/share/libalpm/hooks/guardian-test.hook",
                b"[Action]\nExec = /usr/bin/sh /usr/share/guardian-test/big.sh\n",
            ),
            ("usr/share/guardian-test/big.sh", &big),
            ("etc/profile.d/guardian-test-big.sh", &big),
        ],
    );
    let (report, scanned) = scan(&archive, "sample");
    scanned.unwrap();
    assert_eq!(report.gaps.len(), 3, "{:?}", report.gaps);
    unread(
        &report,
        "a compiled file (ELF executable) in an auto-run location",
    );
    unread(
        &report,
        "big.sh, which /usr/share/libalpm/hooks/guardian-test.hook names, is text over",
    );
    unread(
        &report,
        "auto-run file /etc/profile.d/guardian-test-big.sh exceeds",
    );
    // The hook itself was still reviewed.
    assert_eq!(report.agent_input.len(), 1);

    // A scriptlet over the limit, and one of binary data.
    let long = TempDir::new("pacman-long-scriptlet");
    fs::write(long.path().join(".INSTALL"), &big).unwrap();
    let archive = build_package(long.path(), None);
    let add = |directory: &Path, archive: &Path| {
        assert!(
            Command::new("/usr/bin/bsdtar")
                .arg("-rf")
                .arg(archive)
                .arg(".INSTALL")
                .current_dir(directory)
                .status()
                .unwrap()
                .success()
        );
    };
    add(long.path(), &archive);
    let (report, scanned) = scan(&archive, "sample");
    assert!(scanned.unwrap().0, "a scriptlet is there, if unread");
    unread(
        &report,
        "the install scriptlet exceeds the 2 MiB review limit",
    );

    let binary = TempDir::new("pacman-binary-scriptlet");
    fs::write(binary.path().join(".INSTALL"), ELF).unwrap();
    let archive = build_package(binary.path(), None);
    add(binary.path(), &archive);
    let (report, scanned) = scan(&archive, "sample");
    assert!(scanned.unwrap().0);
    unread(&report, "holds binary data");

    // What the gate refuses stays refused, whatever else is unread:
    // an oversized scriptlet does not get a package past its name.
    let (report, scanned) = scan(&archive, "other-name");
    assert!(scanned.is_err());
    assert!(report.gaps.is_empty(), "{:?}", report.gaps);
    let refused = Gap::Package(scanned.err().unwrap());
    assert!(!refused.content_hashed());
}
