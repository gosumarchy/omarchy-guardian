//! Guardian's own sweep units, and what stands in for them.
//!
//! The daily sweep is a systemd user unit, and the root checks a system
//! unit. systemd lets a file in another unit directory replace a unit, and a
//! drop-in change any line of it: a `HOME=`, an `XDG_STATE_HOME=` or an
//! `ExecStart=` in `omarchy-guardian-sweep.service.d/` makes the sweep look
//! at another home, write its results elsewhere or not run at all, while the
//! bar still shows a sweep that ran. Anything of that kind is an alert of
//! its own, which allowing the file does not quiet.

use std::fs;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use super::collect::{Body, Item, Origin, Scope, WITHHELD};
use super::read::{self, Found, View};
use super::tier::Tier;
use crate::autorun::Category;
use crate::rules::RuleId;

/// The units of the user's sweep and of the root checks.
const USER_UNITS: &[&str] = &[
    "omarchy-guardian-sweep.service",
    "omarchy-guardian-sweep.timer",
];
const SYSTEM_UNITS: &[&str] = &[
    "omarchy-guardian-sweep-collect.service",
    "omarchy-guardian-sweep-collect.timer",
];

/// Why an override root found has no hash.
const NOT_READ: &str =
    "there, and not read: too large, not a regular file, or closed to its account";

/// Where systemd reads user units from besides the package's own
/// directory, relative to the home: every directory of its search path
/// (`systemd-analyze --user unit-paths`), all of which but the late
/// generators' outrank the package's, and the data directory Flatpak adds
/// to the user manager's `XDG_DATA_DIRS`.
const HOME_DIRECTORIES: &[&str] = &[
    ".config/systemd/user",
    ".config/systemd/user.control",
    ".config/systemd/user.attached",
    ".local/share/systemd/user",
    ".local/share/flatpak/exports/share/systemd/user",
];
/// The same below `/run/user/<uid>`.
const RUNTIME_DIRECTORIES: &[&str] = &[
    "systemd/user",
    "systemd/user.control",
    "systemd/user.attached",
    "systemd/transient",
    "systemd/generator",
    "systemd/generator.early",
    "systemd/generator.late",
];
/// The same for every user, relative to the root. The two under `share`
/// are the system's `XDG_DATA_DIRS`: systemd looks there before
/// `/usr/lib/systemd/user`, so a unit of the same name there replaces the
/// package's.
const SHARED_USER_DIRECTORIES: &[&str] = &[
    "etc/systemd/user",
    "etc/xdg/systemd/user",
    "run/systemd/user",
    "usr/local/share/systemd/user",
    "usr/share/systemd/user",
    "var/lib/flatpak/exports/share/systemd/user",
    "usr/local/lib/systemd/user",
];
/// Where systemd reads system units from besides the package's own
/// (`systemd-analyze --system unit-paths`).
const SYSTEM_DIRECTORIES: &[&str] = &[
    "etc/systemd/system",
    "etc/systemd/system.control",
    "etc/systemd/system.attached",
    "run/systemd/system",
    "run/systemd/system.control",
    "run/systemd/system.attached",
    "run/systemd/transient",
    "run/systemd/generator",
    "run/systemd/generator.early",
    "run/systemd/generator.late",
    "usr/local/lib/systemd/system",
];
/// The package's own directories: its units are there, so only a drop-in
/// beside them is an override.
const PACKAGE_USER: &str = "usr/lib/systemd/user";
const PACKAGE_SYSTEM: &str = "usr/lib/systemd/system";

/// The most drop-ins looked at in one directory.
const MAX_DROP_INS: usize = 64;

/// What was seen, for the alert.
const SEEN: &str = "stands in for, or changes, a unit of Guardian's own sweep";

/// The drop-in directories whose files apply to `unit`: its own, the ones
/// for every unit whose name starts like it (`omarchy-.service.d`), and
/// the one for every unit of its type (`service.d`).
fn drop_in_directories(unit: &str) -> Vec<String> {
    let (name, kind) = unit.rsplit_once('.').unwrap_or((unit, ""));
    let mut directories = vec![format!("{unit}.d"), format!("{kind}.d")];
    for (at, _) in name.match_indices('-') {
        directories.push(format!("{}-.{kind}.d", &name[..at]));
    }
    directories
}

/// Whether the file at `relative` (to a unit directory) overrides one of
/// `units`.
fn overrides(units: &[&str], relative: &str, with_units: bool) -> bool {
    units.iter().any(|unit| {
        (with_units && relative == *unit)
            || relative.split_once('/').is_some_and(|(directory, file)| {
                !file.contains('/') && drop_in_directories(unit).iter().any(|own| own == directory)
            })
    })
}

/// Whether `path` (relative to the root) overrides one of Guardian's units,
/// for a sweep whose home is `home`.
pub fn is_override(home: Option<&str>, path: &str) -> bool {
    let under = |directory: &str, units: &[&str], with_units: bool| {
        path.strip_prefix(directory)
            .and_then(|rest| rest.strip_prefix('/'))
            .is_some_and(|relative| overrides(units, relative, with_units))
    };
    let in_home = home.is_some_and(|home| {
        HOME_DIRECTORIES
            .iter()
            .any(|directory| under(&format!("{home}/{directory}"), USER_UNITS, true))
    });
    let in_runtime = path.strip_prefix("run/user/").is_some_and(|rest| {
        rest.split_once('/').is_some_and(|(_, below)| {
            RUNTIME_DIRECTORIES.iter().any(|directory| {
                below
                    .strip_prefix(directory)
                    .and_then(|rest| rest.strip_prefix('/'))
                    .is_some_and(|relative| overrides(USER_UNITS, relative, true))
            })
        })
    });
    in_home
        || in_runtime
        || SHARED_USER_DIRECTORIES
            .iter()
            .any(|directory| under(directory, USER_UNITS, true))
        || SYSTEM_DIRECTORIES
            .iter()
            .any(|directory| under(directory, SYSTEM_UNITS, true))
        || under(PACKAGE_USER, USER_UNITS, false)
        || under(PACKAGE_SYSTEM, SYSTEM_UNITS, false)
}

/// The paths under unit directory `directory` that may override one of
/// `units`: the unit files themselves, and what `list` says their drop-in
/// directories hold.
fn candidates(
    directory: &str,
    units: &[&str],
    with_units: bool,
    list: &dyn Fn(&str) -> Vec<String>,
) -> Vec<String> {
    let mut found = Vec::new();
    for unit in units {
        if with_units {
            found.push(format!("{directory}/{unit}"));
        }
        for drop_ins in drop_in_directories(unit) {
            let holder = format!("{directory}/{drop_ins}");
            let mut names = list(&holder);
            names.sort();
            for name in names.into_iter().take(MAX_DROP_INS) {
                let path = format!("{holder}/{name}");
                if !found.contains(&path) {
                    found.push(path);
                }
            }
        }
    }
    found
}

fn names_in(entries: fs::ReadDir) -> Vec<String> {
    entries
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .take(MAX_DROP_INS + 1)
        .collect()
}

/// The id of the user whose directory `home` is.
fn owner(root: &Path, home: &str) -> Option<u32> {
    fs::symlink_metadata(root.join(home))
        .ok()
        .map(|metadata| metadata.uid())
}

/// The paths under `root` of what may override Guardian's units outside
/// the package's own directories: in the system's other unit directories
/// and, with a home (relative to the root), in that home's and its runtime
/// directory's. With `packaged`, the drop-ins beside the package's own
/// units as well.
fn candidates_under(root: &Path, home: Option<&str>, packaged: bool) -> Vec<String> {
    let list = |directory: &str| -> Vec<String> {
        fs::read_dir(root.join(directory))
            .map(names_in)
            .unwrap_or_default()
    };
    let mut paths = Vec::new();
    for directory in SHARED_USER_DIRECTORIES {
        paths.extend(candidates(directory, USER_UNITS, true, &list));
    }
    for directory in SYSTEM_DIRECTORIES {
        paths.extend(candidates(directory, SYSTEM_UNITS, true, &list));
    }
    if packaged {
        paths.extend(candidates(PACKAGE_USER, USER_UNITS, false, &list));
        paths.extend(candidates(PACKAGE_SYSTEM, SYSTEM_UNITS, false, &list));
    }
    if let Some(home) = home {
        for directory in HOME_DIRECTORIES {
            paths.extend(candidates(
                &format!("{home}/{directory}"),
                USER_UNITS,
                true,
                &list,
            ));
        }
        if let Some(uid) = owner(root, home) {
            for directory in RUNTIME_DIRECTORIES {
                paths.extend(candidates(
                    &format!("run/user/{uid}/{directory}"),
                    USER_UNITS,
                    true,
                    &list,
                ));
            }
        }
    }
    paths
        .into_iter()
        .filter(|path| fs::symlink_metadata(root.join(path)).is_ok())
        .collect()
}

/// The paths of what may override Guardian's units and `scope` can look
/// at as itself: in the system's unit directories and, with a home, in
/// that home's and its runtime directory's. The root collector looks at
/// root's own home here; the homes of the accounts its results go to are
/// looked at as those accounts (`of_account`).
pub fn paths(scope: &Scope<'_>) -> Vec<String> {
    candidates_under(scope.root, scope.home, true)
}

/// What stands in for Guardian's units right now, for the bar: the same
/// files the sweep alerts on (`is_override`), found without the package
/// index, which is too much to load every half minute. Drop-ins in the
/// package's own directories are therefore left to the sweep: only it
/// can tell the one a repository package ships for every unit from one
/// put there by hand.
pub fn standing(root: &Path, home: Option<&str>) -> Vec<String> {
    candidates_under(root, home, false)
        .into_iter()
        .filter(|path| is_override(home, path))
        .collect()
}

/// Puts the alert on `item`, which overrides one of Guardian's units. An
/// alert takes away whatever trust its tier gave it: a mask is no longer
/// inert.
pub fn mark(item: &mut Item) {
    if !item
        .alerts
        .iter()
        .any(|(rule, _)| *rule == RuleId::GuardianOverride)
    {
        item.alerts.push((RuleId::GuardianOverride, SEEN.into()));
    }
}

/// Whether there is anything at `path`, as account `view` could tell
/// itself: it may enter the directory the name is in.
fn is_there(scope: &Scope<'_>, path: &str, view: View) -> bool {
    let Some((directory, name)) = path.rsplit_once('/') else {
        return false;
    };
    match read::seen(scope.root, directory, view).map(|seen| seen.what) {
        Some(read::Public::Directory(handle)) => {
            fs::symlink_metadata(format!("/proc/self/fd/{}/{name}", handle.as_raw_fd())).is_ok()
        }
        _ => false,
    }
}

/// The overrides of the user sweep's units in the home of account `uid`
/// (`home`, relative to the root) and its runtime directory, as the root
/// collector may report them: looked at as that account could itself, with
/// no link followed, and with the content left where it is. So the finding
/// does not rest on that account's own sweep being honest.
///
/// What is there and cannot be hashed (a drop-in padded past the read
/// limit, a file closed to its own account, something that is no file) is
/// reported all the same, without a hash: root's report is for the case
/// where the account's own sweep was turned away, and dropping what could
/// not be read would be the way to turn root away too. That something is
/// there tells the account nothing it cannot see: the path is one Guardian
/// chose, not one a user named, it lies in the account's own home or
/// runtime directory, and it is looked for only through directories the
/// account may enter itself.
pub fn of_account(scope: &Scope<'_>, home: &str, uid: u32) -> Vec<Item> {
    let view = View::Owner(uid);
    let list = |directory: &str| -> Vec<String> {
        match read::seen(scope.root, directory, view).map(|seen| seen.what) {
            Some(read::Public::Directory(handle)) => {
                fs::read_dir(format!("/proc/self/fd/{}", handle.as_raw_fd()))
                    .map(names_in)
                    .unwrap_or_default()
            }
            _ => Vec::new(),
        }
    };
    let mut paths = Vec::new();
    for directory in HOME_DIRECTORIES {
        paths.extend(candidates(
            &format!("{home}/{directory}"),
            USER_UNITS,
            true,
            &list,
        ));
    }
    for directory in RUNTIME_DIRECTORIES {
        paths.extend(candidates(
            &format!("run/user/{uid}/{directory}"),
            USER_UNITS,
            true,
            &list,
        ));
    }
    paths
        .into_iter()
        .filter_map(|path| {
            let (sha256, body) = match read::look_as(scope.root, &path, view) {
                Some(Found::File { sha256, .. }) => (Some(sha256), Body::Binary(WITHHELD)),
                Some(Found::Link(target)) => (None, Body::Link(target)),
                Some(Found::Other | Found::Unreadable(_)) => {
                    (None, Body::Unreadable(NOT_READ.into()))
                }
                None if is_there(scope, &path, view) => (None, Body::Unreadable(NOT_READ.into())),
                None => return None,
            };
            let mut item = Item {
                origin: Origin::Root,
                category: Category::Systemd,
                path,
                tier: Tier::Unknown,
                sha256,
                body,
                runs: Vec::new(),
                run_by: None,
                notes: vec!["seen by the root checks".into()],
                alerts: Vec::new(),
            };
            mark(&mut item);
            Some(item)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    use super::{is_override, of_account, standing};
    use crate::rules::RuleId;
    use crate::sweep::collect::{Body, Origin, Scope, WITHHELD, collect};
    use crate::sweep::index::PackageIndex;
    use crate::test_support::TempDir;

    #[test]
    fn what_overrides_guardians_units_is_told_from_what_enables_them() {
        let home = Some("home/u");
        for path in [
            "home/u/.config/systemd/user/omarchy-guardian-sweep.service",
            "home/u/.config/systemd/user/omarchy-guardian-sweep.timer",
            "home/u/.config/systemd/user/omarchy-guardian-sweep.service.d/x.conf",
            "home/u/.config/systemd/user/omarchy-guardian-.service.d/x.conf",
            "home/u/.config/systemd/user/omarchy-.service.d/x.conf",
            "home/u/.config/systemd/user/service.d/x.conf",
            "home/u/.config/systemd/user.control/omarchy-guardian-sweep.timer.d/50-x.conf",
            "home/u/.local/share/systemd/user/omarchy-guardian-sweep.service",
            "run/user/1000/systemd/transient/omarchy-guardian-sweep.service",
            "etc/systemd/user/omarchy-guardian-sweep.timer",
            // Ahead of the package's own directory on systemd's path.
            "usr/share/systemd/user/omarchy-guardian-sweep.service",
            "usr/local/share/systemd/user/omarchy-guardian-sweep.timer",
            "usr/share/systemd/user/service.d/x.conf",
            "var/lib/flatpak/exports/share/systemd/user/omarchy-guardian-sweep.service",
            "home/u/.local/share/flatpak/exports/share/systemd/user/omarchy-guardian-sweep.service",
            "home/u/.config/systemd/user.attached/omarchy-guardian-sweep.service",
            "run/user/1000/systemd/user.attached/omarchy-guardian-sweep.service.d/x.conf",
            "run/systemd/system.attached/omarchy-guardian-sweep-collect.service",
            "etc/systemd/system/omarchy-guardian-sweep-collect.service.d/x.conf",
            "etc/systemd/system/omarchy-guardian-sweep-collect.timer",
            "usr/lib/systemd/user/omarchy-guardian-sweep.service.d/x.conf",
        ] {
            assert!(is_override(home, path), "{path}");
        }
        for path in [
            // The package's own units, and the links that enable them.
            "usr/lib/systemd/user/omarchy-guardian-sweep.service",
            "usr/lib/systemd/system/omarchy-guardian-sweep-collect.timer",
            "home/u/.config/systemd/user/timers.target.wants/omarchy-guardian-sweep.timer",
            "etc/systemd/system/timers.target.wants/omarchy-guardian-sweep-collect.timer",
            // Other units, and another home.
            "home/u/.config/systemd/user/other.service.d/x.conf",
            "home/u/.config/systemd/user/omarchy-guardian-sweep.service.d/sub/x.conf",
            "home/v/.config/systemd/user/omarchy-guardian-sweep.service",
            "etc/systemd/system/omarchy-guardian-sweep.service",
            "usr/share/systemd/user/other.service",
        ] {
            assert!(!is_override(home, path), "{path}");
        }
    }

    #[test]
    fn overrides_are_found_by_the_user_and_by_root_looking_as_that_user() {
        let dir = TempDir::new("sweep-own");
        let root = dir.path();
        let uid = fs::metadata(root).unwrap().uid();
        let units = root.join("home/u/.config/systemd/user");
        fs::create_dir_all(units.join("omarchy-guardian-sweep.service.d")).unwrap();
        fs::write(
            units.join("omarchy-guardian-sweep.service.d/home.conf"),
            "[Service]\nEnvironment=HOME=/tmp/fake\n",
        )
        .unwrap();
        symlink("/dev/null", units.join("omarchy-guardian-sweep.timer")).unwrap();
        fs::write(units.join("other.service"), "[Service]\nExecStart=/x\n").unwrap();
        let index = PackageIndex::with_foreign(HashSet::new());
        let scope = Scope {
            root,
            home: Some("home/u"),
            index: &index,
            origin: Origin::System,
        };
        let collection = collect(&scope);
        let found: Vec<_> = collection
            .items
            .iter()
            .filter(|item| !item.alerts.is_empty())
            .collect();
        let paths: Vec<&str> = found.iter().map(|item| item.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "home/u/.config/systemd/user/omarchy-guardian-sweep.service.d/home.conf",
                "home/u/.config/systemd/user/omarchy-guardian-sweep.timer",
            ]
        );
        assert!(found.iter().all(|item| {
            item.alerts
                .iter()
                .any(|(rule, _)| *rule == RuleId::GuardianOverride)
                && !item.is_trusted()
        }));
        // Another unit beside them is an ordinary item.
        assert!(
            collection
                .items
                .iter()
                .any(|item| { item.path.ends_with("other.service") && item.alerts.is_empty() })
        );

        // The bar finds the same two without a package index. A drop-in
        // beside the package's own units is left to the sweep, which can
        // tell whether a repository package ships it.
        let beside = root.join("usr/lib/systemd/user/omarchy-guardian-sweep.service.d");
        fs::create_dir_all(&beside).unwrap();
        fs::write(beside.join("x.conf"), "[Service]\n").unwrap();
        assert_eq!(standing(root, Some("home/u")), paths);
        assert!(standing(root, None).is_empty());
        assert_eq!(super::paths(&scope).len(), 3);

        // Root, for the account the results go to: the same files, by
        // hash, without their content.
        let as_root = Scope {
            root,
            home: Some("root"),
            index: &index,
            origin: Origin::Root,
        };
        let reported = of_account(&as_root, "home/u", uid);
        assert_eq!(reported.len(), 2);
        assert_eq!(reported[0].body, Body::Binary(WITHHELD));
        assert!(reported[0].sha256.is_some());
        assert_eq!(reported[1].body, Body::Link("/dev/null".into()));
        // An account that could not read the directory itself is told
        // nothing about it.
        if uid != 0 {
            assert!(of_account(&as_root, "home/u", uid + 1).len() <= 2);
            fs::set_permissions(root.join("home/u"), fs::Permissions::from_mode(0o700)).unwrap();
            assert!(of_account(&as_root, "home/u", uid + 1).is_empty());
        }
    }
    #[test]
    fn a_unit_where_systemd_looks_before_the_packages_directory_is_an_override() {
        let dir = TempDir::new("sweep-own-ahead");
        let root = dir.path();
        let index = PackageIndex::with_foreign(HashSet::new());
        let scope = Scope {
            root,
            home: Some("home/u"),
            index: &index,
            origin: Origin::System,
        };
        let ahead = "usr/share/systemd/user/omarchy-guardian-sweep.service";
        fs::create_dir_all(root.join(ahead).parent().unwrap()).unwrap();
        fs::write(root.join(ahead), "[Service]\nExecStart=/usr/bin/true\n").unwrap();
        assert_eq!(standing(root, None), [ahead]);
        let replaced = collect(&scope);
        assert!(replaced.items.iter().any(|item| {
            item.path == ahead
                && item
                    .alerts
                    .iter()
                    .any(|(rule, _)| *rule == RuleId::GuardianOverride)
        }));
    }

    #[test]
    fn root_reports_an_override_it_cannot_hash_by_its_path() {
        let dir = TempDir::new("sweep-own-unread");
        let root = dir.path();
        let uid = fs::metadata(root).unwrap().uid();
        let drop_ins = root.join("home/u/.config/systemd/user/omarchy-guardian-sweep.service.d");
        fs::create_dir_all(&drop_ins).unwrap();
        fs::write(drop_ins.join("read.conf"), "[Service]\n").unwrap();
        let index = PackageIndex::with_foreign(HashSet::new());
        let as_root = Scope {
            root,
            home: Some("root"),
            index: &index,
            origin: Origin::Root,
        };
        // What is there and cannot be hashed is reported too, without a
        // hash: a drop-in closed to its own account, one that is no file,
        // and one padded past the read limit.
        fs::write(drop_ins.join("closed.conf"), "[Service]\nExecStart=\n").unwrap();
        fs::set_permissions(
            drop_ins.join("closed.conf"),
            fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        fs::create_dir(drop_ins.join("odd.conf")).unwrap();
        let padded = fs::File::create(drop_ins.join("padded.conf")).unwrap();
        padded
            .set_len(crate::scan::MAX_HASHED_FILE_SIZE + 1)
            .unwrap();
        let reported = of_account(&as_root, "home/u", uid);
        let unread: Vec<&str> = reported
            .iter()
            .filter(|item| matches!(item.body, Body::Unreadable(_)))
            .map(|item| {
                assert_eq!(item.sha256, None);
                assert!(
                    item.alerts
                        .iter()
                        .any(|(rule, _)| *rule == RuleId::GuardianOverride)
                );
                item.path.rsplit('/').next().unwrap()
            })
            .collect();
        // Root reads a closed file anyway: there is none to play as root.
        if uid == 0 {
            assert_eq!(unread, ["odd.conf", "padded.conf"]);
        } else {
            assert_eq!(unread, ["closed.conf", "odd.conf", "padded.conf"]);
        }
        assert_eq!(reported.len(), 4);
        // An account that may not enter the directory is told nothing.
        if uid != 0 {
            fs::set_permissions(root.join("home/u"), fs::Permissions::from_mode(0o700)).unwrap();
            assert!(of_account(&as_root, "home/u", uid + 1).is_empty());
        }
    }
}
