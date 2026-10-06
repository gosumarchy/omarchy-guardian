//! Tests of the command search path and of what takes a system command's name.

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::symlink;

use super::{
    Search, assignments, entries, mark, opaque, search, shadowing_programs, unsafe_entries,
};
use crate::autorun::Category;
use crate::rules::RuleId;
use crate::sweep::collect::{self, Origin, Scope};
use crate::sweep::index::PackageIndex;
use crate::sweep::tier::Tier;
use crate::test_support::{TempDir, hand_to_a_user};

#[test]
fn a_path_is_read_in_order_and_split_at_the_systems_own() {
    assert_eq!(
        entries(
            "home/u",
            "/home/u/.local/share/mise/shims:$HOME/go/bin:/usr/local/bin:/usr/bin:~/.local/bin:$X/bin::."
        ),
        [
            ("home/u/.local/share/mise/shims".to_string(), true),
            ("home/u/go/bin".to_string(), true),
            ("usr/local/bin".to_string(), true),
            ("usr/bin".to_string(), false),
            ("home/u/.local/bin".to_string(), false),
        ]
    );
    // What a start-up file puts before the old PATH is ahead; what it
    // puts after is not.
    assert_eq!(
        entries("home/u", "$HOME/.bun/bin:$PATH:/opt/x/bin"),
        [
            ("home/u/.bun/bin".to_string(), true),
            ("opt/x/bin".to_string(), false)
        ]
    );
}

#[test]
fn path_lines_of_every_shell_are_read() {
    let text = "export PATH=\"$HOME/.bun/bin:$PATH\"\nPATH=/tmp/x:$PATH; export PATH\n# PATH=/no\npath=(~/bin $path)\npath+=(/opt/y)\nset -gx PATH $HOME/.deno/bin $PATH\nfish_add_path -g ~/.cargo/bin\nfish_add_path --append /opt/z\nSETUVAR fish_user_paths:/home/u/a\\x1e/tmp/b\necho PATH=$PATH\n";
    let values: Vec<String> = assignments(text)
        .into_iter()
        .map(|(_, value)| value)
        .collect();
    assert_eq!(
        values,
        [
            "$HOME/.bun/bin:$PATH",
            "/tmp/x:$PATH",
            "~/bin:$path",
            "$PATH:/opt/y",
            "$HOME/.deno/bin:$PATH",
            "~/.cargo/bin:$PATH",
            "$PATH:/opt/z",
            "/home/u/a:/tmp/b:$PATH",
        ]
    );
    let lines: Vec<usize> = unsafe_entries(text)
        .into_iter()
        .map(|(line, _)| line)
        .collect();
    assert_eq!(lines, [2, 9]);
    let odd = unsafe_entries(
        "PATH=.:$PATH\nPATH=$PATH:\nexport PATH=\"$HOME/.cache/x/bin:$PATH\"\nPATH=$HOME/bin:$PATH\n",
    );
    assert_eq!(odd.len(), 3, "{odd:?}");
    assert!(odd[0].1.contains("typed in") && odd[2].1.contains(".cache/x/bin"));
}

#[test]
fn a_path_is_found_wherever_on_a_line_it_is_set() {
    let values = |text: &str| -> Vec<String> {
        assignments(text)
            .into_iter()
            .map(|(_, value)| value)
            .collect()
    };
    for (line, expected) in [
        ("[ -d ~/.x ] && export PATH=~/.x:$PATH", "~/.x:$PATH"),
        (
            "if [ -d /opt/a ]; then PATH=/opt/a:$PATH; fi",
            "/opt/a:$PATH",
        ),
        ("declare -x PATH=\"/opt/b:$PATH\"", "/opt/b:$PATH"),
        ("typeset -gx PATH=/opt/c:$PATH", "/opt/c:$PATH"),
        ("export A=1 PATH=/opt/d:$PATH B=2", "/opt/d:$PATH"),
        ("A=1 PATH=/opt/e:$PATH", "/opt/e:$PATH"),
        ("test -d x || { PATH=/opt/f:$PATH; }", "/opt/f:$PATH"),
        ("  *) PATH=\"/opt/g${PATH:+:$PATH}\" ;;", "/opt/g:$PATH"),
        ("PATH=\"${PATH:+$PATH:}/opt/h\"", "$PATH:/opt/h"),
        ("PATH+=:/opt/i", "$PATH:/opt/i"),
        (
            "export PATH=\"$HOME/my tools:$PATH\"",
            "$HOME/my tools:$PATH",
        ),
        ("[[ -d ~/z ]] && path=(~/z $path)", "~/z:$path"),
        ("true; path+=(/opt/j /opt/k)", "$PATH:/opt/j:/opt/k"),
        ("test -d ~/f; and set -gx PATH ~/f $PATH", "~/f:$PATH"),
        ("status is-login && fish_add_path ~/g", "~/g:$PATH"),
        ("setenv PATH ${PATH}:/opt/l", "${PATH}:/opt/l"),
        (
            "PATH DEFAULT=@{HOME}/bin:${PATH} OVERRIDE=",
            "$HOME/bin:${PATH}",
        ),
        ("env = PATH,$HOME/h:$PATH", "$HOME/h:$PATH"),
        ("hl.env(\"PATH\", \"/opt/m:/usr/bin\")", "/opt/m:/usr/bin"),
    ] {
        assert_eq!(values(line), [expected], "{line}");
        assert!(opaque(line).is_empty(), "{line}");
    }
    // Not a lasting change of PATH, or not one at all.
    for line in [
        "PATH=/opt/x:$PATH make install",
        "echo PATH=/opt/x",
        "export MANPATH=/opt/x",
        "# export PATH=/opt/x:$PATH",
        "true # PATH=/opt/x",
        "alias p='echo $PATH'",
        "hl.env(\"OMARCHY_PATH\", paths.omarchy_path)",
        "env = XCURSOR_SIZE,24",
    ] {
        assert!(values(line).is_empty(), "{line}: {:?}", values(line));
        assert!(opaque(line).is_empty(), "{line}");
    }
    // What only running it would tell is said, not passed over.
    for line in [
        "export PATH=$(getconf PATH):$PATH",
        "PATH=\"$(/usr/bin/tool path)\"",
        "PATH=`tool path`:$PATH",
        "set -gx PATH (tool path) $PATH",
        "hl.env(\"PATH\", table.concat(kept, \":\"))",
    ] {
        assert!(values(line).is_empty(), "{line}: {:?}", values(line));
        assert_eq!(opaque(line), [1], "{line}");
    }
    assert_eq!(
        unsafe_entries("[ -d /tmp/b ] && export PATH=/tmp/b:$PATH\n").len(),
        1
    );
}

#[test]
fn every_file_a_shell_or_a_session_reads_counts_for_the_path() {
    let dir = TempDir::new("sweep-path-sources");
    let root = dir.path();
    let write = |path: &str, text: &str| {
        fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
        fs::write(root.join(path), text).unwrap();
    };
    write(
        "home/u/.bashrc",
        "[ -r ~/.config/shell/extra ] && . ~/.config/shell/extra\nX=$HOME/opt\nsource $X/env.sh\neval \"$(mise activate bash)\"\n",
    );
    write(
        "home/u/.config/shell/extra",
        "export PATH=\"$HOME/a/bin:$PATH\"\n",
    );
    write(
        "home/u/opt/env.sh",
        "if true; then PATH=$HOME/b/bin:$PATH; fi\n",
    );
    write(
        "home/u/.config/fish/conf.d/x.fish",
        "fish_add_path ~/c/bin\n",
    );
    write(
        "home/u/.config/environment.d/10-x.conf",
        "PATH=$HOME/d/bin:$PATH\n",
    );
    write(
        "home/u/.pam_environment",
        "PATH DEFAULT=@{HOME}/e/bin:${PATH}\n",
    );
    write(
        "home/u/.config/uwsm/env-hyprland",
        "export PATH=$HOME/f/bin:$PATH\n",
    );
    write(
        "home/u/.config/hypr/envs.conf",
        "env = PATH,$HOME/g/bin:$PATH\n",
    );
    write("etc/profile.d/x.sh", "PATH=/opt/h/bin:$PATH\n");
    write("etc/environment.d/x.conf", "PATH=/opt/i/bin:${PATH}\n");
    write(
        "usr/share/omarchy/default/hypr/envs.lua",
        "hl.env(\"PATH\", \"/opt/j/bin:/usr/bin\")\n",
    );
    let installs = "home/u/.local/share/mise/installs";
    write(&format!("{installs}/node/22.1.0/bin/node"), "node");
    write(&format!("{installs}/node/22.1.0/bin/sudo"), "odd");
    write(&format!("{installs}/tool/latest/tool"), "tool");
    write("usr/bin/node", "system");
    write("usr/bin/sudo", "system");
    for directory in ["a", "b", "c", "d", "e", "f", "g"] {
        fs::create_dir_all(root.join(format!("home/u/{directory}/bin"))).unwrap();
    }
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: Some("home/u"),
        index: &index,
        origin: Origin::System,
    };
    // A home is its user's, whoever runs the test.
    if !hand_to_a_user(&root.join("home")) {
        return;
    }
    let found = search(&scope);
    for directory in ["a", "b", "c", "d", "e", "f", "g"] {
        let directory = format!("home/u/{directory}/bin");
        assert!(found.shadowing.contains(&directory), "{directory}");
    }
    let at = |directory: &str| {
        found
            .directories
            .iter()
            .position(|known| known == directory)
    };
    let system = at("usr/bin").unwrap();
    for directory in ["opt/h/bin", "opt/i/bin", "opt/j/bin"] {
        assert!(at(directory).is_some_and(|at| at < system), "{directory}");
    }
    // What mise installed is ahead in a shell it is turned on for.
    let node = format!("{installs}/node/22.1.0/bin");
    assert!(found.shadowing.contains(&node), "{:?}", found.shadowing);
    let (paths, _) = shadowing_programs(&scope, &found);
    assert!(paths.contains(&format!("{node}/node")));
    assert!(found.shadowing.contains(&format!("{installs}/tool/latest")));
    let mut items: Vec<_> = paths
        .into_iter()
        .map(|path| collect::item(&scope, Category::LocalBin, path, None))
        .collect();
    mark(&scope, &found, &mut items);
    let alerts = |name: &str| {
        items
            .iter()
            .find(|item| item.path == format!("{node}/{name}"))
            .map(|item| item.alerts.len())
    };
    assert_eq!(alerts("node"), Some(0));
    assert_eq!(alerts("sudo"), Some(1));
}

#[test]
fn only_the_versions_mise_has_in_use_are_ahead() {
    let dir = TempDir::new("sweep-path-mise");
    let root = dir.path();
    let installs = "home/u/.local/share/mise/installs";
    for version in ["2.1.1", "2.1.2"] {
        let directory = root.join(format!("{installs}/claude/{version}"));
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("claude"), version).unwrap();
    }
    fs::create_dir_all(root.join(format!("{installs}/node/22.1.0/bin"))).unwrap();
    // mise links the version in use under shorter names; the older
    // one kept beside it is on no `PATH`.
    for alias in ["latest", "2"] {
        symlink("./2.1.2", root.join(format!("{installs}/claude/{alias}"))).unwrap();
    }
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: Some("home/u"),
        index: &index,
        origin: Origin::System,
    };
    let directories: Vec<String> = super::mise_directories(&scope, "home/u")
        .into_iter()
        .map(|(directory, _)| directory)
        .collect();
    assert_eq!(
        directories,
        [
            format!("{installs}/claude/2.1.2"),
            // Without links, any version may be the one in use.
            format!("{installs}/node/22.1.0/bin"),
            "home/u/.local/share/mise/shims".to_string(),
        ]
    );
}

#[test]
fn a_start_up_file_that_sets_the_path_from_a_command_says_so() {
    let dir = TempDir::new("sweep-path-opaque");
    let root = dir.path();
    fs::create_dir_all(root.join("home/u")).unwrap();
    fs::write(
        root.join("home/u/.zshrc"),
        "export PATH=$(tool path):$PATH\n",
    )
    .unwrap();
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: Some("home/u"),
        index: &index,
        origin: Origin::System,
    };
    let item = collect::item(&scope, Category::Shell, "home/u/.zshrc".into(), None);
    assert!(
        item.notes
            .iter()
            .any(|note| note.starts_with("line 1 sets PATH in a way Guardian cannot follow")),
        "{:?}",
        item.notes
    );
}

#[test]
fn programs_ahead_of_the_systems_own_are_found_where_the_start_up_files_put_them() {
    let dir = TempDir::new("sweep-path");
    let root = dir.path();
    let write = |path: &str, text: &str| {
        fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
        fs::write(root.join(path), text).unwrap();
    };
    for name in ["sudo", "node", "ls", "mise", "omarchy-menu", "omarchy"] {
        write(&format!("usr/bin/{name}"), "system");
    }
    write("home/u/.bashrc", "export PATH=\"$HOME/tools/bin:$PATH\"\n");
    write("home/u/tools/bin/sudo", "#!/bin/sh\n");
    write("home/u/tools/bin/omarchy", "#!/bin/sh\n");
    write("home/u/tools/bin/ls", "#!/bin/sh\n");
    write("home/u/tools/bin/mine", "#!/bin/sh\n");
    // A version manager's: shims that are links to mise, and what it
    // installed.
    fs::create_dir_all(root.join("home/u/.local/share/mise/shims")).unwrap();
    for name in ["node", "sudo"] {
        symlink(
            "/usr/bin/mise",
            root.join("home/u/.local/share/mise/shims").join(name),
        )
        .unwrap();
    }
    symlink(
        "/home/u/tools/bin/mine",
        root.join("home/u/.local/share/mise/shims/ls"),
    )
    .unwrap();
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: Some("home/u"),
        index: &index,
        origin: Origin::System,
    };
    // A home is its user's, whoever runs the test.
    if !hand_to_a_user(&root.join("home")) {
        return;
    }
    let found = search(&scope);
    assert_eq!(found.directories[0], "home/u/tools/bin");
    assert!(found.shadowing.contains(&"home/u/tools/bin".to_string()));
    assert!(
        found
            .shadowing
            .contains(&"home/u/.local/share/mise/shims".to_string())
    );
    assert_eq!(
        found.directories.last().map(String::as_str),
        Some("usr/bin")
    );

    let (paths, unchecked) = shadowing_programs(&scope, &found);
    assert!(unchecked.is_empty());
    assert_eq!(
        paths,
        [
            "home/u/tools/bin/ls",
            "home/u/tools/bin/omarchy",
            "home/u/tools/bin/sudo",
            "home/u/.local/share/mise/shims/ls",
            "home/u/.local/share/mise/shims/node",
            "home/u/.local/share/mise/shims/sudo",
        ]
    );
    let mut items: Vec<_> = paths
        .into_iter()
        .map(|path| collect::item(&scope, Category::LocalBin, path, None))
        .collect();
    mark(&scope, &found, &mut items);
    let alerted = |path: &str| {
        items
            .iter()
            .find(|item| item.path == path)
            .is_some_and(|item| {
                item.alerts
                    .iter()
                    .any(|(rule, _)| *rule == RuleId::PathHijack)
            })
    };
    // `sudo` is an alert wherever it is, a mise shim or not; `ls` is
    // listed; a shim for `node` is what mise is for.
    assert!(alerted("home/u/tools/bin/sudo"));
    // The bare dispatcher, not only the `omarchy-*` commands.
    assert!(alerted("home/u/tools/bin/omarchy"));
    assert!(alerted("home/u/.local/share/mise/shims/sudo"));
    assert!(!alerted("home/u/tools/bin/ls"));
    assert!(!alerted("home/u/.local/share/mise/shims/node"));
    let node = items
        .iter()
        .find(|item| item.path.ends_with("shims/node"))
        .unwrap();
    assert_eq!(node.tier, Tier::UserBuilt);
    assert!(node.notes.iter().any(|note| note.contains("mise shim")));
    // A link in the shims directory that is not to mise is no shim,
    // though it sits where a version manager keeps its own.
    let ls = items
        .iter()
        .find(|item| item.path.ends_with("shims/ls"))
        .unwrap();
    assert!(!ls.notes.iter().any(|note| note.contains("mise shim")));
}

#[test]
fn a_directory_behind_the_systems_own_takes_no_commands_name() {
    let dir = TempDir::new("sweep-path-behind");
    let root = dir.path();
    let write = |path: &str, text: &str| {
        fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
        fs::write(root.join(path), text).unwrap();
    };
    fs::create_dir_all(root.join("home/u/.local/share/mise/shims")).unwrap();
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = Scope {
        root,
        home: Some("home/u"),
        index: &index,
        origin: Origin::System,
    };
    // A directory a start-up file puts behind the system's own takes
    // no command's name there.
    write("home/u/.bashrc", "export PATH=\"$PATH:$HOME/.local/bin\"\n");
    write("home/u/.local/bin/sudo", "#!/bin/sh\n");
    // A home is its user's, whoever runs the test.
    if !hand_to_a_user(&root.join("home")) {
        return;
    }
    let behind = search(&scope);
    assert!(!behind.shadowing.contains(&"home/u/.local/bin".to_string()));
    assert!(
        behind
            .directories
            .contains(&"home/u/.local/bin".to_string())
    );
    // The directories no `PATH` that was read speaks of stay ahead.
    assert!(
        behind
            .shadowing
            .contains(&"home/u/.local/share/mise/shims".to_string())
    );

    // Nothing but the usual directories without a home.
    let bare = search(&Scope {
        root,
        home: None,
        index: &index,
        origin: Origin::System,
    });
    assert_eq!(
        bare,
        Search {
            directories: crate::sweep::commands::default_search("root"),
            shadowing: Vec::new(),
        }
    );
}

#[test]
fn a_directory_ahead_that_cannot_be_listed_is_said() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new("sweep-path-closed");
    let root = dir.path();
    for file in ["usr/bin/sudo", "home/u/bin/sudo", "home/u/closed/sudo"] {
        let path = root.join(file);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, "x").unwrap();
    }
    fs::write(root.join("home/u/file"), "no directory").unwrap();
    symlink("bin", root.join("home/u/linked")).unwrap();
    let index = PackageIndex::with_foreign(HashSet::new());
    let scope = |origin| Scope {
        root,
        home: Some("home/u"),
        index: &index,
        origin,
    };
    let ahead = |directories: &[&str]| Search {
        directories: Vec::new(),
        shadowing: directories
            .iter()
            .map(|name| format!("home/u/{name}"))
            .collect(),
    };
    let closed = |name: &str| {
        format!(
            "/home/u/{name}: could not be listed; programs ahead of /usr/bin there were not checked"
        )
    };
    // What is there and is no directory to list is said, whoever
    // looks; what is gone since the search saw it is not.
    for origin in [Origin::System, Origin::Root] {
        let (paths, unchecked) =
            shadowing_programs(&scope(origin), &ahead(&["gone", "file", "bin"]));
        assert_eq!(paths, ["home/u/bin/sudo"], "{origin:?}");
        assert_eq!(unchecked, [closed("file")], "{origin:?}");
    }
    // Root follows no link into a directory, and says it did not look.
    let (paths, unchecked) = shadowing_programs(&scope(Origin::Root), &ahead(&["linked"]));
    assert!(paths.is_empty(), "{paths:?}");
    assert_eq!(unchecked, [closed("linked")]);
    let (paths, unchecked) = shadowing_programs(&scope(Origin::System), &ahead(&["linked"]));
    assert_eq!(paths, ["home/u/linked/sudo"]);
    assert!(unchecked.is_empty(), "{unchecked:?}");
    // A directory closed to the reader. Nothing is closed to root, who
    // then lists it like any other.
    let directory = root.join("home/u/closed");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o000)).unwrap();
    let is_closed = fs::read_dir(&directory).is_err();
    let found = shadowing_programs(&scope(Origin::System), &ahead(&["closed"]));
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
    if is_closed {
        assert_eq!(found, (vec![], vec![closed("closed")]));
    } else {
        assert_eq!(found, (vec!["home/u/closed/sudo".to_string()], vec![]));
    }
}
