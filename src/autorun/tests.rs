//! Tests for the auto-run locations.

use std::collections::HashSet;

use super::{
    Category, Kind, SYSTEM, SYSTEM_SWEEP, USER, is_auto_run, is_auto_run_directory, is_reviewed,
    named_words, sweep_only_location, system_location,
};

#[test]
fn auto_run_locations() {
    for path in [
        "usr/share/libalpm/hooks/foo.hook",
        "usr/share/libalpm/scripts/foo",
        "etc/sudoers",
        "etc/sudoers.d/foo",
        "usr/share/polkit-1/rules.d/50-foo.rules",
        "etc/pam.d/foo",
        "usr/lib/systemd/system/multi-user.target.wants/foo.service",
        "usr/lib/systemd/user/default.target.wants/foo.service",
        "usr/lib/systemd/system/foo.service.d/override.conf",
        "etc/systemd/system.conf.d/env.conf",
        "usr/lib/systemd/system-generators/foo",
        "usr/lib/systemd/system-sleep/foo",
        "usr/lib/tmpfiles.d/foo.conf",
        "usr/lib/sysctl.d/50-foo.conf",
        "usr/lib/modules-load.d/foo.conf",
        "usr/lib/initcpio/hooks/foo",
        "usr/lib/kernel/install.d/50-foo.install",
        "etc/NetworkManager/dispatcher.d/foo",
        "usr/lib/udev/rules.d/99-foo.rules",
        "etc/profile.d/foo.sh",
        "etc/profile",
        "etc/bash.bashrc",
        "etc/xdg/autostart/foo.desktop",
        "etc/cron.daily/foo",
        "usr/share/dbus-1/system-services/org.foo.service",
        "usr/share/dbus-1/services/org.foo.service",
        "etc/ld.so.preload",
        "etc/ssh/sshd_config.d/foo.conf",
        "etc/systemd/system-generators/foo",
        "usr/local/lib/systemd/system/multi-user.target.wants/foo.service",
        "usr/local/lib/udev/rules.d/99-foo.rules",
        "etc/crontab",
        "var/spool/cron/root",
        "usr/share/polkit-1/actions/org.foo.policy",
        "etc/doas.conf",
        "etc/gitconfig",
        "etc/ssh/sshrc",
        "etc/makepkg.conf.d/foo.conf",
        "usr/local/bin/sudo",
        // A unit ahead of the system's own stands in for it.
        "usr/local/lib/systemd/system/sshd.service",
        "usr/local/lib/systemd/user/pipewire.service",
        "usr/local/share/systemd/user/pipewire.service",
        "usr/share/systemd/user/pipewire.service",
        "usr/share/uwsm/env.d/20-x",
        "usr/share/uwsm/plugins/hyprland.sh",
        "etc/xdg/uwsm/env",
        "usr/share/nvim/site/plugin/x.lua",
        "usr/share/nvim/site/pack/dist/start/x/plugin/x.vim",
        "usr/share/vim/vimfiles/plugin/x.vim",
        "usr/share/vim/vimfiles/after/plugin/x.vim",
        "usr/share/vim/vimfiles/ftdetect/x.vim",
        "etc/xdg/nvim/sysinit.vim",
        "usr/share/limine-entry-tool.d/10-x.conf",
        "etc/cmdline.d/x.conf",
        "etc/ca-certificates/trust-source/anchors/x.crt",
        "usr/share/ca-certificates/trust-source/x.p11-kit",
        "usr/share/git-core/templates/hooks/post-checkout",
        "usr/share/makepkg/tidy/x.sh",
        "etc/bash_completion.d/x",
        "usr/share/bash-completion/completions/foo",
        "usr/share/zsh/site-functions/_foo",
        "usr/share/fish/vendor_functions.d/ls.fish",
        "etc/skel/.bashrc",
        "etc/skel/.config/hypr/hyprland.conf",
        "etc/skel/.config/autostart/x.desktop",
        "usr/share/pipewire/pipewire.conf.d/x.conf",
        "etc/pipewire/pipewire.conf",
        "etc/chromium/policies/managed/x.json",
        "usr/lib/mozilla/native-messaging-hosts/x.json",
        "usr/lib/firefox/distribution/policies.json",
        "var/spool/atd/a0000101",
    ] {
        assert!(is_auto_run(path), "{path}");
    }
    for path in [
        "usr/bin/foo",
        "usr/lib/systemd/system/foo.service",
        "usr/share/doc/foo/README",
        "usr/share/applications/foo.desktop",
        "usr/lib/systemd/system/a.wants/b/c.service",
        "usr/lib/systemd/system/a.service.d/b/c.conf",
        "etc/sudoers.d/../../usr/bin/x",
        // Read once a file or a command asks for them, not at start.
        "usr/share/vim/vimfiles/autoload/x.vim",
        "usr/share/vim/vimfiles/ftplugin/x.vim",
        "usr/share/nvim/site/pack/dist/opt/x/plugin/x.vim",
        "usr/share/pipewire/pipewire.conf",
        // Only what runs on its own in a new home, not all of it.
        "etc/skel/.local/share/nvim/lazy/x/README.md",
        "etc/skel/.config/app/settings.json",
        // Sweep-only locations are not part of the gate's review.
        "usr/lib/security/pam_x.so",
        "boot/limine.conf",
    ] {
        assert!(!is_auto_run(path), "{path}");
    }
}

#[test]
fn completions_and_the_trust_bundle_are_reviewed_for_other_than_official_packages() {
    for path in [
        "usr/share/bash-completion/completions/foo",
        "usr/share/zsh/site-functions/_foo",
        "usr/share/fish/vendor_completions.d/foo.fish",
        "usr/share/fish/vendor_functions.d/ls.fish",
        "etc/bash_completion.d/foo",
        "usr/share/ca-certificates/trust-source/mozilla.trust.p11-kit",
    ] {
        assert!(is_reviewed(path, false), "{path}");
        assert!(!is_reviewed(path, true), "{path}");
    }
    // Everything else is reviewed whoever ships it.
    for path in [
        "etc/sudoers.d/x",
        "etc/skel/.bashrc",
        "etc/ca-certificates/trust-source/anchors/x.crt",
        "usr/share/vim/vimfiles/plugin/x.vim",
    ] {
        assert!(
            is_reviewed(path, true) && is_reviewed(path, false),
            "{path}"
        );
    }
    assert!(!is_reviewed("usr/bin/foo", false));
}

#[test]
fn sweep_only_locations_are_known_to_the_gate() {
    for (path, category) in [
        ("usr/lib/security/pam_x.so", Category::Pam),
        ("usr/lib/glibc-hwcaps/x86-64-v3/libc.so.6", Category::Linker),
        ("etc/default/limine", Category::Boot),
        ("etc/kernel/cmdline", Category::Boot),
        ("boot/limine.conf", Category::Boot),
    ] {
        assert_eq!(
            sweep_only_location(path).map(|found| found.category),
            Some(category),
            "{path}"
        );
    }
    // What the gate reviews is not also called unreviewed: no
    // sweep-only row lies under a reviewed location.
    for location in SYSTEM_SWEEP {
        let inside = format!("{}x", location.path);
        let path = if location.kind == Kind::File {
            location.path
        } else {
            inside.as_str()
        };
        assert!(!is_auto_run(path), "{}", location.path);
    }
    for reviewed in [
        "etc/ca-certificates/trust-source/anchors/x.crt",
        "usr/lib/firefox/distribution/policies.json",
        "etc/tmux.conf",
        "etc/inputrc",
    ] {
        assert!(sweep_only_location(reviewed).is_none(), "{reviewed}");
        assert!(is_reviewed(reviewed, false), "{reviewed}");
    }
    assert!(sweep_only_location("usr/lib/libc.so.6").is_none());
    assert!(sweep_only_location("usr/lib/security/../x").is_none());
}

#[test]
fn locations_are_relative_unique_and_categorised() {
    let mut seen = HashSet::new();
    for location in SYSTEM.iter().chain(SYSTEM_SWEEP).chain(USER) {
        assert!(!location.path.starts_with('/'), "{}", location.path);
        assert_eq!(
            location.path.ends_with('/'),
            !matches!(location.kind, Kind::File | Kind::Glob),
            "{}",
            location.path
        );
        assert_eq!(
            location.path.contains('*'),
            location.kind == Kind::Glob,
            "{}",
            location.path
        );
        assert!(seen.insert(location.path), "{}", location.path);
        assert!(!location.category.label().is_empty());
        assert!(!location.category.when().is_empty());
    }
    let pth = SYSTEM
        .iter()
        .find(|location| location.path.ends_with("*.pth"))
        .unwrap();
    assert!(pth.contains("usr/lib/python3.13/site-packages/evil.pth"));
    assert!(!pth.contains("usr/lib/python3.13/site-packages/pkg/evil.pth"));
    assert!(!pth.contains("usr/lib/python3.13/site-packages/evil.py"));
    for category in Category::ALL {
        assert_eq!(Category::from_name(category.name()), Some(category));
    }
    assert_eq!(
        system_location("etc/udev/rules.d/99-x.rules").map(|found| found.category),
        Some(Category::Udev)
    );
    assert_eq!(
        system_location("usr/lib/systemd/system-generators/x").map(|found| found.category),
        Some(Category::SystemdGenerator)
    );
}

#[test]
fn a_directory_of_auto_run_files_is_told_from_a_file_in_one() {
    for directory in [
        "etc/cron.d",
        "etc/systemd/system-sleep",
        "usr/share/libalpm",
        "usr/share/libalpm/hooks",
        "usr/lib/systemd/system/multi-user.target.wants",
        "usr/lib/systemd/system/foo.service.d",
        "etc/systemd/system.conf.d",
        "usr/local/bin",
        "etc/systemd/system/multi-user.target.wants",
        "etc/systemd/system/foo.service.d",
        "etc/systemd/user/default.target.requires",
    ] {
        assert!(is_auto_run_directory(directory), "{directory}");
    }
    for other in [
        "etc/sudoers.d/out",
        "etc/cron.d/job",
        "usr/lib/systemd/system/foo.service",
        "usr/lib/systemd/system/multi-user.target.wants/foo.service",
        "usr/share/doc",
        "etc/systemd/system/display-manager.service",
        "etc/cron.d/jobs.d",
        "etc/sudoers",
        "lib",
    ] {
        assert!(!is_auto_run_directory(other), "{other}");
    }
    let alias = super::is_alias_of_reviewed_directory;
    assert!(alias("etc/xdg/systemd/user", "etc/systemd/user"));
    assert!(alias("etc/cron.daily", "etc/cron.weekly"));
    // Below a catalogued directory may be a link elsewhere.
    assert!(!alias("etc/xdg/systemd/user", "etc/systemd/user/sub"));
    assert!(!alias("etc/cron.d", "etc/cron.daily/sub"));
    // Another kind of file, a directory that is not all auto-run, a
    // directory above one, or somewhere else entirely.
    assert!(!alias("etc/sudoers.d", "usr/local/bin"));
    assert!(!alias("etc/cron.d", "usr/local/bin"));
    assert!(!alias("etc/xdg/systemd/user", "usr/lib/systemd/system"));
    assert!(!alias("etc/xdg/systemd", "etc/systemd/user"));
    assert!(!alias("etc/cron.d", "usr/share/x/sleep"));
    assert!(!alias("etc/cron.d", "etc"));
}

#[test]
fn every_word_of_a_line_may_name_a_file() {
    let words = |text: &'static str| named_words(text).collect::<Vec<_>>();
    // A program, with systemd's prefixes, and an interpreter's script.
    assert_eq!(
        words("ExecStartPre=-/usr/lib/foo/pre\nExec = /usr/bin/sh /usr/share/pkg/run.sh --all\n"),
        [
            "ExecStartPre",
            "-/usr/lib/foo/pre",
            "Exec",
            "/usr/bin/sh",
            "/usr/share/pkg/run.sh",
            "--all"
        ]
    );
    // Quotes, a variable before a path, a sourced file, a udev rule
    // and a cron line.
    assert_eq!(
        words("post_install() { \"${pkgdir}/usr/lib/pkg/setup.sh\"; . /usr/share/pkg/env.sh; }"),
        [
            "post_install",
            "pkgdir",
            "/usr/lib/pkg/setup.sh",
            ".",
            "/usr/share/pkg/env.sh"
        ]
    );
    assert_eq!(
        words("ACTION==\"add\", RUN+=\"/usr/lib/pkg/plug %k\"\n"),
        ["ACTION", "add", "RUN+", "/usr/lib/pkg/plug", "%k"]
    );
    assert_eq!(
        words("*/5 * * * * root python3 /usr/lib/pkg/x.py"),
        ["/5", "root", "python3", "/usr/lib/pkg/x.py"]
    );
}
