//! Tests for `integrations`.

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

use super::edit::{HYPR_MARKER, INTERCEPTOR_MARKER, with_menu_entries, without_interceptor};
use super::{
    HYPR_LINE, INTERCEPTOR_LINE, Integration, MENU_ENTRY, Part, Paths, SESSION_ENV, State, Step,
    THEME_OVERRIDES, WRAPPED,
};
use crate::test_support::TempDir;

fn paths(dir: &TempDir) -> Paths {
    let root = dir.path();
    fs::create_dir_all(root.join("share")).unwrap();
    fs::create_dir_all(root.join("omarchy")).unwrap();
    fs::write(root.join("share/guardian.hook"), "[Trigger]\n").unwrap();
    fs::write(root.join("yay"), "").unwrap();
    fs::write(root.join("installer"), "").unwrap();
    Paths {
        hook_source: root.join("share/guardian.hook"),
        hook_target: root.join("hooks/guardian.hook"),
        yay: root.join("yay"),
        yay_config: root.join("yay.json"),
        interceptor_installer: root.join("installer"),
        bashrc: root.join("bashrc"),
        omarchy: root.join("omarchy"),
        menu: root.join("menu/omarchy-menu.jsonc"),
        widget_source: root.join("share/bar-widget"),
        widget_target: root.join("plugins/omarchy-guardian"),
        shell_config: root.join("shell.json"),
        waybar_config: root.join("waybar/config"),
        waybar_style: root.join("waybar/style.css"),
        opencode_missing: false,
        sweep_timer: root.join("units/omarchy-guardian-sweep.timer"),
        sweep_timer_link: root.join("user-wants/omarchy-guardian-sweep.timer"),
        sweep_root_timer: root.join("units/omarchy-guardian-sweep-collect.timer"),
        sweep_root_timer_link: root.join("system-wants/omarchy-guardian-sweep-collect.timer"),
        sweep_consent: None,
        sweep_group: Some("u".into()),
        sweep_overrides: Vec::new(),
        login_shell: Some("bash".into()),
        makepkg_gate: root.join("guardian-makepkg"),
        owner: std::os::unix::fs::MetadataExt::uid(&fs::metadata(root).unwrap()),
        system_bin: root.join("bin"),
        paru_config: root.join("paru.conf"),
        shell_startup: vec![root.join("bashrc"), root.join("zshrc")],
        path_dirs: Vec::new(),
        manager_path: None,
        wrappers: root.join("wrappers"),
        session_env: root.join("uwsm/env.d/90-omarchy-guardian"),
        hypr_config: root.join("hypr/hyprland.lua"),
        hypr_path: root.join("hyprland-path.lua"),
    }
}

#[test]
fn the_system_sweep_needs_its_timer_and_an_answer_about_root() {
    use crate::config::model::RootConsent;
    let dir = TempDir::new("integrations-sweep");
    let mut paths = paths(&dir);
    assert!(matches!(
        paths.state(Integration::SystemSweep),
        State::Unavailable(_)
    ));
    fs::create_dir_all(dir.path().join("units")).unwrap();
    fs::write(&paths.sweep_timer, "").unwrap();
    fs::write(&paths.sweep_root_timer, "").unwrap();
    assert_eq!(paths.state(Integration::SystemSweep), State::Off);
    let plan = paths.plan(Integration::SystemSweep, &State::Off).unwrap();
    // The question comes before the daily sweep starts.
    assert_eq!(plan.steps[0], Step::AskSweepRoot);
    assert!(matches!(&plan.steps[1], Step::Command(argv) if argv.contains(&"--user".to_string())));

    fs::create_dir_all(paths.sweep_timer_link.parent().unwrap()).unwrap();
    fs::write(&paths.sweep_timer_link, "").unwrap();
    assert!(matches!(
        paths.state(Integration::SystemSweep),
        State::Partial(_)
    ));
    // What stands in for one of the sweep's units (a unit file of its
    // name, a drop-in: `sweep::own` finds them) is named, whatever it
    // holds.
    paths.sweep_overrides = vec![
        "home/u/.config/systemd/user/omarchy-guardian-sweep.service.d/home.conf".into(),
        "home/u/.config/systemd/user.control/omarchy-guardian-sweep.timer".into(),
    ];
    let state = paths.state(Integration::SystemSweep);
    assert!(
        matches!(&state, State::Partial(detail) if detail.starts_with(
            "/home/u/.config/systemd/user/omarchy-guardian-sweep.service.d/home.conf and 1 more overrides or masks"
        )),
        "{state:?}"
    );
    paths.sweep_overrides.clear();

    paths.sweep_consent = Some(RootConsent::Declined);
    let state = paths.state(Integration::SystemSweep);
    assert!(matches!(&state, State::Partial(detail) if detail.contains("declined")));
    assert_eq!(
        paths.plan(Integration::SystemSweep, &state).unwrap().steps,
        [Step::AskSweepRoot]
    );

    paths.sweep_consent = Some(RootConsent::Allowed);
    let state = paths.state(Integration::SystemSweep);
    let steps = paths.plan(Integration::SystemSweep, &state).unwrap().steps;
    assert!(matches!(&steps[..], [Step::Command(argv)] if argv.iter().any(|arg| arg == "enable")));
    fs::create_dir_all(paths.sweep_root_timer_link.parent().unwrap()).unwrap();
    fs::write(&paths.sweep_root_timer_link, "").unwrap();
    assert_eq!(paths.state(Integration::SystemSweep), State::On);
    // Off disables both timers and keeps the answer.
    let off = paths
        .plan(Integration::SystemSweep, &State::On)
        .unwrap()
        .steps;
    assert_eq!(off.len(), 2);
    assert!(!off.contains(&Step::AskSweepRoot));
}

#[test]
fn hook_state_distinguishes_the_packaged_link() {
    let dir = TempDir::new("integrations-hook");
    let paths = paths(&dir);
    assert_eq!(paths.state(Integration::PacmanHook), State::Off);

    fs::create_dir_all(dir.path().join("hooks")).unwrap();
    symlink(&paths.hook_source, &paths.hook_target).unwrap();
    assert_eq!(paths.state(Integration::PacmanHook), State::On);
    // Off takes the link away and nothing else: the hook pacman always
    // loads from libalpm's own directory stays with the package, and
    // lets every transaction through once the link is gone.
    let plan = paths.plan(Integration::PacmanHook, &State::On).unwrap();
    let link = paths.hook_target.display().to_string();
    assert!(
        matches!(&plan.steps[..], [Step::Command(argv)]
            if argv[1..] == ["/usr/bin/rm".to_string(), "-f".to_string(), link.clone()]),
        "{plan:?}"
    );
    // The packaged hook file alone is not the hook turned on.
    fs::remove_file(&paths.hook_target).unwrap();
    assert!(paths.hook_source.exists());
    assert_eq!(paths.state(Integration::PacmanHook), State::Off);
    symlink(&paths.hook_source, &paths.hook_target).unwrap();

    fs::remove_file(&paths.hook_target).unwrap();
    fs::write(&paths.hook_target, "[Trigger]\n").unwrap();
    assert!(matches!(
        paths.state(Integration::PacmanHook),
        State::Foreign(_)
    ));

    fs::remove_file(&paths.hook_source).unwrap();
    assert!(matches!(
        paths.state(Integration::PacmanHook),
        State::Unavailable(_)
    ));
    assert_eq!(
        paths.plan(
            Integration::PacmanHook,
            &paths.state(Integration::PacmanHook)
        ),
        None
    );
}

#[test]
fn aur_gate_state_reads_the_yay_config() {
    let dir = TempDir::new("integrations-yay");
    let paths = paths(&dir);
    assert_eq!(paths.state(Integration::AurGate), State::Off);
    let configure = |makepkg: &str| {
        fs::write(
            &paths.yay_config,
            format!("{{\"makepkgbin\": \"{makepkg}\"}}"),
        )
        .unwrap();
    };
    let gate = paths.makepkg_gate.display().to_string();
    fs::write(&paths.makepkg_gate, "").unwrap();
    configure(&gate);
    assert_eq!(paths.state(Integration::AurGate), State::On);
    let plan = paths.plan(Integration::AurGate, &State::On).unwrap();
    assert!(matches!(&plan.steps[..], [Step::Command(argv)] if argv[2] == "makepkg"));
    let plan = paths.plan(Integration::AurGate, &State::Off).unwrap();
    assert!(matches!(&plan.steps[..], [Step::Command(argv)] if argv[2] == gate));

    // makepkg itself is off; any other program is not Guardian's gate.
    configure("/usr/bin/makepkg");
    assert_eq!(paths.state(Integration::AurGate), State::Off);
    configure("/tmp/guardian-makepkg");
    let state = paths.state(Integration::AurGate);
    assert!(matches!(&state, State::Partial(why) if why.contains("not Guardian's gate")));
}

#[test]
fn a_configured_aur_gate_that_is_bypassed_is_not_on() {
    let dir = TempDir::new("integrations-yay-bypass");
    let mut paths = paths(&dir);
    let gate = paths.makepkg_gate.display().to_string();
    fs::write(&paths.yay_config, format!("{{\"makepkgbin\": \"{gate}\"}}")).unwrap();
    let partial = |paths: &Paths, expected: &str| {
        let state = paths.state(Integration::AurGate);
        assert!(
            matches!(&state, State::Partial(why) if why.contains(expected)),
            "{state:?}"
        );
    };

    // The shim is not there, or is not one only its owner can write.
    partial(&paths, "is missing");
    fs::write(&paths.makepkg_gate, "").unwrap();
    fs::set_permissions(&paths.makepkg_gate, fs::Permissions::from_mode(0o666)).unwrap();
    partial(&paths, "not root's alone to write");
    fs::set_permissions(&paths.makepkg_gate, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(paths.state(Integration::AurGate), State::On);
    // Owned by somebody else than the installer.
    paths.owner += 1;
    partial(&paths, "not root's alone to write");
    paths.owner -= 1;

    // Another yay earlier on PATH.
    let front = dir.path().join("front");
    fs::create_dir_all(&front).unwrap();
    paths.path_dirs = vec![front.clone(), dir.path().to_path_buf()];
    assert_eq!(paths.state(Integration::AurGate), State::On);
    fs::write(front.join("yay"), "").unwrap();
    partial(&paths, "another yay comes first on PATH");
    fs::remove_file(front.join("yay")).unwrap();

    // An alias or function in front of it that names its own makepkg.
    fs::write(
        dir.path().join("zshrc"),
        "alias yay='yay --makepkg /usr/bin/makepkg'\n",
    )
    .unwrap();
    partial(&paths, "an alias or function named yay");
    fs::write(dir.path().join("zshrc"), "alias yay='yay --noconfirm'\n").unwrap();
    assert_eq!(paths.state(Integration::AurGate), State::On);
}

#[test]
fn other_aur_helpers_without_the_gate_are_issues() {
    let dir = TempDir::new("integrations-helpers");
    let paths = paths(&dir);
    assert!(paths.helper_issues().is_empty());
    fs::create_dir_all(&paths.system_bin).unwrap();
    fs::write(paths.system_bin.join("paru"), "").unwrap();
    fs::write(paths.system_bin.join("pikaur"), "").unwrap();
    let issues = paths.helper_issues();
    assert_eq!(issues.len(), 2, "{issues:?}");
    assert!(issues[0].starts_with("paru builds AUR packages without Guardian"));
    assert_eq!(issues[1], "pikaur builds AUR packages without Guardian");

    // paru pointed at the gate by hand counts, in its own section only.
    let gate = paths.makepkg_gate.display();
    fs::write(&paths.paru_config, format!("[options]\nMakepkg = {gate}\n")).unwrap();
    assert_eq!(paths.helper_issues().len(), 2);
    fs::write(
        &paths.paru_config,
        format!("[options]\nBottomUp\n[bin]\nMakepkg = {gate}\n"),
    )
    .unwrap();
    assert_eq!(paths.helper_issues().len(), 1);
    fs::write(
        dir.path().join("bashrc"),
        "paru() {\n  command paru --makepkg makepkg \"$@\"\n}\n",
    )
    .unwrap();
    assert!(paths.helper_issues()[0].contains("an alias or function named paru"));
}

#[test]
fn an_interceptor_line_that_cannot_take_effect_is_partial_and_repaired_at_the_end() {
    let dir = TempDir::new("integrations-bashrc-broken");
    let paths = paths(&dir);
    for bashrc in [
        ": source /usr/lib/omarchy-guardian/omarchy-bash-interceptor.sh\n".to_string(),
        format!("{INTERCEPTOR_LINE}\nunset -f omarchy\n"),
        format!("never() {{\n{INTERCEPTOR_LINE}\n}}\n"),
    ] {
        fs::write(&paths.bashrc, &bashrc).unwrap();
        let state = paths.state(Integration::ThemeInterceptor);
        assert!(
            matches!(&state, State::Partial(why) if why.starts_with("not effective in Bash")),
            "{state:?} for {bashrc}"
        );
        // Taken out, then written again by the installer, at the end.
        let steps = paths
            .plan(Integration::ThemeInterceptor, &state)
            .unwrap()
            .steps;
        assert_eq!(steps[0], Step::RemoveInterceptor);
        assert!(matches!(&steps[1], Step::Command(_)), "{steps:?}");
        // Off takes it out too.
        let off = paths
            .plan(Integration::ThemeInterceptor, &State::On)
            .unwrap()
            .steps;
        assert!(off.contains(&Step::RemoveInterceptor));
    }
}

#[test]
fn a_menu_override_counts_only_when_it_is_the_entry_in_effect() {
    let dir = TempDir::new("integrations-menu-effective");
    let paths = paths(&dir);
    fs::write(&paths.bashrc, format!("{INTERCEPTOR_LINE}\n")).unwrap();
    paths.edit(&Step::AddThemeMenu).unwrap();
    paths.edit(&Step::AddMenuEntry).unwrap();
    assert_eq!(paths.state(Integration::ThemeInterceptor), State::On);
    assert_eq!(paths.state(Integration::MenuEntry), State::On);
    let written = fs::read_to_string(&paths.menu).unwrap();

    // A later entry of the same name wins when the menu reads the file.
    let later = written.replace(
        "\n}\n",
        "\n  \"update.themes\": {\"action\":\"omarchy-theme-update\"},\n  \"setup.guardian\": {\"action\":\"true\"},\n}\n",
    );
    fs::write(&paths.menu, &later).unwrap();
    let state = paths.state(Integration::ThemeInterceptor);
    assert!(
        matches!(&state, State::Partial(why) if why.contains("\"update.themes\" is not Guardian's")),
        "{state:?}"
    );
    assert!(matches!(
        paths.state(Integration::MenuEntry),
        State::Partial(_)
    ));
    // Turning it on writes Guardian's entries anew, after the other.
    for step in paths
        .plan(Integration::ThemeInterceptor, &state)
        .unwrap()
        .steps
    {
        paths.edit(&step).unwrap();
    }
    assert_eq!(paths.state(Integration::ThemeInterceptor), State::On);

    // A file the menu cannot parse is ignored by it, whatever it holds.
    fs::write(&paths.menu, written.replace("\n}\n", "\n  oops\n}\n")).unwrap();
    let state = paths.state(Integration::ThemeInterceptor);
    assert!(
        matches!(&state, State::Partial(why) if why.contains("ignores its user file")),
        "{state:?}"
    );
    assert!(matches!(
        paths.state(Integration::MenuEntry),
        State::Partial(_)
    ));
    // Guardian's path in an entry for something else proves nothing.
    fs::write(
        &paths.menu,
        "{\n  \"x\": {\"action\":\"/usr/lib/omarchy-guardian/guardian-theme install\"},\n}\n",
    )
    .unwrap();
    assert!(matches!(
        paths.state(Integration::ThemeInterceptor),
        State::Partial(why) if why.starts_with("terminal only")
    ));
    assert_eq!(THEME_OVERRIDES.len(), 3);
}

/// A home as `protect` finds it on Omarchy: the packaged wrappers and
/// PATH file, and a Hyprland configuration that loads Omarchy's
/// defaults. Returns the directory standing for Omarchy's own commands.
fn omarchy_session(dir: &TempDir, paths: &Paths) -> std::path::PathBuf {
    fs::create_dir_all(&paths.wrappers).unwrap();
    for name in WRAPPED {
        fs::write(paths.wrappers.join(name), "").unwrap();
    }
    fs::write(&paths.hypr_path, "").unwrap();
    fs::create_dir_all(paths.hypr_config.parent().unwrap()).unwrap();
    fs::write(
        &paths.hypr_config,
        "require(\"default.hypr.omarchy\")\nrequire(\"hypr.autostart\")\n\n-- Add any other personal Hyprland configuration below.\n",
    )
    .unwrap();
    let stock = dir.path().join("stock");
    fs::create_dir_all(&stock).unwrap();
    fs::write(stock.join("omarchy-theme-install"), "").unwrap();
    stock
}

#[test]
fn the_session_path_is_on_only_where_the_wrappers_are_found_first() {
    let dir = TempDir::new("integrations-session");
    let mut paths = paths(&dir);
    assert!(matches!(
        paths.state(Integration::SessionPath),
        State::Unavailable(_)
    ));
    let stock = omarchy_session(&dir, &paths);
    assert_eq!(paths.state(Integration::SessionPath), State::Off);

    let on = paths.plan(Integration::SessionPath, &State::Off).unwrap();
    assert_eq!(on.steps, [Step::AddSessionPath]);
    assert!(on.describe(&paths)[0].contains("add a line to"));
    paths.edit(&Step::AddSessionPath).unwrap();
    assert_eq!(fs::read_to_string(&paths.session_env).unwrap(), SESSION_ENV);
    // The line goes after everything Omarchy's defaults did, and the
    // file as it was is kept.
    let config = fs::read_to_string(&paths.hypr_config).unwrap();
    assert!(
        config.ends_with(&format!("below.\n\n{HYPR_MARKER}\n{HYPR_LINE}\n")),
        "{config}"
    );
    let backup = paths.hypr_config.with_extension("lua.guardian-bak");
    assert!(!fs::read_to_string(&backup).unwrap().contains("Guardian"));

    // Written, and as Omarchy's own PATH line leaves the session until
    // the next login: its commands first. That is not on.
    paths.manager_path = Some(vec![stock.clone(), paths.wrappers.clone()]);
    let state = paths.state(Integration::SessionPath);
    assert!(
        matches!(&state, State::Partial(why)
            if why.contains("not in effect for the session") && why.contains("comes before it on PATH")),
        "{state:?}"
    );
    paths.login_shell = Some("zsh".into());
    assert!(paths.theme_caveat().is_some());
    // After it: Guardian's first, then Omarchy's.
    paths.manager_path = Some(vec![
        paths.wrappers.clone(),
        stock.clone(),
        dir.path().join("tools"),
    ]);
    assert_eq!(paths.state(Integration::SessionPath), State::On);
    // In another shell the Bash interceptor is not needed for it.
    assert_eq!(paths.theme_caveat(), None);
    // Turning it on again changes nothing.
    paths.edit(&Step::AddSessionPath).unwrap();
    assert_eq!(fs::read_to_string(&paths.hypr_config).unwrap(), config);

    // Not on the session's PATH at all.
    paths.manager_path = Some(vec![stock.clone()]);
    let state = paths.state(Integration::SessionPath);
    assert!(
        matches!(&state, State::Partial(why) if why.contains("is not on PATH")),
        "{state:?}"
    );
    paths.manager_path = Some(vec![paths.wrappers.clone(), stock.clone()]);

    // A wrapper, or the PATH file, anyone can rewrite is no gate.
    for file in [paths.wrappers.join("omarchy"), paths.hypr_path.clone()] {
        fs::set_permissions(&file, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            paths.state(Integration::SessionPath),
            State::Partial(why) if why.contains("not to be trusted")
        ));
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
    }

    // A line added to the session file, or the line changed, is not
    // Guardian's file.
    fs::write(
        &paths.session_env,
        format!("{SESSION_ENV}export PATH=/tmp:$PATH\n"),
    )
    .unwrap();
    let state = paths.state(Integration::SessionPath);
    assert!(
        matches!(&state, State::Partial(why) if why.contains("half set up")),
        "{state:?}"
    );
    paths.edit(&Step::AddSessionPath).unwrap();
    assert_eq!(paths.state(Integration::SessionPath), State::On);

    // Off removes Guardian's file and its line, and only those.
    paths.edit(&Step::RemoveSessionPath).unwrap();
    assert!(!paths.session_env.exists());
    assert_eq!(
        fs::read_to_string(&paths.hypr_config).unwrap(),
        fs::read_to_string(&backup).unwrap()
    );
    assert_eq!(paths.state(Integration::SessionPath), State::Off);
    fs::write(&paths.session_env, "export X=1\n").unwrap();
    paths.edit(&Step::RemoveSessionPath).unwrap();
    assert!(paths.session_env.exists());
}

#[test]
fn guardians_hyprland_line_counts_only_where_it_runs_last() {
    let dir = TempDir::new("integrations-hypr");
    let mut paths = paths(&dir);
    let stock = omarchy_session(&dir, &paths);
    paths.manager_path = Some(vec![paths.wrappers.clone(), stock]);
    paths.edit(&Step::AddSessionPath).unwrap();
    assert_eq!(paths.state(Integration::SessionPath), State::On);
    let written = fs::read_to_string(&paths.hypr_config).unwrap();

    // The session file alone: Omarchy's `envs.lua` puts its own
    // commands first again, which is the state that never went calm.
    fs::write(&paths.hypr_config, "require(\"default.hypr.omarchy\")\n").unwrap();
    let state = paths.state(Integration::SessionPath);
    assert!(
        matches!(&state, State::Partial(why) if why.contains("Omarchy's own PATH line")),
        "{state:?}"
    );
    // Turning it on is the way out of every partial state.
    let plan = paths.plan(Integration::SessionPath, &state).unwrap();
    assert_eq!(plan.steps, [Step::AddSessionPath]);

    // Commented out, in a block that does not run, or undone below.
    for broken in [
        format!("if false then\n{HYPR_LINE}\nend\n"),
        format!("--[[\n{HYPR_LINE}\n]]\n"),
        format!("{HYPR_LINE}\nhl.env(\"PATH\", \"/usr/share/omarchy/bin:/usr/bin\")\n"),
    ] {
        fs::write(&paths.hypr_config, &broken).unwrap();
        let state = paths.state(Integration::SessionPath);
        assert!(
            matches!(&state, State::Partial(why) if why.contains("not effective")),
            "{state:?} for {broken}"
        );
        // Written anew at the end, once.
        paths.edit(&Step::AddSessionPath).unwrap();
        let repaired = fs::read_to_string(&paths.hypr_config).unwrap();
        assert_eq!(repaired.matches(HYPR_LINE).count(), 1, "{repaired}");
        assert!(repaired.ends_with(&format!("{HYPR_MARKER}\n{HYPR_LINE}\n")));
    }
    // What a user adds below Guardian's line leaves it in effect.
    fs::write(
        &paths.hypr_config,
        format!("{written}o.window(\"qemu\", {{ workspace = \"5\" }})\n"),
    )
    .unwrap();
    assert_eq!(paths.state(Integration::SessionPath), State::On);

    // Without a Hyprland Lua configuration nothing reorders PATH: the
    // session file is the whole of it, and no configuration is made.
    fs::remove_file(&paths.hypr_config).unwrap();
    assert_eq!(paths.state(Integration::SessionPath), State::On);
    paths.edit(&Step::AddSessionPath).unwrap();
    assert!(!paths.hypr_config.exists());
    let plan = paths.plan(Integration::SessionPath, &State::Off).unwrap();
    assert!(!plan.describe(&paths)[0].contains("add a line"));
}

#[test]
fn two_callers_with_different_paths_read_the_same_state() {
    let dir = TempDir::new("integrations-callers");
    let mut bar = paths(&dir);
    let stock = omarchy_session(&dir, &bar);
    let gate = bar.makepkg_gate.display().to_string();
    fs::write(&bar.yay_config, format!("{{\"makepkgbin\": \"{gate}\"}}")).unwrap();
    fs::write(&bar.makepkg_gate, "").unwrap();
    bar.edit(&Step::AddSessionPath).unwrap();
    // Another yay, and Omarchy's commands, in directories only the
    // second caller's shell has in front.
    let front = dir.path().join("front");
    fs::create_dir_all(&front).unwrap();
    fs::write(front.join("yay"), "").unwrap();
    bar.manager_path = Some(vec![bar.wrappers.clone(), stock.clone()]);
    bar.path_dirs = vec![bar.wrappers.clone(), stock.clone()];
    let mut remote = bar.clone();
    remote.path_dirs = vec![front, stock.clone()];

    // Both read the session's PATH, so both read the same.
    for integration in [Integration::SessionPath, Integration::AurGate] {
        assert_eq!(bar.state(integration), State::On);
        assert_eq!(remote.state(integration), State::On);
    }
    assert!(bar.unsettled().is_empty() && remote.unsettled().is_empty());
    // The second caller is told about its own shell, beside the gate.
    assert_eq!(bar.path_caveat(), None);
    assert!(
        remote
            .path_caveat()
            .is_some_and(|caveat| caveat.contains("is not on PATH"))
    );

    // With no session to ask, each reads its own PATH, and says that
    // what it read is not to be put on record.
    bar.manager_path = None;
    remote.manager_path = None;
    assert_eq!(bar.state(Integration::SessionPath), State::On);
    assert!(matches!(
        remote.state(Integration::SessionPath),
        State::Partial(why) if why.contains("this shell")
    ));
    assert!(matches!(
        remote.state(Integration::AurGate),
        State::Partial(why) if why.contains("another yay")
    ));
    assert_eq!(
        remote.unsettled(),
        [Integration::AurGate, Integration::SessionPath]
    );
    assert_eq!(remote.path_caveat(), None);
}

#[test]
fn what_has_nothing_to_guard_on_this_machine_is_not_a_problem() {
    use crate::status::gate_issue;
    let dir = TempDir::new("integrations-applies");
    let paths = paths(&dir);
    fs::create_dir_all(&paths.wrappers).unwrap();
    // Plain Arch: no yay, no Omarchy.
    fs::remove_file(&paths.yay).unwrap();
    fs::remove_dir_all(&paths.omarchy).unwrap();
    for integration in [
        Integration::AurGate,
        Integration::SessionPath,
        Integration::MenuEntry,
    ] {
        let state = paths.state(integration);
        assert!(matches!(state, State::Unavailable(_)), "{state:?}");
        assert!(!paths.applies(integration));
        assert_eq!(gate_issue(&paths, integration, &state), None);
    }
    // A gate that does apply and cannot be there is protection missing.
    fs::remove_file(&paths.hook_source).unwrap();
    let state = paths.state(Integration::PacmanHook);
    assert!(
        gate_issue(&paths, Integration::PacmanHook, &state)
            .is_some_and(|issue| issue.contains("is unavailable"))
    );
    // With Omarchy there, wrappers the package did not bring are one too.
    fs::create_dir_all(&paths.omarchy).unwrap();
    fs::remove_dir_all(&paths.wrappers).unwrap();
    let state = paths.state(Integration::SessionPath);
    assert!(gate_issue(&paths, Integration::SessionPath, &state).is_some());
    assert!(
        gate_issue(&paths, Integration::SessionPath, &State::Off)
            .is_some_and(|issue| issue.contains("not fully on"))
    );
    assert_eq!(
        gate_issue(&paths, Integration::SessionPath, &State::On),
        None
    );
}

#[test]
fn the_file_as_it_was_before_the_first_edit_is_kept_once() {
    let dir = TempDir::new("integrations-backup");
    let paths = paths(&dir);
    let original = format!("alias ll='ls -l'\n\n{INTERCEPTOR_MARKER}\n{INTERCEPTOR_LINE}\n");
    fs::write(&paths.bashrc, &original).unwrap();
    paths.edit(&Step::RemoveInterceptor).unwrap();
    let backup = dir.path().join("bashrc.guardian-bak");
    assert_eq!(fs::read_to_string(&backup).unwrap(), original);
    assert_eq!(
        fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
        0o600
    );

    // A later edit leaves the first copy alone.
    fs::write(&paths.bashrc, format!("export X=1\n{INTERCEPTOR_LINE}\n")).unwrap();
    paths.edit(&Step::RemoveInterceptor).unwrap();
    assert_eq!(fs::read_to_string(&backup).unwrap(), original);
    assert_eq!(fs::read_to_string(&paths.bashrc).unwrap(), "export X=1\n");

    // A file Guardian makes itself has nothing to keep.
    paths.edit(&Step::AddMenuEntry).unwrap();
    let menu_backup = dir.path().join("menu/omarchy-menu.jsonc.guardian-bak");
    assert!(!menu_backup.exists());
    paths.edit(&Step::AddThemeMenu).unwrap();
    assert!(
        fs::read_to_string(&menu_backup)
            .unwrap()
            .contains("setup.guardian")
    );
}

#[test]
fn interceptor_lines_are_removed_exactly() {
    let bashrc = format!(
        "alias ll='ls -l'\n\n{INTERCEPTOR_MARKER}\n[[ -r /usr/lib/omarchy-guardian/omarchy-bash-interceptor.sh ]] && source /usr/lib/omarchy-guardian/omarchy-bash-interceptor.sh\nexport X=1\n"
    );
    assert_eq!(
        without_interceptor(&bashrc),
        "alias ll='ls -l'\nexport X=1\n"
    );

    let dir = TempDir::new("integrations-bashrc");
    let paths = paths(&dir);
    fs::write(&paths.bashrc, &bashrc).unwrap();
    // Bash alone leaves the Omarchy menu's theme items ungated.
    assert!(matches!(
        paths.state(Integration::ThemeInterceptor),
        State::Partial(reason) if reason.starts_with("terminal only")
    ));
    paths.edit(&Step::RemoveInterceptor).unwrap();
    assert_eq!(paths.state(Integration::ThemeInterceptor), State::Off);
}

#[test]
fn menu_entry_is_added_and_removed() {
    let template = "{\n  // Comments\n  // \"personal\": {\"icon\":\"\"},\n}\n";
    let added = with_menu_entries(template, &[MENU_ENTRY]).unwrap();
    assert!(added.ends_with(&format!("  {MENU_ENTRY}\n}}\n")));

    let without_comma = "{\n  \"a\": {\"label\":\"A\"}\n}\n";
    assert!(
        with_menu_entries(without_comma, &[MENU_ENTRY])
            .unwrap()
            .contains("\"a\": {\"label\":\"A\"},\n")
    );
    assert!(with_menu_entries("{ \"a\": 1 }", &[MENU_ENTRY]).is_err());

    let dir = TempDir::new("integrations-menu");
    let paths = paths(&dir);
    assert_eq!(paths.state(Integration::MenuEntry), State::Off);
    paths.edit(&Step::AddMenuEntry).unwrap();
    assert_eq!(paths.state(Integration::MenuEntry), State::On);
    paths.edit(&Step::RemoveMenuEntry).unwrap();
    assert_eq!(paths.state(Integration::MenuEntry), State::Off);
    assert_eq!(fs::read_to_string(&paths.menu).unwrap(), "{\n}\n");
}

#[test]
fn a_hook_without_opencode_installs_it_first_and_counts_as_partial() {
    let dir = TempDir::new("integrations-opencode");
    let mut paths = paths(&dir);
    paths.opencode_missing = true;

    let plan = paths.plan(Integration::PacmanHook, &State::Off).unwrap();
    let commands: Vec<String> = plan
        .steps
        .iter()
        .filter_map(|step| match step {
            Step::Command(argv) => Some(argv.join(" ")),
            _ => None,
        })
        .collect();
    assert_eq!(
        commands[0],
        "/usr/bin/sudo /usr/bin/pacman -S --needed extra/opencode"
    );
    assert_eq!(commands.len(), 3);

    fs::create_dir_all(dir.path().join("hooks")).unwrap();
    symlink(&paths.hook_source, &paths.hook_target).unwrap();
    let state = paths.state(Integration::PacmanHook);
    assert!(matches!(&state, State::Partial(reason) if reason.contains("OpenCode")));
    // Already linked: only OpenCode is missing.
    let plan = paths.plan(Integration::PacmanHook, &state).unwrap();
    assert_eq!(plan.steps.len(), 1);

    paths.opencode_missing = false;
    assert_eq!(paths.state(Integration::PacmanHook), State::On);
}

#[test]
fn the_theme_gate_covers_the_omarchy_menu_too() {
    let dir = TempDir::new("integrations-theme-menu");
    let paths = paths(&dir);
    let own = "{\n  \"install.style.theme\": {\"label\":\"Mine\"},\n}\n";
    fs::create_dir_all(paths.menu.parent().unwrap()).unwrap();
    fs::write(&paths.menu, own).unwrap();

    let plan = paths
        .plan(Integration::ThemeInterceptor, &State::Off)
        .unwrap();
    assert!(plan.steps.contains(&Step::AddThemeMenu), "{plan:?}");
    paths.edit(&Step::AddThemeMenu).unwrap();
    assert!(matches!(
        paths.state(Integration::ThemeInterceptor),
        State::Partial(reason) if reason.starts_with("menu only")
    ));
    let menu = fs::read_to_string(&paths.menu).unwrap();
    assert!(menu.contains("guardian-theme install"), "{menu}");
    assert!(menu.contains("guardian-theme update"), "{menu}");
    assert!(menu.contains("guardian-plugin add"), "{menu}");

    fs::write(
        &paths.bashrc,
        format!("{INTERCEPTOR_MARKER}\n{INTERCEPTOR_LINE}\n"),
    )
    .unwrap();
    assert_eq!(paths.state(Integration::ThemeInterceptor), State::On);

    // In another login shell the Bash interceptor is never read.
    let mut zsh = self::paths(&dir);
    zsh.login_shell = Some("zsh".into());
    assert_eq!(zsh.state(Integration::ThemeInterceptor), State::On);
    assert!(
        zsh.theme_caveat()
            .is_some_and(|caveat| caveat.contains("typed in zsh skip Guardian"))
    );
    assert_eq!(paths.theme_caveat(), None);
    let passwd = "root:x:0:0::/root:/usr/bin/bash\nu:x:1000:1000::/home/u:/usr/bin/zsh\nv:x:1001:1001::/home/v:\n";
    assert_eq!(
        super::shell_of(passwd, 1000).as_deref(),
        Some("/usr/bin/zsh")
    );
    assert_eq!(super::shell_of(passwd, 1001), None);
    assert_eq!(super::shell_of(passwd, 1002), None);

    // Turning it off removes only Guardian's overrides.
    let plan = paths
        .plan(Integration::ThemeInterceptor, &State::On)
        .unwrap();
    for step in &plan.steps {
        paths.edit(step).unwrap();
    }
    assert_eq!(paths.state(Integration::ThemeInterceptor), State::Off);
    assert_eq!(fs::read_to_string(&paths.menu).unwrap(), own);
}

const WAYBAR_CONFIG: &str = "{\n  \"layer\": \"top\",\n  \"modules-left\": [\"custom/omarchy\"],\n  \"modules-right\": [\"network\", \"battery\"],\n  // a comment\n  \"clock\": {}\n}\n";

#[test]
fn the_waybar_module_is_added_and_removed_exactly() {
    let added = super::edit::with_waybar_module(WAYBAR_CONFIG).unwrap();
    assert!(
        added.contains("\"modules-right\": [\"image#omarchy-guardian\", \"network\", \"battery\"]")
    );
    assert_eq!(added.lines().nth(1).unwrap(), super::WAYBAR_DEFINITION);
    assert!(added.contains("// a comment"));
    // Adding twice keeps one copy.
    assert_eq!(super::edit::with_waybar_module(&added).unwrap(), added);
    assert_eq!(super::edit::without_waybar_module(&added), WAYBAR_CONFIG);

    let empty = "{\n  \"modules-right\": [],\n}\n";
    assert!(
        super::edit::with_waybar_module(empty)
            .unwrap()
            .contains("[\"image#omarchy-guardian\"]")
    );
    assert!(super::edit::with_waybar_module("{\n}\n").is_err());

    // An empty list over several lines, or with a comment in it,
    // gets no comma after the module.
    for empty in [
        "{\n  \"modules-right\": [\n  ]\n}\n",
        "{\n  \"modules-right\": [ /* none */ ]\n}\n",
        "{\n  \"modules-right\": [\n    // none\n  ]\n}\n",
    ] {
        let added = super::edit::with_waybar_module(empty).unwrap();
        assert!(!added.contains("guardian\","), "{added}");
        assert!(!super::edit::without_waybar_module(&added).contains("guardian"));
    }
    // One per line: taking it out leaves no comma of its own.
    let listed =
        "{\n  \"modules-right\": [\n    \"image#omarchy-guardian\",\n    \"clock\"\n  ]\n}\n";
    assert!(!super::edit::without_waybar_module(listed).contains(','));
}

#[test]
fn a_line_that_is_commented_out_turns_nothing_on() {
    let dir = TempDir::new("integrations-commented");
    let paths = paths(&dir);
    fs::create_dir_all(paths.menu.parent().unwrap()).unwrap();
    fs::write(&paths.menu, format!("{{\n  // {MENU_ENTRY}\n}}\n")).unwrap();
    assert_eq!(paths.state(Integration::MenuEntry), State::Off);
    // Named only in a comment after something else.
    assert!(!super::names(
        "  \"clock\", // \"image#omarchy-guardian\"",
        super::WAYBAR_MODULE
    ));
    assert!(super::names(
        "  \"image#omarchy-guardian\", // ours",
        super::WAYBAR_MODULE
    ));
    // Slashes inside a string before it start no comment.
    assert!(super::names(
        "  \"x\": \"https://a.test\", \"image#omarchy-guardian\"",
        super::WAYBAR_MODULE
    ));
    // A line that loads the interceptor with no marker above it is
    // taken out all the same.
    let loads = format!("x=1\n[[ -r y ]] && source {}\n", super::INTERCEPTOR_SOURCE);
    assert_eq!(without_interceptor(&loads), "x=1\n");
    // The marker alone, or the line after it commented out.
    for bashrc in [
        format!("{INTERCEPTOR_MARKER}\n"),
        format!(
            "{INTERCEPTOR_MARKER}\n# [[ -r x ]] && source {}\n",
            super::INTERCEPTOR_SOURCE
        ),
    ] {
        fs::write(&paths.bashrc, bashrc).unwrap();
        assert_eq!(paths.theme_parts().0, Part::Off);
    }
    fs::write(
        &paths.bashrc,
        format!("{INTERCEPTOR_MARKER}\n{INTERCEPTOR_LINE}\n"),
    )
    .unwrap();
    assert_eq!(paths.theme_parts().0, Part::On);
}

#[test]
fn a_file_is_replaced_whole_and_a_link_to_it_stays_a_link() {
    let dir = TempDir::new("integrations-replace");
    let real = dir.path().join("real.conf");
    let link = dir.path().join("link.conf");
    fs::write(&real, "old\n").unwrap();
    symlink(&real, &link).unwrap();
    super::edit::replace_file(&link, "new\n").unwrap();
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_to_string(&real).unwrap(), "new\n");
    // Nothing is left beside it.
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    // Its mode stays what it was.
    fs::set_permissions(&real, fs::Permissions::from_mode(0o640)).unwrap();
    super::edit::replace_file(&real, "newer\n").unwrap();
    assert_eq!(
        fs::metadata(&real).unwrap().permissions().mode() & 0o777,
        0o640
    );
    // A link that leads nowhere yet gets its file.
    let dangling = dir.path().join("dangling.conf");
    symlink(dir.path().join("made.conf"), &dangling).unwrap();
    super::edit::replace_file(&dangling, "made\n").unwrap();
    assert_eq!(
        fs::read_to_string(dir.path().join("made.conf")).unwrap(),
        "made\n"
    );
}

#[test]
fn the_waybar_integration_round_trips_config_and_style() {
    let dir = TempDir::new("integrations-waybar");
    let paths = paths(&dir);
    assert!(matches!(
        paths.state(Integration::WaybarModule),
        State::Unavailable(_)
    ));
    fs::create_dir_all(dir.path().join("waybar")).unwrap();
    fs::write(&paths.waybar_config, WAYBAR_CONFIG).unwrap();
    let style = "* { font-size: 12px; }\n\n#network,\n#battery {\n  padding: 0 9px;\n  border-radius: 11px;\n}\n\n#battery.warning { color: red; }\n";
    fs::write(&paths.waybar_style, style).unwrap();
    assert_eq!(paths.state(Integration::WaybarModule), State::Off);

    let on = paths.plan(Integration::WaybarModule, &State::Off).unwrap();
    for step in &on.steps {
        paths.edit(step).unwrap();
    }
    assert_eq!(paths.state(Integration::WaybarModule), State::On);
    assert!(
        fs::read_to_string(&paths.waybar_style)
            .unwrap()
            .contains("#image.omarchy-guardian { padding: 0 9px; border-radius: 11px; }")
    );

    let off = paths.plan(Integration::WaybarModule, &State::On).unwrap();
    for step in &off.steps {
        paths.edit(step).unwrap();
    }
    assert_eq!(paths.state(Integration::WaybarModule), State::Off);
    assert_eq!(
        fs::read_to_string(&paths.waybar_config).unwrap(),
        WAYBAR_CONFIG
    );
    assert_eq!(fs::read_to_string(&paths.waybar_style).unwrap(), style);
}

#[test]
fn an_edited_waybar_line_is_repaired_by_turning_the_module_on() {
    let dir = TempDir::new("integrations-waybar-repair");
    let paths = paths(&dir);
    fs::create_dir_all(dir.path().join("waybar")).unwrap();
    fs::write(&paths.waybar_config, WAYBAR_CONFIG).unwrap();
    fs::write(&paths.waybar_style, "#battery { padding: 0 9px; }\n").unwrap();
    let on = paths.plan(Integration::WaybarModule, &State::Off).unwrap();
    for step in &on.steps {
        paths.edit(step).unwrap();
    }
    assert_eq!(paths.state(Integration::WaybarModule), State::On);

    // A line pointing at another binary, as a hand edit or an older
    // Guardian would leave it.
    let config = fs::read_to_string(&paths.waybar_config).unwrap();
    fs::write(
        &paths.waybar_config,
        config.replace(
            "\"omarchy-guardian status --waybar\"",
            "\"/tmp/other status --waybar\"",
        ),
    )
    .unwrap();
    let state = paths.state(Integration::WaybarModule);
    assert!(matches!(state, State::Partial(_)), "{state:?}");

    let repair = paths.plan(Integration::WaybarModule, &state).unwrap();
    for step in &repair.steps {
        paths.edit(step).unwrap();
    }
    assert_eq!(paths.state(Integration::WaybarModule), State::On);
    let repaired = fs::read_to_string(&paths.waybar_config).unwrap();
    assert!(!repaired.contains("/tmp/other"));
    assert_eq!(repaired.matches("\"image#omarchy-guardian\"").count(), 2);
}

#[test]
fn a_comma_goes_before_a_comment_that_ends_the_line() {
    let text = "{\n  \"a\": \"x // not a comment\" // the last one\n}\n";
    let out = with_menu_entries(text, &["\"b\": 1"]).unwrap();
    assert_eq!(
        out,
        "{\n  \"a\": \"x // not a comment\", // the last one\n  \"b\": 1\n}\n"
    );
    // Already ended, or nothing before it: nothing is added.
    let out = with_menu_entries("{\n  \"a\": 1, // c\n}\n", &["\"b\": 1"]).unwrap();
    assert_eq!(out, "{\n  \"a\": 1, // c\n  \"b\": 1\n}\n");
}

#[test]
fn the_widget_added_as_a_plugin_of_its_own_stands_in_for_the_packaged_copy() {
    let dir = TempDir::new("integrations-listed-widget");
    let paths = paths(&dir);
    let root = dir.path();
    fs::create_dir_all(root.join("share/bar-widget")).unwrap();
    fs::write(
        root.join("share/bar-widget/manifest.json"),
        r#"{"id":"omarchy-guardian"}"#,
    )
    .unwrap();
    fs::create_dir_all(root.join("omarchy/bin")).unwrap();
    fs::write(root.join("omarchy/bin/omarchy-plugin-enable"), "").unwrap();
    assert_eq!(paths.state(Integration::BarWidget), State::Off);

    let listed = root.join("plugins/io.github.gosumarchy.guardian");
    fs::create_dir_all(&listed).unwrap();
    fs::write(
        listed.join("manifest.json"),
        r#"{"id":"io.github.gosumarchy.guardian"}"#,
    )
    .unwrap();

    // Installed and not in the bar: turning it on places it, and copies
    // nothing.
    let state = paths.state(Integration::BarWidget);
    assert!(matches!(state, State::Partial(_)), "{state:?}");
    let enable = root.join("omarchy/bin/omarchy-plugin-enable");
    assert_eq!(
        paths.plan(Integration::BarWidget, &state).unwrap().steps,
        [Step::Command(vec![
            enable.display().to_string(),
            "io.github.gosumarchy.guardian".into()
        ])]
    );

    // In the bar it is on; turning it off takes it out and removes nothing.
    fs::write(
        &paths.shell_config,
        r#"{"bar":{"layout":{"right":[{"id":"io.github.gosumarchy.guardian"}]}}}"#,
    )
    .unwrap();
    assert_eq!(paths.state(Integration::BarWidget), State::On);
    let disable = root.join("omarchy/bin/omarchy-plugin-disable");
    assert_eq!(
        paths
            .plan(Integration::BarWidget, &State::On)
            .unwrap()
            .steps,
        [Step::Optional(vec![
            disable.display().to_string(),
            "io.github.gosumarchy.guardian".into()
        ])]
    );

    // A folder of that name holding another plugin is not it.
    fs::write(listed.join("manifest.json"), r#"{"id":"other"}"#).unwrap();
    assert_eq!(paths.state(Integration::BarWidget), State::Off);
    fs::write(
        listed.join("manifest.json"),
        r#"{"id":"io.github.gosumarchy.guardian"}"#,
    )
    .unwrap();

    // With the packaged copy there too, that one is still Guardian's to
    // update and to remove.
    fs::create_dir_all(&paths.widget_target).unwrap();
    fs::write(
        paths.widget_target.join("manifest.json"),
        r#"{"id":"omarchy-guardian"}"#,
    )
    .unwrap();
    let state = paths.state(Integration::BarWidget);
    assert!(matches!(state, State::Partial(_)), "{state:?}");
    assert!(
        paths
            .plan(Integration::BarWidget, &state)
            .unwrap()
            .steps
            .contains(&Step::InstallBarWidget)
    );
}
