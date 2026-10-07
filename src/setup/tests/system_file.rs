//! What setup, the sweep's consent and the accepted weaker settings do to a
//! system file that is already there: one that cannot be read or is not
//! valid is left alone, and a valid one keeps everything they do not set.

use std::cell::RefCell;
use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;

use super::super::{
    Choice, HEADER, MAX_SYSTEM_FILE, PRIVILEGED_COMMUNITY, Place, USER_CLASSES, render_system,
    render_user, run, set_sweep_root_at, tested_variant, with_accepted_at, write_system_at,
};
use super::super::{insecure_refusal, load_system};
use super::{Fake, script};
use crate::config::file::{PartialConfig, parse};
use crate::config::load::{Insecure, check_root_owned};
use crate::config::model::{Action, Named, Profile, RootConsent, SourceClass, Thinking};
use crate::test_support::TempDir;

/// A system file an administrator wrote: settings no setup screen asks
/// about, next to ones setup does write.
const ADMIN: &str = "# Managed by the administrator\n\
profile = \"strict\"\n\
official_repos = [\"core\", \"extra\"]\n\
trusted_reviewer_packages = [\"opencode-bin\"]\n\
\n[permit]\nstrict = \"allowed\"\n\
\n[update]\ncheck = \"off\"\n\
\n[agent]\nmodel = \"ollama/qwen3\"\nmax_chunks = 4\n\
\n[class.official]\non_findings = \"block\"\n\
\n[class.third-party-repo]\nthinking = \"max\"\ntimeout_secs = 600\n\
\n[class.aur]\ntimeout_secs = 120\n";

/// A directory holding a system file with `text`.
fn system_file(text: &str) -> (TempDir, PathBuf) {
    let directory = TempDir::new("setup-system");
    let path = directory.path().join("config.toml");
    fs::write(&path, text).unwrap();
    (directory, path)
}

/// A directory where the system file would be: reading it fails, for root too.
fn unreadable() -> (TempDir, PathBuf) {
    let directory = TempDir::new("setup-system");
    let path = directory.path().join("config.toml");
    fs::create_dir(&path).unwrap();
    (directory, path)
}

/// The system file at `path`, with the check on its owner and mode passed:
/// a test's files are its user's, not root's.
fn at(path: &Path) -> Place<'_> {
    Place {
        path,
        secure: &|_| Ok(()),
    }
}

fn parsed(text: &str) -> PartialConfig {
    parse(Path::new("system"), text).unwrap_or_else(|error| panic!("{error}\n{text}"))
}

/// Everything `ADMIN` sets that none of the three writers owns.
fn assert_admin_settings_kept(config: &PartialConfig) {
    let admin = parsed(ADMIN);
    assert_eq!(config.official_repos, admin.official_repos);
    assert_eq!(
        config.official_repos,
        Some(vec!["core".to_string(), "extra".to_string()])
    );
    assert_eq!(
        config.trusted_reviewer_packages,
        admin.trusted_reviewer_packages
    );
    assert_eq!(config.permit_strict, Some(true));
    assert_eq!(config.update_check, Some(false));
    assert_eq!(config.agent.max_chunks, Some(4));
    assert_eq!(
        config.class(SourceClass::Official).on_findings,
        Some(Action::Block)
    );
    assert_eq!(
        config.class(SourceClass::ThirdPartyRepo).timeout_secs,
        Some(600)
    );
    assert_eq!(config.class(SourceClass::Aur).timeout_secs, Some(120));
    assert_eq!(
        config.class(SourceClass::Aur),
        admin.class(SourceClass::Aur)
    );
}

/// What an installer was given, recorded instead of running sudo.
#[derive(Default)]
struct Installed(RefCell<Vec<String>>);

impl Installed {
    fn installer(&self) -> impl Fn(&str) -> Result<(), String> + '_ {
        |text| {
            self.0.borrow_mut().push(text.to_string());
            Ok(())
        }
    }
}

#[test]
fn the_sweeps_consent_keeps_every_other_setting() {
    let (_directory, path) = system_file(ADMIN);
    let installed = Installed::default();

    set_sweep_root_at(
        &at(&path),
        &installed.installer(),
        RootConsent::Allowed,
        Some("wheel".into()),
    )
    .unwrap();

    let installed = installed.0.borrow();
    assert_eq!(installed.len(), 1);
    let config = parsed(&installed[0]);
    assert_eq!(config.sweep.root, Some(RootConsent::Allowed));
    assert_eq!(config.sweep.group.as_deref(), Some("wheel"));

    // Nothing but the sweep's settings differs from the file as it was.
    let mut expected = parsed(ADMIN);
    expected.sweep = config.sweep.clone();
    assert_eq!(config, expected);
    assert_eq!(config.profile, Some(Profile::Strict));
    assert_admin_settings_kept(&config);
    assert!(installed[0].starts_with("# Managed by the administrator\n"));
}

#[test]
fn accepting_weaker_settings_keeps_every_other_setting() {
    let (_directory, path) = system_file(ADMIN);

    let (text, existing) = with_accepted_at(&at(&path), vec!["aur.ai=off".into()]).unwrap();

    assert_eq!(existing, ADMIN);
    let config = parsed(&text);
    let mut expected = parsed(ADMIN);
    expected.acknowledged_weaker = Some(vec!["aur.ai=off".to_string()]);
    assert_eq!(config, expected);
    assert_eq!(config.profile, Some(Profile::Strict));
    assert_admin_settings_kept(&config);
}

#[test]
fn a_setup_run_keeps_what_it_does_not_ask_about() {
    let (_directory, path) = system_file(ADMIN);
    let environment = Fake {
        opencode: true,
        test_passes: true,
        system_path: Some(path.clone()),
        ..Fake::default()
    };
    // profile 2 = strict (as it is), model 2 = sonnet (the one change),
    // official model (default), thinking (default), confirm the system write
    let mut terminal = script(&["2", "2", "", "", "y"]);

    run(&mut terminal, &environment).unwrap();

    let system = environment.system_written.borrow().clone().unwrap();
    let config = parsed(&system);
    assert_eq!(config.profile, Some(Profile::Strict));
    assert_eq!(
        config.agent.model.as_deref(),
        Some("anthropic/claude-sonnet-5")
    );
    assert_admin_settings_kept(&config);
    // The diff shown says the same: none of them is a removed line.
    let removed: Vec<&str> = terminal
        .output
        .lines()
        .filter(|line| line.starts_with("- "))
        .collect();
    assert!(
        removed.contains(&"- [agent] model = \"ollama/qwen3\""),
        "{removed:?}"
    );
    for kept in [
        "official_repos",
        "check",
        "timeout_secs",
        "max_chunks",
        "on_findings",
        "strict",
        "trusted_reviewer_packages",
    ] {
        assert!(
            !removed.iter().any(|line| line.contains(kept)),
            "{kept}\n{removed:?}"
        );
    }
    assert_eq!(fs::read_to_string(&path).unwrap(), ADMIN);
}

#[test]
fn setup_changes_only_the_keys_it_asks_about() {
    let choice = Choice {
        profile: Profile::Standard,
        model: None,
        official_model: Some("anthropic/claude-haiku-4-5".into()),
        thinking: Thinking::Default,
    };

    let merged = super::super::system_config(&choice, parsed(ADMIN));

    // Owned: set to what was chosen, and removed where the choice is "unset".
    assert_eq!(merged.profile, Some(Profile::Standard));
    assert_eq!(merged.agent.model, None);
    assert!(merged.agent.variants.is_empty());
    assert_eq!(
        merged.class(SourceClass::Official).model.as_deref(),
        Some("anthropic/claude-haiku-4-5")
    );
    for class in PRIVILEGED_COMMUNITY {
        assert_eq!(merged.class(class).thinking, Some(Thinking::Default));
    }

    // With those keys put back, it is the file as it was.
    let admin = parsed(ADMIN);
    let mut restored = merged;
    restored.profile = admin.profile;
    restored.agent.model.clone_from(&admin.agent.model);
    restored.class_mut(SourceClass::Official).model = None;
    restored.class_mut(SourceClass::ThirdPartyRepo).thinking = Some(Thinking::Max);
    restored.class_mut(SourceClass::LocalPackage).thinking = None;
    assert_eq!(parsed(&write_render(&restored)), admin);
}

/// Through the file format, so that classes with nothing set compare equal
/// to classes that are not listed.
fn write_render(config: &PartialConfig) -> String {
    crate::config::write::render(config, "")
}

#[test]
fn a_system_file_that_cannot_be_read_is_not_replaced() {
    let (_directory, path) = unreadable();
    let installed = Installed::default();
    let install = installed.installer();
    let shown = path.display().to_string();

    let error = set_sweep_root_at(&at(&path), &install, RootConsent::Declined, None).unwrap_err();
    assert!(
        error.contains(&shown) && error.contains("is a directory"),
        "{error}"
    );
    assert!(error.contains("config check"), "{error}");

    let error = with_accepted_at(&at(&path), vec!["aur.ai=off".into()]).unwrap_err();
    assert!(error.contains(&shown), "{error}");

    let error = write_system_at(&at(&path), &install, "profile = \"standard\"\n").unwrap_err();
    assert!(error.contains(&shown), "{error}");

    let environment = Fake {
        opencode: true,
        test_passes: true,
        system_path: Some(path.clone()),
        ..Fake::default()
    };
    let mut terminal = script(&["", "2", "", "", "y"]);
    let error = run(&mut terminal, &environment).unwrap_err();
    assert!(error.contains(&shown), "{error}");
    assert!(
        error.contains("Setup wrote nothing, not your own settings file either"),
        "{error}"
    );
    assert!(environment.user_written.borrow().is_none());
    assert!(environment.system_written.borrow().is_none());
    assert!(environment.tested.borrow().is_empty());

    assert!(installed.0.borrow().is_empty());
    assert!(path.is_dir());
}

#[test]
fn a_system_file_that_is_not_text_is_not_replaced() {
    let directory = TempDir::new("setup-system");
    let path = directory.path().join("config.toml");
    fs::write(&path, b"profile = \"strict\"\n\xff\xfe\n").unwrap();
    let installed = Installed::default();

    let error = set_sweep_root_at(
        &at(&path),
        &installed.installer(),
        RootConsent::Allowed,
        None,
    )
    .unwrap_err();

    assert!(error.contains(&path.display().to_string()), "{error}");
    assert!(with_accepted_at(&at(&path), Vec::new()).is_err());
    assert!(installed.0.borrow().is_empty());
}

#[test]
fn a_system_file_that_is_not_valid_is_not_replaced() {
    // A typo in a key: the administrator meant `profile = "strict"`.
    let malformed = "profil = \"strict\"\nofficial_repos = [\"core\"]\n";
    let (_directory, path) = system_file(malformed);
    let installed = Installed::default();
    let install = installed.installer();
    let names_the_problem = |error: &str| {
        assert!(error.contains(&path.display().to_string()), "{error}");
        assert!(error.contains("profil"), "{error}");
        assert!(error.contains("unknown key"), "{error}");
        assert!(error.contains("was not changed"), "{error}");
        assert!(
            error.contains(&format!("sudoedit {}", path.display())),
            "{error}"
        );
        assert!(error.contains("omarchy-guardian config check"), "{error}");
    };

    names_the_problem(
        &set_sweep_root_at(&at(&path), &install, RootConsent::Allowed, None).unwrap_err(),
    );
    names_the_problem(&with_accepted_at(&at(&path), vec!["aur.ai=off".into()]).unwrap_err());
    names_the_problem(
        &write_system_at(&at(&path), &install, "profile = \"standard\"\n").unwrap_err(),
    );

    let environment = Fake {
        opencode: true,
        test_passes: true,
        system_path: Some(path.clone()),
        ..Fake::default()
    };
    let mut terminal = script(&["", "2", "", "", "y"]);
    names_the_problem(&run(&mut terminal, &environment).unwrap_err());
    assert!(environment.user_written.borrow().is_none());
    assert!(environment.system_written.borrow().is_none());

    assert!(installed.0.borrow().is_empty());
    assert_eq!(fs::read_to_string(&path).unwrap(), malformed);
}

#[test]
fn a_system_file_that_turns_invalid_during_setup_is_not_replaced() {
    let (_directory, path) = system_file(ADMIN);
    let installed = Installed::default();

    // Valid when the diff was drawn up, not when it is installed.
    fs::write(&path, "profile = \n").unwrap();
    let error = write_system_at(
        &at(&path),
        &installed.installer(),
        "profile = \"standard\"\n",
    )
    .unwrap_err();

    assert!(error.contains(&path.display().to_string()), "{error}");
    assert!(installed.0.borrow().is_empty());
}

#[test]
fn saving_a_whole_system_file_keeps_the_settings_no_screen_edits() {
    let (_directory, path) = system_file(ADMIN);
    let installed = Installed::default();

    write_system_at(
        &at(&path),
        &installed.installer(),
        "# Written by a screen\nprofile = \"standard\"\n",
    )
    .unwrap();

    let installed = installed.0.borrow();
    let config = parsed(&installed[0]);
    assert_eq!(config.profile, Some(Profile::Standard));
    assert_eq!(config.permit_strict, Some(true));
    assert_eq!(
        config.trusted_reviewer_packages,
        Some(vec!["opencode-bin".to_string()])
    );
    // A whole file says what the rest is: here, unset.
    assert_eq!(config.official_repos, None);
}

#[test]
fn without_a_system_file_one_is_created_as_before() {
    let directory = TempDir::new("setup-system");
    let path = directory.path().join("config.toml");
    let installed = Installed::default();
    let install = installed.installer();

    set_sweep_root_at(
        &at(&path),
        &install,
        RootConsent::Allowed,
        Some("wheel".into()),
    )
    .unwrap();
    assert_eq!(
        installed.0.borrow()[0],
        format!("{HEADER}\n[sweep]\nroot = \"allowed\"\ngroup = \"wheel\"\n")
    );

    let (text, existing) = with_accepted_at(&at(&path), vec!["aur.ai=off".into()]).unwrap();
    assert_eq!(existing, "");
    assert_eq!(
        text,
        format!("{HEADER}\n[acknowledged]\nweaker = [\"aur.ai=off\"]\n")
    );

    write_system_at(&at(&path), &install, "profile = \"standard\"\n").unwrap();
    assert_eq!(installed.0.borrow()[1], "profile = \"standard\"\n");

    let environment = Fake {
        opencode: true,
        test_passes: true,
        system_path: Some(path.clone()),
        ..Fake::default()
    };
    // profile (default), model 2 = sonnet, official model 3 = haiku,
    // thinking (default), confirm the system write
    let mut terminal = script(&["", "2", "3", "", "y"]);
    run(&mut terminal, &environment).unwrap();
    let choice = Choice {
        profile: Profile::Standard,
        model: Some("anthropic/claude-sonnet-5".into()),
        official_model: Some("anthropic/claude-haiku-4-5".into()),
        thinking: Thinking::High,
    };
    assert_eq!(
        environment.system_written.borrow().as_deref(),
        Some(written_by_hand(&choice, &PRIVILEGED_COMMUNITY, true).as_str())
    );
    assert_eq!(
        environment.user_written.borrow().as_deref(),
        Some(written_by_hand(&choice, &USER_CLASSES, false).as_str())
    );
    assert!(!path.exists());
}

/// The files as setup wrote them before it rendered through the config
/// model: the text built key by key.
fn written_by_hand(choice: &Choice, classes: &[SourceClass], official_model: bool) -> String {
    let mut text = format!("{HEADER}profile = \"{}\"\n", choice.profile.name());

    if let Some(model) = &choice.model {
        let _ = write!(text, "\n[agent]\nmodel = \"{model}\"\n");
    }
    if let Some(level) = tested_variant(choice) {
        let _ = write!(
            text,
            "\n[agent.variants]\n{} = \"{}\"\n",
            level.name(),
            level.name()
        );
    }
    if official_model && let Some(model) = &choice.official_model {
        let _ = write!(text, "\n[class.official]\nmodel = \"{model}\"\n");
    }
    if choice.profile != Profile::LocalOnly {
        for class in classes {
            let _ = write!(
                text,
                "\n[class.{}]\nthinking = \"{}\"\n",
                class.name(),
                choice.thinking.name()
            );
        }
    }
    text
}

#[test]
fn every_choice_renders_the_files_it_always_did() {
    let models = [
        None,
        Some("anthropic/claude-sonnet-5".to_string()),
        Some("claude-code/claude-sonnet-5-5".to_string()),
        Some("ollama/qwen3:8b@local+x=[1]~._-".to_string()),
    ];
    let mut compared = 0;
    for profile in Profile::ALL.iter().copied() {
        for model in &models {
            for official_model in &models {
                for thinking in Thinking::ALL.iter().copied() {
                    let choice = Choice {
                        profile,
                        model: model.clone(),
                        official_model: official_model.clone(),
                        thinking,
                    };
                    assert_eq!(
                        render_user(&choice),
                        written_by_hand(&choice, &USER_CLASSES, false),
                        "{choice:?}"
                    );
                    assert_eq!(
                        render_system(&choice),
                        written_by_hand(&choice, &PRIVILEGED_COMMUNITY, true),
                        "{choice:?}"
                    );
                    compared += 1;
                }
            }
        }
    }
    assert_eq!(compared, 3 * 4 * 4 * Thinking::ALL.len());
}

/// Every way in refuses the file at `place` with `expected` in the reason,
/// and installs nothing.
fn assert_refused(place: &Place<'_>, expected: &[&str]) {
    let installed = Installed::default();
    let install = installed.installer();
    let shown = place.path.display().to_string();
    let errors = [
        set_sweep_root_at(place, &install, RootConsent::Allowed, Some("wheel".into())).unwrap_err(),
        with_accepted_at(place, vec!["aur.ai=off".into()]).unwrap_err(),
        write_system_at(place, &install, "profile = \"standard\"\n").unwrap_err(),
    ];
    for error in errors {
        assert!(error.contains(&shown), "{error}");
        assert!(error.contains("changed"), "{error}");
        for part in expected {
            assert!(error.contains(part), "{part}\n{error}");
        }
    }
    assert!(installed.0.borrow().is_empty());
}

#[test]
fn a_system_file_the_gate_refuses_as_insecure_is_not_taken_over() {
    // Valid, and what a writer other than root would want installed as root's.
    let (directory, path) = system_file("profile = \"local-only\"\n");
    let place = Place {
        path: &path,
        secure: &|file| Err(Insecure::owned_by(file, 1000)),
    };
    let shown = path.display().to_string();
    let folder = directory.path().display().to_string();

    assert_refused(
        &place,
        &[
            "insecure",
            "is owned by uid 1000, not root",
            "it was not changed",
            &format!("sudo chown root:root {folder} {shown}"),
            &format!("sudo chmod 755 {folder}"),
            &format!("sudo chmod 644 {shown}"),
            "omarchy-guardian config check",
        ],
    );

    let environment = Fake {
        opencode: true,
        test_passes: true,
        system_path: Some(path.clone()),
        system_insecure: Some(1000),
        ..Fake::default()
    };
    let mut terminal = script(&["", "2", "", "", "y"]);
    let error = run(&mut terminal, &environment).unwrap_err();
    assert!(error.contains("insecure"), "{error}");
    assert!(error.contains("Setup wrote nothing"), "{error}");
    assert!(environment.user_written.borrow().is_none());
    assert!(environment.system_written.borrow().is_none());
    // Not shown as what the system file holds, either.
    assert!(
        !terminal.output.contains("local-only\""),
        "{}",
        terminal.output
    );
}

#[test]
fn an_insecure_system_file_is_named_once_with_its_repair() {
    let (directory, path) = system_file(ADMIN);
    let shown = path.display().to_string();
    let folder = directory.path().display().to_string();
    let repair = format!(
        "; it was not changed. Check what it holds, then make it root's: `sudo chown root:root \
{folder} {shown} && sudo chmod 755 {folder} && sudo chmod 644 {shown}` (`omarchy-guardian config \
check` shows the problem)."
    );
    let refused = |secure: &dyn Fn(&Path) -> Result<(), Insecure>| {
        load_system(&Place {
            path: &path,
            secure,
        })
        .err()
        .unwrap()
    };

    // The file's owner: the reason names the file itself.
    assert_eq!(
        refused(&|file| Err(Insecure::owned_by(file, 1000))),
        format!("insecure: {shown} is owned by uid 1000, not root{repair}")
    );
    // Its directory's mode: the file, then what is wrong with the directory.
    assert_eq!(
        refused(&|file| Err(Insecure::writable(file.parent().unwrap()))),
        format!("{shown}: insecure: {folder} is writable by group or others{repair}")
    );
}

#[test]
fn in_a_namespace_without_root_no_chown_is_advised() {
    let path = Path::new("/etc/omarchy-guardian/config.toml");
    let nobodys = Insecure::owned_by(path, 65_534);
    assert_eq!(
        insecure_refusal(path, &nobodys, true),
        "insecure: /etc/omarchy-guardian/config.toml is owned by uid 65534, not root; it was not \
changed. This is running in a user namespace that does not map root, where root's files look like \
nobody's: run it outside the sandbox."
    );
    // The same owner where root is mapped is somebody's file to take back.
    let mapped = insecure_refusal(path, &nobodys, false);
    assert!(mapped.contains("sudo chown root:root"), "{mapped}");
    assert!(!mapped.contains("sandbox"), "{mapped}");
}

#[test]
fn the_gates_own_check_decides_what_is_insecure() {
    // Writable by the group: refused whoever runs the test (as a user, for
    // the owner already).
    let (_directory, path) = system_file(ADMIN);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o664)).unwrap();
    assert_refused(
        &Place {
            path: &path,
            secure: &check_root_owned,
        },
        &["insecure", "sudo chmod 644"],
    );

    // A file as it should be, in a directory others can write.
    let (directory, path) = system_file(ADMIN);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o777)).unwrap();
    assert_refused(
        &Place {
            path: &path,
            secure: &check_root_owned,
        },
        &["insecure", "sudo chmod 755"],
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), ADMIN);
}

#[test]
fn a_link_in_place_of_the_system_file_is_not_followed() {
    let directory = TempDir::new("setup-system");
    let target = directory.path().join("mine.toml");
    fs::write(&target, "profile = \"local-only\"\n").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o666)).unwrap();
    let path = directory.path().join("config.toml");
    symlink(&target, &path).unwrap();

    assert_refused(&at(&path), &["is a symbolic link", "config check"]);
    assert_eq!(
        fs::read_to_string(&target).unwrap(),
        "profile = \"local-only\"\n"
    );

    // One that leads nowhere is still something at the path, not no file.
    let dangling = directory.path().join("dangling.toml");
    symlink(directory.path().join("nothing"), &dangling).unwrap();
    assert_refused(&at(&dangling), &["is a symbolic link"]);
}

#[test]
fn a_pipe_in_place_of_the_system_file_is_refused_without_waiting() {
    let directory = TempDir::new("setup-system");
    let path = directory.path().join("config.toml");
    let made = Command::new("mkfifo").arg(&path).status().unwrap();
    assert!(made.success());

    // Nothing ever writes to it: reading it would wait for ever.
    assert_refused(&at(&path), &["is not a regular file"]);
}

#[test]
fn a_system_file_larger_than_any_config_is_not_read() {
    let size = usize::try_from(MAX_SYSTEM_FILE).unwrap() + 1;
    let (_directory, path) = system_file(&"#".repeat(size));

    assert_refused(&at(&path), &["is larger than 1024 KiB"]);
}

#[test]
fn what_stands_in_the_way_of_the_system_file_is_an_error_not_no_file() {
    // A file where the directory would be.
    let directory = TempDir::new("setup-system");
    let blocker = directory.path().join("omarchy-guardian");
    fs::write(&blocker, "").unwrap();
    let path = blocker.join("config.toml");

    assert_refused(&at(&path), &["cannot read", "sudoedit", "config check"]);
}

#[test]
fn without_its_directory_there_is_no_system_file() {
    let directory = TempDir::new("setup-system");
    let path = directory
        .path()
        .join("omarchy-guardian")
        .join("config.toml");
    let installed = Installed::default();

    // Not asked about a file that is not there.
    let place = Place {
        path: &path,
        secure: &|_| Err(Insecure::other("never asked".into())),
    };
    set_sweep_root_at(&place, &installed.installer(), RootConsent::Declined, None).unwrap();

    assert_eq!(
        installed.0.borrow()[0],
        format!("{HEADER}\n[sweep]\nroot = \"declined\"\n")
    );
}
