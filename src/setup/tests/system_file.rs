//! What setup, the sweep's consent and the accepted weaker settings do to a
//! system file that is already there: one that cannot be read or is not
//! valid is left alone, and a valid one keeps everything they do not set.

use std::cell::RefCell;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use super::super::{
    Choice, HEADER, PRIVILEGED_COMMUNITY, USER_CLASSES, render_system, render_user, run,
    set_sweep_root_at, tested_variant, with_accepted_at, write_system_at,
};
use super::{Fake, script};
use crate::config::file::{PartialConfig, parse};
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
        &path,
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

    let (text, existing) = with_accepted_at(&path, vec!["aur.ai=off".into()]).unwrap();

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
    for kept in [
        "- official_repos",
        "- check = \"off\"",
        "- timeout_secs",
        "- max_chunks",
        "- on_findings",
        "- strict = \"allowed\"",
        "- trusted_reviewer_packages",
    ] {
        assert!(
            !terminal.output.contains(kept),
            "{kept}\n{}",
            terminal.output
        );
    }
    assert!(terminal.output.contains("- model = \"ollama/qwen3\""));
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

    let error = set_sweep_root_at(&path, &install, RootConsent::Declined, None).unwrap_err();
    assert!(
        error.contains(&shown) && error.contains("cannot read"),
        "{error}"
    );

    let error = with_accepted_at(&path, vec!["aur.ai=off".into()]).unwrap_err();
    assert!(error.contains(&shown), "{error}");

    let error = write_system_at(&path, &install, "profile = \"standard\"\n").unwrap_err();
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

    let error =
        set_sweep_root_at(&path, &installed.installer(), RootConsent::Allowed, None).unwrap_err();

    assert!(error.contains(&path.display().to_string()), "{error}");
    assert!(with_accepted_at(&path, Vec::new()).is_err());
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
    };

    names_the_problem(&set_sweep_root_at(&path, &install, RootConsent::Allowed, None).unwrap_err());
    names_the_problem(&with_accepted_at(&path, vec!["aur.ai=off".into()]).unwrap_err());
    names_the_problem(&write_system_at(&path, &install, "profile = \"standard\"\n").unwrap_err());

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
    let error =
        write_system_at(&path, &installed.installer(), "profile = \"standard\"\n").unwrap_err();

    assert!(error.contains(&path.display().to_string()), "{error}");
    assert!(installed.0.borrow().is_empty());
}

#[test]
fn saving_a_whole_system_file_keeps_the_settings_no_screen_edits() {
    let (_directory, path) = system_file(ADMIN);
    let installed = Installed::default();

    write_system_at(
        &path,
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

    set_sweep_root_at(&path, &install, RootConsent::Allowed, Some("wheel".into())).unwrap();
    assert_eq!(
        installed.0.borrow()[0],
        format!("{HEADER}\n[sweep]\nroot = \"allowed\"\ngroup = \"wheel\"\n")
    );

    let (text, existing) = with_accepted_at(&path, vec!["aur.ai=off".into()]).unwrap();
    assert_eq!(existing, "");
    assert_eq!(
        text,
        format!("{HEADER}\n[acknowledged]\nweaker = [\"aur.ai=off\"]\n")
    );

    write_system_at(&path, &install, "profile = \"standard\"\n").unwrap();
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
