//! Tests for `app`.

use std::path::PathBuf;

use super::{App, Effect, Loaded, Mode, Row, Tab, Task};
use crate::config::file::PartialConfig;
use crate::config::load::FileStatus;
use crate::config::model::{AiRequirement, Profile, RootConsent, SourceClass};
use crate::integrations::Plan;
use crate::tui::canvas::Canvas;
use crate::tui::fields::Scope;
use crate::tui::term::Key;

fn loaded(user: PartialConfig, system: PartialConfig) -> Loaded {
    Loaded {
        user,
        system,
        user_status: FileStatus::Missing,
        system_status: FileStatus::Missing,
        system_path: PathBuf::from("/etc/omarchy-guardian/config.toml"),
        system_text: String::new(),
        paths: None,
    }
}

fn app() -> App {
    App::new(
        loaded(PartialConfig::default(), PartialConfig::default()),
        Mode::Expert,
    )
}

fn press(app: &mut App, keys: &[Key]) -> Vec<Effect> {
    keys.iter().filter_map(|key| app.handle(*key)).collect()
}

fn screen(app: &mut App) -> String {
    let mut canvas = Canvas::new(90, 28);
    app.draw(&mut canvas);
    canvas.rows().join("\n")
}

#[test]
fn draws_tabs_and_inherited_values() {
    let mut app = app();
    let text = screen(&mut app);
    assert!(text.contains("Omarchy Guardian"), "{text}");
    assert!(text.contains("1 Profiles"));
    assert!(text.contains("Your sources"));
    assert!(text.contains("standard  (inherited)"));
}

#[test]
fn choosing_a_profile_edits_the_user_draft_and_saves_it() {
    let mut app = app();
    // Enter opens the choice list: inherit, standard, strict, local-only.
    press(&mut app, &[Key::Enter, Key::Down, Key::Down, Key::Enter]);
    assert_eq!(app.user.profile, Some(Profile::Strict));
    assert!(screen(&mut app).contains("1 unsaved"));

    let effects = press(&mut app, &[Key::Char('s')]);
    assert!(
        matches!(&effects[..], [Effect::SaveUser(text)] if text.contains("profile = \"strict\"")),
        "{effects:?}"
    );
}

#[test]
fn space_cycles_and_x_resets_to_inherit() {
    let mut app = app();
    press(&mut app, &[Key::Char('2')]);
    assert_eq!(app.tab, Tab::Sources);
    // The first field is the official class's AI knob (system file).
    press(&mut app, &[Key::Char(' ')]);
    assert_eq!(
        app.system.class(SourceClass::Official).ai,
        Some(AiRequirement::Off)
    );
    press(&mut app, &[Key::Char(' ')]);
    assert_eq!(
        app.system.class(SourceClass::Official).ai,
        Some(AiRequirement::Optional)
    );
    press(&mut app, &[Key::Char('x')]);
    assert_eq!(app.system.class(SourceClass::Official).ai, None);
}

#[test]
fn saving_the_system_file_asks_with_a_diff() {
    let mut app = app();
    press(&mut app, &[Key::Down, Key::Char(' ')]);
    assert_eq!(app.system.profile, Some(Profile::Standard));

    assert!(press(&mut app, &[Key::Char('s')]).is_empty());
    let text = screen(&mut app);
    assert!(text.contains("Save the system file?"), "{text}");
    assert!(text.contains("+ profile = \"standard\""), "{text}");
    let effects = press(&mut app, &[Key::Char('y')]);
    assert!(matches!(&effects[..], [Effect::SaveSystem(_)]));
}

#[test]
fn user_then_system_saves_chain() {
    let mut app = app();
    press(&mut app, &[Key::Char(' '), Key::Down, Key::Char(' ')]);
    let effects = press(&mut app, &[Key::Char('s')]);
    let [effect @ Effect::SaveUser(_)] = &effects[..] else {
        panic!("{effects:?}");
    };
    app.finish(effect, Ok("Saved.".into()));
    assert!(screen(&mut app).contains("Save the system file?"));
}

/// The event loop's step after an effect that went well, with `user` and
/// `system` as the files it reads back.
fn settle(app: &mut App, effect: &Effect, user: PartialConfig, system: PartialConfig) {
    assert!(app.settle(effect, Ok("Done.".into()), || loaded(user, system)));
}

fn toggle() -> Effect {
    Effect::Integration(Plan {
        summary: "Turn a gate on".into(),
        steps: Vec::new(),
    })
}

#[test]
fn the_system_draft_outlives_saving_the_user_file() {
    let mut app = app();
    press(&mut app, &[Key::Char(' '), Key::Down, Key::Char(' ')]);
    let effects = press(&mut app, &[Key::Char('s')]);
    let [effect @ Effect::SaveUser(_)] = &effects[..] else {
        panic!("{effects:?}");
    };
    // The user file now holds the draft; the system file is as it was.
    let written = app.user.clone();
    settle(&mut app, effect, written, PartialConfig::default());

    assert_eq!(app.system.profile, Some(Profile::Standard));
    assert!(!app.dirty(Scope::User));
    let text = screen(&mut app);
    assert!(text.contains("Save the system file?"), "{text}");
    assert!(text.contains("+ profile = \"standard\""), "{text}");
    let effects = press(&mut app, &[Key::Char('y')]);
    let [effect @ Effect::SaveSystem(saved)] = &effects[..] else {
        panic!("{effects:?}");
    };
    assert!(saved.contains("profile = \"standard\""), "{saved}");

    let (user, system) = (app.user.clone(), app.system.clone());
    settle(&mut app, effect, user, system);
    assert_eq!(app.changed_count(), 0);
    assert!(!app.dirty(Scope::System));
}

#[test]
fn a_save_that_fails_keeps_its_draft() {
    let mut app = app();
    press(&mut app, &[Key::Char(' ')]);
    let effects = press(&mut app, &[Key::Char('s')]);
    let [effect @ Effect::SaveUser(_)] = &effects[..] else {
        panic!("{effects:?}");
    };
    app.settle(effect, Err("read-only file system".into()), || {
        loaded(PartialConfig::default(), PartialConfig::default())
    });
    assert_eq!(app.user.profile, Some(Profile::Standard));
    assert!(screen(&mut app).contains("read-only file system"));
}

#[test]
fn an_integration_toggle_keeps_unsaved_edits() {
    let mut app = app();
    press(&mut app, &[Key::Char(' '), Key::Down, Key::Char(' ')]);
    settle(
        &mut app,
        &toggle(),
        PartialConfig::default(),
        PartialConfig::default(),
    );
    assert_eq!(app.user.profile, Some(Profile::Standard));
    assert_eq!(app.system.profile, Some(Profile::Standard));
    assert!(screen(&mut app).contains("2 unsaved"));
}

#[test]
fn a_kept_system_draft_takes_the_sweep_consent_a_toggle_recorded() {
    let mut app = app();
    press(&mut app, &[Key::Down, Key::Char(' ')]);
    let mut system = PartialConfig::default();
    system.sweep.root = Some(RootConsent::Allowed);
    settle(
        &mut app,
        &toggle(),
        PartialConfig::default(),
        system.clone(),
    );
    assert_eq!(app.system.profile, Some(Profile::Standard));
    assert_eq!(app.system.sweep, system.sweep);
    assert_eq!(app.changed_count(), 1);
}

#[test]
fn a_draft_without_edits_follows_its_file() {
    let mut app = app();
    press(&mut app, &[Key::Char(' ')]);
    let system = PartialConfig {
        profile: Some(Profile::Strict),
        ..PartialConfig::default()
    };
    settle(
        &mut app,
        &toggle(),
        PartialConfig::default(),
        system.clone(),
    );
    assert_eq!(app.user.profile, Some(Profile::Standard));
    assert_eq!(app.system, system);
    assert!(!app.dirty(Scope::System));
}

#[test]
fn setup_and_the_editor_replace_both_drafts() {
    for effect in [
        Effect::GuidedSetup,
        Effect::Edit(Scope::User),
        Effect::Edit(Scope::System),
    ] {
        let mut app = app();
        press(&mut app, &[Key::Char(' '), Key::Down, Key::Char(' ')]);
        settle(
            &mut app,
            &effect,
            PartialConfig::default(),
            PartialConfig::default(),
        );
        assert_eq!(app.changed_count(), 0, "{effect:?}");
    }
}

/// Edits the pacman gate's profile, asks to save and confirms.
fn system_save(app: &mut App) -> Effect {
    press(app, &[Key::Down, Key::Char(' ')]);
    let effects = press(app, &[Key::Char('s'), Key::Char('y')]);
    let [effect @ Effect::SaveSystem(_)] = &effects[..] else {
        panic!("{effects:?}");
    };
    effect.clone()
}

#[test]
fn a_system_save_that_fails_keeps_its_draft() {
    let mut app = app();
    let effect = system_save(&mut app);
    app.settle(&effect, Err("sudo: a password is required".into()), || {
        loaded(PartialConfig::default(), PartialConfig::default())
    });
    assert_eq!(app.system.profile, Some(Profile::Standard));
    assert!(app.dirty(Scope::System));
}

#[test]
fn a_user_save_that_fails_does_not_go_on_to_the_system_file() {
    let mut app = app();
    press(&mut app, &[Key::Char(' '), Key::Down, Key::Char(' ')]);
    let effects = press(&mut app, &[Key::Char('s')]);
    let [effect @ Effect::SaveUser(_)] = &effects[..] else {
        panic!("{effects:?}");
    };
    assert!(app.system_after_user);
    app.settle(effect, Err("read-only file system".into()), || {
        loaded(PartialConfig::default(), PartialConfig::default())
    });
    assert!(!app.system_after_user);
    assert!(app.dialog.is_none(), "{:?}", app.dialog);
    assert_eq!(app.changed_count(), 2);
}

#[test]
fn a_saved_system_draft_becomes_the_file_as_read_back() {
    let mut app = app();
    let effect = system_save(&mut app);
    // What is read back is not the draft: a section of the file was kept,
    // and the level was set again elsewhere right after.
    let mut installed = app.system.clone();
    installed.sweep.root = Some(RootConsent::Declined);
    installed.profile = Some(Profile::Strict);
    settle(
        &mut app,
        &effect,
        PartialConfig::default(),
        installed.clone(),
    );
    assert_eq!(app.system, installed);
    assert!(!app.dirty(Scope::System));
}

#[test]
fn an_integration_toggle_that_fails_keeps_unsaved_edits() {
    let mut app = app();
    press(&mut app, &[Key::Char(' '), Key::Down, Key::Char(' ')]);
    app.settle(&toggle(), Err("pacman hook: exit status 1".into()), || {
        loaded(PartialConfig::default(), PartialConfig::default())
    });
    assert_eq!(app.user.profile, Some(Profile::Standard));
    assert_eq!(app.system.profile, Some(Profile::Standard));
}

#[test]
fn the_system_save_after_a_root_checks_toggle_carries_the_consent() {
    let mut app = app();
    press(&mut app, &[Key::Down, Key::Char(' ')]);
    let mut system = PartialConfig::default();
    system.sweep.root = Some(RootConsent::Allowed);
    settle(&mut app, &toggle(), PartialConfig::default(), system);
    let effects = press(&mut app, &[Key::Char('s'), Key::Char('y')]);
    let [Effect::SaveSystem(text)] = &effects[..] else {
        panic!("{effects:?}");
    };
    assert!(text.contains("[sweep]\nroot = \"allowed\""), "{text}");
    assert!(text.contains("profile = \"standard\""), "{text}");
}

/// A system file with every setting no field of the app shows.
fn system_only() -> PartialConfig {
    let mut system = PartialConfig {
        trusted_reviewer_packages: Some(vec!["opencode-bin".into()]),
        acknowledged_weaker: Some(vec!["aur.ai=off".into()]),
        permit_strict: Some(true),
        update_check: Some(false),
        ..PartialConfig::default()
    };
    system.sweep.root = Some(RootConsent::Allowed);
    system
}

#[test]
fn saving_a_kept_draft_does_not_undo_what_changed_in_the_file() {
    let mut app = App::new(
        loaded(PartialConfig::default(), system_only()),
        Mode::Expert,
    );
    press(&mut app, &[Key::Down, Key::Char(' ')]);
    // Meanwhile, elsewhere: the acknowledgement and the rest are revoked,
    // and a setting that has a field here is set.
    let mut revoked = PartialConfig::default();
    revoked.agent.model = Some("opencode/free".into());
    settle(
        &mut app,
        &toggle(),
        PartialConfig::default(),
        revoked.clone(),
    );
    assert_eq!(app.changed_count(), 1);

    let effects = press(&mut app, &[Key::Char('s'), Key::Char('y')]);
    let [Effect::SaveSystem(text)] = &effects[..] else {
        panic!("{effects:?}");
    };
    assert!(text.contains("profile = \"standard\""), "{text}");
    assert!(text.contains("model = \"opencode/free\""), "{text}");
    for gone in ["weaker", "[permit]", "trusted", "[sweep]", "[update]"] {
        assert!(!text.contains(gone), "{gone}: {text}");
    }
    revoked.profile = Some(Profile::Standard);
    assert_eq!(app.system, revoked);
}

#[test]
fn undoing_the_edit_of_a_kept_draft_leaves_nothing_unsaved() {
    let mut app = app();
    press(&mut app, &[Key::Char(' ')]);
    let user = PartialConfig {
        update_check: Some(false),
        ..PartialConfig::default()
    };
    settle(&mut app, &toggle(), user.clone(), PartialConfig::default());
    assert_eq!(app.user.update_check, Some(false));
    assert_eq!(app.changed_count(), 1);

    press(&mut app, &[Key::Char('u')]);
    assert_eq!(app.user, user);
    assert!(!screen(&mut app).contains("unsaved"));
    assert!(press(&mut app, &[Key::Char('s')]).is_empty());
    assert_eq!(press(&mut app, &[Key::Char('q')]), [Effect::Quit]);
    assert!(app.quit);
}

#[test]
fn edits_of_a_file_that_became_invalid_are_dropped_and_said() {
    let mut app = app();
    press(&mut app, &[Key::Char(' ')]);
    let mut broken = loaded(PartialConfig::default(), PartialConfig::default());
    broken.user_status = FileStatus::Invalid("line 1: expected key = value".into());
    assert!(app.settle(&toggle(), Ok("Done.".into()), || broken));

    assert_eq!(app.user, PartialConfig::default());
    let text = screen(&mut app);
    assert!(
        text.contains("The user file is no longer valid; your unsaved changes"),
        "{text}"
    );
    assert!(press(&mut app, &[Key::Char('s')]).is_empty());
    assert!(app.dialog.is_none());
}

#[test]
fn the_chained_system_save_stops_when_that_file_became_invalid() {
    let mut app = app();
    press(&mut app, &[Key::Char(' '), Key::Down, Key::Char(' ')]);
    let effects = press(&mut app, &[Key::Char('s')]);
    let [effect @ Effect::SaveUser(_)] = &effects[..] else {
        panic!("{effects:?}");
    };
    let mut broken = loaded(app.user.clone(), PartialConfig::default());
    broken.system_status = FileStatus::Invalid("not owned by root".into());
    app.settle(effect, Ok("Saved.".into()), || broken);

    assert!(app.dialog.is_none(), "{:?}", app.dialog);
    assert!(!app.dirty(Scope::System));
    assert!(screen(&mut app).contains("The system file is no longer valid"));
}

#[test]
fn a_file_that_cannot_be_read_is_not_saved_over() {
    for scope in [Scope::User, Scope::System] {
        let mut app = app();
        press(&mut app, &[Key::Char(' '), Key::Down, Key::Char(' ')]);
        let status = FileStatus::Invalid("line 3: unknown key".into());
        match scope {
            Scope::User => app.files.user_status = status,
            Scope::System => {
                app.files.system_status = status;
                // Only the system file is left to save.
                app.user = app.files.user.clone();
            }
        }
        assert!(press(&mut app, &[Key::Char('s')]).is_empty(), "{scope:?}");
        assert!(app.dialog.is_none(), "{scope:?}");
        assert!(screen(&mut app).contains("fix it under Maintenance"));
    }
}

#[test]
fn an_edit_taken_back_is_not_carried_over() {
    let mut app = app();
    // A class knob of the user file, set and cleared again: the draft is
    // left with an empty section for that class.
    press(&mut app, &[Key::Char('2')]);
    while !matches!(app.selected(), Some(Row::Field(field)) if field.scope == Scope::User) {
        press(&mut app, &[Key::Down]);
    }
    press(&mut app, &[Key::Char(' '), Key::Char('x')]);
    assert!(app.dirty(Scope::User));
    settle(
        &mut app,
        &toggle(),
        PartialConfig::default(),
        PartialConfig::default(),
    );
    assert_eq!(app.user, PartialConfig::default());
}

#[test]
fn clearing_what_the_file_no_longer_sets_is_not_a_change() {
    let mut user = PartialConfig::default();
    user.class_mut(SourceClass::Aur).ai = Some(AiRequirement::Off);
    let mut app = App::new(loaded(user, PartialConfig::default()), Mode::Expert);
    press(&mut app, &[Key::Char('2')]);
    while !matches!(app.selected(), Some(Row::Field(field)) if field.scope == Scope::User) {
        press(&mut app, &[Key::Down]);
    }
    press(&mut app, &[Key::Char('x')]);
    assert_eq!(app.changed_count(), 1);
    // Meanwhile the file lost that section.
    settle(
        &mut app,
        &toggle(),
        PartialConfig::default(),
        PartialConfig::default(),
    );
    assert_eq!(app.user, PartialConfig::default());
}

#[test]
fn reports_do_not_read_the_files_again() {
    let mut app = app();
    let effect = Effect::Report(Task::ShowConfig);
    assert!(!app.settle(&effect, Ok("line".into()), || panic!("read again")));
}

#[test]
fn invalid_numbers_stay_in_the_input_with_an_error() {
    let mut app = app();
    // AI tab: model, then input per call.
    press(&mut app, &[Key::Char('3'), Key::Down, Key::Enter]);
    press(&mut app, &[Key::Char('9'), Key::Enter]);
    let text = screen(&mut app);
    assert!(
        text.contains("expected a whole number from 16 to 1024"),
        "{text}"
    );
    press(
        &mut app,
        &[Key::Backspace, Key::Char('3'), Key::Char('2'), Key::Enter],
    );
    assert_eq!(app.user.agent.max_input_kib, Some(32));
}

#[test]
fn quitting_with_changes_asks_first() {
    let mut app = app();
    press(&mut app, &[Key::Char(' ')]);
    assert!(press(&mut app, &[Key::Char('q')]).is_empty());
    assert!(!app.quit);
    assert!(screen(&mut app).contains("Quit without saving?"));
    assert_eq!(press(&mut app, &[Key::Char('y')]), [Effect::Quit]);
    assert!(app.quit);

    let mut clean = App::new(
        loaded(PartialConfig::default(), PartialConfig::default()),
        Mode::Expert,
    );
    assert_eq!(press(&mut clean, &[Key::Char('q')]), [Effect::Quit]);
}

#[test]
fn an_invalid_file_cannot_be_edited_here() {
    let mut files = loaded(PartialConfig::default(), PartialConfig::default());
    files.user_status = FileStatus::Invalid("line 3: unknown key".into());
    let mut app = App::new(files, Mode::Expert);
    press(&mut app, &[Key::Enter]);
    assert!(screen(&mut app).contains("fix it under Maintenance"));
    assert_eq!(app.user, PartialConfig::default());
}

#[test]
fn maintenance_tasks_become_effects() {
    let mut app = app();
    let effects = press(&mut app, &[Key::Char('5'), Key::Enter]);
    assert!(matches!(&effects[..], [Effect::Report(_)]));
    app.finish(&effects[0], Ok("line one\nline two".into()));
    assert!(screen(&mut app).contains("line two"));
}

#[test]
fn small_windows_ask_to_grow() {
    let mut app = app();
    let mut canvas = Canvas::new(30, 8);
    app.draw(&mut canvas);
    assert!(canvas.rows()[0].contains("too small"));
}
