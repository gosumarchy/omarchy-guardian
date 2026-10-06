//! Tests for `app`.

use std::path::PathBuf;

use super::{App, Effect, Loaded, Mode, Tab, Task};
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
    for effect in [Effect::GuidedSetup, Effect::Edit(Scope::User)] {
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
