//! Simple mode: the protection level, the AI model, turning every gate on,
//! and a reset to defaults, with the Guardian mascot saying how things
//! stand. Expert mode (`e`) has every other setting.

use super::{App, Dialog, Effect, Tone, draw_dialog, value_hint, wrap};
use crate::config::file::AgentDefaults;
use crate::config::file::PartialConfig;
use crate::config::load::FileStatus;
use crate::config::model::{Named, Profile, SourceClass};
use crate::tui::canvas::{Canvas, Style, color};
use crate::tui::fields::{Field, Scope, Setting};
use crate::tui::integrations::{Integration, Plan, State};
use crate::tui::mascot::{self, Mood};
use crate::tui::term::Key;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Item {
    Level(Profile),
    Model,
    ProtectEverything,
    Defaults,
}

/// The protection levels, as the profiles they set.
const LEVELS: [(Profile, &str, &str); 3] = [
    (
        Profile::Standard,
        "Balanced",
        "AI review for AUR, themes and third-party packages",
    ),
    (
        Profile::Strict,
        "Maximum",
        "AI review for everything; any finding blocks",
    ),
    (
        Profile::LocalOnly,
        "Private",
        "No AI: nothing leaves this machine; you confirm installs",
    ),
];

/// The gates that protect installs. The menu entry is a convenience, not
/// protection.
const GATES: [Integration; 3] = [
    Integration::PacmanHook,
    Integration::AurGate,
    Integration::ThemeInterceptor,
];

fn level_name(profile: Profile) -> &'static str {
    LEVELS
        .iter()
        .find(|(candidate, _, _)| *candidate == profile)
        .map_or("Custom", |(_, name, _)| name)
}

impl App {
    fn simple_items(&self) -> Vec<Item> {
        let mut items: Vec<Item> = LEVELS
            .iter()
            .map(|(profile, _, _)| Item::Level(*profile))
            .collect();
        items.push(Item::Model);
        if !self.gates_off().is_empty() {
            items.push(Item::ProtectEverything);
        }
        items.push(Item::Defaults);
        items
    }

    fn simple_selected(&self) -> Option<Item> {
        let items = self.simple_items();
        items
            .get(self.simple_cursor.min(items.len().saturating_sub(1)))
            .copied()
    }

    /// The level both files agree on, or `None` when they differ.
    fn level(&self) -> Option<Profile> {
        let settings = self.settings();
        let user = settings.profile_for(SourceClass::Source);
        (user == settings.system_profile()).then_some(user)
    }

    /// Gates that exist here but are not on.
    fn gates_off(&self) -> Vec<Integration> {
        self.integrations
            .iter()
            .filter(|(integration, state)| {
                GATES.contains(integration)
                    && matches!(state, State::Off | State::Foreign(_) | State::Partial(_))
            })
            .map(|(integration, _)| *integration)
            .collect()
    }

    /// Anything set beyond what simple mode edits.
    fn has_expert_settings(&self) -> bool {
        [&self.user, &self.system].iter().any(|config| {
            let simple = PartialConfig {
                profile: config.profile,
                agent: AgentDefaults {
                    model: config.agent.model.clone(),
                    variants: config.agent.variants.clone(),
                    ..Default::default()
                },
                ..PartialConfig::default()
            };
            simple != **config
        })
    }

    fn files_invalid(&self) -> bool {
        [&self.files.user_status, &self.files.system_status]
            .iter()
            .any(|status| matches!(status, FileStatus::Invalid(_)))
    }

    fn mood(&self) -> Mood {
        if self.files_invalid() || !self.gates_off().is_empty() {
            return Mood::Worried;
        }
        match self.level() {
            Some(Profile::Strict) => Mood::Vigilant,
            Some(Profile::LocalOnly) => Mood::Private,
            Some(Profile::Standard) | None => Mood::Calm,
        }
    }

    /// What the Guardian says, and in which colour.
    fn speech(&self) -> (String, u8) {
        if self.files_invalid() {
            return (
                "I can't read one of my settings files. Press e and fix it under Maintenance."
                    .into(),
                color::YELLOW,
            );
        }
        if self.dirty(Scope::User) || self.dirty(Scope::System) {
            return (
                "You have unsaved changes. Press s to save them.".into(),
                color::YELLOW,
            );
        }
        // A gate that is on but not doing its whole job is the more
        // surprising problem, so it is named first.
        let partial = self
            .integrations
            .iter()
            .find_map(|(gate, state)| match state {
                State::Partial(reason) if GATES.contains(gate) => Some((*gate, reason.clone())),
                _ => None,
            });
        if let Some((gate, reason)) = partial {
            return (
                format!(
                    "My {} gate is {reason}. Choose Protect everything to fix it.",
                    gate_name(gate)
                ),
                color::YELLOW,
            );
        }
        let off = self.gates_off();
        if !off.is_empty() {
            let names: Vec<&str> = off.iter().map(|gate| gate_name(*gate)).collect();
            let list = match names.split_last() {
                Some((last, rest)) if !rest.is_empty() => format!("{} or {last}", rest.join(", ")),
                _ => names.concat(),
            };
            return (
                format!(
                    "I'm not watching {list} yet. Choose Protect everything below so nothing slips past me."
                ),
                color::YELLOW,
            );
        }
        let text = match self.level() {
            None => {
                "Your own sources and pacman use different levels. Pick one to protect both the same way."
            }
            Some(Profile::Standard) => {
                "Balanced protection is on. I read AUR builds, themes and third-party packages before they run."
            }
            Some(Profile::Strict) => {
                "Maximum protection. Everything needs a clear AI review, and any finding stops the install."
            }
            Some(Profile::LocalOnly) => {
                "Private mode. Nothing leaves this machine: I check locally and ask you before anything runs."
            }
        };
        (text.into(), color::GREEN)
    }

    pub(super) fn handle_simple(&mut self, key: Key) -> Option<Effect> {
        let count = self.simple_items().len();
        match key {
            Key::Char('q') | Key::Escape | Key::Interrupt => self.request_quit(),
            Key::Up | Key::Char('k') => {
                self.simple_cursor = self.simple_cursor.min(count - 1).saturating_sub(1);
                None
            }
            Key::Down | Key::Char('j') | Key::Tab => {
                self.simple_cursor = (self.simple_cursor + 1).min(count - 1);
                None
            }
            Key::Home | Key::Char('g') => {
                self.simple_cursor = 0;
                None
            }
            Key::End | Key::Char('G') => {
                self.simple_cursor = count - 1;
                None
            }
            Key::Char(digit @ '1'..='3') => {
                let index = digit.to_digit(10).map_or(0, |number| number as usize - 1);
                self.simple_cursor = index;
                self.activate_simple()
            }
            Key::Enter | Key::Char(' ') => self.activate_simple(),
            Key::Char('s') => self.save(),
            _ => None,
        }
    }

    fn activate_simple(&mut self) -> Option<Effect> {
        let item = self.simple_selected()?;
        if self.files_invalid() && item != Item::ProtectEverything {
            let scope = if matches!(self.files.user_status, FileStatus::Invalid(_)) {
                Scope::User
            } else {
                Scope::System
            };
            self.editable(scope);
            return None;
        }
        match item {
            Item::Level(profile) => {
                let user = Field::new(Scope::User, Setting::Profile);
                let system = Field::new(Scope::System, Setting::Profile);
                if let Err(error) = self.set_both(user, Some(system), Some(profile.name())) {
                    self.message = Some((error, Tone::Bad));
                }
                None
            }
            Item::Model => {
                let user = Field::new(Scope::User, Setting::AgentModel);
                if self.models.is_none() {
                    self.say("Asking OpenCode for its models…");
                    return Some(Effect::LoadModels(user));
                }
                self.open_model_picker(user, Some(Field::new(Scope::System, Setting::AgentModel)));
                None
            }
            Item::ProtectEverything => {
                let paths = self.files.paths.as_ref()?;
                let mut steps = Vec::new();
                for gate in self.gates_off() {
                    let state = self
                        .integrations
                        .iter()
                        .find(|(candidate, _)| *candidate == gate)
                        .map(|(_, state)| state.clone())?;
                    if let Some(plan) = paths.plan(gate, &state) {
                        steps.extend(plan.steps);
                    }
                }
                let plan = Plan {
                    summary: "Protect everything".into(),
                    steps,
                };
                self.dialog = Some(Dialog::Confirm {
                    title: "Turn on every gate?".into(),
                    lines: plan.describe(paths),
                    effect: Effect::Integration(plan),
                });
                None
            }
            Item::Defaults => {
                self.dialog = Some(Dialog::Confirm {
                    title: "Reset to defaults?".into(),
                    lines: vec![
                        "Balanced protection and OpenCode's default model, for your".into(),
                        "sources and for pacman. Every expert setting is removed.".into(),
                        "Nothing is written until you press s.".into(),
                    ],
                    effect: Effect::ResetDefaults,
                });
                None
            }
        }
    }

    pub(super) fn reset_defaults(&mut self) {
        self.user = PartialConfig::default();
        self.system = PartialConfig::default();
        if self.dirty(Scope::User) || self.dirty(Scope::System) {
            self.say("Defaults set. Press s to save.");
        } else {
            self.say("Already at the defaults.");
        }
    }

    pub(super) fn draw_simple(&mut self, canvas: &mut Canvas) {
        let (width, height) = (canvas.width, canvas.height);
        let border = Style::fg(color::MUTED);
        canvas.frame(0, 0, width, height, border);
        let end = canvas.text(2, 0, " \u{f0483} ", Style::fg(color::ACCENT).bold(), 4);
        canvas.text(
            end,
            0,
            "Omarchy Guardian ",
            Style::fg(color::ACCENT).bold(),
            20,
        );
        let version = format!(" v{} ", env!("CARGO_PKG_VERSION"));
        canvas.text(width - 2 - version.chars().count(), 0, &version, border, 12);

        self.simple_cursor = self.simple_cursor.min(self.simple_items().len() - 1);
        let (speech, tone) = self.speech();
        let with_mascot = height >= 27;
        let mut y = 2;
        if with_mascot {
            mascot::draw(canvas, 3, 1, self.mood(), self.blinking());
            let bubble_x = 4 + mascot::WIDTH + 2;
            let bubble_width = width.saturating_sub(bubble_x + 3).min(60);
            let lines = wrap(&speech, bubble_width.saturating_sub(5));
            mascot::bubble(
                canvas,
                bubble_x,
                2,
                bubble_width,
                &lines[..lines.len().min(4)],
                tone,
            );
            y = 1 + mascot::HEIGHT + 1;
        }
        y = self.draw_levels(canvas, y);
        y = self.draw_model(canvas, y + 1);
        y = self.draw_gates(canvas, y + 1);
        y = self.draw_actions(canvas, y);
        let footer = height - 4;
        if self.has_expert_settings() && y + 1 < footer {
            canvas.text_fit(
                6,
                y + 1,
                "Some expert settings are set too; press e to see them.",
                Style::fg(color::MUTED),
                width - 10,
            );
        }
        self.draw_simple_footer(canvas, if with_mascot { None } else { Some(speech) });
    }

    /// Highlights the row of item `index` when it has the cursor; returns
    /// the style to draw it with.
    fn simple_row(&self, canvas: &mut Canvas, y: usize, index: usize) -> Style {
        if index == self.simple_cursor && self.dialog.is_none() {
            canvas.fill(1, y, canvas.width - 2, Style::PLAIN.reverse());
            Style::PLAIN.reverse()
        } else {
            Style::PLAIN
        }
    }

    fn draw_levels(&self, canvas: &mut Canvas, mut y: usize) -> usize {
        let inner = canvas.width - 4;
        let current = self.level();
        canvas.text(
            2,
            y,
            "Protection level",
            Style::fg(color::ACCENT).bold(),
            inner,
        );
        y += 1;
        for (index, (profile, name, summary)) in LEVELS.iter().enumerate() {
            let base = self.simple_row(canvas, y, index);
            let chosen = current == Some(*profile);
            let (mark, fg) = if chosen {
                ("●", color::GREEN)
            } else {
                ("○", color::MUTED)
            };
            canvas.text(4, y, mark, base.with_fg(fg).bold(), 1);
            canvas.text(6, y, name, if chosen { base.bold() } else { base }, 10);
            canvas.text_fit(
                17,
                y,
                summary,
                base.with_fg(color::MUTED),
                inner.saturating_sub(15),
            );
            y += 1;
        }
        if current.is_none() {
            let settings = self.settings();
            let text = format!(
                "now: {} for your sources, {} for pacman",
                level_name(settings.profile_for(SourceClass::Source)),
                level_name(settings.system_profile())
            );
            canvas.text_fit(6, y, &text, Style::fg(color::YELLOW), inner - 4);
            y += 1;
        }
        y
    }

    fn draw_model(&self, canvas: &mut Canvas, mut y: usize) -> usize {
        let inner = canvas.width - 4;
        let settings = self.settings();
        canvas.text(
            2,
            y,
            "AI provider & model",
            Style::fg(color::ACCENT).bold(),
            inner,
        );
        y += 1;
        let base = self.simple_row(canvas, y, LEVELS.len());
        let model = Field::new(Scope::User, Setting::AgentModel).effective(
            &settings,
            &self.user,
            &self.system,
        );
        let pacman = Field::new(Scope::System, Setting::AgentModel).effective(
            &settings,
            &self.user,
            &self.system,
        );
        canvas.text(6, y, "Model", base, 10);
        canvas.text_fit(
            17,
            y,
            &model,
            base.with_fg(color::GREEN).bold(),
            inner.saturating_sub(15),
        );
        y += 1;
        if pacman != model {
            canvas.text_fit(
                17,
                y,
                &format!("pacman uses {pacman}"),
                Style::fg(color::MUTED),
                inner.saturating_sub(15),
            );
            y += 1;
        }
        y
    }

    fn draw_gates(&self, canvas: &mut Canvas, mut y: usize) -> usize {
        let inner = canvas.width - 4;
        canvas.text(
            2,
            y,
            "Where I watch",
            Style::fg(color::ACCENT).bold(),
            inner,
        );
        y += 1;
        let mut x = 6;
        for gate in GATES {
            let state = self
                .integrations
                .iter()
                .find(|(candidate, _)| *candidate == gate)
                .map(|(_, state)| state);
            let (label, fg) = match state {
                Some(State::On) => ("● on", color::GREEN),
                Some(State::Off | State::Foreign(_)) => ("○ off", color::YELLOW),
                Some(State::Partial(_)) => ("◐ partly", color::YELLOW),
                Some(State::Unavailable(_)) | None => ("– n/a", color::MUTED),
            };
            x = canvas.text(x, y, gate_name(gate), Style::PLAIN, inner) + 1;
            x = canvas.text(x, y, label, Style::fg(fg), inner) + 3;
        }
        y + 1
    }

    fn draw_actions(&self, canvas: &mut Canvas, mut y: usize) -> usize {
        let items = self.simple_items();
        for (index, item) in items.iter().enumerate().skip(LEVELS.len() + 1) {
            match item {
                Item::ProtectEverything => {
                    let base = self.simple_row(canvas, y, index);
                    canvas.text(4, y, "›", base.with_fg(color::YELLOW).bold(), 1);
                    canvas.text(6, y, "Protect everything", base.bold(), 30);
                }
                Item::Defaults => {
                    y += 1;
                    let base = self.simple_row(canvas, y, index);
                    canvas.text(6, y, "Reset to defaults", base, 30);
                }
                Item::Level(_) | Item::Model => {}
            }
            y += 1;
        }
        y
    }

    /// Help for the selected item (or, without the mascot, what it would
    /// say), the last message and the keys.
    fn draw_simple_footer(&self, canvas: &mut Canvas, speech: Option<String>) {
        let (width, height) = (canvas.width, canvas.height);
        let inner = width - 4;
        let border = Style::fg(color::MUTED);
        let footer = height - 4;
        canvas.divider(0, footer, width, border);
        let help = speech.unwrap_or_else(|| self.simple_help());
        canvas.text_fit(2, footer + 1, &help, Style::fg(color::MUTED), inner);
        if let Some((text, tone)) = &self.message {
            let (fg, mark) = match tone {
                Tone::Info => (color::CYAN, "›"),
                Tone::Good => (color::GREEN, "✓"),
                Tone::Bad => (color::RED, "✗"),
            };
            canvas.text_fit(
                2,
                footer + 2,
                &format!("{mark} {text}"),
                Style::fg(fg).bold(),
                inner,
            );
        }
        let keys = if self.dialog.is_some() {
            " enter select · esc close "
        } else {
            " ↑↓ move  enter choose  s save  e expert mode  q quit "
        };
        canvas.text_fit(2, height - 1, keys, border, inner);
        if let Some(dialog) = &self.dialog {
            draw_dialog(canvas, dialog, &value_hint(dialog));
        }
    }

    fn simple_help(&self) -> String {
        match self.simple_selected() {
            Some(Item::Level(_)) => {
                "The level for AUR builds, themes, scans and pacman (pacman's is saved with sudo)."
            }
            Some(Item::Model) => "The OpenCode model that reviews for you and for pacman.",
            Some(Item::ProtectEverything) => {
                "Turns on the pacman hook, the AUR gate and the theme gate (asks for sudo)."
            }
            Some(Item::Defaults) => "Back to Balanced and OpenCode's default model.",
            None => "",
        }
        .into()
    }
}

const fn gate_name(gate: Integration) -> &'static str {
    match gate {
        Integration::PacmanHook => "pacman",
        Integration::AurGate => "AUR",
        Integration::ThemeInterceptor => "themes",
        Integration::MenuEntry => "menu",
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::super::{App, Effect, Loaded, Mode};
    use crate::config::file::PartialConfig;
    use crate::config::load::FileStatus;
    use crate::config::model::Profile;
    use crate::test_support::TempDir;
    use crate::tui::canvas::Canvas;
    use crate::tui::integrations::{Paths, Step};
    use crate::tui::term::Key;

    fn files(paths: Option<Paths>) -> Loaded {
        Loaded {
            user: PartialConfig::default(),
            system: PartialConfig::default(),
            user_status: FileStatus::Missing,
            system_status: FileStatus::Missing,
            system_path: PathBuf::from("/etc/omarchy-guardian/config.toml"),
            system_text: String::new(),
            paths,
        }
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
    fn shows_the_mascot_levels_and_model() {
        let mut app = App::new(files(None), Mode::Simple);
        let text = screen(&mut app);
        assert!(text.contains("▄█▀▀▀██████▄"), "{text}");
        assert!(text.contains("██▀▀████▀▀██"), "open eyes: {text}");
        assert!(text.contains("● Balanced"));
        assert!(text.contains("Balanced protection is on"));
        assert!(text.contains("OpenCode default"));
        assert!(!text.contains("Protect everything"));
    }

    #[test]
    fn a_level_sets_both_files_and_saves_through_both() {
        let mut app = App::new(files(None), Mode::Simple);
        press(&mut app, &[Key::Char('2')]);
        assert_eq!(app.user.profile, Some(Profile::Strict));
        assert_eq!(app.system.profile, Some(Profile::Strict));
        assert!(screen(&mut app).contains("unsaved changes"));

        let effects = press(&mut app, &[Key::Char('s')]);
        let [effect @ Effect::SaveUser(_)] = &effects[..] else {
            panic!("{effects:?}");
        };
        app.finish(effect, Ok("Saved.".into()));
        assert!(screen(&mut app).contains("Save the system file?"));
    }

    #[test]
    fn mixed_levels_are_shown_and_resolved_by_picking_one() {
        let mut loaded = files(None);
        loaded.user.profile = Some(Profile::LocalOnly);
        let mut app = App::new(loaded, Mode::Simple);
        let text = screen(&mut app);
        assert!(
            text.contains("now: Private for your sources, Balanced for pacman"),
            "{text}"
        );
        press(&mut app, &[Key::Char('1')]);
        assert!(screen(&mut app).contains("● Balanced"));
    }

    #[test]
    fn protect_everything_turns_on_every_gate_that_is_off() {
        let dir = TempDir::new("simple-gates");
        let root = dir.path();
        fs::create_dir_all(root.join("omarchy")).unwrap();
        fs::write(root.join("hook"), "").unwrap();
        fs::write(root.join("yay"), "").unwrap();
        fs::write(root.join("installer"), "").unwrap();
        let paths = Paths {
            hook_source: root.join("hook"),
            hook_target: root.join("hooks/hook"),
            yay: root.join("yay"),
            yay_config: root.join("yay.json"),
            interceptor_installer: root.join("installer"),
            bashrc: root.join("bashrc"),
            omarchy: root.join("omarchy"),
            menu: root.join("menu.jsonc"),
            opencode_missing: false,
        };
        let mut app = App::new(files(Some(paths)), Mode::Simple);
        assert!(screen(&mut app).contains("not watching pacman, AUR or themes"));

        // Levels, model, then Protect everything.
        press(&mut app, &[Key::Down, Key::Down, Key::Down, Key::Down]);
        assert!(press(&mut app, &[Key::Enter]).is_empty());
        let effects = press(&mut app, &[Key::Char('y')]);
        let [Effect::Integration(plan)] = &effects[..] else {
            panic!("{effects:?}");
        };
        let commands = plan
            .steps
            .iter()
            .filter(|step| matches!(step, Step::Command(_)))
            .count();
        assert_eq!(commands, 4, "{plan:?}");
    }

    #[test]
    fn e_switches_between_simple_and_expert() {
        let mut app = App::new(files(None), Mode::Simple);
        press(&mut app, &[Key::Char('e')]);
        assert!(screen(&mut app).contains("1 Profiles"));
        press(&mut app, &[Key::Char('e')]);
        assert!(screen(&mut app).contains("Protection level"));
    }

    #[test]
    fn reset_to_defaults_only_changes_drafts() {
        let mut loaded = files(None);
        loaded.user.profile = Some(Profile::Strict);
        let mut app = App::new(loaded, Mode::Simple);
        press(&mut app, &[Key::End, Key::Enter]);
        assert!(screen(&mut app).contains("Reset to defaults?"));
        assert!(press(&mut app, &[Key::Char('y')]).is_empty());
        assert_eq!(app.user, PartialConfig::default());
        assert!(screen(&mut app).contains("Press s to save"));
    }
}
