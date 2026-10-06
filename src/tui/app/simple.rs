//! Simple mode: the protection level, the AI model, turning every gate on,
//! and a reset to defaults, with the Guardian mascot saying how things
//! stand. Expert mode (`e`) has every other setting.

use super::{App, Dialog, Effect, Mode, Tone, draw_dialog, value_hint, wrap};
use crate::config::file::AgentDefaults;
use crate::config::file::PartialConfig;
use crate::config::load::FileStatus;
use crate::config::model::{Named, Profile, SourceClass};
use crate::integrations::{Integration, Plan, State};
use crate::tui::canvas::{Canvas, Style, color};
use crate::tui::fields::{Field, Scope, Setting};
use crate::tui::mascot::{self, Mood};
use crate::tui::term::Key;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Item {
    Level(Profile),
    Model,
    ProtectEverything,
    Test,
    Expert,
    Defaults,
}

/// The protection levels, as the profiles they set.
const LEVELS: [(Profile, &str, &str); 3] = [
    (
        Profile::Standard,
        "Balanced",
        "AI review for all sources; lenient for official packages",
    ),
    (
        Profile::Strict,
        "Maximum",
        "AI review for everything; any finding blocks",
    ),
    (
        Profile::LocalOnly,
        "Private",
        "No AI: source stays here; you confirm your own installs",
    ),
];

/// The gates that protect installs. The menu entry is a convenience, not
/// protection.
const GATES: [Integration; 5] = [
    Integration::PacmanHook,
    Integration::AurGate,
    Integration::ThemeInterceptor,
    Integration::SessionPath,
    Integration::SystemSweep,
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
        items.extend([Item::Test, Item::Expert, Item::Defaults]);
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
                "Balanced protection is on. I read packages, AUR builds, themes and plugins before they run."
            }
            Some(Profile::Strict) => {
                "Maximum protection. Everything needs a clear AI review, and any finding stops the install."
            }
            Some(Profile::LocalOnly) => {
                "Private mode. No source goes to an AI: I check locally and ask before your own installs run."
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
            Key::Char('t') => Some(self.test_reviewer()),
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
            Item::Test => Some(self.test_reviewer()),
            Item::Expert => {
                self.mode = Mode::Expert;
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
        let with_mascot = height >= 28;
        let mut y = 2;
        if with_mascot {
            mascot::draw(canvas, 3, 1, self.mood(), self.blinking());
            y = self.draw_hero(canvas, 4 + mascot::WIDTH + 2, &speech, tone);
            y = y.max(1 + mascot::HEIGHT);
        }
        y = self.draw_levels(canvas, y);
        y = self.draw_model(canvas, y);
        y = self.draw_gates(canvas, y);
        y = self.draw_actions(canvas, y, height - 5);
        let footer = height - 4;
        if self.has_expert_settings() && y < footer {
            canvas.text_fit(
                3,
                y,
                "Some expert settings are set too; press e to see them.",
                Style::fg(color::MUTED),
                width - 6,
            );
        }
        self.draw_simple_footer(canvas, if with_mascot { None } else { Some(speech) });
    }

    /// Beside the knight: the name, the level and model as a dim uppercase
    /// line, and what the knight has to say. Returns the next free row.
    fn draw_hero(&self, canvas: &mut Canvas, x: usize, speech: &str, tone: u8) -> usize {
        let inner = canvas.width.saturating_sub(x + 3);
        let settings = self.settings();
        canvas.text(x, 3, "Guardian", Style::PLAIN.bold(), inner);
        let meta = format!(
            "{} · {}",
            self.level().map_or("Custom", level_name),
            Field::new(Scope::User, Setting::AgentModel).effective(
                &settings,
                &self.user,
                &self.system
            )
        )
        .to_uppercase();
        canvas.text_fit(x, 4, &meta, Style::fg(color::MUTED), inner);
        let mut y = 6;
        for line in wrap(speech, inner).iter().take(3) {
            canvas.text(x, y, line, Style::fg(tone), inner);
            y += 1;
        }
        y
    }

    /// A thin rule and a dim uppercase section name; returns the next row.
    fn section(canvas: &mut Canvas, y: usize, title: &str) -> usize {
        let rule = "─".repeat(canvas.width - 6);
        canvas.text(3, y, &rule, Style::fg(color::MUTED), canvas.width - 6);
        canvas.text(
            3,
            y + 1,
            title,
            Style::fg(color::MUTED).bold(),
            canvas.width - 6,
        );
        y + 2
    }

    /// A status word right-aligned on row `y`, like the shell's panels.
    fn status_word(canvas: &mut Canvas, y: usize, word: &str, style: Style) {
        let x = canvas.width - 3 - word.chars().count();
        canvas.text(x, y, word, style, word.chars().count());
    }

    /// Marks the row of item `index` when it has the cursor (an accent bar
    /// and bold text); returns the style to draw it with.
    fn simple_row(&self, canvas: &mut Canvas, y: usize, index: usize) -> Style {
        if index == self.simple_cursor && self.dialog.is_none() {
            canvas.text(1, y, "▌", Style::fg(color::ACCENT), 1);
            Style::PLAIN.bold()
        } else {
            Style::PLAIN
        }
    }

    fn draw_levels(&self, canvas: &mut Canvas, y: usize) -> usize {
        let inner = canvas.width - 6;
        let current = self.level();
        let mut y = Self::section(canvas, y, "PROTECTION LEVEL");
        for (index, (profile, name, summary)) in LEVELS.iter().enumerate() {
            let base = self.simple_row(canvas, y, index);
            let chosen = current == Some(*profile);
            canvas.text(3, y, name, base, 10);
            canvas.text_fit(
                14,
                y,
                summary,
                Style::fg(color::MUTED),
                inner.saturating_sub(20),
            );
            if chosen {
                Self::status_word(canvas, y, "ACTIVE", Style::fg(color::ACCENT).bold());
            }
            y += 1;
        }
        if current.is_none() {
            let settings = self.settings();
            let text = format!(
                "now: {} for your sources, {} for pacman",
                level_name(settings.profile_for(SourceClass::Source)),
                level_name(settings.system_profile())
            );
            canvas.text_fit(3, y, &text, Style::fg(color::YELLOW), inner);
            y += 1;
        }
        y
    }

    fn draw_model(&self, canvas: &mut Canvas, y: usize) -> usize {
        let inner = canvas.width - 6;
        let settings = self.settings();
        let mut y = Self::section(canvas, y, "AI MODEL");
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
        canvas.text(3, y, "Model", base, 10);
        canvas.text_fit(14, y, &model, base, inner.saturating_sub(12));
        y += 1;
        if pacman != model {
            canvas.text_fit(
                14,
                y,
                &format!("pacman uses {pacman}"),
                Style::fg(color::MUTED),
                inner.saturating_sub(12),
            );
            y += 1;
        }
        y
    }

    fn draw_gates(&self, canvas: &mut Canvas, y: usize) -> usize {
        let mut y = Self::section(canvas, y, "GATES");
        for gate in GATES {
            let state = self
                .integrations
                .iter()
                .find(|(candidate, _)| *candidate == gate)
                .map(|(_, state)| state);
            let (word, fg) = match state {
                Some(State::On) => ("ON", color::ACCENT),
                Some(State::Off | State::Foreign(_)) => ("OFF", color::RED),
                Some(State::Partial(_)) => ("PARTLY", color::YELLOW),
                Some(State::Unavailable(_)) | None => ("N/A", color::MUTED),
            };
            canvas.text(3, y, gate.label(), Style::PLAIN, canvas.width - 14);
            Self::status_word(canvas, y, word, Style::fg(fg).bold());
            y += 1;
        }
        y
    }

    /// The actions as tiles (a glyph over a label) when there is room, else
    /// as plain rows.
    fn draw_actions(&self, canvas: &mut Canvas, y: usize, bottom: usize) -> usize {
        let items = self.simple_items();
        let actions: Vec<(usize, &str, &str)> = items
            .iter()
            .enumerate()
            .skip(LEVELS.len() + 1)
            .filter_map(|(index, item)| match item {
                Item::ProtectEverything => Some((index, "\u{f0483}", "Protect everything")),
                Item::Test => Some((index, "\u{f0668}", "Test reviewer")),
                Item::Expert => Some((index, "\u{f0493}", "Expert mode")),
                Item::Defaults => Some((index, "\u{f0450}", "Reset to defaults")),
                Item::Level(_) | Item::Model => None,
            })
            .collect();
        let y = y + 1;
        let tile_width = ((canvas.width - 6).saturating_sub(2 * (actions.len().max(1) - 1))
            / actions.len().max(1))
        .min(24);
        if y + 4 <= bottom {
            let mut x = 3;
            for (index, glyph, label) in &actions {
                let selected = *index == self.simple_cursor && self.dialog.is_none();
                let edge = if selected {
                    Style::fg(color::ACCENT)
                } else {
                    Style::fg(color::MUTED)
                };
                canvas.frame(x, y, tile_width, 4, edge);
                let center = |text: &str| x + (tile_width - text.chars().count()) / 2;
                canvas.text(
                    center(glyph),
                    y + 1,
                    glyph,
                    Style::fg(color::ACCENT).bold(),
                    2,
                );
                let style = if selected {
                    Style::PLAIN.bold()
                } else {
                    Style::PLAIN
                };
                canvas.text(center(label), y + 2, label, style, tile_width - 2);
                x += tile_width + 2;
            }
            y + 5
        } else {
            let mut y = y;
            for (index, _, label) in &actions {
                let base = self.simple_row(canvas, y, *index);
                canvas.text(3, y, label, base, 30);
                y += 1;
            }
            y
        }
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
            " ↑↓ move  enter choose  s save  t test  e expert mode  q quit "
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
                "Turns on the pacman hook, the AUR gate and the theme & plugin gate (asks for sudo)."
            }
            Some(Item::Test) => {
                "Sends a malicious and a harmless sample to the saved model; both must be judged right."
            }
            Some(Item::Expert) => "Every setting, integration and maintenance task.",
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
        Integration::ThemeInterceptor => "themes & plugins",
        Integration::SessionPath => "theme & plugin commands",
        Integration::MenuEntry => "menu",
        Integration::BarWidget => "bar widget",
        Integration::WaybarModule => "Waybar module",
        Integration::SystemSweep => "system sweep",
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::super::{App, Effect, Loaded, Mode, Task};
    use crate::config::file::PartialConfig;
    use crate::config::load::FileStatus;
    use crate::config::model::Profile;
    use crate::integrations::{Paths, Plan, Step};
    use crate::test_support::TempDir;
    use crate::tui::canvas::Canvas;
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

    /// Whether the row for `level` carries the ACTIVE status word.
    fn active_level(text: &str, level: &str) -> bool {
        text.lines()
            .any(|line| line.contains(&format!(" {level} ")) && line.contains("ACTIVE"))
    }

    #[test]
    fn shows_the_mascot_levels_and_model() {
        let mut app = App::new(files(None), Mode::Simple);
        let text = screen(&mut app);
        assert!(text.contains("▄█▀▀▀██████▄"), "{text}");
        assert!(text.contains("██▀▀████▀▀██"), "open eyes: {text}");
        assert!(active_level(&text, "Balanced"), "{text}");
        assert!(text.contains("Balanced protection is on"));
        assert!(text.contains("OpenCode default"));
        assert!(!text.contains("Protect everything"));
    }

    #[test]
    fn the_model_picker_suggests_claude_code_when_nothing_is_set() {
        let mut app = App::new(files(None), Mode::Simple);
        let effects = press(&mut app, &[Key::Down, Key::Down, Key::Down, Key::Enter]);
        let [effect @ Effect::LoadModels(_)] = &effects[..] else {
            panic!("{effects:?}");
        };
        app.finish(
            effect,
            Ok("claude-code/claude-sonnet-5-5\nclaude-code/claude-haiku-4-5\nopencode/free".into()),
        );
        press(&mut app, &[Key::Enter]);
        assert_eq!(
            app.user.agent.model.as_deref(),
            Some("claude-code/claude-sonnet-5-5")
        );
        assert_eq!(
            app.system.agent.model.as_deref(),
            Some("claude-code/claude-sonnet-5-5")
        );
    }

    #[test]
    fn t_tests_the_saved_reviewer_and_shows_the_result() {
        let mut app = App::new(files(None), Mode::Simple);
        let effects = press(&mut app, &[Key::Char('t')]);
        assert_eq!(effects, [Effect::Report(Task::TestReviewer)]);
        assert!(screen(&mut app).contains("malicious and a harmless sample"));

        press(&mut app, &[Key::Char('2')]);
        press(&mut app, &[Key::Char('t')]);
        assert!(screen(&mut app).contains("unsaved changes are not tested"));

        app.finish(&effects[0], Ok("✓ AUR, themes and plugins: passed".into()));
        assert!(screen(&mut app).contains("AUR, themes and plugins: passed"));
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
    fn a_level_reaches_the_system_file_after_the_user_file_is_saved() {
        let mut app = App::new(files(None), Mode::Simple);
        press(&mut app, &[Key::Char('2')]);
        let effects = press(&mut app, &[Key::Char('s')]);
        let [effect @ Effect::SaveUser(_)] = &effects[..] else {
            panic!("{effects:?}");
        };
        // What the event loop reads back: the user file as just written.
        let mut written = files(None);
        written.user = app.user.clone();
        assert!(app.settle(effect, Ok("Saved.".into()), || written));

        assert_eq!(app.system.profile, Some(Profile::Strict));
        let text = screen(&mut app);
        assert!(text.contains("Save the system file?"), "{text}");
        assert!(text.contains("+ profile = \"strict\""), "{text}");
        let effects = press(&mut app, &[Key::Char('y')]);
        let [Effect::SaveSystem(saved)] = &effects[..] else {
            panic!("{effects:?}");
        };
        assert!(saved.contains("profile = \"strict\""), "{saved}");
    }

    #[test]
    fn turning_the_gates_on_keeps_an_unsaved_level() {
        let dir = TempDir::new("simple-toggle");
        let mut app = App::new(files(None), Mode::Simple);
        press(&mut app, &[Key::Char('2')]);
        assert!(app.gates_off().is_empty());
        let effect = Effect::Integration(Plan {
            summary: "Protect everything".into(),
            steps: Vec::new(),
        });
        let read = files(Some(paths(dir.path())));
        assert!(app.settle(&effect, Ok("Done.".into()), || read));

        assert_eq!(app.user.profile, Some(Profile::Strict));
        assert_eq!(app.system.profile, Some(Profile::Strict));
        assert!(screen(&mut app).contains("unsaved changes"));
        // The gates themselves are looked at again.
        assert!(!app.gates_off().is_empty());
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
        assert!(active_level(&screen(&mut app), "Balanced"));
    }

    /// A machine under `root` where every gate can be turned on and none is.
    fn paths(root: &Path) -> Paths {
        fs::create_dir_all(root.join("omarchy")).unwrap();
        fs::write(root.join("hook"), "").unwrap();
        fs::write(root.join("yay"), "").unwrap();
        fs::write(root.join("installer"), "").unwrap();
        Paths {
            hook_source: root.join("hook"),
            hook_target: root.join("hooks/hook"),
            yay: root.join("yay"),
            yay_config: root.join("yay.json"),
            interceptor_installer: root.join("installer"),
            bashrc: root.join("bashrc"),
            omarchy: root.join("omarchy"),
            menu: root.join("menu.jsonc"),
            widget_source: root.join("widget"),
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
            login_shell: None,
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
    fn protect_everything_turns_on_every_gate_that_is_off() {
        let dir = TempDir::new("simple-gates");
        let mut app = App::new(files(Some(paths(dir.path()))), Mode::Simple);
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
        assert!(screen(&mut app).contains("PROTECTION LEVEL"));
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
