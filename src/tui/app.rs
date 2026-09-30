//! The settings TUI's state, key handling and drawing. Nothing here touches
//! the system: actions come back as `Effect`s for the event loop to carry
//! out, and their outcomes are reported back through `finish`.

use std::path::PathBuf;

use crate::config::Settings;
use crate::config::file::PartialConfig;
use crate::config::load::FileStatus;
use crate::config::model::{Named, Profile, SourceClass};
use crate::setup::line_diff;
use crate::tui::canvas::{Canvas, Style, color};
use crate::tui::fields::{Field, Input, Knob, Scope, Setting, validate};
use crate::tui::integrations::{Integration, Paths, Plan, State};
use crate::tui::term::Key;

mod simple;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Profiles,
    Sources,
    Ai,
    Integrations,
    Maintenance,
}

impl Tab {
    const ALL: [Self; 5] = [
        Self::Profiles,
        Self::Sources,
        Self::Ai,
        Self::Integrations,
        Self::Maintenance,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Profiles => "Profiles",
            Self::Sources => "Sources",
            Self::Ai => "AI",
            Self::Integrations => "Integrations",
            Self::Maintenance => "Maintenance",
        }
    }

    fn index(self) -> usize {
        Self::ALL.iter().position(|tab| *tab == self).unwrap_or(0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Task {
    ShowConfig,
    CheckConfig,
    ReviewMemory,
    ForgetMemory,
    GuidedSetup,
    EditUser,
    EditSystem,
}

impl Task {
    const fn label(self) -> &'static str {
        match self {
            Self::ShowConfig => "Show effective settings",
            Self::CheckConfig => "Check both config files",
            Self::ReviewMemory => "Review memory usage",
            Self::ForgetMemory => "Forget all review memory",
            Self::GuidedSetup => "Run guided setup",
            Self::EditUser => "Edit user file in $EDITOR",
            Self::EditSystem => "Edit system file (sudoedit)",
        }
    }

    const fn help(self) -> &'static str {
        match self {
            Self::ShowConfig => {
                "Every class's saved policy, with where each value comes from (`config show`)."
            }
            Self::CheckConfig => {
                "Validates both files and the system file's ownership (`config check`)."
            }
            Self::ReviewMemory => {
                "Where approved baselines and cached verdicts are kept, and their size."
            }
            Self::ForgetMemory => {
                "Drops every approved baseline and cached verdict; the next reviews run in full."
            }
            Self::GuidedSetup => {
                "Pick a profile and model, run a two-sample test review, and write both files."
            }
            Self::EditUser => {
                "Open the user file in your editor. Unsaved changes here are discarded."
            }
            Self::EditSystem => "Open /etc/omarchy-guardian/config.toml with sudoedit.",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Row {
    Header(String),
    Info(String),
    Blank,
    Field(Field),
    Integration(Integration),
    Task(Task),
}

impl Row {
    const fn selectable(&self) -> bool {
        matches!(self, Self::Field(_) | Self::Integration(_) | Self::Task(_))
    }
}

/// What the event loop is asked to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    SaveUser(String),
    SaveSystem(String),
    Integration(Plan),
    /// `config show`, `config check` or the review-memory line.
    Report(Task),
    ForgetMemory,
    GuidedSetup,
    Edit(Scope),
    LoadModels(Field),
    /// Simple mode's reset: drafts only, nothing is written.
    ResetDefaults,
    Quit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Dialog {
    Choice {
        field: Field,
        options: Vec<String>,
        selected: usize,
        /// Offer free text after the listed options (models).
        typed: bool,
        /// A second field set to the same value (simple mode sets one model
        /// for both files).
        also: Option<Field>,
    },
    Input {
        field: Field,
        buffer: String,
        error: Option<String>,
        also: Option<Field>,
    },
    Confirm {
        title: String,
        lines: Vec<String>,
        effect: Effect,
    },
    Pager {
        title: String,
        lines: Vec<String>,
        scroll: usize,
    },
}

/// An open choice list, taken apart for key handling.
struct Choice {
    field: Field,
    options: Vec<String>,
    selected: usize,
    typed: bool,
    also: Option<Field>,
}

/// Simple mode shows the essentials; expert mode every setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Simple,
    Expert,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tone {
    Info,
    Good,
    Bad,
}

/// The files as last read, and the drafts being edited.
pub struct Loaded {
    pub user: PartialConfig,
    pub system: PartialConfig,
    pub user_status: FileStatus,
    pub system_status: FileStatus,
    pub system_path: PathBuf,
    /// The system file's text, for the diff shown before saving it.
    pub system_text: String,
    pub paths: Option<Paths>,
}

impl Loaded {
    pub fn from_settings(settings: &Settings, system_text: String, paths: Option<Paths>) -> Self {
        Self {
            user: settings.user_config().clone(),
            system: settings.system_config().clone(),
            user_status: settings.user_status().clone(),
            system_status: settings.system_status().clone(),
            system_path: settings.system_path().to_path_buf(),
            system_text,
            paths,
        }
    }
}

pub struct App {
    tab: Tab,
    cursors: [usize; 5],
    scrolls: [usize; 5],
    files: Loaded,
    user: PartialConfig,
    system: PartialConfig,
    integrations: Vec<(Integration, State)>,
    dialog: Option<Dialog>,
    message: Option<(String, Tone)>,
    /// Ask to save the system file once the user file is saved.
    system_after_user: bool,
    models: Option<Vec<String>>,
    mode: Mode,
    simple_cursor: usize,
    /// Event-loop ticks, for the mascot's blink.
    ticks: u64,
    pub quit: bool,
}

impl App {
    pub fn new(files: Loaded, mode: Mode) -> Self {
        let mut app = Self {
            tab: Tab::Profiles,
            cursors: [0; 5],
            scrolls: [0; 5],
            user: files.user.clone(),
            system: files.system.clone(),
            files,
            integrations: Vec::new(),
            dialog: None,
            message: None,
            system_after_user: false,
            models: None,
            mode,
            simple_cursor: 0,
            ticks: 0,
            quit: false,
        };
        app.refresh_integrations();
        for tab in Tab::ALL {
            app.tab = tab;
            app.cursors[tab.index()] = app.next_selectable(0, 1).unwrap_or(0);
        }
        app.tab = Tab::Profiles;
        app
    }

    /// Replaces the files after a save, an edit or setup, keeping the
    /// position and any drafts of files that were not reloaded.
    pub fn reload(&mut self, files: Loaded) {
        self.user = files.user.clone();
        self.system = files.system.clone();
        self.files = files;
        self.refresh_integrations();
        for status in [&self.files.user_status, &self.files.system_status] {
            if let FileStatus::Invalid(reason) = status {
                self.message = Some((reason.clone(), Tone::Bad));
            }
        }
    }

    fn refresh_integrations(&mut self) {
        self.integrations = match &self.files.paths {
            Some(paths) => Integration::ALL
                .iter()
                .map(|integration| (*integration, paths.state(*integration)))
                .collect(),
            None => Vec::new(),
        };
    }

    fn settings(&self) -> Settings {
        Settings::from_parts(self.system.clone(), self.user.clone())
    }

    fn draft(&self, scope: Scope) -> &PartialConfig {
        match scope {
            Scope::User => &self.user,
            Scope::System => &self.system,
        }
    }

    fn saved(&self, scope: Scope) -> &PartialConfig {
        match scope {
            Scope::User => &self.files.user,
            Scope::System => &self.files.system,
        }
    }

    fn status(&self, scope: Scope) -> &FileStatus {
        match scope {
            Scope::User => &self.files.user_status,
            Scope::System => &self.files.system_status,
        }
    }

    fn dirty(&self, scope: Scope) -> bool {
        self.draft(scope) != self.saved(scope)
    }

    fn changed_count(&self) -> usize {
        Tab::ALL
            .iter()
            .flat_map(|tab| rows(*tab))
            .filter(|row| match row {
                Row::Field(field) => {
                    field.get(self.draft(field.scope)) != field.get(self.saved(field.scope))
                }
                _ => false,
            })
            .count()
    }

    pub fn say(&mut self, text: &str) {
        self.message = Some((text.to_string(), Tone::Info));
    }

    /// Reports how an effect went.
    pub fn finish(&mut self, effect: &Effect, outcome: Result<String, String>) {
        match outcome {
            Err(error) => {
                self.message = Some((error, Tone::Bad));
                self.system_after_user = false;
            }
            Ok(text) => match effect {
                Effect::Report(task) => {
                    self.dialog = Some(Dialog::Pager {
                        title: task.label().to_string(),
                        lines: text.lines().map(str::to_string).collect(),
                        scroll: 0,
                    });
                }
                Effect::LoadModels(field) => {
                    let models: Vec<String> = text.lines().map(str::to_string).collect();
                    self.models = Some(models);
                    let also = (self.mode == Mode::Simple)
                        .then_some(Field::new(Scope::System, Setting::AgentModel));
                    self.open_model_picker(*field, also);
                }
                Effect::SaveUser(_) => {
                    self.message = Some((text, Tone::Good));
                    if std::mem::take(&mut self.system_after_user) {
                        self.confirm_system_save();
                    }
                }
                _ => self.message = Some((text, Tone::Good)),
            },
        }
    }

    /// Called when no key arrived for a while; returns whether to redraw.
    pub fn tick(&mut self) -> bool {
        self.ticks += 1;
        self.mode == Mode::Simple && matches!(self.ticks % 20, 0 | 19)
    }

    fn blinking(&self) -> bool {
        // One 200 ms tick in twenty, never on the first frame.
        self.ticks % 20 == 19
    }

    pub fn handle(&mut self, key: Key) -> Option<Effect> {
        if self.dialog.is_some() {
            return self.handle_dialog(key);
        }
        self.message = None;
        if key == Key::Char('e') {
            self.mode = match self.mode {
                Mode::Simple => Mode::Expert,
                Mode::Expert => Mode::Simple,
            };
            return None;
        }
        if self.mode == Mode::Simple {
            return self.handle_simple(key);
        }
        match key {
            Key::Char('q') | Key::Escape | Key::Interrupt => self.request_quit(),
            Key::Tab | Key::Right | Key::Char('l') => self.switch_tab(1),
            Key::BackTab | Key::Left | Key::Char('h') => self.switch_tab(Tab::ALL.len() - 1),
            Key::Char(digit @ '1'..='5') => {
                let index = digit.to_digit(10).map_or(0, |number| number as usize - 1);
                self.tab = Tab::ALL[index];
                None
            }
            Key::Up | Key::Char('k') => self.move_cursor(-1),
            Key::Down | Key::Char('j') => self.move_cursor(1),
            Key::PageUp => self.move_cursor(-10),
            Key::PageDown => self.move_cursor(10),
            Key::Home | Key::Char('g') => {
                self.cursors[self.tab.index()] = self.next_selectable(0, 1).unwrap_or(0);
                None
            }
            Key::End | Key::Char('G') => {
                let last = rows(self.tab).len().saturating_sub(1);
                self.cursors[self.tab.index()] = self.next_selectable(last, -1).unwrap_or(0);
                None
            }
            Key::Enter => self.activate(),
            Key::Char(' ') => self.cycle(),
            Key::Backspace | Key::Delete | Key::Char('x') => self.reset(),
            Key::Char('u') => self.undo(),
            Key::Char('s') => self.save(),
            Key::Char(_) => None,
        }
    }

    fn switch_tab(&mut self, step: usize) -> Option<Effect> {
        self.tab = Tab::ALL[(self.tab.index() + step) % Tab::ALL.len()];
        None
    }

    fn request_quit(&mut self) -> Option<Effect> {
        if self.dirty(Scope::User) || self.dirty(Scope::System) {
            self.dialog = Some(Dialog::Confirm {
                title: "Quit without saving?".into(),
                lines: vec![
                    format!("{} unsaved change(s) will be lost.", self.changed_count()),
                    "Press s first to save them.".into(),
                ],
                effect: Effect::Quit,
            });
            None
        } else {
            self.quit = true;
            Some(Effect::Quit)
        }
    }

    fn selected(&self) -> Option<Row> {
        rows(self.tab).get(self.cursors[self.tab.index()]).cloned()
    }

    fn next_selectable(&self, from: usize, step: isize) -> Option<usize> {
        let rows = rows(self.tab);
        let mut index = from.min(rows.len().checked_sub(1)?);
        loop {
            if rows[index].selectable() {
                return Some(index);
            }
            index = index
                .checked_add_signed(step)
                .filter(|next| *next < rows.len())?;
        }
    }

    fn move_cursor(&mut self, delta: isize) -> Option<Effect> {
        let tab = self.tab.index();
        let rows = rows(self.tab);
        let step = delta.signum();
        let mut index = self.cursors[tab];
        let mut remaining = delta.unsigned_abs();
        while remaining > 0 {
            let Some(next) = index
                .checked_add_signed(step)
                .filter(|next| *next < rows.len())
            else {
                break;
            };
            index = next;
            if rows[index].selectable() {
                self.cursors[tab] = index;
                remaining -= 1;
            }
        }
        None
    }

    /// Refuses edits to a file that could not be read, since saving would
    /// replace it.
    fn editable(&mut self, scope: Scope) -> bool {
        if let FileStatus::Invalid(reason) = self.status(scope) {
            self.message = Some((
                format!(
                    "The {} file is invalid ({reason}); fix it under Maintenance first.",
                    scope.name()
                ),
                Tone::Bad,
            ));
            return false;
        }
        true
    }

    fn set(&mut self, field: Field, value: Option<&str>) -> Result<(), String> {
        let draft = match field.scope {
            Scope::User => &mut self.user,
            Scope::System => &mut self.system,
        };
        field.set(draft, value)
    }

    fn activate(&mut self) -> Option<Effect> {
        match self.selected()? {
            Row::Field(field) => {
                if !self.editable(field.scope) {
                    return None;
                }
                let current = field.get(self.draft(field.scope));
                match field.input() {
                    Input::Choice(names) => {
                        let mut options = vec![self.inherit_label(field)];
                        options.extend(names.iter().map(ToString::to_string));
                        let selected = current
                            .and_then(|value| options.iter().position(|option| *option == value))
                            .unwrap_or(0);
                        self.dialog = Some(Dialog::Choice {
                            field,
                            options,
                            selected,
                            typed: false,
                            also: None,
                        });
                        None
                    }
                    Input::Model => {
                        if self.models.is_none() {
                            self.say("Asking OpenCode for its models…");
                            return Some(Effect::LoadModels(field));
                        }
                        self.open_model_picker(field, None);
                        None
                    }
                    Input::Number(_) | Input::Repos => {
                        self.dialog = Some(Dialog::Input {
                            field,
                            buffer: current.unwrap_or_default(),
                            error: None,
                            also: None,
                        });
                        None
                    }
                }
            }
            Row::Integration(integration) => {
                let state = self
                    .integrations
                    .iter()
                    .find(|(candidate, _)| *candidate == integration)
                    .map(|(_, state)| state.clone())?;
                let paths = self.files.paths.as_ref()?;
                let Some(plan) = paths.plan(integration, &state) else {
                    if let State::Unavailable(reason) = state {
                        self.message = Some((format!("Unavailable: {reason}."), Tone::Bad));
                    }
                    return None;
                };
                self.dialog = Some(Dialog::Confirm {
                    title: plan.summary.clone(),
                    lines: plan.describe(paths),
                    effect: Effect::Integration(plan),
                });
                None
            }
            Row::Task(task) => self.start_task(task),
            Row::Header(_) | Row::Info(_) | Row::Blank => None,
        }
    }

    fn start_task(&mut self, task: Task) -> Option<Effect> {
        let discards = self.dirty(Scope::User) || self.dirty(Scope::System);
        let confirm = |title: &str, lines: Vec<String>, effect: Effect| Dialog::Confirm {
            title: title.to_string(),
            lines,
            effect,
        };
        match task {
            Task::ShowConfig | Task::CheckConfig | Task::ReviewMemory => Some(Effect::Report(task)),
            Task::ForgetMemory => {
                self.dialog = Some(confirm(
                    "Forget all review memory?",
                    vec![
                        "Every approved baseline and cached verdict is deleted.".into(),
                        "The next review of each source runs in full.".into(),
                    ],
                    Effect::ForgetMemory,
                ));
                None
            }
            Task::GuidedSetup | Task::EditUser | Task::EditSystem => {
                let effect = match task {
                    Task::GuidedSetup => Effect::GuidedSetup,
                    Task::EditUser => Effect::Edit(Scope::User),
                    _ => Effect::Edit(Scope::System),
                };
                if discards {
                    self.dialog = Some(confirm(
                        "Discard unsaved changes?",
                        vec![format!(
                            "{} unsaved change(s) are dropped; the files are reloaded afterwards.",
                            self.changed_count()
                        )],
                        effect,
                    ));
                    None
                } else {
                    Some(effect)
                }
            }
        }
    }

    fn inherit_label(&self, field: Field) -> String {
        let mut without = self.draft(field.scope).clone();
        if field.set(&mut without, None).is_err() {
            return "inherit".into();
        }
        let (user, system) = match field.scope {
            Scope::User => (without, self.system.clone()),
            Scope::System => (self.user.clone(), without),
        };
        let settings = Settings::from_parts(system.clone(), user.clone());
        format!("inherit ({})", field.effective(&settings, &user, &system))
    }

    fn open_model_picker(&mut self, field: Field, also: Option<Field>) {
        let current = field.get(self.draft(field.scope));
        let mut options = vec![self.inherit_label(field)];
        options.extend(self.models.iter().flatten().cloned());
        options.push("Type a model…".into());
        let selected = current
            .and_then(|value| options.iter().position(|option| *option == value))
            .unwrap_or(0);
        self.dialog = Some(Dialog::Choice {
            field,
            options,
            selected,
            typed: true,
            also,
        });
    }

    /// Space: the next value of a choice field, wrapping through inherit.
    fn cycle(&mut self) -> Option<Effect> {
        let Some(Row::Field(field)) = self.selected() else {
            return None;
        };
        let Input::Choice(names) = field.input() else {
            return self.activate();
        };
        if !self.editable(field.scope) {
            return None;
        }
        let current = field.get(self.draft(field.scope));
        let next = match current.and_then(|value| names.iter().position(|name| *name == value)) {
            None => names.first().copied(),
            Some(index) => names.get(index + 1).copied(),
        };
        if let Err(error) = self.set(field, next) {
            self.message = Some((error, Tone::Bad));
        }
        None
    }

    fn reset(&mut self) -> Option<Effect> {
        if let Some(Row::Field(field)) = self.selected()
            && self.editable(field.scope)
            && let Err(error) = self.set(field, None)
        {
            self.message = Some((error, Tone::Bad));
        }
        None
    }

    fn undo(&mut self) -> Option<Effect> {
        if let Some(Row::Field(field)) = self.selected() {
            let saved = field.get(self.saved(field.scope));
            if let Err(error) = self.set(field, saved.as_deref()) {
                self.message = Some((error, Tone::Bad));
            }
        }
        None
    }

    fn save(&mut self) -> Option<Effect> {
        let user = self.dirty(Scope::User);
        let system = self.dirty(Scope::System);
        if !user && !system {
            self.say("Nothing to save.");
            return None;
        }
        if user {
            match validate(&self.user) {
                Ok(text) => {
                    self.system_after_user = system;
                    return Some(Effect::SaveUser(text));
                }
                Err(error) => {
                    self.message = Some((error, Tone::Bad));
                    return None;
                }
            }
        }
        self.confirm_system_save();
        None
    }

    fn confirm_system_save(&mut self) {
        match validate(&self.system) {
            Ok(text) => {
                let mut lines = vec![
                    format!(
                        "{} (pacman gate settings), installed with sudo:",
                        self.files.system_path.display()
                    ),
                    String::new(),
                ];
                // Only settings lines: the header comment and spacing are noise.
                lines.extend(
                    line_diff(&self.files.system_text, &text)
                        .lines()
                        .filter(|line| {
                            let content = line.get(2..).unwrap_or_default().trim();
                            !content.is_empty() && !content.starts_with('#')
                        })
                        .map(str::to_string),
                );
                self.dialog = Some(Dialog::Confirm {
                    title: "Save the system file?".into(),
                    lines,
                    effect: Effect::SaveSystem(text),
                });
            }
            Err(error) => self.message = Some((error, Tone::Bad)),
        }
    }

    fn handle_dialog(&mut self, key: Key) -> Option<Effect> {
        let dialog = self.dialog.take()?;
        match dialog {
            Dialog::Confirm {
                title,
                lines,
                effect,
            } => match key {
                Key::Char('y' | 'Y') | Key::Enter => {
                    if effect == Effect::ResetDefaults {
                        self.reset_defaults();
                        return None;
                    }
                    if effect == Effect::Quit {
                        self.quit = true;
                    }
                    Some(effect)
                }
                Key::Char('n' | 'N' | 'q') | Key::Escape | Key::Interrupt => {
                    self.system_after_user = false;
                    None
                }
                _ => {
                    self.dialog = Some(Dialog::Confirm {
                        title,
                        lines,
                        effect,
                    });
                    None
                }
            },
            Dialog::Pager {
                title,
                lines,
                scroll,
            } => {
                let scroll = match key {
                    Key::Char('q') | Key::Escape | Key::Enter | Key::Interrupt => return None,
                    Key::Up | Key::Char('k') => scroll.saturating_sub(1),
                    Key::Down | Key::Char('j') => scroll + 1,
                    Key::PageUp => scroll.saturating_sub(10),
                    Key::PageDown | Key::Char(' ') => scroll + 10,
                    Key::Home | Key::Char('g') => 0,
                    Key::End | Key::Char('G') => lines.len(),
                    _ => scroll,
                };
                let scroll = scroll.min(lines.len().saturating_sub(1));
                self.dialog = Some(Dialog::Pager {
                    title,
                    lines,
                    scroll,
                });
                None
            }
            Dialog::Choice {
                field,
                options,
                selected,
                typed,
                also,
            } => {
                self.choice_key(
                    Choice {
                        field,
                        options,
                        selected,
                        typed,
                        also,
                    },
                    key,
                );
                None
            }
            Dialog::Input {
                field,
                buffer,
                error,
                also,
            } => {
                self.input_key(field, also, buffer, error, key);
                None
            }
        }
    }

    fn choice_key(&mut self, choice: Choice, key: Key) {
        let Choice {
            field,
            options,
            selected,
            typed,
            also,
        } = choice;
        let last = options.len().saturating_sub(1);
        let selected = match key {
            Key::Escape | Key::Char('q') | Key::Interrupt => return,
            Key::Up | Key::Char('k') => selected.saturating_sub(1),
            Key::Down | Key::Char('j') => (selected + 1).min(last),
            Key::Home => 0,
            Key::End => last,
            Key::Enter | Key::Char(' ') => {
                if typed && selected == last {
                    self.dialog = Some(Dialog::Input {
                        field,
                        buffer: field.get(self.draft(field.scope)).unwrap_or_default(),
                        error: None,
                        also,
                    });
                    return;
                }
                let value = (selected > 0).then(|| options[selected].clone());
                if let Err(error) = self.set_both(field, also, value.as_deref()) {
                    self.message = Some((error, Tone::Bad));
                }
                return;
            }
            _ => selected,
        };
        self.dialog = Some(Dialog::Choice {
            field,
            options,
            selected,
            typed,
            also,
        });
    }

    /// Sets `field`, and `also` when given, to one value; neither changes
    /// unless both accept it.
    fn set_both(
        &mut self,
        field: Field,
        also: Option<Field>,
        value: Option<&str>,
    ) -> Result<(), String> {
        let (user, system) = (self.user.clone(), self.system.clone());
        let result = self
            .set(field, value)
            .and_then(|()| also.map_or(Ok(()), |also| self.set(also, value)));
        if result.is_err() {
            self.user = user;
            self.system = system;
        }
        result
    }

    fn input_key(
        &mut self,
        field: Field,
        also: Option<Field>,
        mut buffer: String,
        mut error: Option<String>,
        key: Key,
    ) {
        match key {
            Key::Escape | Key::Interrupt => return,
            Key::Enter => {
                let value = buffer.trim();
                let value = (!value.is_empty()).then_some(value);
                match self.set_both(field, also, value) {
                    Ok(()) => return,
                    Err(message) => error = Some(message),
                }
            }
            Key::Backspace => {
                buffer.pop();
                error = None;
            }
            Key::Char(character) if buffer.chars().count() < 200 => {
                buffer.push(character);
                error = None;
            }
            _ => {}
        }
        self.dialog = Some(Dialog::Input {
            field,
            buffer,
            error,
            also,
        });
    }

    pub fn draw(&mut self, canvas: &mut Canvas) {
        let (width, height) = (canvas.width, canvas.height);
        if width < 48 || height < 14 {
            canvas.text_fit(0, 0, "Guardian: window too small", Style::PLAIN, width);
            return;
        }
        if self.mode == Mode::Simple {
            self.draw_simple(canvas);
            return;
        }
        let border = Style::fg(color::MUTED);
        canvas.frame(0, 0, width, height, border);
        let title_end = canvas.text(2, 0, " \u{f0483} ", Style::fg(color::ACCENT).bold(), 4);
        let title_end = canvas.text(
            title_end,
            0,
            "Omarchy Guardian ",
            Style::fg(color::ACCENT).bold(),
            20,
        );
        let version = format!(" v{} ", env!("CARGO_PKG_VERSION"));
        canvas.text(width - 2 - version.chars().count(), 0, &version, border, 12);
        let _ = title_end;

        self.draw_tabs(canvas);
        canvas.divider(0, 2, width, border);
        let footer = height - 5;
        canvas.divider(0, footer, width, border);
        self.draw_rows(canvas, 3, footer - 3);
        self.draw_status(canvas, footer + 1);
        let keys = if self.dialog.is_some() {
            " enter select · esc close "
        } else {
            " ↑↓ move  ⇥ tabs  enter edit  space cycle  x inherit  u undo  s save  e simple  q quit "
        };
        canvas.text_fit(2, height - 1, keys, border, width - 4);

        if let Some(dialog) = &self.dialog {
            draw_dialog(canvas, dialog, &value_hint(dialog));
        }
    }

    fn draw_tabs(&self, canvas: &mut Canvas) {
        let mut x = 2;
        for (index, tab) in Tab::ALL.iter().enumerate() {
            let label = format!(" {} {} ", index + 1, tab.label());
            let style = if *tab == self.tab {
                Style::fg(color::ACCENT).bold().reverse()
            } else {
                Style::PLAIN
            };
            x = canvas.text(x, 1, &label, style, canvas.width.saturating_sub(x + 2)) + 1;
        }
        let changes = self.changed_count();
        if changes > 0 {
            let text = format!("● {changes} unsaved ");
            let start = canvas.width.saturating_sub(2 + text.chars().count());
            if start > x {
                canvas.text(start, 1, &text, Style::fg(color::YELLOW).bold(), 20);
            }
        }
    }

    fn draw_rows(&mut self, canvas: &mut Canvas, top: usize, visible: usize) {
        let rows = rows(self.tab);
        let tab = self.tab.index();
        let cursor = self.cursors[tab];
        let scroll = &mut self.scrolls[tab];
        if cursor < *scroll {
            // Keep the section header above the cursor in view.
            *scroll = cursor.saturating_sub(1);
        } else if cursor >= *scroll + visible {
            *scroll = cursor + 1 - visible;
        }
        let scroll = *scroll;
        let settings = self.settings();
        let width = canvas.width - 4;
        let label_width = (width / 3).clamp(18, 30);

        for (offset, row) in rows.iter().enumerate().skip(scroll).take(visible) {
            let y = top + offset - scroll;
            let selected = offset == cursor && self.dialog.is_none();
            if selected {
                canvas.fill(1, y, canvas.width - 2, Style::PLAIN.reverse());
            }
            let line = Line {
                y,
                base: if selected {
                    Style::PLAIN.reverse()
                } else {
                    Style::PLAIN
                },
                width,
                label_width,
            };
            match row {
                Row::Header(text) => {
                    canvas.text_fit(2, y, text, Style::fg(color::ACCENT).bold(), width);
                }
                Row::Info(text) => canvas.text_fit(4, y, text, Style::fg(color::MUTED), width - 2),
                Row::Blank => {}
                Row::Field(field) => self.draw_field(canvas, *field, &settings, &line),
                Row::Integration(integration) => {
                    canvas.text_fit(4, y, integration.label(), line.base, label_width);
                    let (text, fg) = self.integration_state(*integration);
                    let value_x = line.value_x();
                    canvas.text_fit(
                        value_x,
                        y,
                        &text,
                        line.base.with_fg(fg),
                        width.saturating_sub(value_x),
                    );
                }
                Row::Task(task) => {
                    let style = if *task == Task::ForgetMemory {
                        line.base.with_fg(color::RED)
                    } else {
                        line.base
                    };
                    canvas.text_fit(4, y, task.label(), style, width - 2);
                }
            }
        }
        if rows.len() > visible {
            let text = format!(" {}/{} ", cursor + 1, rows.len());
            canvas.text(
                canvas.width - 2 - text.chars().count(),
                top + visible,
                &text,
                Style::fg(color::MUTED),
                12,
            );
        }
    }

    fn draw_field(&self, canvas: &mut Canvas, field: Field, settings: &Settings, line: &Line) {
        let draft = field.get(self.draft(field.scope));
        if draft != field.get(self.saved(field.scope)) {
            canvas.text(2, line.y, "●", line.base.with_fg(color::YELLOW), 1);
        }
        canvas.text_fit(4, line.y, field.label(), line.base, line.label_width);
        let value_x = line.value_x();
        let value_width = line.width.saturating_sub(value_x + 10);
        if let Some(value) = draft {
            let style = line.base.with_fg(color::GREEN).bold();
            canvas.text_fit(value_x, line.y, &value, style, value_width);
        } else {
            let effective = field.effective(settings, &self.user, &self.system);
            canvas.text_fit(
                value_x,
                line.y,
                &format!("{effective}  (inherited)"),
                line.base.with_fg(color::MUTED),
                value_width,
            );
        }
        if let Some(origin) = field.origin(settings) {
            let text = format!("{origin:>7}");
            canvas.text(
                line.width - 6,
                line.y,
                &text,
                line.base.with_fg(color::MUTED),
                8,
            );
        }
    }

    fn integration_state(&self, integration: Integration) -> (String, u8) {
        let state = self
            .integrations
            .iter()
            .find(|(candidate, _)| *candidate == integration)
            .map(|(_, state)| state.clone());
        match state {
            Some(State::On) => ("● on".to_string(), color::GREEN),
            Some(State::Off) => ("○ off".to_string(), color::MUTED),
            Some(State::Foreign(reason)) => (format!("! {reason}"), color::YELLOW),
            Some(State::Unavailable(reason)) => (format!("– {reason}"), color::MUTED),
            None => ("– unknown".to_string(), color::MUTED),
        }
    }

    fn draw_status(&self, canvas: &mut Canvas, top: usize) {
        let width = canvas.width - 4;
        let help = match self.selected() {
            Some(Row::Field(field)) => {
                let file = match field.scope {
                    Scope::User => "user file",
                    Scope::System => "system file · saved with sudo",
                };
                format!("{}  [{file}]", field.help())
            }
            Some(Row::Integration(integration)) => integration.help().to_string(),
            Some(Row::Task(task)) => task.help().to_string(),
            _ => String::new(),
        };
        let lines = wrap(&help, width);
        for (index, line) in lines.iter().take(2).enumerate() {
            canvas.text_fit(2, top + index, line, Style::fg(color::MUTED), width);
        }
        if let Some((text, tone)) = &self.message {
            let (fg, mark) = match tone {
                Tone::Info => (color::CYAN, "›"),
                Tone::Good => (color::GREEN, "✓"),
                Tone::Bad => (color::RED, "✗"),
            };
            canvas.text_fit(
                2,
                top + 2,
                &format!("{mark} {text}"),
                Style::fg(fg).bold(),
                width,
            );
        }
    }
}

fn value_hint(dialog: &Dialog) -> String {
    match dialog {
        Dialog::Input { field, .. } | Dialog::Choice { field, .. } => match field.input() {
            Input::Number(range) => {
                format!("{} to {}; empty to inherit", range.start(), range.end())
            }
            Input::Repos => "repository names separated by commas; empty to inherit".into(),
            Input::Model => "provider/model; empty to inherit".into(),
            Input::Choice(_) => String::new(),
        },
        _ => String::new(),
    }
}

/// Where one list row is drawn.
struct Line {
    y: usize,
    base: Style,
    width: usize,
    label_width: usize,
}

impl Line {
    const fn value_x(&self) -> usize {
        4 + self.label_width + 1
    }
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

/// A dialog's title and styled lines.
fn dialog_body(dialog: &Dialog, hint: &str) -> (String, Vec<(String, Style)>) {
    match dialog {
        Dialog::Confirm { title, lines, .. } => {
            let mut body: Vec<(String, Style)> = lines
                .iter()
                .map(|line| {
                    let style = if line.starts_with("+ ") {
                        Style::fg(color::GREEN)
                    } else if line.starts_with("- ") {
                        Style::fg(color::RED)
                    } else {
                        Style::PLAIN
                    };
                    (line.clone(), style)
                })
                .collect();
            body.push((String::new(), Style::PLAIN));
            body.push(("[y] yes    [n] no".into(), Style::fg(color::ACCENT).bold()));
            (title.clone(), body)
        }
        Dialog::Pager {
            title,
            lines,
            scroll,
        } => {
            let body = lines
                .iter()
                .skip(*scroll)
                .map(|line| (line.clone(), Style::PLAIN))
                .collect();
            (title.clone(), body)
        }
        Dialog::Choice {
            field,
            options,
            selected,
            ..
        } => {
            let body = options
                .iter()
                .enumerate()
                .map(|(index, option)| {
                    if index == *selected {
                        (format!("› {option}"), Style::fg(color::ACCENT).bold())
                    } else {
                        (format!("  {option}"), Style::PLAIN)
                    }
                })
                .collect();
            (field.label().to_string(), body)
        }
        Dialog::Input {
            field,
            buffer,
            error,
            ..
        } => {
            let mut body = vec![
                (format!("› {buffer}█"), Style::fg(color::ACCENT).bold()),
                (hint.to_string(), Style::fg(color::MUTED)),
            ];
            if let Some(error) = error {
                body.push((format!("✗ {error}"), Style::fg(color::RED)));
            }
            (field.label().to_string(), body)
        }
    }
}

fn draw_dialog(canvas: &mut Canvas, dialog: &Dialog, hint: &str) {
    let (title, body) = dialog_body(dialog, hint);
    let longest = body
        .iter()
        .map(|(line, _)| line.chars().count())
        .chain([title.chars().count() + 4])
        .max()
        .unwrap_or(20);
    let width = (longest + 4).clamp(36, canvas.width.saturating_sub(4));
    let max_height = canvas.height.saturating_sub(4);
    let height = (body.len() + 2).min(max_height);
    let x = (canvas.width - width) / 2;
    let y = (canvas.height - height) / 2;

    // A selected choice beyond the box's height scrolls into view.
    let skip = match dialog {
        Dialog::Choice { selected, .. } => (selected + 3).saturating_sub(height),
        _ => 0,
    };
    canvas.frame(x, y, width, height, Style::fg(color::ACCENT));
    canvas.text(
        x + 2,
        y,
        &format!(" {title} "),
        Style::fg(color::ACCENT).bold(),
        width - 4,
    );
    for (index, (line, style)) in body.iter().skip(skip).take(height - 2).enumerate() {
        canvas.text_fit(x + 2, y + 1 + index, line, *style, width - 4);
    }
    if let Dialog::Pager { lines, scroll, .. } = dialog {
        let text = format!(" {}/{} · q close ", scroll + 1, lines.len().max(1));
        canvas.text(
            x + width - 2 - text.chars().count(),
            y + height - 1,
            &text,
            Style::fg(color::MUTED),
            width,
        );
    }
}

fn class_header(class: SourceClass) -> String {
    let (name, gate) = match class {
        SourceClass::Official => ("Official repositories", "pacman gate · system file"),
        SourceClass::ThirdPartyRepo => ("Third-party repositories", "pacman gate · system file"),
        SourceClass::LocalPackage => ("Local packages (pacman -U)", "pacman gate · system file"),
        SourceClass::Aur => ("AUR builds", "yay gate · user file"),
        SourceClass::Theme => ("Omarchy themes", "theme gate · user file"),
        SourceClass::Plugin => ("Plugins", "user file"),
        SourceClass::Source => ("Sources you scan or guard", "user file"),
    };
    format!("{name}  ·  {gate}")
}

fn rows(tab: Tab) -> Vec<Row> {
    match tab {
        Tab::Profiles => {
            let mut rows = vec![
                Row::Header("Profiles".into()),
                Row::Field(Field::new(Scope::User, Setting::Profile)),
                Row::Field(Field::new(Scope::System, Setting::Profile)),
                Row::Blank,
            ];
            for profile in Profile::ALL.iter().copied() {
                rows.push(Row::Info(format!(
                    "{:<11} {}",
                    profile.name(),
                    profile.summary()
                )));
            }
            rows
        }
        Tab::Sources => {
            let mut rows = Vec::new();
            for class in SourceClass::ALL.iter().copied() {
                if !rows.is_empty() {
                    rows.push(Row::Blank);
                }
                rows.push(Row::Header(class_header(class)));
                rows.extend(
                    Knob::for_class(class)
                        .iter()
                        .map(|knob| Row::Field(Field::class(class, *knob))),
                );
            }
            rows
        }
        Tab::Ai => vec![
            Row::Header("Your sources  ·  user file".into()),
            Row::Field(Field::new(Scope::User, Setting::AgentModel)),
            Row::Field(Field::new(Scope::User, Setting::MaxInputKib)),
            Row::Field(Field::new(Scope::User, Setting::MaxChunks)),
            Row::Field(Field::new(Scope::User, Setting::CacheDays)),
            Row::Field(Field::new(Scope::User, Setting::MaxStoreMib)),
            Row::Blank,
            Row::Header("Pacman gate  ·  system file".into()),
            Row::Field(Field::new(Scope::System, Setting::AgentModel)),
            Row::Field(Field::new(Scope::System, Setting::MaxInputKib)),
            Row::Field(Field::new(Scope::System, Setting::MaxChunks)),
            Row::Field(Field::new(Scope::System, Setting::OfficialRepos)),
        ],
        Tab::Integrations => {
            let mut rows = vec![Row::Header("Where Guardian steps in".into())];
            rows.extend(
                Integration::ALL
                    .iter()
                    .map(|integration| Row::Integration(*integration)),
            );
            rows
        }
        Tab::Maintenance => vec![
            Row::Header("Configuration".into()),
            Row::Task(Task::ShowConfig),
            Row::Task(Task::CheckConfig),
            Row::Task(Task::EditUser),
            Row::Task(Task::EditSystem),
            Row::Blank,
            Row::Header("Review memory".into()),
            Row::Task(Task::ReviewMemory),
            Row::Task(Task::ForgetMemory),
            Row::Blank,
            Row::Header("Setup".into()),
            Row::Task(Task::GuidedSetup),
        ],
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{App, Effect, Loaded, Mode, Tab};
    use crate::config::file::PartialConfig;
    use crate::config::load::FileStatus;
    use crate::config::model::{AiRequirement, Profile, SourceClass};
    use crate::tui::canvas::Canvas;
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
}
