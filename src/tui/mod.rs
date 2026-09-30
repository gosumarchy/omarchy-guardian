//! `omarchy-guardian tui`: a full-screen settings editor in the style of
//! Omarchy's own terminal apps. It edits the user and system config files
//! through the same parser that reads them, toggles the integrations, and
//! runs the maintenance commands.

mod app;
mod canvas;
mod fields;
mod integrations;
mod mascot;
mod term;

use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::config::Settings;
use crate::config::load::{self, SYSTEM_PATH};
use crate::config::model::{AgentSettings, Named, SourceClass};
use crate::config::show::{render_check, render_memory, render_show};
use crate::engine::baseline;
use crate::engine::store::Store;
use crate::pacman;
use crate::setup::{self, Environment as _};

use app::{App, Effect, Loaded, Mode, Task};
use canvas::Canvas;
use fields::{HEADER, Scope};
use integrations::{Paths, Plan, Step};
use term::Terminal;

pub fn run(expert: bool) -> Result<(), String> {
    let mut terminal =
        Terminal::open().map_err(|error| format!("cannot use the terminal: {error}"))?;
    let mode = if expert { Mode::Expert } else { Mode::Simple };
    let mut app = App::new(load_files(), mode);
    let mut size = (0, 0);
    let mut dirty = true;

    while !app.quit {
        let current = terminal.size();
        if dirty || current != size {
            size = current;
            draw(&mut terminal, &mut app, size)?;
            dirty = false;
        }
        let keys = terminal.keys().map_err(|error| error.to_string())?;
        if keys.is_empty() && app.tick() {
            dirty = true;
        }
        for key in keys {
            dirty = true;
            let Some(effect) = app.handle(key) else {
                continue;
            };
            if effect == Effect::Quit {
                break;
            }
            // Show what is happening before a slow step starts.
            draw(&mut terminal, &mut app, size)?;
            let outcome = perform(&mut terminal, &effect);
            if reloads(&effect) {
                app.reload(load_files());
            }
            app.finish(&effect, outcome);
        }
    }
    Ok(())
}

fn draw(
    terminal: &mut Terminal,
    app: &mut App,
    (width, height): (usize, usize),
) -> Result<(), String> {
    let mut canvas = Canvas::new(width, height);
    app.draw(&mut canvas);
    terminal
        .draw(&canvas.render())
        .map_err(|error| error.to_string())
}

fn load_files() -> Loaded {
    let settings = Settings::load();
    let system_text = fs::read_to_string(SYSTEM_PATH).unwrap_or_default();
    Loaded::from_settings(&settings, system_text, paths(&settings))
}

/// The integration paths, knowing whether the pacman gate lacks the
/// root-owned OpenCode its settings require.
fn paths(settings: &Settings) -> Option<Paths> {
    let opencode_missing = !pacman::classes_requiring_ai(settings).is_empty()
        && !pacman::system_reviewer_ready(settings)
        && pacman::system_reviewer_is_opencode(settings);
    Paths::real(opencode_missing)
}

const fn reloads(effect: &Effect) -> bool {
    matches!(
        effect,
        Effect::SaveUser(_)
            | Effect::SaveSystem(_)
            | Effect::Integration(_)
            | Effect::GuidedSetup
            | Effect::Edit(_)
    )
}

fn perform(terminal: &mut Terminal, effect: &Effect) -> Result<String, String> {
    match effect {
        Effect::SaveUser(text) => save_user(text),
        Effect::SaveSystem(text) => on_terminal(terminal, false, || {
            println!("Installing {SYSTEM_PATH} with sudo…");
            setup::RealEnvironment.write_system(text)?;
            Ok(format!("Saved {SYSTEM_PATH}."))
        }),
        Effect::Integration(plan) => integration(terminal, plan),
        Effect::Report(task) => Ok(report(*task)),
        Effect::ForgetMemory => forget_memory(),
        Effect::GuidedSetup => on_terminal(terminal, true, || {
            setup::run(&mut setup::TtyTerminal, &setup::RealEnvironment)
                .map(|()| "Setup finished; settings reloaded.".to_string())
        }),
        Effect::Edit(scope) => edit(terminal, *scope),
        Effect::LoadModels(_) => Ok(setup::RealEnvironment.models().join("\n")),
        Effect::ResetDefaults | Effect::Quit => Ok(String::new()),
    }
}

/// Runs `work` on the normal screen, for sudo prompts and other programs'
/// output. With `pause`, or when it fails, waits for Enter before
/// returning to the TUI.
fn on_terminal(
    terminal: &mut Terminal,
    pause: bool,
    work: impl FnOnce() -> Result<String, String>,
) -> Result<String, String> {
    terminal.suspend().map_err(|error| error.to_string())?;
    let outcome = work();
    if let Err(error) = &outcome {
        eprintln!("\n{error}");
    }
    if pause || outcome.is_err() {
        terminal.pause("Press Enter to return to Guardian.");
    }
    terminal.resume().map_err(|error| error.to_string())?;
    outcome
}

/// Writes the user file atomically. A hand-written file is kept as
/// `config.toml.bak` first, since rewriting drops its comments.
fn save_user(text: &str) -> Result<String, String> {
    let path = load::user_config_path().ok_or("cannot find the user config directory")?;
    if let Ok(existing) = fs::read_to_string(&path)
        && !existing.starts_with(HEADER)
    {
        let backup = path.with_extension("toml.bak");
        fs::write(&backup, existing).map_err(|error| error.to_string())?;
    }
    let written = setup::RealEnvironment.write_user(text)?;
    Ok(format!("Saved {}.", written.display()))
}

fn integration(terminal: &mut Terminal, plan: &Plan) -> Result<String, String> {
    let paths = paths(&Settings::load()).ok_or("HOME is not set")?;
    let run_steps = || -> Result<String, String> {
        for step in &plan.steps {
            match step {
                Step::Command(argv) | Step::Optional(argv) => {
                    let Some((program, args)) = argv.split_first() else {
                        continue;
                    };
                    let mut command = Command::new(program);
                    command.args(args);
                    if matches!(step, Step::Optional(_)) {
                        command
                            .stdin(Stdio::null())
                            .stdout(Stdio::null())
                            .stderr(Stdio::null());
                    }
                    let status = command.status();
                    let succeeded = status.as_ref().is_ok_and(std::process::ExitStatus::success);
                    if !succeeded && matches!(step, Step::Command(_)) {
                        return Err(match status {
                            Ok(status) => format!("{} exited with {status}", argv.join(" ")),
                            Err(error) => format!("{program}: {error}"),
                        });
                    }
                }
                Step::RemoveInterceptor
                | Step::AddMenuEntry
                | Step::RemoveMenuEntry
                | Step::AddThemeMenu
                | Step::RemoveThemeMenu => {
                    paths.edit(step)?;
                }
            }
        }
        Ok(format!("{}: done.", plan.summary))
    };
    if plan.needs_terminal() {
        on_terminal(terminal, false, run_steps)
    } else {
        run_steps()
    }
}

fn report(task: Task) -> String {
    let settings = Settings::load();
    match task {
        Task::CheckConfig => render_check(&settings).0,
        Task::ReviewMemory => render_memory(Store::default_root().as_deref())
            .trim()
            .to_string(),
        Task::TestReviewer => test_reviewer(&settings),
        _ => render_show(&settings, SourceClass::ALL),
    }
}

/// Setup's two-sample test against the saved settings: the model for your
/// sources, then the pacman gate's when it differs, and whether the pacman
/// gate has the root-owned reviewer it needs.
fn test_reviewer(settings: &Settings) -> String {
    let test = |label: &str, agent: &AgentSettings| match setup::RealEnvironment.test_review(agent)
    {
        Ok(elapsed) => format!(
            "✓ {label}: passed in {}s ({})",
            elapsed.as_secs(),
            agent.label()
        ),
        Err(reason) => format!("✗ {label}: {reason} ({})", agent.label()),
    };
    let user = settings.agent_settings(SourceClass::Aur);
    let official = settings.agent_settings(SourceClass::Official);
    let mut lines = vec![test("AUR, themes and plugins", &user)];
    if official.model == user.model && official.variant == user.variant {
        lines.push("  Official packages use the same model.".into());
    } else {
        lines.push(test("Official packages", &official));
    }
    if !pacman::classes_requiring_ai(settings).is_empty()
        && !pacman::system_reviewer_ready(settings)
    {
        lines
            .push("✗ The pacman gate has no root-owned reviewer in /usr/bin for its model.".into());
    }
    lines.join("\n")
}

fn forget_memory() -> Result<String, String> {
    let root = Store::default_root().ok_or("no state directory (set HOME or XDG_STATE_HOME)")?;
    if !root.is_dir() {
        return Ok("The review memory is already empty.".into());
    }
    let store = Store::open(root)?;
    baseline::forget_all(&store)
        .map(|count| format!("Forgot {count} approved baseline(s) and every cached verdict."))
        .map_err(|error| error.to_string())
}

fn editor() -> String {
    ["VISUAL", "EDITOR"]
        .iter()
        .find_map(|name| env::var(name).ok().filter(|value| !value.trim().is_empty()))
        .unwrap_or_else(|| "nvim".into())
}

/// Opens a config file in the user's editor: the user file directly, the
/// system file through `sudoedit`. Both are re-read (and re-validated)
/// afterwards.
fn edit(terminal: &mut Terminal, scope: Scope) -> Result<String, String> {
    on_terminal(terminal, false, || match scope {
        Scope::User => {
            let path = load::user_config_path().ok_or("cannot find the user config directory")?;
            ensure_user_file(&path)?;
            let editor = editor();
            let status = Command::new("/bin/sh")
                .args(["-c", "exec $0 \"$1\"", &editor])
                .arg(&path)
                .status()
                .map_err(|error| error.to_string())?;
            if status.success() {
                Ok(format!("Edited {}; reloaded.", path.display()))
            } else {
                Err(format!("{editor} exited with {status}"))
            }
        }
        Scope::System => {
            let directory = Path::new(SYSTEM_PATH)
                .parent()
                .ok_or("invalid system path")?;
            let status = Command::new("/usr/bin/sudo")
                .args([
                    "/usr/bin/install",
                    "-d",
                    "-m",
                    "0755",
                    "-o",
                    "root",
                    "-g",
                    "root",
                ])
                .arg(directory)
                .status()
                .and_then(|status| {
                    if status.success() {
                        Command::new("/usr/bin/sudoedit")
                            .env("SUDO_EDITOR", editor())
                            .arg(SYSTEM_PATH)
                            .status()
                    } else {
                        Ok(status)
                    }
                })
                .map_err(|error| error.to_string())?;
            if status.success() {
                Ok(format!("Edited {SYSTEM_PATH}; reloaded."))
            } else {
                Err(format!("sudoedit exited with {status}"))
            }
        }
    })
}

fn ensure_user_file(path: &PathBuf) -> Result<(), String> {
    if path.exists() {
        return Ok(());
    }
    if let Some(directory) = path.parent() {
        fs::create_dir_all(directory).map_err(|error| error.to_string())?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    let example = SourceClass::Aur.name();
    write!(
        file,
        "{HEADER}\n# [class.{example}]\n# on_findings = \"block\"\n"
    )
    .map_err(|error| error.to_string())
}
