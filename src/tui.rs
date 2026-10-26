//! `omarchy-guardian tui`: a full-screen settings editor in the style of
//! Omarchy's own terminal apps. It edits the user and system config files
//! through the same parser that reads them, toggles the integrations, and
//! runs the maintenance commands.

mod app;
mod canvas;
mod fields;
mod mascot;
mod term;

use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::Settings;
use crate::config::load::{self, SYSTEM_PATH};
use crate::config::model::{Named, SourceClass};
use crate::config::show::{render_check, render_memory, render_show};
use crate::engine::baseline;
use crate::engine::store::Store;
use crate::error::{Error, IoContext};
use crate::integrations::Plan;
use crate::protect::{paths, run_plan, test_reviewer};
use crate::setup::{self, Environment as _};
use crate::status;

pub(crate) use app::Mode;
use app::{App, Effect, Loaded, Task};
use canvas::Canvas;
use fields::{HEADER, Scope};
use term::{TTY, Terminal};

pub(crate) fn run(mode: Mode) -> Result<(), Error> {
    let mut terminal = Terminal::open().at(Path::new(TTY))?;
    status::watched();
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
        let keys = terminal.keys().at(Path::new(TTY))?;
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
            if app.settle(&effect, outcome, load_files) {
                // Changed here, knowingly: recorded, so the bar does not
                // call it news.
                status::chosen();
            }
        }
    }
    Ok(())
}

fn draw(
    terminal: &mut Terminal,
    app: &mut App,
    (width, height): (usize, usize),
) -> Result<(), Error> {
    let mut canvas = Canvas::new(width, height);
    app.draw(&mut canvas);
    terminal.draw(&canvas.render()).at(Path::new(TTY))
}

fn load_files() -> Loaded {
    let settings = Settings::load();
    let system_text = fs::read_to_string(SYSTEM_PATH).unwrap_or_default();
    Loaded::from_settings(&settings, system_text, paths(&settings))
}

fn perform(terminal: &mut Terminal, effect: &Effect) -> Result<String, Error> {
    match effect {
        Effect::SaveUser(text) => save_user(text),
        Effect::SaveSystem(text) => on_terminal(terminal, false, || {
            outln!("Installing {SYSTEM_PATH} with sudo…");
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
    work: impl FnOnce() -> Result<String, Error>,
) -> Result<String, Error> {
    terminal.suspend().at(Path::new(TTY))?;
    let outcome = work();
    if let Err(error) = &outcome {
        errln!("\n{error}");
    }
    if pause || outcome.is_err() {
        terminal.pause("Press Enter to return to Guardian.");
    }
    terminal.resume().at(Path::new(TTY))?;
    outcome
}

/// Writes the user file atomically. A hand-written file is kept as
/// `config.toml.bak` first, since rewriting drops its comments.
fn save_user(text: &str) -> Result<String, Error> {
    let path = load::user_config_path()
        .ok_or_else(|| Error::Message("cannot find the user config directory".into()))?;
    if let Ok(existing) = fs::read_to_string(&path)
        && !existing.starts_with(HEADER)
    {
        // Made new: whatever sits under that name (a link somebody left
        // there) is removed, never written through.
        let backup = path.with_extension("toml.bak");
        drop(fs::remove_file(&backup));
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&backup)
            .and_then(|mut file| file.write_all(existing.as_bytes()))
            .at(&backup)?;
    }
    let written = setup::RealEnvironment.write_user(text)?;
    Ok(format!("Saved {}.", written.display()))
}

fn integration(terminal: &mut Terminal, plan: &Plan) -> Result<String, Error> {
    let paths = paths(&Settings::load()).ok_or_else(|| Error::Message("HOME is not set".into()))?;
    let done = if plan.needs_terminal() {
        on_terminal(terminal, false, || run_plan(&paths, plan))
    } else {
        run_plan(&paths, plan)
    };
    if done.is_ok() {
        crate::audit::gate_changed(&plan.summary, "", "changed in the settings app");
    }
    done
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

fn forget_memory() -> Result<String, Error> {
    let root = Store::default_root()
        .ok_or_else(|| Error::Message("no state directory (set HOME or XDG_STATE_HOME)".into()))?;
    if !root.is_dir() {
        return Ok("The review memory is already empty.".into());
    }
    let forget = || -> Result<usize, Error> {
        let store = Store::open(root.clone())?;
        let count = baseline::forget_all(&store)?;
        // What the AUR gate remembers on its own (answers, program hashes)
        // goes with the rest.
        crate::makepkg_gate::forget_all(&root)?;
        Ok(count)
    };
    let count = forget()?;
    crate::audit::forgot("everything (settings app)");
    Ok(format!(
        "Forgot {count} approved baseline(s) and every cached verdict."
    ))
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
fn edit(terminal: &mut Terminal, scope: Scope) -> Result<String, Error> {
    on_terminal(terminal, false, || match scope {
        Scope::User => {
            let path = load::user_config_path()
                .ok_or_else(|| Error::Message("cannot find the user config directory".into()))?;
            ensure_user_file(&path)?;
            let editor = editor();
            let status = Command::new("/bin/sh")
                .args(["-c", "exec $0 \"$1\"", &editor])
                .arg(&path)
                .status()
                .spawning(&editor)?;
            if status.success() {
                Ok(format!("Edited {}; reloaded.", path.display()))
            } else {
                Err(Error::Message(format!("{editor} exited with {status}")))
            }
        }
        Scope::System => {
            let directory = Path::new(SYSTEM_PATH)
                .parent()
                .ok_or_else(|| Error::Message("invalid system path".into()))?;
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
                .spawning("sudo")?;
            if status.success() {
                crate::audit::settings_changed("the system settings file was edited");
                Ok(format!("Edited {SYSTEM_PATH}; reloaded."))
            } else {
                Err(Error::Message(format!("sudoedit exited with {status}")))
            }
        }
    })
}

fn ensure_user_file(path: &PathBuf) -> Result<(), Error> {
    if path.exists() {
        return Ok(());
    }
    if let Some(directory) = path.parent() {
        fs::create_dir_all(directory).at(directory)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .at(path)?;
    let example = SourceClass::Aur.name();
    write!(
        file,
        "{HEADER}\n# [class.{example}]\n# on_findings = \"block\"\n"
    )
    .at(path)
}
