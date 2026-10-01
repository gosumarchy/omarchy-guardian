//! The system sweep (`omarchy-guardian sweep`): what already runs on its
//! own on this machine, and how far each of it can be trusted (see `autorun`
//! for the locations).
//!
//! - `index` reads which package installed each file and what pacman
//!   recorded for it; `tier` decides from that whether a file is what its
//!   package shipped.
//! - `collect` gathers the items (with `read`, which never follows links into
//!   files, and `commands`/`lua`, which find what each item runs).
//! - `judge` sends what isn't trusted through the local rules and the AI
//!   review; `output` shows it.
//! - `root` is the read-only root collector behind `sweep --root`.

pub mod collect;
pub mod commands;
pub mod index;
pub mod judge;
pub mod lua;
pub mod output;
pub mod read;
pub mod root;
pub mod state;
pub mod tier;

use std::env;
use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::Settings;
use crate::config::model::{RootConsent, SourceClass};
use crate::engine::store::{self, Store};
use crate::notify;
use crate::report::{Decision, Gap};
use crate::review::ReviewContext;
use crate::tools::OpenCode;
use collect::{Collection, Origin, Scope};
use index::{LOCAL_DB, PackageIndex};
use state::{Change, Remembered};

/// How a sweep is shown.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum View {
    /// What isn't trusted, then the report.
    #[default]
    List,
    /// Every item, trusted ones too.
    All,
    /// Only what changed since the last sweep.
    Changes,
    /// One JSON document.
    Json,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub view: View,
    /// Also run the root collector now (asks for the sudo password).
    pub root: bool,
    /// Run by the timer: show what changed and notify about it.
    pub scheduled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Run(Options),
    /// Trust one item as it is now (its label, as the sweep shows it).
    Allow(String),
    /// Stop trusting one item, or every item with `None`.
    Forget(Option<String>),
}

pub fn command(command: &Command, settings: &Settings) -> ExitCode {
    if store::effective_uid().is_ok_and(|uid| uid == 0) {
        errln!(
            "omarchy-guardian sweep: run it as your user; `sweep --root` asks for root for the parts that need it"
        );
        return ExitCode::from(2);
    }
    let result = match command {
        Command::Run(options) => return run(*options, settings),
        Command::Allow(label) => allow(label),
        Command::Forget(label) => forget(label.as_deref()),
    };
    match result {
        Ok(message) => {
            outln!("{message}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            errln!("omarchy-guardian sweep: {message}");
            ExitCode::from(2)
        }
    }
}

/// The home directory relative to `/`.
fn home() -> Option<String> {
    env::var("HOME")
        .ok()
        .filter(|home| home.starts_with('/') && home.len() > 1)
        .map(|home| {
            home.trim_start_matches('/')
                .trim_end_matches('/')
                .to_string()
        })
}

/// Collects this system and the user's home.
fn collect_here(home: Option<&str>) -> Result<(Collection, PackageIndex), String> {
    let index = index::foreign_packages()
        .and_then(|foreign| PackageIndex::load(Path::new(LOCAL_DB), foreign))
        .map_err(|error| format!("cannot read the package database: {error}"))?;
    let collection = collect::collect(&Scope {
        root: Path::new("/"),
        home,
        index: &index,
        origin: Origin::System,
    });
    Ok((collection, index))
}

fn state_directory() -> Result<std::path::PathBuf, String> {
    let root = Store::default_root().ok_or("no state directory (set HOME or XDG_STATE_HOME)")?;
    state::directory(&root)
}

fn allow(label: &str) -> Result<String, String> {
    let home = home();
    let (collection, _) = collect_here(home.as_deref())?;
    let item = collection
        .items
        .iter()
        .find(|item| judge::label(item, home.as_deref()) == label)
        .ok_or_else(|| {
            format!("{label} is not something the sweep lists; use the path as it shows it")
        })?;
    if judge::is_trusted(item.tier) {
        return Ok(format!(
            "{label} is already trusted ({}).",
            item.tier.name()
        ));
    }
    if item.sha256.is_none() && !matches!(item.body, collect::Body::Link(_)) {
        return Err(format!(
            "{label} cannot be read, so it cannot be allowed as it is"
        ));
    }
    let directory = state_directory()?;
    let mut allowed = state::allowed(&directory);
    allowed.insert(label.to_string(), state::fingerprint(item));
    state::save_allowed(&directory, &allowed)?;
    Ok(format!(
        "Allowed {label} as it is now; if it changes, the sweep shows it again."
    ))
}

fn forget(label: Option<&str>) -> Result<String, String> {
    let directory = state_directory()?;
    let mut allowed = state::allowed(&directory);
    match label {
        None => allowed.clear(),
        Some(label) => {
            if allowed.remove(label).is_none() {
                return Err(format!("{label} was not allowed"));
            }
        }
    }
    state::save_allowed(&directory, &allowed)?;
    Ok(label.map_or_else(
        || "Forgot every allowed item.".to_string(),
        |label| format!("{label} is no longer allowed."),
    ))
}

/// Adds what root found: now through sudo (`--root`), or from the daily
/// root timer when the system configuration allows the root checks.
fn add_root_part(
    collection: &mut Collection,
    options: Options,
    settings: &Settings,
    notes: &mut Vec<String>,
) {
    if options.root {
        match root::from_root() {
            Ok(part) => root::merge(collection, part),
            Err(reason) => notes.push(format!("the root checks did not run ({reason})")),
        }
        return;
    }
    match settings.sweep_root().0 {
        Some(RootConsent::Allowed) => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs());
            match root::from_results(Path::new(root::RESULTS), now) {
                Ok(part) => root::merge(collection, part),
                Err(reason) => notes.push(format!("root checks: {reason}")),
            }
        }
        Some(RootConsent::Declined) => notes.push(
            "root checks are declined in the system configuration; what only root can read is not checked".into(),
        ),
        None => notes.push(
            "root checks are not set up: `omarchy-guardian protect` asks to allow them, `sweep --root` runs them once".into(),
        ),
    }
}

/// `omarchy-guardian sweep`.
fn run(options: Options, settings: &Settings) -> ExitCode {
    let home = home();
    let (mut collection, index) = match collect_here(home.as_deref()) {
        Ok(found) => found,
        Err(message) => {
            errln!("omarchy-guardian sweep: {message}");
            return ExitCode::from(2);
        }
    };
    let mut notes = Vec::new();
    add_root_part(&mut collection, options, settings, &mut notes);
    let directory = state_directory()
        .map_err(|reason| notes.push(format!("nothing remembered between sweeps ({reason})")))
        .ok();
    let label = |item: &collect::Item| judge::label(item, home.as_deref());
    if let Some(directory) = &directory {
        state::apply_allowed(&mut collection.items, &state::allowed(directory), label);
    }

    let state_root = Store::default_root();
    let context = ReviewContext {
        settings,
        class: SourceClass::System,
        opencode: &OpenCode::UserPath,
        units: &[],
        state_root: state_root.as_deref(),
        context: &[],
    };
    let mut report = judge::judge(&collection, home.as_deref(), &context);
    report.gaps.extend(
        index
            .problems
            .iter()
            .map(|problem| Gap::Sweep(format!("package record {problem}"))),
    );
    report.gaps.extend(
        collection
            .truncated
            .iter()
            .map(|location| Gap::Sweep(format!("{location}: more entries than were looked at"))),
    );
    // Nothing to review is a clean sweep, not a limited one.
    let decision = match report.decide(&|class| settings.policy(class)) {
        Decision::Limited => Decision::Clear,
        decision => decision,
    };

    let current: Remembered = collection
        .items
        .iter()
        .filter(|item| !judge::is_trusted(item.tier))
        .map(|item| (label(item), state::fingerprint(item)))
        .collect();
    let changes = directory
        .as_ref()
        .map(|directory| state::diff(&state::baseline(directory), &current))
        .unwrap_or_default();

    if options.view == View::Json {
        outln!(
            "{}",
            output::json(&collection, &report, decision, home.as_deref(), &notes)
        );
    } else {
        if options.view == View::Changes || options.scheduled {
            output::print_changes(&changes);
        } else {
            output::print(
                &collection,
                &report,
                home.as_deref(),
                options.view == View::All,
            );
        }
        for note in &notes {
            outln!("Note: {}", crate::text::shown(note));
        }
        report.print(false, decision);
    }
    if let Some(directory) = &directory
        && let Err(reason) = state::save_baseline(directory, &current)
    {
        errln!("omarchy-guardian sweep: {reason}");
    }
    if options.scheduled {
        let arrived = changes
            .iter()
            .filter(|(change, _)| *change != Change::Removed)
            .count();
        if arrived > 0 {
            notify::found(
                &format!("{arrived} new or changed startup item(s)"),
                "the daily system sweep found something that runs on its own and that no package vouches for",
            );
        }
    }
    decision.exit_code()
}
