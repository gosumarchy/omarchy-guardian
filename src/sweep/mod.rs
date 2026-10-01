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
pub mod tier;

use std::env;
use std::path::Path;
use std::process::ExitCode;

use crate::config::Settings;
use crate::config::model::SourceClass;
use crate::engine::store::{self, Store};
use crate::report::{Decision, Gap};
use crate::review::ReviewContext;
use crate::tools::OpenCode;
use collect::{Origin, Scope};
use index::{LOCAL_DB, PackageIndex};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    /// List trusted items too.
    pub all: bool,
    pub json: bool,
    /// Also run the root collector (asks for the sudo password).
    pub root: bool,
}

/// `omarchy-guardian sweep`.
pub fn run(options: Options, settings: &Settings) -> ExitCode {
    if store::effective_uid().is_ok_and(|uid| uid == 0) {
        errln!(
            "omarchy-guardian sweep: run it as your user; `sweep --root` asks for root for the parts that need it"
        );
        return ExitCode::from(2);
    }
    let index = match index::foreign_packages()
        .and_then(|foreign| PackageIndex::load(Path::new(LOCAL_DB), foreign))
    {
        Ok(index) => index,
        Err(error) => {
            errln!("omarchy-guardian sweep: cannot read the package database: {error}");
            return ExitCode::from(2);
        }
    };
    let home = env::var("HOME")
        .ok()
        .filter(|home| home.starts_with('/') && home.len() > 1)
        .map(|home| {
            home.trim_start_matches('/')
                .trim_end_matches('/')
                .to_string()
        });
    let mut collection = collect::collect(&Scope {
        root: Path::new("/"),
        home: home.as_deref(),
        index: &index,
        origin: Origin::System,
    });
    if options.root {
        match root::from_root() {
            Ok(part) => root::merge(&mut collection, part),
            Err(reason) => errln!("Guardian: the root checks did not run ({reason})."),
        }
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
    if options.json {
        outln!(
            "{}",
            output::json(&collection, &report, decision, home.as_deref())
        );
    } else {
        output::print(&collection, &report, home.as_deref(), options.all);
        report.print(false, decision);
    }
    decision.exit_code()
}
