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
pub mod live;
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
use crate::report::{AgentOutcome, Blocked, Decision, Gap, Report};
use crate::review::ReviewContext;
use crate::tools::OpenCode;
use collect::{Collection, Origin, Scope};
use index::{LOCAL_DB, PackageIndex};
use state::{Change, LastRun, Outcome, Remembered};

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
    /// Also save the report as a page, open it, and say how to ask an AI
    /// agent about it.
    pub report: bool,
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
        Command::Allow(label) => allow(label, settings),
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
/// Collects this system and the user's home, and runs the live checks;
/// returns the live checks' notes too.
fn collect_here(home: Option<&str>) -> Result<(Collection, PackageIndex, Vec<String>), String> {
    let index = index::foreign_packages()
        .and_then(|foreign| PackageIndex::load(Path::new(LOCAL_DB), foreign))
        .map_err(|error| format!("cannot read the package database: {error}"))?;
    let scope = Scope {
        root: Path::new("/"),
        home,
        index: &index,
        origin: Origin::System,
    };
    let mut collection = collect::collect(&scope);
    let live = live::check(&scope);
    collect::merge(&mut collection, live.items);
    collection.truncated.extend(live.unchecked);
    Ok((collection, index, live.notes))
}

fn state_directory() -> Result<std::path::PathBuf, String> {
    let root = Store::default_root().ok_or("no state directory (set HOME or XDG_STATE_HOME)")?;
    state::directory(&root)
}

fn allow(label: &str, settings: &Settings) -> Result<String, String> {
    let home = home();
    let (mut collection, _, mut notes) = collect_here(home.as_deref())?;
    // Items only root can read come from root's latest results.
    add_root_part(&mut collection, Options::default(), settings, &mut notes);
    let item = collection
        .items
        .iter()
        .find(|item| judge::label(item, home.as_deref()) == label)
        .ok_or_else(|| {
            format!("{label} is not something the sweep lists; use the path as it shows it")
        })?;
    if item.is_trusted() {
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
    // Something outside the home is allowed in root's list, through sudo:
    // a program running as you cannot quiet it.
    if !state::is_home_label(label) {
        root::system_allow(&["--add", label, &state::fingerprint(item)])?;
        return Ok(format!(
            "Allowed {label} for this system as it is now; if it changes, the sweep shows it again."
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
    if let Some(label) = label.filter(|label| !state::is_home_label(label)) {
        // An entry an older Guardian kept in the user's own list counted
        // for nothing; it goes either way.
        let directory = state_directory()?;
        let mut own = state::allowed(&directory);
        let stale = own.remove(label).is_some();
        if stale {
            state::save_allowed(&directory, &own)?;
        }
        if !state::system_allowed(Path::new(state::SYSTEM_ALLOWED)).contains_key(label) {
            return if stale {
                Ok(format!("{label} is no longer allowed."))
            } else {
                Err(format!(
                    "{label} is not in the system's list of allowed items"
                ))
            };
        }
        root::system_allow(&["--remove", label])?;
        return Ok(format!("{label} is no longer allowed."));
    }
    if label.is_none() && !state::system_allowed(Path::new(state::SYSTEM_ALLOWED)).is_empty() {
        root::system_allow(&["--clear"])?;
    }
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

/// Merges what root found into the user's sweep, with what it says of
/// the system as a whole (a tainted kernel, say).
fn merge_root_part(collection: &mut Collection, mut part: root::RootPart, notes: &mut Vec<String>) {
    let seen_by_root = std::mem::take(&mut part.notes);
    root::merge(collection, part);
    // Root saw every process; the user's notes that leave some to the
    // root checks no longer apply. What root itself could not see, it
    // says in its own words, and that is kept.
    notes.retain(|note| !note.contains("the root checks cover them"));
    for note in seen_by_root {
        if !notes.contains(&note) {
            notes.push(note);
        }
    }
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
            Ok(part) => merge_root_part(collection, part, notes),
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
                Ok(part) => merge_root_part(collection, part, notes),
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

/// The untrusted items' fingerprints, to remember for the next sweep.
/// What could not be read this time (root's results missing or old) keeps
/// its last fingerprint, rather than counting as changed now and again once
/// root's results are back.
fn remembered(
    collection: &Collection,
    report: &Report,
    previous: Option<&Remembered>,
    label: impl Fn(&collect::Item) -> String,
) -> Remembered {
    // A finding on a file is part of what is remembered about it: one that
    // appears later on a file that did not change (the AI was unavailable
    // the day it arrived) is then news.
    let mut flagged: std::collections::HashSet<&str> = report
        .findings
        .iter()
        .map(|finding| finding.path.as_str())
        .collect();
    for run in &report.agent_runs {
        if let AgentOutcome::Reviewed(review) = &run.outcome {
            flagged.extend(review.findings.iter().map(|finding| finding.file.as_str()));
        }
    }
    collection
        .items
        .iter()
        .filter(|item| !item.is_trusted())
        .map(|item| {
            let label = label(item);
            let mut fingerprint = state::fingerprint(item);
            if fingerprint == state::UNREAD
                && let Some(known) = previous.and_then(|previous| previous.get(&label))
            {
                fingerprint.clone_from(known);
            } else if flagged.contains(label.as_str()) && !fingerprint.ends_with(state::FLAGGED) {
                fingerprint.push_str(state::FLAGGED);
            }
            (label, fingerprint)
        })
        .collect()
}

/// What this sweep is measured against, and whether there is nothing yet
/// (a first sweep): for the timer's sweep, what the timer's sweeps told
/// about; for a sweep by hand, the last sweep of any kind.
fn before(directory: Option<&Path>, scheduled: bool) -> (bool, Option<Remembered>) {
    let Some(directory) = directory else {
        return (false, None);
    };
    if scheduled {
        (!state::has_told(directory), Some(state::told(directory)))
    } else {
        (
            !state::has_baseline(directory),
            Some(state::baseline(directory)),
        )
    }
}

/// Remembers what this sweep saw; the timer's sweep also as told about.
fn remember(directory: &Path, current: &Remembered, scheduled: bool) -> Result<(), String> {
    state::save_baseline(directory, current)?;
    if scheduled {
        state::save_told(directory, current)?;
    }
    Ok(())
}

/// What a scheduled sweep tells the desktop: new or changed items, or
/// for the first sweep (nothing to compare with) whether it found
/// something or could not finish.
fn notify_scheduled(
    first: bool,
    decision: Decision,
    changes: &[(Change, String)],
    unfinished: Option<&str>,
) {
    let arrived = changes
        .iter()
        .filter(|(change, _)| *change != Change::Removed)
        .count();
    // The first sweep has nothing to compare with: everything is "new".
    // It says only whether it found something.
    if first {
        match decision {
            Decision::Blocked(Blocked::Findings) => notify::found(
                "something to look at in its first system sweep",
                "the first system sweep found startup items with alerts; run `omarchy-guardian sweep` for the full list",
            ),
            Decision::Blocked(blocked) => notify::found(
                "that its first system sweep could not finish",
                notify::reason(blocked),
            ),
            Decision::Clear | Decision::Warned | Decision::Limited => {}
        }
    } else {
        if arrived > 0 {
            notify::found(
                &format!("{arrived} new or changed startup item(s)"),
                "the daily system sweep found something that runs on its own and that no package vouches for",
            );
        }
        if let Some(reason) = unfinished {
            notify::found("that its daily system sweep could not finish", reason);
        }
    }
}

/// Seconds since the epoch.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Records how this scheduled sweep ended for the bar (see
/// `state::LastRun`), and returns whether that is news: it did not end
/// this way last time. Only the timer's sweeps are recorded: the bar tells
/// whether those still work, and a sweep run by hand (with other options,
/// or where no AI can be reached) says nothing about that. A record that
/// cannot be written is the bar's to notice: it goes stale.
fn record(directory: Option<&Path>, run: &LastRun) -> bool {
    // Nothing remembered: nothing to tell news from, so nothing is said
    // every day; the bar shows that no sweep is on record.
    let Some(directory) = directory else {
        return false;
    };
    let previous = state::last_run(directory);
    if let Err(reason) = state::save_last_run(directory, run) {
        errln!("omarchy-guardian sweep: {reason}");
    }
    is_news(previous.as_ref(), run)
}

/// Whether `run` did not finish, in a way the run before it had not
/// already: by the kind of reason (its first), since the rest names files
/// and counts that move from day to day.
fn is_news(previous: Option<&LastRun>, run: &LastRun) -> bool {
    run.outcome != Outcome::Complete
        && previous.is_none_or(|previous| {
            previous.outcome != run.outcome || previous.reasons.first() != run.reasons.first()
        })
}

/// A sweep that could not even collect.
fn could_not_run(options: Options, message: &str) -> ExitCode {
    errln!("omarchy-guardian sweep: {message}");
    // The timer counts exit 2 as an incomplete sweep, not a failure, so a
    // sweep that could not run at all says so itself: when that starts, not
    // every day it lasts (the bar keeps showing it).
    if options.scheduled {
        let run = LastRun::new(now(), Outcome::Failed, vec![message.to_string()]);
        if record(state_directory().ok().as_deref(), &run) {
            notify::found("that its daily system sweep could not run", message);
        }
    }
    ExitCode::from(2)
}

/// Records how a scheduled sweep ended, and tells the desktop what it has
/// to say.
fn remember_run(
    options: Options,
    directory: Option<&Path>,
    report: &Report,
    decision: Decision,
    first: bool,
    changes: &[(Change, String)],
) {
    if !options.scheduled {
        return;
    }
    // Findings are a sweep that did its job; anything else that blocks is
    // one that could not see or review everything.
    let reasons: Vec<String> = match decision {
        Decision::Blocked(Blocked::Findings)
        | Decision::Clear
        | Decision::Warned
        | Decision::Limited => Vec::new(),
        Decision::Blocked(blocked) => std::iter::once(notify::reason(blocked).to_string())
            .chain(
                report
                    .agent_runs
                    .iter()
                    .filter_map(|run| match &run.outcome {
                        AgentOutcome::Unavailable(error) => Some(error.to_string()),
                        AgentOutcome::Reviewed(_) => None,
                    }),
            )
            .chain(report.gaps.iter().map(ToString::to_string))
            .collect(),
    };
    let outcome = if reasons.is_empty() {
        Outcome::Complete
    } else {
        Outcome::Incomplete
    };
    let last = LastRun::new(now(), outcome, reasons);
    let unfinished = record(directory, &last).then(|| last.reasons.join("; "));
    notify_scheduled(first, decision, changes, unfinished.as_deref());
}

/// `sweep --report`: the page, opened in the browser, and how to ask about
/// it.
fn save_report(collection: &Collection, decision: Decision) {
    let to_look_at = collection
        .items
        .iter()
        .filter(|item| !item.is_trusted())
        .count();
    let detail = format!(
        "{to_look_at} item(s) to look at; {}",
        match decision {
            Decision::Clear | Decision::Limited => "the review is clear",
            Decision::Warned => "the review warned",
            Decision::Blocked(blocked) => notify::reason(blocked),
        }
    );
    let clear = matches!(decision, Decision::Clear | Decision::Limited);
    match notify::save_and_open(
        "Guardian checked this system",
        &detail,
        notify::Ran::Swept { clear },
    ) {
        Some((path, id)) => {
            outln!("\nReport saved: {}", path.display());
            outln!("Ask your AI agent about it: omarchy-guardian ask {id}");
        }
        None => errln!("omarchy-guardian sweep: could not save the report"),
    }
}

/// Marks the items allowed in the user's list (home) and the system's
/// (everything else), and says how many system entries an older Guardian
/// left in the user's own list, which count for nothing now.
fn apply_allowed(
    items: &mut [collect::Item],
    directory: &Path,
    label: &dyn Fn(&collect::Item) -> String,
    notes: &mut Vec<String>,
) {
    let system = state::system_allowed(Path::new(state::SYSTEM_ALLOWED));
    let allowed = state::all_allowed(directory, Path::new(state::SYSTEM_ALLOWED));
    state::apply_allowed(items, &allowed, label);
    // An entry an older Guardian kept in the user's list that the system's
    // list now holds is done with; the rest are said.
    let mut own = state::allowed(directory);
    let (dropped, left) = migrate_own_list(&mut own, &system);
    if dropped {
        drop(state::save_allowed(directory, &own));
    }
    if !left.is_empty() {
        let named: Vec<&str> = left.iter().take(3).map(String::as_str).collect();
        notes.push(format!(
            "{} system item(s) you allowed before are no longer allowed from your own list ({}{}): allow one again with `sweep allow LABEL` (it asks for the sudo password), or drop it with `sweep forget LABEL`",
            left.len(),
            named.join(", "),
            if left.len() > named.len() { ", ..." } else { "" }
        ));
    }
}

/// Takes out of the user's own list the system entries an older Guardian
/// kept there that the system's list now holds. Returns whether any went,
/// and the system entries left in it, which count for nothing.
fn migrate_own_list(own: &mut Remembered, system: &Remembered) -> (bool, Vec<String>) {
    let before = own.len();
    own.retain(|label, _| state::is_home_label(label) || !system.contains_key(label));
    let left = own
        .keys()
        .filter(|label| !state::is_home_label(label))
        .cloned()
        .collect();
    (own.len() < before, left)
}

/// `omarchy-guardian sweep`.
fn run(options: Options, settings: &Settings) -> ExitCode {
    let home = home();
    if options.scheduled
        && let Ok(directory) = state_directory()
        && let Err(reason) = state::mark_started(&directory, now())
    {
        errln!("omarchy-guardian sweep: {reason}");
    }
    let (mut collection, index, mut notes) = match collect_here(home.as_deref()) {
        Ok(found) => found,
        Err(message) => return could_not_run(options, &message),
    };
    add_root_part(&mut collection, options, settings, &mut notes);
    let directory = state_directory()
        .map_err(|reason| notes.push(format!("nothing remembered between sweeps ({reason})")))
        .ok();
    let label = |item: &collect::Item| judge::label(item, home.as_deref());
    if let Some(directory) = &directory {
        apply_allowed(&mut collection.items, directory, &label, &mut notes);
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
        collect::bounded(collection.truncated.clone())
            .into_iter()
            .map(Gap::Sweep),
    );
    // Nothing to review is a clean sweep, not a limited one.
    let decision = match report.decide(&|class| settings.policy(class)) {
        Decision::Limited => Decision::Clear,
        decision => decision,
    };

    let (first, previous) = before(directory.as_deref(), options.scheduled);
    let current = remembered(&collection, &report, previous.as_ref(), label);
    let changes = previous
        .as_ref()
        .map(|previous| state::diff(previous, &current))
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
        output::print_notes(&notes);
        report.print(false, decision);
        if options.report {
            save_report(&collection, decision);
        }
    }
    if let Some(directory) = &directory
        && let Err(reason) = remember(directory, &current, options.scheduled)
    {
        errln!("omarchy-guardian sweep: {reason}");
        // Without it the next sweep would see nothing as new.
        if options.scheduled {
            notify::found(
                "that it cannot remember what it saw",
                "the daily system sweep could not save what it found, so it cannot tell what is new",
            );
        }
    }
    remember_run(
        options,
        directory.as_deref(),
        &report,
        decision,
        first,
        &changes,
    );
    decision.exit_code()
}

#[cfg(test)]
mod tests {
    #[test]
    fn old_system_entries_in_the_users_list_go_once_root_holds_them() {
        let entry = |labels: &[&str]| -> super::state::Remembered {
            labels
                .iter()
                .map(|label| ((*label).to_string(), "x".to_string()))
                .collect()
        };
        let mut own = entry(&["~/.bashrc", "/root/a", "/root/b"]);
        let system = entry(&["/root/a"]);
        let (dropped, left) = super::migrate_own_list(&mut own, &system);
        assert!(dropped);
        assert_eq!(left, ["/root/b"]);
        assert_eq!(own.keys().collect::<Vec<_>>(), ["/root/b", "~/.bashrc"]);
        let (dropped, _) = super::migrate_own_list(&mut own, &system);
        assert!(!dropped);
    }

    use super::state::{LastRun, Outcome};
    use super::{is_news, record};
    use crate::test_support::TempDir;

    #[test]
    fn what_root_says_of_the_system_is_kept_and_what_it_covers_is_dropped() {
        let covered = "3 process(es) of other users were not looked at; the root checks cover them";
        let mut notes = vec![covered.to_string(), "the kernel is tainted".to_string()];
        let part = super::root::RootPart {
            items: Vec::new(),
            truncated: Vec::new(),
            notes: vec![
                "the kernel is tainted".into(),
                "1 module(s) no package installed".into(),
                "2 listening socket(s) have no process that can be found".into(),
            ],
        };
        super::merge_root_part(&mut super::Collection::default(), part, &mut notes);
        assert_eq!(
            notes,
            [
                "the kernel is tainted",
                "1 module(s) no package installed",
                "2 listening socket(s) have no process that can be found"
            ]
        );
    }

    #[test]
    fn an_unfinished_sweep_is_news_when_it_starts_or_its_kind_changes() {
        let run = |outcome, reasons: &[&str]| {
            LastRun::new(
                1,
                outcome,
                reasons.iter().map(|reason| (*reason).to_string()).collect(),
            )
        };
        let complete = run(Outcome::Complete, &[]);
        let no_ai = run(Outcome::Incomplete, &["the AI reviewer was unavailable"]);
        let gaps = run(Outcome::Incomplete, &["the review was incomplete", "/a"]);
        let other_gaps = run(Outcome::Incomplete, &["the review was incomplete", "/b"]);
        let failed = run(Outcome::Failed, &["cannot read the package database"]);

        assert!(!is_news(None, &complete));
        assert!(!is_news(Some(&gaps), &complete));
        assert!(is_news(None, &gaps));
        assert!(is_news(Some(&complete), &gaps));
        assert!(is_news(Some(&no_ai), &gaps));
        // The same kind of trouble, with other files named: said already.
        assert!(!is_news(Some(&gaps), &other_gaps));
        assert!(is_news(Some(&gaps), &failed));
        assert!(!is_news(Some(&failed), &failed));

        // Recorded, and news only the first time.
        let dir = TempDir::new("sweep-record");
        assert!(record(Some(dir.path()), &failed));
        assert!(!record(Some(dir.path()), &failed));
        assert!(!record(Some(dir.path()), &complete));
        assert_eq!(super::state::last_run(dir.path()), Some(complete));
    }
}
