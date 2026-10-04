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

pub mod access;
pub mod boot;
pub mod collect;
pub mod commands;
pub mod config;
pub mod index;
pub mod judge;
pub mod live;
pub mod lua;
pub mod output;
pub mod own;
pub mod path;
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
    /// Move what an older Guardian kept in the user's own list of allowed
    /// items to the system's, after showing it.
    Migrate,
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
        Command::Migrate => migrate(settings),
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
    let mut notes = live.notes;
    notes.append(&mut collection.notes);
    // Guardian itself is installed that way, and says so nowhere else.
    let by_hand: Vec<&str> = index
        .unverified
        .iter()
        .map(String::as_str)
        .filter(|name| *name != "omarchy-guardian")
        .collect();
    if !by_hand.is_empty() {
        notes.push(format!(
            "{} package(s) a repository carries by name were installed from a package file nothing checked (pacman -U): {}{}; their files count as user-built",
            by_hand.len(),
            by_hand.iter().take(5).copied().collect::<Vec<_>>().join(", "),
            if by_hand.len() > 5 { ", ..." } else { "" }
        ));
    }
    Ok((collection, index, notes))
}

fn state_directory() -> Result<std::path::PathBuf, String> {
    let root = Store::default_root().ok_or("no state directory (set HOME or XDG_STATE_HOME)")?;
    state::directory(&root)
}

/// The item the sweep shows as `label`, with everything root's latest
/// results add.
fn collect_for_allow(settings: &Settings) -> Result<(Collection, Option<String>), String> {
    let home = home();
    let (mut collection, _, mut notes) = collect_here(home.as_deref())?;
    // Items only root can read come from root's latest results.
    add_root_part(&mut collection, Options::default(), settings, &mut notes);
    Ok((collection, home))
}

fn allow(label: &str, settings: &Settings) -> Result<String, String> {
    let (collection, home) = collect_for_allow(settings)?;
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
    if let Some(reason) = state::not_allowable(item) {
        return Err(format!("{label} cannot be allowed: {reason}"));
    }
    if item.sha256.is_none() && !matches!(item.body, collect::Body::Link(_)) {
        return Err(format!(
            "{label} cannot be read, so it cannot be allowed as it is"
        ));
    }
    // Every allow goes into root's list, through sudo: a program running
    // as you cannot quiet what it planted, in your home or anywhere else.
    root::system_allow(&["--add", label, &state::fingerprint(item)])?;
    Ok(format!(
        "Allowed {label} as it is now; if it changes, the sweep shows it again."
    ))
}

/// `sweep allow --migrate`: shows what an older Guardian kept in the
/// user's own list and, after a yes, moves the entries whose items are
/// still as they were allowed into the system's list.
fn migrate(settings: &Settings) -> Result<String, String> {
    use std::io::IsTerminal as _;
    let directory = state_directory()?;
    let mut old = state::old_allowed(&directory);
    if old.is_empty() {
        return Ok("Nothing to move: no list of an older Guardian is left.".into());
    }
    let uid = store::effective_uid()?;
    let current = state::all_allowed(Path::new(state::SYSTEM_ALLOWED), uid);
    let (collection, home) = collect_for_allow(settings)?;
    let (movable, stale) = movable(&old, &current, &collection.items, &|item| {
        judge::label(item, home.as_deref())
    });
    if !stale.is_empty() {
        outln!("Changed since they were allowed, gone, or trusted anyway; not moved:");
        for label in &stale {
            outln!("  {}", crate::text::shown(label));
        }
    }
    if movable.is_empty() {
        state::save_old_allowed(&directory, &Remembered::new())?;
        return Ok("Nothing to move; the old list is dropped.".into());
    }
    outln!("Allowed with an older Guardian, and unchanged since:");
    for (label, _) in &movable {
        outln!("  {}", crate::text::shown(label));
    }
    // The old list was the user's own to write, so any program running as
    // them could have added to it: nothing moves without a yes.
    if !std::io::stdin().is_terminal() {
        return Err(
            "these are only moved after you looked at them: run `sweep allow --migrate` in a terminal".into(),
        );
    }
    errln!(
        "Any program running as you could have added to that list. Move these {} item(s) only if you recognise every one. Move them? [y/N]",
        movable.len()
    );
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(|error| format!("cannot read the answer: {error}"))?;
    if !matches!(answer.trim(), "y" | "Y" | "yes") {
        return Ok("Nothing moved.".into());
    }
    let mut arguments = Vec::new();
    for (label, fingerprint) in &movable {
        arguments.extend(["--add", label.as_str(), fingerprint.as_str()]);
    }
    root::system_allow(&arguments)?;
    old.clear();
    state::save_old_allowed(&directory, &old)?;
    Ok(format!(
        "Moved {} item(s) to the system's list of allowed items; the old list is dropped.",
        movable.len()
    ))
}

/// Splits the entries of an old list into the ones that can move to the
/// system's list (their item is listed, not trusted otherwise, allowable,
/// and still has the fingerprint it was allowed with) and the labels of
/// the rest. What the system's list already holds is neither.
fn movable(
    old: &Remembered,
    current: &Remembered,
    items: &[collect::Item],
    label: &dyn Fn(&collect::Item) -> String,
) -> (Vec<(String, String)>, Vec<String>) {
    let mut movable = Vec::new();
    let mut stale = Vec::new();
    for (entry, fingerprint) in old {
        if current.get(entry) == Some(fingerprint) {
            continue;
        }
        let unchanged = items.iter().any(|item| {
            label(item) == *entry
                && !item.is_trusted()
                && state::not_allowable(item).is_none()
                && state::fingerprint(item) == *fingerprint
        });
        if unchanged {
            movable.push((entry.clone(), fingerprint.clone()));
        } else {
            stale.push(entry.clone());
        }
    }
    (movable, stale)
}

fn forget(label: Option<&str>) -> Result<String, String> {
    let uid = store::effective_uid()?;
    let allowed = state::all_allowed(Path::new(state::SYSTEM_ALLOWED), uid);
    // What an older Guardian kept in the user's own list counted for
    // nothing; it goes either way.
    let directory = state_directory()?;
    let mut old = state::old_allowed(&directory);
    let Some(label) = label else {
        if !allowed.is_empty() {
            root::system_allow(&["--clear"])?;
        }
        state::save_old_allowed(&directory, &Remembered::new())?;
        return Ok("Forgot every allowed item.".into());
    };
    let stale = old.remove(label).is_some();
    if stale {
        state::save_old_allowed(&directory, &old)?;
    }
    if allowed.contains_key(label) {
        root::system_allow(&["--remove", label])?;
    } else if !stale {
        return Err(format!("{label} is not in the list of allowed items"));
    }
    Ok(format!("{label} is no longer allowed."))
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
/// Returns whether root's part is in.
fn add_root_part(
    collection: &mut Collection,
    options: Options,
    settings: &Settings,
    notes: &mut Vec<String>,
) -> bool {
    let part = if options.root {
        root::from_root().map_err(|reason| format!("the root checks did not run ({reason})"))
    } else {
        match settings.sweep_root().0 {
            Some(RootConsent::Allowed) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |elapsed| elapsed.as_secs());
                root::from_results(Path::new(root::RESULTS), now)
                    .map_err(|reason| format!("root checks: {reason}"))
            }
            Some(RootConsent::Declined) => Err(
                "root checks are declined in the system configuration; what only root can read is not checked".into(),
            ),
            None => Err(
                "root checks are not set up: `omarchy-guardian protect` asks to allow them, `sweep --root` runs them once".into(),
            ),
        }
    };
    match part {
        Ok(part) => {
            merge_root_part(collection, part, notes);
            true
        }
        Err(note) => {
            notes.push(note);
            false
        }
    }
}

/// Whether a new item of this kind is a finding in itself: an account, a
/// member of an administrator group, an SSH key, a certificate authority.
fn is_trust(item: &collect::Item) -> bool {
    use crate::autorun::Category;
    item.category == Category::Account
        || (item.category == Category::Trust && item.path != "etc/hosts")
}

/// The labels of the accounts, group members, keys and trust anchors that
/// were not there at the sweep before, or not as they are now. Nothing is
/// news to a sweep that never looked at such things before (after an
/// update of Guardian, or the first time root's part is in).
fn trust_news(
    collection: &Collection,
    previous: Option<&Remembered>,
    label: &dyn Fn(&collect::Item) -> String,
) -> std::collections::HashSet<String> {
    let Some(previous) = previous else {
        return std::collections::HashSet::new();
    };
    collection
        .items
        .iter()
        .filter(|item| !item.is_trusted() && is_trust(item))
        .filter(|item| {
            previous.contains_key(if item.origin == Origin::Root {
                state::ROOT_TRUST_SEEN
            } else {
                state::TRUST_SEEN
            })
        })
        .filter_map(|item| {
            let label = label(item);
            let now = state::fingerprint(item);
            match previous.get(&label) {
                None => Some(label),
                Some(before)
                    if before != state::UNREAD
                        && state::content_of(before) != state::content_of(&now) =>
                {
                    Some(label)
                }
                Some(_) => None,
            }
        })
        .collect()
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
        .chain([(state::TRUST_SEEN.to_string(), "1".to_string())])
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
        crate::audit::sweep_failed();
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
    crate::audit::sweep_ended(report, decision, changes.len());
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

/// Marks the items allowed in the system's list, and says how many
/// entries an older Guardian left in the user's own list, which count for
/// nothing now.
fn apply_allowed(
    items: &mut [collect::Item],
    directory: Option<&Path>,
    label: &dyn Fn(&collect::Item) -> String,
    notes: &mut Vec<String>,
) {
    let allowed = match store::effective_uid() {
        Ok(uid) => state::all_allowed(Path::new(state::SYSTEM_ALLOWED), uid),
        Err(reason) => {
            notes.push(format!("allowed items do not count this time ({reason})"));
            return;
        }
    };
    state::apply_allowed(items, &allowed, label);
    let Some(directory) = directory else {
        return;
    };
    // An entry of the old list that the system's list now holds is done
    // with; the rest are said.
    let mut old = state::old_allowed(directory);
    if drop_moved(&mut old, &allowed) {
        drop(state::save_old_allowed(directory, &old));
    }
    if !old.is_empty() {
        let named: Vec<&str> = old.keys().take(3).map(String::as_str).collect();
        notes.push(format!(
            "{} item(s) allowed with an older Guardian no longer count ({}{}): that list was your own to write, and so any program's running as you. `omarchy-guardian sweep allow --migrate` shows them and moves the unchanged ones to the system's list (it asks for the sudo password); `sweep forget --all` drops them",
            old.len(),
            named.join(", "),
            if old.len() > named.len() { ", ..." } else { "" }
        ));
    }
}

/// Takes out of the user's old list the entries the system's list now
/// holds as they are. Returns whether any went.
fn drop_moved(old: &mut Remembered, allowed: &Remembered) -> bool {
    let before = old.len();
    old.retain(|label, fingerprint| allowed.get(label) != Some(fingerprint));
    old.len() < before
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
    let with_root = add_root_part(&mut collection, options, settings, &mut notes);
    let directory = state_directory()
        .map_err(|reason| notes.push(format!("nothing remembered between sweeps ({reason})")))
        .ok();
    let label = |item: &collect::Item| judge::label(item, home.as_deref());
    apply_allowed(
        &mut collection.items,
        directory.as_deref(),
        &label,
        &mut notes,
    );
    let (first, previous) = before(directory.as_deref(), options.scheduled);
    let news = trust_news(&collection, previous.as_ref(), &label);

    let state_root = Store::default_root();
    let context = ReviewContext {
        settings,
        class: SourceClass::System,
        opencode: &OpenCode::UserPath,
        units: &[],
        state_root: state_root.as_deref(),
        context: &[],
    };
    let mut report = judge::judge(&collection, home.as_deref(), &context, &news);
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

    let mut current = remembered(&collection, &report, previous.as_ref(), label);
    if with_root {
        current.insert(state::ROOT_TRUST_SEEN.to_string(), "1".to_string());
    }
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
    crate::gatewatch::after_sweep(options.scheduled, settings);
    decision.exit_code()
}

#[cfg(test)]
mod tests {
    use super::collect::{Body, Collection, Item, Origin};
    use super::state::{self, Remembered};
    use crate::autorun::Category;

    fn entries(pairs: &[(&str, &str)]) -> Remembered {
        pairs
            .iter()
            .map(|(label, value)| ((*label).to_string(), (*value).to_string()))
            .collect()
    }

    fn item(path: &str, category: Category, text: &str) -> Item {
        Item {
            origin: Origin::User,
            category,
            path: path.into(),
            tier: super::tier::Tier::Unknown,
            sha256: Some(crate::sha256::Sha256::digest(text.as_bytes())),
            body: Body::Text(text.into()),
            runs: Vec::new(),
            run_by: None,
            notes: Vec::new(),
            alerts: Vec::new(),
        }
    }

    #[test]
    fn the_old_list_is_only_moved_where_nothing_changed() {
        let mut old = entries(&[("~/.bashrc", "x"), ("/root/a", "y"), ("/root/b", "z")]);
        // What root's list holds as it is, is done with; the rest stays to
        // be told about.
        let system = entries(&[("/root/a", "y"), ("/root/b", "other")]);
        assert!(super::drop_moved(&mut old, &system));
        assert_eq!(old.keys().collect::<Vec<_>>(), ["/root/b", "~/.bashrc"]);
        assert!(!super::drop_moved(&mut old, &system));

        let label = |item: &Item| format!("/{}", item.path);
        let unchanged = item("etc/a", Category::Shell, "one");
        let changed = item("etc/b", Category::Shell, "two");
        let mut redirecting = item("etc/c", Category::Systemd, "three");
        redirecting.alerts.push((
            crate::rules::RuleId::GuardianOverride,
            "changes the sweep".into(),
        ));
        let old = entries(&[
            ("/etc/a", &state::fingerprint(&unchanged)),
            ("/etc/b", "what it was when it was allowed"),
            ("/etc/c", &state::fingerprint(&redirecting)),
            ("/etc/gone", "x"),
            ("/etc/held", "h"),
        ]);
        let (movable, stale) = super::movable(
            &old,
            &entries(&[("/etc/held", "h")]),
            &[unchanged.clone(), changed, redirecting],
            &label,
        );
        assert_eq!(
            movable,
            [("/etc/a".to_string(), state::fingerprint(&unchanged))]
        );
        assert_eq!(stale, ["/etc/b", "/etc/c", "/etc/gone"]);
    }

    #[test]
    fn a_key_or_member_that_was_not_there_before_is_news_once_such_things_were_looked_at() {
        let label = |item: &Item| format!("/{}", item.path);
        let known = item(
            "etc/group#wheel:u",
            Category::Account,
            "member u of group wheel",
        );
        let added = item(
            "etc/group#wheel:evil",
            Category::Account,
            "member evil of group wheel",
        );
        let mut of_root = item(
            "root/.ssh/authorized_keys#abc",
            Category::Account,
            "ssh-ed25519",
        );
        of_root.origin = Origin::Root;
        let anchor = item(
            "etc/ca-certificates/trust-source/anchors/x.crt",
            Category::Trust,
            "pem",
        );
        let hosts = item("etc/hosts", Category::Trust, "127.0.0.1 localhost");
        let unit = item(
            "etc/systemd/system/x.service",
            Category::Systemd,
            "[Service]",
        );
        let collection = Collection {
            items: vec![known.clone(), added, of_root, anchor, hosts, unit],
            ..Collection::default()
        };
        // A sweep from before such things were looked at: nothing is news.
        let before = entries(&[("/etc/x", "1")]);
        assert!(super::trust_news(&collection, Some(&before), &label).is_empty());
        assert!(super::trust_news(&collection, None, &label).is_empty());
        // Once they were: what is new is, as far as each part was seen.
        let mut seen = entries(&[
            (state::TRUST_SEEN, "1"),
            // An alert or a finding that came or went is no new content.
            (
                "/etc/group#wheel:u",
                &format!("{}+finding", state::fingerprint(&known)),
            ),
        ]);
        let mut news: Vec<String> = super::trust_news(&collection, Some(&seen), &label)
            .into_iter()
            .collect();
        news.sort();
        assert_eq!(
            news,
            [
                "/etc/ca-certificates/trust-source/anchors/x.crt",
                "/etc/group#wheel:evil"
            ]
        );
        seen.insert(state::ROOT_TRUST_SEEN.into(), "1".into());
        assert!(
            super::trust_news(&collection, Some(&seen), &label)
                .contains("/root/.ssh/authorized_keys#abc")
        );
        // A changed list is news too.
        seen.insert("/etc/group#wheel:u".into(), "another".into());
        assert!(super::trust_news(&collection, Some(&seen), &label).contains("/etc/group#wheel:u"));
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
        super::merge_root_part(&mut Collection::default(), part, &mut notes);
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
        assert_eq!(state::last_run(dir.path()), Some(complete));
    }
}
