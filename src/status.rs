//! `omarchy-guardian status`: what the bar widgets show. An overall state
//! (`ok`, `attention` or `off`), each gate, the protection level and model,
//! problems to fix, and the last block: as JSON for the Omarchy shell widget
//! (`status`), or for the Waybar image module (`status --waybar`).
//! `status --dismiss` marks the current blocks as seen, and
//! `status --open-report` opens the last one.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::agent;
use crate::config::Settings;
use crate::config::model::{
    Action, AiRequirement, Named, Profile, RootConsent, SourceClass, builtin,
};
use crate::config::weaker;
use crate::engine::store::Store;
use crate::gatewatch::{self, Level, Observer};
use crate::integrations::{Integration, Paths, State};
use crate::json::Json;
use crate::notify;
use crate::pacman;
use crate::protect::paths;
use crate::rules::RuleId;
use crate::sweep::root::{RESULTS, RootPart, from_results, results_problem};
use crate::sweep::state::{self, LastRun, Outcome};
use crate::tools::Reviewer;

/// A block younger than this needs attention until it is dismissed.
const RECENT_SECS: u64 = 24 * 60 * 60;
/// The newest report id the user has dismissed, in the reports directory.
const SEEN: &str = ".seen";
/// Waybar refreshes the module on `SIGRTMIN+WAYBAR_SIGNAL`.
pub const WAYBAR_SIGNAL: u8 = 9;

/// A daily sweep, or daily root results, older than this have stopped.
const STALE_SECS: u64 = 3 * 24 * 60 * 60;
/// How long after boot the timers get before a missing run counts: they
/// start minutes after boot, then wait a random while.
const GRACE_SECS: u64 = 60 * 60;
/// A scheduled sweep still running after this is not running: its unit
/// stops it after an hour.
const UNFINISHED_SECS: u64 = 2 * 60 * 60;

/// The gates that protect installs; the menu entry and widgets are
/// conveniences.
const GATES: [Integration; 5] = [
    Integration::PacmanHook,
    Integration::AurGate,
    Integration::ThemeInterceptor,
    Integration::SessionPath,
    Integration::SystemSweep,
];

struct Gate {
    label: &'static str,
    state: &'static str,
    detail: String,
}

struct Status {
    state: &'static str,
    profile: &'static str,
    model: String,
    gates: Vec<Gate>,
    issues: Vec<String>,
    block: Option<LastBlock>,
    /// A release newer than the one installed, as the last check found.
    update: Option<String>,
}

fn collect() -> Status {
    let settings = Settings::load();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let mut issues: Vec<String> = settings.warnings().to_vec();
    if let Some(reason) = settings.privileged_block() {
        issues.push(reason.to_string());
    }

    let paths = paths(&settings);
    let mut gates = Vec::new();
    let mut on = 0;
    if let Some(paths) = &paths {
        for integration in GATES {
            let state = paths.state(integration);
            let (name, detail) = match &state {
                State::On => ("on", String::new()),
                State::Off => ("off", String::new()),
                State::Foreign(detail) => ("foreign", detail.clone()),
                State::Partial(detail) => ("partial", detail.clone()),
                State::Unavailable(detail) => ("unavailable", detail.clone()),
            };
            if state == State::On {
                on += 1;
            }
            issues.extend(gate_issue(paths, integration, &state));
            // On, and reviewing with the local checks alone: said beside
            // the gate, as a choice and not a fault.
            let caveats: Vec<String> = [
                local_only(&settings, integration),
                (integration == Integration::ThemeInterceptor)
                    .then(|| paths.theme_caveat())
                    .flatten(),
                (integration == Integration::SessionPath)
                    .then(|| paths.path_caveat())
                    .flatten(),
            ]
            .into_iter()
            .flatten()
            .collect();
            let detail = if state == State::On && !caveats.is_empty() {
                caveats.join("; ")
            } else {
                detail
            };
            gates.push(Gate {
                label: integration.label(),
                state: name,
                detail,
            });
        }
    }
    if let Err(reason) = pacman::preflight(&settings, pacman::system_reviewer_ready(&settings)) {
        issues.push(reason);
    }
    issues.extend(quiet_weakenings(&settings, paths.as_ref()));
    if let Some(paths) = &paths {
        issues.extend(overrides_issue(&root_overrides(paths)));
        let enabled = |link: &Path| fs::symlink_metadata(link).is_ok();
        if enabled(&paths.sweep_timer_link) {
            let root_problem = (paths.sweep_consent == Some(RootConsent::Allowed)
                && enabled(&paths.sweep_root_timer_link))
            .then(|| results_problem(Path::new(RESULTS), now))
            .flatten();
            issues.extend(sweep_health(
                now,
                uptime(now),
                Store::default_root()
                    .and_then(|root| state::last_run_in(&root))
                    .as_ref(),
                Store::default_root().and_then(|root| state::started_in(&root)),
                root_problem.as_deref(),
            ));
        }
    }

    let block = notify::reports_dir().and_then(|directory| last_block(&directory, now));
    let unseen = block.as_ref().is_some_and(|block| block.unseen);
    let state = if on == 0 {
        "off"
    } else if !issues.is_empty() || unseen {
        "attention"
    } else {
        "ok"
    };
    Status {
        state,
        profile: settings.profile_for(SourceClass::Source).name(),
        model: settings.agent_settings(SourceClass::Aur).label(),
        gates,
        issues,
        block,
        update: crate::update::available(&settings),
    }
}

/// The bar's problem line for a gate that is not on, if it is one. A gate
/// with nothing on this machine to guard (the AUR gate without yay, the
/// PATH wrappers without Omarchy) is not protection missing; any other
/// gate that cannot be there is.
pub(crate) fn gate_issue(paths: &Paths, integration: Integration, state: &State) -> Option<String> {
    match state {
        State::On => None,
        State::Unavailable(_) if !paths.applies(integration) => None,
        State::Unavailable(detail) => {
            Some(format!("{} is unavailable: {detail}", integration.label()))
        }
        _ => Some(format!("{} is not fully on", integration.label())),
    }
}

/// Root's results are a few kilobytes; past this the bar leaves them to
/// the sweep, which reads them whole.
const MAX_ROOT_RESULTS: u64 = 4 * 1024 * 1024;

/// The files the daily root checks reported standing in for one of the
/// sweep's own units (a unit or a drop-in in another account-wide or
/// per-user unit directory), absolute, without those the bar found itself
/// and names beside the sweep's gate. Empty when the root checks are off
/// or their results are not usable: that is a problem of its own.
fn root_overrides(paths: &Paths) -> Vec<String> {
    let enabled = |link: &Path| fs::symlink_metadata(link).is_ok();
    if paths.sweep_consent != Some(RootConsent::Allowed) || !enabled(&paths.sweep_root_timer_link) {
        return Vec::new();
    }
    let results = Path::new(RESULTS);
    if fs::metadata(results).map_or(true, |metadata| metadata.len() > MAX_ROOT_RESULTS) {
        return Vec::new();
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    from_results(results, now)
        .map(|part| reported_overrides(&part, &paths.sweep_overrides))
        .unwrap_or_default()
}

/// The items among root's that carry the alert, without the `known` ones.
fn reported_overrides(part: &RootPart, known: &[String]) -> Vec<String> {
    part.items
        .iter()
        .filter(|item| {
            item.alerts
                .iter()
                .any(|(rule, _)| *rule == RuleId::GuardianOverride)
        })
        .filter(|item| !known.contains(&item.path))
        .map(|item| format!("/{}", item.path))
        .collect()
}

/// The bar's line for them.
fn overrides_issue(found: &[String]) -> Option<String> {
    let (first, rest) = found.split_first()?;
    Some(format!(
        "the root checks found {first}{} standing in for, or changing, one of Guardian's own sweep units: the sweep may not run as packaged (see `omarchy-guardian sweep`)",
        if rest.is_empty() {
            String::new()
        } else {
            format!(" and {} more", rest.len())
        }
    ))
}

/// What makes protection less than the gates' states say, each a problem
/// for the bar: a class reviewed more weakly than its level, an AUR helper
/// with no gate, and what was on when Guardian last looked and is not now.
fn quiet_weakenings(settings: &Settings, paths: Option<&Paths>) -> Vec<String> {
    // A weaker class makes its gate do less than it reads, or nothing: a
    // problem until the root-owned system file accepts it. (Accepted ones
    // stay beside the gate.)
    let mut issues: Vec<String> = weaker::weakenings(settings)
        .iter()
        .filter(|weakening| !weakening.acknowledged)
        .map(weaker::Weakening::issue)
        .collect();
    if let Some(paths) = paths {
        issues.extend(paths.helper_issues());
    }
    // A gate that is off is already listed with the gates: this adds the
    // rest (the menu entry, the bar widgets, the pacman gate's reviewer,
    // the settings files). Tests keep no record in the real home.
    if !cfg!(test) {
        issues.extend(
            gatewatch::observe(&snapshot_of(settings, paths), Observer::Watching)
                .into_iter()
                // What the root checks saw standing in for the sweep's
                // units is listed for as long as it is there (`collect`).
                .filter(|(key, _)| {
                    key != gatewatch::SWEEP_UNITS
                        && !GATES.iter().any(|gate| gate.label() == key)
                })
                .map(|(_, line)| line),
        );
    }
    issues
}

/// Every gate, integration and weaker setting as it is now, for the record
/// that tells when one of them drops (see `gatewatch`).
pub fn snapshot(settings: &Settings) -> gatewatch::Snapshot {
    snapshot_of(settings, paths(settings).as_ref())
}

fn snapshot_of(settings: &Settings, paths: Option<&Paths>) -> gatewatch::Snapshot {
    let mut gates = Vec::new();
    if let Some(paths) = paths {
        for integration in Integration::ALL {
            let label = integration.label();
            let (level, now) = match paths.state(integration) {
                State::On => (Level::On, format!("{label} is on")),
                State::Off => (Level::Off, format!("{label} is off")),
                State::Partial(detail) => (
                    Level::Partial,
                    format!("{label} is only partly on ({detail})"),
                ),
                State::Foreign(detail) => (
                    Level::Off,
                    format!("{label} is not Guardian's own ({detail})"),
                ),
                State::Unavailable(detail) => {
                    (Level::Off, format!("{label} is unavailable ({detail})"))
                }
            };
            gates.push(gatewatch::Gate {
                key: label.to_string(),
                level,
                now,
            });
        }
    }
    // The pacman gate reviews with a root-owned program; one that went
    // away, or stopped being root's, leaves it refusing or unreviewed.
    let reviewer = pacman::classes_requiring_ai(settings).is_empty()
        || pacman::system_reviewer_ready(settings);
    gates.push(gatewatch::Gate {
        key: "pacman reviewer".into(),
        level: if reviewer { Level::On } else { Level::Off },
        now: "the pacman gate's root-owned reviewer is gone".into(),
    });
    let usable = settings.user_block().is_none() && settings.privileged_block().is_none();
    gates.push(gatewatch::Gate {
        key: "settings".into(),
        level: if usable { Level::On } else { Level::Off },
        now: "a Guardian settings file cannot be used".into(),
    });
    // A settings file of the reviewer's own in /etc applies to every
    // review, whatever Guardian passes the reviewer.
    let mut reviewers: Vec<Reviewer> = [SourceClass::Aur, SourceClass::Official]
        .iter()
        .map(|class| Reviewer::for_model(settings.agent_settings(*class).model.as_deref()))
        .collect();
    reviewers.dedup();
    let exposures: Vec<agent::Exposure> = reviewers
        .into_iter()
        .map(|reviewer| agent::exposure(reviewer, true))
        .collect();
    gates.push(gatewatch::reviewer_settings(&exposures));
    gates.push(gatewatch::sweep_units(
        &paths.map(root_overrides).unwrap_or_default(),
    ));
    gatewatch::Snapshot {
        gates,
        // Read from this caller's own PATH, for want of the session's:
        // another caller would read them otherwise.
        unknown: paths
            .map(Paths::unsettled)
            .unwrap_or_default()
            .into_iter()
            .map(|integration| integration.label().to_string())
            .collect(),
        weak: weaker::weakenings(settings)
            .iter()
            .filter(|weakening| !weakening.acknowledged)
            .map(|weakening| {
                (
                    weakening.key(),
                    format!(
                        "{}: {} = {} is weaker than the {} level",
                        weaker::subject(weakening.class),
                        weakening.knob,
                        weakening.value,
                        weakening.profile
                    ),
                )
            })
            .collect(),
    }
}

/// Records the gates as they are after the user changed one through
/// Guardian (`protect`, the settings app): known, so not news.
pub fn chosen() {
    gatewatch::observe(&snapshot(&Settings::load()), Observer::Chosen);
}

/// Looks at the gates before the user changes one through Guardian, so
/// what dropped by itself until now is told as news and not recorded as
/// the user's choice along with the change.
pub fn watched() {
    gatewatch::observe(&snapshot(&Settings::load()), Observer::Watching);
}

/// What to say beside a gate that is on while the AI review is off for
/// what it reviews, unless that is the protection level chosen as a whole
/// (the level already says "no AI").
fn local_only(settings: &Settings, integration: Integration) -> Option<String> {
    let classes: &[(SourceClass, &str)] = match integration {
        Integration::PacmanHook => &[
            (SourceClass::ThirdPartyRepo, "third-party packages"),
            (SourceClass::LocalPackage, "local packages"),
        ],
        Integration::AurGate => &[(SourceClass::Aur, "AUR builds")],
        Integration::ThemeInterceptor => &[
            (SourceClass::Theme, "themes"),
            (SourceClass::Plugin, "plugins"),
        ],
        Integration::SystemSweep => &[(SourceClass::System, "the sweep")],
        _ => &[],
    };
    let named = |weak: &dyn Fn(SourceClass) -> bool| -> Option<String> {
        let names: Vec<&str> = classes
            .iter()
            .filter(|(class, _)| weak(*class))
            .map(|(_, name)| *name)
            .collect();
        (!names.is_empty()).then(|| names.join(" and "))
    };
    let mut notes = Vec::new();
    if let Some(names) = named(&|class| {
        settings.profile_for(class) != Profile::LocalOnly
            && settings.policy(class).ai == AiRequirement::Off
    }) {
        notes.push(format!("local checks only: AI review is off for {names}"));
    }
    // A class set to warn where its protection level blocks lets through
    // what the level would stop.
    if let Some(names) = named(&|class| {
        let policy = settings.policy(class);
        let level = builtin(settings.profile_for(class), class);
        (policy.on_findings == Action::Warn && level.on_findings == Action::Block)
            || (policy.on_ai_suspicious == Action::Warn && level.on_ai_suspicious == Action::Block)
    }) {
        notes.push(format!("findings only warn, and do not block, for {names}"));
    }
    // The same for a review the AI could not give.
    if let Some(names) = named(&|class| {
        settings.policy(class).ai == AiRequirement::Optional
            && builtin(settings.profile_for(class), class).ai == AiRequirement::Required
    }) {
        notes.push(format!(
            "an AI review that cannot run only warns, and does not block, for {names}"
        ));
    }
    (!notes.is_empty()).then(|| notes.join("; "))
}

/// Seconds the sweep's timers have had: since boot, or since the user's
/// service manager started if that is later (its timer counts from there).
fn uptime(now: u64) -> u64 {
    let boot = fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|text| text.split(['.', ' ']).next()?.parse().ok())
        .unwrap_or(0);
    let session = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .and_then(|runtime| fs::metadata(runtime.join("systemd/private")).ok())
        .and_then(|socket| socket.modified().ok())
        .and_then(|started| started.duration_since(UNIX_EPOCH).ok())
        .map(|started| now.saturating_sub(started.as_secs()));
    session.map_or(boot, |session| session.min(boot))
}

/// What is wrong with a sweep that is turned on: its timer's sweeps
/// stopped, the last one could not finish, or the daily root results are
/// not usable (`root_problem`, when root checks are on). A sweep that only
/// spoke up about what it found would go quiet exactly when it broke.
fn sweep_health(
    now: u64,
    uptime: u64,
    last: Option<&LastRun>,
    started: Option<u64>,
    root_problem: Option<&str>,
) -> Vec<String> {
    let mut issues = Vec::new();
    // Still marked as started long after its unit would have stopped it:
    // it was killed, or crashed.
    if let Some(started) = started
        && now.saturating_sub(started) >= UNFINISHED_SECS
    {
        issues.push(format!(
            "a scheduled system sweep started {} ago and never ended",
            age(now.saturating_sub(started)).trim_end_matches(" ago")
        ));
    }
    let settled = uptime >= GRACE_SECS;
    let days = |seconds: u64| seconds / (24 * 60 * 60);
    match last {
        None if settled => issues.push("the daily system sweep has not run yet".into()),
        None => {}
        Some(last) => {
            let age = now.saturating_sub(last.at);
            if age >= STALE_SECS && settled {
                issues.push(format!(
                    "the daily system sweep has not run for {} days",
                    days(age)
                ));
            }
            let why = last.reasons.join("; ");
            match last.outcome {
                Outcome::Complete => {}
                Outcome::Incomplete => {
                    issues.push(format!("the last system sweep could not finish: {why}"));
                }
                Outcome::Failed => {
                    issues.push(format!("the last system sweep could not run: {why}"));
                }
            }
        }
    }
    if let Some(problem) = root_problem
        && settled
    {
        issues.push(format!("the daily root checks: {problem}"));
    }
    issues
}

/// The Omarchy shell widget's JSON.
pub fn json() -> String {
    let status = collect();
    let rendered = Json::object([
        ("version", Json::from(env!("CARGO_PKG_VERSION"))),
        ("state", Json::from(status.state)),
        ("profile", Json::from(status.profile)),
        ("model", Json::from(status.model)),
        (
            "gates",
            Json::Array(
                status
                    .gates
                    .into_iter()
                    .map(|gate| {
                        Json::object([
                            ("label", Json::from(gate.label)),
                            ("state", Json::from(gate.state)),
                            ("detail", Json::from(gate.detail)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "issues",
            Json::Array(status.issues.into_iter().map(Json::from).collect()),
        ),
        (
            "update",
            status.update.map_or(Json::Null, |version| {
                Json::object([
                    ("version", Json::from(version)),
                    ("how", Json::from(crate::update::HOW)),
                ])
            }),
        ),
        (
            "last_block",
            status.block.map_or(Json::Null, |block| {
                Json::object([
                    ("id", Json::from(block.id)),
                    ("title", Json::from(block.title)),
                    ("age_secs", Json::from(block.age_secs)),
                    ("unseen", Json::from(block.unseen)),
                    ("report", Json::from(block.report)),
                ])
            }),
        ),
    ])
    .to_string();
    escape_hidden(&rendered)
}

/// `json` (rendered JSON) with every hidden character written as a JSON
/// escape: still JSON, and nothing a terminal acts on when it is printed.
/// The title of a report saved long ago may hold anything.
fn escape_hidden(json: &str) -> String {
    json.chars().fold(String::new(), |mut out, character| {
        if crate::text::is_hidden(character) {
            let mut units = [0; 2];
            for unit in character.encode_utf16(&mut units) {
                let _ = write!(out, "\\u{unit:04x}");
            }
        } else {
            out.push(character);
        }
        out
    })
}

/// details.
pub fn waybar() -> String {
    let status = collect();
    let icon = match status.state {
        "ok" => "omarchy-guardian",
        "off" => "omarchy-guardian-off",
        _ => "omarchy-guardian-alert",
    };
    let headline = match status.state {
        "ok" => "Protecting this machine",
        "off" => "Protection is off",
        _ => "Needs your attention",
    };
    let level = match status.profile {
        "standard" => "Balanced protection",
        "strict" => "Maximum protection",
        "local-only" => "Private (no AI)",
        other => other,
    };
    // What is not Guardian's own wording is escaped where it goes in, so
    // a `<b>` in a title or a setting stays text.
    let mut tooltip = format!(
        "<b>Guardian</b> · {headline}\n{} · {}\n",
        markup_safe(level),
        markup_safe(&status.model)
    );
    for gate in &status.gates {
        let mark = if gate.state == "on" { "●" } else { "○" };
        let _ = write!(
            tooltip,
            "\n{mark} {}  {}",
            markup_safe(gate.label),
            gate.state.to_uppercase()
        );
        if !gate.detail.is_empty() {
            let _ = write!(tooltip, "\n    {}", markup_safe(&gate.detail));
        }
    }
    if !status.issues.is_empty() {
        tooltip.push_str("\n\n<b>Needs fixing</b>");
        for issue in &status.issues {
            let _ = write!(tooltip, "\n! {}", markup_safe(issue));
        }
    }
    if let Some(block) = &status.block {
        let _ = write!(
            tooltip,
            "\n\n<b>Last block</b> · {}\n{}",
            age(block.age_secs),
            markup_safe(&block.title)
        );
    }
    if let Some(version) = &status.update {
        let _ = write!(
            tooltip,
            "\n\n<b>Guardian {} is available</b>\nTo upgrade, {}",
            markup_safe(version),
            markup_safe(crate::update::HOW)
        );
    }
    tooltip.push_str("\n\nLeft-click: settings · right-click: last report");
    // Waybar takes the tooltip from one line: its line breaks go as
    // markup.
    format!(
        "/usr/share/icons/hicolor/scalable/apps/{icon}.svg\n{}",
        tooltip.replace('\n', "&#10;")
    )
}

/// Escapes text for Pango markup; a line break or another control
/// character in it (which markup cannot hold) becomes a space.
fn markup_safe(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace(char::is_control, " ")
}

fn age(seconds: u64) -> String {
    match seconds {
        0..60 => "just now".into(),
        60..3600 => format!("{} min ago", seconds / 60),
        3600..86_400 => format!("{} h ago", seconds / 3600),
        _ => format!("{} d ago", seconds / 86_400),
    }
}

struct LastBlock {
    id: String,
    title: String,
    age_secs: u64,
    unseen: bool,
    report: String,
}

/// The newest saved report, and whether it is recent and not yet dismissed.
fn last_block(directory: &Path, now: u64) -> Option<LastBlock> {
    let (newest, id) = newest_report(directory, now)?;
    let text = fs::read_to_string(directory.join(format!("{newest}.txt"))).unwrap_or_default();
    let title = text.lines().next().unwrap_or_default().to_string();
    let age_secs = now.saturating_sub(id.0);
    Some(LastBlock {
        unseen: age_secs < RECENT_SECS && seen(directory, id, now) != Some(id),
        report: directory
            .join(format!("{newest}.html"))
            .display()
            .to_string(),
        id: newest,
        title,
        age_secs,
    })
}

/// The newest report: its name and its id (`<seconds>-<pid>`, compared as
/// numbers). One dated after `now` is not a report Guardian saved: left
/// in, it would be "the newest" for ever and hide every real one.
fn newest_report(directory: &Path, now: u64) -> Option<(String, (u64, u64))> {
    report_ids(directory)
        .into_iter()
        .filter(|(_, id)| id.0 <= now)
        .max_by_key(|(_, id)| *id)
}

/// Every saved report: its name and id. Only names of the shape Guardian
/// writes count; any other `.html` file in the directory is not a report.
fn report_ids(directory: &Path) -> Vec<(String, (u64, u64))> {
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_str()?.strip_suffix(".html")?;
            Some((name.to_string(), notify::report_id(name)?))
        })
        .collect()
}

/// The report id the user last dismissed, when `.seen` holds one that can
/// be true: a report id no newer than the `newest` report or the clock. A
/// file that says more has been seen than was ever saved is not believed,
/// and nothing counts as seen.
fn seen(directory: &Path, newest: (u64, u64), now: u64) -> Option<(u64, u64)> {
    let text = fs::read_to_string(directory.join(SEEN)).ok()?;
    notify::report_id(text.trim()).filter(|seen| *seen <= newest && seen.0 <= now)
}

/// Records `id`, a report the user asked for, as seen, so it raises no
/// alert; returns whether it did. Not while another report the bar would
/// show is still waiting to be seen (one saved at the same moment by the
/// daily sweep or a gate, say): that keeps the bar's attention. Reports
/// too old for the bar to show do not count, and what is seen never moves
/// back.
pub fn mark_seen_unless_waiting(directory: &Path, id: &str, now: u64) -> bool {
    let Some(asked) = notify::report_id(id) else {
        return false;
    };
    let newest = newest_report(directory, now).map_or(asked, |(_, newest)| newest.max(asked));
    let seen = seen(directory, newest, now);
    let waiting = report_ids(directory).into_iter().any(|(_, other)| {
        other != asked
            && other.0 <= now
            && seen.is_none_or(|seen| other > seen)
            && now.saturating_sub(other.0) < RECENT_SECS
    });
    if waiting {
        return false;
    }
    if seen.is_none_or(|seen| seen < asked) {
        drop(fs::write(directory.join(SEEN), id));
    }
    true
}

/// Marks every report so far as seen and every gate that dropped as
/// known, and refreshes the Waybar module.
pub fn dismiss() -> Result<(), String> {
    gatewatch::dismiss();
    let directory = notify::reports_dir().ok_or("no reports directory (set HOME)")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    if let Some((newest, _)) = newest_report(&directory, now) {
        fs::write(directory.join(SEEN), newest).map_err(|error| error.to_string())?;
    }
    refresh_waybar();
    Ok(())
}

/// Opens the last block's report in the browser and marks it seen.
pub fn open_report() -> Result<(), String> {
    let directory = notify::reports_dir().ok_or("no reports directory (set HOME)")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let (newest, _) = newest_report(&directory, now).ok_or("no block reports yet")?;
    let page = directory.join(format!("{newest}.html"));
    Command::new("omarchy-launch-browser")
        .arg(format!("file://{}", page.display()))
        .spawn()
        .map_err(|error| format!("could not open the browser: {error}"))?;
    dismiss()
}

/// Asks a running Waybar to re-run the module now.
pub fn refresh_waybar() {
    drop(
        Command::new("pkill")
            .arg(format!("-RTMIN+{WAYBAR_SIGNAL}"))
            .arg("-x")
            .arg("waybar")
            .status(),
    );
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{RECENT_SECS, SEEN, age, last_block, mark_seen_unless_waiting, markup_safe};
    use crate::test_support::TempDir;

    #[test]
    fn what_root_saw_standing_in_for_the_sweeps_units_is_a_problem_of_the_bars() {
        use super::{overrides_issue, reported_overrides};
        use crate::autorun::Category;
        use crate::rules::RuleId;
        use crate::sweep::collect::{Body, Item, Origin};
        use crate::sweep::root::RootPart;
        use crate::sweep::tier::Tier;

        let item = |path: &str, rule: Option<RuleId>| Item {
            file: None,
            origin: Origin::Root,
            category: Category::Systemd,
            path: path.into(),
            tier: Tier::Unknown,
            sha256: None,
            body: Body::Link("/dev/null".into()),
            runs: Vec::new(),
            run_by: None,
            notes: Vec::new(),
            alerts: rule
                .map(|rule| (rule, "seen".to_string()))
                .into_iter()
                .collect(),
        };
        let part = RootPart {
            items: vec![
                item("etc/systemd/system/other.service", None),
                item(
                    "etc/systemd/user/omarchy-guardian-sweep.timer",
                    Some(RuleId::GuardianOverride),
                ),
                item(
                    "home/u/.config/systemd/user/omarchy-guardian-sweep.service.d/x.conf",
                    Some(RuleId::GuardianOverride),
                ),
                item("etc/ld.so.preload", Some(RuleId::ModifiedPackageFile)),
            ],
            ..RootPart::default()
        };
        // The one the bar found itself is named beside the sweep's gate.
        let known =
            ["home/u/.config/systemd/user/omarchy-guardian-sweep.service.d/x.conf".to_string()];
        let found = reported_overrides(&part, &known);
        assert_eq!(found, ["/etc/systemd/user/omarchy-guardian-sweep.timer"]);
        let issue = overrides_issue(&found).unwrap();
        assert!(
            issue.starts_with(
                "the root checks found /etc/systemd/user/omarchy-guardian-sweep.timer standing in"
            ),
            "{issue}"
        );
        assert_eq!(reported_overrides(&part, &[]).len(), 2);
        assert!(
            overrides_issue(&reported_overrides(&part, &[]))
                .unwrap()
                .contains(" and 1 more ")
        );
        assert_eq!(overrides_issue(&[]), None);
    }

    #[test]
    fn a_requested_report_is_seen_unless_an_alert_is_waiting() {
        let dir = TempDir::new("status-seen");
        let now = 1_000_000;
        let seen = || fs::read_to_string(dir.path().join(SEEN)).unwrap_or_default();
        let save = |id: &str| fs::write(dir.path().join(format!("{id}.html")), "").unwrap();

        // Nothing waiting: the requested report is seen.
        save("999000-1");
        assert!(mark_seen_unless_waiting(dir.path(), "999000-1", now));
        assert_eq!(seen(), "999000-1");

        // A recent alert nobody has seen keeps the bar's attention.
        save("999100-7");
        save("999200-1");
        assert!(!mark_seen_unless_waiting(dir.path(), "999200-1", now));
        assert_eq!(seen(), "999000-1");

        // One too old for the bar to show does not hold it back.
        let dir = TempDir::new("status-seen-old");
        fs::write(dir.path().join("1-1.html"), "").unwrap();
        fs::write(dir.path().join("999200-1.html"), "").unwrap();
        assert!(mark_seen_unless_waiting(
            dir.path(),
            "999200-1",
            1 + RECENT_SECS
        ));
        assert_eq!(
            fs::read_to_string(dir.path().join(SEEN)).unwrap(),
            "999200-1"
        );

        // What is seen never moves back.
        fs::write(dir.path().join("999300-1.html"), "").unwrap();
        fs::write(dir.path().join(SEEN), "999300-1").unwrap();
        assert!(mark_seen_unless_waiting(dir.path(), "999250-1", now));
        assert_eq!(
            fs::read_to_string(dir.path().join(SEEN)).unwrap(),
            "999300-1"
        );
    }

    #[test]
    fn a_recent_block_needs_attention_until_dismissed() {
        let dir = TempDir::new("status");
        assert!(last_block(dir.path(), 1_000_000).is_none());

        for id in ["999000-7", "999500-8"] {
            fs::write(dir.path().join(format!("{id}.html")), "page").unwrap();
        }
        fs::write(
            dir.path().join("999500-8.txt"),
            "Guardian blocked the AUR build of x: the recipe: risk\n\nreport",
        )
        .unwrap();

        let block = last_block(dir.path(), 1_000_000).unwrap();
        assert_eq!(block.id, "999500-8");
        assert_eq!(block.age_secs, 500);
        assert!(block.unseen);
        assert!(
            block
                .title
                .starts_with("Guardian blocked the AUR build of x")
        );

        fs::write(dir.path().join(SEEN), "999500-8").unwrap();
        assert!(!last_block(dir.path(), 1_000_000).unwrap().unseen);

        fs::write(dir.path().join(SEEN), "").unwrap();
        assert!(
            !last_block(dir.path(), 999_500 + RECENT_SECS)
                .unwrap()
                .unseen
        );
    }

    #[test]
    fn a_seen_mark_or_a_file_name_cannot_hide_a_block() {
        let now = 1_000_000;
        let dir = TempDir::new("status-seen-forged");
        fs::write(dir.path().join("999500-8.html"), "page").unwrap();
        let unseen = || last_block(dir.path(), now).unwrap().unseen;
        assert!(unseen());

        // A mark ahead of every report, or of the clock, is not believed;
        // one that is no report id is no mark.
        for forged in [
            "9999999999-9",
            "999500-9",
            "999501-1",
            "zzz",
            "999500-8x",
            "-",
            "",
        ] {
            fs::write(dir.path().join(SEEN), forged).unwrap();
            assert!(unseen(), "{forged}");
        }
        fs::write(dir.path().join(SEEN), "999500-8\n").unwrap();
        assert!(!unseen());

        // Names Guardian never writes are not reports, and neither is one
        // dated after now: none of them is "the newest".
        for planted in [
            "zzz.html",
            "9999999999-9.html",
            "999600-x.html",
            "-.html",
            ".html",
        ] {
            fs::write(dir.path().join(planted), "").unwrap();
        }
        assert_eq!(last_block(dir.path(), now).unwrap().id, "999500-8");
        // Ids compare as numbers, not as text.
        fs::write(dir.path().join("999999-10.html"), "").unwrap();
        fs::write(dir.path().join("999999-9.html"), "").unwrap();
        fs::write(dir.path().join("99-99999999.html"), "").unwrap();
        let block = last_block(dir.path(), now).unwrap();
        assert_eq!(block.id, "999999-10");
        assert!(block.unseen);
        // Asking for a planted name marks nothing seen.
        assert!(!mark_seen_unless_waiting(dir.path(), "zzz", now));
    }

    #[test]
    fn a_sweep_that_stopped_or_could_not_finish_is_an_issue() {
        use super::{GRACE_SECS, STALE_SECS, sweep_health};
        use crate::sweep::state::{LastRun, Outcome};
        let now = 10_000_000;
        let up = GRACE_SECS;
        let ran = |ago: u64, outcome, reasons: &[&str]| {
            LastRun::new(
                now - ago,
                outcome,
                reasons.iter().map(|reason| (*reason).to_string()).collect(),
            )
        };
        let fresh = ran(3600, Outcome::Complete, &[]);
        assert!(sweep_health(now, up, Some(&fresh), None, None).is_empty());

        // Stopped: only once the timers have had their time after boot.
        let old = ran(STALE_SECS + 86_400, Outcome::Complete, &[]);
        assert_eq!(
            sweep_health(now, up, Some(&old), None, None),
            ["the daily system sweep has not run for 4 days"]
        );
        assert!(sweep_health(now, up - 1, Some(&old), None, None).is_empty());
        assert_eq!(
            sweep_health(now, up, None, None, None),
            ["the daily system sweep has not run yet"]
        );
        assert!(sweep_health(now, 0, None, None, None).is_empty());

        // Could not finish, or run: said for as long as it lasts.
        let unfinished = ran(60, Outcome::Incomplete, &["the AI review is unavailable"]);
        assert_eq!(
            sweep_health(now, 0, Some(&unfinished), None, None),
            ["the last system sweep could not finish: the AI review is unavailable"]
        );
        let failed = ran(60, Outcome::Failed, &["cannot read the package database"]);
        assert_eq!(
            sweep_health(now, 0, Some(&failed), None, None),
            ["the last system sweep could not run: cannot read the package database"]
        );

        // Started and never ended: said once its unit would have stopped it.
        assert!(sweep_health(now, up, Some(&fresh), Some(now - 600), None).is_empty());
        assert_eq!(
            sweep_health(now, up, Some(&fresh), Some(now - 3 * 3600), None),
            ["a scheduled system sweep started 3 h ago and never ended"]
        );

        // Root's daily results, when they are on and not usable.
        let problem = Some("their results are more than 36 hours old");
        assert_eq!(
            sweep_health(now, up, Some(&fresh), None, problem),
            ["the daily root checks: their results are more than 36 hours old"]
        );
        assert!(sweep_health(now, 0, Some(&fresh), None, problem).is_empty());
    }

    #[test]
    fn a_gate_reviewing_without_ai_says_so_unless_that_is_the_level() {
        use super::local_only;
        use crate::config::Settings;
        use crate::config::file::PartialConfig;
        use crate::config::model::{AiRequirement, Profile, SourceClass};
        use crate::integrations::Integration;
        let defaults = Settings::from_parts(PartialConfig::default(), PartialConfig::default());
        for gate in [
            Integration::PacmanHook,
            Integration::AurGate,
            Integration::ThemeInterceptor,
            Integration::SystemSweep,
        ] {
            assert_eq!(local_only(&defaults, gate), None, "{gate:?}");
        }
        let mut user = PartialConfig::default();
        user.class_mut(SourceClass::Theme).ai = Some(AiRequirement::Off);
        let settings = Settings::from_parts(PartialConfig::default(), user);
        assert_eq!(
            local_only(&settings, Integration::ThemeInterceptor).as_deref(),
            Some("local checks only: AI review is off for themes")
        );
        assert_eq!(local_only(&settings, Integration::AurGate), None);
        // A class that only warns where its level blocks says so.
        let mut user = PartialConfig::default();
        user.class_mut(SourceClass::Aur).on_findings = Some(crate::config::model::Action::Warn);
        let settings = Settings::from_parts(PartialConfig::default(), user);
        assert_eq!(
            local_only(&settings, Integration::AurGate).as_deref(),
            Some("findings only warn, and do not block, for AUR builds")
        );
        // The level as a whole already says "no AI".
        let private = Settings::from_parts(PartialConfig::default(), PartialConfig::default())
            .with_profile(Profile::LocalOnly);
        assert_eq!(local_only(&private, Integration::AurGate), None);
    }

    #[test]
    fn the_status_is_json_with_nothing_hidden_in_it() {
        let text = super::json();
        assert!(crate::json::Json::parse(&text).is_ok(), "{text}");
        assert!(!text.chars().any(crate::text::is_hidden), "{text}");
        // Hidden characters become escapes that parse back to themselves.
        let title = "a\u{202e}b\u{e0041}\u{85}";
        let rendered = crate::json::Json::from(title).to_string();
        let escaped = super::escape_hidden(&rendered);
        assert!(!escaped.chars().any(crate::text::is_hidden), "{escaped}");
        assert_eq!(
            crate::json::Json::parse(&escaped).unwrap().as_str(),
            Some(title)
        );
    }

    #[test]
    fn what_goes_into_a_tooltip_is_text_on_one_line() {
        assert_eq!(
            markup_safe("<b>Last</b> <script> & x\ny\u{1}z"),
            "&lt;b&gt;Last&lt;/b&gt; &lt;script&gt; &amp; x y z"
        );
        assert_eq!(age(30), "just now");
        assert_eq!(age(7200), "2 h ago");
    }
}
