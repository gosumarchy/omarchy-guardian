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

use super::integrations::{Integration, State};
use super::paths;
use crate::config::Settings;
use crate::config::model::{AiRequirement, Named, Profile, RootConsent, SourceClass};
use crate::engine::store::Store;
use crate::json::Json;
use crate::notify;
use crate::pacman;
use crate::sweep::root::{RESULTS, results_problem};
use crate::sweep::state::{self, LastRun, Outcome};

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
const GATES: [Integration; 4] = [
    Integration::PacmanHook,
    Integration::AurGate,
    Integration::ThemeInterceptor,
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

    let mut gates = Vec::new();
    let mut on = 0;
    if let Some(paths) = paths(&settings) {
        for integration in GATES {
            let state = paths.state(integration);
            let (name, detail) = match &state {
                State::On => ("on", String::new()),
                State::Off => ("off", String::new()),
                State::Foreign(detail) => ("foreign", detail.clone()),
                State::Partial(detail) => ("partial", detail.clone()),
                State::Unavailable(detail) => ("unavailable", detail.clone()),
            };
            match &state {
                State::On => on += 1,
                State::Unavailable(_) => {}
                _ => issues.push(format!("{} is not fully on", integration.label())),
            }
            // On, and reviewing with the local checks alone: said beside
            // the gate, as a choice and not a fault.
            let caveats: Vec<String> = [
                local_only(&settings, integration),
                (integration == Integration::ThemeInterceptor)
                    .then(|| paths.theme_caveat())
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
    if let Some(paths) = paths(&settings) {
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
    }
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
    let off: Vec<&str> = classes
        .iter()
        .filter(|(class, _)| {
            settings.profile_for(*class) != Profile::LocalOnly
                && settings.policy(*class).ai == AiRequirement::Off
        })
        .map(|(_, name)| *name)
        .collect();
    (!off.is_empty()).then(|| {
        format!(
            "local checks only: AI review is off for {}",
            off.join(" and ")
        )
    })
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
    Json::object([
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
    .to_string()
}

/// The Waybar image module's output: the knight for the state (calm,
/// red-eyed, or dimmed when protection is off), then a tooltip with the
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
    let mut tooltip = format!("<b>Guardian</b> · {headline}\n{level} · {}\n", status.model);
    for gate in &status.gates {
        let mark = if gate.state == "on" { "●" } else { "○" };
        let _ = write!(
            tooltip,
            "\n{mark} {}  {}",
            gate.label,
            gate.state.to_uppercase()
        );
        if !gate.detail.is_empty() {
            let _ = write!(tooltip, "\n    {}", gate.detail);
        }
    }
    if !status.issues.is_empty() {
        tooltip.push_str("\n\n<b>Needs fixing</b>");
        for issue in &status.issues {
            let _ = write!(tooltip, "\n! {issue}");
        }
    }
    if let Some(block) = &status.block {
        let _ = write!(
            tooltip,
            "\n\n<b>Last block</b> · {}\n{}",
            age(block.age_secs),
            block.title
        );
    }
    tooltip.push_str("\n\nLeft-click: settings · right-click: last report");
    format!(
        "/usr/share/icons/hicolor/scalable/apps/{icon}.svg\n{}",
        markup_safe(&tooltip)
    )
}

/// Escapes text for Pango markup, keeping Guardian's own `<b>` tags.
fn markup_safe(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace("&lt;b&gt;", "<b>")
        .replace("&lt;/b&gt;", "</b>")
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
    let newest = newest_report(directory)?;
    let seconds: u64 = newest.split_once('-')?.0.parse().ok()?;
    let text = fs::read_to_string(directory.join(format!("{newest}.txt"))).unwrap_or_default();
    let title = text.lines().next().unwrap_or_default().to_string();
    let seen = fs::read_to_string(directory.join(SEEN)).unwrap_or_default();
    let age_secs = now.saturating_sub(seconds);
    Some(LastBlock {
        unseen: age_secs < RECENT_SECS && seen.trim() < newest.as_str(),
        report: directory
            .join(format!("{newest}.html"))
            .display()
            .to_string(),
        id: newest,
        title,
        age_secs,
    })
}

/// The newest report id (`<seconds>-<pid>`); ids sort by time.
fn newest_report(directory: &Path) -> Option<String> {
    report_ids(directory).into_iter().max()
}

/// Every saved report's id.
fn report_ids(directory: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            entry
                .file_name()
                .to_str()?
                .strip_suffix(".html")
                .map(str::to_string)
        })
        .collect()
}

/// Records `id`, a report the user asked for, as seen, so it raises no
/// alert; returns whether it did. Not while another report the bar would
/// show is still waiting to be seen (one saved at the same moment by the
/// daily sweep or a gate, say): that keeps the bar's attention. Reports
/// too old for the bar to show do not count, and what is seen never moves
/// back.
pub fn mark_seen_unless_waiting(directory: &Path, id: &str, now: u64) -> bool {
    let seen = fs::read_to_string(directory.join(SEEN)).unwrap_or_default();
    let seen = seen.trim();
    let waiting = report_ids(directory).into_iter().any(|other| {
        other != id
            && other.as_str() > seen
            && other
                .split_once('-')
                .and_then(|(seconds, _)| seconds.parse::<u64>().ok())
                .is_some_and(|seconds| now.saturating_sub(seconds) < RECENT_SECS)
    });
    if waiting {
        return false;
    }
    if seen < id {
        drop(fs::write(directory.join(SEEN), id));
    }
    true
}

/// Marks every report so far as seen, and refreshes the Waybar module.
pub fn dismiss() -> Result<(), String> {
    let directory = notify::reports_dir().ok_or("no reports directory (set HOME)")?;
    let Some(newest) = newest_report(&directory) else {
        return Ok(());
    };
    fs::write(directory.join(SEEN), newest).map_err(|error| error.to_string())?;
    refresh_waybar();
    Ok(())
}

/// Opens the last block's report in the browser and marks it seen.
pub fn open_report() -> Result<(), String> {
    let directory = notify::reports_dir().ok_or("no reports directory (set HOME)")?;
    let newest = newest_report(&directory).ok_or("no block reports yet")?;
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
        use crate::tui::integrations::Integration;
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
        // The level as a whole already says "no AI".
        let private = Settings::from_parts(PartialConfig::default(), PartialConfig::default())
            .with_profile(Profile::LocalOnly);
        assert_eq!(local_only(&private, Integration::AurGate), None);
    }

    #[test]
    fn tooltips_escape_everything_but_guardian_bold() {
        assert_eq!(
            markup_safe("<b>Last</b> <script> & x"),
            "<b>Last</b> &lt;script&gt; &amp; x"
        );
        assert_eq!(age(30), "just now");
        assert_eq!(age(7200), "2 h ago");
    }
}
