//! `omarchy-guardian status`: what the bar widgets show. An overall state
//! (`ok`, `attention` or `off`), each gate, the protection level and model,
//! problems to fix, and the last block: as JSON for the Omarchy shell widget
//! (`status`), or for the Waybar image module (`status --waybar`).
//! `status --dismiss` marks the current blocks as seen, and
//! `status --open-report` opens the last one.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use super::integrations::{Integration, State};
use super::paths;
use crate::config::Settings;
use crate::config::model::{Named, SourceClass};
use crate::json::Json;
use crate::notify;
use crate::pacman;

/// A block younger than this needs attention until it is dismissed.
const RECENT_SECS: u64 = 24 * 60 * 60;
/// The newest report id the user has dismissed, in the reports directory.
const SEEN: &str = ".seen";
/// Waybar refreshes the module on `SIGRTMIN+WAYBAR_SIGNAL`.
pub const WAYBAR_SIGNAL: u8 = 9;

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
    fs::read_dir(directory)
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            entry
                .file_name()
                .to_str()?
                .strip_suffix(".html")
                .map(str::to_string)
        })
        .max()
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

    use super::{RECENT_SECS, SEEN, age, last_block, markup_safe};
    use crate::test_support::TempDir;

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
    fn tooltips_escape_everything_but_guardian_bold() {
        assert_eq!(
            markup_safe("<b>Last</b> <script> & x"),
            "<b>Last</b> &lt;script&gt; &amp; x"
        );
        assert_eq!(age(30), "just now");
        assert_eq!(age(7200), "2 h ago");
    }
}
