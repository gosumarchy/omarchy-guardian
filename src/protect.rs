//! `omarchy-guardian protect` and `omarchy-guardian test`: turning the gates
//! on and off from the command line, carrying out an integration's plan, and
//! the reviewer test. The settings app runs the same plans and the same test.

use std::fs::OpenOptions;
use std::process::{Command, Stdio};

use crate::cli::Confirm;
use crate::config::Settings;
use crate::config::model::{AgentSettings, RootConsent, SourceClass};
use crate::integrations::{Integration, Paths, Plan, State, Step};
use crate::pacman;
use crate::setup::{self, Environment as _};
use crate::status;

/// The integration paths, knowing whether the pacman gate lacks the
/// root-owned OpenCode its settings require.
pub(crate) fn paths(settings: &Settings) -> Option<Paths> {
    let opencode_missing = !pacman::classes_requiring_ai(settings).is_empty()
        && !pacman::system_reviewer_ready(settings)
        && pacman::system_reviewer_is_opencode(settings);
    Paths::real(opencode_missing, settings.sweep_root())
}

/// Runs a plan's steps in order; a failed command stops it.
pub(crate) fn run_plan(paths: &Paths, plan: &Plan) -> Result<String, String> {
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
            // A failed root setup (a cancelled sudo prompt) must not stop
            // the rest of the plan, the daily sweep included.
            Step::AskSweepRoot => match ask_sweep_root() {
                Ok(message) => outln!("{message}"),
                Err(reason) => outln!(
                    "Root checks not set up ({reason}); run `omarchy-guardian protect` again to retry."
                ),
            },
            Step::RemoveInterceptor
            | Step::AddMenuEntry
            | Step::RemoveMenuEntry
            | Step::AddThemeMenu
            | Step::RemoveThemeMenu
            | Step::InstallBarWidget
            | Step::RemoveBarWidget
            | Step::AddWaybarModule
            | Step::RemoveWaybarModule
            | Step::AddSessionPath
            | Step::RemoveSessionPath => {
                paths.edit(step)?;
            }
        }
    }
    Ok(format!("{}: done.", plan.summary))
}

/// What the root checks are, asked once on the terminal; the answer goes to
/// the system configuration, and a yes enables their daily timer. Without a
/// terminal nothing is recorded, so a non-interactive run is never a no.
fn ask_sweep_root() -> Result<String, String> {
    if OpenOptions::new().read(true).open("/dev/tty").is_err() {
        return Ok(
            "Root checks not set up: run `omarchy-guardian protect` in a terminal to answer."
                .into(),
        );
    }
    outln!(
        "\nThe system sweep needs root to check what your user can't read: the sudoers\n\
file and its drop-ins, polkit rules, root's crontab, shell files and SSH keys,\n\
and programs only root can read. It only reads them: of /etc/shadow only\n\
whether an account has a password that works (never a hash), and never a\n\
private key. It runs nothing it finds and reports only what no package vouches\n\
for. Its daily results are kept readable by your group only."
    );
    let allowed =
        crate::cli::TtyConfirm.confirm("Allow Guardian to run the read-only root checks daily?");
    let consent = if allowed {
        RootConsent::Allowed
    } else {
        RootConsent::Declined
    };
    let group = crate::sweep::root::primary_group();
    setup::set_sweep_root(consent, group.clone())?;
    if !allowed {
        return Ok("Root checks declined; sweeps will say what they could not check.".into());
    }
    if group.is_none() {
        return Ok("Root checks allowed with `omarchy-guardian sweep --root`. Your primary group is shared with other accounts, so the daily root results would be readable by them; the daily root timer stays off.".into());
    }
    let status = Command::new("/usr/bin/sudo")
        .args([
            "/usr/bin/systemctl",
            "enable",
            "--now",
            "omarchy-guardian-sweep-collect.timer",
        ])
        .status()
        .map_err(|error| error.to_string())?;
    if status.success() {
        Ok("Root checks allowed; they run daily.".into())
    } else {
        Err(format!(
            "enabling the root checks' timer exited with {status}"
        ))
    }
}

/// The gates that protect installs, plus the menu entry and the bar widgets:
/// what `omarchy-guardian protect` and the installer turn on.
const PROTECT: [Integration; 8] = [
    Integration::PacmanHook,
    Integration::AurGate,
    Integration::ThemeInterceptor,
    Integration::SessionPath,
    Integration::MenuEntry,
    Integration::BarWidget,
    Integration::WaybarModule,
    Integration::SystemSweep,
];

/// `omarchy-guardian protect`: turns on every gate that is off, after
/// showing each step and, unless `yes`, asking. The pacman hook is left off
/// when the pacman gate could not review with the current settings, since it
/// would refuse every such install.
pub fn protect(yes: bool, confirm: &mut dyn Confirm) -> Result<String, String> {
    status::watched();
    let settings = Settings::load();
    let paths = paths(&settings).ok_or("HOME is not set")?;
    let mut steps = Vec::new();
    let mut notes = Vec::new();
    for integration in PROTECT {
        let state = paths.state(integration);
        match &state {
            State::On => notes.push(format!("✓ {} is on", integration.label())),
            State::Unavailable(reason) => {
                notes.push(format!("- {}: {reason}", integration.label()));
            }
            _ => {
                if integration == Integration::PacmanHook
                    && !paths.opencode_missing
                    && let Err(reason) =
                        pacman::preflight(&settings, pacman::system_reviewer_ready(&settings))
                {
                    notes.push(format!("✗ {} left off: {reason}", integration.label()));
                    continue;
                }
                if let Some(plan) = paths.plan(integration, &state) {
                    steps.extend(plan.steps);
                }
            }
        }
    }
    // Root consent is a question, never assumed: `--yes` leaves it unasked.
    if yes && steps.contains(&Step::AskSweepRoot) {
        steps.retain(|step| *step != Step::AskSweepRoot);
        notes.push(
            "- System sweep root checks: not answered (`--yes` never allows them); run `omarchy-guardian protect` to answer"
                .into(),
        );
    }
    for note in &notes {
        outln!("{note}");
    }
    if steps.is_empty() {
        return Ok("Nothing to turn on.".into());
    }
    let plan = Plan {
        summary: "Protect everything".into(),
        steps,
    };
    outln!("\nTo turn the rest on, Guardian will:");
    for line in plan.describe(&paths) {
        outln!("  {line}");
    }
    if !yes && !confirm.confirm("Go ahead?") {
        return Err("nothing was changed".into());
    }
    let outcome = run_plan(&paths, &plan);
    status::chosen();
    outcome
}

/// `omarchy-guardian protect --off`: turns the three install gates and the
/// system sweep off (the menu entry and the bar widget stay), after showing
/// each step and, unless `yes`, asking. A hand-installed pacman hook is left
/// alone.
pub fn unprotect(yes: bool, confirm: &mut dyn Confirm) -> Result<String, String> {
    status::watched();
    let settings = Settings::load();
    let paths = paths(&settings).ok_or("HOME is not set")?;
    let mut steps = Vec::new();
    for integration in [
        Integration::PacmanHook,
        Integration::AurGate,
        Integration::ThemeInterceptor,
        Integration::SessionPath,
        Integration::SystemSweep,
    ] {
        match paths.state(integration) {
            State::On | State::Partial(_) => {
                if let Some(plan) = paths.plan(integration, &State::On) {
                    steps.extend(plan.steps);
                }
            }
            State::Foreign(detail) => outln!("- {} left as is: {detail}", integration.label()),
            State::Off | State::Unavailable(_) => {}
        }
    }
    if steps.is_empty() {
        return Ok("Protection is already off.".into());
    }
    let plan = Plan {
        summary: "Protection off".into(),
        steps,
    };
    outln!("To turn protection off, Guardian will:");
    for line in plan.describe(&paths) {
        outln!("  {line}");
    }
    outln!("Until you turn it back on, installs are not reviewed.");
    if !yes && !confirm.confirm("Turn protection off?") {
        return Err("nothing was changed".into());
    }
    let outcome = run_plan(&paths, &plan);
    status::chosen();
    outcome
}

/// `omarchy-guardian test`: the settings app's reviewer test; false when a
/// check failed.
pub fn test() -> (String, bool) {
    let report = test_reviewer(&Settings::load());
    let passed = !report.lines().any(|line| line.starts_with('✗'));
    (report, passed)
}

/// Setup's two-sample test against the saved settings: the model for your
/// sources, then the pacman gate's when it differs, and whether the pacman
/// gate has the root-owned reviewer it needs.
pub(crate) fn test_reviewer(settings: &Settings) -> String {
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
