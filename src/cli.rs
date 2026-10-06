//! Command-line parsing and the top-level commands.

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use crate::ask;
use crate::audit::{self, Gate};
use crate::config::Settings;
use crate::config::model::{Named, SourceClass};
use crate::config::show;
use crate::config::weaker;
use crate::engine::baseline;
use crate::engine::store::Store;
use crate::error::Error;
use crate::makepkg_gate;
use crate::notify;
use crate::pacman::{self, HookArgs};
use crate::permit::{self, Content};
use crate::protect;
use crate::report::Decision;
use crate::setup;
use crate::status;
use crate::sweep;
use crate::tools::OpenCode;
use crate::tui;

mod gate;
mod parse;

pub use gate::{Confirm, TtyConfirm};
pub(crate) use gate::{Target, Verdict, passed, review_and_decide};
use gate::{exec_command, guard_command, sandbox_command};
use parse::{ConfigCommand, Forget, Invocation, StatusMode, USAGE, parse};

const USAGE_ERROR: u8 = 2;

pub fn run(args: impl Iterator<Item = OsString>) -> ExitCode {
    let args: Vec<OsString> = args.collect();
    let invocation = match parse(&args) {
        Ok(invocation) => invocation,
        Err(message) => {
            errln!("omarchy-guardian: {message}\n\n{USAGE}");
            return ExitCode::from(USAGE_ERROR);
        }
    };

    // Root's halves are given everything they act on as arguments: they
    // run before any settings file of the user's is read.
    let invocation = match invocation {
        Invocation::PermitSystem(arguments) => return permit::system_command(&arguments),
        Invocation::HookResult(arguments) => return permit::hook_result_command(&arguments),
        other => other,
    };

    let settings = Settings::load();
    for warning in settings.warnings() {
        errln!("omarchy-guardian: {warning}");
    }
    // A user file that does not parse is not reviewed around: its settings
    // (a stricter level, say) would be gone without a word.
    if reviews_for_the_user(&invocation) && settings.user_block().is_some() {
        errln!("omarchy-guardian: nothing was reviewed or run: the user settings file is invalid.");
        return ExitCode::from(2);
    }

    match invocation {
        Invocation::Scan(target) => scan_command(&with_state_root(target), &settings),
        Invocation::Guard(target, command) => guard_command(
            &with_state_root(target),
            &command,
            &settings,
            &OpenCode::UserPath,
            &mut TtyConfirm,
            &mut exec_command,
        ),
        Invocation::Sandbox(target, command) => sandbox_command(
            &with_state_root(target),
            &command,
            &settings,
            &mut TtyConfirm,
        ),
        Invocation::PacmanHook(hook) => pacman_hook_command(
            &hook,
            &settings,
            std::env::var_os(permit::ROOT_HOOK).is_some(),
        ),
        Invocation::Permit(command) => permit::command(&command, &settings),
        Invocation::PermitSystem(arguments) => permit::system_command(&arguments),
        Invocation::HookResult(arguments) => permit::hook_result_command(&arguments),
        Invocation::Log(options) => audit::log::command(&options),
        Invocation::MakepkgGate(command) => makepkg_gate::run(&command, &settings),
        Invocation::HookPreflight => preflight_command(&settings),
        Invocation::Config(command) => config_command(&command, &settings),
        Invocation::Forget(forget) => forget_command(&forget, Store::default_root()),
        Invocation::Setup => match setup::run(&mut setup::TtyTerminal, &setup::RealEnvironment) {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                errln!("omarchy-guardian setup: {message}");
                ExitCode::from(2)
            }
        },
        Invocation::Protect { yes, off } => protect_command(yes, off),
        Invocation::Test => {
            outln!("Testing the reviewer with a malicious and a harmless sample...");
            let (report, passed) = protect::test();
            outln!("{report}");
            if passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Invocation::Sweep(command) => sweep::command(&command, &settings),
        Invocation::SweepCollect { out } => sweep::root::collect_command(out, &settings),
        Invocation::SweepAllowSystem(arguments) => sweep::root::system_allow_command(&arguments),
        Invocation::Status(mode) => status_command(mode),
        Invocation::Update => crate::update::command(),
        Invocation::Ask(target) => {
            errln!("omarchy-guardian ask: {}", ask::run(&target, &settings));
            ExitCode::from(2)
        }
        Invocation::Tui { expert } => match tui::run(expert) {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                errln!("omarchy-guardian tui: {message}");
                ExitCode::from(2)
            }
        },
    }
}

/// `pacman-hook --preflight`: whether the pacman gate could review.
fn preflight_command(settings: &Settings) -> ExitCode {
    match pacman::preflight(settings, pacman::system_reviewer_ready(settings)) {
        Ok(()) => {
            outln!("The pacman gate can review transactions with these settings.");
            ExitCode::SUCCESS
        }
        Err(reason) => {
            errln!("omarchy-guardian: {reason}");
            ExitCode::from(2)
        }
    }
}

/// `protect [--off]`: every gate on, or the install gates off; what came of
/// it goes into the audit trail.
fn protect_command(yes: bool, off: bool) -> ExitCode {
    let outcome = if off {
        protect::unprotect(yes, &mut TtyConfirm)
    } else {
        protect::protect(yes, &mut TtyConfirm)
    };
    match outcome {
        Ok(message) => {
            audit::gate_changed(if off { "protect --off" } else { "protect" }, "", &message);
            outln!("{message}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            errln!("omarchy-guardian protect: {message}");
            ExitCode::from(2)
        }
    }
}

/// Whether `invocation` reviews with the user file's settings: the gates
/// and reviews that are not the pacman hook's. Settings commands are not, so
/// a broken file can still be shown and fixed.
const fn reviews_for_the_user(invocation: &Invocation) -> bool {
    matches!(
        invocation,
        Invocation::Scan(_)
            | Invocation::Guard(..)
            | Invocation::Sandbox(..)
            | Invocation::MakepkgGate(_)
            | Invocation::Sweep(sweep::Command::Run(_))
    )
}

/// A one-run profile override (`--profile`) applies on top of the loaded
/// settings; without it the loaded settings are used unchanged.
fn settings_for(target: &Target, settings: &Settings) -> Settings {
    match target.profile {
        Some(profile) => settings.clone().with_profile(profile),
        None => settings.clone(),
    }
}

/// Commands review with the user's review memory.
fn with_state_root(mut target: Target) -> Target {
    target.state_root = Store::default_root();
    target
}

fn scan_command(target: &Target, settings: &Settings) -> ExitCode {
    let settings = settings_for(target, settings);
    review_and_decide(
        target,
        &settings,
        &OpenCode::UserPath,
        None,
        &[],
        Gate::Scan,
        None,
    )
    .decision
    .exit_code()
}

fn status_command(mode: StatusMode) -> ExitCode {
    let result = match mode {
        // Written as it is: the terminal-safe output would rewrite a
        // hidden character inside a string into something that is no JSON.
        StatusMode::Shell => {
            writeln!(io::stdout(), "{}", status::json()).map_err(|error| error.to_string())
        }
        StatusMode::Waybar => {
            outln!("{}", status::waybar());
            Ok(())
        }
        StatusMode::Dismiss => status::dismiss(),
        StatusMode::OpenReport => status::open_report(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            errln!("omarchy-guardian status: {message}");
            ExitCode::from(2)
        }
    }
}

/// The pacman gate. `root_hook` says the hook script's root half started
/// this review and takes a used permit away: it is told by the exit code
/// (see `permit::PERMITTED_EXIT`), which the script turns into 0.
fn pacman_hook_command(hook: &HookArgs, settings: &Settings, root_hook: bool) -> ExitCode {
    // A reviewer from PATH is for the end-to-end tests, whose pacman is a
    // script of the user's. In front of a real transaction (pacman runs as
    // root) it is refused, however it came to be asked for.
    if hook.opencode == OpenCode::UserPath
        && process_owner(hook.pacman_pid).is_none_or(|owner| owner == 0)
    {
        errln!(
            "Guardian blocked the pacman transaction: --opencode-from-path is for tests and is refused for a pacman run by root."
        );
        audit::refused(Gate::Pacman, "a reviewer from PATH was asked for", 2);
        return ExitCode::from(2);
    }
    match pacman::review_transaction(hook, settings) {
        Ok(mut report) => {
            let decision = report.decide(&|class| settings.policy(class));
            let contents: Vec<Content> = pacman::reviewed_content(&report).into_iter().collect();
            let standing = permit::standing(
                &contents,
                &report,
                decision,
                settings,
                Store::default_root().as_deref(),
            );
            report.permit = standing.permitted().map(str::to_string);
            report.print(false, decision);
            let exit = match (standing.permitted(), root_hook) {
                (Some(_), true) => permit::PERMITTED_EXIT,
                (Some(_), false) => 0,
                (None, _) => decision.exit_status(),
            };
            audit::review(
                &audit::Reviewed {
                    gate: Gate::Pacman,
                    class: &pacman::reviewed_classes(&report),
                    subject: &pacman::reviewed_names(&report),
                    digest: &pacman::reviewed_digests(&report),
                    decision,
                    permit: standing.permitted(),
                    offered: standing.offered(),
                    // What pacman is told: a permitted transaction goes on.
                    exit: if standing.permitted().is_some() {
                        0
                    } else {
                        exit
                    },
                },
                &report,
            )
            .record();
            if let Some(permit) = standing.permitted() {
                errln!(
                    "Guardian: your permit {permit} overrules {}; the transaction goes on.",
                    report.decision_name(decision)
                );
            } else if let Decision::Blocked(blocked) = decision {
                standing.say();
                notify::blocked(
                    "a pacman transaction",
                    notify::reason(blocked),
                    notify::Ran::Nothing,
                );
            }
            ExitCode::from(exit)
        }
        Err(error) => {
            errln!("Guardian blocked the pacman transaction: {error}");
            audit::refused(Gate::Pacman, &error.to_string(), 2);
            notify::blocked(
                "a pacman transaction",
                &error.to_string(),
                notify::Ran::Nothing,
            );
            ExitCode::from(2)
        }
    }
}

/// The user a process runs as, from the owner of its `/proc` entry.
fn process_owner(pid: u32) -> Option<u32> {
    std::fs::metadata(format!("/proc/{pid}"))
        .ok()
        .map(|metadata| std::os::unix::fs::MetadataExt::uid(&metadata))
}

/// `config acknowledge`: writes the weaker-than-the-level settings of the
/// user file into the system file's `[acknowledged]` list, after showing
/// them and the change, with sudo. Only root can write that file, so a
/// program running as the user cannot accept its own weakening.
fn acknowledge_command(settings: &Settings, confirm: &mut dyn Confirm) -> Result<String, String> {
    if settings.user_block().is_some() || settings.privileged_block().is_some() {
        return Err("fix the settings files first (see `omarchy-guardian config check`)".into());
    }
    let keys = weaker::to_acknowledge(settings);
    if keys == settings.acknowledged_weaker() {
        return Ok(if keys.is_empty() {
            "Nothing in your settings is weaker than the protection level.".into()
        } else {
            "Every weaker setting is already acknowledged.".into()
        });
    }
    for weakening in weaker::weakenings(settings) {
        if keys.contains(&weakening.key()) {
            outln!(
                "  {}: {} = {} (the {} level has {})",
                weaker::subject(weakening.class),
                weakening.knob,
                weakening.value,
                weakening.profile,
                weakening.level
            );
        }
    }
    let (text, existing) = setup::with_accepted(keys)?;
    outln!("\nSystem file {}:", settings.system_path().display());
    outln!("{}", setup::line_diff(&existing, &text));
    if !confirm.confirm("Accept these weaker settings and install the file with sudo?") {
        return Err("nothing was changed".into());
    }
    setup::install_accepted(&text)?;
    audit::settings_changed(&format!(
        "weaker settings acknowledged: {}",
        weaker::to_acknowledge(settings).join(", ")
    ));
    status::chosen();
    Ok("Acknowledged; the bar no longer counts them as a problem.".into())
}

fn config_command(command: &ConfigCommand, settings: &Settings) -> ExitCode {
    match command {
        ConfigCommand::Show(class) => {
            let classes: Vec<SourceClass> = match class {
                Some(class) => vec![*class],
                None => SourceClass::ALL.to_vec(),
            };
            out!("{}", show::render_show(settings, &classes));
            out!("{}", show::render_memory(Store::default_root().as_deref()));
            ExitCode::SUCCESS
        }
        ConfigCommand::Check => {
            let (text, valid) = show::render_check(settings);
            out!("{text}");
            if valid {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
        ConfigCommand::Acknowledge => match acknowledge_command(settings, &mut TtyConfirm) {
            Ok(message) => {
                outln!("{message}");
                ExitCode::SUCCESS
            }
            Err(message) => {
                errln!("omarchy-guardian config acknowledge: {message}");
                ExitCode::from(2)
            }
        },
        ConfigCommand::Path => {
            outln!("{}", settings.system_path().display());
            if let Some(path) = settings.user_path() {
                outln!("{}", path.display());
            }
            ExitCode::SUCCESS
        }
    }
}

/// Drops approved baselines (and with `--all`, every cached verdict; one
/// identity's cached verdicts are kept, since verdicts are not keyed by
/// identity), and what the AUR gate remembers: the builds it was told to
/// go on with, their binaries and what it extracted.
fn forget_command(forget: &Forget, root: Option<PathBuf>) -> ExitCode {
    let Some(root) = root else {
        errln!("omarchy-guardian: no state directory (set HOME or XDG_STATE_HOME)");
        return ExitCode::from(2);
    };
    if !root.is_dir() {
        outln!("Nothing to forget: {} does not exist.", root.display());
        return ExitCode::SUCCESS;
    }
    let store = match Store::open(root.clone()) {
        Ok(store) => store,
        Err(reason) => {
            errln!("omarchy-guardian: {reason}");
            return ExitCode::from(2);
        }
    };
    match forget_in(forget, &store) {
        Ok(message) => {
            outln!("{message}");
            let (gate, what) = match forget {
                Forget::All => (makepkg_gate::forget_all(&root), "everything".to_string()),
                Forget::One(identity) => (
                    makepkg_gate::forget(&root, identity.as_str()),
                    identity.as_str().to_string(),
                ),
            };
            match gate {
                Ok(0) => {}
                Ok(count) => outln!("Forgot {count} record(s) of the AUR gate."),
                Err(reason) => {
                    errln!("omarchy-guardian: {reason}");
                    return ExitCode::from(2);
                }
            }
            audit::forgot(&what);
            ExitCode::SUCCESS
        }
        Err(error) => {
            errln!("omarchy-guardian: {error}");
            ExitCode::from(2)
        }
    }
}

/// Forgets what `forget` names in `store`; returns the line to print.
fn forget_in(forget: &Forget, store: &Store) -> Result<String, Error> {
    match forget {
        Forget::All => baseline::forget_all(store)
            .map(|count| format!("Forgot {count} approved baseline(s) and every cached verdict.")),
        Forget::One(identity) => baseline::forget(store, identity).map(|count| {
            format!(
                "Forgot {count} approved baseline(s) for {}. Cached verdicts are kept; use forget --all to clear them too.",
                identity.as_str()
            )
        }),
    }
}

#[cfg(test)]
mod tests;
