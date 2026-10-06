//! Reading the command line: the usage text, what an invocation can be, and
//! the parser of each command's arguments.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use crate::audit;
use crate::config::model::{Named, Profile, SourceClass};
use crate::engine::baseline::{Identity, Unit};
use crate::makepkg_gate;
use crate::pacman::HookArgs;
use crate::permit;
use crate::scan::ScanConfig;
use crate::sweep;
use crate::tools::OpenCode;

use super::gate::Target;

pub(super) const USAGE: &str = "\
Usage:
  omarchy-guardian scan [--thorough] [--hashes] [--exclude NAME]... [--class CLASS] [--profile PROFILE] [--identity ID | --unit DIR ID ...] <file-or-directory>
  omarchy-guardian guard [--thorough] [--hashes] [--exclude NAME]... [--class CLASS] [--profile PROFILE] [--identity ID | --unit DIR ID ...] <file-or-directory> -- <command> [args...]
  omarchy-guardian sandbox [--hashes] [--profile PROFILE] [--identity ID | --unit DIR ID ...] <directory> -- <command> [args...]
  omarchy-guardian pacman-hook --pacman-pid PID --cwd DIR   (run by the pacman hook)
  omarchy-guardian pacman-hook --preflight                  (can the pacman gate review?)
  omarchy-guardian makepkg-gate -- <makepkg> [args...]      (run by the yay makepkg shim)
  omarchy-guardian config show [--class CLASS] | check | path | acknowledge
                                                    (acknowledge: accept, with sudo, settings weaker than the level)
  omarchy-guardian forget <identity> | --all
  omarchy-guardian permit [ID | --revoke ID]        (let one blocked install through; lists them without ID)
  omarchy-guardian log [--since TIME] [-n N] [--json]
                                                    (what Guardian decided, from the system journal)
  omarchy-guardian setup
  omarchy-guardian protect [--off] [--yes]          (turn every gate on, or the install gates and the sweep off)
  omarchy-guardian test                             (test the saved reviewer with two samples)
  omarchy-guardian sweep [--all] [--json] [--root] [--diff] [--report] | allow PATH|--migrate | forget PATH|--all
                                                    (check what already runs on its own on this system)
  omarchy-guardian ask <report-id>                  (open your AI agent on a saved report)
  omarchy-guardian status [--waybar | --dismiss | --open-report]
                                                    (bar widget status; mark blocks seen; open the last report)
  omarchy-guardian update                           (is there a newer release? installs nothing)
  omarchy-guardian tui [--expert]                   (settings app; --expert shows every setting)

CLASS: aur, theme, plugin, source (default). PROFILE: standard, strict, local-only.
ID names what is reviewed for the review memory, e.g. aur:yay-bin.
forget ID drops that source's approved baselines and what the AUR gate
remembers of it; cached verdicts are kept (forget --all clears them too).
Exit codes: 0 clear, warned, limited review or permitted; 1 findings; 2
incomplete review, AI unavailable, not confirmed, invalid settings file, or
usage error. guard and sandbox replace these with the command's own exit code
once it starts.";

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Invocation {
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
    /// Run as root by `sweep allow` and `sweep forget` through sudo.
    SweepAllowSystem(Vec<String>),
    /// `permit [ID | --revoke ID]`.
    Permit(permit::Command),
    /// Run as root by `permit` through sudo.
    PermitSystem(Vec<String>),
    /// Run as root by the pacman hook script once the review has ended.
    HookResult(Vec<String>),
    /// `log [--since TIME] [-n N] [--json]`.
    Log(audit::log::Options),
    /// `ask <report-id | omarchy-guardian://ask/<id>>`, opened from a report.
    Ask(String),
    /// `status [--waybar | --dismiss | --open-report]`.
    Status(StatusMode),
    Update,
    Tui {
        expert: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StatusMode {
    /// JSON for the Omarchy shell widget.
    Shell,
    Waybar,
    Dismiss,
    OpenReport,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ConfigCommand {
    Show(Option<SourceClass>),
    Check,
    Path,
    /// Accepts the user file's weaker-than-the-level settings in the
    /// system file.
    Acknowledge,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Forget {
    All,
    One(Identity),
}

fn parse_sweep(args: &[OsString]) -> Result<sweep::Command, String> {
    const USAGE: &str = "usage: omarchy-guardian sweep [--all] [--json] [--root] [--diff] [--report] | allow PATH | allow --migrate | forget PATH | forget --all";
    let text: Vec<&str> = args
        .iter()
        .map(|arg| arg.to_str().ok_or("arguments must be UTF-8"))
        .collect::<Result<_, _>>()?;
    match text.as_slice() {
        ["allow", "--migrate"] => return Ok(sweep::Command::Migrate),
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

#[derive(Clone, Copy)]
struct Allowed {
    thorough: bool,
    exclude: bool,
    class: bool,
}

pub(super) fn parse(args: &[OsString]) -> Result<Invocation, String> {
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
        Some("permit") => permit::parse(rest).map(Invocation::Permit),
        Some("log") => audit::log::parse(rest).map(Invocation::Log),
        // Run as root by `permit` and by the pacman hook script; not listed.
        Some("permit-system") => {
            utf8_arguments("permit-system", rest).map(Invocation::PermitSystem)
        }
        Some("pacman-hook-result") => {
            utf8_arguments("pacman-hook-result", rest).map(Invocation::HookResult)
        }
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
        // Run as root by `sweep allow` and `sweep forget`; not listed.
        Some("sweep-allow-system") => {
            utf8_arguments("sweep-allow-system", rest).map(Invocation::SweepAllowSystem)
        }
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
        Some("update") if rest.is_empty() => Ok(Invocation::Update),
        Some("update") => Err("usage: omarchy-guardian update".into()),
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

/// The arguments of a command root's half runs, as text.
fn utf8_arguments(command: &str, args: &[OsString]) -> Result<Vec<String>, String> {
    args.iter()
        .map(|argument| {
            argument
                .to_str()
                .map(str::to_string)
                .ok_or_else(|| format!("{command}: arguments must be UTF-8"))
        })
        .collect()
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
        ["acknowledge"] => Ok(ConfigCommand::Acknowledge),
        _ => Err("config takes show [--class CLASS], check, path or acknowledge".into()),
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
                // `system` is the sweep's own class, not one to review a
                // directory as.
                let parsed = SourceClass::parse(name)
                    .filter(|class| !class.is_privileged() && *class != SourceClass::System)
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
