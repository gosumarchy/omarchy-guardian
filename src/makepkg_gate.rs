//! `omarchy-guardian makepkg-gate -- <makepkg> [args...]`, run by the yay
//! makepkg shim in the AUR build directory. Beyond `guard` on the recipe it:
//!
//! 1. looks the package up in the AUR and reports trust signals (new,
//!    unvoted, orphaned, recently changed by someone other than its
//!    submitter), which also go to the AI review as facts;
//! 2. reviews the recipe (PKGBUILD, install script, patches) as before;
//! 3. for a call that will run PKGBUILD functions, reads the source list
//!    (only now: `--printsrcinfo` runs the PKGBUILD, which is reviewed by
//!    then) and warns about unverified or unpinned sources, then fetches and
//!    extracts the sources without running any function, and has the AI
//!    review what runs during the build: the whole upstream when it is
//!    small, its build files and scripts otherwise;
//! 4. starts makepkg with the original arguments.

use std::env;
use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::aur::{self, AurInfo, Upstream};
use crate::cli::{Target, TtyConfirm, exec_command, review_and_decide};
use crate::config::Settings;
use crate::config::model::SourceClass;
use crate::engine::baseline::{Identity, Unit};
use crate::engine::store::Store;
use crate::error::Error;
use crate::json::Json;
use crate::osv;
use crate::pacman;
use crate::report::Decision;
use crate::review::{self, ReviewContext};
use crate::scan::{self, ScanConfig};
use crate::tools::{self, Limits, OpenCode};

const RPC_URL: &str = "https://aur.archlinux.org/rpc/v5/info?arg[]=";
const RPC_LIMITS: Limits = Limits {
    timeout_secs: 20,
    max_output: 1024 * 1024,
};
const SRCINFO_LIMITS: Limits = Limits {
    timeout_secs: 60,
    max_output: 4 * 1024 * 1024,
};

/// makepkg flags a pre-extraction mirrors from the original call, so it
/// verifies and extracts the sources the way the build will.
const MIRRORED_FLAGS: &[&str] = &[
    "--skippgpcheck",
    "--skipchecksums",
    "--skipinteg",
    "--ignorearch",
    "-A",
];

pub fn run(command: &[OsString], settings: &Settings) -> ExitCode {
    let Some((makepkg, arguments)) = command.split_first() else {
        eprintln!("omarchy-guardian makepkg-gate: no makepkg command was given");
        return ExitCode::from(2);
    };
    let build_dir = match env::current_dir().and_then(|dir| dir.canonicalize()) {
        Ok(dir) => dir,
        Err(error) => {
            eprintln!("omarchy-guardian makepkg-gate: cannot use the working directory: {error}");
            return ExitCode::from(2);
        }
    };
    if !build_dir.join("PKGBUILD").is_file() {
        eprintln!("Guardian makepkg gate requires a PKGBUILD in the working directory.");
        return ExitCode::from(2);
    }
    let name = build_dir
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default()
        .to_string();

    // 1. What the AUR says, before anything of the package runs.
    let facts = aur_facts(&name);

    // 2. The recipe.
    let identity = |text: String| Identity::parse(&text).ok();
    let target = Target {
        config: ScanConfig {
            root: build_dir.clone(),
            include_ignored_dirs: true,
            excluded_top_level: vec!["src".into(), "pkg".into()],
        },
        show_hashes: false,
        class: SourceClass::Aur,
        profile: None,
        units: identity(format!("aur:{name}"))
            .map(|identity| {
                vec![Unit {
                    prefix: String::new(),
                    identity,
                }]
            })
            .unwrap_or_default(),
        state_root: Store::default_root(),
    };
    let mut recipe_context = vec![aur::RECIPE_SCOPE.to_string()];
    recipe_context.extend(facts.iter().cloned());
    let (report, decision) = review_and_decide(
        &target,
        settings,
        &OpenCode::UserPath,
        Some(&mut TtyConfirm),
        &recipe_context,
    );
    if !decision.allows_running() {
        eprintln!("Guardian blocked makepkg because the review of the recipe did not allow it.");
        return decision.exit_code();
    }
    if let Err(error) = scan::verify_unchanged(&target.config, &report.snapshot) {
        eprintln!("Guardian blocked makepkg because {error}.");
        return ExitCode::from(2);
    }

    // 3. The upstream sources, for a call that runs PKGBUILD functions.
    let invocation = aur::classify(arguments);
    if invocation.runs_functions {
        let exit = review_upstream(
            &UpstreamStep {
                makepkg: Path::new(makepkg),
                arguments,
                build_dir: &build_dir,
                name: &name,
                extract: invocation.extracts,
            },
            settings,
            facts,
        );
        if let Some(exit) = exit {
            return exit;
        }
    }

    // 4. The build.
    eprintln!(
        "Guardian: review clear; starting {}",
        Path::new(makepkg).display()
    );
    exec_command(command)
}

/// The AUR's facts about `name` for the reviews, printing its summary and
/// any trust warnings.
fn aur_facts(name: &str) -> Vec<String> {
    let mut facts = Vec::new();
    match aur_info(name) {
        Ok(Some(info)) => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs());
            let (found, warnings) = aur::trust_signals(&info, now);
            if let Some(summary) = found.first() {
                outln!("{summary}");
            }
            facts.extend(found);
            print_warnings("AUR trust signals", &warnings);
            facts.extend(
                warnings
                    .iter()
                    .map(|warning| format!("Guardian's AUR check warns: {warning}.")),
            );
        }
        Ok(None) => {
            let fact = format!("{name} is not a package in the AUR (a local or private PKGBUILD).");
            outln!("{fact}");
            facts.push(fact);
        }
        Err(error) => eprintln!("Guardian: AUR metadata unavailable ({error})."),
    }
    facts
}

struct UpstreamStep<'a> {
    makepkg: &'a Path,
    arguments: &'a [OsString],
    build_dir: &'a Path,
    name: &'a str,
    /// The call extracts the sources itself, so they are extracted here
    /// first, without running any PKGBUILD function.
    extract: bool,
}

/// Returns an exit code when makepkg must not start.
fn review_upstream(
    step: &UpstreamStep<'_>,
    settings: &Settings,
    facts: Vec<String>,
) -> Option<ExitCode> {
    let mut context = vec![aur::UPSTREAM_SCOPE.to_string()];
    let pkgbuild = std::fs::read_to_string(step.build_dir.join("PKGBUILD")).unwrap_or_default();
    context.push(if aur::runs_tests(&pkgbuild) {
        "The recipe defines check(), so the upstream test suite runs during this build.".into()
    } else {
        "The recipe defines no check(), so the upstream test suite does not run during this build."
            .into()
    });
    match source_list(step.makepkg, step.build_dir) {
        Ok(sources) => {
            let checks = aur::check_sources(&sources);
            print_warnings("Source checks", &checks.warnings);
            if !checks.blocking.is_empty() {
                print_warnings("Source checks (blocking)", &checks.blocking);
                eprintln!("Guardian blocked makepkg: a source can be replaced in transit.");
                return Some(ExitCode::from(1));
            }
            context.extend(
                checks
                    .warnings
                    .iter()
                    .map(|warning| format!("Guardian's source check warns: {warning}.")),
            );
        }
        Err(error) => eprintln!("Guardian: could not read the source list ({error})."),
    }
    context.extend(facts);

    if step.extract {
        eprintln!(
            "Guardian: fetching and extracting the sources for review (no PKGBUILD function runs)..."
        );
        let mut command = Command::new(step.makepkg);
        command
            .current_dir(step.build_dir)
            .args(["--nobuild", "--noprepare", "--nodeps", "--noconfirm"])
            .args(
                step.arguments
                    .iter()
                    .filter(|arg| MIRRORED_FLAGS.iter().any(|flag| *arg == OsStr::new(flag))),
            );
        match command.status() {
            Ok(status) if status.success() => {}
            Ok(status) => {
                eprintln!(
                    "Guardian blocked makepkg: fetching the sources for review failed ({status})."
                );
                return Some(ExitCode::from(2));
            }
            Err(error) => {
                eprintln!(
                    "Guardian blocked makepkg: could not run makepkg to fetch the sources ({error})."
                );
                return Some(ExitCode::from(2));
            }
        }
    }

    let upstream = aur::collect_upstream(&step.build_dir.join("src"));
    if upstream.files.is_empty() {
        outln!("Upstream: no text sources to review.");
        return None;
    }
    let decision = review_upstream_files(step, settings, &upstream, &context);
    match decision {
        // Nothing was sent to the AI (`ai = off`): the recipe decision stands.
        Decision::Limited | Decision::Clear | Decision::Warned => None,
        Decision::Blocked(_) => {
            eprintln!(
                "Guardian blocked makepkg because the review of the upstream sources did not allow it."
            );
            Some(decision.exit_code())
        }
    }
}

fn review_upstream_files(
    step: &UpstreamStep<'_>,
    settings: &Settings,
    upstream: &Upstream,
    context: &[String],
) -> Decision {
    let state_root = Store::default_root();
    let review_context = ReviewContext {
        settings,
        class: SourceClass::Aur,
        opencode: &OpenCode::UserPath,
        units: &[],
        state_root: state_root.as_deref(),
        context,
    };
    let mut report = review::collected_report(
        format!("{} · upstream sources", step.build_dir.display()),
        &review_context,
    );
    for file in &upstream.files {
        review::analyze_payload(&mut report, &file.path, &file.text);
    }
    let units: Vec<Unit> = Identity::parse(&format!("aur-src:{}", step.name))
        .map(|identity| {
            vec![Unit {
                prefix: String::new(),
                identity,
            }]
        })
        .unwrap_or_default();
    let report = review::review_collected(report, &review_context, &units);
    let decision = report.decide(&|class| settings.policy(class));
    outln!(
        "Upstream: {} of {} code and build file(s) reviewed{}; {} data or documentation file(s) not reviewed.",
        upstream.files.len(),
        upstream.text_files,
        if upstream.whole {
            " (all of them)".to_string()
        } else {
            format!(
                " (build files and scripts first, then code by depth; {} code file(s) past the review budget)",
                upstream.left_out
            )
        },
        upstream.data_files
    );
    report.print(false, decision);
    decision
}

/// The sources and checksums from `makepkg --printsrcinfo`.
fn source_list(makepkg: &Path, build_dir: &Path) -> Result<Vec<aur::Source>, Error> {
    let captured = tools::run_in(
        makepkg,
        &["--printsrcinfo".into()],
        build_dir,
        &[("LC_ALL", "C")],
        SRCINFO_LIMITS,
    )?
    .into_success()?;
    Ok(aur::parse_srcinfo(&String::from_utf8_lossy(&captured)))
}

/// The AUR's record of `name`, or `None` when it has none.
fn aur_info(name: &str) -> Result<Option<AurInfo>, Error> {
    if !pacman::is_valid_package_name(name) {
        return Ok(None);
    }
    let encoded: String = name
        .chars()
        .map(|character| match character {
            '+' => "%2B".to_string(),
            '@' => "%40".to_string(),
            other => other.to_string(),
        })
        .collect();
    let mut args = osv::curl_args();
    args.push(format!("{RPC_URL}{encoded}").into());
    let body = tools::run(Path::new(tools::CURL), &args, None, &[], RPC_LIMITS)?.into_success()?;
    let reply = Json::parse(&String::from_utf8_lossy(&body))
        .map_err(|error| Error::parse("the AUR reply", error))?;
    Ok(aur::parse_rpc_info(&reply))
}

fn print_warnings(title: &str, warnings: &[String]) {
    if warnings.is_empty() {
        return;
    }
    outln!("{title}:");
    for warning in warnings {
        outln!("  ! {warning}");
    }
}

/// Parses `makepkg-gate -- <makepkg> [args...]`.
pub fn parse(args: &[OsString]) -> Result<Vec<OsString>, String> {
    match args.split_first() {
        Some((separator, rest)) if separator == "--" && !rest.is_empty() => Ok(rest.to_vec()),
        _ => Err("usage: omarchy-guardian makepkg-gate -- <makepkg> [args...]".into()),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::parse;

    #[test]
    fn parses_the_wrapped_command() {
        let args = |list: &[&str]| list.iter().map(OsString::from).collect::<Vec<_>>();
        assert_eq!(
            parse(&args(&["--", "/usr/bin/makepkg", "-si"])).unwrap(),
            args(&["/usr/bin/makepkg", "-si"])
        );
        assert!(parse(&args(&["/usr/bin/makepkg"])).is_err());
        assert!(parse(&args(&["--"])).is_err());
    }
}
