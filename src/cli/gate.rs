//! The gate: what is reviewed, the verdict on it, asking the user, and the
//! commands that review before they run something.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use crate::audit::{self, Gate};
use crate::config::Settings;
use crate::config::model::{AiRequirement, Named, Profile, SourceClass};
use crate::engine::baseline::Unit;
use crate::notify;
use crate::permit::{self, Content, Standing};
use crate::report::{Blocked, Decision, Report};
use crate::review::{self, ReviewContext};
use crate::sandbox;
use crate::scan::{self, ScanConfig};
use crate::tools::OpenCode;

use super::{USAGE_ERROR, settings_for};

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
    pub(crate) fn subject(&self) -> String {
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
        // The question names what is being reviewed: nothing in a name
        // may move the cursor or hide part of the line.
        if write!(tty, "{} [y/N] ", crate::text::shown(question))
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

/// A review, its decision, and how a blocked one stands with permits.
pub(crate) struct Verdict {
    pub(crate) report: Report,
    pub(crate) decision: Decision,
    pub(crate) standing: Standing,
}

impl Verdict {
    /// Whether the gate may go on: the review allows it, or a permit of
    /// the user's overrules the review for exactly this content.
    pub(crate) fn allows_running(&self) -> bool {
        self.decision.allows_running() || self.standing.permitted().is_some()
    }
}

/// What a gate's review is of, as permits and the audit trail name it
/// (see `permit::standing`); nothing when it has no digest.
pub(crate) type ContentOf<'a> = &'a dyn Fn(&Report) -> Vec<Content>;

/// The reviewed tree by its manifest digest, for a gate that reviews one.
pub(super) fn tree_content(gate: Gate, target: &Target, report: &Report) -> Vec<Content> {
    if report.snapshot.files().is_empty() {
        return Vec::new();
    }
    Content::tree(
        gate,
        target.class,
        &target.subject(),
        &report.snapshot.manifest_digest().to_string(),
    )
    .into_iter()
    .collect()
}

/// The exit code of a gate that did not start its command: never 0, which
/// a caller reads as "the command ran".
const fn not_started_status(decision: Decision) -> u8 {
    match decision {
        Decision::Blocked(_) => decision.exit_status(),
        Decision::Clear | Decision::Warned | Decision::Limited => 2,
    }
}

/// Reviews a target, applies confirmation and the user's permits, then
/// prints the report once with the final decision — never a stale
/// pre-confirmation headline — and records it in the audit trail. A plain
/// scan has no `content`: nothing runs after it, so nothing is permitted.
pub(crate) fn review_and_decide(
    target: &Target,
    settings: &Settings,
    opencode: &OpenCode,
    confirm: Option<&mut dyn Confirm>,
    context: &[String],
    gate: Gate,
    content: Option<ContentOf<'_>>,
) -> Verdict {
    let mut report = review::review_tree(
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

    let contents = content.map_or_else(Vec::new, |content| content(&report));
    let content = contents.first();
    let standing = permit::standing(
        &contents,
        &report,
        decision,
        settings,
        target.state_root.as_deref(),
    );
    report.permit = standing.permitted().map(str::to_string);
    report.print(target.show_hashes, decision);

    let verdict = Verdict {
        report,
        decision,
        standing,
    };
    let exit = if gate == Gate::Scan {
        decision.exit_status()
    } else if verdict.allows_running() {
        0
    } else {
        not_started_status(decision)
    };
    let manifest = if verdict.report.snapshot.files().is_empty() {
        String::new()
    } else {
        format!("tree:{}", verdict.report.snapshot.manifest_digest())
    };
    audit::review(
        &audit::Reviewed {
            gate,
            class: content.map_or(target.class.name(), Content::class),
            subject: &target.subject(),
            digest: &content.map_or(manifest, Content::digest),
            decision,
            permit: verdict.standing.permitted(),
            offered: verdict.standing.offered(),
            exit,
        },
        &verdict.report,
    )
    .record();
    verdict
}

/// What a gate says when it goes on: the review's own word, or the permit
/// that overruled it.
pub(crate) fn passed(verdict: &Verdict) -> String {
    match verdict.standing.permitted() {
        Some(permit) => format!(
            "your permit {permit} overrules {}",
            verdict.report.decision_name(verdict.decision)
        ),
        None if verdict.decision == Decision::Warned => "review passed with warnings".into(),
        None => "review clear".into(),
    }
}

/// Reviews the target and hands `command` to `launch` only after a clear or
/// warned review, an approved confirmation and an unchanged re-hash of the
/// tree.
pub(super) fn guard_command(
    target: &Target,
    command: &[OsString],
    settings: &Settings,
    opencode: &OpenCode,
    confirm: &mut dyn Confirm,
    launch: &mut dyn FnMut(&[OsString]) -> ExitCode,
) -> ExitCode {
    let settings = settings_for(target, settings);
    let gate = Gate::of_guard(target.class);
    let verdict = review_and_decide(
        target,
        &settings,
        opencode,
        Some(confirm),
        &[],
        gate,
        Some(&|report| tree_content(gate, target, report)),
    );
    let decision = verdict.decision;

    if !verdict.allows_running() {
        match decision {
            Decision::Blocked(Blocked::NotConfirmed) => {
                errln!("Guardian did not start the command: not confirmed.");
                verdict.standing.say();
            }
            Decision::Blocked(blocked) => {
                errln!("Guardian blocked the command because the review did not allow it.");
                verdict.standing.say();
                notify::blocked(
                    &target.subject(),
                    notify::reason(blocked),
                    notify::Ran::Nothing,
                );
            }
            _ => errln!("Guardian did not start the command: there was nothing to review."),
        }
        return not_started(decision);
    }
    if let Err(error) = scan::verify_unchanged(&target.config, &verdict.report.snapshot) {
        errln!("Guardian blocked the command because {error}.");
        audit::refused(gate, &format!("{}: {error}", target.subject()), 2);
        notify::blocked(&target.subject(), &format!("{error}"), notify::Ran::Nothing);
        return ExitCode::from(2);
    }

    errln!(
        "Guardian: {}; starting {}",
        passed(&verdict),
        command.first().map_or_else(String::new, |program| program
            .to_string_lossy()
            .into_owned())
    );
    launch(command)
}

/// The exit code of a `guard` or `sandbox` that did not start its command.
pub(super) fn not_started(decision: Decision) -> ExitCode {
    ExitCode::from(not_started_status(decision))
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

pub(super) fn sandbox_command(
    target: &Target,
    command: &[OsString],
    settings: &Settings,
    confirm: &mut dyn Confirm,
) -> ExitCode {
    let settings = settings_for(target, settings);
    let verdict = review_and_decide(
        target,
        &settings,
        &OpenCode::UserPath,
        Some(confirm),
        &[],
        Gate::Sandbox,
        Some(&|report| tree_content(Gate::Sandbox, target, report)),
    );
    let decision = verdict.decision;

    if !verdict.allows_running() {
        if decision == Decision::Blocked(Blocked::NotConfirmed) {
            errln!("Guardian did not start the sandbox command: not confirmed.");
        } else {
            errln!("Guardian did not run the sandbox command because the review did not allow it.");
        }
        verdict.standing.say();
        return not_started(decision);
    }
    if let Some(permit) = verdict.standing.permitted() {
        errln!(
            "Guardian: your permit {permit} overrules {}; starting the sandbox command.",
            verdict.report.decision_name(decision)
        );
    }
    match sandbox::run(&target.config, &verdict.report.snapshot, command) {
        Ok(code) => code,
        Err(error) => {
            errln!("Guardian blocked the sandbox run because {error}.");
            audit::refused(Gate::Sandbox, &format!("{}: {error}", target.subject()), 2);
            ExitCode::from(2)
        }
    }
}
