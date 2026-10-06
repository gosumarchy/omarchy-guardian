//! Review results, the decision derived from them against a per-class
//! policy, and their terminal rendering.

use std::collections::HashMap;
use std::fmt::{self, Write as _};
use std::process::ExitCode;

use crate::agent::{AgentReview, SourceFile, Status};
use crate::config::model::{Action, AiRequirement, Policy, SourceClass};
use crate::deps::Inventory;
use crate::error::Error;
use crate::osv::Audit;
use crate::rules::{RuleId, Scheme};
use crate::scan::Snapshot;

pub(crate) mod html;
mod terminal;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Severity {
    High,
    Medium,
    Low,
}

impl Severity {
    pub(crate) fn parse(text: &str) -> Option<Self> {
        match text.to_ascii_lowercase().as_str() {
            "high" => Some(Self::High),
            "medium" => Some(Self::Medium),
            "low" => Some(Self::Low),
            _ => None,
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
        }
    }

    const fn color(self) -> &'static str {
        match self {
            Self::High => "31;1",
            Self::Medium => "33;1",
            Self::Low => "36;1",
        }
    }
}

/// A reason the review cannot vouch for what it was asked to review. Any gap
/// blocks the decision as `Blocked(Incomplete)`.
#[derive(Debug)]
pub(crate) enum Gap {
    Io(Error),
    Symlink(String),
    SpecialFile(String),
    NonUtf8Name(String),
    OversizedText(String),
    HashLimit(String),
    UnresolvedLfs(String),
    SensitiveWithheld(String),
    AgentInputTooLarge,
    /// An install or build entry point larger than one AI request.
    EntryPointTooLarge(String),
    /// Git state the walk cannot stand for: a git directory whose
    /// configuration or hooks git would take from somewhere else.
    GitState(String),
    /// A file the sweep could not read as this user.
    RootOnly(String),
    /// Something else that kept the sweep from seeing everything.
    Sweep(String),
    /// A script, build or config file (or an executable file of unknown
    /// format) that holds binary data.
    Undecodable(String),
    /// The tree passed a whole-tree limit (see `scan::Limits`).
    TreeTooLarge {
        files: usize,
        bytes: u64,
    },
    NoReviewableFiles,
    Agent(Error),
    Dependency(String),
    /// What the pacman gate refuses or cannot stand for: a package it will
    /// not take, an archive it could not read or attribute, system state
    /// it could not look at. Nothing a digest of the reviewed content
    /// covers, so no permit overrules it.
    Package(Error),
    /// A part of a package archive the pacman gate could not review, while
    /// the archive itself was read and fingerprinted: a named file over the
    /// size or count limits, an oversized or binary scriptlet, a compiled
    /// program in an auto-run location.
    PackageUnread(String),
    /// A file a reviewed one runs or reads in as code, which Guardian could
    /// not read as text.
    RunsUnread(String),
}

impl Gap {
    /// Whether what the gap is about is still covered by the SHA-256 of
    /// what was reviewed: the review could not read or judge it, but a
    /// permit bound to that digest is bound to it too. Anything else (a
    /// file that could not be opened or hashed, a link leading elsewhere, a
    /// package Guardian refused) is content nobody put a digest on, which
    /// no permit can stand for.
    pub(crate) const fn content_hashed(&self) -> bool {
        match self {
            Self::OversizedText(_)
            | Self::UnresolvedLfs(_)
            | Self::SensitiveWithheld(_)
            | Self::AgentInputTooLarge
            | Self::EntryPointTooLarge(_)
            | Self::Undecodable(_)
            | Self::NoReviewableFiles
            | Self::Agent(_)
            | Self::Dependency(_)
            | Self::PackageUnread(_)
            | Self::RunsUnread(_) => true,
            Self::Io(_)
            | Self::Symlink(_)
            | Self::SpecialFile(_)
            | Self::NonUtf8Name(_)
            | Self::HashLimit(_)
            | Self::GitState(_)
            | Self::RootOnly(_)
            | Self::Sweep(_)
            | Self::TreeTooLarge { .. }
            | Self::Package(_) => false,
        }
    }
}

impl fmt::Display for Gap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) | Self::Package(error) => write!(f, "{error}"),
            Self::Symlink(path) => write!(f, "{path}: refusing to follow a symbolic link"),
            Self::SpecialFile(path) => write!(f, "{path}: not a regular file or directory"),
            Self::NonUtf8Name(path) => write!(f, "{path}: file name is not valid UTF-8"),
            Self::OversizedText(path) => {
                write!(f, "{path}: text file exceeds the 2 MiB review limit")
            }
            Self::HashLimit(path) => {
                write!(f, "{path}: file exceeds the 512 MiB integrity-hash limit")
            }
            Self::UnresolvedLfs(path) => write!(
                f,
                "{path}: Git LFS content is unresolved; refusing to review a pointer as source"
            ),
            Self::SensitiveWithheld(path) => write!(
                f,
                "{path}: withheld from the AI provider because it looks sensitive"
            ),
            Self::RunsUnread(text) | Self::PackageUnread(text) => write!(f, "{text}"),
            Self::Undecodable(path) => write!(
                f,
                "{path}: a script, build or config file holds binary data and cannot be reviewed"
            ),
            Self::TreeTooLarge { files, bytes } => write!(
                f,
                "source tree too large to review (stopped at {files} files, {} MiB; limits: {} files, {} MiB text, {} MiB hashed)",
                bytes / (1024 * 1024),
                crate::scan::Limits::DEFAULT.files,
                crate::scan::Limits::DEFAULT.text_bytes / (1024 * 1024),
                crate::scan::Limits::DEFAULT.hashed_bytes / (1024 * 1024)
            ),
            Self::AgentInputTooLarge => {
                f.write_str("source exceeds the AI review input limit (max_input_kib × max_chunks)")
            }
            Self::Sweep(reason) => write!(f, "sweep: {reason}"),
            Self::GitState(what) => f.write_str(what),
            Self::RootOnly(path) => write!(
                f,
                "{path}: only root can read it; run `omarchy-guardian sweep --root` to check it"
            ),
            Self::EntryPointTooLarge(path) => write!(
                f,
                "{path}: an install or build entry point is larger than one AI request (max_input_kib); it cannot be reviewed in pieces"
            ),
            Self::NoReviewableFiles => {
                f.write_str("no readable text source files were available for review")
            }
            Self::Agent(error) => write!(f, "AI review failed: {error}"),
            Self::Dependency(message) => f.write_str(message),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Blocked {
    Findings,
    Incomplete,
    AiUnavailable,
    NotConfirmed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Decision {
    Clear,
    Warned,
    /// Nothing reviewable existed (a pacman transaction without scriptlets).
    Limited,
    Blocked(Blocked),
}

impl Decision {
    pub(crate) fn exit_code(self) -> ExitCode {
        ExitCode::from(self.exit_status())
    }

    /// The exit code as a number, for the audit trail.
    pub(crate) const fn exit_status(self) -> u8 {
        match self {
            Self::Clear | Self::Warned | Self::Limited => 0,
            Self::Blocked(Blocked::Findings) => 1,
            Self::Blocked(Blocked::Incomplete | Blocked::AiUnavailable | Blocked::NotConfirmed) => {
                2
            }
        }
    }

    /// Whether `guard` and `sandbox` may start their command.
    pub(crate) const fn allows_running(self) -> bool {
        match self {
            Self::Clear | Self::Warned => true,
            Self::Limited | Self::Blocked(_) => false,
        }
    }
}

#[derive(Debug)]
pub(crate) enum AgentOutcome {
    Reviewed(AgentReview),
    Unavailable(Error),
}

/// One OpenCode call and the files it covered.
#[derive(Debug)]
pub(crate) struct AgentRun {
    pub(crate) files: Vec<String>,
    /// `model · thinking`, from `AgentSettings::label`.
    pub(crate) label: String,
    /// 1-based chunk index and count when the review needed several calls.
    pub(crate) chunk: Option<(usize, usize)>,
    /// Set when the verdict came from the cache: `from cache: ...`.
    pub(crate) cached: Option<String>,
    pub(crate) outcome: AgentOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalFinding {
    pub(crate) path: String,
    pub(crate) line: usize,
    pub(crate) rule: RuleId,
    pub(crate) excerpt: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct NetworkRequest {
    pub(crate) path: String,
    pub(crate) line: usize,
    pub(crate) scheme: Scheme,
    pub(crate) host: String,
}

#[derive(Debug, Default)]
pub(crate) struct Report {
    pub(crate) subject: String,
    pub(crate) snapshot: Snapshot,
    pub(crate) gaps: Vec<Gap>,
    pub(crate) text_files_reviewed: usize,
    /// Text files decoded with replacement characters (a legacy encoding).
    pub(crate) lossy_files: usize,
    /// Files hashed but not read, named to the AI.
    pub(crate) hash_only: Vec<crate::engine::plan::HashOnly>,
    /// What an approved version is bound to besides its text.
    pub(crate) unread: crate::engine::baseline::Unread,
    pub(crate) findings: Vec<LocalFinding>,
    pub(crate) network: Vec<NetworkRequest>,
    pub(crate) agent_input: Vec<SourceFile>,
    pub(crate) agent_input_overflowed: bool,
    /// Classes whose policy has `ai = off`: their files are never queued for
    /// the AI provider, so AI-input gaps do not apply to them either. Files
    /// are matched through `class_of`, so `file_classes` must be set before
    /// a file is analyzed.
    pub(crate) ai_off_classes: Vec<SourceClass>,
    pub(crate) dependencies: Inventory,
    pub(crate) audit: Option<Audit>,
    /// Class of every file not listed in `file_classes`.
    pub(crate) class: SourceClass,
    /// Per-file classes when one report spans several (pacman transactions).
    pub(crate) file_classes: HashMap<String, SourceClass>,
    pub(crate) agent_runs: Vec<AgentRun>,
    /// Profile name shown next to AI verdicts.
    pub(crate) profile: String,
    /// Review-memory lines: the upgrade summary and store problems. Never gaps.
    pub(crate) notes: Vec<String>,
    /// Facts Guardian established for the AI review (see `Request::context`).
    pub(crate) context: Vec<String>,
    /// What each reviewed file runs or reads in as code, by line (see
    /// `review::check_runs`).
    pub(crate) runs: Vec<RunRef>,
    /// The files each reviewed file downloads to, lowercased.
    pub(crate) fetches: Vec<(String, String)>,
    /// More were found than are recorded (see `review::MAX_RUNS`).
    pub(crate) runs_overflowed: bool,
    /// The package archives a pacman transaction was reviewed from, each
    /// with the SHA-256 of its bytes: what the audit trail records and a
    /// permit is bound to.
    pub(crate) archives: Vec<ReviewedArchive>,
    /// The permit of the user's that overrules this report's decision
    /// (see `permit`): it is printed as PERMITTED.
    pub(crate) permit: Option<String>,
}

/// One archive of a reviewed pacman transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReviewedArchive {
    /// The archive's file name without `.pkg.tar.*`: name, version, build
    /// and architecture.
    pub(crate) name: String,
    pub(crate) class: SourceClass,
    /// Hex SHA-256 of the archive's bytes.
    pub(crate) sha256: String,
}

/// A file one reviewed file runs or reads in as code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RunRef {
    pub(crate) rel: String,
    pub(crate) line: usize,
    pub(crate) excerpt: String,
    /// As written on the line (`./data/x.png`).
    pub(crate) target: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Counts {
    high: usize,
    medium: usize,
    low: usize,
}

impl Counts {
    fn add(&mut self, severity: Severity) {
        match severity {
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
        }
    }

    const fn total(self) -> usize {
        self.high + self.medium + self.low
    }
}

#[derive(Default)]
struct Tally {
    ai_unavailable: bool,
    blocked: bool,
    warned: bool,
}

impl Tally {
    fn apply(&mut self, action: Action) {
        match action {
            Action::Block => self.blocked = true,
            Action::Warn => self.warned = true,
        }
    }
}

impl Report {
    pub(crate) fn new(subject: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            ..Self::default()
        }
    }

    pub(crate) fn class_of(&self, path: &str) -> SourceClass {
        self.file_classes.get(path).copied().unwrap_or(self.class)
    }

    fn run_classes(&self, run: &AgentRun) -> Vec<SourceClass> {
        let mut classes: Vec<SourceClass> =
            run.files.iter().map(|file| self.class_of(file)).collect();
        classes.sort();
        classes.dedup();
        if classes.is_empty() {
            classes.push(self.class);
        }
        classes
    }

    /// Spec §9. Precedence: incomplete, AI unavailable, findings, warned,
    /// then limited or clear.
    pub(crate) fn decide(&self, policy_for: &dyn Fn(SourceClass) -> Policy) -> Decision {
        if !self.gaps.is_empty() {
            return Decision::Blocked(Blocked::Incomplete);
        }

        let mut tally = Tally::default();
        for run in &self.agent_runs {
            let classes = self.run_classes(run);
            match &run.outcome {
                AgentOutcome::Unavailable(_) => {
                    for class in classes {
                        if policy_for(class).ai == AiRequirement::Required {
                            tally.ai_unavailable = true;
                        } else {
                            tally.warned = true;
                        }
                    }
                }
                AgentOutcome::Reviewed(review) if review.status == Status::Inconclusive => {
                    return Decision::Blocked(Blocked::Incomplete);
                }
                AgentOutcome::Reviewed(review) => {
                    let mut flagged: Vec<SourceClass> = review
                        .findings
                        .iter()
                        .flat_map(|finding| {
                            if run.files.contains(&finding.file) {
                                vec![self.class_of(&finding.file)]
                            } else {
                                // Every chunk sees the whole manifest, so a
                                // finding may name a file outside this run.
                                // Apply both the run's own classes and the
                                // named file's class: the strictest of the
                                // two must decide, never only the looser.
                                let mut named = classes.clone();
                                named.push(self.class_of(&finding.file));
                                named
                            }
                        })
                        .collect();
                    if review.status == Status::Suspicious && flagged.is_empty() {
                        flagged.clone_from(&classes);
                    }
                    for class in flagged {
                        tally.apply(policy_for(class).on_ai_suspicious);
                    }
                }
            }
        }

        for finding in &self.findings {
            tally.apply(policy_for(self.class_of(&finding.path)).on_findings);
        }
        if self
            .audit
            .as_ref()
            .is_some_and(|audit| !audit.advisories.is_empty())
        {
            tally.apply(policy_for(self.class).on_findings);
        }

        if tally.ai_unavailable {
            Decision::Blocked(Blocked::AiUnavailable)
        } else if tally.blocked {
            Decision::Blocked(Blocked::Findings)
        } else if tally.warned || !self.snapshot.skipped().is_empty() {
            // A skipped directory's marker is easy to fake: never CLEAR.
            Decision::Warned
        } else if self.text_files_reviewed == 0 && self.agent_runs.is_empty() {
            Decision::Limited
        } else {
            Decision::Clear
        }
    }

    /// The decision as one word or two, as the saved report and the audit
    /// trail name it.
    pub(crate) fn decision_name(&self, decision: Decision) -> &'static str {
        match decision {
            Decision::Clear => "CLEAR",
            Decision::Warned => "WARNED",
            Decision::Limited => "LIMITED",
            Decision::Blocked(Blocked::Findings) if self.counts().high > 0 => "HIGH RISK",
            Decision::Blocked(Blocked::Findings) => "REVIEW REQUIRED",
            Decision::Blocked(Blocked::Incomplete) => "INCOMPLETE",
            Decision::Blocked(Blocked::AiUnavailable) => "AI UNAVAILABLE",
            Decision::Blocked(Blocked::NotConfirmed) => "NOT CONFIRMED",
        }
    }

    /// Whether a permit could stand for this report's content: every gap
    /// is about something the digest of what was reviewed still covers.
    pub(crate) fn content_hashed(&self) -> bool {
        self.gaps.iter().all(Gap::content_hashed)
    }

    /// What was found, for the audit trail: the alert counts, the local
    /// rules that matched and how many reasons left the review incomplete.
    /// Numbers and rule ids only: nothing of the reviewed text.
    pub(crate) fn audit_findings(&self) -> String {
        let counts = self.counts();
        let mut text = format!(
            "high={} medium={} low={} incomplete={}",
            counts.high,
            counts.medium,
            counts.low,
            self.gaps.len()
        );
        let mut rules: Vec<&str> = self
            .findings
            .iter()
            .map(|finding| finding.rule.name())
            .collect();
        rules.sort_unstable();
        rules.dedup();
        if !rules.is_empty() {
            let _ = write!(text, " rules={}", rules.join(","));
        }
        text
    }

    /// The AI review in numbers, for the audit trail: the model and
    /// thinking level, how many calls there were and how each ended.
    pub(crate) fn audit_ai(&self) -> String {
        if self.agent_runs.is_empty() {
            return "none".into();
        }
        let mut labels: Vec<&str> = self
            .agent_runs
            .iter()
            .map(|run| run.label.as_str())
            .collect();
        labels.sort_unstable();
        labels.dedup();
        let count = |wanted: &dyn Fn(&AgentRun) -> bool| {
            self.agent_runs.iter().filter(|run| wanted(run)).count()
        };
        let ended = |status: Status| move |run: &AgentRun| matches!(&run.outcome, AgentOutcome::Reviewed(review) if review.status == status);
        format!(
            "{} chunks={} clear={} suspicious={} inconclusive={} unavailable={} from-cache={}",
            labels.join(","),
            self.agent_runs.len(),
            count(&ended(Status::Clear)),
            count(&ended(Status::Suspicious)),
            count(&ended(Status::Inconclusive)),
            count(&|run| matches!(run.outcome, AgentOutcome::Unavailable(_))),
            count(&|run| run.cached.is_some()),
        )
    }

    /// What a permit for this report would overrule, a line each and at
    /// most `limit` of them: the alerts by where they are, and why the
    /// review is incomplete. Shown to the user before they permit.
    pub(crate) fn overruled_summary(&self, limit: usize) -> Vec<String> {
        let mut lines: Vec<String> = self
            .findings
            .iter()
            .map(|finding| {
                format!(
                    "{} {}:{} {}",
                    finding.rule.severity().label(),
                    finding.path,
                    finding.line,
                    finding.rule.name()
                )
            })
            .collect();
        for run in &self.agent_runs {
            match &run.outcome {
                AgentOutcome::Reviewed(review) => {
                    lines.extend(review.findings.iter().map(|finding| {
                        format!(
                            "{} {} (AI) {}",
                            finding.severity.label(),
                            finding.file,
                            finding.title
                        )
                    }));
                    if review.status != Status::Clear && review.findings.is_empty() {
                        lines.push(format!("AI review: {}", review.status.label()));
                    }
                }
                AgentOutcome::Unavailable(error) => {
                    lines.push(format!("AI review unavailable: {error}"));
                }
            }
        }
        for advisory in self.audit.iter().flat_map(|audit| &audit.advisories) {
            lines.push(format!(
                "known vulnerability {} in {}@{}",
                advisory.id, advisory.package, advisory.version
            ));
        }
        lines.extend(self.gaps.iter().map(|gap| format!("not reviewed: {gap}")));
        let more = lines.len().saturating_sub(limit);
        lines.truncate(limit);
        if more > 0 {
            lines.push(format!("and {more} more"));
        }
        lines
    }

    /// Dependency advisories without a known severity count as medium.
    fn counts(&self) -> Counts {
        let mut counts = Counts::default();
        for finding in &self.findings {
            counts.add(finding.rule.severity());
        }
        let agent_findings = self.agent_runs.iter().flat_map(|run| match &run.outcome {
            AgentOutcome::Reviewed(review) => review.findings.as_slice(),
            AgentOutcome::Unavailable(_) => &[],
        });
        for finding in agent_findings {
            counts.add(finding.severity);
        }
        for advisory in self.audit.iter().flat_map(|audit| &audit.advisories) {
            counts.add(advisory.severity.unwrap_or(Severity::Medium));
        }
        counts
    }

    fn oversized_count(&self) -> usize {
        self.gaps
            .iter()
            .filter(|gap| matches!(gap, Gap::OversizedText(_)))
            .count()
    }

    fn withheld_count(&self) -> usize {
        self.gaps
            .iter()
            .filter(|gap| matches!(gap, Gap::SensitiveWithheld(_)))
            .count()
    }
}

/// What to do after a review with this decision.
const fn recommendation(decision: Decision) -> &'static str {
    match decision {
        Decision::Blocked(Blocked::Findings) => {
            "Recommendation: do not install or run this source until findings are resolved."
        }
        Decision::Blocked(Blocked::Incomplete) => {
            "Recommendation: do not proceed; complete the review first."
        }
        Decision::Blocked(Blocked::AiUnavailable) => {
            "Recommendation: fix the AI reviewer setup (see `omarchy-guardian setup`) and retry."
        }
        Decision::Blocked(Blocked::NotConfirmed) => "Not confirmed; nothing was run.",
        Decision::Warned => "Proceeding with warnings; read them above.",
        Decision::Limited => {
            "Scope: install scriptlets and new or changed auto-run files are reviewed; the rest of each package's payload is not."
        }
        Decision::Clear => "Scope: this is a heuristic source review, not a safety guarantee.",
    }
}

#[cfg(test)]
mod tests;
