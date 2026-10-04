//! Review results, the decision derived from them against a per-class
//! policy, and their terminal rendering.

use std::collections::HashMap;
use std::fmt::{self, Write as _};
use std::process::ExitCode;

use crate::agent::{AgentReview, SourceFile, Status};
use crate::config::model::{Action, AiRequirement, Policy, SourceClass};
use crate::deps::Inventory;
use crate::error::Error;
use crate::layout::{self, Painter, Span, Table};
use crate::osv::Audit;
use crate::rules::{RuleId, Scheme};
use crate::scan::{FileKind, Snapshot};
use crate::text::shown;

pub mod html;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn parse(text: &str) -> Option<Self> {
        match text.to_ascii_lowercase().as_str() {
            "high" => Some(Self::High),
            "medium" => Some(Self::Medium),
            "low" => Some(Self::Low),
            _ => None,
        }
    }

    pub const fn label(self) -> &'static str {
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
pub enum Gap {
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
    Package(Error),
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
    pub const fn content_hashed(&self) -> bool {
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
            Self::RunsUnread(text) => write!(f, "{text}"),
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
pub enum Blocked {
    Findings,
    Incomplete,
    AiUnavailable,
    NotConfirmed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Clear,
    Warned,
    /// Nothing reviewable existed (a pacman transaction without scriptlets).
    Limited,
    Blocked(Blocked),
}

impl Decision {
    pub fn exit_code(self) -> ExitCode {
        ExitCode::from(self.exit_status())
    }

    /// The exit code as a number, for the audit trail.
    pub const fn exit_status(self) -> u8 {
        match self {
            Self::Clear | Self::Warned | Self::Limited => 0,
            Self::Blocked(Blocked::Findings) => 1,
            Self::Blocked(Blocked::Incomplete | Blocked::AiUnavailable | Blocked::NotConfirmed) => {
                2
            }
        }
    }

    /// Whether `guard` and `sandbox` may start their command.
    pub const fn allows_running(self) -> bool {
        match self {
            Self::Clear | Self::Warned => true,
            Self::Limited | Self::Blocked(_) => false,
        }
    }
}

#[derive(Debug)]
pub enum AgentOutcome {
    Reviewed(AgentReview),
    Unavailable(Error),
}

/// One OpenCode call and the files it covered.
#[derive(Debug)]
pub struct AgentRun {
    pub files: Vec<String>,
    /// `model · thinking`, from `AgentSettings::label`.
    pub label: String,
    /// 1-based chunk index and count when the review needed several calls.
    pub chunk: Option<(usize, usize)>,
    /// Set when the verdict came from the cache: `from cache: ...`.
    pub cached: Option<String>,
    pub outcome: AgentOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalFinding {
    pub path: String,
    pub line: usize,
    pub rule: RuleId,
    pub excerpt: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NetworkRequest {
    pub path: String,
    pub line: usize,
    pub scheme: Scheme,
    pub host: String,
}

#[derive(Debug, Default)]
pub struct Report {
    pub subject: String,
    pub snapshot: Snapshot,
    pub gaps: Vec<Gap>,
    pub text_files_reviewed: usize,
    /// Text files decoded with replacement characters (a legacy encoding).
    pub lossy_files: usize,
    /// Files hashed but not read, named to the AI.
    pub hash_only: Vec<crate::engine::plan::HashOnly>,
    /// What an approved version is bound to besides its text.
    pub unread: crate::engine::baseline::Unread,
    pub findings: Vec<LocalFinding>,
    pub network: Vec<NetworkRequest>,
    pub agent_input: Vec<SourceFile>,
    pub agent_input_overflowed: bool,
    /// Classes whose policy has `ai = off`: their files are never queued for
    /// the AI provider, so AI-input gaps do not apply to them either. Files
    /// are matched through `class_of`, so `file_classes` must be set before
    /// a file is analyzed.
    pub ai_off_classes: Vec<SourceClass>,
    pub dependencies: Inventory,
    pub audit: Option<Audit>,
    /// Class of every file not listed in `file_classes`.
    pub class: SourceClass,
    /// Per-file classes when one report spans several (pacman transactions).
    pub file_classes: HashMap<String, SourceClass>,
    pub agent_runs: Vec<AgentRun>,
    /// Profile name shown next to AI verdicts.
    pub profile: String,
    /// Review-memory lines: the upgrade summary and store problems. Never gaps.
    pub notes: Vec<String>,
    /// Facts Guardian established for the AI review (see `Request::context`).
    pub context: Vec<String>,
    /// What each reviewed file runs or reads in as code, by line (see
    /// `review::check_runs`).
    pub runs: Vec<RunRef>,
    /// The files each reviewed file downloads to, lowercased.
    pub fetches: Vec<(String, String)>,
    /// More were found than are recorded (see `review::MAX_RUNS`).
    pub runs_overflowed: bool,
    /// The package archives a pacman transaction was reviewed from, each
    /// with the SHA-256 of its bytes: what the audit trail records and a
    /// permit is bound to.
    pub archives: Vec<ReviewedArchive>,
    /// The permit of the user's that overrules this report's decision
    /// (see `permit`): it is printed as PERMITTED.
    pub permit: Option<String>,
}

/// One archive of a reviewed pacman transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewedArchive {
    /// The archive's file name without `.pkg.tar.*`: name, version, build
    /// and architecture.
    pub name: String,
    pub class: SourceClass,
    /// Hex SHA-256 of the archive's bytes.
    pub sha256: String,
}

/// A file one reviewed file runs or reads in as code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunRef {
    pub rel: String,
    pub line: usize,
    pub excerpt: String,
    /// As written on the line (`./data/x.png`).
    pub target: String,
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
    pub fn new(subject: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            ..Self::default()
        }
    }

    pub fn class_of(&self, path: &str) -> SourceClass {
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
    pub fn decide(&self, policy_for: &dyn Fn(SourceClass) -> Policy) -> Decision {
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
    pub fn decision_name(&self, decision: Decision) -> &'static str {
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
    pub fn content_hashed(&self) -> bool {
        self.gaps.iter().all(Gap::content_hashed)
    }

    /// What was found, for the audit trail: the alert counts, the local
    /// rules that matched and how many reasons left the review incomplete.
    /// Numbers and rule ids only: nothing of the reviewed text.
    pub fn audit_findings(&self) -> String {
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
    pub fn audit_ai(&self) -> String {
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
    pub fn overruled_summary(&self, limit: usize) -> Vec<String> {
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

    pub fn print(&self, show_hashes: bool, decision: Decision) {
        let painter = Painter::for_stdout();
        let width = layout::width();

        outln!();
        outln!("{}", self.verdict_box(decision, width, painter));
        let mut rows = Vec::new();
        self.coverage_fields(&mut rows);
        for note in &self.notes {
            rows.push(("Review memory", vec![Span::plain(shown(note))]));
        }
        self.inventory_fields(&mut rows);
        self.agent_fields(&mut rows);
        if self.findings.is_empty() && decision != Decision::Limited {
            rows.push(("Local checks", vec![Span::new("no matches", "32")]));
        }
        outln!("{}", layout::fields(&rows, width, painter));
        if show_hashes {
            self.print_hashes();
        }
        self.print_findings(width, painter);

        for gap in &self.gaps {
            crate::output::stderr_line(format_args!("  ! {}", shown(&gap.to_string())));
        }
        let advice = match (&self.permit, decision) {
            (Some(_), Decision::Blocked(_)) => PERMITTED_ADVICE,
            _ => recommendation(decision),
        };
        outln!("\n{}", painter.paint(advice, "2"));
        html::collect(self, decision);
    }

    /// The one-line verdict and its terminal colour.
    fn headline(&self, decision: Decision) -> (String, &'static str) {
        let counts = self.counts();
        let total = counts.total();
        if let (Some(permit), Decision::Blocked(_)) = (&self.permit, decision) {
            return (
                format!(
                    "! PERMITTED — your permit {permit} overrules {} for exactly this content",
                    self.decision_name(decision)
                ),
                "33;1",
            );
        }
        match decision {
            Decision::Clear => ("✓ CLEAR — no known concerns found".to_string(), "32"),
            Decision::Warned => (
                format!("! WARNED — {total} alert(s); allowed by policy for this source"),
                "33;1",
            ),
            Decision::Blocked(Blocked::Findings) if counts.high > 0 => (
                format!("✗ HIGH RISK — {total} alert(s) across local and AI review"),
                "31;1",
            ),
            Decision::Blocked(Blocked::Findings) => (
                format!("! REVIEW REQUIRED — {total} alert(s) across local and AI review"),
                "33;1",
            ),
            Decision::Blocked(Blocked::Incomplete) => (
                "! INCOMPLETE — this scan is not a clean result".to_string(),
                "33;1",
            ),
            Decision::Blocked(Blocked::AiUnavailable) => (
                "! AI REVIEW UNAVAILABLE — this source needs a completed AI review".to_string(),
                "33;1",
            ),
            Decision::Blocked(Blocked::NotConfirmed) => (
                "! NOT CONFIRMED — local checks passed but nothing was approved".to_string(),
                "33;1",
            ),
            Decision::Limited => (
                "· LIMITED REVIEW — no install scriptlet or new auto-run file to review"
                    .to_string(),
                "36;1",
            ),
        }
    }

    /// The verdict, and the alert counts when there are any, in a box the
    /// verdict's colour.
    fn verdict_box(&self, decision: Decision, width: usize, painter: Painter) -> String {
        let counts = self.counts();
        let (headline, color) = self.headline(decision);
        let mut lines = vec![Span::new(headline, color)];
        if counts.total() > 0 {
            lines.push(Span::plain(format!(
                "Alerts: {} high · {} medium · {} low",
                counts.high, counts.medium, counts.low
            )));
        }
        let title = format!("Omarchy Guardian · {}", shown(&self.subject));
        let edge = color.split(';').next().unwrap_or(color);
        layout::boxed(&title, &lines, width, edge, painter)
    }

    fn coverage_fields(&self, rows: &mut Vec<(&'static str, Vec<Span>)>) {
        let lossy = if self.lossy_files > 0 {
            format!(
                " ({} decoded with replacement characters)",
                self.lossy_files
            )
        } else {
            String::new()
        };
        rows.push((
            "Coverage",
            vec![Span::plain(format!(
                "{} text file(s) reviewed{lossy} · {} binary file(s) hashed only · {} oversized text file(s) skipped",
                self.text_files_reviewed,
                self.snapshot.count(FileKind::Binary),
                self.oversized_count()
            ))],
        ));

        for skipped in self.snapshot.skipped() {
            rows.push((
                "Not reviewed",
                vec![Span::new(
                    format!(
                        "{}/ ({} entries, generated); rerun with --thorough to include it",
                        shown(&skipped.path),
                        skipped.files
                    ),
                    "33",
                )],
            ));
        }

        let files = self.snapshot.files();
        if !files.is_empty() {
            let mut spans = vec![Span::plain(format!(
                "SHA-256 manifest ({} file(s) hashed)",
                files.len()
            ))];
            spans.push(Span::whole(
                self.snapshot.manifest_digest().to_string(),
                "36",
            ));
            rows.push(("Integrity", spans));
        }

        let withheld = self.withheld_count();
        if withheld > 0 {
            rows.push((
                "Privacy",
                vec![Span::plain(format!(
                    "{withheld} sensitive-looking file(s) withheld from the OpenCode provider"
                ))],
            ));
        }
    }

    /// One line per file, to copy or compare line by line.
    fn print_hashes(&self) {
        outln!("\nPer-file SHA-256:");
        for file in self.snapshot.files() {
            let kind = match file.kind {
                FileKind::Text => "reviewed-text",
                FileKind::Symlink => "symlink",
                FileKind::Binary | FileKind::OversizedText => "hash-only",
                FileKind::Undecodable => "undecodable",
            };
            outln!("  {}  {kind}  {}", file.sha256, shown(&file.path));
        }
    }

    fn inventory_fields(&self, rows: &mut Vec<(&'static str, Vec<Span>)>) {
        if !self.network.is_empty() {
            let mut endpoints = self.network.clone();
            endpoints.sort();
            endpoints.dedup();
            let mut spans = vec![Span::plain(format!(
                "{} destination(s) observed",
                endpoints.len()
            ))];
            for endpoint in endpoints.iter().take(20) {
                spans.push(Span::new(
                    format!(
                        "{}:{} → {}://{}",
                        shown(&endpoint.path),
                        endpoint.line,
                        endpoint.scheme.as_str(),
                        shown(&endpoint.host)
                    ),
                    "36",
                ));
            }
            if endpoints.len() > 20 {
                spans.push(Span::new(
                    format!("… and {} more endpoint(s)", endpoints.len() - 20),
                    "2",
                ));
            }
            rows.push(("Network", spans));
        }

        let lockfiles = self.dependencies.lockfile_count();
        if lockfiles == 0 {
            return;
        }
        let packages = self.dependencies.packages().len();
        let text = if packages == 0 {
            format!("{lockfiles} lockfile(s) parsed; no registry packages found")
        } else {
            let (status, advisories) = match &self.audit {
                Some(audit) => ("checked against OSV", audit.advisories.len()),
                None => ("OSV audit incomplete", 0),
            };
            format!(
                "{packages} locked package/version(s) · {lockfiles} lockfile(s) · {status} · {advisories} known vulnerability advisory(ies)"
            )
        };
        rows.push(("Dependencies", vec![Span::plain(text)]));
    }

    fn agent_fields(&self, rows: &mut Vec<(&'static str, Vec<Span>)>) {
        if self.agent_input_overflowed {
            rows.push((
                "AI review",
                vec![Span::new(
                    "not run — source exceeds the AI input limit",
                    "33;1",
                )],
            ));
        }
        for run in &self.agent_runs {
            let mut context = String::new();
            if let Some((index, count)) = run.chunk {
                let _ = write!(context, " · chunk {index}/{count}");
            }
            if let Some(note) = &run.cached {
                let _ = write!(context, " · {note}");
            }
            let about = Span::new(
                format!("{}{context} · profile {}", run.label, self.profile),
                "2",
            );
            let spans = match &run.outcome {
                AgentOutcome::Reviewed(review) => {
                    let (mark, color) = match review.status {
                        Status::Clear => ("✓", "32"),
                        Status::Suspicious => ("✗", "31;1"),
                        Status::Inconclusive => ("!", "33;1"),
                    };
                    vec![
                        Span::new(format!("{mark} {}", review.status.label()), color),
                        about,
                        Span::plain(shown(&review.summary)),
                    ]
                }
                AgentOutcome::Unavailable(error) => vec![
                    Span::new("! UNAVAILABLE", "33;1"),
                    about,
                    Span::plain(shown(&error.to_string())),
                ],
            };
            rows.push(("AI review", spans));
        }
    }

    fn print_findings(&self, width: usize, painter: Painter) {
        let severity = |severity: Severity| vec![Span::new(severity.label(), severity.color())];
        if !self.findings.is_empty() {
            let mut table = Table::new(vec!["Severity", "Where", "Local check"]);
            for finding in &self.findings {
                let mut what = vec![
                    Span::new(finding.rule.name(), "1"),
                    Span::plain(finding.rule.description()),
                ];
                if !finding.excerpt.is_empty() {
                    what.push(Span::new(shown(&finding.excerpt), "2"));
                }
                table.row(vec![
                    severity(finding.rule.severity()),
                    vec![Span::plain(format!(
                        "{}:{}",
                        shown(&finding.path),
                        finding.line
                    ))],
                    what,
                ]);
            }
            outln!("\n{}", painter.paint("  Local checks", "1"));
            outln!("{}", table.render(width, 2, painter));
        }

        let mut table = Table::new(vec!["Severity", "Where", "AI finding"]);
        let mut any = false;
        for run in &self.agent_runs {
            let AgentOutcome::Reviewed(review) = &run.outcome else {
                continue;
            };
            for finding in &review.findings {
                any = true;
                let line = finding
                    .line
                    .map(|line| format!(":{line}"))
                    .unwrap_or_default();
                table.row(vec![
                    severity(finding.severity),
                    vec![Span::plain(format!("{}{line}", shown(&finding.file)))],
                    vec![
                        Span::new(shown(&finding.title), "1"),
                        Span::plain(shown(&finding.reason)),
                    ],
                ]);
            }
        }
        if any {
            outln!("\n{}", painter.paint("  AI findings", "1"));
            outln!("{}", table.render(width, 2, painter));
        }

        if let Some(audit) = self
            .audit
            .as_ref()
            .filter(|audit| !audit.advisories.is_empty())
        {
            let mut table = Table::new(vec!["Severity", "Package", "Advisory"]);
            for advisory in &audit.advisories {
                let (label, color) = advisory.severity.map_or(("UNRATED", "36;1"), |severity| {
                    (severity.label(), severity.color())
                });
                let mut what = vec![Span::new(
                    format!("{} ({})", shown(&advisory.id), shown(&advisory.lockfile)),
                    "1",
                )];
                if let Some(summary) = &advisory.summary {
                    what.push(Span::plain(shown(summary)));
                }
                table.row(vec![
                    vec![Span::new(label, color)],
                    vec![Span::plain(format!(
                        "{}@{}",
                        shown(&advisory.package),
                        shown(&advisory.version)
                    ))],
                    what,
                ]);
            }
            outln!(
                "\n{}",
                painter.paint("  Known dependency vulnerabilities", "1")
            );
            outln!("{}", table.render(width, 2, painter));
            if audit.truncated {
                outln!("  … OSV reported more advisories than it returned in one page");
            }
        }
    }
}

/// Said under a report that a permit let through.
const PERMITTED_ADVICE: &str = "Proceeding on your permit: the review did not clear this content, you did. \
The permit ends on its own and covers only these exact bytes.";

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
mod tests {
    use super::{AgentOutcome, AgentRun, Blocked, Decision, Gap, LocalFinding, Report};
    use crate::agent::{AgentFinding, AgentReview, Status};
    use crate::config::model::{Profile, SourceClass, builtin};
    use crate::error::Error;
    use crate::layout::Painter;
    use crate::osv::{Advisory, Audit};
    use crate::report::Severity;
    use crate::rules::RuleId;

    fn standard(class: SourceClass) -> crate::config::model::Policy {
        builtin(Profile::Standard, class)
    }

    #[test]
    fn a_permitted_report_says_so_and_names_what_it_overruled() {
        let mut report = Report::new("theme:demo");
        report.gaps.push(Gap::Undecodable("install.sh".into()));
        let blocked = Decision::Blocked(Blocked::Incomplete);
        assert!(report.headline(blocked).0.contains("INCOMPLETE"));
        assert_eq!(blocked.exit_status(), 2);

        report.permit = Some("0123456789abcdef".into());
        let (headline, _) = report.headline(blocked);
        assert!(headline.contains("PERMITTED"), "{headline}");
        assert!(
            headline.contains("permit 0123456789abcdef overrules INCOMPLETE"),
            "{headline}"
        );
        // A permit says nothing about a review that passed on its own.
        assert!(report.headline(Decision::Clear).0.contains("CLEAR"));
        // The decision itself is what it was: only the gate goes on.
        assert_eq!(report.decision_name(blocked), "INCOMPLETE");
    }

    #[test]
    fn a_permit_needs_every_gap_to_be_about_hashed_content() {
        let refused = || Error::Refused("x".into());
        for gap in [
            Gap::OversizedText("x".into()),
            Gap::UnresolvedLfs("x".into()),
            Gap::SensitiveWithheld("x".into()),
            Gap::AgentInputTooLarge,
            Gap::EntryPointTooLarge("x".into()),
            Gap::Undecodable("x".into()),
            Gap::NoReviewableFiles,
            Gap::Agent(refused()),
            Gap::Dependency("x".into()),
            Gap::RunsUnread("x".into()),
        ] {
            assert!(gap.content_hashed(), "{gap}");
        }
        for gap in [
            Gap::Io(refused()),
            Gap::Symlink("x".into()),
            Gap::SpecialFile("x".into()),
            Gap::NonUtf8Name("x".into()),
            Gap::HashLimit("x".into()),
            Gap::GitState("x".into()),
            Gap::RootOnly("x".into()),
            Gap::Sweep("x".into()),
            Gap::TreeTooLarge { files: 1, bytes: 1 },
            Gap::Package(refused()),
        ] {
            assert!(!gap.content_hashed(), "{gap}");
            let mut report = Report::new("x");
            report.gaps.push(Gap::NoReviewableFiles);
            assert!(report.content_hashed());
            report.gaps.push(gap);
            assert!(!report.content_hashed());
        }
    }

    #[test]
    fn the_audit_trail_gets_numbers_and_the_user_gets_the_reasons() {
        let mut report = Report::new("x");
        assert_eq!(report.audit_ai(), "none");
        assert_eq!(
            report.audit_findings(),
            "high=0 medium=0 low=0 incomplete=0"
        );
        report.agent_runs.push(reviewed(Status::Clear, &["a"]));
        let mut suspicious = reviewed(Status::Suspicious, &["b"]);
        suspicious.cached = Some("from cache: 1 day old".into());
        report.agent_runs.push(suspicious);
        report.agent_runs.push(AgentRun {
            files: vec!["c".into()],
            label: "m · high".into(),
            chunk: None,
            cached: None,
            outcome: AgentOutcome::Unavailable(Error::Refused("no network".into())),
        });
        assert_eq!(
            report.audit_ai(),
            "m · high chunks=3 clear=1 suspicious=1 inconclusive=0 unavailable=1 from-cache=1"
        );
        report.findings.push(LocalFinding {
            path: "install.sh".into(),
            line: 3,
            rule: RuleId::DownloadAndExecute,
            excerpt: "curl x | sh".into(),
        });
        report.gaps.push(Gap::Undecodable("blob".into()));
        let summary = report.overruled_summary(10);
        assert!(
            summary[0].ends_with("install.sh:3 download-and-execute"),
            "{summary:?}"
        );
        assert!(summary.iter().any(|line| line == "AI review: SUSPICIOUS"));
        assert!(
            summary
                .iter()
                .any(|line| line.starts_with("AI review unavailable"))
        );
        assert!(
            summary
                .iter()
                .any(|line| line.starts_with("not reviewed: blob"))
        );
        // Bounded, and it says what it left out.
        assert_eq!(report.overruled_summary(2).len(), 3);
        assert_eq!(report.overruled_summary(2)[2], "and 2 more");
    }

    fn reviewed(status: Status, files: &[&str]) -> AgentRun {
        AgentRun {
            files: files.iter().map(ToString::to_string).collect(),
            label: "m · high".into(),
            chunk: None,
            cached: None,
            outcome: AgentOutcome::Reviewed(AgentReview {
                status,
                summary: "summary".into(),
                findings: Vec::new(),
            }),
        }
    }

    fn unavailable(files: &[&str]) -> AgentRun {
        AgentRun {
            files: files.iter().map(ToString::to_string).collect(),
            label: "m · high".into(),
            chunk: None,
            cached: None,
            outcome: AgentOutcome::Unavailable(Error::Refused("provider down".into())),
        }
    }

    fn finding(path: &str) -> LocalFinding {
        LocalFinding {
            path: path.into(),
            line: 1,
            rule: RuleId::PrivilegeEscalation,
            excerpt: String::new(),
        }
    }

    fn report(class: SourceClass) -> Report {
        Report {
            class,
            text_files_reviewed: 1,
            ..Report::default()
        }
    }

    #[test]
    fn an_empty_scriptlet_review_is_limited() {
        assert_eq!(Report::default().decide(&standard), Decision::Limited);
    }

    #[test]
    fn a_clean_review_is_clear() {
        let mut report = report(SourceClass::Aur);
        report
            .agent_runs
            .push(reviewed(Status::Clear, &["PKGBUILD"]));
        assert_eq!(report.decide(&standard), Decision::Clear);
    }

    #[test]
    fn official_proceeds_when_ai_is_unavailable_under_standard() {
        let mut official = report(SourceClass::Official);
        official.agent_runs.push(unavailable(&["a/.INSTALL"]));
        assert_eq!(official.decide(&standard), Decision::Warned);

        let mut aur = report(SourceClass::Aur);
        aur.agent_runs.push(unavailable(&["PKGBUILD"]));
        assert_eq!(
            aur.decide(&standard),
            Decision::Blocked(Blocked::AiUnavailable)
        );
    }

    #[test]
    fn local_findings_follow_on_findings() {
        let mut official = report(SourceClass::Official);
        official.findings.push(finding("a/.INSTALL"));
        official
            .agent_runs
            .push(reviewed(Status::Clear, &["a/.INSTALL"]));
        assert_eq!(official.decide(&standard), Decision::Warned);

        let mut theme = report(SourceClass::Theme);
        theme.findings.push(finding("hyprland.lua"));
        theme
            .agent_runs
            .push(reviewed(Status::Clear, &["hyprland.lua"]));
        assert_eq!(
            theme.decide(&standard),
            Decision::Blocked(Blocked::Findings)
        );
    }

    #[test]
    fn ai_suspicion_blocks_official_under_standard() {
        let mut official = report(SourceClass::Official);
        official
            .agent_runs
            .push(reviewed(Status::Suspicious, &["a/.INSTALL"]));
        assert_eq!(
            official.decide(&standard),
            Decision::Blocked(Blocked::Findings)
        );
    }

    #[test]
    fn inconclusive_and_gaps_are_incomplete_in_every_profile() {
        let lenient = |class| builtin(Profile::LocalOnly, class);

        let mut inconclusive = report(SourceClass::Official);
        inconclusive
            .agent_runs
            .push(reviewed(Status::Inconclusive, &["a"]));
        assert_eq!(
            inconclusive.decide(&lenient),
            Decision::Blocked(Blocked::Incomplete)
        );

        let mut gap = report(SourceClass::Official);
        gap.gaps.push(Gap::NoReviewableFiles);
        assert_eq!(gap.decide(&lenient), Decision::Blocked(Blocked::Incomplete));
    }

    #[test]
    fn findings_are_attributed_to_their_files_class() {
        let mut mixed = report(SourceClass::ThirdPartyRepo);
        mixed
            .file_classes
            .insert("core-pkg/.INSTALL".into(), SourceClass::Official);
        mixed
            .file_classes
            .insert("chaotic-pkg/.INSTALL".into(), SourceClass::ThirdPartyRepo);

        let mut run = reviewed(
            Status::Suspicious,
            &["core-pkg/.INSTALL", "chaotic-pkg/.INSTALL"],
        );
        if let AgentOutcome::Reviewed(review) = &mut run.outcome {
            review.findings.push(AgentFinding {
                severity: Severity::Medium,
                file: "core-pkg/.INSTALL".into(),
                line: None,
                title: "t".into(),
                reason: "r".into(),
            });
        }
        mixed.agent_runs.push(run);

        // Only the official file was named, and official blocks on AI
        // suspicion under standard too, so this blocks either way; with a
        // warn policy for official it must only warn.
        let warn_official = |class| {
            let mut policy = standard(class);
            if class == SourceClass::Official {
                policy.on_ai_suspicious = crate::config::model::Action::Warn;
            }
            policy
        };
        assert_eq!(mixed.decide(&warn_official), Decision::Warned);
        assert_eq!(
            mixed.decide(&standard),
            Decision::Blocked(Blocked::Findings)
        );
    }

    #[test]
    fn a_finding_naming_another_chunks_file_applies_that_files_class_too() {
        let mut mixed = report(SourceClass::ThirdPartyRepo);
        mixed
            .file_classes
            .insert("core-pkg/.INSTALL".into(), SourceClass::Official);
        mixed
            .file_classes
            .insert("chaotic-pkg/.INSTALL".into(), SourceClass::ThirdPartyRepo);

        // This run's own files are only the third-party one; a chunk sees
        // the whole manifest, so its finding can still name a file that
        // belongs to a different chunk (and class) entirely.
        let mut run = reviewed(Status::Suspicious, &["chaotic-pkg/.INSTALL"]);
        if let AgentOutcome::Reviewed(review) = &mut run.outcome {
            review.findings.push(AgentFinding {
                severity: Severity::Medium,
                file: "core-pkg/.INSTALL".into(),
                line: None,
                title: "t".into(),
                reason: "r".into(),
            });
        }
        mixed.agent_runs.push(run);

        // Third-party (the run's own class) is lenient here; official (the
        // named file's own class) keeps standard's block. Both classes'
        // policies must be applied, so the named file's stricter class
        // still blocks even though the run's own class would only warn.
        let lenient_third_party = |class| {
            let mut policy = standard(class);
            if class == SourceClass::ThirdPartyRepo {
                policy.on_ai_suspicious = crate::config::model::Action::Warn;
            }
            policy
        };
        assert_eq!(
            mixed.decide(&lenient_third_party),
            Decision::Blocked(Blocked::Findings)
        );
    }

    #[test]
    fn advisories_follow_the_reports_class() {
        let mut aur = report(SourceClass::Aur);
        aur.agent_runs
            .push(reviewed(Status::Clear, &["Cargo.lock"]));
        aur.audit = Some(Audit {
            advisories: vec![Advisory {
                id: "GHSA-x".into(),
                package: "p".into(),
                version: "1".into(),
                lockfile: "Cargo.lock".into(),
                severity: None,
                summary: None,
            }],
            truncated: false,
        });
        assert_eq!(aur.decide(&standard), Decision::Blocked(Blocked::Findings));
        assert_eq!(aur.counts().medium, 1);
    }

    #[test]
    fn decisions_map_to_exit_codes() {
        use std::process::ExitCode;
        assert_eq!(Decision::Clear.exit_code(), ExitCode::SUCCESS);
        assert_eq!(Decision::Warned.exit_code(), ExitCode::SUCCESS);
        assert_eq!(Decision::Limited.exit_code(), ExitCode::SUCCESS);
        assert_eq!(
            Decision::Blocked(Blocked::Findings).exit_code(),
            ExitCode::from(1)
        );
        for blocked in [
            Blocked::Incomplete,
            Blocked::AiUnavailable,
            Blocked::NotConfirmed,
        ] {
            assert_eq!(Decision::Blocked(blocked).exit_code(), ExitCode::from(2));
        }
        assert!(Decision::Warned.allows_running());
        assert!(!Decision::Limited.allows_running());
    }

    #[test]
    fn colors_can_be_disabled() {
        assert_eq!(Painter::plain().paint("CLEAR", "32"), "CLEAR");
        assert_eq!(
            Painter::colored().paint("CLEAR", "32"),
            "\x1b[32mCLEAR\x1b[0m"
        );
    }
}
