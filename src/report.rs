//! Review results, the decision derived from them against a per-class
//! policy, and their terminal rendering.

use std::collections::HashMap;
use std::env;
use std::fmt::{self, Write as _};
use std::io::{self, IsTerminal};
use std::process::ExitCode;

use crate::agent::{AgentReview, SourceFile, Status};
use crate::config::model::{Action, AiRequirement, Policy, SourceClass};
use crate::deps::Inventory;
use crate::error::Error;
use crate::osv::Audit;
use crate::rules::{RuleId, Scheme};
use crate::scan::{FileKind, Snapshot};

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
    NoReviewableFiles,
    Agent(Error),
    Dependency(String),
    Package(Error),
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
            Self::AgentInputTooLarge => {
                f.write_str("source exceeds the AI review input limit (max_input_kib × max_chunks)")
            }
            Self::NoReviewableFiles => {
                f.write_str("no readable text source files were available for review")
            }
            Self::Agent(error) => write!(f, "OpenCode review failed: {error}"),
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
        match self {
            Self::Clear | Self::Warned | Self::Limited => ExitCode::SUCCESS,
            Self::Blocked(Blocked::Findings) => ExitCode::from(1),
            Self::Blocked(Blocked::Incomplete | Blocked::AiUnavailable | Blocked::NotConfirmed) => {
                ExitCode::from(2)
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
        } else if tally.warned {
            Decision::Warned
        } else if self.text_files_reviewed == 0 && self.agent_runs.is_empty() {
            Decision::Limited
        } else {
            Decision::Clear
        }
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

        println!("Omarchy Guardian  ·  {}", self.subject);
        self.print_headline(decision, painter);
        self.print_coverage(show_hashes, painter);
        for note in &self.notes {
            println!("Review memory: {note}");
        }
        self.print_inventory();
        self.print_agent_summary(painter);
        self.print_findings(decision, painter);

        for gap in &self.gaps {
            eprintln!("  ! {gap}");
        }
        println!(
            "\n{}",
            match decision {
                Decision::Blocked(Blocked::Findings) => {
                    "Recommendation: do not install or run this source until findings are resolved."
                }
                Decision::Blocked(Blocked::Incomplete) => {
                    "Recommendation: do not proceed; complete the review first."
                }
                Decision::Blocked(Blocked::AiUnavailable) => {
                    "Recommendation: fix the OpenCode setup (see `omarchy-guardian setup`) and retry."
                }
                Decision::Blocked(Blocked::NotConfirmed) => "Not confirmed; nothing was run.",
                Decision::Warned => "Proceeding with warnings; read them above.",
                Decision::Limited => {
                    "Scope: package payloads were not inspected by this scriptlet-only review."
                }
                Decision::Clear =>
                    "Scope: this is a heuristic source review, not a safety guarantee.",
            }
        );
    }

    fn print_headline(&self, decision: Decision, painter: Painter) {
        let counts = self.counts();
        let total = counts.total();
        let (headline, color) = match decision {
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
                "· LIMITED REVIEW — no text install scripts were available".to_string(),
                "36;1",
            ),
        };
        println!("{}", painter.paint(&headline, color));

        if total > 0 {
            println!(
                "Alerts: {} high · {} medium · {} low",
                painter.paint(
                    &counts.high.to_string(),
                    if counts.high > 0 { "31;1" } else { "2" }
                ),
                painter.paint(
                    &counts.medium.to_string(),
                    if counts.medium > 0 { "33;1" } else { "2" }
                ),
                painter.paint(
                    &counts.low.to_string(),
                    if counts.low > 0 { "36;1" } else { "2" }
                ),
            );
        }
    }

    fn print_coverage(&self, show_hashes: bool, painter: Painter) {
        println!(
            "Coverage: {} text file(s) reviewed · {} binary file(s) hashed only · {} oversized text file(s) skipped",
            self.text_files_reviewed,
            self.snapshot.count(FileKind::Binary),
            self.oversized_count()
        );

        let files = self.snapshot.files();
        if !files.is_empty() {
            println!(
                "Integrity: SHA-256 manifest {} ({} file(s) hashed)",
                painter.paint(&self.snapshot.manifest_digest().to_string(), "36"),
                files.len(),
            );
            if show_hashes {
                println!("Per-file SHA-256:");
                for file in files {
                    let kind = if file.kind == FileKind::Text {
                        "reviewed-text"
                    } else {
                        "hash-only"
                    };
                    println!("  {}  {kind}  {}", file.sha256, file.path);
                }
            }
        }

        let withheld = self.withheld_count();
        if withheld > 0 {
            println!(
                "Privacy: {withheld} sensitive-looking file(s) withheld from the OpenCode provider"
            );
        }
    }

    fn print_inventory(&self) {
        if !self.network.is_empty() {
            let mut endpoints = self.network.clone();
            endpoints.sort();
            endpoints.dedup();
            println!("Network destinations observed: {}", endpoints.len());
            for endpoint in endpoints.iter().take(20) {
                println!(
                    "  {}:{} → {}://{}",
                    endpoint.path,
                    endpoint.line,
                    endpoint.scheme.as_str(),
                    endpoint.host
                );
            }
            if endpoints.len() > 20 {
                println!("  … and {} more endpoint(s)", endpoints.len() - 20);
            }
        }

        let lockfiles = self.dependencies.lockfile_count();
        if lockfiles == 0 {
            return;
        }
        let packages = self.dependencies.packages().len();
        if packages == 0 {
            println!("Dependencies: {lockfiles} lockfile(s) parsed; no registry packages found");
            return;
        }
        let (status, advisories) = match &self.audit {
            Some(audit) => ("checked against OSV", audit.advisories.len()),
            None => ("OSV audit incomplete", 0),
        };
        println!(
            "Dependencies: {packages} locked package/version(s) · {lockfiles} lockfile(s) · {status} · {advisories} known vulnerability advisory(ies)"
        );
    }

    fn print_agent_summary(&self, painter: Painter) {
        if self.agent_input_overflowed {
            println!("OpenCode review: not run — source exceeds the AI input limit");
        }
        for run in &self.agent_runs {
            let mut context = String::new();
            if let Some((index, count)) = run.chunk {
                let _ = write!(context, " · chunk {index}/{count}");
            }
            if let Some(note) = &run.cached {
                let _ = write!(context, " · {note}");
            }

            match &run.outcome {
                AgentOutcome::Reviewed(review) => {
                    let color = match review.status {
                        Status::Clear => "32",
                        Status::Suspicious => "31;1",
                        Status::Inconclusive => "33;1",
                    };
                    println!(
                        "OpenCode: {} · {}{context} · profile {} — {}",
                        painter.paint(review.status.label(), color),
                        run.label,
                        self.profile,
                        review.summary
                    );
                }
                AgentOutcome::Unavailable(error) => println!(
                    "OpenCode: {} · {}{context} · profile {} — {error}",
                    painter.paint("UNAVAILABLE", "33;1"),
                    run.label,
                    self.profile
                ),
            }
        }
    }

    fn print_findings(&self, decision: Decision, painter: Painter) {
        if self.findings.is_empty() {
            if decision != Decision::Limited {
                println!("Local checks: no matches");
            }
        } else {
            println!("\nLocal checks:");
            for finding in &self.findings {
                let severity = finding.rule.severity();
                println!(
                    "  [{}] {}:{} — {}",
                    painter.paint(severity.label(), severity.color()),
                    finding.path,
                    finding.line,
                    finding.rule.name()
                );
                println!("       {}", finding.rule.description());
                if !finding.excerpt.is_empty() {
                    println!("       {}", finding.excerpt);
                }
            }
        }

        let mut findings_heading_printed = false;
        for run in &self.agent_runs {
            let AgentOutcome::Reviewed(review) = &run.outcome else {
                continue;
            };
            for finding in &review.findings {
                if !findings_heading_printed {
                    println!("\nOpenCode findings:");
                    findings_heading_printed = true;
                }
                let line = finding
                    .line
                    .map(|line| format!(":{line}"))
                    .unwrap_or_default();
                println!(
                    "  [{}] {}{line} — {}",
                    painter.paint(finding.severity.label(), finding.severity.color()),
                    finding.file,
                    finding.title
                );
                println!("       {}", finding.reason);
            }
        }

        if let Some(audit) = self
            .audit
            .as_ref()
            .filter(|audit| !audit.advisories.is_empty())
        {
            println!("\nKnown dependency vulnerabilities:");
            for advisory in &audit.advisories {
                let (label, color) = advisory.severity.map_or(("UNRATED", "36;1"), |severity| {
                    (severity.label(), severity.color())
                });
                println!(
                    "  [{}] {}@{} — {} ({})",
                    painter.paint(label, color),
                    advisory.package,
                    advisory.version,
                    advisory.id,
                    advisory.lockfile
                );
                if let Some(summary) = &advisory.summary {
                    println!("       {summary}");
                }
            }
            if audit.truncated {
                println!("  … OSV reported more advisories than it returned in one page");
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Painter {
    enabled: bool,
}

impl Painter {
    fn for_stdout() -> Self {
        Self {
            enabled: io::stdout().is_terminal()
                && env::var_os("NO_COLOR").is_none_or(|value| value.is_empty())
                && env::var("TERM").is_ok_and(|term| term != "dumb"),
        }
    }

    fn paint(self, text: &str, color: &str) -> String {
        if self.enabled {
            format!("\x1b[{color}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AgentOutcome, AgentRun, Blocked, Decision, Gap, LocalFinding, Painter, Report};
    use crate::agent::{AgentFinding, AgentReview, Status};
    use crate::config::model::{Profile, SourceClass, builtin};
    use crate::error::Error;
    use crate::osv::{Advisory, Audit};
    use crate::report::Severity;
    use crate::rules::RuleId;

    fn standard(class: SourceClass) -> crate::config::model::Policy {
        builtin(Profile::Standard, class)
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
        assert_eq!(Painter { enabled: false }.paint("CLEAR", "32"), "CLEAR");
        assert_eq!(
            Painter { enabled: true }.paint("CLEAR", "32"),
            "\x1b[32mCLEAR\x1b[0m"
        );
    }
}
