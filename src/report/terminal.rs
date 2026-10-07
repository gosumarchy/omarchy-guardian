//! The report as the terminal shows it: the verdict box, the coverage,
//! inventory and reviewer fields, and the findings.

use std::fmt::Write as _;

use crate::agent::Status;
use crate::layout::{self, Painter, Span, Table};
use crate::scan::FileKind;
use crate::text::shown;

use super::{AgentOutcome, Blocked, Decision, Report, Severity, html, recommendation};

/// What the remarks are, after their count in the verdict box: for a
/// review that is clear, and for one that is not (something else decided
/// it: another chunk, a local rule, a gap).
const fn remarks_are(decision: Decision) -> &'static str {
    match decision {
        Decision::Clear => "the AI review is clear; these are not alerts",
        Decision::Warned | Decision::Limited | Decision::Blocked(_) => {
            "from parts the AI review judged clear; they did not decide this"
        }
    }
}

/// Said above the remarks, for the same two cases.
pub(super) const fn remarks_note(decision: Decision) -> &'static str {
    match decision {
        Decision::Clear => {
            "The AI review is clear; it noted these all the same. They do not block."
        }
        Decision::Warned | Decision::Limited | Decision::Blocked(_) => {
            "From the parts the AI review judged clear. They did not decide this review."
        }
    }
}

impl Report {
    pub(crate) fn print(&self, show_hashes: bool, decision: Decision) {
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
        out!("{}", self.findings_text(decision, width, painter));

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
    pub(super) fn headline(&self, decision: Decision) -> (String, &'static str) {
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
            Decision::Clear if self.remark_count() > 0 => (
                format!(
                    "✓ CLEAR — no known concerns found; the AI reviewer left {} remark(s)",
                    self.remark_count()
                ),
                "32",
            ),
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

    /// The verdict, and the counts of alerts and of remarks when there are
    /// any, in a box the verdict's colour.
    pub(super) fn verdict_box(&self, decision: Decision, width: usize, painter: Painter) -> String {
        let counts = self.counts();
        let (headline, color) = self.headline(decision);
        let mut lines = vec![Span::new(headline, color)];
        if counts.total() > 0 {
            lines.push(Span::plain(format!(
                "Alerts: {} high · {} medium · {} low",
                counts.high, counts.medium, counts.low
            )));
        }
        let remarks = self.remark_count();
        if remarks > 0 {
            lines.push(Span::plain(format!(
                "Remarks: {remarks} low · {}",
                remarks_are(decision)
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

    /// The tables of what was found: the local checks, the AI's findings,
    /// its remarks and the dependency advisories, each under its title.
    pub(super) fn findings_text(
        &self,
        decision: Decision,
        width: usize,
        painter: Painter,
    ) -> String {
        let mut text = String::new();
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
            let _ = writeln!(text, "\n{}", painter.paint("  Local checks", "1"));
            let _ = writeln!(text, "{}", table.render(width, 2, painter));
        }

        // The remarks of a clear verdict have a table of their own, so
        // that none reads as an alert.
        for (remarks, title, column) in [
            (false, "  AI findings", "AI finding"),
            (true, "  AI remarks", "AI remark"),
        ] {
            let mut table = Table::new(vec!["Severity", "Where", column]);
            let mut any = false;
            for finding in self.agent_findings(remarks) {
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
            if any {
                let _ = writeln!(text, "\n{}", painter.paint(title, "1"));
                if remarks {
                    let _ = writeln!(text, "  {}", painter.paint(remarks_note(decision), "2"));
                }
                let _ = writeln!(text, "{}", table.render(width, 2, painter));
            }
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
            let _ = writeln!(
                text,
                "\n{}",
                painter.paint("  Known dependency vulnerabilities", "1")
            );
            let _ = writeln!(text, "{}", table.render(width, 2, painter));
            if audit.truncated {
                text.push_str("  … OSV reported more advisories than it returned in one page\n");
            }
        }
        text
    }
}

/// Said under a report that a permit let through.
const PERMITTED_ADVICE: &str = "Proceeding on your permit: the review did not clear this content, you did. \
The permit ends on its own and covers only these exact bytes.";
