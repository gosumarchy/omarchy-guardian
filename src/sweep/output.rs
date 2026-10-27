//! How a sweep is shown: a summary, then a table of what isn't trusted for
//! each area, before the usual report of the review; or one JSON document.

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;

use super::collect::{Body, Collection, Item, Origin};
use super::judge::label;
use super::tier::Tier;
use crate::agent::Status;
use crate::json::Json;
use crate::layout::{self, Painter, Span, Table};
use crate::report::html::{self, esc};
use crate::report::{AgentOutcome, AgentRun, Blocked, Decision, Gap, Report, Severity};
use crate::text::shown;

/// A tier's word in the list and its colour.
const fn tier_style(tier: Tier) -> (&'static str, &'static str) {
    match tier {
        Tier::Vendor => ("package", "32"),
        Tier::Inert => ("inert", "2"),
        Tier::Copied => ("copy", "2"),
        Tier::UserBuilt => ("user-built", "34"),
        Tier::Edited => ("edited", "36"),
        Tier::Modified => ("MODIFIED", "31;1"),
        Tier::Allowed => ("allowed", "32"),
        Tier::Unknown => ("unknown", "33"),
    }
}

/// What a tier means, for the legend.
const fn tier_meaning(tier: Tier) -> &'static str {
    match tier {
        Tier::Vendor => "installed by a repository package, unchanged",
        Tier::Inert => "does nothing (empty, or masked)",
        Tier::Copied => "identical to a file a repository package ships",
        Tier::UserBuilt => "installed by an AUR or local package, unchanged",
        Tier::Edited => "a package's config file that was edited",
        Tier::Modified => "a package's file that no longer matches what it installed",
        Tier::Allowed => "you allowed it as it is",
        Tier::Unknown => "no package installed it",
    }
}

/// The paths the local rules or the AI flagged.
fn flagged(report: &Report) -> HashSet<String> {
    let mut paths: HashSet<String> = report
        .findings
        .iter()
        .map(|finding| finding.path.clone())
        .collect();
    for run in &report.agent_runs {
        if let AgentOutcome::Reviewed(review) = &run.outcome {
            paths.extend(review.findings.iter().map(|finding| finding.file.clone()));
        }
    }
    paths
}

/// How many items the summary lists by name; the rest are in the full
/// report. Arbitrary: about what one screen shows below the box.
const SHOWN_CONCERNS: usize = 10;

/// How many reasons the review is incomplete the summary lists.
/// Arbitrary, like `SHOWN_CONCERNS`.
const SHOWN_GAPS: usize = 3;

/// The trust bar and the item counts, for the verdict box.
fn trust_lines(collection: &Collection, flagged: usize) -> Vec<Span> {
    let total = collection.items.len();
    let trusted = collection
        .items
        .iter()
        .filter(|item| item.is_trusted())
        .count();
    let (filled, empty) = layout::bar(trusted, total, 40);
    let percent = (trusted * 100).checked_div(total).unwrap_or(100);
    vec![
        Span::plain(""),
        Span::new(format!("{filled}{empty}  {percent}% trusted"), "32"),
        Span::plain(format!(
            "{total} item(s) checked · {trusted} trusted · {} to look at · {flagged} flagged",
            total - trusted
        )),
    ]
}

/// The legend of the listed items: how many of each tier, and what the
/// tier means.
fn tier_legend(shown_items: &[&Item]) -> Vec<Span> {
    let mut by_tier: BTreeMap<Tier, usize> = BTreeMap::new();
    for item in shown_items {
        *by_tier.entry(item.tier).or_default() += 1;
    }
    by_tier
        .into_iter()
        .map(|(tier, count)| {
            let (word, color) = tier_style(tier);
            Span::new(
                format!("{count:>4}  {word:<10}  {}", tier_meaning(tier)),
                color,
            )
        })
        .collect()
}

/// What the review raised about one file: its worst alert, and how many
/// alerts there are in all.
#[derive(Debug)]
struct Concern {
    severity: Severity,
    why: String,
    alerts: usize,
}

/// The files the review raised alerts on (see `Report::alerts`), worst
/// first, one entry per file.
fn concerns(report: &Report) -> Vec<(String, Concern)> {
    let mut by_file: BTreeMap<String, Concern> = BTreeMap::new();
    for (file, severity, why) in report.alerts() {
        let concern = by_file.entry(file.to_string()).or_insert(Concern {
            severity,
            why: why.clone(),
            alerts: 0,
        });
        concern.alerts += 1;
        if severity < concern.severity {
            concern.severity = severity;
            concern.why = why;
        }
    }
    let mut concerns: Vec<(String, Concern)> = by_file.into_iter().collect();
    concerns.sort_by_key(|(_, concern)| concern.severity);
    concerns
}

/// Why the review is incomplete, one line each: what it could not read and
/// the AI reviews that did not run.
fn not_reviewed(report: &Report) -> Vec<String> {
    // A gap of the sweep's own is said without the "sweep: " its `Display`
    // starts with: under the sweep's summary that repeats what is said.
    let mut lines: Vec<String> = report
        .gaps
        .iter()
        .map(|gap| match gap {
            Gap::Sweep(text) => text.clone(),
            gap => gap.to_string(),
        })
        .collect();
    lines.extend(
        report
            .agent_runs
            .iter()
            .filter_map(unfinished)
            .map(|problem| format!("AI review: {problem}")),
    );
    lines.dedup();
    lines
}

/// The list below the verdict box: what needs a look, then why the review
/// is incomplete, each cut short with a count of the rest.
fn attention(report: &Report, painter: Painter) -> String {
    let mut text = String::new();
    let concerns = concerns(report);
    if !concerns.is_empty() {
        let _ = writeln!(text, "\n{}", painter.paint("Needs a look", "1"));
        // One plain line each: a table's borders and cut paths cost more
        // lines and hide the file name, which is what the reader needs.
        for (file, concern) in concerns.iter().take(SHOWN_CONCERNS) {
            let mut why = shown(&concern.why).into_owned();
            if concern.alerts > 1 {
                let _ = write!(why, " ({} alerts)", concern.alerts);
            }
            let _ = writeln!(
                text,
                "  {}  {}  {}",
                painter.paint(
                    &format!("{:<6}", concern.severity.label()),
                    concern.severity.color()
                ),
                shown(file),
                painter.paint(&why, "2")
            );
        }
        if concerns.len() > SHOWN_CONCERNS {
            let rest = concerns.len() - SHOWN_CONCERNS;
            let _ = writeln!(text, "  {}", painter.paint(&format!("… {rest} more"), "2"));
        }
    }
    let gaps = not_reviewed(report);
    if !gaps.is_empty() {
        let _ = writeln!(text, "\n{}", painter.paint("Not reviewed", "1"));
        for gap in gaps.iter().take(SHOWN_GAPS) {
            let _ = writeln!(
                text,
                "  {}",
                painter.paint(&format!("! {}", shown(gap)), "33")
            );
        }
        if gaps.len() > SHOWN_GAPS {
            let rest = gaps.len() - SHOWN_GAPS;
            let _ = writeln!(text, "  {}", painter.paint(&format!("… {rest} more"), "2"));
        }
    }
    text
}

/// The sweep's verdict lines and their colour. The alerts come first;
/// what could not be checked is a line of its own, so a sweep that found
/// alerts says so even when a part could not be checked. `decision` is the
/// report's, as for every gate, and alone decides whether the box is green:
/// an inconclusive AI review, or a suspicious one that names no finding,
/// has no alert to count and must not read as clear.
fn verdict_lines(report: &Report, decision: Decision) -> (Vec<Span>, &'static str) {
    let counts = report.counts();
    let total = counts.total();
    let (headline, color) = match (total, counts.high) {
        (0, _) if decision == Decision::Clear => ("✓ NO ALERTS".to_string(), "32"),
        (0, _) => ("! NO ALERTS COUNTED".to_string(), "33;1"),
        (_, 0) => (
            format!(
                "! {total} ALERT(S) — {} medium · {} low",
                counts.medium, counts.low
            ),
            "33;1",
        ),
        (_, high) => (
            format!(
                "✗ {total} ALERT(S) — {high} high · {} medium · {} low",
                counts.medium, counts.low
            ),
            "31;1",
        ),
    };
    let mut lines = vec![Span::new(headline, color)];
    let mut unchecked = Vec::new();
    if !report.gaps.is_empty() {
        unchecked.push(format!("{} part(s) not checked", report.gaps.len()));
    }
    let incomplete = report
        .agent_runs
        .iter()
        .filter(|run| unfinished(run).is_some())
        .count();
    if incomplete > 0 {
        unchecked.push(format!("{incomplete} AI request(s) did not complete"));
    }
    if !unchecked.is_empty() {
        lines.push(Span::new(
            format!("Not fully checked: {}", unchecked.join("; ")),
            "33",
        ));
    }
    let unnamed = report.agent_runs.iter().any(|run| {
        matches!(&run.outcome, AgentOutcome::Reviewed(review)
            if review.status == Status::Suspicious && review.findings.is_empty())
    });
    if unnamed {
        lines.push(Span::new(
            "The AI review found something suspicious; see sweep details",
            "33",
        ));
    }
    if decision == Decision::Warned {
        lines.push(Span::new("Allowed by policy", "2"));
    }
    // Clear means no alerts, so its headline is green; the edge takes a
    // plain colour code.
    let edge = match decision {
        Decision::Clear => "32",
        _ if counts.high > 0 => "31",
        _ => "33",
    };
    (lines, edge)
}

/// Why an AI request gave no full answer, for a run that gave none: it
/// failed, was never sent, or came back inconclusive.
fn unfinished(run: &AgentRun) -> Option<String> {
    match &run.outcome {
        AgentOutcome::Reviewed(review) if review.status == Status::Inconclusive => {
            Some(format!("inconclusive: {}", review.summary))
        }
        AgentOutcome::Reviewed(_) => None,
        outcome => outcome.problem(),
    }
}

/// The top of a sweep: the verdict with how much is trusted in one box,
/// then what needs a look and what was not reviewed. `changes` is how many
/// items changed since the last sweep, when that is asked for.
pub(super) fn summary(
    collection: &Collection,
    report: &Report,
    decision: Decision,
    home: Option<&str>,
    changes: Option<usize>,
) -> String {
    let painter = Painter::for_stdout();
    let width = layout::width();
    let flagged_paths = flagged(report);
    let flagged = collection
        .items
        .iter()
        .filter(|item| !item.is_trusted() && flagged_paths.contains(&label(item, home)))
        .count();
    let (mut lines, edge) = verdict_lines(report, decision);
    lines.extend(trust_lines(collection, flagged));
    match changes {
        Some(0) => lines.push(Span::new(
            "✓ nothing new or changed since the last sweep",
            "32",
        )),
        Some(count) => lines.push(Span::new(
            format!("{count} change(s) since the last sweep"),
            "33;1",
        )),
        None => {}
    }
    let title = format!("Omarchy Guardian · {}", shown(&report.subject));
    let boxed = layout::boxed(&title, &lines, width, edge, painter);
    format!("{boxed}\n{}", attention(report, painter))
}

/// A tier's colour on the report page.
const fn tier_tone(tier: Tier) -> &'static str {
    match tier {
        Tier::Vendor | Tier::Allowed => "green",
        Tier::Inert | Tier::Copied => "dim",
        Tier::UserBuilt | Tier::Edited => "cyan",
        Tier::Modified => "red",
        Tier::Unknown => "amber",
    }
}

/// The items for the report page: a table for each area.
fn items_html(
    groups: &BTreeMap<&'static str, Vec<&Item>>,
    home: Option<&str>,
    flagged: &HashSet<String>,
) -> String {
    let mut html = String::from("<section><hr><h3>What the sweep lists</h3>");
    if groups.is_empty() {
        html.push_str("<p class=\"dim\">Nothing to look at: every item is trusted.</p>");
    }
    for (heading, items) in groups {
        let when = items.first().map_or("", |item| item.category.when());
        let _ = write!(
            html,
            "<h3>{} <span class=\"dim small\">{}</span></h3><table><tr><th>Status</th><th>Item</th><th>Details</th></tr>",
            esc(heading),
            esc(when)
        );
        for item in items {
            let label = label(item, home);
            let (word, _) = tier_style(item.tier);
            let (word, tone) = if flagged.contains(&label) {
                (format!("✗ {word}"), "red")
            } else {
                (word.to_string(), tier_tone(item.tier))
            };
            let mut details = Vec::new();
            match &item.body {
                Body::Link(target) => details.push(format!("→ {}", esc(target))),
                Body::Binary(format) => details.push(format!("[{}]", esc(format))),
                Body::Unreadable(_) => details.push("[not readable]".to_string()),
                Body::Text(_) | Body::Undecodable | Body::Oversized | Body::Plugin(_) => {}
            }
            details.extend(
                item.runs
                    .iter()
                    .map(|command| format!("runs <code>{}</code>", esc(command))),
            );
            details.extend(item.notes.iter().map(|note| esc(note)));
            if item.origin == Origin::Root {
                details.push("read as root".to_string());
            }
            let _ = write!(
                html,
                "<tr><td class=\"{tone}\">{}</td><td><code>{}</code></td><td>{}</td></tr>",
                esc(&word),
                esc(&label),
                details.join("<br>")
            );
        }
        html.push_str("</table>");
    }
    html.push_str("</section>");
    html
}

/// One row of an area's table.
fn item_row(item: &Item, home: Option<&str>, flagged: &HashSet<String>) -> Vec<Vec<Span>> {
    let label = label(item, home);
    let (word, color) = tier_style(item.tier);
    let mut status = if flagged.contains(&label) {
        vec![Span::new(format!("✗ {word}"), "31;1")]
    } else {
        vec![Span::new(word, color)]
    };
    if item.origin == Origin::Root {
        status.push(Span::new("as root", "2"));
    }
    let mut details = Vec::new();
    match &item.body {
        Body::Link(target) => details.push(Span::new(format!("→ {}", shown(target)), "36")),
        Body::Binary(format) => details.push(Span::new(format!("[{format}]"), "35")),
        Body::Unreadable(_) => details.push(Span::new("[not readable]", "33")),
        Body::Text(_) | Body::Undecodable | Body::Oversized | Body::Plugin(_) => {}
    }
    for command in item.runs.iter().take(3) {
        details.push(Span::plain(format!("runs {}", shown(command))));
    }
    if item.runs.len() > 3 {
        details.push(Span::new(
            format!("… and {} more", item.runs.len() - 3),
            "2",
        ));
    }
    for note in &item.notes {
        details.push(Span::new(shown(note), "2"));
    }
    vec![status, vec![Span::plain(shown(&label))], details]
}

/// The legend, then a table of items for each area: what isn't trusted,
/// or with `all` every item.
pub(super) fn print(collection: &Collection, report: &Report, home: Option<&str>, all: bool) {
    let painter = Painter::for_stdout();
    let width = layout::width();
    let shown_items: Vec<&Item> = collection
        .items
        .iter()
        .filter(|item| all || !item.is_trusted())
        .collect();
    let flagged = flagged(report);
    let legend = tier_legend(&shown_items);
    if !legend.is_empty() {
        outln!();
        outln!("{}", layout::fields(&[("Listed", legend)], width, painter));
    }

    let mut groups: BTreeMap<&'static str, Vec<&Item>> = BTreeMap::new();
    for item in shown_items {
        groups.entry(item.category.label()).or_default().push(item);
    }
    html::collect_section(items_html(&groups, home, &flagged));
    let mut headings = Vec::new();
    let mut tables = Vec::new();
    for (heading, items) in groups {
        let when = items.first().map_or("", |item| item.category.when());
        headings.push(format!(
            "\n{} {}  {}",
            painter.paint("▌", "36"),
            painter.paint(heading, "1"),
            painter.paint(when, "2")
        ));
        let mut table = Table::new(vec!["Status", "Item", "Details"]);
        for item in items {
            table.row(item_row(item, home, &flagged));
        }
        tables.push(table);
    }
    // One width for every area's table, so they line up.
    for (heading, table) in headings
        .iter()
        .zip(Table::render_all(&tables, width, 2, painter))
    {
        outln!("{heading}");
        outln!("{table}");
    }
}

/// Notes on what the sweep could not check, as a list; empty when there
/// are none.
pub(super) fn notes_text(notes: &[String]) -> String {
    if notes.is_empty() {
        return String::new();
    }
    let spans: Vec<Span> = notes
        .iter()
        .map(|note| Span::new(format!("• {}", shown(note)), "33"))
        .collect();
    let fields = layout::fields(&[("Notes", spans)], layout::width(), Painter::for_stdout());
    format!("\n{fields}\n")
}

/// What changed since the last sweep, in a box with a table below.
pub(super) fn print_changes(changes: &[(super::state::Change, String)]) {
    let painter = Painter::for_stdout();
    let width = layout::width();
    let line = if changes.is_empty() {
        Span::new("✓ nothing new or changed since the last sweep", "32")
    } else {
        Span::new(
            format!("{} change(s) since the last sweep", changes.len()),
            "33;1",
        )
    };
    outln!(
        "{}",
        layout::boxed("Guardian sweep", &[line], width, "36", painter)
    );
    print_changes_table(changes);
}

/// What changed since the last sweep, as a table; nothing when nothing did.
pub(super) fn print_changes_table(changes: &[(super::state::Change, String)]) {
    if changes.is_empty() {
        return;
    }
    let mut page = String::from(
        "<section><hr><h3>What changed since the last sweep</h3><table><tr><th>Change</th><th>Item</th></tr>",
    );
    for (change, label) in changes {
        let _ = write!(
            page,
            "<tr><td class=\"amber\">{}</td><td><code>{}</code></td></tr>",
            esc(change.shown().0),
            esc(label)
        );
    }
    page.push_str("</table></section>");
    html::collect_section(page);
    let mut table = Table::new(vec!["Change", "Item"]);
    for (change, label) in changes {
        let (word, color) = change.shown();
        table.row(vec![
            vec![Span::new(word, color)],
            vec![Span::plain(shown(label))],
        ]);
    }
    outln!(
        "{}",
        table.render(layout::width(), 2, Painter::for_stdout())
    );
}

/// The sweep as one JSON document.
pub(super) fn json(
    collection: &Collection,
    report: &Report,
    decision: Decision,
    home: Option<&str>,
    notes: &[String],
) -> Json {
    let flagged = flagged(report);
    let items = collection.items.iter().map(|item| {
        let label = label(item, home);
        let mut members = vec![
            ("path", Json::from(label.as_str())),
            ("category", Json::from(item.category.name())),
            ("tier", Json::from(item.tier.name())),
            (
                "origin",
                Json::from(match item.origin {
                    Origin::System => "system",
                    Origin::User => "user",
                    Origin::Root => "root",
                }),
            ),
            ("flagged", Json::Bool(flagged.contains(&label))),
            (
                "runs",
                Json::Array(
                    item.runs
                        .iter()
                        .map(|run| Json::from(run.as_str()))
                        .collect(),
                ),
            ),
            (
                "notes",
                Json::Array(
                    item.notes
                        .iter()
                        .map(|note| Json::from(note.as_str()))
                        .collect(),
                ),
            ),
        ];
        if let Some(digest) = &item.sha256 {
            members.push(("sha256", Json::from(digest.to_string())));
        }
        if let Some(by) = &item.run_by {
            members.push(("run_by", Json::from(format!("/{by}"))));
        }
        Json::object(members)
    });
    Json::object([
        ("version", Json::from(1_u64)),
        ("decision", Json::from(decision_name(decision))),
        ("items", Json::Array(items.collect())),
        (
            "notes",
            Json::Array(notes.iter().map(|note| Json::from(note.as_str())).collect()),
        ),
        ("findings", findings_json(report)),
        ("ai", reviews_json(report)),
        (
            "gaps",
            Json::Array(
                report
                    .gaps
                    .iter()
                    .map(|gap| Json::from(gap.to_string()))
                    .collect(),
            ),
        ),
    ])
}

const fn decision_name(decision: Decision) -> &'static str {
    match decision {
        Decision::Clear | Decision::Limited => "clear",
        Decision::Warned => "warned",
        Decision::Blocked(Blocked::Findings) => "findings",
        Decision::Blocked(_) => "incomplete",
    }
}

/// The local findings.
fn findings_json(report: &Report) -> Json {
    let findings = report.findings.iter().map(|finding| {
        Json::object([
            ("path", Json::from(finding.path.as_str())),
            (
                "line",
                Json::from(u64::try_from(finding.line).unwrap_or(u64::MAX)),
            ),
            ("rule", Json::from(finding.rule.name())),
            (
                "severity",
                Json::from(finding.severity.label().to_ascii_lowercase()),
            ),
        ])
    });
    Json::Array(findings.collect())
}

/// The AI reviews.
fn reviews_json(report: &Report) -> Json {
    let reviews = report
        .agent_runs
        .iter()
        .filter_map(|run| match &run.outcome {
            AgentOutcome::Reviewed(review) => Some(Json::object([
                (
                    "status",
                    Json::from(match review.status {
                        Status::Clear => "clear",
                        Status::Suspicious => "suspicious",
                        Status::Inconclusive => "inconclusive",
                    }),
                ),
                ("summary", Json::from(review.summary.as_str())),
                (
                    "findings",
                    Json::Array(
                        review
                            .findings
                            .iter()
                            .map(|finding| {
                                Json::object([
                                    ("path", Json::from(finding.file.as_str())),
                                    (
                                        "severity",
                                        Json::from(finding.severity.label().to_ascii_lowercase()),
                                    ),
                                    ("title", Json::from(finding.title.as_str())),
                                    ("reason", Json::from(finding.reason.as_str())),
                                ])
                            })
                            .collect(),
                    ),
                ),
            ])),
            AgentOutcome::Unavailable(_) | AgentOutcome::NotAttempted { .. } => None,
        });
    Json::Array(reviews.collect())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashSet};

    use super::{
        SHOWN_CONCERNS, attention, concerns, findings_json, items_html, not_reviewed, verdict_lines,
    };
    use crate::agent::{AgentFinding, AgentReview, Status};
    use crate::autorun::Category;
    use crate::config::model::{AiRequirement, Profile, builtin};
    use crate::error::Error;
    use crate::layout::Painter;
    use crate::report::{
        AgentOutcome, AgentRun, Decision, Gap, LocalFinding, Report, ReviewScope, Severity,
    };
    use crate::review::analyze_text_locally;
    use crate::rules::RuleId;
    use crate::sweep::collect::{Body, Item, Origin};
    use crate::sweep::tier::Tier;

    fn local(path: &str, rule: RuleId) -> LocalFinding {
        LocalFinding {
            path: path.into(),
            line: 1,
            rule,
            severity: rule.severity(),
            excerpt: String::new(),
        }
    }

    fn ai(file: &str, severity: Severity, title: &str) -> AgentFinding {
        AgentFinding {
            severity,
            file: file.into(),
            line: None,
            title: title.into(),
            reason: String::new(),
        }
    }

    fn run(outcome: AgentOutcome) -> AgentRun {
        AgentRun {
            files: vec!["~/a".into()],
            label: "m".into(),
            chunk: None,
            cached: None,
            outcome,
        }
    }

    fn suspicious(findings: Vec<AgentFinding>) -> AgentRun {
        reviewed(Status::Suspicious, findings)
    }

    #[test]
    fn each_file_is_one_concern_under_its_worst_alert_and_the_worst_come_first() {
        let mut report = Report::default();
        // The match's own severity counts, not the rule's (see
        // `RuleId::severity_on`).
        let graded_low = LocalFinding {
            severity: Severity::Low,
            ..local("~/b", RuleId::ShellCommandExecution)
        };
        report.findings = vec![
            local("~/a", RuleId::ShellCommandExecution),
            local("~/a", RuleId::ShellCommandExecution),
            graded_low,
        ];
        report.agent_runs.push(suspicious(vec![
            ai("~/a", Severity::High, "fetches and runs a script"),
            ai("~/0", Severity::Low, "turns a cooldown off"),
        ]));

        let concerns = concerns(&report);
        let shown: Vec<(&str, Severity, &str, usize)> = concerns
            .iter()
            .map(|(file, concern)| {
                (
                    file.as_str(),
                    concern.severity,
                    concern.why.as_str(),
                    concern.alerts,
                )
            })
            .collect();
        assert_eq!(
            shown,
            [
                ("~/a", Severity::High, "AI: fetches and runs a script", 3),
                ("~/0", Severity::Low, "AI: turns a cooldown off", 1),
                (
                    "~/b",
                    Severity::Low,
                    "local check shell-command-execution",
                    1
                ),
            ]
        );
    }

    #[test]
    fn the_summary_names_a_few_concerns_and_counts_the_rest() {
        let mut report = Report::default();
        report.agent_runs.push(suspicious(
            (0..SHOWN_CONCERNS + 2)
                .map(|index| ai(&format!("~/f{index:02}"), Severity::Medium, "odd"))
                .collect(),
        ));
        let text = attention(&report, Painter::plain());
        assert!(text.contains("Needs a look"), "{text}");
        assert!(text.contains("~/f00") && text.contains("~/f09"), "{text}");
        assert!(!text.contains("~/f10"), "{text}");
        assert!(text.contains("… 2 more"), "{text}");
        assert!(!text.contains("Not reviewed"), "{text}");
        assert_eq!(attention(&Report::default(), Painter::plain()), "");
    }

    fn headline(report: &Report) -> (Vec<String>, &'static str) {
        let decision = report.decide(&|class| builtin(Profile::Standard, class));
        let (lines, edge) = verdict_lines(report, decision);
        let text = lines.iter().map(|line| format!("{line:?}")).collect();
        (text, edge)
    }

    fn reviewed(status: Status, findings: Vec<AgentFinding>) -> AgentRun {
        run(AgentOutcome::Reviewed(AgentReview {
            status,
            summary: "unsure".into(),
            findings,
        }))
    }

    #[test]
    fn the_verdict_leads_with_the_alerts_and_says_apart_what_was_not_checked() {
        let mut clear = Report::default();
        clear.agent_runs.push(reviewed(Status::Clear, Vec::new()));
        let (lines, edge) = headline(&clear);
        assert!(
            lines[0].contains("✓ NO ALERTS") && lines.len() == 1,
            "{lines:?}"
        );
        assert_eq!(edge, "32");

        let mut unread = clear;
        unread
            .gaps
            .push(Gap::Sweep("/boot/EFI: could not be listed".into()));
        let (lines, edge) = headline(&unread);
        assert!(lines[0].contains("! NO ALERTS COUNTED"), "{lines:?}");
        assert!(lines[1].contains("Not fully checked: 1 part(s) not checked"));
        assert_eq!(edge, "33", "not fully checked is never green");

        let mut found = unread;
        found.findings.push(LocalFinding {
            severity: Severity::Low,
            ..local("~/a", RuleId::ShellCommandExecution)
        });
        found
            .agent_runs
            .push(suspicious(vec![ai("~/b", Severity::Medium, "odd")]));
        found
            .agent_runs
            .push(run(AgentOutcome::Unavailable(Error::Message(
                "no network".into(),
            ))));
        let (lines, _) = headline(&found);
        assert!(
            lines[0].contains("! 2 ALERT(S) — 1 medium · 1 low"),
            "{lines:?}"
        );
        assert!(
            lines[1].contains("1 part(s) not checked; 1 AI request(s) did not complete"),
            "{lines:?}"
        );

        found
            .agent_runs
            .push(suspicious(vec![ai("~/c", Severity::High, "bad")]));
        let (lines, edge) = headline(&found);
        assert!(
            lines[0].contains("✗ 3 ALERT(S) — 1 high · 1 medium · 1 low"),
            "{lines:?}"
        );
        assert_eq!(edge, "31");
    }

    /// Runs that block with no alert to count are never shown as clear.
    #[test]
    fn a_review_that_blocks_without_an_alert_is_not_green() {
        let mut inconclusive = Report::default();
        inconclusive
            .agent_runs
            .push(reviewed(Status::Inconclusive, Vec::new()));
        let (lines, edge) = headline(&inconclusive);
        assert_eq!(edge, "33", "{lines:?}");
        assert!(
            lines[1].contains("1 AI request(s) did not complete"),
            "{lines:?}"
        );
        assert!(
            not_reviewed(&inconclusive)[0].contains("AI review: inconclusive: unsure"),
            "{lines:?}"
        );

        // With the AI optional, a review that did not run warns: nothing
        // was found suspicious, and the box must not say so.
        let mut optional = Report::default();
        optional
            .agent_runs
            .push(run(AgentOutcome::Unavailable(Error::Message(
                "no network".into(),
            ))));
        let decision = optional.decide(&|class| {
            let mut policy = builtin(Profile::Standard, class);
            policy.ai = AiRequirement::Optional;
            policy
        });
        assert_eq!(decision, Decision::Warned);
        let (lines, _) = verdict_lines(&optional, decision);
        let lines: Vec<String> = lines.iter().map(|line| format!("{line:?}")).collect();
        assert!(
            !lines.iter().any(|line| line.contains("suspicious")),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|line| line.contains("Allowed by policy")),
            "{lines:?}"
        );

        let mut suspicious = Report::default();
        suspicious
            .agent_runs
            .push(reviewed(Status::Suspicious, Vec::new()));
        let (lines, edge) = headline(&suspicious);
        assert_eq!(edge, "33", "{lines:?}");
        assert!(
            lines
                .iter()
                .any(|line| line.contains("found something suspicious")),
            "{lines:?}"
        );
    }

    #[test]
    fn the_summary_says_why_the_review_is_incomplete() {
        let mut report = Report::default();
        report
            .gaps
            .push(Gap::Sweep("/boot/EFI: could not be listed".into()));
        report
            .agent_runs
            .push(run(AgentOutcome::Unavailable(Error::Message(
                "no network".into(),
            ))));
        let lines = not_reviewed(&report);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert_eq!(lines[0], "/boot/EFI: could not be listed");
        assert!(lines[1].starts_with("AI review: ") && lines[1].contains("no network"));

        let text = attention(&report, Painter::plain());
        assert!(
            text.contains("Not reviewed")
                && text.contains("! /boot/EFI: could not be listed")
                && text.contains("! AI review: "),
            "{text}"
        );
    }

    #[test]
    fn a_finding_carries_the_severity_of_its_match() {
        let mut report = Report::new("sweep", ReviewScope::default());
        analyze_text_locally(
            &mut report,
            "~/.config/hooks/hook.py",
            "subprocess.run([\"git\", \"status\"])\nsubprocess.run(cmd, shell=True)\n",
        );
        let json = findings_json(&report);
        let severities: Vec<&str> = json
            .as_array()
            .expect("findings_json returns an array")
            .iter()
            .map(|finding| finding.get("severity").and_then(|value| value.as_str()))
            .collect::<Option<_>>()
            .expect("every finding has a severity");
        assert_eq!(severities, ["low", "medium"]);
    }

    #[test]
    fn the_page_escapes_what_it_lists() {
        let item = Item {
            file: None,
            origin: Origin::Root,
            category: Category::Shell,
            path: "home/u/<b>evil</b>".into(),
            tier: Tier::Unknown,
            sha256: None,
            body: Body::Link("<script>x</script>".into()),
            runs: vec!["curl \"a\" & <x>".into()],
            run_by: None,
            notes: vec!["<i>note</i>".into()],
            alerts: Vec::new(),
        };
        let mut groups = BTreeMap::new();
        groups.insert(item.category.label(), vec![&item]);
        let flagged: HashSet<String> = ["~/<b>evil</b>".to_string()].into();
        let html = items_html(&groups, Some("home/u"), &flagged);
        assert!(!html.contains("<b>") && !html.contains("<script>") && !html.contains("<i>"));
        assert!(html.contains("&lt;b&gt;evil") && html.contains("✗ unknown"));
        assert!(html.contains("read as root") && html.contains("&amp;"));
        assert!(
            items_html(&BTreeMap::new(), None, &HashSet::new()).contains("every item is trusted")
        );
    }
}
