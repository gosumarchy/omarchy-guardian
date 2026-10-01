//! How a sweep is shown: a summary, then a table of what isn't trusted for
//! each area, before the usual report of the review; or one JSON document.

use std::collections::{BTreeMap, HashSet};

use super::collect::{Body, Collection, Item, Origin};
use super::judge::label;
use super::tier::Tier;
use crate::agent::Status;
use crate::json::Json;
use crate::layout::{self, Painter, Span, Table};
use crate::report::{AgentOutcome, Decision, Report};
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

/// The summary card: how much is trusted, and what the rest is.
fn summary(shown_items: &[&Item], total: usize, trusted: usize, flagged: usize) -> Vec<Span> {
    let width = 40;
    let (filled, empty) = layout::bar(trusted, total, width);
    let percent = (trusted * 100).checked_div(total).unwrap_or(100);
    let mut lines = vec![
        Span::new(format!("{filled}{empty}  {percent}% trusted"), "32"),
        Span::plain(format!(
            "{total} item(s) checked · {trusted} trusted · {} to look at · {flagged} flagged",
            total - trusted
        )),
    ];
    let mut by_tier: BTreeMap<Tier, usize> = BTreeMap::new();
    for item in shown_items {
        *by_tier.entry(item.tier).or_default() += 1;
    }
    if !by_tier.is_empty() {
        lines.push(Span::plain(""));
    }
    for (tier, count) in by_tier {
        let (word, color) = tier_style(tier);
        lines.push(Span::new(
            format!("{count:>4}  {word:<10}  {}", tier_meaning(tier)),
            color,
        ));
    }
    lines
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
        Body::Text(_) | Body::Undecodable | Body::Oversized => {}
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

/// The summary card, then a table of items for each area.
pub fn print(collection: &Collection, report: &Report, home: Option<&str>, all: bool) {
    let painter = Painter::for_stdout();
    let width = layout::width();
    let shown_items: Vec<&Item> = collection
        .items
        .iter()
        .filter(|item| all || !item.is_trusted())
        .collect();
    let trusted = collection
        .items
        .iter()
        .filter(|item| item.is_trusted())
        .count();
    let flagged = flagged(report);
    let flagged_count = shown_items
        .iter()
        .filter(|item| flagged.contains(&label(item, home)))
        .count();
    let lines = summary(&shown_items, collection.items.len(), trusted, flagged_count);
    outln!(
        "{}",
        layout::boxed("Guardian sweep", &lines, width, "36", painter)
    );

    let mut groups: BTreeMap<&'static str, Vec<&Item>> = BTreeMap::new();
    for item in shown_items {
        groups.entry(item.category.label()).or_default().push(item);
    }
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

/// Notes on what the sweep could not check, as a list.
pub fn print_notes(notes: &[String]) {
    if notes.is_empty() {
        return;
    }
    let painter = Painter::for_stdout();
    let spans: Vec<Span> = notes
        .iter()
        .map(|note| Span::new(format!("• {}", shown(note)), "33"))
        .collect();
    outln!();
    outln!(
        "{}",
        layout::fields(&[("Notes", spans)], layout::width(), painter)
    );
}

/// What changed since the last sweep, in a table.
pub fn print_changes(changes: &[(super::state::Change, String)]) {
    let painter = Painter::for_stdout();
    let width = layout::width();
    if changes.is_empty() {
        let lines = [Span::new(
            "✓ nothing new or changed since the last sweep",
            "32",
        )];
        outln!(
            "{}",
            layout::boxed("Guardian sweep", &lines, width, "36", painter)
        );
        return;
    }
    let lines = [Span::new(
        format!("{} change(s) since the last sweep", changes.len()),
        "33;1",
    )];
    outln!(
        "{}",
        layout::boxed("Guardian sweep", &lines, width, "36", painter)
    );
    let mut table = Table::new(vec!["Change", "Item"]);
    for (change, label) in changes {
        let (word, color) = change.shown();
        table.row(vec![
            vec![Span::new(word, color)],
            vec![Span::plain(shown(label))],
        ]);
    }
    outln!("{}", table.render(width, 2, painter));
}

/// The sweep as one JSON document.
pub fn json(
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
        Decision::Blocked(crate::report::Blocked::Findings) => "findings",
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
                Json::from(finding.rule.severity().label().to_ascii_lowercase()),
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
            AgentOutcome::Unavailable(_) => None,
        });
    Json::Array(reviews.collect())
}
