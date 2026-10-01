//! How a sweep is shown: a list of what isn't trusted, grouped by what it
//! is, before the usual report of the review; or one JSON document.

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;

use super::collect::{Body, Collection, Item, Origin};
use super::judge::{is_trusted, label};
use super::tier::Tier;
use crate::agent::Status;
use crate::json::Json;
use crate::report::{AgentOutcome, Decision, Report};
use crate::text::shown;

const fn tier_word(tier: Tier) -> &'static str {
    match tier {
        Tier::Vendor => "package",
        Tier::Inert => "inert",
        Tier::Copied => "copy",
        Tier::UserBuilt => "user-built",
        Tier::Edited => "edited",
        Tier::Modified => "MODIFIED",
        Tier::Unknown => "unknown",
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

/// The list of items, then the summary line.
pub fn print(collection: &Collection, report: &Report, home: Option<&str>, all: bool) {
    let shown_items: Vec<&Item> = collection
        .items
        .iter()
        .filter(|item| all || !is_trusted(item.tier))
        .collect();
    let trusted = collection
        .items
        .iter()
        .filter(|item| is_trusted(item.tier))
        .count();
    outln!(
        "Guardian sweep · {} item(s) · {trusted} trusted · {} to look at",
        collection.items.len(),
        collection.items.len() - trusted
    );
    let flagged = flagged(report);
    let mut groups: BTreeMap<&'static str, Vec<&Item>> = BTreeMap::new();
    for item in shown_items {
        groups.entry(item.category.label()).or_default().push(item);
    }
    for (heading, items) in groups {
        let when = items.first().map_or("", |item| item.category.when());
        outln!("\n{heading} — {when}");
        for item in items {
            let label = label(item, home);
            let mark = if flagged.contains(&label) { "✗" } else { " " };
            let mut line = format!("  {mark} {:<10} {}", tier_word(item.tier), shown(&label));
            if item.origin == Origin::Root {
                line.push_str("  (root)");
            }
            match &item.body {
                Body::Link(target) => {
                    let _ = write!(line, " → {}", shown(target));
                }
                Body::Binary(format) => {
                    let _ = write!(line, "  [{format}]");
                }
                Body::Unreadable(_) => line.push_str("  [not readable]"),
                Body::Text(_) | Body::Undecodable | Body::Oversized => {}
            }
            outln!("{line}");
            for command in item.runs.iter().take(3) {
                outln!("        runs {}", shown(command));
            }
            for note in &item.notes {
                outln!("        {}", shown(note));
            }
        }
    }
    outln!();
}

/// The sweep as one JSON document.
pub fn json(
    collection: &Collection,
    report: &Report,
    decision: Decision,
    home: Option<&str>,
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
