//! The local-rule pass: the line rules over each file, commands that span
//! lines, and what the files run.

use std::collections::{HashMap, HashSet};

use crate::image;
use crate::mask;
use crate::report::{Gap, LocalFinding, NetworkRequest, Report, RunRef};
use crate::rules::{self, RuleId, Scheme};

use super::{EXCERPT_CHARS, excerpt};

/// Records the destinations in `active`, the line without comments and
/// printed messages; `line` is the original, shown as the excerpt.
fn record_network(report: &mut Report, rel: &str, number: usize, line: &str, active: &str) {
    for (scheme, host) in rules::extract_network_destinations(active) {
        if !rules::is_local_host(&host) {
            if scheme == Scheme::Http {
                push_finding(report, rel, number, line, RuleId::CleartextNetworkRequest);
            }
            if rules::is_ip_host(&host) {
                push_finding(report, rel, number, line, RuleId::DirectIpNetworkRequest);
            }
        }
        report.network.push(NetworkRequest {
            path: rel.to_string(),
            line: number,
            scheme,
            host,
        });
    }
    // The host's reputation and its name, judged from the path but recorded
    // without it.
    for (host, concern) in rules::host_concerns(active) {
        if rules::is_local_host(&host) {
            continue;
        }
        if concern.lookalike {
            push_finding(report, rel, number, line, RuleId::LookalikeHost);
        }
        if concern.drop {
            push_finding(report, rel, number, line, RuleId::DataDropHost);
        }
    }
}

/// The most downloaded files followed through one file.
const MAX_FETCHED_FILES: usize = 64;

/// Runs the local rules over `text`: each line by itself, each command
/// continued over several lines as the one line a shell reads, and a
/// download saved to a file that the same text later runs.
pub(super) fn apply_rules(report: &mut Report, rel: &str, text: &str, inventory_network: bool) {
    let masked = mask::lines(rel, text);
    let lines: Vec<&str> = text.lines().collect();
    let variables = rules::command_variables(text);
    let recipe = rel
        .rsplit('/')
        .next()
        .is_some_and(|name| name.eq_ignore_ascii_case("PKGBUILD"));
    // Each line lowercased for the rules, and as written for file names.
    let mut views: Vec<(String, String)> = Vec::with_capacity(lines.len());
    let mut written: Vec<String> = Vec::with_capacity(lines.len());
    for (index, (line, view)) in lines.iter().zip(&masked).enumerate() {
        let number = index + 1;
        if inventory_network {
            record_network(report, rel, number, line, &view.quiet);
        }
        // What a recipe declares as a source or a homepage is not in
        // `quiet`; a host there that reads as another is still a finding.
        if recipe && rules::declares_lookalike_host(&view.code, &view.quiet) {
            push_finding(report, rel, number, line, RuleId::LookalikeHost);
        }
        // Tabs as spaces, so `sudo<TAB>x` matches like `sudo x`.
        let as_written = view.code.replace('\t', " ");
        let code = rules::with_variables(&as_written.to_lowercase(), &variables);
        let quiet =
            rules::with_variables(&view.quiet.to_lowercase().replace('\t', " "), &variables);
        for rule in rules::line_rules(&code, &quiet) {
            push_finding(report, rel, number, line, rule);
        }
        views.push((code, quiet));
        written.push(as_written);
    }

    // A value followed across lines from where it is made to where it runs.
    let code_lines: Vec<String> = views.iter().map(|(code, _)| code.clone()).collect();
    for (number, rule) in rules::flow::findings(&code_lines) {
        push_finding(
            report,
            rel,
            number,
            lines.get(number - 1).copied().unwrap_or(""),
            rule,
        );
    }

    apply_command_groups(report, rel, &lines, &views, &written);
}

/// Each command of `text`, as the one line a shell reads it as (continued
/// over several source lines), matched by the rules, recorded as what it
/// runs and downloads, and checked for running a file fetched or decoded
/// earlier (download-and-run within one file).
fn apply_command_groups(
    report: &mut Report,
    rel: &str,
    lines: &[&str],
    views: &[(String, String)],
    written: &[String],
) {
    let joined = |parts: &mut dyn Iterator<Item = &String>| {
        parts
            .map(|part| part.trim_end().trim_end_matches('\\'))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let mut fetched: Vec<String> = Vec::new();
    let mut start = 0;
    while start < views.len() {
        // The lines of one command: a blank or comment line after a pipe
        // or `&&` does not end it.
        let mut end = start + 1;
        let mut last = start;
        while end < views.len() {
            let open = views[last].0.trim_end();
            if views[end].0.trim().is_empty() && (open.ends_with('|') || open.ends_with("&&")) {
                end += 1;
            } else if rules::continues(&views[last].0, &views[end].0) {
                last = end;
                end += 1;
            } else {
                break;
            }
        }
        let end = last + 1;
        let group = &views[start..end];
        let code = joined(&mut group.iter().map(|(code, _)| code));
        let mut found: Vec<RuleId> = group
            .iter()
            .flat_map(|(code, quiet)| rules::line_rules(code, quiet))
            .collect();
        if group.len() > 1 {
            let quiet = joined(&mut group.iter().map(|(_, quiet)| quiet));
            for rule in rules::line_rules(&code, &quiet) {
                if !found.contains(&rule) {
                    found.push(rule);
                    push_finding(report, rel, start + 1, lines[start], rule);
                }
            }
        }
        let as_written = joined(&mut written[start..end].iter());
        record_runs(report, rel, start + 1, lines[start], &as_written);
        // A fetch or a decoder that writes a file: a file run later is
        // download-and-run / encoded execution just as a piped one is.
        let lowered = as_written.to_lowercase();
        let brought_in = rules::fetched_files(&as_written)
            .into_iter()
            .chain(rules::encoded::decoded_file(&lowered));
        for file in brought_in {
            let file = file.to_lowercase();
            if report.fetches.len() < MAX_RUNS {
                report.fetches.push((rel.to_string(), file.clone()));
            } else {
                report.runs_overflowed = true;
            }
            if !fetched.contains(&file) {
                // Past the limit the oldest is let go: a download is run
                // soon after it is made.
                if fetched.len() == MAX_FETCHED_FILES {
                    fetched.remove(0);
                }
                fetched.push(file);
            }
        }
        if !found.contains(&RuleId::DownloadAndExecute)
            && fetched
                .iter()
                .any(|file| code.contains(file.as_str()) && rules::runs_file(&code, file))
        {
            push_finding(
                report,
                rel,
                start + 1,
                lines[start],
                RuleId::DownloadAndExecute,
            );
        }
        start = end;
    }
}

/// The most prose files kept for the run-through check.
pub(super) const MAX_PROSE_TARGETS: usize = 512;

/// Applies the command rules to a prose file after all, when a reviewed
/// line runs or reads it in as code. A README is text, so it is not an
/// unread file, and it is prose, so the rules skipped it; without this a
/// script that does `sh ./README` hides its payload there. Each finding is
/// marked with the line that runs the file.
///
/// Only `MAX_PROSE_TARGETS` prose files are kept for this. A line that
/// runs one of the others (`not_kept`) leaves the review incomplete: the
/// rules did not read what it runs. A tree with more prose files than
/// that, none of which a reviewed line runs past the bound, is not held
/// against it.
pub(super) fn check_run_prose(
    report: &mut Report,
    prose: &HashMap<String, String>,
    not_kept: &HashSet<String>,
) {
    if prose.is_empty() || report.runs.is_empty() {
        return;
    }
    // Which prose file each run names (from beside the runner or the top of
    // the tree), and the first line that runs it.
    let mut runners: Vec<(String, String, usize)> = Vec::new();
    let mut unchecked: Vec<(String, String, usize)> = Vec::new();
    for run in &report.runs {
        let paths = run_paths(&run.rel, &run.target);
        if let Some(path) = paths
            .iter()
            .find(|candidate| prose.contains_key(*candidate))
            && !runners.iter().any(|(doc, _, _)| doc == path)
        {
            runners.push((path.clone(), run.rel.clone(), run.line));
        }
        if let Some(path) = paths.iter().find(|candidate| not_kept.contains(*candidate))
            && !unchecked.iter().any(|(doc, _, _)| doc == path)
        {
            unchecked.push((path.clone(), run.rel.clone(), run.line));
        }
    }
    for (doc, rel, line) in runners {
        let before = report.findings.len();
        apply_rules(report, &doc, &prose[&doc], false);
        let note = format!(" (run by {rel}:{line})");
        for finding in &mut report.findings[before..] {
            let room = EXCERPT_CHARS.saturating_sub(note.len());
            finding.excerpt = finding.excerpt.chars().take(room).collect::<String>() + &note;
        }
    }
    for (doc, rel, line) in unchecked.iter().take(MAX_RUN_GAPS) {
        report.gaps.push(Gap::RunsUnread(format!(
            "{rel}:{line} runs or reads in {doc}, a documentation file past the first {MAX_PROSE_TARGETS} of this tree, which the local rules therefore did not read"
        )));
    }
    if unchecked.len() > MAX_RUN_GAPS {
        report.gaps.push(Gap::RunsUnread(format!(
            "{} more documentation files that a reviewed line runs and the local rules did not read",
            unchecked.len() - MAX_RUN_GAPS
        )));
    }
}

/// Records what the command at `line` runs (see `check_runs`).
pub(super) fn record_runs(report: &mut Report, rel: &str, line: usize, text: &str, command: &str) {
    let targets = rules::run_targets(command);
    if report.runs.len() + targets.len() > MAX_RUNS {
        report.runs_overflowed = true;
        return;
    }
    for target in targets {
        report.runs.push(RunRef {
            rel: rel.to_string(),
            line,
            excerpt: excerpt(text),
            target,
        });
    }
}

/// The most files run, and downloads, recorded for one review. Past it the
/// review is incomplete: what runs further on is not followed.
pub const MAX_RUNS: usize = 100_000;

/// What one reviewed file does with another: runs one that a different
/// file downloads (download-and-run across files), or runs or reads in as
/// code one Guardian could not read as text (`unread`, with why), which is
/// then not reviewed although it runs.
pub fn check_runs(report: &mut Report, unread: &[(String, String)]) {
    if report.runs_overflowed {
        report.gaps.push(Gap::RunsUnread(format!(
            "more than {MAX_RUNS} lines run or download a file: the rest are not followed"
        )));
    }
    let runs = std::mem::take(&mut report.runs);
    // Which files download what, and which files Guardian could not read,
    // each looked up once.
    let mut downloaders: HashMap<String, HashSet<String>> = HashMap::new();
    for (rel, file) in &report.fetches {
        downloaders
            .entry(file.clone())
            .or_default()
            .insert(rel.clone());
    }
    let unread_by_path: HashMap<&str, &str> = unread
        .iter()
        .map(|(path, why)| (path.as_str(), why.as_str()))
        .collect();
    let flagged: HashSet<(String, usize)> = report
        .findings
        .iter()
        .filter(|finding| finding.rule == RuleId::DownloadAndExecute)
        .map(|finding| (finding.path.clone(), finding.line))
        .collect();
    let mut gapped: HashSet<(String, String)> = HashSet::new();
    let mut gaps = 0;
    for run in &runs {
        let downloaded_elsewhere = downloaders
            .get(&run.target.to_lowercase())
            .is_some_and(|rels| rels.iter().any(|rel| *rel != run.rel));
        if downloaded_elsewhere && !flagged.contains(&(run.rel.clone(), run.line)) {
            report.findings.push(LocalFinding {
                path: run.rel.clone(),
                line: run.line,
                rule: RuleId::DownloadAndExecute,
                // A run recorded elsewhere (the AUR gate's upstream files)
                // holds the line as written.
                excerpt: excerpt(&run.excerpt),
            });
        }
        // The file the line names: beside the file that runs it, or from
        // the top of the tree.
        let Some(path) = run_paths(&run.rel, &run.target)
            .into_iter()
            .find(|candidate| unread_by_path.contains_key(candidate.as_str()))
        else {
            // An image is never read as text, and one that is whole is not
            // among the unread files either (see `is_plain_image`): that
            // rests on nothing running it, so a line that does is a gap by
            // the name alone, wherever the path leads.
            if image::is_named(&run.target) && gapped.insert((run.rel.clone(), run.target.clone()))
            {
                gaps += 1;
                if gaps <= MAX_RUN_GAPS {
                    report.gaps.push(Gap::RunsUnread(format!(
                        "{}:{} runs or reads in {}, an image by its name, which is not reviewed as text",
                        run.rel, run.line, run.target
                    )));
                }
            }
            continue;
        };
        if !gapped.insert((run.rel.clone(), path.clone())) {
            continue;
        }
        gaps += 1;
        if gaps > MAX_RUN_GAPS {
            continue;
        }
        let why = unread_by_path
            .get(path.as_str())
            .copied()
            .unwrap_or_default();
        report.gaps.push(Gap::RunsUnread(format!(
            "{}:{} runs or reads in {path} ({why}), which could not be reviewed as text",
            run.rel, run.line
        )));
    }
    if gaps > MAX_RUN_GAPS {
        report.gaps.push(Gap::RunsUnread(format!(
            "{} more files that run or read in what could not be reviewed",
            gaps - MAX_RUN_GAPS
        )));
    }
    report.runs = runs;
}

/// The most such gaps named one by one.
const MAX_RUN_GAPS: usize = 32;

/// The paths a `target` written in the file `rel` may name, relative to the
/// top of the tree: beside that file, and from the top.
fn run_paths(rel: &str, target: &str) -> Vec<String> {
    if target.contains('$') || target.starts_with('/') {
        return Vec::new();
    }
    let target = target.trim_start_matches("./");
    let directory = rel.rsplit_once('/').map_or("", |(directory, _)| directory);
    let beside = if directory.is_empty() {
        target.to_string()
    } else {
        format!("{directory}/{target}")
    };
    [beside, target.to_string()]
        .into_iter()
        .filter_map(|path| {
            let mut parts: Vec<&str> = Vec::new();
            for part in path.split('/') {
                match part {
                    "" | "." => {}
                    ".." => {
                        parts.pop()?;
                    }
                    other => parts.push(other),
                }
            }
            Some(parts.join("/"))
        })
        .collect()
}

fn push_finding(report: &mut Report, rel: &str, number: usize, line: &str, rule: RuleId) {
    report.findings.push(LocalFinding {
        path: rel.to_string(),
        line: number,
        rule,
        excerpt: excerpt(line),
    });
}
