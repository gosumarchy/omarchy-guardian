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
use crate::osv;
use crate::report::{AgentOutcome, Decision, Gap, LocalFinding, Report};
use crate::rules::{self, RuleId};
use crate::scan::{self, FileHash, FileKind, ScanConfig, TextFile};
use crate::tools::OpenCode;

mod local;

use local::{MAX_PROSE_TARGETS, apply_rules, check_run_prose};
pub(crate) use local::{MAX_RUNS, check_runs};

const EXCERPT_CHARS: usize = 180;

/// A line as a finding shows it: trimmed, cut to length, and without the
/// login a URL in it may carry (`scheme://user:password@host` is shown as
/// `scheme://***@host`). An excerpt is printed, saved in a report and
/// handed on from there, and none of that needs the password. The login
/// is taken out by the rule a git configuration's addresses are, which
/// only takes out plain characters, so nothing that could be code is
/// hidden. The rules have matched on the line as written before this.
fn excerpt(line: &str) -> String {
    git_state::without_url_credentials(line.trim())
        .chars()
        .take(EXCERPT_CHARS)
        .collect()
}
const LFS_POINTER: &str = "version https://git-lfs.github.com/spec/v1";

/// What one review runs against: the settings, the class the target itself
/// belongs to, and where to find OpenCode.
pub(crate) struct ReviewContext<'a> {
    pub(crate) settings: &'a Settings,
    pub(crate) class: SourceClass,
    pub(crate) opencode: &'a OpenCode,
    /// What the target is remembered as; empty for `<class>:<canonical path>`.
    pub(crate) units: &'a [Unit],
    /// The review-memory store; `None` reviews without it.
    pub(crate) state_root: Option<&'a Path>,
    /// Facts for the AI review (see `Request::context`).
    pub(crate) context: &'a [String],
}

/// Reviews a file or directory tree as one source class.
pub(crate) fn review_tree(config: &ScanConfig, context: &ReviewContext<'_>) -> Report {
    let mut report = collected_report(config.root.display().to_string(), context);

    // The text of prose files, which the command rules skip: kept so a
    // dangerous one that a reviewed line runs can be checked after all.
    let mut prose: HashMap<String, String> = HashMap::new();
    // The prose files past that many, by path alone: a line that runs one
    // of them is said, since the rules then never read what it runs.
    let mut prose_not_kept: HashSet<String> = HashSet::new();
    let mut surroundings = image::Surroundings::default();
    let (snapshot, walk_gaps) = scan::walk(config, &mut |file: TextFile<'_>| {
        surroundings.note_text(file.rel, file.text);
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
            if rules::is_documentation(file.rel) {
                if prose.len() < MAX_PROSE_TARGETS {
                    prose.insert(file.rel.to_string(), file.text.to_string());
                } else {
                    prose_not_kept.insert(file.rel.to_string());
                }
            }
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
    for file in snapshot.files() {
        surroundings.note_file(&file.path, file.executable);
    }
    report.unread = snapshot
        .files()
        .iter()
        .filter(|file| !is_plain_image_among(&config.root, file, &surroundings))
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
    check_run_prose(&mut report, &prose, &prose_not_kept);
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
pub(crate) fn collected_report(subject: impl Into<String>, context: &ReviewContext<'_>) -> Report {
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

/// `is_plain_image` for a file of a tree whose `surroundings` are known: an
/// image is passed over only away from where files are run. One beside a
/// script, or in a directory whose files a reviewed line runs, is an unread
/// file like any other, so a new or changed one is reviewed in full.
fn is_plain_image_among(root: &Path, file: &FileHash, surroundings: &image::Surroundings) -> bool {
    file.kind == FileKind::Text
        || (surroundings.leaves_alone(&file.path) && is_plain_image(root, file))
}

/// Runs the AI review of what `report` has queued, with the review memory
/// for `units`, and records an approved baseline.
pub(crate) fn review_collected(
    mut report: Report,
    context: &ReviewContext<'_>,
    units: &[Unit],
) -> Report {
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
pub(crate) fn ai_off_classes(settings: &Settings, classes: &[SourceClass]) -> Vec<SourceClass> {
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
            excerpt: self::excerpt(&excerpt),
        });
    }
}

/// Applies the local checks to one text file and queues it for the AI review.
pub(crate) fn analyze_text(report: &mut Report, rel: &str, text: &str, inspect_dependencies: bool) {
    analyze(report, rel, text, inspect_dependencies, true);
}

/// Applies the local checks to one text file that stays on this machine:
/// nothing of it is queued for the AI review, and that it is not is no gap
/// of the review (the caller says why it is kept, see `sweep::judge`).
pub(crate) fn analyze_text_locally(report: &mut Report, rel: &str, text: &str) {
    analyze(report, rel, text, false, false);
}

fn analyze(report: &mut Report, rel: &str, text: &str, inspect_dependencies: bool, queue: bool) {
    // These two read every text file, prose included, since that is where
    // text for the reviewer and hidden characters hide.
    analyze_reviewer_text(report, rel, text);
    analyze_hidden_characters(report, rel, text);
    if git_state::is_git_config(rel) {
        return analyze_git_config(report, rel, text);
    }
    report.text_files_reviewed += 1;

    if text.lines().next() == Some(LFS_POINTER) {
        report.gaps.push(Gap::UnresolvedLfs(rel.to_string()));
    }
    if queue {
        queue_for_agent(report, rel, text);
    }

    let documentation = rules::is_documentation(rel);
    let inventory_network = !documentation && rules::is_executable_or_runtime_config(rel);
    if !documentation {
        apply_rules(report, rel, text, inventory_network);
    }

    if inspect_dependencies {
        deps::inspect(&mut report.dependencies, &mut report.gaps, rel, text);
    }
}

/// Flags lines that address the AI reviewer rather than the user. Runs on
/// every text file, prose included (see `rules::addressed`).
fn analyze_reviewer_text(report: &mut Report, rel: &str, text: &str) {
    for (line, excerpt) in rules::addressed::findings(text) {
        report.findings.push(LocalFinding {
            path: rel.to_string(),
            line,
            rule: RuleId::ReviewerInstruction,
            excerpt: self::excerpt(&excerpt),
        });
    }
}

/// Flags reordering controls, invisible tag characters and hidden
/// characters inside tokens (see `rules::hidden`).
fn analyze_hidden_characters(report: &mut Report, rel: &str, text: &str) {
    for found in rules::hidden::findings(rel, text) {
        report.findings.push(LocalFinding {
            path: rel.to_string(),
            line: found.line,
            rule: found.rule,
            excerpt: excerpt(&found.excerpt),
        });
    }
}

/// Queues a package payload file that acts on its own (see `payload`) for
/// the AI review only. The local rules are written for scripts and code;
/// these files are where legitimate services, rules and privileges live, so
/// the rules' matches on them are noise. Returns whether it was queued: a
/// class with `ai = off` does not review payload files at all.
pub(crate) fn analyze_payload(report: &mut Report, rel: &str, text: &str) -> bool {
    if report.ai_off_classes.contains(&report.class_of(rel)) {
        return false;
    }
    report.text_files_reviewed += 1;
    queue_for_agent(report, rel, text);
    true
}

/// Hands one file of an AUR package's upstream source to the review, and
/// says whether the AI review takes it. Where it does not (the AI is off
/// for the class), the source would otherwise pass unread, so the local
/// rules read it. Only their high findings are kept: a source tree is full
/// of ordinary uses of what the medium rules name (a program that starts
/// another, a path under the home), while the high ones name what no build
/// needs. With the AI on, upstream code is its to judge: an install script
/// quoted in a project's own tooling would otherwise block every build of
/// it. Two things are still looked for there, because they are aimed at
/// the reviewer and at whoever reads its report rather than at the build:
/// invisible tag characters and controls that reorder text. Neither has a
/// use in source code, and the rule is quiet where writing systems need
/// them. Text addressed to the reviewer is not kept with the AI on:
/// projects ship prompts and agent instructions of their own, the request
/// shows invisible characters as codes, and the reply says when the
/// source spoke to it.
pub(crate) fn analyze_upstream(report: &mut Report, rel: &str, text: &str) -> bool {
    let before = report.findings.len();
    if analyze_payload(report, rel, text) {
        analyze_hidden_characters(report, rel, text);
        let mut found = report.findings.split_off(before);
        found.retain(|finding| {
            matches!(finding.rule, RuleId::InvisibleText | RuleId::ReorderedText)
        });
        report.findings.append(&mut found);
        return true;
    }
    analyze_reviewer_text(report, rel, text);
    analyze_hidden_characters(report, rel, text);
    if !rules::is_documentation(rel) {
        apply_rules(report, rel, text, false);
    }
    let mut found = report.findings.split_off(before);
    found.retain(|finding| finding.rule.severity() == crate::report::Severity::High);
    report.findings.append(&mut found);
    false
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
pub(crate) fn run_agents(
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
mod tests;
