//! The review of the upstream files: what the AI is told about what it
//! cannot see, the files the build runs, and the review itself.

use std::collections::HashSet;
use std::fmt::Write as _;

use super::confirm::confirm_prebuilt;
use super::{MAX_BINARIES_NAMED, UpstreamReview, UpstreamStep};
use crate::aur::{self, Upstream};
use crate::cli::Confirm;
use crate::config::Settings;
use crate::config::model::SourceClass;
use crate::engine::baseline::{Identity, Unit};
use crate::engine::store::Store;
use crate::error::Error;
use crate::report::{Blocked, Decision, Gap, Report, RunRef};
use crate::review::{self, ReviewContext};
use crate::rules;
use crate::tools::OpenCode;

/// Sources with no text to review. That is no clear review: the binaries
/// are still recorded and compared (by the caller), and a package made of
/// prebuilt programs still needs the user's yes.
pub(super) fn unreviewable_sources(
    step: &UpstreamStep<'_>,
    review: &UpstreamReview<'_>,
    confirm: &mut dyn Confirm,
) -> Decision {
    outln!(
        "Upstream: no text sources to review{}.",
        if review.upstream.binary_files > 0 {
            format!(
                " ({} binary file(s), which Guardian cannot review)",
                review.upstream.binary_files
            )
        } else {
            String::new()
        }
    );
    if confirm_prebuilt(step, review.prebuilt, confirm) {
        Decision::Clear
    } else {
        Decision::Blocked(Blocked::NotConfirmed)
    }
}

/// Facts about what the upstream review cannot see.
pub(super) fn upstream_facts(review: &UpstreamReview<'_>) -> Vec<String> {
    let upstream = review.upstream;
    let mut facts = Vec::new();
    if upstream.binary_files > 0 {
        facts.push(format!(
            "The sources hold {} binary file(s) Guardian cannot review{}.",
            upstream.binary_files,
            if upstream.executables.is_empty() {
                String::new()
            } else {
                format!(
                    ", including {} executable(s) listed in upstream-summary",
                    upstream.executables.len()
                )
            }
        ));
    }
    if !review.prebuilt.programs.is_empty() {
        facts.push(format!(
            "Guardian established that {}. It asks the user to confirm that itself; the programs are not among the supplied files.",
            review.prebuilt.statement()
        ));
    }
    let left_out = upstream.omitted.len() + upstream.left_out;
    if left_out > 0 || upstream.data_files > 0 {
        facts.push(format!(
            "Guardian left {left_out} code file(s) and {} data or documentation file(s) out of this review (upstream-summary names some); build files, scripts and files a build file names were not left out. Guardian checks itself whether a supplied line runs or reads in a file that was left out.",
            upstream.data_files
        ));
    }
    if !upstream.unpacked.is_empty() {
        facts.push(format!(
            "Guardian unpacked {} archive(s) the recipe opens itself; their files are supplied under the archive's path followed by `!`.",
            upstream.unpacked.len()
        ));
    }
    if !upstream.lockfiles.is_empty() {
        facts.push(
            "Guardian scanned the dependency lockfiles itself for where they fetch from; upstream-summary holds what it found, and lockfiles too large to send are not among the supplied files."
                .into(),
        );
    }
    facts
}

/// The most left-out files named one by one in the summary.
const MAX_LEFT_OUT_NAMED: usize = 40;

/// The raw source entries and what was left out, as untrusted data.
pub(super) fn upstream_summary(review: &UpstreamReview<'_>) -> String {
    let upstream = review.upstream;
    let mut summary = String::from("Source entries:\n");
    for (index, source) in review.sources.iter().enumerate() {
        let _ = writeln!(summary, "{}. {}", index + 1, source.entry);
    }
    if !upstream.executables.is_empty() {
        summary.push_str("\nExecutable binaries:\n");
        for path in &upstream.executables {
            let _ = writeln!(summary, "{path}");
        }
    }
    if !upstream.unpacked.is_empty() {
        summary.push_str("\nArchives Guardian unpacked:\n");
        for path in &upstream.unpacked {
            let _ = writeln!(summary, "{path}");
        }
    }
    if !upstream.lockfiles.is_empty() {
        summary.push_str("\nDependency lockfiles, as Guardian scanned them:\n");
        for line in upstream.lockfiles.iter().take(MAX_LEFT_OUT_NAMED) {
            let _ = writeln!(summary, "{line}");
        }
    }
    if upstream.changed.0 > 0 {
        let _ = writeln!(
            summary,
            "\nChanged since Guardian extracted the sources: {} file(s), {} of them supplied.",
            upstream.changed.0, upstream.changed.1
        );
    }
    let left_out = upstream
        .omitted
        .iter()
        .map(|(path, reason)| (format!("src/{path}"), *reason))
        .chain(
            upstream
                .unreviewed
                .iter()
                .filter(|(_, reason)| *reason != aur::NOT_REVIEWED_DATA)
                .cloned(),
        );
    let total = left_out.clone().count();
    if total > 0 {
        summary.push_str("\nLeft out:\n");
        for (path, reason) in left_out.take(MAX_LEFT_OUT_NAMED) {
            let _ = writeln!(summary, "{path}: {reason}");
        }
        if total > MAX_LEFT_OUT_NAMED {
            let _ = writeln!(
                summary,
                "and {} more, not named here",
                total - MAX_LEFT_OUT_NAMED
            );
        }
    }
    summary
}

/// A file the upstream code or the recipe runs or reads in as code that
/// was not reviewed as text (a binary, or one left out) leaves the review
/// incomplete: the build runs it. A prebuilt program the recipe runs is
/// asked about instead (see `prebuilt`): it could not be reviewed anyway.
pub(super) fn upstream_runs(report: &mut Report, step: &UpstreamStep<'_>, upstream: &Upstream) {
    for file in &upstream.files {
        for (index, line) in file.text.lines().enumerate() {
            for target in rules::run_targets(line) {
                if report.runs.len() >= review::MAX_RUNS {
                    report.runs_overflowed = true;
                    break;
                }
                report.runs.push(RunRef {
                    rel: file.path.clone(),
                    line: index + 1,
                    excerpt: line.trim().chars().take(200).collect(),
                    target,
                });
            }
        }
    }
    let unread: Vec<(String, String)> = upstream
        .omitted
        .iter()
        .map(|(path, why)| (format!("src/{path}"), (*why).to_string()))
        .chain(
            upstream
                .unreviewed
                .iter()
                .map(|(path, why)| (path.clone(), (*why).to_string())),
        )
        .chain(
            upstream
                .unread
                .keys()
                .map(|path| (path.clone(), "binary".to_string())),
        )
        .collect();
    review::check_runs(report, &unread);
    // The recipe's own functions run in the source tree as well, from
    // whichever of its directories they change into.
    let mut gapped: HashSet<(String, String)> = HashSet::new();
    for (name, text) in &step.functions.files {
        for (line, _, target) in aur::recipe_runs(text, &step.functions.variables) {
            let left_out = unread
                .iter()
                .filter(|(path, _)| !upstream.unread.contains_key(path))
                .find(|(path, _)| aur::is_target(path, &target));
            if let Some((path, why)) = left_out
                && gapped.len() < MAX_LEFT_OUT_NAMED
                && gapped.insert((name.clone(), path.clone()))
            {
                report.gaps.push(Gap::RunsUnread(format!(
                    "{name}:{line} runs or reads in {path} ({why}), which was not sent for review"
                )));
            }
        }
    }
}

/// Reviews the upstream files; the report is the caller's to print, once
/// it knows how the decision stands with permits (see `settle_upstream`).
pub(super) fn review_upstream_files(
    step: &UpstreamStep<'_>,
    settings: &Settings,
    review: &UpstreamReview<'_>,
    context: &[String],
    confirm: &mut dyn Confirm,
) -> (Report, Decision) {
    let upstream = review.upstream;
    let state_root = Store::default_root();
    let mut context = context.to_vec();
    context.extend(upstream_facts(review));
    let review_context = ReviewContext {
        settings,
        class: SourceClass::Aur,
        opencode: &OpenCode::UserPath,
        units: &[],
        state_root: state_root.as_deref(),
        context: &context,
    };
    let mut report = review::collected_report(
        format!("{} · upstream sources", step.build_dir.display()),
        &review_context,
    );
    for file in &upstream.files {
        review::analyze_upstream(&mut report, &file.path, &file.text);
    }
    review::analyze_payload(&mut report, "upstream-summary", &upstream_summary(review));
    for gap in &upstream.gaps {
        report.gaps.push(Gap::Package(Error::Refused(gap.clone())));
    }
    upstream_runs(&mut report, step, upstream);
    report.unread.clone_from(&upstream.unread);
    let units: Vec<Unit> = Identity::parse(&format!("aur-src:{}", step.key))
        .map(|identity| {
            vec![Unit {
                prefix: String::new(),
                identity,
            }]
        })
        .unwrap_or_default();
    let report = review::review_collected(report, &review_context, &units);
    let mut decision = report.decide(&|class| settings.policy(class));
    outln!(
        "Upstream: {} of {} code and build file(s) reviewed{}; {} data or documentation file(s), {} binary file(s) not reviewed{}.",
        upstream.files.len(),
        upstream.text_files,
        if upstream.whole {
            " (all of them)".to_string()
        } else {
            format!(
                " (build files and scripts first, then code by depth; {} code file(s) past the review budget)",
                upstream.left_out
            )
        },
        upstream.data_files,
        upstream.binary_files,
        if upstream.omitted.is_empty() {
            String::new()
        } else {
            format!("; {} other file(s) left out", upstream.omitted.len())
        }
    );
    for line in upstream
        .lockfiles
        .iter()
        .filter(|line| !line.ends_with("all on its registry"))
        .take(MAX_BINARIES_NAMED)
    {
        outln!("  ! lockfile {line}");
    }
    // Asked only of a build the review lets through, and never in its
    // place: a yes approves the programs, not the code beside them.
    // (`Limited` is a review with `ai = off`, which the build goes on from.)
    let passes = !matches!(decision, Decision::Blocked(_));
    if passes && !confirm_prebuilt(step, review.prebuilt, confirm) {
        decision = Decision::Blocked(Blocked::NotConfirmed);
    }
    (report, decision)
}
