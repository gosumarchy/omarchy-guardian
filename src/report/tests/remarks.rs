//! The low findings of a clear AI verdict: remarks where the profile shows
//! them, findings where it does not.

use super::super::html;
use super::{finding, report, reviewed};
use crate::agent::{AgentFinding, Status, review_from_json};
use crate::config::model::{Action, Named, Profile, Remarks, SourceClass, builtin};
use crate::json::Json;
use crate::layout::Painter;
use crate::report::{AgentOutcome, AgentRun, Blocked, Decision, Report, Severity};

const FINDINGS: Decision = Decision::Blocked(Blocked::Findings);

/// A reviewed run over `files` with a finding of each severity given, each
/// naming `named`.
fn run_naming(status: Status, files: &[&str], named: &str, severities: &[Severity]) -> AgentRun {
    let mut run = reviewed(status, files);
    if let AgentOutcome::Reviewed(review) = &mut run.outcome {
        review.findings = severities
            .iter()
            .enumerate()
            .map(|(index, severity)| AgentFinding {
                severity: *severity,
                file: named.into(),
                line: None,
                title: format!("noticed {index}"),
                reason: "upstream code quality".into(),
            })
            .collect();
    }
    run
}

fn run_with(status: Status, files: &[&str], severities: &[Severity]) -> AgentRun {
    run_naming(status, files, files[0], severities)
}

/// A report of `class` as a gate builds it under `profile` (see
/// `review::remark_classes`).
fn report_under(profile: Profile, class: SourceClass) -> Report {
    let mut report = report(class);
    if builtin(profile, class).ai_remarks == Remarks::Shown {
        report.remark_classes.push(class);
    }
    report
}

#[test]
fn only_strict_counts_the_low_findings_of_a_clear_verdict() {
    for (profile, expected) in [
        (Profile::Standard, Remarks::Shown),
        (Profile::LocalOnly, Remarks::Shown),
        (Profile::Strict, Remarks::Findings),
    ] {
        for class in SourceClass::ALL {
            assert_eq!(builtin(profile, *class).ai_remarks, expected);
        }
    }
    assert!(Remarks::Shown < Remarks::Findings);
}

#[test]
fn low_findings_of_a_clear_verdict_block_only_under_strict() {
    use Severity::{High, Low, Medium};
    for profile in [Profile::Standard, Profile::LocalOnly, Profile::Strict] {
        for status in [Status::Clear, Status::Suspicious] {
            for severities in [&[][..], &[Low, Low], &[Low, Medium], &[High]] {
                for local in [false, true] {
                    let mut report = report_under(profile, SourceClass::Aur);
                    report
                        .agent_runs
                        .push(run_with(status, &["PKGBUILD"], severities));
                    if local {
                        report.findings.push(finding("PKGBUILD"));
                    }
                    let remarks = status == Status::Clear
                        && severities == [Low, Low]
                        && profile != Profile::Strict;
                    let blocks = local
                        || status == Status::Suspicious
                        || (!severities.is_empty() && !remarks);
                    let case = format!("{profile:?} {status:?} {severities:?} local={local}");
                    assert_eq!(
                        report.decide(&|class| builtin(profile, class)),
                        if blocks { FINDINGS } else { Decision::Clear },
                        "{case}"
                    );
                    assert_eq!(report.remark_count(), if remarks { 2 } else { 0 }, "{case}");
                    // A remark is no alert; anything else is counted as before.
                    let low = severities.iter().filter(|severity| **severity == Low);
                    assert_eq!(
                        report.counts().low,
                        if remarks { 0 } else { low.count() },
                        "{case}"
                    );
                }
            }
        }
    }
}

#[test]
fn a_report_nobody_gave_remark_classes_counts_every_finding() {
    // As the system sweep builds its report, in every profile.
    let mut report = report(SourceClass::System);
    report.agent_runs.push(run_with(
        Status::Clear,
        &["~/.bashrc"],
        &[Severity::Low, Severity::Low],
    ));
    assert_eq!(
        report.decide(&|class| builtin(Profile::Standard, class)),
        FINDINGS
    );
    assert_eq!((report.remark_count(), report.counts().low), (0, 2));
    assert_eq!(
        report.audit_findings(),
        "high=0 medium=0 low=2 incomplete=0"
    );
    assert!(
        report
            .headline(FINDINGS)
            .0
            .starts_with("! REVIEW REQUIRED — 2 alert(s)")
    );
    assert_eq!(report.overruled_summary(10).len(), 2);
}

#[test]
fn one_run_with_more_than_remarks_blocks_and_the_others_keep_theirs() {
    for other in [
        run_with(Status::Suspicious, &["b.sh"], &[]),
        run_with(Status::Clear, &["b.sh"], &[Severity::Medium]),
        run_with(Status::Clear, &["b.sh"], &[Severity::Low, Severity::High]),
    ] {
        let mut report = report_under(Profile::Standard, SourceClass::Aur);
        report.agent_runs.push(run_with(
            Status::Clear,
            &["a.sh"],
            &[Severity::Low, Severity::Low],
        ));
        let alerts = match &other.outcome {
            AgentOutcome::Reviewed(review) => review.findings.len(),
            AgentOutcome::Unavailable(_) => 0,
        };
        report.agent_runs.push(other);
        assert_eq!(
            report.decide(&|class| builtin(Profile::Standard, class)),
            FINDINGS
        );
        // Everything is shown: the first run's as remarks, the other's as
        // the alerts they are, and a low one beside a high one is an alert.
        assert_eq!(report.remark_count(), 2);
        assert_eq!(report.counts().total(), alerts);
        let shown = report.findings_text(100, Painter::plain());
        assert!(shown.contains("AI remarks"), "{shown}");
        assert_eq!(shown.contains("AI findings"), alerts > 0, "{shown}");
        // A permit would overrule the block, not the remarks.
        let summary = report.overruled_summary(10);
        assert!(
            !summary.iter().any(|line| line.contains("a.sh")),
            "{summary:?}"
        );
        assert!(!summary.is_empty());
    }
}

#[test]
fn local_findings_act_as_before_beside_remarks() {
    let standard = |class| builtin(Profile::Standard, class);
    let lows = [Severity::Low, Severity::Low];

    // Official under standard: `on_findings = warn`.
    let mut official = report_under(Profile::Standard, SourceClass::Official);
    official.findings.push(finding("a/.INSTALL"));
    official
        .agent_runs
        .push(run_with(Status::Clear, &["a/.INSTALL"], &lows));
    assert_eq!(official.decide(&standard), Decision::Warned);
    assert_eq!(official.remark_count(), 2);
    let (headline, _) = official.headline(Decision::Warned);
    assert!(headline.starts_with("! WARNED — 1 alert(s)"), "{headline}");

    // Without the local finding it is clear, and a medium finding of the
    // AI's blocks an official package as before.
    official.findings.clear();
    assert_eq!(official.decide(&standard), Decision::Clear);
    official.agent_runs.push(run_with(
        Status::Clear,
        &["b/.INSTALL"],
        &[Severity::Medium],
    ));
    assert_eq!(official.decide(&standard), FINDINGS);

    // A class that blocks on local findings blocks, with the remarks
    // still remarks.
    let mut theme = report_under(Profile::Standard, SourceClass::Theme);
    theme.findings.push(finding("hyprland.lua"));
    theme
        .agent_runs
        .push(run_with(Status::Clear, &["hyprland.lua"], &lows));
    assert_eq!(theme.decide(&standard), FINDINGS);
    assert_eq!((theme.remark_count(), theme.counts().total()), (2, 1));
}

#[test]
fn under_strict_low_findings_follow_on_ai_suspicious() {
    let mut report = report_under(Profile::Strict, SourceClass::Aur);
    report
        .agent_runs
        .push(run_with(Status::Clear, &["PKGBUILD"], &[Severity::Low]));
    assert_eq!(
        report.decide(&|class| builtin(Profile::Strict, class)),
        FINDINGS
    );
    // Whoever set the knob to warn under strict is warned, as before.
    let warn = |class| {
        let mut policy = builtin(Profile::Strict, class);
        policy.on_ai_suspicious = Action::Warn;
        policy
    };
    assert_eq!(report.decide(&warn), Decision::Warned);
    assert_eq!(report.counts().low, 1);
}

#[test]
fn every_class_a_run_touches_must_show_remarks() {
    let files = ["core-pkg/.INSTALL", "chaotic-pkg/.INSTALL"];
    let transaction = |remark_classes: &[SourceClass]| {
        let mut report = report(SourceClass::ThirdPartyRepo);
        report
            .file_classes
            .insert(files[0].into(), SourceClass::Official);
        report
            .file_classes
            .insert(files[1].into(), SourceClass::ThirdPartyRepo);
        report.remark_classes = remark_classes.to_vec();
        report
    };
    let standard = |class| builtin(Profile::Standard, class);
    let both = [SourceClass::Official, SourceClass::ThirdPartyRepo];
    let low = [Severity::Low];

    // The run holds the third-party file alone and names the official
    // one, which another chunk carried; or it holds both, and names its
    // own third-party file; or it names a file nobody listed, which is of
    // the report's class.
    let cases: [(&str, &[&str], &str); 3] = [
        ("names a file outside the run", &files[1..], files[0]),
        ("two classes in one run", &files, files[1]),
        ("names an unknown file", &files[..1], "(no file named)"),
    ];
    for (name, run_files, named) in cases {
        let run = || run_naming(Status::Clear, run_files, named, &low);
        let mut shown = transaction(&both);
        shown.agent_runs.push(run());
        assert_eq!(shown.decide(&standard), Decision::Clear, "{name}");
        assert_eq!(shown.remark_count(), 1, "{name}");

        // One of the two classes counts them as findings: so they are.
        for one in both {
            let mut strict = transaction(&[one]);
            strict.agent_runs.push(run());
            assert_eq!(strict.decide(&standard), FINDINGS, "{name} {one:?}");
            assert_eq!(strict.remark_count(), 0, "{name} {one:?}");
        }
    }
}

/// A run over `PKGBUILD` with the review a reply of this JSON is read as.
fn run_from_reply(reply: &str) -> AgentRun {
    let mut run = reviewed(Status::Clear, &["PKGBUILD"]);
    run.outcome = AgentOutcome::Reviewed(review_from_json(&Json::parse(reply).unwrap()).unwrap());
    run
}

#[test]
fn a_severity_that_is_not_low_as_written_is_no_remark() {
    let standard = |class| builtin(Profile::Standard, class);
    for (severity, remark) in [
        (r#""severity":"low","#, true),
        (r#""severity":"LOW","#, true),
        (r#""severity":"lowest","#, false),
        (r#""severity":"info","#, false),
        (r#""severity":"","#, false),
        (r#""severity":1,"#, false),
        ("", false),
    ] {
        let mut report = report_under(Profile::Standard, SourceClass::Aur);
        report.agent_runs.push(run_from_reply(&format!(
            r#"{{"status":"clear","summary":"s","findings":[{{{severity}"file":"PKGBUILD","title":"t","reason":"r"}}]}}"#
        )));
        assert_eq!(
            report.decide(&standard),
            if remark { Decision::Clear } else { FINDINGS },
            "{severity}"
        );
        assert_eq!(report.remark_count(), usize::from(remark), "{severity}");
    }
}

#[test]
fn content_that_speaks_to_the_reviewer_is_never_a_remark() {
    let standard = |class| builtin(Profile::Standard, class);
    let mut report = report_under(Profile::Standard, SourceClass::Aur);
    report.agent_runs.push(run_from_reply(
        r#"{"status":"clear","summary":"s","addressed_to_reviewer":true,"findings":[{"severity":"low","file":"PKGBUILD","title":"t","reason":"r"}]}"#,
    ));
    assert_eq!(report.decide(&standard), FINDINGS);
    assert_eq!(report.remark_count(), 0);
    assert_eq!(report.decision_name(FINDINGS), "HIGH RISK");

    // The local rule for such text is a local finding, beside which the
    // remarks of a clear verdict change nothing.
    let mut local = report_under(Profile::Standard, SourceClass::Aur);
    local.findings.push(crate::report::LocalFinding {
        rule: crate::rules::RuleId::ReviewerInstruction,
        ..finding("PKGBUILD")
    });
    local
        .agent_runs
        .push(run_with(Status::Clear, &["PKGBUILD"], &[Severity::Low]));
    assert_eq!(local.decide(&standard), FINDINGS);
}

/// The review this change was made for: a locally built AUR package in
/// three chunks, all clear, with two low remarks on upstream code.
fn three_clear_chunks_with_two_remarks(profile: Profile) -> Report {
    let mut report = report_under(profile, SourceClass::Aur);
    report.subject = "demo · upstream sources".into();
    report.profile = "standard".into();
    report.text_files_reviewed = 3;
    for (index, file) in ["build.sh", "fetch.sh", "warn.sh"].iter().enumerate() {
        let mut run = reviewed(Status::Clear, &[file]);
        run.chunk = Some((index + 1, 3));
        report.agent_runs.push(run);
    }
    let remarks = [
        (
            1,
            "fetch.sh",
            12,
            "Download without certificate checks",
            "curl -k skips TLS verification for a release archive; the archive is checked against a pinned checksum afterwards.",
        ),
        (
            2,
            "warn.sh",
            4,
            "Unquoted command substitution",
            "The warning message expands $(basename $0) unquoted; a path with spaces would split.",
        ),
    ];
    for (run, file, line, title, reason) in remarks {
        if let AgentOutcome::Reviewed(review) = &mut report.agent_runs[run].outcome {
            review.findings.push(AgentFinding {
                severity: Severity::Low,
                file: file.into(),
                line: Some(line),
                title: title.into(),
                reason: reason.into(),
            });
        }
    }
    report
}

#[test]
fn a_clear_review_with_remarks_reads_as_clear() {
    let report = three_clear_chunks_with_two_remarks(Profile::Standard);
    let decision = report.decide(&|class| builtin(Profile::Standard, class));
    assert_eq!(decision, Decision::Clear);
    assert_eq!(decision.exit_status(), 0);
    assert!(decision.allows_running());
    assert_eq!(report.decision_name(decision), "CLEAR");
    assert_eq!(
        report.audit_findings(),
        "high=0 medium=0 low=0 incomplete=0 remarks=2"
    );
    assert!(report.overruled_summary(10).is_empty());

    let plain = Painter::plain();
    let banner = report.verdict_box(decision, 100, plain);
    let tables = report.findings_text(100, plain);
    let shown = format!("{banner}\n{tables}");
    for expected in [
        "✓ CLEAR — no known concerns found; the AI reviewer left 2 remark(s)",
        "Remarks: 2 low · the AI review is clear; these are not alerts",
        "  AI remarks",
        "They do not block.",
        "AI remark",
        "fetch.sh:12",
        "Download without certificate checks",
        "warn.sh:4",
        "Unquoted command substitution",
    ] {
        assert!(shown.contains(expected), "{expected}\n{shown}");
    }
    for absent in ["REVIEW REQUIRED", "Alerts:", "alert(s)", "AI finding"] {
        assert!(!shown.contains(absent), "{absent}\n{shown}");
    }
    let advice = crate::report::recommendation(decision);
    assert!(!advice.contains("do not install"), "{advice}");

    // The saved page says the same.
    let page = html::section(&report, decision);
    for expected in [
        r#"<span class="word green">CLEAR</span>"#,
        "0 HIGH · 0 MEDIUM · 0 LOW · 2 AI REMARK(S) · ",
        "<h3>AI remarks</h3>",
        "AI REMARK · fetch.sh:12",
        "Unquoted command substitution",
    ] {
        assert!(page.contains(expected), "{expected}\n{page}");
    }
    for absent in ["REVIEW REQUIRED", "<h3>Findings</h3>", "do not install"] {
        assert!(!page.contains(absent), "{absent}\n{page}");
    }
}

#[test]
fn under_strict_the_same_review_blocks_as_before() {
    let report = three_clear_chunks_with_two_remarks(Profile::Strict);
    let decision = report.decide(&|class| builtin(Profile::Strict, class));
    assert_eq!(decision, FINDINGS);
    assert_eq!(decision.exit_status(), 1);
    assert_eq!(report.decision_name(decision), "REVIEW REQUIRED");
    assert_eq!(
        report.audit_findings(),
        "high=0 medium=0 low=2 incomplete=0"
    );
    assert_eq!(report.overruled_summary(10).len(), 2);

    let plain = Painter::plain();
    let shown = format!(
        "{}\n{}",
        report.verdict_box(decision, 100, plain),
        report.findings_text(100, plain)
    );
    for expected in [
        "! REVIEW REQUIRED — 2 alert(s) across local and AI review",
        "Alerts: 0 high · 0 medium · 2 low",
        "  AI findings",
    ] {
        assert!(shown.contains(expected), "{expected}\n{shown}");
    }
    assert!(!shown.contains("emark"), "{shown}");
    let page = html::section(&report, decision);
    assert!(page.contains("REVIEW REQUIRED") && page.contains("<h3>Findings</h3>"));
    assert!(!page.contains("REMARK"), "{page}");
}
