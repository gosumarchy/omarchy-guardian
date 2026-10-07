//! Tests for `report`.

use super::{AgentOutcome, AgentRun, Blocked, Decision, Gap, LocalFinding, Report};
use crate::agent::{AgentFinding, AgentReview, Status};
use crate::config::model::{Profile, SourceClass, builtin};
use crate::error::Error;
use crate::layout::Painter;
use crate::osv::{Advisory, Audit};
use crate::report::Severity;
use crate::rules::RuleId;

fn standard(class: SourceClass) -> crate::config::model::Policy {
    builtin(Profile::Standard, class)
}

#[test]
fn a_permitted_report_says_so_and_names_what_it_overruled() {
    let mut report = Report::new("theme:demo");
    report.gaps.push(Gap::Undecodable("install.sh".into()));
    let blocked = Decision::Blocked(Blocked::Incomplete);
    assert!(report.headline(blocked).0.contains("INCOMPLETE"));
    assert_eq!(blocked.exit_status(), 2);

    report.permit = Some("0123456789abcdef".into());
    let (headline, _) = report.headline(blocked);
    assert!(headline.contains("PERMITTED"), "{headline}");
    assert!(
        headline.contains("permit 0123456789abcdef overrules INCOMPLETE"),
        "{headline}"
    );
    // A permit says nothing about a review that passed on its own.
    assert!(report.headline(Decision::Clear).0.contains("CLEAR"));
    // The decision itself is what it was: only the gate goes on.
    assert_eq!(report.decision_name(blocked), "INCOMPLETE");
}

#[test]
fn a_permit_needs_every_gap_to_be_about_hashed_content() {
    let refused = || Error::Refused("x".into());
    for gap in [
        Gap::OversizedText("x".into()),
        Gap::UnresolvedLfs("x".into()),
        Gap::SensitiveWithheld("x".into()),
        Gap::AgentInputTooLarge,
        Gap::EntryPointTooLarge("x".into()),
        Gap::Undecodable("x".into()),
        Gap::NoReviewableFiles,
        Gap::Agent(refused()),
        Gap::Dependency("x".into()),
        Gap::RunsUnread("x".into()),
        Gap::PackageUnread("x".into()),
    ] {
        assert!(gap.content_hashed(), "{gap}");
    }
    for gap in [
        Gap::Io(refused()),
        Gap::Symlink("x".into()),
        Gap::SpecialFile("x".into()),
        Gap::NonUtf8Name("x".into()),
        Gap::HashLimit("x".into()),
        Gap::GitState("x".into()),
        Gap::RootOnly("x".into()),
        Gap::Sweep("x".into()),
        Gap::TreeTooLarge { files: 1, bytes: 1 },
        Gap::Package(refused()),
    ] {
        assert!(!gap.content_hashed(), "{gap}");
        let mut report = Report::new("x");
        report.gaps.push(Gap::NoReviewableFiles);
        assert!(report.content_hashed());
        report.gaps.push(gap);
        assert!(!report.content_hashed());
    }
}

#[test]
fn the_audit_trail_gets_numbers_and_the_user_gets_the_reasons() {
    let mut report = Report::new("x");
    assert_eq!(report.audit_ai(), "none");
    assert_eq!(
        report.audit_findings(),
        "high=0 medium=0 low=0 incomplete=0"
    );
    report.agent_runs.push(reviewed(Status::Clear, &["a"]));
    let mut suspicious = reviewed(Status::Suspicious, &["b"]);
    suspicious.cached = Some("from cache: 1 day old".into());
    report.agent_runs.push(suspicious);
    report.agent_runs.push(AgentRun {
        files: vec!["c".into()],
        label: "m · high".into(),
        chunk: None,
        cached: None,
        outcome: AgentOutcome::Unavailable(Error::Refused("no network".into())),
    });
    assert_eq!(
        report.audit_ai(),
        "m · high chunks=3 clear=1 suspicious=1 inconclusive=0 unavailable=1 from-cache=1"
    );
    report.findings.push(LocalFinding {
        path: "install.sh".into(),
        line: 3,
        rule: RuleId::DownloadAndExecute,
        excerpt: "curl x | sh".into(),
    });
    report.gaps.push(Gap::Undecodable("blob".into()));
    let summary = report.overruled_summary(10);
    // Why the review is incomplete comes first, then the alerts.
    assert!(summary[0].starts_with("not reviewed: blob"), "{summary:?}");
    assert!(
        summary[1].ends_with("install.sh:3 download-and-execute"),
        "{summary:?}"
    );
    assert!(summary.iter().any(|line| line == "AI review: SUSPICIOUS"));
    assert!(
        summary
            .iter()
            .any(|line| line.starts_with("AI review unavailable"))
    );
    // Bounded, and it says what it left out.
    assert_eq!(report.overruled_summary(2).len(), 3);
    assert_eq!(report.overruled_summary(2)[2], "and 2 more");
}

fn local_findings(count: usize) -> Vec<LocalFinding> {
    (1..=count)
        .map(|line| LocalFinding {
            path: "install.sh".into(),
            line,
            rule: RuleId::DownloadAndExecute,
            excerpt: "curl x | sh".into(),
        })
        .collect()
}

fn not_attempted(chunk: (usize, usize)) -> AgentRun {
    AgentRun {
        chunk: Some(chunk),
        outcome: AgentOutcome::Unavailable(Error::Refused(format!(
            "{}: no reply",
            super::NOT_ATTEMPTED
        ))),
        ..unavailable(&["x"])
    }
}

#[test]
fn the_summary_keeps_why_the_review_is_incomplete_whatever_else_there_is() {
    // More alerts than the summary has lines for, and a gap.
    let mut report = Report::new("x");
    report.findings = local_findings(20);
    report
        .gaps
        .push(Gap::Agent(Error::Refused("no reply".into())));
    let summary = report.overruled_summary(16);
    assert_eq!(summary[0], "not reviewed: AI review failed: no reply");
    assert_eq!(summary.len(), 17);
    assert_eq!(summary[16], "and 5 more");

    // The first of eight chunks failed, so seven were never sent, beside
    // nine local findings: one line for the seven.
    let mut report = Report::new("x");
    report.findings = local_findings(9);
    report.agent_runs = (2..=8).map(|index| not_attempted((index, 8))).collect();
    report
        .gaps
        .push(Gap::Agent(Error::Refused("chunk 1/8: no reply".into())));
    let summary = report.overruled_summary(16);
    assert_eq!(
        summary[0],
        "not reviewed: AI review failed: chunk 1/8: no reply"
    );
    let collapsed: Vec<&String> = summary
        .iter()
        .filter(|line| line.contains("not attempted"))
        .collect();
    assert_eq!(
        collapsed,
        ["7 chunk(s) not attempted after an earlier chunk failed"]
    );
    assert_eq!(summary.len(), 11, "{summary:?}");

    // The second of four chunks failed and the two after it found sixteen
    // things between them.
    let mut report = Report::new("x");
    report.agent_runs.push(reviewed(Status::Clear, &["a"]));
    for file in ["c", "d"] {
        let mut run = reviewed(Status::Suspicious, &[file]);
        if let AgentOutcome::Reviewed(review) = &mut run.outcome {
            review.findings = (0..8)
                .map(|_| AgentFinding {
                    severity: Severity::High,
                    file: file.into(),
                    line: None,
                    title: "runs a download".into(),
                    reason: "mock".into(),
                })
                .collect();
        }
        report.agent_runs.push(run);
    }
    report
        .gaps
        .push(Gap::Agent(Error::Refused("chunk 2/4: no reply".into())));
    let summary = report.overruled_summary(16);
    assert_eq!(
        summary[0],
        "not reviewed: AI review failed: chunk 2/4: no reply"
    );
    assert_eq!(summary[16], "and 1 more");
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
    assert_eq!(Painter::plain().paint("CLEAR", "32"), "CLEAR");
    assert_eq!(
        Painter::colored().paint("CLEAR", "32"),
        "\x1b[32mCLEAR\x1b[0m"
    );
}
