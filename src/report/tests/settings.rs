//! The owner's own settings: AI findings in the sweep that the reviewer
//! marks `owner_setting` and Guardian checks before it shows them apart.

use super::super::html;
use super::{finding, report, reviewed};
use crate::agent::{Status, review_from_json};
use crate::config::model::{Profile, SourceClass, builtin};
use crate::json::Json;
use crate::layout::Painter;
use crate::report::{AgentOutcome, AgentRun, Blocked, Decision, Report};

const FINDINGS: Decision = Decision::Blocked(Blocked::Findings);
const BASHRC: &str = "~/.bashrc";

fn standard(class: SourceClass) -> crate::config::model::Policy {
    builtin(Profile::Standard, class)
}

/// A system sweep's report as `sweep::judge` makes it outside strict.
fn sweep() -> Report {
    let mut report = report(SourceClass::System);
    report.scope.setting_classes.push(SourceClass::System);
    report
}

/// A run over `files` whose review is `reply`'s.
fn run(files: &[&str], reply: &str) -> AgentRun {
    let mut run = reviewed(Status::Clear, files);
    run.outcome = AgentOutcome::Reviewed(review_from_json(&Json::parse(reply).unwrap()).unwrap());
    run
}

/// A reply of `status` with one finding naming `file`, graded `severity`
/// and claimed as the owner's setting.
fn claimed(status: &str, file: &str, severity: &str) -> String {
    format!(
        r#"{{"status":"{status}","summary":"s","findings":[{{"severity":"{severity}","file":"{file}","title":"skips permission prompts","reason":"alias","owner_setting":true}}]}}"#
    )
}

/// The sweep the change was made for: a clear review of `~/.bashrc` whose
/// one finding, an alias, is claimed as the owner's setting.
fn alias_sweep() -> Report {
    let mut report = sweep();
    report
        .agent_runs
        .push(run(&[BASHRC], &claimed("clear", BASHRC, "medium")));
    report
}

#[test]
fn a_checked_claim_is_a_setting_and_no_alert() {
    let report = alias_sweep();
    assert_eq!(report.decide(&standard), Decision::Clear);
    assert_eq!(report.owner_settings().count(), 1);
    assert_eq!(report.alerts().count(), 0);
    assert!(report.flagged_paths().is_empty());
    assert!(report.overruled_summary(10).is_empty());
    assert_eq!(
        report.audit_findings(),
        "high=0 medium=0 low=0 incomplete=0 settings=1"
    );

    let tables = report.findings_text(Decision::Clear, 100, Painter::plain());
    assert!(
        tables.contains("Your own settings (not alerts)"),
        "{tables}"
    );
    assert!(tables.contains("skips permission prompts"), "{tables}");
    assert!(!tables.contains("AI findings"), "{tables}");
    let page = html::section(&report, Decision::Clear, None);
    assert!(page.contains("<h3>Your own settings</h3>"), "{page}");
    assert!(page.contains("0 HIGH · 0 MEDIUM · 0 LOW"), "{page}");
}

#[test]
fn each_condition_alone_keeps_the_finding_an_alert() {
    // `named` is the file the finding names, as the alert shows it.
    let refused = |case: &str, named: &str, report: Report| {
        assert_eq!(report.owner_settings().count(), 0, "{case}");
        assert!(report.alerts().any(|(file, _, _)| file == named), "{case}");
        assert!(report.flagged_paths().contains(named), "{case}");
        assert_eq!(report.decide(&standard), FINDINGS, "{case}");
        let tables = report.findings_text(FINDINGS, 100, Painter::plain());
        assert!(!tables.contains("Your own settings"), "{case}: {tables}");
    };
    let with = |files: &[&str], reply: &str| {
        let mut report = sweep();
        report.agent_runs.push(run(files, reply));
        report
    };

    refused(
        "not claimed",
        BASHRC,
        with(
            &[BASHRC],
            &claimed("clear", BASHRC, "medium").replace(r#","owner_setting":true"#, ""),
        ),
    );
    refused(
        "graded high",
        BASHRC,
        with(&[BASHRC], &claimed("clear", BASHRC, "high")),
    );
    refused(
        "a severity that cannot be read counts as high",
        BASHRC,
        with(&[BASHRC], &claimed("clear", BASHRC, "minor")),
    );
    refused(
        "outside the home",
        "/etc/bash.bashrc",
        with(
            &["/etc/bash.bashrc"],
            &claimed("clear", "/etc/bash.bashrc", "medium"),
        ),
    );
    refused(
        "root's home, as `sweep --root` labels it",
        "/root/.bashrc",
        with(
            &["/root/.bashrc"],
            &claimed("clear", "/root/.bashrc", "medium"),
        ),
    );
    refused(
        "a name that is also a file outside the home",
        ".bashrc",
        with(
            &[BASHRC, "/etc/skel/.bashrc"],
            &claimed("clear", ".bashrc", "medium"),
        ),
    );
    refused("not sent in that run", BASHRC, {
        let mut report = with(&["~/.profile"], &claimed("clear", BASHRC, "medium"));
        report.agent_runs.push(reviewed(Status::Clear, &[BASHRC]));
        report
    });
    refused("strict: no class may hold settings", BASHRC, {
        let mut report = alias_sweep();
        report.scope.setting_classes.clear();
        report
    });
    refused(
        "the review said the content spoke to the reviewer",
        BASHRC,
        with(
            &[BASHRC],
            &claimed("clear", BASHRC, "medium")
                .replace(r#"{"status""#, r#"{"addressed_to_reviewer":true,"status""#),
        ),
    );
    refused("a class other than the sweep's", BASHRC, {
        let mut report = alias_sweep();
        report.scope.class = SourceClass::Aur;
        report
    });
    refused("a run that also holds a file of another class", BASHRC, {
        let mut report = with(&[BASHRC, "PKGBUILD"], &claimed("clear", BASHRC, "medium"));
        report
            .file_classes
            .insert("PKGBUILD".into(), SourceClass::Aur);
        report
    });
    refused("a local rule matched in the file", BASHRC, {
        let mut report = alias_sweep();
        report.findings.push(finding(BASHRC));
        report
    });

    // A local rule in another file leaves the claim as it is.
    let mut report = alias_sweep();
    report.findings.push(finding("~/.profile"));
    assert_eq!(report.owner_settings().count(), 1);
}

#[test]
fn a_suspicious_review_with_only_settings_still_blocks() {
    let mut report = sweep();
    report
        .agent_runs
        .push(run(&[BASHRC], &claimed("suspicious", BASHRC, "low")));
    assert_eq!(report.owner_settings().count(), 1);
    assert_eq!(report.counts().total(), 0);
    assert_eq!(report.decide(&standard), FINDINGS);
    assert_eq!(report.overruled_summary(10), ["AI review: SUSPICIOUS"]);
}

#[test]
fn a_claim_never_makes_a_remark() {
    // Where the low findings of a clear verdict are remarks, a claimed one
    // is neither a remark nor a setting, but an alert.
    let mut report = report(SourceClass::Aur);
    report.scope.remark_classes.push(SourceClass::Aur);
    report
        .agent_runs
        .push(run(&["PKGBUILD"], &claimed("clear", "PKGBUILD", "low")));
    assert!(!report.is_remarks(&report.agent_runs[0]));
    assert_eq!(report.remark_count(), 0);
    assert_eq!(report.decide(&standard), FINDINGS);
}
