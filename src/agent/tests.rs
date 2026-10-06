//! Tests for `agent`.

use std::fs;

use super::{
    AgentError, Exposure, SourceFile, Status, claude_effort, claude_verdict, exposure_in,
    parse_review, review, review_from_json, review_to_json, scan_events, verdict,
};
use crate::config::model::SourceClass;
use crate::config::model::{AgentSettings, Thinking};
use crate::engine::request::Request;
use crate::json::Json;
use crate::report::Severity;
use crate::test_support::{
    TempDir, mock_opencode, mock_opencode_failing, mock_opencode_output, mock_opencode_then,
    write_script,
};
use crate::tools::Reviewer;

/// A stream-json transcript: `blocks` are the assistant's content blocks
/// before the result.
fn claude_result(blocks: &str, denials: &str, is_error: bool, result: &str) -> String {
    format!(
        "{{\"type\":\"system\",\"subtype\":\"init\"}}\n\
             {{\"type\":\"assistant\",\"message\":{{\"content\":[{blocks}]}}}}\n\
             {{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":{is_error},\
             \"num_turns\":2,\"permission_denials\":{denials},\"result\":{}}}\n",
        Json::from(result)
    )
}

const THINKING: &str = r#"{"type":"thinking","thinking":""}"#;

#[test]
fn claude_code_results_are_judged_like_opencode_ones() {
    let reply = r#"{"nonce":"n1","status":"clear","summary":"ok","findings":[]}"#;
    // A turn continued after a safety-classifier interruption is fine.
    let review = claude_verdict(&claude_result(THINKING, "[]", false, reply), None, "n1").unwrap();
    assert_eq!(review.status, Status::Clear);

    // A tool attempt is a wrong answer, not an absent reviewer.
    for output in [
        claude_result(
            r#"{"type":"tool_use","name":"Bash","input":{}}"#,
            "[]",
            false,
            reply,
        ),
        claude_result(
            r#"{"type":"server_tool_use","name":"web_search"}"#,
            "[]",
            false,
            reply,
        ),
        claude_result(THINKING, r#"[{"tool_name":"Read"}]"#, false, reply),
    ] {
        assert!(matches!(
            claude_verdict(&output, None, "n1"),
            Err(AgentError::Invalid(_))
        ));
    }
    // An error after the model saw the source is a failed review.
    let refused = "{\"type\":\"assistant\",\"message\":{\"content\":[]}}\n{\"type\":\"result\",\"is_error\":true,\"result\":\"API Error: usage policy\"}\n";
    assert!(matches!(
        claude_verdict(refused, None, "n1"),
        Err(AgentError::Invalid(_))
    ));
    let events = scan_events(
        "{\"type\":\"step_start\"}\n{\"type\":\"error\",\"error\":{\"data\":{\"message\":\"refused\"}}}\n",
    );
    assert!(matches!(
        verdict(events, None, "n1"),
        Err(AgentError::Invalid(_))
    ));
    // A provider error or a crash is an unavailable reviewer.
    assert!(matches!(
        claude_verdict(
            "{\"type\":\"system\",\"subtype\":\"init\"}\n{\"type\":\"result\",\"is_error\":true,\"result\":\"rate limited\",\"usage\":{\"output_tokens\":0}}\n",
            None,
            "n1"
        ),
        Err(AgentError::Unavailable(_))
    ));
    assert!(matches!(
        claude_verdict("", Some("exited with 1".into()), "n1"),
        Err(AgentError::Unavailable(_))
    ));
    // A run cut short after the model used a tool, or after it began
    // to answer, is no absent reviewer.
    let tool = r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash"}]}}"#;
    assert!(matches!(
        claude_verdict(tool, Some("timed out".into()), "n1"),
        Err(AgentError::Invalid(_))
    ));
    let began = r#"{"type":"assistant","message":{"content":[{"type":"text","text":"{"}]}}"#;
    assert!(matches!(
        claude_verdict(began, Some("timed out".into()), "n1"),
        Err(AgentError::OutOfTime(_))
    ));
    // The nonce must be echoed.
    assert!(matches!(
        claude_verdict(&claude_result(THINKING, "[]", false, reply), None, "other"),
        Err(AgentError::Invalid(_))
    ));
}

#[test]
fn claude_code_is_chosen_by_the_model_prefix() {
    assert_eq!(
        Reviewer::for_model(Some("claude-code/claude-sonnet-5-5")),
        Reviewer::ClaudeCode
    );
    assert_eq!(
        Reviewer::for_model(Some("anthropic/claude-sonnet-5-5")),
        Reviewer::OpenCode
    );
    assert_eq!(Reviewer::for_model(None), Reviewer::OpenCode);
    assert_eq!(claude_effort(Thinking::Default), None);
    assert_eq!(claude_effort(Thinking::Minimal), Some("low"));
    assert_eq!(claude_effort(Thinking::Max), Some("max"));
}

/// The render closure for a single whole-file request.
fn render(files: &[SourceFile]) -> impl Fn(&str) -> String + use<> {
    let request = Request::for_files(SourceClass::Source, files);
    move |nonce| request.render(nonce)
}

#[test]
fn reviews_round_trip_through_json() {
    let review = parse_review(
        r#"{"nonce":"n","status":"suspicious","summary":"s","findings":[
 {"severity":"high","file":"a.sh","line":3,"title":"t","reason":"r"},
 {"severity":"low","file":"b.sh","title":"t2","reason":"r2"}]}"#,
        "n",
    )
    .unwrap();
    assert_eq!(review_from_json(&review_to_json(&review)).unwrap(), review);
}

#[test]
fn extracts_json_text_events_from_opencode() {
    let output = r#"{"type":"step_start"}
{"type":"text","part":{"type":"text","text":"{\"status\":"}}
{"type":"text","part":{"type":"text","text":"\"clear\"}"}}"#;
    let events = scan_events(output);
    assert_eq!(events.text, r#"{"status":"clear"}"#);
    assert!(!events.tool_use && events.malformed.is_none() && events.error.is_none());
}

#[test]
fn rejects_tool_calls_errors_and_empty_replies() {
    let judge = |output: &str| verdict(scan_events(output), None, "n");

    assert!(matches!(
        judge(r#"{"type":"tool_use","part":{}}"#),
        Err(AgentError::Invalid(_))
    ));
    assert!(matches!(
        judge(r#"{"type":"error","error":{"name":"AuthError"}}"#),
        Err(AgentError::Unavailable(_))
    ));
    assert!(matches!(
        judge(r#"{"type":"step_start"}"#),
        Err(AgentError::Invalid(_))
    ));
    assert!(matches!(judge("not json"), Err(AgentError::Invalid(_))));
    // Out of time after the model had the source: not an absent
    // reviewer; before it, a slow provider.
    assert!(matches!(
        verdict(
            scan_events(r#"{"type":"step_start"}"#),
            Some("timed out".into()),
            "n"
        ),
        Err(AgentError::OutOfTime(_))
    ));
    assert!(matches!(
        verdict(scan_events(""), Some("timed out".into()), "n"),
        Err(AgentError::Unavailable(_))
    ));
    // A request the model cannot take is the source's doing, not an
    // absent reviewer.
    assert!(matches!(
        judge(
            r#"{"type":"error","error":{"data":{"message":"prompt is too long: 250000 tokens > 200000 maximum"}}}"#
        ),
        Err(AgentError::Invalid(_))
    ));
    assert!(matches!(
        claude_verdict(
            r#"{"type":"result","is_error":true,"result":"Prompt is too long"}"#,
            None,
            "n"
        ),
        Err(AgentError::Invalid(_))
    ));
    // A provider asking to slow down is an absent reviewer.
    assert!(matches!(
        claude_verdict(
            r#"{"type":"result","is_error":true,"result":"Too many tokens, please wait before trying again"}"#,
            None,
            "n"
        ),
        Err(AgentError::Unavailable(_))
    ));
    assert!(matches!(
        claude_verdict(
            r#"{"type":"result","is_error":true,"result":"Invalid API key"}"#,
            None,
            "n"
        ),
        Err(AgentError::Unavailable(_))
    ));
}

#[test]
fn parses_a_review_and_requires_the_nonce() {
    let reply = r#"```json
{"nonce":"abc","status":"suspicious","summary":"bad","findings":[
 {"severity":"high","file":"install.sh","line":4,"title":"t","reason":"r"}]}
```"#;
    let parsed = parse_review(reply, "abc").unwrap();
    assert_eq!(parsed.status, Status::Suspicious);
    assert_eq!(parsed.findings[0].severity, Severity::High);
    assert_eq!(parsed.findings[0].line, Some(4));

    assert!(parse_review(reply, "other").is_err());
    assert!(parse_review(r#"{"status":"clear","summary":"ok"}"#, "abc").is_err());
}

#[test]
fn rejects_an_invalid_status() {
    assert!(parse_review(r#"{"nonce":"n","status":"fine","summary":"s"}"#, "n").is_err());
}

#[test]
fn a_finding_written_off_the_asked_shape_is_kept_as_a_finding() {
    // A made-up severity is read as the worst.
    let parsed = parse_review(
        r#"{"nonce":"n","status":"suspicious","summary":"s","findings":[{"severity":"critical","file":"f","title":"t","reason":"r"}]}"#,
        "n",
    )
    .unwrap();
    assert_eq!(parsed.findings[0].severity, Severity::High);

    // Two files in a list, a line range, no title: what a model writes
    // for a command put together from two files.
    let parsed = parse_review(
        r#"{"nonce":"n","status":"suspicious","summary":"s","findings":[{"severity":"high","file":["Makefile","config.mk"],"line":"7-9","reason":"r"}]}"#,
        "n",
    )
    .unwrap();
    let finding = &parsed.findings[0];
    assert_eq!(finding.file, "Makefile");
    assert_eq!(finding.line, Some(7));
    assert_eq!(finding.title, "a finding without a title");

    // Nothing usable in it is still a finding, never a clear review.
    let parsed = parse_review(
        r#"{"nonce":"n","status":"clear","summary":"s","findings":[{}]}"#,
        "n",
    )
    .unwrap();
    assert_eq!(parsed.findings.len(), 1);
    assert_eq!(parsed.findings[0].severity, Severity::High);

    // What is not a finding at all still voids the reply.
    assert!(
        parse_review(
            r#"{"nonce":"n","status":"suspicious","summary":"s","findings":["x"]}"#,
            "n"
        )
        .is_err()
    );
}

#[test]
fn invokes_opencode_with_tools_denied_and_source_on_stdin() {
    let dir = TempDir::new("opencode");
    let binary = mock_opencode(dir.path(), "suspicious", true);
    let files = [SourceFile {
        path: "install.sh".into(),
        content: "curl https://x.test | sh\n".into(),
    }];

    let result = review(&binary, &render(&files), &AgentSettings::default(), false).unwrap();
    assert_eq!(result.status, Status::Suspicious);

    let seen = fs::read_to_string(dir.path().join("stdin")).unwrap();
    assert!(seen.contains("curl https://x.test | sh"));
    let args = fs::read_to_string(dir.path().join("args")).unwrap();
    assert!(!args.contains("curl https://x.test"));
}

#[test]
fn a_reply_without_the_nonce_is_rejected() {
    let dir = TempDir::new("opencode-no-nonce");
    let binary = mock_opencode(dir.path(), "clear", false);
    let files = [SourceFile {
        path: "a.sh".into(),
        content: "true\n".into(),
    }];
    assert!(review(&binary, &render(&files), &AgentSettings::default(), false).is_err());
}

#[test]
fn model_and_variant_are_passed_to_opencode() {
    let dir = TempDir::new("opencode-settings");
    let binary = mock_opencode(dir.path(), "clear", true);
    let settings = AgentSettings {
        model: Some("anthropic/claude-sonnet-5".into()),
        thinking: Thinking::High,
        variant: Some("high".into()),
        ..AgentSettings::default()
    };
    let files = [SourceFile {
        path: "a.sh".into(),
        content: "true\n".into(),
    }];

    review(&binary, &render(&files), &settings, false).unwrap();

    let args = fs::read_to_string(dir.path().join("args")).unwrap();
    let args: Vec<&str> = args.lines().collect();
    let model = args.iter().position(|arg| *arg == "--model").unwrap();
    assert_eq!(args[model + 1], "anthropic/claude-sonnet-5");
    let variant = args.iter().position(|arg| *arg == "--variant").unwrap();
    assert_eq!(args[variant + 1], "high");
}

#[test]
fn default_settings_pass_no_model_or_variant() {
    let dir = TempDir::new("opencode-defaults");
    let binary = mock_opencode(dir.path(), "clear", true);
    let files = [SourceFile {
        path: "a.sh".into(),
        content: "true\n".into(),
    }];

    review(&binary, &render(&files), &AgentSettings::default(), false).unwrap();

    let args = fs::read_to_string(dir.path().join("args")).unwrap();
    assert!(!args.contains("--model") && !args.contains("--variant"));
}

#[test]
fn provider_errors_are_unavailable() {
    let dir = TempDir::new("opencode-provider-error");
    let binary = mock_opencode_failing(
        dir.path(),
        "ProviderModelNotFoundError: no such variant xhigh",
    );
    let files = [SourceFile {
        path: "a.sh".into(),
        content: "true\n".into(),
    }];

    let error = review(&binary, &render(&files), &AgentSettings::default(), false).unwrap_err();
    let AgentError::Unavailable(error) = error else {
        panic!("expected unavailable, got {error:?}");
    };
    assert!(error.to_string().contains("xhigh"));

    let missing = review(
        std::path::Path::new("/nonexistent/opencode"),
        &render(&files),
        &AgentSettings::default(),
        false,
    );
    assert!(matches!(missing, Err(AgentError::Unavailable(_))));
}

#[test]
fn bad_replies_are_invalid() {
    let dir = TempDir::new("opencode-bad-reply");
    let binary = mock_opencode(dir.path(), "clear", false);
    let files = [SourceFile {
        path: "a.sh".into(),
        content: "true\n".into(),
    }];
    assert!(matches!(
        review(&binary, &render(&files), &AgentSettings::default(), false),
        Err(AgentError::Invalid(_))
    ));
    assert!(matches!(
        verdict(scan_events(r#"{"type":"tool_use","part":{}}"#), None, "n"),
        Err(AgentError::Invalid(_))
    ));
    assert!(matches!(
        verdict(
            scan_events(r#"{"type":"error","error":{"data":{"message":"rate limited"}}}"#),
            None,
            "n"
        ),
        Err(AgentError::Unavailable(_))
    ));
}

fn one_file() -> [SourceFile; 1] {
    [SourceFile {
        path: "a.sh".into(),
        content: "true\n".into(),
    }]
}

#[test]
fn a_tool_attempt_before_a_failed_exit_is_invalid() {
    let dir = TempDir::new("opencode-tool-then-exit");
    let binary = mock_opencode_output(dir.path(), r#"{"type":"tool_use","part":{}}"#, 1);

    assert!(matches!(
        review(
            &binary,
            &render(&one_file()),
            &AgentSettings::default(),
            false
        ),
        Err(AgentError::Invalid(_))
    ));
}

#[test]
fn a_reply_followed_by_an_error_is_invalid() {
    let dir = TempDir::new("opencode-reply-then-error");
    let binary = mock_opencode_then(
        dir.path(),
        "clear",
        true,
        r#"printf '%s\n' '{"type":"error","error":{"data":{"message":"stream aborted"}}}'
exit 1"#,
    );

    let error = review(
        &binary,
        &render(&one_file()),
        &AgentSettings::default(),
        false,
    )
    .unwrap_err();
    let AgentError::Invalid(error) = error else {
        panic!("expected invalid, got {error:?}");
    };
    assert!(error.to_string().contains("stream aborted"));
}

#[test]
fn an_error_event_without_output_is_unavailable() {
    let dir = TempDir::new("opencode-error-only");
    let binary = mock_opencode_output(
        dir.path(),
        r#"{"type":"error","error":{"data":{"message":"unknown variant"}}}"#,
        1,
    );

    let error = review(
        &binary,
        &render(&one_file()),
        &AgentSettings::default(),
        false,
    )
    .unwrap_err();
    let AgentError::Unavailable(error) = error else {
        panic!("expected unavailable, got {error:?}");
    };
    assert!(error.to_string().contains("unknown variant"));
}

#[test]
fn no_output_and_a_failed_exit_is_unavailable() {
    let dir = TempDir::new("opencode-silent-exit");
    let binary = mock_opencode_output(dir.path(), "", 1);

    assert!(matches!(
        review(
            &binary,
            &render(&one_file()),
            &AgentSettings::default(),
            false
        ),
        Err(AgentError::Unavailable(_))
    ));
}

#[test]
fn a_valid_reply_survives_a_failed_exit_without_an_error_event() {
    let dir = TempDir::new("opencode-reply-then-exit");
    let binary = mock_opencode_then(dir.path(), "clear", true, "exit 3");

    let result = review(
        &binary,
        &render(&one_file()),
        &AgentSettings::default(),
        false,
    )
    .unwrap();
    assert_eq!(result.status, Status::Clear);
}

#[test]
fn the_pacman_gate_runs_opencode_with_private_config_and_cache() {
    let dir = TempDir::new("agent-isolated");
    let mock = mock_opencode(dir.path(), "clear", true);
    // Record the environment around the mock.
    let wrapper = dir.path().join("wrapped");
    write_script(
        &wrapper,
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$XDG_CONFIG_HOME\" \"$XDG_CACHE_HOME\" \"$PWD\" > {}/env\nexec {} \"$@\"\n",
            dir.path().display(),
            mock.display()
        ),
    );
    let files = [SourceFile {
        path: "a.sh".into(),
        content: "true\n".into(),
    }];
    review(&wrapper, &render(&files), &AgentSettings::default(), true).unwrap();
    let env = fs::read_to_string(dir.path().join("env")).unwrap();
    let lines: Vec<&str> = env.lines().collect();
    assert!(
        lines[0].contains("omarchy-guardian-opencode") && lines[0].ends_with("/config"),
        "{env}"
    );
    assert!(lines[1].ends_with("/cache"), "{env}");
    assert!(
        lines[2].contains("omarchy-guardian-opencode") && lines[2].ends_with("/empty"),
        "{env}"
    );

    // A user-level review keeps the user's configuration and cache;
    // only the directory it runs in is Guardian's.
    review(&wrapper, &render(&files), &AgentSettings::default(), false).unwrap();
    let env = fs::read_to_string(dir.path().join("env")).unwrap();
    let lines: Vec<&str> = env.lines().collect();
    assert!(
        !lines[0].contains("omarchy-guardian-opencode")
            && !lines[1].contains("omarchy-guardian-opencode"),
        "{env}"
    );
    assert!(lines[2].ends_with("/empty"), "{env}");
}

#[test]
fn opencode_runs_in_an_empty_private_directory_with_its_other_inputs_off() {
    let dir = TempDir::new("agent-directory");
    let mock = mock_opencode(dir.path(), "clear", true);
    // Record where it runs, what is there, who may enter, and the
    // switches.
    let wrapper = dir.path().join("wrapped");
    write_script(
        &wrapper,
        &format!(
            "#!/bin/sh\n{{ pwd; ls -A | wc -l; stat -c %a .; env | grep '^OPENCODE_DISABLE' | sort; }} > {}/seen\nexec {} \"$@\"\n",
            dir.path().display(),
            mock.display()
        ),
    );
    let files = [SourceFile {
        path: "a.sh".into(),
        content: "true\n".into(),
    }];
    for isolated in [false, true] {
        review(
            &wrapper,
            &render(&files),
            &AgentSettings::default(),
            isolated,
        )
        .unwrap();
        let seen = fs::read_to_string(dir.path().join("seen")).unwrap();
        let lines: Vec<&str> = seen.lines().collect();
        assert!(!lines[0].starts_with("/usr"), "{seen}");
        assert_eq!(lines[1].trim(), "0", "{seen}");
        assert_eq!(lines[2], "700", "{seen}");
        assert_eq!(
            lines[3..],
            [
                "OPENCODE_DISABLE_AUTOUPDATE=1",
                "OPENCODE_DISABLE_CLAUDE_CODE=1",
                "OPENCODE_DISABLE_CLAUDE_CODE_PROMPT=1",
                "OPENCODE_DISABLE_CLAUDE_CODE_SKILLS=1",
                "OPENCODE_DISABLE_DEFAULT_PLUGINS=1",
                "OPENCODE_DISABLE_EXTERNAL_SKILLS=1",
                "OPENCODE_DISABLE_LSP_DOWNLOAD=1",
                "OPENCODE_DISABLE_PROJECT_CONFIG=1",
            ],
            "{seen}"
        );
        // `--dir` names the same directory, which is gone afterwards.
        let args = fs::read_to_string(dir.path().join("args")).unwrap();
        let args: Vec<&str> = args.lines().collect();
        let at = args.iter().position(|arg| *arg == "--dir").unwrap();
        assert_eq!(args[at + 1], lines[0], "{args:?}");
        assert!(!std::path::Path::new(lines[0]).exists());
    }
}

/// `exposure_in` with `set` as the variables that are set and `etc` in
/// place of `/etc`.
fn exposed(reviewer: Reviewer, privileged: bool, set: &[&str], etc: &TempDir) -> Exposure {
    exposure_in(
        reviewer,
        privileged,
        &|name| set.contains(&name),
        etc.path(),
    )
}

#[test]
fn variables_that_steer_the_reviewer_are_named_and_never_shown() {
    let etc = TempDir::new("agent-env");
    assert_eq!(
        exposed(Reviewer::ClaudeCode, false, &["HOME", "PATH"], &etc),
        Exposure::default()
    );
    let exposure = exposed(
        Reviewer::ClaudeCode,
        false,
        &[
            "ANTHROPIC_BASE_URL",
            "https_proxy",
            "NODE_EXTRA_CA_CERTS",
            "NODE_OPTIONS",
            "LD_PRELOAD",
            "OPENCODE_PERMISSION",
        ],
        &etc,
    );
    assert_eq!(exposure.refusal, None);
    assert!(
        matches!(
            exposure.notes.as_slice(),
            [kept, removed]
                if kept.starts_with(
                    "the reviewer ran with: ANTHROPIC_BASE_URL, https_proxy, NODE_EXTRA_CA_CERTS ("
                ) && removed
                    == "removed from the reviewer's environment: NODE_OPTIONS, LD_PRELOAD, OPENCODE_PERMISSION"
        ),
        "{:?}",
        exposure.notes
    );
    // Every variable the review names or removes is in exactly one list.
    for name in super::REMOVED_VARIABLES {
        assert!(!super::NAMED_VARIABLES.contains(name), "{name}");
    }
    for name in [
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_BEDROCK_BASE_URL",
        "ANTHROPIC_VERTEX_BASE_URL",
        "CLAUDE_CONFIG_DIR",
        "OPENCODE_CONFIG",
        "OPENCODE_CONFIG_DIR",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "NODE_EXTRA_CA_CERTS",
        "SSL_CERT_FILE",
    ] {
        assert!(super::NAMED_VARIABLES.contains(&name), "{name}");
    }
    for name in [
        "NODE_OPTIONS",
        "BUN_OPTIONS",
        "NODE_TLS_REJECT_UNAUTHORIZED",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
    ] {
        assert!(super::REMOVED_VARIABLES.contains(&name), "{name}");
    }
}

#[test]
fn system_wide_reviewer_settings_are_reported_and_refused_for_root_transactions() {
    let etc = TempDir::new("agent-managed");
    let claude = etc.path().join("claude-code");
    fs::create_dir_all(claude.join("managed-settings.d")).unwrap();
    let settings = claude.join("managed-settings.json");
    let judged = |reviewer, privileged| exposed(reviewer, privileged, &[], &etc);

    // Nothing there: nothing to say.
    assert_eq!(judged(Reviewer::ClaudeCode, true), Exposure::default());

    // Settings that only restrict are reported and used.
    fs::write(
        &settings,
        r#"{"permissions":{"deny":["WebFetch"]},"cleanupPeriodDays":7,"env":{},"hooks":null}"#,
    )
    .unwrap();
    let exposure = judged(Reviewer::ClaudeCode, true);
    assert_eq!(exposure.refusal, None);
    assert_eq!(
        exposure.notes,
        [format!(
            "the reviewer loads system-wide settings from {}",
            settings.display()
        )]
    );
    // They are Claude Code's: an OpenCode review does not read them.
    assert_eq!(judged(Reviewer::OpenCode, true), Exposure::default());

    // Each way of sending the review elsewhere or running a command.
    for (risky, key) in [
        (r#"{"apiKeyHelper":"/usr/local/bin/key"}"#, "apiKeyHelper"),
        (
            r#"{"env":{"ANTHROPIC_BASE_URL":"https://x.test"}}"#,
            "ANTHROPIC_BASE_URL, env",
        ),
        (r#"{"env":{"HTTPS_PROXY":"http://192.0.2.1:8080"}}"#, "env"),
        (r#"{"hooks":{"Stop":[{"hooks":[]}]}}"#, "hooks"),
        (r#"{"enabledPlugins":{"x@y":true}}"#, "enabledPlugins"),
        (r#"{"awsAuthRefresh":"aws sso login"}"#, "awsAuthRefresh"),
        (
            r#"{"model":{"api_base_url":"https://x.test"}}"#,
            "api_base_url",
        ),
        (r#"{"a":[{"b":{"Endpoint":"https://x.test"}}]}"#, "Endpoint"),
    ] {
        fs::write(&settings, risky).unwrap();
        let user = judged(Reviewer::ClaudeCode, false);
        assert_eq!(user.refusal, None, "{risky}");
        assert_eq!(user.notes.len(), 1, "{risky}");
        let root = judged(Reviewer::ClaudeCode, true);
        assert_eq!(root.notes, user.notes);
        let reason = root.refusal.unwrap();
        assert!(
            reason.contains(&format!("managed-settings.json sets {key}")),
            "{reason}"
        );
        assert!(!reason.contains("x.test"), "values are not shown: {reason}");
    }

    // What cannot be read as JSON is not known to be harmless.
    for unreadable in ["{ // a comment\n}", "", "{\"env\":"] {
        fs::write(&settings, unreadable).unwrap();
        let reason = judged(Reviewer::ClaudeCode, true).refusal.unwrap();
        assert!(reason.contains("cannot be read as JSON"), "{reason}");
    }
    fs::write(
        &settings,
        format!("{{\"a\":\"{}\"}}", "x".repeat(1024 * 1024)),
    )
    .unwrap();
    assert!(judged(Reviewer::ClaudeCode, true).refusal.is_some());

    // Drop-ins are settings too; other files in the directory are not.
    fs::write(&settings, "{}").unwrap();
    fs::write(
        claude.join("managed-settings.d/10-hooks.json"),
        r#"{"hooks":{"Stop":[1]}}"#,
    )
    .unwrap();
    fs::write(claude.join("managed-settings.d/notes.txt"), "hooks").unwrap();
    let exposure = judged(Reviewer::ClaudeCode, true);
    assert_eq!(exposure.notes.len(), 2, "{:?}", exposure.notes);
    assert!(
        exposure
            .refusal
            .unwrap()
            .contains("10-hooks.json sets hooks")
    );
}

#[test]
fn opencodes_managed_config_is_judged_the_same_way() {
    // OpenCode merges its managed config over the one Guardian passes.
    let etc = TempDir::new("agent-managed-opencode");
    let judged = |reviewer, privileged| exposed(reviewer, privileged, &[], &etc);
    let opencode = etc.path().join("opencode");
    fs::create_dir(&opencode).unwrap();
    fs::write(opencode.join("opencode.json"), r#"{"autoupdate":false}"#).unwrap();
    let exposure = judged(Reviewer::OpenCode, true);
    assert_eq!((exposure.notes.len(), exposure.refusal), (1, None));
    for (risky, key) in [
        (
            r#"{"provider":{"x":{"options":{"baseURL":"https://x.test"}}}}"#,
            "baseURL, provider",
        ),
        (r#"{"permission":{"bash":"allow"}}"#, "permission"),
        (r#"{"plugin":["x"]}"#, "plugin"),
        (
            r#"{"agent":{"guardian-review":{"tools":{"bash":true}}}}"#,
            "agent",
        ),
        (
            r#"{"instructions":["/etc/opencode/rules.md"]}"#,
            "instructions",
        ),
    ] {
        fs::write(opencode.join("opencode.json"), risky).unwrap();
        let reason = judged(Reviewer::OpenCode, true).refusal.unwrap();
        assert!(
            reason.contains(&format!("opencode.json sets {key}")),
            "{reason}"
        );
        assert_eq!(judged(Reviewer::OpenCode, false).refusal, None);
    }
    // A config with comments is one Guardian cannot read.
    fs::write(opencode.join("opencode.json"), "{}").unwrap();
    fs::write(opencode.join("opencode.jsonc"), "{ /* provider */ }").unwrap();
    let exposure = judged(Reviewer::OpenCode, true);
    assert_eq!(exposure.notes.len(), 2);
    assert!(
        exposure
            .refusal
            .unwrap()
            .contains("opencode.jsonc cannot be read")
    );
}

#[test]
fn a_provider_that_refuses_the_source_is_no_absent_reviewer() {
    // The wordings providers and the two CLIs use when the request
    // itself is refused; none came with any assistant output.
    for refused in [
        "API Error: Claude Code is unable to respond to this request, which appears to violate our Usage Policy (https://www.anthropic.com/legal/aup).",
        "API Error: 400 Output blocked by content filtering policy",
        "API output_content_filtered: the response was withheld",
        "The response was filtered due to the prompt triggering Azure OpenAI's content management policy. Please modify your prompt and retry.",
        "Your request was rejected as a result of our safety system.",
        "AI_APICallError: Invalid prompt: your prompt was flagged as potentially violating our usage policy.",
        "content_policy_violation",
        "Provider returned error: finish_reason: content_filter",
        "The model refused: refusal (stop_reason=refusal)",
        "Request blocked by the safety monitor",
        "Candidate was blocked due to PROHIBITED_CONTENT",
        "Blocked by guardrail: GUARDRAIL_INTERVENED",
        // A refusal that speaks of retrying, of waiting or of a quota
        // is a refusal: those words alone do not make it a slow-down.
        "Your prompt was flagged as violating our usage policy. Please try again with a different prompt.",
        "content_filter: the request was blocked. Please wait and try again later.",
        "Rejected by our safety system (request 4290 of your quota was not charged)",
        "The model is overloaded with requests like this one, which violate the content policy",
    ] {
        assert!(super::rejects_content(refused), "{refused}");
        let claude = format!(
            "{{\"type\":\"system\",\"subtype\":\"init\"}}\n{{\"type\":\"result\",\"is_error\":true,\"result\":{},\"usage\":{{\"output_tokens\":0}}}}\n",
            Json::from(refused)
        );
        let error = claude_verdict(&claude, None, "n").unwrap_err();
        let AgentError::Invalid(error) = error else {
            panic!("expected invalid for {refused}, got {error:?}");
        };
        assert!(error.to_string().contains("refused this source"), "{error}");

        let event = format!(
            "{{\"type\":\"error\",\"error\":{{\"data\":{{\"message\":{}}}}}}}",
            Json::from(refused)
        );
        assert!(
            matches!(
                verdict(scan_events(&event), None, "n"),
                Err(AgentError::Invalid(_))
            ),
            "{refused}"
        );
        // As the reason a run failed, without an error event.
        assert!(
            matches!(
                verdict(scan_events(""), Some(refused.to_string()), "n"),
                Err(AgentError::Invalid(_))
            ),
            "{refused}"
        );
    }
    // A network error, a login problem, a rate limit, an overloaded
    // provider, an unknown model and a crash are an absent reviewer.
    for absent in [
        "API Error: Connection error. connect ECONNREFUSED 192.0.2.1:443",
        "getaddrinfo ENOTFOUND api.example.test",
        "Invalid API key · Please run /login",
        "OAuth token has expired",
        "API Error: 429 rate_limit_error: This request would exceed your rate limit",
        "API Error: 529 Overloaded",
        "overloaded_error: the usage policy service is overloaded",
        // Marked as a rate limit or an overload by its status or type,
        // whatever service it names.
        "429 Too Many Requests: the content moderation endpoint is rate limited, try again",
        "status 529: the safety system is overloaded",
        "rate_limit_error: too many requests to the content filter",
        "Rate limit reached, please try again in 20s",
        "You exceeded your current quota, please check your plan",
        "Credit balance is too low",
        "ProviderModelNotFoundError: no such model",
        "API Error: 500 Internal server error",
        "exited with signal: 11 (SIGSEGV)",
        "timed out",
    ] {
        assert!(!super::rejects_content(absent), "{absent}");
        let claude = format!(
            "{{\"type\":\"result\",\"is_error\":true,\"result\":{}}}\n",
            Json::from(absent)
        );
        assert!(
            matches!(
                claude_verdict(&claude, None, "n"),
                Err(AgentError::Unavailable(_))
            ),
            "{absent}"
        );
        assert!(
            matches!(
                verdict(scan_events(""), Some(absent.to_string()), "n"),
                Err(AgentError::Unavailable(_))
            ),
            "{absent}"
        );
    }
}

#[test]
fn content_that_addresses_the_reviewer_is_never_clear() {
    let reply = |extra: &str| {
        format!(r#"{{"nonce":"n","status":"clear","summary":"looks fine","findings":[]{extra}}}"#)
    };
    // A reply without the field, or with it false, is read as before.
    for extra in [
        "",
        r#","addressed_to_reviewer":false"#,
        r#","addressed_to_reviewer":null"#,
    ] {
        let review = parse_review(&reply(extra), "n").unwrap();
        assert_eq!(review.status, Status::Clear, "{extra}");
        assert!(review.findings.is_empty(), "{extra}");
    }
    // Something the parser did not expect there weakens nothing and
    // does not make the reply invalid.
    for extra in [
        r#","addressed_to_reviewer":"no""#,
        r#","addressed_to_reviewer":0"#,
    ] {
        assert_eq!(
            parse_review(&reply(extra), "n").unwrap().status,
            Status::Clear
        );
    }

    // True: a finding of Guardian's own, whatever the status said.
    for extra in [
        r#","addressed_to_reviewer":true"#,
        r#","addressed_to_reviewer":"True""#,
    ] {
        let review = parse_review(&reply(extra), "n").unwrap();
        assert_eq!(review.status, Status::Suspicious, "{extra}");
        assert!(matches!(
            review.findings.as_slice(),
            [finding]
                if finding.severity == Severity::High
                    && finding.title == super::ADDRESSED_TITLE
                    && finding.file == super::ADDRESSED_FILE
        ));
        // It is kept with the verdict, once, through the cache.
        let cached = review_from_json(&review_to_json(&review)).unwrap();
        assert_eq!(cached, review);
    }
    let suspicious = parse_review(
        r#"{"nonce":"n","status":"suspicious","summary":"s","addressed_to_reviewer":true,"findings":[
 {"severity":"low","file":"a.sh","title":"t","reason":"r"}]}"#,
        "n",
    )
    .unwrap();
    assert_eq!(suspicious.status, Status::Suspicious);
    assert_eq!(suspicious.findings.len(), 2);
    let inconclusive = parse_review(
        r#"{"nonce":"n","status":"inconclusive","summary":"s","addressed_to_reviewer":true}"#,
        "n",
    )
    .unwrap();
    assert_eq!(inconclusive.status, Status::Inconclusive);
}
