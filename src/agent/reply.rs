//! Reading the reviewer's reply out of what each CLI printed, and the
//! stored form of a review.

use crate::error::Error;
use crate::json::Json;
use crate::report::Severity;

use super::provider::{TIMED_OUT, content_rejected, out_of_time, rejects_content, rejects_input};
use super::{
    ADDRESSED_FIELD, ADDRESSED_FILE, ADDRESSED_TITLE, AgentError, AgentFinding, AgentReview,
    NONCE_MISSING, Status,
};

/// Classifies a Claude Code `--output-format stream-json` transcript. A
/// `tool_use` block in any assistant message, or a permission denial, means
/// the model tried to use a tool. Extra turns alone do not: the CLI adds a
/// synthetic turn to continue a reply its safety classifier interrupted, which
/// happens when the model reasons about a credential-stealing payload.
pub(super) fn claude_verdict(
    output: &str,
    failure: Option<String>,
    nonce: &str,
) -> Result<AgentReview, AgentError> {
    let unavailable = |detail: String| {
        AgentError::Unavailable(Error::ToolFailed {
            tool: "claude".into(),
            detail,
        })
    };
    let events = Json::parse_stream(output).unwrap_or_default();
    let tool_use = events.iter().any(|event| {
        event.get("type").and_then(Json::as_str) == Some("assistant")
            && event
                .get("message")
                .and_then(|message| message.get("content"))
                .and_then(Json::as_array)
                .is_some_and(|content| {
                    content.iter().any(|block| {
                        block
                            .get("type")
                            .and_then(Json::as_str)
                            .is_some_and(|kind| kind.ends_with("tool_use"))
                    })
                })
    });
    let delivered = events
        .iter()
        .any(|event| event.get("type").and_then(Json::as_str) == Some("assistant"));
    let Some(result) = events
        .iter()
        .rev()
        .find(|event| event.get("type").and_then(Json::as_str) == Some("result"))
    else {
        // A run that ended without a result after the model used a tool, or
        // after it had started to answer, is not an absent reviewer: content
        // crafted to break the run must not turn a review into a warning.
        if tool_use {
            return Err(AgentError::Invalid(Error::Refused(
                "the Claude Code CLI attempted to use a tool during source review".into(),
            )));
        }
        return Err(match failure {
            Some(detail) if delivered && detail == TIMED_OUT => {
                AgentError::OutOfTime(out_of_time())
            }
            Some(detail) if delivered => AgentError::Invalid(Error::Refused(format!(
                "the AI saw the source and the review then failed ({detail}); retry"
            ))),
            Some(detail) => unavailable(detail),
            None => {
                AgentError::Invalid(Error::parse("the Claude Code result", "not a JSON result"))
            }
        });
    };
    let denials = result
        .get("permission_denials")
        .and_then(Json::as_array)
        .is_some_and(|denials| !denials.is_empty());
    if tool_use || denials {
        return Err(AgentError::Invalid(Error::Refused(
            "the Claude Code CLI attempted to use a tool during source review".into(),
        )));
    }
    let text = result
        .get("result")
        .and_then(Json::as_str)
        .unwrap_or_default();
    if result.get("is_error").and_then(Json::as_bool) == Some(true) {
        let detail = if text.is_empty() {
            failure.unwrap_or_else(|| "reported an error".into())
        } else {
            text.chars().take(300).collect()
        };
        // A model that saw the source and then declined or failed is not an
        // absent reviewer: content crafted to trigger a refusal must not
        // turn a review into a warning.
        let delivered = delivered
            || result
                .get("usage")
                .and_then(|usage| usage.get("output_tokens"))
                .and_then(Json::as_u64)
                .is_some_and(|tokens| tokens > 0);
        return Err(if delivered {
            AgentError::Invalid(Error::Refused(format!(
                "the AI saw the source and then declined or failed to review it ({detail}); retry"
            )))
        } else if rejects_input(&detail) {
            AgentError::Invalid(Error::Refused(format!(
                "the AI could not take this source in one request ({detail}); lower max_input_kib or use a model with a larger context"
            )))
        } else if rejects_content(&detail) {
            AgentError::Invalid(content_rejected(&detail))
        } else {
            unavailable(detail)
        });
    }
    if text.is_empty() {
        return Err(AgentError::Invalid(Error::Refused(
            "the Claude Code CLI returned no review text".into(),
        )));
    }
    parse_review(text, nonce).map_err(AgentError::Invalid)
}

/// What OpenCode's JSON event stream contained, gathered in full before the
/// exit status is considered.
#[derive(Debug, Default)]
pub(super) struct Events {
    pub(super) text: String,
    pub(super) tool_use: bool,
    pub(super) malformed: Option<Error>,
    pub(super) error: Option<String>,
    /// The model started a step or reasoned: the request reached it.
    delivered: bool,
}

pub(super) fn scan_events(output: &str) -> Events {
    let mut events = Events::default();

    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        let event = match Json::parse(line) {
            Ok(event) => event,
            Err(error) => {
                events
                    .malformed
                    .get_or_insert(Error::parse("OpenCode event stream", error));
                continue;
            }
        };

        match event.get("type").and_then(Json::as_str) {
            Some("error") => {
                let message = event
                    .get("error")
                    .and_then(|error| error.get("data"))
                    .and_then(|data| data.get("message"))
                    .and_then(Json::as_str)
                    .unwrap_or("OpenCode reported an agent error");
                events.error.get_or_insert_with(|| message.to_string());
            }
            Some("tool_use") => events.tool_use = true,
            Some("step_start" | "step-start" | "reasoning") => events.delivered = true,
            Some("text") => {
                if let Some(text) = event
                    .get("part")
                    .and_then(|part| part.get("text"))
                    .and_then(Json::as_str)
                {
                    events.text.push_str(text);
                }
            }
            Some(_) | None => {}
        }
    }

    events
}

/// Classifies a finished run. Only a run that produced neither text nor a
/// tool attempt can be `Unavailable`; `failure` is the exit-status detail
/// when OpenCode did not exit successfully.
pub(super) fn verdict(
    events: Events,
    failure: Option<String>,
    nonce: &str,
) -> Result<AgentReview, AgentError> {
    if events.tool_use {
        return Err(AgentError::Invalid(Error::Refused(
            "OpenCode attempted to use a tool during source review".into(),
        )));
    }
    if let Some(error) = events.malformed {
        return Err(AgentError::Invalid(error));
    }

    if !events.text.is_empty() {
        if let Some(message) = events.error {
            return Err(AgentError::Invalid(Error::ToolFailed {
                tool: "opencode".into(),
                detail: format!("reported an error after replying: {message}"),
            }));
        }
        return parse_review(&events.text, nonce).map_err(AgentError::Invalid);
    }

    if events.delivered
        && let Some(message) = &events.error
    {
        return Err(AgentError::Invalid(Error::Refused(format!(
            "the AI saw the source and then declined or failed to review it ({message}); retry"
        ))));
    }
    if events.delivered && failure.as_deref() == Some(TIMED_OUT) {
        return Err(AgentError::OutOfTime(out_of_time()));
    }
    // Wherever it is said: as an error event, or as the reason the run
    // failed.
    if let Some(message) = [events.error.as_deref(), failure.as_deref()]
        .into_iter()
        .flatten()
        .find(|message| rejects_input(message))
    {
        return Err(AgentError::Invalid(Error::Refused(format!(
            "the AI could not take this source in one request ({message}); lower max_input_kib or use a model with a larger context"
        ))));
    }
    if let Some(message) = [events.error.as_deref(), failure.as_deref()]
        .into_iter()
        .flatten()
        .find(|message| rejects_content(message))
    {
        return Err(AgentError::Invalid(content_rejected(message)));
    }
    if let Some(detail) = events.error.or(failure) {
        return Err(AgentError::Unavailable(Error::ToolFailed {
            tool: "opencode".into(),
            detail,
        }));
    }
    Err(AgentError::Invalid(Error::Refused(
        "OpenCode returned no review text".into(),
    )))
}

/// Removes one Markdown code fence around the reply, which models add even
/// when told not to.
fn strip_code_fence(text: &str) -> &str {
    let trimmed = text.trim();
    let Some(body) = trimmed.strip_prefix("```") else {
        return trimmed;
    };
    let body = body.strip_prefix("json").unwrap_or(body);
    body.strip_suffix("```").map_or(trimmed, str::trim)
}

pub fn parse_review(text: &str, nonce: &str) -> Result<AgentReview, Error> {
    let value = Json::parse(strip_code_fence(text))
        .map_err(|error| Error::parse("the OpenCode security report", error))?;
    if value.get("nonce").and_then(Json::as_str) != Some(nonce) {
        return Err(Error::parse("the OpenCode security report", NONCE_MISSING));
    }
    review_from_json(&value)
}

/// A review in the reply's own JSON shape, without the nonce.
pub fn review_to_json(review: &AgentReview) -> Json {
    let findings = review
        .findings
        .iter()
        .map(|finding| {
            let mut members = vec![
                (
                    "severity",
                    Json::from(finding.severity.label().to_ascii_lowercase()),
                ),
                ("file", Json::from(finding.file.as_str())),
            ];
            if let Some(line) = finding.line {
                members.push(("line", Json::from(line)));
            }
            members.push(("title", Json::from(finding.title.as_str())));
            members.push(("reason", Json::from(finding.reason.as_str())));
            Json::object(members)
        })
        .collect();
    Json::object([
        ("status", Json::from(review.status.name())),
        ("summary", Json::from(review.summary.as_str())),
        ("findings", Json::Array(findings)),
    ])
}

/// Reads a review from the reply's JSON shape; the nonce is not checked here.
pub fn review_from_json(value: &Json) -> Result<AgentReview, Error> {
    let invalid = |detail: &str| Error::parse("the OpenCode security report", detail);
    let status = value
        .get("status")
        .and_then(Json::as_str)
        .and_then(Status::parse)
        .ok_or_else(|| invalid("missing or invalid status"))?;
    let summary = value
        .get("summary")
        .and_then(Json::as_str)
        .ok_or_else(|| invalid("missing summary"))?
        .to_string();

    let mut findings: Vec<AgentFinding> = match value.get("findings") {
        None | Some(Json::Null) => Vec::new(),
        Some(findings) => findings
            .as_array()
            .ok_or_else(|| invalid("findings is not an array"))?
            .iter()
            .map(|finding| parse_finding(finding).ok_or_else(|| invalid("malformed finding")))
            .collect::<Result<_, _>>()?,
    };

    // A reply that says the content spoke to the reviewer is not taken at
    // its word for the rest: Guardian adds a finding of its own, so the
    // outcome follows `on_ai_suspicious` whatever status came with it. The
    // field is optional; a reply without it is read as before.
    let addressed = match value.get(ADDRESSED_FIELD) {
        Some(Json::Bool(addressed)) => *addressed,
        Some(Json::String(text)) => text.eq_ignore_ascii_case("true"),
        _ => false,
    };
    let status = if addressed {
        findings.push(AgentFinding {
            severity: Severity::High,
            file: ADDRESSED_FILE.into(),
            line: None,
            title: ADDRESSED_TITLE.into(),
            reason: "The AI reported text in the reviewed content that speaks to whoever \
reviews it (instructions, a verdict, a nonce or a reason to stop reading). A review of \
content that tries to steer its reviewer is not trusted to be clear."
                .into(),
        });
        match status {
            Status::Clear => Status::Suspicious,
            Status::Suspicious | Status::Inconclusive => status,
        }
    } else {
        status
    };

    Ok(AgentReview {
        status,
        summary,
        findings,
    })
}

/// Reads one finding of the reply. A finding is the model saying something
/// is wrong, so one written a little off the asked shape (two files named
/// in a list, a line given as "3-5", a severity it made up) is kept and
/// read as strictly as it can be, never dropped: voiding the whole reply
/// over it would turn a block with its reasons into a review that failed.
/// Only something that is not an object at all is malformed.
fn parse_finding(value: &Json) -> Option<AgentFinding> {
    value.as_object()?;
    let text = |key: &str| {
        value
            .get(key)
            .and_then(Json::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(str::to_string)
    };
    // The first file of a list stands for the finding; the rest are in
    // the reason the model gave.
    let file = text("file").or_else(|| {
        value
            .get("file")
            .and_then(Json::as_array)
            .and_then(|files| files.iter().find_map(Json::as_str))
            .map(str::to_string)
    });
    let line = match value.get("line") {
        Some(Json::String(written)) => written
            .trim()
            .split(|character: char| !character.is_ascii_digit())
            .next()
            .and_then(|digits| digits.parse::<u64>().ok()),
        Some(line) => line.as_u64(),
        None => None,
    }
    .filter(|line| *line > 0);

    Some(AgentFinding {
        // A severity that cannot be read counts as the worst.
        severity: value
            .get("severity")
            .and_then(Json::as_str)
            .and_then(Severity::parse)
            .unwrap_or(Severity::High),
        file: file.unwrap_or_else(|| "(no file named)".to_string()),
        line,
        title: text("title").unwrap_or_else(|| "a finding without a title".to_string()),
        reason: text("reason").unwrap_or_else(|| "the reviewer gave no reason".to_string()),
    })
}
