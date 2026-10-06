//! Reading a provider's errors: out of time, input or content rejected,
//! asked to slow down.

use crate::error::Error;

/// What a run stopped by the timeout reports as its failure.
pub(super) const TIMED_OUT: &str = "timed out";

pub(super) fn out_of_time() -> Error {
    Error::Refused(
        "the AI saw the source and ran out of time reviewing it; retry, or raise timeout_secs"
            .into(),
    )
}

/// Whether a provider's error says the request itself was too much for
/// the model. That is the source's doing, not an absent reviewer: a file
/// made to overflow the model must not turn a review into a warning.
pub(super) fn rejects_input(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    // A provider asking to slow down speaks of tokens too.
    if asks_to_slow_down(&message) {
        return false;
    }
    [
        "prompt is too long",
        "prompt too long",
        "context length",
        "context_length",
        "maximum context",
        "input is too long",
        "maximum prompt length",
        "exceeds the maximum number of tokens",
        "request too large",
        "request entity too large",
        "request_too_large",
        "reduce the length",
        "exceeds the context window",
        "exceeds the available context size",
        "exceeded model token limit",
    ]
    .iter()
    .any(|sign| message.contains(sign))
}

/// Whether a lowercased provider error is a rate limit, a quota or an
/// overload: reasons to come back later, never the source's doing.
fn asks_to_slow_down(message: &str) -> bool {
    [
        "rate limit",
        "rate_limit",
        "throttl",
        "please wait",
        "try again",
        "quota",
        "overloaded",
    ]
    .iter()
    .any(|sign| message.contains(sign))
}

/// Whether a provider's error says it refused what it was sent: a safety
/// or usage-policy refusal, a content filter, a guardrail. A source can be
/// written to provoke that, so it is no absent reviewer either. The signs
/// are the wordings of Anthropic's API and Claude Code ("Usage Policy",
/// "Output blocked by content filtering policy", `stop_reason` refusal, a
/// safety monitor), of the `OpenAI` and Azure APIs (`content_filter`,
/// `content_policy_violation`, "content management policy", "safety
/// system"), Google's (`SAFETY`, `PROHIBITED_CONTENT`, `RECITATION`) and
/// Bedrock's guardrails.
pub(super) fn rejects_content(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    [
        "usage policy",
        "usage policies",
        "content filter",
        "content_filter",
        "contentfilter",
        "content management policy",
        "content policy",
        "content_policy",
        "content moderation",
        "moderation",
        "safety system",
        "safety monitor",
        "safety filter",
        "safety settings",
        "safety reasons",
        "finish_reason: safety",
        "finishreason: safety",
        "prohibited_content",
        "prohibited content",
        "recitation",
        "responsible ai",
        "responsibleai",
        "guardrail",
        "refusal",
        "violates",
        "violating",
        "policy violation",
        "violation of",
    ]
    .iter()
    .any(|sign| message.contains(sign))
        // A refusal that also says "try again" is still a refusal: the
        // words of a slow-down do not undo it. Only an error the provider
        // itself marks as a rate limit or an overload is an absent one.
        && !is_marked_slow_down(&message)
}

/// Whether a lowercased provider error carries the status code or the
/// error type of a rate limit or an overload (429, 529, `rate_limit_error`,
/// `overloaded_error`), rather than only words a refusal may use too.
fn is_marked_slow_down(message: &str) -> bool {
    let has_status = |code: &str| {
        message.match_indices(code).any(|(at, _)| {
            let digit_at = |index: Option<usize>| {
                index
                    .and_then(|index| message.as_bytes().get(index))
                    .is_some_and(u8::is_ascii_digit)
            };
            !digit_at(at.checked_sub(1)) && !digit_at(Some(at + code.len()))
        })
    };
    message.contains("rate_limit_error")
        || message.contains("overloaded_error")
        || has_status("429")
        || has_status("529")
}

pub(super) fn content_rejected(detail: &str) -> Error {
    Error::Refused(format!(
        "the AI provider refused this source ({detail}); a source can be written to be refused, so this is not an absent reviewer"
    ))
}
