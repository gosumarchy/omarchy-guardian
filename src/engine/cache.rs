//! Cached AI verdicts, one per chunk request. A verdict is reused only for
//! the exact same request (its instructions and scope included) under the
//! same prompt version, system prompt, model, variant, thinking level and
//! class.

use std::str;

use crate::agent::{self, AgentReview, Status};
use crate::config::model::{AgentSettings, Named, SourceClass};
use crate::engine::request::{PROMPT_VERSION, Request};
use crate::engine::store::{Store, VERDICTS};
use crate::error::Error;
use crate::json::Json;
use crate::sha256::Sha256;
use crate::time::SECONDS_PER_DAY;

/// Stands in for the per-run nonce when a request is hashed: the nonce is
/// random, everything else in the request is what was judged.
const KEY_NONCE: &str = "cache-key";

pub(super) struct Cached {
    pub(super) review: AgentReview,
    /// The `AgentSettings::label` of the run that produced it.
    pub(super) model: String,
    pub(super) age_days: u64,
}

pub(super) fn key(settings: &AgentSettings, class: SourceClass, request: &Request) -> String {
    let mut hasher = Sha256::new();
    let header = format!(
        "omarchy-guardian-verdict\0{PROMPT_VERSION}\0{}\0{}\0{}\0{}\0",
        settings.model.as_deref().unwrap_or_default(),
        settings.variant.as_deref().unwrap_or_default(),
        settings.thinking.name(),
        class.name()
    );
    hasher.update(header.as_bytes());
    // The rendered request holds the instructions and scope it was sent
    // with; the positional message and the system prompt are not in it.
    for prompt in agent::FIXED_PROMPTS {
        hasher.update(prompt.as_bytes());
        hasher.update(b"\0");
    }
    hasher.update(request.render(KEY_NONCE).as_bytes());
    hasher.finalize().to_string()
}

/// A digest of the two prompts outside the request and of `fixed`, the
/// request wording of a class (`Request::fixed_text`), for what a baseline
/// is bound to.
pub(super) fn prompt_digest(fixed: &str) -> String {
    let mut hasher = Sha256::new();
    for prompt in agent::FIXED_PROMPTS {
        hasher.update(prompt.as_bytes());
        hasher.update(b"\0");
    }
    hasher.update(fixed.as_bytes());
    hasher.finalize().to_string()
}

/// The cached verdict for `key` if it is younger than `max_age_secs`.
/// Entries that are expired, unreadable, dated in the future or stored under
/// another key are deleted.
pub(super) fn lookup(
    store: &Store,
    key: &str,
    now: u64,
    max_age_secs: u64,
) -> Result<Option<Cached>, Error> {
    let Some(bytes) = store.read(VERDICTS, key)? else {
        return Ok(None);
    };
    if let Some(cached) = decode(&bytes, key, now, max_age_secs) {
        Ok(Some(cached))
    } else {
        store.remove(VERDICTS, key)?;
        Ok(None)
    }
}

fn decode(bytes: &[u8], key: &str, now: u64, max_age_secs: u64) -> Option<Cached> {
    let value = Json::parse(str::from_utf8(bytes).ok()?).ok()?;
    if value.get("key").and_then(Json::as_str) != Some(key) {
        return None;
    }
    let recorded = value.get("recorded").and_then(Json::as_u64)?;
    let age = now.checked_sub(recorded)?;
    if age >= max_age_secs {
        return None;
    }
    let review = agent::review_from_json(value.get("review")?).ok()?;
    if review.status == Status::Inconclusive {
        return None;
    }
    Some(Cached {
        review,
        model: value.get("model").and_then(Json::as_str)?.to_string(),
        age_days: age / SECONDS_PER_DAY,
    })
}

/// Caches a live verdict. Inconclusive verdicts are not cached: they block,
/// and a later run may well conclude.
pub(super) fn save(
    store: &Store,
    key: &str,
    review: &AgentReview,
    model: &str,
    now: u64,
) -> Result<(), Error> {
    if review.status == Status::Inconclusive {
        return Ok(());
    }
    let entry = Json::object([
        ("key", Json::from(key)),
        ("recorded", Json::from(now)),
        ("model", Json::from(model)),
        ("review", agent::review_to_json(review)),
    ]);
    store.write(VERDICTS, key, entry.to_string().as_bytes())
}

/// Deletes every verdict that is expired or unreadable.
pub(super) fn expire(store: &Store, now: u64, max_age_secs: u64) -> Result<(), Error> {
    for name in store.list(VERDICTS)? {
        let fresh = store
            .read(VERDICTS, &name)?
            .is_some_and(|bytes| decode(&bytes, &name, now, max_age_secs).is_some());
        if !fresh {
            store.remove(VERDICTS, &name)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{expire, key, lookup, save};
    use crate::agent::{AgentReview, SourceFile, Status};
    use crate::config::model::{AgentSettings, SourceClass, Thinking};
    use crate::engine::request::Request;
    use crate::engine::store::{Store, VERDICTS};
    use crate::test_support::TempDir;

    const DAY: u64 = 86_400;

    fn request(content: &str) -> Request {
        Request::for_files(
            SourceClass::Aur,
            &[SourceFile {
                path: "PKGBUILD".into(),
                content: content.into(),
            }],
        )
    }

    fn review(status: Status) -> AgentReview {
        AgentReview {
            status,
            summary: "ok".into(),
            findings: Vec::new(),
        }
    }

    #[test]
    fn keys_cover_settings_class_and_content() {
        let settings = AgentSettings::default();
        let base = key(&settings, SourceClass::Aur, &request("a"));

        assert_eq!(key(&settings, SourceClass::Aur, &request("a")), base);
        assert_ne!(key(&settings, SourceClass::Aur, &request("b")), base);
        assert_ne!(key(&settings, SourceClass::Theme, &request("a")), base);
        let thinking = AgentSettings {
            thinking: Thinking::Max,
            ..AgentSettings::default()
        };
        assert_ne!(key(&thinking, SourceClass::Aur, &request("a")), base);
        let model = AgentSettings {
            model: Some("a/b".into()),
            ..AgentSettings::default()
        };
        assert_ne!(key(&model, SourceClass::Aur, &request("a")), base);
    }

    #[test]
    fn keys_cover_the_wording_of_the_request_and_of_the_prompts() {
        use crate::sha256::Sha256;

        // The instructions and scope are in the rendered request, which is
        // hashed whole: the key is the digest of the header, the two
        // prompts outside the request, and that text.
        let settings = AgentSettings::default();
        let request = request("a");
        let rendered = request.render(super::KEY_NONCE);
        assert!(rendered.contains("Review the supplied source for concrete malicious"));
        let digest_with = |prompts: [&str; 2], rendered: &str| {
            let mut hasher = Sha256::new();
            hasher.update(
                format!(
                    "omarchy-guardian-verdict\0{}\0\0\0default\0aur\0",
                    super::PROMPT_VERSION
                )
                .as_bytes(),
            );
            for prompt in prompts {
                hasher.update(prompt.as_bytes());
                hasher.update(b"\0");
            }
            hasher.update(rendered.as_bytes());
            hasher.finalize().to_string()
        };
        let base = key(&settings, SourceClass::Aur, &request);
        assert_eq!(base, digest_with(crate::agent::FIXED_PROMPTS, &rendered));
        // One changed word in either prompt, or in the instructions, and
        // the old verdict is not found, with the version left as it was.
        let [message, system] = crate::agent::FIXED_PROMPTS;
        assert_ne!(
            base,
            digest_with([message, &system.replace("only", "just")], &rendered)
        );
        assert_ne!(
            base,
            digest_with([&message.replace("nonce", "token"), system], &rendered)
        );
        assert_ne!(
            base,
            digest_with(
                crate::agent::FIXED_PROMPTS,
                &rendered.replace("concrete malicious", "malicious")
            )
        );
    }

    #[test]
    fn a_saved_verdict_is_found_until_it_expires() {
        let dir = TempDir::new("cache-roundtrip");
        let store = Store::open(dir.path().join("store")).unwrap();
        let key = key(&AgentSettings::default(), SourceClass::Aur, &request("a"));

        save(&store, &key, &review(Status::Suspicious), "m · high", 1_000).unwrap();

        let hit = lookup(&store, &key, 1_000 + DAY, 30 * DAY)
            .unwrap()
            .unwrap();
        assert_eq!(hit.review, review(Status::Suspicious));
        assert_eq!((hit.model.as_str(), hit.age_days), ("m · high", 1));

        assert!(
            lookup(&store, &key, 1_000 + 30 * DAY, 30 * DAY)
                .unwrap()
                .is_none()
        );
        assert!(store.list(VERDICTS).unwrap().is_empty());
    }

    #[test]
    fn inconclusive_verdicts_are_not_cached() {
        let dir = TempDir::new("cache-inconclusive");
        let store = Store::open(dir.path().join("store")).unwrap();
        save(&store, "k", &review(Status::Inconclusive), "m", 1).unwrap();
        assert!(store.list(VERDICTS).unwrap().is_empty());
    }

    #[test]
    fn entries_under_another_key_or_from_the_future_are_dropped() {
        let dir = TempDir::new("cache-mismatch");
        let store = Store::open(dir.path().join("store")).unwrap();
        let real = key(&AgentSettings::default(), SourceClass::Aur, &request("a"));
        let other = key(&AgentSettings::default(), SourceClass::Aur, &request("b"));

        save(&store, &real, &review(Status::Clear), "m", 1_000).unwrap();
        let bytes = store.read(VERDICTS, &real).unwrap().unwrap();
        store.write(VERDICTS, &other, &bytes).unwrap();
        assert!(lookup(&store, &other, 1_000, DAY).unwrap().is_none());
        assert!(store.read(VERDICTS, &other).unwrap().is_none());

        // A clock set back must not keep a verdict alive.
        assert!(lookup(&store, &real, 999, DAY).unwrap().is_none());
    }

    #[test]
    fn expire_keeps_fresh_verdicts_only() {
        let dir = TempDir::new("cache-expire");
        let store = Store::open(dir.path().join("store")).unwrap();
        let old = key(&AgentSettings::default(), SourceClass::Aur, &request("old"));
        let fresh = key(
            &AgentSettings::default(),
            SourceClass::Aur,
            &request("fresh"),
        );
        save(&store, &old, &review(Status::Clear), "m", 0).unwrap();
        save(&store, &fresh, &review(Status::Clear), "m", 10 * DAY).unwrap();
        store.write(VERDICTS, "garbage", b"not json").unwrap();

        expire(&store, 12 * DAY, 5 * DAY).unwrap();

        assert_eq!(store.list(VERDICTS).unwrap(), [fresh]);
    }
}
