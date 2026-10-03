//! The review engine: plans chunked AI requests for the files a review
//! queued, answers them from the verdict cache where it can, and keeps the
//! approved baselines of user-level sources
//! (docs/superpowers/specs/2026-09-28-review-engine-design.md).

pub mod baseline;
pub mod cache;
pub mod diff;
pub mod plan;
pub mod request;
pub mod store;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::agent::{self, AgentError, AgentReview, SourceFile};
use crate::config::Settings;
use crate::config::model::{AgentSettings, AiRequirement, SourceClass, Toggle};
use crate::engine::baseline::{Approved, Unit, Unread};
use crate::engine::plan::{HashOnly, ManifestEntry, Plan, PlanInput, Previous, Sent};
use crate::engine::request::Request;
use crate::engine::store::Store;
use crate::error::Error;
use crate::report::{AgentOutcome, AgentRun, LocalFinding};
use crate::tools::{OpenCode, Reviewer};

const SECONDS_PER_DAY: u64 = 86_400;

/// Bytes charged per local finding on top of its path and excerpt.
const FINDING_OVERHEAD: usize = 48;

/// What the review of one user-level target may remember.
pub struct Memory {
    pub store: Store,
    pub class: SourceClass,
    pub units: Vec<Unit>,
    pub use_cache: bool,
    pub use_diff: bool,
    pub cache_max_age_secs: u64,
    pub max_store_bytes: u64,
    pub now: u64,
}

impl Memory {
    /// `Ok(None)` when this review uses no memory: no state root, a pacman
    /// class, `ai = off`, or both cache and diff turned off. `Err` when it
    /// should, but the store cannot be used.
    pub fn open(
        settings: &Settings,
        class: SourceClass,
        units: Vec<Unit>,
        root: Option<PathBuf>,
    ) -> Result<Option<Self>, String> {
        let Some(root) = root else {
            return Ok(None);
        };
        if class.is_privileged() {
            return Ok(None);
        }
        let policy = settings.policy(class);
        if policy.ai == AiRequirement::Off {
            return Ok(None);
        }
        let limits = settings.store_settings();
        let use_cache = policy.cache == Toggle::On && limits.cache_days > 0;
        let use_diff = policy.diff == Toggle::On && !units.is_empty();
        if !use_cache && !use_diff {
            return Ok(None);
        }

        Ok(Some(Self {
            store: Store::open(root)?,
            class,
            units,
            use_cache,
            use_diff,
            cache_max_age_secs: u64::from(limits.cache_days) * SECONDS_PER_DAY,
            max_store_bytes: u64::from(limits.max_store_mib) * 1024 * 1024,
            now: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs()),
        }))
    }
}

/// Files that share one set of agent settings, reviewed as one plan.
pub struct Group<'a> {
    pub settings: &'a AgentSettings,
    pub class: SourceClass,
    pub files: &'a [SourceFile],
    pub findings: &'a [LocalFinding],
    /// The review's units, for ranking a unit-relative top-level path (spec
    /// §4); independent of whether memory is enabled for this review.
    pub units: &'a [Unit],
    /// Trusted facts for every request (see `Request::context`).
    pub context: &'a [String],
    /// Files hashed but not read, named in every request's manifest.
    pub hash_only: &'a [HashOnly],
    /// What the review cannot read (see `Unread`): an upgrade is reviewed
    /// as one only while these are what the approved version had.
    pub unread: &'a Unread,
}

/// What reviewing one group produced.
#[derive(Debug, Default)]
pub struct GroupReview {
    /// One run per chunk, in order.
    pub runs: Vec<AgentRun>,
    /// An invalid reply: the review is blocked and nothing from it is cached.
    pub invalid: Option<Error>,
    /// The plan needed more than `max_chunks` requests; nothing was sent.
    pub too_large: bool,
    /// An entry point larger than one request; nothing was sent.
    pub entry_point_too_large: Option<String>,
    /// Lines for the report: the upgrade summary and memory problems.
    pub notes: Vec<String>,
}

pub fn review_group(
    group: &Group<'_>,
    opencode: &OpenCode,
    memory: Option<&Memory>,
) -> GroupReview {
    // Defence in depth: the pacman invariant (privileged classes never touch
    // the store) must hold here too, not only via `Memory::open`.
    let memory = memory.filter(|_| !group.class.is_privileged());
    let mut review = GroupReview::default();
    let (previous, facts, unapproved) = match previous_version(memory, group, &mut review.notes) {
        Approval::Diff(approved) => {
            let unapproved = group.unread.keys().any(|path| !approved.covers(path));
            (Some(approved.files), Vec::new(), unapproved)
        }
        Approval::Changed(fact) => (None, vec![fact], false),
        Approval::None => (None, Vec::new(), false),
    };
    let flagged: BTreeSet<String> = group
        .findings
        .iter()
        .map(|finding| finding.path.clone())
        .collect();
    let findings_bytes = group
        .findings
        .iter()
        .map(|finding| finding.path.len() + finding.excerpt.len() + FINDING_OVERHEAD)
        .sum();
    let unit_prefixes: Vec<String> = group.units.iter().map(|unit| unit.prefix.clone()).collect();
    let input = PlanInput {
        files: group.files,
        flagged: &flagged,
        findings_bytes,
        previous: previous.as_ref(),
        max_input_bytes: group.settings.max_input_bytes,
        max_chunks: group.settings.max_chunks,
        unit_prefixes: &unit_prefixes,
        hash_only: group.hash_only,
    };
    // A tree identical to its approved version may have been approved by a
    // first review (a first install, or yay's second makepkg pass over it):
    // that first-review plan is used when the cache answers every one of its
    // chunks. Otherwise (the baseline came from an upgrade review, or the
    // verdicts expired) the normal upgrade plan is used, never a full
    // review that might be larger than the diff that was approved.
    let cached_first_review = previous
        .as_ref()
        .filter(|previous| is_identical(previous, group.files))
        .and_then(|_| {
            plan::build(&PlanInput {
                previous: None,
                ..input
            })
            .ok()
        })
        .filter(|first| is_fully_cached(group, first, memory));
    let built = match cached_first_review {
        Some(first) => Ok(first),
        None => plan::build(&input),
    };
    // A diff-mode review must never be less complete than a full one would
    // be, so two outcomes are reviewed in full instead. Nothing to send,
    // yet files are gone or unread files no approval covers are here: the
    // tree is not the approved one, and is not passed without a review. Or
    // the plan is too large: removed baseline paths alone can push the
    // manifest over the limit, and a full review may still fit.
    let full_instead = match &built {
        Ok(plan)
            if plan.upgrade && plan.chunks.is_empty() && (unapproved || has_removals(plan)) =>
        {
            Some(
                "nothing changed in the approved text, but the tree is not the approved one (files were removed, or unread files have no approval); reviewing in full instead",
            )
        }
        Err(too_large) if previous.is_some() && too_large.entry_point.is_none() => {
            Some("the diff-mode plan needed too many chunks; reviewing in full instead")
        }
        _ => None,
    };
    let built = match full_instead {
        Some(note) => plan::build(&PlanInput {
            previous: None,
            ..input
        })
        .inspect(|_| review.notes.push(note.to_string())),
        None => built,
    };
    let plan = match built {
        Ok(plan) => plan,
        Err(too_large) => {
            review.too_large = true;
            review.entry_point_too_large = too_large.entry_point;
            return review;
        }
    };
    if plan.upgrade {
        review.notes.push(upgrade_note(&plan.manifest));
        if plan.chunks.is_empty() {
            review.notes.push(
                "every file is unchanged since the approved version; no AI call was needed"
                    .to_string(),
            );
        }
    }

    let mut runner = Runner {
        group,
        opencode,
        memory,
        fresh: Vec::new(),
    };
    match runner.run_all(&requests(group, &plan, &facts), &mut review.notes) {
        Ok(runs) => review.runs = runs,
        Err((runs, error)) => {
            review.runs = runs;
            review.invalid = Some(error);
            return review;
        }
    }
    runner.save(&mut review.notes);
    review
}

/// One request per chunk of `plan`, each carrying the local findings for
/// the files it sends, and `facts` after the group's own.
fn requests(group: &Group<'_>, plan: &Plan, facts: &[String]) -> Vec<Request> {
    let count = plan.chunks.len();
    plan.chunks
        .iter()
        .enumerate()
        .map(|(index, items)| Request {
            class: group.class,
            upgrade: plan.upgrade,
            chunk: (index + 1, count),
            manifest: plan.manifest.clone(),
            findings: group
                .findings
                .iter()
                .filter(|finding| items.iter().any(|item| item.path() == finding.path))
                .cloned()
                .collect(),
            items: items.clone(),
            context: group.context.iter().chain(facts).cloned().collect(),
        })
        .collect()
}

/// Whether the verdict cache holds a verdict for every chunk of `plan`
/// under this group's settings and class; false without a cache or chunks.
fn is_fully_cached(group: &Group<'_>, plan: &Plan, memory: Option<&Memory>) -> bool {
    let Some(memory) = memory.filter(|memory| memory.use_cache) else {
        return false;
    };
    !plan.chunks.is_empty()
        && requests(group, plan, &[]).iter().all(|request| {
            let key = cache::key(group.settings, group.class, request);
            matches!(
                cache::lookup(&memory.store, &key, memory.now, memory.cache_max_age_secs),
                Ok(Some(_))
            )
        })
}

fn has_removals(plan: &Plan) -> bool {
    plan.manifest
        .iter()
        .any(|entry| entry.sent == Sent::Removed)
}

/// What an earlier approval means for this review.
enum Approval {
    /// The approved version to diff against.
    Diff(Approved),
    /// Not the approved version: what differs, as a fact for the AI.
    Changed(String),
    None,
}

/// The approved version to diff against, when this review uses diffs, the
/// baseline was approved under these agent settings, and what the review
/// does not read is what that version had: a binary or link that was
/// added, changed or removed may be what the unchanged text now runs, so
/// the text is then reviewed in full, and told what changed beside it.
fn previous_version(
    memory: Option<&Memory>,
    group: &Group<'_>,
    notes: &mut Vec<String>,
) -> Approval {
    let Some(memory) = memory.filter(|memory| memory.use_diff) else {
        return Approval::None;
    };
    match baseline::load(&memory.store, memory.class, &memory.units, group.settings) {
        Ok(Some(approved)) => match baseline::unread_changes(&approved, group.unread) {
            Some(fact) => {
                notes.push(
                    "what Guardian does not read here (binaries, links, skipped directories) cannot be matched to the approved version; reviewing in full"
                        .to_string(),
                );
                Approval::Changed(fact)
            }
            None => Approval::Diff(approved),
        },
        Ok(None) => Approval::None,
        Err(error) => {
            notes.push(format!(
                "approved baseline unavailable, reviewing in full: {error}"
            ));
            Approval::None
        }
    }
}

/// Whether `files` are exactly the approved version: the same paths with
/// the same content.
fn is_identical(previous: &Previous, files: &[SourceFile]) -> bool {
    let current: BTreeMap<&str, &str> = files
        .iter()
        .map(|file| (file.path.as_str(), file.content.as_str()))
        .collect();
    current.len() == files.len()
        && current.len() == previous.len()
        && previous
            .iter()
            .all(|(path, content)| current.get(path.as_str()) == Some(&content.as_str()))
}

fn upgrade_note(manifest: &[ManifestEntry]) -> String {
    let count = |sent: Sent| manifest.iter().filter(|entry| entry.sent == sent).count();
    format!(
        "upgrade of the approved version: {} file(s) sent as diffs, {} unchanged, {} removed, {} unchanged sent because a change names them; entry points and new files are reviewed whole, and so are changed files where that fits",
        count(Sent::Diff),
        count(Sent::Unchanged),
        count(Sent::Removed),
        count(Sent::Named)
    )
}

/// How many chunk reviews run at once, after the first.
const PARALLEL_REVIEWS: usize = 3;

/// The pause before retrying a review that found the AI unavailable.
const RETRY_DELAY: Duration = if cfg!(test) {
    Duration::ZERO
} else {
    Duration::from_secs(2)
};

/// A chunk's live review: the result, and the failure a retry recovered from.
type Live = (Result<AgentReview, AgentError>, Option<String>);

/// Runs a plan's requests and remembers the verdicts to cache.
struct Runner<'a> {
    group: &'a Group<'a>,
    opencode: &'a OpenCode,
    memory: Option<&'a Memory>,
    /// Live verdicts to cache once no chunk was invalid.
    fresh: Vec<(String, AgentReview)>,
}

impl Runner<'_> {
    /// One run per request, in order, or the runs before the first invalid
    /// reply together with that reply's error. The cache answers what it
    /// can; the first live request runs alone, so an unavailable AI costs
    /// one call (and its retry), and the rest run `PARALLEL_REVIEWS` at a
    /// time. Once a request finds the AI unavailable or invalid, requests
    /// not yet started are not attempted.
    fn run_all(
        &mut self,
        requests: &[Request],
        notes: &mut Vec<String>,
    ) -> Result<Vec<AgentRun>, (Vec<AgentRun>, Error)> {
        let memory = self.memory.filter(|memory| memory.use_cache);
        let keys: Vec<Option<String>> = requests
            .iter()
            .map(|request| {
                memory.map(|_| cache::key(self.group.settings, self.group.class, request))
            })
            .collect();
        let mut outcomes: Vec<Option<(AgentOutcome, Option<String>)>> = keys
            .iter()
            .map(|key| self.cached(key.as_deref(), notes))
            .collect();

        let live: Vec<usize> = (0..requests.len())
            .filter(|&index| outcomes[index].is_none())
            .collect();
        let mut results: Vec<Option<Live>> = requests.iter().map(|_| None).collect();
        if let Some((&first, rest)) = live.split_first() {
            match self.binary() {
                Err(error) => {
                    let reason = error.to_string();
                    outcomes[first] = Some((AgentOutcome::Unavailable(error), None));
                    for &index in rest {
                        outcomes[index] = Some((not_attempted(&reason), None));
                    }
                }
                Ok(binary) => {
                    let settings = self.group.settings;
                    let isolated = matches!(self.opencode, OpenCode::SystemOnly);
                    let probe = review_with_retry(&binary, &requests[first], settings, isolated);
                    let proceed = probe.0.is_ok();
                    results[first] = Some(probe);
                    if proceed {
                        for (index, result) in
                            review_parallel(&binary, requests, rest, settings, isolated)
                        {
                            results[index] = Some(result);
                        }
                    }
                }
            }
        }

        let mut runs = Vec::with_capacity(requests.len());
        let mut stopped: Option<String> = None;
        for (index, request) in requests.iter().enumerate() {
            let (outcome, cached) = match (outcomes[index].take(), results[index].take()) {
                (Some(done), _) => done,
                (None, Some((result, retried))) => {
                    if let Some(reason) = retried {
                        notes.push(format!(
                            "the AI review failed once and was retried: {reason}"
                        ));
                    }
                    match result {
                        Ok(review) => {
                            if let Some(key) = keys[index].clone() {
                                self.fresh.push((key, review.clone()));
                            }
                            (AgentOutcome::Reviewed(review), None)
                        }
                        Err(AgentError::Unavailable(error)) => {
                            stopped.get_or_insert_with(|| error.to_string());
                            (AgentOutcome::Unavailable(error), None)
                        }
                        // The official repositories' content is not chosen
                        // by whoever could write a source to keep the
                        // reviewer busy: there it is a slow provider.
                        Err(AgentError::OutOfTime(error))
                            if self.group.class == SourceClass::Official =>
                        {
                            stopped.get_or_insert_with(|| error.to_string());
                            (AgentOutcome::Unavailable(error), None)
                        }
                        Err(AgentError::Invalid(error) | AgentError::OutOfTime(error)) => {
                            return Err((runs, error));
                        }
                    }
                }
                (None, None) => {
                    let reason = stopped
                        .clone()
                        .unwrap_or_else(|| "an earlier chunk failed".into());
                    (not_attempted(&reason), None)
                }
            };
            runs.push(AgentRun {
                files: request.paths(),
                label: self.group.settings.label(),
                chunk: (request.chunk.1 > 1).then_some(request.chunk),
                cached,
                outcome,
            });
        }
        Ok(runs)
    }

    /// The cached verdict for `key`, if the cache has one.
    fn cached(
        &self,
        key: Option<&str>,
        notes: &mut Vec<String>,
    ) -> Option<(AgentOutcome, Option<String>)> {
        let memory = self.memory.filter(|memory| memory.use_cache)?;
        match cache::lookup(&memory.store, key?, memory.now, memory.cache_max_age_secs) {
            Ok(Some(hit)) => {
                let note = format!(
                    "from cache: reviewed by {} {} day(s) ago",
                    hit.model, hit.age_days
                );
                Some((AgentOutcome::Reviewed(hit.review), Some(note)))
            }
            Ok(None) => None,
            Err(error) => {
                notes.push(format!("verdict cache unavailable: {error}"));
                None
            }
        }
    }

    /// The reviewer CLI's binary for this group's model.
    fn binary(&self) -> Result<PathBuf, Error> {
        let reviewer = Reviewer::for_model(self.group.settings.model.as_deref());
        self.opencode.resolve_reviewer(reviewer)
    }

    /// Caches the live verdicts; only called when no chunk was invalid.
    fn save(&self, notes: &mut Vec<String>) {
        let Some(memory) = self.memory else {
            return;
        };
        let label = self.group.settings.label();
        for (key, review) in &self.fresh {
            if let Err(error) = cache::save(&memory.store, key, review, &label, memory.now) {
                notes.push(format!("could not cache a verdict: {error}"));
                return;
            }
        }
    }
}

fn not_attempted(reason: &str) -> AgentOutcome {
    AgentOutcome::Unavailable(Error::Refused(format!(
        "not attempted after an earlier chunk failed: {reason}"
    )))
}

/// One review, retried once after a short pause when the AI was unavailable
/// for a reason a retry can fix: not a timeout, which would double a long
/// wait, and not a reviewer that could not be started.
fn review_with_retry(
    binary: &Path,
    request: &Request,
    settings: &AgentSettings,
    isolated: bool,
) -> Live {
    let review = || {
        agent::review(
            binary,
            &|nonce: &str| request.render(nonce),
            settings,
            isolated,
        )
    };
    match review() {
        Err(AgentError::Unavailable(error)) if is_retryable(&error) => {
            thread::sleep(RETRY_DELAY);
            (review(), Some(error.to_string()))
        }
        // A reply that missed this run's nonce is asked for once more: a
        // model now and then drops it, and the next reply must carry its
        // own new nonce.
        Err(AgentError::Invalid(error)) if error.to_string().contains("nonce") => {
            (review(), Some(error.to_string()))
        }
        result => (result, None),
    }
}

fn is_retryable(error: &Error) -> bool {
    match error {
        Error::ToolFailed { detail, .. } => detail != "timed out",
        Error::Spawn { .. } => false,
        _ => true,
    }
}

/// Reviews `requests[index]` for each of `indexes`, `PARALLEL_REVIEWS` at a
/// time. A worker starts no new review once one was unavailable or invalid,
/// so those requests have no result.
fn review_parallel(
    binary: &Path,
    requests: &[Request],
    indexes: &[usize],
    settings: &AgentSettings,
    isolated: bool,
) -> Vec<(usize, Live)> {
    let next = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let results = Mutex::new(Vec::new());
    thread::scope(|scope| {
        for _ in 0..PARALLEL_REVIEWS.min(indexes.len()) {
            scope.spawn(|| {
                while !stop.load(Ordering::SeqCst) {
                    let Some(&index) = indexes.get(next.fetch_add(1, Ordering::SeqCst)) else {
                        break;
                    };
                    let live = review_with_retry(binary, &requests[index], settings, isolated);
                    if live.0.is_err() {
                        stop.store(true, Ordering::SeqCst);
                    }
                    results
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push((index, live));
                }
            });
        }
    });
    results.into_inner().unwrap_or_else(PoisonError::into_inner)
}

/// After the whole review: keep `approved` as the baseline, with the
/// `unread` files beside it, bound to the agent settings every file was
/// reviewed with (the caller passes it only
/// after every chunk was clear, with no gaps and a clear decision, and all
/// files shared one set of settings), then prune the store. Returns notes
/// for the report.
pub fn remember(
    memory: &Memory,
    approved: Option<(&[SourceFile], &AgentSettings)>,
    unread: &Unread,
) -> Vec<String> {
    let mut notes = Vec::new();
    if let Some((files, settings)) = approved.filter(|_| memory.use_diff)
        && let Err(error) = baseline::record(
            &memory.store,
            memory.class,
            &memory.units,
            files,
            unread,
            settings,
            memory.now,
        )
    {
        notes.push(format!("could not record the approved baseline: {error}"));
    }
    let pruned =
        cache::expire(&memory.store, memory.now, memory.cache_max_age_secs).and_then(|()| {
            baseline::collect_garbage(&memory.store, memory.max_store_bytes, memory.now)
        });
    if let Err(error) = pruned {
        notes.push(format!("could not prune the review memory: {error}"));
    }
    notes
}

#[cfg(test)]
#[expect(clippy::format_collect, reason = "test data generation")]
#[expect(
    clippy::type_complexity,
    reason = "test-only tuple, not worth a dedicated type"
)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::{Group, Memory, is_retryable, remember, review_group};
    use crate::agent::SourceFile;
    use crate::config::Settings;
    use crate::config::file::{AgentDefaults, PartialConfig};
    use crate::config::model::{AgentSettings, Profile, SourceClass, Thinking};
    use crate::engine::baseline::{self, Identity, Unit, Unread};
    use crate::engine::store::{Store, VERDICTS};
    use crate::error::Error;
    use crate::report::AgentOutcome;
    use crate::test_support::{TempDir, mock_opencode, mock_opencode_counting, write_script};
    use crate::tools::OpenCode;

    static NOTHING_UNREAD: Unread = Unread::new();

    fn file(path: &str, content: &str) -> SourceFile {
        SourceFile {
            path: path.into(),
            content: content.into(),
        }
    }

    fn units(identity: &str) -> Vec<Unit> {
        vec![Unit {
            prefix: String::new(),
            identity: Identity::parse(identity).unwrap(),
        }]
    }

    fn memory(state: &TempDir, units: Vec<Unit>) -> Memory {
        Memory {
            store: Store::open(state.path().join("store")).unwrap(),
            class: SourceClass::Aur,
            units,
            use_cache: true,
            use_diff: true,
            cache_max_age_secs: 86_400,
            max_store_bytes: 1 << 30,
            now: 1_000_000,
        }
    }

    fn group<'a>(settings: &'a AgentSettings, files: &'a [SourceFile]) -> Group<'a> {
        Group {
            settings,
            class: SourceClass::Aur,
            files,
            findings: &[],
            units: &[],
            context: &[],
            hash_only: &[],
            unread: &NOTHING_UNREAD,
        }
    }

    /// Three 300-byte files that each need their own chunk: overhead is
    /// 3 × (3 + 32) = 105, leaving 495 bytes, and each file costs 303.
    fn three_chunks() -> (AgentSettings, Vec<SourceFile>) {
        let settings = AgentSettings {
            max_input_bytes: 600,
            ..AgentSettings::default()
        };
        let files = ["a.c", "b.c", "c.c"]
            .map(|path| file(path, &"x".repeat(300)))
            .to_vec();
        (settings, files)
    }

    #[test]
    fn each_chunk_is_its_own_run() {
        let bin = TempDir::new("engine-chunks-bin");
        let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));
        let (settings, files) = three_chunks();

        let review = review_group(&group(&settings, &files), &opencode, None);

        let chunks: Vec<(Option<(usize, usize)>, Vec<String>)> = review
            .runs
            .iter()
            .map(|run| (run.chunk, run.files.clone()))
            .collect();
        assert_eq!(
            chunks,
            [
                (Some((1, 3)), vec!["a.c".to_string()]),
                (Some((2, 3)), vec!["b.c".to_string()]),
                (Some((3, 3)), vec!["c.c".to_string()]),
            ]
        );
    }

    #[test]
    fn a_cache_hit_makes_no_opencode_call() {
        let state = TempDir::new("engine-cache");
        let bin = TempDir::new("engine-cache-bin");
        let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));
        let memory = memory(&state, Vec::new());
        let settings = AgentSettings::default();
        let files = [file("a.c", "int main(void) { return 0; }\n")];

        let first = review_group(&group(&settings, &files), &opencode, Some(&memory));
        assert!(matches!(first.runs.as_slice(), [run] if run.cached.is_none()));
        fs::remove_file(bin.path().join("stdin")).unwrap();

        let second = review_group(&group(&settings, &files), &opencode, Some(&memory));
        assert!(matches!(
            second.runs.as_slice(),
            [run] if run.cached.as_deref().is_some_and(|note| note.starts_with("from cache"))
        ));
        assert!(!bin.path().join("stdin").exists());
    }

    #[test]
    fn cached_chunks_need_no_opencode() {
        let state = TempDir::new("engine-no-opencode");
        let bin = TempDir::new("engine-no-opencode-bin");
        let memory = memory(&state, Vec::new());
        let settings = AgentSettings::default();
        let files = [file("a.c", "int x;\n")];

        let live = OpenCode::At(mock_opencode(bin.path(), "clear", true));
        review_group(&group(&settings, &files), &live, Some(&memory));

        let missing = OpenCode::At(PathBuf::from("/nonexistent/opencode"));
        let review = review_group(&group(&settings, &files), &missing, Some(&memory));
        assert!(matches!(
            review.runs.as_slice(),
            [run] if matches!(run.outcome, AgentOutcome::Reviewed(_)) && run.cached.is_some()
        ));
    }

    #[test]
    fn an_invalid_chunk_blocks_and_caches_nothing() {
        let state = TempDir::new("engine-invalid");
        let bin = TempDir::new("engine-invalid-bin");
        let opencode = OpenCode::At(mock_opencode_counting(
            bin.path(),
            1,
            "printf '%s\\n' 'not json'",
        ));
        let memory = memory(&state, Vec::new());
        let (settings, files) = three_chunks();

        let review = review_group(&group(&settings, &files), &opencode, Some(&memory));

        assert!(review.invalid.is_some());
        assert_eq!(review.runs.len(), 1);
        assert!(memory.store.list(VERDICTS).unwrap().is_empty());
    }

    #[test]
    fn an_unavailable_first_chunk_is_retried_once_and_stops_later_calls() {
        let state = TempDir::new("engine-unavailable");
        let bin = TempDir::new("engine-unavailable-bin");
        let opencode = OpenCode::At(mock_opencode_counting(bin.path(), 0, "exit 1"));
        let memory = memory(&state, Vec::new());
        let (settings, files) = three_chunks();

        let review = review_group(&group(&settings, &files), &opencode, Some(&memory));

        assert!(review.invalid.is_none());
        assert_eq!(review.runs.len(), 3);
        assert!(
            review
                .runs
                .iter()
                .all(|run| matches!(run.outcome, AgentOutcome::Unavailable(_)))
        );
        assert!(matches!(
            &review.runs[2].outcome,
            AgentOutcome::Unavailable(error) if error.to_string().contains("not attempted")
        ));
        assert_eq!(
            fs::read_to_string(bin.path().join("count")).unwrap().trim(),
            "2"
        );
        assert!(memory.store.list(VERDICTS).unwrap().is_empty());
    }

    #[test]
    fn a_later_unavailable_chunk_keeps_the_other_verdicts() {
        let state = TempDir::new("engine-unavailable-later");
        let bin = TempDir::new("engine-unavailable-later-bin");
        let opencode = OpenCode::At(mock_opencode_counting(bin.path(), 1, "exit 1"));
        let memory = memory(&state, Vec::new());
        let (settings, files) = three_chunks();

        let review = review_group(&group(&settings, &files), &opencode, Some(&memory));

        assert!(review.invalid.is_none());
        assert!(matches!(review.runs[0].outcome, AgentOutcome::Reviewed(_)));
        assert!(
            review.runs[1..]
                .iter()
                .all(|run| matches!(run.outcome, AgentOutcome::Unavailable(_)))
        );
        assert_eq!(memory.store.list(VERDICTS).unwrap().len(), 1);
    }

    #[test]
    fn a_failure_the_retry_recovers_from_is_a_review_with_a_note() {
        let bin = TempDir::new("engine-retry-bin");
        let clear = mock_opencode(bin.path(), "clear", true);
        let flaky = bin.path().join("flaky");
        write_script(
            &flaky,
            &format!(
                "#!/bin/sh\nif [ ! -e \"$0.failed\" ]; then : >\"$0.failed\"; cat >/dev/null; \
                 echo 'rate limited' >&2; exit 1; fi\nexec {} \"$@\"\n",
                clear.display()
            ),
        );
        let settings = AgentSettings::default();
        let files = [file("a.c", "int x;\n")];

        let review = review_group(&group(&settings, &files), &OpenCode::At(flaky), None);

        assert!(matches!(
            review.runs.as_slice(),
            [run] if matches!(run.outcome, AgentOutcome::Reviewed(_))
        ));
        assert!(
            review
                .notes
                .iter()
                .any(|note| note.contains("retried") && note.contains("rate limited")),
            "{:?}",
            review.notes
        );
    }

    #[test]
    fn a_reply_that_misses_the_nonce_is_asked_for_once_more() {
        let bin = TempDir::new("engine-nonce-retry");
        // The first reply echoes another nonce; the second is right.
        let then = r#"if [ "$count" -eq 1 ]; then nonce=wrong; else nonce=$(printf '%s\n' "$input" | sed -n 's/^Nonce: //p' | tr -d '\n'); fi
reply="{\"nonce\":\"$nonce\",\"status\":\"clear\",\"summary\":\"mock\",\"findings\":[]}"
escaped=$(printf '%s' "$reply" | sed 's/"/\\"/g')
printf '{"type":"text","part":{"type":"text","text":"%s"}}\n' "$escaped""#;
        let opencode = OpenCode::At(mock_opencode_counting(bin.path(), 0, then));
        let settings = AgentSettings::default();
        let files = [file("install.sh", "echo hi\n")];
        let review = review_group(&group(&settings, &files), &opencode, None);
        assert!(review.invalid.is_none(), "{:?}", review.invalid);
        assert!(
            review.notes.iter().any(|note| note.contains("retried")),
            "{:?}",
            review.notes
        );
    }

    #[test]
    fn running_out_of_time_on_the_source_blocks_except_for_official_packages() {
        let bin = TempDir::new("engine-out-of-time");
        let opencode = OpenCode::At(mock_opencode_counting(
            bin.path(),
            0,
            "printf '{\"type\":\"step_start\"}\\n'\nsleep 5",
        ));
        let settings = AgentSettings {
            timeout_secs: 1,
            ..AgentSettings::default()
        };
        let files = [file("install.sh", "echo hi\n")];
        let aur = review_group(&group(&settings, &files), &opencode, None);
        assert!(aur.invalid.is_some(), "{:?}", aur.runs);
        let official = Group {
            class: SourceClass::Official,
            ..group(&settings, &files)
        };
        let official = review_group(&official, &opencode, None);
        assert!(official.invalid.is_none());
        assert!(matches!(
            official.runs.as_slice(),
            [run] if matches!(run.outcome, AgentOutcome::Unavailable(_))
        ));
    }

    #[test]
    fn a_timeout_is_not_retried() {
        let timeout = Error::ToolFailed {
            tool: "opencode".into(),
            detail: "timed out".into(),
        };
        let provider = Error::ToolFailed {
            tool: "opencode".into(),
            detail: "rate limited".into(),
        };
        assert!(!is_retryable(&timeout));
        assert!(is_retryable(&provider));
    }

    #[test]
    fn an_upgrade_sends_changed_files_as_diffs_and_entry_points_whole() {
        let state = TempDir::new("engine-upgrade");
        let bin = TempDir::new("engine-upgrade-bin");
        let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));
        let memory = memory(&state, units("aur:demo"));
        let settings = AgentSettings::default();
        // Large enough that a change to it is sent as a diff.
        let library: String = (1..=6000)
            .map(|line| format!("int value_{line} = {line};\n"))
            .collect();

        let first = [
            file("PKGBUILD", "pkgname=demo\n"),
            file("src/lib.c", &library),
        ];
        assert_eq!(
            review_group(&group(&settings, &first), &opencode, Some(&memory))
                .runs
                .len(),
            1
        );
        assert!(remember(&memory, Some((&first, &settings)), &NOTHING_UNREAD).is_empty());

        let upgraded = [
            file("PKGBUILD", "pkgname=demo\n"),
            file(
                "src/lib.c",
                &library.replace("value_20 = 20", "value_20 = 21"),
            ),
        ];
        let review = review_group(&group(&settings, &upgraded), &opencode, Some(&memory));

        assert!(
            review
                .notes
                .iter()
                .any(|note| note.contains("1 file(s) sent as diffs")),
            "{:?}",
            review.notes
        );
        let sent = fs::read_to_string(bin.path().join("stdin")).unwrap();
        assert!(sent.contains(r#""path":"src/lib.c","kind":"diff""#));
        assert!(sent.contains(r#""path":"PKGBUILD","kind":"whole""#));
        assert!(sent.contains("-int value_20 = 20;"));
    }

    #[test]
    fn an_unchanged_tree_is_a_first_review_answered_from_the_cache() {
        let state = TempDir::new("engine-unchanged");
        let bin = TempDir::new("engine-unchanged-bin");
        let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));
        let memory = memory(&state, units("aur:demo"));
        let settings = AgentSettings::default();
        let files = [
            file("PKGBUILD", "pkgname=demo\n"),
            file("src/lib.c", "int a;\n"),
        ];

        let first = review_group(&group(&settings, &files), &opencode, Some(&memory));
        assert!(matches!(first.runs.as_slice(), [run] if run.cached.is_none()));
        assert!(remember(&memory, Some((&files, &settings)), &NOTHING_UNREAD).is_empty());
        fs::remove_file(bin.path().join("stdin")).unwrap();

        let second = review_group(&group(&settings, &files), &opencode, Some(&memory));

        assert!(
            !second.notes.iter().any(|note| note.contains("upgrade")),
            "{:?}",
            second.notes
        );
        assert!(matches!(
            second.runs.as_slice(),
            [run] if run.cached.as_deref().is_some_and(|note| note.starts_with("from cache"))
        ));
        assert!(!bin.path().join("stdin").exists());
    }

    #[test]
    fn an_unchanged_tree_approved_by_an_upgrade_is_reviewed_as_an_upgrade() {
        let state = TempDir::new("engine-unchanged-upgrade");
        let bin = TempDir::new("engine-unchanged-upgrade-bin");
        let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));
        let memory = memory(&state, units("aur:demo"));
        let settings = AgentSettings::default();
        // Large enough that a change to it is sent as a diff.
        let library: String = (1..=6000)
            .map(|line| format!("int value_{line} = {line};\n"))
            .collect();
        let v1 = [
            file("PKGBUILD", "pkgname=demo\n"),
            file("src/lib.c", &library),
        ];
        assert!(remember(&memory, Some((&v1, &settings)), &NOTHING_UNREAD).is_empty());

        // Pass 1 of v2: an upgrade (src/lib.c as a diff), approved.
        let v2 = [
            file("PKGBUILD", "pkgname=demo\n"),
            file("src/lib.c", &library.replace("value_9 = 9", "value_9 = 10")),
        ];
        let first = review_group(&group(&settings, &v2), &opencode, Some(&memory));
        assert!(matches!(first.runs.as_slice(), [run] if run.cached.is_none()));
        assert!(
            fs::read_to_string(bin.path().join("stdin"))
                .unwrap()
                .contains(r#""kind":"diff""#)
        );
        assert!(remember(&memory, Some((&v2, &settings)), &NOTHING_UNREAD).is_empty());
        fs::remove_file(bin.path().join("stdin")).unwrap();

        // Pass 2 over the identical v2 tree: no first review of v2 is
        // cached, so it stays an upgrade and only the entry point is sent.
        let second = review_group(&group(&settings, &v2), &opencode, Some(&memory));

        assert!(
            second
                .notes
                .iter()
                .any(|note| note.contains("0 file(s) sent as diffs, 1 unchanged, 0 removed")),
            "{:?}",
            second.notes
        );
        let sent = fs::read_to_string(bin.path().join("stdin")).unwrap();
        assert!(sent.contains("This is an upgrade"));
        assert!(sent.contains(r#""path":"src/lib.c","bytes":"#));
        assert!(sent.contains(r#""sent":"unchanged""#));
        assert!(sent.contains(r#""path":"PKGBUILD","kind":"whole""#));
        assert!(!sent.contains(r#""path":"src/lib.c","kind""#));
    }

    #[test]
    fn an_upgrade_with_nothing_to_send_says_so() {
        let state = TempDir::new("engine-nothing-to-send");
        let bin = TempDir::new("engine-nothing-to-send-bin");
        let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));
        let memory = memory(&state, units("aur:demo"));
        let settings = AgentSettings::default();
        // No entry point, and nothing changed.
        let approved = [file("src/lib.c", "int a;\n"), file("src/old.c", "int b;\n")];
        assert!(remember(&memory, Some((&approved, &settings)), &NOTHING_UNREAD).is_empty());

        let review = review_group(&group(&settings, &approved), &opencode, Some(&memory));

        assert!(review.runs.is_empty() && !review.too_large && review.invalid.is_none());
        assert!(
            review
                .notes
                .iter()
                .any(|note| note.contains("0 file(s) sent as diffs, 2 unchanged, 0 removed")),
            "{:?}",
            review.notes
        );
        assert!(
            review.notes.iter().any(|note| note
                == "every file is unchanged since the approved version; no AI call was needed"),
            "{:?}",
            review.notes
        );
        assert!(!bin.path().join("stdin").exists());
    }

    #[test]
    fn an_upgrade_that_only_removes_files_is_reviewed_in_full() {
        let state = TempDir::new("engine-only-removed");
        let bin = TempDir::new("engine-only-removed-bin");
        let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));
        let memory = memory(&state, units("aur:demo"));
        let settings = AgentSettings::default();
        let approved = [file("src/lib.c", "int a;\n"), file("src/old.c", "int b;\n")];
        assert!(remember(&memory, Some((&approved, &settings)), &NOTHING_UNREAD).is_empty());

        let current = [file("src/lib.c", "int a;\n")];
        let review = review_group(&group(&settings, &current), &opencode, Some(&memory));

        assert_eq!(review.runs.len(), 1);
        assert!(
            review
                .notes
                .iter()
                .any(|note| note.contains("the tree is not the approved one")),
            "{:?}",
            review.notes
        );
        let sent = fs::read_to_string(bin.path().join("stdin")).unwrap();
        assert!(!sent.contains("This is an upgrade"));
        assert!(sent.contains(r#""path":"src/lib.c","kind":"whole""#));
    }

    #[test]
    fn a_unit_without_a_baseline_does_not_undo_another_units() {
        let settings = AgentSettings::default();
        let unit = |prefix: &str, identity: &str| Unit {
            prefix: prefix.into(),
            identity: Identity::parse(identity).unwrap(),
        };
        let unread = |entries: &[&str]| -> Unread {
            entries
                .iter()
                .map(|path| ((*path).to_string(), "a".repeat(64)))
                .collect()
        };
        let state = TempDir::new("engine-two-units");
        let bin = TempDir::new("engine-two-units-bin");
        let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));
        // Only `a/` was ever approved.
        let approved = Memory {
            units: vec![unit("a/", "theme:a")],
            ..memory(&state, Vec::new())
        };
        let a = [file("a/init.lua", "print(1)\n")];
        let a_unread = unread(&["a/helper.so"]);
        assert!(remember(&approved, Some((&a, &settings)), &a_unread).is_empty());

        let both = Memory {
            units: vec![unit("a/", "theme:a"), unit("b/", "theme:b")],
            ..memory(&state, Vec::new())
        };
        // `b/` has text: it is sent whole, `a/` stays approved.
        let files = [
            file("a/init.lua", "print(1)\n"),
            file("b/init.lua", "print(2)\n"),
        ];
        let all_unread = unread(&["a/helper.so", "b/helper.so"]);
        let with_b = Group {
            unread: &all_unread,
            ..group(&settings, &files)
        };
        let review = review_group(&with_b, &opencode, Some(&both));
        assert_eq!(review.runs.len(), 1, "{:?}", review.notes);
        let sent = fs::read_to_string(bin.path().join("stdin")).unwrap();
        assert!(sent.contains("This is an upgrade"));
        assert!(sent.contains(r#""path":"b/init.lua","kind":"whole""#));
        assert!(!sent.contains(r#""path":"a/init.lua","kind""#));

        // `b/` is only a binary: nothing to send, and nobody approved it.
        fs::remove_file(bin.path().join("stdin")).unwrap();
        let only_binary = Group {
            unread: &all_unread,
            ..group(&settings, &a)
        };
        let review = review_group(&only_binary, &opencode, Some(&both));
        assert_eq!(review.runs.len(), 1, "{:?}", review.notes);
        assert!(
            review
                .notes
                .iter()
                .any(|note| note.contains("the tree is not the approved one")),
            "{:?}",
            review.notes
        );
        let sent = fs::read_to_string(bin.path().join("stdin")).unwrap();
        assert!(sent.contains(r#""path":"a/init.lua","kind":"whole""#));
    }

    #[test]
    fn a_new_or_changed_binary_makes_an_upgrade_a_full_review() {
        let digest = |fill: &str| fill.repeat(64);
        let unread = |entries: &[(&str, &str)]| -> Unread {
            entries
                .iter()
                .map(|(path, fill)| ((*path).to_string(), digest(fill)))
                .collect()
        };
        let settings = AgentSettings::default();
        let files = [file("main.lua", "require('lib.helper')\n")];
        let approved = unread(&[("lib/helper.so", "a")]);
        for (name, current) in [
            (
                "added",
                unread(&[("lib/helper.so", "a"), ("lib/extra.so", "b")]),
            ),
            ("changed", unread(&[("lib/helper.so", "b")])),
            ("removed", unread(&[])),
        ] {
            let state = TempDir::new(&format!("engine-binary-{name}"));
            let bin = TempDir::new(&format!("engine-binary-{name}-bin"));
            let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));
            let memory = memory(&state, units("aur:demo"));
            assert!(remember(&memory, Some((&files, &settings)), &approved).is_empty());

            let same = Group {
                unread: &approved,
                ..group(&settings, &files)
            };
            let review = review_group(&same, &opencode, Some(&memory));
            assert!(review.runs.is_empty(), "{name}: {:?}", review.notes);

            let group = Group {
                unread: &current,
                ..group(&settings, &files)
            };
            let review = review_group(&group, &opencode, Some(&memory));
            assert_eq!(review.runs.len(), 1, "{name}: {:?}", review.notes);
            assert!(
                review
                    .notes
                    .iter()
                    .any(|note| note.contains("cannot be matched to the approved version")),
                "{name}: {:?}",
                review.notes
            );
            let sent = fs::read_to_string(bin.path().join("stdin")).unwrap();
            assert!(!sent.contains("This is an upgrade"), "{name}");
            assert!(
                sent.contains(r#""path":"main.lua","kind":"whole""#),
                "{name}"
            );
        }
    }

    #[test]
    fn a_baseline_approved_under_other_agent_settings_is_not_diffed_against() {
        let state = TempDir::new("engine-other-settings");
        let bin = TempDir::new("engine-other-settings-bin");
        let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));
        let memory = memory(&state, units("aur:demo"));
        let weaker = AgentSettings::default();
        let stronger = AgentSettings {
            thinking: Thinking::Max,
            ..AgentSettings::default()
        };
        let approved = [
            file("PKGBUILD", "pkgname=demo\n"),
            file("src/lib.c", "int a;\n"),
        ];
        assert!(remember(&memory, Some((&approved, &weaker)), &NOTHING_UNREAD).is_empty());

        let upgraded = [
            file("PKGBUILD", "pkgname=demo\n"),
            file("src/lib.c", "int a;\n"),
            file("src/new.c", "int b;\n"),
        ];
        let review = review_group(&group(&stronger, &upgraded), &opencode, Some(&memory));

        assert!(
            !review.notes.iter().any(|note| note.contains("upgrade")),
            "{:?}",
            review.notes
        );
        let sent = fs::read_to_string(bin.path().join("stdin")).unwrap();
        assert!(sent.contains("This is the first review"));
        assert!(sent.contains(r#""path":"src/lib.c","kind":"whole""#));
        // The mismatched baseline is gone, so a later review under the old
        // settings cannot fall back to it either.
        assert!(
            baseline::load(&memory.store, SourceClass::Aur, &memory.units, &weaker)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_plan_over_max_chunks_makes_no_call() {
        let bin = TempDir::new("engine-too-large-bin");
        let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));
        let (mut settings, files) = three_chunks();
        settings.max_chunks = 2;

        let review = review_group(&group(&settings, &files), &opencode, None);

        assert!(review.too_large && review.runs.is_empty());
        assert!(!bin.path().join("stdin").exists());
    }

    #[test]
    fn diff_mode_retries_in_full_when_removed_baseline_paths_alone_are_too_large() {
        let state = TempDir::new("engine-diff-retry");
        let bin = TempDir::new("engine-diff-retry-bin");
        let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));
        let memory = memory(&state, units("aur:demo"));

        // Five baseline files that no longer exist: their paths alone (not
        // the tiny current file) push the manifest overhead over the limit.
        let removed_files: Vec<SourceFile> = (0..5)
            .map(|index| file(&format!("removed-{index}.c"), "old\n"))
            .collect();
        let settings = AgentSettings {
            max_input_bytes: 400,
            ..AgentSettings::default()
        };
        baseline::record(
            &memory.store,
            SourceClass::Aur,
            &memory.units,
            &removed_files,
            &NOTHING_UNREAD,
            &settings,
            memory.now,
        )
        .unwrap();
        let files = [file("a.c", "hi\n")];

        let review = review_group(&group(&settings, &files), &opencode, Some(&memory));

        assert!(!review.too_large, "{:?}", review.notes);
        assert!(matches!(
            review.runs.as_slice(),
            [run] if matches!(run.outcome, AgentOutcome::Reviewed(_))
        ));
        assert!(
            review
                .notes
                .iter()
                .any(|note| note.contains("reviewing in full")),
            "{:?}",
            review.notes
        );
    }

    #[test]
    fn review_group_ignores_memory_for_a_privileged_class() {
        let state = TempDir::new("engine-privileged");
        let bin = TempDir::new("engine-privileged-bin");
        let opencode = OpenCode::At(mock_opencode(bin.path(), "clear", true));
        let memory = memory(&state, Vec::new());
        let settings = AgentSettings::default();
        let files = [file("a.c", "int x;\n")];
        let mut privileged = group(&settings, &files);
        privileged.class = SourceClass::Official;

        let first = review_group(&privileged, &opencode, Some(&memory));
        assert!(matches!(first.runs.as_slice(), [run] if run.cached.is_none()));

        // A second run still calls OpenCode: memory was never consulted for
        // a privileged class, so nothing was cached from the first run.
        let second = review_group(&privileged, &opencode, Some(&memory));
        assert!(matches!(second.runs.as_slice(), [run] if run.cached.is_none()));
        assert!(memory.store.list(VERDICTS).unwrap().is_empty());
    }

    #[test]
    fn remember_records_a_baseline_only_when_approved() {
        let state = TempDir::new("engine-remember");
        let memory = memory(&state, units("aur:demo"));
        let settings = AgentSettings::default();
        let files = [file("PKGBUILD", "pkgname=demo\n")];

        assert!(remember(&memory, None, &NOTHING_UNREAD).is_empty());
        assert!(
            baseline::load(&memory.store, SourceClass::Aur, &memory.units, &settings)
                .unwrap()
                .is_none()
        );

        assert!(remember(&memory, Some((&files, &settings)), &NOTHING_UNREAD).is_empty());
        assert!(
            baseline::load(&memory.store, SourceClass::Aur, &memory.units, &settings)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn memory_is_for_user_level_reviews_that_want_it() {
        let state = TempDir::new("engine-open");
        let root = || Some(state.path().join("store"));
        let standard = Settings::from_parts(PartialConfig::default(), PartialConfig::default());

        assert!(
            Memory::open(&standard, SourceClass::Official, units("x:y"), root())
                .unwrap()
                .is_none()
        );
        assert!(
            Memory::open(&standard, SourceClass::Aur, units("aur:x"), None)
                .unwrap()
                .is_none()
        );
        let opened = Memory::open(&standard, SourceClass::Aur, units("aur:x"), root())
            .unwrap()
            .unwrap();
        assert!(opened.use_cache && opened.use_diff);

        let local = standard.clone().with_profile(Profile::LocalOnly);
        assert!(
            Memory::open(&local, SourceClass::Aur, units("aur:x"), root())
                .unwrap()
                .is_none()
        );

        let no_cache = Settings::from_parts(
            PartialConfig::default(),
            PartialConfig {
                agent: AgentDefaults {
                    cache_days: Some(0),
                    ..AgentDefaults::default()
                },
                ..PartialConfig::default()
            },
        );
        assert!(
            Memory::open(&no_cache, SourceClass::Aur, Vec::new(), root())
                .unwrap()
                .is_none()
        );
    }
}
