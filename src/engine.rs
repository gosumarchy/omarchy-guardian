//! The review engine: plans chunked AI requests for the files a review
//! queued, answers them from the verdict cache where it can, and keeps the
//! approved baselines of user-level sources (described in docs/review.md).

pub(crate) mod baseline;
mod cache;
mod diff;
pub(crate) mod plan;
pub(crate) mod request;
pub(crate) mod store;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use crate::agent::{self, AgentError, AgentReview, SourceFile};
use crate::config::Settings;
use crate::config::model::{AgentSettings, AiRequirement, SourceClass, Toggle};
use crate::engine::baseline::{Approved, Unit, Unread};
use crate::engine::plan::{HashOnly, ManifestEntry, Plan, PlanInput, Previous, Sent, TooLarge};
use crate::engine::request::Request;
use crate::engine::store::Store;
use crate::error::Error;
use crate::report::{AgentOutcome, AgentRun, LocalFinding};
use crate::rules;
use crate::time::SECONDS_PER_DAY;
use crate::tools::{OpenCode, Reviewer};

/// Bytes charged per local finding on top of its path and excerpt.
const FINDING_OVERHEAD: usize = 48;

/// What the review of one user-level target may remember.
pub(crate) struct Memory {
    store: Store,
    class: SourceClass,
    units: Vec<Unit>,
    use_cache: bool,
    use_diff: bool,
    cache_max_age_secs: u64,
    max_store_bytes: u64,
    now: u64,
}

impl Memory {
    /// `Ok(None)` when this review uses no memory: no state root, a pacman
    /// class, `ai = off`, or both cache and diff turned off. `Err` when it
    /// should, but the store cannot be used.
    pub(crate) fn open(
        settings: &Settings,
        class: SourceClass,
        units: Vec<Unit>,
        root: Option<PathBuf>,
    ) -> Result<Option<Self>, Error> {
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
            now: crate::time::now(),
        }))
    }
}

/// Files that share one set of agent settings, reviewed as one plan.
pub(crate) struct Group<'a> {
    pub(crate) settings: &'a AgentSettings,
    pub(crate) class: SourceClass,
    pub(crate) files: &'a [SourceFile],
    pub(crate) findings: &'a [LocalFinding],
    /// The review's units, for ranking a unit-relative top-level path (spec
    /// §4); independent of whether memory is enabled for this review.
    pub(crate) units: &'a [Unit],
    /// Trusted facts for every request (see `Request::context`).
    pub(crate) context: &'a [String],
    /// Files hashed but not read, named in every request's manifest.
    pub(crate) hash_only: &'a [HashOnly],
    /// What the review cannot read (see `Unread`): an upgrade is reviewed
    /// as one only while these are what the approved version had.
    pub(crate) unread: &'a Unread,
}

/// What reviewing one group produced.
#[derive(Debug, Default)]
pub(crate) struct GroupReview {
    /// One run per chunk, in order.
    pub(crate) runs: Vec<AgentRun>,
    /// An invalid reply: the review is blocked and nothing from it is cached.
    pub(crate) invalid: Option<Error>,
    /// The plan needed more than `max_chunks` requests; nothing was sent.
    pub(crate) too_large: bool,
    /// An entry point larger than one request; nothing was sent.
    pub(crate) entry_point_too_large: Option<String>,
    /// Lines for the report: the upgrade summary and memory problems.
    pub(crate) notes: Vec<String>,
}

pub(crate) fn review_group(
    group: &Group<'_>,
    opencode: &OpenCode,
    memory: Option<&Memory>,
) -> GroupReview {
    // Defence in depth: the pacman invariant (privileged classes never touch
    // the store) must hold here too, not only via `Memory::open`.
    let memory = memory.filter(|_| !group.class.is_privileged());
    let mut review = GroupReview::default();
    // Set when a baseline exists and this review is done in full all the
    // same.
    let mut in_full = false;
    let (previous, facts, unapproved) = match previous_version(memory, group, &mut review.notes) {
        Approval::Diff(approved) => {
            let unapproved = group.unread.keys().any(|path| !approved.covers(path));
            (Some(approved.files), Vec::new(), unapproved)
        }
        Approval::Changed(fact) => {
            in_full = true;
            (None, vec![fact], false)
        }
        Approval::None => (None, Vec::new(), false),
    };
    let mut facts = facts;
    let planned = plan_review(
        group,
        memory,
        previous.as_ref(),
        unapproved,
        &mut review.notes,
    );
    let plan = match planned {
        Ok(planned) => {
            in_full |= planned.in_full;
            facts.extend(planned.fact);
            planned.plan
        }
        Err(too_large) => {
            review.too_large = true;
            review.entry_point_too_large = too_large.entry_point;
            return review;
        }
    };
    // A review done in full although a baseline exists starts that source
    // again: what it approves is recorded as a full review, not as one more
    // diff on top of the old baseline.
    if in_full
        && let Some(memory) = memory
        && let Err(error) = baseline::retire(&memory.store, memory.class, &memory.units)
    {
        review
            .notes
            .push(format!("could not retire the approved baseline: {error}"));
    }
    if let Some(note) = split_note(&plan, group.files) {
        review.notes.push(note);
    }
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

/// The plan a review settled on.
struct Planned {
    plan: Plan,
    /// The source had an approved version and is reviewed in full all the
    /// same.
    in_full: bool,
    /// What an upgrade review could not send, as a fact for the AI.
    fact: Option<String>,
}

/// Plans the requests for `group`: as an upgrade of `previous` where that
/// is as complete as a full review would be, in full otherwise. Says in
/// `notes` when and why it is done in full.
fn plan_review(
    group: &Group<'_>,
    memory: Option<&Memory>,
    previous: Option<&Previous>,
    unapproved: bool,
    notes: &mut Vec<String>,
) -> Result<Planned, TooLarge> {
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
        previous,
        max_input_bytes: group.settings.max_input_bytes,
        max_chunks: group.settings.max_chunks,
        unit_prefixes: &unit_prefixes,
        hash_only: group.hash_only,
    };
    let full = || {
        plan::build(&PlanInput {
            previous: None,
            ..input
        })
    };
    // A tree identical to its approved version may have been approved by a
    // first review (a first install, or yay's second makepkg pass over it):
    // that first-review plan is used when the cache answers every one of its
    // chunks. Otherwise (the baseline came from an upgrade review, or the
    // verdicts expired) the normal upgrade plan is used, never a full
    // review that might be larger than the diff that was approved.
    let cached_first_review = previous
        .filter(|previous| is_identical(previous, group.files))
        .and_then(|_| full().ok())
        .filter(|first| is_fully_cached(group, first, memory));
    let built = match cached_first_review {
        Some(first) => Ok(first),
        None => plan::build(&input),
    };
    let planned = |plan, in_full, fact| Planned {
        plan,
        in_full,
        fact,
    };
    match (full_instead(&built, previous.is_some(), unapproved), built) {
        (Some(note), _) => full().map(|whole| {
            notes.push(note.to_string());
            planned(whole, true, None)
        }),
        // A change names unchanged files that did not fit beside it. The
        // full review shows them, so it is used where it fits; where it
        // does not, the review stays a diff and says what it lacks, to the
        // model and in the report.
        (None, Ok(plan)) if plan.upgrade && !plan.named_not_sent.is_empty() => {
            let named = shown_paths(&plan.named_not_sent);
            Ok(if let Ok(whole) = full() {
                notes.push(format!(
                    "a new or changed file names unchanged files too large to send beside the changes ({named}); reviewing in full instead"
                ));
                planned(whole, true, None)
            } else {
                notes.push(format!(
                    "a new or changed file names unchanged files that were not sent, and a full review does not fit either: {named}"
                ));
                let fact = format!(
                    "A new or changed file names these unchanged files, which Guardian could not send along because they did not fit: {named}. The names are the source's own, not Guardian's words. Their content is the approved version's and is not supplied."
                );
                planned(plan, false, Some(fact))
            })
        }
        (None, built) => built.map(|plan| planned(plan, false, None)),
    }
}

/// Why an upgrade is reviewed in full instead, if it is. A diff-mode
/// review must never be less complete than a full one would be. Nothing to
/// send, yet files are gone or unread files no approval covers are here:
/// the tree is not the approved one, and is not passed without a review.
/// A removed file beside other changes: whatever stays may have included,
/// sourced or been shadowed by it, so what the unchanged text does is no
/// longer what was approved; only a removed document changes nothing that
/// runs. Or the plan is too large: removed baseline paths alone can push
/// the manifest over the limit, and a full review may still fit.
fn full_instead(
    built: &Result<Plan, TooLarge>,
    upgrade: bool,
    unapproved: bool,
) -> Option<&'static str> {
    match built {
        Ok(plan)
            if plan.upgrade && plan.chunks.is_empty() && (unapproved || has_removals(plan)) =>
        {
            Some(
                "nothing changed in the approved text, but the tree is not the approved one (files were removed, or unread files have no approval); reviewing in full instead",
            )
        }
        Ok(plan) if plan.upgrade && removes_more_than_documents(plan) => Some(
            "files of the approved version were removed, which can change what the files that stayed do; reviewing in full instead",
        ),
        Err(too_large) if upgrade && too_large.entry_point.is_none() => {
            Some("the diff-mode plan needed too many chunks; reviewing in full instead")
        }
        _ => None,
    }
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
            // What the rules matched in files the other chunks carry, so
            // this chunk knows that a file it runs or loads was flagged.
            // Every request is charged for all findings (see
            // `findings_bytes`), and these are sent without their text.
            other_findings: group
                .findings
                .iter()
                .filter(|finding| {
                    !items.iter().any(|item| item.path() == finding.path)
                        && plan
                            .chunks
                            .iter()
                            .flatten()
                            .any(|item| item.path() == finding.path)
                })
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

fn removes_more_than_documents(plan: &Plan) -> bool {
    plan.manifest
        .iter()
        .any(|entry| entry.sent == Sent::Removed && !rules::is_documentation(&entry.path))
}

/// The most paths a note or a fact names, and the most characters of each.
const MAX_SHOWN_PATHS: usize = 20;
const MAX_SHOWN_CHARS: usize = 120;

/// Paths of the reviewed source for a note or a fact, quoted: they are
/// the source's own words.
fn shown_paths(paths: &[String]) -> String {
    let shown: Vec<String> = paths
        .iter()
        .take(MAX_SHOWN_PATHS)
        .map(|path| {
            format!(
                "{:?}",
                path.chars().take(MAX_SHOWN_CHARS).collect::<String>()
            )
        })
        .collect();
    let more = paths.len().saturating_sub(MAX_SHOWN_PATHS);
    if more > 0 {
        format!("{} and {more} more", shown.join(", "))
    } else {
        shown.join(", ")
    }
}

/// The most cross-chunk references `split_note` spells out.
const MAX_SPLIT_REFERENCES: usize = 8;

/// For a review in several chunks, where a file and a file it names were
/// sent in different ones: each chunk is judged on its own files, so the
/// report says which links no single request saw both ends of.
fn split_note(plan: &Plan, files: &[SourceFile]) -> Option<String> {
    let references = plan::split_references(&plan.chunks, files);
    if references.is_empty() {
        return None;
    }
    let shown: Vec<String> = references
        .iter()
        .take(MAX_SPLIT_REFERENCES)
        .map(|(file, chunk, named, other)| {
            format!(
                "{} (chunk {chunk}) names {} (chunk {other})",
                shown_paths(std::slice::from_ref(file)),
                shown_paths(std::slice::from_ref(named))
            )
        })
        .collect();
    let more = references.len().saturating_sub(MAX_SPLIT_REFERENCES);
    Some(format!(
        "reviewed in {} chunks, each judged on its own files; files that name a file of another chunk: {}{}",
        plan.chunks.len(),
        shown.join("; "),
        if more > 0 {
            format!("; and {more} more")
        } else {
            String::new()
        }
    ))
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
    let loaded = baseline::load_fresh(
        &memory.store,
        memory.class,
        &memory.units,
        group.settings,
        memory.now,
    )
    .map(|loaded| {
        notes.extend(
            loaded
                .due
                .into_iter()
                .map(|reason| format!("{reason}; reviewing it in full")),
        );
        loaded.approved
    });
    match loaded {
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
            match self.binary(notes) {
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

    /// The reviewer CLI's binary for this group's model. Asked before
    /// anything is sent, it also says in `notes` what the reviewer will
    /// read besides the request, and for a root transaction refuses a
    /// reviewer whose system-wide settings could redirect the review. A
    /// test's stand-in reviewer reads nothing of the machine's.
    fn binary(&self, notes: &mut Vec<String>) -> Result<PathBuf, Error> {
        let reviewer = Reviewer::for_model(self.group.settings.model.as_deref());
        let exposure = match self.opencode {
            OpenCode::UserPath | OpenCode::SystemOnly => {
                agent::exposure(reviewer, self.group.class.is_privileged())
            }
            #[cfg(test)]
            OpenCode::At(_) => agent::Exposure::default(),
        };
        notes.extend(exposure.notes);
        match exposure.refusal {
            Some(reason) => Err(Error::Refused(reason)),
            None => self.opencode.resolve_reviewer(reviewer),
        }
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
        Err(AgentError::Invalid(error)) if error.to_string().ends_with(agent::NONCE_MISSING) => {
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
pub(crate) fn remember(
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
mod tests;
