//! The recipe and the upstream sources as a permit names them, and how a
//! review stands once permits are held against it.

use super::confirm::{Prebuilt, confirm_prebuilt};
use super::{UpstreamStep, written_downloads};
use crate::audit::{self, Gate};
use crate::aur::{self, Upstream};
use crate::cli::{Confirm, Target};
use crate::config::Settings;
use crate::config::model::{Named, SourceClass};
use crate::engine::store::Store;
use crate::permit::{self, Content, Standing};
use crate::report::{Blocked, Decision, Report};
use crate::scan::Snapshot;
use crate::sha256::Sha256;

/// One SHA-256 over the recipe as reviewed: every file of the build
/// directory by path, hash and execute bit, but for those under the
/// top-level names in `left_out` (and their partial downloads).
pub(super) fn recipe_digest(snapshot: &Snapshot, left_out: &[String]) -> String {
    let mut hasher = Sha256::new();
    for file in snapshot.files() {
        let top = file.path.split('/').next().unwrap_or_default();
        if left_out
            .iter()
            .any(|name| name == top || top.strip_suffix(".part") == Some(name))
        {
            continue;
        }
        hasher.update(file.path.as_bytes());
        hasher.update(&[0]);
        hasher.update(file.sha256.to_string().as_bytes());
        hasher.update(&[u8::from(file.executable), b'\n']);
    }
    hasher.finalize().to_string()
}

/// Every file of the recipe but the PKGBUILD, by path, with its hash and
/// execute bit.
pub(super) fn recipe_files(snapshot: &Snapshot) -> Vec<(String, String)> {
    snapshot
        .files()
        .iter()
        .filter(|file| file.path != "PKGBUILD")
        .map(|file| {
            let state = format!("{} {}", file.sha256, u8::from(file.executable));
            (file.path.clone(), state)
        })
        .collect()
}

/// The recipe as a permit names it. A permit is offered for the build
/// directory as it is; one given before makepkg downloaded the sources
/// into that directory still stands for the recipe once they are there,
/// so the second form leaves those files out. A file that was already
/// there when the permit was given is part of the first form only: one
/// changed since has no permit.
pub(super) fn recipe_contents(target: &Target, snapshot: &Snapshot, recipe: &str) -> Vec<Content> {
    if snapshot.files().is_empty() {
        return Vec::new();
    }
    let mut digests = vec![
        recipe_digest(snapshot, &[]),
        recipe_digest(snapshot, &written_downloads(recipe)),
    ];
    digests.dedup();
    digests
        .iter()
        .filter_map(|digest| {
            Content::new(
                Gate::Aur,
                SourceClass::Aur.name(),
                &target.subject(),
                vec![format!("recipe:{digest}")],
            )
        })
        .collect()
}

/// Version-control sources: what makepkg fetches of them has no one hash.
const VCS: &[&str] = &["git", "hg", "svn", "bzr", "fossil"];

/// The upstream sources of a build as a permit names them: the recipe, and
/// the downloaded files by their hashes, which are the same at every
/// makepkg call of one build. Sources that are no plain downloads (a
/// checkout) are named by every file the walk read instead, which a
/// build's own `prepare()` changes. `None` when a file among them has no
/// SHA-256: nothing can stand for it.
pub(super) fn upstream_content(
    step: &UpstreamStep<'_>,
    upstream: &Upstream,
    sources: &[aur::Source],
) -> Option<Content> {
    let plain = !upstream.downloads.is_empty()
        && sources
            .iter()
            .all(|source| !VCS.contains(&aur::source_protocol(&source.entry)));
    let files = if plain {
        &upstream.downloads
    } else {
        &upstream.seen
    };
    let mut hasher = Sha256::new();
    for (path, digest) in files {
        if digest.len() != 64 {
            return None;
        }
        hasher.update(path.as_bytes());
        hasher.update(&[0]);
        hasher.update(digest.as_bytes());
        hasher.update(b"\n");
    }
    Content::new(
        Gate::Aur,
        SourceClass::Aur.name(),
        &format!("aur:{} upstream sources", step.key),
        vec![
            format!("recipe:{}", step.recipe_digest),
            format!("sources:{}", hasher.finalize()),
        ],
    )
}

/// What of `contents` a permit can stand for under `decision`. A question
/// the user declined is the user's own no, and the way to say yes is to
/// answer it: a permit neither overrules it nor is offered for it.
pub(super) fn permittable(decision: Decision, contents: &[Content]) -> &[Content] {
    if decision == Decision::Blocked(Blocked::NotConfirmed) {
        &[]
    } else {
        contents
    }
}

/// Whether the call only downloads, with nothing extracted to review yet
/// and nothing it extracts itself. One that builds from a tree extracted
/// earlier (`--noextract`) is not such a call: it must find that tree.
pub(super) fn only_downloads(
    step: &UpstreamStep<'_>,
    sources: &[aur::Source],
    upstream: &Upstream,
) -> bool {
    !sources.is_empty() && !upstream.found && !step.uses_sources && upstream.gaps.is_empty()
}

/// What is left to ask once a permit overrules the review. A permit says
/// yes to the review's verdict on the very bytes it read; whether to
/// install programs nobody reviewed is another question, which a review
/// that did not pass never came to ask (see `review_upstream_files`). It is
/// asked here as on a review that passed, and a no is the user's own
/// (`NOT CONFIRMED`), which the permit does not overrule.
pub(super) fn asked_under_permit(
    step: &UpstreamStep<'_>,
    prebuilt: &Prebuilt,
    decision: Decision,
    permitted: bool,
    confirm: &mut dyn Confirm,
) -> Decision {
    let overruled =
        permitted && matches!(decision, Decision::Blocked(why) if why != Blocked::NotConfirmed);
    if overruled && !confirm_prebuilt(step, prebuilt, confirm) {
        Decision::Blocked(Blocked::NotConfirmed)
    } else {
        decision
    }
}

/// How the upstream review stands with permits, printed and recorded: the
/// report (when there was text to review) with its final decision, which
/// is returned beside the standing. A permit that overrules the review
/// still leaves the prebuilt programs to be asked about.
pub(super) fn settle_upstream(
    step: &UpstreamStep<'_>,
    settings: &Settings,
    content: Option<Content>,
    reviewed: (Option<Report>, Decision),
    prebuilt: &Prebuilt,
    confirm: &mut dyn Confirm,
) -> (Standing, Decision) {
    let (report, reviewed) = reviewed;
    let printed = report.is_some();
    let mut report =
        report.unwrap_or_else(|| Report::new(format!("{} · upstream sources", step.name)));
    let contents: Vec<Content> = content.into_iter().collect();
    let mut standing = permit::standing(
        permittable(reviewed, &contents),
        &report,
        reviewed,
        settings,
        Store::default_root().as_deref(),
    );
    let permitted = standing.permitted().is_some();
    let decision = asked_under_permit(step, prebuilt, reviewed, permitted, confirm);
    if decision != reviewed {
        // Declined: the run is not one the permit let through.
        standing = Standing::None;
    }
    report.permit = standing.permitted().map(str::to_string);
    if printed {
        report.print(false, decision);
    }
    let permitted = standing.permitted().is_some();
    audit::review(
        &audit::Reviewed {
            gate: Gate::Aur,
            class: SourceClass::Aur.name(),
            subject: &format!("aur:{} upstream sources", step.key),
            digest: &contents.first().map(Content::digest).unwrap_or_default(),
            decision,
            permit: standing.permitted(),
            offered: standing.offered(),
            exit: if permitted { 0 } else { decision.exit_status() },
        },
        &report,
    )
    .record();
    (standing, decision)
}
