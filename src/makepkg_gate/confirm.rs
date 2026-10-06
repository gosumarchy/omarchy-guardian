//! What the user has to say yes to, and how a yes is remembered: a recipe
//! whose sources Guardian cannot follow, prebuilt programs, and binaries
//! that changed since the last build.

use std::collections::BTreeMap;

use super::{MAX_BINARIES_NAMED, UpstreamStep, state};
use crate::aur::recipe::{self, Sources};
use crate::aur::{self, Upstream};
use crate::cli::Confirm;
use crate::paths::file_name;
use crate::sha256::Sha256;

/// What reading the recipe's text says about a listing of it.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Followed {
    /// The listing is what the recipe writes out, or the recipe works its
    /// sources out the same way wherever it is loaded.
    Yes,
    /// Written out plainly, and the listing gave something else for this
    /// array: the recipe told the listing another thing than its text says.
    Differs(String),
    /// Set where Guardian cannot follow (`line N: why`): the listing shows
    /// what the recipe gave in the jail, which the build need not repeat.
    No(Vec<String>),
}

pub(super) fn followed(recipe: &str, srcinfo: &str) -> Followed {
    match recipe::sources(recipe) {
        Sources::Written(arrays) => match aur::written_mismatch(&arrays, srcinfo) {
            Some(array) => Followed::Differs(array),
            None => Followed::Yes,
        },
        Sources::Derived => Followed::Yes,
        Sources::NotFollowed(reasons) => Followed::No(reasons),
    }
}

/// A hash of `parts`, each kept apart, as what a confirmation is remembered
/// by: the same question about the same thing is not asked twice.
fn confirmation(kind: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update(&[0]);
    }
    format!("{kind} {}", hasher.finalize())
}

/// `recipe` without what its `pkgver=` and `pkgrel=` lines are set to,
/// where those are plain values: a `pkgver()` function has makepkg rewrite
/// them between two calls of one install, and nothing else of the recipe.
fn without_version(recipe: &str) -> String {
    let plain = |value: &str| {
        value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._+~:-'\"".contains(c))
    };
    let mut text = String::with_capacity(recipe.len());
    for line in recipe.lines() {
        let kept = ["pkgver=", "pkgrel="].into_iter().find(|name| {
            line.strip_prefix(name)
                .is_some_and(|value| plain(value.trim_end()))
        });
        text.push_str(kept.unwrap_or(line));
        text.push('\n');
    }
    text
}

/// What a yes to a recipe whose sources are not followed is remembered by:
/// the PKGBUILD (see `without_version`) and every other file of the
/// recipe, which it can read its sources from (`. ./sources.inc`), but for
/// the `downloads` makepkg puts beside them.
fn sources_asked(step: &UpstreamStep<'_>, downloads: &[String]) -> String {
    let recipe = without_version(step.recipe);
    let mut parts = vec![recipe.as_str()];
    for (path, state) in step.recipe_files {
        let top = path.split('/').next().unwrap_or_default();
        let downloaded = downloads
            .iter()
            .any(|name| name == top || top.strip_suffix(".part") == Some(name));
        if !downloaded {
            parts.extend([path.as_str(), state.as_str()]);
        }
    }
    confirmation("sources", &parts)
}

/// Asks about a recipe whose sources Guardian cannot follow, unless the
/// user said yes to this very recipe before. False when the build must not
/// go on.
pub(super) fn confirm_not_followed(
    step: &UpstreamStep<'_>,
    reasons: &[String],
    downloads: &[String],
    confirm: &mut dyn Confirm,
) -> bool {
    outln!("Source listing: the recipe sets what it fetches where Guardian cannot follow:");
    for reason in reasons {
        outln!("  ! {reason}");
    }
    let asked = sources_asked(step, downloads);
    if step.state.is_confirmed(&asked) {
        outln!("  You confirmed this recipe as it is before.");
        return true;
    }
    outln!(
        "  Guardian reviews the sources the recipe listed in its sandbox; the build loads the recipe again and can arrive at others."
    );
    let question = format!(
        "The PKGBUILD of {} computes its sources where Guardian cannot follow. Go on with it?",
        step.name
    );
    if confirm.confirm(&question) {
        step.state.remember_confirmed(&asked);
        return true;
    }
    false
}

/// Prebuilt programs among the sources that end up installed or run: no
/// one reviewed them, and no one can.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Prebuilt {
    /// The programs, with their hashes.
    pub(super) programs: BTreeMap<String, String>,
    /// Those the recipe's functions or install scripts run.
    pub(super) run: Vec<String>,
    /// Where the sources were downloaded from.
    hosts: Vec<String>,
}

impl Prebuilt {
    /// What the user and the AI are told.
    pub(super) fn statement(&self) -> String {
        let from = if self.hosts.is_empty() {
            "that came with its sources".to_string()
        } else {
            format!("downloaded from {}", self.hosts.join(", "))
        };
        format!(
            "this package installs {} prebuilt program(s) nobody reviewed, {from}{}",
            self.programs.len(),
            if self.run.is_empty() {
                String::new()
            } else {
                format!(
                    "; its recipe runs {} of them during the build or the install",
                    self.run.len()
                )
            }
        )
    }

    /// What a yes is remembered by: these very programs from these hosts.
    /// `None` when one of them could not be hashed: it could be anything
    /// next time.
    fn asked(&self) -> Option<String> {
        if self.programs.values().any(String::is_empty) {
            return None;
        }
        let mut parts: Vec<&str> = Vec::new();
        for (path, digest) in &self.programs {
            parts.extend([path.as_str(), digest.as_str()]);
        }
        parts.push("from");
        parts.extend(self.hosts.iter().map(String::as_str));
        // A recipe that comes to run one of them asks for more than one
        // that installs them.
        parts.push("run");
        parts.extend(self.run.iter().map(String::as_str));
        Some(confirmation("prebuilt", &parts))
    }
}

/// The prebuilt programs of a package the user has to say yes to: all of
/// them when the recipe builds nothing (no `build()`: the package is made
/// of what it downloads), else the ones the recipe names, runs, or takes
/// out of an archive it opens itself. A source tree that only carries a
/// binary among its test data is not asked about.
pub(super) fn prebuilt(
    step: &UpstreamStep<'_>,
    upstream: &Upstream,
    sources: &[aur::Source],
) -> Prebuilt {
    let functions = step.functions;
    let mut run: Vec<String> = Vec::new();
    for (_, text) in &functions.files {
        for (_, _, target) in aur::recipe_runs(text, &functions.variables) {
            let found = upstream
                .unread
                .keys()
                .chain(upstream.programs.keys())
                .find(|path| aur::is_target(path, &target));
            if let Some(path) = found
                && !run.contains(path)
            {
                run.push(path.clone());
            }
        }
    }
    let builds = aur::defines_function(step.recipe, "build");
    let named = |path: &str| {
        let name = file_name(path);
        upstream.is_unpacked(path) || (name.len() >= 5 && functions.written.contains(name))
    };
    let mut programs: BTreeMap<String, String> = upstream
        .programs
        .iter()
        .filter(|(path, _)| !builds || named(path) || run.contains(*path))
        .map(|(path, digest)| (path.clone(), digest.clone()))
        .collect();
    for path in &run {
        let digest = upstream.unread.get(path).cloned().unwrap_or_default();
        programs.entry(path.clone()).or_insert(digest);
    }
    let mut hosts: Vec<String> = sources
        .iter()
        .filter_map(|source| aur::source_host(&source.entry))
        .collect();
    hosts.sort();
    hosts.dedup();
    Prebuilt {
        programs,
        run,
        hosts,
    }
}

/// The most programs named one by one before the question.
const MAX_PROGRAMS_NAMED: usize = 8;

/// Says plainly that the package installs prebuilt programs and asks,
/// unless the user said yes to these very programs before. False when the
/// build must not go on.
pub(super) fn confirm_prebuilt(
    step: &UpstreamStep<'_>,
    prebuilt: &Prebuilt,
    confirm: &mut dyn Confirm,
) -> bool {
    if prebuilt.programs.is_empty() {
        return true;
    }
    outln!("Prebuilt programs: {}.", prebuilt.statement());
    for path in prebuilt.programs.keys().take(MAX_PROGRAMS_NAMED) {
        outln!("  ! {path}");
    }
    if prebuilt.programs.len() > MAX_PROGRAMS_NAMED {
        outln!(
            "  and {} more",
            prebuilt.programs.len() - MAX_PROGRAMS_NAMED
        );
    }
    let asked = prebuilt.asked();
    if asked
        .as_deref()
        .is_some_and(|asked| step.state.is_confirmed(asked))
    {
        outln!("  You confirmed these programs, from these hosts, before.");
        return true;
    }
    let question = format!(
        "{} installs {} prebuilt program(s) nobody reviewed. Build and install it?",
        step.name,
        prebuilt.programs.len()
    );
    if confirm.confirm(&question) {
        if let Some(asked) = asked {
            step.state.remember_confirmed(&asked);
        }
        return true;
    }
    false
}

/// What the binaries among the sources are now, held against the ones of
/// the last build of this package that passed: printed, and a fact for the
/// AI. `None` when they are the same, or there was no such build.
pub(super) fn binary_changes(step: &UpstreamStep<'_>, upstream: &Upstream) -> Option<String> {
    let known = step.state.binaries()?;
    let (changed, gone) = state::binary_changes(&known, &all_binaries(upstream));
    if changed.is_empty() && gone.is_empty() {
        return None;
    }
    outln!(
        "Binaries: {} new or changed and {} gone since the last build of this package Guardian let through:",
        changed.len(),
        gone.len()
    );
    for path in changed.iter().take(MAX_BINARIES_NAMED) {
        outln!("  ! {path} (new or changed)");
    }
    if changed.len() > MAX_BINARIES_NAMED {
        outln!("  and {} more", changed.len() - MAX_BINARIES_NAMED);
    }
    Some(format!(
        "Guardian compared the binary files among these sources, which it cannot review, with those of the last build of this package it let through: {} are new or changed and {} are gone.",
        changed.len(),
        gone.len()
    ))
}

/// Every binary among the sources that is not reviewed, with its hash.
pub(super) fn all_binaries(upstream: &Upstream) -> BTreeMap<String, String> {
    let mut binaries = upstream.unread.clone();
    binaries.extend(
        upstream
            .programs
            .iter()
            .map(|(path, digest)| (path.clone(), digest.clone())),
    );
    binaries
}
