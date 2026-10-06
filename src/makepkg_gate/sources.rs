//! Checks of the listed sources before anything is fetched or reviewed: the
//! names makepkg keeps them under, mirrors and checkouts already there, and
//! what the source checks say.

use std::fs;
use std::path::Path;

use super::{Dirs, UpstreamStep, print_warnings};
use crate::aur;

/// The first source makepkg would keep under a name that is not a plain
/// file name. makepkg takes the text before `::` as it is, so `a/b` or
/// `../x` would be written somewhere else than among the downloads.
pub(super) fn misnamed_source(sources: &[aur::Source]) -> Option<&str> {
    sources
        .iter()
        .map(|source| source.entry.as_str())
        .find(|entry| {
            let name = aur::source_filename(entry);
            name.is_empty()
                || name.contains('/')
                || name.starts_with('-')
                || [".", "..", ".git"].contains(&name.as_str())
        })
}

/// Sections and keys (lowercase: git ignores their case) of the
/// configuration `git clone --mirror` writes.
const MIRROR_CONFIG: &[(&str, &[&str])] = &[
    (
        "[core]",
        &[
            "repositoryformatversion",
            "filemode",
            "bare",
            "logallrefupdates",
            "ignorecase",
            "precomposeunicode",
            "symlinks",
        ],
    ),
    ("[remote \"origin\"]", &["url", "fetch", "mirror", "tagopt"]),
];

/// Whether `mirror` is a git mirror as makepkg makes one for `url`: its
/// configuration holds nothing but what `git clone --mirror` writes, it has
/// no hooks, and its configuration is its own. makepkg runs `git fetch`
/// inside an existing mirror, and git does what a repository's
/// configuration and hooks say.
pub(super) fn is_plain_mirror(mirror: &Path, url: &str) -> bool {
    let is_dir = |path: &Path| fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir());
    let Ok(config) = fs::read_to_string(mirror.join("config")) else {
        return false;
    };
    let mut keys: &[&str] = &[];
    let mut origin = None;
    for line in config
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if let Some((_, allowed)) = MIRROR_CONFIG.iter().find(|(section, _)| *section == line) {
            keys = allowed;
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return false;
        };
        let (key, value) = (key.trim().to_ascii_lowercase(), value.trim());
        // git fetches from the first `url` and reports the last.
        if !keys.contains(&key.as_str())
            || value.ends_with('\\')
            || (key == "url" && origin.is_some())
        {
            return false;
        }
        if key == "url" {
            origin = Some(value);
        }
    }
    let hooks = mirror.join("hooks");
    let no_hooks = !hooks.exists()
        || (is_dir(&hooks)
            && fs::read_dir(&hooks).is_ok_and(|entries| {
                entries.flatten().all(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name.ends_with(".sample"))
                })
            }));
    // makepkg takes a URL with or without the `.git` as the same one.
    let bare = |url: &str| url.strip_suffix(".git").unwrap_or(url).to_string();
    is_dir(mirror)
        && origin.map(bare) == Some(bare(url))
        && no_hooks
        && !["commondir", "config.worktree", "gitdir"]
            .iter()
            .any(|name| mirror.join(name).exists())
}

/// The first version-control source whose checkout is already there, in
/// the recipe's directory (where makepkg looks first) or the download
/// directory, and is not a plain git mirror: makepkg would run that tool
/// inside a directory someone else may have laid out.
pub(super) fn foreign_checkout<'a>(sources: &'a [aur::Source], dirs: &Dirs) -> Option<&'a str> {
    sources
        .iter()
        .map(|source| source.entry.as_str())
        .filter(|entry| aur::is_vcs_source(entry))
        .find(|entry| {
            [&dirs.startdir, &dirs.srcdest].iter().any(|directory| {
                let checkout = directory.join(aur::source_filename(entry));
                fs::symlink_metadata(&checkout).is_ok()
                    && !(aur::source_protocol(entry) == "git"
                        && is_plain_mirror(&checkout, aur::git_source_url(entry)))
            })
        })
}

/// The source checks: printed, blocking when a source can be replaced in
/// transit, and otherwise facts for the AI in Guardian's own words.
pub(super) fn source_context(
    sources: &[aur::Source],
    uses_sources: bool,
) -> Result<Vec<String>, ()> {
    let checks = aur::check_sources(sources);
    print_warnings("Source checks", &checks.warnings);
    if !checks.blocking.is_empty() {
        // A call that only downloads (to verify, or to generate the very
        // checksums that are missing) builds nothing from them. One that
        // builds from a tree extracted earlier (`--noextract`) does.
        if uses_sources {
            print_warnings("Source checks (blocking)", &checks.blocking);
            return Err(());
        }
        print_warnings("Source checks (these block a build)", &checks.blocking);
    }
    Ok(checks
        .context
        .iter()
        .map(|line| format!("Guardian's source check: {line}"))
        .collect())
}

/// Why the listed sources must not be fetched, as a message and its short
/// form: the recipe is not the package it sits in, a source would be
/// written outside the downloads, or a checkout to update is not makepkg's.
pub(super) fn fetch_refusal(
    step: &UpstreamStep<'_>,
    pkgbase: &str,
    sources: &[aur::Source],
    dirs: &Dirs,
) -> Option<(String, &'static str)> {
    // The package base names the source tree under a shared build
    // directory, which the fetch replaces.
    if let Some(base) = step.base
        && base != pkgbase
    {
        return Some((
            format!("the PKGBUILD's pkgbase {pkgbase:?} is not its AUR repository's ({base})."),
            "the PKGBUILD names another package as its base",
        ));
    }
    if let Some(entry) = misnamed_source(sources) {
        return Some((
            format!("a source is kept under a name that is not a file name: {entry:?}."),
            "a source is named as a path",
        ));
    }
    // Whether Guardian fetches or the build does, makepkg updates it.
    let entry = foreign_checkout(sources, dirs)?;
    Some((
        format!(
            "there is already a checkout for {entry:?} that is not a plain git mirror of it; remove it to fetch the source afresh."
        ),
        "an existing source checkout is not a plain mirror",
    ))
}

/// The top-level names makepkg downloads a source list into when
/// `SRCDEST` is the build directory. Never `PKGBUILD`: makepkg keeps the
/// one that is there, which must stay as reviewed.
pub(super) fn download_names(sources: &[aur::Source]) -> Vec<String> {
    let mut names: Vec<String> = sources
        .iter()
        .filter(|source| aur::source_protocol(&source.entry) != "local")
        .map(|source| aur::source_filename(&source.entry))
        .filter(|name| !name.is_empty() && name != "PKGBUILD")
        .collect();
    names.sort();
    names.dedup();
    names
}
