//! Packaged files are trusted for their content, not for their path.
//!
//! The other live checks vouch for a running program, a preloaded library
//! or a loaded kernel module when a repository package installed the file
//! at its path. Whoever can write there (root, or a mistake in a
//! package's permissions) can put anything at that path, so each such
//! file is compared here with what its package recorded, once per sweep.
//!
//! The same comparison runs over the directories programs, libraries, PAM
//! modules, systemd's own programs and the running kernel's modules are
//! loaded from, where a changed file runs sooner or later without being in
//! any auto-run location; and what no package owns there is listed. Every
//! sweep compares every file: one that compared a share a day would show
//! a changed file on some days and not on others.

use std::fs;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use super::{Found, collect, kernel_installed, kernel_release, push_note};
use crate::autorun::Category;
use crate::sweep::collect::{Body, Item, Origin, Scope};
use crate::sweep::index::Recorded;
use crate::sweep::read::{self, View};
use crate::sweep::tier::Tier;

/// The most bytes read to compare the files the live checks vouch for
/// (running programs, preloads, loaded modules) with their packages.
const MAX_VOUCHED: u64 = 2 * 1024 * 1024 * 1024;

/// The most bytes read on top of that for the look through the
/// directories.
const MAX_INSTALLED: u64 = 8 * 1024 * 1024 * 1024;

/// The most threads that read files at once.
const MAX_READERS: usize = 8;

/// A directory whose files are loaded or run by name.
struct Place {
    directory: &'static str,
    category: Category,
    /// Which file names count.
    wanted: fn(&str) -> bool,
}

const PLACES: &[Place] = &[
    Place {
        directory: "usr/bin",
        category: Category::LocalBin,
        wanted: |_| true,
    },
    Place {
        directory: "usr/lib",
        category: Category::Linker,
        wanted: is_library,
    },
    Place {
        directory: "usr/lib/security",
        category: Category::Pam,
        wanted: |_| true,
    },
    Place {
        directory: "usr/lib/systemd",
        category: Category::Systemd,
        wanted: |_| true,
    },
];

/// Whether `name` has `extension`, alone or before a version or a
/// compression's (`libz.so`, `libz.so.1`, `x.ko.zst`).
fn has_extension(name: &str, extension: &str) -> bool {
    name.split('.').skip(1).any(|part| part == extension)
}

fn is_library(name: &str) -> bool {
    has_extension(name, "so")
}

fn is_module(name: &str) -> bool {
    has_extension(name, "ko")
}

/// Whether the packaged file at `path` is still what its package
/// installed. One that is not becomes an item (a modified package file).
/// Each path is read once per sweep; past the bound the rest are taken
/// on their path's word, and the sweep says so.
pub(super) fn intact(scope: &Scope<'_>, found: &mut Found, category: Category, path: &str) -> bool {
    if let Some(known) = found.verified.get(path) {
        return *known;
    }
    let size = fs::symlink_metadata(scope.root.join(path)).map_or(0, |metadata| metadata.len());
    if found.hashed.saturating_add(size) > MAX_VOUCHED {
        found.cut_short = true;
        return true;
    }
    found.hashed += size;
    let item = collect::item(scope, category, path.to_string(), None);
    let intact = item.tier != Tier::Modified;
    if !intact {
        keep(found, item);
    }
    found.verified.insert(path.to_string(), intact);
    intact
}

/// Keeps `item`, a file that is not what its package installed.
fn keep(found: &mut Found, item: Item) {
    let kept = found.items.entry(item.path.clone()).or_insert(item);
    // An item another check made first is of the same file.
    kept.tier = Tier::Modified;
    push_note(
        kept,
        "its content is not what its package installed".to_string(),
    );
}

/// Says what the comparisons left out to stay within their bounds: a
/// note, and for the root checks, which nothing else covers, something
/// left unchecked.
pub(super) fn say_what_was_cut(scope: &Scope<'_>, found: &mut Found) {
    if !found.cut_short {
        return;
    }
    let sentence =
        "too many bytes of running programs and installed files: not every one was compared with its package"
            .to_string();
    if scope.origin == Origin::Root {
        found.unchecked.push(sentence);
    } else {
        found.notes.push(sentence);
    }
}

/// The item of the file at `path` in one of the places. Among the
/// system's own programs none stands ahead of another, as one in
/// `/usr/local/bin` would: that note is not for these. Root hands back
/// the content of the auto-run locations' own files only, and these are
/// not among them: from root they come as a hash, and the user's own
/// sweep reads what the user may read.
fn item_at(scope: &Scope<'_>, category: Category, path: &str) -> Item {
    let mut item = collect::item(scope, category, path.to_string(), None);
    item.notes.retain(|note| !note.starts_with("shadows "));
    if scope.origin == Origin::Root {
        if matches!(
            item.body,
            Body::Text(_) | Body::Oversized | Body::Undecodable
        ) {
            item.body = Body::Binary(collect::WITHHELD);
        }
        item.runs.clear();
    }
    item
}

/// A packaged file to compare with its package.
struct Candidate {
    path: String,
    category: Category,
}

/// Looks through the directories of `PLACES` and the running kernel's
/// modules: what no package owns is listed, and every packaged file is
/// compared with its package.
pub(super) fn check(scope: &Scope<'_>, found: &mut Found) {
    let mut candidates = Vec::new();
    let mut budget = MAX_INSTALLED;
    for place in PLACES {
        for (name, metadata) in entries(scope, place.directory, found) {
            let path = format!("{}/{name}", place.directory);
            let category = place.category;
            if !metadata.is_dir()
                && (place.wanted)(&name)
                && file(scope, found, (&path, category), &metadata, &mut budget)
            {
                candidates.push(Candidate { path, category });
            }
        }
    }
    // Only while the running kernel is the installed one: after an update
    // its modules are gone or outside any package until the next boot.
    if let Some(release) = kernel_release(scope) {
        let directory = format!("usr/lib/modules/{release}");
        if kernel_installed(scope, &directory) {
            modules(scope, found, &directory, &mut budget, &mut candidates);
        }
    }
    if budget == 0 {
        found.cut_short = true;
    }
    for item in changed(scope, &candidates) {
        keep(found, item);
    }
}

/// The names under `directory` with what each is, through the directory
/// as it was opened: one swapped for a link elsewhere is not listed.
fn entries(scope: &Scope<'_>, directory: &str, found: &mut Found) -> Vec<(String, fs::Metadata)> {
    let Some(read::Public::Directory(opened)) =
        read::seen(scope.root, directory, View::Pinned).map(|seen| seen.what)
    else {
        return Vec::new();
    };
    let Ok(listing) = fs::read_dir(format!("/proc/self/fd/{}", opened.as_raw_fd())) else {
        return Vec::new();
    };
    let mut entries = Vec::new();
    for entry in listing.filter_map(Result::ok) {
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        match entry.file_name().into_string() {
            Ok(name) => entries.push((name, metadata)),
            Err(name) => found.unchecked.push(collect::not_utf8(&format!(
                "{directory}/{}",
                name.to_string_lossy()
            ))),
        }
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    entries
}

/// The running kernel's modules directory: every packaged file in it is
/// compared; of what no package owns only modules are listed (depmod's
/// indexes are generated), and those DKMS built are left to the check of
/// loaded modules, which notes them.
fn modules(
    scope: &Scope<'_>,
    found: &mut Found,
    root: &str,
    budget: &mut u64,
    candidates: &mut Vec<Candidate>,
) {
    let dkms = scope.root.join("var/lib/dkms").is_dir();
    let mut pending = vec![root.to_string()];
    while let Some(directory) = pending.pop() {
        for (name, metadata) in entries(scope, &directory, found) {
            let path = format!("{directory}/{name}");
            if metadata.is_dir() {
                pending.push(path);
                continue;
            }
            let owned = scope.index.owner(&path).is_some();
            let built = dkms && path.contains("/updates/dkms/");
            if (owned || (is_module(&name) && !built))
                && file(scope, found, (&path, Category::Kernel), &metadata, budget)
            {
                candidates.push(Candidate {
                    path,
                    category: Category::Kernel,
                });
            }
        }
    }
}

/// Looks at one file or link of a place. One no package owns is listed
/// here; whether a packaged one is to be compared with its package is
/// returned.
fn file(
    scope: &Scope<'_>,
    found: &mut Found,
    (path, category): (&str, Category),
    metadata: &fs::Metadata,
    budget: &mut u64,
) -> bool {
    // Seen by another check already, as it is.
    if found.items.contains_key(path) || found.verified.contains_key(path) {
        return false;
    }
    let Some(owned) = scope.index.owner(path) else {
        found
            .items
            .insert(path.to_string(), item_at(scope, category, path));
        return false;
    };
    if metadata.file_type().is_symlink() {
        // A link is what its package made it while it leads where the
        // package said.
        let unchanged = matches!(&owned.recorded, Recorded::Link(recorded)
            if fs::read_link(scope.root.join(path))
                .is_ok_and(|target| target.to_str() == Some(recorded.as_str())));
        return !unchanged;
    }
    if !metadata.is_file() {
        return false;
    }
    if metadata.len() > *budget {
        *budget = 0;
        return false;
    }
    *budget -= metadata.len();
    true
}

/// The items of the `candidates` that are not what their packages
/// installed. Reading is shared between a few threads: it is some
/// gigabytes of files.
fn changed(scope: &Scope<'_>, candidates: &[Candidate]) -> Vec<Item> {
    let readers = thread::available_parallelism()
        .map_or(1, std::num::NonZero::get)
        .min(MAX_READERS);
    let next = AtomicUsize::new(0);
    let read = || {
        let mut changed = Vec::new();
        while let Some(candidate) = candidates.get(next.fetch_add(1, Ordering::Relaxed)) {
            let item = item_at(scope, candidate.category, &candidate.path);
            if item.tier == Tier::Modified {
                changed.push(item);
            }
        }
        changed
    };
    let mut changed: Vec<Item> = thread::scope(|threads| {
        let readers: Vec<_> = (0..readers).map(|_| threads.spawn(read)).collect();
        readers
            .into_iter()
            .flat_map(|reader| reader.join().unwrap_or_default())
            .collect()
    });
    changed.sort_by(|left, right| left.path.cmp(&right.path));
    changed
}
