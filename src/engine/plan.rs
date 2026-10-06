//! Turns the files queued for the AI review into chunked requests: rank by
//! risk, choose what each file is sent as on an upgrade, and pack.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::mem;

use crate::agent::SourceFile;
use crate::engine::diff;
use crate::json;
use crate::paths::file_name;
use crate::rules;

mod mentions;

pub(crate) use mentions::glob_matches;
use mentions::{Mentions, directory, named_in};

/// Unchanged lines shown around each change in an upgrade diff.
const DIFF_CONTEXT: usize = 20;

/// A changed file up to this size always goes whole on an upgrade: a diff
/// shows the lines around a change, and what a changed line switches on
/// may sit anywhere in the file (a guard flipped far above a dormant body).
const WHOLE_ON_UPGRADE: usize = 48 * 1024;
/// Larger changed files go whole too while together they fit this share
/// of one request, the riskiest first; past it they are sent as diffs.
const WHOLE_SHARE: usize = 2;

/// Unchanged files named by a changed one are sent along with it, up to
/// this share of one request: what a change switches on may sit in a file
/// that did not change.
const NAMED_SHARE: usize = 2;

/// Bytes charged for each manifest entry on top of its path.
const MANIFEST_ENTRY_OVERHEAD: usize = 32;

/// A cut line piece must hold at least one character of any width.
const MIN_PIECE: usize = 4;

/// The approved version of each file, by path, when the target is an upgrade.
pub(super) type Previous = BTreeMap<String, String>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Item {
    Whole {
        path: String,
        content: String,
    },
    /// Part of a file larger than one chunk, by 1-based line numbers.
    Piece {
        path: String,
        content: String,
        first_line: usize,
        last_line: usize,
        total_lines: usize,
        /// The previous piece's last lines (from this line), for reference.
        context: Option<(usize, String)>,
    },
    /// A unified diff against the approved version.
    Diff {
        path: String,
        diff: String,
    },
}

impl Item {
    pub(super) fn path(&self) -> &str {
        match self {
            Self::Whole { path, .. } | Self::Piece { path, .. } | Self::Diff { path, .. } => path,
        }
    }

    fn cost(&self) -> usize {
        match self {
            Self::Whole { path, content } => path.len() + weight(content),
            Self::Piece {
                path,
                content,
                context,
                ..
            } => {
                path.len() + weight(content) + context.as_ref().map_or(0, |(_, text)| weight(text))
            }
            Self::Diff { path, diff } => path.len() + weight(diff),
        }
    }
}

/// The bytes `text` takes in the request, where it is a JSON string: a
/// control or invisible character is written as six (twelve past the basic
/// plane), so a file of them is several times its size there.
fn weight(text: &str) -> usize {
    text.chars().map(char_weight).sum()
}

/// Asked of the writer itself, so the two cannot drift apart.
const fn char_weight(character: char) -> usize {
    json::written_len(character)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Sent {
    Whole,
    Diff,
    Unchanged,
    /// An unchanged file sent whole because a changed one names it.
    Named,
    Removed,
    /// A binary file Guardian hashed but did not send.
    HashOnly,
    /// A generated directory Guardian did not review.
    Skipped,
}

impl Sent {
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Whole => "whole",
            Self::Diff => "diff",
            Self::Unchanged => "unchanged",
            Self::Named => "unchanged-sent",
            Self::Removed => "removed",
            Self::HashOnly => "hash-only",
            Self::Skipped => "skipped",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ManifestEntry {
    pub(super) path: String,
    pub(super) bytes: usize,
    pub(super) sent: Sent,
    /// The detected format of hash-only files.
    pub(super) format: Option<String>,
    /// How many files a grouped entry stands for.
    pub(super) files: Option<usize>,
}

/// A file the review hashed but did not read: named to the AI with its
/// format, so a supplied file that runs, loads or unpacks it is judged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HashOnly {
    pub(crate) path: String,
    pub(crate) bytes: u64,
    pub(crate) label: &'static str,
    /// Images, audio, video and fonts: grouped per directory.
    pub(crate) media: bool,
    /// A skipped generated directory, with the entries it holds.
    pub(crate) skipped_files: Option<usize>,
}

/// The most hash-only manifest rows; the rest are counted in one row.
const MAX_HASH_ONLY_ROWS: usize = 64;

/// Manifest rows for hash-only files: one per file, except media, which get
/// one row per directory. Past the limit, the files a reviewed text names
/// (`named`) come first.
fn hash_only_entries(files: &[HashOnly], named: &HashSet<&str>) -> Vec<ManifestEntry> {
    let mut entries: Vec<ManifestEntry> = Vec::new();
    let mut media: BTreeMap<String, (usize, usize, BTreeSet<&str>)> = BTreeMap::new();
    for file in files {
        let bytes = usize::try_from(file.bytes).unwrap_or(usize::MAX);
        if let Some(count) = file.skipped_files {
            entries.push(ManifestEntry {
                path: format!("{}/", file.path),
                bytes,
                sent: Sent::Skipped,
                format: Some(file.label.to_string()),
                files: Some(count),
            });
        } else if file.media {
            let directory = file
                .path
                .rsplit_once('/')
                .map_or_else(String::new, |(directory, _)| format!("{directory}/"));
            let group = media.entry(directory).or_default();
            group.0 += 1;
            group.1 = group.1.saturating_add(bytes);
            group.2.insert(file.label);
        } else {
            entries.push(ManifestEntry {
                path: file.path.clone(),
                bytes,
                sent: Sent::HashOnly,
                format: Some(file.label.to_string()),
                files: None,
            });
        }
    }
    for (directory, (count, bytes, labels)) in media {
        entries.push(ManifestEntry {
            path: if directory.is_empty() {
                "./".into()
            } else {
                directory
            },
            bytes,
            sent: Sent::HashOnly,
            format: Some(labels.into_iter().collect::<Vec<_>>().join(", ")),
            files: Some(count),
        });
    }
    if entries.len() > MAX_HASH_ONLY_ROWS {
        // What a reviewed file names keeps its row.
        entries.sort_by_key(|entry| !named.contains(file_name(&entry.path)));
        let rest = entries.split_off(MAX_HASH_ONLY_ROWS - 1);
        entries.push(ManifestEntry {
            path: "(more hash-only files)".into(),
            bytes: rest
                .iter()
                .map(|entry| entry.bytes)
                .fold(0, usize::saturating_add),
            sent: Sent::HashOnly,
            format: Some("various".into()),
            files: Some(rest.iter().map(|entry| entry.files.unwrap_or(1)).sum()),
        });
    }
    entries
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Plan {
    pub(super) chunks: Vec<Vec<Item>>,
    pub(super) manifest: Vec<ManifestEntry>,
    pub(super) upgrade: bool,
    /// On an upgrade, the unchanged files a new or changed file names that
    /// did not fit beside the changes and were not sent.
    pub(super) named_not_sent: Vec<String>,
}

/// The plan needs more than `max_chunks` requests, or the manifest and
/// findings every request repeats leave too little room for source, or an
/// entry point does not fit one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TooLarge {
    /// An install or build entry point larger than one request: it runs as
    /// a whole, so it is not reviewed in pieces.
    pub(super) entry_point: Option<String>,
}

impl TooLarge {
    const INPUT: Self = Self { entry_point: None };
}

/// The most lines a piece repeats from the previous piece.
const MAX_CONTEXT_LINES: usize = 200;

pub(super) struct PlanInput<'a> {
    pub(super) files: &'a [SourceFile],
    /// Paths with a local finding: always sent whole and first.
    pub(super) flagged: &'a BTreeSet<String>,
    /// Bytes the local-findings block adds to every request.
    pub(super) findings_bytes: usize,
    pub(super) previous: Option<&'a Previous>,
    pub(super) max_input_bytes: usize,
    pub(super) max_chunks: usize,
    /// The review's unit prefixes (`Unit::prefix`), so a unit-relative path
    /// like `good/install.sh` still ranks as top-level under `--unit`.
    pub(super) unit_prefixes: &'a [String],
    /// Files hashed but not read, listed in the manifest.
    pub(super) hash_only: &'a [HashOnly],
}

/// 0: entry points that run at install, build or login time, and flagged
/// files; 1: other code and runtime config; 2: everything else.
fn tier(path: &str, content: &str, flagged: bool, unit_prefixes: &[String]) -> u8 {
    if flagged || is_entry_point(path, content, unit_prefixes) {
        0
    } else if rules::is_executable_or_runtime_config(path) {
        1
    } else {
        2
    }
}

fn is_entry_point(path: &str, content: &str, unit_prefixes: &[String]) -> bool {
    let name = file_name(path).to_ascii_lowercase();
    let extension = name.rsplit_once('.').map_or("", |(_, extension)| extension);
    let top_level = is_top_level(path, unit_prefixes);

    matches!(
        name.as_str(),
        "pkgbuild"
            | ".install"
            | "makefile"
            | "gnumakefile"
            | "cmakelists.txt"
            | "meson.build"
            | "build.rs"
            | "setup.py"
            | "pyproject.toml"
            | "package.json"
    ) || matches!(
        extension,
        "install" | "service" | "timer" | "socket" | "path" | "desktop" | "qml"
    ) || (top_level && extension == "sh")
        || (extension == "conf"
            && content
                .lines()
                .any(|line| line.trim_start().starts_with("exec")))
}

/// A path is top-level within its unit when it has no '/' left after
/// stripping whichever unit prefix it falls under; a path under no known
/// prefix (or when no units are known) is judged by its whole path, the
/// same rule a single unprefixed unit already gives.
fn is_top_level(path: &str, unit_prefixes: &[String]) -> bool {
    let relative = unit_prefixes
        .iter()
        .find_map(|prefix| path.strip_prefix(prefix.as_str()))
        .unwrap_or(path);
    !relative.contains('/')
}

enum Choice {
    Whole,
    /// Unchanged, and sent whole because a change names it.
    Named,
    Diff(String),
    Unchanged,
}

/// The files by risk: tier, then code before documentation, then path.
fn ranked<'a>(input: &'a PlanInput<'_>) -> Vec<(u8, bool, &'a SourceFile)> {
    let mut ranked: Vec<(u8, bool, &SourceFile)> = input
        .files
        .iter()
        .map(|file| {
            let flagged = input.flagged.contains(&file.path);
            (
                tier(&file.path, &file.content, flagged, input.unit_prefixes),
                rules::is_documentation(&file.path),
                file,
            )
        })
        .collect();
    ranked.sort_by(|left, right| {
        (left.0, left.1, &left.2.path).cmp(&(right.0, right.1, &right.2.path))
    });
    ranked
}

/// The manifest rows of the files that were hashed and not read.
fn hash_only_rows(input: &PlanInput<'_>) -> Vec<ManifestEntry> {
    // Which of them a reviewed file names only matters past the limit.
    let names: HashSet<&str> = if input.hash_only.len() > MAX_HASH_ONLY_ROWS {
        input
            .hash_only
            .iter()
            .map(|file| file_name(&file.path))
            .collect()
    } else {
        HashSet::new()
    };
    hash_only_entries(
        input.hash_only,
        &named_in(
            &names,
            &mut input.files.iter().map(|file| file.content.as_str()),
        ),
    )
}

pub(super) fn build(input: &PlanInput<'_>) -> Result<Plan, TooLarge> {
    // An upgrade shows more than the changes while that fits; where it
    // does not, the changes alone are still an upgrade review.
    build_with(input, true).or_else(|too_large| {
        if input.previous.is_some() && too_large.entry_point.is_none() {
            build_with(input, false)
        } else {
            Err(too_large)
        }
    })
}

/// `build`, with or without what an upgrade sends beyond its changes
/// (`extras`): larger changed files whole, and unchanged files a change
/// names.
fn build_with(input: &PlanInput<'_>, extras: bool) -> Result<Plan, TooLarge> {
    let ranked = ranked(input);

    let current: BTreeSet<&str> = input.files.iter().map(|file| file.path.as_str()).collect();
    let removed: Vec<(&String, &String)> = input
        .previous
        .into_iter()
        .flatten()
        .filter(|(path, _)| !current.contains(path.as_str()))
        .collect();

    let hash_only = hash_only_rows(input);
    let overhead = input.findings_bytes
        + hash_only
            .iter()
            .map(|entry| {
                entry.path.len()
                    + entry.format.as_ref().map_or(0, String::len)
                    + MANIFEST_ENTRY_OVERHEAD
            })
            .sum::<usize>()
        + input
            .files
            .iter()
            .map(|file| file.path.len() + MANIFEST_ENTRY_OVERHEAD)
            .sum::<usize>()
        + removed
            .iter()
            .map(|(path, _)| path.len() + MANIFEST_ENTRY_OVERHEAD)
            .sum::<usize>();
    if overhead.saturating_mul(2) > input.max_input_bytes {
        return Err(TooLarge::INPUT);
    }
    let capacity = input.max_input_bytes - overhead;

    let mut whole_room = if extras { capacity / WHOLE_SHARE } else { 0 };
    let mut choices: Vec<Choice> = ranked
        .iter()
        .map(|(tier, _, file)| choose(file, *tier == 0, input.previous, capacity, &mut whole_room))
        .collect();
    // Without the extras nothing named is sent along, and all of it is
    // reported as left out.
    let named_room = if extras { capacity / NAMED_SHARE } else { 0 };
    let named_not_sent = input.previous.map_or_else(Vec::new, |previous| {
        send_what_a_change_names(&ranked, &mut choices, previous, named_room)
    });

    let mut manifest = Vec::with_capacity(ranked.len() + removed.len());
    let mut items = Vec::new();
    for ((_, _, file), choice) in ranked.into_iter().zip(choices) {
        let sent = match choice {
            // Measured as it is packed: an entry point runs as a whole,
            // so it is not reviewed in pieces.
            Choice::Whole
                if file.path.len() + weight(&file.content) > capacity
                    && is_entry_point(&file.path, &file.content, input.unit_prefixes) =>
            {
                return Err(TooLarge {
                    entry_point: Some(file.path.clone()),
                });
            }
            Choice::Whole | Choice::Named => {
                items.push(Item::Whole {
                    path: file.path.clone(),
                    content: file.content.clone(),
                });
                if matches!(choice, Choice::Named) {
                    Sent::Named
                } else {
                    Sent::Whole
                }
            }
            Choice::Diff(diff) => {
                items.push(Item::Diff {
                    path: file.path.clone(),
                    diff,
                });
                Sent::Diff
            }
            Choice::Unchanged => Sent::Unchanged,
        };
        manifest.push(ManifestEntry {
            path: file.path.clone(),
            bytes: file.content.len(),
            sent,
            format: None,
            files: None,
        });
    }
    for (path, content) in removed {
        manifest.push(ManifestEntry {
            path: path.clone(),
            bytes: content.len(),
            sent: Sent::Removed,
            format: None,
            files: None,
        });
    }
    manifest.extend(hash_only);

    let chunks = pack(items, capacity, input.files)?;
    if chunks.len() > input.max_chunks {
        return Err(TooLarge::INPUT);
    }
    Ok(Plan {
        chunks,
        manifest,
        upgrade: input.previous.is_some(),
        named_not_sent,
    })
}

/// On an upgrade, turns the unchanged files a new or changed one names
/// into whole ones, the riskiest first, while they fit `room`: a change
/// that only switches on what another file already held is then seen with
/// that file. Returns the named files that did not fit, which stay listed
/// as unchanged.
fn send_what_a_change_names(
    ranked: &[(u8, bool, &SourceFile)],
    choices: &mut [Choice],
    previous: &Previous,
    mut room: usize,
) -> Vec<String> {
    // The files that are new or changed: an entry point sent whole as it
    // was names nothing new.
    let mut mentions = Mentions::default();
    for (_, _, file) in ranked {
        if previous.get(&file.path) != Some(&file.content) {
            mentions.add(directory(&file.path), &file.content);
        }
    }
    // Any unchanged file, whatever it is: what a change switches on may be
    // a test fixture, a build helper or a document as well as code.
    let mut left_out = Vec::new();
    for ((_, _, file), choice) in ranked.iter().zip(choices.iter_mut()) {
        if !matches!(choice, Choice::Unchanged) || !mentions.names(&file.path) {
            continue;
        }
        let cost = file.path.len() + weight(&file.content);
        if cost <= room {
            room -= cost;
            *choice = Choice::Named;
        } else {
            left_out.push(file.path.clone());
        }
    }
    left_out
}

/// What an upgrade sends for one file. Entry points always go whole, and
/// so does a small changed file, and a larger one while `whole_room`
/// lasts. A diff is used past that, when it is smaller than the file and
/// fits one chunk.
fn choose(
    file: &SourceFile,
    entry_point: bool,
    previous: Option<&Previous>,
    capacity: usize,
    whole_room: &mut usize,
) -> Choice {
    let Some(old) = previous
        .filter(|_| !entry_point)
        .and_then(|previous| previous.get(&file.path))
    else {
        return Choice::Whole;
    };
    if *old == file.content {
        return Choice::Unchanged;
    }
    // Whole only where it is seen whole: split into pieces, it would be
    // judged piece by piece, and a diff shows the change better.
    let cost = file.path.len() + weight(&file.content);
    if file.content.len() <= WHOLE_ON_UPGRADE && cost <= capacity {
        return Choice::Whole;
    }
    if cost <= *whole_room {
        *whole_room -= cost;
        return Choice::Whole;
    }
    match diff::unified(old, &file.content, DIFF_CONTEXT) {
        Some(diff)
            if diff.len() < file.content.len() && file.path.len() + weight(&diff) <= capacity =>
        {
            Choice::Diff(diff)
        }
        Some(_) | None => Choice::Whole,
    }
}

/// Packs items in order, starting a new chunk when the next one does not
/// fit. A source that needs several chunks is then packed again with the
/// files that belong together side by side (see `groups`), and that
/// packing is used when it needs no more chunks: each chunk is judged on
/// its own files, so a file and what it runs are better judged together.
fn pack(
    items: Vec<Item>,
    capacity: usize,
    files: &[SourceFile],
) -> Result<Vec<Vec<Item>>, TooLarge> {
    let mut pieces = Vec::new();
    for item in items {
        pieces.extend(split(item, capacity)?);
    }
    let costs: Vec<usize> = pieces.iter().map(Item::cost).collect();
    let in_order: Vec<usize> = (0..pieces.len()).collect();
    let plain = fill(&in_order, &costs, None, capacity);
    let chunk_count = |filled: &[usize]| filled.last().map_or(0, |last| last + 1);

    let (order, filled) = if chunk_count(&plain) > 1 {
        let (grouped, group_of) = groups(&pieces, files);
        // Whole groups in one chunk where that costs nothing, else at
        // least next to each other.
        [Some(group_of.as_slice()), None]
            .into_iter()
            .map(|whole| fill(&grouped, &costs, whole, capacity))
            .find(|filled| chunk_count(filled) <= chunk_count(&plain))
            .map_or((in_order, plain), |filled| (grouped, filled))
    } else {
        (in_order, plain)
    };

    let mut chunks: Vec<Vec<Item>> = Vec::new();
    chunks.resize_with(chunk_count(&filled), Vec::new);
    let mut pieces: Vec<Option<Item>> = pieces.into_iter().map(Some).collect();
    for (index, chunk) in order.into_iter().zip(filled) {
        chunks[chunk].extend(pieces[index].take());
    }
    Ok(chunks)
}

/// The chunk each of `order` (indexes into `costs`) goes in, filling
/// chunks in turn. With `group_of`, a group that would be cut by the end
/// of the chunk, and fits a chunk of its own, starts a new one.
fn fill(
    order: &[usize],
    costs: &[usize],
    group_of: Option<&[usize]>,
    capacity: usize,
) -> Vec<usize> {
    let mut filled = Vec::with_capacity(order.len());
    let mut chunk = 0;
    let mut used = 0;
    for (position, &index) in order.iter().enumerate() {
        let starts_group = group_of.is_some_and(|group_of| {
            position == 0 || group_of[order[position - 1]] != group_of[index]
        });
        let needed = match group_of.filter(|_| starts_group) {
            Some(group_of) => {
                let whole: usize = order[position..]
                    .iter()
                    .take_while(|next| group_of[**next] == group_of[index])
                    .map(|next| costs[*next])
                    .sum();
                if whole <= capacity {
                    whole
                } else {
                    costs[index]
                }
            }
            None => costs[index],
        };
        if used + needed > capacity && used > 0 {
            chunk += 1;
            used = 0;
        }
        used += costs[index];
        filled.push(chunk);
    }
    filled
}

/// The pieces in an order that puts side by side what belongs together,
/// and a group number for each piece. Files in the same directory share a
/// group, and so do a file and the files it names. Groups come in the
/// order of their riskiest file; within one, each file is followed by the
/// files it names, and otherwise the order the files had is kept.
fn groups(pieces: &[Item], files: &[SourceFile]) -> (Vec<usize>, Vec<usize>) {
    let mut paths: Vec<&str> = Vec::new();
    let mut numbers: HashMap<&str, usize> = HashMap::new();
    let mut pieces_of: Vec<Vec<usize>> = Vec::new();
    for (index, piece) in pieces.iter().enumerate() {
        let path = *numbers.entry(piece.path()).or_insert_with(|| {
            paths.push(piece.path());
            pieces_of.push(Vec::new());
            paths.len() - 1
        });
        pieces_of[path].push(index);
    }
    // Each path starts as its own group.
    let mut group: Vec<usize> = (0..paths.len()).collect();
    let mut by_directory: HashMap<&str, usize> = HashMap::new();
    for (index, path) in paths.iter().enumerate() {
        let first = *by_directory.entry(directory(path)).or_insert(index);
        join_groups(&mut group, first, index);
    }
    let content: HashMap<&str, &str> = files
        .iter()
        .map(|file| (file.path.as_str(), file.content.as_str()))
        .collect();
    let mut named: Vec<Vec<usize>> = vec![Vec::new(); paths.len()];
    for (index, path) in paths.iter().enumerate() {
        let Some(text) = content.get(path) else {
            continue;
        };
        let mut mentions = Mentions::default();
        mentions.add(directory(path), text);
        for (other, candidate) in paths.iter().enumerate() {
            if other != index && mentions.names(candidate) {
                join_groups(&mut group, index, other);
                named[index].push(other);
            }
        }
    }

    let mut members: HashMap<usize, Vec<usize>> = HashMap::new();
    for path in 0..paths.len() {
        members
            .entry(group_root(&mut group, path))
            .or_default()
            .push(path);
    }
    let mut placed = vec![false; paths.len()];
    let mut order = Vec::with_capacity(pieces.len());
    for first in 0..paths.len() {
        let group = group_root(&mut group, first);
        for &member in members.remove(&group).iter().flatten() {
            // A file, then what it names, then what those name.
            let mut next = vec![member];
            while let Some(path) = next.pop() {
                if mem::replace(&mut placed[path], true) {
                    continue;
                }
                order.extend(&pieces_of[path]);
                next.extend(named[path].iter().rev().filter(|other| !placed[**other]));
            }
        }
    }
    let mut group_of = vec![0; pieces.len()];
    for (path, pieces) in pieces_of.iter().enumerate() {
        let group = group_root(&mut group, path);
        for &piece in pieces {
            group_of[piece] = group;
        }
    }
    (order, group_of)
}

/// The group `index` is in: the entry that stands for itself at the end of
/// the chain from it.
fn group_root(group: &mut [usize], mut index: usize) -> usize {
    while group[index] != index {
        group[index] = group[group[index]];
        index = group[index];
    }
    index
}

/// Makes two groups one, named by the earlier of the two.
fn join_groups(group: &mut [usize], left: usize, right: usize) {
    let (left, right) = (group_root(group, left), group_root(group, right));
    group[left.max(right)] = left.min(right);
}

/// The files of one chunk that name files of another, as (file, its
/// chunk, the file it names, that file's chunk), chunks counted from 1:
/// each chunk is judged without the other's content, so the report says
/// where a split falls between a file and what it names.
pub(super) fn split_references(
    chunks: &[Vec<Item>],
    files: &[SourceFile],
) -> Vec<(String, usize, String, usize)> {
    if chunks.len() < 2 {
        return Vec::new();
    }
    // A file cut into pieces is in the chunk of its first piece here.
    let mut chunk_of: Vec<(&str, usize)> = Vec::new();
    for (number, chunk) in chunks.iter().enumerate() {
        for item in chunk {
            if !chunk_of.iter().any(|(path, _)| *path == item.path()) {
                chunk_of.push((item.path(), number + 1));
            }
        }
    }
    let content: HashMap<&str, &str> = files
        .iter()
        .map(|file| (file.path.as_str(), file.content.as_str()))
        .collect();
    let mut references = Vec::new();
    for (path, chunk) in &chunk_of {
        let Some(text) = content.get(path) else {
            continue;
        };
        let mut mentions = Mentions::default();
        mentions.add(directory(path), text);
        for (named, other) in &chunk_of {
            if other != chunk && mentions.names(named) {
                references.push(((*path).to_string(), *chunk, (*named).to_string(), *other));
            }
        }
    }
    references
}

/// Splits a whole file that exceeds `capacity` into pieces on line
/// boundaries; a single longer line is cut at character boundaries.
fn split(item: Item, capacity: usize) -> Result<Vec<Item>, TooLarge> {
    if item.cost() <= capacity {
        return Ok(vec![item]);
    }
    // Diffs are only chosen when they fit, and pieces are made only here.
    let Item::Whole { path, content } = item else {
        return Err(TooLarge::INPUT);
    };
    let room = capacity
        .checked_sub(path.len())
        .filter(|room| *room >= MIN_PIECE)
        .ok_or(TooLarge::INPUT)?;

    let lines: Vec<&str> = content.split_inclusive('\n').collect();
    let total_lines = lines.len();
    let piece = |text: String, first_line: usize, last_line: usize, context| Item::Piece {
        path: path.clone(),
        content: text,
        first_line,
        last_line,
        total_lines,
        context,
    };

    // Each piece after the first repeats up to an eighth of its room from
    // the end of the previous one, so logic across a cut is seen together.
    let budget = room / 8;
    let mut pieces = Vec::new();
    let mut text = String::new();
    let mut used = 0;
    let mut first_line = 1;
    let mut context: Option<(usize, String)> = None;
    let mut available = room;
    for (index, line) in lines.iter().enumerate() {
        let number = index + 1;
        let line_weight = weight(line);
        if !text.is_empty() && used + line_weight > available {
            let done = mem::take(&mut text);
            used = 0;
            let next = tail(&done, first_line, budget);
            pieces.push(piece(done, first_line, number - 1, context.take()));
            first_line = number;
            context = next;
            available = room - context.as_ref().map_or(0, |(_, text)| weight(text));
        }
        // A line that does not fit beside the repeated lines keeps as
        // many of them as it leaves room for.
        if line_weight > available {
            context = context
                .take()
                .and_then(|(first, text)| tail(&text, first, room.saturating_sub(line_weight)));
            available = room - context.as_ref().map_or(0, |(_, text)| weight(text));
        }
        if line_weight > room {
            // A line longer than a piece is cut; each part after the first
            // repeats the end of the one before, so nothing is hidden by
            // being split exactly at a cut.
            let overlap = budget.max(MIN_PIECE);
            let mut before: Option<&str> = None;
            for part in cut(line, room - overlap) {
                let context = before
                    .map(|before| end(before, overlap))
                    .filter(|text| !text.is_empty())
                    .map(|text| (number, text.to_string()));
                pieces.push(piece(part.to_string(), number, number, context));
                before = Some(part);
            }
            first_line = number + 1;
            continue;
        }
        text.push_str(line);
        used += line_weight;
    }
    if !text.is_empty() {
        pieces.push(piece(text, first_line, total_lines, context));
    }
    Ok(pieces)
}

/// The last lines of `text` (which starts at line `first_line`) within
/// `budget` bytes and `MAX_CONTEXT_LINES`, with the number of the first.
fn tail(text: &str, first_line: usize, budget: usize) -> Option<(usize, String)> {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let mut bytes = 0;
    let mut kept = 0;
    for line in lines.iter().rev().take(MAX_CONTEXT_LINES) {
        if bytes + weight(line) > budget {
            break;
        }
        bytes += weight(line);
        kept += 1;
    }
    (kept > 0).then(|| {
        (
            first_line + lines.len() - kept,
            lines[lines.len() - kept..].concat(),
        )
    })
}

/// The end of `text` within `budget` bytes of the request.
fn end(text: &str, budget: usize) -> &str {
    let mut used = 0;
    let mut start = text.len();
    for (index, character) in text.char_indices().rev() {
        used += char_weight(character);
        if used > budget {
            break;
        }
        start = index;
    }
    &text[start..]
}

/// Cuts `line` into parts of at most `room` bytes of the request, at
/// character boundaries. `room` is at least `MIN_PIECE`, so every part
/// holds one character.
fn cut(line: &str, room: usize) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut used = 0;
    for (index, character) in line.char_indices() {
        let size = char_weight(character);
        if used + size > room && index > start {
            parts.push(&line[start..index]);
            start = index;
            used = 0;
        }
        used += size;
    }
    if start < line.len() {
        parts.push(&line[start..]);
    }
    parts
}

#[cfg(test)]
mod tests;
