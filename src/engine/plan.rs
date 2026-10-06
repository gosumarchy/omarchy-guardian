//! Turns the files queued for the AI review into chunked requests: rank by
//! risk, choose what each file is sent as on an upgrade, and pack.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::mem;

use crate::agent::SourceFile;
use crate::engine::diff;
use crate::json;
use crate::paths::file_name;
use crate::rules;

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
/// The shortest file name looked for in the changed files.
const MIN_NAMED: usize = 5;

/// Bytes charged for each manifest entry on top of its path.
pub const MANIFEST_ENTRY_OVERHEAD: usize = 32;

/// A cut line piece must hold at least one character of any width.
const MIN_PIECE: usize = 4;

/// The approved version of each file, by path, when the target is an upgrade.
pub type Previous = BTreeMap<String, String>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item {
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
    pub fn path(&self) -> &str {
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
pub enum Sent {
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
    pub const fn name(self) -> &'static str {
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
pub struct ManifestEntry {
    pub path: String,
    pub bytes: usize,
    pub sent: Sent,
    /// The detected format of hash-only files.
    pub format: Option<String>,
    /// How many files a grouped entry stands for.
    pub files: Option<usize>,
}

/// A file the review hashed but did not read: named to the AI with its
/// format, so a supplied file that runs, loads or unpacks it is judged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashOnly {
    pub path: String,
    pub bytes: u64,
    pub label: &'static str,
    /// Images, audio, video and fonts: grouped per directory.
    pub media: bool,
    /// A skipped generated directory, with the entries it holds.
    pub skipped_files: Option<usize>,
}

/// The most hash-only manifest rows; the rest are counted in one row.
const MAX_HASH_ONLY_ROWS: usize = 64;

/// A file name without its extension, as code names a module (`import
/// helper` for `helper.py`).
fn stem(name: &str) -> Option<&str> {
    name.rsplit_once('.')
        .map(|(stem, _)| stem)
        .filter(|stem| !stem.is_empty())
}

/// The directory a path is in; empty at the top level.
fn directory(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(directory, _)| directory)
}

/// A directory or a glob written in a text: `hooks.d/*`, `tests/*.dat`,
/// `for f in dir/`, or a bare `*.sh` beside the file that says it.
struct Glob<'a> {
    /// The directory as written, without `.` parts; empty for a bare glob.
    directory: String,
    /// What the file name must match; `*` for a directory named alone.
    pattern: &'a str,
    /// The directory of the file that wrote it.
    from: &'a str,
}

/// What texts say about other files: the words, path parts and globs in
/// them. A file is named by its name or module name as a word, by its
/// name as a part of something written as a path, or by a directory or
/// glob that covers it.
#[derive(Default)]
pub(crate) struct Mentions<'a> {
    words: HashSet<&'a str>,
    parts: HashSet<&'a str>,
    /// By the last directory a glob names; under the empty key, the ones
    /// that name none.
    globs: HashMap<&'a str, Vec<Glob<'a>>>,
}

impl<'a> Mentions<'a> {
    /// Adds what `text`, a file in directory `from`, mentions.
    pub(crate) fn add(&mut self, from: &'a str, text: &'a str) {
        for token in text.split(|character: char| {
            !(character.is_alphanumeric()
                || matches!(character, '.' | '_' | '-' | '+' | '/' | '*' | '?'))
        }) {
            if !token.contains(['/', '*', '?']) {
                self.word(token);
                continue;
            }
            let mut parts: Vec<&str> = token
                .split('/')
                .filter(|part| !part.is_empty() && *part != ".")
                .collect();
            let Some(&last) = parts.last() else {
                continue;
            };
            if last.contains(['*', '?']) {
                parts.pop();
                // A lone `*` is multiplication more often than a glob.
                if !parts.is_empty() || last.chars().any(char::is_alphanumeric) {
                    self.glob(&parts, last, from);
                }
            } else if token.ends_with('/') {
                self.glob(&parts, "*", from);
            }
            for part in parts {
                if !part.contains(['*', '?']) {
                    self.parts.insert(part);
                    self.word(part);
                }
            }
        }
    }

    /// As written, without what may only end a sentence (`see
    /// payload.c.`), and each part between dots (`pkg.helper`).
    fn word(&mut self, word: &'a str) {
        if word.is_empty() {
            return;
        }
        self.words.insert(word);
        self.words.insert(word.trim_end_matches(['.', '-', '+']));
        self.words
            .extend(word.split('.').filter(|part| !part.is_empty()));
    }

    fn glob(&mut self, directory: &[&'a str], pattern: &'a str, from: &'a str) {
        self.globs
            .entry(directory.last().copied().unwrap_or_default())
            .or_default()
            .push(Glob {
                directory: directory.join("/"),
                pattern,
                from,
            });
    }

    /// Whether the texts name the file at `path`. A short name without an
    /// extension (`run`, `x`) is a word in too many places: it counts only
    /// as a part of something written as a path (`build-aux/run`).
    pub(crate) fn names(&self, path: &str) -> bool {
        let name = file_name(path);
        let stem = stem(name);
        if self.parts.contains(name)
            || (self.words.contains(name) && (stem.is_some() || name.len() >= MIN_NAMED))
            || stem.is_some_and(|stem| stem.len() >= MIN_NAMED && self.words.contains(stem))
        {
            return true;
        }
        let parent = directory(path);
        let beside = self
            .globs
            .get("")
            .into_iter()
            .flatten()
            .filter(|glob| glob.from == parent);
        // Written from anywhere: `tests/*.dat` is `$srcdir/tests/*.dat`.
        let under = self
            .globs
            .get(file_name(parent))
            .into_iter()
            .flatten()
            .filter(|glob| {
                !glob.directory.is_empty()
                    && parent
                        .strip_suffix(glob.directory.as_str())
                        .is_some_and(|above| above.is_empty() || above.ends_with('/'))
            });
        beside
            .chain(under)
            .any(|glob| glob_matches(glob.pattern, name))
    }
}

/// Whether `name` matches a shell pattern of literal characters, `*` and
/// `?`.
pub(crate) fn glob_matches(pattern: &str, name: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    let (mut at, mut seen) = (0, 0);
    // Where the last `*` was, and how much of the name it has taken.
    let mut star: Option<(usize, usize)> = None;
    while seen < name.len() {
        match pattern.get(at) {
            Some('*') => {
                star = Some((at, seen));
                at += 1;
            }
            Some(&character) if character == '?' || character == name[seen] => {
                at += 1;
                seen += 1;
            }
            _ => {
                let Some((star_at, taken)) = star else {
                    return false;
                };
                star = Some((star_at, taken + 1));
                at = star_at + 1;
                seen = taken + 1;
            }
        }
    }
    pattern[at..].iter().all(|character| *character == '*')
}

/// Which of `names` the texts hold as a word: a file name they mention.
fn named_in<'a>(
    names: &HashSet<&'a str>,
    texts: &mut dyn Iterator<Item = &str>,
) -> HashSet<&'a str> {
    let mut found = HashSet::new();
    if names.is_empty() {
        return found;
    }
    for text in texts {
        for word in text.split(|character: char| {
            !(character.is_alphanumeric() || matches!(character, '.' | '_' | '-' | '+'))
        }) {
            // As written, without what may only end a sentence (`see
            // payload.c.`), and each part between dots (`pkg.helper`).
            for candidate in [word, word.trim_end_matches(['.', '-', '+'])]
                .into_iter()
                .chain(word.split('.'))
            {
                if let Some(name) = names.get(candidate) {
                    found.insert(*name);
                }
            }
        }
    }
    found
}

/// Manifest rows for hash-only files: one per file, except media, which get
/// one row per directory. Past the limit, the files a reviewed text names
/// (`named`) come first.
pub fn hash_only_entries(files: &[HashOnly], named: &HashSet<&str>) -> Vec<ManifestEntry> {
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
pub struct Plan {
    pub chunks: Vec<Vec<Item>>,
    pub manifest: Vec<ManifestEntry>,
    pub upgrade: bool,
    /// On an upgrade, the unchanged files a new or changed file names that
    /// did not fit beside the changes and were not sent.
    pub named_not_sent: Vec<String>,
}

/// The plan needs more than `max_chunks` requests, or the manifest and
/// findings every request repeats leave too little room for source, or an
/// entry point does not fit one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TooLarge {
    /// An install or build entry point larger than one request: it runs as
    /// a whole, so it is not reviewed in pieces.
    pub entry_point: Option<String>,
}

impl TooLarge {
    pub const INPUT: Self = Self { entry_point: None };
}

/// The most lines a piece repeats from the previous piece.
const MAX_CONTEXT_LINES: usize = 200;

pub struct PlanInput<'a> {
    pub files: &'a [SourceFile],
    /// Paths with a local finding: always sent whole and first.
    pub flagged: &'a BTreeSet<String>,
    /// Bytes the local-findings block adds to every request.
    pub findings_bytes: usize,
    pub previous: Option<&'a Previous>,
    pub max_input_bytes: usize,
    pub max_chunks: usize,
    /// The review's unit prefixes (`Unit::prefix`), so a unit-relative path
    /// like `good/install.sh` still ranks as top-level under `--unit`.
    pub unit_prefixes: &'a [String],
    /// Files hashed but not read, listed in the manifest.
    pub hash_only: &'a [HashOnly],
}

/// 0: entry points that run at install, build or login time, and flagged
/// files; 1: other code and runtime config; 2: everything else.
pub fn tier(path: &str, content: &str, flagged: bool, unit_prefixes: &[String]) -> u8 {
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

pub fn build(input: &PlanInput<'_>) -> Result<Plan, TooLarge> {
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
pub fn split_references(
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
mod tests {
    use std::collections::BTreeSet;

    use super::{Item, Plan, PlanInput, Previous, Sent, TooLarge, build, tier};
    use crate::agent::SourceFile;

    fn file(path: &str, content: &str) -> SourceFile {
        SourceFile {
            path: path.into(),
            content: content.into(),
        }
    }

    fn plan(
        files: &[SourceFile],
        previous: Option<&Previous>,
        max_input_bytes: usize,
        max_chunks: usize,
    ) -> Result<Plan, TooLarge> {
        build(&PlanInput {
            files,
            flagged: &BTreeSet::new(),
            findings_bytes: 0,
            previous,
            max_input_bytes,
            max_chunks,
            unit_prefixes: &[],
            hash_only: &[],
        })
    }

    fn paths(chunk: &[Item]) -> Vec<&str> {
        chunk.iter().map(Item::path).collect()
    }

    #[test]
    fn an_upgrade_shows_what_a_change_may_switch_on() {
        let big = |seed: &str| format!("// {seed}\n{}", "int v = 1;\n".repeat(9000));
        let previous: Previous = [
            ("src/a.c".to_string(), big("one")),
            ("src/b.c".to_string(), big("one")),
            ("src/main.c".to_string(), "run();\n".to_string()),
            (
                "src/payload.c".to_string(),
                "void payload(void);\n".to_string(),
            ),
            ("src/other.c".to_string(), "void other(void);\n".to_string()),
            ("src/helper.py".to_string(), "def run(): pass\n".to_string()),
            ("PKGBUILD".to_string(), "source=(listed.c)\n".to_string()),
            (
                "src/listed.c".to_string(),
                "void listed(void);\n".to_string(),
            ),
        ]
        .into_iter()
        .collect();
        let files = [
            // Two changed files past the size that always goes whole: the
            // first still does, the second no longer fits beside it.
            file("src/a.c", &big("two")),
            file("src/b.c", &big("two")),
            // A change that names a file which did not change.
            file(
                "src/main.c",
                "#include \"payload.c\"\nfrom pkg.helper import run\nrun();\n",
            ),
            file("src/payload.c", "void payload(void);\n"),
            file("src/other.c", "void other(void);\n"),
            file("src/helper.py", "def run(): pass\n"),
            // An entry point goes whole as it was; what it names is not
            // sent for that.
            file("PKGBUILD", "source=(listed.c)\n"),
            file("src/listed.c", "void listed(void);\n"),
        ];
        let plan = plan(&files, Some(&previous), 256 * 1024, 8).unwrap();
        let sent: Vec<(&str, Sent)> = plan
            .manifest
            .iter()
            .map(|entry| (entry.path.as_str(), entry.sent))
            .collect();
        assert_eq!(
            sent,
            [
                ("PKGBUILD", Sent::Whole),
                ("src/a.c", Sent::Whole),
                ("src/b.c", Sent::Diff),
                // Named without its extension, as a module is.
                ("src/helper.py", Sent::Named),
                ("src/listed.c", Sent::Unchanged),
                ("src/main.c", Sent::Whole),
                ("src/other.c", Sent::Unchanged),
                ("src/payload.c", Sent::Named),
            ]
        );
    }

    /// The approved version of `files`, as a plan's `previous`.
    fn approved(files: &[(&str, &str)]) -> Previous {
        files
            .iter()
            .map(|(path, content)| ((*path).to_string(), (*content).to_string()))
            .collect()
    }

    fn sent(plan: &Plan) -> Vec<(&str, Sent)> {
        plan.manifest
            .iter()
            .map(|entry| (entry.path.as_str(), entry.sent))
            .collect()
    }

    #[test]
    fn a_change_that_switches_on_a_dormant_file_is_sent_with_it() {
        // The shape of the xz backdoor: files that sit in the tree as test
        // data and build helpers, and one changed build line that runs them.
        let dormant = [
            ("tests/fixture.dat", "#!/bin/sh\necho payload\n"),
            ("build-aux/run", "exec \"$@\"\n"),
            ("m4/x.m4", "AC_DEFUN([X], [])\n"),
            ("configure", "#!/bin/sh\necho configure\n"),
            ("docs/NOTES.md", "notes\n"),
            ("src/quiet.c", "int quiet;\n"),
            ("src/run.c", "int run;\n"),
        ];
        let mut before = dormant.to_vec();
        before.push(("src/build.mk", "all:\n\tcc -o demo src/quiet.c\n"));
        let previous = approved(&before);
        let plan_for = |changed: &str| {
            let mut files: Vec<SourceFile> = dormant
                .iter()
                .map(|(path, content)| file(path, content))
                .collect();
            files.push(file("src/build.mk", changed));
            plan(&files, Some(&previous), 256 * 1024, 8).unwrap()
        };
        let named = |changed: &str| -> Vec<String> {
            plan_for(changed)
                .manifest
                .iter()
                .filter(|entry| entry.sent == Sent::Named)
                .map(|entry| entry.path.clone())
                .collect()
        };

        // By path, at any tier, whatever the file is called.
        assert_eq!(
            named("all:\n\tsh tests/fixture.dat\n"),
            ["tests/fixture.dat"]
        );
        assert_eq!(
            named("all:\n\t$(top_srcdir)/build-aux/run x\n"),
            ["build-aux/run"]
        );
        assert_eq!(named("all:\n\tm4 -I m4 x.m4\n"), ["m4/x.m4"]);
        // An extensionless name of some length, as a bare word.
        assert_eq!(named("all:\n\t./configure --prefix=/usr\n"), ["configure"]);
        // Documentation as well: what is run need not look like code.
        assert_eq!(named("all:\n\tsh docs/NOTES.md\n"), ["docs/NOTES.md"]);
        // A short name without an extension is a word in too many places:
        // `run` alone names nothing, as a part of a path it does.
        assert_eq!(
            named("all:\n\trun the tests, then run them again\n"),
            [""; 0]
        );
        assert_eq!(named("all:\n\t./build-aux/run\n"), ["build-aux/run"]);
        // A module name still stands for its file, a short one does not.
        assert_eq!(named("all:\n\tcc quiet.o\n"), ["src/quiet.c"]);
        assert_eq!(named("all:\n\tcc run.o\n"), [""; 0]);
        // A glob or a directory pulls in what it covers, wherever the
        // changed file is; a bare glob means the files beside it.
        assert_eq!(
            named("all:\n\tcat $(srcdir)/tests/*.dat | sh\n"),
            ["tests/fixture.dat"]
        );
        assert_eq!(
            named("all:\n\tfor f in build-aux/; do sh $$f; done\n"),
            ["build-aux/run"]
        );
        assert_eq!(named("all:\n\tcc *.c\n"), ["src/quiet.c", "src/run.c"]);
        assert_eq!(named("all:\n\techo 2 * 3\n"), [""; 0]);
        // Nothing named: only the change is sent.
        let quiet = plan_for("all:\n\ttrue\n");
        assert!(quiet.named_not_sent.is_empty());
        assert_eq!(
            sent(&quiet)
                .iter()
                .filter(|(_, sent)| *sent != Sent::Unchanged)
                .count(),
            1
        );
    }

    #[test]
    fn a_named_file_that_does_not_fit_is_reported_not_dropped() {
        let large = "x = 1\n".repeat(30_000);
        let previous = approved(&[
            ("install.mk", "all:\n\ttrue\n"),
            ("tests/big.dat", &large),
            ("tests/small.dat", "s\n"),
        ]);
        let files = [
            file("install.mk", "all:\n\tsh tests/big.dat tests/small.dat\n"),
            file("tests/big.dat", &large),
            file("tests/small.dat", "s\n"),
        ];
        // Half a request is 128 KiB; the file is 180 KiB there.
        let plan = plan(&files, Some(&previous), 256 * 1024, 8).unwrap();
        assert_eq!(plan.named_not_sent, ["tests/big.dat"]);
        assert_eq!(
            sent(&plan),
            [
                ("install.mk", Sent::Whole),
                ("tests/big.dat", Sent::Unchanged),
                ("tests/small.dat", Sent::Named),
            ]
        );
    }

    #[test]
    fn globs_match_as_a_shell_matches_names() {
        for (pattern, name, matches) in [
            ("*", "anything", true),
            ("*.dat", "fixture.dat", true),
            ("*.dat", "fixture.data", false),
            ("fix*", "fixture.dat", true),
            ("f*x*t", "fixture.dat", true),
            ("f?xture.dat", "fixture.dat", true),
            ("f?xture.dat", "fxture.dat", false),
            ("*.d?t", "a.dot", true),
            ("a*b*c", "abcabc", true),
            ("a*b*c", "abcab", false),
            ("", "", true),
            ("", "a", false),
            ("**", "", true),
        ] {
            assert_eq!(
                super::glob_matches(pattern, name),
                matches,
                "{pattern} {name}"
            );
        }
    }

    #[test]
    fn files_that_belong_together_share_a_chunk_where_that_is_free() {
        // Four files, two to a chunk. By rank the two units, which are
        // entry points, come first and share a chunk, and the scripts they
        // start share the other; grouped by directory, each unit is with
        // its script.
        let body = |seed: &str| format!("# {seed}\n{}", "x".repeat(390));
        let files = [
            file("a/x.service", &body("a1")),
            file("b/y.service", &body("b1")),
            file("a/two.sh", &body("a2")),
            file("b/two.sh", &body("b2")),
        ];
        let unit = files[0].path.len() + super::weight(&files[0].content);
        let overhead = 2 * (11 + 32) + 2 * (8 + 32);
        let by_directory = plan(&files, None, overhead + 2 * unit, 8).unwrap();
        let chunks: Vec<Vec<&str>> = by_directory
            .chunks
            .iter()
            .map(|chunk| paths(chunk))
            .collect();
        assert_eq!(
            chunks,
            [["a/x.service", "a/two.sh"], ["b/y.service", "b/two.sh"]]
        );

        // A file and the file it names, across directories: `run.sh`
        // sources `lib/z.sh`, which by path would land in another chunk.
        let files = [
            file("lib/a.sh", &body("a")),
            file("lib/b.sh", &body("b")),
            file("lib/c.sh", &body("c")),
            file("lib/z.sh", &body("z")),
            file("run.sh", &format!(". lib/z.sh\n{}", "x".repeat(384))),
            file("zz/tail.sh", &body("t")),
        ];
        let cost = |file: &SourceFile| file.path.len() + super::weight(&file.content);
        let overhead: usize = files.iter().map(|file| file.path.len() + 32).sum();
        let plan = plan(&files, None, overhead + 2 * cost(&files[0]) + 6, 8).unwrap();
        let chunk_of = |path: &str| {
            plan.chunks
                .iter()
                .position(|chunk| paths(chunk).contains(&path))
                .unwrap()
        };
        // Grouping must not cost a chunk: three pairs either way.
        assert_eq!(plan.chunks.len(), 3);
        assert_eq!(chunk_of("run.sh"), chunk_of("lib/z.sh"));
        assert_eq!(chunk_of("run.sh"), 0, "the entry point's group goes first");
    }

    #[test]
    fn grouping_never_takes_more_chunks_than_packing_by_rank() {
        // Sizes that pack tightly by rank and badly by directory: grouped
        // packing would need a third chunk, so the rank order is kept.
        let files = [
            file("a/1.c", &"x".repeat(150)),
            file("b/1.c", &"x".repeat(50)),
            file("a/2.c", &"x".repeat(150)),
            file("b/2.c", &"x".repeat(50)),
        ];
        let overhead = 4 * (5 + 32);
        let by_rank = plan(&files, None, overhead + 2 * 155 + 2 * 55, 8).unwrap();
        assert_eq!(by_rank.chunks.len(), 1);
        let tight = plan(&files, None, overhead + 155 + 55 + 100, 8).unwrap();
        let chunks: Vec<Vec<&str>> = tight.chunks.iter().map(|chunk| paths(chunk)).collect();
        assert!(chunks.len() <= 2, "{chunks:?}");
        assert_eq!(chunks.iter().map(Vec::len).sum::<usize>(), 4, "{chunks:?}");
    }

    #[test]
    fn references_across_chunks_are_found() {
        let files = [
            file("a.sh", &format!(". ./lib/far.sh\n{}", "x".repeat(280))),
            file("lib/far.sh", &"y".repeat(300)),
        ];
        let overhead = (4 + 32) + (10 + 32);
        let plan = plan(&files, None, overhead + 320, 8).unwrap();
        assert_eq!(plan.chunks.len(), 2);
        assert_eq!(
            super::split_references(&plan.chunks, &files),
            [("a.sh".to_string(), 1, "lib/far.sh".to_string(), 2)]
        );
        let one = build(&PlanInput {
            files: &files,
            flagged: &BTreeSet::new(),
            findings_bytes: 0,
            previous: None,
            max_input_bytes: 64 * 1024,
            max_chunks: 8,
            unit_prefixes: &[],
            hash_only: &[],
        })
        .unwrap();
        assert!(super::split_references(&one.chunks, &files).is_empty());
    }

    #[test]
    fn an_upgrade_that_cannot_show_more_still_shows_its_changes() {
        let body =
            |seed: &str, lines: usize| format!("// {seed}\n{}", "int v = 1;\n".repeat(lines));
        let previous: Previous = [("src/a.c".to_string(), body("one", 9000))]
            .into_iter()
            .collect();
        // A changed file that would go whole, and a new one beside which
        // it no longer fits one request.
        let files = [
            file("src/a.c", &body("two", 9000)),
            file("src/new.c", &body("new", 14_000)),
        ];
        let sent = |max_chunks| {
            plan(&files, Some(&previous), 256 * 1024, max_chunks).map(|plan| {
                plan.manifest
                    .iter()
                    .map(|entry| (entry.path.clone(), entry.sent))
                    .collect::<Vec<_>>()
            })
        };
        assert_eq!(sent(8).unwrap()[0], ("src/a.c".to_string(), Sent::Whole));
        assert_eq!(sent(1).unwrap()[0], ("src/a.c".to_string(), Sent::Diff));
    }

    #[test]
    fn an_entry_point_is_measured_as_it_is_sent() {
        // Small on disk, six times that in the request: not one piece.
        let files = [file("PKGBUILD", &"\u{1}".repeat(60_000))];
        assert_eq!(
            plan(&files, None, 256 * 1024, 8),
            Err(TooLarge {
                entry_point: Some("PKGBUILD".into())
            })
        );
    }

    #[test]
    fn a_long_line_keeps_what_it_can_of_the_lines_before_it() {
        // Short lines, then one that leaves little room beside it.
        let mut content = "short();\n".repeat(400);
        content.push_str(&"x".repeat(3000));
        content.push('\n');
        content.push_str(&"short();\n".repeat(400));
        let plan = plan(&[file("src/a.c", &content)], None, 4096, 64).unwrap();
        let pieces: Vec<&Item> = plan.chunks.iter().flatten().collect();
        assert!(pieces.len() > 2);
        // None is larger than a request has room for.
        assert!(pieces.iter().all(|piece| piece.cost() <= 4096));
        for piece in &pieces[1..] {
            assert!(
                matches!(
                    piece,
                    Item::Piece {
                        context: Some(_),
                        ..
                    }
                ),
                "{piece:?}"
            );
        }
    }

    #[test]
    fn tiers_rank_entry_points_first() {
        assert_eq!(tier("PKGBUILD", "", false, &[]), 0);
        assert_eq!(tier("guardian.install", "", false, &[]), 0);
        assert_eq!(tier("pkg/archive/.INSTALL", "", false, &[]), 0);
        assert_eq!(tier("install.sh", "", false, &[]), 0);
        assert_eq!(tier("tools/run.sh", "", false, &[]), 1);
        assert_eq!(
            tier("hypr/autostart.conf", "exec-once = x\n", false, &[]),
            0
        );
        assert_eq!(tier("hypr/colors.conf", "col = 1\n", false, &[]), 1);
        assert_eq!(tier("src/main.c", "", false, &[]), 1);
        assert_eq!(tier("README.md", "", false, &[]), 2);
        assert_eq!(tier("notes.txt", "", true, &[]), 0);
    }

    #[test]
    fn a_unit_relative_top_level_script_ranks_as_an_entry_point() {
        // Without a unit_prefixes it does not, but under `--unit good
        // theme:good` the file `good/install.sh` is top-level within its
        // unit and must still rank tier 0 (spec §4: top-level *.sh always
        // sent whole).
        assert_eq!(tier("good/install.sh", "", false, &[]), 1);
        let prefixes = ["good/".to_string()];
        assert_eq!(tier("good/install.sh", "", false, &prefixes), 0);
        assert_eq!(tier("good/nested/install.sh", "", false, &prefixes), 1);
        assert_eq!(tier("other/install.sh", "", false, &prefixes), 1);
    }

    #[test]
    fn files_are_ordered_by_tier_then_documentation_then_path() {
        let files = [
            file("README.md", "r"),
            file("src/main.c", "m"),
            file("PKGBUILD", "p"),
            file("docs.txt", "d"),
        ];
        let plan = plan(&files, None, 4096, 8).unwrap();
        assert_eq!(plan.chunks.len(), 1);
        assert_eq!(
            paths(&plan.chunks[0]),
            ["PKGBUILD", "src/main.c", "docs.txt", "README.md"]
        );
        assert!(!plan.upgrade);
        assert!(plan.manifest.iter().all(|entry| entry.sent == Sent::Whole));
    }

    #[test]
    fn packing_fills_a_chunk_exactly_then_starts_the_next() {
        let files = [file("b.c", &"b".repeat(100)), file("c.c", &"c".repeat(100))];
        // Overhead: 2 × (3 + 32) = 70; each item costs 103.
        let one = plan(&files, None, 70 + 206, 8).unwrap();
        assert_eq!(one.chunks.len(), 1);
        let two = plan(&files, None, 70 + 205, 8).unwrap();
        assert_eq!(two.chunks.len(), 2);
    }

    #[test]
    fn a_large_file_is_split_on_line_boundaries() {
        // A line takes 100 bytes of the request: its newline is two there.
        let line = format!("{}\n", "x".repeat(98));
        let files = [file("big.c", &line.repeat(5))];
        // Overhead 5 + 32 = 37; capacity 205 leaves 200 bytes of text per piece.
        let plan = plan(&files, None, 37 + 205, 8).unwrap();
        let pieces: Vec<(usize, usize, usize)> = plan
            .chunks
            .iter()
            .flatten()
            .map(|item| match item {
                Item::Piece {
                    first_line,
                    last_line,
                    total_lines,
                    ..
                } => (*first_line, *last_line, *total_lines),
                Item::Whole { .. } | Item::Diff { .. } => panic!("expected pieces, got {item:?}"),
            })
            .collect();
        assert_eq!(pieces, [(1, 2, 5), (3, 4, 5), (5, 5, 5)]);
        assert_eq!(plan.chunks.len(), 3);

        assert_eq!(
            build(&PlanInput {
                files: &files,
                flagged: &BTreeSet::new(),
                findings_bytes: 0,
                previous: None,
                max_input_bytes: 37 + 205,
                max_chunks: 2,
                unit_prefixes: &[],
                hash_only: &[],
            }),
            Err(TooLarge::INPUT)
        );
    }

    #[test]
    fn a_piece_carries_the_tail_of_the_previous_piece() {
        // Lines of 10 bytes in the request; room 200 gives a 25-byte
        // context budget.
        let line = format!("{}\n", "z".repeat(8));
        let files = [file("big.c", &line.repeat(40))];
        let plan = plan(&files, None, 37 + 205, 8).unwrap();
        let pieces: Vec<_> = plan
            .chunks
            .iter()
            .flatten()
            .map(|item| match item {
                Item::Piece {
                    first_line,
                    context,
                    content,
                    ..
                } => (*first_line, context.clone(), content.len()),
                Item::Whole { .. } | Item::Diff { .. } => panic!("expected pieces, got {item:?}"),
            })
            .collect();
        assert_eq!(pieces[0], (1, None, 180));
        assert_eq!(pieces[1], (21, Some((19, line.repeat(2))), 162));
        assert!(plan.chunks.iter().flatten().all(|item| item.cost() <= 205));
    }

    #[test]
    fn an_entry_point_larger_than_a_chunk_is_too_large() {
        let line = format!("{}\n", "x".repeat(99));
        let files = [file("guardian.install", &line.repeat(5))];
        assert_eq!(
            plan(&files, None, 48 + 205, 8),
            Err(TooLarge {
                entry_point: Some("guardian.install".into())
            })
        );
        // A flagged file that is not an entry point is still split.
        let files = [file("lib/big.js", &line.repeat(5))];
        let flagged = BTreeSet::from(["lib/big.js".to_string()]);
        assert!(
            build(&PlanInput {
                files: &files,
                flagged: &flagged,
                findings_bytes: 0,
                previous: None,
                max_input_bytes: 42 + 205,
                max_chunks: 8,
                unit_prefixes: &[],
                hash_only: &[],
            })
            .is_ok()
        );
    }

    #[test]
    fn a_line_longer_than_a_chunk_is_cut() {
        let files = [file("min.js", &"y".repeat(450))];
        // Overhead 6 + 32 = 38; capacity 206 leaves 200 bytes per piece.
        let plan = plan(&files, None, 38 + 206, 8).unwrap();
        let sizes: Vec<(usize, usize)> = plan
            .chunks
            .iter()
            .flatten()
            .map(|item| match item {
                Item::Piece {
                    content,
                    first_line,
                    ..
                } => (content.len(), *first_line),
                Item::Whole { .. } | Item::Diff { .. } => panic!("expected pieces, got {item:?}"),
            })
            .collect();
        // Each part after the first repeats the last 25 bytes of the one
        // before: what straddles a cut is seen whole in one of them.
        assert_eq!(sizes, [(175, 1), (175, 1), (100, 1)]);
        let contexts: Vec<Option<usize>> = plan
            .chunks
            .iter()
            .flatten()
            .map(|item| match item {
                Item::Piece { context, .. } => context.as_ref().map(|(_, text)| text.len()),
                Item::Whole { .. } | Item::Diff { .. } => None,
            })
            .collect();
        assert_eq!(contexts, [None, Some(25), Some(25)]);
        assert!(plan.chunks.iter().flatten().all(|item| item.cost() <= 206));
    }

    #[test]
    fn a_small_changed_file_too_heavy_for_a_chunk_is_not_sent_whole() {
        // 600 control characters: small, but 3600 bytes in the request.
        let old = "\u{1}".repeat(600);
        let new = format!("{old}\nrun();\n");
        let previous: Previous = [("lib/blob.js".to_string(), old)].into_iter().collect();
        let files = [file("lib/blob.js", &new)];
        let plan = plan(&files, Some(&previous), 2 * (43 + 1000), 16).unwrap();
        // A diff or pieces of it, never the file as one item over the room.
        assert!(
            plan.chunks
                .iter()
                .flatten()
                .all(|item| !matches!(item, Item::Whole { .. })),
            "{:?}",
            plan.chunks
        );
    }

    #[test]
    fn a_file_is_budgeted_by_what_it_takes_in_the_request() {
        // Control characters are written as six bytes each.
        let files = [file("blob.js", &"\u{1}".repeat(100))];
        let plan = plan(&files, None, 39 + 207, 16).unwrap();
        assert!(plan.chunks.len() >= 3, "{}", plan.chunks.len());
        assert!(plan.chunks.iter().flatten().all(|item| item.cost() <= 207));
        assert_eq!(super::weight("a\"\n\u{1}é"), 1 + 2 + 2 + 6 + 2);
        // An invisible character is charged as the escape it is sent as,
        // so a file of them cannot outgrow its chunk.
        let hidden = "x\u{200b}\u{202e}\u{e0041}\u{7f}é\n";
        assert_eq!(
            super::weight(hidden),
            crate::json::Json::from(hidden).to_string().len() - 2
        );
        assert_eq!(super::weight("\u{200b}\u{e0041}"), 6 + 12);
        let tags = [file("tags.txt", &"\u{e0041}".repeat(100))];
        let tagged = build(&PlanInput {
            files: &tags,
            flagged: &BTreeSet::new(),
            findings_bytes: 0,
            previous: None,
            max_input_bytes: 40 + 207,
            max_chunks: 16,
            unit_prefixes: &[],
            hash_only: &[],
        })
        .unwrap();
        assert!(tagged.chunks.len() >= 6, "{}", tagged.chunks.len());
        assert!(
            tagged
                .chunks
                .iter()
                .flatten()
                .all(|item| item.cost() <= 207)
        );
    }

    #[test]
    fn a_manifest_larger_than_half_the_limit_is_too_large() {
        let files: Vec<SourceFile> = (0..200)
            .map(|index| file(&format!("f{index:03}.txt"), "x"))
            .collect();
        // 200 × (8 + 32) = 8000 bytes of manifest against a 10000-byte limit.
        assert_eq!(plan(&files, None, 10_000, 64), Err(TooLarge::INPUT));
    }

    #[test]
    fn upgrades_send_diffs_and_list_unchanged_and_removed_files() {
        use std::fmt::Write as _;

        // Past the size a changed file still goes whole at.
        let library = (1..=8000).fold(String::new(), |mut acc, line| {
            let _ = writeln!(acc, "int v{line} = {line};");
            acc
        });
        let previous: Previous = [
            ("PKGBUILD".to_string(), "pkgver=1\n".to_string()),
            ("src/a.c".to_string(), "same\n".to_string()),
            ("src/b.c".to_string(), library.clone()),
            ("src/small.c".to_string(), "if (0) run();\n".to_string()),
            ("gone.c".to_string(), "old\n".to_string()),
        ]
        .into_iter()
        .collect();
        let files = [
            file("PKGBUILD", "pkgver=2\n"),
            file("src/a.c", "same\n"),
            file("src/b.c", &library.replace("v10 = 10", "v10 = 11")),
            file("src/small.c", "if (1) run();\n"),
            file("new.c", "fresh\n"),
        ];

        let plan = plan(&files, Some(&previous), 256 * 1024, 8).unwrap();

        assert!(plan.upgrade);
        let manifest: Vec<(&str, Sent)> = plan
            .manifest
            .iter()
            .map(|entry| (entry.path.as_str(), entry.sent))
            .collect();
        assert_eq!(
            manifest,
            [
                ("PKGBUILD", Sent::Whole),
                ("new.c", Sent::Whole),
                ("src/a.c", Sent::Unchanged),
                ("src/b.c", Sent::Diff),
                // A small changed file goes whole: what the change
                // switches on may be anywhere in it.
                ("src/small.c", Sent::Whole),
                ("gone.c", Sent::Removed),
            ]
        );
        let diff = plan
            .chunks
            .iter()
            .flatten()
            .find_map(|item| match item {
                Item::Diff { path, diff } if path == "src/b.c" => Some(diff),
                _ => None,
            })
            .unwrap();
        assert!(diff.contains("-int v10 = 10;\n+int v10 = 11;\n"));
        // Twenty lines either side of the change.
        assert!(diff.contains("int v30 = 30;") && !diff.contains("int v31 = 31;"));
    }

    #[test]
    fn entry_points_and_flagged_files_are_sent_whole_even_when_unchanged() {
        let previous: Previous = [
            ("PKGBUILD".to_string(), "pkgver=1\n".to_string()),
            ("src/a.c".to_string(), "same\n".to_string()),
        ]
        .into_iter()
        .collect();
        let files = [file("PKGBUILD", "pkgver=1\n"), file("src/a.c", "same\n")];
        let flagged: BTreeSet<String> = ["src/a.c".to_string()].into_iter().collect();

        let plan = build(&PlanInput {
            files: &files,
            flagged: &flagged,
            findings_bytes: 0,
            previous: Some(&previous),
            max_input_bytes: 64 * 1024,
            max_chunks: 8,
            unit_prefixes: &[],
            hash_only: &[],
        })
        .unwrap();

        assert!(plan.manifest.iter().all(|entry| entry.sent == Sent::Whole));
        assert_eq!(paths(&plan.chunks[0]), ["PKGBUILD", "src/a.c"]);
    }

    #[test]
    fn sent_variant_names_are_correct() {
        assert_eq!(
            [Sent::Whole, Sent::Diff, Sent::Unchanged, Sent::Removed].map(Sent::name),
            ["whole", "diff", "unchanged", "removed"]
        );
    }

    #[test]
    fn hash_only_files_are_named_and_media_grouped_per_directory() {
        let file = |path: &str, label: &'static str, media: bool| super::HashOnly {
            path: path.into(),
            bytes: 100,
            label,
            media,
            skipped_files: None,
        };
        let none = std::collections::HashSet::new();
        let entries = super::hash_only_entries(
            &[
                file("bin/tool", "ELF executable", false),
                file("backgrounds/a.jpg", "JPEG image", true),
                file("backgrounds/b.png", "PNG image", true),
            ],
            &none,
        );
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, "bin/tool");
        assert_eq!(entries[0].format.as_deref(), Some("ELF executable"));
        assert_eq!(entries[1].path, "backgrounds/");
        assert_eq!(entries[1].files, Some(2));
        assert_eq!(entries[1].format.as_deref(), Some("JPEG image, PNG image"));

        let many: Vec<super::HashOnly> = (0..500)
            .map(|index| file(&format!("icons/{index}/a.png"), "PNG image", true))
            .collect();
        let entries = super::hash_only_entries(&many, &none);
        assert_eq!(entries.len(), 64);
        assert_eq!(entries.last().unwrap().files, Some(437));

        // Past the limit, a file a reviewed text names keeps its row.
        let mut binaries: Vec<super::HashOnly> = (0..200)
            .map(|index| file(&format!("lib/p{index}.so"), "ELF shared object", false))
            .collect();
        binaries.push(file("lib/loaded.so", "ELF shared object", false));
        let named = std::collections::HashSet::from(["loaded.so"]);
        let entries = super::hash_only_entries(&binaries, &named);
        assert_eq!(entries.len(), 64);
        assert_eq!(entries[0].path, "lib/loaded.so");
        assert!(
            !super::hash_only_entries(&binaries, &none)
                .iter()
                .any(|entry| entry.path == "lib/loaded.so")
        );
    }
}
