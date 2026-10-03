//! Turns the files queued for the AI review into chunked requests: rank by
//! risk, choose what each file is sent as on an upgrade, and pack.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::mem;

use crate::agent::SourceFile;
use crate::engine::diff;
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
/// control character is written as six, so a file of them is six times its
/// size there.
fn weight(text: &str) -> usize {
    text.chars().map(char_weight).sum()
}

fn char_weight(character: char) -> usize {
    match character {
        '"' | '\\' | '\n' | '\r' | '\t' => 2,
        control if u32::from(control) < 0x20 => 6,
        other => other.len_utf8(),
    }
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

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// A file name without its extension, as code names a module (`import
/// helper` for `helper.py`).
fn stem(name: &str) -> Option<&str> {
    name.rsplit_once('.')
        .map(|(stem, _)| stem)
        .filter(|stem| !stem.is_empty())
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
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
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
    if let Some(previous) = input.previous.filter(|_| extras) {
        send_what_a_change_names(&ranked, &mut choices, previous, capacity);
    }

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

    let chunks = pack(items, capacity)?;
    if chunks.len() > input.max_chunks {
        return Err(TooLarge::INPUT);
    }
    Ok(Plan {
        chunks,
        manifest,
        upgrade: input.previous.is_some(),
    })
}

/// On an upgrade, turns the unchanged files a changed one names into
/// whole ones, code first, while they fit `NAMED_SHARE` of a request: a
/// change that only switches on what another file already held is then
/// seen with that file.
fn send_what_a_change_names(
    ranked: &[(u8, bool, &SourceFile)],
    choices: &mut [Choice],
    previous: &Previous,
    capacity: usize,
) {
    let names: HashSet<&str> = ranked
        .iter()
        .zip(choices.iter())
        .filter(|((tier, documentation, _), choice)| {
            matches!(choice, Choice::Unchanged) && *tier <= 1 && !documentation
        })
        .flat_map(|((_, _, file), _)| {
            let name = file_name(&file.path);
            [Some(name), stem(name)]
        })
        .flatten()
        .filter(|name| name.len() >= MIN_NAMED)
        .collect();
    let named = named_in(
        &names,
        // The files that are new or changed: an entry point sent whole
        // as it was names nothing new.
        &mut ranked
            .iter()
            .filter(|(_, _, file)| previous.get(&file.path) != Some(&file.content))
            .map(|(_, _, file)| file.content.as_str()),
    );
    let mut room = capacity / NAMED_SHARE;
    for ((_, _, file), choice) in ranked.iter().zip(choices.iter_mut()) {
        let name = file_name(&file.path);
        if !matches!(choice, Choice::Unchanged)
            || !(named.contains(name) || stem(name).is_some_and(|stem| named.contains(stem)))
        {
            continue;
        }
        let cost = file.path.len() + weight(&file.content);
        if cost <= room {
            room -= cost;
            *choice = Choice::Named;
        }
    }
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

/// Packs items in order, starting a new chunk when the next one does not fit.
fn pack(items: Vec<Item>, capacity: usize) -> Result<Vec<Vec<Item>>, TooLarge> {
    let mut chunks = Vec::new();
    let mut current: Vec<Item> = Vec::new();
    let mut used = 0;
    for item in items {
        for piece in split(item, capacity)? {
            let cost = piece.cost();
            if used + cost > capacity && !current.is_empty() {
                chunks.push(mem::take(&mut current));
                used = 0;
            }
            used += cost;
            current.push(piece);
        }
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    Ok(chunks)
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
