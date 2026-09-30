//! Turns the files queued for the AI review into chunked requests: rank by
//! risk, choose what each file is sent as on an upgrade, and pack.

use std::collections::{BTreeMap, BTreeSet};
use std::mem;

use crate::agent::SourceFile;
use crate::engine::diff;
use crate::rules;

/// Unchanged lines shown around each change in an upgrade diff.
const DIFF_CONTEXT: usize = 3;

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
            Self::Whole { path, content } | Self::Piece { path, content, .. } => {
                path.len() + content.len()
            }
            Self::Diff { path, diff } => path.len() + diff.len(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sent {
    Whole,
    Diff,
    Unchanged,
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

/// Manifest rows for hash-only files: one per file, except media, which get
/// one row per directory.
pub fn hash_only_entries(files: &[HashOnly]) -> Vec<ManifestEntry> {
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
/// findings every request repeats leave too little room for source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TooLarge;

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
    Diff(String),
    Unchanged,
}

pub fn build(input: &PlanInput<'_>) -> Result<Plan, TooLarge> {
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

    let current: BTreeSet<&str> = input.files.iter().map(|file| file.path.as_str()).collect();
    let removed: Vec<(&String, &String)> = input
        .previous
        .into_iter()
        .flatten()
        .filter(|(path, _)| !current.contains(path.as_str()))
        .collect();

    let hash_only = hash_only_entries(input.hash_only);
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
        return Err(TooLarge);
    }
    let capacity = input.max_input_bytes - overhead;

    let mut manifest = Vec::with_capacity(ranked.len() + removed.len());
    let mut items = Vec::new();
    for (tier, _, file) in ranked {
        let sent = match choose(file, tier == 0, input.previous, capacity) {
            Choice::Whole => {
                items.push(Item::Whole {
                    path: file.path.clone(),
                    content: file.content.clone(),
                });
                Sent::Whole
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
        return Err(TooLarge);
    }
    Ok(Plan {
        chunks,
        manifest,
        upgrade: input.previous.is_some(),
    })
}

/// What an upgrade sends for one file. Entry points always go whole; a diff
/// is used only when it is smaller than the file and fits one chunk.
fn choose(
    file: &SourceFile,
    entry_point: bool,
    previous: Option<&Previous>,
    capacity: usize,
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
    match diff::unified(old, &file.content, DIFF_CONTEXT) {
        Some(diff)
            if diff.len() < file.content.len() && file.path.len() + diff.len() <= capacity =>
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
        return Err(TooLarge);
    };
    let room = capacity
        .checked_sub(path.len())
        .filter(|room| *room >= MIN_PIECE)
        .ok_or(TooLarge)?;

    let lines: Vec<&str> = content.split_inclusive('\n').collect();
    let total_lines = lines.len();
    let piece = |text: String, first_line: usize, last_line: usize| Item::Piece {
        path: path.clone(),
        content: text,
        first_line,
        last_line,
        total_lines,
    };

    let mut pieces = Vec::new();
    let mut text = String::new();
    let mut first_line = 1;
    for (index, line) in lines.iter().enumerate() {
        let number = index + 1;
        if !text.is_empty() && text.len() + line.len() > room {
            pieces.push(piece(mem::take(&mut text), first_line, number - 1));
            first_line = number;
        }
        if line.len() > room {
            for part in cut(line, room) {
                pieces.push(piece(part.to_string(), number, number));
            }
            first_line = number + 1;
            continue;
        }
        text.push_str(line);
    }
    if !text.is_empty() {
        pieces.push(piece(text, first_line, total_lines));
    }
    Ok(pieces)
}

/// Cuts `line` into parts of at most `room` bytes at character boundaries.
/// `room` is at least `MIN_PIECE`, so every part holds one character.
fn cut(line: &str, room: usize) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut rest = line;
    while rest.len() > room {
        let mut end = room;
        while !rest.is_char_boundary(end) {
            end -= 1;
        }
        let (head, tail) = rest.split_at(end);
        parts.push(head);
        rest = tail;
    }
    if !rest.is_empty() {
        parts.push(rest);
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
        let line = format!("{}\n", "x".repeat(99));
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
            Err(TooLarge)
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
        assert_eq!(sizes, [(200, 1), (200, 1), (50, 1)]);
    }

    #[test]
    fn a_manifest_larger_than_half_the_limit_is_too_large() {
        let files: Vec<SourceFile> = (0..200)
            .map(|index| file(&format!("f{index:03}.txt"), "x"))
            .collect();
        // 200 × (8 + 32) = 8000 bytes of manifest against a 10000-byte limit.
        assert_eq!(plan(&files, None, 10_000, 64), Err(TooLarge));
    }

    #[test]
    fn upgrades_send_diffs_and_list_unchanged_and_removed_files() {
        use std::fmt::Write as _;

        let library = (1..=20).fold(String::new(), |mut acc, line| {
            let _ = writeln!(acc, "int v{line} = {line};");
            acc
        });
        let previous: Previous = [
            ("PKGBUILD".to_string(), "pkgver=1\n".to_string()),
            ("src/a.c".to_string(), "same\n".to_string()),
            ("src/b.c".to_string(), library.clone()),
            ("gone.c".to_string(), "old\n".to_string()),
        ]
        .into_iter()
        .collect();
        let files = [
            file("PKGBUILD", "pkgver=2\n"),
            file("src/a.c", "same\n"),
            file("src/b.c", &library.replace("v10 = 10", "v10 = 11")),
            file("new.c", "fresh\n"),
        ];

        let plan = plan(&files, Some(&previous), 64 * 1024, 8).unwrap();

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
                ("gone.c", Sent::Removed),
            ]
        );
        assert_eq!(paths(&plan.chunks[0]), ["PKGBUILD", "new.c", "src/b.c"]);
        assert!(
            matches!(&plan.chunks[0][2], Item::Diff { diff, .. } if diff.contains("-int v10 = 10;\n+int v10 = 11;\n"))
        );
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
        let entries = super::hash_only_entries(&[
            file("bin/tool", "ELF executable", false),
            file("backgrounds/a.jpg", "JPEG image", true),
            file("backgrounds/b.png", "PNG image", true),
        ]);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, "bin/tool");
        assert_eq!(entries[0].format.as_deref(), Some("ELF executable"));
        assert_eq!(entries[1].path, "backgrounds/");
        assert_eq!(entries[1].files, Some(2));
        assert_eq!(entries[1].format.as_deref(), Some("JPEG image, PNG image"));

        let many: Vec<super::HashOnly> = (0..500)
            .map(|index| file(&format!("icons/{index}/a.png"), "PNG image", true))
            .collect();
        let entries = super::hash_only_entries(&many);
        assert_eq!(entries.len(), 64);
        assert_eq!(entries.last().unwrap().files, Some(437));
    }
}
