//! Tests for `plan`.

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
    let body = |seed: &str, lines: usize| format!("// {seed}\n{}", "int v = 1;\n".repeat(lines));
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
