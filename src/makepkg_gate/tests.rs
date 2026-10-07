//! Tests for the makepkg gate.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use std::fs;
use std::process::Command;

use super::{
    Asker, Blocked, Configured, Confirm, Decision, Followed, Functions, Prebuilt, State, Upstream,
    UpstreamReview, UpstreamStep, all_binaries, aur, binary_changes, confirm_not_followed,
    confirm_prebuilt, download_names, fetch_recipe, followed, foreign_checkout,
    hold_against_extraction, is_jailable, is_plain_mirror, listing_recipe, listing_report,
    mirrored_arguments, misnamed_source, only_downloads, parse, permittable, prebuilt,
    public_keyring, recipe_functions, record_extraction, source_context, state, tools, unpack,
    unreviewable_sources, upstream_facts, upstream_runs, upstream_summary, with_mounts,
};
use crate::test_support::TempDir;

fn args(list: &[&str]) -> Vec<OsString> {
    list.iter().map(OsString::from).collect()
}

#[test]
fn a_recipe_permit_outlasts_the_downloads_makepkg_adds() {
    use super::{recipe_contents, recipe_target, written_downloads};
    let dir = TempDir::new("gate-recipe-content");
    let recipe = "pkgname=demo\nsource=(https://example.org/demo-1.tar.gz fix.patch)\nsha256sums=(SKIP SKIP)\nbuild() { :; }\n";
    fs::write(dir.path().join("PKGBUILD"), recipe).unwrap();
    fs::write(dir.path().join("fix.patch"), "--- a\n+++ b\n").unwrap();
    assert_eq!(written_downloads(recipe), ["demo-1.tar.gz"]);
    let target = recipe_target(dir.path(), "demo", true);
    let keys = || -> Vec<String> {
        let (snapshot, _) = crate::scan::walk(&target.config, &mut |_| {});
        recipe_contents(&target, &snapshot, recipe)
            .iter()
            .map(crate::permit::Content::key)
            .collect()
    };
    // Before anything is downloaded the recipe has one name.
    let before = keys();
    assert_eq!(before.len(), 1);

    // makepkg downloads into the build directory: the directory as it
    // is has another name, the recipe without its downloads the same.
    fs::write(dir.path().join("demo-1.tar.gz"), [0x1f, 0x8b, 0, 1, 2]).unwrap();
    fs::write(dir.path().join("demo-1.tar.gz.part"), [0x1f, 0x8b]).unwrap();
    let after = keys();
    assert_eq!(after.len(), 2);
    assert_ne!(after[0], before[0]);
    assert_eq!(after[1], before[0]);

    // A recipe file that changed is another recipe by every name.
    fs::write(dir.path().join("fix.patch"), "--- a\n+++ c\n").unwrap();
    assert!(keys().iter().all(|key| !after.contains(key)));
    // So is one that became executable.
    fs::write(dir.path().join("fix.patch"), "--- a\n+++ b\n").unwrap();
    assert_eq!(keys(), after);
    let mode = std::os::unix::fs::PermissionsExt::from_mode(0o755);
    fs::set_permissions(dir.path().join("fix.patch"), mode).unwrap();
    assert!(keys().iter().all(|key| !after.contains(key)));
}

#[test]
fn upstream_sources_are_named_by_their_downloads_or_by_every_file() {
    use super::upstream_content;
    let fixture = Fixture::new("gate-upstream-content", "pkgname=demo\nbuild() { :; }\n");
    let step = fixture.step();
    let hash = |character: &str| character.repeat(64);
    let mut upstream = Upstream::default();
    upstream.downloads.insert("demo.tar.gz".into(), hash("a"));
    upstream.seen.insert("src/demo.tar.gz".into(), hash("a"));
    upstream.seen.insert("src/demo/main.c".into(), hash("b"));
    let tarball = sources(&["https://example.org/demo.tar.gz"]);
    let key = |step: &UpstreamStep<'_>, upstream: &Upstream, listed: &[aur::Source]| {
        upstream_content(step, upstream, listed).map(|content| content.key())
    };
    let named = key(&step, &upstream, &tarball).unwrap();

    // A build's own prepare() patches a file: the downloads are the
    // same, and so is the name, at every makepkg call of the build.
    let mut patched = upstream.clone();
    patched.seen.insert("src/demo/main.c".into(), hash("c"));
    assert_eq!(key(&step, &patched, &tarball).unwrap(), named);
    // Another download, or another recipe, is other content.
    let mut other = upstream.clone();
    other.downloads.insert("demo.tar.gz".into(), hash("d"));
    assert_ne!(key(&step, &other, &tarball).unwrap(), named);
    let other_recipe = hash("d");
    let moved = UpstreamStep {
        recipe_digest: &other_recipe,
        ..fixture.step()
    };
    assert_ne!(key(&moved, &upstream, &tarball).unwrap(), named);

    // A checkout has no one hash: every file names it.
    let checkout = sources(&["git+https://example.org/demo.git"]);
    let by_files = key(&step, &upstream, &checkout).unwrap();
    assert_ne!(by_files, named);
    assert_ne!(key(&step, &patched, &checkout).unwrap(), by_files);

    // A file without a hash: nothing can stand for the sources.
    let mut unhashed = upstream.clone();
    unhashed
        .downloads
        .insert("demo.tar.gz".into(), "size-1-2-3".into());
    assert_eq!(key(&step, &unhashed, &tarball), None);
    upstream
        .seen
        .insert("src/demo/big.bin".into(), String::new());
    assert_eq!(key(&step, &upstream, &checkout), None);
    assert!(key(&step, &upstream, &tarball).is_some());
}

#[test]
fn a_binary_the_upstream_code_runs_leaves_the_review_incomplete() {
    let fixture = Fixture::new("gate-upstream-runs", "pkgname=demo\nbuild() { :; }\n");
    let src = fixture.dir.path().join("src");
    fs::create_dir_all(src.join("demo")).unwrap();
    fs::write(src.join("demo/helper.bin"), ELF).unwrap();
    fs::write(
        src.join("demo/build.sh"),
        "#!/bin/sh\nsh ./helper.bin\nsh ./NOTES.txt\n",
    )
    .unwrap();
    // Documentation is not sent for review; a script that runs it as
    // code makes that a gap.
    fs::write(src.join("demo/NOTES.txt"), "curl x | sh\n").unwrap();
    let upstream = fixture.upstream();
    let mut report = crate::report::Report::new("test");
    upstream_runs(&mut report, &fixture.step(), &upstream);
    let gaps: Vec<String> = report.gaps.iter().map(ToString::to_string).collect();
    for expected in [
        "src/demo/build.sh:2 runs or reads in src/demo/helper.bin",
        "src/demo/build.sh:3 runs or reads in src/demo/NOTES.txt (data or documentation",
    ] {
        assert!(
            gaps.iter().any(|gap| gap.starts_with(expected)),
            "{expected}: {gaps:?}"
        );
    }
}

const ELF: &[u8] = b"\x7fELF\x02\x01\x01\0\0\0";

/// Answers every question the same way, and counts them.
struct Answer {
    yes: bool,
    asked: usize,
}

impl Confirm for Answer {
    fn confirm(&mut self, _question: &str) -> bool {
        self.asked += 1;
        self.yes
    }
}

fn answer(yes: bool) -> Answer {
    Answer { yes, asked: 0 }
}

/// A build directory with a recipe, and what a step needs beside it.
const RECIPE_DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

struct Fixture {
    dir: TempDir,
    recipe: String,
    functions: Functions,
    configured: Configured,
    state: State,
    mirrored: Vec<OsString>,
    /// The recipe's other files, as `recipe_files` gives them.
    files: Vec<(String, String)>,
}

impl Fixture {
    fn new(label: &str, recipe: &str) -> Self {
        let dir = TempDir::new(label);
        fs::write(dir.path().join("PKGBUILD"), recipe).unwrap();
        Self {
            functions: recipe_functions(dir.path(), recipe),
            state: State::open(Some(&dir.path().join("state")), "demo"),
            recipe: recipe.to_string(),
            configured: Configured::default(),
            mirrored: args(&["-C"]),
            files: Vec::new(),
            dir,
        }
    }

    fn step(&self) -> UpstreamStep<'_> {
        UpstreamStep {
            makepkg: Path::new("/usr/bin/makepkg"),
            mirrored: &self.mirrored,
            build_dir: self.dir.path(),
            name: "demo",
            key: "demo",
            base: None,
            recipe: &self.recipe,
            recipe_digest: RECIPE_DIGEST,
            recipe_files: &self.files,
            functions: &self.functions,
            extract: false,
            uses_sources: true,
            configured: &self.configured,
            state: &self.state,
        }
    }

    fn roots(&self) -> aur::Roots<'_> {
        // As with makepkg's defaults: downloads beside the recipe.
        aur::Roots {
            build_dir: self.dir.path(),
            srcdest: Some(self.dir.path()),
        }
    }

    fn collected(&self) -> aur::Collected {
        let src = self.dir.path().join("src");
        aur::walk_upstream(&src, &self.roots(), &self.functions.written, &[])
    }

    fn upstream(&self) -> Upstream {
        self.collected().select(1024 * 1024)
    }
}

fn sources(entries: &[&str]) -> Vec<aur::Source> {
    entries
        .iter()
        .map(|entry| aur::Source {
            entry: (*entry).to_string(),
            checksums: vec!["abc".into()],
        })
        .collect()
}

#[test]
fn what_the_recipe_runs_is_followed_into_the_sources() {
    let recipe = "pkgname=demo\n_tool=helper\nbuild() {\n  cd demo\n  ./$_tool --generate\n  sh \"$srcdir/demo/go\"\n}\n";
    let fixture = Fixture::new("gate-recipe-runs", recipe);
    fs::write(
        fixture.dir.path().join("demo.install"),
        "post_install() {\n  /opt/demo/setup\n}\n",
    )
    .unwrap();
    let fixture = Fixture {
        functions: recipe_functions(fixture.dir.path(), recipe),
        ..fixture
    };
    let src = fixture.dir.path().join("src");
    fs::create_dir_all(src.join("demo/opt/demo")).unwrap();
    fs::write(src.join("demo/helper"), ELF).unwrap();
    fs::write(src.join("demo/opt/demo/setup"), ELF).unwrap();
    fs::write(src.join("demo/unused"), ELF).unwrap();
    let mut upstream = fixture.upstream();
    // A file left out past the budget that the recipe runs.
    upstream
        .unreviewed
        .push(("src/demo/go".into(), aur::NOT_REVIEWED_BUDGET));
    let mut report = crate::report::Report::new("test");
    upstream_runs(&mut report, &fixture.step(), &upstream);
    let gaps: Vec<String> = report.gaps.iter().map(ToString::to_string).collect();
    assert_eq!(gaps.len(), 1, "{gaps:?}");
    assert!(
        gaps[0].starts_with(
            "PKGBUILD:6 runs or reads in src/demo/go (left out past the review budget)"
        ),
        "{gaps:?}"
    );
    // The programs it runs are asked about, the one it does not is
    // not: the recipe builds, so a binary beside the code is no
    // package of its own.
    let found = prebuilt(&fixture.step(), &upstream, &sources(&["demo.tar.gz"]));
    assert_eq!(found.run, ["src/demo/helper", "src/demo/opt/demo/setup"]);
    assert_eq!(found.programs.len(), 2, "{found:?}");
    assert!(found.statement().contains(
        "installs 2 prebuilt program(s) nobody reviewed, that came with its sources; its recipe runs 2 of them"
    ));
}

#[test]
fn a_package_of_prebuilt_programs_needs_a_yes_that_is_remembered() {
    let recipe = "pkgname=demo-bin\npackage() {\n  cp -r opt \"$pkgdir\"\n}\n";
    let fixture = Fixture::new("gate-prebuilt", recipe);
    let src = fixture.dir.path().join("src");
    fs::create_dir_all(src.join("opt/demo")).unwrap();
    fs::write(src.join("opt/demo/demo"), ELF).unwrap();
    let listed = sources(&[
        "https://downloads.example.org/demo-1.0.tar.gz",
        "git+https://github.com/x/y.git",
        "demo.desktop",
    ]);
    let step = fixture.step();
    let upstream = fixture.upstream();
    let found = prebuilt(&step, &upstream, &listed);
    assert_eq!(
        found.statement(),
        "this package installs 1 prebuilt program(s) nobody reviewed, downloaded from downloads.example.org, github.com"
    );

    // No, or no terminal to say yes on: the build does not go on.
    let mut no = answer(false);
    assert!(!confirm_prebuilt(&step, &found, &mut no));
    assert_eq!(no.asked, 1);
    // A yes is remembered: yay's next makepkg call, and a rebuild of
    // the same version, do not ask again.
    let mut yes = answer(true);
    assert!(confirm_prebuilt(&step, &found, &mut yes));
    let mut silent = answer(false);
    assert!(confirm_prebuilt(&fixture.step(), &found, &mut silent));
    assert_eq!((yes.asked, silent.asked), (1, 0));

    // Other bytes, or another host, are another question.
    fs::write(src.join("opt/demo/demo"), b"\x7fELF\x02\x01\x01\0\0\x01").unwrap();
    let changed = prebuilt(&step, &fixture.upstream(), &listed);
    assert!(!confirm_prebuilt(&step, &changed, &mut no));
    let moved = prebuilt(
        &step,
        &upstream,
        &sources(&["https://evil.example/demo.tar.gz"]),
    );
    assert!(!confirm_prebuilt(&step, &moved, &mut no));
    assert_eq!(no.asked, 3);

    // A program that could not be hashed is asked about every time.
    let mut unhashed = prebuilt(&step, &upstream, &listed);
    unhashed.programs.insert("src/huge".into(), String::new());
    assert!(confirm_prebuilt(&step, &unhashed, &mut yes));
    assert!(!confirm_prebuilt(&step, &unhashed, &mut no));

    // A recipe that builds, with a binary among its test data, is not
    // asked about.
    let building = Fixture::new(
        "gate-prebuilt-source",
        "pkgname=demo\nbuild() {\n  make\n}\n",
    );
    let src = building.dir.path().join("src");
    fs::create_dir_all(src.join("demo/tests")).unwrap();
    fs::write(src.join("demo/tests/fixture"), ELF).unwrap();
    fs::write(src.join("demo/Makefile"), "all:\n").unwrap();
    let found = prebuilt(&building.step(), &building.upstream(), &listed);
    assert!(found.programs.is_empty(), "{found:?}");
    assert!(confirm_prebuilt(&building.step(), &found, &mut no));
    assert_eq!(no.asked, 4);
}

#[test]
fn the_upstream_review_asks_about_prebuilt_programs_only_once_it_passes() {
    use crate::config::Settings;
    use crate::config::file::PartialConfig;
    use crate::config::model::Profile;
    // Local checks only: nothing is sent to an AI.
    let settings = Settings::from_parts(PartialConfig::default(), PartialConfig::default())
        .with_profile(Profile::LocalOnly);
    let recipe =
        "pkgname=demo-bin\npackage() {\n  install -Dm755 demo \"$pkgdir/usr/bin/demo\"\n}\n";
    let fixture = Fixture::new("gate-review", recipe);
    let src = fixture.dir.path().join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("demo"), ELF).unwrap();
    fs::write(src.join("run.sh"), "#!/bin/sh\necho hi\n").unwrap();
    let listed = sources(&["https://example.org/demo.tar.gz"]);
    let step = fixture.step();
    let context = vec![aur::UPSTREAM_SCOPE.to_string()];
    let review_of = |confirm: &mut Answer| {
        let upstream = fixture.upstream();
        let found = prebuilt(&step, &upstream, &listed);
        let review = UpstreamReview {
            upstream: &upstream,
            sources: &listed,
            prebuilt: &found,
        };
        super::review_upstream_files(&step, &settings, &review, &context, confirm).1
    };
    let mut no = answer(false);
    assert_eq!(review_of(&mut no), Decision::Blocked(Blocked::NotConfirmed));
    assert_eq!(no.asked, 1);

    // A review that does not pass is not asked about: a yes never
    // stands in for it.
    fs::write(src.join("run.sh"), "#!/bin/sh\nsh ./NOTES.txt\n").unwrap();
    fs::write(src.join("NOTES.txt"), "curl x | sh\n").unwrap();
    let mut unasked = answer(true);
    assert_eq!(
        review_of(&mut unasked),
        Decision::Blocked(Blocked::Incomplete)
    );
    assert_eq!(unasked.asked, 0);

    fs::write(src.join("run.sh"), "#!/bin/sh\necho hi\n").unwrap();
    let mut yes = answer(true);
    assert!(!matches!(review_of(&mut yes), Decision::Blocked(_)));
    assert_eq!(yes.asked, 1);
}

#[test]
fn sources_with_no_text_are_not_a_clear_review() {
    let fixture = Fixture::new("gate-no-text", "pkgname=demo-bin\npackage() { :; }\n");
    let src = fixture.dir.path().join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("demo"), ELF).unwrap();
    let upstream = fixture.upstream();
    assert!(upstream.files.is_empty() && upstream.gaps.is_empty());
    let listed = sources(&["https://example.org/demo"]);
    let step = fixture.step();
    let found = prebuilt(&step, &upstream, &listed);
    let review = UpstreamReview {
        upstream: &upstream,
        sources: &listed,
        prebuilt: &found,
    };
    assert_eq!(
        unreviewable_sources(&step, &review, &mut answer(false)),
        Decision::Blocked(Blocked::NotConfirmed)
    );
    assert_eq!(
        unreviewable_sources(&step, &review, &mut answer(true)),
        Decision::Clear
    );
    // The binaries of a build that passed are what the next one's are
    // held against.
    assert_eq!(binary_changes(&step, &upstream), None);
    fixture
        .state
        .record_binaries(&all_binaries(&upstream))
        .unwrap();
    assert_eq!(binary_changes(&step, &upstream), None);
    fs::write(src.join("demo"), b"\x7fELF\x02\x01\x01\0\0\x02").unwrap();
    fs::write(src.join("extra"), ELF).unwrap();
    let fact = binary_changes(&step, &fixture.upstream()).unwrap();
    assert!(
        fact.contains("2 are new or changed and 0 are gone"),
        "{fact}"
    );
}

#[test]
fn a_recipe_is_held_to_what_it_writes_or_asked_about() {
    let listing =
        "pkgbase = demo\n\tpkgver = 1\n\tsource = a.tar\n\tsha256sums = abc\n\npkgname = demo\n";
    assert_eq!(
        followed("pkgname=demo\nsource=(a.tar)\nsha256sums=(abc)\n", listing),
        Followed::Yes
    );
    // The listing was told something else than the text says.
    assert_eq!(
        followed("pkgname=demo\nsource=(b.tar)\nsha256sums=(abc)\n", listing),
        Followed::Differs("source".into())
    );
    assert_eq!(
        followed("pkgname=demo\nsha256sums=(abc)\n", listing),
        Followed::Differs("source".into())
    );
    assert_eq!(
        followed("pkgver=1.2\nsource=(\"a-${pkgver%.*}.tar\")\n", listing),
        Followed::Yes
    );
    let hidden = "pkgname=demo\n[[ -w . ]] && source=(evil.tar)\n";
    let Followed::No(reasons) = followed(hidden, listing) else {
        panic!("followed");
    };
    assert!(reasons[0].starts_with("line 2: source is set under a condition"));

    let fixture = Fixture::new("gate-not-followed", hidden);
    let mut no = answer(false);
    assert!(!confirm_not_followed(
        &fixture.step(),
        &reasons,
        &[],
        &mut no
    ));
    let mut yes = answer(true);
    assert!(confirm_not_followed(
        &fixture.step(),
        &reasons,
        &[],
        &mut yes
    ));
    // The same recipe is not asked about again; a changed one is.
    assert!(confirm_not_followed(
        &fixture.step(),
        &reasons,
        &[],
        &mut no
    ));
    assert_eq!((no.asked, yes.asked), (1, 1));
    let other = Fixture {
        recipe: format!("{hidden}# changed\n"),
        ..fixture
    };
    assert!(!confirm_not_followed(&other.step(), &reasons, &[], &mut no));
    assert_eq!(no.asked, 2);
}

#[test]
fn a_yes_to_sources_not_followed_covers_every_file_the_recipe_reads() {
    let recipe =
        "pkgname=demo-git\npkgver=r1.abc\npkgrel=1\n. ./sources.inc\npkgver() { echo r2; }\n";
    let reasons = ["line 4: `.` runs or reads in code".to_string()];
    let state = |hash: &str| format!("{hash} 0");
    let fixture = Fixture {
        files: vec![("sources.inc".into(), state("aa"))],
        ..Fixture::new("gate-sources-asked", recipe)
    };
    let mut yes = answer(true);
    let mut no = answer(false);
    assert!(confirm_not_followed(
        &fixture.step(),
        &reasons,
        &[],
        &mut yes
    ));
    assert!(confirm_not_followed(
        &fixture.step(),
        &reasons,
        &[],
        &mut no
    ));
    assert_eq!((yes.asked, no.asked), (1, 0));

    // makepkg rewrote the version between two calls of one install,
    // and downloaded a source beside the recipe: the same question.
    let downloaded = Fixture {
        recipe: recipe.replace("pkgver=r1.abc", "pkgver=r2.def"),
        files: vec![
            ("demo.tar.gz".into(), state("cc")),
            ("demo.tar.gz.part".into(), state("dd")),
            ("sources.inc".into(), state("aa")),
        ],
        ..fixture
    };
    let downloads = ["demo.tar.gz".to_string()];
    assert!(confirm_not_followed(
        &downloaded.step(),
        &reasons,
        &downloads,
        &mut no
    ));
    assert_eq!(no.asked, 0);

    // The file the sources come from changed: asked again. So is a
    // version that is no plain value, and any other line.
    let changed = Fixture {
        files: vec![("sources.inc".into(), state("bb"))],
        ..downloaded
    };
    assert!(!confirm_not_followed(
        &changed.step(),
        &reasons,
        &[],
        &mut no
    ));
    for other in [
        recipe.replace("pkgver=r1.abc", "pkgver=$(curl x)"),
        recipe.replace("pkgver=r1.abc", "pkgver=1; source=(evil)"),
        recipe.replace("pkgrel=1", " pkgrel=2"),
        recipe.replace("pkgname=demo-git", "pkgname=other-git"),
    ] {
        let other = Fixture {
            recipe: other,
            files: vec![("sources.inc".into(), state("aa"))],
            ..Fixture::new("gate-sources-asked-other", recipe)
        };
        let other = Fixture {
            state: State::open(Some(&changed.dir.path().join("state")), "demo"),
            ..other
        };
        assert!(
            !confirm_not_followed(&other.step(), &reasons, &[], &mut no),
            "{}",
            other.recipe
        );
    }
}

#[test]
fn a_question_with_no_terminal_to_ask_on_is_noted() {
    let mut terminal = Asker {
        path: "/nonexistent/guardian-test/tty",
        missing: false,
    };
    assert!(!terminal.confirm("Go on?"));
    assert!(terminal.missing);
    assert!(!Asker::new().missing);
}

#[test]
fn a_source_anyone_can_replace_blocks_every_call_that_uses_it() {
    let unverified = [aur::Source {
        entry: "http://example.org/demo.tar.gz".into(),
        checksums: vec!["SKIP".into()],
    }];
    // Extracting, or building from an earlier extraction.
    assert_eq!(source_context(&unverified, true), Err(()));
    // Only downloading, to verify or to generate the checksum.
    assert_eq!(source_context(&unverified, false), Ok(Vec::new()));
    for (arguments, blocks) in [
        (&["--noextract", "--noprepare"][..], true),
        (&["-e"], true),
        (&["--nobuild"], true),
        (&["--verifysource"], false),
        (&["-g"], false),
    ] {
        assert_eq!(
            aur::classify(&args(arguments)).uses_sources,
            blocks,
            "{arguments:?}"
        );
    }
}

#[test]
fn a_later_call_is_held_against_what_guardian_extracted() {
    let fixture = Fixture::new("gate-extraction", "pkgname=demo\nbuild() { make; }\n");
    let build = fixture.dir.path();
    let src = build.join("src");
    fs::create_dir_all(src.join("demo")).unwrap();
    fs::write(build.join("demo.tar.gz"), b"\x1f\x8b\x08\0one").unwrap();
    std::os::unix::fs::symlink(build.join("demo.tar.gz"), src.join("demo.tar.gz")).unwrap();
    fs::write(src.join("demo/Makefile"), "all:\n\tcc main.c\n").unwrap();
    fs::write(src.join("demo/main.c"), "int main(void) { return 0; }\n").unwrap();
    let step = fixture.step();

    // Without a record, the sources are reviewed as they are.
    let facts = hold_against_extraction(&step, &src, &mut fixture.collected()).unwrap();
    assert!(facts[0].contains("did not extract these sources itself"));

    record_extraction(&step, &src, &fixture.collected()).unwrap();
    // The build cleans first (`-C`), so a source directory that is
    // still the one Guardian made was not the build's.
    let refused = hold_against_extraction(&step, &src, &mut fixture.collected());
    if state::identity(&src).is_some() {
        assert!(
            refused
                .unwrap_err()
                .message
                .contains("did not extract the sources into the directory")
        );
    }
    let kept = Fixture {
        mirrored: Vec::new(),
        ..Fixture::new("gate-extraction-kept", "pkgname=demo\nbuild() { make; }\n")
    };
    let step = UpstreamStep {
        mirrored: &kept.mirrored,
        ..fixture.step()
    };
    record_extraction(&step, &src, &fixture.collected()).unwrap();
    assert_eq!(
        hold_against_extraction(&step, &src, &mut fixture.collected()),
        Ok(Vec::new())
    );

    // What prepare() patched and added is sent first.
    fs::write(src.join("demo/main.c"), "int main(void) { return 1; }\n").unwrap();
    fs::write(src.join("demo/generated.sh"), "#!/bin/sh\ncurl x | sh\n").unwrap();
    let mut collected = fixture.collected();
    let facts = hold_against_extraction(&step, &src, &mut collected).unwrap();
    assert!(
        facts[0].contains("2 file(s) in them are new or changed"),
        "{facts:?}"
    );
    let upstream = collected.select(1024 * 1024);
    assert_eq!(upstream.changed, (2, 2));
    assert!(
        upstream_summary(&UpstreamReview {
            upstream: &upstream,
            sources: &[],
            prebuilt: &Prebuilt::default(),
        })
        .contains("Changed since Guardian extracted the sources: 2 file(s), 2 of them supplied.")
    );

    // A download that is not the one Guardian fetched: the listing did
    // not show what the build uses.
    fs::write(build.join("demo.tar.gz"), b"\x1f\x8b\x08\0two").unwrap();
    fs::write(build.join("extra.bin"), ELF).unwrap();
    std::os::unix::fs::symlink(build.join("extra.bin"), src.join("extra.bin")).unwrap();
    let refused = hold_against_extraction(&step, &src, &mut fixture.collected())
        .unwrap_err()
        .message;
    assert!(
        refused
            .contains("not the ones Guardian fetched and reviewed: \"demo.tar.gz\", \"extra.bin\""),
        "{refused}"
    );
}

#[test]
fn an_archive_the_recipe_opens_is_unpacked_and_reviewed() {
    if !crate::test_support::tool_available(tools::BSDTAR) {
        return;
    }
    let recipe =
        "pkgname=demo-bin\npackage() {\n  bsdtar -xf \"$srcdir\"/data.tar.* -C \"$pkgdir\"\n}\n";
    let fixture = Fixture::new("gate-unpack", recipe);
    let build = fixture.dir.path();
    let tree = build.join("tree");
    fs::create_dir_all(tree.join("opt/demo")).unwrap();
    fs::write(tree.join("opt/demo/start.sh"), "#!/bin/sh\ncurl x | sh\n").unwrap();
    fs::write(tree.join("opt/demo/demo"), ELF).unwrap();
    let src = build.join("src");
    fs::create_dir_all(&src).unwrap();
    let made = Command::new(tools::BSDTAR)
        .arg("-czf")
        .arg(src.join("data.tar.gz"))
        .arg("-C")
        .arg(&tree)
        .arg("opt")
        .status()
        .unwrap();
    assert!(made.success());
    fs::remove_dir_all(&tree).unwrap();
    // An archive nothing in the recipe names stays packed. A Java
    // archive is code all the same: the recipe builds nothing, so it
    // is one of the programs the package is made of.
    fs::write(src.join("vendored.jar"), b"PK\x03\x04\x14\0\0\0").unwrap();
    // A directory that only looks like an unpacked archive is not one.
    fs::create_dir_all(src.join("other.tar!")).unwrap();
    fs::write(src.join("other.tar!/notes.txt"), "notes\n").unwrap();

    // Left packed, the review is incomplete: the recipe opens it.
    let packed = fixture.upstream();
    assert!(
        packed
            .gaps
            .iter()
            .any(|gap| gap.starts_with("src/data.tar.gz: the recipe opens this archive itself")),
        "{:?}",
        packed.gaps
    );

    let mut collected = fixture.collected();
    let archives = collected.to_unpack();
    assert_eq!(archives.len(), 1, "{archives:?}");
    let mut scratch = unpack::Scratch::create(build).unwrap();
    let into = scratch.next().unwrap();
    unpack::unpack(&[], &archives[0].file, &into).unwrap();
    collected.add_unpacked(
        &archives[0],
        &into,
        &fixture.roots(),
        &fixture.functions.written,
    );
    assert!(collected.to_unpack().is_empty());
    let upstream = collected.select(1024 * 1024);
    assert!(upstream.gaps.is_empty(), "{:?}", upstream.gaps);
    let script = upstream
        .files
        .iter()
        .find(|file| file.path == "src/data.tar.gz!/opt/demo/start.sh")
        .unwrap();
    assert!(script.text.contains("curl x | sh"));
    assert_eq!(upstream.unpacked, ["src/data.tar.gz"]);
    // The program in it is one the package installs.
    let found = prebuilt(
        &fixture.step(),
        &upstream,
        &sources(&["https://example.org/demo.deb"]),
    );
    assert_eq!(
        found.programs.keys().collect::<Vec<_>>(),
        ["src/data.tar.gz!/opt/demo/demo", "src/vendored.jar"]
    );
    assert!(upstream.is_unpacked("src/data.tar.gz!/opt/demo/demo"));
    assert!(!upstream.is_unpacked("src/other.tar!/notes.txt"));
    assert!(!upstream.is_unpacked("src/data.tar.gz"));
    let facts = upstream_facts(&UpstreamReview {
        upstream: &upstream,
        sources: &[],
        prebuilt: &found,
    })
    .join("\n");
    assert!(facts.contains("Guardian unpacked 1 archive(s)"), "{facts}");
    assert!(
        facts.contains("installs 2 prebuilt program(s) nobody reviewed"),
        "{facts}"
    );
}

#[test]
fn a_directory_named_like_an_unpacked_archive_is_no_archive() {
    let recipe = "pkgname=demo\nbuild() {\n  make\n}\n";
    let fixture = Fixture::new("gate-bang-directory", recipe);
    let src = fixture.dir.path().join("src");
    fs::create_dir_all(src.join("tests.tar!/bin")).unwrap();
    fs::write(src.join("tests.tar!/bin/sample"), ELF).unwrap();
    fs::write(src.join("Makefile"), "all:\n\tcc main.c\n").unwrap();
    let upstream = fixture.upstream();
    assert!(upstream.programs.contains_key("src/tests.tar!/bin/sample"));
    // The recipe builds, and neither names nor runs the binary: it is
    // test data among the sources, not what the package installs.
    let found = prebuilt(&fixture.step(), &upstream, &sources(&["demo.tar.gz"]));
    assert!(found.programs.is_empty(), "{found:?}");
}

#[test]
fn code_that_is_no_program_file_is_asked_about_too() {
    // A package made of a Java archive: no text, and no file bash
    // would call a program.
    let recipe = "pkgname=demo-bin\npackage() {\n  install -Dm644 -t \"$pkgdir/usr/share/java\" */*.jar\n}\n";
    let fixture = Fixture::new("gate-jar-only", recipe);
    let src = fixture.dir.path().join("src");
    fs::create_dir_all(src.join("demo")).unwrap();
    fs::write(src.join("demo/app.jar"), b"PK\x03\x04\x14\0\0\0").unwrap();
    fs::write(src.join("demo/app.asar"), b"\x04\0\0\0\x10\0\0\0").unwrap();
    fs::write(src.join("demo/logo.png"), [0x89, b'P', b'N', b'G', 0, 1]).unwrap();
    let upstream = fixture.upstream();
    assert!(upstream.files.is_empty() && upstream.gaps.is_empty());
    let listed = sources(&["https://example.org/demo.tar.gz"]);
    let found = prebuilt(&fixture.step(), &upstream, &listed);
    assert_eq!(
        found.programs.keys().collect::<Vec<_>>(),
        ["src/demo/app.asar", "src/demo/app.jar"]
    );
    let review = UpstreamReview {
        upstream: &upstream,
        sources: &listed,
        prebuilt: &found,
    };
    let mut no = answer(false);
    assert_eq!(
        unreviewable_sources(&fixture.step(), &review, &mut no),
        Decision::Blocked(Blocked::NotConfirmed)
    );
    assert_eq!(no.asked, 1);
}

#[test]
fn a_permit_that_overrules_the_review_does_not_answer_the_prebuilt_question() {
    use super::asked_under_permit;
    let recipe =
        "pkgname=demo-bin\npackage() {\n  install -Dm755 demo \"$pkgdir/usr/bin/demo\"\n}\n";
    let fixture = Fixture::new("gate-permitted", recipe);
    let src = fixture.dir.path().join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("demo"), ELF).unwrap();
    fs::write(src.join("run.sh"), "#!/bin/sh\necho hi\n").unwrap();
    let listed = sources(&["https://example.org/demo.tar.gz"]);
    let step = fixture.step();
    let found = prebuilt(&step, &fixture.upstream(), &listed);
    assert_eq!(found.programs.len(), 1);
    let blocked = Decision::Blocked(Blocked::Findings);
    let declined = Decision::Blocked(Blocked::NotConfirmed);

    // A block no permit overrules stays what it is, unasked: a yes
    // never stands in for the review.
    let mut unasked = answer(true);
    assert_eq!(
        asked_under_permit(&step, &found, blocked, false, &mut unasked),
        blocked
    );
    assert_eq!(unasked.asked, 0);

    // The permit lets the review's block through, not the programs:
    // a no is the user's own, and no permit stands for it.
    let mut no = answer(false);
    assert_eq!(
        asked_under_permit(&step, &found, blocked, true, &mut no),
        declined
    );
    assert_eq!(no.asked, 1);
    let incomplete = Decision::Blocked(Blocked::Incomplete);
    assert_eq!(
        asked_under_permit(&step, &found, incomplete, true, &mut no),
        declined
    );
    assert_eq!(no.asked, 2);
    assert!(permittable(declined, &[]).is_empty());

    // A yes goes on as permitted and is remembered for these programs,
    // as on a review that passed.
    let mut yes = answer(true);
    assert_eq!(
        asked_under_permit(&step, &found, blocked, true, &mut yes),
        blocked
    );
    assert_eq!(
        asked_under_permit(&step, &found, blocked, true, &mut yes),
        blocked
    );
    assert_eq!(yes.asked, 1);

    // Nothing prebuilt, nothing to ask.
    let mut none = answer(false);
    assert_eq!(
        asked_under_permit(&step, &Prebuilt::default(), blocked, true, &mut none),
        blocked
    );
    assert_eq!(none.asked, 0);
}

#[test]
fn a_declined_question_is_no_block_a_permit_overrules() {
    use super::upstream_content;
    let fixture = Fixture::new("gate-declined", "pkgname=demo\n");
    let mut upstream = Upstream::default();
    let hash = "d".repeat(64);
    upstream.downloads.insert("demo.tar.gz".into(), hash);
    let content = upstream_content(&fixture.step(), &upstream, &sources(&["demo.tar.gz"])).unwrap();
    let contents = [content];
    let declined = Decision::Blocked(Blocked::NotConfirmed);
    assert!(permittable(declined, &contents).is_empty());
    assert_eq!(
        permittable(Decision::Blocked(Blocked::Findings), &contents).len(),
        1
    );
}

#[test]
fn a_build_from_an_extracted_tree_must_find_it() {
    let fixture = Fixture::new("gate-noextract-empty", "pkgname=demo\n");
    let listed = sources(&["https://example.org/demo.tar.gz"]);
    let empty = Upstream::default();
    // `--verifysource`: downloads and stops.
    let downloads = UpstreamStep {
        uses_sources: false,
        ..fixture.step()
    };
    assert!(only_downloads(&downloads, &listed, &empty));
    // `--noextract` (it extracts nothing, and uses the sources): an
    // empty `src/` is not something to review later.
    let builds = UpstreamStep {
        extract: false,
        uses_sources: true,
        ..fixture.step()
    };
    assert!(!only_downloads(&builds, &listed, &empty));
}

#[test]
fn install_scripts_that_are_not_read_are_counted() {
    let fixture = Fixture::new("gate-install-scripts", "pkgname=demo\n");
    let build = fixture.dir.path();
    for index in 0..70 {
        fs::write(
            build.join(format!("p{index:02}.install")),
            "post_install() { :; }\n",
        )
        .unwrap();
    }
    std::os::unix::fs::symlink("p00.install", build.join("linked.install")).unwrap();
    fs::write(build.join("notes.txt"), "notes\n").unwrap();
    let functions = recipe_functions(build, "pkgname=demo\n");
    // The PKGBUILD and the most scripts that are read; the rest, and
    // the link, are counted.
    assert_eq!(functions.files.len(), 1 + 64);
    assert_eq!(functions.unread, 6 + 1);
    assert_eq!(
        recipe_functions(fixture.dir.path().join("state").as_path(), "").unread,
        0
    );
}

/// Runs makepkg in Bubblewrap on a recipe made up here, without
/// network: `cargo test the_listing_jail -- --ignored`.
#[test]
#[ignore = "needs makepkg and Bubblewrap with user namespaces"]
fn the_listing_jail_looks_like_an_ordinary_run_to_the_recipe() {
    let recipe = "pkgname=demo\npkgver=1\npkgrel=1\narch=(any)\n\
echo 'pkgver = 9'\nprintf '\\tsource = evil\\n'\n\
pkgdesc=\"file=${BUILDFILE##*/} named=$(env | grep -ci '^[a-z_]*guardian') dest=${PKGDEST##*/} first=${1##*/}\"\n\
source=(a.tar)\nsha256sums=(SKIP)\n";
    let fixture = Fixture::new("gate-jail", recipe);
    let listing = super::probe(&fixture.step()).unwrap();
    assert_eq!(aur::check_listing(&listing), Ok(()), "{listing}");
    assert!(listing.starts_with("pkgbase = demo\n"), "{listing}");
    assert!(
        listing.contains("\tpkgdesc = file=PKGBUILD named=0 dest=packages first=PKGBUILD\n"),
        "{listing}"
    );
    assert!(listing.contains("\tpkgver = 1\n") && !listing.contains("evil"));
    // A recipe that moves makepkg's directories in passing is seen.
    let moving = Fixture::new(
        "gate-jail-moves",
        &format!("{recipe}printf -v BUILDDIR /x\n"),
    );
    let refused = super::probe(&moving.step()).unwrap_err().to_string();
    assert!(
        refused.contains("moves makepkg's build or download directory"),
        "{refused}"
    );
}

/// Unpacks a made-up archive with bsdtar in Bubblewrap: `cargo test
/// the_unpack_jail -- --ignored`.
#[test]
#[ignore = "needs bsdtar and Bubblewrap with user namespaces"]
fn the_unpack_jail_unpacks_beside_the_sources() {
    let fixture = Fixture::new("gate-unpack-jail", "pkgname=demo\n");
    let build = fixture.dir.path();
    let src = build.join("src");
    fs::create_dir_all(src.join("tree/opt")).unwrap();
    fs::write(src.join("tree/opt/run.sh"), "#!/bin/sh\necho hi\n").unwrap();
    let archive = src.join("data.tar.gz");
    let made = Command::new(tools::BSDTAR)
        .arg("-czf")
        .arg(&archive)
        .arg("-C")
        .arg(src.join("tree"))
        .arg("opt")
        .status()
        .unwrap();
    assert!(made.success());
    let mut scratch = None;
    let into = super::unpack_one(&fixture.step(), &src, &archive, &mut scratch).unwrap();
    assert!(
        into.starts_with(build) && !into.starts_with(&src),
        "{into:?}"
    );
    assert_eq!(
        fs::read_to_string(into.join("opt/run.sh")).unwrap(),
        "#!/bin/sh\necho hi\n"
    );
    drop(scratch);
    assert!(!into.exists());
}

#[test]
fn mounts_go_before_the_directory_the_jail_starts_in() {
    let command = args(&["--ro-bind", "/usr", "/usr", "--chdir", "/build", "--"]);
    assert_eq!(
        with_mounts(command, args(&["--bind", "/a", "/b"])),
        args(&[
            "--ro-bind",
            "/usr",
            "/usr",
            "--bind",
            "/a",
            "/b",
            "--chdir",
            "/build",
            "--"
        ])
    );
    // As `sandbox::fetch_jail` ends its arguments.
    let jail = crate::sandbox::fetch_jail(&crate::sandbox::FetchJail {
        home: Path::new("/home/x"),
        readable: &[],
        writable: &[],
        keyring: None,
        network: false,
        environment: &[],
        directory: Path::new("/build"),
    });
    assert_eq!(jail[jail.len() - 3..], args(&["--chdir", "/build", "--"]));
}

#[test]
fn parses_the_wrapped_command() {
    assert_eq!(
        parse(&args(&["--", "/usr/bin/makepkg", "-si"])).unwrap(),
        args(&["/usr/bin/makepkg", "-si"])
    );
    assert!(parse(&args(&["/usr/bin/makepkg"])).is_err());
    assert!(parse(&args(&["--"])).is_err());
}

#[test]
fn mirrors_flags_config_and_settings_and_refuses_other_recipes() {
    assert_eq!(
        mirrored_arguments(&args(&[
            "--nobuild",
            "-fC",
            "--ignorearch",
            "--config",
            "/etc/x.conf",
            "BUILDDIR=/tmp/b",
            "-si"
        ]))
        .unwrap(),
        args(&[
            "-C",
            "--ignorearch",
            "--config",
            "/etc/x.conf",
            "BUILDDIR=/tmp/b"
        ])
    );
    assert!(mirrored_arguments(&args(&["-p", "other"])).is_err());
    assert!(mirrored_arguments(&args(&["-D", "/elsewhere"])).is_err());
    assert!(mirrored_arguments(&args(&["-sp", "other"])).is_err());
    // A shortened long option is the option makepkg takes it for.
    for shortened in ["--fil", "--di", "--dir=/x", "--conf", "--f"] {
        assert!(
            mirrored_arguments(&args(&[shortened, "x"])).is_err(),
            "{shortened}"
        );
    }
    assert!(mirrored_arguments(&args(&["--force", "--clean"])).is_ok());
}

#[test]
fn the_fetch_recipe_holds_the_listed_sources_and_no_code() {
    let srcinfo = "pkgbase = demo
\tpkgdesc = $(touch /tmp/x)
\tpkgver = 1.2
\tpkgrel = 3
\tinstall = demo.install
\tarch = x86_64
\tarch = aarch64
\tmakedepends = git
\tnoextract = a.tar.gz
\tsource = a.tar.gz::https://example.org/a.tar.gz
\tsource = it's $(odd) `name`.txt
\tvalidpgpkeys = ABCDEF
\tsha256sums = abc
\tsha256sums = SKIP
\tsource_x86_64 = git+https://example.org/r.git#commit=abc
\tb2sums_x86_64 = SKIP
\tsource_x86-64;touch = x
\tSOURCE_EVIL = x

pkgname = demo-a
\tsource = not-a-global-source
";
    assert_eq!(
        fetch_recipe(srcinfo).unwrap(),
        "pkgbase='demo'
pkgname=('demo')
pkgver='1.2'
pkgrel='3'
arch=('x86_64' 'aarch64')
noextract=('a.tar.gz')
source=('a.tar.gz::https://example.org/a.tar.gz' 'it'\\''s $(odd) `name`.txt')
validpgpkeys=('ABCDEF')
sha256sums=('abc' 'SKIP')
source_x86_64=('git+https://example.org/r.git#commit=abc')
b2sums_x86_64=('SKIP')
package() { :; }
"
    );
    for pkgbase in ["", "../x", "-x", ".x", "a b", "a/b", "$(x)", "a'b"] {
        assert_eq!(
            fetch_recipe(&format!("pkgbase = {pkgbase}\n")),
            None,
            "{pkgbase:?}"
        );
    }
}

#[test]
fn the_fetch_recipe_runs_nothing_when_bash_reads_it() {
    let dir = TempDir::new("fetch-recipe");
    let srcinfo = format!(
        "pkgbase = demo\n\tpkgver = 1\n\tsource = a'; touch {0}/ran; '\n\tsource = $(touch {0}/ran)\n\tsource = `touch {0}/ran`\n\tnoextract = \\'; touch {0}/ran #\n",
        dir.path().display()
    );
    fs::write(dir.path().join("PKGBUILD"), fetch_recipe(&srcinfo).unwrap()).unwrap();
    let output = Command::new("/usr/bin/bash")
        .args([
            "-c",
            "source ./PKGBUILD && printf '%s\\n' \"${#source[@]}\" \"${source[0]}\"",
        ])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("3\na'; touch {}/ran; '\n", dir.path().display())
    );
    assert!(!dir.path().join("ran").exists());
}

#[test]
fn the_listing_reports_the_directories_as_the_recipe_left_them() {
    // Sourced the way makepkg does, with the two directories set.
    let report_of = |name: &str, recipe: &str| -> Option<Vec<u8>> {
        let dir = TempDir::new(name);
        let report = dir.path().join("report");
        let real = dir.path().join("it's the real one");
        fs::write(&real, recipe).unwrap();
        fs::write(dir.path().join("PKGBUILD"), listing_recipe(&real, &report)).unwrap();
        let output = Command::new("/usr/bin/bash")
            .args(["-c", "source ./PKGBUILD"])
            .current_dir(dir.path())
            .env_clear()
            .env("BUILDDIR", "/tmp/r/build")
            .env("SRCDEST", "/tmp/r/sources")
            .output()
            .unwrap();
        assert!(output.status.success() || !report.exists(), "{name}");
        // What the recipe prints while it loads is not in the listing.
        assert_eq!(String::from_utf8_lossy(&output.stdout), "", "{name}");
        listing_report(&report)
    };
    // Nothing of Guardian's is in the recipe's environment.
    let wrapper = listing_recipe(Path::new("/tmp/makepkg-1/PKGBUILD"), Path::new("/tmp/r"));
    assert!(!wrapper.to_lowercase().contains("guardian"), "{wrapper}");
    let kept: &[u8] = b"/tmp/r/build\0/tmp/r/sources\0";
    for (name, recipe) in [
        ("plain", "pkgname=demo\n"),
        ("echo", "echo 'pkgver = 9'\nprintf '\\tsource = evil\\n'\n"),
        ("return", "pkgname=demo\nreturn 0\n"),
        ("reads", "x=\"$SRCDEST/a\"\n"),
    ] {
        assert_eq!(report_of(name, recipe).as_deref(), Some(kept), "{name}");
    }
    for (name, recipe) in [
        ("then", "if true; then SRCDEST=/x; fi\n"),
        ("braces", ": {\nBUILDDIR=/x\n"),
        ("function", "f() { SRCDEST=/x; }; f\n"),
        ("printf", "printf -v BUILDDIR %s /x\n"),
    ] {
        let report = report_of(name, recipe);
        assert!(
            report.is_some() && report.as_deref() != Some(kept),
            "{name}"
        );
    }
    assert_eq!(report_of("exit", "exit 0\n"), None);

    // Only a plain file of a sane size is a report.
    let dir = TempDir::new("listing-report");
    std::os::unix::fs::symlink("/etc/hostname", dir.path().join("link")).unwrap();
    assert_eq!(listing_report(&dir.path().join("link")), None);
    fs::write(dir.path().join("huge"), vec![0; 32 * 1024]).unwrap();
    assert_eq!(listing_report(&dir.path().join("huge")), None);
    assert_eq!(listing_report(&dir.path().join("missing")), None);
}

#[test]
fn the_configured_directories_or_the_recipes_own_are_used() {
    assert_eq!(Configured::parse(b"\0\0"), Some(Configured::default()));
    assert_eq!(Configured::parse(b"/b"), None);
    let configured = Configured::parse(b"/b\0/dl\0").unwrap();
    let dirs = configured.dirs(Path::new("/start"), "demo");
    assert_eq!(dirs.builddir, PathBuf::from("/b"));
    assert_eq!(dirs.srcdest, PathBuf::from("/dl"));
    assert_eq!(dirs.srcdir(), PathBuf::from("/b/demo/src"));

    let own = Configured::default().dirs(Path::new("/"), "demo");
    assert_eq!(own.srcdest, PathBuf::from("/"));
    assert_eq!(own.srcdir(), PathBuf::from("/src"));
}

#[test]
fn makepkg_is_not_let_into_what_the_jail_hides() {
    let home = TempDir::new("jail-home");
    let build = home.path().join(".cache/yay/demo");
    fs::create_dir_all(&build).unwrap();
    assert!(is_jailable(&build, home.path()));
    assert!(!is_jailable(home.path(), home.path()));
    assert!(!is_jailable(home.path().parent().unwrap(), home.path()));
    assert!(!is_jailable(Path::new("/"), home.path()));
    assert!(!is_jailable(Path::new("/usr/share"), home.path()));
    assert!(!is_jailable(Path::new("/etc"), home.path()));
    assert!(!is_jailable(&std::env::temp_dir(), home.path()));
    assert!(!is_jailable(&home.path().join("missing"), home.path()));
    // A link to the home is the home.
    let link = build.join("link");
    std::os::unix::fs::symlink(home.path(), &link).unwrap();
    assert!(!is_jailable(&link, home.path()));
}

#[test]
fn the_jail_gets_the_public_keyring_only() {
    let home = TempDir::new("keyring-home");
    let work = TempDir::new("keyring-work");
    assert_eq!(public_keyring(home.path(), work.path()), None);

    let gnupg = home.path().join(".gnupg");
    fs::create_dir_all(gnupg.join("private-keys-v1.d")).unwrap();
    fs::create_dir_all(gnupg.join("public-keys.d")).unwrap();
    for name in [
        "pubring.kbx",
        "trustdb.gpg",
        "public-keys.d/pubring.db",
        "private-keys-v1.d/secret.key",
        "secring.gpg",
    ] {
        fs::write(gnupg.join(name), name).unwrap();
    }
    let copy = public_keyring(home.path(), work.path()).unwrap();
    let mut copied: Vec<String> = Vec::new();
    let mut pending = vec![copy.clone()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).unwrap().flatten() {
            if entry.path().is_dir() {
                pending.push(entry.path());
            } else {
                let path = entry.path();
                copied.push(path.strip_prefix(&copy).unwrap().display().to_string());
            }
        }
    }
    copied.sort();
    assert_eq!(
        copied,
        ["public-keys.d/pubring.db", "pubring.kbx", "trustdb.gpg"]
    );
}

#[test]
fn download_names_follow_makepkg() {
    let source = |entry: &str| aur::Source {
        entry: entry.into(),
        checksums: Vec::new(),
    };
    assert_eq!(
        download_names(&[
            source("demo-1.0.tar.gz::https://example.org/v1.0.tar.gz"),
            source("git+https://github.com/someone/proj.git#commit=abc"),
            source("https://example.org/files/patch.diff?raw=1"),
            source("local.patch"),
            source("PKGBUILD::https://example.org/PKGBUILD"),
        ]),
        ["demo-1.0.tar.gz", "patch.diff?raw=1", "proj"]
    );
}

#[test]
fn a_source_must_be_kept_under_a_file_name() {
    let source = |entry: &str| aur::Source {
        entry: entry.into(),
        checksums: Vec::new(),
    };
    let plain = [
        source("demo-1.0.tar.gz::https://example.org/v1.0.tar.gz"),
        source("git+https://github.com/someone/proj.git"),
        source(".gitignore"),
    ];
    assert_eq!(misnamed_source(&plain), None);
    for entry in [
        ".git/commondir::https://example.org/x",
        "../PKGBUILD::https://example.org/x",
        "a/b::https://example.org/x",
        "..::https://example.org/x",
        ".git::git+https://example.org/x",
        "::https://example.org/x",
        "-o::https://example.org/x",
        "https://example.org/dir/",
    ] {
        assert_eq!(misnamed_source(&[source(entry)]), Some(entry), "{entry}");
    }
}

#[test]
fn only_a_mirror_as_makepkg_makes_one_is_fetched_into() {
    let dir = TempDir::new("mirror");
    let url = "https://example.org/proj.git";
    let mirror = dir.path().join("proj");
    let made = Command::new("/usr/bin/git")
        .args(["init", "--quiet", "--bare"])
        .arg(&mirror)
        .status()
        .unwrap();
    assert!(made.success());
    let config = mirror.join("config");
    let plain = format!(
        "{}[remote \"origin\"]\n\turl = {url}\n\ttagOpt = --no-tags\n\tfetch = +refs/*:refs/*\n\tmirror = true\n",
        fs::read_to_string(&config).unwrap()
    );
    fs::write(&config, &plain).unwrap();
    assert!(is_plain_mirror(&mirror, url));
    assert!(is_plain_mirror(&mirror, "https://example.org/proj"));
    assert!(!is_plain_mirror(&mirror, "https://example.org/other.git"));
    // git fetches from the first of two URLs.
    let twice = plain.replace("\turl = ", "\turl = https://evil.example/x.git\n\turl = ");
    fs::write(&config, twice).unwrap();
    assert!(!is_plain_mirror(&mirror, url));
    fs::write(&config, &plain).unwrap();

    for extra in [
        "\tuploadpack = touch x; git-upload-pack\n",
        "[core]\n\tsshCommand = touch x\n",
        "[core]\n\tgitProxy = touch x\n",
        "[credential]\n\thelper = !touch x\n",
        "[include]\n\tpath = ../evil\n",
        "[url \"https://evil.example/\"]\n\tinsteadOf = https://example.org/\n",
        "\tmirror = true \\\n",
    ] {
        fs::write(&config, format!("{plain}{extra}")).unwrap();
        assert!(!is_plain_mirror(&mirror, url), "{extra:?}");
    }
    fs::write(&config, &plain).unwrap();
    fs::write(mirror.join("hooks/reference-transaction"), "#!/bin/sh\n").unwrap();
    assert!(!is_plain_mirror(&mirror, url));
    fs::remove_file(mirror.join("hooks/reference-transaction")).unwrap();
    fs::write(mirror.join("commondir"), "..\n").unwrap();
    assert!(!is_plain_mirror(&mirror, url));
    fs::remove_file(mirror.join("commondir")).unwrap();
    assert!(is_plain_mirror(&mirror, url));

    // In the download directory, any other checkout is foreign.
    let source = |entry: &str| aur::Source {
        entry: entry.into(),
        checksums: Vec::new(),
    };
    let dirs = Configured::default().dirs(dir.path(), "demo");
    let git = source("git+https://example.org/proj.git#commit=abc");
    let other = source("git+https://example.org/new.git");
    let hg = source("proj::hg+https://example.org/proj");
    assert_eq!(foreign_checkout(&[git.clone(), other], &dirs), None);
    assert_eq!(
        foreign_checkout(std::slice::from_ref(&hg), &dirs),
        Some(hg.entry.as_str())
    );
    // makepkg looks in the recipe's directory before the downloads.
    let elsewhere = TempDir::new("mirror-downloads");
    let configured = Configured {
        srcdest: Some(elsewhere.path().to_path_buf()),
        ..Configured::default()
    };
    let apart = configured.dirs(dir.path(), "demo");
    assert_eq!(foreign_checkout(std::slice::from_ref(&git), &apart), None);
    assert_eq!(
        foreign_checkout(std::slice::from_ref(&hg), &apart),
        Some(hg.entry.as_str())
    );
    fs::write(&config, format!("{plain}\tuploadpack = x\n")).unwrap();
    assert_eq!(
        foreign_checkout(std::slice::from_ref(&git), &dirs),
        Some(git.entry.as_str())
    );
}
