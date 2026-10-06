//! Tests for how the record of an extraction is written and read back,
//! with paths that are not plain ASCII.

use std::collections::{BTreeMap, HashSet};
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use super::super::{
    Configured, UpstreamStep, hold_against_extraction, recipe_functions, record_extraction,
};
use super::{Drift, Extraction, State, identity};
use crate::aur;
use crate::test_support::{Rng, TempDir};

/// A name with every kind of character the record writes escaped, and a
/// space, which it does not.
const ODD: &str = "jos\u{e9} 'l' \"q\" back\\slash\ttab\nline \u{65e5}\u{672c}";

fn map(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|(path, digest)| ((*path).to_string(), (*digest).to_string()))
        .collect()
}

fn odd_extraction() -> Extraction {
    Extraction {
        srcdir: format!("/home/{ODD}/build/src"),
        identity: Some("1:2:3".into()),
        cleanbuild: false,
        downloads: map(&[
            (&format!("{ODD}.tar.gz"), &"a".repeat(32)),
            ("plain.tar.gz", &"b".repeat(32)),
        ]),
        files: map(&[
            (&format!("src/{ODD}/main.c"), &"c".repeat(32)),
            ("src/caf\u{e9}/\u{1f600}", "size-1-2-3"),
            ("src/unhashed \\n", ""),
        ]),
    }
}

/// The record as it was written before paths were kept as they are: the
/// directory escaped once, each path twice.
fn old_text(extraction: &Extraction) -> String {
    let mut text = format!(
        "srcdir {}\nidentity {}\ncleanbuild {}\n",
        extraction.srcdir.escape_default(),
        extraction.identity.as_deref().unwrap_or("-"),
        u8::from(extraction.cleanbuild)
    );
    for (kind, entries) in [("D", &extraction.downloads), ("F", &extraction.files)] {
        for (path, digest) in entries {
            let digest = if digest.is_empty() { "-" } else { digest };
            let twice = path.escape_default().to_string();
            let _ = writeln!(text, "{kind} {digest} {}", twice.escape_default());
        }
    }
    text
}

#[test]
fn a_record_with_odd_paths_reads_back_as_it_was() {
    let extraction = odd_extraction();
    let text = extraction.to_text();
    assert!(
        text.bytes()
            .all(|byte| byte == b'\n' || (b' '..=b'~').contains(&byte)),
        "{text:?}"
    );
    assert_eq!(text.lines().count(), 3 + 2 + 3, "{text:?}");
    assert_eq!(Extraction::parse(&text), Some(extraction.clone()));

    // Through the file, as the next makepkg call reads it.
    let dir = TempDir::new("gate-record-odd");
    let state = State::open(Some(&dir.path().join("state")), "demo");
    state.record_extraction(&extraction);
    let read = state.extraction().unwrap();
    assert_eq!(read, extraction);
    assert!(read.is_of(Path::new(&extraction.srcdir)));
    assert!(!read.is_of(Path::new("/home/jos\\u{e9}/build/src")));

    // The same tree: only the file without a hash counts as changed.
    let unhashed: HashSet<String> = HashSet::from(["src/unhashed \\n".to_string()]);
    assert_eq!(
        read.drift(Some("9:9:9"), &extraction.downloads, &extraction.files),
        Drift::Files(unhashed.clone())
    );
    // A download that changed and one that is new, under odd names.
    let mut downloads = extraction.downloads.clone();
    downloads.insert(format!("{ODD}.tar.gz"), "f".repeat(64));
    downloads.insert("new\u{e9}.bin".into(), "e".repeat(64));
    assert_eq!(
        read.drift(None, &downloads, &extraction.files),
        Drift::Downloads(vec![format!("{ODD}.tar.gz"), "new\u{e9}.bin".into()])
    );
    // A file that changed, and one whose name is another's written escaped.
    let mut files = extraction.files.clone();
    files.insert(format!("src/{ODD}/main.c"), "d".repeat(64));
    files.insert("src/caf\\u{e9}/\\u{1f600}".into(), "size-1-2-3".into());
    let mut expected = unhashed;
    expected.insert(format!("src/{ODD}/main.c"));
    expected.insert("src/caf\\u{e9}/\\u{1f600}".into());
    assert_eq!(
        read.drift(None, &extraction.downloads, &files),
        Drift::Files(expected)
    );
}

struct Tree {
    dir: TempDir,
    build: PathBuf,
    state: State,
}

impl Tree {
    /// A build directory named `name` with one download linked into its
    /// sources and two source files.
    fn new(label: &str, name: OsString, download: &str) -> Self {
        let dir = TempDir::new(label);
        let build = dir.path().join(name);
        let src = build.join("src");
        fs::create_dir_all(src.join("demo")).unwrap();
        fs::write(build.join("PKGBUILD"), RECIPE).unwrap();
        fs::write(build.join(download), b"\x1f\x8b\x08\0one").unwrap();
        std::os::unix::fs::symlink(build.join(download), src.join(download)).unwrap();
        fs::write(src.join("demo/main.c"), "int main(void) { return 0; }\n").unwrap();
        fs::write(src.join(format!("demo/{ODD}.c")), "int odd;\n").unwrap();
        let state = State::open(Some(&dir.path().join("state")), "demo");
        Self { dir, build, state }
    }

    fn src(&self) -> PathBuf {
        self.build.join("src")
    }

    fn collected(&self) -> aur::Collected {
        let roots = aur::Roots {
            build_dir: &self.build,
            srcdest: Some(&self.build),
        };
        aur::walk_upstream(&self.src(), &roots, RECIPE, &[])
    }
}

const RECIPE: &str = "pkgname=demo\nbuild() { make; }\n";

/// Runs `check` with the gate's step for `build`, called with `mirrored`.
fn with_step<T>(build: &Tree, mirrored: &[&str], check: impl FnOnce(&UpstreamStep<'_>) -> T) -> T {
    let mirrored: Vec<OsString> = mirrored.iter().map(Into::into).collect();
    let functions = recipe_functions(&build.build, RECIPE);
    let configured = Configured::default();
    check(&UpstreamStep {
        makepkg: Path::new("/usr/bin/makepkg"),
        mirrored: &mirrored,
        build_dir: &build.build,
        name: "demo",
        key: "demo",
        base: None,
        recipe: RECIPE,
        recipe_digest: "",
        recipe_files: &[],
        functions: &functions,
        extract: false,
        uses_sources: true,
        configured: &configured,
        state: &build.state,
    })
}

#[test]
fn the_gate_holds_a_build_under_an_odd_directory_against_its_record() {
    let download = "d\u{e9}mo 'x' \"1\" back\\slash\ttab\nline \u{65e5}.tar.gz".to_string();
    let build = Tree::new("gate-record-gate", ODD.into(), &download);
    let src = build.src();
    let seen = build.collected();
    assert!(
        seen.upstream().downloads.contains_key(&download),
        "{:?}",
        seen.upstream().downloads
    );
    assert!(
        seen.upstream()
            .seen
            .contains_key(&format!("src/demo/{ODD}.c"))
    );

    with_step(&build, &[], |step| {
        record_extraction(step, &src, &build.collected());
        let record = step.state.extraction().unwrap();
        assert!(record.is_of(&src));
        // The names are kept as they are (the hashes are kept short).
        assert!(record.downloads.keys().eq(seen.upstream().downloads.keys()));
        assert!(record.files.keys().eq(seen.upstream().seen.keys()));
        // The record is this directory's and nothing changed.
        assert_eq!(
            hold_against_extraction(step, &src, &mut build.collected()),
            Ok(Vec::new())
        );
        // A file changed and a file added, under odd names.
        fs::write(src.join(format!("demo/{ODD}.c")), "int odd = 1;\n").unwrap();
        fs::write(src.join("demo/n\u{e9}w.sh"), "#!/bin/sh\n").unwrap();
        let facts = hold_against_extraction(step, &src, &mut build.collected()).unwrap();
        assert!(
            facts[0].contains("2 file(s) in them are new or changed"),
            "{facts:?}"
        );
    });
    // A build that cleans first and finds the directory Guardian made.
    with_step(&build, &["-C"], |step| {
        record_extraction(step, &src, &build.collected());
        let refused = hold_against_extraction(step, &src, &mut build.collected());
        if identity(&src).is_some() {
            assert!(
                refused
                    .unwrap_err()
                    .contains("did not extract the sources into the directory")
            );
        }
    });
    // A download that is not the one Guardian fetched.
    with_step(&build, &[], |step| {
        record_extraction(step, &src, &build.collected());
        fs::write(build.build.join(&download), b"\x1f\x8b\x08\0another").unwrap();
        let refused = hold_against_extraction(step, &src, &mut build.collected()).unwrap_err();
        assert!(
            refused.contains("not the ones Guardian fetched and reviewed")
                && refused.contains(&format!("{download:?}")),
            "{refused}"
        );
    });
    drop(build.dir);
}

#[test]
fn a_name_that_is_not_text_is_never_taken_for_another() {
    // A directory whose name is not UTF-8 is kept with the replacement
    // character, which is also the name another directory can really have.
    let bytes = OsString::from_vec(b"build-\xff".to_vec());
    let build = Tree::new("gate-record-bytes", bytes, "demo.tar.gz");
    let src = build.src();
    let lossy = PathBuf::from(src.to_string_lossy().into_owned());
    assert_ne!(lossy, src);
    with_step(&build, &[], |step| {
        record_extraction(step, &src, &build.collected());
        let record = step.state.extraction().unwrap();
        assert_eq!(Path::new(&record.srcdir), lossy);
        assert!(!record.is_of(&src));
        assert!(!record.is_of(&lossy));
        // As before: no record for this directory.
        let facts = hold_against_extraction(step, &src, &mut build.collected()).unwrap();
        assert!(facts[0].contains("did not extract these sources itself"));
        let facts = hold_against_extraction(step, &lossy, &mut build.collected()).unwrap();
        assert!(facts[0].contains("did not extract these sources itself"));
    });

    // A download or file kept that way never counts as the one extracted.
    let name = "demo-\u{fffd}.tar.gz";
    let extraction = Extraction {
        srcdir: "/x".into(),
        downloads: map(&[(name, &"a".repeat(32))]),
        files: map(&[("src/\u{fffd}", &"b".repeat(32))]),
        ..Extraction::default()
    };
    let read = Extraction::parse(&extraction.to_text()).unwrap();
    assert_eq!(read, extraction);
    assert_eq!(
        read.drift(None, &extraction.downloads, &extraction.files),
        Drift::Downloads(vec![name.into()])
    );
    assert_eq!(
        read.drift(None, &BTreeMap::new(), &extraction.files),
        Drift::Files(HashSet::from(["src/\u{fffd}".to_string()]))
    );
}

const PIECES: &[&str] = &[
    "a",
    "Z",
    "9",
    "/",
    " ",
    "-",
    ".",
    "\u{e9}",
    "'",
    "\"",
    "\\",
    "\n",
    "\r",
    "\t",
    "\u{65e5}",
    "\u{1f600}",
    "\u{0}",
    "\u{7f}",
    "\u{85}",
    "\u{2028}",
    "\\u{e9}",
    "\\n",
    "u{",
    "{",
    "}",
];

/// Pieces that are written as they are.
const PLAIN: &[&str] = &["a", "Z", "9", "/", " ", "-", ".", "_", "+", "~", "{", "}"];

fn generated(rng: &mut Rng, pieces: &[&str]) -> Extraction {
    let digests = ["", "size-10-20-30", &"a".repeat(32), &"0f".repeat(16)];
    let entries = |rng: &mut Rng| -> BTreeMap<String, String> {
        (0..rng.below(6))
            .map(|_| (rng.text(pieces, 12), (*rng.pick(&digests)).to_string()))
            .collect()
    };
    Extraction {
        downloads: entries(rng),
        files: entries(rng),
        srcdir: rng.text(pieces, 20),
        identity: (!rng.chance(4)).then(|| format!("{}:{}:7", rng.below(99), rng.below(99))),
        cleanbuild: rng.chance(2),
    }
}

#[test]
fn any_record_reads_back_as_it_was() {
    let mut rng = Rng::new(41);
    for _ in 0..2000 {
        let extraction = generated(&mut rng, PIECES);
        let text = extraction.to_text();
        assert!(
            text.bytes()
                .all(|byte| byte == b'\n' || (b' '..=b'~').contains(&byte)),
            "{text:?}"
        );
        let read = Extraction::parse(&text);
        assert_eq!(read.as_ref(), Some(&extraction), "{text:?}");
        let read = read.unwrap();
        assert!(read.is_of(Path::new(&extraction.srcdir)), "{text:?}");
        // The same tree: nothing but the files without a hash.
        let hashed = |entries: &BTreeMap<String, String>| -> BTreeMap<String, String> {
            entries
                .iter()
                .filter(|(_, digest)| !digest.is_empty())
                .map(|(path, digest)| (path.clone(), digest.clone()))
                .collect()
        };
        let (downloads, files) = (hashed(&extraction.downloads), hashed(&extraction.files));
        assert_eq!(
            read.drift(Some("x"), &downloads, &files),
            Drift::Files(HashSet::new()),
            "{text:?}"
        );
        // A name that was not extracted is always seen, whatever it is.
        let other = rng.text(PIECES, 12);
        if !extraction.downloads.contains_key(&other) {
            let mut more = downloads.clone();
            more.insert(other.clone(), "a".repeat(32));
            assert_eq!(
                read.drift(Some("x"), &more, &files),
                Drift::Downloads(vec![other]),
                "{text:?}"
            );
        }
    }
}

#[test]
fn a_broken_record_never_panics_and_reads_one_way_only() {
    let mut rng = Rng::new(42);
    let mut read = 0;
    for _ in 0..4000 {
        let extraction = generated(&mut rng, PIECES);
        let text = rng.mutated(&extraction.to_text(), PIECES);
        let Some(parsed) = Extraction::parse(&text) else {
            continue;
        };
        read += 1;
        // What is read is what the text says: each path, written again,
        // is in the text as it stands.
        let line = format!("srcdir {}\n", parsed.srcdir.escape_default());
        assert!(text.starts_with(&line), "{text:?}");
        for path in parsed.downloads.keys().chain(parsed.files.keys()) {
            let end = format!(" {}\n", path.escape_default());
            assert!(text.contains(&end), "{path:?} in {text:?}");
        }
        assert_eq!(
            text.lines().count(),
            3 + parsed.downloads.len() + parsed.files.len(),
            "{text:?}"
        );
    }
    assert!(read > 100, "{read}");
}

#[test]
fn an_escape_the_record_does_not_write_is_rejected() {
    let record = |srcdir: &str, path: &str| {
        format!("srcdir {srcdir}\nidentity -\ncleanbuild 0\nD aa {path}\n")
    };
    assert!(Extraction::parse(&record("/x", "a")).is_some());
    assert!(Extraction::parse(&record("/x\\u{e9}", "a\\\\b\\'\\\"\\t\\r\\n\\u{0}")).is_some());
    for bad in [
        "\\",
        "a\\",
        "\\q",
        "\\0",
        "\\x41",
        "\\u",
        "\\u{",
        "\\u{}",
        "\\u{e9",
        "\\ue9}",
        "\\u{E9}",
        "\\u{00e9}",
        "\\u{+e9}",
        "\\u{ e9}",
        "\\u{41}",
        "\\u{a}",
        "\\u{d800}",
        "\\u{110000}",
        "\\u{ffffffffffffffffffff}",
        "\\u{g}",
        "\\N",
        "caf\u{e9}",
        "tab\there",
        "it's",
        "\"quoted\"",
        "bell\u{7}",
        "line\r",
    ] {
        assert_eq!(Extraction::parse(&record(bad, "a")), None, "{bad:?}");
        assert_eq!(Extraction::parse(&record("/x", bad)), None, "{bad:?}");
    }
    // The record itself: cut short, an unknown line, a path twice.
    for bad in [
        "",
        "srcdir /x\nidentity -\ncleanbuild 0",
        "srcdir /x\nidentity -\ncleanbuild 2\n",
        "srcdir /x\nidentity -\ncleanbuild 1\r\n",
        "srcdir /x\nidentity -\ncleanbuild 0\n\n",
        "srcdir /x\nidentity -\ncleanbuild 0\nD aa\n",
        "srcdir /x\nidentity -\ncleanbuild 0\nX aa a\n",
        "srcdir /x\nidentity -\ncleanbuild 0\nD aa a\nD bb a\n",
        "srcdir /x\nidentity -\ncleanbuild 0\nF aa a\nF aa a\n",
        "identity -\nsrcdir /x\ncleanbuild 0\n",
    ] {
        assert_eq!(Extraction::parse(bad), None, "{bad:?}");
    }

    // On disk, such a record is no record: nothing in it is taken as
    // what Guardian extracted.
    let dir = TempDir::new("gate-record-broken");
    let state = State::open(Some(&dir.path().join("state")), "demo");
    state.record_extraction(&odd_extraction());
    assert!(state.extraction().is_some());
    state.write("extraction", &record("/x", "caf\\u{E9}"));
    assert_eq!(state.extraction(), None);
}

#[test]
fn a_plain_record_is_written_as_it_always_was() {
    // Byte for byte what the version before wrote and reads.
    let text = format!(
        "srcdir /home/user/.cache/yay/demo-git/src\nidentity 66306:1234:1700000000000000000\ncleanbuild 1\nD {a} demo-1.0.tar.gz\nD size-5-6-7 demo-git\nF {b} src/demo-1.0/a file+x~{{1}}.c\nF - src/demo-1.0/unhashed\n",
        a = "a".repeat(32),
        b = "b".repeat(32)
    );
    let extraction = Extraction {
        srcdir: "/home/user/.cache/yay/demo-git/src".into(),
        identity: Some("66306:1234:1700000000000000000".into()),
        cleanbuild: true,
        downloads: map(&[
            ("demo-1.0.tar.gz", &"a".repeat(32)),
            ("demo-git", "size-5-6-7"),
        ]),
        files: map(&[
            ("src/demo-1.0/a file+x~{1}.c", &"b".repeat(32)),
            ("src/demo-1.0/unhashed", ""),
        ]),
    };
    assert_eq!(extraction.to_text(), text);
    assert_eq!(old_text(&extraction), text);
    assert_eq!(Extraction::parse(&text), Some(extraction));

    let mut rng = Rng::new(43);
    for _ in 0..2000 {
        let extraction = generated(&mut rng, PLAIN);
        let old = old_text(&extraction);
        assert_eq!(extraction.to_text(), old);
        assert_eq!(Extraction::parse(&old), Some(extraction));
    }
}

#[test]
fn an_older_record_with_odd_paths_is_still_held_to() {
    // The directory was written once, as now, so the record is found;
    // each odd path was written twice over and reads as another name, so
    // the path itself counts as not extracted, as it did before.
    let extraction = odd_extraction();
    let read = Extraction::parse(&old_text(&extraction)).unwrap();
    assert!(read.is_of(Path::new(&extraction.srcdir)));
    assert_eq!(read.downloads["plain.tar.gz"], "b".repeat(32));
    assert_eq!(
        read.drift(None, &extraction.downloads, &extraction.files),
        Drift::Downloads(vec![format!("{ODD}.tar.gz")])
    );
    let plain = map(&[("plain.tar.gz", &"b".repeat(32))]);
    let Drift::Files(changed) = read.drift(None, &plain, &extraction.files) else {
        panic!("files");
    };
    assert_eq!(changed.len(), extraction.files.len());
}
