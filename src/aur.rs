//! What the AUR gate knows beyond the recipe: how a makepkg call will use
//! the sources, whether those sources are pinned and verified, what the AUR
//! says about the package, and which upstream files run during the build.
//!
//! Parsing and selection are pure functions; the few steps that touch the
//! network or run makepkg live in `cli::makepkg_gate`.

use std::ffi::OsString;
use std::fs;
use std::path::Path;

use crate::json::Json;
use crate::scan::MAX_TEXT_FILE_SIZE;

/// How one makepkg invocation uses the sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Invocation {
    /// Runs PKGBUILD functions that use the sources (prepare, build,
    /// check, package), so upstream code may run.
    pub runs_functions: bool,
    /// Extracts the sources itself (no `--noextract`).
    pub extracts: bool,
}

/// Classifies makepkg's arguments. Calls that only print, download, verify
/// or generate checksums run nothing from the sources.
pub fn classify(args: &[OsString]) -> Invocation {
    let mut info_only = false;
    let mut nobuild = false;
    let mut noprepare = false;
    let mut noextract = false;
    for arg in args {
        let Some(arg) = arg.to_str() else { continue };
        match arg {
            "--packagelist" | "--printsrcinfo" | "--verifysource" | "--geninteg" | "--source"
            | "--allsource" | "--version" | "--help" => info_only = true,
            "--nobuild" => nobuild = true,
            "--noprepare" => noprepare = true,
            "--noextract" => noextract = true,
            _ => {
                if let Some(flags) = arg
                    .strip_prefix('-')
                    .filter(|flags| !flags.starts_with('-'))
                {
                    for flag in flags.chars() {
                        match flag {
                            'g' | 'V' | 'h' => info_only = true,
                            'o' => nobuild = true,
                            'e' => noextract = true,
                            _ => {}
                        }
                    }
                }
            }
        }
    }
    // `--nobuild --noprepare` stops after extracting, before any function.
    let runs_functions = !info_only && (!nobuild || !noprepare);
    Invocation {
        runs_functions,
        extracts: runs_functions && !noextract,
    }
}

/// One `source` entry with the checksums given for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source {
    pub entry: String,
    pub checksums: Vec<String>,
}

/// The sources of `makepkg --printsrcinfo` output, each paired with its
/// checksums of every algorithm, per architecture.
pub fn parse_srcinfo(text: &str) -> Vec<Source> {
    const ALGORITHMS: &[&str] = &[
        "cksums",
        "md5sums",
        "sha1sums",
        "sha224sums",
        "sha256sums",
        "sha384sums",
        "sha512sums",
        "b2sums",
    ];
    // Keys are `source` or `sha256sums`, optionally with `_<arch>`.
    let mut sources: Vec<(String, Vec<String>)> = Vec::new();
    let mut sums: Vec<(String, Vec<String>)> = Vec::new();
    for line in text.lines() {
        let Some((key, value)) = line.trim().split_once(" = ") else {
            continue;
        };
        let (base, arch) = key.split_once('_').unwrap_or((key, ""));
        let push = |list: &mut Vec<(String, Vec<String>)>| {
            let arch = arch.to_string();
            match list.iter_mut().find(|(candidate, _)| *candidate == arch) {
                Some((_, values)) => values.push(value.to_string()),
                None => list.push((arch, vec![value.to_string()])),
            }
        };
        if base == "source" {
            push(&mut sources);
        } else if ALGORITHMS.contains(&base) {
            push(&mut sums);
        }
    }

    let mut result = Vec::new();
    for (arch, entries) in &sources {
        for (index, entry) in entries.iter().enumerate() {
            let checksums = sums
                .iter()
                .filter(|(sum_arch, _)| sum_arch == arch)
                .filter_map(|(_, values)| values.get(index).cloned())
                .collect();
            result.push(Source {
                entry: entry.clone(),
                checksums,
            });
        }
    }
    result
}

/// What the source check found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SourceChecks {
    /// Sources whose content can change after the review: unpinned
    /// repositories and unverified downloads over an encrypted connection.
    pub warnings: Vec<String>,
    /// Unverified downloads over an unencrypted connection: anyone on the
    /// network path can replace them, so the build does not start.
    pub blocking: Vec<String>,
}

/// Sources whose content can differ from what a checksum or a commit pins:
/// code fetched without verification can change after the review, or
/// between one download and the next.
pub fn check_sources(sources: &[Source]) -> SourceChecks {
    let mut checks = SourceChecks::default();
    let warnings = &mut checks.warnings;
    for source in sources {
        let url = source
            .entry
            .split_once("::")
            .map_or(source.entry.as_str(), |(_, url)| url);
        if !url.contains("://") {
            // A file from the AUR repository itself, reviewed with the recipe.
            continue;
        }
        let vcs = ["git+", "git://", "hg+", "svn+", "bzr+", "fossil+"]
            .iter()
            .any(|prefix| url.starts_with(prefix));
        let shown: String = url.chars().take(160).collect();
        if vcs {
            let fragment = url.split_once('#').map_or("", |(_, fragment)| fragment);
            if fragment.starts_with("commit=") || fragment.starts_with("revision=") {
                continue;
            }
            if fragment.starts_with("tag=") {
                warnings.push(format!(
                    "{shown} is pinned to a tag, which its owner can move to other code"
                ));
            } else {
                warnings.push(format!(
                    "{shown} is a repository not pinned to a commit: its code can change after this review"
                ));
            }
        } else if source.checksums.is_empty() || source.checksums.iter().all(|sum| sum == "SKIP") {
            if url.starts_with("http://") || url.starts_with("ftp://") {
                checks.blocking.push(format!(
                    "{shown} is downloaded without a checksum over an unencrypted connection: anyone on the network path can replace it"
                ));
            } else {
                warnings.push(format!(
                    "{shown} is downloaded without a checksum: its content is not verified"
                ));
            }
        }
    }
    checks
}

/// What the AUR says about a package, from `/rpc/v5/info`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AurInfo {
    pub name: String,
    pub first_submitted: u64,
    pub last_modified: u64,
    pub votes: u64,
    pub maintainer: Option<String>,
    pub submitter: Option<String>,
    pub out_of_date: bool,
}

/// The first result of an AUR RPC `info` reply, or `None` when the AUR does
/// not know the package.
pub fn parse_rpc_info(reply: &Json) -> Option<AurInfo> {
    let result = reply.get("results")?.as_array()?.first()?;
    let text = |key: &str| result.get(key).and_then(Json::as_str).map(str::to_string);
    let number = |key: &str| result.get(key).and_then(Json::as_u64).unwrap_or(0);
    Some(AurInfo {
        name: text("Name")?,
        first_submitted: number("FirstSubmitted"),
        last_modified: number("LastModified"),
        votes: number("NumVotes"),
        maintainer: text("Maintainer"),
        submitter: text("Submitter"),
        out_of_date: result.get("OutOfDate").and_then(Json::as_u64).is_some(),
    })
}

const DAY: u64 = 86_400;
/// A package younger than this is new.
const NEW_DAYS: u64 = 30;
/// A package with fewer votes has no track record.
const FEW_VOTES: u64 = 5;

/// Trust signals: `(facts, warnings)`. Facts describe the package for the
/// AI review; warnings are the signals worth the user's attention. New and
/// unvoted packages, and packages recently changed by someone other than
/// their submitter, are how most AUR malware has arrived.
pub fn trust_signals(info: &AurInfo, now: u64) -> (Vec<String>, Vec<String>) {
    let age_days = now.saturating_sub(info.first_submitted) / DAY;
    let changed_days = now.saturating_sub(info.last_modified) / DAY;
    let mut facts = vec![format!(
        "AUR package {}: first submitted {age_days} day(s) ago, last changed {changed_days} day(s) ago, {} vote(s), maintainer {}, submitted by {}.",
        info.name,
        info.votes,
        info.maintainer.as_deref().unwrap_or("none (orphaned)"),
        info.submitter.as_deref().unwrap_or("unknown")
    )];
    let mut warnings = Vec::new();
    if age_days < NEW_DAYS {
        warnings.push(format!(
            "{} was first submitted {age_days} day(s) ago",
            info.name
        ));
    }
    if info.votes < FEW_VOTES {
        warnings.push(format!("{} has {} vote(s)", info.name, info.votes));
    }
    match (&info.maintainer, &info.submitter) {
        (None, _) => warnings.push(format!("{} is orphaned", info.name)),
        (Some(maintainer), Some(submitter)) if maintainer != submitter && changed_days < 14 => {
            warnings.push(format!(
                "{} was changed {changed_days} day(s) ago by {maintainer}, who did not submit it (submitted by {submitter})",
                info.name
            ));
        }
        _ => {}
    }
    if info.out_of_date {
        facts.push(format!("{} is flagged out of date.", info.name));
    }
    (facts, warnings)
}

/// Upstream text that fits one full review; larger sources are reviewed by
/// their build files only.
pub const FULL_REVIEW_BYTES: u64 = 1024 * 1024;
/// The most text sent when a source is reviewed in part: its build files
/// and scripts first, then its other code, shallowest first.
pub const PARTIAL_REVIEW_BYTES: u64 = 1024 * 1024;
const MAX_DEPTH: usize = 16;
const MAX_ENTRIES: usize = 200_000;
/// Scripts deeper than this are not treated as build files.
const SCRIPT_DEPTH: usize = 3;

const SKIPPED_DIRECTORIES: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    ".bzr",
    "node_modules",
    "__pycache__",
    ".venv",
    // Continuous integration and development containers, which do not run
    // during a makepkg build.
    ".github",
    ".gitlab",
    ".circleci",
    ".devcontainer",
];

/// Files that drive or run during a build.
const BUILD_NAMES: &[&str] = &[
    "makefile",
    "gnumakefile",
    "cmakelists.txt",
    "configure",
    "configure.ac",
    "configure.in",
    "meson.build",
    "meson_options.txt",
    "meson.options",
    "build.rs",
    "cargo.toml",
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
    "package.json",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
    "pom.xml",
    "rakefile",
    "build.zig",
    "justfile",
    "sconstruct",
    "build",
    "build.bazel",
    "workspace",
    "taskfile.yml",
    "makefile.am",
];
const BUILD_EXTENSIONS: &[&str] = &["mk", "cmake"];
/// Data and documentation, which neither run nor build anything; left out
/// of the review so the budget goes to code. Build files keep their names
/// (`package.json` is a build file).
const DATA_EXTENSIONS: &[&str] = &[
    "json", "md", "markdown", "rst", "txt", "csv", "tsv", "svg", "po", "pot", "lock", "sum",
    "adoc", "html", "css",
];
const SCRIPT_EXTENSIONS: &[&str] = &["sh", "bash", "zsh", "py", "pl"];

/// One upstream text file, by its path under the build directory's `src/`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamFile {
    pub path: String,
    pub text: String,
    depth: usize,
    build: bool,
}

/// What was taken from the extracted sources for the review.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Upstream {
    pub files: Vec<UpstreamFile>,
    /// Every text file was taken.
    pub whole: bool,
    /// Text files left out (not build files, or past the budget).
    pub left_out: usize,
    /// Text files other than data and documentation.
    pub text_files: usize,
    /// Data and documentation files, not reviewed.
    pub data_files: usize,
}

fn is_build_file(name: &str, depth: usize, text: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let extension = lower
        .rsplit_once('.')
        .map_or("", |(_, extension)| extension);
    BUILD_NAMES.contains(&lower.as_str())
        || BUILD_EXTENSIONS.contains(&extension)
        || extension == "cabal"
        || (depth <= SCRIPT_DEPTH
            && (SCRIPT_EXTENSIONS.contains(&extension) || text.starts_with("#!")))
}

/// Collects upstream code under `src`, without following links. A source
/// whose code fits `FULL_REVIEW_BYTES` is taken whole; otherwise its build
/// files and scripts first, then its other code, up to
/// `PARTIAL_REVIEW_BYTES`.
pub fn collect_upstream(src: &Path) -> Upstream {
    let mut all: Vec<UpstreamFile> = Vec::new();
    let mut pending = vec![(src.to_path_buf(), String::new(), 0_usize)];
    let mut visited = 0;
    let mut skipped_data = 0;
    while let Some((directory, rel, depth)) = pending.pop() {
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        let mut names: Vec<_> = entries.flatten().collect();
        names.sort_by_key(fs::DirEntry::file_name);
        for entry in names {
            visited += 1;
            if visited > MAX_ENTRIES {
                break;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let Ok(metadata) = fs::symlink_metadata(entry.path()) else {
                continue;
            };
            let child = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            if metadata.is_dir() {
                if depth < MAX_DEPTH && !SKIPPED_DIRECTORIES.contains(&name.as_str()) {
                    pending.push((entry.path(), child, depth + 1));
                }
            } else if metadata.is_file() && metadata.len() <= MAX_TEXT_FILE_SIZE {
                let Ok(bytes) = fs::read(entry.path()) else {
                    continue;
                };
                let Ok(text) = String::from_utf8(bytes) else {
                    continue;
                };
                if text.contains('\0') {
                    continue;
                }
                let build = is_build_file(&name, depth, &text);
                let lower = name.to_ascii_lowercase();
                let data = !build
                    && lower
                        .rsplit_once('.')
                        .is_some_and(|(_, extension)| DATA_EXTENSIONS.contains(&extension));
                if data {
                    skipped_data += 1;
                    continue;
                }
                all.push(UpstreamFile {
                    path: format!("src/{child}"),
                    text,
                    depth,
                    build,
                });
            }
        }
    }

    let total: u64 = all.iter().map(|file| file.text.len() as u64).sum();
    let text_files = all.len();
    if total <= FULL_REVIEW_BYTES {
        all.sort_by(|left, right| left.path.cmp(&right.path));
        return Upstream {
            files: all,
            whole: true,
            left_out: 0,
            text_files,
            data_files: skipped_data,
        };
    }

    // Build files and scripts run during the build, so they come first;
    // the rest of the budget goes to the other code, shallowest first.
    all.sort_by(|left, right| {
        right
            .build
            .cmp(&left.build)
            .then(left.depth.cmp(&right.depth))
            .then(left.path.cmp(&right.path))
    });
    let mut taken = Vec::new();
    let mut used = 0_u64;
    for file in all {
        let size = file.text.len() as u64;
        if used + size > PARTIAL_REVIEW_BYTES {
            continue;
        }
        used += size;
        taken.push(file);
    }
    taken.sort_by(|left, right| left.path.cmp(&right.path));
    Upstream {
        left_out: text_files - taken.len(),
        files: taken,
        whole: false,
        text_files,
        data_files: skipped_data,
    }
}

/// What the AI is told about the recipe it reviews in the AUR gate.
pub const RECIPE_SCOPE: &str = "This is an AUR package recipe: the PKGBUILD, install script, \
patches and other files from the package's AUR repository. The upstream sources it downloads \
are fetched and reviewed separately in the next step, before any PKGBUILD function runs, and \
prebuilt binaries or proprietary programs it installs cannot be reviewed by anyone: neither \
their absence nor their being opaque is grounds for inconclusive or a finding by itself. \
Guardian checks and reports itself whether sources are pinned to a commit and verified by a \
checksum; do not report that either. Judge what the recipe itself does: its functions, install \
script and patches, and whether it downloads, runs or installs anything beyond what the \
package needs. Routine packaging is not concerning by itself: installing files into $pkgdir, \
desktop entries, licenses, services and completions, and setuid on the package's own sandbox \
helper.";

/// What the AI is told about upstream files, alongside the facts.
pub const UPSTREAM_SCOPE: &str = "These files are from the upstream source that this AUR package \
downloads and builds (the recipe was reviewed separately). Report only malicious intent, not \
quality. That is: code that runs on this machine during the build (build scripts, makefiles, \
scripts the recipe runs, and the test suite when the recipe runs it) and does something \
harmful, such as downloading or running code the recipe does not declare, writing outside the \
build directory, touching home directories, credentials or keys, or installing persistence; \
or program code with a concealed malicious purpose, such as a backdoor, credential or data \
theft, hidden remote code execution, or an obfuscated payload. Do not report bugs, security \
vulnerabilities, insecure but ordinary practices, test code when the recipe does not run the \
tests, or features that do what the program is for.";

/// Whether a PKGBUILD defines `check()`, which runs the upstream test suite
/// during the build.
pub fn runs_tests(pkgbuild: &str) -> bool {
    pkgbuild.lines().any(|line| {
        let line = line.trim_start();
        let line = line.strip_prefix("function ").unwrap_or(line).trim_start();
        line.strip_prefix("check").is_some_and(|rest| {
            rest.trim_start().starts_with("()")
                || rest.starts_with(' ') && rest.trim_start().starts_with('{')
        })
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;

    use super::{
        AurInfo, Invocation, Source, check_sources, classify, collect_upstream, parse_rpc_info,
        parse_srcinfo, trust_signals,
    };
    use crate::json::Json;
    use crate::test_support::TempDir;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    #[test]
    fn classifies_what_a_makepkg_call_runs() {
        let runs = |list: &[&str]| classify(&args(list));
        // yay's calls: verify sources, extract and prepare, build.
        assert!(!runs(&["--verifysource", "--skippgpcheck", "-f", "-Cc"]).runs_functions);
        assert_eq!(
            runs(&["--nobuild", "-fC", "--ignorearch"]),
            Invocation {
                runs_functions: true,
                extracts: true
            }
        );
        assert_eq!(
            runs(&[
                "-cf",
                "--noconfirm",
                "--noextract",
                "--noprepare",
                "--holdver"
            ]),
            Invocation {
                runs_functions: true,
                extracts: false
            }
        );
        assert!(!runs(&["--packagelist"]).runs_functions);
        assert!(!runs(&["-g"]).runs_functions);
        assert!(!runs(&["--nobuild", "--noprepare"]).runs_functions);
        assert!(runs(&["-si"]).extracts);
        assert!(!runs(&["-se"]).extracts);
    }

    const SRCINFO: &str = "\
pkgbase = demo
\tpkgver = 1.0
\tsource = demo-1.0.tar.gz::https://example.org/demo-1.0.tar.gz
\tsource = patches::git+https://github.com/someone/patches.git
\tsource = pinned::git+https://example.org/p.git#commit=abc123
\tsource = tagged::git+https://example.org/t.git#tag=v1
\tsource = fix.patch
\tsource = http://example.org/unsigned.bin
\tsha256sums = 1111
\tsha256sums = SKIP
\tsha256sums = SKIP
\tsha256sums = SKIP
\tsha256sums = 2222
\tsha256sums = SKIP
\tsource_x86_64 = https://example.org/demo-x86_64.bin
\tsha256sums_x86_64 = 3333

pkgname = demo
";

    #[test]
    fn warns_about_unpinned_and_unverified_sources() {
        let sources = parse_srcinfo(SRCINFO);
        assert_eq!(sources.len(), 7);
        assert_eq!(
            sources[6],
            Source {
                entry: "https://example.org/demo-x86_64.bin".into(),
                checksums: vec!["3333".into()]
            }
        );
        let checks = check_sources(&sources);
        assert_eq!(checks.warnings.len(), 2, "{checks:#?}");
        assert!(checks.warnings[0].contains("patches.git is a repository not pinned to a commit"));
        assert!(checks.warnings[1].contains("pinned to a tag"));
        assert_eq!(checks.blocking.len(), 1, "{checks:#?}");
        assert!(checks.blocking[0].contains("unsigned.bin is downloaded without a checksum over"));
    }

    const NOW: u64 = 1_790_000_000;

    fn info(age_days: u64, votes: u64, maintainer: Option<&str>) -> AurInfo {
        AurInfo {
            name: "demo".into(),
            first_submitted: NOW - age_days * 86_400,
            last_modified: NOW - 86_400,
            votes,
            maintainer: maintainer.map(str::to_string),
            submitter: Some("alice".into()),
            out_of_date: false,
        }
    }

    #[test]
    fn trust_signals_flag_new_unvoted_orphaned_and_adopted_packages() {
        let (facts, warnings) = trust_signals(&info(400, 250, Some("alice")), NOW);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert!(facts[0].contains("first submitted 400 day(s) ago"));

        let (_, warnings) = trust_signals(&info(2, 0, Some("alice")), NOW);
        assert_eq!(warnings.len(), 2, "{warnings:?}");

        let (_, warnings) = trust_signals(&info(400, 250, None), NOW);
        assert_eq!(warnings, ["demo is orphaned"]);

        let (_, warnings) = trust_signals(&info(400, 250, Some("mallory")), NOW);
        assert!(warnings[0].contains("changed 1 day(s) ago by mallory, who did not submit it"));
    }

    #[test]
    fn finds_whether_the_recipe_runs_the_tests() {
        use super::runs_tests;
        assert!(runs_tests(
            "build() {\n  make\n}\ncheck() {\n  make test\n}\n"
        ));
        assert!(runs_tests("function check {\n  true\n}\n"));
        assert!(!runs_tests(
            "build() {\n  make check_all\n}\n# check() is not needed\n"
        ));
    }

    #[test]
    fn parses_the_aur_rpc_reply() {
        let reply = Json::parse(
            r#"{"resultcount":1,"results":[{"Name":"yay","FirstSubmitted":1475688004,"LastModified":1727000000,"NumVotes":2300,"Maintainer":"jguer","Submitter":"jguer","OutOfDate":null}],"type":"multiinfo","version":5}"#,
        )
        .unwrap();
        let parsed = parse_rpc_info(&reply).unwrap();
        assert_eq!(parsed.votes, 2300);
        assert_eq!(parsed.maintainer.as_deref(), Some("jguer"));
        assert!(!parsed.out_of_date);
        let none = Json::parse(r#"{"resultcount":0,"results":[]}"#).unwrap();
        assert_eq!(parse_rpc_info(&none), None);
    }

    #[test]
    fn small_sources_are_taken_whole_and_large_ones_by_build_files() {
        let dir = TempDir::new("upstream");
        let src = dir.path().join("src");
        fs::create_dir_all(src.join("demo/lib")).unwrap();
        fs::create_dir_all(src.join("demo/.git")).unwrap();
        fs::write(src.join("demo/Makefile"), "all:\n\tcc main.c\n").unwrap();
        fs::write(src.join("demo/main.c"), "int main(void) { return 0; }\n").unwrap();
        fs::write(src.join("demo/.git/config"), "[core]\n").unwrap();
        fs::write(src.join("demo/index.json"), "{}\n").unwrap();
        fs::write(src.join("demo/package.json"), "{\"scripts\":{}}\n").unwrap();
        fs::write(src.join("demo/logo.png"), [0_u8, 159, 146, 150]).unwrap();

        let small = collect_upstream(&src);
        assert!(small.whole);
        let paths: Vec<&str> = small.files.iter().map(|file| file.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "src/demo/Makefile",
                "src/demo/main.c",
                "src/demo/package.json"
            ]
        );
        assert_eq!(small.data_files, 1);

        // Past the whole-review size: build files first, then shallow code
        // until the budget, leaving out what does not fit.
        fs::write(src.join("demo/lib/big.c"), "x".repeat(1_100_000)).unwrap();
        fs::write(src.join("demo/install.sh"), "#!/bin/sh\necho hi\n").unwrap();
        let large = collect_upstream(&src);
        assert!(!large.whole);
        let paths: Vec<&str> = large.files.iter().map(|file| file.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "src/demo/Makefile",
                "src/demo/install.sh",
                "src/demo/main.c",
                "src/demo/package.json"
            ]
        );
        assert_eq!(large.left_out, 1);
    }
}
