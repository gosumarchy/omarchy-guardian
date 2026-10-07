//! `omarchy-guardian makepkg-gate -- <makepkg> [args...]`, run by the yay
//! makepkg shim in the AUR build directory. Beyond `guard` on the recipe it:
//!
//! 1. refuses a recipe that moves makepkg's build or download directories,
//!    and establishes whether the directory is a clone of an AUR package,
//!    whose trust signals (new, unvoted, orphaned, recently changed by
//!    someone other than its submitter) then go to the AI review as facts;
//! 2. reviews the recipe (PKGBUILD, install script, patches) as before;
//! 3. for a call that runs PKGBUILD functions, has makepkg list the
//!    recipe's sources and then fetch and extract them, both in a jail (see
//!    `sandbox::FetchJail`). The listing sources the recipe, which can run
//!    anything at its top level, so it gets no network and nothing to write
//!    to. The fetch does not run the recipe at all: makepkg is given a
//!    recipe Guardian writes from that listing, holding the sources and
//!    their checksums and no code. No upstream code runs before its review,
//!    and what is reviewed is what makepkg itself extracted. Unverified or
//!    unpinned sources are reported, sources anyone on the network can
//!    replace block, and the AI reviews what runs during the build;
//! 4. checks the recipe once more and starts makepkg with the original
//!    arguments, plus `--holdver` after a pre-extraction so the build does
//!    not fetch newer VCS sources than were reviewed, and the build and
//!    download directories pinned to the configured ones.
//!
//! The listing in step 3 is only as good as the recipe is the same in the
//! jail and in the build, and a recipe can tell the two apart. So the gate
//! also reads how the recipe arrives at its sources (`aur::recipe`): written
//! out, they must be what the listing gave; set where Guardian cannot
//! follow, the user is asked. What the gate extracted is remembered
//! (`state`), and a later call for the same build (`--noextract`) is held
//! against it. A build of prebuilt programs, which no one can review, needs
//! the user's yes as well.

mod confirm;
mod jail;
mod permits;
mod rpc;
mod sources;
mod state;
mod unpack;
mod upstream;

use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use self::confirm::{
    Followed, Prebuilt, all_binaries, binary_changes, confirm_not_followed, followed, prebuilt,
};
use self::jail::{home, pre_extract, probe};
use self::permits::{
    only_downloads, recipe_contents, recipe_digest, recipe_files, settle_upstream, upstream_content,
};
use self::rpc::aur_facts;
use self::sources::{download_names, fetch_refusal, source_context};
use self::state::{Drift, Extraction, Kept, State};
use self::upstream::{review_upstream_files, unreviewable_sources};
use crate::audit::{self, Gate};
use crate::aur::recipe::{self, Sources};
use crate::aur::{self, Roots, Upstream};
use crate::cli::{Confirm, Target, TtyConfirm, Verdict, passed, review_and_decide};
use crate::config::Settings;
use crate::config::model::SourceClass;
use crate::engine::baseline::{Identity, Unit};
use crate::engine::store::Store;
use crate::error::Error;
use crate::notify::{self, Ran};
use crate::report::{Blocked, Decision};
use crate::rules;
use crate::sandbox::{self, FetchJail};
use crate::scan::{self, ScanConfig, Snapshot};
use crate::sha256::Sha256;
use crate::tools::{self, Limits, OpenCode};

#[cfg(test)]
use self::confirm::confirm_prebuilt;
#[cfg(test)]
use self::jail::{is_jailable, listing_recipe, listing_report, public_keyring, with_mounts};
#[cfg(test)]
use self::permits::{asked_under_permit, permittable};
#[cfg(test)]
use self::sources::{foreign_checkout, is_plain_mirror, misnamed_source};
#[cfg(test)]
use self::upstream::{upstream_facts, upstream_runs, upstream_summary};

const SRCINFO_LIMITS: Limits = Limits {
    timeout_secs: 60,
    max_output: 4 * 1024 * 1024,
};

/// Flags a Guardian makepkg run mirrors from the original call, so it
/// verifies and extracts the sources the way the build will.
const MIRRORED_FLAGS: &[&str] = &[
    "--skippgpcheck",
    "--skipchecksums",
    "--skipinteg",
    "--ignorearch",
    "--holdver",
    "--cleanbuild",
];
/// Short flags mirrored out of a cluster like `-fCA`.
const MIRRORED_SHORT: &[char] = &['A', 'C'];

/// Scalars and arrays of a source listing that a fetch needs, besides the
/// sources and their checksums.
const FETCH_SCALARS: &[&str] = &["pkgver", "pkgrel", "epoch"];
const FETCH_ARRAYS: &[&str] = &["arch", "noextract", "validpgpkeys"];

/// A pacman package name: what a `pkgbase` may be used as a path part for.
fn is_package_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with(['-', '.'])
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "@._+-".contains(character))
}

/// The `pkgbase` of a `makepkg --printsrcinfo` listing.
fn listed_pkgbase(srcinfo: &str) -> Option<&str> {
    srcinfo
        .lines()
        .find_map(|line| line.trim().strip_prefix("pkgbase = "))
        .filter(|name| is_package_name(name))
}

/// A recipe that fetches what `srcinfo` lists and does nothing else: the
/// version, the sources with their checksums, what not to extract and the
/// signing keys, each value quoted, and no code of the listed recipe.
/// makepkg run on it downloads, verifies and extracts exactly as it would
/// for that recipe, into the same `src/`. `None` without a usable `pkgbase`.
fn fetch_recipe(srcinfo: &str) -> Option<String> {
    let pkgbase = listed_pkgbase(srcinfo)?;
    let quoted = |value: &str| format!("'{}'", value.replace('\'', "'\\''"));
    let mut scalars: Vec<(&str, &str)> = Vec::new();
    let mut arrays: Vec<(&str, Vec<&str>)> = Vec::new();
    // Per-package sections follow the first `pkgname`; sources are not there.
    for line in srcinfo
        .lines()
        .take_while(|line| !line.starts_with("pkgname = "))
    {
        let Some((key, value)) = line.trim().split_once(" = ") else {
            continue;
        };
        let base = key.split_once('_').map_or(key, |(base, _)| base);
        // A key becomes a variable name, unquoted.
        let named = key.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        });
        if FETCH_SCALARS.contains(&key) {
            scalars.push((key, value));
        } else if named
            && (FETCH_ARRAYS.contains(&key) || base == "source" || aur::CHECKSUMS.contains(&base))
        {
            match arrays.iter_mut().find(|(name, _)| *name == key) {
                Some((_, values)) => values.push(value),
                None => arrays.push((key, vec![value])),
            }
        }
    }
    let mut recipe = format!("pkgbase={0}\npkgname=({0})\n", quoted(pkgbase));
    for (key, value) in scalars {
        let _ = writeln!(recipe, "{key}={}", quoted(value));
    }
    for (key, values) in arrays {
        let values: Vec<String> = values.into_iter().map(quoted).collect();
        let _ = writeln!(recipe, "{key}=({})", values.join(" "));
    }
    recipe.push_str("package() { :; }\n");
    Some(recipe)
}

/// Asks at the terminal, and notes when there was none to ask on: that is
/// a no the user never gave, and never saw being asked for.
struct Asker {
    path: &'static str,
    missing: bool,
}

impl Asker {
    const fn new() -> Self {
        Self {
            path: "/dev/tty",
            missing: false,
        }
    }

    /// Says that a question went unasked, on the terminal's stand-in and
    /// on the desktop: a build started from a graphical front end or a
    /// timer shows nothing else of it.
    fn say_if_missing(&self, name: &str, ran: Ran) {
        if self.missing {
            errln!("{NO_TERMINAL}.");
            notify::blocked(&subject(name), NO_TERMINAL, ran);
        }
    }
}

const NO_TERMINAL: &str =
    "Guardian needed to ask you something and found no terminal: run this build from a terminal";

impl Confirm for Asker {
    fn confirm(&mut self, question: &str) -> bool {
        let reachable = OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.path)
            .is_ok();
        if !reachable {
            self.missing = true;
            return false;
        }
        TtyConfirm.confirm(question)
    }
}

pub(crate) fn run(command: &[OsString], settings: &Settings) -> ExitCode {
    // makepkg's standard output is makepkg's: the helper that called it
    // reads the package list and the source listing from it.
    crate::output::leave_stdout_to_the_command();
    let Some((makepkg, arguments)) = command.split_first() else {
        errln!("omarchy-guardian makepkg-gate: no makepkg command was given");
        return ExitCode::from(2);
    };
    let mirrored = match mirrored_arguments(arguments) {
        Ok(mirrored) => mirrored,
        Err(message) => {
            errln!("Guardian makepkg gate: {message}");
            return ExitCode::from(2);
        }
    };
    let build_dir = match env::current_dir().and_then(|dir| dir.canonicalize()) {
        Ok(dir) => dir,
        Err(error) => {
            errln!("omarchy-guardian makepkg-gate: cannot use the working directory: {error}");
            return ExitCode::from(2);
        }
    };
    let Ok(recipe) = fs::read_to_string(build_dir.join("PKGBUILD")) else {
        errln!("Guardian makepkg gate requires a readable PKGBUILD in the working directory.");
        return ExitCode::from(2);
    };
    remove_stale_copies(&build_dir);
    let directory_name = build_dir
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default()
        .to_string();

    // 1. A recipe that moves where makepkg works escapes the review.
    if let Some(exit) = refuse_moved_directories(&recipe, &directory_name) {
        return exit;
    }
    let git_config = fs::read_to_string(build_dir.join(".git/config")).unwrap_or_default();
    let base = aur::aur_identity(&directory_name, &git_config);
    let facts = aur_facts(base.as_deref(), &directory_name, &recipe);
    let key = base.clone().unwrap_or_else(|| local_key(&build_dir));
    let state = State::open(Store::default_root().as_deref(), &key);

    // 2. The recipe.
    let target = recipe_target(&build_dir, &key, base.is_some());
    let recipe_context = recipe_context(&facts, &recipe);
    let mut terminal = Asker::new();
    let verdict = match review_recipe(&target, settings, &recipe_context, &recipe, &mut terminal) {
        Ok(verdict) => verdict,
        Err(exit) => return exit,
    };
    let report = &verdict.report;
    let recipe_digest = recipe_digest(&report.snapshot, &written_downloads(&recipe));
    let recipe_files = recipe_files(&report.snapshot);

    // 3. The upstream sources, for a call that runs PKGBUILD functions.
    let invocation = aur::classify(arguments);
    let mut pinned: Option<Dirs> = None;
    let mut downloads: Vec<String> = Vec::new();
    if invocation.runs_functions {
        let read = Configured::read();
        let Ok(configured) = read.map_err(|error| errln!("Guardian blocked makepkg: {error}."))
        else {
            return ExitCode::from(2);
        };
        let functions = recipe_functions(&build_dir, &recipe);
        let step = UpstreamStep {
            makepkg: Path::new(makepkg),
            mirrored: &mirrored,
            build_dir: &build_dir,
            name: &directory_name,
            key: &key,
            base: base.as_deref(),
            recipe: &recipe,
            recipe_digest: &recipe_digest,
            recipe_files: &recipe_files,
            functions: &functions,
            extract: invocation.extracts,
            uses_sources: invocation.uses_sources,
            configured: &configured,
            state: &state,
        };
        match upstream_step(&step, settings, facts, &mut terminal) {
            Ok(outcome) => {
                downloads = outcome.downloads;
                pinned = Some(outcome.dirs);
            }
            Err(exit) => return exit,
        }
    }

    // 4. The build: the recipe must be exactly what was reviewed.
    if let Err(error) = verify_recipe(&target.config, &report.snapshot, &downloads) {
        errln!("Guardian blocked makepkg because {error}.");
        let ran = if invocation.runs_functions {
            Ran::RecipeToFetch
        } else {
            Ran::Nothing
        };
        audit::refused(Gate::Aur, &format!("{}: {error}", target.subject()), 2);
        notify::blocked(&subject(&directory_name), &error.to_string(), ran);
        return ExitCode::from(2);
    }
    errln!(
        "Guardian: {}; starting {}",
        passed(&verdict),
        Path::new(makepkg).display()
    );
    start_build(Path::new(makepkg), arguments, invocation.extracts, pinned)
}

/// The top-level names makepkg downloads into the build directory, as far
/// as the recipe writes its sources out: files that are not there when a
/// build is first reviewed and are there at every call after.
fn written_downloads(recipe: &str) -> Vec<String> {
    let Sources::Written(arrays) = recipe::sources(recipe) else {
        return Vec::new();
    };
    arrays
        .iter()
        .filter(|(name, _)| name == "source" || name.starts_with("source_"))
        .flat_map(|(_, entries)| entries)
        .filter(|entry| aur::source_protocol(entry) != "local")
        .map(|entry| aur::source_filename(entry))
        .filter(|name| !name.is_empty() && name != "PKGBUILD")
        .collect()
}

/// Reviews the recipe in `target`. `Err` is the exit code of a gate that
/// goes no further: the review did not allow it and no permit of the
/// user's overrules it, or the recipe changed meanwhile.
fn review_recipe(
    target: &Target,
    settings: &Settings,
    context: &[String],
    recipe: &str,
    terminal: &mut Asker,
) -> Result<Verdict, ExitCode> {
    let name = target
        .config
        .root
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default();
    let verdict = review_and_decide(
        target,
        settings,
        &OpenCode::UserPath,
        Some(terminal),
        context,
        Gate::Aur,
        Some(&|report| recipe_contents(target, &report.snapshot, recipe)),
    );
    if !verdict.allows_running() {
        errln!("Guardian blocked makepkg because the review of the recipe did not allow it.");
        verdict.standing.say();
        terminal.say_if_missing(name, Ran::Nothing);
        notify_block(name, verdict.decision, "the recipe", Ran::Nothing);
        return Err(verdict.decision.exit_code());
    }
    if let Err(error) = scan::verify_unchanged(&target.config, &verdict.report.snapshot) {
        errln!("Guardian blocked makepkg because {error}.");
        audit::refused(Gate::Aur, &format!("{}: {error}", target.subject()), 2);
        notify::blocked(&subject(name), &error.to_string(), Ran::Nothing);
        return Err(ExitCode::from(2));
    }
    Ok(verdict)
}

/// What the AI is told beside the recipe it reviews: the scope, the AUR's
/// facts, and, when Guardian cannot follow how the recipe sets its sources,
/// that it cannot. That review reads the very code that could tell a
/// listing from a build.
fn recipe_context(facts: &[String], recipe: &str) -> Vec<String> {
    let mut context = vec![aur::RECIPE_SCOPE.to_string()];
    context.extend(facts.iter().cloned());
    if matches!(recipe::sources(recipe), Sources::NotFollowed(_)) {
        context.push(NOT_FOLLOWED_FACT.to_string());
    }
    context
}

/// Refuses a recipe that assigns makepkg's path variables.
fn refuse_moved_directories(recipe: &str, directory_name: &str) -> Option<ExitCode> {
    let moved = aur::path_variable_assignments(recipe);
    if moved.is_empty() {
        return None;
    }
    errln!(
        "Guardian blocked makepkg: the PKGBUILD sets makepkg's own directories, which moves the sources past the review:"
    );
    for line in &moved {
        errln!("  ! {line}");
    }
    notify::blocked(
        &subject(directory_name),
        "the PKGBUILD moves makepkg's build or download directories",
        Ran::Nothing,
    );
    audit::refused(
        Gate::Aur,
        &format!("{directory_name}: the PKGBUILD moves makepkg's directories"),
        1,
    );
    Some(ExitCode::from(1))
}

/// A review-memory key for a build directory that is not an AUR clone.
fn local_key(build_dir: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(build_dir.as_os_str().as_encoded_bytes());
    let digest = hasher.finalize().to_string();
    format!("local:{}", &digest[..16])
}

/// Replaces this process with makepkg: the original arguments, plus
/// `--holdver` after a pre-extraction (the build must not fetch different
/// code than was reviewed), with the configured directories pinned.
fn start_build(
    makepkg: &Path,
    arguments: &[OsString],
    extracted: bool,
    pinned: Option<Dirs>,
) -> ExitCode {
    let mut arguments = arguments.to_vec();
    if extracted && !arguments.iter().any(|arg| arg == "--holdver") {
        arguments.push("--holdver".into());
    }
    drop(io::stdout().flush());
    let mut build = Command::new(makepkg);
    build.args(&arguments);
    if let Some(dirs) = pinned {
        build.env("BUILDDIR", &dirs.builddir);
        build.env("SRCDEST", &dirs.srcdest);
    }
    let error = build.exec();
    errln!("Could not start {}: {error}", makepkg.display());
    ExitCode::from(2)
}

fn recipe_target(build_dir: &Path, key: &str, aur: bool) -> Target {
    let identity = Identity::parse(&if aur {
        format!("aur:{key}")
    } else {
        key.to_string()
    })
    .ok();
    Target {
        config: ScanConfig {
            root: build_dir.to_path_buf(),
            include_ignored_dirs: true,
            excluded_top_level: vec!["src".into(), "pkg".into()],
            excluded_entries: Vec::new(),
            limits: scan::Limits::DEFAULT,
        },
        show_hashes: false,
        class: SourceClass::Aur,
        profile: None,
        units: identity
            .map(|identity| {
                vec![Unit {
                    prefix: String::new(),
                    identity,
                }]
            })
            .unwrap_or_default(),
        state_root: Store::default_root(),
    }
}

/// Whether `text` is a long option the gate cannot go along with, in a
/// form the exact match above does not see: `--file` or `--dir` with their
/// value attached (`--dir=/x`), or any of them and `--config` shortened,
/// which makepkg takes as that option.
fn is_abbreviated(text: &str) -> bool {
    let name = text.split('=').next().unwrap_or(text);
    name.len() > 2
        && (["--file", "--dir"]
            .iter()
            .any(|option| option.starts_with(name))
            || ("--config".starts_with(name) && name != "--config"))
}

/// The arguments every Guardian makepkg run mirrors from the call:
/// `MIRRORED_FLAGS` (also out of short clusters like `-fCA`), `--config
/// <file>`, and makepkg's trailing `NAME=value` settings. A call that picks
/// another recipe or directory (`-p`, `-D`) is refused.
fn mirrored_arguments(arguments: &[OsString]) -> Result<Vec<OsString>, String> {
    let unsupported = |text: &str| {
        format!("{text} is not supported: the gate reviews the PKGBUILD in the working directory")
    };
    let mut mirrored = Vec::new();
    let mut iter = arguments.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.to_str() else {
            return Err(format!(
                "an argument is not UTF-8: {}",
                arg.to_string_lossy()
            ));
        };
        match text {
            "-p" | "--file" | "-D" | "--dir" => return Err(unsupported(text)),
            "--config" => {
                let file = iter.next().ok_or("--config needs a file")?;
                mirrored.extend(["--config".into(), file.clone()]);
            }
            _ if text.starts_with("--config=") || MIRRORED_FLAGS.contains(&text) => {
                mirrored.push(arg.clone());
            }
            // makepkg takes a long option by any unambiguous beginning:
            // `--fil x` is `--file x`.
            _ if is_abbreviated(text) => return Err(unsupported(text)),
            _ if text.starts_with("--") => {}
            _ if text.starts_with('-') => {
                let cluster = &text[1..];
                if cluster.contains(['p', 'D']) {
                    return Err(unsupported(text));
                }
                for flag in cluster.chars().filter(|flag| MIRRORED_SHORT.contains(flag)) {
                    mirrored.push(format!("-{flag}").into());
                }
            }
            _ if is_setting(text) => mirrored.push(arg.clone()),
            _ => {}
        }
    }
    Ok(mirrored)
}

/// makepkg's own `NAME=value` argument pattern.
fn is_setting(text: &str) -> bool {
    let Some((name, _)) = text.split_once('=') else {
        return false;
    };
    let name = name.strip_suffix('+').unwrap_or(name);
    let mut characters = name.chars();
    characters
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

/// A crashed run's hidden recipe copy, or what it unpacked for review,
/// must not linger in the recipe.
fn remove_stale_copies(build_dir: &Path) {
    unpack::remove_stale(build_dir);
    let Ok(entries) = fs::read_dir(build_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(".guardian-") && name.ends_with(".PKGBUILD") {
            drop(fs::remove_file(entry.path()));
        }
    }
}

struct UpstreamStep<'a> {
    makepkg: &'a Path,
    mirrored: &'a [OsString],
    build_dir: &'a Path,
    name: &'a str,
    /// The review-memory key: the AUR package base, or a local key.
    key: &'a str,
    /// The confirmed AUR package base.
    base: Option<&'a str>,
    recipe: &'a str,
    /// The recipe as reviewed, in one SHA-256 (see `recipe_digest`).
    recipe_digest: &'a str,
    /// The recipe's other files as reviewed (see `recipe_files`).
    recipe_files: &'a [(String, String)],
    /// The recipe's files whose commands run during the build or install.
    functions: &'a Functions,
    /// The call extracts the sources itself, so they are extracted here
    /// first, without running any PKGBUILD function.
    extract: bool,
    /// The call goes on to use the sources (see `aur::Invocation`).
    uses_sources: bool,
    configured: &'a Configured,
    state: &'a State,
}

/// The most install scripts read beside a PKGBUILD; a recipe has one for
/// each of its packages at most.
const MAX_INSTALL_SCRIPTS: usize = 64;

/// The recipe's own code as the build and the install run it: the PKGBUILD
/// and its install scripts, with the variables the PKGBUILD writes out
/// plainly, so that `./$_tool` is read as the file it runs.
struct Functions {
    /// Each file by its name, with its text.
    files: Vec<(String, String)>,
    variables: Vec<(String, String)>,
    /// All of them as one text with the variables put in: what names a
    /// file of the sources.
    written: String,
    /// Install scripts that were not read: past the most that are, too
    /// large, or not plain files.
    unread: usize,
}

fn recipe_functions(build_dir: &Path, recipe: &str) -> Functions {
    let mut files = vec![("PKGBUILD".to_string(), recipe.to_string())];
    let mut scripts: Vec<PathBuf> = fs::read_dir(build_dir)
        .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
        .unwrap_or_default();
    scripts.sort();
    let mut unread = 0;
    for path in scripts {
        if path
            .extension()
            .is_none_or(|extension| extension != "install")
        {
            continue;
        }
        let plain = fs::symlink_metadata(&path)
            .is_ok_and(|found| found.is_file() && found.len() <= scan::MAX_TEXT_FILE_SIZE);
        if files.len() <= MAX_INSTALL_SCRIPTS
            && plain
            && let Ok(text) = fs::read_to_string(&path)
        {
            let name = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned());
            files.push((name.unwrap_or_default(), text));
        } else {
            unread += 1;
        }
    }
    let variables = recipe::written_variables(recipe);
    let written = files
        .iter()
        .map(|(_, text)| rules::with_variables(text, &variables))
        .collect::<Vec<_>>()
        .join("\n");
    Functions {
        files,
        variables,
        written,
        unread,
    }
}

/// Where makepkg builds and keeps downloads for a recipe: the configured
/// directories, or the recipe's own.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Dirs {
    builddir: PathBuf,
    srcdest: PathBuf,
    pkgbase: String,
    startdir: PathBuf,
}

impl Dirs {
    /// `srcdir` exactly as makepkg computes it.
    fn srcdir(&self) -> PathBuf {
        let builddir = fs::canonicalize(&self.builddir).ok();
        if builddir.is_some() && builddir == fs::canonicalize(&self.startdir).ok() {
            self.builddir.join("src")
        } else {
            self.builddir.join(&self.pkgbase).join("src")
        }
    }
}

/// Where the user's own makepkg configuration and environment put the
/// build and the downloads, before any recipe is read. Only these, and the
/// recipe's directory, are writable while Guardian fetches the sources.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Configured {
    builddir: Option<PathBuf>,
    srcdest: Option<PathBuf>,
}

/// Loads makepkg's configuration the way makepkg does and prints the two
/// directories. Fixed text; the configuration is the user's own.
const CONFIGURED_SCRIPT: &str = "source /usr/share/makepkg/util/message.sh && \
source /usr/share/makepkg/util/util.sh && source /usr/share/makepkg/util/config.sh && \
load_makepkg_config && printf '%s\\0%s\\0' \"$BUILDDIR\" \"$SRCDEST\"";

impl Configured {
    fn read() -> Result<Self, Error> {
        let output = tools::run(
            Path::new("/usr/bin/bash"),
            &["-c".into(), CONFIGURED_SCRIPT.into()],
            None,
            &[],
            SRCINFO_LIMITS,
        )?
        .into_success()?;
        Self::parse(&output)
            .ok_or_else(|| Error::Refused("makepkg's configuration could not be read".into()))
    }

    fn parse(output: &[u8]) -> Option<Self> {
        let text = str::from_utf8(output).ok()?;
        let mut fields = text.split('\0');
        let mut directory = || {
            let field = fields.next()?;
            Some((!field.is_empty()).then(|| PathBuf::from(field)))
        };
        Some(Self {
            builddir: directory()?,
            srcdest: directory()?,
        })
    }

    /// Where makepkg settles for the recipe in `build_dir`: unset, both
    /// directories are the recipe's own.
    fn dirs(&self, build_dir: &Path, pkgbase: &str) -> Dirs {
        let or_recipe = |configured: &Option<PathBuf>| {
            configured
                .clone()
                .unwrap_or_else(|| build_dir.to_path_buf())
        };
        Dirs {
            builddir: or_recipe(&self.builddir),
            srcdest: or_recipe(&self.srcdest),
            pkgbase: pkgbase.to_string(),
            startdir: build_dir.to_path_buf(),
        }
    }
}

struct UpstreamOutcome {
    dirs: Dirs,
    /// Top-level names makepkg downloads into the build directory.
    downloads: Vec<String>,
}

/// How much upstream code the AI may be sent: the AUR class's input limit
/// times its chunks, and at least a partial review's worth.
fn upstream_budget(settings: &Settings) -> u64 {
    let aur = settings.agent_settings(SourceClass::Aur);
    u64::try_from(aur.max_input_bytes.saturating_mul(aur.max_chunks))
        .unwrap_or(u64::MAX)
        .max(aur::PARTIAL_REVIEW_BYTES)
}

/// The fact the AI is given about a recipe whose sources are not followed.
const NOT_FOLLOWED_FACT: &str = "Guardian established that this recipe sets its sources, their \
checksums or makepkg's directories where Guardian cannot follow (under a condition, in a \
function, through eval or a command that assigns). Guardian fetches and reviews the sources the \
recipe lists in a sandbox without network; the build loads the recipe again and may arrive at \
others. Weigh whether the recipe's top-level code can tell the two apart or act on it.";

/// The most changed binaries named one by one.
const MAX_BINARIES_NAMED: usize = 8;

/// Unpacks the archives the recipe opens itself, each in the jail, and
/// takes their files into what is collected. One that cannot be unpacked
/// leaves the review incomplete.
fn unpack_archives(
    step: &UpstreamStep<'_>,
    srcdir: &Path,
    roots: &Roots<'_>,
    collected: &mut aur::Collected,
) -> Option<unpack::Scratch> {
    let mut scratch: Option<unpack::Scratch> = None;
    loop {
        let archives = collected.to_unpack();
        if archives.is_empty() {
            return scratch;
        }
        for archive in archives {
            let unpacked = unpack_one(step, srcdir, &archive.file, &mut scratch);
            match unpacked {
                Ok(directory) => {
                    errln!(
                        "Guardian: unpacked src/{} for review (the recipe opens it itself).",
                        archive.rel
                    );
                    collected.add_unpacked(&archive, &directory, roots, &step.functions.written);
                }
                Err(why) => collected.not_unpacked(&archive, &why),
            }
        }
    }
}

fn unpack_one(
    step: &UpstreamStep<'_>,
    srcdir: &Path,
    archive: &Path,
    scratch: &mut Option<unpack::Scratch>,
) -> Result<PathBuf, String> {
    if scratch.is_none() {
        let beside = srcdir.parent().unwrap_or(srcdir);
        *scratch = Some(unpack::Scratch::create(beside)?);
    }
    let into = scratch
        .as_mut()
        .ok_or("no directory to unpack into")?
        .next()?;
    let home = home().map_err(|error| error.to_string())?;
    let archive = fs::canonicalize(archive).map_err(|error| error.to_string())?;
    let mut jail: Vec<OsString> = vec![tools::BWRAP.into()];
    jail.extend(sandbox::fetch_jail(&FetchJail {
        home: &home,
        readable: std::slice::from_ref(&archive),
        writable: &[into.as_path()],
        keyring: None,
        network: false,
        environment: &[
            ("HOME", home.as_os_str()),
            ("PATH", "/usr/bin".as_ref()),
            ("LC_ALL", "C".as_ref()),
        ],
        directory: step.build_dir,
    }));
    // The jail starts in the build directory, which it does not show.
    let at = jail.len().saturating_sub(2);
    jail[at] = into.clone().into();
    unpack::unpack(&jail, &archive, &into)?;
    Ok(into)
}

/// Why a call must not go on with the sources it finds: what is said, and
/// what is noted of it.
#[derive(Debug, PartialEq, Eq)]
struct NotHeld {
    message: String,
    why: &'static str,
}

impl NotHeld {
    /// The sources are not what Guardian extracted.
    fn changed(message: String) -> Self {
        Self {
            message,
            why: "the sources are not the ones Guardian fetched and reviewed",
        }
    }

    /// There is a record of what Guardian extracted, and it cannot be
    /// used: what the build would be held against is not known.
    fn unusable(step: &UpstreamStep<'_>, reason: &str) -> Self {
        Self {
            message: format!(
                "Guardian's record of the sources it extracted for this build cannot be used ({reason}), so the sources cannot be held against it. Nothing was built. Run the build again from the start: Guardian extracts the sources again and writes a new record. Or remove the record with `omarchy-guardian forget aur:{}` (it also drops what else Guardian remembers of this package): the sources are then reviewed as they are found.",
                step.key
            ),
            why: "the record of what Guardian extracted cannot be used",
        }
    }

    /// The sources were too many to record (see `Extraction::unlisted`).
    fn unlisted() -> Self {
        Self {
            message: "the sources have more files, or files with longer names, than Guardian can keep a record of, so a build cannot be held to what Guardian extracted and reviewed. Nothing was built.".into(),
            why: "the sources are too many to hold the build to",
        }
    }
}

/// Holds the sources as a call that does not extract finds them against
/// what Guardian extracted for this build. `Err` is why the build must not
/// go on; `Ok` holds facts for the AI about what changed in between. Only
/// where there is no record, or the record is of another directory, are
/// the sources reviewed as they are; a record that cannot be used stops
/// the build.
fn hold_against_extraction(
    step: &UpstreamStep<'_>,
    srcdir: &Path,
    collected: &mut aur::Collected,
) -> Result<Vec<String>, NotHeld> {
    let extraction = match step.state.extraction() {
        Kept::Usable(extraction) if extraction.is_of(srcdir) => extraction,
        Kept::Unusable(reason) => return Err(NotHeld::unusable(step, &reason)),
        Kept::Absent | Kept::Usable(_) => {
            outln!(
                "Sources: Guardian has no record of extracting them for this build; they are reviewed as they are now."
            );
            return Ok(vec![
                "Guardian did not extract these sources itself for this build: they are reviewed as an earlier makepkg run left them.".into(),
            ]);
        }
    };
    if extraction.unlisted {
        return Err(NotHeld::unlisted());
    }
    let identity = state::identity(srcdir);
    let seen = collected.upstream();
    match extraction.drift(identity.as_deref(), &seen.downloads, &seen.seen) {
        Drift::Elsewhere => Err(NotHeld::changed(format!(
            "makepkg did not extract the sources into the directory Guardian reviewed ({}): the build's own extraction and prepare() ran somewhere else, or not at all.",
            srcdir.display()
        ))),
        Drift::Downloads(names) => Err(NotHeld::changed(format!(
            "the build uses download(s) that are not the ones Guardian fetched and reviewed: {}.",
            names
                .iter()
                .take(MAX_BINARIES_NAMED)
                .map(|name| format!("{name:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        ))),
        Drift::Files(changed) if changed.is_empty() => Ok(Vec::new()),
        Drift::Files(changed) => {
            let count = changed.len();
            collected.mark_changed(&changed);
            outln!(
                "Sources: {count} file(s) are new or changed since Guardian extracted them (the build's own extraction, prepare() and pkgver() ran in between); they are reviewed before other code."
            );
            Ok(vec![format!(
                "Since Guardian extracted these sources itself, {count} file(s) in them are new or changed: the build extracted them again and ran prepare() and pkgver(). Those files are sent first; upstream-summary says how many did not fit."
            )])
        }
    }
}

/// Records what Guardian extracted, for the calls that follow. Returns
/// whether it could be recorded whole; where not, the record says so.
fn record_extraction(step: &UpstreamStep<'_>, srcdir: &Path, collected: &aur::Collected) -> bool {
    let seen = collected.upstream();
    let cleans = step
        .mirrored
        .iter()
        .any(|argument| argument == "-C" || argument == "--cleanbuild");
    step.state.record_extraction(&Extraction {
        srcdir: srcdir.to_string_lossy().into_owned(),
        identity: state::identity(srcdir),
        cleanbuild: cleans,
        downloads: seen.downloads.clone(),
        files: seen.seen.clone(),
        unlisted: false,
    })
}

/// Facts about the dependencies a build downloads on its own.
fn dependency_facts(upstream: &Upstream) -> Vec<String> {
    if upstream.ecosystems.is_empty() {
        return Vec::new();
    }
    let mut ecosystems = upstream.ecosystems.clone();
    ecosystems.sort();
    let names: Vec<&str> = ecosystems
        .iter()
        .map(|ecosystem| ecosystem.label())
        .collect();
    print_warnings(
        "Dependencies",
        &[format!(
            "the sources hold {} manifests or lockfiles: what the build downloads through them during prepare() or build() is not reviewed",
            names.join(", ")
        )],
    );
    vec![format!(
        "The sources hold dependency manifests or lockfiles ({}). Dependencies the build downloads through them during prepare() or build() go into the user's caches and are not among the supplied files: Guardian does not review them. Weigh what the supplied build files make of them (install scripts, registries, addresses).",
        names.join(", ")
    )]
}

/// A block of the upstream step: said, notified, and turned into the exit
/// code. It notes that the recipe ran: makepkg sources it, in the jail, to
/// list the sources.
fn block(step: &UpstreamStep<'_>, message: &str, why: &str, code: u8) -> ExitCode {
    errln!("Guardian blocked makepkg: {message}");
    audit::refused(Gate::Aur, &format!("aur:{}: {why}", step.key), code);
    notify::blocked(&subject(step.name), why, Ran::RecipeToFetch);
    ExitCode::from(code)
}

/// The user said no, or there was no terminal to say yes on.
fn not_confirmed() -> ExitCode {
    errln!("Guardian did not start makepkg: not confirmed (decision: NOT CONFIRMED).");
    Decision::Blocked(Blocked::NotConfirmed).exit_code()
}

/// What a recipe lists, once the listing is known to be one.
struct Listed {
    srcinfo: String,
    pkgbase: String,
    /// The recipe Guardian fetches from (see `fetch_recipe`).
    fetch: String,
    sources: Vec<aur::Source>,
    /// A fact for the AI when the listing may not be what the build uses.
    fact: Option<&'static str>,
}

/// Lists the recipe's sources and holds the listing against the recipe's
/// text (see `followed`).
fn list_sources(step: &UpstreamStep<'_>, confirm: &mut dyn Confirm) -> Result<Listed, ExitCode> {
    let unreadable = |error: String| {
        block(
            step,
            &format!("could not read the source list ({error})."),
            "the source list could not be read",
            2,
        )
    };
    let srcinfo = probe(step).map_err(|error| unreadable(error.to_string()))?;
    aur::check_listing(&srcinfo)
        .map_err(|why| unreadable(format!("it is not as makepkg prints one: {why}")))?;
    let (Some(pkgbase), Some(fetch)) = (listed_pkgbase(&srcinfo), fetch_recipe(&srcinfo)) else {
        return Err(unreadable("it names no usable pkgbase".into()));
    };
    let fact = match followed(step.recipe, &srcinfo) {
        Followed::Yes => None,
        Followed::Differs(array) => {
            return Err(block(
                step,
                &format!(
                    "listing the recipe gave another {array} than it writes out; what it builds with cannot be known."
                ),
                "the recipe lists other sources than it writes out",
                2,
            ));
        }
        Followed::No(reasons) => {
            let downloads = download_names(&aur::parse_srcinfo(&srcinfo));
            if !confirm_not_followed(step, &reasons, &downloads, confirm) {
                return Err(not_confirmed());
            }
            Some(NOT_FOLLOWED_FACT)
        }
    };
    Ok(Listed {
        pkgbase: pkgbase.to_string(),
        sources: aur::parse_srcinfo(&srcinfo),
        srcinfo,
        fetch,
        fact,
    })
}

/// Walks the extracted sources, unpacks what the recipe opens itself, holds
/// them against what Guardian extracted (or records that), and decides what
/// is sent for review. Facts about what changed are added to `context`.
fn collect_sources(
    step: &UpstreamStep<'_>,
    listed: &Listed,
    dirs: &Dirs,
    budget: u64,
    context: &mut Vec<String>,
) -> Result<Upstream, ExitCode> {
    let srcdir = dirs.srcdir();
    let roots = Roots {
        build_dir: step.build_dir,
        srcdest: Some(&dirs.srcdest),
    };
    let noextract: Vec<String> = aur::base_section(&listed.srcinfo)
        .filter(|(key, _)| *key == "noextract")
        .map(|(_, name)| name.to_string())
        .collect();
    let mut collected = aur::walk_upstream(&srcdir, &roots, &step.functions.written, &noextract);
    // Kept until the files are chosen: the unpacked ones are read from it.
    let scratch = unpack_archives(step, &srcdir, &roots, &mut collected);
    let not_held = |refused: NotHeld| block(step, &refused.message, refused.why, 2);
    if step.extract {
        if !record_extraction(step, &srcdir, &collected) {
            return Err(not_held(NotHeld::unlisted()));
        }
    } else if collected.upstream().found {
        context.extend(hold_against_extraction(step, &srcdir, &mut collected).map_err(not_held)?);
    }
    let upstream = collected.select(budget);
    drop(scratch);
    Ok(upstream)
}

/// Reviews the upstream sources (see `review_upstream`), and says so when
/// a question it had went unasked for want of a terminal.
fn upstream_step(
    step: &UpstreamStep<'_>,
    settings: &Settings,
    facts: Vec<String>,
    terminal: &mut Asker,
) -> Result<UpstreamOutcome, ExitCode> {
    let outcome = review_upstream(step, settings, facts, terminal);
    if outcome.is_err() {
        terminal.say_if_missing(step.name, Ran::RecipeToFetch);
    }
    outcome
}

/// Returns why makepkg must not start, as an exit code.
fn review_upstream(
    step: &UpstreamStep<'_>,
    settings: &Settings,
    facts: Vec<String>,
    confirm: &mut dyn Confirm,
) -> Result<UpstreamOutcome, ExitCode> {
    let listed = list_sources(step, confirm)?;
    let sources = &listed.sources;
    let dirs = step.configured.dirs(step.build_dir, &listed.pkgbase);
    if let Some((message, why)) = fetch_refusal(step, &listed.pkgbase, sources, &dirs) {
        return Err(block(step, &message, why, 1));
    }

    let mut context = vec![aur::UPSTREAM_SCOPE.to_string()];
    context.extend(listed.fact.map(str::to_string));
    context.push(if aur::runs_tests(step.recipe) {
        "The recipe defines check(), so the upstream test suite runs during this build.".into()
    } else {
        "The recipe defines no check(), so the upstream test suite does not run during this build."
            .into()
    });
    let checked = source_context(sources, step.uses_sources).map_err(|()| {
        block(
            step,
            "a source can be replaced in transit.",
            "a source can be replaced in transit",
            1,
        )
    })?;
    context.extend(checked);
    context.extend(facts);

    if step.extract {
        pre_extract(step, &dirs, &listed.fetch).map_err(|message| {
            block(step, &message, "fetching the sources for review failed", 2)
        })?;
    }

    let budget = upstream_budget(settings);
    let upstream = collect_sources(step, &listed, &dirs, budget, &mut context)?;
    let downloads = download_names(sources);
    if only_downloads(step, sources, &upstream) {
        // To stderr: such a call's output may be what the caller wants
        // (`makepkg -g >>PKGBUILD`).
        errln!("Upstream: no extracted sources yet; they are reviewed when they are extracted.");
        return Ok(UpstreamOutcome { dirs, downloads });
    }
    if !sources.is_empty() && !upstream.found {
        return Err(block(
            step,
            &format!(
                "the extracted sources were not found where makepkg put them ({}).",
                dirs.srcdir().display()
            ),
            "the extracted sources could not be found for review",
            2,
        ));
    }
    let mut upstream = upstream;
    if step.functions.unread > 0 {
        upstream.gaps.push(format!(
            "{} install script(s) beside the PKGBUILD could not be read for what they run",
            step.functions.unread
        ));
    }
    context.extend(dependency_facts(&upstream));
    context.extend(binary_changes(step, &upstream));
    let prebuilt = prebuilt(step, &upstream, sources);
    let review = UpstreamReview {
        upstream: &upstream,
        sources,
        prebuilt: &prebuilt,
    };
    let reviewed = if upstream.files.is_empty() && upstream.gaps.is_empty() {
        (None, unreviewable_sources(step, &review, confirm))
    } else {
        let (report, decision) = review_upstream_files(step, settings, &review, &context, confirm);
        (Some(report), decision)
    };
    let content = upstream_content(step, &upstream, sources);
    let (standing, decision) =
        settle_upstream(step, settings, content, reviewed, &prebuilt, confirm);
    match decision {
        // The user's own no: no permit overrules it, and none is offered.
        Decision::Blocked(Blocked::NotConfirmed) => Err(not_confirmed()),
        // The prebuilt programs were asked about in `settle_upstream`.
        Decision::Blocked(_) if standing.permitted().is_some() => {
            errln!(
                "Guardian: your permit {} overrules the review of the upstream sources.",
                standing.permitted().unwrap_or_default()
            );
            step.state.record_binaries(&all_binaries(&upstream));
            Ok(UpstreamOutcome { dirs, downloads })
        }
        // Nothing was sent to the AI (`ai = off`): the recipe decision stands.
        Decision::Limited | Decision::Clear | Decision::Warned => {
            // What a later build's binaries are held against.
            step.state.record_binaries(&all_binaries(&upstream));
            Ok(UpstreamOutcome { dirs, downloads })
        }
        Decision::Blocked(_) => {
            errln!(
                "Guardian blocked makepkg because the review of the upstream sources did not allow it."
            );
            standing.say();
            notify_block(
                step.name,
                decision,
                "the upstream sources",
                Ran::RecipeToFetch,
            );
            Err(decision.exit_code())
        }
    }
}
/// The recipe must be exactly what was reviewed, apart from what makepkg
/// itself downloads into the build directory.
fn verify_recipe(
    config: &ScanConfig,
    reviewed: &Snapshot,
    downloads: &[String],
) -> Result<(), Error> {
    let mut config = config.clone();
    config.excluded_entries.extend(downloads.iter().cloned());
    // A partial download is makepkg's own file only when it was not there
    // at the review: one that was is a recipe file like any other.
    let reviewed_part = |top: &str| {
        reviewed
            .files()
            .iter()
            .any(|file| file.path.split('/').next() == Some(top))
    };
    let excluded = |path: &str| {
        let top = path.split('/').next().unwrap_or_default();
        downloads.iter().any(|name| name == top)
            || (Path::new(top)
                .extension()
                .is_some_and(|extension| extension == "part")
                && !reviewed_part(top))
            || (top.starts_with(".guardian-") && top.ends_with(".PKGBUILD"))
    };
    let (current, gaps) = scan::walk(&config, &mut |_| {});
    if !gaps.is_empty() {
        return Err(Error::Refused(
            "the recipe became unreadable after review".into(),
        ));
    }
    let now: Vec<_> = current
        .files()
        .iter()
        .filter(|file| !excluded(&file.path))
        .collect();
    let then: Vec<_> = reviewed
        .files()
        .iter()
        .filter(|file| !excluded(&file.path))
        .collect();
    if now == then {
        Ok(())
    } else {
        Err(Error::Refused("the recipe changed after review".into()))
    }
}

fn subject(name: &str) -> String {
    format!("the AUR build of {name}")
}

/// Notifies a blocked review of `what`; a build the user declined is not news.
fn notify_block(name: &str, decision: Decision, what: &str, ran: Ran) {
    if let Decision::Blocked(blocked) = decision
        && blocked != Blocked::NotConfirmed
    {
        notify::blocked(
            &subject(name),
            &format!("{what}: {}", notify::reason(blocked)),
            ran,
        );
    }
}

/// What one upstream review is of.
struct UpstreamReview<'a> {
    upstream: &'a Upstream,
    sources: &'a [aur::Source],
    prebuilt: &'a Prebuilt,
}

/// Forgets what the gate remembers of the source `identity` names
/// (`aur:<pkg>`, `aur-src:<pkg>`, or a local build's own key) under the
/// review memory's `root`: the questions answered, the binaries and what
/// was extracted. Returns how many records went.
pub(crate) fn forget(root: &Path, identity: &str) -> Result<usize, Error> {
    let key = identity
        .strip_prefix("aur:")
        .or_else(|| identity.strip_prefix("aur-src:"))
        .unwrap_or(identity);
    state::forget(root, key)
}

/// Forgets everything the gate remembers under `root`.
pub(crate) fn forget_all(root: &Path) -> Result<usize, Error> {
    state::forget_all(root)
}

fn print_warnings(title: &str, warnings: &[String]) {
    if warnings.is_empty() {
        return;
    }
    outln!("{title}:");
    for warning in warnings {
        outln!("  ! {warning}");
    }
}

/// Parses `makepkg-gate -- <makepkg> [args...]`.
pub(crate) fn parse(args: &[OsString]) -> Result<Vec<OsString>, String> {
    match args.split_first() {
        Some((separator, rest)) if separator == "--" && !rest.is_empty() => Ok(rest.to_vec()),
        _ => Err("usage: omarchy-guardian makepkg-gate -- <makepkg> [args...]".into()),
    }
}

#[cfg(test)]
mod tests;
