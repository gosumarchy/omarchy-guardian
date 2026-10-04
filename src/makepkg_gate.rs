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

mod state;
mod unpack;

use std::collections::{BTreeMap, HashSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use self::state::{Drift, Extraction, State};
use crate::audit::{self, Gate};
use crate::aur::recipe::{self, Sources};
use crate::aur::{self, AurInfo, Roots, Upstream};
use crate::cli::{Confirm, Target, TtyConfirm, Verdict, passed, review_and_decide};
use crate::config::Settings;
use crate::config::model::{Named, SourceClass};
use crate::engine::baseline::{Identity, Unit};
use crate::engine::store::Store;
use crate::error::{Error, IoContext};
use crate::json::Json;
use crate::notify::{self, Ran};
use crate::osv;
use crate::pacman;
use crate::permit::{self, Content, Standing};
use crate::report::{Blocked, Decision, Gap, Report, RunRef};
use crate::review::{self, ReviewContext};
use crate::rules;
use crate::sandbox::{self, FetchJail, Workspace};
use crate::scan::{self, ScanConfig, Snapshot};
use crate::sha256::Sha256;
use crate::tools::{self, Limits, OpenCode};

const RPC_URL: &str = "https://aur.archlinux.org/rpc/v5/info";
const RPC_SEARCH_URL: &str = "https://aur.archlinux.org/rpc/v5/search";
const RPC_LIMITS: Limits = Limits {
    timeout_secs: 20,
    max_output: 1024 * 1024,
};
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

pub fn run(command: &[OsString], settings: &Settings) -> ExitCode {
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
    let verdict = match review_recipe(&target, settings, &recipe_context, &recipe) {
        Ok(verdict) => verdict,
        Err(exit) => return exit,
    };
    let report = &verdict.report;
    let recipe_digest = recipe_digest(&report.snapshot, &written_downloads(&recipe));

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
            functions: &functions,
            extract: invocation.extracts,
            uses_sources: invocation.uses_sources,
            configured: &configured,
            state: &state,
        };
        match review_upstream(&step, settings, facts, &mut TtyConfirm) {
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

/// One SHA-256 over the recipe as reviewed: every file of the build
/// directory by path, hash and execute bit, but for those under the
/// top-level names in `left_out` (and their partial downloads).
fn recipe_digest(snapshot: &Snapshot, left_out: &[String]) -> String {
    let mut hasher = Sha256::new();
    for file in snapshot.files() {
        let top = file.path.split('/').next().unwrap_or_default();
        if left_out
            .iter()
            .any(|name| name == top || top.strip_suffix(".part") == Some(name))
        {
            continue;
        }
        hasher.update(file.path.as_bytes());
        hasher.update(&[0]);
        hasher.update(file.sha256.to_string().as_bytes());
        hasher.update(&[u8::from(file.executable), b'\n']);
    }
    hasher.finalize().to_string()
}

/// The recipe as a permit names it. A permit is offered for the build
/// directory as it is; one given before makepkg downloaded the sources
/// into that directory still stands for the recipe once they are there,
/// so the second form leaves those files out. A file that was already
/// there when the permit was given is part of the first form only: one
/// changed since has no permit.
fn recipe_contents(target: &Target, snapshot: &Snapshot, recipe: &str) -> Vec<Content> {
    if snapshot.files().is_empty() {
        return Vec::new();
    }
    let mut digests = vec![
        recipe_digest(snapshot, &[]),
        recipe_digest(snapshot, &written_downloads(recipe)),
    ];
    digests.dedup();
    digests
        .iter()
        .filter_map(|digest| {
            Content::new(
                Gate::Aur,
                SourceClass::Aur.name(),
                &target.subject(),
                vec![format!("recipe:{digest}")],
            )
        })
        .collect()
}

/// Version-control sources: what makepkg fetches of them has no one hash.
const VCS: &[&str] = &["git", "hg", "svn", "bzr", "fossil"];

/// The upstream sources of a build as a permit names them: the recipe, and
/// the downloaded files by their hashes, which are the same at every
/// makepkg call of one build. Sources that are no plain downloads (a
/// checkout) are named by every file the walk read instead, which a
/// build's own `prepare()` changes. `None` when a file among them has no
/// SHA-256: nothing can stand for it.
fn upstream_content(
    step: &UpstreamStep<'_>,
    upstream: &Upstream,
    sources: &[aur::Source],
) -> Option<Content> {
    let plain = !upstream.downloads.is_empty()
        && sources
            .iter()
            .all(|source| !VCS.contains(&aur::source_protocol(&source.entry)));
    let files = if plain {
        &upstream.downloads
    } else {
        &upstream.seen
    };
    let mut hasher = Sha256::new();
    for (path, digest) in files {
        if digest.len() != 64 {
            return None;
        }
        hasher.update(path.as_bytes());
        hasher.update(&[0]);
        hasher.update(digest.as_bytes());
        hasher.update(b"\n");
    }
    Content::new(
        Gate::Aur,
        SourceClass::Aur.name(),
        &format!("aur:{} upstream sources", step.key),
        vec![
            format!("recipe:{}", step.recipe_digest),
            format!("sources:{}", hasher.finalize()),
        ],
    )
}

/// How the upstream review stands with permits, printed and recorded: the
/// report (when there was text to review) with its final decision.
fn settle_upstream(
    step: &UpstreamStep<'_>,
    settings: &Settings,
    content: Option<Content>,
    report: Option<Report>,
    decision: Decision,
) -> Standing {
    let printed = report.is_some();
    let mut report =
        report.unwrap_or_else(|| Report::new(format!("{} · upstream sources", step.name)));
    let contents: Vec<Content> = content.into_iter().collect();
    let standing = permit::standing(
        &contents,
        &report,
        decision,
        settings,
        Store::default_root().as_deref(),
    );
    report.permit = standing.permitted().map(str::to_string);
    if printed {
        report.print(false, decision);
    }
    let permitted = standing.permitted().is_some();
    audit::review(
        &audit::Reviewed {
            gate: Gate::Aur,
            class: SourceClass::Aur.name(),
            subject: &format!("aur:{} upstream sources", step.key),
            digest: &contents.first().map(Content::digest).unwrap_or_default(),
            decision,
            permit: standing.permitted(),
            offered: standing.offered(),
            exit: if permitted { 0 } else { decision.exit_status() },
        },
        &report,
    )
    .record();
    standing
}

/// Reviews the recipe in `target`. `Err` is the exit code of a gate that
/// goes no further: the review did not allow it and no permit of the
/// user's overrules it, or the recipe changed meanwhile.
fn review_recipe(
    target: &Target,
    settings: &Settings,
    context: &[String],
    recipe: &str,
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
        Some(&mut TtyConfirm),
        context,
        Gate::Aur,
        Some(&|report| recipe_contents(target, &report.snapshot, recipe)),
    );
    if !verdict.allows_running() {
        errln!("Guardian blocked makepkg because the review of the recipe did not allow it.");
        verdict.standing.say();
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

/// The AUR's facts about `base` (a confirmed AUR clone) for the reviews,
/// printing its summary and any trust warnings. Without a confirmed
/// identity, only that fact.
fn aur_facts(base: Option<&str>, directory_name: &str, recipe: &str) -> Vec<String> {
    let mut facts = Vec::new();
    let Some(base) = base else {
        let fact = format!(
            "The build directory {directory_name:?} is not a clone of an AUR package (a local or private PKGBUILD); no AUR facts apply."
        );
        outln!("{fact}");
        facts.push(fact);
        return facts;
    };
    let mut names = vec![base.to_string()];
    names.extend(aur::declared_names(recipe));
    names.dedup();
    match aur_info(base, &names) {
        Ok(Some(info)) => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs());
            let (found, mut warnings) = aur::trust_signals(&info, now);
            if let Some(summary) = found.first() {
                outln!("{summary}");
            }
            facts.extend(found);
            warnings.extend(lookalikes(&info));
            print_warnings("AUR trust signals", &warnings);
            facts.extend(
                warnings
                    .iter()
                    .map(|warning| format!("Guardian's AUR check warns: {warning}.")),
            );
        }
        Ok(None) => {
            let fact = format!("{base} is not a package base in the AUR.");
            outln!("{fact}");
            facts.push(fact);
        }
        // The build goes on without them, and both the user and the AI
        // are told that they are missing, not that they are fine.
        Err(error) => {
            errln!("Guardian: AUR metadata unavailable ({error}).");
            print_warnings("AUR trust signals", &[aur::TRUST_UNKNOWN.to_string()]);
            facts.push(aur::TRUST_UNKNOWN.to_string());
        }
    }
    facts
}

/// Known packages a little-voted package's name could be taken for (see
/// `aur::lookalikes`). The official names come from pacman's own databases
/// on this machine; the AUR is asked once, and sent only the name. Without
/// either, that part is not checked.
fn lookalikes(info: &AurInfo) -> Vec<String> {
    if !aur::is_little_voted(info.votes) {
        return Vec::new();
    }
    let official: Vec<String> = tools::run(
        Path::new(tools::PACMAN),
        &["-Slq".into()],
        None,
        &[],
        RPC_LIMITS,
    )
    .and_then(tools::Captured::into_success)
    .map(|names| {
        String::from_utf8_lossy(&names)
            .lines()
            .map(str::to_string)
            .collect()
    })
    .unwrap_or_default();
    let searched = aur::lookalike_search_term(&info.name)
        .filter(|term| pacman::is_valid_package_name(term))
        .and_then(|term| {
            let mut args = osv::curl_args();
            args.push(format!("{RPC_SEARCH_URL}/{}?by=name", url_encoded(&term)).into());
            let body = tools::run(Path::new(tools::CURL), &args, None, &[], RPC_LIMITS)
                .and_then(tools::Captured::into_success)
                .ok()?;
            Json::parse(&String::from_utf8_lossy(&body)).ok()
        })
        .map(|reply| aur::parse_rpc_search(&reply))
        .unwrap_or_default();
    aur::lookalikes(&info.name, info.votes, &official, &searched)
}

/// A package name as part of an address.
fn url_encoded(name: &str) -> String {
    name.chars()
        .map(|character| match character {
            '+' => "%2B".to_string(),
            '@' => "%40".to_string(),
            other => other.to_string(),
        })
        .collect()
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

/// The most install scripts read beside a PKGBUILD.
const MAX_INSTALL_SCRIPTS: usize = 8;

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
}

fn recipe_functions(build_dir: &Path, recipe: &str) -> Functions {
    let mut files = vec![("PKGBUILD".to_string(), recipe.to_string())];
    let mut scripts: Vec<PathBuf> = fs::read_dir(build_dir)
        .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
        .unwrap_or_default();
    scripts.sort();
    for path in scripts {
        let plain = fs::symlink_metadata(&path)
            .is_ok_and(|found| found.is_file() && found.len() <= scan::MAX_TEXT_FILE_SIZE);
        if files.len() <= MAX_INSTALL_SCRIPTS
            && plain
            && path
                .extension()
                .is_some_and(|extension| extension == "install")
            && let Ok(text) = fs::read_to_string(&path)
        {
            let name = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned());
            files.push((name.unwrap_or_default(), text));
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

/// The hidden recipe makepkg fetches from (`-p`, which must be beside the
/// real one), removed on drop.
struct RecipeCopy {
    path: PathBuf,
}

impl RecipeCopy {
    fn create(build_dir: &Path, recipe: &str) -> Result<Self, Error> {
        let path = build_dir.join(format!(".guardian-{}.PKGBUILD", random_name()?));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .at(&path)?;
        file.write_all(recipe.as_bytes()).at(&path)?;
        Ok(Self { path })
    }

    fn name(&self) -> OsString {
        self.path
            .file_name()
            .map(OsStr::to_os_string)
            .unwrap_or_default()
    }
}

impl Drop for RecipeCopy {
    fn drop(&mut self) {
        drop(fs::remove_file(&self.path));
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

/// Whether makepkg may be given `path` to write to in the jail: not a
/// directory whose binding would bring back what the jail hides (the home,
/// the system, the temporary directory, or anything above them).
fn is_jailable(path: &Path, home: &Path) -> bool {
    let Ok(path) = fs::canonicalize(path) else {
        return false;
    };
    let hidden = [home, Path::new("/usr"), Path::new("/etc"), &env::temp_dir()];
    !hidden.iter().any(|kept| {
        fs::canonicalize(kept)
            .unwrap_or_else(|_| kept.to_path_buf())
            .starts_with(&path)
    }) && !path.starts_with("/usr")
        && !path.starts_with("/etc")
}

/// Environment variables a download may need, passed into the jail as set.
const PASSED_VARIABLES: &[&str] = &[
    "LANG",
    "TERM",
    "XDG_CONFIG_HOME",
    "http_proxy",
    "https_proxy",
    "ftp_proxy",
    "all_proxy",
    "no_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "FTP_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
];

/// The files of a gpg home directory that hold public keys and their trust.
const PUBLIC_KEYRING: &[&str] = &[
    "pubring.kbx",
    "pubring.gpg",
    "trustdb.gpg",
    "gpg.conf",
    "common.conf",
    "public-keys.d/pubring.db",
];

/// Copies the public part of the user's keyring into `workspace`, so
/// source signatures verify in the jail without the private keys being
/// there. `None` without a keyring.
fn public_keyring(home: &Path, workspace: &Path) -> Option<PathBuf> {
    let source = env::var_os("GNUPGHOME").map_or_else(|| home.join(".gnupg"), PathBuf::from);
    if !source.is_dir() {
        return None;
    }
    let copy = workspace.join("gnupg");
    let private = |path: &Path| DirBuilder::new().mode(0o700).create(path);
    private(&copy).ok()?;
    private(&copy.join("public-keys.d")).ok()?;
    for name in PUBLIC_KEYRING {
        let from = source.join(name);
        if fs::metadata(&from).is_ok_and(|metadata| metadata.is_file()) {
            fs::copy(&from, copy.join(name)).ok()?;
        }
    }
    Some(copy)
}

/// One of Guardian's two makepkg runs in the jail, with the build and
/// download directories makepkg is given in it.
#[derive(Clone, Copy)]
enum Run<'a> {
    /// Listing the sources: directories inside the jail's temporary one.
    /// The recipe's own code runs here, so the jail shows it as little of
    /// Guardian as it can: `wrapper` stands where the PKGBUILD is, and the
    /// workspace is seen at `inside`, a name like any build directory's.
    List {
        dirs: &'a Dirs,
        wrapper: &'a Path,
        inside: &'a Path,
    },
    /// Fetching them: the real directories, writable.
    Fetch(&'a Dirs),
}

/// The user's home, which the jail empties.
fn home() -> Result<PathBuf, Error> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| home.is_absolute() && home.parent().is_some())
        .ok_or_else(|| Error::Refused("HOME is not set to a directory".into()))
}

/// Puts `extra` Bubblewrap arguments before the `--chdir <dir> --` that
/// `sandbox::fetch_jail` ends with, so they are mounted over what it binds.
fn with_mounts(mut command: Vec<OsString>, extra: Vec<OsString>) -> Vec<OsString> {
    let at = command.len().saturating_sub(3);
    command.splice(at..at, extra);
    command
}

/// The Bubblewrap command that runs makepkg with `arguments` in the jail,
/// for one of two runs. Listing the sources sources the real recipe: no
/// network, the recipe's directory read-only, and makepkg's build and
/// download directories pointed at the jail's own temporary directory.
/// Fetching (`fetch`) runs the generated recipe: the network, a copy of
/// the public keyring, and the real directories writable. `workspace` is
/// writable in both, for the listing's report and the keyring.
fn jailed(
    step: &UpstreamStep<'_>,
    workspace: &Workspace,
    run: Run<'_>,
    arguments: &[OsString],
) -> Result<Vec<OsString>, Error> {
    let home = home()?;
    let configuration = env::var_os("XDG_CONFIG_HOME")
        .map_or_else(|| home.join(".config"), PathBuf::from)
        .join("pacman/makepkg.conf");
    let mut readable = vec![configuration, home.join(".makepkg.conf")];
    let mut writable: Vec<&Path> = Vec::new();
    let mut keyring = None;
    let mut mounts: Vec<OsString> = Vec::new();
    let (dirs, fetch) = match run {
        Run::Fetch(dirs) => {
            writable.push(workspace.path());
            for directory in [step.build_dir, &dirs.builddir, &dirs.srcdest] {
                // makepkg would create a configured one; a bind needs it.
                fs::create_dir_all(directory).at(directory)?;
                if !is_jailable(directory, &home) {
                    return Err(Error::Refused(format!(
                        "{} holds more than a build, so the sources cannot be fetched into it in the sandbox",
                        directory.display()
                    )));
                }
                if !writable.contains(&directory) {
                    writable.push(directory);
                }
            }
            keyring = public_keyring(&home, workspace.path());
            (dirs, true)
        }
        Run::List {
            dirs,
            wrapper,
            inside,
        } => {
            readable.push(step.build_dir.to_path_buf());
            mounts.extend([
                "--bind".into(),
                workspace.path().into(),
                inside.into(),
                "--ro-bind".into(),
                wrapper.into(),
                step.build_dir.join("PKGBUILD").into(),
            ]);
            (dirs, false)
        }
    };

    // The listing has no network, and what it prints becomes requests: it
    // is not told the proxies, which may hold credentials.
    let passed: Vec<(&str, OsString)> = PASSED_VARIABLES
        .iter()
        .filter(|name| fetch || !name.to_ascii_lowercase().ends_with("_proxy"))
        .filter_map(|name| Some((*name, env::var_os(name)?)))
        .collect();
    let mut environment: Vec<(&str, &OsStr)> = vec![
        ("HOME", home.as_os_str()),
        ("PATH", "/usr/bin".as_ref()),
        ("BUILDDIR", dirs.builddir.as_os_str()),
        ("SRCDEST", dirs.srcdest.as_os_str()),
    ];
    // Nothing is packaged or logged in the jail. makepkg only wants a
    // package directory it can write to: for the listing, where a user's
    // own setting could point; the others are left as makepkg finds them.
    let packages = home.join("packages");
    if fetch {
        for name in ["PKGDEST", "SRCPKGDEST", "LOGDEST"] {
            environment.push((name, "/tmp".as_ref()));
        }
    } else {
        environment.push(("PKGDEST", packages.as_os_str()));
    }
    environment.extend(
        passed
            .iter()
            .map(|(name, value)| (*name, value.as_os_str())),
    );

    let command = sandbox::fetch_jail(&FetchJail {
        home: &home,
        readable: &readable,
        writable: &writable,
        keyring: keyring.as_deref(),
        network: fetch,
        environment: &environment,
        directory: step.build_dir,
    });
    let mut command = with_mounts(command, mounts);
    command.push(step.makepkg.into());
    command.extend(arguments.iter().cloned());
    Ok(command)
}

struct UpstreamOutcome {
    dirs: Dirs,
    /// Top-level names makepkg downloads into the build directory.
    downloads: Vec<String>,
}

/// The recipe the listing runs in place of the real one: it loads the real
/// one, a copy at `real`, and then writes the two directories as that left
/// them to `report`. It runs in the shell the recipe ran in, so it shows
/// what a recipe did in passing (however it was written), not what one
/// written to deceive it wants hidden. What the recipe prints while it
/// loads goes to standard error: the listing is read from standard output,
/// which makepkg alone should write.
fn listing_recipe(real: &Path, report: &Path) -> String {
    let quoted = |path: &Path| format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"));
    format!(
        "source {} >&2\nprintf '%s\\0%s\\0' \"$BUILDDIR\" \"$SRCDEST\" >{}\n",
        quoted(real),
        quoted(report)
    )
}

/// The most a listing's report can hold: two paths.
const MAX_REPORT_BYTES: u64 = 16 * 1024;

/// What the listing run reported, if it left a plain file of a sane size:
/// the recipe's shell wrote it, so it may be anything.
fn listing_report(path: &Path) -> Option<Vec<u8>> {
    fs::symlink_metadata(path)
        .ok()
        .filter(|metadata| metadata.is_file() && metadata.len() <= MAX_REPORT_BYTES)
        .and_then(|_| fs::read(path).ok())
}

/// Eight random bytes as text, for a name no recipe can know beforehand.
fn random_name() -> Result<String, Error> {
    let mut bytes = [0_u8; 8];
    fs::File::open("/dev/urandom")
        .and_then(|mut random| io::Read::read_exact(&mut random, &mut bytes))
        .at(Path::new("/dev/urandom"))?;
    Ok(bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    }))
}

/// Has makepkg list the recipe's sources (`--printsrcinfo`), in the jail:
/// the recipe's top-level code runs there, with no network and nothing of
/// the user's to read or write. Its build and download directories are
/// pointed at names made up for this run, inside the jail's own temporary
/// directory. Returns the listing, unless the recipe did not leave those
/// two as they were: it would move the real build's too.
///
/// The jail is made to look like an ordinary run as far as that is cheap:
/// makepkg is called as a user calls it, on a file named `PKGBUILD` in the
/// recipe's directory, with no variable of Guardian's in the environment.
/// A recipe that looks can still tell: there is no network, its directory
/// is read-only, the home is empty, and the file it is loaded from is a
/// copy in the temporary directory.
fn probe(step: &UpstreamStep<'_>) -> Result<String, Error> {
    let workspace = Workspace::create("probe")?;
    // The name is random, so no recipe can assign these by rote.
    let inside = Path::new("/tmp").join(format!("makepkg-{}", random_name()?));
    let write = |name: &str, text: &str| -> Result<PathBuf, Error> {
        let path = workspace.path().join(name);
        fs::write(&path, text).at(&path)?;
        Ok(path)
    };
    write("PKGBUILD", step.recipe)?;
    let wrapper = write(
        "wrapper",
        &listing_recipe(&inside.join("PKGBUILD"), &inside.join("report")),
    )?;
    let listing = Dirs {
        builddir: inside.join("build"),
        srcdest: inside.join("sources"),
        pkgbase: String::new(),
        startdir: step.build_dir.to_path_buf(),
    };
    let mut args: Vec<OsString> = vec!["--printsrcinfo".into()];
    args.extend(step.mirrored.iter().cloned());
    let run = Run::List {
        dirs: &listing,
        wrapper: &wrapper,
        inside: &inside,
    };
    let command = jailed(step, &workspace, run, &args)?;
    let captured = tools::run_in(
        Path::new(tools::BWRAP),
        &command,
        step.build_dir,
        &[],
        SRCINFO_LIMITS,
    )?
    .into_success()?;
    let mut expected = listing.builddir.as_os_str().as_encoded_bytes().to_vec();
    expected.push(0);
    expected.extend(listing.srcdest.as_os_str().as_encoded_bytes());
    expected.push(0);
    match listing_report(&workspace.path().join("report")) {
        Some(report) if report == expected => Ok(String::from_utf8_lossy(&captured).into_owned()),
        Some(_) => Err(Error::Refused(
            "the PKGBUILD moves makepkg's build or download directory".into(),
        )),
        None => Err(Error::Refused(
            "the PKGBUILD did not finish loading here (it stops or fails on this system)".into(),
        )),
    }
}

/// Fetches and extracts the sources, in the jail with the network on, from
/// `recipe`: the generated one, so none of the package's recipe runs. A
/// source tree left by an earlier run is removed first (`--cleanbuild`).
fn pre_extract(step: &UpstreamStep<'_>, dirs: &Dirs, recipe: &str) -> Result<(), String> {
    let prepare = |error: Error| format!("could not prepare the sources ({error}).");
    let workspace = Workspace::create("fetch").map_err(prepare)?;
    let copy = RecipeCopy::create(step.build_dir, recipe).map_err(prepare)?;
    let mut args: Vec<OsString> = vec!["-p".into(), copy.name()];
    args.extend(
        [
            "--nobuild",
            "--noprepare",
            "--nodeps",
            "--noconfirm",
            "--cleanbuild",
        ]
        .map(Into::into),
    );
    args.extend(step.mirrored.iter().cloned());
    let command = jailed(step, &workspace, Run::Fetch(dirs), &args).map_err(prepare)?;
    errln!(
        "Guardian: fetching and extracting the sources for review, in a sandbox (makepkg downloads what the PKGBUILD lists; the PKGBUILD itself does not run and nothing is built)..."
    );
    let status = Command::new(tools::BWRAP)
        .current_dir(step.build_dir)
        .args(command)
        .stdin(Stdio::null())
        .status()
        .map_err(|error| format!("could not run makepkg to fetch the sources ({error})."))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "fetching the sources for review failed ({status})."
        ))
    }
}

/// The first source makepkg would keep under a name that is not a plain
/// file name. makepkg takes the text before `::` as it is, so `a/b` or
/// `../x` would be written somewhere else than among the downloads.
fn misnamed_source(sources: &[aur::Source]) -> Option<&str> {
    sources
        .iter()
        .map(|source| source.entry.as_str())
        .find(|entry| {
            let name = aur::source_filename(entry);
            name.is_empty()
                || name.contains('/')
                || name.starts_with('-')
                || [".", "..", ".git"].contains(&name.as_str())
        })
}

/// Sections and keys (lowercase: git ignores their case) of the
/// configuration `git clone --mirror` writes.
const MIRROR_CONFIG: &[(&str, &[&str])] = &[
    (
        "[core]",
        &[
            "repositoryformatversion",
            "filemode",
            "bare",
            "logallrefupdates",
            "ignorecase",
            "precomposeunicode",
            "symlinks",
        ],
    ),
    ("[remote \"origin\"]", &["url", "fetch", "mirror", "tagopt"]),
];

/// Whether `mirror` is a git mirror as makepkg makes one for `url`: its
/// configuration holds nothing but what `git clone --mirror` writes, it has
/// no hooks, and its configuration is its own. makepkg runs `git fetch`
/// inside an existing mirror, and git does what a repository's
/// configuration and hooks say.
fn is_plain_mirror(mirror: &Path, url: &str) -> bool {
    let is_dir = |path: &Path| fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir());
    let Ok(config) = fs::read_to_string(mirror.join("config")) else {
        return false;
    };
    let mut keys: &[&str] = &[];
    let mut origin = None;
    for line in config
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if let Some((_, allowed)) = MIRROR_CONFIG.iter().find(|(section, _)| *section == line) {
            keys = allowed;
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return false;
        };
        let (key, value) = (key.trim().to_ascii_lowercase(), value.trim());
        // git fetches from the first `url` and reports the last.
        if !keys.contains(&key.as_str())
            || value.ends_with('\\')
            || (key == "url" && origin.is_some())
        {
            return false;
        }
        if key == "url" {
            origin = Some(value);
        }
    }
    let hooks = mirror.join("hooks");
    let no_hooks = !hooks.exists()
        || (is_dir(&hooks)
            && fs::read_dir(&hooks).is_ok_and(|entries| {
                entries.flatten().all(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name.ends_with(".sample"))
                })
            }));
    // makepkg takes a URL with or without the `.git` as the same one.
    let bare = |url: &str| url.strip_suffix(".git").unwrap_or(url).to_string();
    is_dir(mirror)
        && origin.map(bare) == Some(bare(url))
        && no_hooks
        && !["commondir", "config.worktree", "gitdir"]
            .iter()
            .any(|name| mirror.join(name).exists())
}

/// The first version-control source whose checkout is already there, in
/// the recipe's directory (where makepkg looks first) or the download
/// directory, and is not a plain git mirror: makepkg would run that tool
/// inside a directory someone else may have laid out.
fn foreign_checkout<'a>(sources: &'a [aur::Source], dirs: &Dirs) -> Option<&'a str> {
    sources
        .iter()
        .map(|source| source.entry.as_str())
        .filter(|entry| aur::is_vcs_source(entry))
        .find(|entry| {
            [&dirs.startdir, &dirs.srcdest].iter().any(|directory| {
                let checkout = directory.join(aur::source_filename(entry));
                fs::symlink_metadata(&checkout).is_ok()
                    && !(aur::source_protocol(entry) == "git"
                        && is_plain_mirror(&checkout, aur::git_source_url(entry)))
            })
        })
}

/// The source checks: printed, blocking when a source can be replaced in
/// transit, and otherwise facts for the AI in Guardian's own words.
fn source_context(sources: &[aur::Source], uses_sources: bool) -> Result<Vec<String>, ()> {
    let checks = aur::check_sources(sources);
    print_warnings("Source checks", &checks.warnings);
    if !checks.blocking.is_empty() {
        // A call that only downloads (to verify, or to generate the very
        // checksums that are missing) builds nothing from them. One that
        // builds from a tree extracted earlier (`--noextract`) does.
        if uses_sources {
            print_warnings("Source checks (blocking)", &checks.blocking);
            return Err(());
        }
        print_warnings("Source checks (these block a build)", &checks.blocking);
    }
    Ok(checks
        .context
        .iter()
        .map(|line| format!("Guardian's source check: {line}"))
        .collect())
}

/// How much upstream code the AI may be sent: the AUR class's input limit
/// times its chunks, and at least a partial review's worth.
fn upstream_budget(settings: &Settings) -> u64 {
    let aur = settings.agent_settings(SourceClass::Aur);
    u64::try_from(aur.max_input_bytes.saturating_mul(aur.max_chunks))
        .unwrap_or(u64::MAX)
        .max(aur::PARTIAL_REVIEW_BYTES)
}

/// Why the listed sources must not be fetched, as a message and its short
/// form: the recipe is not the package it sits in, a source would be
/// written outside the downloads, or a checkout to update is not makepkg's.
fn fetch_refusal(
    step: &UpstreamStep<'_>,
    pkgbase: &str,
    sources: &[aur::Source],
    dirs: &Dirs,
) -> Option<(String, &'static str)> {
    // The package base names the source tree under a shared build
    // directory, which the fetch replaces.
    if let Some(base) = step.base
        && base != pkgbase
    {
        return Some((
            format!("the PKGBUILD's pkgbase {pkgbase:?} is not its AUR repository's ({base})."),
            "the PKGBUILD names another package as its base",
        ));
    }
    if let Some(entry) = misnamed_source(sources) {
        return Some((
            format!("a source is kept under a name that is not a file name: {entry:?}."),
            "a source is named as a path",
        ));
    }
    // Whether Guardian fetches or the build does, makepkg updates it.
    let entry = foreign_checkout(sources, dirs)?;
    Some((
        format!(
            "there is already a checkout for {entry:?} that is not a plain git mirror of it; remove it to fetch the source afresh."
        ),
        "an existing source checkout is not a plain mirror",
    ))
}

/// What reading the recipe's text says about a listing of it.
#[derive(Debug, PartialEq, Eq)]
enum Followed {
    /// The listing is what the recipe writes out, or the recipe works its
    /// sources out the same way wherever it is loaded.
    Yes,
    /// Written out plainly, and the listing gave something else for this
    /// array: the recipe told the listing another thing than its text says.
    Differs(String),
    /// Set where Guardian cannot follow (`line N: why`): the listing shows
    /// what the recipe gave in the jail, which the build need not repeat.
    No(Vec<String>),
}

fn followed(recipe: &str, srcinfo: &str) -> Followed {
    match recipe::sources(recipe) {
        Sources::Written(arrays) => match aur::written_mismatch(&arrays, srcinfo) {
            Some(array) => Followed::Differs(array),
            None => Followed::Yes,
        },
        Sources::Derived => Followed::Yes,
        Sources::NotFollowed(reasons) => Followed::No(reasons),
    }
}

/// A hash of `parts`, each kept apart, as what a confirmation is remembered
/// by: the same question about the same thing is not asked twice.
fn confirmation(kind: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update(&[0]);
    }
    format!("{kind} {}", hasher.finalize())
}

/// The fact the AI is given about a recipe whose sources are not followed.
const NOT_FOLLOWED_FACT: &str = "Guardian established that this recipe sets its sources, their \
checksums or makepkg's directories where Guardian cannot follow (under a condition, in a \
function, through eval or a command that assigns). Guardian fetches and reviews the sources the \
recipe lists in a sandbox without network; the build loads the recipe again and may arrive at \
others. Weigh whether the recipe's top-level code can tell the two apart or act on it.";

/// Asks about a recipe whose sources Guardian cannot follow, unless the
/// user said yes to this very recipe before. False when the build must not
/// go on.
fn confirm_not_followed(
    step: &UpstreamStep<'_>,
    reasons: &[String],
    confirm: &mut dyn Confirm,
) -> bool {
    outln!("Source listing: the recipe sets what it fetches where Guardian cannot follow:");
    for reason in reasons {
        outln!("  ! {reason}");
    }
    let asked = confirmation("sources", &[step.recipe]);
    if step.state.is_confirmed(&asked) {
        outln!("  You confirmed this recipe as it is before.");
        return true;
    }
    outln!(
        "  Guardian reviews the sources the recipe listed in its sandbox; the build loads the recipe again and can arrive at others."
    );
    let question = format!(
        "The PKGBUILD of {} computes its sources where Guardian cannot follow. Go on with it?",
        step.name
    );
    if confirm.confirm(&question) {
        step.state.remember_confirmed(&asked);
        return true;
    }
    false
}

/// Prebuilt programs among the sources that end up installed or run: no
/// one reviewed them, and no one can.
#[derive(Debug, Default, PartialEq, Eq)]
struct Prebuilt {
    /// The programs, with their hashes.
    programs: BTreeMap<String, String>,
    /// Those the recipe's functions or install scripts run.
    run: Vec<String>,
    /// Where the sources were downloaded from.
    hosts: Vec<String>,
}

impl Prebuilt {
    /// What the user and the AI are told.
    fn statement(&self) -> String {
        let from = if self.hosts.is_empty() {
            "that came with its sources".to_string()
        } else {
            format!("downloaded from {}", self.hosts.join(", "))
        };
        format!(
            "this package installs {} prebuilt program(s) nobody reviewed, {from}{}",
            self.programs.len(),
            if self.run.is_empty() {
                String::new()
            } else {
                format!(
                    "; its recipe runs {} of them during the build or the install",
                    self.run.len()
                )
            }
        )
    }

    /// What a yes is remembered by: these very programs from these hosts.
    /// `None` when one of them could not be hashed: it could be anything
    /// next time.
    fn asked(&self) -> Option<String> {
        if self.programs.values().any(String::is_empty) {
            return None;
        }
        let mut parts: Vec<&str> = Vec::new();
        for (path, digest) in &self.programs {
            parts.extend([path.as_str(), digest.as_str()]);
        }
        parts.push("from");
        parts.extend(self.hosts.iter().map(String::as_str));
        Some(confirmation("prebuilt", &parts))
    }
}

/// The prebuilt programs of a package the user has to say yes to: all of
/// them when the recipe builds nothing (no `build()`: the package is made
/// of what it downloads), else the ones the recipe names, runs, or takes
/// out of an archive it opens itself. A source tree that only carries a
/// binary among its test data is not asked about.
fn prebuilt(step: &UpstreamStep<'_>, upstream: &Upstream, sources: &[aur::Source]) -> Prebuilt {
    let functions = step.functions;
    let mut run: Vec<String> = Vec::new();
    for (_, text) in &functions.files {
        for (_, _, target) in aur::recipe_runs(text, &functions.variables) {
            let found = upstream
                .unread
                .keys()
                .chain(upstream.programs.keys())
                .find(|path| aur::is_target(path, &target));
            if let Some(path) = found
                && !run.contains(path)
            {
                run.push(path.clone());
            }
        }
    }
    let builds = aur::defines_function(step.recipe, "build");
    let named = |path: &str| {
        let name = path.rsplit('/').next().unwrap_or(path);
        path.contains("!/") || (name.len() >= 5 && functions.written.contains(name))
    };
    let mut programs: BTreeMap<String, String> = upstream
        .programs
        .iter()
        .filter(|(path, _)| !builds || named(path) || run.contains(*path))
        .map(|(path, digest)| (path.clone(), digest.clone()))
        .collect();
    for path in &run {
        let digest = upstream.unread.get(path).cloned().unwrap_or_default();
        programs.entry(path.clone()).or_insert(digest);
    }
    let mut hosts: Vec<String> = sources
        .iter()
        .filter_map(|source| aur::source_host(&source.entry))
        .collect();
    hosts.sort();
    hosts.dedup();
    Prebuilt {
        programs,
        run,
        hosts,
    }
}

/// The most programs named one by one before the question.
const MAX_PROGRAMS_NAMED: usize = 8;

/// Says plainly that the package installs prebuilt programs and asks,
/// unless the user said yes to these very programs before. False when the
/// build must not go on.
fn confirm_prebuilt(
    step: &UpstreamStep<'_>,
    prebuilt: &Prebuilt,
    confirm: &mut dyn Confirm,
) -> bool {
    if prebuilt.programs.is_empty() {
        return true;
    }
    outln!("Prebuilt programs: {}.", prebuilt.statement());
    for path in prebuilt.programs.keys().take(MAX_PROGRAMS_NAMED) {
        outln!("  ! {path}");
    }
    if prebuilt.programs.len() > MAX_PROGRAMS_NAMED {
        outln!(
            "  and {} more",
            prebuilt.programs.len() - MAX_PROGRAMS_NAMED
        );
    }
    let asked = prebuilt.asked();
    if asked
        .as_deref()
        .is_some_and(|asked| step.state.is_confirmed(asked))
    {
        outln!("  You confirmed these programs, from these hosts, before.");
        return true;
    }
    let question = format!(
        "{} installs {} prebuilt program(s) nobody reviewed. Build and install it?",
        step.name,
        prebuilt.programs.len()
    );
    if confirm.confirm(&question) {
        if let Some(asked) = asked {
            step.state.remember_confirmed(&asked);
        }
        return true;
    }
    false
}

/// The most changed binaries named one by one.
const MAX_BINARIES_NAMED: usize = 8;

/// What the binaries among the sources are now, held against the ones of
/// the last build of this package that passed: printed, and a fact for the
/// AI. `None` when they are the same, or there was no such build.
fn binary_changes(step: &UpstreamStep<'_>, upstream: &Upstream) -> Option<String> {
    let known = step.state.binaries()?;
    let (changed, gone) = state::binary_changes(&known, &all_binaries(upstream));
    if changed.is_empty() && gone.is_empty() {
        return None;
    }
    outln!(
        "Binaries: {} new or changed and {} gone since the last build of this package Guardian let through:",
        changed.len(),
        gone.len()
    );
    for path in changed.iter().take(MAX_BINARIES_NAMED) {
        outln!("  ! {path} (new or changed)");
    }
    if changed.len() > MAX_BINARIES_NAMED {
        outln!("  and {} more", changed.len() - MAX_BINARIES_NAMED);
    }
    Some(format!(
        "Guardian compared the binary files among these sources, which it cannot review, with those of the last build of this package it let through: {} are new or changed and {} are gone.",
        changed.len(),
        gone.len()
    ))
}

/// Every binary among the sources that is not reviewed, with its hash.
fn all_binaries(upstream: &Upstream) -> BTreeMap<String, String> {
    let mut binaries = upstream.unread.clone();
    binaries.extend(
        upstream
            .programs
            .iter()
            .map(|(path, digest)| (path.clone(), digest.clone())),
    );
    binaries
}

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

/// Holds the sources as a call that does not extract finds them against
/// what Guardian extracted for this build. `Err` is why the build must not
/// go on; `Ok` holds facts for the AI about what changed in between.
fn hold_against_extraction(
    step: &UpstreamStep<'_>,
    srcdir: &Path,
    collected: &mut aur::Collected,
) -> Result<Vec<String>, String> {
    let extraction = step
        .state
        .extraction()
        .filter(|extraction| Path::new(&extraction.srcdir) == srcdir);
    let Some(extraction) = extraction else {
        outln!(
            "Sources: Guardian has no record of extracting them for this build; they are reviewed as they are now."
        );
        return Ok(vec![
            "Guardian did not extract these sources itself for this build: they are reviewed as an earlier makepkg run left them.".into(),
        ]);
    };
    let identity = state::identity(srcdir);
    let seen = collected.upstream();
    match extraction.drift(identity.as_deref(), &seen.downloads, &seen.seen) {
        Drift::Elsewhere => Err(format!(
            "makepkg did not extract the sources into the directory Guardian reviewed ({}): the build's own extraction and prepare() ran somewhere else, or not at all.",
            srcdir.display()
        )),
        Drift::Downloads(names) => Err(format!(
            "the build uses download(s) that are not the ones Guardian fetched and reviewed: {}.",
            names
                .iter()
                .take(MAX_BINARIES_NAMED)
                .map(|name| format!("{name:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        )),
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

/// Records what Guardian extracted, for the calls that follow.
fn record_extraction(step: &UpstreamStep<'_>, srcdir: &Path, collected: &aur::Collected) {
    let seen = collected.upstream();
    let cleans = step
        .mirrored
        .iter()
        .any(|argument| argument == "-C" || argument == "--cleanbuild");
    step.state.record_extraction(&Extraction {
        srcdir: srcdir.to_string_lossy().into_owned(),
        identity: state::identity(srcdir),
        cleanbuild: cleans,
        downloads: Extraction::keyed(&seen.downloads),
        files: Extraction::keyed(&seen.seen),
    });
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
            if !confirm_not_followed(step, &reasons, confirm) {
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
    if step.extract {
        record_extraction(step, &srcdir, &collected);
    } else if collected.upstream().found {
        let changed = hold_against_extraction(step, &srcdir, &mut collected).map_err(|why| {
            block(
                step,
                &why,
                "the sources are not the ones Guardian fetched and reviewed",
                2,
            )
        })?;
        context.extend(changed);
    }
    let upstream = collected.select(budget);
    drop(scratch);
    Ok(upstream)
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
    if !sources.is_empty() && !upstream.found && !step.extract && upstream.gaps.is_empty() {
        // A call that only downloads: there is nothing extracted to review
        // yet, and it extracts nothing either.
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
    context.extend(dependency_facts(&upstream));
    context.extend(binary_changes(step, &upstream));
    let prebuilt = prebuilt(step, &upstream, sources);
    let review = UpstreamReview {
        upstream: &upstream,
        sources,
        prebuilt: &prebuilt,
    };
    let (report, decision) = if upstream.files.is_empty() && upstream.gaps.is_empty() {
        (None, unreviewable_sources(step, &review, confirm))
    } else {
        let (report, decision) = review_upstream_files(step, settings, &review, &context, confirm);
        (Some(report), decision)
    };
    let content = upstream_content(step, &upstream, sources);
    let standing = settle_upstream(step, settings, content, report, decision);
    match decision {
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
        Decision::Blocked(Blocked::NotConfirmed) => {
            let exit = not_confirmed();
            standing.say();
            Err(exit)
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
/// Sources with no text to review. That is no clear review: the binaries
/// are still recorded and compared (by the caller), and a package made of
/// prebuilt programs still needs the user's yes.
fn unreviewable_sources(
    step: &UpstreamStep<'_>,
    review: &UpstreamReview<'_>,
    confirm: &mut dyn Confirm,
) -> Decision {
    outln!(
        "Upstream: no text sources to review{}.",
        if review.upstream.binary_files > 0 {
            format!(
                " ({} binary file(s), which Guardian cannot review)",
                review.upstream.binary_files
            )
        } else {
            String::new()
        }
    );
    if confirm_prebuilt(step, review.prebuilt, confirm) {
        Decision::Clear
    } else {
        Decision::Blocked(Blocked::NotConfirmed)
    }
}

/// The top-level names makepkg downloads a source list into when
/// `SRCDEST` is the build directory. Never `PKGBUILD`: makepkg keeps the
/// one that is there, which must stay as reviewed.
fn download_names(sources: &[aur::Source]) -> Vec<String> {
    let mut names: Vec<String> = sources
        .iter()
        .filter(|source| aur::source_protocol(&source.entry) != "local")
        .map(|source| aur::source_filename(&source.entry))
        .filter(|name| !name.is_empty() && name != "PKGBUILD")
        .collect();
    names.sort();
    names.dedup();
    names
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

/// Facts about what the upstream review cannot see.
fn upstream_facts(review: &UpstreamReview<'_>) -> Vec<String> {
    let upstream = review.upstream;
    let mut facts = Vec::new();
    if upstream.binary_files > 0 {
        facts.push(format!(
            "The sources hold {} binary file(s) Guardian cannot review{}.",
            upstream.binary_files,
            if upstream.executables.is_empty() {
                String::new()
            } else {
                format!(
                    ", including {} executable(s) listed in upstream-summary",
                    upstream.executables.len()
                )
            }
        ));
    }
    if !review.prebuilt.programs.is_empty() {
        facts.push(format!(
            "Guardian established that {}. It asks the user to confirm that itself; the programs are not among the supplied files.",
            review.prebuilt.statement()
        ));
    }
    let left_out = upstream.omitted.len() + upstream.left_out;
    if left_out > 0 || upstream.data_files > 0 {
        facts.push(format!(
            "Guardian left {left_out} code file(s) and {} data or documentation file(s) out of this review (upstream-summary names some); build files, scripts and files a build file names were not left out. Guardian checks itself whether a supplied line runs or reads in a file that was left out.",
            upstream.data_files
        ));
    }
    if !upstream.unpacked.is_empty() {
        facts.push(format!(
            "Guardian unpacked {} archive(s) the recipe opens itself; their files are supplied under the archive's path followed by `!`.",
            upstream.unpacked.len()
        ));
    }
    if !upstream.lockfiles.is_empty() {
        facts.push(
            "Guardian scanned the dependency lockfiles itself for where they fetch from; upstream-summary holds what it found, and lockfiles too large to send are not among the supplied files."
                .into(),
        );
    }
    facts
}

/// The most left-out files named one by one in the summary.
const MAX_LEFT_OUT_NAMED: usize = 40;

/// The raw source entries and what was left out, as untrusted data.
fn upstream_summary(review: &UpstreamReview<'_>) -> String {
    let upstream = review.upstream;
    let mut summary = String::from("Source entries:\n");
    for (index, source) in review.sources.iter().enumerate() {
        let _ = writeln!(summary, "{}. {}", index + 1, source.entry);
    }
    if !upstream.executables.is_empty() {
        summary.push_str("\nExecutable binaries:\n");
        for path in &upstream.executables {
            let _ = writeln!(summary, "{path}");
        }
    }
    if !upstream.unpacked.is_empty() {
        summary.push_str("\nArchives Guardian unpacked:\n");
        for path in &upstream.unpacked {
            let _ = writeln!(summary, "{path}");
        }
    }
    if !upstream.lockfiles.is_empty() {
        summary.push_str("\nDependency lockfiles, as Guardian scanned them:\n");
        for line in upstream.lockfiles.iter().take(MAX_LEFT_OUT_NAMED) {
            let _ = writeln!(summary, "{line}");
        }
    }
    if upstream.changed.0 > 0 {
        let _ = writeln!(
            summary,
            "\nChanged since Guardian extracted the sources: {} file(s), {} of them supplied.",
            upstream.changed.0, upstream.changed.1
        );
    }
    let left_out = upstream
        .omitted
        .iter()
        .map(|(path, reason)| (format!("src/{path}"), *reason))
        .chain(
            upstream
                .unreviewed
                .iter()
                .filter(|(_, reason)| *reason != aur::NOT_REVIEWED_DATA)
                .cloned(),
        );
    let total = left_out.clone().count();
    if total > 0 {
        summary.push_str("\nLeft out:\n");
        for (path, reason) in left_out.take(MAX_LEFT_OUT_NAMED) {
            let _ = writeln!(summary, "{path}: {reason}");
        }
        if total > MAX_LEFT_OUT_NAMED {
            let _ = writeln!(
                summary,
                "and {} more, not named here",
                total - MAX_LEFT_OUT_NAMED
            );
        }
    }
    summary
}

/// A file the upstream code or the recipe runs or reads in as code that
/// was not reviewed as text (a binary, or one left out) leaves the review
/// incomplete: the build runs it. A prebuilt program the recipe runs is
/// asked about instead (see `prebuilt`): it could not be reviewed anyway.
fn upstream_runs(report: &mut Report, step: &UpstreamStep<'_>, upstream: &Upstream) {
    for file in &upstream.files {
        for (index, line) in file.text.lines().enumerate() {
            for target in rules::run_targets(line) {
                if report.runs.len() >= review::MAX_RUNS {
                    report.runs_overflowed = true;
                    break;
                }
                report.runs.push(RunRef {
                    rel: file.path.clone(),
                    line: index + 1,
                    excerpt: line.trim().chars().take(200).collect(),
                    target,
                });
            }
        }
    }
    let unread: Vec<(String, String)> = upstream
        .omitted
        .iter()
        .map(|(path, why)| (format!("src/{path}"), (*why).to_string()))
        .chain(
            upstream
                .unreviewed
                .iter()
                .map(|(path, why)| (path.clone(), (*why).to_string())),
        )
        .chain(
            upstream
                .unread
                .keys()
                .map(|path| (path.clone(), "binary".to_string())),
        )
        .collect();
    review::check_runs(report, &unread);
    // The recipe's own functions run in the source tree as well, from
    // whichever of its directories they change into.
    let mut gapped: HashSet<(String, String)> = HashSet::new();
    for (name, text) in &step.functions.files {
        for (line, _, target) in aur::recipe_runs(text, &step.functions.variables) {
            let left_out = unread
                .iter()
                .filter(|(path, _)| !upstream.unread.contains_key(path))
                .find(|(path, _)| aur::is_target(path, &target));
            if let Some((path, why)) = left_out
                && gapped.len() < MAX_LEFT_OUT_NAMED
                && gapped.insert((name.clone(), path.clone()))
            {
                report.gaps.push(Gap::RunsUnread(format!(
                    "{name}:{line} runs or reads in {path} ({why}), which was not sent for review"
                )));
            }
        }
    }
}

/// Reviews the upstream files; the report is the caller's to print, once
/// it knows how the decision stands with permits (see `settle_upstream`).
fn review_upstream_files(
    step: &UpstreamStep<'_>,
    settings: &Settings,
    review: &UpstreamReview<'_>,
    context: &[String],
    confirm: &mut dyn Confirm,
) -> (Report, Decision) {
    let upstream = review.upstream;
    let state_root = Store::default_root();
    let mut context = context.to_vec();
    context.extend(upstream_facts(review));
    let review_context = ReviewContext {
        settings,
        class: SourceClass::Aur,
        opencode: &OpenCode::UserPath,
        units: &[],
        state_root: state_root.as_deref(),
        context: &context,
    };
    let mut report = review::collected_report(
        format!("{} · upstream sources", step.build_dir.display()),
        &review_context,
    );
    for file in &upstream.files {
        review::analyze_upstream(&mut report, &file.path, &file.text);
    }
    review::analyze_payload(&mut report, "upstream-summary", &upstream_summary(review));
    for gap in &upstream.gaps {
        report.gaps.push(Gap::Package(Error::Refused(gap.clone())));
    }
    upstream_runs(&mut report, step, upstream);
    report.unread.clone_from(&upstream.unread);
    let units: Vec<Unit> = Identity::parse(&format!("aur-src:{}", step.key))
        .map(|identity| {
            vec![Unit {
                prefix: String::new(),
                identity,
            }]
        })
        .unwrap_or_default();
    let report = review::review_collected(report, &review_context, &units);
    let mut decision = report.decide(&|class| settings.policy(class));
    outln!(
        "Upstream: {} of {} code and build file(s) reviewed{}; {} data or documentation file(s), {} binary file(s) not reviewed{}.",
        upstream.files.len(),
        upstream.text_files,
        if upstream.whole {
            " (all of them)".to_string()
        } else {
            format!(
                " (build files and scripts first, then code by depth; {} code file(s) past the review budget)",
                upstream.left_out
            )
        },
        upstream.data_files,
        upstream.binary_files,
        if upstream.omitted.is_empty() {
            String::new()
        } else {
            format!("; {} other file(s) left out", upstream.omitted.len())
        }
    );
    for line in upstream
        .lockfiles
        .iter()
        .filter(|line| !line.ends_with("all on its registry"))
        .take(MAX_BINARIES_NAMED)
    {
        outln!("  ! lockfile {line}");
    }
    // Asked only of a build the review lets through, and never in its
    // place: a yes approves the programs, not the code beside them.
    // (`Limited` is a review with `ai = off`, which the build goes on from.)
    let passes = !matches!(decision, Decision::Blocked(_));
    if passes && !confirm_prebuilt(step, review.prebuilt, confirm) {
        decision = Decision::Blocked(Blocked::NotConfirmed);
    }
    (report, decision)
}

/// Forgets what the gate remembers of the source `identity` names
/// (`aur:<pkg>`, `aur-src:<pkg>`, or a local build's own key) under the
/// review memory's `root`: the questions answered, the binaries and what
/// was extracted. Returns how many records went.
pub fn forget(root: &Path, identity: &str) -> Result<usize, String> {
    let key = identity
        .strip_prefix("aur:")
        .or_else(|| identity.strip_prefix("aur-src:"))
        .unwrap_or(identity);
    state::forget(root, key)
}

/// Forgets everything the gate remembers under `root`.
pub fn forget_all(root: &Path) -> Result<usize, String> {
    state::forget_all(root)
}

/// The AUR's record of the package base `base`, looked up by `names`.
fn aur_info(base: &str, names: &[String]) -> Result<Option<AurInfo>, Error> {
    let query: Vec<String> = names
        .iter()
        .filter(|name| pacman::is_valid_package_name(name))
        .take(20)
        .map(|name| format!("arg[]={}", url_encoded(name)))
        .collect();
    if query.is_empty() {
        return Ok(None);
    }
    let mut args = osv::curl_args();
    args.push(format!("{RPC_URL}?{}", query.join("&")).into());
    let body = tools::run(Path::new(tools::CURL), &args, None, &[], RPC_LIMITS)?.into_success()?;
    let reply = Json::parse(&String::from_utf8_lossy(&body))
        .map_err(|error| Error::parse("the AUR reply", error))?;
    Ok(aur::parse_rpc_info(&reply, base))
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
pub fn parse(args: &[OsString]) -> Result<Vec<OsString>, String> {
    match args.split_first() {
        Some((separator, rest)) if separator == "--" && !rest.is_empty() => Ok(rest.to_vec()),
        _ => Err("usage: omarchy-guardian makepkg-gate -- <makepkg> [args...]".into()),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    use std::fs;
    use std::process::Command;

    use super::{
        Blocked, Configured, Confirm, Decision, Followed, Functions, Prebuilt, State, Upstream,
        UpstreamReview, UpstreamStep, all_binaries, aur, binary_changes, confirm_not_followed,
        confirm_prebuilt, download_names, fetch_recipe, followed, foreign_checkout,
        hold_against_extraction, is_jailable, is_plain_mirror, listing_recipe, listing_report,
        mirrored_arguments, misnamed_source, parse, prebuilt, public_keyring, recipe_functions,
        record_extraction, source_context, state, tools, unpack, unreviewable_sources,
        upstream_facts, upstream_runs, upstream_summary, with_mounts,
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
        fixture.state.record_binaries(&all_binaries(&upstream));
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
        let listing = "pkgbase = demo\n\tpkgver = 1\n\tsource = a.tar\n\tsha256sums = abc\n\npkgname = demo\n";
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
        assert!(!confirm_not_followed(&fixture.step(), &reasons, &mut no));
        let mut yes = answer(true);
        assert!(confirm_not_followed(&fixture.step(), &reasons, &mut yes));
        // The same recipe is not asked about again; a changed one is.
        assert!(confirm_not_followed(&fixture.step(), &reasons, &mut no));
        assert_eq!((no.asked, yes.asked), (1, 1));
        let other = Fixture {
            recipe: format!("{hidden}# changed\n"),
            ..fixture
        };
        assert!(!confirm_not_followed(&other.step(), &reasons, &mut no));
        assert_eq!(no.asked, 2);
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

        record_extraction(&step, &src, &fixture.collected());
        // The build cleans first (`-C`), so a source directory that is
        // still the one Guardian made was not the build's.
        let refused = hold_against_extraction(&step, &src, &mut fixture.collected());
        if state::identity(&src).is_some() {
            assert!(
                refused
                    .unwrap_err()
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
        record_extraction(&step, &src, &fixture.collected());
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
            .contains(
                "Changed since Guardian extracted the sources: 2 file(s), 2 of them supplied."
            )
        );

        // A download that is not the one Guardian fetched: the listing did
        // not show what the build uses.
        fs::write(build.join("demo.tar.gz"), b"\x1f\x8b\x08\0two").unwrap();
        fs::write(build.join("extra.bin"), ELF).unwrap();
        std::os::unix::fs::symlink(build.join("extra.bin"), src.join("extra.bin")).unwrap();
        let refused = hold_against_extraction(&step, &src, &mut fixture.collected()).unwrap_err();
        assert!(
            refused.contains(
                "not the ones Guardian fetched and reviewed: \"demo.tar.gz\", \"extra.bin\""
            ),
            "{refused}"
        );
    }

    #[test]
    fn an_archive_the_recipe_opens_is_unpacked_and_reviewed() {
        if !crate::test_support::tool_available(tools::BSDTAR) {
            return;
        }
        let recipe = "pkgname=demo-bin\npackage() {\n  bsdtar -xf \"$srcdir\"/data.tar.* -C \"$pkgdir\"\n}\n";
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
        // An archive nothing in the recipe names stays packed.
        fs::write(src.join("vendored.jar"), b"PK\x03\x04\x14\0\0\0").unwrap();

        // Left packed, the review is incomplete: the recipe opens it.
        let packed = fixture.upstream();
        assert!(
            packed.gaps.iter().any(|gap| gap
                .starts_with("src/data.tar.gz: the recipe opens this archive itself")),
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
            ["src/data.tar.gz!/opt/demo/demo"]
        );
        let facts = upstream_facts(&UpstreamReview {
            upstream: &upstream,
            sources: &[],
            prebuilt: &found,
        })
        .join("\n");
        assert!(facts.contains("Guardian unpacked 1 archive(s)"), "{facts}");
        assert!(
            facts.contains("installs 1 prebuilt program(s) nobody reviewed"),
            "{facts}"
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
}
