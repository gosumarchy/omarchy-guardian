//! `omarchy-guardian makepkg-gate -- <makepkg> [args...]`, run by the yay
//! makepkg shim in the AUR build directory. Beyond `guard` on the recipe it:
//!
//! 1. refuses a recipe that moves makepkg's build or download directories,
//!    and establishes whether the directory is a clone of an AUR package,
//!    whose trust signals (new, unvoted, orphaned, recently changed by
//!    someone other than its submitter) then go to the AI review as facts;
//! 2. reviews the recipe (PKGBUILD, install script, patches) as before;
//! 3. for a call that runs PKGBUILD functions, runs makepkg from a hidden
//!    copy of the recipe whose `pkgver()`, `prepare()` and `verify()` do
//!    nothing: first to read the source list and where makepkg will put
//!    the sources (`BUILDDIR`, `SRCDEST`), then to fetch and extract them.
//!    No upstream code runs before its review. Unverified or unpinned
//!    sources are reported, sources anyone on the network can replace
//!    block, and the AI reviews what runs during the build;
//! 4. checks the recipe once more and starts makepkg with the original
//!    arguments, plus `--holdver` after a pre-extraction so the build does
//!    not fetch newer VCS sources than were reviewed, and the probed
//!    directories pinned.

use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::aur::{self, AurInfo, Roots, Upstream};
use crate::cli::{Target, TtyConfirm, review_and_decide};
use crate::config::Settings;
use crate::config::model::SourceClass;
use crate::engine::baseline::{Identity, Unit};
use crate::engine::store::Store;
use crate::error::{Error, IoContext};
use crate::json::Json;
use crate::notify::{self, Ran};
use crate::osv;
use crate::pacman;
use crate::report::{Blocked, Decision, Gap};
use crate::review::{self, ReviewContext};
use crate::sandbox::Workspace;
use crate::scan::{self, ScanConfig, Snapshot};
use crate::sha256::Sha256;
use crate::tools::{self, Limits, OpenCode};

const RPC_URL: &str = "https://aur.archlinux.org/rpc/v5/info";
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

/// Ends the hidden recipe copy: the functions that run on downloaded
/// sources before their review do nothing (`pkgver()` keeps the current
/// version, so makepkg never rewrites the recipe), and the directories
/// makepkg settled on are reported. Nothing untrusted in it: `token` is the
/// copy's random name, which only keeps it apart from the recipe's own
/// names (a recipe can read it from its file name).
///
/// The recipe's own code ran first and may have made its functions
/// read-only or aliased their names, so the replacements are checked by the
/// token in their bodies (an assignment: no command a recipe could have
/// redefined) and then made read-only themselves. The report is written
/// only when they took, and the gate needs it from every run of the copy;
/// otherwise makepkg stops. This is a check inside a shell the recipe has
/// already run in, so it catches what a recipe can do in passing, not a
/// recipe written to defeat it: that one has to get past its own review.
fn trailer(token: &str) -> String {
    format!(
        "
pkgver() {{ guardian_{token}=1; printf '%s\\n' \"$pkgver\"; }}
prepare() {{ guardian_{token}=1; }}
verify() {{ guardian_{token}=1; }}
readonly -f pkgver prepare verify
if [[ $(declare -f pkgver) == *guardian_{token}=1* && $(declare -f prepare) == *guardian_{token}=1* && $(declare -f verify) == *guardian_{token}=1* ]]; then
  if [[ -n ${{GUARDIAN_PROBE:-}} ]]; then
    printf '%s\\0%s\\0%s\\0%s\\0' \"$BUILDDIR\" \"$SRCDEST\" \"${{pkgbase:-${{pkgname[0]}}}}\" \"$startdir\" >\"$GUARDIAN_PROBE\"
  fi
else
  exit 1
fi
"
    )
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

    // 2. The recipe.
    let target = recipe_target(&build_dir, &key, base.is_some());
    let mut recipe_context = vec![aur::RECIPE_SCOPE.to_string()];
    recipe_context.extend(facts.iter().cloned());
    let (report, decision) = review_and_decide(
        &target,
        settings,
        &OpenCode::UserPath,
        Some(&mut TtyConfirm),
        &recipe_context,
    );
    if !decision.allows_running() {
        errln!("Guardian blocked makepkg because the review of the recipe did not allow it.");
        notify_block(&directory_name, decision, "the recipe", Ran::Nothing);
        return decision.exit_code();
    }
    if let Err(error) = scan::verify_unchanged(&target.config, &report.snapshot) {
        errln!("Guardian blocked makepkg because {error}.");
        notify::blocked(&subject(&directory_name), &error.to_string(), Ran::Nothing);
        return ExitCode::from(2);
    }

    // 3. The upstream sources, for a call that runs PKGBUILD functions.
    let invocation = aur::classify(arguments);
    let mut pinned: Option<Probe> = None;
    let mut downloads: Vec<String> = Vec::new();
    if invocation.runs_functions {
        let step = UpstreamStep {
            makepkg: Path::new(makepkg),
            mirrored: &mirrored,
            build_dir: &build_dir,
            name: &directory_name,
            key: &key,
            base: base.as_deref(),
            recipe: &recipe,
            extract: invocation.extracts,
        };
        match review_upstream(&step, settings, facts) {
            Ok(outcome) => {
                downloads = outcome.downloads;
                pinned = Some(outcome.probe);
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
        notify::blocked(&subject(&directory_name), &error.to_string(), ran);
        return ExitCode::from(2);
    }
    start_build(Path::new(makepkg), arguments, invocation.extracts, pinned)
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
/// code than was reviewed), with the probed directories pinned.
fn start_build(
    makepkg: &Path,
    arguments: &[OsString],
    extracted: bool,
    pinned: Option<Probe>,
) -> ExitCode {
    errln!("Guardian: review clear; starting {}", makepkg.display());
    let mut arguments = arguments.to_vec();
    if extracted && !arguments.iter().any(|arg| arg == "--holdver") {
        arguments.push("--holdver".into());
    }
    drop(io::stdout().flush());
    let mut build = Command::new(makepkg);
    build.args(&arguments);
    if let Some(probe) = pinned {
        build.env("BUILDDIR", &probe.builddir);
        build.env("SRCDEST", &probe.srcdest);
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

/// A crashed run's hidden recipe copy must not linger in the recipe.
fn remove_stale_copies(build_dir: &Path) {
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
            "{directory_name} is not a clone of an AUR package (a local or private PKGBUILD); no AUR facts apply."
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
            let (found, warnings) = aur::trust_signals(&info, now);
            if let Some(summary) = found.first() {
                outln!("{summary}");
            }
            facts.extend(found);
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
        Err(error) => errln!("Guardian: AUR metadata unavailable ({error})."),
    }
    facts
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
    /// The call extracts the sources itself, so they are extracted here
    /// first, without running any PKGBUILD function.
    extract: bool,
}

/// Where makepkg settles, as the recipe copy reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Probe {
    builddir: PathBuf,
    srcdest: PathBuf,
    pkgbase: String,
    startdir: PathBuf,
}

impl Probe {
    fn parse(bytes: &[u8]) -> Option<Self> {
        let text = String::from_utf8(bytes.to_vec()).ok()?;
        let mut fields = text.split('\0');
        let builddir = fields.next()?.to_string();
        let srcdest = fields.next()?.to_string();
        let pkgbase = fields.next()?.to_string();
        let startdir = fields.next()?.to_string();
        if builddir.is_empty() || pkgbase.is_empty() || startdir.is_empty() {
            return None;
        }
        Some(Self {
            srcdest: if srcdest.is_empty() {
                PathBuf::from(&startdir)
            } else {
                PathBuf::from(srcdest)
            },
            builddir: PathBuf::from(builddir),
            pkgbase,
            startdir: PathBuf::from(startdir),
        })
    }

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

/// The hidden recipe copy makepkg runs from (`-p`), removed on drop.
struct RecipeCopy {
    path: PathBuf,
}

impl RecipeCopy {
    fn create(build_dir: &Path, recipe: &str) -> Result<Self, Error> {
        let mut bytes = [0_u8; 8];
        fs::File::open("/dev/urandom")
            .and_then(|mut random| io::Read::read_exact(&mut random, &mut bytes))
            .at(Path::new("/dev/urandom"))?;
        let suffix = bytes.iter().fold(String::new(), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        });
        let path = build_dir.join(format!(".guardian-{suffix}.PKGBUILD"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .at(&path)?;
        file.write_all(recipe.as_bytes())
            .and_then(|()| file.write_all(trailer(&suffix).as_bytes()))
            .at(&path)?;
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

struct UpstreamOutcome {
    probe: Probe,
    /// Top-level names makepkg downloads into the build directory.
    downloads: Vec<String>,
}

/// Runs makepkg from the recipe copy to read the source list and the
/// directories it will use.
fn probe(step: &UpstreamStep<'_>, copy: &RecipeCopy) -> Result<(Vec<aur::Source>, Probe), Error> {
    let workspace = Workspace::create("probe")?;
    let probe_file = workspace.path().join("probe");
    let probe_text = probe_file.display().to_string();
    let mut args: Vec<OsString> = vec!["-p".into(), copy.name(), "--printsrcinfo".into()];
    args.extend(step.mirrored.iter().cloned());
    let captured = tools::run_in(
        step.makepkg,
        &args,
        step.build_dir,
        &[("LC_ALL", "C"), ("GUARDIAN_PROBE", &probe_text)],
        SRCINFO_LIMITS,
    )?
    .into_success()?;
    let sources = aur::parse_srcinfo(&String::from_utf8_lossy(&captured));
    let probe = fs::read(&probe_file)
        .ok()
        .and_then(|bytes| Probe::parse(&bytes))
        .ok_or_else(|| Error::Refused("makepkg did not report where it builds".into()))?;
    Ok((sources, probe))
}

/// Fetches and extracts the sources from the recipe copy, where
/// `pkgver()`, `prepare()` and `verify()` do nothing. A run without the
/// copy's report is one where that was not established: the recipe's own
/// functions may have run on the downloads, and the build is blocked.
fn pre_extract(step: &UpstreamStep<'_>, copy: &RecipeCopy) -> Result<(), String> {
    let workspace = Workspace::create("fetch")
        .map_err(|error| format!("could not prepare the sources ({error})."))?;
    let report = workspace.path().join("probe");
    errln!(
        "Guardian: fetching and extracting the sources for review (makepkg runs the approved PKGBUILD only to download them; pkgver(), prepare() and verify() do not run and nothing is built)..."
    );
    let status = Command::new(step.makepkg)
        .current_dir(step.build_dir)
        .arg("-p")
        .arg(copy.name())
        .args(["--nobuild", "--noprepare", "--nodeps", "--noconfirm"])
        .args(step.mirrored)
        .env("GUARDIAN_PROBE", &report)
        .status()
        .map_err(|error| format!("could not run makepkg to fetch the sources ({error})."))?;
    if !status.success() {
        Err(format!(
            "fetching the sources for review failed ({status})."
        ))
    } else if fs::read(&report).is_ok_and(|bytes| Probe::parse(&bytes).is_some()) {
        Ok(())
    } else {
        Err(
            "the PKGBUILD kept its pkgver(), prepare() or verify() from being switched off for the fetch."
                .into(),
        )
    }
}

/// The source checks: printed, blocking when a source can be replaced in
/// transit, and otherwise facts for the AI in Guardian's own words.
fn source_context(sources: &[aur::Source]) -> Result<Vec<String>, ()> {
    let checks = aur::check_sources(sources);
    print_warnings("Source checks", &checks.warnings);
    if !checks.blocking.is_empty() {
        print_warnings("Source checks (blocking)", &checks.blocking);
        return Err(());
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

/// Returns why makepkg must not start, as an exit code. A block notes that
/// the recipe ran: makepkg sources the recipe copy from the first probe on.
fn review_upstream(
    step: &UpstreamStep<'_>,
    settings: &Settings,
    facts: Vec<String>,
) -> Result<UpstreamOutcome, ExitCode> {
    let block = |message: String, why: &str, code: u8| {
        errln!("Guardian blocked makepkg: {message}");
        notify::blocked(&subject(step.name), why, Ran::RecipeToFetch);
        ExitCode::from(code)
    };
    let copy = RecipeCopy::create(step.build_dir, step.recipe).map_err(|error| {
        block(
            format!("could not prepare the sources ({error})."),
            "the sources could not be prepared for review",
            2,
        )
    })?;
    let (sources, probe) = probe(step, &copy).map_err(|error| {
        block(
            format!("could not read the source list ({error})."),
            "the source list could not be read",
            2,
        )
    })?;
    if let Some(base) = step.base
        && base != probe.pkgbase
    {
        errln!(
            "Guardian: the PKGBUILD's pkgbase {:?} differs from its AUR repository {base}.",
            probe.pkgbase
        );
    }

    let mut context = vec![aur::UPSTREAM_SCOPE.to_string()];
    context.push(if aur::runs_tests(step.recipe) {
        "The recipe defines check(), so the upstream test suite runs during this build.".into()
    } else {
        "The recipe defines no check(), so the upstream test suite does not run during this build."
            .into()
    });
    let checked = source_context(&sources).map_err(|()| {
        block(
            "a source can be replaced in transit.".into(),
            "a source can be replaced in transit",
            1,
        )
    })?;
    context.extend(checked);
    context.extend(facts);

    if step.extract {
        pre_extract(step, &copy)
            .map_err(|message| block(message, "fetching the sources for review failed", 2))?;
    }
    drop(copy);

    let budget = upstream_budget(settings);
    let srcdir = probe.srcdir();
    let roots = Roots {
        build_dir: step.build_dir,
        srcdest: Some(&probe.srcdest),
    };
    let upstream = aur::collect_upstream(&srcdir, &roots, step.recipe, budget);
    let downloads = download_names(&sources);
    if !sources.is_empty() && !upstream.found {
        return Err(block(
            format!(
                "the extracted sources were not found where makepkg put them ({}).",
                srcdir.display()
            ),
            "the extracted sources could not be found for review",
            2,
        ));
    }
    if upstream.files.is_empty() && upstream.gaps.is_empty() {
        outln!(
            "Upstream: no text sources to review{}.",
            if upstream.binary_files > 0 {
                format!(" ({} binary file(s))", upstream.binary_files)
            } else {
                String::new()
            }
        );
        return Ok(UpstreamOutcome { probe, downloads });
    }
    let decision = review_upstream_files(step, settings, &upstream, &context, &sources);
    match decision {
        // Nothing was sent to the AI (`ai = off`): the recipe decision stands.
        Decision::Limited | Decision::Clear | Decision::Warned => {
            Ok(UpstreamOutcome { probe, downloads })
        }
        Decision::Blocked(_) => {
            errln!(
                "Guardian blocked makepkg because the review of the upstream sources did not allow it."
            );
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

/// The top-level names makepkg downloads a source list into when
/// `SRCDEST` is the build directory: `name::` prefixes, or the last URL
/// path segment (a repository's name without `.git`).
fn download_names(sources: &[aur::Source]) -> Vec<String> {
    let mut names: Vec<String> = sources
        .iter()
        .filter(|source| source.entry.contains("://") || source.entry.contains("+lp:"))
        .map(|source| {
            if let Some((name, _)) = source.entry.split_once("::") {
                return name.to_string();
            }
            let url = source.entry.split(['#', '?']).next().unwrap_or_default();
            let last = url
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .unwrap_or_default();
            last.strip_suffix(".git").unwrap_or(last).to_string()
        })
        .filter(|name| !name.is_empty())
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
    let excluded = |path: &str| {
        let top = path.split('/').next().unwrap_or_default();
        downloads.iter().any(|name| name == top)
            || Path::new(top)
                .extension()
                .is_some_and(|extension| extension == "part")
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

/// Facts about what the upstream review cannot see.
fn upstream_facts(upstream: &Upstream) -> Vec<String> {
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
    if !upstream.omitted.is_empty() || upstream.left_out > 0 {
        facts.push(format!(
            "Guardian left {} file(s) out of this review (listed in upstream-summary); build files and scripts were not left out.",
            upstream.omitted.len() + upstream.left_out
        ));
    }
    facts
}

/// The raw source entries and what was left out, as untrusted data.
fn upstream_summary(upstream: &Upstream, sources: &[aur::Source]) -> String {
    let mut summary = String::from("Source entries:\n");
    for (index, source) in sources.iter().enumerate() {
        let _ = writeln!(summary, "{}. {}", index + 1, source.entry);
    }
    if !upstream.executables.is_empty() {
        summary.push_str("\nExecutable binaries:\n");
        for path in &upstream.executables {
            let _ = writeln!(summary, "{path}");
        }
    }
    if !upstream.omitted.is_empty() {
        summary.push_str("\nLeft out:\n");
        for (path, reason) in upstream.omitted.iter().take(40) {
            let _ = writeln!(summary, "src/{path}: {reason}");
        }
    }
    summary
}

fn review_upstream_files(
    step: &UpstreamStep<'_>,
    settings: &Settings,
    upstream: &Upstream,
    context: &[String],
    sources: &[aur::Source],
) -> Decision {
    let state_root = Store::default_root();
    let mut context = context.to_vec();
    context.extend(upstream_facts(upstream));
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
        review::analyze_payload(&mut report, &file.path, &file.text);
    }
    review::analyze_payload(
        &mut report,
        "upstream-summary",
        &upstream_summary(upstream, sources),
    );
    for gap in &upstream.gaps {
        report.gaps.push(Gap::Package(Error::Refused(gap.clone())));
    }
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
    let decision = report.decide(&|class| settings.policy(class));
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
    report.print(false, decision);
    decision
}

/// The AUR's record of the package base `base`, looked up by `names`.
fn aur_info(base: &str, names: &[String]) -> Result<Option<AurInfo>, Error> {
    let encode = |name: &str| -> String {
        name.chars()
            .map(|character| match character {
                '+' => "%2B".to_string(),
                '@' => "%40".to_string(),
                other => other.to_string(),
            })
            .collect()
    };
    let query: Vec<String> = names
        .iter()
        .filter(|name| pacman::is_valid_package_name(name))
        .take(20)
        .map(|name| format!("arg[]={}", encode(name)))
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
    use std::path::PathBuf;

    use std::fs;
    use std::process::Command;

    use super::{Probe, aur, download_names, mirrored_arguments, parse, trailer};
    use crate::test_support::TempDir;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
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
    }

    #[test]
    fn the_recipe_copy_reports_only_when_its_functions_are_switched_off() {
        // Sourced the way makepkg does, then pkgver() and prepare() run.
        let run = |name: &str, recipe: &str| -> (bool, bool, String) {
            let dir = TempDir::new(name);
            let report = dir.path().join("report");
            let script = format!("pkgver=1\npkgname=demo\n{recipe}\n{}", trailer("0011aabb"));
            fs::write(dir.path().join("PKGBUILD"), script).unwrap();
            let output = Command::new("/usr/bin/bash")
                .args(["-c", "source ./PKGBUILD; pkgver; prepare; verify"])
                .current_dir(dir.path())
                .env("GUARDIAN_PROBE", &report)
                .env("BUILDDIR", "/b")
                .env("startdir", "/start")
                .output()
                .unwrap();
            (
                report.exists(),
                dir.path().join("ran").exists(),
                String::from_utf8_lossy(&output.stdout).into_owned(),
            )
        };
        let own =
            "pkgver() { touch ran; echo 2; }\nprepare() { touch ran; }\nverify() { touch ran; }";

        assert_eq!(run("trailer-plain", own), (true, false, "1\n".to_string()));
        assert_eq!(run("trailer-none", ""), (true, false, "1\n".to_string()));
        // Once switched off, they stay off.
        let late = format!("{own}\ntrap 'pkgver() {{ touch ran; }}' RETURN");
        assert!(!run("trailer-late", &late).1);

        for (name, trick) in [
            ("readonly", "readonly -f pkgver"),
            ("exit", "readonly -f prepare\nexit() { :; }"),
            ("alias", "shopt -s expand_aliases\nalias pkgver=other"),
            ("return", "return 0"),
        ] {
            let recipe = format!("{own}\n{trick}");
            let (reported, _, _) = run(&format!("trailer-{name}"), &recipe);
            assert!(!reported, "{name}");
        }
    }

    #[test]
    fn srcdir_follows_makepkg() {
        let probe = Probe::parse(b"/b\0\0demo\0/start\0").unwrap();
        assert_eq!(probe.srcdest, PathBuf::from("/start"));
        assert_eq!(probe.srcdir(), PathBuf::from("/b/demo/src"));
        assert!(Probe::parse(b"/b\0").is_none());
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
            ]),
            ["demo-1.0.tar.gz", "patch.diff", "proj"]
        );
    }
}
