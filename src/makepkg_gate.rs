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
use crate::report::{Blocked, Decision, Gap, Report, RunRef};
use crate::review::{self, ReviewContext};
use crate::rules;
use crate::sandbox::{self, FetchJail, Workspace};
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
    let mut pinned: Option<Dirs> = None;
    let mut downloads: Vec<String> = Vec::new();
    if invocation.runs_functions {
        let configured = match Configured::read() {
            Ok(configured) => configured,
            Err(error) => {
                errln!("Guardian blocked makepkg: {error}.");
                return ExitCode::from(2);
            }
        };
        let step = UpstreamStep {
            makepkg: Path::new(makepkg),
            mirrored: &mirrored,
            build_dir: &build_dir,
            name: &directory_name,
            key: &key,
            base: base.as_deref(),
            recipe: &recipe,
            extract: invocation.extracts,
            configured: &configured,
        };
        match review_upstream(&step, settings, facts) {
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
/// code than was reviewed), with the configured directories pinned.
fn start_build(
    makepkg: &Path,
    arguments: &[OsString],
    extracted: bool,
    pinned: Option<Dirs>,
) -> ExitCode {
    errln!("Guardian: review clear; starting {}", makepkg.display());
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
    configured: &'a Configured,
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
    List(&'a Dirs),
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
    let fetch = match run {
        Run::Fetch(dirs) => Some(dirs),
        Run::List(_) => None,
    };
    let home = home()?;
    let configuration = env::var_os("XDG_CONFIG_HOME")
        .map_or_else(|| home.join(".config"), PathBuf::from)
        .join("pacman/makepkg.conf");
    let mut readable = vec![configuration, home.join(".makepkg.conf")];
    let mut writable: Vec<&Path> = vec![workspace.path()];
    let report = workspace.path().join("report");
    let mut keyring = None;
    let (builddir, srcdest): (&Path, &Path) = if let Some(dirs) = fetch {
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
        (&dirs.builddir, &dirs.srcdest)
    } else {
        readable.push(step.build_dir.to_path_buf());
        let (Run::List(dirs) | Run::Fetch(dirs)) = run;
        (&dirs.builddir, &dirs.srcdest)
    };

    // The listing has no network, and what it prints becomes requests: it
    // is not told the proxies, which may hold credentials.
    let passed: Vec<(&str, OsString)> = PASSED_VARIABLES
        .iter()
        .filter(|name| fetch.is_some() || !name.to_ascii_lowercase().ends_with("_proxy"))
        .filter_map(|name| Some((*name, env::var_os(name)?)))
        .collect();
    let mut environment: Vec<(&str, &OsStr)> = vec![
        ("HOME", home.as_os_str()),
        ("PATH", "/usr/bin".as_ref()),
        ("BUILDDIR", builddir.as_os_str()),
        ("SRCDEST", srcdest.as_os_str()),
        // Nothing is packaged or logged in the jail; these only have to
        // be writable for makepkg to start.
        ("PKGDEST", "/tmp".as_ref()),
        ("SRCPKGDEST", "/tmp".as_ref()),
        ("LOGDEST", "/tmp".as_ref()),
    ];
    environment.extend(
        passed
            .iter()
            .map(|(name, value)| (*name, value.as_os_str())),
    );
    if fetch.is_none() {
        // The listing is parsed.
        environment.push(("LC_ALL", "C".as_ref()));
        environment.push(("GUARDIAN_REPORT", report.as_os_str()));
    }

    let mut command = sandbox::fetch_jail(&FetchJail {
        home: &home,
        readable: &readable,
        writable: &writable,
        keyring: keyring.as_deref(),
        network: fetch.is_some(),
        environment: &environment,
        directory: step.build_dir,
    });
    command.push(step.makepkg.into());
    command.extend(arguments.iter().cloned());
    Ok(command)
}

struct UpstreamOutcome {
    dirs: Dirs,
    /// Top-level names makepkg downloads into the build directory.
    downloads: Vec<String>,
}

/// The recipe the listing runs: the real one, then a report of the two
/// directories as it left them. Fixed text. It runs in the shell the recipe
/// ran in, so it shows what a recipe did in passing (however it was
/// written), not what one written to deceive it wants hidden.
const LISTING_RECIPE: &str = "source \"$startdir/PKGBUILD\"
printf '%s\\0%s\\0' \"$BUILDDIR\" \"$SRCDEST\" >\"$GUARDIAN_REPORT\"
";

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

/// Has makepkg list the recipe's sources (`--printsrcinfo`), in the jail:
/// the recipe's top-level code runs there, with no network and nothing of
/// the user's to read or write. Its build and download directories are
/// pointed at names made up for this run, inside the jail's own temporary
/// directory. Returns the listing, unless the recipe did not leave those
/// two as they were: it would move the real build's too.
fn probe(step: &UpstreamStep<'_>) -> Result<String, Error> {
    let workspace = Workspace::create("probe")?;
    let copy = RecipeCopy::create(step.build_dir, LISTING_RECIPE)?;
    // The copy's name is random, so no recipe can assign these by rote.
    let inside = Path::new("/tmp").join(copy.name());
    let listing = Dirs {
        builddir: inside.join("build"),
        srcdest: inside.join("sources"),
        pkgbase: String::new(),
        startdir: step.build_dir.to_path_buf(),
    };
    let mut args: Vec<OsString> = vec!["-p".into(), copy.name(), "--printsrcinfo".into()];
    args.extend(step.mirrored.iter().cloned());
    let command = jailed(step, &workspace, Run::List(&listing), &args)?;
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
fn source_context(sources: &[aur::Source], extracts: bool) -> Result<Vec<String>, ()> {
    let checks = aur::check_sources(sources);
    print_warnings("Source checks", &checks.warnings);
    if !checks.blocking.is_empty() {
        // A call that only downloads (to verify, or to generate the very
        // checksums that are missing) builds nothing from them.
        if extracts {
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

/// Where the recipe writes its sources out plainly, listing it must give
/// the same ones: a recipe that lists other sources than it says has told
/// the listing something else than the build. True when they agree, or the
/// recipe computes its sources.
fn listed_as_written(recipe: &str, srcinfo: &str, sources: &[aur::Source]) -> bool {
    let Some(mut written) = aur::literal_sources(recipe, srcinfo) else {
        return true;
    };
    let mut listed: Vec<String> = sources.iter().map(|source| source.entry.clone()).collect();
    written.sort();
    written.dedup();
    listed.sort();
    listed.dedup();
    written == listed
}

/// Returns why makepkg must not start, as an exit code. A block notes that
/// the recipe ran: makepkg sources it, in the jail, to list the sources.
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
    let unreadable = |error: String| {
        block(
            format!("could not read the source list ({error})."),
            "the source list could not be read",
            2,
        )
    };
    let srcinfo = probe(step).map_err(|error| unreadable(error.to_string()))?;
    let (Some(pkgbase), Some(recipe)) = (listed_pkgbase(&srcinfo), fetch_recipe(&srcinfo)) else {
        return Err(unreadable("it names no usable pkgbase".into()));
    };
    let sources = aur::parse_srcinfo(&srcinfo);
    if !listed_as_written(step.recipe, &srcinfo, &sources) {
        return Err(block(
            "listing the recipe gave other sources than it writes out; what it builds with cannot be known.".into(),
            "the recipe lists other sources than it writes out",
            2,
        ));
    }
    let dirs = step.configured.dirs(step.build_dir, pkgbase);
    if let Some((message, why)) = fetch_refusal(step, pkgbase, &sources, &dirs) {
        return Err(block(message, why, 1));
    }

    let mut context = vec![aur::UPSTREAM_SCOPE.to_string()];
    context.push(if aur::runs_tests(step.recipe) {
        "The recipe defines check(), so the upstream test suite runs during this build.".into()
    } else {
        "The recipe defines no check(), so the upstream test suite does not run during this build."
            .into()
    });
    let checked = source_context(&sources, step.extract).map_err(|()| {
        block(
            "a source can be replaced in transit.".into(),
            "a source can be replaced in transit",
            1,
        )
    })?;
    context.extend(checked);
    context.extend(facts);

    if step.extract {
        pre_extract(step, &dirs, &recipe)
            .map_err(|message| block(message, "fetching the sources for review failed", 2))?;
    }

    let budget = upstream_budget(settings);
    let srcdir = dirs.srcdir();
    let roots = Roots {
        build_dir: step.build_dir,
        srcdest: Some(&dirs.srcdest),
    };
    let upstream = aur::collect_upstream(&srcdir, &roots, step.recipe, budget);
    let downloads = download_names(&sources);
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
        return Ok(UpstreamOutcome { dirs, downloads });
    }
    let decision = review_upstream_files(step, settings, &upstream, &context, &sources);
    match decision {
        // Nothing was sent to the AI (`ai = off`): the recipe decision stands.
        Decision::Limited | Decision::Clear | Decision::Warned => {
            Ok(UpstreamOutcome { dirs, downloads })
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

/// The most left-out files named one by one in the summary.
const MAX_LEFT_OUT_NAMED: usize = 40;

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
        for (path, reason) in upstream.omitted.iter().take(MAX_LEFT_OUT_NAMED) {
            let _ = writeln!(summary, "src/{path}: {reason}");
        }
        if upstream.omitted.len() > MAX_LEFT_OUT_NAMED {
            let _ = writeln!(
                summary,
                "and {} more, not named here",
                upstream.omitted.len() - MAX_LEFT_OUT_NAMED
            );
        }
    }
    summary
}

/// A file the upstream code runs or reads in as code that was not reviewed
/// as text (a binary, or one left out) leaves the review incomplete: the
/// build runs it.
fn upstream_runs(report: &mut Report, upstream: &Upstream) {
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
                .unread
                .keys()
                .map(|path| (path.clone(), "binary".to_string())),
        )
        .collect();
    review::check_runs(report, &unread);
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
    upstream_runs(&mut report, upstream);
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
    use std::path::{Path, PathBuf};

    use std::fs;
    use std::process::Command;

    use super::{
        Configured, LISTING_RECIPE, aur, download_names, fetch_recipe, foreign_checkout,
        is_jailable, is_plain_mirror, listing_report, mirrored_arguments, misnamed_source, parse,
        public_keyring,
    };
    use crate::test_support::TempDir;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    #[test]
    fn a_binary_the_upstream_code_runs_leaves_the_review_incomplete() {
        let dir = TempDir::new("gate-upstream-runs");
        let src = dir.path().join("src");
        fs::create_dir_all(src.join("demo")).unwrap();
        fs::write(src.join("demo/helper.bin"), b"\x7fELF\x02\x01\x01\0\0\0").unwrap();
        fs::write(src.join("demo/build.sh"), "#!/bin/sh\nsh ./helper.bin\n").unwrap();
        let roots = aur::Roots {
            build_dir: dir.path(),
            srcdest: None,
        };
        let upstream = aur::collect_upstream(&src, &roots, "", 1024 * 1024);
        let mut report = crate::report::Report::new("test");
        super::upstream_runs(&mut report, &upstream);
        let gaps: Vec<String> = report.gaps.iter().map(ToString::to_string).collect();
        assert!(
            gaps.iter()
                .any(|gap| gap
                    .starts_with("src/demo/build.sh:2 runs or reads in src/demo/helper.bin")),
            "{gaps:?}"
        );
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
            fs::write(dir.path().join("PKGBUILD"), recipe).unwrap();
            fs::write(dir.path().join("listing"), LISTING_RECIPE).unwrap();
            let status = Command::new("/usr/bin/bash")
                .args(["-c", "source ./listing"])
                .current_dir(dir.path())
                .env("startdir", dir.path())
                .env("BUILDDIR", "/tmp/r/build")
                .env("SRCDEST", "/tmp/r/sources")
                .env("GUARDIAN_REPORT", &report)
                .status()
                .unwrap();
            assert!(status.success() || !report.exists(), "{name}");
            listing_report(&report)
        };
        let kept: &[u8] = b"/tmp/r/build\0/tmp/r/sources\0";
        for (name, recipe) in [
            ("plain", "pkgname=demo\n"),
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
