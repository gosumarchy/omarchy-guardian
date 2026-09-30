//! The pacman pre-transaction hook: review the `.INSTALL` scriptlets of the
//! exact package archives a transaction is about to install.
//!
//! libalpm runs hooks as direct children of pacman after `chroot` +
//! `chdir("/")`, so the hook's own working directory says nothing about the
//! user's. The hook script passes pacman's PID and its working directory
//! (`/proc/<pid>/cwd`, readable only by root), and this module reads pacman's
//! exact argv from `/proc/<pid>/cmdline` instead of re-parsing a shell string.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, BufRead};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::classify;
use crate::config::Settings;
use crate::config::model::{AiRequirement, Named, SourceClass};
use crate::content::Content;
use crate::engine::plan::HashOnly;
use crate::error::{Error, IoContext};
use crate::notify;
use crate::payload;
use crate::report::{Gap, Report};
use crate::review;
use crate::tools::{self, Limits, OpenCode, Reviewer};

const ARCHIVE_EXTENSIONS: &[&str] = &[".pkg.tar.zst", ".pkg.tar.xz", ".pkg.tar.gz", ".pkg.tar"];
const DEFAULT_CACHE_DIR: &str = "/var/cache/pacman/pkg/";
const TOOL_LIMITS: Limits = Limits {
    timeout_secs: 30,
    max_output: 4 * 1024 * 1024,
};
const C_LOCALE: &[(&str, &str)] = &[("LC_ALL", "C")];

/// Every class a transaction target can resolve to.
const PRIVILEGED: [SourceClass; 3] = [
    SourceClass::Official,
    SourceClass::ThirdPartyRepo,
    SourceClass::LocalPackage,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HookArgs {
    pub pacman_pid: u32,
    pub cwd: PathBuf,
    /// `SystemOnly` in production. The hook script passes `UserPath` only on
    /// its non-root branch, which pacman never takes; tests use it.
    pub opencode: OpenCode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Sync,
    LocalUpgrade,
}

/// The pacman classes whose policy requires an AI review.
pub fn classes_requiring_ai(settings: &Settings) -> Vec<SourceClass> {
    PRIVILEGED
        .iter()
        .copied()
        .filter(|class| settings.policy(*class).ai == AiRequirement::Required)
        .collect()
}

/// Whether every pacman class that requires the AI review has a root-owned
/// binary of the reviewer CLI its model selects.
pub fn system_reviewer_ready(settings: &Settings) -> bool {
    classes_requiring_ai(settings).iter().all(|class| {
        let reviewer = Reviewer::for_model(settings.agent_settings(*class).model.as_deref());
        OpenCode::SystemOnly.resolve_reviewer(reviewer).is_ok()
    })
}

/// Whether the pacman classes that require the AI review use OpenCode, so a
/// missing reviewer is fixed by installing `extra/opencode`.
pub fn system_reviewer_is_opencode(settings: &Settings) -> bool {
    classes_requiring_ai(settings).iter().all(|class| {
        Reviewer::for_model(settings.agent_settings(*class).model.as_deref()) == Reviewer::OpenCode
    })
}

/// Whether the pacman gate can review transactions with these settings.
/// Without a root-owned OpenCode, every transaction with a target whose
/// class requires the AI review is refused; this says so before the hook
/// is turned on rather than on the next install.
pub fn preflight(settings: &Settings, opencode_ready: bool) -> Result<(), String> {
    if let Some(reason) = settings.privileged_block() {
        return Err(reason.to_string());
    }
    let requiring = classes_requiring_ai(settings);
    if requiring.is_empty() || opencode_ready {
        return Ok(());
    }
    let names: Vec<&str> = requiring.iter().map(|class| class.name()).collect();
    let fix = if system_reviewer_is_opencode(settings) {
        "there is no root-owned OpenCode at /usr/bin/opencode or /usr/local/bin/opencode. Install it with: sudo pacman -S extra/opencode, or install Claude Code (sudo pacman -S claude-code) and set the model to claude-code/claude-sonnet-5-5 in omarchy-guardian tui"
    } else {
        "the model set for them runs through the Claude Code CLI, and there is no root-owned `claude` at /usr/bin/claude or /usr/local/bin/claude. Install it with: sudo pacman -S claude-code"
    };
    Err(format!(
        "{} packages require an AI review, so pacman would refuse every such install (including AUR packages yay installs with pacman -U): {fix}",
        names.join(", ")
    ))
}

pub fn review_transaction(args: &HookArgs, settings: &Settings) -> Result<Report, Error> {
    if let Some(reason) = settings.privileged_block() {
        return Err(Error::Refused(reason.to_string()));
    }

    let targets = read_targets(io::stdin().lock())?;
    let argv = pacman_argv(args.pacman_pid)?;
    let operation = parse_operation(&argv)?;

    let mut report = Report::new("pacman transaction");
    // Untagged files (a class-lookup miss) are judged as the strictest
    // pacman class.
    report.class = SourceClass::ThirdPartyRepo;
    report.profile = settings.system_profile().name().to_string();
    report.ai_off_classes = review::ai_off_classes(settings, &PRIVILEGED);

    let trusted = settings.trusted_reviewer_packages();
    let (archives, classes) = match operation {
        Operation::Sync => sync_archives(&targets, settings)?,
        Operation::LocalUpgrade => {
            // `pacman -U` installs missing dependencies from the sync
            // repositories in the same transaction; those are found and
            // classed like `-S` targets.
            let mut archives = local_archives(&argv, &args.cwd)?;
            let dependencies = missing_targets(&targets, &archives);
            if dependencies.is_empty() {
                (archives, HashMap::new())
            } else {
                let (synced, classes) = sync_archives(&dependencies, settings)?;
                archives.extend(synced);
                (archives, classes)
            }
        }
    };

    for target in &targets {
        let class = classes.get(target).copied().unwrap_or(match operation {
            Operation::Sync => SourceClass::ThirdPartyRepo,
            Operation::LocalUpgrade => SourceClass::LocalPackage,
        });
        match archives.get(target) {
            Some(Ok(paths)) => {
                for archive in paths {
                    match scan_package(archive, target, class, &trusted, &mut report) {
                        Ok((scriptlet, summary)) => summary.announce(target, scriptlet),
                        Err(error) => report.gaps.push(Gap::Package(error)),
                    }
                }
            }
            Some(Err(reason)) => report
                .gaps
                .push(Gap::Package(Error::Refused(format!("{target}: {reason}")))),
            None => report.gaps.push(Gap::Package(Error::Refused(format!(
                "no package archive matched transaction target {target}"
            )))),
        }
    }

    review::run_agents(&mut report, settings, &args.opencode, &[], None);
    Ok(report)
}

fn read_targets(input: impl BufRead) -> Result<Vec<String>, Error> {
    let mut targets = Vec::new();
    for line in input.lines() {
        let line = line.at(Path::new("<stdin>"))?;
        let target = line.trim();
        if target.is_empty() {
            continue;
        }
        if !is_valid_package_name(target) {
            return Err(Error::Refused(format!(
                "invalid package target from pacman: {target:?}"
            )));
        }
        targets.push(target.to_string());
    }
    if targets.is_empty() {
        return Err(Error::Refused(
            "pacman hook received no package targets".into(),
        ));
    }
    Ok(targets)
}

/// Pacman package names: alphanumerics and `@._+-`, not starting with `-` or `.`.
pub fn is_valid_package_name(name: &str) -> bool {
    name.chars()
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric() || "@_+".contains(first))
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "@._+-".contains(character))
}

fn pacman_argv(pid: u32) -> Result<Vec<String>, Error> {
    let comm_path = PathBuf::from(format!("/proc/{pid}/comm"));
    let comm = fs::read_to_string(&comm_path).at(&comm_path)?;
    if comm.trim_end() != "pacman" {
        return Err(Error::Refused(format!(
            "the hook's parent process is {:?}, not pacman",
            comm.trim_end()
        )));
    }

    let cmdline_path = PathBuf::from(format!("/proc/{pid}/cmdline"));
    let cmdline = fs::read(&cmdline_path).at(&cmdline_path)?;
    split_cmdline(&cmdline)
}

fn split_cmdline(cmdline: &[u8]) -> Result<Vec<String>, Error> {
    let body = cmdline.strip_suffix(&[0]).unwrap_or(cmdline);
    body.split(|byte| *byte == 0)
        .map(|argument| {
            String::from_utf8(argument.to_vec())
                .map_err(|_| Error::Refused("pacman was given a non-UTF-8 argument".into()))
        })
        .collect()
}

/// Finds the pacman operation. Only sync (`-S`) and upgrade (`-U`)
/// transactions install scriptlets from archives Guardian can locate.
pub fn parse_operation(argv: &[String]) -> Result<Operation, Error> {
    for argument in argv.iter().skip(1) {
        match argument.as_str() {
            "--" => break,
            "--sync" => return Ok(Operation::Sync),
            "--upgrade" => return Ok(Operation::LocalUpgrade),
            _ => {}
        }
        if let Some(flags) = argument.strip_prefix('-')
            && !flags.starts_with('-')
        {
            if flags.contains('S') {
                return Ok(Operation::Sync);
            }
            if flags.contains('U') {
                return Ok(Operation::LocalUpgrade);
            }
        }
    }
    Err(Error::Refused(
        "only pacman sync (-S) and upgrade (-U) transactions are supported".into(),
    ))
}

/// Per-target archive lookup result: the archives, or why none was usable.
type Archives = HashMap<String, Result<Vec<PathBuf>, String>>;

/// For `-U`: every package archive named on the command line, resolved
/// against pacman's working directory and grouped by the package it holds.
fn local_archives(argv: &[String], cwd: &Path) -> Result<Archives, Error> {
    let mut archives: Archives = HashMap::new();

    for argument in argv.iter().skip(1) {
        if !is_package_archive_name(argument) {
            continue;
        }
        if argument.contains("://") {
            return Err(Error::Refused(format!(
                "remote package URLs are not supported: {argument}"
            )));
        }

        let path = cwd.join(argument);
        let metadata = match fs::symlink_metadata(&path) {
            Err(error)
                if error.kind() == io::ErrorKind::NotFound && Path::new(argument).is_relative() =>
            {
                return Err(Error::Refused(format!(
                    "cannot find {argument} relative to pacman's working directory ({}); run pacman -U with an absolute path",
                    cwd.display()
                )));
            }
            other => other.at(&path)?,
        };
        if !metadata.is_file() {
            return Err(Error::Refused(format!(
                "not a regular package archive: {}",
                path.display()
            )));
        }
        check_private(&path, notify::current_uid())?;

        let name = package_name(&path)?;
        if let Ok(paths) = archives.entry(name).or_insert_with(|| Ok(Vec::new())) {
            paths.push(path);
        }
    }

    if archives.is_empty() {
        return Err(Error::Refused(
            "the upgrade did not name a readable package archive".into(),
        ));
    }
    Ok(archives)
}

/// Transaction targets that no archive on the command line provides.
fn missing_targets(targets: &[String], archives: &Archives) -> Vec<String> {
    targets
        .iter()
        .filter(|target| !archives.contains_key(*target))
        .cloned()
        .collect()
}

/// One repository's offer of a package: the version pacman would install and
/// the repository offering it, which decides the package's source class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncCandidate {
    pub version_arch: String,
    pub repo: String,
}

/// For `-S`: the archive of each target's sync-database version in pacman's
/// cache directories, read once and indexed by file name, plus each target's
/// source class as decided by the repository offering it.
fn sync_archives(
    targets: &[String],
    settings: &Settings,
) -> Result<(Archives, HashMap<String, SourceClass>), Error> {
    let versions = sync_versions(targets)?;
    let cache = cache_index(&cache_directories()?)?;
    let mut archives = Archives::new();

    for target in targets {
        let Some(candidates) = versions.get(target) else {
            archives.insert(
                target.clone(),
                Err("pacman has no sync database entry for it".into()),
            );
            continue;
        };

        let mut found = Vec::new();
        for candidate in candidates {
            let version_arch = &candidate.version_arch;
            for extension in ARCHIVE_EXTENSIONS {
                if let Some(path) = cache.get(&format!("{target}-{version_arch}{extension}")) {
                    found.push(path.clone());
                }
            }
        }
        for path in &found {
            let name = package_name(path)?;
            if name != *target {
                return Err(Error::Refused(format!(
                    "{} contains {name}, not {target}",
                    path.display()
                )));
            }
        }

        let entry = if found.is_empty() {
            Err("no archive of the version being installed is in the pacman cache".into())
        } else {
            Ok(found)
        };
        archives.insert(target.clone(), entry);
    }

    let official_repos = settings.official_repos();
    // Every candidate repo's SigLevel is queried at most once per
    // transaction, since `pacman-conf` is one process invocation.
    let mut siglevels: HashMap<String, bool> = HashMap::new();
    let mut classes = HashMap::new();
    for (target, candidates) in &versions {
        let mut candidate_classes = Vec::new();
        for candidate in candidates {
            let required = if let Some(required) = siglevels.get(&candidate.repo) {
                *required
            } else {
                let required = classify::requires_signatures(&classify::siglevel(&candidate.repo)?);
                siglevels.insert(candidate.repo.clone(), required);
                required
            };
            candidate_classes.push(classify::repo_class(
                &candidate.repo,
                &official_repos,
                required,
            ));
        }
        classes.insert(target.clone(), classify::strictest(candidate_classes));
    }

    Ok((archives, classes))
}

/// `name → [candidate, ...]` from `pacman -Si`. A package present in several
/// repositories yields several candidates.
fn sync_versions(targets: &[String]) -> Result<HashMap<String, Vec<SyncCandidate>>, Error> {
    let mut args: Vec<OsString> = vec!["-Si".into(), "--".into()];
    args.extend(targets.iter().map(OsString::from));
    // Unknown targets make pacman exit non-zero while still printing the
    // others; those targets are then reported individually.
    let captured = tools::run(Path::new(tools::PACMAN), &args, None, C_LOCALE, TOOL_LIMITS)?;
    Ok(parse_sync_info(&String::from_utf8_lossy(&captured.stdout)))
}

pub fn parse_sync_info(output: &str) -> HashMap<String, Vec<SyncCandidate>> {
    let mut versions: HashMap<String, Vec<SyncCandidate>> = HashMap::new();
    let mut fields: HashMap<&str, &str> = HashMap::new();

    let mut flush = |fields: &mut HashMap<&str, &str>| {
        if let (Some(name), Some(version), Some(arch), Some(repo)) = (
            fields.get("Name"),
            fields.get("Version"),
            fields.get("Architecture"),
            fields.get("Repository"),
        ) {
            versions
                .entry((*name).to_string())
                .or_default()
                .push(SyncCandidate {
                    version_arch: format!("{version}-{arch}"),
                    repo: (*repo).to_string(),
                });
        }
        fields.clear();
    };

    for line in output.lines() {
        if line.trim().is_empty() {
            flush(&mut fields);
        } else if let Some((key, value)) = line.split_once(':')
            && !line.starts_with(' ')
        {
            fields.insert(key.trim(), value.trim());
        }
    }
    flush(&mut fields);
    versions
}

/// The archive and every directory above it may only be changed by root or
/// the invoking user: pacman opens the path again after the review, so
/// another user who could swap it would install unreviewed code.
fn check_private(path: &Path, uid: Option<u32>) -> Result<(), Error> {
    let mut current = Some(path);
    while let Some(here) = current {
        let metadata = fs::symlink_metadata(here).at(here)?;
        let sticky = metadata.is_dir() && metadata.mode() & 0o1000 != 0;
        let foreign_owner = metadata.uid() != 0
            && Some(metadata.uid()) != uid
            && !(metadata.uid() == overflow_uid() && root_unmapped());
        let shared = metadata.mode() & 0o022 != 0 && !sticky;
        if foreign_owner || shared {
            return Err(Error::Refused(format!(
                "{} can be changed by another user ({}), so the archive pacman installs may not be the one reviewed; move it to a directory only you can write",
                path.display(),
                here.display()
            )));
        }
        current = here.parent();
    }
    Ok(())
}

/// The owner the kernel shows for users a user namespace does not map.
fn overflow_uid() -> u32 {
    fs::read_to_string("/proc/sys/kernel/overflowuid")
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(65_534)
}

/// Whether this process runs in a user namespace that does not map root
/// (a sandbox, as in the end-to-end tests), where root's directories show
/// the overflow owner. The real pacman hook never runs in one.
fn root_unmapped() -> bool {
    fs::read_to_string("/proc/self/uid_map").is_ok_and(|map| {
        !map.lines().any(|line| {
            let mut fields = line.split_whitespace();
            let inside: Option<u64> = fields.next().and_then(|field| field.parse().ok());
            let count: Option<u64> = fields.nth(1).and_then(|field| field.parse().ok());
            matches!((inside, count), (Some(start), Some(count)) if start == 0 && count > 0)
        })
    })
}

/// A cache directory must be root's alone: `-S` packages are reviewed there
/// after pacman verified them, and installed from there.
fn check_cache_directory(directory: &Path) -> Result<(), Error> {
    match fs::symlink_metadata(directory) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).at(directory),
        Ok(metadata) if metadata.uid() == 0 && metadata.mode() & 0o022 == 0 => Ok(()),
        Ok(_) => Err(Error::Refused(format!(
            "the pacman cache directory {} is not root's alone",
            directory.display()
        ))),
    }
}

fn cache_directories() -> Result<Vec<PathBuf>, Error> {
    let output = tools::run(
        Path::new(tools::PACMAN_CONF),
        &["CacheDir".into()],
        None,
        C_LOCALE,
        TOOL_LIMITS,
    )?
    .into_success()?;
    let directories: Vec<PathBuf> = String::from_utf8_lossy(&output)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(PathBuf::from)
        .collect();
    if directories.is_empty() {
        Ok(vec![PathBuf::from(DEFAULT_CACHE_DIR)])
    } else {
        Ok(directories)
    }
}

/// Regular files in the cache directories by name. Symlinks are ignored.
fn cache_index(directories: &[PathBuf]) -> Result<HashMap<String, PathBuf>, Error> {
    let mut index = HashMap::new();
    for directory in directories {
        check_cache_directory(directory)?;
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).at(directory),
        };
        for entry in entries {
            let entry = entry.at(directory)?;
            let is_file = entry.file_type().at(directory)?.is_file();
            if let (true, Ok(name)) = (is_file, entry.file_name().into_string()) {
                index.entry(name).or_insert_with(|| entry.path());
            }
        }
    }
    Ok(index)
}

fn is_package_archive_name(name: &str) -> bool {
    ARCHIVE_EXTENSIONS
        .iter()
        .any(|extension| name.ends_with(extension))
}

fn package_name(archive: &Path) -> Result<String, Error> {
    let output = tools::run(
        Path::new(tools::PACMAN),
        &["-Qqp".into(), "--".into(), archive.into()],
        None,
        C_LOCALE,
        TOOL_LIMITS,
    )?
    .into_success()?;
    let name = String::from_utf8_lossy(&output).trim().to_string();
    if is_valid_package_name(&name) {
        Ok(name)
    } else {
        Err(Error::Refused(format!(
            "pacman reported an invalid package name for {}",
            archive.display()
        )))
    }
}

/// What was found in one package's payload.
struct PayloadSummary {
    reviewed: usize,
    /// Identical to what is already installed, so not reviewed again.
    unchanged: usize,
    /// Auto-run files that could not be reviewed: binaries, or anything
    /// under `ai = off`.
    not_reviewed: Vec<String>,
}

impl PayloadSummary {
    fn announce(&self, target: &str, scriptlet: bool) {
        let nothing = self.reviewed == 0 && self.unchanged == 0 && self.not_reviewed.is_empty();
        if !scriptlet && nothing {
            outln!("Pacman package {target}: no install scriptlet or auto-run files to review.");
        }
        if self.reviewed > 0 {
            outln!(
                "Pacman package {target}: {} new or changed auto-run file(s) reviewed.",
                self.reviewed
            );
        }
        if self.unchanged > 0 {
            outln!(
                "Pacman package {target}: {} auto-run file(s) identical to the installed ones, not reviewed again.",
                self.unchanged
            );
        }
        if !self.not_reviewed.is_empty() {
            let shown: Vec<&str> = self
                .not_reviewed
                .iter()
                .take(3)
                .map(String::as_str)
                .collect();
            let more = self.not_reviewed.len().saturating_sub(shown.len());
            outln!(
                "Pacman package {target}: {} auto-run file(s) not reviewed: {}{}",
                self.not_reviewed.len(),
                shown.join(", "),
                if more > 0 {
                    format!(" and {more} more")
                } else {
                    String::new()
                }
            );
        }
    }
}

/// Reviews one package archive through its exact model (see `payload`):
/// the install scriptlet with the local rules and the AI, and the payload
/// files that run or grant privileges on their own with the AI. Returns
/// whether it had a scriptlet and what the payload held.
fn scan_package(
    archive_path: &Path,
    target: &str,
    class: SourceClass,
    trusted: &[String],
    report: &mut Report,
) -> Result<(bool, PayloadSummary), Error> {
    let archive = payload::Archive::open(archive_path)?;
    let reviewed = payload::review(&archive, target, class, trusted)?;
    let archive_name = archive_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("package");

    let scriptlet = match reviewed.install {
        None => false,
        Some(Content::Undecodable | Content::Binary(_)) => {
            return Err(Error::Refused(format!(
                "the install scriptlet of {} holds binary data and cannot be reviewed",
                archive_path.display()
            )));
        }
        Some(Content::Text(text) | Content::Lossy { text, .. }) => {
            let rel = format!("{target}/{archive_name}/.INSTALL");
            report.file_classes.insert(rel.clone(), class);
            review::analyze_text(report, &rel, &text, false);
            true
        }
    };

    let mut summary = PayloadSummary {
        reviewed: 0,
        unchanged: 0,
        not_reviewed: Vec::new(),
    };
    for file in reviewed.files {
        // An upgrade only brings in what changed; the rest is already active.
        if file.is_installed_unchanged(Path::new("/")) {
            summary.unchanged += 1;
            continue;
        }
        let rel = format!("{target}/{archive_name}/{}", file.path);
        report.file_classes.insert(rel.clone(), class);
        match file.content {
            Content::Text(text) | Content::Lossy { text, .. } => {
                if review::analyze_payload(report, &rel, &text) {
                    summary.reviewed += 1;
                } else {
                    summary
                        .not_reviewed
                        .push(format!("/{} (AI off)", file.path));
                }
            }
            // Official packages ship ELF generators, and hooks and units
            // run compiled programs: they cannot be read, but the AI is told
            // they are there.
            Content::Binary(format)
                if format.executable()
                    && (class == SourceClass::Official || file.run_by.is_some()) =>
            {
                summary
                    .not_reviewed
                    .push(format!("/{} ({})", file.path, format.label()));
                report.hash_only.push(HashOnly {
                    path: rel,
                    bytes: 0,
                    label: format.label(),
                    media: false,
                });
            }
            Content::Binary(format) if format.executable() => {
                report.gaps.push(Gap::Package(Error::Refused(format!(
                    "/{}: a {} in an auto-run location cannot be reviewed; only packages from an official repository may ship one",
                    file.path,
                    format.label()
                ))));
            }
            Content::Binary(_) | Content::Undecodable => {
                report.gaps.push(Gap::Undecodable(rel));
            }
        }
    }
    archive.verify_unchanged()?;
    Ok((scriptlet, summary))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    use super::{
        Archives, Operation, is_valid_package_name, local_archives, missing_targets,
        parse_operation, parse_sync_info, read_targets, scan_package, split_cmdline,
    };
    use crate::agent::{AgentReview, Status};
    use crate::config::Settings;
    use crate::config::file::PartialConfig;
    use crate::config::model::SourceClass;
    use crate::report::{AgentOutcome, AgentRun, Blocked, Decision, Report};
    use crate::review::analyze_text;
    use crate::rules::RuleId;
    use crate::test_support::{TempDir, tool_available};

    fn argv(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn only_sync_and_upgrade_operations_are_accepted() {
        for (line, expected) in [
            ("/usr/bin/pacman -Syu", Operation::Sync),
            ("pacman -yuS foo", Operation::Sync),
            ("pacman --sync foo", Operation::Sync),
            ("pacman -U /tmp/a.pkg.tar.zst", Operation::LocalUpgrade),
            ("pacman --upgrade a.pkg.tar.zst", Operation::LocalUpgrade),
            (
                "/bin/sh /e2e/bin/pacman -U a.pkg.tar.zst",
                Operation::LocalUpgrade,
            ),
        ] {
            assert_eq!(parse_operation(&argv(line)).unwrap(), expected, "{line}");
        }
        for line in ["pacman -Rns foo", "pacman -Qs foo", "pacman -- -S"] {
            assert!(parse_operation(&argv(line)).is_err(), "{line}");
        }
    }

    #[test]
    fn upgrade_dependencies_are_the_targets_without_a_local_archive() {
        let mut archives = Archives::new();
        archives.insert("built".into(), Ok(vec!["built-1-1-any.pkg.tar".into()]));
        let targets = ["built".to_string(), "repo-dependency".to_string()];
        assert_eq!(missing_targets(&targets, &archives), ["repo-dependency"]);
    }

    #[test]
    fn preflight_needs_a_system_opencode_only_when_a_class_requires_ai() {
        use super::{classes_requiring_ai, preflight};
        use crate::config::model::Profile;

        let standard = Settings::from_parts(PartialConfig::default(), PartialConfig::default());
        assert_eq!(
            classes_requiring_ai(&standard),
            [SourceClass::ThirdPartyRepo, SourceClass::LocalPackage]
        );
        let error = preflight(&standard, false).unwrap_err();
        assert!(error.contains("third-party-repo, local-package"), "{error}");
        assert!(error.contains("sudo pacman -S extra/opencode"), "{error}");
        assert_eq!(preflight(&standard, true), Ok(()));

        let private = Settings::from_parts(
            PartialConfig {
                profile: Some(Profile::LocalOnly),
                ..PartialConfig::default()
            },
            PartialConfig::default(),
        );
        assert_eq!(preflight(&private, false), Ok(()));
    }

    #[test]
    fn cmdline_keeps_arguments_with_spaces() {
        assert_eq!(
            split_cmdline(b"pacman\0-U\0/tmp/with space.pkg.tar.zst\0").unwrap(),
            ["pacman", "-U", "/tmp/with space.pkg.tar.zst"]
        );
        assert!(split_cmdline(b"pacman\0\xff\0").is_err());
    }

    #[test]
    fn targets_must_be_package_names() {
        assert_eq!(
            read_targets(&b"linux\n\nlib32-glibc\n"[..]).unwrap(),
            ["linux", "lib32-glibc"]
        );
        assert!(read_targets(&b"\n"[..]).is_err());
        assert!(read_targets(&b"../etc\n"[..]).is_err());
        assert!(is_valid_package_name("gtk2+extra"));
        assert!(is_valid_package_name("@scope"));
        assert!(!is_valid_package_name("-rf"));
        assert!(!is_valid_package_name(".hidden"));
    }

    #[test]
    fn parses_sync_database_versions() {
        let output = "Repository      : core\nName            : linux\nVersion         : 6.10.1.arch1-1\nDescription     : The Linux kernel: and modules\nArchitecture    : x86_64\n\nRepository      : chaotic-aur\nName            : ttf-font\nVersion         : 2:1.0-3\nArchitecture    : any\n";
        let versions = parse_sync_info(output);
        assert_eq!(versions["linux"][0].version_arch, "6.10.1.arch1-1-x86_64");
        assert_eq!(versions["linux"][0].repo, "core");
        assert_eq!(versions["ttf-font"][0].version_arch, "2:1.0-3-any");
        assert_eq!(versions["ttf-font"][0].repo, "chaotic-aur");
    }

    fn clear_run(files: &[&str]) -> AgentRun {
        AgentRun {
            files: files.iter().map(ToString::to_string).collect(),
            label: "m · low".into(),
            chunk: None,
            cached: None,
            outcome: AgentOutcome::Reviewed(AgentReview {
                status: Status::Clear,
                summary: "ok".into(),
                findings: Vec::new(),
            }),
        }
    }

    #[test]
    fn mixed_transaction_uses_each_targets_policy() {
        let settings = Settings::from_parts(PartialConfig::default(), PartialConfig::default());
        let policy = |class| settings.policy(class);

        let mut report = Report::new("pacman transaction");
        report.class = SourceClass::ThirdPartyRepo;
        report
            .file_classes
            .insert("core-pkg/a/.INSTALL".into(), SourceClass::Official);
        report
            .file_classes
            .insert("chaotic-pkg/b/.INSTALL".into(), SourceClass::ThirdPartyRepo);
        analyze_text(
            &mut report,
            "core-pkg/a/.INSTALL",
            "post_install() { setcap cap_net_raw+ep /usr/bin/x; }\n",
            false,
        );
        analyze_text(
            &mut report,
            "chaotic-pkg/b/.INSTALL",
            "post_install() { true; }\n",
            false,
        );
        report.agent_runs.push(clear_run(&[
            "core-pkg/a/.INSTALL",
            "chaotic-pkg/b/.INSTALL",
        ]));
        assert_eq!(report.decide(&policy), Decision::Warned);

        let mut flagged = Report::new("pacman transaction");
        flagged.class = SourceClass::ThirdPartyRepo;
        flagged
            .file_classes
            .insert("core-pkg/a/.INSTALL".into(), SourceClass::Official);
        flagged
            .file_classes
            .insert("chaotic-pkg/b/.INSTALL".into(), SourceClass::ThirdPartyRepo);
        analyze_text(
            &mut flagged,
            "core-pkg/a/.INSTALL",
            "post_install() { true; }\n",
            false,
        );
        analyze_text(
            &mut flagged,
            "chaotic-pkg/b/.INSTALL",
            "post_install() { setcap cap_net_raw+ep /usr/bin/x; }\n",
            false,
        );
        flagged.agent_runs.push(clear_run(&[
            "core-pkg/a/.INSTALL",
            "chaotic-pkg/b/.INSTALL",
        ]));
        assert_eq!(
            flagged.decide(&policy),
            Decision::Blocked(Blocked::Findings)
        );
    }

    #[test]
    fn remote_and_missing_archives_are_refused() {
        let dir = TempDir::new("pacman-missing");
        assert!(
            local_archives(
                &argv("pacman -U https://x.test/a-1-1-any.pkg.tar.zst"),
                dir.path()
            )
            .is_err()
        );
        assert!(
            local_archives(&argv("pacman -U missing-1-1-any.pkg.tar.zst"), dir.path()).is_err()
        );
        assert!(local_archives(&argv("pacman -U"), dir.path()).is_err());
    }

    fn build_package(dir: &Path, install: Option<&str>) -> std::path::PathBuf {
        fs::write(
            dir.join(".PKGINFO"),
            "pkgname = sample\npkgbase = sample\npkgver = 1.0-1\narch = any\n",
        )
        .unwrap();
        let mut members = vec![".PKGINFO"];
        if let Some(script) = install {
            fs::write(dir.join(".INSTALL"), script).unwrap();
            members.push(".INSTALL");
        }
        let archive = dir.join("sample-1.0-1-any.pkg.tar");
        let status = Command::new("/usr/bin/bsdtar")
            .arg("-cf")
            .arg(&archive)
            .args(&members)
            .current_dir(dir)
            .status()
            .unwrap();
        assert!(status.success());
        archive
    }

    #[test]
    fn relative_upgrade_archives_resolve_against_pacmans_directory() {
        if !tool_available("/usr/bin/bsdtar") || !tool_available("/usr/bin/pacman") {
            return;
        }
        let dir = TempDir::new("pacman-relative");
        let archive = build_package(dir.path(), None);

        let archives =
            local_archives(&argv("pacman -U sample-1.0-1-any.pkg.tar"), dir.path()).unwrap();
        assert_eq!(archives["sample"], Ok(vec![archive]));
    }

    #[test]
    fn archives_others_can_swap_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("pacman-private");
        let shared = dir.path().join("shared");
        fs::create_dir(&shared).unwrap();
        fs::write(shared.join("x.pkg.tar.zst"), "x").unwrap();
        let uid = std::os::unix::fs::MetadataExt::uid(&fs::metadata(dir.path()).unwrap());
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(super::check_private(&shared.join("x.pkg.tar.zst"), Some(uid)).is_ok());
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(super::check_private(&shared.join("x.pkg.tar.zst"), Some(uid)).is_err());
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(super::check_private(&shared.join("x.pkg.tar.zst"), Some(uid)).is_ok());
        // Owned by someone else.
        assert!(super::check_private(&shared.join("x.pkg.tar.zst"), Some(uid + 1)).is_err());
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn install_scripts_are_reviewed_through_the_archive_model() {
        if !tool_available("/usr/bin/bsdtar") {
            return;
        }
        let dir = TempDir::new("pacman-install");
        let archive = build_package(dir.path(), Some("post_install() { rm -rf /; }\n"));

        let mut report = Report::new("test");
        let (scriptlet, _) = scan_package(
            &archive,
            "sample",
            SourceClass::LocalPackage,
            &[],
            &mut report,
        )
        .unwrap();
        assert!(scriptlet);
        assert_eq!(
            report.class_of("sample/sample-1.0-1-any.pkg.tar/.INSTALL"),
            SourceClass::LocalPackage
        );
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule, RuleId::DestructiveSystemOperation);
        assert_eq!(
            report.agent_input[0].content,
            "post_install() { rm -rf /; }\n"
        );
        assert!(!dir.path().join("sample").exists());

        // A Latin-1 byte no longer refuses a scriptlet: it is reviewed.
        let latin = TempDir::new("pacman-latin1");
        fs::write(
            latin.path().join(".INSTALL"),
            b"# caf\xe9\npost_install() { true; }\n",
        )
        .unwrap();
        let archive = build_package(latin.path(), None);
        let status = Command::new("/usr/bin/bsdtar")
            .arg("-rf")
            .arg(&archive)
            .arg(".INSTALL")
            .current_dir(latin.path())
            .status()
            .unwrap();
        assert!(status.success());
        let mut report = Report::new("test");
        assert!(
            scan_package(
                &archive,
                "sample",
                SourceClass::LocalPackage,
                &[],
                &mut report
            )
            .unwrap()
            .0
        );

        let plain_dir = TempDir::new("pacman-plain");
        let plain = build_package(plain_dir.path(), None);
        assert!(
            !scan_package(
                &plain,
                "sample",
                SourceClass::LocalPackage,
                &[],
                &mut Report::default()
            )
            .unwrap()
            .0
        );
    }
}
