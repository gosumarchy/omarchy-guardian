//! The pacman pre-transaction hook: review the `.INSTALL` scriptlets of the
//! exact package archives a transaction is about to install.
//!
//! libalpm runs hooks as direct children of pacman after `chroot` +
//! `chdir("/")`, so the hook's own working directory says nothing about the
//! user's. The hook script passes pacman's PID and its working directory
//! (`/proc/<pid>/cwd`, readable only by root), and this module reads pacman's
//! exact argv from `/proc/<pid>/cmdline` instead of re-parsing a shell string.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, BufRead, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::classify;
use crate::config::Settings;
use crate::config::model::{AiRequirement, Named, SourceClass};
use crate::content::{self, Content};
use crate::engine::plan::HashOnly;
use crate::error::{Error, IoContext};
use crate::notify;
use crate::payload;
use crate::report::{Gap, LocalFinding, Report};
use crate::review;
use crate::rules::RuleId;
use crate::scan::MAX_TEXT_FILE_SIZE;
use crate::sweep::read::{self, Public, View};
use crate::tools::{self, Limits, OpenCode, Reviewer};

const DEFAULT_CACHE_DIR: &str = "/var/cache/pacman/pkg/";
/// The configuration pacman and `pacman-conf` read when none is named.
const DEFAULT_CONFIG: &str = "/etc/pacman.conf";
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
    let Transaction {
        operation,
        operands,
    } = parse_transaction(&argv)?;

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
            let mut archives = local_archives(&operands, &args.cwd)?;
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

    let everything: Vec<PathBuf> = archives
        .values()
        .filter_map(|paths| paths.as_ref().ok())
        .flatten()
        .cloned()
        .collect();
    let shipped = Shipped {
        archives: &everything,
        index: RefCell::new(None),
    };
    for target in &targets {
        let class = classes.get(target).copied().unwrap_or(match operation {
            Operation::Sync => SourceClass::ThirdPartyRepo,
            Operation::LocalUpgrade => SourceClass::LocalPackage,
        });
        match archives.get(target) {
            Some(Ok(paths)) => {
                for archive in paths {
                    // What another archive of the transaction ships, for a
                    // link in this one that leads there: each archive is
                    // opened once, and only when such a link is met.
                    let others = |path: &str| shipped.lookup(archive, path);
                    match scan_package(archive, target, class, &trusted, &others, &mut report) {
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

/// Long options that point pacman at another system, database, cache or
/// configuration than the one Guardian reads: the review would be of the
/// wrong packages, or compare with the wrong installed files.
const REDIRECTING: &[&str] = &[
    "root", "dbpath", "config", "cachedir", "sysroot", "hookdir", "gpgdir",
];
/// Long options whose value is the next argument (or follows `=`).
const VALUED: &[&str] = &[
    "ignore",
    "ignoregroup",
    "overwrite",
    "assume-installed",
    "color",
    "print-format",
    "ask",
    "logfile",
    "arch",
];

/// A pacman command line: the operation and its operands (package names
/// for a sync, archives for an upgrade).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub operation: Operation,
    pub operands: Vec<String>,
}

/// Reads pacman's command line. Only sync (`-S`) and upgrade (`-U`)
/// transactions install scriptlets from archives Guardian can locate, and
/// only against the system Guardian itself reads. pacman takes a long
/// option by any unambiguous beginning, so a redirecting or valued one is
/// recognised by its beginning too; an argument that is no option is an
/// operand, whatever it is named.
pub fn parse_transaction(argv: &[String]) -> Result<Transaction, Error> {
    // A script named pacman shows as its interpreter, then itself; after
    // pacman itself, an argument of that name is an operand.
    let named = |index: usize| {
        argv.get(index)
            .is_some_and(|argument| argument.rsplit('/').next() == Some("pacman"))
    };
    let program = usize::from(!named(0) && named(1));
    let redirects = |option: &str| {
        Error::Refused(format!(
            "pacman was given {option}, which points it at another system, database, cache or configuration than the one Guardian reviews against"
        ))
    };
    let begins = |names: &[&str], name: &str| names.iter().any(|known| known.starts_with(name));

    let mut operation = None;
    let mut operands = Vec::new();
    let mut arguments = argv.iter().skip(program + 1);
    while let Some(argument) = arguments.next() {
        if argument == "--" {
            operands.extend(arguments.cloned());
            break;
        }
        if let Some(long) = argument.strip_prefix("--") {
            let (name, value) = long
                .split_once('=')
                .map_or((long, None), |(name, value)| (name, Some(value)));
            match name {
                "sync" => operation = operation.or(Some(Operation::Sync)),
                "upgrade" => operation = operation.or(Some(Operation::LocalUpgrade)),
                // `--print` is an option of its own, not `--print-format`.
                "print" => {}
                // yay names the configuration on every call; the one
                // Guardian reads itself is no redirection.
                _ if name.len() > 1 && "config".starts_with(name) => {
                    let value = value.or_else(|| arguments.next().map(String::as_str));
                    if value != Some(DEFAULT_CONFIG) {
                        return Err(redirects(argument));
                    }
                }
                _ if !name.is_empty() && begins(REDIRECTING, name) => {
                    return Err(redirects(argument));
                }
                _ if !name.is_empty() && begins(VALUED, name) && value.is_none() => {
                    arguments.next();
                }
                _ => {}
            }
        } else if let Some(flags) = argument.strip_prefix('-').filter(|flags| !flags.is_empty()) {
            // `-r` and `-b` are the only short options with a value.
            if flags.contains(['r', 'b']) {
                return Err(redirects(argument));
            }
            if flags.contains('S') {
                operation = operation.or(Some(Operation::Sync));
            } else if flags.contains('U') {
                operation = operation.or(Some(Operation::LocalUpgrade));
            }
        } else {
            operands.push(argument.clone());
        }
    }
    operation
        .map(|operation| Transaction {
            operation,
            operands,
        })
        .ok_or_else(|| {
            Error::Refused(
                "only pacman sync (-S) and upgrade (-U) transactions are supported".into(),
            )
        })
}

/// Per-target archive lookup result: the archives, or why none was usable.
type Archives = HashMap<String, Result<Vec<PathBuf>, String>>;

/// For `-U`: every operand is a package archive, whatever its name (pacman
/// reads the file, not its extension), resolved against pacman's working
/// directory and grouped by the package it holds. One left out would have
/// its target looked up in the sync databases and reviewed as another file.
fn local_archives(operands: &[String], cwd: &Path) -> Result<Archives, Error> {
    let mut archives: Archives = HashMap::new();

    for argument in operands {
        // pacman reads `-` as "archives named on standard input".
        if argument == "-" {
            return Err(Error::Refused(
                "package archives named on standard input are not supported; name them as arguments"
                    .into(),
            ));
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

/// A finding for each right a package hands out without a scriptlet
/// (see `payload::Review::root_set_id`), unless the installed file already
/// has it.
fn grant_findings(
    archive: &payload::Archive,
    grants: Vec<(String, &'static str)>,
    target: &str,
    archive_name: &str,
    class: SourceClass,
    report: &mut Report,
) {
    for (path, what) in grants {
        // Already installed that way: nothing new is being granted.
        let installed = fs::symlink_metadata(Path::new("/").join(&path))
            .is_ok_and(|metadata| payload::already_granted(what, &metadata))
            || (what == payload::WITH_CAPABILITIES
                && archive
                    .shipped_capability(&path)
                    .is_some_and(|shipped| has_capabilities(&path, shipped)));
        if installed {
            continue;
        }
        let rel = format!("{target}/{archive_name}/{path}");
        report.file_classes.insert(rel.clone(), class);
        report.findings.push(LocalFinding {
            path: rel,
            line: 1,
            rule: RuleId::PrivilegeEscalation,
            excerpt: format!(
                "/{path} is installed {what}: {}",
                match what {
                    payload::WITH_CAPABILITIES => "it has root-like rights for whoever starts it",
                    payload::WITH_ACL => "it grants rights its mode does not show",
                    payload::WRITABLE_BY_ALL
                    | payload::OWNED_BY_OTHER
                    | payload::WRITABLE_BY_GROUP =>
                        "someone other than root can replace what it holds",
                    payload::SETUID_OTHER | payload::SETGID_OTHER =>
                        "it runs with that user's or group's rights for whoever starts it",
                    _ => "it runs as root for whoever starts it",
                }
            ),
        });
    }
}

/// Whether the installed file at `path` (relative to `/`) already carries
/// exactly the file capabilities `shipped` (the attribute's value as
/// base64): a package that ships the same again grants nothing new. Any
/// doubt, a missing tool included, counts as "no" and the finding is raised.
fn has_capabilities(path: &str, shipped: &str) -> bool {
    let installed = Path::new("/").join(path);
    if !fs::symlink_metadata(&installed).is_ok_and(|metadata| metadata.is_file()) {
        return false;
    }
    let args: [OsString; 6] = [
        "-n".into(),
        "security.capability".into(),
        "-e".into(),
        "base64".into(),
        "--absolute-names".into(),
        installed.into_os_string(),
    ];
    let Ok(captured) = tools::run(
        Path::new("/usr/bin/getfattr"),
        &args,
        None,
        C_LOCALE,
        TOOL_LIMITS,
    ) else {
        return false;
    };
    let plain = |value: &str| value.trim().trim_end_matches('=').to_string();
    captured.status.success()
        && String::from_utf8_lossy(&captured.stdout)
            .lines()
            .find_map(|line| line.strip_prefix("security.capability=0s"))
            .is_some_and(|installed| !installed.is_empty() && plain(installed) == plain(shipped))
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
    pub version: String,
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
    let filenames = sync_filenames(&versions)?;
    let mut archives = Archives::new();

    for target in targets {
        let Some(candidates) = versions.get(target) else {
            archives.insert(
                target.clone(),
                Err("pacman has no sync database entry for it".into()),
            );
            continue;
        };

        // The archive pacman installs is the one its database names, not
        // one that merely looks like the package's name and version.
        let mut found = Vec::new();
        let mut unknown = None;
        for candidate in candidates {
            let key = (
                candidate.repo.clone(),
                target.clone(),
                candidate.version.clone(),
            );
            match filenames.get(&key) {
                Some(name) => {
                    if let Some(path) = cache.get(name) {
                        found.push(path.clone());
                    }
                }
                // Which file this repository would install is not known:
                // another repository's archive must not stand in for it.
                None => unknown = Some(candidate.repo.clone()),
            }
        }
        if let Some(repo) = unknown {
            archives.insert(
                target.clone(),
                Err(format!(
                    "pacman did not say which file the repository {repo:?} installs for it"
                )),
            );
            continue;
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

/// (repository, package, version) to the archive's file name.
type Filenames = HashMap<(String, String, String), String>;

/// Separates the fields pacman prints for a package: no name, version or
/// file name holds it.
const FIELD: char = '\u{1f}';

/// The file name pacman itself gives each candidate's archive, asked of
/// pacman (`-Sp --print-format`) one repository at a time, so it is read
/// from the sync database exactly as the transaction reads it. `-dd`
/// keeps it to the packages named; printing takes no database lock, which
/// the running transaction holds. A repository pacman cannot answer for
/// has no file names, and its targets then have no archive.
fn sync_filenames(versions: &HashMap<String, Vec<SyncCandidate>>) -> Result<Filenames, Error> {
    let mut wanted: HashMap<&str, Vec<&str>> = HashMap::new();
    for (name, candidates) in versions {
        for candidate in candidates {
            wanted
                .entry(candidate.repo.as_str())
                .or_default()
                .push(name);
        }
    }
    let mut filenames = Filenames::new();
    for (repo, names) in wanted {
        if !is_valid_package_name(repo) {
            continue;
        }
        let mut args: Vec<OsString> = vec![
            "-Sp".into(),
            "-dd".into(),
            "--print-format".into(),
            format!("%r{FIELD}%n{FIELD}%v{FIELD}%f").into(),
            "--".into(),
        ];
        args.extend(
            names
                .iter()
                .map(|name| OsString::from(format!("{repo}/{name}"))),
        );
        let captured = tools::run(Path::new(tools::PACMAN), &args, None, C_LOCALE, TOOL_LIMITS)?;
        if !captured.status.success() {
            continue;
        }
        filenames.extend(parse_filenames(&String::from_utf8_lossy(&captured.stdout)));
    }
    Ok(filenames)
}

/// The packages `pacman -Sp` printed in `sync_filenames`' format. A file
/// name that is not a plain one is left out.
pub fn parse_filenames(output: &str) -> Filenames {
    output
        .lines()
        .filter_map(|line| {
            let mut fields = line.splitn(4, FIELD);
            let key = (
                fields.next()?.to_string(),
                fields.next()?.to_string(),
                fields.next()?.to_string(),
            );
            let filename = fields.next()?;
            let plain =
                !filename.is_empty() && !filename.contains('/') && !filename.starts_with('.');
            plain.then(|| (key, filename.to_string()))
        })
        .collect()
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
                    version: (*version).to_string(),
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
    others: &dyn Fn(&str) -> payload::InArchive,
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
    for mut file in reviewed.files {
        // An upgrade only brings in what changed; the rest is already active.
        // A link that did not change still leads somewhere new when this
        // transaction replaces what it leads to.
        if file.is_installed_unchanged(Path::new("/"))
            && !file
                .leads_outside
                .as_deref()
                .is_some_and(|leads| replaced_by_transaction(leads, others))
        {
            summary.unchanged += 1;
            continue;
        }
        let rel = format!("{target}/{archive_name}/{}", file.path);
        if !follow_outside_link(&mut file, others, report) {
            continue;
        }
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
                    skipped_files: None,
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
    grant_findings(
        &archive,
        reviewed.root_set_id,
        target,
        archive_name,
        class,
        report,
    );
    archive.verify_unchanged()?;
    Ok((scriptlet, summary))
}

/// What the archives of a transaction ship, for a link in one of them that
/// leads to a file another one brings. Which archive ships which path is
/// read once, the first time it is asked; no archive is kept open.
struct Shipped<'a> {
    archives: &'a [PathBuf],
    /// Each path with the archives that ship it, and whether an archive
    /// could not be read.
    index: RefCell<Option<(ShippedPaths, bool)>>,
}

/// Each path with the archives that ship it.
type ShippedPaths = HashMap<String, Vec<PathBuf>>;

impl Shipped<'_> {
    fn lookup(&self, asking: &Path, path: &str) -> payload::InArchive {
        let mut index = self.index.borrow_mut();
        let (paths, unreadable) = index.get_or_insert_with(|| {
            let mut paths = ShippedPaths::new();
            let mut unreadable = false;
            for archive in self.archives {
                match payload::Archive::open(archive) {
                    Ok(opened) => {
                        for shipped in opened.paths() {
                            paths
                                .entry(shipped.to_string())
                                .or_default()
                                .push(archive.clone());
                        }
                    }
                    Err(_) => unreadable = true,
                }
            }
            (paths, unreadable)
        });
        for archive in paths.get(path).into_iter().flatten() {
            if archive == asking {
                continue;
            }
            return payload::Archive::open(archive).map_or(payload::InArchive::Other, |opened| {
                opened.shipped_file(path)
            });
        }
        // An archive that could not be read may be the one that ships it.
        if *unreadable {
            payload::InArchive::Other
        } else {
            payload::InArchive::Absent
        }
    }
}

/// A link to a file this package does not ship is reviewed as that file:
/// as the transaction brings it, or as root alone keeps it on this system
/// now. Returns false, with a gap, when it cannot be.
fn follow_outside_link(
    file: &mut payload::PayloadFile,
    others: &dyn Fn(&str) -> payload::InArchive,
    report: &mut Report,
) -> bool {
    let Some(leads) = file.leads_outside.take() else {
        return true;
    };
    match linked_file(Path::new("/"), &leads, others) {
        // A device (`/dev/null`, which masks a unit) or the kernel's own
        // files: nothing to read, the note says what it is.
        Ok(None) => true,
        Ok(Some((whence, bytes))) => {
            file.content = payload::annotated(
                content::classify_payload(&file.path, &bytes),
                &format!(
                    "# /{} is a symbolic link to {leads}, which this package does not ship; below is that file as {whence}.\n",
                    file.path
                ),
            );
            true
        }
        Err(reason) => {
            report.gaps.push(Gap::Package(Error::Refused(format!(
                "/{} links to {leads}, which {reason}: what it holds cannot be reviewed",
                file.path
            ))));
            false
        }
    }
}

/// Whether this transaction puts something at `leads` other than what is
/// there now.
fn replaced_by_transaction(leads: &str, others: &dyn Fn(&str) -> payload::InArchive) -> bool {
    let rel = leads.trim_start_matches('/');
    match others(rel) {
        payload::InArchive::Absent => false,
        payload::InArchive::Other => true,
        // Only a small regular file is compared; anything else counts as
        // replaced, and is looked at.
        payload::InArchive::File(bytes) => {
            let path = Path::new("/").join(rel);
            !fs::symlink_metadata(&path).is_ok_and(|metadata| {
                metadata.is_file()
                    && metadata.len() <= MAX_TEXT_FILE_SIZE
                    && fs::read(&path).is_ok_and(|now| now == bytes)
            })
        }
    }
}

/// How many links are followed to the file a package's link leads to.
const MAX_LINKED_HOPS: usize = 8;

/// The file at `leads` (an absolute path): as another archive of the
/// transaction ships it, or as it is under `root` when root alone controls
/// the way to it and the file itself. Says where it came from, or why it
/// cannot be used.
fn linked_file(
    root: &Path,
    leads: &str,
    others: &dyn Fn(&str) -> payload::InArchive,
) -> Result<Option<(&'static str, Vec<u8>)>, String> {
    let mut rel = leads.trim_start_matches('/').to_string();
    // Devices and the kernel's own files, which hold nothing to read; not
    // what anyone may write under /dev (`shm`, `mqueue`, `pts`), which is
    // looked at like any other place.
    let special = |rel: &str| {
        let shared = ["dev/shm/", "dev/mqueue/", "dev/pts/"]
            .iter()
            .any(|place| rel.starts_with(place));
        !shared
            && ["dev/", "proc/", "sys/"]
                .iter()
                .any(|top| rel.starts_with(top))
    };
    for _ in 0..MAX_LINKED_HOPS {
        if special(&rel) {
            return Ok(None);
        }
        // At every step: what the transaction puts there is what will be
        // there, even part-way along a chain of the system's links.
        match others(&rel) {
            payload::InArchive::File(bytes) => {
                return Ok(Some((
                    "another package of this transaction ships it",
                    bytes,
                )));
            }
            payload::InArchive::Other => {
                return Err(
                    "this transaction puts there as something other than a file that can be read"
                        .into(),
                );
            }
            payload::InArchive::Absent => {}
        }
        let seen = read::seen(root, &rel, View::Pinned).ok_or("is not on this system")?;
        if !seen.kept {
            return Err("lies where someone other than root can change it".into());
        }
        match seen.what {
            Public::File(file) => {
                let unreadable = |error: io::Error| format!("cannot be read ({error})");
                let metadata = file.metadata().map_err(unreadable)?;
                if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                    return Err("is a file someone other than root can change".into());
                }
                let mut bytes = Vec::new();
                file.take(MAX_TEXT_FILE_SIZE + 1)
                    .read_to_end(&mut bytes)
                    .map_err(unreadable)?;
                if bytes.len() as u64 > MAX_TEXT_FILE_SIZE {
                    return Err("is too large to review".into());
                }
                return Ok(Some(("it is on this system now", bytes)));
            }
            Public::Link(target) => {
                let base = Path::new(&seen.path)
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_default();
                let next = if target.starts_with('/') {
                    PathBuf::from(target.trim_start_matches('/'))
                } else {
                    base.join(&target)
                };
                rel = read::normalize(&next).ok_or("leads out of the system's root")?;
            }
            Public::Other => return Ok(None),
            Public::Directory(_) => return Err("is a directory".into()),
        }
    }
    Err("is behind too many links".into())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    use super::{
        Archives, Operation, is_valid_package_name, local_archives, missing_targets,
        parse_sync_info, parse_transaction, read_targets, scan_package, split_cmdline,
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
            assert_eq!(
                parse_transaction(&argv(line)).unwrap().operation,
                expected,
                "{line}"
            );
        }
        for line in ["pacman -Rns foo", "pacman -Qs foo", "pacman -- -S"] {
            assert!(parse_transaction(&argv(line)).is_err(), "{line}");
        }
    }

    #[test]
    fn every_operand_of_an_upgrade_is_an_archive() {
        let operands = |line: &str| parse_transaction(&argv(line)).unwrap().operands;
        // Even one named like the program.
        assert_eq!(
            operands("pacman ./pacman -U good.pkg.tar.zst"),
            ["./pacman", "good.pkg.tar.zst"]
        );
        // Whatever it is named, and wherever it stands.
        assert_eq!(
            operands("pacman -U good-1-1-any.pkg.tar.zst evil.pkg.tar.lz4 thing.bin"),
            ["good-1-1-any.pkg.tar.zst", "evil.pkg.tar.lz4", "thing.bin"]
        );
        assert_eq!(
            operands("pacman first.bin -U --noconfirm last"),
            ["first.bin", "last"]
        );
        assert_eq!(
            operands("/bin/sh /e2e/bin/pacman -U a.pkg.tar.zst"),
            ["a.pkg.tar.zst"]
        );
        assert_eq!(
            operands("pacman -U -- -odd.pkg.tar.zst --needed"),
            ["-odd.pkg.tar.zst", "--needed"]
        );
        // An option's value is not an operand.
        assert_eq!(
            operands(
                "pacman -U --overwrite /usr/* --ignore foo --color=never a.pkg.tar.zst --print x"
            ),
            ["a.pkg.tar.zst", "x"]
        );
        assert_eq!(operands("pacman -U --ign foo --assume bar=1 a"), ["a"]);
    }

    #[test]
    fn a_transaction_against_another_system_is_refused() {
        for line in [
            "pacman -U --root /mnt a.pkg.tar.zst",
            "pacman -U --root=/mnt a.pkg.tar.zst",
            "pacman -S --dbpath /tmp/db foo",
            "pacman -S --config /tmp/pacman.conf foo",
            "pacman -S --conf=/tmp/pacman.conf foo",
            "pacman -S --cachedir /tmp/cache foo",
            "pacman -S --sysroot /mnt foo",
            "pacman -S --hookdir /tmp/hooks foo",
            "pacman -S --gpgdir /tmp/gpg foo",
            "pacman -Sr /mnt foo",
            "pacman -r/mnt -U a.pkg.tar.zst",
            "pacman -Ub /tmp/db a.pkg.tar.zst",
        ] {
            let error = parse_transaction(&argv(line)).unwrap_err().to_string();
            assert!(error.contains("another system"), "{line}: {error}");
        }
        // After `--` they are operands, not options.
        assert!(parse_transaction(&argv("pacman -S -- --root")).is_ok());
        // yay names the default configuration on every call.
        for line in [
            "pacman -S -y -u --config /etc/pacman.conf --",
            "pacman -U --config=/etc/pacman.conf -- /tmp/a.pkg.tar.zst",
            "pacman -U --conf /etc/pacman.conf a.pkg.tar.zst",
        ] {
            assert!(parse_transaction(&argv(line)).is_ok(), "{line}");
        }
        assert_eq!(
            parse_transaction(&argv("pacman -U --config /etc/pacman.conf -- a b"))
                .unwrap()
                .operands,
            ["a", "b"]
        );
        assert!(parse_transaction(&argv("pacman -S --config")).is_err());
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
        assert_eq!(versions["linux"][0].version, "6.10.1.arch1-1");
        assert_eq!(versions["linux"][0].version_arch, "6.10.1.arch1-1-x86_64");
        assert_eq!(versions["linux"][0].repo, "core");
        assert_eq!(versions["ttf-font"][0].version_arch, "2:1.0-3-any");
        assert_eq!(versions["ttf-font"][0].repo, "chaotic-aur");
    }

    #[test]
    fn the_archive_is_the_one_pacman_names() {
        let output = "core\u{1f}foo\u{1f}1-2\u{1f}foo-1-2-any.pkg.tar.zst\nextra\u{1f}bar\u{1f}2:1.0-3\u{1f}odd name\u{1f}x.pkg\nevil\u{1f}a\u{1f}1-1\u{1f}../../etc/x\nevil\u{1f}b\u{1f}1-1\u{1f}.hidden\nevil\u{1f}c\u{1f}1-1\u{1f}\nshort\u{1f}line\n";
        let filenames = super::parse_filenames(output);
        let key = |repo: &str, name: &str, version: &str| {
            (repo.to_string(), name.to_string(), version.to_string())
        };
        assert_eq!(filenames.len(), 2);
        assert_eq!(
            filenames[&key("core", "foo", "1-2")],
            "foo-1-2-any.pkg.tar.zst"
        );
        assert_eq!(
            filenames[&key("extra", "bar", "2:1.0-3")],
            "odd name\u{1f}x.pkg"
        );

        // Against this system's own databases, when there are any.
        let Ok(candidates) = super::sync_versions(&["pacman".to_string()]) else {
            return;
        };
        let Some(candidate) = candidates.get("pacman").and_then(|found| found.first()) else {
            return;
        };
        let filenames = super::sync_filenames(&candidates).unwrap();
        let name = &filenames[&key(&candidate.repo, "pacman", &candidate.version)];
        assert!(
            name.starts_with(&format!("pacman-{}", candidate.version_arch)),
            "{name}"
        );
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
        let refused = |operands: &str| local_archives(&argv(operands), dir.path()).is_err();
        assert!(refused("https://x.test/a-1-1-any.pkg.tar.zst"));
        // Whatever follows the name: pacman downloads it all the same.
        assert!(refused("https://x.test/a-1-1-any.pkg.tar.zst?x=1"));
        assert!(refused("missing-1-1-any.pkg.tar.zst"));
        assert!(refused(""));
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

        let archives = local_archives(&argv("sample-1.0-1-any.pkg.tar"), dir.path()).unwrap();
        assert_eq!(archives["sample"], Ok(vec![archive.clone()]));

        // A package is what the file holds, not what it is called: an
        // archive under another name is found, never skipped.
        let renamed = dir.path().join("thing.bin");
        fs::rename(&archive, &renamed).unwrap();
        let archives = local_archives(&argv("thing.bin"), dir.path()).unwrap();
        assert_eq!(archives["sample"], Ok(vec![renamed]));
        fs::write(dir.path().join("notes.txt"), "not a package\n").unwrap();
        assert!(local_archives(&argv("thing.bin notes.txt"), dir.path()).is_err());
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
        // Owned by someone else (root's files are trusted, so not as root).
        if uid != 0 {
            assert!(super::check_private(&shared.join("x.pkg.tar.zst"), Some(uid + 1)).is_err());
        }
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn a_file_installed_setuid_root_is_a_finding() {
        use std::os::unix::fs::PermissionsExt;
        if !tool_available("/usr/bin/bsdtar") {
            return;
        }
        let dir = TempDir::new("pacman-setuid");
        let root = dir.path().join("root");
        fs::create_dir_all(root.join("usr/bin")).unwrap();
        fs::create_dir_all(root.join("opt/app")).unwrap();
        fs::create_dir_all(root.join("opt/fake")).unwrap();
        // What a Chromium-based program keeps beside its helper.
        fs::write(root.join("opt/app/icudtl.dat"), "x").unwrap();
        fs::write(root.join("opt/app/resources.pak"), "x").unwrap();
        fs::write(root.join(".PKGINFO"), "pkgname = sample\n").unwrap();
        // A new setuid program, one that is already installed that way,
        // and the helper Chromium-based programs need.
        for path in [
            "usr/bin/guardian-test-shell",
            "usr/bin/chrome-sandbox",
            "opt/fake/chrome-sandbox",
            "usr/bin/su",
            "opt/app/chrome-sandbox",
        ] {
            fs::write(root.join(path), b"\x7fELF\x02\x01\x01\0").unwrap();
            fs::set_permissions(root.join(path), fs::Permissions::from_mode(0o4755)).unwrap();
        }
        let archive = dir.path().join("sample-1-1-any.pkg.tar");
        let status = Command::new("/usr/bin/bsdtar")
            .args(["--uid", "0", "--gid", "0", "-cf"])
            .arg(&archive)
            .args([".PKGINFO", "usr", "opt"])
            .current_dir(&root)
            .status()
            .unwrap();
        assert!(status.success());

        let mut report = Report::new("test");
        scan_package(
            &archive,
            "sample",
            SourceClass::LocalPackage,
            &[],
            &|_| crate::payload::InArchive::Absent,
            &mut report,
        )
        .unwrap();
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.rule == RuleId::PrivilegeEscalation)
        );
        let mut found: Vec<&str> = report
            .findings
            .iter()
            .filter_map(|finding| finding.excerpt.split(' ').next())
            .collect();
        found.sort_unstable();
        // The helper beside its program's runtime is the only one let
        // through; `su` counts as installed where this system has it setuid.
        let su_installed = fs::metadata("/usr/bin/su")
            .is_ok_and(|metadata| metadata.permissions().mode() & 0o4000 != 0);
        let mut expected = vec![
            "/opt/fake/chrome-sandbox",
            "/usr/bin/chrome-sandbox",
            "/usr/bin/guardian-test-shell",
        ];
        if !su_installed {
            expected.push("/usr/bin/su");
        }
        assert_eq!(found, expected);
        assert!(
            report.findings[0]
                .excerpt
                .ends_with("is installed setuid root: it runs as root for whoever starts it")
        );
        assert_eq!(
            report.class_of("sample/sample-1-1-any.pkg.tar/usr/bin/guardian-test-shell"),
            SourceClass::LocalPackage
        );
    }

    #[test]
    fn a_link_to_a_file_the_package_does_not_ship_is_reviewed_as_that_file() {
        if !tool_available("/usr/bin/bsdtar") {
            return;
        }
        let dir = TempDir::new("pacman-outside-link");
        let root = dir.path().join("root");
        fs::create_dir_all(root.join("etc/sudoers.d")).unwrap();
        fs::write(root.join(".PKGINFO"), "pkgname = sample\n").unwrap();
        // One to a file another package of the transaction ships, one to a
        // file root keeps on every system, one to nothing at all.
        for (name, target) in [
            ("shipped", "/usr/lib/other/rule"),
            ("system", "/etc/passwd"),
            ("missing", "/usr/lib/guardian-test-nowhere/rule"),
            ("masked", "/dev/null"),
            ("shared", "/dev/shm/guardian-test"),
        ] {
            std::os::unix::fs::symlink(target, root.join("etc/sudoers.d").join(name)).unwrap();
        }
        let archive = dir.path().join("sample-1-1-any.pkg.tar");
        let status = Command::new("/usr/bin/bsdtar")
            .args(["--uid", "0", "--gid", "0", "-cf"])
            .arg(&archive)
            .args([".PKGINFO", "etc"])
            .current_dir(&root)
            .status()
            .unwrap();
        assert!(status.success());

        let others = |path: &str| {
            if path == "usr/lib/other/rule" {
                crate::payload::InArchive::File(b"ALL ALL=(ALL) NOPASSWD: ALL\n".to_vec())
            } else {
                crate::payload::InArchive::Absent
            }
        };
        let mut report = Report::new("test");
        scan_package(
            &archive,
            "sample",
            SourceClass::LocalPackage,
            &[],
            &others,
            &mut report,
        )
        .unwrap();
        let sent = |name: &str| {
            report
                .agent_input
                .iter()
                .find(|file| file.path.ends_with(&format!("etc/sudoers.d/{name}")))
                .map(|file| file.content.clone())
        };
        assert!(
            sent("shipped").is_some_and(|text| text.contains("NOPASSWD")
                && text.contains("another package of this transaction")),
            "{:?}",
            sent("shipped")
        );
        if fs::metadata("/etc/passwd")
            .is_ok_and(|metadata| std::os::unix::fs::MetadataExt::uid(&metadata) == 0)
        {
            assert!(
                sent("system").is_some_and(|text| text.contains("on this system now")),
                "{:?}",
                sent("system")
            );
        }
        assert!(sent("missing").is_none());
        // A link to /dev/null masks; it is said, not a gap.
        assert!(sent("masked").is_some_and(|text| text.contains("does not ship")));
        // What anyone may write under /dev is no device: a gap.
        assert!(sent("shared").is_none());
        assert_eq!(report.gaps.len(), 2, "{:?}", report.gaps);
        assert!(
            report.gaps.iter().any(|gap| gap
                .to_string()
                .contains("/etc/sudoers.d/missing links to /usr/lib/guardian-test-nowhere/rule")),
            "{:?}",
            report.gaps
        );
    }

    #[test]
    fn a_file_another_archive_ships_is_found_whichever_archive_comes_first() {
        if !tool_available("/usr/bin/bsdtar") {
            return;
        }
        let dir = TempDir::new("pacman-shipped");
        let pack = |name: &str, files: &[(&str, &str)]| {
            let root = dir.path().join(name);
            fs::create_dir_all(&root).unwrap();
            fs::write(root.join(".PKGINFO"), format!("pkgname = {name}\n")).unwrap();
            let mut members = vec![".PKGINFO".to_string()];
            for (path, text) in files {
                fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
                fs::write(root.join(path), text).unwrap();
                members.push((*path).to_string());
            }
            let archive = dir.path().join(format!("{name}-1-1-any.pkg.tar"));
            let status = Command::new("/usr/bin/bsdtar")
                .args(["--uid", "0", "--gid", "0", "-cf"])
                .arg(&archive)
                .args(&members)
                .current_dir(&root)
                .status()
                .unwrap();
            assert!(status.success());
            archive
        };
        let asking = pack("a", &[("etc/a.conf", "x\n")]);
        let other = pack("b", &[("usr/lib/b/data", "y\n")]);
        let shipping = pack("c", &[("usr/lib/other/rule", "ALL ALL=(ALL) ALL\n")]);
        let archives = [asking.clone(), other, shipping];
        let shipped = super::Shipped {
            archives: &archives,
            index: std::cell::RefCell::new(None),
        };
        assert_eq!(
            shipped.lookup(&asking, "usr/lib/other/rule"),
            crate::payload::InArchive::File(b"ALL ALL=(ALL) ALL\n".to_vec())
        );
        assert_eq!(
            shipped.lookup(&asking, "usr/lib/nowhere"),
            crate::payload::InArchive::Absent
        );
        // An archive asks no question of itself.
        assert_eq!(
            shipped.lookup(&asking, "etc/a.conf"),
            crate::payload::InArchive::Absent
        );
        // One that cannot be read may be the one that ships it.
        let broken = [asking.clone(), dir.path().join("missing-1-1-any.pkg.tar")];
        let shipped = super::Shipped {
            archives: &broken,
            index: std::cell::RefCell::new(None),
        };
        assert_eq!(
            shipped.lookup(&asking, "usr/lib/other/rule"),
            crate::payload::InArchive::Other
        );
    }

    #[test]
    fn a_link_chain_ends_at_what_the_transaction_puts_there() {
        use crate::payload::InArchive;
        // `/etc/localtime` is root's link into the zone database: when the
        // transaction replaces that file, its new content is what the
        // chain leads to.
        let Ok(target) = fs::read_link("/etc/localtime") else {
            return;
        };
        let Some(target) = target.to_str().and_then(|target| target.strip_prefix('/')) else {
            return;
        };
        let target = target.to_string();
        let others = |path: &str| {
            if path == target {
                InArchive::File(b"TZif-new".to_vec())
            } else {
                InArchive::Absent
            }
        };
        assert_eq!(
            super::linked_file(Path::new("/"), "/etc/localtime", &others),
            Ok(Some((
                "another package of this transaction ships it",
                b"TZif-new".to_vec()
            )))
        );
        // An unchanged link to it counts as changed, and one to a file the
        // transaction leaves alone does not.
        assert!(super::replaced_by_transaction(
            &format!("/{target}"),
            &others
        ));
        assert!(!super::replaced_by_transaction("/etc/hostname", &others));
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
            &|_| crate::payload::InArchive::Absent,
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
                &|_| crate::payload::InArchive::Absent,
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
                &|_| crate::payload::InArchive::Absent,
                &mut Report::default()
            )
            .unwrap()
            .0
        );
    }
}
