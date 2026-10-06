//! The pacman pre-transaction hook: review the `.INSTALL` scriptlets of the
//! exact package archives a transaction is about to install.
//!
//! libalpm runs hooks as direct children of pacman after `chroot` +
//! `chdir("/")`, so the hook's own working directory says nothing about the
//! user's. The hook script passes pacman's PID and its working directory
//! (`/proc/<pid>/cwd`, readable only by root), and this module reads pacman's
//! exact argv from `/proc/<pid>/cmdline` instead of re-parsing a shell string.

mod archives;
mod argv;
mod links;

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use self::archives::{local_archives, missing_targets, sync_archives};
pub use self::argv::{Transaction, is_valid_package_name, parse_transaction};
use self::argv::{pacman_argv, read_targets};
use self::links::{InstalledLinks, installed_links, local_database, unknown_entries};
use crate::audit::Gate;
use crate::autorun;
use crate::config::Settings;
use crate::config::model::{AiRequirement, Named, SourceClass};
use crate::content::{self, Content};
use crate::engine::plan::HashOnly;
use crate::error::Error;
use crate::payload;
use crate::permit;
use crate::report::{Gap, LocalFinding, Report, ReviewedArchive};
use crate::review;
use crate::rules::{self, RuleId};
use crate::scan::MAX_TEXT_FILE_SIZE;
use crate::sweep::read::{self, Public, View};
use crate::tools::{self, Limits, OpenCode, Reviewer};

#[cfg(test)]
use self::archives::{Archives, check_private, sync_filenames, sync_versions};
#[cfg(test)]
pub use self::archives::{parse_filenames, parse_sync_info};
#[cfg(test)]
use self::argv::split_cmdline;
#[cfg(test)]
use self::links::{mtree_entries, packaged_links};

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
    let links = system_links(&shipped, &mut report);
    let mut fingerprints = Vec::new();
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
                    match scan_package(
                        archive,
                        target,
                        class,
                        &trusted,
                        &others,
                        &links,
                        &mut report,
                    ) {
                        Ok((scriptlet, summary, fingerprint)) => {
                            summary.announce(target, scriptlet);
                            // In pacman's output, and so in its log: the
                            // exact bytes this review is of.
                            outln!(
                                "Pacman package {target}: sha256 {} {}",
                                fingerprint.digest(),
                                fingerprint.name()
                            );
                            report.archives.push(ReviewedArchive {
                                name: fingerprint.name(),
                                class,
                                sha256: fingerprint.digest().to_string(),
                            });
                            fingerprints.push(fingerprint);
                        }
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
    // The AI review took its time. Each archive must still be the file, and
    // hold the bytes, that were reviewed: one rewritten in place meanwhile
    // would be installed unread.
    for fingerprint in &fingerprints {
        if let Err(error) = fingerprint.verify() {
            report.gaps.push(Gap::Package(error));
        }
    }
    Ok(report)
}

/// The links already in the system's auto-run locations: a package that
/// replaces what one leads to changes what that link's file says. What
/// could not be looked at is a gap: system state, which no archive's
/// digest covers, so no permit stands for it.
fn system_links(shipped: &Shipped<'_>, report: &mut Report) -> InstalledLinks {
    let Installed {
        links,
        mut unseen,
        unknown,
    } = installed_links(Path::new("/"), &local_database(), read::MAX_ENTRIES);
    // An entry pacman's record does not describe stops mattering once
    // this transaction puts something else in its place.
    unseen.extend(unknown_entries(&unknown, &|path| {
        !matches!(
            shipped.lookup(Path::new(""), path),
            payload::InArchive::Absent
        )
    }));
    for reason in unseen {
        report.gaps.push(Gap::Package(Error::Refused(reason)));
    }
    links
}

/// The classes of the archives `report` reviewed, joined by `+`.
pub fn reviewed_classes(report: &Report) -> String {
    let mut classes: Vec<&str> = report
        .archives
        .iter()
        .map(|archive| archive.class.name())
        .collect();
    classes.sort_unstable();
    classes.dedup();
    classes.join("+")
}

/// The archives `report` reviewed, by name.
pub fn reviewed_names(report: &Report) -> String {
    let names: Vec<&str> = report
        .archives
        .iter()
        .map(|archive| archive.name.as_str())
        .collect();
    names.join(" ")
}

/// The archives `report` reviewed, each with its SHA-256.
pub fn reviewed_digests(report: &Report) -> String {
    let digests: Vec<String> = report
        .archives
        .iter()
        .map(|archive| format!("{}={}", archive.name, archive.sha256))
        .collect();
    digests.join(" ")
}

/// The transaction `report` reviewed as a permit names it: every archive
/// by its class and the SHA-256 of its bytes. `None` when no archive was
/// read; a transaction with one that was refused has a gap no permit
/// overrules (see `Gap::content_hashed`).
pub fn reviewed_content(report: &Report) -> Option<permit::Content> {
    permit::Content::new(
        Gate::Pacman,
        &reviewed_classes(report),
        &reviewed_names(report),
        report
            .archives
            .iter()
            .map(|archive| format!("{}:{}", archive.class.name(), archive.sha256))
            .collect(),
    )
}

/// What `installed_links` found.
struct Installed {
    links: InstalledLinks,
    /// What could not be looked at, each as a sentence.
    unseen: Vec<String>,
    /// Entries in a directory only root lists that pacman's record does
    /// not describe: the package's record, and the path.
    unknown: Vec<(String, String)>,
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
                "Pacman package {target}: {} file(s) that run on their own, or that those run, not reviewed: {}{}",
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
/// files that run or grant privileges on their own, with the package's
/// files those name, with the AI. `links` are the links already on the
/// system (see `installed_links`). Returns whether it had a scriptlet,
/// what the payload held, and what the archive was when it was read.
fn scan_package(
    archive_path: &Path,
    target: &str,
    class: SourceClass,
    trusted: &[String],
    others: &dyn Fn(&str) -> payload::InArchive,
    links: &InstalledLinks,
    report: &mut Report,
) -> Result<(bool, PayloadSummary, payload::Fingerprint), Error> {
    let archive = payload::Archive::open(archive_path)?;
    // Taken first: everything read from here on is checked against it once
    // the AI review is over.
    let fingerprint = archive.fingerprint()?;
    let reviewed = payload::review(&archive, target, class, trusted)?;
    let archive_name = archive_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("package");

    let scriptlet = match reviewed.install {
        // One over the size limit was not read; `unfollowed` says so.
        None => archive.paths().any(|path| path == ".INSTALL"),
        // Unread, and still the archive's bytes: every check that refuses
        // a package has run by now.
        Some(Content::Undecodable | Content::Binary(_)) => {
            report.gaps.push(Gap::PackageUnread(format!(
                "the install scriptlet of {} holds binary data and cannot be reviewed",
                archive_path.display()
            )));
            true
        }
        Some(Content::Text(text) | Content::Lossy { text, .. }) => {
            let rel = format!("{target}/{archive_name}/.INSTALL");
            review_scriptlet(report, target, class, &rel, &text);
            true
        }
    };
    for reason in reviewed.unfollowed {
        report.gaps.push(Gap::PackageUnread(format!(
            "{}: {reason}",
            archive_path.display()
        )));
    }

    let mut summary = PayloadSummary {
        reviewed: 0,
        unchanged: 0,
        not_reviewed: Vec::new(),
    };
    let root = Path::new("/");
    let official = class == SourceClass::Official;
    let settled = settled(&reviewed.files, root, others);
    let mut as_itself: HashSet<String> = reviewed.read_as_auto_run;
    for mut file in reviewed.files {
        as_itself.insert(file.path.clone());
        if settled.contains(&file.path) {
            summary.unchanged += usize::from(!matches!(file.content, Content::Binary(_)));
            continue;
        }
        let rel = format!("{target}/{archive_name}/{}", file.path);
        if !follow_outside_link(&mut file, others, report) {
            continue;
        }
        report.file_classes.insert(rel.clone(), class);
        let named = !file.run_by.is_empty();
        queue_payload(
            report,
            &mut summary,
            rel,
            &file.path,
            file.content,
            (named, official),
        );
    }

    // What a link already on the system leads to is that link's file: a
    // sudoers drop-in another package linked to this one's `rule` says
    // what this package now puts there.
    let mut led: Vec<(&str, &String)> = archive
        .paths()
        .filter(|path| !as_itself.contains(*path))
        .filter_map(|path| {
            let link = links
                .get(path)?
                .iter()
                .find(|link| autorun::is_reviewed(link, official))?;
            Some((path, link))
        })
        .collect();
    // By path, not in the order the archive happens to list its entries.
    led.sort();
    for (path, link) in led {
        let rel = format!("{target}/{archive_name}/{path}");
        report.file_classes.insert(rel.clone(), class);
        review_led(&archive, (path, link), rel, official, &mut summary, report);
    }

    grant_findings(
        &archive,
        reviewed.root_set_id,
        target,
        archive_name,
        class,
        report,
    );
    for (path, effect) in reviewed.misplaced {
        // Already there: the package brings nothing new into that place.
        if fs::symlink_metadata(root.join(&path)).is_ok() {
            continue;
        }
        let rel = format!("{target}/{archive_name}/{path}");
        report.file_classes.insert(rel.clone(), class);
        report.findings.push(LocalFinding {
            path: rel,
            line: 1,
            rule: RuleId::PrivilegeEscalation,
            excerpt: format!(
                "/{path} {effect}, and its content is not reviewed: only a package from an official repository is expected to ship a file there"
            ),
        });
    }
    archive.verify_unchanged()?;
    Ok((scriptlet, summary, fingerprint))
}

/// The install scriptlet, named `rel` in the report, with the local rules
/// and queued for the AI.
fn review_scriptlet(report: &mut Report, target: &str, class: SourceClass, rel: &str, text: &str) {
    report.file_classes.insert(rel.to_string(), class);
    review::analyze_text(report, rel, text, false);
    own_removal_is_no_attack(report, target, rel, text);
}

/// The payload files an upgrade does not review again: what is installed
/// under `root` is what the package ships. A link that did not change
/// still leads somewhere new when this transaction replaces what it leads
/// to. A file the reviewed ones name is settled with them: when it did not
/// change either (a compiled program is never read) and every file that
/// names it is settled. The scriptlet never is: it runs anew.
fn settled(
    files: &[payload::PayloadFile],
    root: &Path,
    others: &dyn Fn(&str) -> payload::InArchive,
) -> HashSet<String> {
    let mut settled: HashSet<String> = files
        .iter()
        .filter(|file| {
            file.run_by.is_empty()
                && file.is_installed_unchanged(root)
                && !file
                    .leads_outside
                    .as_deref()
                    .is_some_and(|leads| replaced_by_transaction(leads, others))
        })
        .map(|file| file.path.clone())
        .collect();
    loop {
        let more: Vec<String> = files
            .iter()
            .filter(|file| {
                !file.run_by.is_empty()
                    && !settled.contains(&file.path)
                    && file.run_by.iter().all(|by| settled.contains(by))
                    && (matches!(file.content, Content::Binary(_))
                        || file.is_installed_unchanged(root))
            })
            .map(|file| file.path.clone())
            .collect();
        if more.is_empty() {
            return settled;
        }
        settled.extend(more);
    }
}

/// Reviews what `archive` puts at `path`, where `link` (a symbolic link in
/// an auto-run location of this system) leads, as that link's file; `rel`
/// names it in the report.
fn review_led(
    archive: &payload::Archive,
    (path, link): (&str, &str),
    rel: String,
    official: bool,
    summary: &mut PayloadSummary,
    report: &mut Report,
) {
    match archive.replacement(path) {
        None => {}
        // The file as it is installed now adds nothing.
        Some(payload::Replacement::File(bytes))
            if same_as_installed(Path::new("/"), path, &bytes) =>
        {
            summary.unchanged += 1;
        }
        Some(payload::Replacement::File(bytes)) => {
            let content = payload::annotated(
                content::classify_payload(link, &bytes),
                &format!(
                    "# /{path} is what /{link}, a symbolic link on this system, leads to, so it is read as that file. This package replaces it; its new content follows.\n"
                ),
            );
            queue_payload(report, summary, rel, path, content, (true, official));
        }
        Some(payload::Replacement::Binary(label)) => not_read(report, summary, rel, path, label),
        Some(payload::Replacement::TooLarge) => {
            report.gaps.push(Gap::PackageUnread(format!(
                "/{path}, which /{link} on this system links to, is text over the 2 MiB review limit: what the link will hold cannot be reviewed"
            )));
        }
        // A link out of the package, or an archive that could not be
        // read: nothing the archive's digest stands for.
        Some(payload::Replacement::Unreadable(reason)) => {
            report.gaps.push(Gap::Package(Error::Refused(format!(
                "/{path}, which /{link} on this system links to, {reason}: what the link will hold cannot be reviewed"
            ))));
        }
    }
}

/// Guardian's own removal turns its own units and hook off, which the
/// local rules read as switching a protection off. The name is Guardian's
/// only from a local archive or an official repository (`payload::review`
/// refused the rest), and the scriptlet (`text`) still goes to the AI
/// review. Only a line about nothing but Guardian's own is let off.
fn own_removal_is_no_attack(report: &mut Report, target: &str, rel: &str, text: &str) {
    if target != payload::GUARDIAN_PACKAGE {
        return;
    }
    let lines: Vec<&str> = text.lines().collect();
    let line = |number: usize| number.checked_sub(1).and_then(|index| lines.get(index));
    report.findings.retain(|finding| {
        let own = finding.path == rel
            && finding.rule == RuleId::ProtectionDisabled
            && line(finding.line).is_some_and(|written| {
                // A command continued over lines is not read here.
                let continued = |part: &&str| part.trim_end().ends_with('\\');
                !continued(written)
                    && !line(finding.line - 1).is_some_and(continued)
                    && only_guardians_own(written)
            });
        !own
    });
}

/// Whether `line`, which the rules read as switching a protection off,
/// is about Guardian's own units and files alone: it names Guardian, the
/// rule no longer matches once Guardian's names are taken out (so no other
/// service, `ufw disable`, firewall flush, `setenforce` or `ptrace_scope`
/// rides along, in a comment either), and every unit a `systemctl` on it
/// names is one of Guardian's.
fn only_guardians_own(line: &str) -> bool {
    let line = line.to_lowercase().replace('\t', " ");
    if !line.contains(payload::GUARDIAN_PACKAGE) {
        return false;
    }
    let rest: Vec<&str> = line
        .split(' ')
        .filter(|word| !word.contains(payload::GUARDIAN_PACKAGE))
        .collect();
    let rest = rest.join(" ");
    if rules::line_rules(&rest, &rest).any(|rule| rule == RuleId::ProtectionDisabled) {
        return false;
    }
    let mut words = line.split_whitespace();
    while let Some(word) = words.next() {
        if !word.ends_with("systemctl") {
            continue;
        }
        let mut verb = false;
        while let Some(word) = words.next() {
            if matches!(word, ";" | "&&" | "||" | "|" | "&") || word.starts_with('#') {
                break;
            }
            // A redirection, with its file when that is the next word.
            if word.contains(['>', '<']) {
                let file = if word.ends_with(['>', '<']) {
                    words.next().unwrap_or_default()
                } else {
                    word
                };
                if file.ends_with(';') {
                    break;
                }
                continue;
            }
            if word.starts_with('-') {
                continue;
            }
            if !verb {
                verb = true;
                continue;
            }
            let unit = word.trim_end_matches(';').trim_matches(['"', '\'']);
            if !unit.starts_with(payload::GUARDIAN_PACKAGE) {
                return false;
            }
            if word.ends_with(';') {
                break;
            }
        }
    }
    true
}

/// Hands one payload file to the review as what its content is. What
/// cannot be read is named as not reviewed where it is expected: a file
/// the reviewed ones only name (`named`: hooks and units run their
/// package's compiled programs, scriptlets mention its data), and an ELF
/// generator of a package from an official repository (`official`).
/// Elsewhere it makes the review incomplete, as something the archive's
/// digest still covers.
fn queue_payload(
    report: &mut Report,
    summary: &mut PayloadSummary,
    rel: String,
    path: &str,
    content: Content,
    (named, official): (bool, bool),
) {
    match content {
        Content::Text(text) | Content::Lossy { text, .. } => {
            if review::analyze_payload(report, &rel, &text) {
                summary.reviewed += 1;
            } else {
                summary.not_reviewed.push(format!("/{path} (AI off)"));
            }
        }
        Content::Binary(format) if named || (official && format.executable()) => {
            not_read(report, summary, rel, path, format.label());
        }
        // Unread, and the archive's own bytes: a block the user may
        // overrule for exactly this archive.
        Content::Binary(format) if format.executable() => {
            report.gaps.push(Gap::PackageUnread(format!(
                "/{path}: a compiled file ({}) in an auto-run location cannot be reviewed; only packages from an official repository are expected to ship one",
                format.label()
            )));
        }
        Content::Binary(_) | Content::Undecodable => {
            report.gaps.push(Gap::Undecodable(rel));
        }
    }
}

/// Names a file that cannot be read to the user and to the AI.
fn not_read(
    report: &mut Report,
    summary: &mut PayloadSummary,
    rel: String,
    path: &str,
    label: &'static str,
) {
    summary.not_reviewed.push(format!("/{path} ({label})"));
    report.hash_only.push(HashOnly {
        path: rel,
        bytes: 0,
        label,
        media: false,
        skipped_files: None,
    });
}

/// Whether the file at `path` under `root` holds exactly `bytes` now.
fn same_as_installed(root: &Path, path: &str, bytes: &[u8]) -> bool {
    let installed = root.join(path);
    fs::symlink_metadata(&installed)
        .is_ok_and(|metadata| metadata.is_file() && metadata.len() == bytes.len() as u64)
        && fs::read(&installed).is_ok_and(|now| now == bytes)
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
mod content_tests;

#[cfg(test)]
mod tests;
