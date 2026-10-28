//! Judging what the sweep collected: trusted items are only counted; the
//! rest go through the local rules and the AI review (`SourceClass::System`)
//! like any other source, with the review memory, so an unchanged system
//! costs no AI call on the next sweep.

pub(super) mod secrets;
mod variables;

use std::collections::HashSet;
use std::fmt::Write as _;

use super::collect::{self, Body, Collection, Item};
use super::nvim::{self, Review};
use super::tier::Tier;
use super::{boot, commands};
use crate::autorun::Category;
use crate::config::model::Profile;
use crate::engine::baseline::{Identity, Unit};
use crate::engine::plan::HashOnly;
use crate::git_state;
use crate::paths::file_name;
use crate::report::{Gap, LocalFinding, Report, ReviewScope};
use crate::review::{self, ReviewContext};
use crate::rules::RuleId;
use crate::text::shown;
use secrets::{has_boot_secret, without_secrets, without_url_passwords};
use variables::sets_only_variables;

#[cfg(test)]
use secrets::REDACTED;
#[cfg(test)]
use variables::sets_a_variable;

/// Root's home, relative to `/`, whose SSH and git files are local-only too.
const ROOT_HOME: &str = "root";

/// What the review memory remembers the sweep as.
const IDENTITY: &str = "system:sweep";

/// Whether an item is trusted and only counted.
pub(super) const fn is_trusted(tier: Tier) -> bool {
    matches!(
        tier,
        Tier::Vendor | Tier::Inert | Tier::Copied | Tier::Allowed
    )
}

/// How an item is named to the user and the AI: absolute, with the home
/// directory as `~`.
pub(super) fn label(item: &Item, home: Option<&str>) -> String {
    shown_path(&item.path, home)
}

/// `path` (relative to the root) as it is shown: absolute, with the home
/// directory as `~`.
fn shown_path(path: &str, home: Option<&str>) -> String {
    match home.and_then(|home| path.strip_prefix(&format!("{home}/"))) {
        Some(rest) => format!("~/{rest}"),
        None => format!("/{path}"),
    }
}

/// Runs the review of `collection`. `news` holds the labels of the
/// accounts, keys and trust anchors that were not there at the sweep
/// before: each is a finding.
pub(super) fn judge(
    collection: &Collection,
    home: Option<&str>,
    context: &ReviewContext<'_>,
    news: &HashSet<String>,
) -> Report {
    // The sweep lists what is on the system to look at, and a low remark
    // of the AI on an item is one such thing in every profile: it stays a
    // finding here, listed, counted, remembered and told as one.
    //
    // The AI may mark a finding as the owner's own setting (see
    // `Report::is_owner_setting`). The owner chose that this applies to
    // the sweep alone, and that the strict profile keeps every such
    // finding an alert.
    let strict = context.settings.profile_for(context.class) == Profile::Strict;
    let scope = ReviewScope {
        remark_classes: Vec::new(),
        setting_paths: if strict {
            HashSet::new()
        } else {
            setting_paths(collection, home)
        },
        ..review::scope(context.settings, context.class, &[context.class])
    };
    let mut report = Report::new("system sweep", scope);
    let facts = examine(&mut report, collection, home, news);
    let context = ReviewContext {
        context: &facts,
        ..*context
    };
    let units = Identity::parse(IDENTITY)
        .map(|identity| {
            vec![Unit {
                prefix: String::new(),
                identity,
            }]
        })
        .unwrap_or_default();
    review::review_collected(report, &context, &units)
}

/// The kinds of item whose AI findings may be the owner's own settings:
/// shell start-up files, programs in a directory of the home's `PATH` and
/// the entries AI coding agents start (an alias, a wrapper, a plugin's
/// hook). The owner chose these three. Every other kind stays an alert
/// whatever the reviewer says: autostart entries, user units, Hyprland's
/// `exec` lines, cron jobs, Omarchy hooks and the rest are where
/// persistence lives, and one claim graded medium must never turn such a
/// finding into a clear sweep.
///
/// An agent's hook runs on its own too, at every start or tool call, and
/// every entry of one configuration file is sent under that file's path.
/// The owner accepted that risk for the plugin hooks the settings came up
/// in; the other checks of `Report::is_owner_setting` still apply.
const SETTING_CATEGORIES: [Category; 3] = [Category::Shell, Category::LocalBin, Category::Agent];

/// The files, by the path the AI is sent them under, that may hold the
/// owner's own settings: in the home, and of an item of a kind in
/// `SETTING_CATEGORIES` that the catalogue found itself. A file reached by
/// following what another runs or sources is left out: it takes the kind
/// of whatever reached it first, so a payload anywhere in the home that a
/// start-up file runs would count as a start-up file. So is a program
/// under a name Guardian watches on `PATH` (`sudo`, `ssh`, `git`,
/// `omarchy-…`): a fake `sudo` in the home is how a password is taken, and
/// the reviewer's grade alone must not clear it. So is a file that an item
/// of any other kind also stands for. So, last, is a file that leads to a
/// binary only the reviewer's word flags (see `launchers_of_word_alone`).
fn setting_paths(collection: &Collection, home: Option<&str>) -> HashSet<String> {
    let launchers = launchers_of_word_alone(collection);
    let mut allowed = HashSet::new();
    let mut refused = HashSet::new();
    for item in &collection.items {
        let path = shown_path(checked_path(item), home);
        let watched =
            item.category == Category::LocalBin && super::path::is_watched(file_name(&item.path));
        if path.starts_with("~/")
            && item.run_by.is_none()
            && !watched
            && !launchers.contains(item.path.as_str())
            && SETTING_CATEGORIES.contains(&item.category)
        {
            allowed.insert(path);
        } else {
            refused.insert(path);
        }
    }
    allowed.retain(|path| !refused.contains(path));
    allowed
}

/// The paths of the items that lead to a binary for which
/// `flagged_by_word_alone` holds: every one that runs it, what runs those,
/// and so on to the items the catalogue found. They are item paths, as
/// `Collection::runners` holds them (an agent entry's keeps its
/// `#hooks/...` suffix), not the paths the AI is sent.
fn launchers_of_word_alone(collection: &Collection) -> HashSet<&str> {
    let mut launchers = HashSet::new();
    let mut next: Vec<&str> = collection
        .items
        .iter()
        .filter(|item| flagged_by_word_alone(item))
        .map(|item| item.path.as_str())
        .collect();
    while let Some(path) = next.pop() {
        for runner in collection.runners.get(path).into_iter().flatten() {
            // A path already in `launchers` was walked from there, by this
            // binary (a cycle) or another.
            if launchers.insert(runner.as_str()) {
                next.push(runner);
            }
        }
    }
    launchers
}

/// Whether `item` is a binary Guardian could not vouch for that no local
/// rule raises an alert on: one an AUR or `pacman -U` package installed
/// (`hashed` flags those no package installed, or a version manager did,
/// and a changed package file has its own rule). The reviewer's finding on
/// what launches it is then the only alert, so no launcher up to the
/// catalogued item may be shown as the owner's setting: the claim would
/// leave the binary with none.
fn flagged_by_word_alone(item: &Item) -> bool {
    matches!(item.body, Body::Binary(_))
        && item.tier == Tier::UserBuilt
        && !is_version_managed(item)
}

/// Puts what the local checks say of `collection` into `report`, queues
/// for the AI review the text that goes to it, and returns what Guardian
/// established about each such item and each binary it lists by its hash
/// (see `fact`).
fn examine(
    report: &mut Report,
    collection: &Collection,
    home: Option<&str>,
    news: &HashSet<String>,
) -> Vec<String> {
    let mut facts = Vec::new();
    // What Guardian established about each binary listed by its hash, and
    // whether nothing runs it; `MAX_BINARY_FACTS` of them are told.
    let mut binaries = Vec::new();
    for item in collection.items.iter().filter(|item| !item.is_trusted()) {
        let label = label(item, home);
        if item.tier == Tier::Modified {
            report
                .findings
                .push(finding(&label, 1, RuleId::ModifiedPackageFile, ""));
        }
        for (rule, seen) in &item.alerts {
            let (line, seen) = located(seen);
            report.findings.push(finding(&label, line, *rule, seen));
        }
        if news.contains(&label) {
            report.findings.push(finding(
                &label,
                1,
                RuleId::NewTrust,
                item.notes.first().map_or("", String::as_str),
            ));
        }
        // Where a limit cut short what an item runs, the review of its
        // text is all that is left; without one, something went unchecked.
        let reading = match &item.body {
            Body::Text(text) => Some(reading(item, home, text)),
            _ => None,
        };
        if reading != Some(Reading::Reviewed) {
            report.gaps.extend(
                item.notes
                    .iter()
                    .filter_map(|note| note.strip_prefix(collect::NOT_ALL_FOLLOWED))
                    .map(|limit| Gap::Sweep(format!("{label}: not followed past {limit}"))),
            );
        }
        match &item.body {
            Body::Text(text) if reading == Some(Reading::Settings) => {
                report.text_files_reviewed += 1;
                local_checks(report, item, &label, text);
            }
            Body::Text(text) => {
                let before = (report.findings.len(), report.agent_input.len());
                // Read, and where it is sent to the AI sent, without the
                // values that look like secrets. What a path says of the
                // file is asked of the file's own path, not of the name
                // the item is listed under.
                let written = text;
                let text = without_secrets(text);
                let file = shown_path(checked_path(item), home);
                if reading == Some(Reading::Reviewed) {
                    review::analyze_text(report, &file, &text, false);
                    facts.push(fact(item, &label, home));
                } else {
                    review::analyze_text_locally(report, &file, &text);
                }
                // Whoever writes a file picks its path: code that a secret
                // path keeps from the AI must not pass unseen for that.
                if reading == Some(Reading::Secrets)
                    && is_run(item, written)
                    && !sets_only_variables(written)
                {
                    report
                        .findings
                        .push(finding(&label, 1, RuleId::KeptFromReview, ""));
                }
                if file != label {
                    for finding in &mut report.findings[before.0..] {
                        if finding.path == file {
                            finding.path.clone_from(&label);
                        }
                    }
                    for sent in &mut report.agent_input[before.1..] {
                        if sent.path == file {
                            sent.path.clone_from(&label);
                        }
                    }
                }
                // Every item is persistence already; naming another start-up
                // file (`.bash_profile` sourcing `.bashrc`) is not news.
                drop_rule(report, before.0, RuleId::PersistenceModification);
            }
            Body::Binary(format) => {
                let fact = hashed(report, item, label, format, home);
                binaries.push((item.run_by.is_none(), fact));
            }
            Body::Undecodable => report.gaps.push(Gap::Undecodable(label)),
            Body::Oversized => report.gaps.push(Gap::OversizedText(label)),
            Body::Unreadable(_) => report.gaps.push(Gap::RootOnly(label)),
            // A link is judged by its target, which is its own item.
            Body::Link(_) => {}
            Body::Plugin(plugin) => facts.extend(plugin_files(report, plugin, &label)),
        }
    }
    // A binary something runs first: its fact is what the reviewer judges
    // the file that launches it by. The sort is stable, so the rest keep
    // the collection's order.
    binaries.sort_by_key(|(unrun, _)| *unrun);
    let more = binaries.len().saturating_sub(MAX_BINARY_FACTS);
    facts.extend(
        binaries
            .into_iter()
            .take(MAX_BINARY_FACTS)
            .map(|(_, fact)| fact),
    );
    if more > 0 {
        facts.push(format!(
            "Guardian hashed {more} binaries it does not describe here."
        ));
    }
    facts
}

/// Lists `item`, a binary of `format` shown as `label`, by its hash, flags
/// it where no package installed it and something runs it, and returns
/// what Guardian established about it.
///
/// The reviewer is told what Guardian knows of a program it was not sent,
/// so a file that launches one is judged by that, not taken as a reason to
/// call its whole chunk inconclusive (see `SYSTEM_SCOPE`). One no package
/// installed is also flagged here, so it is never passed on the model's
/// word alone; the finding is on the binary, so `sweep allow` binds it to
/// the binary's hash and a replaced binary is flagged again.
fn hashed(
    report: &mut Report,
    item: &Item,
    label: String,
    format: &'static str,
    home: Option<&str>,
) -> String {
    // One without a hash is never recorded as approved, so every sweep
    // that finds it is reviewed in full.
    report.unread.insert(label.clone(), item.sha256);
    let unpackaged = item.tier == Tier::Unknown || is_version_managed(item);
    if unpackaged && let Some(by) = &item.run_by {
        let by = format!("run by {}", shown_path(by, home));
        report
            .findings
            .push(finding(&label, 1, RuleId::UnpackagedBinary, &by));
    }
    let fact = hashed_fact(item, &label, format, home);
    report.hash_only.push(HashOnly {
        path: label,
        bytes: 0,
        label: format,
        media: false,
        skipped_files: None,
    });
    fact
}

/// Puts the files of `plugin`, listed as `label`, that this sweep reviews
/// (see `nvim`) through the local rules and the AI review, as the text of
/// any other item; returns what Guardian established about the plugin
/// where any of it is reviewed.
fn plugin_files(report: &mut Report, plugin: &nvim::Plugin, label: &str) -> Option<String> {
    let (sent, news) = match &plugin.review {
        Review::New(sent) => (sent, nvim::News::New),
        Review::Changed(sent) => (sent, nvim::News::Changed),
        Review::Baseline | Review::Unchanged => return None,
        Review::Unplanned => {
            report.gaps.push(Gap::Sweep(format!(
                "{label}: not compared with what the last sweep saw of it"
            )));
            return None;
        }
        Review::TooLarge { files } => {
            report.gaps.push(Gap::Sweep(format!(
                "{label}: {files} new or changed code files are more than one plugin's review takes; read them yourself, then `sweep allow` it"
            )));
            return None;
        }
    };
    for file in sent {
        let shown = format!("{label}/{}", file.path);
        match &file.body {
            // Whoever writes a plugin picks its file names: code a secret
            // name keeps from the AI must not pass unseen for that.
            Body::Text(text) if crate::rules::is_sensitive_path(&shown) => {
                review::analyze_text_locally(report, &shown, &without_url_passwords(text));
                report
                    .findings
                    .push(finding(&shown, 1, RuleId::KeptFromReview, ""));
            }
            // Plugin code is not configuration: blanking what looks like a
            // secret assignment would let a plugin hide code from the AI
            // behind a name like TOKEN. Only URL passwords are masked.
            Body::Text(text) => {
                review::analyze_text(report, &shown, &without_url_passwords(text), false);
            }
            Body::Oversized => report.gaps.push(Gap::OversizedText(shown)),
            Body::Undecodable => report.gaps.push(Gap::Undecodable(shown)),
            Body::Unreadable(reason) => report
                .gaps
                .push(Gap::Sweep(format!("{shown}: could not be read ({reason})"))),
            Body::Binary(_) => report.gaps.push(Gap::RunsUnread(format!(
                "{shown}: new or changed, and Neovim runs it without the review reading it; check it, then `sweep allow` the plugin"
            ))),
            Body::Link(_) | Body::Plugin(_) => report.gaps.push(Gap::RunsUnread(shown)),
        }
    }
    Some(nvim::fact(plugin, label, news))
}

/// Developer tool configuration that holds no tokens as a rule, and whose
/// hooks and commands are worth a review: the rest of that category is
/// where registry tokens live.
const REVIEWED_TOOL_FILES: &[&str] = &[
    "/mise/config.toml",
    "/.mise.toml",
    "/.cargo/config.toml",
    "/.cargo/config",
];

/// Files whose content may hold secrets (keys, tokens in URLs) are checked
/// here and never sent to the AI: SSH files and git configuration in the
/// home directory, package-manager configuration (`~/.npmrc`, pip, gem,
/// yarn, bun and Go keep registry tokens there), an editor's settings and
/// fish's saved variables. Accounts, keys, trust anchors, `/etc/hosts` and
/// malicious language packages are facts the local checks cover; there is
/// nothing in them to review.
///
/// A program one of these files runs is no such file: it is reviewed like
/// any other, by the local rules and the AI. For the SSH and git files
/// that means: the catalogued file, what it is a link to and what an
/// `Include` reads in are configuration and stay here (the collector
/// marks the latter two, see `collect::configuration_of`); a script a
/// `ProxyCommand` or git's `sshCommand` names is a program, whichever
/// category it was found through. The same holds for every kind of file
/// kept here: what a catalogued link leads to (`~/.npmrc` kept in a
/// dotfiles directory) is that file under another name and stays here,
/// and what it runs is a program.
fn is_local_only(item: &Item, home: Option<&str>) -> bool {
    // The catalogued file itself, or what stands for it: where its link
    // leads, or what it reads in as more of itself.
    let of = collect::configuration_of(item);
    let named = item.run_by.is_none() || of.is_some();
    // A home's file wherever it is kept: a `~/.gitconfig` that is a link
    // to a file on another mount is that home's configuration still.
    let in_home = [Some(item.path.as_str()), of]
        .into_iter()
        .flatten()
        .any(|path| {
            home.into_iter()
                .chain([ROOT_HOME])
                .any(|home| path.starts_with(&format!("{home}/")))
        });
    let path = collect::stands_for(item);
    let name = file_name(path);
    match item.category {
        // The login script is code, not configuration: it is reviewed.
        Category::Ssh if commands::is_ssh_rc(path) => false,
        Category::Ssh | Category::Git => in_home && named,
        // What an extension was granted is checked by the collector's
        // rules (see `extensions`); its code and the profile it came from
        // hold personal data and are never sent.
        Category::Account | Category::BrowserExtension | Category::Package => true,
        // Kernel images and EFI programs are compared with the packaged ones
        // (see `boot`), and one whose bytes read as text is still one of
        // them: nothing in `/boot` goes to the AI but the boot configuration
        // the catalogue collects (the boot loaders' files, `startup.nsh`,
        // `refind.conf`). That stays reviewed on purpose: the local command
        // line check takes whatever it says as configured, so a parameter
        // planted in `limine.conf` (`init=`, `rd.shell`), or an entry that
        // starts another program, is seen only by the review. The secret it
        // can hold is a boot password: a GRUB hash on its exact line is
        // taken out before it is sent (`without_secrets`), and a file with
        // any boot secret that rule cannot mask is not sent at all (see
        // `reading`).
        Category::Boot => path.starts_with("boot/") && !boot::is_configuration(path),
        Category::Trust => named,
        Category::Toolchain => {
            named
                && !REVIEWED_TOOL_FILES
                    .iter()
                    .any(|reviewed| path.ends_with(reviewed))
        }
        Category::Editor => named && name == "settings.json",
        Category::Shell => named && name == "fish_variables",
        _ => false,
    }
}

/// How the text of an item is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reading {
    /// By the local rules and the AI review.
    Reviewed,
    /// Settings that hold tokens, hosts and names: by the rules for that
    /// kind of file, here (see `is_local_only`).
    Settings,
    /// A file whose path marks it as holding secrets, or boot configuration
    /// with a secret the exact hash rule cannot mask: by the local rules,
    /// here. Nothing lifts this: not that something runs the file, not its
    /// first line. What it starts is followed all the same.
    Secrets,
    /// A file a live check named that nothing says is a script: by the
    /// local rules, here. The check goes by a process's arguments, and an
    /// argument may as well be a data file.
    Unsure,
}

impl Reading {
    /// What the item says of being kept from the AI.
    const fn note(self) -> Option<&'static str> {
        match self {
            Self::Reviewed => None,
            Self::Settings => Some(
                "checked locally only and kept from the AI: settings that may hold tokens, hosts or names",
            ),
            Self::Secrets => Some(
                "checked by the local rules only and kept from the AI: it holds secrets (by its path or a boot password)",
            ),
            Self::Unsure => Some(
                "checked by the local rules only and kept from the AI: nothing says it is a script",
            ),
        }
    }
}

/// Whether `item` is an entry of an AI coding agent's configuration,
/// named by its file and its key in it (see `sweep::agents`).
fn is_agent_entry(item: &Item) -> bool {
    item.category == Category::Agent && item.path.contains('#')
}

/// The path the local checks are told an item's text has: its file's own,
/// and for an agent's entry the configuration file it is in. The key after
/// `#` is the configuration's choice, so a server named `notes.md` is not
/// taken for documentation the rules skip.
fn checked_path(item: &Item) -> &str {
    let file = collect::file_of(item);
    if is_agent_entry(item) {
        file.split_once('#').map_or(file, |(config, _)| config)
    } else {
        file
    }
}

/// How the text of `item` is read (see `Reading`). What a path says is
/// asked of the path the content was read from and of the name a link
/// gives it (`~/.ssh/rc` kept in a dotfiles directory is still a file of
/// `~/.ssh`), never of the name the item is listed under, which may carry
/// what a live check saw (`…/.env:tcp-3001`).
fn reading(item: &Item, home: Option<&str>, text: &str) -> Reading {
    // An agent's entry holds only what it starts, its secrets taken out
    // already; its name ends in a key the configuration chose
    // (`…#mcpServers/token.md`), which says nothing of what it holds.
    if is_agent_entry(item) {
        return Reading::Reviewed;
    }
    if is_local_only(item, home) {
        return Reading::Settings;
    }
    let is_boot =
        item.category == Category::Boot || boot::is_configuration(collect::stands_for(item));
    if is_boot && has_boot_secret(text) {
        return Reading::Secrets;
    }
    let file = collect::file_of(item);
    if [file, collect::stands_for(item)]
        .iter()
        .any(|path| crate::rules::is_sensitive_path(path))
    {
        return Reading::Secrets;
    }
    if item.category.is_live() {
        // Without the path the content was read from (results of an older
        // collector), a name that carries what a check saw says nothing of
        // the file: it is not taken for a script's.
        let decorated = item.file.is_none() && item.path.contains(':');
        if decorated || !is_script(file, text) {
            return Reading::Unsure;
        }
    }
    Reading::Reviewed
}

/// Whether `text` is credibly a script by its first line or by the name of
/// the file at `file`.
fn is_script(file: &str, text: &str) -> bool {
    let name = file_name(file);
    text.trim_start_matches('\u{feff}').starts_with("#!")
        || crate::sweep::programs::SCRIPT_EXTENSIONS
            .iter()
            .any(|extension| crate::sweep::read::has_extension(name, extension))
}

/// Whether something runs `item`, a file with content `text`: it is a file
/// of an auto-run location or what a link there leads to, a command names
/// it or a start-up file reads it in, it is the SSH server's login script,
/// or a live check found it running as a script. Not what was only read in
/// as more configuration, not what a unit only reads as a list of
/// variables (`EnvironmentFile=`), and not a file a live check named that
/// is no script: a process's argument may as well be a key or an `.env` it
/// reads.
fn is_run(item: &Item, text: &str) -> bool {
    let stands_for = collect::stands_for(item);
    if commands::is_ssh_rc(stands_for) {
        return true;
    }
    if item.category.is_live() {
        return is_script(collect::file_of(item), text);
    }
    // What a link in an auto-run location leads to is run exactly as a
    // file at the link's own place would be.
    if stands_for != item.path {
        return true;
    }
    collect::configuration_of(item).is_none() && !collect::is_environment_file(item)
}

/// Says on each item that is kept from the AI that it is, and why.
pub(super) fn note_kept(items: &mut [Item], home: Option<&str>) {
    // An account, a key, a certificate authority, an extension or a
    // package OSV named is a fact with no text to send: nothing to say of
    // those.
    let fact = |item: &Item| {
        matches!(
            item.category,
            Category::Account | Category::Trust | Category::BrowserExtension | Category::Package
        )
    };
    for item in items
        .iter_mut()
        .filter(|item| !item.is_trusted() && !fact(item))
    {
        let Body::Text(text) = &item.body else {
            continue;
        };
        if let Some(note) = reading(item, home, text).note()
            && !item.notes.iter().any(|existing| existing == note)
        {
            item.notes.push(note.to_string());
        }
    }
}

fn drop_rule(report: &mut Report, from: usize, rule: RuleId) {
    let mut index = 0;
    report.findings.retain(|finding| {
        let keep = index < from || finding.rule != rule;
        index += 1;
        keep
    });
}

/// Directories nothing lasting runs from.
const TEMPORARY: &[&str] = &[
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/user/",
    "/run/media/",
    "/.cache/",
];

fn local_checks(report: &mut Report, item: &Item, label: &str, text: &str) {
    if item.category == Category::Git {
        // Credential helpers are expected in the user's own configuration
        // (`!gh auth git-credential` too, wherever `gh` was installed),
        // unless one is a shell line of its own or runs a program from a
        // temporary or cache directory; keys that run on every git command
        // are not.
        for (line, excerpt) in git_state::executing_keys(text) {
            let helper = excerpt.starts_with("credential.");
            let odd = excerpt.split_once(" = ").is_some_and(|(_, value)| {
                let value = value.trim_matches('"');
                value.contains(['|', ';', '&', '$', '`', '>', '<'])
                    || TEMPORARY.iter().any(|temporary| value.contains(temporary))
            });
            if !helper || odd {
                report
                    .findings
                    .push(finding(label, line, RuleId::GitConfigCommand, &excerpt));
            }
        }
        return;
    }
    // The other files kept here are covered by the alerts raised when
    // they were collected (`config::alerts`).
    if item.category != Category::Ssh {
        return;
    }
    // A linked file is the file its link stands for: `~/.ssh/rc` kept in
    // a dotfiles directory is still what the server runs at login.
    let name = file_name(collect::stands_for(item));
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        // Key material is never shown: only the keyword.
        let excerpt = if name.starts_with("authorized_keys") {
            key_options(line)
                .filter(|options| {
                    let options = options.to_ascii_lowercase();
                    options.contains("command=") || options.contains("environment=")
                })
                .map(|_| "command= or environment= option".to_string())
        } else {
            // An included file is followed and checked as its own item;
            // one in a temporary directory is said here too.
            commands::ssh(line)
                .filter(|(key, value)| {
                    key != "include" || TEMPORARY.iter().any(|temporary| value.contains(temporary))
                })
                .map(|(key, _)| key)
        };
        if let Some(excerpt) = excerpt {
            report
                .findings
                .push(finding(label, index + 1, RuleId::SshCommand, &excerpt));
        }
    }
}

/// The options of an `authorized_keys` line: everything before the key
/// type, where a quoted option value may hold blanks (`from="a b"`).
fn key_options(line: &str) -> Option<&str> {
    let mut quoted = false;
    let mut start = 0;
    for (index, character) in line.char_indices() {
        match character {
            '"' => quoted = !quoted,
            ' ' | '\t' if !quoted => {
                if is_key_type(&line[start..index]) {
                    return (start > 0).then(|| &line[..start]);
                }
                start = index + 1;
            }
            _ => {}
        }
    }
    // No key type found after options: the whole line is odd; show it.
    (!is_key_type(&line[start..]) && !line.is_empty()).then_some(line)
}

fn is_key_type(word: &str) -> bool {
    word.starts_with("ssh-") || word.starts_with("ecdsa-") || word.starts_with("sk-")
}

/// The line an alert names (`line 4: …`, as `config::alerts` writes it)
/// and what was seen there, so the finding points at the line and not at
/// the top of the file; line 1 for an alert about the file as a whole.
fn located(seen: &str) -> (usize, &str) {
    seen.strip_prefix("line ")
        .and_then(|rest| rest.split_once(": "))
        .and_then(|(line, seen)| Some((line.parse().ok()?, seen)))
        .unwrap_or((1, seen))
}

fn finding(path: &str, line: usize, rule: RuleId, excerpt: &str) -> LocalFinding {
    LocalFinding {
        path: path.to_string(),
        line,
        rule,
        severity: rule.severity(),
        excerpt: excerpt.to_string(),
    }
}

/// Whether `item` was put in the home by a version manager (mise), not by a
/// package: the note `path` gives such an item.
fn is_version_managed(item: &Item) -> bool {
    item.tier == Tier::UserBuilt
        && item
            .notes
            .iter()
            .any(|note| note.contains("version manager"))
}

/// What Guardian established about an item, for the AI. The paths are
/// quoted, so a crafted name cannot pose as Guardian's words, and written
/// as the files sent are (`~/` for the home), so the model can tell which
/// sent file runs it.
fn fact(item: &Item, label: &str, home: Option<&str>) -> String {
    let what = match item.tier {
        Tier::Edited => {
            "a package's configuration file, edited after install (normal for configuration)"
        }
        Tier::UserBuilt if is_version_managed(item) => {
            "installed by a version manager in the home directory, not by a package"
        }
        Tier::UserBuilt => {
            "installed by a package from no configured repository (AUR or a local package), or from a package file nothing checked"
        }
        Tier::Modified => {
            "installed by a package but changed since (it is not what the package shipped)"
        }
        Tier::Unknown => "installed by no package",
        // These three reach here only with an alert on the item, and an
        // allowed item never does (see `Item::is_trusted`): the fact says
        // what installed it, and the alert is a finding of its own.
        Tier::Vendor => "installed unchanged by a package from a configured repository",
        Tier::Copied => "an unchanged copy of a file a repository package ships",
        Tier::Inert => "an empty file or a link to /dev/null",
        Tier::Allowed => "allowed by the user as it is",
    };
    let mut text = format!(
        "{:?} is {what}; it {}.",
        shown(label).as_ref(),
        item.category.when()
    );
    if let Some(by) = &item.run_by {
        let _ = write!(
            text,
            " It is run by {:?}.",
            shown(&shown_path(by, home)).as_ref()
        );
    }
    if item
        .notes
        .iter()
        .any(|note| note.starts_with("a path Omarchy"))
    {
        text.push_str(
            " Omarchy's installer writes a file at this path; its content is not verified.",
        );
    }
    if let Some(command) = item
        .notes
        .iter()
        .find_map(|note| note.strip_prefix("shadows "))
    {
        let _ = write!(
            text,
            " It shadows {:?}, so typing that command runs this instead.",
            shown(command).as_ref()
        );
    }
    text
}

/// What Guardian established about `item`, a binary of `format` listed as
/// `label`, for the AI, which is sent its hash and never its content.
fn hashed_fact(item: &Item, label: &str, format: &str, home: Option<&str>) -> String {
    format!(
        "{} Guardian hashed it ({format}) and did not send its content.",
        fact(item, label, home)
    )
}

/// The most binaries described by a fact: as many hash-only rows as a
/// request's manifest names (`MAX_HASH_ONLY_ROWS` in `engine::plan`), as
/// facts go to every chunk and are not charged to its size.
const MAX_BINARY_FACTS: usize = 64;

#[cfg(test)]
mod tests;
