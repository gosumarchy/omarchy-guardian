//! What the sweep keeps of the plugins between runs: each plugin's code
//! files and their hashes, in `nvim-plugins.json` in the sweep's directory,
//! so a later sweep sends only the files that are new or changed.
//!
//! The sweep's own record (`state`) holds one content hash per item: it
//! says that a plugin changed, not which of its files. The review memory
//! holds the files the AI approved, and the plugins taken on trust never
//! went to the AI. Hence this record.
//!
//! An entry moves on to what a plugin is now when that was taken on trust
//! (the first sweep), allowed by the user, or reviewed without a finding
//! and with every review of its files finished. Otherwise it stays, and
//! the same files are sent again next time (the review memory and the
//! verdict cache make an unchanged repeat cheap).
//!
//! The record is the user's file, as the sweep's own record is: a program
//! running as the user can rewrite it. One that is gone while the last
//! sweep listed plugins, or that cannot be read, is a gap of that sweep,
//! which then takes the plugins as they are and says so.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use super::{Plugin, Review, Sent};
use crate::agent::Status;
use crate::error::Error;
use crate::json::Json;
use crate::report::{AgentOutcome, Gap, Report};
use crate::sha256::Digest;
use crate::sweep::collect::{self, Body, Item};
use crate::sweep::read::{self, Found};
use crate::sweep::state;

const RECORD: &str = "nvim-plugins.json";

/// The largest record read. A `LazyVim` install records some 3,500 files in
/// about 0.5 MiB; this leaves room for 30 times as many.
const MAX_RECORD_BYTES: u64 = 16 * 1024 * 1024;

/// The most code files of one plugin sent in one sweep, and their most
/// bytes. Arbitrary, above the largest plugins of a `LazyVim` install
/// (nvim-lspconfig: some 850 files, 1.9 MiB of Lua).
const MAX_REVIEW_FILES: usize = 1_500;
const MAX_REVIEW_BYTES: u64 = 4 * 1024 * 1024;

/// What is said of a plugin taken as it is on the first sweep that sees
/// plugins.
const FIRST_SIGHT: &str = "taken as it is, unreviewed: the first sweep that saw Neovim plugins; its code is reviewed once it changes";

/// What is said of a plugin taken as it is because the record was lost.
const RECORD_LOST: &str = "taken as it is, unreviewed: the record of what earlier sweeps saw of the plugins was lost; its code is reviewed once it changes";

/// Plugin name to its code files (relative to the plugin) and their
/// hashes.
pub(crate) type Files = BTreeMap<String, BTreeMap<String, Digest>>;

/// The record as this sweep found it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Record {
    /// What the last sweep recorded; empty before any sweep saw plugins.
    Kept(Files),
    /// It cannot stand for the last sweep, for this reason.
    Lost(String),
}

impl Record {
    /// The record in the sweep's `directory`; lost where there is none to
    /// keep one in.
    pub(crate) fn load(directory: Option<&Path>) -> Self {
        let Some(directory) = directory else {
            return Self::Lost("nothing is remembered between sweeps".into());
        };
        if fs::symlink_metadata(directory.join(RECORD)).is_err() {
            return Self::Kept(Files::new());
        }
        match read::look(directory, RECORD) {
            Found::File { size, head, .. } if size <= MAX_RECORD_BYTES => {
                match std::str::from_utf8(&head).ok().and_then(parse) {
                    Some(files) => Self::Kept(files),
                    None => Self::Lost(format!("{RECORD} is not one this sweep writes")),
                }
            }
            Found::File { .. } => Self::Lost(format!("{RECORD} is larger than it can be")),
            Found::Link(_) | Found::Other => Self::Lost(format!("{RECORD} is not a plain file")),
            Found::Unreadable(reason) => Self::Lost(format!("{RECORD}: {reason}")),
        }
    }

    /// Writes `files` as the record in the sweep's `directory`.
    pub(crate) fn save(directory: &Path, files: &Files) -> Result<(), Error> {
        let json = Json::object(files.iter().map(|(name, code)| {
            let code = code
                .iter()
                .map(|(path, digest)| (path.as_str(), Json::from(digest.to_string())));
            (name.as_str(), Json::object(code))
        }));
        state::write_text_mode(&directory.join(RECORD), &json.to_string(), 0o600)
    }
}

/// `{ "<plugin>": { "<path>": "<sha256>" } }`; `None` for anything else.
fn parse(text: &str) -> Option<Files> {
    let json = Json::parse(text).ok()?;
    json.as_object()?
        .iter()
        .map(|(name, code)| {
            let code = code
                .as_object()?
                .iter()
                .map(|(path, digest)| Some((path.clone(), Digest::from_hex(digest.as_str()?)?)))
                .collect::<Option<_>>()?;
            Some((name.clone(), code))
        })
        .collect()
}

/// Decides for each plugin among `items` that is not trusted what this
/// sweep sends of it to the review (see `Review`), against `record`, and
/// reads those files again under `root`. `listed` says whether the last
/// sweep listed an item: a record that is empty while it listed plugins
/// is gone, not new.
///
/// Returns what to report as not checked where the record could not stand
/// for the last sweep and plugins were taken as they are.
pub(crate) fn plan(
    items: &mut [Item],
    record: &Record,
    root: &Path,
    listed: &dyn Fn(&Item) -> bool,
) -> Option<String> {
    let plugins = || items.iter().filter(|item| is_plugin(item));
    let recorded = match record {
        Record::Kept(files) if files.is_empty() && plugins().any(listed) => Err(format!(
            "{RECORD} is gone, though the last sweep listed Neovim plugins"
        )),
        Record::Kept(files) => Ok(files),
        Record::Lost(reason) => Err(reason.clone()),
    };
    let mut taken = false;
    for item in items.iter_mut().filter(|item| !item.is_trusted()) {
        let path = item.path.clone();
        let Body::Plugin(plugin) = &mut item.body else {
            continue;
        };
        plugin.review = match &recorded {
            Ok(files) if !files.is_empty() => changes(root, &path, plugin, files.get(&plugin.name)),
            Ok(_) => {
                item.notes.push(FIRST_SIGHT.into());
                Review::Baseline
            }
            Err(_) => {
                taken = true;
                item.notes.push(RECORD_LOST.into());
                Review::Baseline
            }
        };
    }
    match recorded {
        Err(reason) if taken => Some(format!(
            "the record of Neovim plugins does not stand for the last sweep ({reason}): every plugin was taken as it is now, without a review"
        )),
        Ok(_) | Err(_) => None,
    }
}

fn is_plugin(item: &Item) -> bool {
    matches!(item.body, Body::Plugin(_))
}

/// What of `plugin`, at `path` under `root`, is new or changed since
/// `recorded`, its entry in the record (none for a new plugin).
fn changes(
    root: &Path,
    path: &str,
    plugin: &Plugin,
    recorded: Option<&BTreeMap<String, Digest>>,
) -> Review {
    let changed: Vec<&String> = plugin
        .code
        .iter()
        .filter(|(file, digest)| recorded.and_then(|recorded| recorded.get(*file)) != Some(digest))
        .map(|(file, _)| file)
        .collect();
    if changed.is_empty() {
        return Review::Unchanged;
    }
    let too_large = Review::TooLarge {
        files: changed.len(),
    };
    if changed.len() > MAX_REVIEW_FILES {
        return too_large;
    }
    let mut bytes = 0;
    let mut sent = Vec::new();
    for file in changed {
        let (sha256, body) = match read::look(root, &format!("{path}/{file}")) {
            Found::File {
                sha256, size, head, ..
            } => {
                bytes += size;
                (Some(sha256), collect::body_of(file, size, &head))
            }
            Found::Link(_) | Found::Other => (None, Body::Unreadable("no longer a file".into())),
            Found::Unreadable(reason) => (None, Body::Unreadable(reason)),
        };
        if bytes > MAX_REVIEW_BYTES {
            return too_large;
        }
        sent.push(Sent {
            path: file.clone(),
            sha256,
            body,
        });
    }
    match recorded {
        Some(_) => Review::Changed(sent),
        None => Review::New(sent),
    }
}

/// The record to keep after this sweep, whose report is `report`: each
/// plugin among `items` as it is now where its entry moves on (see the
/// module docs), as `record` had it otherwise. `label` names an item as
/// the report does.
pub(crate) fn settle(
    items: &[Item],
    record: &Record,
    report: &Report,
    label: &dyn Fn(&Item) -> String,
) -> Files {
    let before = |plugin: &Plugin| match record {
        Record::Kept(files) => files.get(&plugin.name).cloned(),
        Record::Lost(_) => None,
    };
    items
        .iter()
        .filter_map(|item| {
            let Body::Plugin(plugin) = &item.body else {
                return None;
            };
            let code = match &plugin.review {
                Review::Unplanned if item.is_trusted() => Some(plugin.code.clone()),
                Review::Baseline | Review::Unchanged => Some(plugin.code.clone()),
                Review::New(sent) | Review::Changed(sent)
                    if is_settled(report, &label(item), sent) =>
                {
                    Some(reviewed(plugin, sent))
                }
                Review::Unplanned
                | Review::New(_)
                | Review::Changed(_)
                | Review::TooLarge { .. } => before(plugin),
            };
            code.map(|code| (plugin.name.clone(), code))
        })
        .collect()
}

/// `plugin`'s code files as they were reviewed: what was read for the
/// review (`sent`) where that differs from what was hashed before.
fn reviewed(plugin: &Plugin, sent: &[Sent]) -> BTreeMap<String, Digest> {
    let mut code = plugin.code.clone();
    for file in sent {
        if let Some(digest) = file.sha256 {
            code.insert(file.path.clone(), digest);
        }
    }
    code
}

/// Whether the review of the files `sent` of the plugin listed as `label`
/// is done and clear: every one was read as text, no finding names one,
/// and every AI review that covered one finished clear. A file the review
/// memory already approved, or that policy keeps from the AI, is covered
/// by no run, which is no reason to send it again.
fn is_settled(report: &Report, label: &str, sent: &[Sent]) -> bool {
    let prefix = format!("{label}/");
    let ours = |path: &str| path.starts_with(&prefix);
    let read = sent
        .iter()
        .all(|file| file.sha256.is_some() && matches!(file.body, Body::Text(_)));
    let found = report.findings.iter().any(|finding| ours(&finding.path));
    let reviewed = report
        .agent_runs
        .iter()
        .filter(|run| run.files.iter().any(|file| ours(file)))
        .all(|run| {
            matches!(&run.outcome, AgentOutcome::Reviewed(review)
                if review.status == Status::Clear
                    && !review.findings.iter().any(|finding| ours(&finding.file)))
        });
    let unsent = report.gaps.iter().any(|gap| {
        matches!(
            gap,
            Gap::AgentInputTooLarge | Gap::EntryPointTooLarge(_) | Gap::Agent(_)
        )
    });
    read && !found && reviewed && !unsent
}
