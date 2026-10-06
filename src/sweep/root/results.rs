//! The root collector's results: written as JSON for the accounts they go
//! to, and read back, checked, by the sweep of one of them.

use std::fs;
use std::os::unix::fs::{self as unix_fs, MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::UNIX_EPOCH;

use super::{MAX_ITEMS, MAX_OUTPUT, RootPart, in_keeping_order};
use crate::autorun::Category;
use crate::error::{Error, IoContext};
use crate::files::{AtomicWrite, Owner, write_atomic};
use crate::json::Json;
use crate::rules::RuleId;
use crate::sha256::Digest;
use crate::sweep::collect::{self, Body, Collection, Item, Origin};
use crate::sweep::tier::Tier;

/// The version of the results. 2: the collector compares packaged programs
/// only root can read, reports what it could not check in the kernel's own
/// accounts, and keeps track of new accounts, members and keys itself.
const VERSION: u64 = 2;
/// The oldest version still read. Its results are kept, and count as those
/// of a collector that does not run every check (see `RootPart::outdated`).
const OLDEST_VERSION: u64 = 1;
/// The most of one note that is kept.
const MAX_NOTE_CHARS: usize = 400;
/// Older results are not used: the daily timer should have replaced them.
const MAX_AGE_SECS: u64 = 36 * 60 * 60;

/// Writes `json` to `path` (and its directory) owned by root and group
/// `gid`: the directory 0750, the file 0640, replaced atomically.
pub(super) fn write_results(path: &Path, json: &str, gid: u32) -> Result<(), Error> {
    let directory = path
        .parent()
        .ok_or_else(|| Error::Refused("no directory".into()))?;
    fs::create_dir_all(directory).at(directory)?;
    unix_fs::chown(directory, Some(0), Some(gid)).at(directory)?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o750)).at(directory)?;
    let options = AtomicWrite {
        owner: Some(Owner {
            uid: 0,
            gid,
            mode: 0o640,
        }),
        ..AtomicWrite::private(path.with_extension("json.tmp"))
    };
    write_atomic(path, json.as_bytes(), &options).at(path)
}

/// What the scheduled root collector found, if it is trustworthy and
/// recent: owned by root and writable by no one else, file and directory,
/// and at most `MAX_AGE_SECS` old.
pub(crate) fn from_results(path: &Path, now: u64) -> Result<RootPart, String> {
    if let Some(problem) = results_problem(path, now) {
        return Err(problem);
    }
    let text = fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    from_json(&text)
}

/// Why the results at `path` are not used, as far as that shows without
/// reading them (the bar asks this too).
pub(crate) fn results_problem(path: &Path, now: u64) -> Option<String> {
    let directory = path.parent()?;
    for checked in [directory, path] {
        let metadata = match fs::symlink_metadata(checked) {
            Ok(metadata) => metadata,
            Err(error) => return Some(format!("{}: {error}", checked.display())),
        };
        if metadata.file_type().is_symlink() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0
        {
            return Some(format!(
                "{} is not root's alone; ignoring it",
                checked.display()
            ));
        }
    }
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => return Some(error.to_string()),
    };
    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |elapsed| elapsed.as_secs());
    if now.saturating_sub(modified) > MAX_AGE_SECS {
        return Some("the daily root check has not run for more than 36 hours".into());
    }
    (metadata.len() > MAX_OUTPUT).then(|| "the root check's results are too large".into())
}

pub(super) fn to_json(collection: &Collection, notes: &[String], news: Option<&[String]>) -> Json {
    let untrusted = || in_keeping_order(&collection.items);
    let mut truncated = collection.truncated.clone();
    let left_out = untrusted().count().saturating_sub(MAX_ITEMS);
    if left_out > 0 {
        truncated.push(format!(
            "the root checks found more than {MAX_ITEMS} items: {left_out} were left out"
        ));
    }
    let mut members = vec![
        ("version", Json::from(VERSION)),
        (
            "items",
            Json::Array(untrusted().take(MAX_ITEMS).map(item_json).collect()),
        ),
    ];
    // Only where the collector kept track: without the list, the sweep
    // that reads this tells what is new from what it remembers itself.
    if let Some(news) = news {
        members.push((
            "new_trust",
            Json::Array(news.iter().map(|path| Json::from(path.as_str())).collect()),
        ));
    }
    members.extend([
        (
            "truncated",
            Json::Array(
                collect::bounded(truncated)
                    .into_iter()
                    .map(Json::from)
                    .collect(),
            ),
        ),
        (
            "notes",
            Json::Array(
                collect::bounded(notes.to_vec())
                    .into_iter()
                    .map(Json::from)
                    .collect(),
            ),
        ),
    ]);
    Json::object(members)
}

fn item_json(item: &Item) -> Json {
    let body = match &item.body {
        Body::Text(text) => Json::object([
            ("kind", Json::from("text")),
            ("text", Json::from(text.as_str())),
        ]),
        Body::Binary(format) => Json::object([
            ("kind", Json::from("binary")),
            ("format", Json::from(*format)),
        ]),
        Body::Undecodable => Json::object([("kind", Json::from("undecodable"))]),
        Body::Oversized => Json::object([("kind", Json::from("oversized"))]),
        Body::Link(target) => Json::object([
            ("kind", Json::from("link")),
            ("target", Json::from(target.as_str())),
        ]),
        Body::Unreadable(reason) => Json::object([
            ("kind", Json::from("unreadable")),
            ("reason", Json::from(reason.as_str())),
        ]),
    };
    let strings = |values: &[String]| {
        Json::Array(
            values
                .iter()
                .map(|value| Json::from(value.as_str()))
                .collect(),
        )
    };
    let mut members = vec![
        ("path", Json::from(item.path.as_str())),
        ("category", Json::from(item.category.name())),
        ("tier", Json::from(item.tier.name())),
        ("body", body),
        ("runs", strings(&item.runs)),
        ("notes", strings(&item.notes)),
        (
            "alerts",
            Json::Array(
                item.alerts
                    .iter()
                    .map(|(rule, seen)| {
                        Json::object([
                            ("rule", Json::from(rule.name())),
                            ("seen", Json::from(seen.as_str())),
                        ])
                    })
                    .collect(),
            ),
        ),
    ];
    if let Some(digest) = &item.sha256 {
        members.push(("sha256", Json::from(digest.to_string())));
    }
    if let Some(by) = &item.run_by {
        members.push(("run_by", Json::from(by.as_str())));
    }
    if let Some(file) = &item.file {
        members.push(("file", Json::from(file.as_str())));
    }
    Json::object(members)
}

/// An item from the root collector's JSON; `None` for anything malformed.
fn item_from_json(json: &Json) -> Option<Item> {
    let text = |key: &str| json.get(key).and_then(Json::as_str);
    let strings = |key: &str| -> Option<Vec<String>> {
        json.get(key)?
            .as_array()?
            .iter()
            .map(|value| value.as_str().map(str::to_string))
            .collect()
    };
    let path = text("path")?;
    // Paths are relative and plain: no `..`, no empty components.
    if path.starts_with('/') || path.split('/').any(|part| matches!(part, "" | "." | "..")) {
        return None;
    }
    let body_json = json.get("body")?;
    let body_text = |key: &str| {
        body_json
            .get(key)
            .and_then(Json::as_str)
            .map(str::to_string)
    };
    let body = match body_json.get("kind")?.as_str()? {
        "text" => Body::Text(body_text("text")?),
        // Binary formats are a short fixed list; a label from the JSON is
        // kept for the life of the run.
        "binary" => {
            let label = body_text("format")?;
            Body::Binary(if label == collect::WITHHELD {
                collect::WITHHELD
            } else {
                crate::content::Format::label_named(&label)
            })
        }
        "undecodable" => Body::Undecodable,
        "oversized" => Body::Oversized,
        "link" => Body::Link(body_text("target")?),
        "unreadable" => Body::Unreadable(body_text("reason")?),
        _ => return None,
    };
    Some(Item {
        // Relative and plain, like the path; one that is not is none.
        file: text("file")
            .filter(|file| {
                !file.starts_with('/')
                    && file.split('/').all(|part| !matches!(part, "" | "." | ".."))
            })
            .map(str::to_string),
        origin: Origin::Root,
        category: Category::from_name(text("category")?)?,
        path: path.to_string(),
        tier: Tier::from_name(text("tier")?)?,
        sha256: match text("sha256") {
            Some(hex) => Some(Digest::from_hex(hex)?),
            None => None,
        },
        body,
        runs: strings("runs")?,
        run_by: text("run_by").map(str::to_string),
        notes: strings("notes")?,
        // Results from before alerts existed have none.
        alerts: json
            .get("alerts")
            .and_then(Json::as_array)
            .unwrap_or_default()
            .iter()
            .map(|alert| {
                Some((
                    RuleId::from_name(alert.get("rule")?.as_str()?)?,
                    alert.get("seen")?.as_str()?.to_string(),
                ))
            })
            .collect::<Option<Vec<_>>>()?,
    })
}

pub(super) fn from_json(text: &str) -> Result<RootPart, String> {
    let json = Json::parse(text.trim()).map_err(|error| format!("unreadable output: {error}"))?;
    let version = json.get("version").and_then(Json::as_u64);
    if !version.is_some_and(|version| (OLDEST_VERSION..=VERSION).contains(&version)) {
        return Err("the root collector is a different version; reinstall Guardian".into());
    }
    let listed = json
        .get("items")
        .and_then(Json::as_array)
        .ok_or("no item list")?;
    let items: Vec<Item> = listed
        .iter()
        .take(MAX_ITEMS)
        // One odd item (a process with a strange `LD_PRELOAD`, say) must not
        // throw away everything else root found.
        .filter_map(item_from_json)
        .collect();
    // But it is said: what root found and this sweep could not read is
    // something that was not checked.
    let unread = listed.len() - items.len();
    let sentences = |key: &str| -> Vec<String> {
        json.get(key)
            .and_then(Json::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(|entry| entry.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut truncated = sentences("truncated");
    if unread > 0 {
        truncated.push(format!(
            "{unread} item(s) of the root checks could not be read and were left out"
        ));
    }
    Ok(RootPart {
        items,
        truncated,
        notes: collect::bounded(sentences("notes"))
            .into_iter()
            .map(|note| note.chars().take(MAX_NOTE_CHARS).collect())
            .collect(),
        outdated: version != Some(VERSION),
        news: json.get("new_trust").and_then(Json::as_array).map(|list| {
            list.iter()
                .filter_map(|path| path.as_str().map(str::to_string))
                .take(MAX_ITEMS)
                .collect()
        }),
    })
}
