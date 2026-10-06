//! One item: what is at a path, its tier and content, what it runs, and
//! the notes and alerts that go with it.

use std::fs;
use std::os::unix::fs::MetadataExt;

use super::sight::{hop, look_past_link};
use super::{
    Body, CLOSED, Item, NOT_ALL_FOLLOWED, Origin, Scope, WITHHELD, is_at_job, is_there, look,
    reader, runs_of,
};
use crate::autorun::Category;
use crate::content::{self, Content};
use crate::paths::file_name;
use crate::rules::RuleId;
use crate::scan::MAX_TEXT_FILE_SIZE;
use crate::sweep::read::{self, Found};
use crate::sweep::tier::{self, Observed, Tier, classify};
use crate::sweep::{commands, config, path};

/// What stands for the content of a packaged script whose interpreter line
/// alone was rewritten.
const PACKAGED_SCRIPT: &str = "packaged script (not read again)";

/// The tier of a packaged file the sweep could not read: modified when its
/// package installs it readable by everyone, since then somebody closed
/// it; unknown otherwise. Asked as the sweep's user only: root reads such
/// a file where it may look at all, and tells nothing of one it may not.
fn unread_tier(scope: &Scope<'_>, path: &str) -> Tier {
    if scope.origin == Origin::Root {
        return Tier::Unknown;
    }
    let closed = fs::symlink_metadata(scope.root.join(path)).is_ok_and(|metadata| {
        metadata.is_file() && tier::is_closed(path, metadata.mode(), scope.index)
    });
    if closed {
        Tier::Modified
    } else {
        Tier::Unknown
    }
}

/// One item: what is at `path`, its tier and content, and what it runs.
pub fn item(scope: &Scope<'_>, category: Category, path: String, run_by: Option<&str>) -> Item {
    let found = look(scope, category, &path, run_by);
    item_of(scope, category, path, run_by, &found)
}

/// The item for what `look` found at `path`.
pub fn item_of(
    scope: &Scope<'_>,
    category: Category,
    path: String,
    run_by: Option<&str>,
    found: &Found,
) -> Item {
    let (tier, sha256, body) = match found {
        Found::File {
            sha256,
            mode,
            size,
            head,
        } => {
            let observed = Observed::File {
                sha256,
                mode: *mode,
                size: *size,
                content: whole(*size, head),
            };
            (
                classify(&path, observed, scope.index),
                Some(*sha256),
                body_of(&path, *size, head),
            )
        }
        Found::Link(target) => {
            let resolved_path = read::resolve_where(&path, target, &|next| hop(scope, next));
            let resolved = resolved_path
                .as_deref()
                .and_then(|resolved| self_tier(scope, resolved));
            let name = file_name(&path);
            let observed = Observed::Link {
                target,
                resolved,
                alias: resolved_path
                    .as_deref()
                    .is_some_and(|resolved| declares_alias(scope, resolved, name)),
            };
            (
                classify(&path, observed, scope.index),
                None,
                Body::Link(target.clone()),
            )
        }
        Found::Other => {
            // Root can list any directory.
            let directory = scope.origin != Origin::Root
                && fs::symlink_metadata(scope.root.join(&path))
                    .is_ok_and(|metadata| metadata.is_dir());
            let reason = if directory {
                "a directory only root can list"
            } else {
                "not a regular file"
            };
            (Tier::Unknown, None, Body::Unreadable(reason.into()))
        }
        Found::Unreadable(reason) => (
            unread_tier(scope, &path),
            None,
            Body::Unreadable(reason.clone()),
        ),
    };
    let reader = reader(category, &path, run_by, tier, &body);
    let runs = match &body {
        Body::Text(text) => runs_of(category, reader, &path, text),
        _ => Vec::new(),
    };
    // An `at` job starts with the whole environment of whoever queued it,
    // tokens and all: it is told by its hash, and never handed on.
    let (body, runs) = match body {
        Body::Text(_) if is_at_job(&path) => (Body::Binary(WITHHELD), Vec::new()),
        body => (body, runs),
    };
    // A packaged script whose interpreter line alone was rewritten is its
    // package's content from the second line on (see `tier`): it is said,
    // and read no more than any other file a package installed.
    let rewritten = tier::interpreter_note(&path, tier, scope.index);
    let body = match body {
        Body::Text(_) if rewritten.is_some() => Body::Binary(PACKAGED_SCRIPT),
        body => body,
    };
    let (body, runs) = handed_back(scope, category, run_by, body, runs);
    let mut notes = notes(scope, category, &path, &body, run_by);
    notes.extend(limits(scope, reader, &path, &body, found));
    if is_closed(scope, &path, tier, found) {
        notes.push(CLOSED.to_string());
    }
    notes.extend(path_notes(category, &body));
    notes.extend(rewritten.map(str::to_string));
    notes.extend(tier::session_note(&path, tier, scope.index).map(str::to_string));
    let alerts = settings_alerts(scope, category, &path, tier, &body);
    Item {
        file: None,
        // The root collector's items are all root's, its home included.
        origin: if scope.origin == Origin::System
            && scope
                .home
                .is_some_and(|home| path.starts_with(&format!("{home}/")))
        {
            Origin::User
        } else {
            scope.origin
        },
        category,
        path,
        tier,
        sha256,
        body,
        runs,
        run_by: run_by.map(str::to_string),
        notes,
        alerts,
    }
}

/// The content of an item and what it runs, as the collector hands them
/// back. As root, what was reached by following (a command, a link, a
/// preload, a live check) can be steered by any user (a crontab line, an
/// `LD_PRELOAD` value) at `/etc/shadow` or a key. Its content is never
/// handed back and nothing is followed from it; the user's own sweep reads
/// whatever the user may read. Only the auto-run locations' own files keep
/// their content.
fn handed_back(
    scope: &Scope<'_>,
    category: Category,
    run_by: Option<&str>,
    body: Body,
    runs: Vec<String>,
) -> (Body, Vec<String>) {
    if scope.origin == Origin::Root && (run_by.is_some() || category.is_live()) {
        let body = match body {
            Body::Text(_) | Body::Oversized | Body::Undecodable => Body::Binary(WITHHELD),
            other => other,
        };
        (body, Vec::new())
    } else {
        (body, runs)
    }
}

/// The notes for the lines of a start-up file that set `PATH` to what only
/// running them would tell (see `path::opaque`).
fn path_notes(category: Category, body: &Body) -> Vec<String> {
    let read = matches!(
        category,
        Category::Shell | Category::Environment | Category::Hyprland
    );
    match body {
        Body::Text(text) if read => path::opaque(text)
            .into_iter()
            .map(|line| {
                format!(
                    "line {line} sets PATH in a way Guardian cannot follow: the directories it adds are not watched"
                )
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Whether what `look` found at `path` is a packaged file somebody took
/// everyone's read access from (see `tier::is_closed`).
fn is_closed(scope: &Scope<'_>, path: &str, tier: Tier, found: &Found) -> bool {
    match found {
        Found::File { mode, .. } => tier::is_closed(path, *mode, scope.index),
        // Only a closed file gives this tier to one that was not read.
        Found::Unreadable(_) => tier == Tier::Modified,
        Found::Link(_) | Found::Other => false,
    }
}

/// What the local checks of configuration files say of an item's text
/// (see `config::alerts`). What a package ships, or a copy of it, is the
/// distribution's choice of settings and is left alone.
pub(super) fn settings_alerts(
    scope: &Scope<'_>,
    category: Category,
    path: &str,
    tier: Tier,
    body: &Body,
) -> Vec<(RuleId, String)> {
    match body {
        Body::Text(text) if !matches!(tier, Tier::Vendor | Tier::Copied | Tier::Inert) => {
            let home = scope.home.unwrap_or("root");
            config::alerts(category, path, text, &|file| {
                is_there(
                    scope,
                    commands::expand(home, file).trim_start_matches('/'),
                    Some(path),
                )
            })
        }
        _ => Vec::new(),
    }
}

/// The notes for the limits reached while looking at an item: a line too
/// long to look through for programs, a chain of links too long to follow.
fn limits(
    scope: &Scope<'_>,
    category: Category,
    path: &str,
    body: &Body,
    found: &Found,
) -> Vec<String> {
    let mut reached = match body {
        Body::Text(text) => commands::unfollowed(category, text),
        _ => Vec::new(),
    };
    if let Found::Link(target) = found
        && read::chain_too_long(path, target, &|next| hop(scope, next))
    {
        reached.push(format!(
            "a chain of more than {} links, or one that goes in a circle",
            read::MAX_HOPS
        ));
    }
    reached
        .into_iter()
        .map(|limit| format!("{NOT_ALL_FOLLOWED}{limit}"))
        .collect()
}

/// What to tell about an item beyond its tier.
fn notes(
    scope: &Scope<'_>,
    category: Category,
    path: &str,
    body: &Body,
    run_by: Option<&str>,
) -> Vec<String> {
    let mut notes = Vec::new();
    if let Some(by) = run_by {
        notes.push(format!("run by /{by}"));
    }
    if let (Body::Unreadable(_), Some(owned)) = (body, scope.index.owner(path)) {
        notes.push(format!(
            "installed by {}; only root can read it",
            scope.index.package(owned)
        ));
    }
    if category == Category::LocalBin
        && let Some(name) = path.rsplit('/').next()
        && scope.root.join("usr/bin").join(name).exists()
    {
        notes.push(format!("shadows /usr/bin/{name}"));
    }
    // A launcher of the same name; `mimeapps.list` is a list of handlers,
    // which the home's and the system's both add to.
    if category == Category::Desktop
        && let Some(name) = path.rsplit('/').next()
        && read::has_extension(name, "desktop")
        && scope
            .root
            .join("usr/share/applications")
            .join(name)
            .exists()
    {
        notes.push(format!(
            "replaces the launcher /usr/share/applications/{name}"
        ));
    }
    notes
}

/// Whether the unit at `unit` declares `name` as an alias (`Alias=` in its
/// `[Install]` section), as `systemctl enable` links it under.
fn declares_alias(scope: &Scope<'_>, unit: &str, name: &str) -> bool {
    let Found::File { head, size, .. } = look_past_link(scope, unit) else {
        return false;
    };
    if size > 64 * 1024 {
        return false;
    }
    String::from_utf8_lossy(&head).lines().any(|line| {
        line.trim()
            .strip_prefix("Alias=")
            .is_some_and(|aliases| aliases.split_whitespace().any(|alias| alias == name))
    })
}

/// The tier of the regular file at `path`, if it is one.
fn self_tier(scope: &Scope<'_>, path: &str) -> Option<Tier> {
    match look_past_link(scope, path) {
        Found::File {
            sha256,
            mode,
            size,
            head,
        } => Some(classify(
            path,
            Observed::File {
                sha256: &sha256,
                mode,
                size,
                content: whole(size, &head),
            },
            scope.index,
        )),
        Found::Link(_) | Found::Other | Found::Unreadable(_) => None,
    }
}

/// The whole content of a file of `size` bytes, when `head` (the first
/// bytes kept while it was hashed) holds all of it.
fn whole(size: u64, head: &[u8]) -> Option<&[u8]> {
    (head.len() as u64 == size).then_some(head)
}

fn body_of(path: &str, size: u64, head: &[u8]) -> Body {
    if size > MAX_TEXT_FILE_SIZE {
        return match content::classify_payload(path, &head[..head.len().min(8192)]) {
            Content::Binary(format) => Body::Binary(format.label()),
            Content::Text(_) | Content::Lossy { .. } => Body::Oversized,
            Content::Undecodable => Body::Undecodable,
        };
    }
    match content::classify_payload(path, head) {
        Content::Text(text) | Content::Lossy { text, .. } => Body::Text(text),
        Content::Binary(format) => Body::Binary(format.label()),
        Content::Undecodable => Body::Undecodable,
    }
}
