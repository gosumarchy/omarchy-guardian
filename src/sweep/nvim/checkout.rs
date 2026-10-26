//! A plugin's directory as lazy.nvim left it: its files, and what its git
//! directory says, read as files. Git itself never runs: a checkout's
//! configuration can make git run commands.

use std::fs;
use std::io;
use std::path::Path;

use crate::git_state;
use crate::scan::MAX_TEXT_FILE_SIZE;
use crate::sha256::Digest;
use crate::sweep::collect;
use crate::sweep::read::{self, Found};

/// The most plugins looked at. Arbitrary: `LazyVim` with all of its extras
/// installs about 200.
const MAX_PLUGINS: usize = 300;

/// How many directories deep a plugin is looked into. Arbitrary: the
/// deepest of a `LazyVim` install's plugins goes 7 deep.
const MAX_DEPTH: usize = 16;

/// The most entries one plugin may hold before the rest is reported, not
/// read: as for every other location the sweep walks.
const MAX_ENTRIES: usize = read::MAX_ENTRIES;

/// The largest `.git/config` or `.git/HEAD` read. Arbitrary: lazy.nvim
/// writes a few hundred bytes.
const MAX_GIT_FILE: u64 = 64 * 1024;

/// A directory, or what stands in for one, under lazy.nvim's.
#[derive(Debug)]
pub(super) struct Checkout {
    /// Its name, which names the plugin.
    pub(super) name: String,
    /// Relative to the root.
    pub(super) path: String,
    pub(super) shape: Shape,
}

#[derive(Debug)]
pub(super) enum Shape {
    /// A directory: what its git directory says (`None` without one) and
    /// every entry outside it, sorted by path relative to the directory.
    Tree {
        git: Option<Git>,
        files: Vec<(String, Entry)>,
    },
    /// A link where the directory belongs, with its target.
    Link(String),
}

/// An entry of a plugin's directory.
#[derive(Debug)]
pub(super) enum Entry {
    File(Digest),
    Link(String),
}

/// What a plugin's `.git` directory says.
#[derive(Debug)]
pub(super) struct Git {
    pub(super) remote: Remote,
    /// The commit `HEAD` is at.
    pub(super) commit: Option<String>,
    /// The keys of `.git/config` that run a command on later git commands,
    /// as (line, `key = value` with URL credentials masked).
    pub(super) runs: Vec<(usize, String)>,
    /// The git hooks it holds (every file or link in `hooks/` but
    /// `*.sample`), by name, sorted.
    pub(super) hooks: Vec<(String, Entry)>,
}

/// Where a checkout fetches from (`remote.origin.url`).
#[derive(Debug)]
pub(super) enum Remote {
    /// The address, without a user or a password.
    Url(String),
    /// `.git/config` names no origin.
    Unnamed,
    /// `.git/config` could not be read; said as not checked.
    Unread,
}

/// Every plugin directory under `lazy` (relative to `root`), sorted by
/// name. What cannot be looked at is said in `unchecked`.
pub(super) fn all(root: &Path, lazy: &str, unchecked: &mut Vec<String>) -> Vec<Checkout> {
    let listing = match fs::read_dir(root.join(lazy)) {
        Ok(listing) => listing,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Vec::new(),
        Err(_) => {
            unchecked.push(format!("/{lazy}: could not be listed"));
            return Vec::new();
        }
    };
    let mut names = Vec::new();
    for entry in listing {
        let Ok(entry) = entry else {
            unchecked.push(format!("/{lazy}: could not be listed in full"));
            break;
        };
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            let shown = format!("{lazy}/{}", entry.file_name().to_string_lossy());
            unchecked.push(collect::not_utf8(&shown));
            continue;
        };
        // lazy.nvim keeps nothing but plugins there; a plain file is no
        // plugin Neovim loads.
        if entry
            .file_type()
            .is_ok_and(|kind| kind.is_dir() || kind.is_symlink())
        {
            names.push(name);
        }
    }
    names.sort();
    if names.len() > MAX_PLUGINS {
        unchecked.push(format!(
            "/{lazy}: more than {MAX_PLUGINS} plugins; the rest were not looked at"
        ));
        names.truncate(MAX_PLUGINS);
    }
    names
        .into_iter()
        .map(|name| checkout(root, lazy, name, unchecked))
        .collect()
}

fn checkout(root: &Path, lazy: &str, name: String, unchecked: &mut Vec<String>) -> Checkout {
    let path = format!("{lazy}/{name}");
    let shape = match read::look(root, &path) {
        Found::Link(target) => {
            unchecked.push(format!(
                "/{path}: a link; the plugin it leads to was not looked at"
            ));
            Shape::Link(target)
        }
        Found::File { .. } | Found::Other | Found::Unreadable(_) => Shape::Tree {
            git: git(root, &path, unchecked),
            files: walk(root, &path, unchecked),
        },
    };
    Checkout { name, path, shape }
}

/// Every entry under the directory `path` but its top-level `.git`, with no
/// link followed, sorted by path relative to `path`.
fn walk(root: &Path, path: &str, unchecked: &mut Vec<String>) -> Vec<(String, Entry)> {
    let mut entries = Vec::new();
    let mut truncated = false;
    let mut pending = vec![(String::new(), 0_usize)];
    while let Some((directory, depth)) = pending.pop() {
        let full = if directory.is_empty() {
            path.to_string()
        } else {
            format!("{path}/{directory}")
        };
        let Ok(listing) = fs::read_dir(root.join(&full)) else {
            unchecked.push(format!("/{full}: could not be listed"));
            continue;
        };
        for entry in listing {
            let Ok(entry) = entry else {
                unchecked.push(format!("/{full}: could not be listed in full"));
                break;
            };
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                let shown = format!("{full}/{}", entry.file_name().to_string_lossy());
                unchecked.push(collect::not_utf8(&shown));
                continue;
            };
            let relative = if directory.is_empty() {
                name
            } else {
                format!("{directory}/{name}")
            };
            if relative == ".git" {
                continue;
            }
            let is_directory = entry.file_type().is_ok_and(|kind| kind.is_dir());
            if is_directory && depth + 1 < MAX_DEPTH {
                pending.push((relative, depth + 1));
            } else if is_directory || entries.len() >= MAX_ENTRIES {
                truncated = true;
            } else {
                let found = read::look(root, &format!("{path}/{relative}"));
                match found {
                    Found::File { sha256, .. } => entries.push((relative, Entry::File(sha256))),
                    Found::Link(target) => entries.push((relative, Entry::Link(target))),
                    Found::Other => {}
                    Found::Unreadable(reason) => {
                        unchecked.push(format!("/{path}/{relative}: could not be read ({reason})"));
                    }
                }
            }
        }
    }
    if truncated {
        unchecked.push(format!("/{path}: more entries than were looked at"));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    entries
}

/// What the `.git` directory of the plugin at `path` says; `None` when it
/// has none (a `.git` file or link is no directory lazy.nvim made).
fn git(root: &Path, path: &str, unchecked: &mut Vec<String>) -> Option<Git> {
    let directory = format!("{path}/.git");
    if !fs::symlink_metadata(root.join(&directory)).is_ok_and(|metadata| metadata.is_dir()) {
        return None;
    }
    let Some(config) = text(root, &format!("{directory}/config"), MAX_GIT_FILE) else {
        unchecked.push(format!(
            "/{directory}/config: could not be read, so where the plugin is fetched from was not checked"
        ));
        return Some(Git {
            remote: Remote::Unread,
            commit: commit(root, &directory),
            runs: Vec::new(),
            hooks: hooks(root, &directory, unchecked),
        });
    };
    let remote = origin(&config).map_or(Remote::Unnamed, |url| Remote::Url(without_userinfo(&url)));
    Some(Git {
        remote,
        commit: commit(root, &directory),
        runs: git_state::executing_keys(&config),
        hooks: hooks(root, &directory, unchecked),
    })
}

/// The text of the file at `path`, if it is a plain file of at most
/// `limit` bytes.
fn text(root: &Path, path: &str, limit: u64) -> Option<String> {
    match read::look(root, path) {
        Found::File { size, head, .. } if size <= limit => {
            Some(String::from_utf8_lossy(&head).into_owned())
        }
        Found::File { .. } | Found::Link(_) | Found::Other | Found::Unreadable(_) => None,
    }
}

/// `remote.origin.url` of a git configuration: the first, which is where
/// git fetches from. Section and key names are case-insensitive in git,
/// the subsection is not.
pub(super) fn origin(config: &str) -> Option<String> {
    let mut in_origin = false;
    for line in config.lines() {
        let line = line.trim();
        if let Some(header) = line.strip_prefix('[') {
            let header = header.split(']').next().unwrap_or_default().trim();
            let (section, subsection) = header
                .split_once(char::is_whitespace)
                .unwrap_or((header, ""));
            in_origin = section.eq_ignore_ascii_case("remote")
                && subsection.trim().trim_matches('"') == "origin";
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if in_origin && key.trim().eq_ignore_ascii_case("url") {
            return Some(value.trim().trim_matches('"').to_string());
        }
    }
    None
}

/// The commit the git directory `directory` has checked out: `HEAD` itself
/// (lazy.nvim checks out a commit, not a branch), or the branch it names,
/// as a loose ref or in `packed-refs`.
fn commit(root: &Path, directory: &str) -> Option<String> {
    let head = text(root, &format!("{directory}/HEAD"), MAX_GIT_FILE)?;
    let head = head.trim();
    if is_hash(head) {
        return Some(head.to_ascii_lowercase());
    }
    let reference = head.strip_prefix("ref:")?.trim();
    let plain = reference.starts_with("refs/")
        && reference
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..");
    if !plain {
        return None;
    }
    if let Some(loose) = text(root, &format!("{directory}/{reference}"), MAX_GIT_FILE) {
        let loose = loose.trim();
        return is_hash(loose).then(|| loose.to_ascii_lowercase());
    }
    let packed = text(
        root,
        &format!("{directory}/packed-refs"),
        MAX_TEXT_FILE_SIZE,
    )?;
    packed.lines().find_map(|line| {
        let (hash, name) = line.split_once(' ')?;
        (name.trim() == reference && is_hash(hash)).then(|| hash.to_ascii_lowercase())
    })
}

/// Whether `text` is a git object name: SHA-1 or SHA-256 in hex.
fn is_hash(text: &str) -> bool {
    matches!(text.len(), 40 | 64) && text.chars().all(|c| c.is_ascii_hexdigit())
}

/// The hooks in the git directory `directory`: every file or link in
/// `hooks/` but the `*.sample` files git puts there, which never run.
fn hooks(root: &Path, directory: &str, unchecked: &mut Vec<String>) -> Vec<(String, Entry)> {
    let path = format!("{directory}/hooks");
    let listing = match fs::read_dir(root.join(&path)) {
        Ok(listing) => listing,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Vec::new(),
        Err(_) => {
            unchecked.push(format!("/{path}: could not be listed"));
            return Vec::new();
        }
    };
    let mut hooks = Vec::new();
    for entry in listing {
        let Ok(entry) = entry else {
            unchecked.push(format!("/{path}: could not be listed in full"));
            break;
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".sample") {
            continue;
        }
        match read::look(root, &format!("{path}/{name}")) {
            Found::File { sha256, .. } => hooks.push((name, Entry::File(sha256))),
            Found::Link(target) => hooks.push((name, Entry::Link(target))),
            Found::Other => {}
            Found::Unreadable(reason) => {
                unchecked.push(format!("/{path}/{name}: could not be read ({reason})"));
            }
        }
    }
    hooks.sort_by(|left, right| left.0.cmp(&right.0));
    hooks
}

/// `url` without the user and password of an address
/// (`https://user:token@host/x` is `https://host/x`): a token there is
/// nobody's business but git's.
pub(super) fn without_userinfo(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    format!("{scheme}://{host}{path}")
}

/// Whether the addresses `left` and `right` name the same repository: the
/// same host and path, whatever the scheme, user, case, trailing `/` or
/// `.git` (`git@github.com:a/b` is `https://github.com/a/b.git`).
pub(super) fn same_place(left: &str, right: &str) -> bool {
    place(left) == place(right)
}

/// `url` as `host/path`, lowercased (GitHub names are not case-sensitive).
fn place(url: &str) -> String {
    let url = without_userinfo(url.trim()).to_ascii_lowercase();
    let place = match url.split_once("://") {
        Some((_, rest)) => rest.to_string(),
        // An scp-like address: `user@host:path`.
        None => match url.split_once(':') {
            Some((host, path)) if !host.contains('/') => {
                let host = host.rsplit_once('@').map_or(host, |(_, host)| host);
                format!("{host}/{path}")
            }
            _ => url.clone(),
        },
    };
    let place = place.trim_end_matches('/');
    place
        .strip_suffix(".git")
        .unwrap_or(place)
        .trim_end_matches('/')
        .to_string()
}
