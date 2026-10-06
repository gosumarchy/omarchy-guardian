//! The links the installed system and its packages hold: which directories
//! a path can be reached through, and where a path leads once they are
//! followed.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::{C_LOCALE, Installed, TOOL_LIMITS};
use crate::autorun::{self, Kind};
use crate::payload;
use crate::sweep::read;
use crate::tools;

/// Where pacman keeps what it installed, when its configuration names no
/// other place.
const DEFAULT_DB_PATH: &str = "/var/lib/pacman/";
const GZIP: &str = "/usr/bin/gzip";
/// The local database of installed packages (`DBPath`/local).
pub(super) fn local_database() -> PathBuf {
    let configured = tools::run(
        Path::new(tools::PACMAN_CONF),
        &["DBPath".into()],
        None,
        C_LOCALE,
        TOOL_LIMITS,
    )
    .ok()
    .and_then(|captured| captured.into_success().ok())
    .map(|output| String::from_utf8_lossy(&output).trim().to_string())
    .filter(|path| path.starts_with('/'));
    PathBuf::from(configured.unwrap_or_else(|| DEFAULT_DB_PATH.to_string())).join("local")
}

/// Where the symbolic links in the system's auto-run locations lead: each
/// file led to (relative to the root), with the links that lead there.
pub(super) type InstalledLinks = HashMap<String, Vec<String>>;

/// The links in the auto-run locations under `root`, by where they lead,
/// and what could not be looked at. A directory this user cannot list
/// (`/etc/sudoers.d`) is read from pacman's record of the packages that
/// ship into it (`db`); a link root made there by hand is not seen. At
/// most `limit` entries are looked through under one location.
pub(super) fn installed_links(root: &Path, db: &Path, limit: usize) -> Installed {
    let mut links = InstalledLinks::new();
    let mut unseen = Vec::new();
    let mut hidden: Vec<String> = Vec::new();
    let mut add = |rel: &str, target: &str| {
        if let Some(leads) = leads_to(root, rel, target) {
            let from = links.entry(leads).or_default();
            if !from.iter().any(|known| known == rel) {
                from.push(rel.to_string());
            }
        }
    };
    for location in autorun::SYSTEM {
        let candidates = match location.kind {
            Kind::File => vec![location.path.to_string()],
            Kind::Glob => {
                let matches = read::matching(root, location.path);
                hidden.extend(matches.unreadable);
                if matches.truncated {
                    unseen.push(format!(
                        "more files match /{} than are looked through for links to the files this transaction replaces; remove what does not belong there",
                        location.path
                    ));
                }
                matches.files
            }
            Kind::Directory | Kind::Units | Kind::Manager => {
                let walk = link_candidates(root, location.path, limit);
                hidden.extend(walk.unreadable);
                if let Some((directory, entries)) = walk.over {
                    unseen.push(format!(
                        "/{} holds more than {limit} entries (/{directory} alone has {entries}), more than are looked through for links to the files this transaction replaces; remove what does not belong there",
                        location.path
                    ));
                }
                walk.files
            }
        };
        for rel in candidates {
            if location.contains(&rel)
                && let Ok(target) = fs::read_link(root.join(&rel))
                && let Some(target) = target.to_str()
            {
                add(&rel, target);
            }
        }
    }
    hidden.sort();
    hidden.dedup();
    let mut unknown = Vec::new();
    if !hidden.is_empty() {
        match packaged_links(db, &hidden) {
            Ok(found) => {
                for (rel, target) in found.links {
                    if autorun::is_auto_run(&rel) {
                        add(&rel, &target);
                    }
                }
                unknown = found.unknown;
            }
            Err(reason) => unseen.push(format!(
                "the links installed packages ship into /{} could not be read from pacman's database ({reason})",
                hidden.join(", /")
            )),
        }
    }
    Installed {
        links,
        unseen,
        unknown,
    }
}

/// What a walk for links found under one location.
struct Walk {
    /// Every entry that is not a directory, sorted.
    files: Vec<String>,
    /// Directories that exist but could not be listed (only root can).
    unreadable: Vec<String>,
    /// The directory at which the limit was passed, and how many entries
    /// it holds itself.
    over: Option<(String, usize)>,
}

/// Every non-directory entry under directory `rel` of `root`, without
/// entering linked directories. However deep: a directory nested further
/// than any catalogued shape is no reason to stop, only the number of
/// entries looked at (directories included) is bounded by `limit`. The
/// directory that passes it is counted to its end, so it can be named with
/// what it holds.
fn link_candidates(root: &Path, rel: &str, limit: usize) -> Walk {
    let mut walk = Walk {
        files: Vec::new(),
        unreadable: Vec::new(),
        over: None,
    };
    let mut seen = 0_usize;
    let mut pending = vec![rel.trim_end_matches('/').to_string()];
    while let Some(directory) = pending.pop() {
        let listing = match fs::read_dir(root.join(&directory)) {
            Ok(listing) => listing,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                continue;
            }
            Err(_) => {
                walk.unreadable.push(directory);
                continue;
            }
        };
        let mut here = 0_usize;
        for entry in listing.filter_map(Result::ok) {
            here += 1;
            if seen + here > limit {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let child = format!("{directory}/{name}");
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                pending.push(child);
            } else {
                walk.files.push(child);
            }
        }
        seen += here;
        if seen > limit {
            walk.over = Some((directory, here));
            break;
        }
    }
    walk.files.sort();
    walk.unreadable.sort();
    walk
}

/// One sentence for each package whose record leaves out what some of its
/// entries in a directory only root lists are (`unknown`), but for the
/// entries this transaction puts something in the place of (`replaced`):
/// those are read from the archive that brings them.
pub(super) fn unknown_entries(
    unknown: &[(String, String)],
    replaced: &dyn Fn(&str) -> bool,
) -> Vec<String> {
    let mut packages: Vec<&str> = unknown
        .iter()
        .map(|(package, _)| package.as_str())
        .collect();
    packages.sort_unstable();
    packages.dedup();
    packages
        .into_iter()
        .filter_map(|package| {
            let paths: Vec<String> = unknown
                .iter()
                .filter(|(owner, path)| owner == package && !replaced(path))
                .map(|(_, path)| format!("/{path}"))
                .collect();
            let first = paths.first()?;
            let more = match paths.len() - 1 {
                0 => String::new(),
                more => format!(" and {more} more"),
            };
            Some(format!(
                "pacman's record of the installed package {package} does not say whether {first}{more} is a symbolic link or where it leads, and only root can look there: whether this transaction replaces what it leads to cannot be told. Install a version of that package with a complete record, or remove it"
            ))
        })
        .collect()
}

/// Where the link at `rel` with the text `target` leads under `root`,
/// relative to it: as the system resolves it when what it leads to is
/// there, and by its text otherwise (the file may be about to be
/// installed).
fn leads_to(root: &Path, rel: &str, target: &str) -> Option<String> {
    let by_text = if target.starts_with('/') {
        PathBuf::from(target.trim_start_matches('/'))
    } else {
        Path::new(rel).parent()?.join(target)
    };
    let by_text = read::normalize(&by_text)?;
    match fs::canonicalize(root.join(&by_text)) {
        Ok(real) => {
            let real_root = fs::canonicalize(root).ok()?;
            Some(real.strip_prefix(real_root).ok()?.to_str()?.to_string())
        }
        Err(_) => Some(payload::through_root_links(&by_text)),
    }
}

/// What pacman's record says of the entries installed packages ship
/// inside directories only root lists.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Packaged {
    /// The symbolic links, with their text.
    pub(super) links: Vec<(String, String)>,
    /// Entries the record does not describe: the package's record
    /// (`name-version`), and the path.
    pub(super) unknown: Vec<(String, String)>,
}

/// The paths a package's `files` record lists: its `%FILES%` section, not
/// the backup list after it.
fn listed_files(files: &str) -> impl Iterator<Item = &str> {
    files
        .lines()
        .skip_while(|line| *line != "%FILES%")
        .skip(1)
        .take_while(|line| !line.is_empty() && !line.starts_with('%'))
}

/// The symbolic links that installed packages ship inside `directories`
/// (relative to the root), with their text, from pacman's own record of
/// each package: its `files` list, which pacman writes from the archive,
/// says which paths to look at, and its `mtree`, which the package brings,
/// what each is. A listed path the `mtree` has no usable line for may be
/// a link to anywhere, and is returned as unknown rather than passed over.
pub(super) fn packaged_links(db: &Path, directories: &[String]) -> Result<Packaged, String> {
    let inside = |path: &str| {
        directories.iter().any(|directory| {
            path.strip_prefix(directory.as_str())
                .is_some_and(|rest| rest.starts_with('/'))
        })
    };
    let mut found = Packaged::default();
    let unreadable = |error: io::Error| format!("{}: {error}", db.display());
    for entry in fs::read_dir(db).map_err(unreadable)? {
        let package = entry.map_err(unreadable)?.path();
        let files = match fs::read(package.join("files")) {
            Ok(files) => String::from_utf8_lossy(&files).into_owned(),
            // The database's own files (`ALPM_DB_VERSION`), or a package
            // without a file list.
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                continue;
            }
            Err(error) => return Err(format!("{}: {error}", package.display())),
        };
        let shipped: Vec<&str> = listed_files(&files)
            .filter(|line| !line.ends_with('/') && inside(line))
            .collect();
        if shipped.is_empty() {
            continue;
        }
        let mtree = tools::run(
            Path::new(GZIP),
            &["-dc".into(), "--".into(), package.join("mtree").into()],
            None,
            C_LOCALE,
            TOOL_LIMITS,
        )
        .and_then(tools::Captured::into_success)
        .map_err(|error| format!("{}: {error}", package.display()))?;
        let mut entries = mtree_entries(&String::from_utf8_lossy(&mtree));
        let name = package
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        for path in shipped {
            match entries.remove(path) {
                Some(Some(target)) => found.links.push((path.to_string(), target)),
                Some(None) => {}
                None => found.unknown.push((name.clone(), path.to_string())),
            }
        }
        // A link the `mtree` has and the file list does not costs one
        // more look and misses nothing.
        let mut extra: Vec<(String, String)> = entries
            .into_iter()
            .filter(|(path, _)| inside(path))
            .filter_map(|(path, target)| Some((path, target?)))
            .collect();
        extra.sort();
        found.links.extend(extra);
    }
    found.links.sort();
    found.unknown.sort();
    Ok(found)
}

/// What an `mtree` says each path (relative to `/`) is: a symbolic link
/// with its text (`./path … type=link link=target`), or something else. A
/// line whose path or link text cannot be read is left out, so what it is
/// about counts as not described.
pub(super) fn mtree_entries(mtree: &str) -> HashMap<String, Option<String>> {
    mtree
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let path = payload::unescape(fields.next()?.strip_prefix("./")?)?;
            let mut link = false;
            let mut target = None;
            for field in fields {
                link = link || field == "type=link";
                target = target.or(field.strip_prefix("link="));
            }
            if link {
                Some((path, Some(payload::unescape(target?)?)))
            } else {
                Some((path, None))
            }
        })
        .collect()
}
