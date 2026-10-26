//! Browser extensions in the home's browser profiles.
//!
//! An extension runs inside the browser, in every page its granted hosts
//! cover, and no file of an auto-run location says it is there: the
//! browser keeps it in the profile. For each profile of Chromium, Brave and
//! Google Chrome the sweep reads the extensions listed in `Preferences`
//! and `Secure Preferences`, and for Firefox and Zen the profile's
//! `extensions.json`, with each extension's manifest for its name, version
//! and update URL.
//!
//! Those files hold browsing data. They are read here, and nothing of them
//! leaves this module but what makes an item: the extension's id, name and
//! version, where it came from, and the permissions and hosts it was
//! granted. The items are of `Category::BrowserExtension`, which the judge
//! keeps from the AI; extension code is not reviewed at all.
//!
//! An item's text, and so what the sweep remembers of it, is the id, the
//! source and what was granted, not the version: an update that grants
//! nothing new is no change. An extension installed since the last sweep
//! is new, and one granted more (or less) is changed, the way the sweep
//! tells any item. An extension loaded unpacked from a directory
//! (developer mode, `--load-extension`, a temporary add-on), one installed
//! from outside the browser's store, and one Firefox does not hold signed
//! raise `risky-configuration`. An unpacked one whose every file a package
//! installed, unchanged, is that package's, and trusted: Omarchy loads its
//! own extensions that way. The browsers' built-in extensions are not
//! listed.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::Path;

use super::collect::{self, Body, Item, Origin, Scope};
use super::read;
use super::tier::Tier;
use crate::autorun::Category;
use crate::error::{Error, IoContext as _};
use crate::files::read_small_file;
use crate::json::Json;
use crate::rules::RuleId;
use crate::sha256::Sha256;

/// The kind of browser a profile belongs to, which decides how its
/// extensions are listed and which store vouches for them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    Chromium,
    Firefox,
}

impl Family {
    const fn store(self) -> &'static str {
        match self {
            Self::Chromium => "Chrome Web Store",
            Self::Firefox => "addons.mozilla.org",
        }
    }
}

/// A browser, and where under the home it keeps its profiles.
#[derive(Debug)]
struct Browser {
    name: &'static str,
    directory: &'static str,
    family: Family,
}

/// The browsers whose extensions are looked at: what Omarchy installs
/// (Chromium) and what its browser policy also knows of. Edge, Vivaldi
/// and the like are not.
const BROWSERS: &[Browser] = &[
    Browser {
        name: "Chromium",
        directory: ".config/chromium",
        family: Family::Chromium,
    },
    Browser {
        name: "Brave",
        directory: ".config/BraveSoftware/Brave-Browser",
        family: Family::Chromium,
    },
    Browser {
        name: "Google Chrome",
        directory: ".config/google-chrome",
        family: Family::Chromium,
    },
    Browser {
        name: "Firefox",
        directory: ".mozilla/firefox",
        family: Family::Firefox,
    },
    // Where Firefox keeps new profiles since it follows the XDG layout.
    Browser {
        name: "Firefox",
        directory: ".config/mozilla/firefox",
        family: Family::Firefox,
    },
    Browser {
        name: "Zen",
        directory: ".zen",
        family: Family::Firefox,
    },
];

/// The update URLs of the Chrome Web Store, as the store writes them into
/// every extension it serves.
const WEB_STORE: &[&str] = &[
    "https://clients2.google.com/service/update2/crx",
    "http://clients2.google.com/service/update2/crx",
    "https://update.googleapis.com/service/update2/crx",
];

/// Chromium's `location` values for the browser's own extensions
/// (`COMPONENT`, `EXTERNAL_COMPONENT`), and for an unpacked one
/// (`UNPACKED`, `COMMAND_LINE`): Chromium's `ManifestLocation`.
const COMPONENT: &[u64] = &[5, 10];
const UNPACKED: &[u64] = &[4, 8];

/// Firefox's locations for the add-ons that ship with it.
const BUILT_IN: &[&str] = &["app-builtin", "app-system-defaults", "app-system-addons"];

/// The largest preferences file read (arbitrary: profiles seen are under
/// one MiB), and the largest manifest or message catalogue.
const MAX_PREFERENCES: u64 = 32 * 1024 * 1024;
const MAX_MANIFEST: u64 = 1024 * 1024;

/// The most profiles of one browser, and extensions of one profile, that
/// are looked at (arbitrary, far above what anyone runs).
const MAX_PROFILES: usize = 32;
const MAX_EXTENSIONS: usize = 500;

/// What every extension item says of how it was checked.
const LOCAL_ONLY: &str = "checked by local rules only: where it came from and what it was granted; its code is not reviewed";

/// Where an extension came from, as far as trusting it goes.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Source {
    /// The browser's store.
    Store,
    /// Installed from elsewhere: the host it updates or came from, if it
    /// names one.
    Elsewhere(Option<String>),
    /// Loaded from a directory, relative to the root.
    Unpacked(String),
    /// Installed in Firefox without Mozilla's signature.
    Unsigned,
    /// Marked by the browser as from its store, where the manifest that
    /// names where it updates from could not be read.
    Unread,
}

/// One extension of one profile.
#[derive(Debug)]
struct Extension {
    browser: &'static Browser,
    /// The profile's directory, relative to the root.
    profile: String,
    id: String,
    name: Option<String>,
    version: Option<String>,
    source: Source,
    permissions: BTreeSet<String>,
    hosts: BTreeSet<String>,
    /// What could not be read of it, as notes for its item.
    notes: Vec<String>,
    /// Why its manifest could not be read, where it could not.
    unread: Option<String>,
}

/// What the extension checks found.
#[derive(Debug, Default)]
pub(super) struct Extensions {
    pub(super) items: Vec<Item>,
    /// What could not be checked, as sentences: the sweep is incomplete.
    pub(super) unchecked: Vec<String>,
}

/// The extensions of every browser profile in the home of `scope`.
pub(super) fn check(scope: &Scope<'_>) -> Extensions {
    let mut found = Extensions::default();
    let Some(home) = scope.home else {
        return found;
    };
    for browser in BROWSERS {
        let directory = format!("{home}/{}", browser.directory);
        let profiles = match profiles(scope.root, &directory, browser.family, &mut found.unchecked)
        {
            Ok(profiles) => profiles,
            Err(error) => {
                found
                    .unchecked
                    .push(format!("{error}; its extensions were not checked"));
                continue;
            }
        };
        if profiles.len() > MAX_PROFILES {
            found.unchecked.push(format!(
                "/{directory}: more than {MAX_PROFILES} profiles; the extensions of the rest were not checked"
            ));
        }
        for profile in profiles.into_iter().take(MAX_PROFILES) {
            let listed = match browser.family {
                Family::Chromium => chromium(scope.root, browser, &profile, &mut found.unchecked),
                Family::Firefox => firefox(scope.root, browser, &profile, &mut found.unchecked),
            };
            let extensions = match listed {
                Ok(extensions) => extensions,
                Err(error) => {
                    found.unchecked.push(format!(
                        "{error}; the extensions of /{profile} were not checked"
                    ));
                    continue;
                }
            };
            // Chromium's are in the order of their ids, which whoever writes
            // the preferences picks: what is left out is said.
            if extensions.len() > MAX_EXTENSIONS {
                found.unchecked.push(format!(
                    "/{profile}: more than {MAX_EXTENSIONS} extensions; the rest were not checked"
                ));
            }
            for extension in extensions.iter().take(MAX_EXTENSIONS) {
                if let Some(reason) = &extension.unread {
                    found.unchecked.push(format!(
                        "{reason}; where /{profile}#extension:{} updates from was not checked",
                        extension.id
                    ));
                }
                found.items.push(item(scope, extension));
            }
        }
    }
    found
}

/// The profile directories under `directory` (relative to `root`), sorted;
/// none when the browser was never started. A link is no profile the
/// browser made, and is passed over. An entry that cannot be read, or
/// whose name is not UTF-8, is added to `unchecked`.
fn profiles(
    root: &Path,
    directory: &str,
    family: Family,
    unchecked: &mut Vec<String>,
) -> Result<Vec<String>, Error> {
    let full = root.join(directory);
    let entries = match fs::read_dir(&full) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        entries => entries.at(&full)?,
    };
    let mut profiles = Vec::new();
    for entry in entries {
        let Ok((entry, kind)) = entry.and_then(|entry| {
            let kind = entry.file_type()?;
            Ok((entry, kind))
        }) else {
            unchecked.push(format!(
                "/{directory}: an entry could not be read; whether it is a profile was not checked"
            ));
            continue;
        };
        let name = entry.file_name();
        let is_profile = match family {
            Family::Chromium => {
                let name = name.to_string_lossy();
                name == "Default" || name.starts_with("Profile ")
            }
            // A Firefox profile has any name; one without `extensions.json`
            // lists nothing.
            Family::Firefox => true,
        };
        if !kind.is_dir() || !is_profile {
            continue;
        }
        match name.into_string() {
            Ok(name) => profiles.push(format!("{directory}/{name}")),
            Err(name) => unchecked.push(format!(
                "/{directory}/{}: a name that is not UTF-8; its extensions were not checked",
                name.to_string_lossy()
            )),
        }
    }
    profiles.sort();
    Ok(profiles)
}

/// Says in `unchecked` that `count` entries of `profile` were passed over
/// for an id the browser does not make.
fn malformed(profile: &str, count: usize, unchecked: &mut Vec<String>) {
    if count > 0 {
        unchecked.push(format!(
            "/{profile}: {count} extension(s) listed under an id the browser does not make; not checked"
        ));
    }
}

/// The text of the file at `path` (relative to `root`), of at most `max`
/// bytes, read without following a link: `None` when it is not there.
fn read_text(root: &Path, path: &str, max: u64) -> Result<Option<String>, Error> {
    let full = root.join(path);
    let metadata = match fs::symlink_metadata(&full) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        metadata => metadata.at(&full)?,
    };
    if metadata.len() > max {
        return Err(Error::Refused(format!(
            "{}: larger than {max} bytes",
            full.display()
        )));
    }
    read_small_file(&full, max)
        .map(Some)
        .ok_or_else(|| Error::Refused(format!("{}: not a file that can be read", full.display())))
}

/// The JSON document at `path`, if it is there.
fn read_json(root: &Path, path: &str, max: u64) -> Result<Option<Json>, Error> {
    let Some(text) = read_text(root, path, max)? else {
        return Ok(None);
    };
    Json::parse(&text)
        .map(Some)
        .map_err(|error| Error::parse(root.join(path).display().to_string(), error))
}

/// The extensions a Chromium profile lists, but the browser's own. An
/// extension listed in both files is taken from `Secure Preferences`,
/// which the browser protects with a MAC where it can.
fn chromium(
    root: &Path,
    browser: &'static Browser,
    profile: &str,
    unchecked: &mut Vec<String>,
) -> Result<Vec<Extension>, Error> {
    let mut settings: BTreeMap<String, Json> = BTreeMap::new();
    for file in ["Secure Preferences", "Preferences"] {
        let Some(preferences) = read_json(root, &format!("{profile}/{file}"), MAX_PREFERENCES)?
        else {
            continue;
        };
        let listed = preferences
            .get("extensions")
            .and_then(|extensions| extensions.get("settings"))
            .and_then(Json::as_object)
            .unwrap_or_default();
        for (id, entry) in listed {
            settings.entry(id.clone()).or_insert_with(|| entry.clone());
        }
    }
    // Chromium's ids are 32 letters from `a` to `p`.
    let (valid, invalid): (Vec<_>, Vec<_>) = settings.iter().partition(|(id, _)| {
        id.len() == 32 && id.bytes().all(|byte| (b'a'..=b'p').contains(&byte))
    });
    malformed(profile, invalid.len(), unchecked);
    Ok(valid
        .into_iter()
        .filter_map(|(id, entry)| chromium_extension(root, browser, profile, id, entry))
        .collect())
}

/// The extension `id`, a valid one, of a Chromium profile, from its entry
/// in the preferences and its manifest; `None` for the browser's own.
fn chromium_extension(
    root: &Path,
    browser: &'static Browser,
    profile: &str,
    id: &str,
    entry: &Json,
) -> Option<Extension> {
    let location = entry.get("location").and_then(Json::as_u64);
    if location.is_some_and(|location| COMPONENT.contains(&location)) {
        return None;
    }
    let unpacked = location.is_some_and(|location| UNPACKED.contains(&location));
    // An unpacked extension's path is the directory it was loaded from; an
    // installed one's is `<id>/<version>` under the profile.
    let directory =
        entry
            .get("path")
            .and_then(Json::as_str)
            .map(|path| match path.strip_prefix('/') {
                Some(absolute) => absolute.to_string(),
                None => format!("{profile}/Extensions/{path}"),
            });
    // The manifest the browser loads is the one on disk; older Chromium
    // kept a copy in the preferences, which only stands where there is no
    // directory to read.
    let manifest = match (directory.as_deref(), entry.get("manifest")) {
        (Some(directory), _) => {
            read_json(root, &format!("{directory}/manifest.json"), MAX_MANIFEST)
        }
        (None, Some(manifest)) => Ok(Some(manifest.clone())),
        (None, None) => Ok(None),
    };
    let (manifest, unread) = match manifest {
        Ok(manifest) => (manifest, None),
        Err(error) => (None, Some(error.to_string())),
    };
    let update = manifest
        .as_ref()
        .and_then(|manifest| manifest.get("update_url"))
        .and_then(Json::as_str);
    let from_store = entry.get("from_webstore").and_then(Json::as_bool) == Some(true);
    // Without the manifest, only the browser's own mark says it is from
    // the store; one without the mark is taken as from elsewhere.
    let source = match (&directory, update, unread.is_some()) {
        (Some(directory), _, _) if unpacked => Source::Unpacked(directory.clone()),
        (None, _, _) if unpacked => Source::Elsewhere(None),
        (_, _, true) if from_store => Source::Unread,
        (_, _, true) => Source::Elsewhere(None),
        (_, Some(update), false) if WEB_STORE.contains(&update.trim_end_matches('/')) => {
            Source::Store
        }
        (_, None, false) if from_store => Source::Store,
        (_, update, false) => Source::Elsewhere(update.and_then(host)),
    };
    let (name, notes) = match manifest
        .as_ref()
        .map(|manifest| chromium_name(root, manifest, directory.as_deref()))
    {
        None => (None, Vec::new()),
        Some(Ok(name)) => (name, Vec::new()),
        Some(Err(error)) => (
            None,
            vec![format!(
                "its message catalogue could not be read ({error}): its name is not known"
            )],
        ),
    };
    let granted = entry
        .get("granted_permissions")
        .or_else(|| entry.get("active_permissions"));
    Some(Extension {
        browser,
        profile: profile.to_string(),
        id: id.to_string(),
        name,
        version: manifest
            .as_ref()
            .and_then(|manifest| manifest.get("version")?.as_str().map(str::to_string)),
        source,
        permissions: strings(granted, &["api", "manifest_permissions"]),
        hosts: strings(granted, &["explicit_host", "scriptable_host"]),
        notes,
        unread,
    })
}

/// An extension's name: the manifest's, or where that is a message
/// (`__MSG_appName__`), the message in the default locale's catalogue;
/// `Err` when the catalogue is there and cannot be read.
fn chromium_name(
    root: &Path,
    manifest: &Json,
    directory: Option<&str>,
) -> Result<Option<String>, Error> {
    let Some(name) = manifest.get("name").and_then(Json::as_str) else {
        return Ok(None);
    };
    let Some(key) = name
        .strip_prefix("__MSG_")
        .and_then(|rest| rest.strip_suffix("__"))
    else {
        return Ok(Some(name.to_string()));
    };
    let locale = manifest.get("default_locale").and_then(Json::as_str);
    let (Some(locale), Some(directory)) = (locale, directory) else {
        return Ok(None);
    };
    if locale.contains(['/', '.']) {
        return Ok(None);
    }
    let path = format!("{directory}/_locales/{locale}/messages.json");
    let Some(catalogue) = read_json(root, &path, MAX_MANIFEST)? else {
        return Ok(None);
    };
    // Message names are matched without regard to case.
    Ok(catalogue
        .as_object()
        .unwrap_or_default()
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(key))
        .and_then(|(_, message)| message.get("message")?.as_str().map(str::to_string)))
}

/// The strings listed under `keys` of `granted`; a permission written as
/// an object (`{"socket": [...]}`) counts by its name.
fn strings(granted: Option<&Json>, keys: &[&str]) -> BTreeSet<String> {
    let listed = keys
        .iter()
        .filter_map(|key| granted?.get(key)?.as_array())
        .flatten();
    listed
        .flat_map(|value| match value {
            Json::String(text) => vec![text.clone()],
            Json::Object(members) => members.iter().map(|(name, _)| name.clone()).collect(),
            Json::Null | Json::Bool(_) | Json::Number(_) | Json::Array(_) => Vec::new(),
        })
        .collect()
}

/// The extensions a Firefox profile lists, but the browser's own add-ons
/// and what is no extension (themes, dictionaries, language packs).
fn firefox(
    root: &Path,
    browser: &'static Browser,
    profile: &str,
    unchecked: &mut Vec<String>,
) -> Result<Vec<Extension>, Error> {
    let Some(listed) = read_json(root, &format!("{profile}/extensions.json"), MAX_PREFERENCES)?
    else {
        return Ok(Vec::new());
    };
    let addons = listed
        .get("addons")
        .and_then(Json::as_array)
        .unwrap_or_default();
    let extensions: Vec<&Json> = addons
        .iter()
        .filter(|addon| addon.get("type").and_then(Json::as_str) == Some("extension"))
        .filter(|addon| {
            !addon
                .get("location")
                .and_then(Json::as_str)
                .is_some_and(|location| BUILT_IN.contains(&location))
        })
        .collect();
    let listed: Vec<Extension> = extensions
        .iter()
        .filter_map(|addon| firefox_extension(browser, profile, addon))
        .collect();
    malformed(profile, extensions.len() - listed.len(), unchecked);
    Ok(listed)
}

/// One extension of a Firefox profile, from its entry in `extensions.json`;
/// `None` where its id is not one Mozilla makes.
fn firefox_extension(browser: &'static Browser, profile: &str, addon: &Json) -> Option<Extension> {
    let text = |key: &str| addon.get(key).and_then(Json::as_str);
    // The id goes into the item's label, which the sweep shows and `sweep
    // allow` takes: Mozilla's ids are an email-like name or a UUID in
    // braces. Any other is not listed, and `firefox` says how many were
    // not.
    let id = text("id").filter(|id| {
        !id.is_empty()
            && id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "@._-+{}".contains(c))
    })?;
    // Firefox's signed states are 1 and above (preliminary, signed, system,
    // privileged); 0 is a missing signature and the negative ones broken or
    // unknown (which `as_u64` gives as `None`), so all of those, and a
    // state not written at all, count as unsigned.
    let signed = addon
        .get("signedState")
        .and_then(Json::as_u64)
        .is_some_and(|state| state >= 1);
    let source = if text("location") == Some("app-temporary") {
        let directory = text("path").unwrap_or_default();
        Source::Unpacked(directory.trim_start_matches('/').to_string())
    } else if !signed {
        Source::Unsigned
    } else {
        match text("sourceURI").and_then(host) {
            Some(host) if host == "addons.mozilla.org" => Source::Store,
            host => Source::Elsewhere(host),
        }
    };
    let granted = addon.get("userPermissions");
    Some(Extension {
        browser,
        profile: profile.to_string(),
        id: id.to_string(),
        name: addon
            .get("defaultLocale")
            .and_then(|locale| locale.get("name")?.as_str())
            .map(str::to_string),
        version: text("version").map(str::to_string),
        source,
        permissions: strings(granted, &["permissions"]),
        hosts: strings(granted, &["origins"]),
        notes: Vec::new(),
        unread: None,
    })
}

/// The host of `url`, without any user name, password or port: what is
/// shown of where an extension updates from.
fn host(url: &str) -> Option<String> {
    let (_, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?.split(':').next()?;
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Whether every file under `directory` is one a package installed and
/// that still matches, and if so the least trusted of their tiers:
/// `Vendor`, or `UserBuilt` where a package from no configured repository
/// installed any of them.
fn packaged(scope: &Scope<'_>, directory: &str) -> Option<Tier> {
    let listing = read::entries(scope.root, directory);
    if listing.files.is_empty()
        || listing.truncated
        || !listing.unreadable.is_empty()
        || !listing.unnamed.is_empty()
    {
        return None;
    }
    let mut least = Tier::Vendor;
    for path in listing.files {
        match collect::item(scope, Category::BrowserExtension, path, None).tier {
            Tier::Vendor => {}
            Tier::UserBuilt => least = Tier::UserBuilt,
            Tier::Inert
            | Tier::Copied
            | Tier::Edited
            | Tier::Modified
            | Tier::Allowed
            | Tier::Unknown => return None,
        }
    }
    Some(least)
}

/// What the sweep remembers of `extension`: its id, where it came from
/// and what it was granted, one per line; not its name or version.
fn text(extension: &Extension) -> String {
    let source = match &extension.source {
        Source::Store => format!("from the {}", extension.browser.family.store()),
        Source::Elsewhere(host) => format!("from elsewhere: {}", host.as_deref().unwrap_or("")),
        Source::Unpacked(directory) => format!("unpacked from /{directory}"),
        Source::Unsigned => "unsigned".to_string(),
        Source::Unread => "from where not known".to_string(),
    };
    let joined = |listed: &BTreeSet<String>| {
        listed
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "extension {}\n{source}\npermissions: {}\nhosts: {}\n",
        extension.id,
        joined(&extension.permissions),
        joined(&extension.hosts)
    )
}

/// The item of `extension`.
fn item(scope: &Scope<'_>, extension: &Extension) -> Item {
    let store = extension.browser.family.store();
    let mut tier = Tier::Unknown;
    let mut notes = vec![format!(
        "{} extension {} {}",
        extension.browser.name,
        extension.name.as_deref().unwrap_or("(no name found)"),
        extension.version.as_deref().unwrap_or("(no version found)")
    )];
    let mut alerts = Vec::new();
    match &extension.source {
        Source::Store => {}
        Source::Elsewhere(host) => {
            let from = host
                .as_deref()
                .map_or(String::new(), |host| format!(" (from {host})"));
            alerts.push(format!("installed from outside the {store}{from}"));
        }
        Source::Unpacked(directory) => match packaged(scope, directory) {
            Some(packaged) => {
                tier = packaged;
                notes.push(format!(
                    "loaded unpacked from /{directory}, every file of which a package installed and still matches"
                ));
            }
            None => alerts.push(format!(
                "loaded unpacked from /{directory} (developer mode, --load-extension or a temporary add-on): nothing vets its code, which changes without an update"
            )),
        },
        Source::Unsigned => alerts.push("not signed by Mozilla".into()),
        Source::Unread => notes.push(format!(
            "marked as from the {store}, but its manifest could not be read: where it updates from was not checked"
        )),
    }
    notes.extend(extension.notes.iter().cloned());
    notes.push(LOCAL_ONLY.into());
    let text = text(extension);
    Item {
        file: None,
        // A user's sweep reads its own home; the root collector's home is
        // root's.
        origin: if scope.origin == Origin::System {
            Origin::User
        } else {
            scope.origin
        },
        category: Category::BrowserExtension,
        path: format!("{}#extension:{}", extension.profile, extension.id),
        tier,
        sha256: Some(Sha256::digest(text.as_bytes())),
        body: Body::Text(text),
        runs: Vec::new(),
        run_by: None,
        notes,
        alerts: alerts
            .into_iter()
            .map(|seen| (RuleId::RiskyConfiguration, seen))
            .collect(),
    }
}

#[cfg(test)]
mod tests;
