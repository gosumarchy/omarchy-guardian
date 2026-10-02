//! The root part of the sweep. Some auto-run files only root can read (the
//! sudoers file and drop-ins, root's crontab, shell files and keys, some
//! programs services run), so `sweep --root` runs `sweep-collect` through
//! sudo. That command only collects: it reads, never runs anything it
//! finds, makes no AI call and writes nothing. It prints the items no
//! package vouches for as JSON on stdout, and the user's own sweep judges
//! them with the user's settings.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write as _};
use std::os::unix::fs::{self as unix_fs, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::time::UNIX_EPOCH;

use super::collect::{self, Body, Collection, Item, Origin, Scope};
use super::index::{self, LOCAL_DB, PackageIndex};
use super::live;
use super::tier::Tier;
use crate::autorun::Category;
use crate::engine::store;
use crate::json::Json;
use crate::rules::RuleId;
use crate::sha256::Digest;

const SUDO: &str = "/usr/bin/sudo";
const INSTALLED: &str = "/usr/bin/omarchy-guardian";
/// Root's home, relative to `/`.
const ROOT_HOME: &str = "root";
/// The most output and items taken from the root collector.
const MAX_OUTPUT: u64 = 64 * 1024 * 1024;
const MAX_ITEMS: usize = 5000;
const VERSION: u64 = 1;

/// What the root collector found.
#[derive(Debug, Default)]
pub struct RootPart {
    pub items: Vec<Item>,
    pub truncated: Vec<String>,
}

/// Where the scheduled root collector leaves what it found.
pub const RESULTS: &str = "/var/lib/omarchy-guardian/sweep/root.json";
/// Older results are not used: the daily timer should have replaced them.
const MAX_AGE_SECS: u64 = 36 * 60 * 60;

/// `omarchy-guardian sweep-collect [--out]`: run as root, by `sweep --root`
/// through sudo (printing to stdout), or by the daily system timer with
/// `--out` (writing `RESULTS`, only when the system configuration allows
/// it, readable by the configured group).
pub fn collect_command(out: bool, settings: &crate::config::Settings) -> ExitCode {
    if !store::effective_uid().is_ok_and(|uid| uid == 0) {
        errln!(
            "omarchy-guardian sweep-collect: only `sweep --root` and its timer run this, as root"
        );
        return ExitCode::from(2);
    }
    let (consent, group) = settings.sweep_root();
    let group = if out {
        if consent != Some(crate::config::model::RootConsent::Allowed) {
            outln!("Root checks are not allowed in the system configuration; nothing collected.");
            return ExitCode::SUCCESS;
        }
        let Some(gid) = group.as_deref().and_then(group_id) else {
            errln!(
                "omarchy-guardian sweep-collect: no valid [sweep] group in the system configuration"
            );
            return ExitCode::from(2);
        };
        Some(gid)
    } else {
        None
    };
    let index = match index::foreign_packages()
        .and_then(|foreign| PackageIndex::load(Path::new(LOCAL_DB), foreign))
    {
        Ok(index) => index,
        Err(error) => {
            errln!("omarchy-guardian sweep-collect: cannot read the package database: {error}");
            return ExitCode::from(2);
        }
    };
    let scope = Scope {
        root: Path::new("/"),
        home: Some(ROOT_HOME),
        index: &index,
        origin: Origin::Root,
    };
    let mut collection = collect::collect(&scope);
    let live = live::check(&scope);
    collect::merge(&mut collection, live.items);
    collection.truncated.extend(live.unchecked);
    let json = to_json(&collection).to_string();
    match group {
        None => {
            outln!("{json}");
            ExitCode::SUCCESS
        }
        Some(gid) => match write_results(Path::new(RESULTS), &json, gid) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                errln!("omarchy-guardian sweep-collect: {error}");
                ExitCode::from(2)
            }
        },
    }
}

/// The name of this process's primary group, from `/proc/self/status` and
/// `/etc/group`.
pub fn primary_group() -> Option<String> {
    let gid: u32 = fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("Gid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    private_group(
        gid,
        &fs::read_to_string("/etc/group").ok()?,
        &fs::read_to_string("/etc/passwd").ok()?,
    )
}

/// The name of group `gid` when it is one person's alone: no listed
/// members, and the primary group of one account only. Root's results are
/// readable by that group, so a shared one (`users`) would show them to
/// everyone in it.
fn private_group(gid: u32, group: &str, passwd: &str) -> Option<String> {
    let (name, members) = group.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        (fields.get(2)?.parse::<u32>().ok()? == gid)
            .then(|| (fields[0].to_string(), fields.get(3).copied().unwrap_or("")))
    })?;
    let primary_of = passwd
        .lines()
        .filter(|line| {
            line.split(':')
                .nth(3)
                .and_then(|field| field.parse::<u32>().ok())
                == Some(gid)
        })
        .count();
    (members.trim().is_empty() && primary_of == 1 && crate::config::file::is_group_name(&name))
        .then_some(name)
}

/// The id of group `name`, from `/etc/group`.
fn group_id(name: &str) -> Option<u32> {
    fs::read_to_string("/etc/group")
        .ok()?
        .lines()
        .find_map(|line| {
            let mut fields = line.split(':');
            (fields.next()? == name)
                .then(|| fields.nth(1)?.parse().ok())
                .flatten()
        })
}

/// Writes `json` to `path` (and its directory) owned by root and group
/// `gid`: the directory 0750, the file 0640, replaced atomically.
fn write_results(path: &Path, json: &str, gid: u32) -> Result<(), String> {
    let describe = |path: &Path, error: std::io::Error| format!("{}: {error}", path.display());
    let directory = path.parent().ok_or("no directory")?;
    fs::create_dir_all(directory).map_err(|error| describe(directory, error))?;
    unix_fs::chown(directory, Some(0), Some(gid)).map_err(|error| describe(directory, error))?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o750))
        .map_err(|error| describe(directory, error))?;
    let temporary = path.with_extension("json.tmp");
    drop(fs::remove_file(&temporary));
    let result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .and_then(|mut file| file.write_all(json.as_bytes()))
        .and_then(|()| unix_fs::chown(&temporary, Some(0), Some(gid)))
        .and_then(|()| fs::set_permissions(&temporary, fs::Permissions::from_mode(0o640)))
        .and_then(|()| fs::rename(&temporary, path));
    if result.is_err() {
        drop(fs::remove_file(&temporary));
    }
    result.map_err(|error| describe(path, error))
}

/// What the scheduled root collector found, if it is trustworthy and
/// recent: owned by root and writable by no one else, file and directory,
/// and at most `MAX_AGE_SECS` old.
pub fn from_results(path: &Path, now: u64) -> Result<RootPart, String> {
    if let Some(problem) = results_problem(path, now) {
        return Err(problem);
    }
    let text = fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    from_json(&text)
}

/// Why the results at `path` are not used, as far as that shows without
/// reading them (the bar asks this too).
pub fn results_problem(path: &Path, now: u64) -> Option<String> {
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
        return Some("the daily root check has not run for more than a day".into());
    }
    (metadata.len() > MAX_OUTPUT).then(|| "the root check's results are too large".into())
}

fn to_json(collection: &Collection) -> Json {
    let items = collection
        .items
        .iter()
        .filter(|item| !item.is_trusted())
        .take(MAX_ITEMS)
        .map(item_json);
    Json::object([
        ("version", Json::from(VERSION)),
        ("items", Json::Array(items.collect())),
        (
            "truncated",
            Json::Array(
                collect::bounded(collection.truncated.clone())
                    .iter()
                    .map(|unchecked| Json::from(unchecked.as_str()))
                    .collect(),
            ),
        ),
    ])
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

fn from_json(text: &str) -> Result<RootPart, String> {
    let json = Json::parse(text.trim()).map_err(|error| format!("unreadable output: {error}"))?;
    if json.get("version").and_then(Json::as_u64) != Some(VERSION) {
        return Err("the root collector is a different version; reinstall Guardian".into());
    }
    let items = json
        .get("items")
        .and_then(Json::as_array)
        .ok_or("no item list")?
        .iter()
        .take(MAX_ITEMS)
        // One odd item (a process with a strange `LD_PRELOAD`, say) must not
        // throw away everything else root found.
        .filter_map(item_from_json)
        .collect();
    let truncated = json
        .get("truncated")
        .and_then(Json::as_array)
        .map(|locations| {
            locations
                .iter()
                .filter_map(|location| location.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    Ok(RootPart { items, truncated })
}

/// Runs the root collector through sudo, which asks for the password on
/// the terminal, and reads what it found.
pub fn from_root() -> Result<RootPart, String> {
    // Always the installed, root-owned Guardian: running the current
    // executable would let a user-writable build run as root.
    let program = Path::new(INSTALLED);
    let metadata = fs::metadata(program).map_err(|error| format!("{INSTALLED}: {error}"))?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(format!("{INSTALLED} is not root's alone"));
    }
    errln!(
        "Guardian needs root to check what your user can't read (sudoers, root's crontab, shell files and keys). It only reads them."
    );
    let mut child = Command::new(SUDO)
        .arg(program)
        .arg("sweep-collect")
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot start sudo: {error}"))?;
    let mut output = String::new();
    let read = child
        .stdout
        .take()
        .ok_or("no output")?
        .take(MAX_OUTPUT)
        .read_to_string(&mut output);
    let status = child.wait().map_err(|error| error.to_string())?;
    read.map_err(|error| error.to_string())?;
    if !status.success() {
        return Err(format!("the root collector exited with {status}"));
    }
    from_json(&output)
}

/// Replaces what the user's sweep could not judge on the system side with
/// what root found: the user's home items and trusted system items stay.
pub fn merge(collection: &mut Collection, part: RootPart) {
    // Root's view only fills in what the user could not read: root's
    // results may be a day old, and what the user read now is newer.
    collection.items.retain(|item| {
        item.origin == Origin::User
            || !item.alerts.is_empty()
            || !matches!(item.body, Body::Unreadable(_))
    });
    collect::merge(collection, part.items);
    collection.truncated.extend(part.truncated);
}

#[cfg(test)]
mod tests {
    use super::{from_json, merge, to_json};
    use crate::autorun::Category;
    use crate::sha256::Sha256;
    use crate::sweep::collect::{Body, Collection, Item, Origin};
    use crate::sweep::tier::Tier;

    fn item(path: &str, origin: Origin, tier: Tier, body: Body) -> Item {
        Item {
            origin,
            category: Category::Sudo,
            path: path.into(),
            tier,
            sha256: Some(Sha256::digest(path.as_bytes())),
            body,
            runs: vec!["/usr/bin/x".into()],
            run_by: Some("etc/y".into()),
            notes: vec!["a note".into()],
            alerts: Vec::new(),
        }
    }

    #[test]
    fn items_round_trip_and_trusted_ones_stay_behind() {
        let collection = Collection {
            items: vec![
                item(
                    "etc/sudoers.d/evil",
                    Origin::Root,
                    Tier::Unknown,
                    Body::Text("ALL ALL=(ALL) NOPASSWD: ALL\n".into()),
                ),
                item(
                    "usr/bin/x",
                    Origin::Root,
                    Tier::Modified,
                    Body::Binary("ELF executable"),
                ),
                item(
                    "etc/sudoers",
                    Origin::Root,
                    Tier::Vendor,
                    Body::Text("trusted".into()),
                ),
            ],
            truncated: vec!["/etc/x".into()],
        };
        let mut collection = collection;
        // The drop-in is in the catalog itself: its content travels.
        collection.items[0].run_by = None;
        collection.items[1]
            .alerts
            .push((crate::rules::RuleId::HiddenProgram, "seen".into()));
        let part = from_json(&to_json(&collection).to_string()).unwrap();
        assert_eq!(part.items, collection.items[..2]);
        assert_eq!(part.truncated, ["/etc/x"]);
    }

    #[test]
    fn only_a_private_group_may_read_roots_results() {
        let passwd = "root:x:0:0::/root:/bin/bash\nu:x:1000:1000::/home/u:/bin/bash\nv:x:1001:100::/home/v:/bin/bash\nw:x:1002:100::/home/w:/bin/bash\n";
        let group = "root:x:0:\nu:x:1000:\nusers:x:100:\nwheel:x:998:u\n";
        assert_eq!(
            super::private_group(1000, group, passwd).as_deref(),
            Some("u")
        );
        assert_eq!(super::private_group(100, group, passwd), None);
        assert_eq!(super::private_group(998, group, passwd), None);
    }

    #[test]
    fn malformed_or_foreign_output_is_refused() {
        assert!(from_json("not json").is_err());
        assert!(from_json(r#"{"version":2,"items":[]}"#).is_err());
        let escaping = r#"{"version":1,"items":[{"path":"../etc/x","category":"sudo","tier":"unknown","body":{"kind":"undecodable"},"runs":[],"notes":[],"alerts":[]}]}"#;
        // A bad item is left out; the rest of root's results still count.
        assert!(from_json(escaping).unwrap().items.is_empty());
    }

    #[test]
    fn what_root_reached_by_following_keeps_only_its_hash() {
        use crate::sweep::collect::{WITHHELD, item as collect_item};
        let dir = crate::test_support::TempDir::new("root-withheld");
        let root = dir.path();
        std::fs::create_dir_all(root.join("var/spool/cron")).unwrap();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/shadow"), "root:$6$hash:\n").unwrap();
        std::fs::write(root.join("var/spool/cron/u"), "* * * * * /etc/shadow\n").unwrap();
        let index =
            crate::sweep::index::PackageIndex::with_foreign(std::collections::HashSet::new());
        let scope = crate::sweep::collect::Scope {
            root,
            home: Some("root"),
            index: &index,
            origin: Origin::Root,
        };
        // A crontab line names it: followed, so its content stays home,
        // whoever may read it, and nothing is followed from it.
        let followed = collect_item(
            &scope,
            Category::Cron,
            "etc/shadow".into(),
            Some("var/spool/cron/u"),
        );
        assert_eq!(followed.body, Body::Binary(WITHHELD));
        assert!(followed.runs.is_empty());
        // The crontab itself is an auto-run file: its content travels.
        let direct = collect_item(&scope, Category::Cron, "var/spool/cron/u".into(), None);
        assert!(matches!(direct.body, Body::Text(_)));
        assert_eq!(direct.runs, ["/etc/shadow"]);
    }

    #[test]
    fn root_findings_replace_what_the_user_could_not_judge() {
        let mut collection = Collection {
            items: vec![
                item(
                    "etc/sudoers",
                    Origin::System,
                    Tier::Unknown,
                    Body::Unreadable("denied".into()),
                ),
                item(
                    "etc/pam.d/x",
                    Origin::System,
                    Tier::Vendor,
                    Body::Text(String::new()),
                ),
                item(
                    "home/u/.bashrc",
                    Origin::User,
                    Tier::Unknown,
                    Body::Text(String::new()),
                ),
            ],
            truncated: Vec::new(),
        };
        // The user's own live alert (a program in memory) stays.
        let mut memory = item(
            "memfd:payload",
            Origin::System,
            Tier::Unknown,
            Body::Unreadable("runs only in memory".into()),
        );
        memory
            .alerts
            .push((crate::rules::RuleId::HiddenProgram, "seen".into()));
        collection.items.push(memory);
        let root = item(
            "etc/sudoers.d/evil",
            Origin::Root,
            Tier::Unknown,
            Body::Text(String::new()),
        );
        merge(
            &mut collection,
            super::RootPart {
                items: vec![root],
                truncated: Vec::new(),
            },
        );
        let paths: Vec<&str> = collection
            .items
            .iter()
            .map(|item| item.path.as_str())
            .collect();
        assert_eq!(
            paths,
            [
                "etc/pam.d/x",
                "etc/sudoers.d/evil",
                "home/u/.bashrc",
                "memfd:payload"
            ]
        );
    }
}
