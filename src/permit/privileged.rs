//! The root half of a permit: adding one to the system store, and the
//! commands the root helper and the pacman hook run.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::ExitCode;

use crate::audit::{self, Entry, Event, Gate};
use crate::config::Settings;
use crate::error::{Error, IoContext};
use crate::json::Json;
use crate::sweep::state;
use crate::time::now;
use crate::user;

use super::{
    DIRECTORY, ID_CHARS, LIFETIME_SECS, PERMITTED_EXIT, Permit, classes, enabled, is_hex, permits,
};

/// The most permits one user may hold at a time.
pub(super) const MAX_PERMITS: usize = 32;

const SYSTEM_USAGE: &str =
    "usage: omarchy-guardian permit-system (--add GATE CLASS SHA256 | --revoke ID)";

/// Removes the permits in `directory` that ended, or that `gone` names.
pub(super) fn remove_where(directory: &Path, gone: &dyn Fn(&str) -> bool) -> usize {
    let Ok(entries) = fs::read_dir(directory) else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_str().is_none_or(gone))
        .filter(|entry| fs::remove_file(entry.path()).is_ok())
        .count()
}

/// Whether the file `name` holds a permit that ended before `now`, or
/// nothing a permit is.
fn ended(directory: &Path, name: &str, now: u64) -> bool {
    fs::read_to_string(directory.join(name))
        .ok()
        .and_then(|text| Json::parse(&text).ok())
        .and_then(|json| json.get("expires")?.as_u64())
        .is_none_or(|expires| expires <= now)
}

/// Root's part of giving a permit: checks the shape of what it is given,
/// and writes the permit for `uid` in `directory`. Returns when it ends.
pub(super) fn add(
    directory: &Path,
    uid: u32,
    gate: &str,
    class: &str,
    key: &str,
    now: u64,
) -> Result<Permit, Error> {
    let gate = Gate::parse(gate)
        .filter(|gate| permits(*gate))
        .ok_or_else(|| Error::Refused(format!("{gate:?} is not a gate permits are for")))?;
    if classes(class).is_none() {
        return Err(Error::Refused(format!("{class:?} is not a class")));
    }
    if !is_hex(key, 64) {
        return Err(Error::Refused(
            "the content is named by its SHA-256 (64 hex characters)".into(),
        ));
    }
    fs::create_dir_all(directory).at(directory)?;
    let open = |path: &Path, mode: u32| {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).at(path)
    };
    // Whatever sudo's umask is, the gates run as the user and must be able
    // to read a permit.
    open(directory, 0o755)?;
    remove_where(directory, &|name| ended(directory, name, now));
    let prefix = format!("{uid}-");
    let held = fs::read_dir(directory)
        .at(directory)?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(&prefix))
        })
        .count();
    if held >= MAX_PERMITS {
        return Err(Error::Refused(
            "too many permits are in force; revoke some or let them end".into(),
        ));
    }
    let permit = Permit {
        uid,
        gate,
        class: class.to_string(),
        key: key.to_string(),
        expires: now + LIFETIME_SECS,
    };
    let path = directory.join(Permit::file_name(uid, gate, key));
    state::write_text_mode(&path, &permit.to_json(), 0o644)?;
    open(&path, 0o644)?;
    Ok(permit)
}

/// The user sudo says ran it: never root itself.
fn invoker() -> Option<u32> {
    std::env::var("SUDO_UID")
        .ok()
        .and_then(|uid| uid.parse::<u32>().ok())
        .filter(|uid| *uid != 0)
}

fn permit_entry(decision: &str, uid: u32) -> Entry {
    Entry::new(Event::Permit)
        .with(audit::DECISION, decision)
        .with(audit::FOR_UID, uid.to_string())
}

fn system_change(arguments: &[String]) -> Result<(), Error> {
    let uid = invoker().ok_or_else(|| {
        Error::Refused(
            "a permit is given to the user who asks through sudo: run `omarchy-guardian permit` as that user".into(),
        )
    })?;
    let directory = Path::new(DIRECTORY);
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["--add", gate, class, key] => {
            // The level is the root-owned system file's to say; the user's
            // file is not read here.
            let settings = Settings::system_only();
            if !enabled(&settings, class) {
                return Err(Error::Refused(
                    "permits are off under these system settings".into(),
                ));
            }
            let permit = add(directory, uid, gate, class, key, now())?;
            permit_entry("GRANTED", uid)
                .gate(permit.gate)
                .with(audit::CLASS, &permit.class)
                .with(audit::DIGEST, format!("content:{}", permit.key))
                .with(audit::PERMIT, &permit.key[..ID_CHARS])
                .with(audit::EXPIRES, permit.expires.to_string())
                .record();
            Ok(())
        }
        ["--revoke", id] if is_hex(id, ID_CHARS) => {
            let prefix = format!("{uid}-");
            let removed = remove_where(directory, &|name| {
                name.strip_prefix(&prefix)
                    .and_then(|rest| rest.split_once('-'))
                    .is_some_and(|(_, key)| key.starts_with(id))
            });
            if removed > 0 {
                permit_entry("REVOKED", uid)
                    .with(audit::PERMIT, *id)
                    .record();
            }
            Ok(())
        }
        _ => Err(Error::Refused(SYSTEM_USAGE.into())),
    }
}

/// `omarchy-guardian permit-system …`, run as root through sudo by
/// `permit`: the permits, which only root writes.
pub(crate) fn system_command(arguments: &[String]) -> ExitCode {
    if !user::effective_uid().is_ok_and(|uid| uid == 0) {
        errln!("omarchy-guardian permit-system: only `permit` runs this, as root");
        return ExitCode::from(2);
    }
    match system_change(arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            errln!("omarchy-guardian permit-system: {reason}");
            ExitCode::from(2)
        }
    }
}

/// `omarchy-guardian pacman-hook-result UID STATUS`, run by the pacman
/// hook's root half once the review, which runs as the user, has ended:
/// root's own line in the audit trail, which no user process can write,
/// and the end of a permit the transaction used.
pub(crate) fn hook_result_command(arguments: &[String]) -> ExitCode {
    if !user::effective_uid().is_ok_and(|uid| uid == 0) {
        errln!("omarchy-guardian pacman-hook-result: only the pacman hook runs this, as root");
        return ExitCode::from(2);
    }
    let [uid, status] = arguments else {
        errln!("usage: omarchy-guardian pacman-hook-result UID STATUS");
        return ExitCode::from(2);
    };
    let (Ok(uid), Ok(status)) = (uid.parse::<u32>(), status.parse::<u8>()) else {
        errln!("usage: omarchy-guardian pacman-hook-result UID STATUS");
        return ExitCode::from(2);
    };
    let permitted = status == PERMITTED_EXIT;
    if permitted {
        let prefix = format!("{uid}-{}-", Gate::Pacman.name());
        let removed = remove_where(Path::new(DIRECTORY), &|name| name.starts_with(&prefix));
        permit_entry("USED", uid)
            .gate(Gate::Pacman)
            .with(
                audit::SUBJECT,
                format!("{removed} pacman permit(s) removed"),
            )
            .record();
    }
    Entry::new(Event::Review)
        .gate(Gate::Pacman)
        .with(audit::SUBJECT, "the hook's root half: how the review ended")
        .with(audit::FOR_UID, uid.to_string())
        .decision(
            match status {
                0 => "PASSED",
                PERMITTED_EXIT => "PERMITTED",
                _ => "BLOCKED",
            },
            if permitted { 0 } else { status },
        )
        .record();
    ExitCode::SUCCESS
}
