//! The root half of the system allow-list: asking for a change through
//! sudo, and making it as root.

use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

use super::{SUDO, installed};
use crate::error::Error;
use crate::sweep::state::{self, Remembered};
use crate::user;

/// Runs the installed Guardian's `command` with `arguments` as root,
/// through sudo, which asks for the password on the terminal, to do
/// `what` ("changing ..."), which is said first. What only root may write
/// is written this way: by the installed, root-owned program, never by the
/// one that is running.
pub(crate) fn as_root(command: &str, arguments: &[&str], what: &str) -> Result<(), Error> {
    let program = installed()?;
    errln!("Guardian needs root for {what}; it asks for your password.");
    let status = Command::new(SUDO)
        .arg(program)
        .arg(command)
        .args(arguments)
        .stdin(Stdio::inherit())
        .status()
        .map_err(|error| Error::Refused(format!("cannot start sudo: {error}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::Refused(format!(
            "{what} failed ({status}); nothing was changed. If the installed Guardian is older than this one, run ./install.sh"
        )))
    }
}

/// Changes the system's list of allowed items through sudo (see
/// `system_allow_command`).
pub(crate) fn system_allow(arguments: &[&str]) -> Result<(), Error> {
    as_root(
        "sweep-allow-system",
        arguments,
        "changing the system's allowed items",
    )
}

/// The longest label and fingerprint the system's list takes.
const MAX_LABEL: usize = 4096;
const MAX_FINGERPRINT: usize = 8192;

const ALLOW_USAGE: &str = "usage: omarchy-guardian sweep-allow-system (--add LABEL FINGERPRINT | --remove LABEL | --clear)...";

/// Applies the changes `arguments` ask for to the system's list. A label
/// in a home (`~/…`) is kept for `invoker`, the user who ran sudo, and for
/// nobody else: root, who has no such user, cannot add one. `--clear`
/// drops the system's items and that user's, and leaves other users' home
/// items alone.
pub(super) fn change_allowed(
    allowed: &mut Remembered,
    arguments: &[String],
    invoker: Option<u32>,
) -> Result<(), String> {
    let key = |label: &str| -> Result<String, String> {
        let plain = label.len() <= MAX_LABEL && !label.chars().any(char::is_control);
        if state::is_home_label(label) && plain {
            invoker.map(|uid| state::system_key(label, uid)).ok_or_else(|| {
                "an item in a home is allowed for the user who asks: run `sweep allow` as that user".to_string()
            })
        } else if label.starts_with('/') && plain {
            Ok(label.to_string())
        } else {
            Err(format!("{label:?} is not a label the sweep shows"))
        }
    };
    if arguments.is_empty() {
        return Err(ALLOW_USAGE.into());
    }
    let mut rest = arguments;
    while let Some((flag, tail)) = rest.split_first() {
        rest = match (flag.as_str(), tail) {
            ("--add", [label, fingerprint, tail @ ..]) => {
                if fingerprint.is_empty()
                    || fingerprint.len() > MAX_FINGERPRINT
                    || fingerprint.chars().any(char::is_control)
                {
                    return Err(format!("{label}: not a fingerprint"));
                }
                allowed.insert(key(label)?, fingerprint.clone());
                tail
            }
            ("--remove", [label, tail @ ..]) => {
                allowed.remove(&key(label)?);
                tail
            }
            ("--clear", tail) => {
                allowed.retain(|key, _| {
                    key.split_once(':').is_some_and(|(owner, label)| {
                        state::is_home_label(label)
                            && owner.parse::<u32>().is_ok_and(|uid| Some(uid) != invoker)
                    })
                });
                tail
            }
            _ => return Err(ALLOW_USAGE.into()),
        };
    }
    Ok(())
}

/// The changes `arguments` ask for as the audit trail keeps them: the
/// labels, without their fingerprints.
fn changes_asked(arguments: &[String]) -> String {
    let mut asked = Vec::new();
    let mut rest = arguments;
    while let Some((flag, tail)) = rest.split_first() {
        rest = match (flag.as_str(), tail) {
            ("--add", [label, _, tail @ ..]) => {
                asked.push(format!("allow {label}"));
                tail
            }
            ("--remove", [label, tail @ ..]) => {
                asked.push(format!("forget {label}"));
                tail
            }
            (_, tail) => {
                asked.push("forget everything".to_string());
                tail
            }
        };
    }
    asked.join("; ")
}

/// `omarchy-guardian sweep-allow-system (--add LABEL FINGERPRINT | --remove
/// LABEL | --clear)...`, run as root through sudo by `sweep allow` and
/// `sweep forget`: the list of allowed items, which only root writes. The
/// user it acts for is the one sudo says ran it (`SUDO_UID`).
pub(crate) fn system_allow_command(arguments: &[String]) -> ExitCode {
    if !user::effective_uid().is_ok_and(|uid| uid == 0) {
        errln!("omarchy-guardian sweep-allow-system: only `sweep allow` runs this, as root");
        return ExitCode::from(2);
    }
    let invoker = std::env::var("SUDO_UID")
        .ok()
        .and_then(|uid| uid.parse::<u32>().ok())
        .filter(|uid| *uid != 0);
    let path = Path::new(state::SYSTEM_ALLOWED);
    if let Err(error) = state::move_legacy_allowed(path, Path::new(state::LEGACY_SYSTEM_ALLOWED)) {
        errln!("omarchy-guardian sweep-allow-system: {error}");
        return ExitCode::from(2);
    }
    let mut allowed = state::system_allowed(path);
    if let Err(reason) = change_allowed(&mut allowed, arguments, invoker) {
        errln!("omarchy-guardian sweep-allow-system: {reason}");
        return ExitCode::from(2);
    }
    match state::save_system_allowed(path, &allowed) {
        Ok(()) => {
            crate::audit::allow_list_changed(&changes_asked(arguments), invoker);
            ExitCode::SUCCESS
        }
        Err(error) => {
            errln!("omarchy-guardian sweep-allow-system: {error}");
            ExitCode::from(2)
        }
    }
}
