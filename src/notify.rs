//! A desktop notification when a gate blocks, so a block is seen even when
//! the terminal that ran yay, pacman or an Omarchy menu install has scrolled
//! past it or closed.

use std::ffi::OsString;
use std::fs;
use std::path::Path;

use crate::report::Blocked;
use crate::tools::{self, Limits};

const NOTIFY_SEND: &str = "/usr/bin/notify-send";

/// Why a gate blocked, in a few words for the notification.
pub const fn reason(blocked: Blocked) -> &'static str {
    match blocked {
        Blocked::Findings => "the review found a risk",
        Blocked::Incomplete => "the review could not be completed",
        Blocked::AiUnavailable => "the AI reviewer was unavailable",
        Blocked::NotConfirmed => "it was not confirmed",
    }
}

/// Shows "Guardian blocked `what`" with `detail`, best effort: nothing
/// happens without `notify-send` or a session bus, and a failure is ignored,
/// because the terminal already carries the full report.
pub fn blocked(what: &str, detail: &str) {
    if cfg!(test) || !Path::new(NOTIFY_SEND).is_file() {
        return;
    }
    let bus = session_bus();
    let mut env = Vec::new();
    if let Some(bus) = &bus {
        env.push(("DBUS_SESSION_BUS_ADDRESS", bus.as_str()));
    }
    let args: Vec<OsString> = [
        "--app-name=Omarchy Guardian",
        "--urgency=critical",
        "--icon=security-high",
        &format!("Guardian blocked {what}"),
        &format!("{detail}\nSee the terminal for the full report."),
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    drop(tools::run(
        Path::new(NOTIFY_SEND),
        &args,
        None,
        &env,
        Limits {
            timeout_secs: 5,
            max_output: 4096,
        },
    ));
}

/// The session bus address: the environment's, else the user's standard
/// socket, which the pacman hook needs because it runs with an empty
/// environment.
fn session_bus() -> Option<String> {
    if let Some(address) = std::env::var_os("DBUS_SESSION_BUS_ADDRESS") {
        return address.into_string().ok();
    }
    let uid = real_uid(&fs::read_to_string("/proc/self/status").ok()?)?;
    let socket = format!("/run/user/{uid}/bus");
    Path::new(&socket)
        .exists()
        .then(|| format!("unix:path={socket}"))
}

fn real_uid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::{real_uid, reason};
    use crate::report::Blocked;

    #[test]
    fn reads_the_real_uid_from_proc_status() {
        let status = "Name:\tomarchy-guardian\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\n";
        assert_eq!(real_uid(status), Some(1000));
        assert_eq!(real_uid("Name:\tx\n"), None);
    }

    #[test]
    fn every_block_has_a_reason() {
        assert_eq!(reason(Blocked::Findings), "the review found a risk");
        assert!(!reason(Blocked::AiUnavailable).is_empty());
    }
}
