//! A desktop notification when a gate blocks, so a block is seen even when
//! the terminal that ran yay, pacman or an Omarchy menu install has scrolled
//! past it or closed. The report is saved, and clicking the notification
//! opens it.

use std::env;
use std::ffi::OsString;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::output;
use crate::report::{Blocked, html};
use crate::tools::{self, Limits};

const NOTIFY_SEND: &str = "/usr/bin/notify-send";
/// The knight with red eyes, installed by the package; a path, so it shows
/// whatever the icon theme.
const ALERT_ICON: &str = "/usr/share/icons/hicolor/scalable/apps/omarchy-guardian-alert.svg";
/// Omarchy's launcher for the default browser, which opens the report.
const LAUNCH_BROWSER: &str = "/usr/share/omarchy/bin/omarchy-launch-browser";
const SETSID: &str = "/usr/bin/setsid";
/// Saved reports kept; older ones are removed.
const KEEP_REPORTS: usize = 20;
/// Set (to anything) by the test harnesses, whose blocks are expected.
const QUIET: &str = "OMARCHY_GUARDIAN_NO_NOTIFY";

/// Waits for a click in the background, then opens the report. `$1`
/// notify-send, `$2` icon, `$3` title, `$4` body, `$5` launcher, `$6` the
/// report's file URL.
const ON_CLICK: &str = r#"action=$(timeout 1d "$1" --app-name="Omarchy Guardian" --urgency=critical \
    --icon="$2" --action=default="Open the report" "$3" "$4") || exit 0
[ "$action" = default ] || exit 0
exec "$5" "$6""#;

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
    if cfg!(test) || env::var_os(QUIET).is_some() || !Path::new(NOTIFY_SEND).is_file() {
        return;
    }
    let title = format!("Guardian blocked {what}");
    let icon = if Path::new(ALERT_ICON).is_file() {
        ALERT_ICON
    } else {
        "security-high"
    };
    let env = session_env();
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();

    let report = save_report(&title, detail);
    if let Some(report) = report.filter(|_| Path::new(LAUNCH_BROWSER).is_file()) {
        let body = format!("{detail}\nClick to open the full report.");
        let mut command = Command::new(SETSID);
        command
            .args(["-f", "/bin/sh", "-c", ON_CLICK, "sh", NOTIFY_SEND, icon])
            .arg(&title)
            .arg(&body)
            .arg(LAUNCH_BROWSER)
            .arg(format!("file://{}", report.display()))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (key, value) in &env {
            command.env(key, value);
        }
        // `setsid -f` forks the waiting shell off and exits at once, so no
        // gate (least of all pacman's hook) waits for the click.
        if command.status().is_ok_and(|status| status.success()) {
            return;
        }
    }

    let args: Vec<OsString> = [
        "--app-name=Omarchy Guardian".to_string(),
        "--urgency=critical".to_string(),
        format!("--icon={icon}"),
        title,
        format!("{detail}\nSee the terminal for the full report."),
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

/// Writes what this run printed, and why it blocked, to a private file under
/// `$XDG_CACHE_HOME/omarchy-guardian/reports`, keeping the newest few.
fn save_report(title: &str, detail: &str) -> Option<PathBuf> {
    let directory = reports_dir()?;
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&directory)
        .ok()?;
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let id = format!("{seconds}-{}", std::process::id());
    let captured = output::captured();
    // The page for people; the plain text for `omarchy-guardian ask`.
    let plain = format!("{title}: {detail}\n\n{}", html::strip_ansi(&captured));
    write_private(&directory.join(format!("{id}.txt")), &plain)?;
    let page = html::page(title, detail, &html::utc(seconds), &id, &captured);
    let path = directory.join(format!("{id}.html"));
    write_private(&path, &page)?;
    prune(&directory);
    Some(path)
}

fn write_private(path: &Path, text: &str) -> Option<()> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| file.write_all(text.as_bytes()))
        .ok()
}

/// The reports directory: `$XDG_CACHE_HOME/omarchy-guardian/reports`.
pub fn reports_dir() -> Option<PathBuf> {
    let base = env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))?;
    Some(base.join("omarchy-guardian/reports"))
}

/// Removes all but the newest `KEEP_REPORTS` reports, page and text alike
/// (names start with the time, so they sort by age).
fn prune(directory: &Path) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    let mut pages: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "html")
        })
        .collect();
    pages.sort();
    let excess = pages.len().saturating_sub(KEEP_REPORTS);
    for old in &pages[..excess] {
        drop(fs::remove_file(old.with_extension("txt")));
        drop(fs::remove_file(old));
    }
}

/// The session bus and runtime directory: the environment's, else the
/// user's standard ones, which the pacman hook needs because it runs with an
/// empty environment. The launcher reaches the desktop through them.
fn session_env() -> Vec<(&'static str, String)> {
    let mut env = Vec::new();
    let runtime = env::var("XDG_RUNTIME_DIR").ok().or_else(|| {
        let uid = real_uid(&fs::read_to_string("/proc/self/status").ok()?)?;
        let directory = format!("/run/user/{uid}");
        Path::new(&directory).is_dir().then_some(directory)
    });
    if let Some(runtime) = runtime {
        if env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none()
            && Path::new(&runtime).join("bus").exists()
        {
            env.push((
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={runtime}/bus"),
            ));
        }
        env.push(("XDG_RUNTIME_DIR", runtime));
    }
    if let Ok(path) = env::var("PATH")
        && !path
            .split(':')
            .any(|entry| entry == "/usr/share/omarchy/bin")
    {
        env.push(("PATH", format!("{path}:/usr/share/omarchy/bin")));
    }
    env
}

/// The real uid of this process.
pub fn current_uid() -> Option<u32> {
    real_uid(&fs::read_to_string("/proc/self/status").ok()?)
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
    use std::fs;

    use super::{KEEP_REPORTS, prune, real_uid, reason};
    use crate::report::Blocked;
    use crate::test_support::TempDir;

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

    #[test]
    fn only_the_newest_reports_are_kept() {
        let dir = TempDir::new("reports");
        for second in 0..KEEP_REPORTS + 3 {
            fs::write(dir.path().join(format!("{second:010}-1.html")), "r").unwrap();
            fs::write(dir.path().join(format!("{second:010}-1.txt")), "r").unwrap();
        }
        fs::write(dir.path().join("keep.log"), "other").unwrap();
        prune(dir.path());
        let mut left: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(left.len(), 2 * KEEP_REPORTS + 1);
        assert_eq!(left[0], "0000000003-1.html");
        assert_eq!(left[1], "0000000003-1.txt");
        assert!(left.contains(&"keep.log".to_string()));
    }
}
