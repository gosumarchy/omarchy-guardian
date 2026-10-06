//! A desktop notification when a gate blocks, so a block is seen even when
//! the terminal that ran yay, pacman or an Omarchy menu install has scrolled
//! past it or closed. The report is saved, and clicking the notification
//! opens it.

use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::output;
use crate::report::{Blocked, html};
use crate::text;
use crate::tools::{self, Limits};

const NOTIFY_SEND: &str = "/usr/bin/notify-send";
/// The knight with red eyes, installed by the package; a path, so it shows
/// whatever the icon theme.
const ALERT_ICON: &str = "/usr/share/icons/hicolor/scalable/apps/omarchy-guardian-alert.svg";
/// The knight as it is when nothing is wrong.
const ICON: &str = "/usr/share/icons/hicolor/scalable/apps/omarchy-guardian.svg";
/// Omarchy's launcher for the default browser, which opens the report.
const LAUNCH_BROWSER: &str = "/usr/share/omarchy/bin/omarchy-launch-browser";
const SETSID: &str = "/usr/bin/setsid";
/// Saved reports kept; older ones are removed.
const KEEP_REPORTS: usize = 20;
/// Set (to anything) by the test harnesses, whose blocks are expected: no
/// pop-up is shown and no browser opened. The report is saved all the same,
/// so a line in a shell start-up file cannot hide a block from the bar.
const QUIET: &str = "OMARCHY_GUARDIAN_NO_NOTIFY";

/// Waits for a click in the background, then opens the report. `$1`
/// notify-send, `$2` icon, `$3` title, `$4` body, `$5` launcher, `$6` the
/// report's file URL.
const ON_CLICK: &str = r#"action=$(timeout 1d "$1" --app-name="Omarchy Guardian" --urgency=critical \
    --icon="$2" --action=default="Open the report" -- "$3" "$4") || exit 0
[ "$action" = default ] || exit 0
exec "$5" "$6""#;

/// What of the blocked source had run when the gate stopped it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ran {
    /// Nothing: the block came before any of it ran.
    Nothing,
    /// makepkg had run the reviewed recipe to fetch and unpack the sources.
    RecipeToFetch,
    /// Nothing was blocked: the system sweep found these already in place.
    AlreadyOnSystem,
    /// Nothing was blocked: the user ran the sweep and asked for its page
    /// (`sweep --report`); `clear` when it found nothing to worry about.
    Swept { clear: bool },
}

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
pub fn blocked(what: &str, detail: &str, ran: Ran) {
    alert(&format!("Guardian blocked {what}"), detail, ran);
}

/// Shows "Guardian found `what`" for what the scheduled system sweep found,
/// with the same saved report and click-to-open as a block.
pub fn found(what: &str, detail: &str) {
    alert(
        &format!("Guardian found {what}"),
        detail,
        Ran::AlreadyOnSystem,
    );
}

/// Shows "Guardian protection changed" with `detail`: a gate that was on
/// is not, or a setting became weaker. Only a pop-up: there is no review
/// to save a report of.
pub fn changed(detail: &str) {
    popup(
        "Guardian protection changed",
        &format!(
            "{}\nOpen Guardian's settings to see why.",
            text::shown(detail)
        ),
    );
}

/// Shows "Guardian `version` is available" with how to upgrade (`how`).
/// Only a pop-up, like `changed`.
pub fn update(version: &str, how: &str) {
    // The calm knight: a release is no alarm.
    let icon = if Path::new(ICON).is_file() {
        ICON
    } else {
        "software-update-available"
    };
    popup_with(
        &format!("Guardian {} is available", text::shown(version)),
        &format!("To upgrade, {how}"),
        icon,
    );
}

fn popup(title: &str, body: &str) {
    popup_with(title, body, alert_icon());
}

fn popup_with(title: &str, body: &str, icon: &str) {
    if !popups() {
        return;
    }
    let env = session_env();
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let args = notify_args(title, body, icon);
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

/// Whether pop-ups are shown: not under the test harnesses, and not
/// without `notify-send`.
fn popups() -> bool {
    !cfg!(test) && env::var_os(QUIET).is_none() && Path::new(NOTIFY_SEND).is_file()
}

fn alert_icon() -> &'static str {
    if Path::new(ALERT_ICON).is_file() {
        ALERT_ICON
    } else {
        "security-high"
    }
}

fn alert(title: &str, detail: &str, ran: Ran) {
    if cfg!(test) {
        return;
    }
    let title = title.to_string();
    let detail = &text::shown(detail);
    // Saved whether or not a pop-up can be shown: the bar's last block
    // comes from here.
    let report = crate::engine::store::effective_uid()
        .ok()
        .and_then(|uid| save_report(&title, detail, ran, uid));
    if !popups() {
        return;
    }
    let icon = alert_icon();
    let env = session_env();
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    if let Some(report) = report.filter(|_| Path::new(LAUNCH_BROWSER).is_file()) {
        let body = format!("{detail}\nClick to open the full report.");
        let mut command = Command::new(SETSID);
        command
            .args(["-f", "/bin/sh", "-c", ON_CLICK, "sh", NOTIFY_SEND, icon])
            .arg(pango(&title))
            .arg(pango(&body))
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

    let args = notify_args(
        &title,
        &format!("{detail}\nSee the terminal for the full report."),
        icon,
    );
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

/// notify-send's arguments: the title and body after `--`, so neither can be
/// read as an option, and escaped for the Pango markup notification daemons
/// render.
fn notify_args(title: &str, body: &str, icon: &str) -> Vec<OsString> {
    [
        "--app-name=Omarchy Guardian".to_string(),
        "--urgency=critical".to_string(),
        format!("--icon={icon}"),
        "--".to_string(),
        pango(title),
        pango(body),
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

/// `text` for Pango markup, with hidden characters shown as codes and lines
/// kept.
fn pango(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text::shown_block(text).chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

/// Saves what this run printed as a report page and opens it in the
/// browser (not under the test harnesses); returns the page and its id for
/// `omarchy-guardian ask`. Nothing is saved as root.
pub fn save_and_open(title: &str, detail: &str, ran: Ran) -> Option<(PathBuf, String)> {
    let uid = crate::engine::store::effective_uid().ok()?;
    let path = save_report(title, detail, ran, uid)?;
    let id = path.file_stem()?.to_str()?.to_string();
    // Asked for and opened, it is seen; checked after saving, so an alert
    // saved meanwhile still keeps the bar's attention.
    if let Some(directory) = path.parent() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        crate::status::mark_seen_unless_waiting(directory, &id, now);
    }
    if env::var_os(QUIET).is_none() && Path::new(LAUNCH_BROWSER).is_file() {
        let env = session_env();
        let mut command = Command::new(SETSID);
        command
            .arg("-f")
            .arg(LAUNCH_BROWSER)
            .arg(format!("file://{}", path.display()))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (key, value) in &env {
            command.env(key, value);
        }
        drop(command.status());
    }
    Some((path, id))
}

/// Writes what this run printed, and why it blocked, to a private file under
/// `$XDG_CACHE_HOME/omarchy-guardian/reports`, keeping the newest few.
/// Root saves nothing: under `sudo -E` that directory is the user's, and
/// root would leave files there the user cannot remove, so the terminal
/// carries the report.
fn save_report(title: &str, detail: &str, ran: Ran, uid: u32) -> Option<PathBuf> {
    if uid == 0 {
        return None;
    }
    let directory = reports_dir()?;
    crate::engine::store::private_dir(&directory, uid).ok()?;
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let id = format!("{seconds}-{}", std::process::id());
    let captured = output::captured();
    // The page for people; the plain text for `omarchy-guardian ask`.
    let plain = format!("{title}: {detail}\n\n{}", html::strip_ansi(&captured));
    write_private(&directory.join(format!("{id}.txt")), &plain)?;
    let page = html::page(title, detail, ran, &html::utc(seconds), &id, &captured);
    let path = directory.join(format!("{id}.html"));
    write_private(&path, &page)?;
    prune(&directory, uid);
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

/// The time and process of a report id, `<seconds>-<pid>` in digits only:
/// the one shape Guardian saves. Anything else under that name is not a
/// report.
pub fn report_id(id: &str) -> Option<(u64, u64)> {
    let (seconds, pid) = id.split_once('-')?;
    let digits = |text: &str| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
    if !digits(seconds) || !digits(pid) {
        return None;
    }
    Some((seconds.parse().ok()?, pid.parse().ok()?))
}

/// Removes all but the newest `KEEP_REPORTS` reports, page and text alike,
/// by the time in their names. Only regular files owned by `uid` are
/// removed; a symlink named like a report is left alone, and so is a file
/// that is not named like one.
fn prune(directory: &Path, uid: u32) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    let mut pages: Vec<((u64, u64), PathBuf)> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter_map(|path| {
            let id = path.file_name()?.to_str()?.strip_suffix(".html")?;
            Some((report_id(id)?, path.clone()))
        })
        .collect();
    pages.sort();
    let pages: Vec<PathBuf> = pages.into_iter().map(|(_, path)| path).collect();
    let excess = pages.len().saturating_sub(KEEP_REPORTS);
    let owned_file = |path: &Path| {
        fs::symlink_metadata(path)
            .is_ok_and(|metadata| metadata.file_type().is_file() && metadata.uid() == uid)
    };
    for old in &pages[..excess] {
        for path in [old.with_extension("txt"), old.clone()] {
            if owned_file(&path) {
                drop(fs::remove_file(path));
            }
        }
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

    use std::os::unix::fs::{MetadataExt, symlink};

    use super::{
        KEEP_REPORTS, ON_CLICK, Ran, notify_args, pango, prune, real_uid, reason, save_report,
    };
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
        let uid = fs::metadata(dir.path()).unwrap().uid();
        prune(dir.path(), uid);
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

    #[test]
    fn a_symlink_named_like_a_report_is_not_removed() {
        let dir = TempDir::new("reports-link");
        let target = TempDir::new("reports-target");
        let victim = target.path().join("victim");
        fs::write(&victim, "keep").unwrap();
        symlink(&victim, dir.path().join("0000000000-1.html")).unwrap();
        for second in 1..=KEEP_REPORTS + 1 {
            fs::write(dir.path().join(format!("{second:010}-1.html")), "r").unwrap();
        }
        let uid = fs::metadata(dir.path()).unwrap().uid();
        prune(dir.path(), uid);
        assert!(dir.path().join("0000000000-1.html").is_symlink());
        assert!(!dir.path().join("0000000001-1.html").exists());
        assert!(victim.exists());
    }

    #[test]
    fn only_names_guardian_writes_are_report_ids() {
        use super::report_id;
        assert_eq!(
            report_id("1790792730-953463"),
            Some((1_790_792_730, 953_463))
        );
        assert!(report_id("999999-10") > report_id("999999-9"));
        for bad in [
            "zzz", "1-", "-2", "12", "1-2-3", "+1-2", "1-2 ", "1.5-2", "",
        ] {
            assert_eq!(report_id(bad), None, "{bad}");
        }
        // A name that is no report is never pruned as the oldest one.
        let dir = TempDir::new("reports-names");
        for second in 0..=KEEP_REPORTS {
            fs::write(dir.path().join(format!("{second}-1.html")), "r").unwrap();
        }
        fs::write(dir.path().join("zzz.html"), "other").unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();
        prune(dir.path(), uid);
        assert!(dir.path().join("zzz.html").exists());
        // By number: 0 is older than 10, whatever the text order says.
        assert!(!dir.path().join("0-1.html").exists());
        assert!(dir.path().join("10-1.html").exists());
    }

    #[test]
    fn root_saves_no_report() {
        assert_eq!(save_report("t", "d", Ran::Nothing, 0), None);
    }

    #[test]
    fn notification_text_is_never_an_option_or_markup() {
        let args = notify_args("--version", "b", "i");
        let position = args.iter().position(|arg| arg == "--").unwrap();
        assert_eq!(args[position + 1], "--version");
        assert_eq!(
            pango("<b>x</b> & \x1b[1m\nnext"),
            "&lt;b&gt;x&lt;/b&gt; &amp; \\u{1b}[1m\nnext"
        );
        assert!(ON_CLICK.contains(r#"-- "$3" "$4""#));
    }
}
