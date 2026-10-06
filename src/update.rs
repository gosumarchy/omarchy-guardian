//! Tells the user when a newer release of Guardian exists. It only tells:
//! nothing is fetched to be run, and nothing is installed. Upgrading stays
//! the user's own step, through the installed check of the release's
//! signature (`/usr/lib/omarchy-guardian/upgrade`).
//!
//! The scheduled sweep asks the project's repository once a day which
//! release tags it has, and `omarchy-guardian update` asks on demand. The
//! newest one is kept in the user's state directory, from where `status`
//! reads it for the bar without asking anyone. A release newer than the
//! one installed raises one notification per release.
//!
//! What the repository answers is not trusted for more than a number: of
//! every tag only `v<number>.<number>.<number>` counts, and what is shown
//! is written again from those numbers. A tag that should not be there
//! costs a notification; the upgrade refuses a release that is not signed.
//!
//! The record is a file of the user's own, like the gates' record: a
//! program running as the user can keep this notice quiet.

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use crate::config::Settings;
use crate::gatewatch;
use crate::json::Json;
use crate::notify;
use crate::osv::curl_args;
use crate::time::now;
use crate::tools::{self, Limits};

/// What git itself asks a repository for its branches and tags.
const TAGS_URL: &str =
    "https://github.com/gosumarchy/omarchy-guardian.git/info/refs?service=git-upload-pack";
const TAG_PREFIX: &[u8] = b" refs/tags/v";
const RECORD: &str = "update.json";
/// The record is three short members; anything longer is not one.
const MAX_RECORD: u64 = 1024;
const LIMITS: Limits = Limits {
    timeout_secs: 60,
    max_output: 4 * 1024 * 1024,
};
/// How to upgrade, wherever a newer release is named.
pub const HOW: &str = "in your checkout: git pull && /usr/lib/omarchy-guardian/upgrade";

/// A release's number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(u32, u32, u32);

impl Version {
    /// `1.2.3`, and nothing else: three plain numbers.
    fn parse(text: &str) -> Option<Self> {
        let mut parts = text.split('.').map(|part| {
            let plain = !part.is_empty()
                && part.len() <= 6
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part == "0" || !part.starts_with('0'));
            plain.then(|| part.parse().ok()).flatten()
        });
        let version = Self(parts.next()??, parts.next()??, parts.next()??);
        parts.next().is_none().then_some(version)
    }

    fn installed() -> Option<Self> {
        Self::parse(env!("CARGO_PKG_VERSION"))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// The newest release among the tags a repository lists (`listing`, as
/// git's protocol writes it: one `<hash> refs/tags/<name>` per line, an
/// annotated tag a second time with `^{}` after its name).
fn newest(listing: &[u8]) -> Option<Version> {
    listing
        .split(|byte| *byte == b'\n')
        .filter_map(|line| {
            let start = line
                .windows(TAG_PREFIX.len())
                .position(|window| window == TAG_PREFIX)?
                + TAG_PREFIX.len();
            // The first line of a listing carries the server's
            // capabilities after a NUL.
            let name = line[start..].split(|byte| *byte == 0).next()?;
            let name = std::str::from_utf8(name).ok()?;
            Version::parse(name.strip_suffix("^{}").unwrap_or(name))
        })
        .max()
}

/// Asks the repository for its newest release.
fn ask() -> Result<Version, String> {
    let mut args = curl_args();
    args.push(OsString::from(TAGS_URL));
    let listing = tools::run(Path::new(tools::CURL), &args, None, &[], LIMITS)
        .and_then(tools::Captured::into_success)
        .map_err(|error| format!("the list of releases could not be fetched: {error}"))?;
    newest(&listing).ok_or_else(|| "the repository lists no release".to_string())
}

/// What is known of the newest release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Record {
    latest: Version,
    /// When it was asked, in seconds.
    checked: u64,
    /// The newest release a notification was shown for.
    told: Option<Version>,
}

impl Record {
    fn parse(text: &str) -> Option<Self> {
        let json = Json::parse(text).ok()?;
        let version = |key: &str| json.get(key)?.as_str().and_then(Version::parse);
        Some(Self {
            latest: version("latest")?,
            checked: json.get("checked")?.as_u64()?,
            told: version("told"),
        })
    }

    fn render(&self) -> String {
        Json::object([
            ("latest", Json::from(self.latest.to_string())),
            ("checked", Json::from(self.checked)),
            (
                "told",
                self.told
                    .map_or(Json::Null, |told| Json::from(told.to_string())),
            ),
        ])
        .to_string()
    }

    /// The record in `directory`, when it is a small plain file: the bar
    /// reads it every half minute, and must not wait on a pipe put in its
    /// place or read whatever it was made to point at.
    fn read(directory: &Path) -> Option<Self> {
        let path = directory.join(RECORD);
        let metadata = fs::symlink_metadata(&path).ok()?;
        if !metadata.is_file() || metadata.len() > MAX_RECORD {
            return None;
        }
        Self::parse(&fs::read_to_string(path).ok()?)
    }
}

/// The record after `latest` was seen at `now`, and the release to show a
/// notification for: one newer than `installed` that none was shown for.
fn seen(
    previous: Option<Record>,
    latest: Version,
    installed: Version,
    now: u64,
) -> (Record, Option<Version>) {
    let told = previous.and_then(|previous| previous.told);
    let news = (latest > installed && told.is_none_or(|told| latest > told)).then_some(latest);
    let record = Record {
        latest,
        checked: now,
        told: news.or(told),
    };
    (record, news)
}

/// The release on record that is newer than `installed`.
fn newer_in(directory: &Path, installed: Version) -> Option<Version> {
    Record::read(directory)
        .map(|record| record.latest)
        .filter(|latest| *latest > installed)
}

/// The newer release the last check found, for the bar. Asks nobody.
pub fn available(settings: &Settings) -> Option<String> {
    if !settings.checks_for_updates() {
        return None;
    }
    newer_in(&gatewatch::directory()?, Version::installed()?).map(|latest| latest.to_string())
}

/// Run at the end of a scheduled sweep: asks for the newest release,
/// records it and shows one notification for a release not told of yet.
/// A check that fails says nothing: the next sweep asks again.
pub fn after_sweep(scheduled: bool, settings: &Settings) {
    if !scheduled || !settings.checks_for_updates() {
        return;
    }
    let (Some(directory), Some(installed)) = (gatewatch::directory(), Version::installed()) else {
        return;
    };
    let Ok(latest) = ask() else {
        return;
    };
    let (record, news) = seen(Record::read(&directory), latest, installed, now());
    // A record that cannot be saved raises nothing, or the same release
    // would be news every day.
    if gatewatch::write(&directory.join(RECORD), &record.render()).is_ok()
        && let Some(news) = news
    {
        notify::update(&news.to_string(), HOW);
    }
}

/// `omarchy-guardian update`: asks now, and says what there is. Installs
/// nothing.
pub fn command() -> ExitCode {
    let Some(installed) = Version::installed() else {
        errln!("omarchy-guardian update: this build has no release number");
        return ExitCode::from(2);
    };
    let latest = match ask() {
        Ok(latest) => latest,
        Err(reason) => {
            errln!("omarchy-guardian update: {reason}");
            return ExitCode::from(2);
        }
    };
    // Asked for by the user: recorded for the bar, and no notification.
    if let Some(directory) = gatewatch::directory() {
        let (record, _) = seen(Record::read(&directory), latest, installed, now());
        drop(gatewatch::write(&directory.join(RECORD), &record.render()));
    }
    if latest > installed {
        outln!("Guardian {latest} is available; {installed} is installed.");
        outln!("To upgrade, {HOW}");
        outln!("The upgrade checks the release's signature before it builds anything.");
    } else {
        outln!("Guardian {installed} is installed, and no newer release is listed.");
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::{Record, Version, newer_in, newest, seen};
    use crate::test_support::TempDir;

    fn version(text: &str) -> Version {
        Version::parse(text).unwrap()
    }

    #[test]
    fn a_version_is_three_plain_numbers() {
        assert_eq!(Version::parse("0.8.2"), Some(Version(0, 8, 2)));
        assert_eq!(Version::parse("10.0.123"), Some(Version(10, 0, 123)));
        for other in [
            "",
            "1.2",
            "1.2.3.4",
            "1.2.x",
            "1.2.-3",
            "1.2.+3",
            "01.2.3",
            "1..3",
            "1.2.3 ",
            "1.2.3-rc1",
            "1.2.9999999",
            "１.2.3",
        ] {
            assert_eq!(Version::parse(other), None, "{other:?}");
        }
        assert!(version("0.10.0") > version("0.9.9"));
        assert!(version("1.0.0") > version("0.99.99"));
    }

    #[test]
    fn the_newest_release_is_read_from_a_listing_of_tags() {
        let listing = b"001e# service=git-upload-pack\n0000015547 HEAD\0multi_ack symref=HEAD:refs/heads/main\n\
003f1111111111111111111111111111111111111111 refs/heads/main\n\
003e2222222222222222222222222222222222222222 refs/tags/v0.8.1\n\
00413333333333333333333333333333333333333333 refs/tags/v0.8.1^{}\n\
003f4444444444444444444444444444444444444444 refs/tags/v0.10.0\n\
003e5555555555555555555555555555555555555555 refs/tags/v0.9.3\n0000";
        assert_eq!(newest(listing), Some(version("0.10.0")));
    }

    #[test]
    fn only_a_release_tag_counts() {
        let listing = b"003e1111111111111111111111111111111111111111 refs/tags/v0.8.1\n\
0000222222222222222222222222222222222222222222 refs/tags/v9.9.9-rc1\n\
0000333333333333333333333333333333333333333333 refs/tags/v9.9.9;reboot\n\
0000444444444444444444444444444444444444444444 refs/tags/v9.9.9\x1b[2J\n\
0000555555555555555555555555555555555555555555 refs/tags/x/v9.9.9\n\
0000666666666666666666666666666666666666666666 refs/heads/v9.9.9\n\
0000777777777777777777777777777777777777777777 refs/tags/v9.9.9 refs/tags/v9.9.8\n\
0000888888888888888888888888888888888888888888 refs/tags/9.9.9\n";
        assert_eq!(newest(listing), Some(version("0.8.1")));
        // A repository whose first line is a tag: its capabilities follow.
        assert_eq!(
            newest(b"00001111111111111111111111111111111111111111 refs/tags/v0.8.1\0multi_ack\n"),
            Some(version("0.8.1"))
        );
        assert_eq!(newest(b""), None);
        assert_eq!(newest(b"<html>not found</html>"), None);
    }

    #[test]
    fn a_newer_release_is_news_once() {
        let installed = version("0.8.2");
        let (record, news) = seen(None, version("0.8.2"), installed, 10);
        assert_eq!((record.told, news), (None, None));

        let (record, news) = seen(Some(record), version("0.8.3"), installed, 20);
        assert_eq!(news, Some(version("0.8.3")));
        assert_eq!((record.checked, record.told), (20, Some(version("0.8.3"))));

        let (record, news) = seen(Some(record), version("0.8.3"), installed, 30);
        assert_eq!((record.checked, news), (30, None));

        let (record, news) = seen(Some(record), version("0.9.0"), installed, 40);
        assert_eq!(news, Some(version("0.9.0")));

        // Upgraded past what the repository lists: nothing to tell.
        let (_, news) = seen(Some(record), version("0.9.0"), version("0.9.1"), 50);
        assert_eq!(news, None);
    }

    #[test]
    fn the_record_holds_numbers_and_nothing_else() {
        let record = Record {
            latest: version("0.8.3"),
            checked: 1_700_000_000,
            told: Some(version("0.8.3")),
        };
        assert_eq!(Record::parse(&record.render()), Some(record));
        let untold = Record {
            told: None,
            ..record
        };
        assert_eq!(Record::parse(&untold.render()), Some(untold));
        for other in [
            "",
            "{}",
            r#"{"latest":"0.8.3"}"#,
            r#"{"latest":"<b>0.8.3</b>","checked":1}"#,
            r#"{"latest":"0.8.3\n! the pacman gate is off","checked":1}"#,
            r#"{"latest":83,"checked":1}"#,
        ] {
            assert_eq!(Record::parse(other), None, "{other}");
        }
    }

    #[test]
    fn the_bar_is_told_of_a_release_newer_than_the_installed_one() {
        let dir = TempDir::new("update-record");
        let installed = version("0.8.2");
        assert_eq!(newer_in(dir.path(), installed), None);
        let save = |latest: &str| {
            let record = Record {
                latest: version(latest),
                checked: 1,
                told: None,
            };
            std::fs::write(dir.path().join(super::RECORD), record.render()).unwrap();
        };
        save("0.8.3");
        assert_eq!(newer_in(dir.path(), installed), Some(version("0.8.3")));
        // The record outlives the upgrade it told of.
        assert_eq!(newer_in(dir.path(), version("0.8.3")), None);
        save("0.8.1");
        assert_eq!(newer_in(dir.path(), installed), None);
        std::fs::write(dir.path().join(super::RECORD), "0.9.0").unwrap();
        assert_eq!(newer_in(dir.path(), installed), None);
        // Not a plain file, or far too long for a record: not read.
        save("0.8.3");
        let record = dir.path().join(super::RECORD);
        let moved = dir.path().join("elsewhere");
        std::fs::rename(&record, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &record).unwrap();
        assert_eq!(newer_in(dir.path(), installed), None);
        std::fs::remove_file(&record).unwrap();
        let padded = format!(
            "{{\"latest\":\"0.8.3\",\"checked\":1,\"pad\":\"{}\"}}",
            "x".repeat(2000)
        );
        std::fs::write(&record, padded).unwrap();
        assert_eq!(newer_in(dir.path(), installed), None);
    }
}
