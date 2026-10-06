//! `omarchy-guardian log`: the audit trail, read back from the journal.
//!
//! The entries are whatever the journal holds under Guardian's identifier,
//! and any user can write one. What journald adds itself cannot be forged:
//! above all `_UID`, the user id of the process that sent the entry. So
//! every line starts, after its time, with who wrote it: `root` for
//! Guardian's root halves (which no user process can pass for), `you` for
//! the reader (Guardian run by them, or any program running as them),
//! `uid N` for another user, `?` for nobody the journal could name. That
//! column is made from journald's own fields alone and stands before
//! anything the sender wrote; what the sender wrote is shown with every
//! run of blanks as one, so it cannot hold the two blanks that part the
//! columns and pass for a column of its own.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::io::{self, Write as _};
use std::path::Path;
use std::process::ExitCode;

use super::{
    AI, CLASS, DECISION, DIGEST, EVENT, EXIT, Event, FINDINGS, FOR_UID, FROM, GATE, IDENTIFIER,
    OFFERED, OVERRULED, PERMIT, PROFILE, SUBJECT, TEST, VERSION,
};
use crate::json::Json;
use crate::notify;
use crate::text::shown;
use crate::time::utc;
use crate::tools::{self, Limits};

const JOURNALCTL: &str = "/usr/bin/journalctl";
const LIMITS: Limits = Limits {
    timeout_secs: 60,
    max_output: 64 * 1024 * 1024,
};
const DEFAULT_ENTRIES: usize = 50;
const MAX_ENTRIES: usize = 10_000;
const MAX_SUBJECT_CHARS: usize = 72;
const DIGEST_CHARS: usize = 12;
const USAGE: &str = "usage: omarchy-guardian log [--since TIME] [-n N] [--json]";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    /// A time as journalctl takes one (`yesterday`, `2026-01-31`, `-2h`).
    since: Option<String>,
    /// The newest entries shown.
    entries: usize,
    json: bool,
}

/// A time for `journalctl --since`: short, and of the characters its time
/// formats are made of.
fn is_time(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || " :-+.".contains(character))
}

pub fn parse(args: &[OsString]) -> Result<Options, String> {
    let mut options = Options {
        since: None,
        entries: DEFAULT_ENTRIES,
        json: false,
    };
    let mut args = args.iter().map(|arg| arg.to_str().ok_or(USAGE));
    while let Some(arg) = args.next() {
        match arg? {
            "--json" => options.json = true,
            "--since" => {
                let time = args.next().ok_or(USAGE)??;
                if !is_time(time) {
                    return Err(format!(
                        "--since takes a time as journalctl does (yesterday, 2026-01-31, -2h), not {time:?}"
                    ));
                }
                options.since = Some(time.to_string());
            }
            "-n" => {
                options.entries = args
                    .next()
                    .ok_or(USAGE)??
                    .parse::<usize>()
                    .ok()
                    .filter(|count| (1..=MAX_ENTRIES).contains(count))
                    .ok_or_else(|| format!("-n takes a number from 1 to {MAX_ENTRIES}"))?;
            }
            _ => return Err(USAGE.into()),
        }
    }
    Ok(options)
}

/// Who the journal says wrote an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Writer {
    /// The user reading the log: Guardian run by them, or anything else
    /// that runs as them.
    Reader,
    /// Root: one of Guardian's root halves, or root itself.
    Root,
    /// Another user.
    Other(u32),
    /// The journal names no user.
    Unknown,
}

impl Writer {
    /// The first column of a line.
    fn column(self) -> String {
        match self {
            Self::Root => "root".to_string(),
            Self::Reader => "you".to_string(),
            Self::Other(uid) => format!("uid {uid}"),
            Self::Unknown => "?".to_string(),
        }
    }
}

/// One entry, as far as the log shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Line {
    /// Seconds since the epoch, by the journal's own clock.
    at: u64,
    writer: Writer,
    /// Sent the way Guardian sends entries: by `logger`, to the journal's
    /// own socket.
    by_logger: bool,
    fields: Vec<(&'static str, String)>,
    /// The entry's message, for one without Guardian's fields.
    message: String,
}

/// The fields the log shows or passes on.
const SHOWN: [&str; 16] = [
    EVENT, GATE, CLASS, SUBJECT, DIGEST, DECISION, EXIT, FINDINGS, AI, PROFILE, VERSION, PERMIT,
    OVERRULED, OFFERED, FOR_UID, FROM,
];

impl Line {
    fn of(entry: &Json, reader: Option<u32>) -> Self {
        let text = |field: &str| entry.get(field).and_then(Json::as_str).unwrap_or_default();
        let writer = match text("_UID").parse::<u32>() {
            Ok(0) => Writer::Root,
            Ok(uid) if Some(uid) == reader => Writer::Reader,
            Ok(uid) => Writer::Other(uid),
            Err(_) => Writer::Unknown,
        };
        let mut fields: Vec<(&'static str, String)> = SHOWN
            .iter()
            .filter(|field| !text(field).is_empty())
            .map(|field| (*field, text(field).to_string()))
            .collect();
        if !text(TEST).is_empty() {
            fields.push((TEST, "1".into()));
        }
        Self {
            at: text("__REALTIME_TIMESTAMP").parse::<u64>().unwrap_or(0) / 1_000_000,
            writer,
            // journald may not get to read a short-lived sender's name: a
            // missing one says nothing, another one does.
            by_logger: text("_TRANSPORT") == "journal" && matches!(text("_COMM"), "" | "logger"),
            fields,
            message: text("MESSAGE").to_string(),
        }
    }

    fn field(&self, name: &str) -> &str {
        self.fields
            .iter()
            .find(|(field, _)| *field == name)
            .map_or("", |(_, value)| value.as_str())
    }

    /// What else is said about the entry, at the end of its line: how it
    /// was sent, and whether a test harness wrote it. Who wrote it is
    /// never said here, where a sender's own text could say the same.
    fn marks(&self) -> String {
        let mut marks = Vec::new();
        if !self.by_logger || self.field(EVENT).is_empty() {
            marks.push("[! not written as Guardian writes]".to_string());
        }
        if !self.field(TEST).is_empty() {
            marks.push("[test]".to_string());
        }
        marks.join(" ")
    }

    /// The start of the first digest, and how many more there are.
    fn digest(&self) -> String {
        let mut digests = self
            .field(DIGEST)
            .split(' ')
            .filter(|part| !part.is_empty());
        let Some(first) = digests.next() else {
            return String::new();
        };
        let hex = first.rsplit(['=', ':']).next().unwrap_or(first);
        let start: String = hex.chars().take(DIGEST_CHARS).collect();
        match digests.count() {
            0 => start,
            more => format!("{start} +{more}"),
        }
    }

    /// The entry on one line, without its time: who wrote it first.
    fn rendered(&self) -> String {
        // A sender's text, bounded, with every run of blanks (of any
        // kind) as one: two in a row part the columns, and only this
        // function writes them.
        let brief = |text: &str, limit: usize| -> String {
            let shown = shown(text);
            let one: Vec<&str> = shown.split_whitespace().collect();
            let one = one.join(" ");
            if one.chars().count() <= limit {
                one
            } else {
                let mut cut: String = one.chars().take(limit).collect();
                cut.push('…');
                cut
            }
        };
        let writer = self.writer.column();
        let event = self.field(EVENT);
        if event.is_empty() {
            return format!(
                "{writer:<8}  {}  {}",
                brief(&self.message, 100),
                self.marks()
            );
        }
        let gate = self.field(GATE);
        let mut line = format!(
            "{writer:<8}  {:<15}  {:<8}",
            brief(self.field(DECISION), 40),
            brief(if gate.is_empty() { event } else { gate }, 8),
        );
        let mut add = |text: String| {
            if !text.is_empty() {
                let _ = write!(line, "  {text}");
            }
        };
        add(brief(self.field(SUBJECT), MAX_SUBJECT_CHARS));
        for (label, field) in [
            ("permit", PERMIT),
            ("overrules", OVERRULED),
            ("for user", FOR_UID),
        ] {
            if !self.field(field).is_empty() {
                add(format!("{label} {}", brief(self.field(field), 40)));
            }
        }
        add(brief(&self.digest(), 80));
        add(self.marks());
        line.trim_end().to_string()
    }

    fn to_json(&self) -> Json {
        let mut members: Vec<(&str, Json)> = vec![("time", Json::from(self.at))];
        members.push((
            "written_by",
            Json::from(match self.writer {
                Writer::Reader => "you",
                Writer::Root => "root",
                Writer::Other(_) => "another-user",
                Writer::Unknown => "unknown",
            }),
        ));
        if let Writer::Other(uid) = self.writer {
            members.push(("uid", Json::from(u64::from(uid))));
        }
        members.push(("as_guardian_writes", Json::from(self.by_logger)));
        for (field, value) in &self.fields {
            members.push((field, Json::from(value.as_str())));
        }
        if self.field(EVENT).is_empty() {
            members.push(("MESSAGE", Json::from(self.message.as_str())));
        }
        Json::object(members)
    }
}

/// The entries of journalctl's JSON output, one a line; a line that is no
/// entry is left out.
fn lines(output: &str, reader: Option<u32>) -> Vec<Line> {
    output
        .lines()
        .filter_map(|line| Json::parse(line).ok())
        .filter(|entry| entry.as_object().is_some())
        .map(|entry| Line::of(&entry, reader))
        .collect()
}

/// The lines as the terminal shows them: each with its time, and one that
/// repeats the line before it counted instead of said again (yay calls the
/// makepkg gate several times for one build).
fn rendered(lines: &[Line]) -> Vec<String> {
    let mut out: Vec<(String, String, usize)> = Vec::new();
    for line in lines {
        let text = line.rendered();
        match out.last_mut() {
            Some((_, last, count)) if *last == text => *count += 1,
            _ => out.push((utc(line.at), text, 1)),
        }
    }
    out.into_iter()
        .map(|(time, text, count)| {
            if count > 1 {
                format!("{time}  {text}  ×{count}")
            } else {
                format!("{time}  {text}")
            }
        })
        .collect()
}

fn read(options: &Options) -> Result<(String, String), String> {
    let mut arguments: Vec<OsString> = vec![
        "--no-pager".into(),
        "--quiet".into(),
        "--all".into(),
        "--output=json".into(),
        format!("--identifier={IDENTIFIER}").into(),
        format!("--lines={}", options.entries).into(),
    ];
    if let Some(since) = &options.since {
        arguments.push(format!("--since={since}").into());
    }
    // Only entries with one of Guardian's events: the sweep's timer unit
    // has the same identifier, and what it prints is not the audit trail.
    arguments.extend(
        Event::ALL
            .iter()
            .map(|event| OsString::from(format!("{EVENT}={}", event.name()))),
    );
    let captured = tools::run(Path::new(JOURNALCTL), &arguments, None, &[], LIMITS)
        .map_err(|error| error.to_string())?;
    let notes = String::from_utf8_lossy(&captured.stderr).into_owned();
    let output = captured.into_success().map_err(|error| error.to_string())?;
    Ok((String::from_utf8_lossy(&output).into_owned(), notes))
}

pub fn command(options: &Options) -> ExitCode {
    let (output, notes) = match read(options) {
        Ok(read) => read,
        Err(reason) => {
            errln!("omarchy-guardian log: cannot read the journal: {reason}");
            return ExitCode::from(2);
        }
    };
    let lines = lines(&output, notify::current_uid());
    if options.json {
        let mut stdout = io::stdout().lock();
        for line in &lines {
            // Written as it is: the terminal-safe output would turn a
            // hidden character inside a string into something that is no
            // JSON.
            if writeln!(stdout, "{}", line.to_json()).is_err() {
                break;
            }
        }
        return ExitCode::SUCCESS;
    }
    if lines.is_empty() {
        outln!("The journal holds no entry of Guardian's for that time.");
    }
    for line in rendered(&lines) {
        outln!("{line}");
    }
    // journalctl says so itself when the reader sees only their own
    // entries; root's are then missing.
    if notes.contains("not seeing messages") {
        errln!(
            "\nEntries written by root (the pacman hook's result, permits, the sweep's allow list) are shown only to members of the systemd-journal, adm or wheel group: run this with sudo to see them."
        );
    }
    errln!(
        "\nThe column after the time says who wrote each entry, as the journal itself recorded it: `you` is your own user (Guardian, or anything else that runs as you), `root` entries no user process can write, `uid N` is another user. Nothing further along a line says who wrote it. No entry can be changed or removed afterwards."
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::{Options, Writer, lines, parse, rendered};

    fn args(words: &[&str]) -> Vec<OsString> {
        words.iter().map(OsString::from).collect()
    }

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn entry(uid: &str, comm: &str, extra: &str) -> String {
        format!(
            r#"{{"__REALTIME_TIMESTAMP":"1791128979597851","_UID":"{uid}","_COMM":"{comm}","_TRANSPORT":"journal","SYSLOG_IDENTIFIER":"omarchy-guardian","MESSAGE":"review"{extra}}}"#
        )
    }

    fn review(uid: &str, decision: &str) -> String {
        entry(
            uid,
            "logger",
            &format!(
                r#","GUARDIAN_EVENT":"review","GUARDIAN_GATE":"pacman","GUARDIAN_DECISION":"{decision}","GUARDIAN_SUBJECT":"demo-1.0-1-any","GUARDIAN_DIGEST":"demo-1.0-1-any={A} other=bbbb""#
            ),
        )
    }

    #[test]
    fn options_parse_and_a_time_cannot_be_an_option() {
        assert_eq!(
            parse(&args(&[])).unwrap(),
            Options {
                since: None,
                entries: 50,
                json: false
            }
        );
        let parsed = parse(&args(&["--since", "-2h", "-n", "7", "--json"])).unwrap();
        assert_eq!(parsed.since.as_deref(), Some("-2h"));
        assert_eq!(parsed.entries, 7);
        assert!(parsed.json);
        assert!(parse(&args(&["--since", "2026-01-31 10:00"])).is_ok());
        for bad in [
            &["--since"][..],
            &["--since", ""],
            &["--since", "x --file=/etc/shadow"],
            &["--since", "a\nb"],
            &["--since", "$(id)"],
            &["-n", "0"],
            &["-n", "many"],
            &["-n", "100000"],
            &["--follow"],
            &["extra"],
        ] {
            assert!(parse(&args(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_line_says_who_wrote_it_when_that_is_not_the_reader() {
        let output = [
            review("1000", "CLEAR"),
            review("0", "PASSED"),
            review("1001", "CLEAR"),
            entry("1000", "python3", r#","GUARDIAN_EVENT":"review""#),
            entry("1000", "logger", ""),
            "not json".to_string(),
            "[1]".to_string(),
        ]
        .join("\n");
        let lines = lines(&output, Some(1000));
        assert_eq!(lines.len(), 5);
        assert_eq!(lines[0].writer, Writer::Reader);
        assert_eq!(lines[0].marks(), "");
        assert_eq!(lines[1].writer, Writer::Root);
        assert_eq!(lines[1].marks(), "");
        assert_eq!(lines[2].writer, Writer::Other(1001));
        // Sent by something other than logger, or without Guardian's fields.
        assert!(lines[3].marks().contains("not written as Guardian writes"));
        assert!(lines[4].marks().contains("not written as Guardian writes"));

        let shown = rendered(&lines);
        // The journal's own time, then who the journal says wrote it.
        for (line, start) in [
            (0, "2026-10-04 15:49 UTC  you       CLEAR "),
            (1, "2026-10-04 15:49 UTC  root      PASSED "),
            (2, "2026-10-04 15:49 UTC  uid 1001  CLEAR "),
            (4, "2026-10-04 15:49 UTC  you       review  [! not written"),
        ] {
            assert!(shown[line].starts_with(start), "{}", shown[line]);
        }
        let unnamed = rendered(&super::lines(&review("", "CLEAR"), Some(1000)));
        assert!(
            unnamed[0].starts_with("2026-10-04 15:49 UTC  ?         CLEAR "),
            "{}",
            unnamed[0]
        );
        assert!(shown[0].contains("CLEAR"), "{}", shown[0]);
        assert!(shown[0].contains("pacman"), "{}", shown[0]);
        assert!(shown[0].contains("demo-1.0-1-any"), "{}", shown[0]);
        assert!(shown[0].contains("aaaaaaaaaaaa +1"), "{}", shown[0]);
        assert!(!shown[0].contains(A), "{}", shown[0]);
        // Nobody reading: every entry with a user is someone else's.
        assert_eq!(
            super::lines(&review("1000", "CLEAR"), None)[0].writer,
            Writer::Other(1000)
        );
        let json = lines[1].to_json().to_string();
        assert!(json.contains(r#""written_by":"root""#), "{json}");
        assert!(json.contains(r#""GUARDIAN_DECISION":"PASSED""#), "{json}");
    }

    #[test]
    fn repeated_lines_are_counted_and_hostile_text_stays_on_its_line() {
        let output = [
            review("1000", "CLEAR"),
            review("1000", "CLEAR"),
            review("1000", "CLEAR"),
            review("1000", "INCOMPLETE"),
            entry(
                "1000",
                "logger",
                r#","GUARDIAN_EVENT":"review","GUARDIAN_DECISION":"CLEAR\n2026 [root]","GUARDIAN_SUBJECT":"x\u001b[2J""#,
            ),
        ]
        .join("\n");
        let shown = rendered(&lines(&output, Some(1000)));
        assert_eq!(shown.len(), 3);
        assert!(shown[0].ends_with("×3"), "{}", shown[0]);
        assert!(shown[1].contains("INCOMPLETE"));
        assert!(!shown[2].contains('\n') && !shown[2].contains('\u{1b}'));
        assert!(shown[2].contains("\\n"), "{}", shown[2]);
    }

    #[test]
    fn a_users_entry_cannot_pass_for_roots() {
        // The hook's root half writes this line; a program running as the
        // user sends the same fields, with the mark an older `log` put at
        // the end written into the subject, behind every kind of blank.
        let fields = |subject: &str, more: &str| {
            format!(
                r#","GUARDIAN_EVENT":"review","GUARDIAN_GATE":"pacman","GUARDIAN_DECISION":"PASSED","GUARDIAN_SUBJECT":"{subject}"{more}"#
            )
        };
        let real = entry(
            "0",
            "logger",
            &fields(
                "the hook's root half: how the review ended",
                r#","GUARDIAN_FOR_UID":"1000""#,
            ),
        );
        let granted = entry(
            "1000",
            "logger",
            r#","GUARDIAN_EVENT":"permit","GUARDIAN_GATE":"aur","GUARDIAN_DECISION":"GRANTED","GUARDIAN_PERMIT":"0123456789abcdef  for user 1000  [root]""#,
        );
        let mut output = vec![real, granted];
        // As JSON writes them: no-break, ideographic and em spaces, tabs.
        for blanks in ["  ", "\\u00a0\\u00a0", "\\u3000 ", " \\u2003 ", "\\t\\t"] {
            output.push(entry(
                "1000",
                "logger",
                &fields(
                    &format!(
                        "the hook's root half: how the review ended{blanks}for user 1000{blanks}[root]"
                    ),
                    "",
                ),
            ));
            output.push(entry(
                "1000",
                "logger",
                &fields(&format!("x{blanks}root{blanks}PASSED{blanks}pacman"), ""),
            ));
        }
        let shown = rendered(&lines(&output.join("\n"), Some(1000)));
        assert_eq!(shown.len(), output.len());
        let after_time = |line: &str| line["2026-10-04 15:49 UTC  ".len()..].to_string();
        assert_eq!(
            after_time(&shown[0]),
            "root      PASSED           pacman    the hook's root half: how the review ended  for user 1000"
        );
        for forged in &shown[1..] {
            let line = after_time(forged);
            // Who wrote it stands first, from the journal; the sender's
            // text holds no column of its own.
            assert!(line.starts_with("you       "), "{forged}");
            assert_ne!(line, after_time(&shown[0]), "{forged}");
            assert!(!line.contains("  [root]"), "{forged}");
            assert!(!line.contains("  root  "), "{forged}");
            assert!(!line.contains("  for user 1000"), "{forged}");
        }
    }

    #[test]
    fn a_permit_is_shown_with_who_it_is_for_and_what_it_overruled() {
        let granted = entry(
            "0",
            "logger",
            &format!(
                r#","GUARDIAN_EVENT":"permit","GUARDIAN_GATE":"aur","GUARDIAN_DECISION":"GRANTED","GUARDIAN_PERMIT":"0123456789abcdef","GUARDIAN_FOR_UID":"1000","GUARDIAN_DIGEST":"content:{A}""#
            ),
        );
        let used = entry(
            "1000",
            "logger",
            &format!(
                r#","GUARDIAN_EVENT":"review","GUARDIAN_GATE":"aur","GUARDIAN_DECISION":"PERMITTED","GUARDIAN_SUBJECT":"aur:demo","GUARDIAN_PERMIT":"0123456789abcdef","GUARDIAN_OVERRULED":"INCOMPLETE","GUARDIAN_DIGEST":"recipe:{A}""#
            ),
        );
        let shown = rendered(&lines(&[granted, used].join("\n"), Some(1000)));
        assert!(
            shown[0].ends_with(
                "UTC  root      GRANTED          aur       permit 0123456789abcdef  for user 1000  aaaaaaaaaaaa"
            ),
            "{}",
            shown[0]
        );
        assert!(
            shown[1].ends_with(
                "UTC  you       PERMITTED        aur       aur:demo  permit 0123456789abcdef  overrules INCOMPLETE  aaaaaaaaaaaa"
            ),
            "{}",
            shown[1]
        );
    }
}
