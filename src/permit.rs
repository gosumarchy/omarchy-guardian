//! Permits: the user's own, explicit way past one block of an install gate.
//!
//! A gate that blocks on something a person may reasonably overrule (the
//! review's findings, an incomplete review, an unavailable AI, a question
//! nobody answered) ends its report with `omarchy-guardian permit <ID>`
//! and the SHA-256 the ID is the start of. That SHA-256 is over the gate,
//! the class and the digests of exactly what was reviewed, so a permit
//! stands for those bytes and for nothing else: a changed archive, recipe
//! or source has another ID, and is blocked as before.
//!
//! What the gate blocked is kept in the user's own state directory, to be
//! shown again when the user permits it. The permit itself is a small file
//! only root writes (through sudo, like the sweep's allow list), under
//! `/var/lib/omarchy-guardian/permits`: a program running as the user can
//! write the record of a block, but not the permit, which takes a word
//! typed on the terminal and the password. The root half is given the
//! gate, the class and the content's SHA-256 and stores those, the user
//! sudo names and when the permit ends; it reads no file of the user's.
//! Since the record is the user's to write, a program running as them
//! could put other content under an ID a gate printed, if it found some
//! whose SHA-256 starts the same: the ID is long enough (128 bits) that
//! none is found, and the gate prints the whole SHA-256 for the user to
//! compare with the one `permit` shows before it asks.
//!
//! A permit ends 30 minutes after it was given. The gates run as the user
//! and cannot remove root's file, so until then it lets the same bytes
//! through again (yay calls the makepkg gate several times for one build);
//! the pacman hook's root half removes the permit a transaction used.
//!
//! Never permitted: anything a gate refuses rather than reviews (a package
//! that would replace Guardian or its reviewer, a redirected transaction,
//! an archive that changed during the review), and any block where part of
//! the content has no digest to bind a permit to (see `Gap::content_hashed`).

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write as _};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::audit::{self, Entry, Event, Gate};
use crate::config::Settings;
use crate::config::model::{Named, Profile, SourceClass};
use crate::engine::store::Store;
use crate::json::Json;
use crate::paths;
use crate::report::{Decision, Report};
use crate::sha256::Sha256;
use crate::sweep::{root, state};
use crate::text::shown;
use crate::time::{now, utc};
use crate::user;

/// Where root keeps the permits: one file each.
pub const DIRECTORY: &str = "/var/lib/omarchy-guardian/permits";
/// How long a permit lasts.
pub const LIFETIME_SECS: u64 = 30 * 60;
/// The exit code of a pacman gate that let a transaction through on a
/// permit, when the hook's root half asked to be told (`ROOT_HOOK`): the
/// script removes the permit and goes on with 0.
pub const PERMITTED_EXIT: u8 = 10;
/// Set by the hook script's root half for the review it starts.
pub const ROOT_HOOK: &str = "OMARCHY_GUARDIAN_ROOT_HOOK";

/// Hex characters of the content's SHA-256 that make the ID: 128 bits,
/// so that no second content with the same ID can be searched for (the
/// record a permit is given from is the user's own file, see `Pending`).
const ID_CHARS: usize = 32;
/// The most digests one permit's content may be made of (a system upgrade
/// is a few hundred archives).
const MAX_PARTS: usize = 4096;
/// Blocks kept to be permitted, and for how long.
const MAX_PENDING: usize = 20;
const PENDING_SECS: u64 = 24 * 60 * 60;
const PENDING_DIRECTORY: &str = "permits";
const MAX_PENDING_BYTES: u64 = 1024 * 1024;
/// The most lines of a block's findings kept and shown.
const MAX_SUMMARY: usize = 16;
const MAX_SHOWN_CHARS: usize = 300;
const MAX_PERMIT_BYTES: u64 = 4096;
/// The most permits one user may hold at a time.
const MAX_PERMITS: usize = 32;
/// What the user types to give a permit.
const WORD: &str = "permit";

const SYSTEM_USAGE: &str =
    "usage: omarchy-guardian permit-system (--add GATE CLASS SHA256 | --revoke ID)";

fn is_hex(text: &str, length: usize) -> bool {
    text.len() == length
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Whether `gate` is one a permit can be for: the install gates.
const fn permits(gate: Gate) -> bool {
    matches!(
        gate,
        Gate::Pacman | Gate::Aur | Gate::Theme | Gate::Plugin | Gate::Guard | Gate::Sandbox
    )
}

/// The classes a permit's class names: one, or for a pacman transaction of
/// several kinds of package, each joined by `+`.
fn classes(class: &str) -> Option<Vec<SourceClass>> {
    class
        .split('+')
        .map(|name| SourceClass::parse(name).filter(|class| *class != SourceClass::System))
        .collect()
}

/// One digest of the content: what it is of (`recipe`, `tree`, a class)
/// and its hex SHA-256.
fn is_part(part: &str) -> bool {
    part.split_once(':').is_some_and(|(label, digest)| {
        !label.is_empty()
            && label.len() <= 32
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && is_hex(digest, 64)
    })
}

/// Exactly what a gate reviewed, as a permit names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Content {
    gate: Gate,
    class: String,
    /// What it is called, for the user; not part of the key.
    subject: String,
    parts: Vec<String>,
}

impl Content {
    /// `None` when a permit cannot name this: no digest, one that is not a
    /// SHA-256, or a gate or class permits are not for.
    pub fn new(gate: Gate, class: &str, subject: &str, mut parts: Vec<String>) -> Option<Self> {
        parts.sort();
        parts.dedup();
        let named = permits(gate)
            && classes(class).is_some()
            && !parts.is_empty()
            && parts.len() <= MAX_PARTS
            && parts.iter().all(|part| is_part(part));
        named.then(|| Self {
            gate,
            class: class.to_string(),
            subject: subject.to_string(),
            parts,
        })
    }

    /// A reviewed tree, by its snapshot's manifest digest.
    pub fn tree(gate: Gate, class: SourceClass, subject: &str, manifest: &str) -> Option<Self> {
        Self::new(
            gate,
            class.name(),
            subject,
            vec![format!("tree:{manifest}")],
        )
    }

    /// The SHA-256 over the gate, the class and every digest: what root
    /// stores and what the gate looks a permit up by.
    pub fn key(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"omarchy-guardian permit 1\n");
        for line in [self.gate.name(), self.class.as_str()]
            .into_iter()
            .chain(self.parts.iter().map(String::as_str))
        {
            hasher.update(line.as_bytes());
            hasher.update(b"\n");
        }
        hasher.finalize().to_string()
    }

    pub fn id(&self) -> String {
        self.key()[..ID_CHARS].to_string()
    }

    fn offer(&self) -> Offer {
        Offer {
            id: self.id(),
            key: self.key(),
        }
    }

    pub fn class(&self) -> &str {
        &self.class
    }

    /// One digest for the audit trail: the only part, or the key over all.
    pub fn digest(&self) -> String {
        match self.parts.as_slice() {
            [part] => part.clone(),
            _ => format!("content:{}", self.key()),
        }
    }
}

/// Whether permits are on for `class` under these settings: not under the
/// strict level unless the root-owned system file allows them there, and
/// not while that file cannot be read (nobody can say what it sets).
pub fn enabled(settings: &Settings, class: &str) -> bool {
    if settings.privileged_block().is_some() {
        return false;
    }
    let Some(classes) = classes(class) else {
        return false;
    };
    let strict = settings.system_profile() == Profile::Strict
        || classes
            .iter()
            .any(|class| settings.profile_for(*class) == Profile::Strict);
    !strict || settings.permits_under_strict()
}

/// The permit a block is offered: its ID, and the whole SHA-256 of the
/// content that ID is the start of. Shown as the ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    id: String,
    key: String,
}

impl std::fmt::Display for Offer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.id)
    }
}

/// How a blocked review stands with permits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Standing {
    /// Not blocked, or blocked on what no permit can overrule.
    None,
    /// A permit of this ID lets it through.
    Permitted(String),
    /// The block can be permitted under this offer's ID.
    Offered(Offer),
}

impl Standing {
    pub fn permitted(&self) -> Option<&str> {
        match self {
            Self::Permitted(id) => Some(id),
            Self::None | Self::Offered(_) => None,
        }
    }

    pub fn offered(&self) -> Option<&str> {
        match self {
            Self::Offered(offer) => Some(&offer.id),
            Self::None | Self::Permitted(_) => None,
        }
    }

    /// The lines a block that can be permitted ends with, kept with the
    /// saved report: the command, and the whole SHA-256 a permit would be
    /// for. `permit` reads what it asks about from a file any program
    /// running as the user can write; this is the gate's own word for
    /// what it blocked, to hold against what `permit` shows.
    pub fn say(&self) {
        if let Self::Offered(offer) = self {
            crate::output::stderr_line(format_args!(
                "To install this exact content anyway: omarchy-guardian permit {}",
                offer.id
            ));
            crate::output::stderr_line(format_args!(
                "  content SHA-256 {}  (permit shows it again before it asks: the two must be the same)",
                offer.key
            ));
        }
    }
}

/// Where permits are looked for and what makes one root's.
struct Place<'a> {
    directory: &'a Path,
    /// Who must own a permit and the directories above it, up to `anchor`.
    owner: u32,
    anchor: &'a Path,
}

/// Root's permits, under a directory only root writes.
fn root_place() -> Place<'static> {
    Place {
        directory: Path::new(DIRECTORY),
        owner: 0,
        anchor: Path::new(state::ROOT_STATE_ANCHOR),
    }
}

/// A permit as root wrote it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Permit {
    uid: u32,
    gate: Gate,
    class: String,
    key: String,
    expires: u64,
}

impl Permit {
    fn file_name(uid: u32, gate: Gate, key: &str) -> String {
        format!("{uid}-{}-{key}", gate.name())
    }

    fn to_json(&self) -> String {
        Json::object([
            ("uid", Json::from(u64::from(self.uid))),
            ("gate", Json::from(self.gate.name())),
            ("class", Json::from(self.class.as_str())),
            ("key", Json::from(self.key.as_str())),
            ("expires", Json::from(self.expires)),
        ])
        .to_string()
    }

    /// The permit in the file at `path`, while the file is `place`'s
    /// owner's alone and says what its name says.
    fn read(path: &Path, place: &Place<'_>) -> Option<Self> {
        if !state::owned_alone(path, place.owner, place.anchor, MAX_PERMIT_BYTES) {
            return None;
        }
        let json = Json::parse(&fs::read_to_string(path).ok()?).ok()?;
        let permit = Self {
            uid: u32::try_from(json.get("uid")?.as_u64()?).ok()?,
            gate: Gate::parse(json.get("gate")?.as_str()?).filter(|gate| permits(*gate))?,
            class: json.get("class")?.as_str()?.to_string(),
            key: json.get("key")?.as_str()?.to_string(),
            expires: json.get("expires")?.as_u64()?,
        };
        let named =
            path.file_name()?.to_str()? == Self::file_name(permit.uid, permit.gate, &permit.key);
        (named && is_hex(&permit.key, 64) && classes(&permit.class).is_some()).then_some(permit)
    }

    /// Still good at `now`: not ended, and not ending later than a permit
    /// given now would (a clock set back does not make one last).
    const fn valid(&self, now: u64) -> bool {
        now < self.expires && self.expires - now <= LIFETIME_SECS
    }
}

/// The permit of user `uid` for `content`, if root gave one that still
/// stands.
fn find(place: &Place<'_>, uid: u32, content: &Content, now: u64) -> Option<Permit> {
    let key = content.key();
    let path = place
        .directory
        .join(Permit::file_name(uid, content.gate, &key));
    Permit::read(&path, place).filter(|permit| {
        permit.uid == uid
            && permit.gate == content.gate
            && permit.class == content.class
            && permit.key == key
            && permit.valid(now)
    })
}

/// Every standing permit of user `uid`.
fn standing_permits(place: &Place<'_>, uid: u32, now: u64) -> Vec<Permit> {
    let Ok(entries) = fs::read_dir(place.directory) else {
        return Vec::new();
    };
    let mut permits: Vec<Permit> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| Permit::read(&entry.path(), place))
        .filter(|permit| permit.uid == uid && permit.valid(now))
        .collect();
    permits.sort_by_key(|permit| permit.expires);
    permits
}

/// A block kept in the user's state directory until it is permitted.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Pending {
    content: Content,
    /// The decision's name.
    decision: String,
    /// What the review found, a line each.
    summary: Vec<String>,
    at: u64,
}

impl Pending {
    fn to_json(&self) -> String {
        let list = |lines: &[String]| {
            Json::Array(lines.iter().map(|line| Json::from(line.as_str())).collect())
        };
        Json::object([
            ("id", Json::from(self.content.id())),
            ("key", Json::from(self.content.key())),
            ("gate", Json::from(self.content.gate.name())),
            ("class", Json::from(self.content.class.as_str())),
            ("subject", Json::from(self.content.subject.as_str())),
            ("parts", list(&self.content.parts)),
            ("decision", Json::from(self.decision.as_str())),
            ("summary", list(&self.summary)),
            ("at", Json::from(self.at)),
        ])
        .to_string()
    }

    /// The record is a file anything running as the user can write: every
    /// field is checked for its shape, and the ID and key it gives must be
    /// the ones its gate, class and digests hash to.
    fn parse(text: &str) -> Option<Self> {
        let json = Json::parse(text).ok()?;
        let text_of = |key: &str| json.get(key).and_then(Json::as_str);
        let lines = |key: &str, limit: usize| -> Option<Vec<String>> {
            let items = json.get(key)?.as_array()?;
            (items.len() <= limit).then_some(())?;
            items
                .iter()
                .map(|item| item.as_str().map(str::to_string))
                .collect()
        };
        let content = Content::new(
            Gate::parse(text_of("gate")?)?,
            text_of("class")?,
            text_of("subject")?,
            lines("parts", MAX_PARTS)?,
        )?;
        (text_of("key")? == content.key() && text_of("id")? == content.id()).then_some(())?;
        Some(Self {
            content,
            decision: text_of("decision")?.to_string(),
            summary: lines("summary", MAX_SUMMARY + 1)?,
            at: json.get("at")?.as_u64()?,
        })
    }
}

/// The user's directory of blocks to permit, private to them.
fn pending_directory(state_root: &Path) -> Result<PathBuf, String> {
    let uid = user::effective_uid()?;
    paths::private_dir(state_root, uid)?;
    let directory = state_root.join(PENDING_DIRECTORY);
    paths::private_dir(&directory, uid)?;
    Ok(directory)
}

/// The blocks kept under `state_root` that can still be permitted at
/// `now`, newest first. Reads only: nothing is created.
fn pending_blocks(state_root: &Path, now: u64) -> Vec<Pending> {
    let Ok(entries) = fs::read_dir(state_root.join(PENDING_DIRECTORY)) else {
        return Vec::new();
    };
    let mut blocks: Vec<Pending> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).ok()?;
            (metadata.is_file() && metadata.len() <= MAX_PENDING_BYTES).then_some(())?;
            let block = Pending::parse(&fs::read_to_string(&path).ok()?)?;
            let named = path.file_name()?.to_str()? == format!("{}.json", block.content.id());
            (named && now.saturating_sub(block.at) <= PENDING_SECS && block.at <= now + 60)
                .then_some(block)
        })
        .collect();
    blocks.sort_by_key(|block| std::cmp::Reverse(block.at));
    blocks
}

/// Keeps `block` to be permitted, and drops the ones that are too old or
/// too many.
fn keep_pending(state_root: &Path, block: &Pending) -> Result<(), String> {
    let directory = pending_directory(state_root)?;
    let kept: Vec<String> = pending_blocks(state_root, block.at)
        .into_iter()
        .take(MAX_PENDING - 1)
        .map(|kept| format!("{}.json", kept.content.id()))
        .collect();
    let name = format!("{}.json", block.content.id());
    state::write_text_mode(&directory.join(&name), &block.to_json(), 0o600)?;
    for entry in fs::read_dir(&directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?
        .filter_map(Result::ok)
    {
        let stale = entry
            .file_name()
            .to_str()
            .is_none_or(|found| found != name && !kept.iter().any(|kept| kept == found));
        if stale {
            drop(fs::remove_file(entry.path()));
        }
    }
    Ok(())
}

fn drop_pending(state_root: &Path, id: &str) {
    drop(fs::remove_file(
        state_root
            .join(PENDING_DIRECTORY)
            .join(format!("{id}.json")),
    ));
}

/// How `report`, decided as `decision`, stands with permits. `contents`
/// are the ways to name what was reviewed (none when it has no digest): a
/// permit for any of them lets it through, and a block is offered a permit
/// for the first. A block that can be permitted is kept under `state_root`
/// to be shown again; without a place to keep it, nothing is offered.
pub fn standing(
    contents: &[Content],
    report: &Report,
    decision: Decision,
    settings: &Settings,
    state_root: Option<&Path>,
) -> Standing {
    standing_at(
        &root_place(),
        contents,
        report,
        decision,
        settings,
        state_root,
        now(),
    )
}

fn standing_at(
    place: &Place<'_>,
    contents: &[Content],
    report: &Report,
    decision: Decision,
    settings: &Settings,
    state_root: Option<&Path>,
    now: u64,
) -> Standing {
    let (Decision::Blocked(_), Some(content)) = (decision, contents.first()) else {
        return Standing::None;
    };
    if !report.content_hashed() || !enabled(settings, &content.class) {
        return Standing::None;
    }
    let Some(uid) = user::real_uid() else {
        return Standing::None;
    };
    if let Some(permitted) = contents
        .iter()
        .find(|content| find(place, uid, content, now).is_some())
    {
        return Standing::Permitted(permitted.id());
    }
    let Some(state_root) = state_root else {
        return Standing::None;
    };
    let block = Pending {
        content: content.clone(),
        decision: report.decision_name(decision).to_string(),
        summary: report.overruled_summary(MAX_SUMMARY),
        at: now,
    };
    match keep_pending(state_root, &block) {
        Ok(()) => Standing::Offered(content.offer()),
        Err(reason) => {
            errln!("omarchy-guardian: this block cannot be offered a permit ({reason}).");
            Standing::None
        }
    }
}

/// `omarchy-guardian permit [ID | --revoke ID]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    List,
    Grant(String),
    Revoke(String),
}

pub fn parse(args: &[std::ffi::OsString]) -> Result<Command, String> {
    const USAGE: &str = "usage: omarchy-guardian permit [ID | --revoke ID]";
    let words: Vec<&str> = args
        .iter()
        .map(|arg| arg.to_str().ok_or(USAGE))
        .collect::<Result<_, _>>()?;
    let id = |text: &str| {
        if is_hex(text, ID_CHARS) {
            Ok(text.to_string())
        } else {
            Err(format!(
                "{text:?} is not a permit ID ({ID_CHARS} hex characters, as a blocked gate prints it)"
            ))
        }
    };
    match words.as_slice() {
        [] => Ok(Command::List),
        ["--revoke", text] => id(text).map(Command::Revoke),
        [text] if !text.starts_with('-') => id(text).map(Command::Grant),
        _ => Err(USAGE.into()),
    }
}

/// Reads one line the user types on the terminal. `None` without a
/// terminal: a permit is never given unattended.
pub trait Typed {
    fn typed(&mut self, prompt: &str) -> Option<String>;
}

pub struct TtyTyped;

impl Typed for TtyTyped {
    fn typed(&mut self, prompt: &str) -> Option<String> {
        let mut tty = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .ok()?;
        write!(tty, "{}", shown(prompt))
            .and_then(|()| tty.flush())
            .ok()?;
        let mut answer = String::new();
        BufReader::new(tty).read_line(&mut answer).ok()?;
        Some(answer.trim().to_string())
    }
}

/// A line of the user's own record, as it is shown: one bounded line.
fn brief(text: &str) -> String {
    shown(text).chars().take(MAX_SHOWN_CHARS).collect()
}

fn minutes_left(expires: u64, now: u64) -> u64 {
    expires.saturating_sub(now).div_ceil(60)
}

/// What is being overruled and what root will store, before the user is
/// asked.
fn show(block: &Pending, uid: u32) {
    let content = &block.content;
    outln!("Guardian blocked this at {}:", utc(block.at));
    outln!("  Gate      {}", content.gate.name());
    outln!("  Class     {}", content.class);
    outln!("  What      {}", brief(&content.subject));
    outln!("  Decision  {}", brief(&block.decision));
    if !block.summary.is_empty() {
        outln!("  The review's reasons, which a permit overrules:");
        for line in &block.summary {
            outln!("    {}", brief(line));
        }
    }
    outln!();
    outln!("With your password, root stores this and nothing else:");
    outln!(
        "  user {uid} · gate {} · class {} · {} minutes",
        content.gate.name(),
        content.class,
        LIFETIME_SECS / 60
    );
    outln!();
    outln!("  content SHA-256 {}", content.key());
    outln!();
    outln!(
        "Compare this SHA-256 with the one the blocked gate printed under its permit line: they must be the same, character for character. Everything else shown here is from a record in your own state directory, which any program running as you can write; the SHA-256 is what root stores, and what the gate will let through."
    );
    outln!(
        "The gate lets content with this SHA-256 through until the permit ends{}. Anything else, a changed file included, is reviewed and blocked as before.",
        if content.gate == Gate::Pacman {
            " or a transaction used it"
        } else {
            ""
        }
    );
}

fn grant(
    id: &str,
    settings: &Settings,
    state_root: &Path,
    typed: &mut dyn Typed,
    as_root: &dyn Fn(&[&str]) -> Result<(), String>,
) -> Result<String, String> {
    let now = now();
    let block = pending_blocks(state_root, now)
        .into_iter()
        .find(|block| block.content.id() == id)
        .ok_or_else(|| {
            format!("no blocked install is kept under {id}; `omarchy-guardian permit` lists them")
        })?;
    let content = &block.content;
    if !enabled(settings, &content.class) {
        return Err(
            "permits are off under the strict level; the system file's [permit] strict = \"allowed\" turns them on"
                .into(),
        );
    }
    let uid = user::real_uid().ok_or("cannot tell which user this is")?;
    if uid == 0 {
        return Err("a permit is given by the user who was blocked, not by root".into());
    }
    show(&block, uid);
    let answer = typed
        .typed(&format!(
            "Type {WORD} to overrule the review, anything else to leave it: "
        ))
        .ok_or("a permit is given on a terminal, by you: there is none here")?;
    if answer != WORD {
        return Err("nothing was permitted".into());
    }
    as_root(&["--add", content.gate.name(), &content.class, &content.key()])?;
    drop_pending(state_root, id);
    Ok(format!(
        "Permitted for {} minutes. Run the install again: the gate reviews it again and lets exactly this content through.",
        LIFETIME_SECS / 60
    ))
}

fn list(state_root: Option<&Path>) {
    let now = now();
    let blocks = state_root.map_or_else(Vec::new, |root| pending_blocks(root, now));
    if blocks.is_empty() {
        outln!("No blocked install is waiting for a permit.");
    } else {
        outln!("Blocked installs you can permit (omarchy-guardian permit ID):");
        for block in &blocks {
            outln!(
                "  {}  {}  {}  {}  {}",
                block.content.id(),
                utc(block.at),
                block.content.gate.name(),
                brief(&block.decision),
                brief(&block.content.subject)
            );
        }
    }
    let permits = user::real_uid()
        .map(|uid| standing_permits(&root_place(), uid, now))
        .unwrap_or_default();
    if !permits.is_empty() {
        outln!("\nPermits in force (omarchy-guardian permit --revoke ID):");
        for permit in &permits {
            outln!(
                "  {}  {}  {}  {} minute(s) left",
                &permit.key[..ID_CHARS],
                permit.gate.name(),
                permit.class,
                minutes_left(permit.expires, now)
            );
        }
    }
}

fn revoke(id: &str, state_root: Option<&Path>) -> Result<String, String> {
    if let Some(root) = state_root {
        drop_pending(root, id);
    }
    let held = user::real_uid().is_some_and(|uid| {
        standing_permits(&root_place(), uid, now())
            .iter()
            .any(|permit| permit.key.starts_with(id))
    });
    if !held {
        return Ok(format!("No permit {id} is in force; nothing to revoke."));
    }
    system(&["--revoke", id])?;
    Ok(format!("Revoked permit {id}."))
}

/// The root half, through sudo.
fn system(arguments: &[&str]) -> Result<(), String> {
    root::as_root("permit-system", arguments, "changing your permits")
}

pub fn command(command: &Command, settings: &Settings) -> ExitCode {
    let state_root = Store::default_root();
    let result = match command {
        Command::List => {
            list(state_root.as_deref());
            return ExitCode::SUCCESS;
        }
        Command::Grant(id) => match state_root.as_deref() {
            Some(root) => grant(id, settings, root, &mut TtyTyped, &system),
            None => Err("no state directory (set HOME or XDG_STATE_HOME)".into()),
        },
        Command::Revoke(id) => revoke(id, state_root.as_deref()),
    };
    match result {
        Ok(message) => {
            outln!("{message}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            errln!("omarchy-guardian permit: {message}");
            ExitCode::from(2)
        }
    }
}

/// Removes the permits in `directory` that ended, or that `gone` names.
fn remove_where(directory: &Path, gone: &dyn Fn(&str) -> bool) -> usize {
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
fn add(
    directory: &Path,
    uid: u32,
    gate: &str,
    class: &str,
    key: &str,
    now: u64,
) -> Result<Permit, String> {
    let gate = Gate::parse(gate)
        .filter(|gate| permits(*gate))
        .ok_or_else(|| format!("{gate:?} is not a gate permits are for"))?;
    if classes(class).is_none() {
        return Err(format!("{class:?} is not a class"));
    }
    if !is_hex(key, 64) {
        return Err("the content is named by its SHA-256 (64 hex characters)".into());
    }
    fs::create_dir_all(directory).map_err(|error| format!("{}: {error}", directory.display()))?;
    let open = |path: &Path, mode: u32| {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|error| format!("{}: {error}", path.display()))
    };
    // Whatever sudo's umask is, the gates run as the user and must be able
    // to read a permit.
    open(directory, 0o755)?;
    remove_where(directory, &|name| ended(directory, name, now));
    let prefix = format!("{uid}-");
    let held = fs::read_dir(directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(&prefix))
        })
        .count();
    if held >= MAX_PERMITS {
        return Err("too many permits are in force; revoke some or let them end".into());
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

fn system_change(arguments: &[String]) -> Result<(), String> {
    let uid = invoker().ok_or(
        "a permit is given to the user who asks through sudo: run `omarchy-guardian permit` as that user",
    )?;
    let directory = Path::new(DIRECTORY);
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["--add", gate, class, key] => {
            // The level is the root-owned system file's to say; the user's
            // file is not read here.
            let settings = Settings::system_only();
            if !enabled(&settings, class) {
                return Err("permits are off under these system settings".into());
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
        _ => Err(SYSTEM_USAGE.into()),
    }
}

/// `omarchy-guardian permit-system …`, run as root through sudo by
/// `permit`: the permits, which only root writes.
pub fn system_command(arguments: &[String]) -> ExitCode {
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
pub fn hook_result_command(arguments: &[String]) -> ExitCode {
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

#[cfg(test)]
mod tests;
