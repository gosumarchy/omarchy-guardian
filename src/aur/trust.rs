//! What the AUR says about a package: its record from the RPC, the trust
//! signals drawn from it, and better-known packages with a look-alike name.

use crate::json::Json;

/// What the AUR says about a package, from `/rpc/v5/info`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AurInfo {
    pub name: String,
    pub package_base: String,
    pub first_submitted: u64,
    pub last_modified: u64,
    pub votes: u64,
    pub maintainer: Option<String>,
    pub submitter: Option<String>,
    pub out_of_date: bool,
}

/// The result of an AUR RPC `info` reply whose package base is `base`, or
/// `None` when the AUR has none.
pub fn parse_rpc_info(reply: &Json, base: &str) -> Option<AurInfo> {
    let result = reply
        .get("results")?
        .as_array()?
        .iter()
        .find(|result| result.get("PackageBase").and_then(Json::as_str) == Some(base))?;
    let text = |key: &str| result.get(key).and_then(Json::as_str).map(str::to_string);
    let number = |key: &str| result.get(key).and_then(Json::as_u64).unwrap_or(0);
    Some(AurInfo {
        name: text("Name")?,
        package_base: text("PackageBase")?,
        first_submitted: number("FirstSubmitted"),
        last_modified: number("LastModified"),
        votes: number("NumVotes"),
        maintainer: text("Maintainer"),
        submitter: text("Submitter"),
        out_of_date: result.get("OutOfDate").and_then(Json::as_u64).is_some(),
    })
}

/// The AUR package base a build directory is a clone of: its git `origin`
/// must be `https://aur.archlinux.org/<base>.git` and the directory must be
/// named `<base>`, as yay and `git clone` make it. Anything else is not an
/// AUR clone, and gets no AUR facts. The config is read as text; git is
/// never run in the untrusted directory.
pub fn aur_identity(directory_name: &str, git_config: &str) -> Option<String> {
    let mut in_origin = false;
    for line in git_config.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_origin = line.replace(' ', "") == "[remote\"origin\"]";
            continue;
        }
        if !in_origin {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "url" {
            continue;
        }
        let base = value
            .trim()
            .strip_prefix("https://aur.archlinux.org/")?
            .trim_end_matches('/');
        let base = base.strip_suffix(".git").unwrap_or(base);
        return (base == directory_name && crate::pacman::is_valid_package_name(base))
            .then(|| base.to_string());
    }
    None
}

/// The names a PKGBUILD declares in simple top-level `pkgname=` lines, as
/// lookup keys only (the reply is checked against the package base).
pub fn declared_names(pkgbuild: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in pkgbuild.lines() {
        let Some(value) = line.strip_prefix("pkgname=") else {
            continue;
        };
        let value = value.split('#').next().unwrap_or_default();
        for name in value
            .trim_matches(|character| character == '(' || character == ')' || character == ' ')
            .split_whitespace()
        {
            let name = name.trim_matches(|character| character == '\'' || character == '"');
            if crate::pacman::is_valid_package_name(name) {
                names.push(name.to_string());
            }
        }
    }
    names
}

const DAY: u64 = crate::time::SECONDS_PER_DAY;
/// A package younger than this is new.
const NEW_DAYS: u64 = 30;
/// A package with fewer votes has no track record.
const FEW_VOTES: u64 = 5;

/// Trust signals: `(facts, warnings)`. Facts describe the package for the
/// AI review; warnings are the signals worth the user's attention. New and
/// unvoted packages, and packages recently changed by someone other than
/// their submitter, are how most AUR malware has arrived.
pub fn trust_signals(info: &AurInfo, now: u64) -> (Vec<String>, Vec<String>) {
    let age_days = now.saturating_sub(info.first_submitted) / DAY;
    let changed_days = now.saturating_sub(info.last_modified) / DAY;
    let mut facts = vec![format!(
        "AUR package {}: first submitted {age_days} day(s) ago, last changed {changed_days} day(s) ago, {} vote(s), maintainer {}, submitted by {}.",
        info.name,
        info.votes,
        info.maintainer.as_deref().unwrap_or("none (orphaned)"),
        info.submitter.as_deref().unwrap_or("unknown")
    )];
    let mut warnings = Vec::new();
    if age_days < NEW_DAYS {
        warnings.push(format!(
            "{} was first submitted {age_days} day(s) ago",
            info.name
        ));
    }
    if info.votes < FEW_VOTES {
        warnings.push(format!("{} has {} vote(s)", info.name, info.votes));
    }
    match (&info.maintainer, &info.submitter) {
        (None, _) => warnings.push(format!("{} is orphaned", info.name)),
        (Some(maintainer), Some(submitter)) if maintainer != submitter && changed_days < 14 => {
            warnings.push(format!(
                "{} was changed {changed_days} day(s) ago by {maintainer}, who did not submit it (submitted by {submitter})",
                info.name
            ));
        }
        _ => {}
    }
    if info.out_of_date {
        facts.push(format!("{} is flagged out of date.", info.name));
    }
    (facts, warnings)
}

/// Whether a package has too few votes to have a track record.
pub const fn is_little_voted(votes: u64) -> bool {
    votes < FEW_VOTES
}

/// What the AI and the user are told when the AUR could not be asked.
pub const TRUST_UNKNOWN: &str = "Guardian could not fetch the AUR's record of this package: its \
age, votes and maintainer are unknown to this review, and nothing here says they are fine.";

/// Endings that make a new package name out of a known one. The AUR
/// malware of July 2025 arrived under such names (`librewolf-fix-bin`,
/// `firefox-patch-bin`, `zen-browser-patched-bin`).
const VARIANT_SUFFIXES: &[&str] = &["-bin", "-git", "-patched", "-patch", "-fixed", "-fix"];
/// A package with at least this many votes is one people know.
const KNOWN_VOTES: u64 = 50;
/// The most look-alikes named.
const MAX_LOOKALIKES: usize = 3;

/// `name` without its variant endings: `zen-browser-patched-bin` is
/// `zen-browser`.
pub fn plain_name(name: &str) -> &str {
    let mut plain = name;
    while let Some(shorter) = VARIANT_SUFFIXES
        .iter()
        .find_map(|suffix| plain.strip_suffix(suffix))
        .filter(|shorter| !shorter.is_empty())
    {
        plain = shorter;
    }
    plain
}

/// How many letters have to be changed, added or dropped to make `right`
/// of `left`, counted up to `most + 1`.
fn edit_distance(left: &str, right: &str, most: usize) -> usize {
    let (left, right): (Vec<char>, Vec<char>) = (left.chars().collect(), right.chars().collect());
    if left.len().abs_diff(right.len()) > most {
        return most + 1;
    }
    let mut previous: Vec<usize> = (0..=right.len()).collect();
    for (row, from) in left.iter().enumerate() {
        let mut current = vec![row + 1];
        for (column, to) in right.iter().enumerate() {
            let change = previous[column] + usize::from(from != to);
            current.push(
                change
                    .min(previous[column + 1] + 1)
                    .min(current[column] + 1),
            );
        }
        previous = current;
    }
    previous.last().copied().unwrap_or(0).min(most + 1)
}

/// Whether `name` is a letter or two from `known` without being it: close
/// enough to be taken for it. Names that differ only in digits (`qt5`,
/// `qt6`) are versions of each other, and short names are close to
/// everything.
fn is_lookalike(name: &str, known: &str) -> bool {
    let letters = |text: &str| -> String { text.chars().filter(|c| !c.is_ascii_digit()).collect() };
    let most = if name.len() < 8 { 1 } else { 2 };
    name != known
        && name.len() >= 5
        && letters(name) != letters(known)
        && edit_distance(name, known, most) <= most
}

/// The names and votes of an AUR RPC `search` reply.
pub fn parse_rpc_search(reply: &Json) -> Vec<(String, u64)> {
    reply
        .get("results")
        .and_then(Json::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(|result| {
            Some((
                result.get("Name").and_then(Json::as_str)?.to_string(),
                result.get("NumVotes").and_then(Json::as_u64).unwrap_or(0),
            ))
        })
        .collect()
}

/// What to search the AUR's names for, to find what `name` could be taken
/// for: its plain name, or, when it has no variant ending, its first two
/// thirds, which a name one or two letters off further on still shares.
/// Only this text is sent.
pub fn lookalike_search_term(name: &str) -> Option<String> {
    let plain = plain_name(name);
    let term = if plain == name {
        let keep = (name.chars().count() * 2).div_ceil(3).max(4);
        name.chars().take(keep).collect()
    } else {
        plain.to_string()
    };
    (term.len() >= 4).then_some(term)
}

/// Known packages a little-voted package's name could be taken for:
/// official ones (`official`, the names in the sync databases) and AUR ones
/// with many more votes (`searched`, from `parse_rpc_search`). One warning
/// for each, in Guardian's words with validated package names. A package
/// people have voted for is not asked about.
pub fn lookalikes(
    name: &str,
    votes: u64,
    official: &[String],
    searched: &[(String, u64)],
) -> Vec<String> {
    if votes >= FEW_VOTES {
        return Vec::new();
    }
    let plain = plain_name(name);
    let mut found = Vec::new();
    let valid = |known: &str| crate::pacman::is_valid_package_name(known) && known != name;
    for known in official.iter().filter(|known| valid(known)) {
        if plain == known {
            found.push(format!(
                "{name} has {votes} vote(s) and is named like the official package {known} with another ending"
            ));
        } else if is_lookalike(name, known) || is_lookalike(plain, known) {
            found.push(format!(
                "{name} has {votes} vote(s) and its name is a letter or two from the official package {known}"
            ));
        }
    }
    for (known, known_votes) in searched.iter().filter(|(known, _)| valid(known)) {
        if *known_votes < KNOWN_VOTES || *known_votes < votes.saturating_mul(20) {
            continue;
        }
        let known_plain = plain_name(known);
        if plain == known_plain {
            found.push(format!(
                "{name} has {votes} vote(s) and is named like the AUR package {known} ({known_votes} votes) with another ending"
            ));
        } else if is_lookalike(plain, known_plain) {
            found.push(format!(
                "{name} has {votes} vote(s) and its name is a letter or two from the AUR package {known} ({known_votes} votes)"
            ));
        }
    }
    found.truncate(MAX_LOOKALIKES);
    found
}
