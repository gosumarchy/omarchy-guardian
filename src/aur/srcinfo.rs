//! The sources a recipe lists (`.SRCINFO`): how each entry is read, whether
//! the listing matches what the recipe writes, and whether each source is
//! pinned, verified and fetched over a connection nobody can change.

use super::{Authority, CHECKSUMS, UNPARSEABLE_HOST};
use crate::paths::file_name;

/// One `source` entry with the checksums given for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Source {
    pub(crate) entry: String,
    pub(crate) checksums: Vec<String>,
}

/// A source entry's protocol as makepkg reads it: `git`, `https`, ..., or
/// `local` for a file beside the recipe.
pub(crate) fn source_protocol(entry: &str) -> &str {
    let after_name = entry.split_once("::").map_or(entry, |(_, rest)| rest);
    if let Some((scheme, _)) = entry
        .contains("://")
        .then(|| after_name.split_once("://"))
        .flatten()
    {
        scheme.split('+').next().unwrap_or(scheme)
    } else if entry.contains("lp:") {
        after_name
            .find("+lp:")
            .map_or(after_name, |index| &after_name[..index])
    } else {
        "local"
    }
}

/// The name makepkg keeps a source under in the download directory,
/// derived the way makepkg derives it.
pub(crate) fn source_filename(entry: &str) -> String {
    if let Some((name, _)) = entry.split_once("::") {
        return name.to_string();
    }
    let protocol = source_protocol(entry);
    if !VCS.contains(&protocol) {
        return file_name(entry).to_string();
    }
    let url = entry.split(['#', '?']).next().unwrap_or_default();
    let url = url.strip_suffix('/').unwrap_or(url);
    let mut name = file_name(url);
    match protocol {
        "bzr" => name = name.split_once("lp:").map_or(name, |(_, rest)| rest),
        "fossil" => return format!("{name}.fossil"),
        "git" => name = name.find(".git").map_or(name, |index| &name[..index]),
        _ => {}
    }
    name.to_string()
}

/// The repository URL makepkg clones a git source from.
pub(crate) fn git_source_url(entry: &str) -> &str {
    let url = entry.split_once("::").map_or(entry, |(_, url)| url);
    let url = url.strip_prefix("git+").unwrap_or(url);
    url.split(['#', '?']).next().unwrap_or(url)
}

/// Whether a source is kept as a version-control checkout.
pub(crate) fn is_vcs_source(entry: &str) -> bool {
    VCS.contains(&source_protocol(entry))
}

/// The arrays of a listing that say what is fetched and how it is checked.
fn is_listed_array(key: &str) -> bool {
    let base = key.split_once('_').map_or(key, |(base, _)| base);
    matches!(key, "noextract" | "validpgpkeys") || base == "source" || CHECKSUMS.contains(&base)
}

/// The `key = value` lines of a listing's first section, the one for the
/// package base: sources and checksums are only there.
pub(crate) fn base_section(srcinfo: &str) -> impl Iterator<Item = (&str, &str)> {
    srcinfo
        .lines()
        .take_while(|line| !line.starts_with("pkgname = "))
        .filter_map(|line| line.trim_start().split_once(" = "))
        .map(|(key, value)| (key, value.trim_end()))
}

/// Why `srcinfo` is not a listing as `makepkg --printsrcinfo` prints one,
/// if it is not. The recipe is loaded by the shell that prints the listing,
/// so anything it writes to the same output lands in it: a listing with
/// text before its first line, a second package base, or a line of another
/// shape was not written by makepkg alone.
pub(crate) fn check_listing(srcinfo: &str) -> Result<(), String> {
    let mut lines = srcinfo.lines();
    if !lines
        .next()
        .is_some_and(|line| line.starts_with("pkgbase = "))
    {
        return Err("it does not start with the package base".into());
    }
    let mut packages = 0;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if line.chars().any(|c| c.is_control() && c != '\t') {
            return Err("it holds control characters".into());
        }
        if line.starts_with("pkgname = ") {
            packages += 1;
            continue;
        }
        let entry = line
            .strip_prefix('\t')
            .and_then(|rest| rest.split_once(" ="));
        let named = entry.is_some_and(|(key, value)| {
            !key.is_empty()
                && (value.is_empty() || value.starts_with(' '))
                && key
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        });
        if !named || entry.is_some_and(|(key, _)| key == "pkgbase") {
            return Err(if line.trim_start().starts_with("pkgbase =") {
                "it names more than one package base".into()
            } else {
                "it holds a line makepkg does not print".into()
            });
        }
    }
    if packages == 0 {
        return Err("it names no package".into());
    }
    Ok(())
}

/// Where a recipe that writes its arrays out plainly (`written`, from
/// `recipe::sources`) and its listing disagree: the name of the first array
/// that differs. Such a recipe told the listing something else than its
/// text says, so what it builds with cannot be known. An array for an
/// architecture the listing does not name is not listed, and is left out.
pub(crate) fn written_mismatch(written: &[(String, Vec<String>)], srcinfo: &str) -> Option<String> {
    let mut listed: Vec<(&str, Vec<&str>)> = Vec::new();
    let mut arches: Vec<&str> = Vec::new();
    for (key, value) in base_section(srcinfo) {
        if key == "arch" {
            arches.push(value);
        }
        if !is_listed_array(key) {
            continue;
        }
        match listed.iter_mut().find(|(known, _)| *known == key) {
            Some((_, values)) => values.push(value),
            None => listed.push((key, vec![value])),
        }
    }
    // makepkg prints a value with its blanks made single and none at its
    // ends; an empty one says nothing either way.
    let printed = |words: &[String]| -> Vec<String> {
        words
            .iter()
            .map(|word| word.split_whitespace().collect::<Vec<_>>().join(" "))
            .filter(|word| !word.is_empty())
            .collect()
    };
    for (key, values) in &listed {
        let values: Vec<&str> = values.iter().copied().filter(|v| !v.is_empty()).collect();
        let same = written
            .iter()
            .find(|(name, _)| name == key)
            .map_or(values.is_empty(), |(_, words)| printed(words) == values);
        if !same {
            return Some((*key).to_string());
        }
    }
    written
        .iter()
        .find(|(name, words)| {
            let arch = name.split_once('_').map(|(_, arch)| arch);
            !printed(words).is_empty()
                && !listed.iter().any(|(key, _)| key == name)
                && arch.is_none_or(|arch| arches.contains(&arch))
        })
        .map(|(name, _)| name.clone())
}

/// The sources of `makepkg --printsrcinfo` output, each paired with its
/// checksums of every algorithm, per architecture.
pub(crate) fn parse_srcinfo(text: &str) -> Vec<Source> {
    // Keys are `source` or `sha256sums`, optionally with `_<arch>`.
    let mut sources: Vec<(String, Vec<String>)> = Vec::new();
    let mut sums: Vec<(String, Vec<String>)> = Vec::new();
    for (key, value) in base_section(text) {
        let (base, arch) = key.split_once('_').unwrap_or((key, ""));
        let push = |list: &mut Vec<(String, Vec<String>)>| {
            let arch = arch.to_string();
            match list.iter_mut().find(|(candidate, _)| *candidate == arch) {
                Some((_, values)) => values.push(value.to_string()),
                None => list.push((arch, vec![value.to_string()])),
            }
        };
        if base == "source" {
            push(&mut sources);
        } else if CHECKSUMS.contains(&base) {
            push(&mut sums);
        }
    }

    let mut result = Vec::new();
    for (arch, entries) in &sources {
        for (index, entry) in entries.iter().enumerate() {
            let checksums = sums
                .iter()
                .filter(|(sum_arch, _)| sum_arch == arch)
                .filter_map(|(_, values)| values.get(index).cloned())
                .collect();
            result.push(Source {
                entry: entry.clone(),
                checksums,
            });
        }
    }
    result
}

/// What the source check found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SourceChecks {
    /// Sources whose content can change after the review: unpinned
    /// repositories and unverified downloads over an encrypted connection.
    pub(crate) warnings: Vec<String>,
    /// Sources anyone on the network path can replace (unverified and
    /// unencrypted): the build does not start.
    pub(crate) blocking: Vec<String>,
    /// The same warnings for the AI, written only from Guardian's own
    /// words and a validated host name, never from the entry's text.
    pub(crate) context: Vec<String>,
}

/// A source entry split the way makepkg reads it.
struct Parsed<'a> {
    /// The version-control system (`git`, `hg`, ...), if any.
    vcs: Option<&'a str>,
    /// The transport, lowercased (`https`, `git`, `http`, ...).
    transport: String,
    host: String,
    /// `key=value` after `#`.
    fragment: Option<(&'a str, &'a str)>,
}

const VCS: &[&str] = &["git", "hg", "svn", "bzr", "fossil"];
/// `lp` is Launchpad, which bzr reaches over https or ssh.
const ENCRYPTED: &[&str] = &["https", "ssh", "scp", "sftp", "file", "lp"];

/// `None` for a local file (reviewed with the recipe).
fn parse_source(entry: &str) -> Option<Parsed<'_>> {
    let url = entry.split_once("::").map_or(entry, |(_, url)| url);
    let (scheme, rest) = if let Some((scheme, rest)) = url.split_once("://") {
        (scheme, rest)
    } else {
        let index = url.find("+lp:")?;
        (&url[..index + 3], &url[index + 4..])
    };
    let scheme_lower = scheme.to_ascii_lowercase();
    let (vcs, transport) = match scheme_lower.split_once('+') {
        Some((vcs, transport)) => (
            VCS.iter().find(|name| **name == vcs).copied(),
            transport.to_string(),
        ),
        None => (
            VCS.iter().find(|name| **name == scheme_lower).copied(),
            scheme_lower.clone(),
        ),
    };
    let fragment = rest
        .split_once('#')
        .and_then(|(_, fragment)| fragment.split_once('='));
    // `scp` takes what follows the last `://` for its address.
    let host = if transport == "scp" && rest.contains("://") {
        UNPARSEABLE_HOST.into()
    } else {
        Authority::of(rest).shown()
    };
    Some(Parsed {
        vcs,
        transport,
        host,
        fragment,
    })
}

/// The host a source is downloaded from, as a validated name; `None` for a
/// local file.
pub(crate) fn source_host(entry: &str) -> Option<String> {
    parse_source(entry).map(|parsed| parsed.host)
}

fn full_hash(value: &str, lengths: &[usize]) -> bool {
    lengths.contains(&value.len()) && value.chars().all(|character| character.is_ascii_hexdigit())
}

/// Replaces control characters, so a source cannot rewrite the terminal.
fn shown(entry: &str) -> String {
    entry
        .chars()
        .take(160)
        .map(|character| {
            if character.is_control() {
                '?'
            } else {
                character
            }
        })
        .collect()
}

/// Sources whose content can differ from what a checksum or a commit pins:
/// code fetched without verification can change after the review, or
/// between one download and the next.
pub(crate) fn check_sources(sources: &[Source]) -> SourceChecks {
    let mut checks = SourceChecks::default();
    let total = sources.len();
    for (index, source) in sources.iter().enumerate() {
        let Some(parsed) = parse_source(&source.entry) else {
            continue;
        };
        let verified = source.checksums.iter().any(|sum| sum != "SKIP");
        let encrypted = ENCRYPTED.contains(&parsed.transport.as_str());
        let number = index + 1;
        let host = &parsed.host;
        let entry = shown(&source.entry);
        let warn = |checks: &mut SourceChecks, terminal: String, context: &str| {
            checks.warnings.push(terminal);
            checks.context.push(format!(
                "source {number} of {total} (host {host}) {context}."
            ));
        };
        if let Some(vcs) = parsed.vcs {
            let (key, value) = parsed.fragment.unwrap_or(("", ""));
            let hash_pinned = match (vcs, key) {
                ("git", "commit") => full_hash(value, &[40, 64]),
                ("hg", "revision") => full_hash(value, &[40]),
                ("fossil", "commit") => value.len() >= 40 && full_hash(value, &[value.len()]),
                _ => false,
            };
            let pinned = hash_pinned || (matches!(key, "commit" | "tag") && verified);
            if !encrypted && !pinned {
                checks.blocking.push(format!(
                    "{entry} is fetched over an unencrypted connection without a full commit or checksum: anyone on the network path can replace it (use https, or pin a full commit)"
                ));
                continue;
            }
            if pinned {
                continue;
            }
            match key {
                "commit" => warn(
                    &mut checks,
                    format!("{entry} names a branch or tag in commit=, not a full commit"),
                    "names a branch or tag, not a full commit",
                ),
                "tag" => warn(
                    &mut checks,
                    format!("{entry} is pinned to a tag, which its owner can move to other code"),
                    "is pinned to a tag, which its owner can move to other code",
                ),
                "revision" => warn(
                    &mut checks,
                    format!("{entry} is pinned by a revision the server resolves"),
                    "is pinned by a revision the server resolves, not a full hash",
                ),
                _ => warn(
                    &mut checks,
                    format!(
                        "{entry} is a repository not pinned to a commit: its code can change after this review"
                    ),
                    "is a repository not pinned to a commit: its code can change after this review",
                ),
            }
        } else if !verified {
            if encrypted {
                warn(
                    &mut checks,
                    format!(
                        "{entry} is downloaded without a checksum: its content is not verified"
                    ),
                    "is downloaded without a checksum: its content is not verified",
                );
            } else {
                checks.blocking.push(format!(
                    "{entry} is downloaded without a checksum over an unencrypted connection: anyone on the network path can replace it"
                ));
            }
        }
    }
    checks
}
